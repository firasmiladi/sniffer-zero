"""
Moteur principal de Cartographie RF

Ce module orchestre la collecte, l'analyse et la visualisation
de tous les flux RF dans l'environnement de la cage de Faraday.
"""

from __future__ import annotations
import json
import time
import uuid
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from collections import defaultdict
from pathlib import Path

import numpy as np

from .core import (
    TypeEmetteur, PrioriteSignal, Affiliations,
    Position3D, CaracterisationSignal, EmetteurRF
)
from .localisation import MesureLocalisation, SystemeLocalisation
from .analyse_spectrale import (
    AnalyseurSpectral, SignalDetecte, TypeModulation, BandeISM
)



@dataclass
class ConfigCartographie:
    """Configuration du système de cartographie"""
    # Paramètres de balayage
    freq_debut_mhz: float = 400.0
    freq_fin_mhz: float = 6000.0
    pas_balayage_mhz: float = 20.0
    temps_par_pas_ms: float = 100.0

    # Paramètres de détection
    seuil_detection_dbm: float = -80.0
    seuil_nouveau_emetteur_mhz: float = 0.5
    temps_expiration_emetteur_min: float = 30.0

    # Paramètres de localisation
    methode_localisation: str = "hybride"
    nb_mesures_min_localisation: int = 3
    incertitude_max_acceptee_m: float = 50.0

    # Paramètres d'export
    intervalle_export_sec: float = 10.0
    format_export: str = "json"
    dossier_export: str = "data/cartographie"

    # Paramètres militaires
    mode_alerte: bool = True
    seuil_alerte_menace: int = 60
    frequences_prioritaires_mhz: List[float] = field(
        default_factory=lambda: [433.0, 868.0, 2412.0, 2437.0, 2462.0, 5180.0, 5240.0]
    )


class MoteurCartographie:
    """
    Moteur principal de cartographie RF

    Orchestre:
    1. Balayage spectral (HackRF One)
    2. Détection et classification des signaux
    3. Localisation des émetteurs
    4. Suivi temporel et trajectoires
    5. Évaluation des menaces
    6. Export pour visualisation
    """

    def __init__(self, config: ConfigCartographie = None):
        self.config = config or ConfigCartographie()
        self.analyseur = AnalyseurSpectral(sample_rate_hz=20e6)
        self.localisateur = SystemeLocalisation()

        # Base de données des émetteurs détectés
        self.emetteurs: Dict[str, EmetteurRF] = {}
        self.signaux_bruts: List[SignalDetecte] = []

        # Historique temporel
        self.historique_balayages: List[Dict] = []
        self.alertes: List[Dict] = []

        # Statistiques globales
        self.stats = {
            "nb_balayages": 0,
            "nb_signaux_detectes": 0,
            "nb_emetteurs_uniques": 0,
            "nb_alertes": 0,
            "debut_session": datetime.now().isoformat(),
            "derniere_mise_a_jour": None
        }

    def demarrer_balayage(self, iq_source=None) -> Dict:
        """
        Démarre un cycle complet de balayage spectral

        En mode réel: Utilise le HackRF One pour balayer les fréquences
        En mode simulation: Génère des données de test
        """
        resultats_cycle = {
            "timestamp": datetime.now().isoformat(),
            "signaux_detectes": [],
            "nouveaux_emetteurs": [],
            "emetteurs_mis_a_jour": [],
            "alertes": []
        }

        # Balayer chaque pas de fréquence
        freq_actuelle = self.config.freq_debut_mhz
        while freq_actuelle < self.config.freq_fin_mhz:
            # En mode réel: capturer IQ du HackRF
            # iq_data = hackrf_capture(freq_actuelle * 1e6, duration_ms)
            # En simulation: données de test
            if iq_source:
                iq_data = iq_source.capturer(freq_actuelle * 1e6)
            else:
                iq_data = self._generer_iq_test(freq_actuelle)

            # Analyser les données IQ
            signaux = self.analyseur.analyser_iq(iq_data, freq_actuelle * 1e6)

            # Traiter chaque signal détecté
            for sig in signaux:
                self._traiter_signal(sig, resultats_cycle)

            freq_actuelle += self.config.pas_balayage_mhz

        # Mise à jour des statistiques
        self.stats["nb_balayages"] += 1
        self.stats["derniere_mise_a_jour"] = datetime.now().isoformat()
        self.stats["nb_emetteurs_uniques"] = len(self.emetteurs)

        # Évaluation des menaces
        self._evaluer_menaces_globales(resultats_cycle)

        # Archiver le balayage
        self.historique_balayages.append(resultats_cycle)

        return resultats_cycle

    def _traiter_signal(self, signal: SignalDetecte, resultats: Dict):
        """Traite un signal détecté: association ou création d'émetteur"""
        self.signaux_bruts.append(signal)
        self.stats["nb_signaux_detectes"] += 1
        resultats["signaux_detectes"].append(signal.to_dict())

        # Chercher un émetteur existant correspondant
        emetteur_id = self._associer_signal_emetteur(signal)

        if emetteur_id:
            # Mise à jour d'un émetteur existant
            self._mettre_a_jour_emetteur(emetteur_id, signal)
            resultats["emetteurs_mis_a_jour"].append(emetteur_id)
        else:
            # Nouvel émetteur détecté
            nouvel_emetteur = self._creer_emetteur(signal)
            self.emetteurs[nouvel_emetteur.id_unique] = nouvel_emetteur
            resultats["nouveaux_emetteurs"].append(nouvel_emetteur.id_unique)

    def _associer_signal_emetteur(self, signal: SignalDetecte) -> Optional[str]:
        """Associe un signal à un émetteur existant"""
        meilleur_match = None
        meilleur_score = 0.0

        for emetteur_id, emetteur in self.emetteurs.items():
            score = self._calculer_similarite(signal, emetteur)
            if score > meilleur_score and score > 0.7:
                meilleur_score = score
                meilleur_match = emetteur_id

        return meilleur_match

    def _calculer_similarite(self, signal: SignalDetecte, emetteur: EmetteurRF) -> float:
        """Calcule la similarité entre un signal et un émetteur"""
        if not emetteur.caracteristiques_signaux:
            return 0.0

        scores = []

        for carac in emetteur.caracteristiques_signaux[-5:]:  # 5 dernières
            # Similarité fréquentielle
            diff_freq = abs(signal.frequence_centre_mhz - carac.frequence_centre_mhz)
            score_freq = max(0, 1.0 - diff_freq / self.config.seuil_nouveau_emetteur_mhz)

            # Similarité de bande passante
            if carac.bande_passante_khz > 0:
                diff_bw = abs(signal.bande_passante_khz - carac.bande_passante_khz)
                score_bw = max(0, 1.0 - diff_bw / (carac.bande_passante_khz * 0.3))
            else:
                score_bw = 0.5

            # Similarité de puissance (tolérance de 10 dB)
            diff_puissance = abs(signal.puissance_dbm - carac.puissance_dbm)
            score_puissance = max(0, 1.0 - diff_puissance / 10.0)

            score_total = 0.5 * score_freq + 0.3 * score_bw + 0.2 * score_puissance
            scores.append(score_total)

        return max(scores) if scores else 0.0

    def _creer_emetteur(self, signal: SignalDetecte) -> EmetteurRF:
        """Crée un nouvel émetteur à partir d'un signal détecté"""
        emetteur_id = str(uuid.uuid4())[:12]

        # Déterminer le type d'émetteur
        type_em = self._classifier_emetteur(signal)

        # Créer la caractérisation
        carac = CaracterisationSignal(
            frequence_centre_mhz=signal.frequence_centre_mhz,
            frequence_min_mhz=signal.frequence_centre_mhz - signal.bande_passante_khz/2000,
            frequence_max_mhz=signal.frequence_centre_mhz + signal.bande_passante_khz/2000,
            bande_passante_khz=signal.bande_passante_khz,
            puissance_db=signal.puissance_dbm,
            puissance_dbm=signal.puissance_dbm,
            modulation_type=signal.modulation.value,
            snr_db=signal.snr_db,
            protocole=signal.protocole_estime
        )

        emetteur = EmetteurRF(
            id_unique=emetteur_id,
            type_emetteur=type_em,
            priorite=self._determiner_priorite(type_em, signal),
            premiere_detection=signal.timestamp,
            derniere_detection=signal.timestamp
        )
        emetteur.ajouter_caracteristique(carac, signal.timestamp)

        # Attribuer couleur et icône
        emetteur.couleur = self._couleur_par_type(type_em)
        emetteur.icone = self._icone_par_type(type_em)

        return emetteur

    def _mettre_a_jour_emetteur(self, emetteur_id: str, signal: SignalDetecte):
        """Met à jour un émetteur existant avec un nouveau signal"""
        emetteur = self.emetteurs[emetteur_id]

        carac = CaracterisationSignal(
            frequence_centre_mhz=signal.frequence_centre_mhz,
            frequence_min_mhz=signal.frequence_centre_mhz - signal.bande_passante_khz/2000,
            frequence_max_mhz=signal.frequence_centre_mhz + signal.bande_passante_khz/2000,
            bande_passante_khz=signal.bande_passante_khz,
            puissance_db=signal.puissance_dbm,
            puissance_dbm=signal.puissance_dbm,
            modulation_type=signal.modulation.value,
            snr_db=signal.snr_db,
            protocole=signal.protocole_estime
        )
        emetteur.ajouter_caracteristique(carac, signal.timestamp)
        emetteur.derniere_detection = signal.timestamp

    def _classifier_emetteur(self, signal: SignalDetecte) -> TypeEmetteur:
        """Classifie le type d'émetteur basé sur le signal"""
        protocole = signal.protocole_estime or ""

        if "WiFi" in protocole:
            return TypeEmetteur.WIFI_AP
        elif "Bluetooth" in protocole or "BLE" in protocole:
            return TypeEmetteur.BLE_PERIPHERIQUE
        elif "LoRa" in protocole:
            return TypeEmetteur.LORA_DEVICE
        elif "Drone" in protocole:
            return TypeEmetteur.DRONE_COMMERCIAL
        elif "LTE" in protocole or "5G" in protocole:
            return TypeEmetteur.CELLULAIRE_5G
        elif "Zigbee" in protocole:
            return TypeEmetteur.IOT

        return TypeEmetteur.INCONNU

    def _determiner_priorite(self, type_em: TypeEmetteur, signal: SignalDetecte) -> PrioriteSignal:
        """Détermine la priorité d'un émetteur"""
        if type_em in [TypeEmetteur.DRONE_MILITAIRE, TypeEmetteur.BROUILLEUR,
                       TypeEmetteur.MILITAIRE_JAMMER]:
            return PrioriteSignal.CRITIQUE
        elif type_em in [TypeEmetteur.INCONNU, TypeEmetteur.DRONE_COMMERCIAL]:
            return PrioriteSignal.HAUTE
        elif type_em in [TypeEmetteur.WIFI_AP, TypeEmetteur.LORA_DEVICE]:
            return PrioriteSignal.MOYENNE
        elif type_em in [TypeEmetteur.BLE_PERIPHERIQUE, TypeEmetteur.IOT]:
            return PrioriteSignal.BASSE
        return PrioriteSignal.INFO

    def _couleur_par_type(self, type_em: TypeEmetteur) -> str:
        """Retourne la couleur de visualisation pour un type"""
        couleurs = {
            TypeEmetteur.WIFI_AP: "#4CAF50",
            TypeEmetteur.WIFI_CLIENT: "#8BC34A",
            TypeEmetteur.BLE_PERIPHERIQUE: "#2196F3",
            TypeEmetteur.LORA_DEVICE: "#FF9800",
            TypeEmetteur.LORA_GATEWAY: "#FF5722",
            TypeEmetteur.DRONE_COMMERCIAL: "#F44336",
            TypeEmetteur.DRONE_MILITAIRE: "#D32F2F",
            TypeEmetteur.BROUILLEUR: "#B71C1C",
            TypeEmetteur.INCONNU: "#9E9E9E",
            TypeEmetteur.CELLULAIRE_5G: "#9C27B0",
            TypeEmetteur.IOT: "#00BCD4",
        }
        return couleurs.get(type_em, "#757575")

    def _icone_par_type(self, type_em: TypeEmetteur) -> str:
        """Retourne l'icône pour un type d'émetteur"""
        icones = {
            TypeEmetteur.WIFI_AP: "wifi",
            TypeEmetteur.BLE_PERIPHERIQUE: "bluetooth",
            TypeEmetteur.LORA_DEVICE: "antenna",
            TypeEmetteur.DRONE_COMMERCIAL: "drone",
            TypeEmetteur.BROUILLEUR: "warning",
            TypeEmetteur.INCONNU: "question",
            TypeEmetteur.CELLULAIRE_5G: "cell_tower",
            TypeEmetteur.IOT: "device",
        }
        return icones.get(type_em, "radio")

    def _evaluer_menaces_globales(self, resultats: Dict):
        """Évalue les menaces et génère des alertes"""
        for emetteur_id, emetteur in self.emetteurs.items():
            niveau = emetteur.evaluer_menace_emetteur()

            if niveau >= self.config.seuil_alerte_menace:
                alerte = {
                    "timestamp": datetime.now().isoformat(),
                    "emetteur_id": emetteur_id,
                    "type": emetteur.type_emetteur.value,
                    "niveau_menace": niveau,
                    "frequence_mhz": (
                        emetteur.caracteristiques_signaux[-1].frequence_centre_mhz
                        if emetteur.caracteristiques_signaux else None
                    ),
                    "description": f"Menace détectée: {emetteur.nom} ({emetteur.type_emetteur.value})"
                }
                self.alertes.append(alerte)
                resultats["alertes"].append(alerte)
                self.stats["nb_alertes"] += 1

    def _generer_iq_test(self, freq_mhz: float) -> np.ndarray:
        """Génère des données IQ de test pour simulation"""
        N = 4096
        t = np.arange(N) / self.analyseur.sample_rate
        noise = (np.random.randn(N) + 1j * np.random.randn(N)) * 0.01

        # Simuler quelques signaux selon la fréquence
        signal_iq = noise.copy()

        if 2400 <= freq_mhz <= 2500:
            # Simuler un WiFi beacon
            signal_iq += 0.5 * np.exp(1j * 2 * np.pi * 1e6 * t)
            # Simuler un BLE
            signal_iq += 0.1 * np.exp(1j * 2 * np.pi * 5e6 * t)
        elif 860 <= freq_mhz <= 870:
            # Simuler un signal LoRa
            chirp = np.exp(1j * np.pi * 125e3 * t**2 / (N/self.analyseur.sample_rate))
            signal_iq += 0.3 * chirp

        return signal_iq



    def generer_rapport_cartographie(self) -> Dict:
        """Génère un rapport complet de cartographie RF"""
        rapport = {
            "metadata": {
                "timestamp_generation": datetime.now().isoformat(),
                "duree_observation": self._calculer_duree_observation(),
            },
            "resume_executif": self._generer_resume_executif(),
            "statistiques_globales": self.stats,
            "inventaire_emetteurs": self._generer_inventaire(),
            "analyse_bandes": self._analyser_occupation_bandes(),
            "carte_menaces": self._generer_carte_menaces(),
            "alertes": self.alertes[-50:],  # 50 dernières alertes
            "recommandations": self._generer_recommandations()
        }
        return rapport

    def _calculer_duree_observation(self) -> str:
        """Calcule la durée totale d'observation"""
        if not self.historique_balayages:
            return "0 minutes"
        nb = len(self.historique_balayages)
        duree_estimee = nb * (self.config.temps_par_pas_ms / 1000) * \
                       ((self.config.freq_fin_mhz - self.config.freq_debut_mhz) / self.config.pas_balayage_mhz)
        if duree_estimee > 3600:
            return f"{duree_estimee/3600:.1f} heures"
        return f"{duree_estimee/60:.1f} minutes"

    def _generer_resume_executif(self) -> Dict:
        """Génère un résumé exécutif pour le commandement"""
        # Comptage par type
        par_type = defaultdict(int)
        par_bande = defaultdict(int)
        par_menace = {"critique": 0, "haute": 0, "moyenne": 0, "basse": 0}

        for em in self.emetteurs.values():
            par_type[em.type_emetteur.value] += 1
            if em.caracteristiques_signaux:
                bande = SignalDetecte(
                    id_signal="", timestamp=datetime.now(),
                    frequence_centre_mhz=em.caracteristiques_signaux[-1].frequence_centre_mhz,
                    bande_passante_khz=0, puissance_dbm=0, snr_db=0,
                    modulation=TypeModulation.INCONNU, bande_ism=BandeISM.AUTRE
                ).identifier_bande()
                par_bande[bande.value] += 1

            if em.niveau_menace >= 75:
                par_menace["critique"] += 1
            elif em.niveau_menace >= 50:
                par_menace["haute"] += 1
            elif em.niveau_menace >= 25:
                par_menace["moyenne"] += 1
            else:
                par_menace["basse"] += 1

        return {
            "total_emetteurs": len(self.emetteurs),
            "total_signaux_capturés": self.stats["nb_signaux_detectes"],
            "repartition_par_type": dict(par_type),
            "repartition_par_bande": dict(par_bande),
            "repartition_menaces": par_menace,
            "alertes_actives": len([a for a in self.alertes if a["niveau_menace"] >= 60]),
            "emetteurs_inconnus": par_type.get("inconnu", 0),
            "conclusion": self._conclusion_resume(par_menace, par_type)
        }

    def _conclusion_resume(self, par_menace: Dict, par_type: Dict) -> str:
        """Génère une conclusion textuelle"""
        total = len(self.emetteurs)
        if total == 0:
            return "Aucun émetteur détecté. Environnement RF silencieux."

        conclusions = []
        if par_menace["critique"] > 0:
            conclusions.append(
                f"ATTENTION: {par_menace['critique']} émetteur(s) avec menace CRITIQUE détecté(s)."
            )
        if par_type.get("inconnu", 0) > 0:
            conclusions.append(
                f"{par_type['inconnu']} émetteur(s) non identifié(s) nécessitent analyse approfondie."
            )
        conclusions.append(
            f"Total: {total} émetteurs actifs dans l'environnement RF observé."
        )
        return " ".join(conclusions)

    def _generer_inventaire(self) -> List[Dict]:
        """Génère l'inventaire complet des émetteurs"""
        inventaire = []
        for em in sorted(self.emetteurs.values(), key=lambda e: e.niveau_menace, reverse=True):
            inventaire.append(em.to_dict())
        return inventaire

    def _analyser_occupation_bandes(self) -> Dict:
        """Analyse l'occupation des différentes bandes ISM"""
        occupation = {}
        bandes_definition = {
            "ISM_433": (433.0, 435.0),
            "ISM_868": (863.0, 870.0),
            "ISM_915": (902.0, 928.0),
            "WiFi_2.4": (2400.0, 2483.5),
            "WiFi_5_UNII1": (5150.0, 5250.0),
            "WiFi_5_UNII2": (5250.0, 5350.0),
            "WiFi_5_UNII3": (5470.0, 5725.0),
            "ISM_5.8": (5725.0, 5875.0),
            "WiFi_6E": (5925.0, 7125.0)
        }

        for nom_bande, (f_min, f_max) in bandes_definition.items():
            emetteurs_dans_bande = []
            for em in self.emetteurs.values():
                if em.caracteristiques_signaux:
                    freq = em.caracteristiques_signaux[-1].frequence_centre_mhz
                    if f_min <= freq <= f_max:
                        emetteurs_dans_bande.append(em)

            occupation[nom_bande] = {
                "frequence_min_mhz": f_min,
                "frequence_max_mhz": f_max,
                "largeur_mhz": f_max - f_min,
                "nb_emetteurs": len(emetteurs_dans_bande),
                "types_presents": list(set(
                    em.type_emetteur.value for em in emetteurs_dans_bande
                )),
                "puissance_max_dbm": max(
                    (em.caracteristiques_signaux[-1].puissance_dbm
                     for em in emetteurs_dans_bande if em.caracteristiques_signaux),
                    default=-100
                ),
                "occupation_pourcent": len(emetteurs_dans_bande) / max(1, len(self.emetteurs)) * 100
            }

        return occupation

    def _generer_carte_menaces(self) -> Dict:
        """Génère une carte des menaces pour visualisation"""
        menaces = {
            "critique": [],
            "haute": [],
            "moyenne": [],
            "basse": []
        }

        for em in self.emetteurs.values():
            entry = {
                "id": em.id_unique,
                "nom": em.nom,
                "type": em.type_emetteur.value,
                "niveau": em.niveau_menace,
                "couleur": em.couleur,
                "position": em.positions[-1].to_dict() if em.positions else None,
                "frequence_mhz": (
                    em.caracteristiques_signaux[-1].frequence_centre_mhz
                    if em.caracteristiques_signaux else None
                )
            }

            if em.niveau_menace >= 75:
                menaces["critique"].append(entry)
            elif em.niveau_menace >= 50:
                menaces["haute"].append(entry)
            elif em.niveau_menace >= 25:
                menaces["moyenne"].append(entry)
            else:
                menaces["basse"].append(entry)

        return menaces

    def _generer_recommandations(self) -> List[Dict]:
        """Génère des recommandations militaires basées sur l'analyse"""
        recommandations = []

        # Analyser la situation
        nb_inconnus = sum(1 for em in self.emetteurs.values()
                        if em.type_emetteur == TypeEmetteur.INCONNU)
        nb_critiques = sum(1 for em in self.emetteurs.values()
                         if em.niveau_menace >= 75)

        if nb_critiques > 0:
            recommandations.append({
                "priorite": "CRITIQUE",
                "action": "Investigation immédiate des émetteurs à menace critique",
                "detail": f"{nb_critiques} émetteur(s) nécessitent une analyse approfondie"
            })

        if nb_inconnus > 0:
            recommandations.append({
                "priorite": "HAUTE",
                "action": "Identification des émetteurs inconnus",
                "detail": f"{nb_inconnus} émetteur(s) non classifié(s) dans l'environnement"
            })

        # Vérifier la cage de Faraday
        recommandations.append({
            "priorite": "STANDARD",
            "action": "Vérification de l'intégrité de la cage de Faraday",
            "detail": "S'assurer qu'aucun signal externe ne pénètre l'environnement de test"
        })

        return recommandations

    def exporter_json(self, chemin: str = None) -> str:
        """Exporte le rapport complet en JSON"""
        chemin = chemin or f"{self.config.dossier_export}/cartographie_{int(time.time())}.json"
        Path(chemin).parent.mkdir(parents=True, exist_ok=True)

        rapport = self.generer_rapport_cartographie()

        with open(chemin, 'w', encoding='utf-8') as f:
            json.dump(rapport, f, indent=2, ensure_ascii=False, default=str)

        return chemin

    def exporter_grafana(self) -> Dict:
        """Exporte les données dans un format compatible Grafana"""
        # Format pour le plugin Grafana Geomap / Table
        series = []

        for em in self.emetteurs.values():
            point = {
                "name": em.nom,
                "type": em.type_emetteur.value,
                "menace": em.niveau_menace,
                "couleur": em.couleur,
                "frequence": (
                    em.caracteristiques_signaux[-1].frequence_centre_mhz
                    if em.caracteristiques_signaux else 0
                ),
                "puissance": (
                    em.caracteristiques_signaux[-1].puissance_dbm
                    if em.caracteristiques_signaux else -100
                ),
                "premiere_detection": em.premiere_detection.isoformat() if em.premiere_detection else "",
                "derniere_detection": em.derniere_detection.isoformat() if em.derniere_detection else "",
            }
            if em.positions:
                point["x"] = em.positions[-1].x
                point["y"] = em.positions[-1].y
                point["z"] = em.positions[-1].z
            series.append(point)

        return {"emetteurs": series, "alertes": self.alertes[-20:]}
