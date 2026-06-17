"""
Capacités SIGINT (Signals Intelligence) avancées - Module Core

Objectifs:
1. Localisation géographique des émetteurs (TDOA, RSSI, AoA)
2. Caractérisation des signaux (modulation, puissance, régularité)
3. Cartographie spatiale 3D des flux RF
4. Suivi temporel des émetteurs mobiles
5. Classification des menaces par signature RF
"""

from __future__ import annotations

import numpy as np
import scipy.signal as signal
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
import hashlib
import json
from collections import defaultdict

class TypeEmetteur(str, Enum):
    """Classification des types d'émetteurs"""
    WIFI_AP = "wifi_access_point"
    WIFI_CLIENT = "wifi_client"
    BLE_PERIPHERIQUE = "ble_peripheral"
    BLE_CENTRAL = "ble_central"
    LORA_GATEWAY = "lora_gateway"
    LORA_DEVICE = "lora_device"
    CELLULAIRE_2G = "cellulaire_2g"
    CELLULAIRE_3G = "cellulaire_3g"
    CELLULAIRE_4G = "cellulaire_4g"
    CELLULAIRE_5G = "cellulaire_5g"
    EQUIPEMENT_PRO_COM = "equipement_pro_com"
    RADAR_PRO = "radar_pro"
    EMETTEUR_INTERFEREUR = "emetteur_interfereur"
    INCONNU = "inconnu"
    BROUILLEUR = "brouilleur"
    DRONE_COMMERCIAL = "drone_commercial"
    DRONE_PRO = "drone_pro"
    IOT = "iot"
    VEHICULE = "vehicule"
    PORTABLE = "telephone_portable"
    SATELLITE = "satellite"
    RADIO_AMATEUR = "radio_amateur"
    AVION = "avion"
    NAVIRE = "navire"

class PrioriteSignal(int, Enum):
    """Priorité pour l'analyse opérationnelle"""
    CRITIQUE = 100  # Brouilleurs, drones, équipements critiques
    HAUTE = 75      # Equipements inconnus, signaux cryptés
    MOYENNE = 50    # WiFi enterprise, BLE medical
    BASSE = 25      # WiFi domestique, BLE grand public
    INFO = 10       # BLE beacons, LoRa public

class Affiliations(str, Enum):
    """Affiliation estimée de l'émetteur"""
    ALLIE = "allié"
    NEUTRE = "neutre"
    ADVERSARIAL = "adversaire"
    INCONNU = "inconnu"
    CIVIL = "civil"
    ALLIE_INSTITUTIONNEL = "allie_institutionnel"
    ADVERSAIRE_INSTITUTIONNEL = "adversaire_institutionnel"
    MENACE_HAUTE = "menace_haute"

@dataclass
class Position3D:
    """Position géographique 3D avec incertitude"""
    latitude: Optional[float] = None  # degrés décimaux
    longitude: Optional[float] = None
    altitude: Optional[float] = None  # mètres
    x: Optional[float] = None  # mètres (système de coordonnées local)
    y: Optional[float] = None
    z: Optional[float] = None
    
    incertitude_meters: float = 0.0
    methode_localisation: str = "unknown"
    timestamp: datetime = field(default_factory=datetime.now)
    
    def to_dict(self) -> Dict:
        return {
            "coords": {
                "lat": self.latitude,
                "lon": self.longitude,
                "alt": self.altitude,
                "x": self.x,
                "y": self.y,
                "z": self.z
            },
            "incertitude": self.incertitude_meters,
            "methode": self.methode_localisation,
            "timestamp": self.timestamp.isoformat()
        }

@dataclass
class CaracterisationSignal:
    """Caractérisation complète d'un signal RF"""
    # Paramètres fondamentaux
    frequence_centre_mhz: float
    frequence_min_mhz: float
    frequence_max_mhz: float
    bande_passante_khz: float
    puissance_db: float
    puissance_dbm: float
    
    # Paramètres de modulation
    modulation_type: str  # "BPSK", "QPSK", "16QAM", "64QAM", "GFSK", "MSK", "LORA"
    symbol_rate_bauds: Optional[float] = None
    chip_rate_chips_sec: Optional[float] = None
    
    # Paramètres temporels
    duree_paquet_ms: Optional[float] = None
    intervalle_paquets_ms: Optional[float] = None
    regularite_temporelle: float = 0.0  # 0-1 (1 = très régulier)
    
    # Analyse spectrale
    forme_onde_iq: Optional[np.ndarray] = None
    spectre_magnitude: Optional[np.ndarray] = None
    spectre_phase: Optional[np.ndarray] = None
    
    # Signatures PHY uniques
    signature_phystique: Optional[str] = None
    empreinte_paquet: Optional[str] = None
    pattern_preamble: Optional[np.ndarray] = None
    
    # Métriques de qualité
    snr_db: Optional[float] = None
    evm_percent: Optional[float] = None
    ber_estimate: Optional[float] = None
    
    # Métadonnées
    protocole: Optional[str] = None  # "802.11", "Bluetooth", "LoRaWAN"
    version_protocole: Optional[str] = None
    
    def calculer_empreinte(self) -> str:
        """Calcule une empreinte numérique unique du signal"""
        if self.signature_phystique:
            return self.signature_phystique
        
        # Créer une signature basée sur les paramètres
        params_str = f"{self.frequence_centre_mhz:.2f}_{self.bande_passante_khz:.0f}_{self.modulation_type}_{self.puissance_dbm:.1f}"
        return hashlib.sha256(params_str.encode()).hexdigest()[:16]
    
    def to_dict(self) -> Dict:
        """Convertit en dictionnaire pour sérialisation"""
        return {
            "frequences": {
                "centre_mhz": self.frequence_centre_mhz,
                "min_mhz": self.frequence_min_mhz,
                "max_mhz": self.frequence_max_mhz,
                "bande_passante_khz": self.bande_passante_khz
            },
            "puissance": {
                "db": self.puissance_db,
                "dbm": self.puissance_dbm
            },
            "modulation": {
                "type": self.modulation_type,
                "symbol_rate": self.symbol_rate_bauds,
                "chip_rate": self.chip_rate_chips_sec
            },
            "temporel": {
                "duree_paquet_ms": self.duree_paquet_ms,
                "intervalle_ms": self.intervalle_paquets_ms,
                "regularite": self.regularite_temporelle
            },
            "qualite": {
                "snr_db": self.snr_db,
                "evm_percent": self.evm_percent,
                "ber": self.ber_estimate
            },
            "signature": {
                "signature_phystique": self.signature_phystique,
                "empreinte": self.calculer_empreinte(),
                "protocole": self.protocole,
                "version": self.version_protocole
            }
        }

@dataclass
class EmetteurRF:
    """Entité représentant un émetteur RF cartographié"""
    # Identification
    id_unique: str
    adresse_mac: Optional[str] = None
    ssid: Optional[str] = None
    nom: str = ""
    
    # Classification
    type_emetteur: TypeEmetteur = TypeEmetteur.INCONNU
    priorite: PrioriteSignal = PrioriteSignal.MOYENNE
    affiliation: Affiliations = Affiliations.INCONNU
    
    # Localisation et mouvement
    positions: List[Position3D] = field(default_factory=list)
    trajectoire: List[Dict] = field(default_factory=list)  # positions avec timestamps
    
    # Caractérisation des signaux
    caracteristiques_signaux: List[CaracterisationSignal] = field(default_factory=list)
    historique_signaux: List[Tuple[datetime, CaracterisationSignal]] = field(default_factory=list)
    
    # Métadonnées temporelles
    premiere_detection: Optional[datetime] = None
    derniere_detection: Optional[datetime] = None
    duree_activite_total_minutes: float = 0.0
    pourcentage_activite: float = 0.0  # % du temps d'observation
    
    # Analyse comportementale
    pattern_horaire: Dict[str, List[Tuple[int, int]]] = field(default_factory=dict)  # {"lundi": [(9,12), (14,17)]}
    pattern_mouvement: Dict[str, Any] = field(default_factory=dict)
    zones_operation: List[Tuple[float, float, float]] = field(default_factory=list)  # zones fréquentées
    
    # Évaluation de menace
    niveau_menace: int = 0  # 0-100
    menaces_detectees: List[str] = field(default_factory=list)
    vulnerabilites_identifiees: List[str] = field(default_factory=list)
    
    # Visualisation
    couleur: str = "#808080"  # Couleur pour la carte
    icone: str = "default"  # Icône pour l'interface
    
    def __post_init__(self):
        """Initialisation après création"""
        if not self.nom:
            if self.ssid:
                self.nom = f"SSID: {self.ssid}"
            elif self.adresse_mac:
                self.nom = f"MAC: {self.adresse_mac}"
            else:
                self.nom = f"Emetteur_{self.id_unique[:8]}"
    
    def ajouter_position(self, position: Position3D):
        """Ajoute une nouvelle position à l'historique"""
        self.positions.append(position)
        self.trajectoire.append(position.to_dict())
        
        # Mise à jour du timestamp de dernière détection
        self.derniere_detection = position.timestamp
        
        # Initialisation première détection
        if self.premiere_detection is None:
            self.premiere_detection = position.timestamp
        
        # Calcul durée activité
        if self.premiere_detection and self.derniere_detection:
            delta = self.derniere_detection - self.premiere_detection
            self.duree_activite_total_minutes = delta.total_seconds() / 60.0
    
    def ajouter_caracteristique(self, caracteristique: CaracterisationSignal, timestamp: datetime = None):
        """Ajoute une caractérisation de signal"""
        self.caracteristiques_signaux.append(caracteristique)
        ts = timestamp or datetime.now()
        self.historique_signaux.append((ts, caracteristique))
    
    def calculer_statistiques_mouvement(self) -> Dict:
        """Calcule les statistiques de mouvement"""
        if len(self.positions) < 2:
            return {"message": "Pas assez de données pour calculer"}
        
        # Calcul de vitesse et accélération
        vitesses = []
        accelerations = []
        distances = []
        directions = []
        
        positions_sorted = sorted(self.positions, key=lambda p: p.timestamp)
        
        for i in range(1, len(positions_sorted)):
            p1 = positions_sorted[i-1]
            p2 = positions_sorted[i]
            
            # Vérifier que les coordonnées sont disponibles
            if None in [p1.x, p1.y, p1.z, p2.x, p2.y, p2.z]:
                continue
            
            delta_t = (p2.timestamp - p1.timestamp).total_seconds()
            if delta_t <= 0:
                continue
            
            # Distance 3D
            dx = p2.x - p1.x
            dy = p2.y - p1.y
            dz = p2.z - p1.z
            distance = np.sqrt(dx**2 + dy**2 + dz**2)
            distances.append(distance)
            
            # Vitesse
            vitesse = distance / delta_t
            vitesses.append(vitesse)
            
            # Direction
            if distance > 0:
                direction = np.degrees(np.arctan2(dy, dx))
                directions.append(direction)
            
            # Accélération (si on a au moins 3 points)
            if i > 1 and len(vitesses) >= 2:
                acceleration = (vitesses[-1] - vitesses[-2]) / delta_t
                accelerations.append(acceleration)
        
        # Calcul des statistiques
        stats = {
            "nb_positions": len(self.positions),
            "nb_deplacements": len(distances),
            "distance_totale": sum(distances) if distances else 0,
            "distance_moyenne": np.mean(distances) if distances else 0,
            "distance_max": np.max(distances) if distances else 0,
            "vitesse_moyenne": np.mean(vitesses) if vitesses else 0,
            "vitesse_max": np.max(vitesses) if vitesses else 0,
            "acceleration_moyenne": np.mean(accelerations) if accelerations else 0,
            "direction_moyenne": np.mean(directions) if directions else None,
            "direction_std": np.std(directions) if directions else None
        }
        
        # Classification du mouvement
        if vitesses:
            vitesse_moy = np.mean(vitesses)
            if vitesse_moy > 5.0:  # m/s
                stats["type_mouvement"] = "rapide"
            elif vitesse_moy > 1.0:
                stats["type_mouvement"] = "modere"
            elif vitesse_moy > 0.1:
                stats["type_mouvement"] = "lent"
            else:
                stats["type_mouvement"] = "statique"
        else:
            stats["type_mouvement"] = "inconnu"
        
        return stats
    
    def calculer_zones_operation(self, resolution_meters: float = 10.0) -> List[Dict]:
        """Détermine les zones d'opération fréquentes"""
        if not self.positions:
            return []
        
        # Créer une grille discrète
        x_vals = [p.x for p in self.positions if p.x is not None]
        y_vals = [p.y for p in self.positions if p.y is not None]
        z_vals = [p.z for p in self.positions if p.z is not None]
        
        if not x_vals or not y_vals:
            return []
        
        # Statistiques de position
        x_center = np.mean(x_vals)
        y_center = np.mean(y_vals)
        z_center = np.mean(z_vals) if z_vals else 0
        
        x_std = np.std(x_vals)
        y_std = np.std(y_vals)
        z_std = np.std(z_vals) if z_vals else 0
        
        # Définir la zone principale d'opération
        zones = [{
            "type": "zone_principale",
            "centre": {"x": x_center, "y": y_center, "z": z_center},
            "rayon": max(x_std, y_std, 5.0),  # Au moins 5m
            "pourcentage_temps": 0.8,  # Estimation
            "concentration": 1.0 / (1.0 + np.sqrt(x_std**2 + y_std**2))
        }]
        
        # Détecter des clusters si assez de points
        if len(self.positions) > 10:
            # Simple clustering basé sur la densité
            from collections import defaultdict
            grid_counts = defaultdict(int)
            
            for p in self.positions:
                if p.x is not None and p.y is not None:
                    grid_x = int(p.x / resolution_meters)
                    grid_y = int(p.y / resolution_meters)
                    grid_counts[(grid_x, grid_y)] += 1
            
            # Trouver les cellules avec haute densité
            dense_cells = [(cell, count) for cell, count in grid_counts.items() 
                         if count >= len(self.positions) * 0.1]  # Au moins 10% du temps
            
            for (grid_x, grid_y), count in dense_cells:
                zones.append({
                    "type": "zone_haute_densite",
                    "centre": {
                        "x": grid_x * resolution_meters + resolution_meters/2,
                        "y": grid_y * resolution_meters + resolution_meters/2,
                        "z": z_center
                    },
                    "rayon": resolution_meters,
                    "pourcentage_temps": count / len(self.positions),
                    "densite": count / (resolution_meters ** 2)
                })
        
        return zones
    
    def identifier_pattern_horaire(self) -> Dict:
        """Identifie les patterns temporels d'activité"""
        if not self.historique_signaux:
            return {}
        
        # Regrouper par jour de la semaine et heure
        activite_par_jour = defaultdict(lambda: [0] * 24)  # 24 heures
        
        for timestamp, _ in self.historique_signaux:
            jour_semaine = timestamp.strftime("%A")
            heure = timestamp.hour
            activite_par_jour[jour_semaine][heure] += 1
        
        # Normaliser
        pattern = {}
        for jour, heures in activite_par_jour.items():
            max_activite = max(heures) if max(heures) > 0 else 1
            heures_normalisees = [h/max_activite for h in heures]
            
            # Trouver les plages horaires actives (> 0.5)
            plages_actives = []
            in_plage = False
            start_hour = 0
            
            for i, activite in enumerate(heures_normalisees):
                if activite >= 0.5 and not in_plage:
                    start_hour = i
                    in_plage = True
                elif activite < 0.5 and in_plage:
                    plages_actives.append((start_hour, i))
                    in_plage = False
            
            if in_plage:
                plages_actives.append((start_hour, 24))
            
            pattern[jour] = {
                "heures": heures_normalisees,
                "plages_actives": plages_actives,
                "pic_activite": heures_normalisees.index(max(heures_normalisees))
            }
        
        self.pattern_horaire = pattern
        return pattern
    
    def evaluer_menace_emetteur(self) -> int:
        """Évalue la menace globale de l'émetteur (0-100)"""
        score = 0
        
        # Facteurs basés sur le type
        scores_type = {
            TypeEmetteur.DRONE_PRO: 90,
            TypeEmetteur.EMETTEUR_INTERFEREUR: 95,
            TypeEmetteur.RADAR_PRO: 70,
            TypeEmetteur.BROUILLEUR: 85,
            TypeEmetteur.DRONE_COMMERCIAL: 60,
            TypeEmetteur.INCONNU: 75,
            TypeEmetteur.EQUIPEMENT_PRO_COM: 65,
            TypeEmetteur.WIFI_AP: 10,
            TypeEmetteur.WIFI_CLIENT: 5,
            TypeEmetteur.BLE_PERIPHERIQUE: 3,
            TypeEmetteur.CELLULAIRE_5G: 20,
            TypeEmetteur.IOT: 15
        }
        
        score += scores_type.get(self.type_emetteur, 20)
        
        # Facteur affiliation
        scores_affiliation = {
            Affiliations.ADVERSAIRE_INSTITUTIONNEL: 80,
            Affiliations.ADVERSARIAL: 70,
            Affiliations.MENACE_HAUTE: 95,
            Affiliations.INCONNU: 50,
            Affiliations.ALLIE_INSTITUTIONNEL: -20,  # Réduction pour allié
            Affiliations.ALLIE: -30,
            Affiliations.CIVIL: 0,
            Affiliations.NEUTRE: 10
        }
        
        score += scores_affiliation.get(self.affiliation, 30)
        
        # Facteurs comportementaux
        stats = self.calculer_statistiques_mouvement()
        
        # Mouvement rapide suspect
        if stats.get("type_mouvement") == "rapide" and self.type_emetteur not in [TypeEmetteur.VEHICULE, TypeEmetteur.AVION]:
            score += 20
        
        # Zones sensibles (à implémenter avec géofencing)
        # Si l'émetteur est près d'infrastructure critique: +30
        
        # Activité nocturne suspecte
        pattern = self.identifier_pattern_horaire()
        for jour, data in pattern.items():
            heures = data.get("heures", [0]*24)
            activite_nocturne = sum(heures[0:6] + heures[22:24]) / len(heures)
            if activite_nocturne > 0.7 and self.type_emetteur not in [TypeEmetteur.WIFI_AP, TypeEmetteur.IOT]:
                score += 25
        
        # Émetteur furtif (peu de caractéristiques)
        if len(self.caracteristiques_signaux) == 0:
            score += 15
        
        # Ajustement basé sur la puissance (fort émetteur = plus dangereux)
        if self.caracteristiques_signaux:
            puissances = [sig.puissance_dbm for sig in self.caracteristiques_signaux if sig.puissance_dbm]
            if puissances:
                puissance_max = max(puissances)
                if puissance_max > 20:  # plus de 20 dBm = puissant
                    score += min(20, (puissance_max - 20) * 2)
        
        self.niveau_menace = min(100, max(0, score))
        return self.niveau_menace
    
    def to_dict(self) -> Dict:
        """Convertit l'émetteur en dictionnaire pour sérialisation"""
        return {
            "identification": {
                "id": self.id_unique,
                "mac": self.adresse_mac,
                "ssid": self.ssid,
                "nom": self.nom
            },
            "classification": {
                "type": self.type_emetteur.value,
                "priorite": self.priorite.value,
                "affiliation": self.affiliation.value,
                "niveau_menace": self.niveau_menace
            },
            "localisation": {
                "nb_positions": len(self.positions),
                "derniere_position": self.positions[-1].to_dict() if self.positions else None,
                "trajectoire": self.trajectoire[-10:] if self.trajectoire else []  # 10 dernières
            },
            "statistiques": {
                "mouvement": self.calculer_statistiques_mouvement(),
                "temporel": {
                    "premiere_detection": self.premiere_detection.isoformat() if self.premiere_detection else None,
                    "derniere_detection": self.derniere_detection.isoformat() if self.derniere_detection else None,
                    "duree_activite_minutes": self.duree_activite_total_minutes,
                    "pourcentage_activite": self.pourcentage_activite
                },
                "zones_operation": self.calculer_zones_operation(),
                "pattern_horaire": self.pattern_horaire
            },
            "signaux": {
                "nb_caracterisations": len(self.caracteristiques_signaux),
                "caracteristiques_recentes": [c.to_dict() for c in self.caracteristiques_signaux[-3:]] if self.caracteristiques_signaux else [],
                "frequences_utilisees": list(set([c.frequence_centre_mhz for c in self.caracteristiques_signaux]))
            },
            "menaces": {
                "niveau": self.niveau_menace,
                "menaces_detectees": self.menaces_detectees,
                "vulnerabilites": self.vulnerabilites_identifiees
            },
            "visualisation": {
                "couleur": self.couleur,
                "icone": self.icone
            }
        }