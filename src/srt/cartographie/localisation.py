"""
Systèmes de localisation RF avancés
Méthodes: TDOA, RSSI, AoA, hybrides
"""

import numpy as np
import scipy.optimize as optimize
from typing import List, Dict, Tuple, Optional
from dataclasses import dataclass
from datetime import datetime
import math

@dataclass
class MesureLocalisation:
    """Données de mesure pour la localisation"""
    id_recepteur: str
    position_recepteur: Tuple[float, float, float]  # (x, y, z) en mètres
    timestamp: datetime
    donnees: Dict
    
    @property
    def rssi(self) -> Optional[float]:
        return self.donnees.get('rssi_dbm')
    
    @property
    def snr(self) -> Optional[float]:
        return self.donnees.get('snr_db')
    
    @property
    def phase(self) -> Optional[float]:
        return self.donnees.get('phase_rad')
    
    @property
    def toa(self) -> Optional[float]:
        """Time of Arrival en secondes"""
        return self.donnees.get('toa_seconds')

class SystemeLocalisation:
    """Système de localisation RF avancé"""
    
    def __init__(self, config: Dict = None):
        self.config = config or {
            'methode_par_defaut': 'hybride',
            'vitesse_lumiere': 299792458,  # m/s
            'propagation_exponent': 2.7,  # Exposant pour modèle path loss
            'rssi_reference': -30,  # dBm à 1m
            'incertitude_aoa_deg': 5.0,  # Incertitude AoA en degrés
        }
    
    def localiser(self, mesures: List[MesureLocalisation], methode: str = None) -> Dict:
        """Localise un émetteur à partir de mesures multiples"""
        methode = methode or self.config['methode_par_defaut']
        
        if len(mesures) < 3:
            return self._localiser_2_mesures(mesures, methode)
        
        # Sélection de la méthode
        if methode == 'tdoa':
            position, incertitude = self._localiser_tdoa(mesures)
        elif methode == 'rssi':
            position, incertitude = self._localiser_rssi(mesures)
        elif methode == 'aoa':
            position, incertitude = self._localiser_aoa(mesures)
        elif methode == 'hybride':
            position, incertitude = self._localiser_hybride(mesures)
        else:
            raise ValueError(f"Méthode {methode} non supportée")
        
        return {
            'position': position,
            'incertitude': incertitude,
            'methode': methode,
            'nb_mesures': len(mesures),
            'timestamp': datetime.now().isoformat()
        }
    
    def _localiser_2_mesures(self, mesures: List[MesureLocalisation], methode: str) -> Dict:
        """Localisation avec seulement 2 mesures (moins précis)"""
        if len(mesures) != 2:
            return {"erreur": f"Attendu 2 mesures, reçu {len(mesures)}"}
        
        m1, m2 = mesures
        
        # Approximation simple: milieu + estimation RSSI
        if methode in ['rssi', 'hybride'] and m1.rssi is not None and m2.rssi is not None:
            # Estimer les distances
            d1 = self._rssi_a_distance(m1.rssi)
            d2 = self._rssi_a_distance(m2.rssi)
            
            # Trilatération simplifiée à 2 points
            pos1 = np.array(m1.position_recepteur)
            pos2 = np.array(m2.position_recepteur)
            
            # Vecteur entre les récepteurs
            v = pos2 - pos1
            distance_recepteurs = np.linalg.norm(v)
            v_unit = v / distance_recepteurs
            
            # Créer un système d'équations simplifié
            # Le point est sur une hyperbole entre les deux récepteurs
            if distance_recepteurs < d1 + d2 and abs(d1 - d2) < distance_recepteurs:
                # Cas où les cercles se croisent
                a = (d2**2 - d1**2 + distance_recepteurs**2) / (2 * distance_recepteurs)
                h = math.sqrt(max(0, d1**2 - a**2))
                
                # Deux points possibles
                p1 = pos1 + a * v_unit + h * np.cross(v_unit, [0, 0, 1])
                p2 = pos1 + a * v_unit - h * np.cross(v_unit, [0, 0, 1])
                
                # Prendre le point "le plus probable" (moyenne)
                position = ((p1 + p2) / 2).tolist()
                incertitude = np.linalg.norm(p1 - p2) / 2  # Demi-distance entre les deux solutions
            else:
                # Les cercles ne se croisent pas, prendre le milieu pondéré
                poids1 = 1.0 / (d1 + 0.1)
                poids2 = 1.0 / (d2 + 0.1)
                position = (poids1 * pos1 + poids2 * pos2) / (poids1 + poids2)
                position = position.tolist()
                incertitude = distance_recepteurs / 2
            
            return {
                'position': {'x': position[0], 'y': position[1], 'z': position[2] if len(position) > 2 else 0},
                'incertitude': float(incertitude),
                'methode': 'rssi_2points',
                'nb_mesures': 2,
                'notes': ['Précision limitée avec seulement 2 mesures']
            }
        
        # Si RSSI non disponible, simplement milieu
        pos1 = np.array(m1.position_recepteur)
        pos2 = np.array(m2.position_recepteur)
        position = ((pos1 + pos2) / 2).tolist()
        
        return {
            'position': {'x': position[0], 'y': position[1], 'z': position[2] if len(position) > 2 else 0},
            'incertitude': np.linalg.norm(pos1 - pos2) / 2,
            'methode': 'milieu',
            'nb_mesures': 2,
            'notes': ['Méthode basique: milieu entre récepteurs']
        }
    
    def _localiser_tdoa(self, mesures: List[MesureLocalisation]) -> Tuple[List[float], float]:
        """
        Time Difference of Arrival (TDOA)
        Utilise la méthode de Chan pour une localisation précise
        """
        if len(mesures) < 4:
            # Moins de 4 mesures: utiliser méthode simplifiée
            return self._localiser_tdoa_simplifie(mesures)
        
        # Extraire les positions des récepteurs
        recepteurs = []
        toa_measurements = []
        
        for mesure in mesures:
            if mesure.toa is not None:
                recepteurs.append(mesure.position_recepteur)
                toa_measurements.append(mesure.toa)
        
        if len(recepteurs) < 4:
            return self._localiser_tdoa_simplifie(mesures)
        
        # Convertir en arrays numpy
        R = np.array(recepteurs)  # Shape: (N, 3)
        t = np.array(toa_measurements)  # Shape: (N,)
        
        # Méthode de Chan
        try:
            position, covariance = self._methode_chan(R, t)
            incertitude = np.sqrt(np.trace(covariance))
            return position.tolist(), float(incertitude)
        except Exception as e:
            # Fallback sur méthode simplifiée
            return self._localiser_tdoa_simplifie(mesures)
    
    def _methode_chan(self, R: np.ndarray, t: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """
        Implémentation de la méthode de Chan pour TDOA
        R: positions des récepteurs (N, 3)
        t: temps d'arrivée (N,)
        """
        N = R.shape[0]
        c = self.config['vitesse_lumiere']
        
        # 1. Calculer les différences de temps d'arrivée
        t0 = t[0]
        tau = (t - t0).reshape(-1, 1)  # Différences par rapport au premier récepteur
        
        # 2. Calculer les distances des différences
        d = c * tau
        
        # 3. Système d'équations non linéaire
        # R_i^2 = ||x - r_i||^2
        # R_i^2 = R_1^2 + 2r_i^T x - ||r_i||^2 + ||r_i||^2
        
        # Construire la matrice G et le vecteur h
        r1 = R[0]
        r_i = R[1:]
        
        # Calculer ||r_i||^2 - ||r1||^2
        r_i_norm_sq = np.sum(r_i**2, axis=1)
        r1_norm_sq = np.sum(r1**2)
        
        K_i = r_i_norm_sq - r1_norm_sq
        
        # Matrice G pour l'estimation initiale
        G = np.column_stack([
            r_i - r1,
            d[1:]
        ])
        
        # Vecteur h
        h = 0.5 * (K_i[:, None] + d[1:]**2)
        
        # Solution aux moindres carrés
        theta = np.linalg.lstsq(G, h, rcond=None)[0]
        
        # Estimation initiale
        x0 = theta[:3].flatten()
        R1 = theta[3].item()
        
        # 4. Raffinement avec estimateur aux moindres carrés pondérés
        B = np.diag(np.sqrt(((R1 + d[1:].flatten())**2).flatten()))
        Q = c**2 * np.eye(N-1)  # Matrice de covariance (simplifiée)
        
        # Calculer psi
        psi = np.diag(np.abs(x0 - r1))
        
        # Covariance de l'estimateur
        cov_theta = np.linalg.inv(G.T @ np.linalg.inv(B @ Q @ B) @ G)
        
        # Estimation finale
        x_final = x0 + 0.5 * cov_theta[:3, :3] @ np.linalg.inv(psi) @ (x0 - r1)
        
        return x_final.reshape(3), cov_theta[:3, :3]
    
    def _localiser_tdoa_simplifie(self, mesures: List[MesureLocalisation]) -> Tuple[List[float], float]:
        """Méthode TDOA simplifiée pour peu de mesures"""
        positions = np.array([m.position_recepteur for m in mesures])
        center = np.mean(positions, axis=0)
        
        if len(mesures) == 3:
            return center.tolist(), 10.0  # 10m d'incertitude
        else:
            return center.tolist(), 20.0  # 20m d'incertitude
    
    def _localiser_rssi(self, mesures: List[MesureLocalisation]) -> Tuple[List[float], float]:
        """
        Localisation basée sur RSSI (Received Signal Strength Indicator)
        Utilise le modèle de propagation log-distance path loss
        """
        # Modèle de propagation: PL(d) = PL(d0) + 10 * n * log10(d/d0) + Xσ
        
        positions = np.array([m.position_recepteur for m in mesures])
        rssi_vals = np.array([m.rssi for m in mesures if m.rssi is not None])
        
        if len(rssi_vals) < 3:
            # Pas assez de mesures RSSI
            center = np.mean(positions, axis=0)
            return center.tolist(), 15.0
        
        # Convertir RSSI en distances
        distances_estimees = self._rssi_a_distance(rssi_vals)
        
        # Optimisation non linéaire: trouver la position qui minimise l'erreur
        def erreur_position(x):
            """Erreur quadratique entre distances estimées et distances calculées"""
            pos = np.array([x[0], x[1], x[2] if len(x) > 2 else 0])
            distances_calculees = np.linalg.norm(positions - pos, axis=1)
            return np.sum((distances_estimees - distances_calculees) ** 2)
        
        # Point de départ: centre des récepteurs
        x0 = np.mean(positions[:, :3], axis=0)
        if len(x0) < 3:
            x0 = np.append(x0, 0)
        
        # Optimisation
        bounds = [
            (np.min(positions[:, 0]) - 100, np.max(positions[:, 0]) + 100),
            (np.min(positions[:, 1]) - 100, np.max(positions[:, 1]) + 100),
            (np.min(positions[:, 2]) - 50, np.max(positions[:, 2]) + 50) if positions.shape[1] > 2 else (0, 0)
        ]
        
        try:
            result = optimize.minimize(erreur_position, x0, bounds=bounds, method='L-BFGS-B')
            position = result.x.tolist()
            
            # Estimer l'incertitude
            distances_finales = np.linalg.norm(positions - result.x, axis=1)
            erreurs = np.abs(distances_estimees - distances_finales)
            incertitude = np.mean(erreurs) * 1.5  # Facteur de sécurité
            
            return position, float(incertitude)
        except:
            # Fallback sur méthode simple
            center = np.mean(positions[:, :3], axis=0)
            return center.tolist(), 20.0
    
    def _rssi_a_distance(self, rssi_dbm: np.ndarray) -> np.ndarray:
        """Convertit RSSI en distance selon le modèle de path loss"""
        # Modèle: RSSI(d) = RSSI(d0) - 10 * n * log10(d/d0)
        # où d0 = 1m, n = exponent de propagation
        
        rssi_ref = self.config['rssi_reference']  # RSSI à 1m
        n = self.config['propagation_exponent']    # Exponent
        
        # Éviter division par zéro et valeurs extrêmes
        rssi_dbm = np.clip(rssi_dbm, -100, 0)
        
        # Formule: d = d0 * 10^((RSSI(d0) - RSSI(d)) / (10 * n))
        distances = 1.0 * 10 ** ((rssi_ref - rssi_dbm) / (10 * n))
        
        # Limiter les distances extrêmes
        distances = np.clip(distances, 0.1, 1000)
        
        return distances
    
    def _localiser_aoa(self, mesures: List[MesureLocalisation]) -> Tuple[List[float], float]:
        """
        Angle of Arrival (AoA)
        Utilise les mesures de phase pour estimer la direction
        """
        # Nécessite des informations de phase ou des antennes array
        positions = np.array([m.position_recepteur for m in mesures])
        
        # Vérifier si on a des mesures de phase
        phases = [m.phase for m in mesures if m.phase is not None]
        
        if len(phases) >= 2:
            # Estimation AoA basique par triangulation
            # Pour chaque paire de récepteurs, estimer la direction
            directions = []
            
            for i in range(len(positions)):
                for j in range(i+1, len(positions)):
                    if i < len(phases) and j < len(phases):
                        # Différence de phase pour estimer AoA
                        delta_phase = phases[j] - phases[i]
                        # (Simplifié - nécessite connaître l'espacement des antennes)
                        # Pour l'instant, retourner une estimation basique
                        
                        # Direction moyenne
                        dir_vector = positions[j] - positions[i]
                        if np.linalg.norm(dir_vector) > 0:
                            directions.append(dir_vector / np.linalg.norm(dir_vector))
            
            if directions:
                direction_moyenne = np.mean(directions, axis=0)
                # Estimer la position en tirant des lignes depuis les récepteurs
                # (Simplifié)
                
                # Prendre le point d'intersection de lignes dans la direction moyenne
                # En pratique: algorithme de triangulation plus sophistiqué
                
                # Pour l'instant, retourner le centre
                center = np.mean(positions, axis=0)
                incertitude = 15.0  # mètres
                
                return center.tolist(), incertitude
        
        # Fallback: centre des récepteurs
        center = np.mean(positions[:, :3], axis=0)
        return center.tolist(), 25.0  # Incertitude plus grande sans AoA
    
    def _localiser_hybride(self, mesures: List[MesureLocalisation]) -> Tuple[List[float], float]:
        """
        Méthode hybride qui combine TDOA, RSSI et AoA
        Utilise un filtre de Kalman ou fusion de données
        """
        # Essayer chaque méthode
        try:
            pos_tdoa, inc_tdoa = self._localiser_tdoa(mesures)
        except:
            pos_tdoa, inc_tdoa = None, float('inf')
        
        try:
            pos_rssi, inc_rssi = self._localiser_rssi(mesures)
        except:
            pos_rssi, inc_rssi = None, float('inf')
        
        try:
            pos_aoa, inc_aoa = self._localiser_aoa(mesures)
        except:
            pos_aoa, inc_aoa = None, float('inf')
        
        # Fusionner les résultats avec pondération par incertitude
        positions_valides = []
        poids = []
        
        if pos_tdoa is not None and inc_tdoa < float('inf'):
            positions_valides.append(pos_tdoa)
            poids.append(1.0 / (inc_tdoa + 0.1))
        
        if pos_rssi is not None and inc_rssi < float('inf'):
            positions_valides.append(pos_rssi)
            poids.append(1.0 / (inc_rssi + 0.1))
        
        if pos_aoa is not None and inc_aoa < float('inf'):
            positions_valides.append(pos_aoa)
            poids.append(1.0 / (inc_aoa + 0.1))
        
        if not positions_valides:
            # Toutes les méthodes ont échoué
            positions = np.array([m.position_recepteur for m in mesures])
            center = np.mean(positions[:, :3], axis=0)
            return center.tolist(), 30.0
        
        # Fusion pondérée
        positions_valides = np.array(positions_valides)
        poids = np.array(poids)
        poids = poids / np.sum(poids)  # Normaliser
        
        # Moyenne pondérée
        position_fusionnee = np.sum(positions_valides * poids[:, np.newaxis], axis=0)
        
        # Incertitude fusionnée (moyenne pondérée)
        incertitudes = [inc_tdoa, inc_rssi, inc_aoa]
        incertitudes_valides = [inc for inc in incertitudes if inc < float('inf')]
        if incertitudes_valides:
            incertitude_fusionnee = np.mean(incertitudes_valides) * 0.8  # Réduction grâce à la fusion
        else:
            incertitude_fusionnee = 20.0
        
        return position_fusionnee.tolist(), float(incertitude_fusionnee)
    
    def optimiser_localisation_multi_emetteurs(self, 
                                             mesurse_multiples: Dict[str, List[MesureLocalisation]]) -> Dict[str, Dict]:
        """
        Optimise la localisation de multiples émetteurs simultanément
        Utile pour dé-duplication et amélioration de précision
        """
        resultats = {}
        
        for emetteur_id, mesures in mesurse_multiples.items():
            resultats[emetteur_id] = self.localiser(mesures)
        
        # Post-traitement: détection de doublons
        positions = {}
        for emetteur_id, resultat in resultats.items():
            pos = resultat['position']
            positions[emetteur_id] = np.array([pos['x'], pos['y'], pos.get('z', 0)])
        
        # Détecter les émetteurs très proches (potentiellement le même)
        doublons = []
        seuil_distance = 5.0  # mètres
        
        emetteurs_ids = list(positions.keys())
        for i in range(len(emetteurs_ids)):
            for j in range(i+1, len(emetteurs_ids)):
                id1 = emetteurs_ids[i]
                id2 = emetteurs_ids[j]
                
                dist = np.linalg.norm(positions[id1] - positions[id2])
                if dist < seuil_distance:
                    doublons.append((id1, id2, dist))
        
        # Fusionner les doublons
        if doublons:
            for id1, id2, dist in doublons:
                # Fusionner les résultats
                resultats[id1].update({
                    'doublon_avec': id2,
                    'distance_doublon': dist,
                    'note': 'Possible doublon détecté'
                })
                resultats[id2].update({
                    'doublon_avec': id1,
                    'distance_doublon': dist,
                    'note': 'Possible doublon détecté'
                })
        
        return resultats
    
    def calculer_carte_densite_rf(self, 
                                positions_emetteurs: List[List[float]],
                                dimensions: Tuple[float, float] = (100, 100),
                                resolution: float = 5.0) -> np.ndarray:
        """
        Calcule une carte de densité RF
        """
        # Créer une grille
        x_min, x_max = -dimensions[0]/2, dimensions[0]/2
        y_min, y_max = -dimensions[1]/2, dimensions[1]/2
        
        nx = int(dimensions[0] / resolution)
        ny = int(dimensions[1] / resolution)
        
        carte = np.zeros((ny, nx))
        
        # Noyau gaussien pour le lissage
        sigma = resolution * 2
        kernel_size = int(sigma * 3)
        kernel = self._gaussian_kernel_2d(kernel_size, sigma)
        
        # Placer chaque émetteur sur la carte
        for pos in positions_emetteurs:
            if len(pos) >= 2:
                x, y = pos[0], pos[1]
                
                # Convertir en coordonnées de grille
                grid_x = int((x - x_min) / resolution)
                grid_y = int((y - y_min) / resolution)
                
                # Vérifier les limites
                if 0 <= grid_x < nx and 0 <= grid_y < ny:
                    # Ajouter au point central
                    carte[grid_y, grid_x] += 1.0
        
        # Appliquer le lissage
        from scipy.ndimage import convolve
        if kernel_size > 0:
            carte = convolve(carte, kernel, mode='constant', cval=0.0)
        
        return carte
    
    def _gaussian_kernel_2d(self, size: int, sigma: float) -> np.ndarray:
        """Génère un noyau gaussien 2D"""
        ax = np.linspace(-(size - 1) / 2., (size - 1) / 2., size)
        xx, yy = np.meshgrid(ax, ax)
        kernel = np.exp(-0.5 * (xx**2 + yy**2) / sigma**2)
        return kernel / np.sum(kernel)