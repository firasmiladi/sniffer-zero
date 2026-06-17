"""
Module d'analyse spectrale avancée pour la cartographie RF
"""

import numpy as np
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


class TypeModulation(str, Enum):
    OFDM = "OFDM"
    BPSK = "BPSK"
    QPSK = "QPSK"
    QAM16 = "16QAM"
    QAM64 = "64QAM"
    QAM256 = "256QAM"
    GFSK = "GFSK"
    MSK = "MSK"
    LORA_CSS = "LoRa_CSS"
    FM = "FM"
    AM = "AM"
    INCONNU = "INCONNU"


class BandeISM(str, Enum):
    ISM_433 = "ISM_433MHz"
    ISM_868 = "ISM_868MHz"
    ISM_915 = "ISM_915MHz"
    ISM_2400 = "ISM_2.4GHz"
    UNII_1 = "U-NII-1_5.2GHz"
    UNII_2 = "U-NII-2_5.3GHz"
    UNII_3 = "U-NII-3_5.5GHz"
    ISM_5800 = "ISM_5.8GHz"
    WIFI_6E = "WiFi6E_6GHz"
    AUTRE = "Autre"



@dataclass
class SignalDetecte:
    """Un signal RF détecté dans l'environnement"""
    id_signal: str
    timestamp: datetime
    frequence_centre_mhz: float
    bande_passante_khz: float
    puissance_dbm: float
    snr_db: float
    modulation: TypeModulation
    bande_ism: BandeISM
    duree_ms: Optional[float] = None
    periodicite_ms: Optional[float] = None
    protocole_estime: Optional[str] = None
    empreinte_spectrale: Optional[str] = None
    metadata: Dict = field(default_factory=dict)

    def identifier_bande(self) -> BandeISM:
        """Identifie la bande ISM du signal"""
        f = self.frequence_centre_mhz
        if 433 <= f <= 435:
            return BandeISM.ISM_433
        elif 863 <= f <= 870:
            return BandeISM.ISM_868
        elif 902 <= f <= 928:
            return BandeISM.ISM_915
        elif 2400 <= f <= 2483:
            return BandeISM.ISM_2400
        elif 5150 <= f <= 5350:
            return BandeISM.UNII_1
        elif 5250 <= f <= 5350:
            return BandeISM.UNII_2
        elif 5470 <= f <= 5725:
            return BandeISM.UNII_3
        elif 5725 <= f <= 5875:
            return BandeISM.ISM_5800
        elif 5925 <= f <= 7125:
            return BandeISM.WIFI_6E
        return BandeISM.AUTRE

    def to_dict(self) -> Dict:
        return {
            "id": self.id_signal,
            "timestamp": self.timestamp.isoformat(),
            "frequence_mhz": self.frequence_centre_mhz,
            "bande_passante_khz": self.bande_passante_khz,
            "puissance_dbm": self.puissance_dbm,
            "snr_db": self.snr_db,
            "modulation": self.modulation.value,
            "bande_ism": self.bande_ism.value,
            "protocole": self.protocole_estime,
            "duree_ms": self.duree_ms,
            "periodicite_ms": self.periodicite_ms,
            "empreinte": self.empreinte_spectrale
        }



class AnalyseurSpectral:
    """Analyseur spectral temps réel pour cartographie RF"""

    def __init__(self, sample_rate_hz: float = 20e6, fft_size: int = 4096):
        self.sample_rate = sample_rate_hz
        self.fft_size = fft_size
        self.signaux_detectes: List[SignalDetecte] = []
        self.historique_spectres: List[Dict] = []
        self.seuil_detection_db = -80  # dBm

    def analyser_iq(self, iq_data: np.ndarray, centre_freq_hz: float) -> List[SignalDetecte]:
        """Analyse les données IQ brutes du HackRF et détecte les signaux"""
        signaux = []

        # FFT avec fenêtrage
        window = np.blackman(len(iq_data))
        iq_windowed = iq_data * window

        # Calcul FFT
        spectre = np.fft.fftshift(np.fft.fft(iq_windowed, self.fft_size))
        magnitude_db = 20 * np.log10(np.abs(spectre) + 1e-12)

        # Axe fréquentiel
        freqs_hz = np.fft.fftshift(
            np.fft.fftfreq(self.fft_size, 1.0 / self.sample_rate)
        ) + centre_freq_hz

        # Détection de pics au-dessus du seuil
        signaux = self._detecter_signaux(magnitude_db, freqs_hz)

        self.signaux_detectes.extend(signaux)
        return signaux

    def _detecter_signaux(self, spectre_db: np.ndarray, freqs_hz: np.ndarray) -> List[SignalDetecte]:
        """Détecte et caractérise les signaux dans le spectre"""
        signaux = []

        # Seuil adaptatif (médiane + offset)
        noise_floor = np.median(spectre_db)
        seuil = noise_floor + 10  # 10 dB au-dessus du bruit

        # Trouver les régions au-dessus du seuil
        above_threshold = spectre_db > seuil
        regions = self._trouver_regions_connexes(above_threshold)

        for debut, fin in regions:
            # Caractériser chaque signal détecté
            freq_centre = np.mean(freqs_hz[debut:fin])
            bw = (freqs_hz[fin - 1] - freqs_hz[debut]) if fin > debut else 0
            puissance = np.max(spectre_db[debut:fin])
            snr = puissance - noise_floor

            # Identifier la modulation
            modulation = self._identifier_modulation(spectre_db[debut:fin], bw)

            # Identifier le protocole
            protocole = self._identifier_protocole(freq_centre / 1e6, bw / 1e3, modulation)

            signal_det = SignalDetecte(
                id_signal=f"sig_{int(freq_centre)}_{int(datetime.now().timestamp())}",
                timestamp=datetime.now(),
                frequence_centre_mhz=freq_centre / 1e6,
                bande_passante_khz=bw / 1e3,
                puissance_dbm=puissance,
                snr_db=snr,
                modulation=modulation,
                bande_ism=BandeISM.AUTRE,
                protocole_estime=protocole
            )
            signal_det.bande_ism = signal_det.identifier_bande()
            signaux.append(signal_det)

        return signaux

    def _trouver_regions_connexes(self, mask: np.ndarray) -> List[Tuple[int, int]]:
        """Trouve les régions connexes dans un masque booléen"""
        regions = []
        in_region = False
        start = 0

        for i, val in enumerate(mask):
            if val and not in_region:
                start = i
                in_region = True
            elif not val and in_region:
                regions.append((start, i))
                in_region = False

        if in_region:
            regions.append((start, len(mask)))

        return regions

    def _identifier_modulation(self, spectre_region: np.ndarray, bw_hz: float) -> TypeModulation:
        """Identifie le type de modulation basé sur les caractéristiques spectrales"""
        if bw_hz <= 0:
            return TypeModulation.INCONNU

        # Caractéristiques spectrales
        flatness = np.std(spectre_region) / (np.mean(spectre_region) + 1e-10)
        peak_to_avg = np.max(spectre_region) - np.mean(spectre_region)

        # Heuristiques de classification
        if bw_hz > 15e6:  # Large bande > 15 MHz
            return TypeModulation.OFDM
        elif bw_hz < 200e3 and flatness < 0.3:  # Bande étroite, plat
            return TypeModulation.GFSK
        elif 100e3 < bw_hz < 500e3:
            if peak_to_avg > 15:
                return TypeModulation.LORA_CSS
            return TypeModulation.GFSK
        elif flatness > 0.7:
            return TypeModulation.OFDM
        elif flatness < 0.2:
            return TypeModulation.BPSK

        return TypeModulation.INCONNU

    def _identifier_protocole(self, freq_mhz: float, bw_khz: float,
                             modulation: TypeModulation) -> Optional[str]:
        """Identifie le protocole basé sur fréquence, BW et modulation"""
        # WiFi
        if 2400 <= freq_mhz <= 2483 and bw_khz >= 15000:
            return "802.11n/ac/ax (WiFi)"
        elif 5150 <= freq_mhz <= 5850 and bw_khz >= 15000:
            return "802.11ac/ax (WiFi 5GHz)"
        elif 5925 <= freq_mhz <= 7125:
            return "802.11ax/be (WiFi 6E/7)"

        # BLE
        if 2400 <= freq_mhz <= 2483 and bw_khz <= 2000:
            if modulation == TypeModulation.GFSK:
                return "Bluetooth LE"

        # LoRa
        if (863 <= freq_mhz <= 870 or 433 <= freq_mhz <= 435):
            if modulation == TypeModulation.LORA_CSS or bw_khz in [125, 250, 500]:
                return "LoRaWAN"

        # Zigbee
        if 2400 <= freq_mhz <= 2483 and 1800 <= bw_khz <= 3000:
            return "Zigbee/802.15.4"

        # Cellulaire
        if 700 <= freq_mhz <= 900 and bw_khz > 5000:
            return "LTE (bande basse)"
        elif 1700 <= freq_mhz <= 2200 and bw_khz > 5000:
            return "LTE/5G (bande moyenne)"
        elif 3300 <= freq_mhz <= 3800:
            return "5G NR (bande C)"

        # Drone
        if 2400 <= freq_mhz <= 2483 and 8000 <= bw_khz <= 12000:
            return "Drone (WiFi/contrôle)"
        elif 5725 <= freq_mhz <= 5850 and bw_khz > 10000:
            return "Drone (vidéo 5.8GHz)"

        return None
