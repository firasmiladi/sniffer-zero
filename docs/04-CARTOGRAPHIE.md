# 04 — Moteur de cartographie RF

Le moteur de cartographie (`src/srt/cartographie/`) transforme une suite de **signaux
détectés** en une **carte d'émetteurs** caractérisés, localisés, suivis dans le temps et
priorisés. Il est conçu pour fonctionner aussi bien avec de vraies captures HackRF
qu'en mode **simulation** (pour démonstration sans matériel).

> **Avertissement central.** Le **scoring de menace** et la **classification
> d'affiliation** sont des **heuristiques d'aide à la priorisation**, pas des verdicts.
> Ils comportent des limites importantes (voir §6) et requièrent une **validation
> humaine** avant toute conclusion.

## 1. Composants

| Fichier | Rôle |
|---|---|
| `core.py` | Modèles de données : `EmetteurRF`, `CaracterisationSignal`, `Position3D`, énumérations (types, priorités, affiliations) et le **scoring de menace**. |
| `analyse_spectrale.py` | `AnalyseurSpectral` : FFT, détection de signaux, classification modulation/protocole/bande. |
| `localisation.py` | `SystemeLocalisation` : TDOA, RSSI, AoA, fusion hybride. |
| `moteur_cartographie.py` | `MoteurCartographie` : orchestration balayage → détection → association → menaces → export. |

## 2. Chaîne de traitement

```
IQ (HackRF ou simulation)
   ▼  AnalyseurSpectral.analyser_iq()
SignalDetecte (fréquence, BW, puissance, SNR, modulation, bande, protocole)
   ▼  MoteurCartographie._traiter_signal()
association à un émetteur existant  ──ou──>  création d'un nouvel EmetteurRF
   ▼
EmetteurRF.evaluer_menace_emetteur()  →  niveau_menace (0–100)
   ▼
export JSON / Grafana / WebSocket (emitter_new, emitter_update, band_update, scan_progress)
```

## 3. Détection des signaux (`AnalyseurSpectral`)

À partir d'un bloc IQ et d'une fréquence centrale :

1. **Fenêtrage** (Blackman) puis **FFT** (`fft_size` = 4096 par défaut), passage en
   magnitude dB.
2. **Plancher de bruit** estimé par la **médiane** du spectre ; seuil = médiane + 10 dB.
3. **Régions connexes** au-dessus du seuil = signaux candidats ; pour chacun : fréquence
   centrale, bande passante, puissance crête, **SNR** (crête − bruit).
4. **Classification de modulation** par heuristiques spectrales :
   - BW > 15 MHz → OFDM ; bande étroite et spectre « plat » → GFSK ; 100–500 kHz avec
     fort *peak-to-average* → **LoRa CSS** ; *flatness* élevé → OFDM ; très faible → BPSK.
5. **Identification de protocole** par (fréquence, BW, modulation) : WiFi (2,4/5/6 GHz,
   BW ≥ 15 MHz), **Bluetooth LE** (2,4 GHz, BW ≤ 2 MHz, GFSK), **LoRaWAN** (433/868 MHz,
   CSS ou BW 125/250/500 kHz), Zigbee, cellulaire, etc.
6. **Bande ISM** déduite de la fréquence (`identifier_bande`).

> Les seuils sont volontairement simples et **explicables** : ils privilégient la
> lisibilité pédagogique à la sophistication. Ils peuvent produire des faux positifs/
> négatifs (cf. §6).

## 4. Émetteurs : modèle, association et suivi

### 4.1 `EmetteurRF`
Chaque émetteur agrège : identification (id, MAC, SSID, nom), **classification**
(`TypeEmetteur`, `PrioriteSignal`, `Affiliations`), un historique de **positions** et de
**caractérisations de signal**, des métadonnées temporelles (première/dernière
détection, durée d'activité), des analyses comportementales (patterns horaires, zones
d'opération, statistiques de mouvement) et un **niveau de menace**.

### 4.2 Association signal → émetteur
`MoteurCartographie._associer_signal_emetteur` calcule une **similarité** entre un
nouveau signal et les émetteurs connus, à partir de :
- proximité **fréquentielle** (poids 0,5, tolérance `seuil_nouveau_emetteur_mhz`),
- proximité de **bande passante** (poids 0,3),
- proximité de **puissance** (poids 0,2, tolérance 10 dB).

Score > 0,7 → mise à jour de l'émetteur existant ; sinon → **nouvel émetteur** (UUID,
type classifié, couleur/icône, priorité).

### 4.3 Suivi temporel et mouvement
`calculer_statistiques_mouvement` calcule vitesses/accélérations/directions à partir des
positions horodatées et classe le mouvement (statique/lent/modéré/rapide).
`identifier_pattern_horaire` agrège l'activité par jour/heure ;
`calculer_zones_operation` détecte des zones de forte densité par grille.

## 5. Localisation (`SystemeLocalisation`)

Le système estime une **position** à partir de mesures provenant de plusieurs récepteurs
(`MesureLocalisation` : position du récepteur, RSSI, SNR, phase, ToA). Quatre méthodes,
plus une fusion.

### 5.1 RSSI (puissance reçue)
Modèle de **perte en log-distance** : `RSSI(d) = RSSI(d0) − 10·n·log10(d/d0)`, inversé en
`d = d0·10^((RSSI_ref − RSSI)/(10·n))` (avec `RSSI_ref ≈ −30 dBm` à 1 m, `n ≈ 2,7`).
Connaissant la **distance estimée** à chaque récepteur, on cherche par **optimisation**
(`scipy.optimize`, L-BFGS-B) la position minimisant l'écart quadratique entre distances
estimées et calculées. **Avantage** : matériel simple. **Limite** : très sensible aux
multitrajets et à l'environnement → incertitude souvent grande.

### 5.2 TDOA (différence de temps d'arrivée)
Principe : un signal émis arrive à des **instants** légèrement différents selon les
récepteurs ; chaque **différence de temps** définit une **hyperbole** des positions
possibles, et l'intersection de plusieurs hyperboles donne la position. Le code
implémente la **méthode de Chan** (≥ 4 récepteurs) : à partir des positions et des ToA,
on construit un système linéarisé (`R_i² = ||x − r_i||²`) résolu aux **moindres carrés**,
puis raffiné avec une pondération par covariance. Avec < 4 mesures, une approximation
simplifiée (centroïde + incertitude forfaitaire) est utilisée. **Avantage** : précis si
la **synchronisation temporelle** des récepteurs est bonne. **Limite** : exige une
synchro fine et plusieurs récepteurs.

### 5.3 AoA (angle d'arrivée)
Principe : en mesurant la **différence de phase** entre éléments d'antenne, on estime la
**direction** d'arrivée ; le croisement de plusieurs directions (triangulation) localise
la source. L'implémentation est **simplifiée** (nécessiterait des antennes en réseau
pour être exploitée pleinement) et retourne une estimation directionnelle avec une
incertitude plus grande à défaut de matériel dédié.

### 5.4 Méthode hybride (fusion)
`_localiser_hybride` exécute les trois méthodes disponibles et **fusionne** leurs
positions par **moyenne pondérée par l'inverse de l'incertitude** (1/(incertitude+ε)),
puis réduit légèrement l'incertitude résultante grâce à la combinaison. C'est la méthode
par défaut (`methode_localisation = "hybride"`). Le système gère aussi la
**dé-duplication** multi-émetteurs (positions très proches < 5 m signalées comme
doublons possibles) et le calcul d'une **carte de densité RF** (noyau gaussien).

> **Réalité matérielle.** Avec un **seul HackRF**, une localisation multi-récepteurs
> précise (TDOA/AoA) n'est pas réalisable telle quelle : ces méthodes supposent
> plusieurs récepteurs synchronisés. En pratique, l'estimation repose surtout sur le
> **RSSI** et reste **indicative**. La cartographie est donc avant tout un outil
> d'**inventaire et de priorisation**, pas un système de géolocalisation métrique.

## 6. Scoring de menace : fonctionnement et **limites**

`EmetteurRF.evaluer_menace_emetteur()` produit un score 0–100 en additionnant des
contributions heuristiques :

- **Type d'émetteur** (table de scores) ;
- **Affiliation** estimée (bonus négatif pour « allié », positif pour « inconnu »…) ;
- **Comportement** : mouvement rapide inattendu, activité nocturne, émetteur « furtif »
  (peu de caractéristiques), **puissance** élevée (> 20 dBm).

Le moteur génère une **alerte** lorsque le score dépasse `seuil_alerte_menace` (60 par
défaut), et range les émetteurs en `critique / haute / moyenne / basse`.

### Limites à connaître (et à présenter en soutenance)
1. **Heuristique, non probabiliste** : les pondérations sont arbitraires, non calibrées
   sur des données réelles. Le score n'est pas une probabilité.
2. **Classification d'affiliation non fiable** : déduire « allié/adverse » d'un signal
   RF seul n'a **pas** de fondement robuste. À considérer comme un **champ de travail**,
   pas une vérité.
3. **Faux positifs/négatifs** : la classification de protocole/type repose sur des seuils
   spectraux simples ; un signal mal classé entraîne un score erroné.
4. **Dépendance à la localisation** : les facteurs « mouvement/zone » dépendent de
   positions souvent imprécises (cf. §5).
5. **Nécessité d'une validation humaine** : le score **priorise** l'attention de
   l'analyste, il ne **décide** pas. Toute alerte doit être vérifiée.

> En clair : le scoring est utile pour **trier** « regardez d'abord ceci », mais aucune
> action ne doit en découler automatiquement.

## 7. Diffusion temps réel (WebSocket)

Lors d'un scan déclenché via l'API (`POST /api/cartography/scan`), le moteur émet, au fil
de l'eau, des messages WebSocket vers les navigateurs :
- `scan_progress` (avancement par pas de fréquence : `started`/`scanning`/`completed`),
- `emitter_new` (nouvel émetteur), `emitter_update` (mise à jour),
- `band_update` (occupation des bandes recalculée).

Le frontend (carte Leaflet + panneaux) se met à jour en direct (voir
[07 — Plateforme web](07-WEB-PLATFORM.md)).

## 8. Analyse d'occupation des bandes

`_analyser_occupation_bandes` répartit les émetteurs détectés dans des bandes définies
(ISM 433/868/915, WiFi 2,4 GHz, U-NII 5 GHz, ISM 5,8 GHz, WiFi 6E) et calcule par bande :
nombre d'émetteurs, types présents, puissance max, pourcentage d'occupation. C'est la
source du panneau **BAND OCCUPATION** de l'interface et de la vue d'ensemble du
spectre. Pour le détail bin-par-bin issu du HackRF, voir
[05 — Spectre HackRF](05-SPECTRE-HACKRF.md).

## 9. Export et rapport

- `exporter_json()` : rapport complet (métadonnées, résumé exécutif, inventaire, analyse
  de bandes, carte des menaces, alertes, recommandations).
- `exporter_grafana()` : format adapté aux panneaux Grafana (Geomap/Table).
- Les schémas `cartographie.*` (TimescaleDB) persistent émetteurs, signaux, positions,
  alertes et balayages (voir [02 — Architecture](02-ARCHITECTURE.md) §7.2).
