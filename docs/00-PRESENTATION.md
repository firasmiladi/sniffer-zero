# 00 — Présentation du projet SRT

## 1. En une phrase

**SRT (sniffer-rt)** est une plateforme modulaire qui **écoute, décode, cartographie
et évalue la sécurité** des communications radiofréquences (RF) sur les bandes ISM
(WiFi, Bluetooth Low Energy, LoRaWAN), pour réaliser des **évaluations de sécurité
autorisées en laboratoire blindé**.

## 2. À quoi sert le projet ?

L'objectif est de **comprendre et auditer l'environnement RF** d'un site : quels
émetteurs sont présents, sur quelles fréquences, avec quels protocoles, et quelles
faiblesses de configuration ou de protocole les exposent. SRT permet de :

- **Reconnaître** passivement les équipements RF environnants (points d'accès WiFi,
  périphériques BLE, capteurs/passerelles LoRa) sans rien émettre.
- **Analyser** la qualité et la sécurité des configurations observées (chiffrement
  WiFi, appairage BLE, anomalies de trafic LoRa…).
- **Cartographier** l'espace RF : associer les signaux à des émetteurs, estimer leur
  position, suivre leur activité dans le temps, repérer les bandes saturées.
- **Démontrer** (en laboratoire, sur des cibles consenties) des classes de
  vulnérabilités connues, à des fins d'évaluation et de sensibilisation.
- **Centraliser** le tout dans une base de données temporelle et une interface web,
  avec tableaux de bord Grafana.

## 3. Contexte d'emploi

SRT est conçu pour un usage **en environnement maîtrisé et isolé** — typiquement une
**cage de Faraday** — dans le cadre d'une **autorisation écrite**. Cette contrainte
n'est pas cosmétique :

- Émettre sur des bandes utilisées par autrui (même ISM) peut être illégal hors cadre
  autorisé et perturber des services réels.
- La cage de Faraday garantit que **aucune énergie RF ne fuit** vers l'extérieur et
  qu'aucun signal externe ne vient polluer les mesures.
- La couche de sécurité logicielle (autorisation + liste blanche + coupe-circuit)
  matérialise ce cadre dans le code (voir [02 — Architecture](02-ARCHITECTURE.md) et
  `docs/legal-scope.md`).

> **Cadre éthique et légal.** Tous les modules actifs lisent le statut d'autorisation
> et refusent de fonctionner sans jeton valide. Le projet ne doit jamais être employé
> sur des infrastructures de production ou des cibles non consenties. La liste blanche
> des cibles doit être traitée comme **fail-closed** (voir la FAQ et l'architecture).

## 4. Capacités de haut niveau

| Domaine | Capacité |
|---|---|
| Reconnaissance WiFi | Survey par saut de canaux, inventaire des AP et des clients, requêtes de sonde, OUI |
| Reconnaissance BLE | Scan des publicités (advertising), nom, UUID de services, RSSI, fabricant |
| Reconnaissance LoRa | Écoute EU868, décodage PHY → trames LoRaWAN, extraction d'en-têtes |
| Spectre | Balayage large bande `hackrf_sweep`, occupation des bandes, détection de signaux transitoires |
| Analyse | Évaluation de sécurité WiFi, analyse de protocole BLE, profilage et détection d'anomalies LoRa |
| Cartographie | Classification des émetteurs, localisation (TDOA/RSSI/AoA/hybride), suivi temporel, scoring de menace |
| Stockage | TimescaleDB (séries temporelles), MQTT (bus temps réel), index des captures |
| Visualisation | Interface web tactique (carte Leaflet, onglets protocoles, spectre, alertes, timeline) + tableaux Grafana |
| Orchestration | Scénarios YAML enchaînant des modules, rapports JSON/Markdown/PDF avec couverture MITRE ATT&CK |

## 5. Le matériel (et uniquement celui-là)

| Équipement | Usage dans SRT | Détail |
|---|---|---|
| **HackRF One** | SDR demi-duplex 1 MHz – 6 GHz | Balayage spectral (`hackrf_sweep`), réception LoRa via GNU Radio. Échantillonnage typique 20 Méch/s. |
| **ALFA 2,4 GHz** (RTL8812AU) | Carte WiFi mode moniteur / injection | Capture 802.11 et trames de gestion sur la **bande 2,4 GHz**. |
| **Dragino LG308N** | Passerelle LoRaWAN | Reçoit le trafic LoRa et le relaie (Semtech UDP → bridge MQTT → ChirpStack). |
| **Raspberry Pi** | Plateforme de calcul + BLE | Exécute SRT ; son **Bluetooth intégré (`hci0`)** sert à la reconnaissance BLE. |

> La reconnaissance **BLE** s'appuie sur le **Bluetooth intégré du Raspberry Pi
> (`hci0`)**. La chaîne **LoRa** repose sur la passerelle **Dragino LG308N → ChirpStack**.

## 6. Glossaire

| Terme | Définition |
|---|---|
| **RF** | Radiofréquence : ondes électromagnétiques utilisées pour communiquer sans fil. |
| **Bande ISM** | *Industrial, Scientific, Medical* : bandes (433/868/915 MHz, 2,4 GHz, 5 GHz…) ouvertes à des usages sans licence individuelle, sous conditions de puissance. |
| **SDR** | *Software-Defined Radio* : radio dont le traitement du signal est réalisé en logiciel (ici le HackRF One). |
| **Mode moniteur** | Mode d'une carte WiFi qui capture **toutes** les trames 802.11 de l'air, y compris les trames de gestion, sans être associée à un réseau. |
| **Injection** | Capacité d'une carte WiFi à **émettre** des trames arbitraires (nécessaire aux modules actifs WiFi). |
| **BLE** | *Bluetooth Low Energy* : variante basse consommation du Bluetooth ; les appareils diffusent des « publicités » (advertising) sur 3 canaux dédiés. |
| **GATT** | *Generic Attribute Profile* : structure de services/caractéristiques exposée par un périphérique BLE. |
| **LoRa** | Modulation radio à étalement de spectre par *chirp* (CSS), longue portée, faible débit. |
| **LoRaWAN** | Protocole réseau bâti sur LoRa (classes d'appareils, chiffrement, gestion des clés). |
| **OTAA / ABP** | Deux méthodes d'activation LoRaWAN : *Over-The-Air Activation* (jonction dynamique, clés dérivées) vs *Activation By Personalization* (clés pré-provisionnées). |
| **ChirpStack** | Serveur de réseau LoRaWAN open source ; sert ici de cible/lab et de point de centralisation. |
| **Passerelle (gateway)** | Équipement qui reçoit les trames LoRa de l'air et les transmet au serveur réseau (ici la Dragino LG308N). |
| **Semtech UDP** | Protocole historique de remontée des passerelles LoRa (paquets UDP, port 1700). |
| **MQTT** | Protocole de messagerie publish/subscribe léger ; SRT l'utilise comme **bus d'événements temps réel** (broker Mosquitto). |
| **TimescaleDB** | Extension PostgreSQL spécialisée dans les **séries temporelles** (hypertables) ; stocke les en-têtes, signaux, positions, alertes. |
| **Grafana** | Outil de tableaux de bord branché sur TimescaleDB. |
| **MITRE ATT&CK** | Base de connaissances publique des **techniques** d'attaquants, identifiées par des codes `Txxxx` ; sert ici à étiqueter chaque module. |
| **TDOA / RSSI / AoA** | Méthodes de localisation : différence de temps d'arrivée / puissance reçue / angle d'arrivée. |
| **Coupe-circuit (kill-switch)** | Mécanisme d'arrêt d'urgence ; la variable `SRT_KILLSWITCH=1` force l'état « non autorisé ». |
| **Liste blanche (whitelist)** | Liste des identifiants de cibles autorisés ; doit être **fail-closed** (toute cible absente est refusée). |

## 7. Ce que SRT n'est pas

- Ce n'est **pas** un outil à employer hors du laboratoire autorisé.
- Ce n'est **pas** un système d'armes ni un outil de **brouillage** opérationnel : les
  modules de brouillage éventuels sont classés `destructive-lab` et **hors périmètre**
  de cette documentation (listés au seul niveau catalogue).
- Le **scoring de menace** de la cartographie est une **heuristique d'aide à la
  priorisation**, pas un verdict : il nécessite une validation humaine (voir
  [04 — Cartographie](04-CARTOGRAPHIE.md)).
