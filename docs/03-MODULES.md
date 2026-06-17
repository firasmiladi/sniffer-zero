# 03 — Référence des modules

Cette référence couvre **tous les modules enregistrés** dans le registre SRT
(`@register`), regroupés par protocole. Pour chaque module : nom canonique, protocole,
**classe de risque**, technique(s) **MITRE ATT&CK**, prérequis, et explication de
**ce qu'il fait** et **pourquoi**.

- Les modules **passifs** (recon, analyse, cartographie, spectre) sont décrits avec
  leur **mécanisme technique en profondeur** (comment la capture/le décodage/l'analyse
  fonctionne).
- Les modules **actifs / d'exploitation** sont traités à un niveau **descriptif,
  pédagogique et défensif** : objectif, classe de vulnérabilité, technique MITRE,
  prérequis, classification de risque, et surtout **comment détecter et corriger**. Ils
  ne contiennent volontairement **aucun mode opératoire offensif**.
- Les modules de **brouillage** (`destructive-lab`) sont listés **au seul niveau
  catalogue** : nom, classe, MITRE, et mention « hors périmètre / autorisation
  spéciale ». Aucun détail opérationnel n'est fourni.

> **Rappel sécurité.** Tout module non passif passe par `precheck`, qui **refuse**
> l'exécution sans autorisation valide (et tout `FORBIDDEN` est refusé d'office). La
> plateforme web force par ailleurs le `dry_run` et exige une autorisation valide
> (HTTP 403 sinon) pour exécuter réellement un module non passif.

## Légende des classes de risque

| Classe | Signification |
|---|---|
| `passive` | Réception/analyse uniquement, aucune émission. |
| `active-lab` | Émission/interaction en laboratoire autorisé. |
| `destructive-lab` | Peut dégrader/interrompre une cible ; double confirmation. |

---

# 1. Modules WiFi

## 1.1 WiFi — modules PASSIFS (mécanisme détaillé)

### `wifi.recon` — survey par saut de canaux
- **Protocole** : wifi · **Risque** : `passive` · **MITRE** : T1040, T1592 · **Prérequis** : `monitor-mode-nic`
- **Quoi/pourquoi** : dresse l'inventaire de l'environnement WiFi — points d'accès (AP),
  clients, requêtes de sonde — base de toute évaluation.
- **Mécanisme** : un **thread de saut de canaux** règle l'interface (ALFA en mode
  moniteur) successivement sur chaque canal (`iw dev <iface> set channel`), avec un
  temps de séjour `dwell_ms`. En parallèle, **scapy** (`sniff`, `monitor=True`) capture
  les trames 802.11. Le gestionnaire de paquets distingue :
  - **Beacons** → extraction du SSID (IE 0), du canal (IE 3 « DS Parameter Set ») et du
    **chiffrement** (heuristique : présence du bit *privacy*, IE 48 = WPA2, IE 221 avec
    OUI `00:50:f2:01` = WPA, sinon WEP).
  - **Probe requests** → MAC client + SSID recherché.
  - **Trames de données** (type 2) → MAC source/destination.
  - Le **RSSI** est lu dans l'en-tête RadioTap (`dBm_AntSignal`).
- **Sorties** : insertion dans `headers` (sans payload), publication MQTT
  `srt/headers/wifi`, artefact « liste d'AP », métriques (nb d'AP/clients/trames).

### `wifi.frame_dissector` — dissection 802.11 approfondie
- **Risque** : `passive` · **MITRE** : T1040, T1592.002 · **Prérequis** : `monitor-mode-nic`
- **Quoi/pourquoi** : décortique finement chaque trame pour exposer les capacités et la
  configuration de sécurité réelles des AP (au-delà du simple « WPA2 »).
- **Mécanisme** : capture live (scapy) **ou** relecture d'un pcap (`rdpcap`). Décode
  tous les **types/sous-types** (gestion/contrôle/données) et extrait les **Information
  Elements** des beacons/probe responses :
  - **RSN IE (48)** : version, *group cipher*, *pairwise ciphers*, **AKM suites**
    (PSK, SAE, 802.1X…), et **capacités RSN** dont `pmf_capable` / `pmf_required`
    (bits 0x80 / 0x40).
  - **WPA IE (221, OUI 00:50:f2:01)**, **HT (45)** / **VHT (191)** / **HE (255 ext.)**,
    débits supportés (IE 1/50), pays (IE 7), détection **WPS** (OUI 00:50:f2:04).
- **Sorties** : statistiques par type/sous-type, résumé des IE par BSSID.

### `wifi.security_assessor` — notation A→F des AP
- **Risque** : `passive` · **MITRE** : T1592.002, T1590 · **Prérequis** : aucun (lit la base)
- **Quoi/pourquoi** : attribue une **note de A à F** à chaque AP et liste les problèmes,
  pour prioriser les correctifs.
- **Mécanisme** : requête sur `headers` (beacons de la session) ; pour chaque AP, la
  fonction de notation combine chiffrement, présence/obligation de **PMF**
  (*Protected Management Frames*), **WPS**, et type de *cipher* :
  - A = WPA3/SAE + PMF requis ; B = WPA2-CCMP + PMF capable ; C = WPA2-CCMP sans PMF ;
    D = WPA2-TKIP ; E = WPA/WEP ; F = ouvert.
  - **Déclassements** : WPS activé (note plafonnée à C), repli TKIP, absence de PMF.
- **Sorties** : « bulletins » par AP, distribution des notes, total des problèmes.

### `wifi.signal_analyzer` — estimation de distance et congestion
- **Risque** : `passive` · **MITRE** : T1592 · **Prérequis** : aucun (lit la base)
- **Quoi/pourquoi** : estime la **distance** des émetteurs et la **congestion** par canal.
- **Mécanisme** : sur les trames en base, calcule par canal le nombre de trames (carte
  de congestion en %), et par source la moyenne/min/max du RSSI. La **distance** est
  estimée par un **modèle de perte en log-distance** :
  `d = 10^((P_tx − RSSI − perte_réf) / (10·n))`, avec `perte_réf ≈ 40 dB` à 1 m (2,4 GHz)
  et exposant `n ≈ 2,7` (intérieur). C'est une **estimation indicative** (multitrajets,
  obstacles).

### `wifi.timing_analyzer` — gigue de beacons et détection de flood
- **Risque** : `passive` · **MITRE** : T1557.004, T1498 · **Prérequis** : aucun (lit la base)
- **Quoi/pourquoi** : repère les **AP malveillants** (jumeaux maléfiques) par anomalie
  de cadence des beacons, et les **floods de deauth** (déni de service).
- **Mécanisme** : regroupe les beacons par BSSID, calcule les intervalles (référence
  802.11 ≈ 102,4 ms = 100 TU) ; un **ratio de gigue** au-dessus de 5 % lève l'alerte
  « possible rogue AP ». Pour les deauth, **fenêtre glissante** (5 s) via `bisect` :
  au-delà de 10 deauth/fenêtre/BSSID → alerte flood. Profilage des intervalles de probe
  par client.

### `wifi.probe_fingerprinter` — empreinte d'appareils et MAC aléatoires
- **Risque** : `passive` · **MITRE** : T1592.002, T1018 · **Prérequis** : aucun (lit la base)
- **Quoi/pourquoi** : identifie le **type d'appareil** et **regroupe les MAC
  randomisées** appartenant au même appareil physique ; reconstitue la **PNL** (liste
  des réseaux préférés) à partir des probes dirigées.
- **Mécanisme** : calcule une **empreinte SHA-256 tronquée** à partir des IE présents,
  des débits, et des capacités HT/VHT/HE. Détecte les MAC **localement administrées**
  (bit 0x02 du premier octet = aléatoire). Le **clustering par empreinte** rapproche
  plusieurs MAC d'un même appareil. Heuristiques de type (Apple/Android/Windows/IoT)
  selon les IE.

### `wifi.psk_crack` — cassage hors-ligne (offline)
- **Risque** : `passive` (hors-ligne, **aucune RF**) · **MITRE** : T1110.002 · **Prérequis** : `hashcat`
- **Quoi/pourquoi** : tente de retrouver une passphrase WPA2 à partir d'un *handshake*
  ou d'un PMKID **déjà capturé**, pour démontrer la faiblesse d'une PSK.
- **Note** : classé `passive` car purement hors-ligne (pas d'émission). Le cassage repose
  sur `hashcat` (mode 22000) et un dictionnaire ; il **n'accélère aucune attaque réelle**
  — il quantifie la robustesse d'un mot de passe.
- **Détection/remédiation** : passphrases longues et aléatoires, WPA3-SAE (résistant au
  dictionnaire hors-ligne), rotation des clés.

## 1.2 WiFi — modules de DÉFENSE (passifs)

### `defense.rogue_ap_detector`
- **Risque** : `passive` · **MITRE** : T1557 · **Prérequis** : `monitor-mode-nic`
- Détecte les **points d'accès malveillants** (jumeaux maléfiques, AP non autorisés) :
  utile côté **bleu** pour repérer une usurpation de SSID/BSSID.

### `defense.alerting`
- **Risque** : `passive` · **MITRE** : — · **Prérequis** : `monitor-mode-nic`
- Génère des **alertes** défensives sur événements observés (corrélation simple,
  remontée vers le bus/UI).

## 1.3 WiFi — renseignement (intel, passifs)

| Module | Risque | MITRE | Prérequis | Rôle |
|---|---|---|---|---|
| `intel.kismet_sigint` | passive | T1040, T1592 | monitor-mode-nic | Capture/inventaire SIGINT via Kismet. |
| `intel.mac_dehide` | passive | T1592.002 | monitor-mode-nic | Tente de dé-anonymiser des MAC randomisées (corrélation). |
| `intel.wigle_geoloc` | passive | T1592 | — | Géolocalise un AP par BSSID via la base Wigle.net (enrichissement, pas de RF). |

## 1.4 WiFi — modules ACTIFS / d'exploitation (niveau descriptif & défensif)

> Présentés pour **comprendre la classe de vulnérabilité, la technique MITRE et la
> remédiation**. Aucun paramétrage offensif n'est documenté.

| Module | Risque | MITRE | CVE | Classe de vulnérabilité | Détection / Remédiation |
|---|---|---|---|---|---|
| `wifi.deauth` | active-lab | T1499.004 | — | Trames de gestion 802.11 non protégées → déconnexion forcée | Activer **PMF (802.11w)** ; surveiller les floods de deauth (`wifi.timing_analyzer`). |
| `wifi.handshake_capture` | active-lab | T1040 | — | Capture du *4-way handshake* WPA2 après réassociation | PSK forte, WPA3-SAE ; PMF limite la provocation de réassociation. |
| `wifi.pmkid` | active-lab | T1110.002 | — | PMKID exposé par certains AP (sans client) | Désactiver l'envoi de PMKID/roaming non nécessaire, PSK robuste. |
| `wifi.wps_pixie` | active-lab | T1110.001 | CVE-2014-4624 | WPS « Pixie Dust » (nonces faibles) | **Désactiver le WPS** ; firmware à jour. |
| `wifi.evil_twin` | active-lab | T1557 | — | AP pirate + portail captif (vol d'identifiants en lab) | Vérification serveur (802.1X/EAP-TLS), méfiance portails, WPA3 ; `defense.rogue_ap_detector`. |
| `wifi.karma` | active-lab | T1557.002, T1583.001 | — | Réponse aux probes pour piéger des clients ayant des réseaux mémorisés | Purger la **PNL**, désactiver l'auto-join réseaux ouverts. |
| `wifi.phishing_portal` | active-lab | T1557, T1598.003 | — | Portail de *phishing* (collecte d'identifiants en lab) | Sensibilisation, MFA, HSTS/validation de certificat. |
| `wifi.eap_relay` / `wifi.eap_capture` | active-lab | T1557, T1556.005 | CVE-2023-52160 | Mauvaise validation serveur en WPA2/3-Enterprise (PEAP) | **Valider le certificat serveur** côté client, EAP-TLS. |
| `wifi.krack` | active-lab | T1557 | famille KRACK | Réinstallation de clé (nonce reuse) sur client non corrigé | **Mettre à jour** les clients/AP (correctifs 2017+). |
| `wifi.fragattack` | active-lab | T1557 | CVE-2020-24586/87/88 | Bugs d'agrégation/fragmentation de trames | Mises à jour de pile WiFi ; PMF. |
| `wifi.macstealer` | active-lab | T1557.002 | CVE-2022-47522 | Détournement de trafic client (SSID/MAC) | Isolation client, PMF, correctifs. |
| `wifi.ssid_confusion` | active-lab | T1557.002 | CVE-2023-52424 | Confusion de SSID (802.11 design) | Authentification mutuelle, profils réseau vérifiés. |
| `wifi.dragonblood` | active-lab | T1557, T1110 | CVE-2019-9494/95/96 | Faiblesses du *handshake* SAE (WPA3) | Firmware corrigé, courbes/timing constants. |
| `wifi.wifite_auto` | active-lab | T1110.002, T1040 | — | Orchestrateur d'audit WiFi automatisé (outillage externe) | Durcissement global (PSK forte, WPS off, PMF). |
| `wifi.beacon_flood` | **destructive-lab** | T1499.002 | — | Inondation de faux SSID (DoS de découverte) | Détection d'anomalies de beacons ; filtrage côté client. |
| `wifi.mdk4_dos` | **destructive-lab** | T1499.002, T1499.004 | — | DoS 802.11 (auth/assoc/deauth) via mdk4 | PMF, détection de floods, surveillance. |

### Modules WiFi « zero-day »
| Module | Risque | MITRE | CVE | Rôle (descriptif) |
|---|---|---|---|---|
| `zero_day.airsnitch` | active-lab | T1557 | — | Démonstration de capture/MITM WiFi à visée recherche (lab). |
| `zero_day.cve_2024_30078` | **destructive-lab** | T1190 | CVE-2024-30078 | Démonstration d'une vulnérabilité d'exécution liée au WiFi Windows ; **remédiation : appliquer le correctif Microsoft**. |

### Modules de post-exploitation (réseau filaire, après accès)
> Ces modules ne sont **pas** des attaques RF : ils relèvent du mouvement latéral réseau
> classique, étiquetés `protocol = "wifi"` car ils prolongent un accès obtenu via WiFi
> en laboratoire. Présentés au niveau descriptif/défensif.

| Module | Risque | MITRE | Rôle (descriptif) | Remédiation |
|---|---|---|---|---|
| `post.responder` | active-lab | T1557.001, T1040 | Empoisonnement LLMNR/NBT-NS (outillage Responder) | Désactiver LLMNR/NBT-NS, SMB signing. |
| `post.ntlm_relay` | active-lab | T1557.001, T1550.002 | Relais NTLM | Signature SMB/LDAP, EPA, Kerberos. |
| `post.bettercap_mitm` | active-lab | T1557.002, T1040 | MITM réseau (bettercap) | Inspection ARP, 802.1X, segmentation. |
| `post.crackmapexec_lateral` | active-lab | T1021.002, T1570 | Mouvement latéral SMB | Comptes à moindre privilège, EDR. |
| `post.bloodhound_recon` | active-lab | T1087.002, T1069.002 | Cartographie AD (BloodHound) | Durcissement AD, surveillance LDAP. |

---

# 2. Modules BLE

> **Matériel** : la reconnaissance BLE de l'équipe utilise le **Bluetooth intégré du
> Raspberry Pi (`hci0`)**. Certains modules actifs déclarent des prérequis matériels
> (`btlejack`, `ubertooth`) qui **ne font pas partie du parc de l'équipe** : ils restent
> alors au **niveau catalogue** (non exécutables avec le matériel disponible).

## 2.1 BLE — modules PASSIFS (mécanisme détaillé)

### `ble.recon` — scan des publicités
- **Risque** : `passive` · **MITRE** : T1592 · **Prérequis** : `ble-adapter` (`hci0`)
- **Quoi/pourquoi** : inventorie les périphériques BLE alentour.
- **Mécanisme** : utilise **bleak** (`BleakScanner` avec *detection callback*). Pour
  chaque publicité reçue : MAC, nom local, **RSSI**, **UUID de services**,
  *manufacturer data* (par *company ID*), **TX power**. Insertion dans `headers`
  (protocole `ble`) et publication MQTT `srt/headers/ble`.

### `ble.pairing_analyzer` — analyse des méthodes d'appairage
- **Risque** : `passive` · **MITRE** : T1557, T1040 · **Prérequis** : aucun (lit la base)
- **Quoi/pourquoi** : évalue la robustesse de l'**appairage** (SMP) et la version BLE.
- **Mécanisme** : à partir des **IO capabilities** observées, déduit la méthode probable
  (*Just Works* / *Passkey Entry* / *Numeric Comparison* / *OOB*) et ses propriétés
  (protection MITM, entropie). Croise avec la **version BLE** (4.0/4.1 = vulnérables à
  l'outil `crackle` en *legacy pairing*). Produit un niveau de risque (Just Works =
  critique) et des **recommandations**. C'est une analyse **défensive**.

### `ble.mac_randomization_tracker` — suivi malgré la randomisation MAC
- **Risque** : `passive` · **MITRE** : T1592.002, T1018 · **Prérequis** : aucun (lit la base)
- **Quoi/pourquoi** : regroupe plusieurs MAC aléatoires d'un même appareil et identifie
  des protocoles de proximité (Apple Continuity, Google Nearby, Microsoft Swift Pair,
  AirTag/FindMy).
- **Mécanisme** : empreinte SHA-256 sur les *manufacturer data* stables, le TX power et
  les UUID de services ; détection du bit « localement administré » ; décodage des
  *company IDs* connus (0x004C Apple, 0x00E0 Google, 0x0006 Microsoft) et des types de
  message Apple Continuity (dont 0x12 = AirTag). Met en évidence des problèmes de **vie
  privée** liés au pistage.

### `ble.protocol_analyzer`
- **Risque** : `passive` · **MITRE** : T1040, T1592.002 · **Prérequis** : aucun
- Analyse de protocole BLE (structure des publicités, services, cohérence).

### `ble.gatt_security_assessor`
- **Risque** : `passive` · **MITRE** : T1592.002, T1602 · **Prérequis** : aucun
- Évalue la **sécurité des caractéristiques GATT** (permissions de lecture/écriture,
  exigence de chiffrement/authentification) à partir des données collectées.

## 2.2 BLE — modules ACTIFS (niveau descriptif & défensif)

| Module | Risque | MITRE | Prérequis | Classe de vulnérabilité | Détection / Remédiation |
|---|---|---|---|---|---|
| `ble.gatt_enum` | active-lab | T1592 | ble-adapter (`hci0`) | Énumération active des services/caractéristiques GATT | Exiger appairage chiffré + authentification sur les caractéristiques sensibles. |
| `ble.unauth_write` | active-lab | T1565 | ble-adapter | Écriture sur caractéristique **sans authentification** | Permissions GATT strictes (write avec authentification/chiffrement). |
| `ble.gattacker_mitm` | active-lab | T1557 | ble-adapter | MITM par relais GATT (clonage de périphérique) | *Secure Connections* (BLE 4.2+), *Numeric Comparison*, OOB. |
| `ble.pair_capture` | active-lab | T1110 | **ubertooth** (hors parc équipe) | Capture d'appairage *Just Works/Legacy* → dérivation de clé (crackle) | *LE Secure Connections*, éviter *Just Works*. **Catalogue uniquement.** |
| `ble.connection_hijack` | **destructive-lab** | T1557 | **btlejack** (hors parc équipe) | Détournement de connexion établie | *Secure Connections*, contrôle de session. **Catalogue uniquement.** |

### Module de brouillage BLE — **catalogue uniquement**
- **`ble.adv_jam`** — Risque **`destructive-lab`** · MITRE **T1499** · Prérequis `btlejack`.
  Module de **brouillage** des canaux d'advertising BLE. **Hors périmètre de cette
  documentation** : aucun détail opérationnel n'est fourni. Nécessite une **autorisation
  spéciale** et reste classé destructif. Le matériel requis n'est pas dans le parc de
  l'équipe.

---

# 3. Modules LoRa / LoRaWAN

> **Chaîne matérielle** : réception via **HackRF One** (modules SDR) ; en exploitation
> « infrastructure », la passerelle **Dragino LG308N** alimente **ChirpStack** (voir
> [01 — Installation](01-INSTALLATION.md)).

## 3.1 LoRa — modules PASSIFS (mécanisme détaillé)

### `lora.recon` — capture passive EU868 + détection d'anomalies
- **Risque** : `passive` · **MITRE** : T1040 · **Prérequis** : `hackrf`
- **Quoi/pourquoi** : écoute les canaux EU868, décode les trames LoRaWAN au niveau PHY,
  journalise DevAddr/FCnt et détecte des anomalies en direct.
- **Mécanisme** : balaie en **round-robin** les trois canaux obligatoires EU868
  (868,1 / 868,3 / 868,5 MHz). Pour chaque canal, tente une démodulation via
  **gr-lora_sdr** (flowgraph GNU Radio lancé en sous-processus) ; **repli** sur une
  capture IQ brute via `hackrf_transfer -r` si gr-lora_sdr est absent. Les octets
  décodés sont parsés par `LoRaWANParser`. Détection en ligne :
  - **DevNonce reuse** (Join Request, MType 0) : un *DevNonce* déjà vu pour un DevEUI →
    anomalie (favorise des attaques de re-clé).
  - **FCnt rollback** (trames de données) : un compteur de trame qui **régresse** →
    anomalie (reset d'appareil ou rejeu).
- **Sorties** : `headers` (protocole `lora`, en-têtes seulement), MQTT
  `srt/headers/lora`, artefact « anomalies ».

### `lora.frame_decoder` — décodage complet (commandes MAC)
- **Risque** : `passive` · **MITRE** : T1040 · **Prérequis** : aucun (lit la base)
- **Quoi/pourquoi** : décode finement le PHYPayload, y compris les **commandes MAC** et
  la détection de version LoRaWAN 1.0/1.1.
- **Mécanisme** : sur `LoRaWANParser`, ajoute le parsing des **commandes MAC** (tous les
  CID montants/descendants : LinkADRReq, RXParamSetupReq, NewChannelReq, DutyCycleReq…),
  le décodage des **flags FCtrl**, la distinction **FOpts vs FPort=0**, et l'inférence de
  **version** (présence de commandes 1.1 comme RekeyInd/ForceRejoinReq → 1.1).

### `lora.anomaly_detector` — détection d'anomalies réseau
- **Risque** : `passive` · **MITRE** : T1040, T1499 · **Prérequis** : aucun (lit la base)
- **Quoi/pourquoi** : passe en revue les trames de la session pour repérer rejeu,
  faiblesses et instabilités.
- **Mécanisme** : quatre détecteurs — **FCnt rollback/gap** (régression ou saut > 10),
  **trames dupliquées** (même DevAddr/FCnt/FPort dans une fenêtre de 60 s → rejeu
  probable), **DevNonce reuse** (critique), **anomalies de timing** (intervalle > 3× la
  moyenne). Chaque anomalie est notée par sévérité (critical/high/medium/low).

### `lora.traffic_profiler` — profilage de trafic et duty cycle
- **Risque** : `passive` · **MITRE** : T1040 · **Prérequis** : aucun (lit la base)
- **Quoi/pourquoi** : caractérise le comportement des appareils et vérifie la conformité
  réglementaire du **duty cycle** EU868.
- **Mécanisme** : intervalles d'uplink par DevAddr, patterns de taille de payload,
  distribution des **SF** (facteurs d'étalement), et estimation du **temps-sur-l'air**
  (table ToA par SF) pour calculer un **duty cycle** ; signale les dépassements du seuil
  EU868 (≈ 1 %).

## 3.2 LoRa — modules ACTIFS (niveau descriptif & défensif)

| Module | Risque | MITRE | Prérequis | Classe de vulnérabilité | Détection / Remédiation |
|---|---|---|---|---|---|
| `lora.uplink_replay_abp` | active-lab | T1565.002 | hackrf | **Rejeu d'uplink ABP** si la validation FCnt est désactivée | **Activer la validation FCnt** ; préférer OTAA ; détection de doublons (`lora.anomaly_detector`). |
| `lora.join_replay` | active-lab | T1110 | hackrf | Rejeu de Join Request (réutilisation de DevNonce) | LoRaWAN 1.0.4+/1.1 (DevNonce compteur), suivi DevNonce. |
| `lora.beacon_spoof` | active-lab | T1557 | hackrf | Usurpation de beacons Class B (décalage des fenêtres RX) | Authentification de beacon, supervision des appareils Class B. |
| `lora.key_extractor` | active-lab | T1110, T1557 | — | Tentative d'extraction/dérivation de clés (ex. AppKey par défaut) | Clés uniques et aléatoires par appareil, rotation, secure element. |

### Module de brouillage LoRa — **catalogue uniquement**
- **`lora.channel_jam`** — Risque **`destructive-lab`** · MITRE **T1499** · Prérequis `hackrf`.
  Module de **brouillage sélectif** d'un canal LoRaWAN. **Hors périmètre de cette
  documentation** : aucun détail opérationnel, aucun paramétrage. Nécessite une
  **autorisation spéciale**, à n'employer qu'en cage de Faraday sous double
  confirmation. Du point de vue **défensif** : un canal brouillé se traduit par des
  **gaps de FCnt** détectables par `lora.anomaly_detector`.

---

# 4. Module Spectre

### `spectrum.sweep` — balayage large bande HackRF
- **Protocole** : spectrum · **Risque** : `passive` · **MITRE** : T1040 · **Prérequis** : `hackrf`
- **Quoi/pourquoi** : cartographie l'**occupation spectrale** d'une plage de fréquences
  (détection de signaux, classification par bande), en **réception seule**.
- **Mécanisme** : enveloppe l'outil **`hackrf_sweep`** (voir
  [05 — Spectre HackRF](05-SPECTRE-HACKRF.md)). `precheck` valide la plage (1–6000 MHz,
  début < fin). En `dry_run`, renvoie un résumé sans matériel. Sinon, exécute un sweep
  unique ou continu (`duration_s`), agrège les bins, estime le plancher de bruit, classe
  par bande ISM et **publie** les résultats sur MQTT (`srt/spectrum/sweep`) et en
  **WebSocket** (`spectrum_update`).

---

# 5. Vérification de cohérence du registre

Tous les noms ci-dessus correspondent à des classes effectivement décorées par
`@register` dans `src/srt/`. Le décompte par famille :

| Famille | Modules |
|---|---|
| recon (passif) | `wifi.recon`, `ble.recon`, `lora.recon`, `ble.gatt_enum` (actif), `spectrum.sweep` |
| analysis (passif) | `wifi.frame_dissector`, `wifi.probe_fingerprinter`, `wifi.security_assessor`, `wifi.signal_analyzer`, `wifi.timing_analyzer`, `ble.protocol_analyzer`, `ble.gatt_security_assessor`, `ble.mac_randomization_tracker`, `ble.pairing_analyzer`, `lora.anomaly_detector`, `lora.frame_decoder`, `lora.key_extractor` (actif), `lora.traffic_profiler` |
| defense (passif) | `defense.alerting`, `defense.rogue_ap_detector` |
| intel (passif) | `intel.kismet_sigint`, `intel.mac_dehide`, `intel.wigle_geoloc` |
| exploit wifi | `wifi.deauth`, `wifi.handshake_capture`, `wifi.psk_crack`, `wifi.pmkid`, `wifi.wps_pixie`, `wifi.evil_twin`, `wifi.karma`, `wifi.eap_relay`, `wifi.eap_capture`, `wifi.phishing_portal`, `wifi.wifite_auto`, `wifi.mdk4_dos`, `wifi.krack`, `wifi.fragattack`, `wifi.macstealer`, `wifi.ssid_confusion`, `wifi.dragonblood`, `wifi.beacon_flood` |
| exploit ble | `ble.connection_hijack`, `ble.adv_jam` (jamming, catalogue), `ble.gattacker_mitm`, `ble.pair_capture`, `ble.unauth_write` |
| exploit lora | `lora.uplink_replay_abp`, `lora.join_replay`, `lora.beacon_spoof`, `lora.channel_jam` (jamming, catalogue) |
| post_exploit | `post.responder`, `post.ntlm_relay`, `post.bettercap_mitm`, `post.crackmapexec_lateral`, `post.bloodhound_recon` |
| zero_day | `zero_day.airsnitch`, `zero_day.cve_2024_30078` |

> Pour obtenir la liste à jour à tout moment : `python -m srt.cli.main list`, ou
> `GET /api/modules` sur la plateforme web.
