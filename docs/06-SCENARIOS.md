# 06 — Scénarios

Un **scénario** enchaîne plusieurs modules en une séquence reproductible, décrite en
**YAML** dans le dossier `scenarios/`. L'orchestrateur (`src/srt/core/orchestrator.py`)
les charge, les exécute, et agrège les résultats dans une **session** (voir
[02 — Architecture](02-ARCHITECTURE.md) §5).

## 1. Format YAML

```yaml
name: mon_scenario
description: >
  Description multi-lignes du scénario.

variables:                 # valeurs réutilisables via {{nom}}
  target_bssid: "AA:BB:CC:DD:EE:FF"
  target_channel: "6"

options:
  bail_on_fail: true       # arrêt au premier échec (défaut: true)
  dry_run: false           # force le dry-run sur tout le scénario
  loop: false              # exécution en boucle (patrouille)
  loop_delay_s: 60         # délai entre itérations si loop
  report_format: [json, markdown, pdf]

steps:
  - id: recon              # id optionnel → chaînage
    module: wifi.recon     # nom canonique d'un module enregistré
    params:
      duration_s: 30
      channels: "1-13"
```

### Points clés
- **`module`** doit correspondre à un module **enregistré** (`@register`) — sinon le
  step échoue. Vérifiez avec `python -m srt.cli.main list`.
- **`params`** sont passés au `ModuleContext`.
- **`id`** : si présent, le `status`, `summary`, `artifacts`, `metrics` du step sont
  stockés dans le contexte et réutilisables par les steps suivants via des variables
  `{{id.metrics.cle}}` (chaînage).
- **Variables** : résolution dans l'ordre **CLI (`--var`) > variables du scénario >
  contexte (steps précédents)**.
- **`bail_on_fail: false`** : continue malgré les échecs (utile pour les scénarios de
  reconnaissance « couverture maximale » et les patrouilles en boucle).

### Lancement
```bash
python -m srt.cli.main scenario scenarios/recon_multi_protocol.yaml
python -m srt.cli.main scenario scenarios/wifi_deep_audit.yaml --var target_bssid=AA:BB:CC:DD:EE:FF
```
Ou via l'API web : `POST /api/scenarios/{name}/launch` (exécution en tâche de fond, suivi
par `GET /api/scenarios/{name}/status` et messages WebSocket `scenario_progress`).

---

## 2. Scénarios de reconnaissance (PASSIFS) — détaillés

Ces scénarios n'émettent rien : ils conviennent à toute démonstration sans risque.

### `recon_wifi_complete.yaml`
Reconnaissance WiFi passive complète sur les canaux 1–13 :
`wifi.recon` (120 s) → `wifi.probe_fingerprinter` → `wifi.security_assessor`
→ `wifi.signal_analyzer` → `wifi.timing_analyzer`.
**But** : inventaire AP/clients, empreinte d'appareils, note de sécurité A→F, estimation
de distance/congestion, détection d'anomalies de cadence (rogue AP). Aucune émission.

### `recon_ble_complete.yaml`
BLE passif : `ble.recon` (90 s) → `ble.protocol_analyzer` →
`ble.mac_randomization_tracker`. **But** : découverte des périphériques, analyse de
protocole, regroupement des MAC aléatoires. Pas de connexion ni d'énumération GATT
active. Utilise le **Bluetooth intégré du Pi (`hci0`)**.

### `recon_multi_protocol.yaml`
Reconnaissance combinée WiFi + BLE + LoRa, puis analyses par protocole :
`wifi.recon` → `ble.recon` → `lora.recon` → `wifi.security_assessor` →
`ble.protocol_analyzer` → `lora.anomaly_detector` → `lora.traffic_profiler`.
**But** : cartographier l'environnement RF sur **toutes les bandes ISM** sans émettre.
`bail_on_fail: false` pour une couverture maximale.

### `survey_spectral.yaml`
Survey spectral en **boucle** (HackRF) :
`spectrum.sweep` 2400–2500 MHz (bin 1 MHz) → `spectrum.sweep` 863–870 MHz (bin 500 kHz)
→ `spectrum.sweep` 433–435 MHz (bin 500 kHz) → `wifi.recon` → `ble.recon` → `lora.recon`.
**But** : occupation spectrale + détection d'émetteurs transitoires, idéal pour une
cartographie d'environnement continue (réception seule). Voir
[05 — Spectre HackRF](05-SPECTRE-HACKRF.md).

### `continuous_monitor.yaml`
Surveillance passive **24/7** en boucle (`loop_delay_s: 30`), pensée pour un déploiement
**Raspberry Pi + systemd**. Enchaîne recon + analyses des trois protocoles
(`wifi.recon`/`timing`/`fingerprint`/`security`, `ble.recon`/`mac_track`/`protocol`,
`lora.recon`/`anomaly`/`profile`). Alertes via Grafana. 100 % passif.

### `autonomous_patrol.yaml`
Patrouille passive minimale en boucle (`loop_delay_s: 60`) : `wifi.recon` → `ble.recon`
→ `lora.recon`. Collecte de données RF ambiantes en continu, tolérante aux échecs.

---

## 3. Scénarios d'audit complet (mixtes — segments actifs **LAB ONLY**)

> Ces scénarios contiennent des steps **actifs** (`active-lab`). Ils ne doivent être
> exécutés qu'en **cage de Faraday autorisée**, avec autorisation valide et cibles en
> liste blanche. En dehors, lancez-les en **`dry_run`** ou limitez-vous aux scénarios de
> reconnaissance ci-dessus.

### `wifi_deep_audit.yaml` — **LAB ONLY** (segments actifs)
Phase passive (recon, dissection, timing, sécurité, fingerprint, signal) **puis** chaîne
active : `wifi.deauth` → `wifi.handshake_capture` → `wifi.pmkid` → `wifi.psk_crack`
(hors-ligne). `bail_on_fail: true`. Rapport PDF + MITRE.

### `wifi_full_audit.yaml` — **LAB ONLY** (segments actifs)
Chaîne WPA2 condensée : `wifi.recon` → `wifi.deauth` → `wifi.handshake_capture` →
`wifi.pmkid` → `wifi.psk_crack`. Démonstration de bout en bout du risque PSK faible.

### `ble_deep_audit.yaml` — **LAB ONLY** (segments actifs)
Audit BLE complet : recon → `ble.gatt_enum` → `ble.gatt_security_assessor` →
`ble.pairing_analyzer` → `ble.mac_randomization_tracker` → `ble.protocol_analyzer` →
**puis** `ble.unauth_write` et `ble.pair_crack` (actifs). `ble.pair_crack` requiert
**Ubertooth** (hors parc de l'équipe) : ce step restera donc non exécutable avec le
matériel disponible.

### `ble_full_audit.yaml` — **LAB ONLY** (segments actifs)
recon → `ble.gatt_enum` → `ble.pair_capture` → `ble.gattacker_mitm`. Mentionne
« BLE adapter (hci0) **ou** Ubertooth » ; les steps nécessitant Ubertooth sont au niveau
catalogue pour l'équipe.

### `lora_deep_audit.yaml` — **LAB ONLY** (segment actif final)
Passif : `lora.recon` (120 s) → `lora.frame_decoder` → `lora.anomaly_detector` →
`lora.traffic_profiler` → `lora.key_extractor` (tentative clés par défaut) **puis**
`lora.replay_abp` (rejeu, actif). Démonstration des risques ABP/clés par défaut.

### `full_deep_audit.yaml` — **LAB ONLY** (segments actifs)
« Tout-en-un » : audit WiFi (passif + deauth/handshake/pmkid) → audit BLE → audit LoRa,
avec corrélation inter-protocoles et rapport unifié JSON/MD/PDF. Requiert ALFA + BLE Pi +
HackRF. `bail_on_fail: false`.

---

## 4. Scénarios de démonstration / rejeu (actifs) — **LAB ONLY**

### `full_demo_jury.yaml` — **LAB ONLY**
Démonstration de soutenance (~12 min) : un enchaînement par protocole — WiFi
(recon/deauth/pmkid/psk_crack), BLE (recon/gatt_enum/pair_capture), LoRaWAN
(recon/uplink_replay_abp). Variables paramétrables (BSSID/MAC/DevAddr de **cibles de
lab**). À exécuter exclusivement en cage de Faraday autorisée.

### `lora_abp_replay_demo.yaml` — **LAB ONLY**
`lora.recon` → `lora.uplink_replay_abp` : démontre qu'un appareil **ABP sans validation
FCnt** accepte un uplink rejoué. Cible (DevAddr) à mettre en liste blanche.

### `lora_otaa_join_replay.yaml` — **LAB ONLY**
`lora.recon` → `lora.join_replay` : teste si le serveur réseau impose l'**unicité du
DevNonce** (vulnérabilité de réutilisation sur LoRaWAN 1.0.x).

### `lab_breach_full.yaml` — **LAB ONLY**
Chaîne longue WiFi → phishing/EAP → handshake → post-exploitation réseau
(`post.responder`, `post.bettercap_mitm`). Démonstration pédagogique d'une *kill chain*
complète **en laboratoire**. Les modules de post-exploitation relèvent du réseau filaire
(voir [03 — Modules](03-MODULES.md) §1.4).

---

## 5. Scénario de cartographie (format étendu)

### `cartographie_complete.yaml` — format spécifique
Ce fichier utilise un **format YAML enrichi** (blocs `configuration`, `success_criteria`,
`post_actions`, et des `steps` nommés `cartographie.init`, `cartographie.balayage_*`,
`cartographie.localisation`, `cartographie.rapport`…). 

> **Important** : ces noms de steps **ne sont pas** des modules enregistrés dans le
> registre `@register`. Ils décrivent le **flux de travail du moteur de cartographie**
> (configuration de balayage, bandes, méthode de localisation hybride, génération de
> rapport classifié) plutôt qu'une séquence de `AttackModule`. Ce scénario sert donc de
> **spécification de balayage cartographique** : il documente la configuration attendue
> (bandes ISM à couvrir, seuils de détection, méthode `hybride`, format de rapport) et
> s'interprète via le `MoteurCartographie` (voir [04 — Cartographie](04-CARTOGRAPHIE.md)),
> et non via l'orchestrateur de modules standard.

Les bandes balayées y sont : ISM 433, ISM 868, WiFi 2,4 GHz, WiFi 5 GHz (U-NII-1/3),
ISM 5,8 GHz — toutes cohérentes avec les capacités du HackRF.

---

## 6. Tableau récapitulatif

| Scénario | Type | Émission ? | Matériel |
|---|---|---|---|
| `recon_wifi_complete` | recon | non | ALFA 2,4 GHz |
| `recon_ble_complete` | recon | non | Pi BLE (`hci0`) |
| `recon_multi_protocol` | recon | non | ALFA + Pi BLE + HackRF |
| `survey_spectral` | spectre/recon (loop) | non | HackRF (+ ALFA/Pi) |
| `continuous_monitor` | surveillance (loop) | non | ALFA + Pi BLE + HackRF |
| `autonomous_patrol` | patrouille (loop) | non | ALFA + Pi BLE + HackRF |
| `wifi_deep_audit` | audit | **oui (lab)** | ALFA |
| `wifi_full_audit` | audit | **oui (lab)** | ALFA |
| `ble_deep_audit` | audit | **oui (lab)** | Pi BLE (+ Ubertooth hors parc) |
| `ble_full_audit` | audit | **oui (lab)** | Pi BLE (+ Ubertooth hors parc) |
| `lora_deep_audit` | audit | **oui (lab)** | HackRF |
| `full_deep_audit` | audit | **oui (lab)** | ALFA + Pi BLE + HackRF |
| `full_demo_jury` | démo | **oui (lab)** | parc complet |
| `lora_abp_replay_demo` | démo | **oui (lab)** | HackRF + ChirpStack |
| `lora_otaa_join_replay` | démo | **oui (lab)** | HackRF + ChirpStack |
| `lab_breach_full` | démo | **oui (lab)** | ALFA + réseau lab |
| `cartographie_complete` | cartographie (format étendu) | non (réception) | HackRF |

> **Conseil soutenance** : pour une démonstration **live sans risque**, privilégiez
> `recon_multi_protocol` ou `survey_spectral` (100 % passifs). Réservez les scénarios
> actifs à la cage de Faraday, ou montrez-les en **`dry_run`**.

---

## 7. Divergences connues entre scénarios et registre

Une vérification automatique (noms de `module:` des scénarios vs noms enregistrés via
`@register`) révèle quelques **incohérences pré-existantes** à connaître, car les steps
concernés **échoueront à la résolution dans le registre** s'ils sont exécutés tels quels :

| Scénario | Step référencé | Nom enregistré réel | À faire |
|---|---|---|---|
| `ble_deep_audit.yaml` | `ble.pair_crack` | **`ble.pair_capture`** | Corriger le nom du step (et noter que `ble.pair_capture` requiert Ubertooth, hors parc). |
| `lora_deep_audit.yaml` | `lora.replay_abp` | **`lora.uplink_replay_abp`** | Corriger le nom du step. |

Par ailleurs, les steps `cartographie.*` de `cartographie_complete.yaml` ne sont **pas**
des modules enregistrés : c'est un **format étendu** décrivant le flux du moteur de
cartographie (voir §5), pas une séquence d'`AttackModule`.

> Ces points sont signalés **à titre documentaire** (exactitude). La correction des noms
> de steps relève d'une modification de scénario, hors du périmètre de cette
> documentation. Pour obtenir la liste exacte des noms valides :
> `python -m srt.cli.main list`.
