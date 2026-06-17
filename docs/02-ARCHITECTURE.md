# 02 — Architecture

SRT traite **toute action** — scan passif ou module actif — comme un objet uniforme
appelé `AttackModule`, qui expose le même cycle de vie et émet des résultats
structurés vers un bus et une base de données partagés. Cette uniformité est le cœur de
l'architecture : elle rend la plateforme facile à étendre, à enseigner et à visualiser.

## 1. Vue en couches

```
┌──────────────────────────────────────────────────────────────────────────┐
│  COUCHE PRÉSENTATION                                                       │
│   • Plateforme web FastAPI (carte Leaflet, onglets, spectre, alertes)      │
│   • WebSocket /ws/live  • Tableaux de bord Grafana  • CLI / rapports       │
└───────────────▲───────────────────────────────────────────▲──────────────┘
                │ REST / WS                                   │ SQL
┌───────────────┴───────────────────────────────────────────┴──────────────┐
│  COUCHE ORCHESTRATION & SÉCURITÉ                                           │
│   • Orchestrator (scénarios YAML, enchaînement, sessions)                  │
│   • Registry (autodiscovery des modules)                                   │
│   • Safety (autorisation + liste blanche + coupe-circuit)                  │
│   • MoteurCartographie (association signaux→émetteurs, menaces)            │
└───────────────▲───────────────────────────────────────────▲──────────────┘
                │ AttackResult                                │ events
┌───────────────┴───────────────────────────────────────────┴──────────────┐
│  COUCHE MODULES (AttackModule)                                             │
│   recon/ (passif)  analysis/ (passif)  exploit/ (actif-lab)                │
│   defense/  intel/  post_exploit/  zero_day/  cartographie/                │
└───────────────▲────────────────────────────────────────────────────────┬─┘
                │ capture / décode                                         │
┌───────────────┴──────────────────────────────────────────────────────┐  │
│  COUCHE MATÉRIEL / SIGNAL                                              │  │
│   HackRF One (SDR) ─ hackrf_sweep / GNU Radio                         │  │
│   ALFA 2,4 GHz (mode moniteur 802.11)                                 │  │
│   Raspberry Pi BLE (hci0)                                             │  │
│   Dragino LG308N ─ Semtech UDP → gateway-bridge → MQTT → ChirpStack   │  │
└───────────────────────────────────────────────────────────────────────┘  │
                ┌───────────────────────────────────────────────────────────┘
                ▼
        STOCKAGE PARTAGÉ : TimescaleDB (séries temporelles) + MQTT (Mosquitto)
```

## 2. Flux de données

```
Matériel ─▶ module recon ─┬─▶ MQTT  srt/headers/<proto>      (temps réel)
                          ├─▶ TimescaleDB  headers / cartographie.signaux
                          └─▶ artefacts (pcap / cfile)  data/captures/...

scenario.yaml ─▶ Orchestrator ─▶ module.run() ─▶ AttackResult ─▶ reporter (JSON/MD/PDF)
                                              └─▶ MQTT  srt/results/<id>

MQTT ─▶ pont web (ws.py) ─▶ WebSocket /ws/live ─▶ navigateur (carte, panneaux)
MoteurCartographie ─▶ messages WS (emitter_new, emitter_update, band_update, scan_progress)
```

Deux topics MQTT structurent le bus : `srt/headers/#` (en-têtes des trames observées),
`srt/alerts/#` (alertes de menace), `srt/results/#` (résultats de modules). Le pont
WebSocket (`src/srt/web/ws.py`) réémet ces messages aux navigateurs connectés.

## 3. Le `AttackModule` et son cycle de vie

Défini dans `src/srt/core/module.py`. Chaque module **déclare** des métadonnées et
**implémente** un cycle de vie en trois temps.

### 3.1 Métadonnées déclaratives

| Attribut | Sens |
|---|---|
| `name` | Nom canonique (`"wifi.recon"`, `"lora.uplink_replay_abp"`…), clé du registre. |
| `protocol` | `"wifi"`, `"ble"`, `"lora"`, `"spectrum"`. |
| `risk` | `Risk.PASSIVE`, `ACTIVE_LAB`, `DESTRUCTIVE_LAB` ou `FORBIDDEN`. |
| `mitre_ttp` | Liste de techniques MITRE ATT&CK (`["T1040"]`…). |
| `cve` | CVE associées le cas échéant. |
| `requires` | Capacités requises (`["hackrf"]`, `["monitor-mode-nic"]`, `["ble-adapter"]`…). |
| `description` | Phrase explicative. |

### 3.2 Cycle de vie

```
precheck(ctx) -> bool      # porte de sécurité + capacités
run(ctx)      -> AttackResult
cleanup(ctx)  -> None       # toujours appelé, même en cas d'échec
```

- **`precheck`** : la porte par défaut **refuse** si `risk == FORBIDDEN`, et refuse si
  `risk > PASSIVE` et `ctx.authorization_ok` est faux. Les modules peuvent surcharger
  `precheck` pour ajouter des vérifications de paramètres/capacités (ex.
  `spectrum.sweep` valide la plage de fréquences).
- **`run`** : exécute l'action et **renvoie toujours** un `AttackResult`.
- **`cleanup`** : libère les ressources ; **toujours** invoqué par l'orchestrateur.

### 3.3 `AttackResult`

Résultat structuré persisté dans la table `module_results` : `module_name`, `protocol`,
`risk`, `status` (`ok`/`fail`/`aborted`/`refused`), horodatages, `summary`,
`mitre_ttp`, `cve`, `artifacts`, `metrics`. La propriété `duration_s` donne la durée.

> **Principe clé.** Les modules sont des **déclarations d'intention** : ils ne
> contournent **jamais** la couche de sécurité (`srt.core.safety`).

## 4. Registre et autodiscovery

`src/srt/core/registry.py` :

- Décorateur `@register` : enregistre une classe par son `name`. **Refuse** un module
  sans `name` ou avec un `name` **déjà pris** (pas de doublon possible).
- `get(name)` / `get_all()` : introspection (utilisé par la CLI, l'orchestrateur,
  l'API web, le reporter).
- `autodiscover((packages))` : importe récursivement tous les sous-modules des paquets
  (`srt.recon`, `srt.exploit`, `srt.analysis` par défaut, plus ceux importés ailleurs)
  pour que les décorateurs `@register` s'exécutent. Les échecs d'import sont
  journalisés sans interrompre le chargement (robustesse face au matériel absent).

## 5. Orchestrateur et scénarios YAML

`src/srt/core/orchestrator.py` :

- **`Scenario.load(path)`** lit un YAML : `name`, `description`, `operator`,
  `variables`, `options`, et `steps` (chaque step = `module` + `params` + `id`
  optionnel).
- **`ScenarioOptions`** : `bail_on_fail` (arrêt au premier échec, défaut vrai),
  `dry_run`, `report_format`, `loop` + `loop_delay_s` (mode patrouille en boucle).
- **`run_module`** : construit le `ModuleContext` (à partir de la sécurité évaluée),
  appelle `precheck` → `run` (ou dry-run) → `cleanup`, puis écrit le résultat en base.
- **`run_scenario`** : ouvre une **session** en base, exécute les steps en séquence,
  gère le **chaînage** via des variables `{{...}}` (les artefacts/metrics d'un step
  identifié par `id` deviennent disponibles pour les steps suivants), applique
  `bail_on_fail`, et clôture la session.

Voir [06 — Scénarios](06-SCENARIOS.md) pour le détail du format et des scénarios livrés.

## 6. Couche de sécurité (safety)

`src/srt/core/safety.py` charge **deux** éléments et les fournit à chaque module via le
`ModuleContext`.

### 6.1 Autorisation

- Source : `authorization/authorization.yaml` ou le bloc YAML dans
  `docs/legal-scope.md`.
- **Coupe-circuit** : si `SRT_KILLSWITCH=1`, l'autorisation est immédiatement
  **refusée** (`ok=False`), quel que soit le contenu des fichiers.
- **Garde anti-placeholder** : si `signed_by` est vide ou commence par `<` (gabarit non
  rempli), l'autorisation est considérée **invalide**. C'est volontaire :
  l'autorisation doit être réellement renseignée et signée.
- Champs exploités : `client`, `scope`, dates, `signed_by`, `signed_doc_sha256`,
  `authorized_bands_mhz`, `authorized_tx_bands_mhz`, `shielded_environment`.

### 6.2 Liste blanche (whitelist)

- Source : `safety/whitelist.yaml`, chargée par `load_whitelist()`.
- Contient les identifiants de cibles autorisés par type (SSID, MAC, DevEUI…).

### 6.3 Classes de risque

| Classe | Exemples | Exigences |
|---|---|---|
| `passive` | recon, décodage, analyse, balayage spectral | Métadonnées d'autorisation + liste blanche de bandes |
| `active-lab` | deauth, capture d'appairage BLE, rejeu LoRa | Faraday + liste blanche + log signé |
| `destructive-lab` | brouillage, crash de pile | Faraday + liste blanche + double confirmation |
| `forbidden` | toute cible non consentie / bande sous licence en réel | **Toujours refusé** |

### 6.4 Recommandation : liste blanche *fail-closed*

La logique de refus la plus sûre est **fail-closed** : si une cible n'est **pas**
explicitement présente dans la liste blanche, le module **refuse**. Concrètement :

- Ne pas introduire d'entrées génériques (`ANY-*`) qui équivalent à « tout autoriser ».
- Ne pas ajouter de bascule du type « ne pas exiger la correspondance de liste blanche »
  (`require_whitelist_match: false`) : c'est un **contournement** de la sécurité, à
  proscrire. Le comportement attendu est l'**exigence** d'une correspondance.
- Le coupe-circuit (`SRT_KILLSWITCH=1`) et l'autorisation valide restent des conditions
  **nécessaires** à toute opération non passive.

> **Position de la documentation.** Nous décrivons et recommandons le renforcement de
> cette couche (fail-closed), jamais son affaiblissement. Les fichiers d'exemple du
> dépôt qui désactivent la vérification doivent être considérés comme **non
> conformes** et corrigés vers un comportement fail-closed avant toute opération réelle.

## 7. Schéma de base de données

### 7.1 Schéma `public` (`01_schema.sql`)

| Table | Contenu |
|---|---|
| `sessions` | Une ligne par exécution (`operator`, `scenario`, `auth_doc_sha`, horodatages). |
| `captures` | Index des artefacts pcap/cfile (`protocol`, `path`, `bytes`, `sha256`). |
| `headers` | **Hypertable** d'en-têtes de trames, **sans charge utile** : `ts`, `protocol`, `src`, `dst`, `channel`, `freq_hz`, `rssi_dbm`, `snr_db`, `fields` (JSONB). |
| `module_results` | Une ligne par `AttackResult` (statut, MITRE, CVE, `summary`, `artifacts`, `metrics`). |
| `secrets` | Hashes/clés capturés en lab (`kind`, `target`, `state`, valeur chiffrée). |
| `v_recent_devices` | Vue : appareils vus sur 24 h, agrégés par protocole/source. |

> Le choix **« en-têtes uniquement, pas de payload »** (`headers`) est un principe de
> conception **préservant la vie privée** (pertinent pour un audit RGPD/sécurité).

### 7.2 Schéma `cartographie` (`02-cartographie-schema.sql`)

| Table / objet | Contenu |
|---|---|
| `cartographie.emetteurs` | Émetteurs cartographiés (id, MAC, SSID, type, priorité, affiliation, `niveau_menace`, détections). |
| `cartographie.signaux` | **Hypertable** des signaux (fréquence, bande passante, puissance, SNR, modulation, bande ISM, protocole estimé). |
| `cartographie.positions` | **Hypertable** des positions (x/y/z, lat/lon/alt, incertitude, méthode de localisation). |
| `cartographie.alertes` | **Hypertable** des alertes de menace. |
| `cartographie.balayages` | **Hypertable** des cycles de balayage. |
| `resume_bandes` | Vue matérialisée : résumé par bande ISM. |
| `emetteurs_actifs` | Vue : émetteurs actifs avec dernière position/signal. |
| Trigger `update_menace_niveau` | Met à jour le niveau de menace à l'insertion d'un signal. |

## 8. Backend web (FastAPI) et frontend

### 8.1 Backend — `src/srt/web/`

- `app.py` — fabrique l'application (`create_app`), gère le cycle de vie (autodiscovery
  + pont MQTT au démarrage), CORS, montage des fichiers statiques, endpoint
  `/api/health`.
- Routeurs API (`src/srt/web/api/`) :
  - `modules.py` — `/api/modules` (liste, filtre par protocole, **lancement** avec
    garde de sécurité : un module non passif en exécution réelle exige une autorisation
    valide, sinon HTTP 403).
  - `cartography.py` — `/api/cartography/*` (émetteurs, scan avec diffusion temps réel,
    stats, alertes, bandes, menaces, timeline, heatmap).
  - `spectrum.py` — `/api/spectrum/*` (sweep HackRF, dernier spectre, bandes, historique).
  - `protocols.py` — `/api/wifi/*`, `/api/ble/*`, `/api/lora/*`.
  - `scenarios.py` — `/api/scenarios/*` (liste, lancement en tâche de fond, statut).
- `ws.py` — endpoint **`/ws/live`** + pont **MQTT → WebSocket** (thread d'arrière-plan).
- `state.py` — **singleton** d'état applicatif (instance `MoteurCartographie`, cache de
  résultats, suivi des scénarios, clients WebSocket, statut MQTT).

### 8.2 Frontend — `src/srt/web/static/`

Interface tactique statique (HTML/CSS/JS, **Leaflet** pour la carte) :

- Barre de navigation : statut de connexion, compteurs (émetteurs, alertes, modules),
  bouton **SCAN**.
- Sidebar gauche : **onglets protocoles** (ALL / WiFi / BLE / LoRa).
- Centre : **carte** Leaflet (`#map`).
- Sidebar droite : **scénarios**, **lanceur de modules** (avec rappel « environnement
  lab requis »), **fil d'alertes**.
- Bas de page : **occupation des bandes** (spectre) et **timeline** des émetteurs.
- Scripts : `websocket.js`, `map.js`, `modules.js`, `protocols.js`, `alerts.js`,
  `spectrum.js`, `scenarios.js`, `realtime.js`, `app.js`.

Voir [07 — Plateforme web](07-WEB-PLATFORM.md) pour le détail des endpoints et messages.

## 9. Pourquoi cette architecture ?

- **API de module uniforme** → facile à enseigner, à noter, à étendre.
- **Séparation nette passif/actif** → s'aligne sur la *Cyber Kill Chain* et les phases
  MITRE ATT&CK (Reconnaissance → Initial Access).
- **Stockage en-têtes seuls** → respect de la vie privée par conception.
- **Infra conteneurisée** → environnement reproductible, identique du portable de
  l'analyste au Raspberry Pi déployable.
