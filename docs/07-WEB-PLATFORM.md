# 07 — Plateforme web tactique

La plateforme web (FastAPI + frontend statique) **centralise** la cartographie, le
lancement de modules, l'exécution de scénarios et la **diffusion temps réel**. Elle est
**découplée du matériel** : en l'absence de HackRF/broker, elle fonctionne en mode
simulation pour la démonstration.

## 1. Démarrage

```bash
uvicorn srt.web.app:create_app --factory --host 0.0.0.0 --port 8000
```

- Racine `/` : sert `src/srt/web/static/index.html`.
- `GET /api/health` : statut (MQTT connecté ?, émetteurs suivis, modules enregistrés).
- Au démarrage : **autodiscovery** des modules + lancement du **pont MQTT → WebSocket**
  (échec silencieux si le broker est absent).

## 2. Interface (panneaux)

Le frontend (`static/index.html`, Leaflet + JS) s'organise ainsi :

```
┌──────────────────────────────────────────────────────────────────┐
│ NAV : statut connexion · EMITTERS · ALERTS · MODULES · [SCAN]      │
├───────────────┬──────────────────────────────┬────────────────────┤
│ SIDEBAR GAUCHE│            CARTE              │  SIDEBAR DROITE     │
│ Onglets:      │        (Leaflet #map)         │  • SCENARIOS        │
│ ALL/WiFi/     │   marqueurs émetteurs,        │  • MODULE LAUNCHER  │
│ BLE/LoRa      │   heatmap, menaces            │  • ALERT FEED       │
├───────────────┴──────────────────────────────┴────────────────────┤
│ BAS : BAND OCCUPATION (spectre)   |   EMITTER TIMELINE              │
└──────────────────────────────────────────────────────────────────┘
```

| Panneau | Contenu | Source API |
|---|---|---|
| Barre de nav | Compteurs (émetteurs/alertes/modules), bouton **SCAN** | `/api/health`, `/api/cartography/scan` |
| Onglets protocoles | Tables WiFi / BLE / LoRa | `/api/wifi/*`, `/api/ble/*`, `/api/lora/*` |
| Carte | Marqueurs d'émetteurs, heatmap, menaces | `/api/cartography/emitters`, `/heatmap`, `/threats` |
| Scénarios | Liste + lancement + progression | `/api/scenarios/*` |
| Lanceur de modules | Liste + lancement (rappel « lab requis ») | `/api/modules/*` |
| Fil d'alertes | Alertes de menace temps réel | `/api/cartography/alerts` + WS |
| Occupation des bandes | Spectre / bandes | `/api/spectrum/*`, `/api/cartography/bands` |
| Timeline | Émetteurs par ordre de détection | `/api/cartography/timeline` |

Scripts JS : `websocket.js`, `map.js`, `modules.js`, `protocols.js`, `alerts.js`,
`spectrum.js`, `scenarios.js`, `realtime.js`, `app.js`.

> Le panneau « MODULE LAUNCHER » affiche un rappel explicite **« MODULES ACTIFS :
> ENVIRONNEMENT LAB REQUIS »**, cohérent avec la garde de sécurité côté backend.

## 3. API REST

### Santé
| Méthode | Endpoint | Description |
|---|---|---|
| GET | `/api/health` | Statut global. |

### Modules (`/api/modules`)
| Méthode | Endpoint | Description |
|---|---|---|
| GET | `/api/modules` | Liste de tous les modules (`name`, `protocol`, `risk`, `description`, `mitre_ttp`, `requires`). |
| GET | `/api/modules/{protocol}` | Filtre par protocole (`wifi`/`ble`/`lora`…). |
| POST | `/api/modules/{name}/launch` | Lance un module. **Garde** : pour un module non passif en exécution réelle (`dry_run=false`), une **autorisation valide est exigée** sinon **HTTP 403**. |

Corps de `launch` : `{ "params": {...}, "dry_run": true, "operator": "web-ui" }`.

### Cartographie (`/api/cartography`)
| Méthode | Endpoint | Description |
|---|---|---|
| GET | `/emitters` | Tous les émetteurs. |
| GET | `/emitters/{protocol}` | Émetteurs filtrés (wifi/ble/lora). |
| POST | `/scan` | Lance un cycle de balayage **avec diffusion temps réel** (WS). |
| GET | `/stats` | Statistiques globales. |
| GET | `/alerts` | 100 dernières alertes. |
| GET | `/bands` | Occupation des bandes. |
| GET | `/threats` | Carte des menaces (critique/haute/moyenne/basse). |
| GET | `/timeline` | Émetteurs triés par détection. |
| GET | `/heatmap` | Points `{lat, lon, intensity}` (position de repli dérivée d'un hash si pas de géoloc). |

### Spectre (`/api/spectrum`)
| Méthode | Endpoint | Description |
|---|---|---|
| POST | `/sweep` | Sweep HackRF (`freq_start_mhz`, `freq_end_mhz`, `bin_width_hz`, `lna_gain`, `vga_gain`). |
| GET | `/live` | Dernier spectre. |
| GET | `/bands` | Occupation par bande du dernier sweep. |
| GET | `/history` | Historique (≤ 50). |

### Protocoles
| Méthode | Endpoint | Description |
|---|---|---|
| GET | `/api/wifi/networks` · `/api/wifi/clients` | AP / clients WiFi. |
| GET | `/api/ble/devices` · `/api/ble/services` | Appareils / services BLE. |
| GET | `/api/lora/devices` · `/api/lora/gateways` · `/api/lora/traffic` | Appareils / passerelles / trafic LoRa. |

### Scénarios (`/api/scenarios`)
| Méthode | Endpoint | Description |
|---|---|---|
| GET | `/api/scenarios` | Liste des YAML (`name`, `description`, `steps_count`, `category`). |
| POST | `/api/scenarios/{name}/launch` | Lance en tâche de fond (HTTP 409 si déjà en cours). |
| GET | `/api/scenarios/{name}/status` | Statut (`idle`/`running`/`completed`/`failed`, steps, résultats). |

> Les scénarios lancés via l'API utilisent un orchestrateur en **`dry_run=True`**
> (opérateur `web-ui`), cohérent avec une plateforme de pilotage prudente.

## 4. WebSocket `/ws/live`

Le navigateur ouvre une connexion sur `/ws/live`. Le serveur **relaie** les topics MQTT
(`srt/headers/#`, `srt/alerts/#`, `srt/results/#`) et émet des messages de cartographie.

### Messages serveur → client
| `type` | Contenu |
|---|---|
| `connection` | Statut initial (`mqtt_available`). |
| `heartbeat` | Battement périodique (toutes ~30 s d'inactivité). |
| `mqtt` | Message relayé : `{ topic, payload }`. |
| `emitter_new` | Nouvel émetteur cartographié. |
| `emitter_update` | Mise à jour d'un émetteur. |
| `band_update` | Occupation des bandes recalculée. |
| `scan_progress` | Avancement du scan (`started`/`scanning`/`completed`, fréquence, steps). |
| `spectrum_update` | Résultat de sweep HackRF. |
| `scenario_progress` | Avancement d'un scénario (step courant, statut). |
| `state_snapshot` | Réponse à `get_state` (émetteurs + stats). |

### Messages client → serveur (commandes)
| `command` | Effet |
|---|---|
| `subscribe` | Accusé d'abonnement à des topics. |
| `subscribe_scenario` | Abonnement à la progression d'un scénario. |
| `get_state` | Demande un instantané de la cartographie. |
| `ping` | Renvoie `pong`. |

## 5. Sécurité de la plateforme

- **CORS** ouvert (`allow_origins=["*"]`) : pratique en lab, mais à **restreindre** pour
  tout déploiement exposé. La plateforme est prévue pour un usage **local / réseau de
  confiance** en environnement maîtrisé.
- **Garde d'exécution** : un module non passif ne s'exécute réellement que si
  l'autorisation est valide (sinon 403) — la couche de sécurité du cœur s'applique aussi
  via l'API.
- **Recommandation** : placer la plateforme derrière un reverse-proxy authentifié si
  elle doit être accessible au-delà du poste local, et conserver la liste blanche
  **fail-closed** (voir [02 — Architecture](02-ARCHITECTURE.md) §6.4).

## 6. État applicatif (`state.py`)

Un **singleton** `AppState` partage entre routeurs : l'instance `MoteurCartographie`, le
cache de résultats de modules, le suivi des scénarios, le statut MQTT et la liste des
clients WebSocket (protégée par un verrou). `reset_state()` réinitialise (tests).
