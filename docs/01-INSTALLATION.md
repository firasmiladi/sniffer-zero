# 01 — Installation pas à pas

Ce guide décrit l'installation **complète et reproductible** de SRT, dans l'ordre :
(a) l'infrastructure Docker, (b) le paquet Python, (c) la plateforme web. Il intègre
les **pièges réels** rencontrés en pratique — lisez les encadrés « ⚠️ Piège ».

> **Prérequis système**
> - Linux (poste de développement ou Raspberry Pi), accès `sudo`.
> - Docker + plugin `docker compose`.
> - Python ≥ 3.10.
> - Pour le matériel : HackRF One, ALFA 2,4 GHz (RTL8812AU), passerelle Dragino LG308N, Raspberry Pi.

---

## 0. Récupérer le dépôt

```bash
git clone <url-du-depot> sniffer
cd sniffer
```

---

## A. Infrastructure Docker

La pile est définie dans `infra/docker-compose.yml` et démarre :

| Service | Image | Rôle | Port (localhost) |
|---|---|---|---|
| `timescaledb` | `timescale/timescaledb:2.15.2-pg16` | Stockage séries temporelles | 5432 |
| `grafana` | `grafana/grafana-oss:11.1.0` | Tableaux de bord | 3000 |
| `mosquitto` | `eclipse-mosquitto:2.0` | Bus MQTT temps réel | 1883 / 9001 |
| `chirpstack-redis` | `redis:7-alpine` | Cache ChirpStack | — |
| `chirpstack-postgres` | `postgres:16-alpine` | Base ChirpStack | — |
| `chirpstack` | `chirpstack/chirpstack:4` | Serveur réseau LoRaWAN | 8080 |

### A.1 Démarrer la pile

```bash
docker compose -f infra/docker-compose.yml up -d
docker compose -f infra/docker-compose.yml ps
```

Vérifications rapides :

```bash
# TimescaleDB doit être "healthy"
docker compose -f infra/docker-compose.yml ps
# Logs ChirpStack
docker compose -f infra/docker-compose.yml logs -f chirpstack
```

### A.2 ⚠️ Piège — l'extension PostgreSQL `pg_trgm` pour ChirpStack

Les **migrations de base de données de ChirpStack échouent** si l'extension
PostgreSQL `pg_trgm` n'est pas présente dans la base `chirpstack`. Le symptôme est une
boucle de redémarrage du conteneur `chirpstack` avec une erreur de migration
mentionnant `pg_trgm` / `gin_trgm_ops`.

**Correctif** — fournir un script d'initialisation qui crée l'extension, et le monter
dans le conteneur `chirpstack-postgres`.

Créez le fichier `infra/chirpstack/postgres-init/01-extensions.sql` :

```sql
-- ChirpStack a besoin de l'extension pg_trgm pour ses migrations.
CREATE EXTENSION IF NOT EXISTS pg_trgm;
```

Puis montez le dossier d'init dans le service `chirpstack-postgres` du
`docker-compose.yml` (les scripts de `/docker-entrypoint-initdb.d` sont exécutés au
**premier** démarrage, base vide) :

```yaml
  chirpstack-postgres:
    image: postgres:16-alpine
    container_name: srt-chirpstack-postgres
    restart: unless-stopped
    environment:
      POSTGRES_USER: chirpstack
      POSTGRES_PASSWORD: chirpstack
      POSTGRES_DB: chirpstack
    volumes:
      - ./volumes/chirpstack-postgres:/var/lib/postgresql/data
      - ./chirpstack/postgres-init:/docker-entrypoint-initdb.d:ro   # ← ajout
    networks: [srt]
```

> Si la base a déjà été créée **avant** d'ajouter ce montage, les scripts d'init ne
> seront pas rejoués. Soit on crée l'extension à la main
> (`docker exec -it srt-chirpstack-postgres psql -U chirpstack -d chirpstack -c "CREATE EXTENSION IF NOT EXISTS pg_trgm;"`),
> soit on repart d'un volume vierge (`docker compose down` puis suppression du dossier
> `infra/volumes/chirpstack-postgres`).

### A.3 ⚠️ Piège — attendre que la base soit prête (`service_healthy`)

ChirpStack démarre parfois **avant** que PostgreSQL n'accepte les connexions, ce qui
provoque des erreurs de connexion en cascade. Le `docker-compose.yml` utilise déjà un
**healthcheck** sur `timescaledb` et un `depends_on: condition: service_healthy` pour
Grafana. **Appliquez le même principe** entre ChirpStack et sa base.

Ajoutez un healthcheck à `chirpstack-postgres` et faites dépendre `chirpstack` de son
état sain :

```yaml
  chirpstack-postgres:
    # ... (voir ci-dessus)
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U chirpstack -d chirpstack"]
      interval: 10s
      timeout: 5s
      retries: 5

  chirpstack:
    image: chirpstack/chirpstack:4
    command: -c /etc/chirpstack
    volumes:
      - ./chirpstack/config:/etc/chirpstack:ro
    depends_on:
      chirpstack-postgres:
        condition: service_healthy     # ← attend que la base soit prête
      chirpstack-redis:
        condition: service_started
      mosquitto:
        condition: service_started
    ports:
      - "127.0.0.1:8080:8080"
    networks: [srt]
```

### A.4 ⚠️ Piège — relayer la passerelle Dragino : `chirpstack-gateway-bridge`

La passerelle **Dragino LG308N** remonte ses paquets via le **protocole Semtech UDP**
(le « packet forwarder », **UDP port 1700**). ChirpStack v4 attend, lui, des messages
de gateway sur **MQTT**. Il faut donc un service **`chirpstack-gateway-bridge`** qui
écoute l'UDP 1700 et le **convertit en MQTT**.

Ajoutez ce service au `docker-compose.yml` :

```yaml
  chirpstack-gateway-bridge:
    image: chirpstack/chirpstack-gateway-bridge:4
    container_name: srt-chirpstack-gw-bridge
    restart: unless-stopped
    ports:
      - "1700:1700/udp"               # Semtech UDP (paquets de la Dragino LG308N)
    volumes:
      - ./chirpstack/gateway-bridge:/etc/chirpstack-gateway-bridge:ro
    depends_on:
      mosquitto:
        condition: service_started
    networks: [srt]
```

Créez la configuration `infra/chirpstack/gateway-bridge/region_eu868.toml` (backend
MQTT côté gateway, région EU868) :

```toml
# chirpstack-gateway-bridge — région EU868
# Reçoit les paquets Semtech UDP de la Dragino LG308N et les republie sur MQTT.

[backend]
  type = "semtech_udp"

  [backend.semtech_udp]
    udp_bind = "0.0.0.0:1700"

[integration]
  marshaler = "protobuf"

  [integration.mqtt]
    event_topic_template   = "eu868/gateway/{{ .GatewayID }}/event/{{ .EventType }}"
    command_topic_template = "eu868/gateway/{{ .GatewayID }}/command/#"

    [integration.mqtt.auth]
      type = "generic"

      [integration.mqtt.auth.generic]
        servers = ["tcp://mosquitto:1883"]
        clean_session = false
```

Côté **Dragino LG308N** (interface d'administration de la passerelle) : sélectionner le
mode **« Semtech UDP / Packet Forwarder »**, et pointer le **Server Address** vers
l'IP de l'hôte Docker, **port 1700**. La passerelle apparaît ensuite dans ChirpStack
une fois enregistrée avec son Gateway EUI.

> ChirpStack est déjà configuré pour la région `eu868` (voir
> `infra/chirpstack/config/chirpstack.toml`, clé `enabled_regions`) et publie les
> événements applicatifs sur MQTT (`application/{{application_id}}/device/{{dev_eui}}/event/{{event}}`).

### A.5 ⚠️ Piège — permissions du volume Grafana

Grafana s'exécute sous l'UID/GID **472**. Si le dossier hôte monté
(`infra/volumes/grafana`) appartient à `root`, Grafana ne peut pas écrire et redémarre
en boucle. Corrigez les permissions **avant** le premier démarrage :

```bash
mkdir -p infra/volumes/grafana
sudo chown -R 472:472 infra/volumes/grafana
```

### A.6 Schéma de base de données

Au **premier** démarrage de `timescaledb`, les scripts de `infra/timescaledb/init/`
sont exécutés automatiquement (montés sur `/docker-entrypoint-initdb.d`) :

- `01_schema.sql` — tables `sessions`, `captures`, `headers` (hypertable), `module_results`, `secrets`, vues.
- `02-cartographie-schema.sql` — schéma `cartographie` (`emetteurs`, `signaux`, `positions`, `alertes`, `balayages`).
- `02_aggregates.sql`, `03_retention.sql`, `04_views.sql`, `05_correlation.sql` — agrégats continus, rétention, vues, corrélation.

Vérification :

```bash
docker exec -it srt-timescaledb psql -U srt -d srt -c "\dt"
docker exec -it srt-timescaledb psql -U srt -d srt -c "\dt cartographie.*"
```

---

## B. Paquet Python

### B.1 Environnement virtuel + installation éditable

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev,ble,report]"
```

Extras disponibles (voir `pyproject.toml`) : `dev` (tests/lint), `ble` (bibliothèque
`bleak`), `report` (PDF via WeasyPrint + matplotlib), `crypto` (pycryptodome).

### B.2 ⚠️ Piège majeur — conflit de nom avec le paquet PyPI `srt`

Le projet s'appelle `srt` **et** expose un script `srt` (voir
`[project.scripts] srt = "srt.cli.main:cli"`). Or il existe **un autre paquet PyPI
nommé `srt`** (manipulation de sous-titres). Selon l'environnement, la commande `srt`
peut donc pointer vers le mauvais programme, ou un import peut résoudre vers le mauvais
module.

**Règle de l'équipe : invoquer la CLI via le module, pas via le script** :

```bash
# ✅ Forme robuste, non ambiguë
python -m srt.cli.main --help
python -m srt.cli.main info
python -m srt.cli.main list

# ⚠️ Peut entrer en conflit avec le paquet PyPI "srt"
srt --help
```

> Si vous tenez à utiliser la commande courte `srt`, assurez-vous que l'autre paquet
> n'est **pas** installé dans le même environnement et que `which srt` pointe bien vers
> le venv du projet. En cas de doute, **utilisez `python -m srt.cli.main`**.

### B.3 Vérifier l'installation

```bash
python -m srt.cli.main info        # version + état de la couche de sécurité
python -m srt.cli.main list        # liste des modules enregistrés
python -m srt.cli.main selftest    # sonde SDR + base + sécurité (code retour ≠ 0 si échec)
```

### B.4 Configurer le matériel

Éditez `config/hardware.yaml` pour refléter **votre** matériel réel :

- **WiFi** : nom de l'interface ALFA (souvent `wlan1`) et son interface moniteur
  (`wlan1mon`). L'ALFA de l'équipe est **2,4 GHz** — ne configurez pas de bandes 5 GHz
  que le matériel ne couvre pas.
- **SDR** : numéro de série du HackRF (`hackrf_info` pour l'obtenir).
- **BLE** : interface `hci0` (Bluetooth intégré du Raspberry Pi).
- **LoRa** : réception via HackRF + paramètres EU868 (868,1 MHz, BW 125 kHz, SF7…).

### B.5 Liste blanche des cibles (sécurité)

`safety/whitelist.yaml` liste les identifiants de cibles autorisés (SSID, MAC, DevEUI…).

> **Important (sécurité).** La liste blanche doit être traitée comme **fail-closed** :
> toute cible **absente** de la liste doit être **refusée**. N'introduisez pas de
> caractères génériques (`ANY-*`) ni de bascule désactivant la vérification : ce sont
> des contournements de la couche de sécurité. Voir la section dédiée dans
> [02 — Architecture](02-ARCHITECTURE.md) et la [FAQ](08-FAQ-SOUTENANCE.md).

---

## C. Plateforme web

La plateforme web (FastAPI) centralise la cartographie, le lancement de modules, les
scénarios et la diffusion temps réel.

### C.1 Lancer le serveur

```bash
# Depuis la racine du dépôt, venv activé
uvicorn srt.web.app:create_app --factory --host 0.0.0.0 --port 8000
```

- Interface : `http://localhost:8000/` (sert `src/srt/web/static/index.html`).
- Santé : `http://localhost:8000/api/health`.
- Le serveur lance au démarrage l'**autodiscovery** des modules et un **pont
  MQTT → WebSocket** (échec silencieux si le broker n'est pas joignable).

### C.2 Données simulées vs matériel

La plateforme est **découplée du matériel** : sans HackRF ni broker, le moteur de
cartographie et le balayage spectral fonctionnent en **mode simulation** (données
synthétiques) pour démonstration. Avec le matériel branché et la pile Docker active,
les mêmes endpoints exploitent les vraies captures.

---

## D. Spécificités Raspberry Pi et VM

### D.1 Passage USB en machine virtuelle

Si vous développez dans une **VM**, les périphériques USB (HackRF, ALFA) doivent être
**passés explicitement** à la VM (USB passthrough). Sans cela, `hackrf_info` et la mise
en mode moniteur de l'ALFA échoueront — le matériel reste vu par l'hôte.

### D.2 ⚠️ Piège — HackRF à haut débit : préférer `hackrf_sweep`

À **fort taux d'échantillonnage**, une capture continue via `hackrf_transfer`
(notamment en USB 2.0, en VM, ou via un hub non alimenté) peut **caler/stall** (pertes
d'échantillons, blocage du transfert). Pour le **balayage spectral**, **préférez
`hackrf_sweep`** : il balaie une plage de fréquences par sauts et reste robuste, c'est
exactement l'outil qu'intègre SRT (voir [05 — Spectre HackRF](05-SPECTRE-HACKRF.md)).

### D.3 Alimentation et thermique

- ALFA + HackRF ensemble peuvent tirer ~1 A : utilisez un **hub USB alimenté** sur Pi.
- Les charges SDR chauffent le Pi : prévoyez un **refroidissement actif**.

---

## E. Récapitulatif de mise en route

```bash
# 1) Permissions Grafana (avant tout)
mkdir -p infra/volumes/grafana && sudo chown -R 472:472 infra/volumes/grafana

# 2) Infra Docker (avec pg_trgm, gateway-bridge, healthchecks configurés)
docker compose -f infra/docker-compose.yml up -d

# 3) Paquet Python
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev,ble,report]"

# 4) Vérifications
python -m srt.cli.main info
python -m srt.cli.main selftest

# 5) Matériel
hackrf_info
nano config/hardware.yaml

# 6) Plateforme web
uvicorn srt.web.app:create_app --factory --host 0.0.0.0 --port 8000
```

En cas de problème, consultez `docs/TROUBLESHOOTING.md` et la section dépannage de la
[FAQ soutenance](08-FAQ-SOUTENANCE.md).
