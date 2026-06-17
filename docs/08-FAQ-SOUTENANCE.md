# 08 — FAQ de soutenance

Questions/réponses anticipées pour la sécurité du projet. Deux parties :
**conceptuel** (comprendre les fondements) et **dépannage** (problèmes concrets).

---

## Partie A — Questions conceptuelles

### A1. Pourquoi les bandes ISM ?
Les bandes **ISM** (*Industrial, Scientific, Medical* : 433/868/915 MHz, 2,4 GHz, 5 GHz…)
sont ouvertes à des usages **sans licence individuelle**, sous conditions de puissance et
de *duty cycle*. C'est pourquoi la plupart des objets sans fil grand public et
industriels (WiFi, BLE, LoRa, télécommandes, capteurs) s'y concentrent. Auditer ces
bandes, c'est couvrir l'essentiel des communications RF d'un site.

### A2. Qu'est-ce que le « mode moniteur » ?
C'est un mode de la carte WiFi (ici l'**ALFA 2,4 GHz**, chipset RTL8812AU) où elle
**capture toutes les trames 802.11** présentes dans l'air, y compris les trames de
gestion (beacons, probe, deauth), **sans être associée** à un réseau. Indispensable à la
reconnaissance passive (`wifi.recon`, `wifi.frame_dissector`). L'**injection** (émettre
des trames) est une capacité distincte, requise par les modules WiFi actifs.

### A3. Comment fonctionne le HackRF et pourquoi `hackrf_sweep` ?
Le HackRF One est un **SDR demi-duplex** (1 MHz–6 GHz, bande instantanée ~20 MHz). Pour
observer une large plage, `hackrf_sweep` **retune** rapidement par pas et fournit une
densité spectrale. On le préfère à une capture IQ continue (`hackrf_transfer`) qui peut
**caler** à fort débit (USB 2.0, VM, hub non alimenté). Voir
[05 — Spectre HackRF](05-SPECTRE-HACKRF.md).

### A4. Quelle différence entre OTAA et ABP en LoRaWAN ?
- **OTAA** (*Over-The-Air Activation*) : l'appareil **rejoint** le réseau dynamiquement
  (Join Request/Accept) ; les clés de session sont **dérivées** à chaque jonction. Plus
  sûr (renouvellement des clés, anti-rejeu si DevNonce unique).
- **ABP** (*Activation By Personalization*) : les clés de session sont **pré-provisionnées
  en dur** dans l'appareil. Plus simple mais plus fragile : si la **validation du
  compteur de trames (FCnt)** est désactivée, un **rejeu d'uplink** devient possible
  (c'est ce que démontre `lora.uplink_replay_abp`).
- **Remédiation** : préférer OTAA, activer la validation FCnt, utiliser des clés uniques.

### A5. Qu'est-ce que MITRE ATT&CK et pourquoi l'utiliser ?
C'est une **base de connaissances publique** des techniques d'attaquants, identifiées par
des codes `Txxxx`. SRT **étiquette** chaque module avec ses techniques (ex. `T1040`
*Network Sniffing*, `T1557` *Adversary-in-the-Middle*). Avantages : vocabulaire commun,
**couverture** mesurable dans les rapports, et alignement avec la *Cyber Kill Chain*
(Reconnaissance → Initial Access).

### A6. Pourquoi TimescaleDB plutôt que PostgreSQL « simple » ?
Les données de SRT sont des **séries temporelles** (en-têtes de trames, signaux,
positions, alertes). TimescaleDB (extension PostgreSQL) ajoute les **hypertables**
(partitionnement temporel automatique), des **agrégats continus** et des **politiques de
rétention**, tout en gardant le **SQL standard** et la compatibilité Grafana. On garde la
puissance de PostgreSQL (JSONB, index GIN) avec des performances temporelles.

### A7. Pourquoi ne stocker que les **en-têtes** (pas les payloads) ?
La table `headers` est **sans charge utile** par conception : on stocke les métadonnées
(protocole, source/destination, canal, fréquence, RSSI…) mais pas le contenu. C'est un
choix de **respect de la vie privée** (pertinent pour un audit RGPD/sécurité) et de
sobriété de stockage.

### A8. Comment la sécurité est-elle appliquée dans le code ?
Trois mécanismes combinés (voir [02 — Architecture](02-ARCHITECTURE.md) §6) :
1. **Autorisation** (`safety.load_authorization`) : lue depuis un fichier ; **invalide**
   si gabarit non rempli (`signed_by` commençant par `<`).
2. **Coupe-circuit** : `SRT_KILLSWITCH=1` force « non autorisé » immédiatement.
3. **Liste blanche** des cibles + **`precheck`** des modules : tout module `> passive`
   est **refusé** sans autorisation, tout `FORBIDDEN` est refusé d'office. La plateforme
   web ajoute une garde (HTTP 403) avant toute exécution réelle non passive.

### A9. Pourquoi la liste blanche doit-elle être *fail-closed* ?
**Fail-closed** = « tout ce qui n'est pas explicitement autorisé est refusé ». C'est le
principe de sécurité par défaut : il garantit qu'on **ne peut pas agir** sur une cible
non listée, même par erreur. Les entrées génériques (`ANY-*`) ou une bascule
« ne pas exiger la correspondance » sont des **contournements** à proscrire : elles
transforment la liste blanche en liste blanche « vide de sens ». La documentation
recommande de **renforcer** ce comportement (exiger une correspondance), jamais de
l'affaiblir.

### A10. Quelles sont les limites du scoring de menace de la cartographie ?
Le score (0–100) est une **heuristique d'aide à la priorisation**, pas un verdict :
pondérations non calibrées, classification d'« affiliation » non fiable à partir du seul
signal RF, sensibilité aux faux positifs de classification, dépendance à une localisation
souvent imprécise (un seul HackRF). **Conclusion** : il sert à **trier l'attention** de
l'analyste ; toute alerte exige une **validation humaine**. Voir
[04 — Cartographie](04-CARTOGRAPHIE.md) §6.

### A11. La localisation est-elle vraiment précise ?
Avec **un seul récepteur** (un HackRF), non : TDOA et AoA supposent **plusieurs
récepteurs synchronisés**, et le RSSI est très sensible à l'environnement. La
localisation est donc **indicative** ; la cartographie vaut surtout comme outil
d'**inventaire et de priorisation**, pas de géolocalisation métrique. C'est une limite à
assumer clairement.

### A12. Cadre légal et éthique d'une évaluation en cage de Faraday ?
Hors cadre autorisé, émettre/intercepter sur ces bandes peut violer la loi (Code pénal
art. 323-1 et s., CPCE, réglementation ANFR/ARCEP). SRT impose donc :
- opération en **cage de Faraday** (aucune fuite RF, aucune interférence externe),
- **autorisation écrite** couvrant la date et la bande,
- **liste blanche** des cibles consenties,
- **coupe-circuit** accessible, **journaux** comme preuves.
Voir `docs/legal-scope.md`. La plateforme **n'est pas** destinée aux infrastructures de
production ni aux cibles non consenties.

### A13. Pourquoi MQTT ?
MQTT (broker **Mosquitto**) est un protocole **publish/subscribe** léger, idéal comme
**bus d'événements temps réel** : les modules publient des en-têtes/alertes/résultats sur
des topics (`srt/headers/#`, `srt/alerts/#`, `srt/results/#`), et le pont web les relaie
en WebSocket vers le navigateur. Découplage propre entre producteurs et consommateurs.

### A14. Que fait exactement un module passif vs actif ?
- **Passif** : **réception/analyse seulement**, aucune émission (ex. `wifi.recon`,
  `lora.recon`, `spectrum.sweep`, toutes les analyses). Sans risque RF.
- **Actif** (`active-lab`) : **émet/interagit** (ex. `wifi.deauth`, `lora.uplink_replay_abp`).
  Soumis à autorisation + liste blanche + cage de Faraday.
- **Destructif** (`destructive-lab`) : peut dégrader une cible (ex. brouillage) ;
  **hors périmètre** de cette documentation au-delà du catalogue.

### A15. Pourquoi `python -m srt.cli.main` plutôt que `srt` ?
Le projet expose une commande `srt`, mais il existe **un autre paquet PyPI nommé `srt`**.
Pour éviter tout conflit de résolution, l'équipe invoque la CLI **par le module** :
`python -m srt.cli.main …`. Voir [01 — Installation](01-INSTALLATION.md) §B.2.

### A16. Quel matériel est réellement utilisé ?
**HackRF One** (SDR : spectre + LoRa), **ALFA 2,4 GHz** (WiFi mode moniteur/injection,
2,4 GHz uniquement), **passerelle LoRa Dragino LG308N** (→ ChirpStack), **Raspberry Pi**
(calcul + **BLE via `hci0`**). Aucun autre matériel n'est supposé présent.

### A17. Comment la passerelle Dragino s'intègre-t-elle à ChirpStack ?
La LG308N remonte ses paquets en **Semtech UDP** (port **1700**). Un service
**`chirpstack-gateway-bridge`** écoute cet UDP et le convertit en **MQTT**, que
**ChirpStack** consomme (région **EU868**). Voir
[01 — Installation](01-INSTALLATION.md) §A.4.

### A18. Comment lancer une démo sûre devant le jury ?
Utiliser un scénario **100 % passif** : `recon_multi_protocol` ou `survey_spectral`, ou la
plateforme web (`POST /api/cartography/scan`, qui fonctionne en simulation sans matériel).
Réserver les scénarios actifs à la cage de Faraday, ou les montrer en **`dry_run`**.

---

## Partie B — Dépannage (troubleshooting)

### B1. ChirpStack redémarre en boucle / erreur de migration
Cause fréquente : l'extension **`pg_trgm`** manque dans la base `chirpstack`. Créez
`infra/chirpstack/postgres-init/01-extensions.sql`
(`CREATE EXTENSION IF NOT EXISTS pg_trgm;`) et montez-le dans `chirpstack-postgres`. Si la
base existait déjà, créez l'extension manuellement
(`docker exec -it srt-chirpstack-postgres psql -U chirpstack -d chirpstack -c "CREATE EXTENSION IF NOT EXISTS pg_trgm;"`)
ou repartez d'un volume vierge. Voir [01 — Installation](01-INSTALLATION.md) §A.2.

### B2. ChirpStack n'arrive pas à se connecter à PostgreSQL au démarrage
Ajoutez un **healthcheck** à `chirpstack-postgres` et un
`depends_on: condition: service_healthy` côté `chirpstack` (comme déjà fait pour
TimescaleDB/Grafana). §A.3.

### B3. La passerelle Dragino n'apparaît pas dans ChirpStack
Vérifiez : (1) le service **`chirpstack-gateway-bridge`** est lancé et expose
**`1700/udp`** ; (2) le `region_eu868.toml` pointe vers `tcp://mosquitto:1883` ; (3) la
LG308N est en mode **Semtech UDP / Packet Forwarder** et pointe vers l'IP de l'hôte
(port 1700) ; (4) la passerelle est enregistrée avec son **Gateway EUI** dans ChirpStack.

### B4. Grafana redémarre en boucle / ne peut pas écrire
Permissions du volume : `sudo chown -R 472:472 infra/volumes/grafana` **avant** le
démarrage (UID/GID Grafana = 472). §A.5.

### B5. `srt` lance le mauvais programme / `ModuleNotFoundError`
Conflit avec le paquet PyPI `srt`. Utilisez **`python -m srt.cli.main`**, et vérifiez
`which srt` / l'absence de l'autre paquet dans le venv. §B.2.

### B6. `hackrf_info` ne voit pas le HackRF (ou ALFA absente) en VM
Activez le **passage USB** vers la VM (USB passthrough). Vérifiez aussi l'alimentation
(hub USB **alimenté** pour ALFA + HackRF). §D.

### B7. Le balayage HackRF cale / pertes d'échantillons
À fort débit, `hackrf_transfer` peut **stall**. Pour le spectre, utilisez
**`hackrf_sweep`** (c'est ce que fait `spectrum.sweep`). Réduisez le débit / la résolution
si besoin (`bin_width_hz`). §D.2 et [05 — Spectre HackRF](05-SPECTRE-HACKRF.md).

### B8. L'ALFA ne passe pas en mode moniteur
Vérifiez le pilote `rtl8812au`, le nom d'interface (`config/hardware.yaml`), et créez
l'interface moniteur (ex. `wlan1mon`). Rappel : l'ALFA de l'équipe est **2,4 GHz** — ne
configurez pas de canaux 5 GHz inexistants pour ce matériel.

### B9. La plateforme web affiche « DISCONNECTED » / pas de données temps réel
Le broker MQTT n'est probablement pas joignable : le pont
**MQTT → WebSocket** échoue silencieusement. Vérifiez que `mosquitto` tourne (port 1883)
et relancez. La cartographie en **mode simulation** (via `POST /api/cartography/scan`)
fonctionne même sans MQTT.

### B10. Un module non passif renvoie HTTP 403 sur l'API
C'est **voulu** : l'autorisation n'est pas valide. Renseignez une autorisation réelle
(`authorization/authorization.yaml`, `signed_by` non placeholder) **et** assurez-vous que
`SRT_KILLSWITCH` n'est pas à `1`. En dehors de la cage, restez en `dry_run`.

### B11. Un module renvoie `refused`
`precheck` a refusé : soit risque `FORBIDDEN`, soit module `> passive` sans autorisation.
Vérifiez l'état via `python -m srt.cli.main info`.

### B12. `selftest` échoue
`python -m srt.cli.main selftest` sonde SDR + base + sécurité. Code retour ≠ 0 = au moins
une sonde a échoué. Vérifiez : pile Docker démarrée (TimescaleDB), HackRF détecté,
autorisation lisible.

### B13. Aucun module n'apparaît (`list` vide / `/api/modules` vide)
L'**autodiscovery** n'a pas tourné ou un import a échoué. Le registre importe
`srt.recon`, `srt.exploit`, `srt.analysis` (+ modules importés ailleurs) ; les échecs
d'import sont journalisés. Lancez `python -m srt.cli.main list` et lisez les avertissements.

### B14. Le scénario échoue dès le premier step
Probable `module` introuvable (faute de frappe) ou `bail_on_fail: true`. Vérifiez le nom
exact via `python -m srt.cli.main list`, ou passez `bail_on_fail: false` pour les
scénarios de couverture.
