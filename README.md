# SRT — Plateforme RF ISM

Plateforme de reconnaissance et cartographie RF pour les bandes ISM (WiFi, Bluetooth, LoRaWAN), à des fins d'évaluation de sécurité en environnement de laboratoire blindé (cage de Faraday).

## Démarrage rapide

```bash
docker compose -f infra/docker-compose.yml up -d
pip install -e ".[dev]"
python -m srt.cli.main web --host 0.0.0.0 --port 8888
Ouvrir http://localhost:8888

Services
Service	URL	Login
Plateforme SRT	http://localhost:8888	—
ChirpStack	http://localhost:8080	admin / admin
Grafana	http://localhost:3000	admin / admin
Matériel
HackRF One — survey spectral 1-6 GHz
ALFA WiFi 2.4 GHz — reconnaissance WiFi (monitor mode)
Passerelle LoRa Dragino LG308N — réception LoRaWAN EU868
Raspberry Pi — plateforme de déploiement (BLE intégré)
Documentation
Voir docs/INDEX.md pour le sommaire complet.

Tests
python -m pytest tests/ --tb=short
