# Documentation SRT — Sommaire général

> **SRT (sniffer-rt)** — Plateforme de reconnaissance et d'évaluation de sécurité RF
> sur les bandes ISM (WiFi / BLE / LoRaWAN), conçue pour un usage **en laboratoire
> blindé autorisé** (cage de Faraday). Ce dossier documentaire accompagne le projet
> fil rouge et la préparation de la soutenance.

Cette documentation a été rédigée pour qu'un coéquipier puisse, **à partir de zéro**,
installer la plateforme, comprendre son architecture du global vers le détail, et
répondre à n'importe quelle question lors de la soutenance.

## Matériel réellement utilisé par l'équipe

| Équipement | Rôle |
|---|---|
| **HackRF One** | SDR pour le balayage spectral large bande et la réception LoRa |
| **ALFA 2,4 GHz** (chipset RTL8812AU) | Adaptateur WiFi mode moniteur / injection, bande 2,4 GHz |
| **Passerelle LoRa Dragino LG308N** | Passerelle LoRaWAN → chaîne ChirpStack |
| **Raspberry Pi** | Plateforme de calcul + Bluetooth intégré (`hci0`) pour le BLE |

> Toute autre référence matérielle éventuellement présente dans d'anciens documents
> du dépôt (capteurs tiers, microcontrôleurs, dongles spécialisés…) **ne fait pas
> partie du périmètre matériel de l'équipe** et ne doit pas être supposée disponible.

## Ordre de lecture conseillé

1. **[00 — Présentation](00-PRESENTATION.md)** — De quoi parle-t-on ? Objectifs, contexte, glossaire.
2. **[01 — Installation](01-INSTALLATION.md)** — Mise en place complète (Docker, paquet Python, plateforme web), avec les pièges réels rencontrés.
3. **[02 — Architecture](02-ARCHITECTURE.md)** — Vue en couches, flux de données, cycle de vie des modules, couche de sécurité, schéma de base de données.
4. **[03 — Modules](03-MODULES.md)** — Référence de tous les modules enregistrés, par protocole.
5. **[04 — Cartographie](04-CARTOGRAPHIE.md)** — Moteur de cartographie RF : détection, classification, localisation, scoring de menace.
6. **[05 — Spectre HackRF](05-SPECTRE-HACKRF.md)** — Fonctionnement du balayage `hackrf_sweep`, format CSV, intégration.
7. **[06 — Scénarios](06-SCENARIOS.md)** — Format YAML et description de chaque scénario livré.
8. **[07 — Plateforme web](07-WEB-PLATFORM.md)** — Interface tactique, API REST, messages WebSocket.
9. **[08 — FAQ soutenance](08-FAQ-SOUTENANCE.md)** — Questions/réponses anticipées (conceptuel + dépannage).

## Documents de référence existants (dépôt)

Ces fichiers étaient déjà présents et restent utiles :

- `docs/architecture.md` — schéma d'architecture historique.
- `docs/legal-scope.md` — **périmètre légal et autorisation (lecture obligatoire)**.
- `docs/attacks/*.md` — catalogues d'attaques (WiFi, WiFi-CVE, BLE, LoRaWAN).
- `docs/HARDWARE-SETUP.md`, `docs/INSTALLATION.md`, `docs/TROUBLESHOOTING.md`.

## Note de cadrage importante

SRT contient des modules **passifs** (écoute/analyse) et des modules **actifs**
(classés `active-lab` ou `destructive-lab`). La présente documentation :

- détaille **en profondeur** le fonctionnement technique des modules **passifs** ;
- traite les modules **actifs** à un niveau **descriptif, pédagogique et défensif**
  (objectif, classe de vulnérabilité, technique MITRE ATT&CK, prérequis,
  classification de risque, **détection et remédiation**), sans fournir de mode
  opératoire offensif ;
- ne documente **pas** la mise en œuvre du brouillage (« jamming ») : les modules
  concernés sont listés au seul niveau catalogue (nom, classe `destructive-lab`,
  technique MITRE, hors périmètre / autorisation spéciale).
