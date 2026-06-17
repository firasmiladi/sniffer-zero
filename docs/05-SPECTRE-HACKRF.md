# 05 — Spectre : `hackrf_sweep`

Ce chapitre explique comment SRT exploite le **balayage spectral** du HackRF One, depuis
le format CSV brut jusqu'à l'intégration dans la plateforme. Le code de référence est
`src/srt/gnuradio/hackrf_sweep.py` ; le module exposé est
[`spectrum.sweep`](03-MODULES.md#4-module-spectre).

## 1. Pourquoi `hackrf_sweep` ?

Le HackRF One est un SDR **demi-duplex** couvrant 1 MHz – 6 GHz, mais sa bande
instantanée est limitée (~20 MHz). Pour observer une **large plage** (ex. toute la bande
2,4 GHz, ou de 433 à 870 MHz), l'outil **`hackrf_sweep`** retune rapidement le récepteur
par **pas** successifs et fournit une **densité spectrale de puissance** sur toute la
plage.

> **Robustesse (rappel installation).** À fort taux d'échantillonnage, une capture
> continue via `hackrf_transfer` peut **caler** (USB 2.0, VM, hub non alimenté).
> `hackrf_sweep` est nettement plus robuste pour le relevé d'occupation : c'est l'outil
> retenu par SRT.

## 2. Format de sortie CSV

`hackrf_sweep` écrit une ligne CSV par segment de fréquence balayé :

```
date, time, freq_hz_lo, freq_hz_hi, freq_bin_width, num_samples, db_1, db_2, ...
```

| Champ | Sens |
|---|---|
| `date`, `time` | Horodatage (`AAAA-MM-JJ`, `HH:MM:SS[.ffffff]`). |
| `freq_hz_lo` / `freq_hz_hi` | Bornes basse/haute du segment balayé. |
| `freq_bin_width` | Largeur d'un **bin** FFT (Hz). |
| `num_samples` | Nombre d'échantillons utilisés. |
| `db_1, db_2, …` | Puissances (dB) des **bins** successifs à partir de `freq_hz_lo`. |

La fréquence du bin *i* vaut donc : `freq_hz = freq_hz_lo + i × freq_bin_width`.

## 3. Parsing (`parse_sweep_line`)

La fonction `parse_sweep_line` :
1. ignore les lignes vides ou commençant par `#` ;
2. lit le CSV, exige au moins 7 champs ;
3. parse l'horodatage (avec ou sans microsecondes, repli sur `now()`) ;
4. lit `freq_lo`, `freq_hi`, `bin_width` ;
5. à partir de l'index 6, convertit chaque valeur de puissance en un **`SweepBin`**
   (`freq_hz`, `power_db`, `timestamp`).

Les bins de toutes les lignes d'un passage sont rassemblés dans un **`SweepResult`**.

## 4. `SweepResult` : agrégats utiles

| Propriété | Calcul |
|---|---|
| `num_bins` | Nombre total de bins. |
| `peak_power_db` | Puissance **maximale**. |
| `avg_power_db` | Puissance **moyenne**. |
| `noise_floor_db` | **Médiane** des puissances (estimation du plancher de bruit). |
| `to_dict()` | Sérialisation JSON (fréquences en MHz + puissances). |
| `get_band_summary()` | Statistiques **par bande ISM** (voir §5). |

## 5. Classification par bande (`_classify_band`)

Chaque bin est rangé dans une bande nommée selon sa fréquence (MHz) :

| Plage | Nom |
|---|---|
| 433–435 | `ISM_433MHz` |
| 863–870 | `ISM_868MHz` |
| 902–928 | `ISM_915MHz` |
| 2400–2500 | `ISM_2.4GHz` |
| 5150–5350 | `U-NII-1_5.2GHz` |
| 5470–5725 | `U-NII-2_5.5GHz` |
| 5725–5875 | `ISM_5.8GHz` |
| 5925–7125 | `WiFi6E_6GHz` |
| autre | `Other_<MHz>MHz` |

`get_band_summary()` calcule, par bande : fréquences min/max, nombre de bins, **puissance
crête**, **puissance moyenne**, **plancher de bruit** (médiane), et un compteur de
**signaux au-dessus du bruit** (bins dépassant médiane + 10 dB).

## 6. Le wrapper `HackRFSweep`

Paramètres principaux :

| Paramètre | Défaut | Sens |
|---|---|---|
| `freq_start_mhz` / `freq_end_mhz` | 2400 / 2500 | Plage balayée. |
| `bin_width_hz` | 1 000 000 | Largeur de bin FFT (résolution). |
| `lna_gain` | 32 | Gain LNA (0–40, pas de 8). |
| `vga_gain` | 20 | Gain VGA (0–62, pas de 2). |

- `single_sweep()` : exécute `hackrf_sweep -1` (passage unique), parse la sortie, renvoie
  un `SweepResult`. La commande construite est de la forme
  `hackrf_sweep -f <start>:<end> -w <bin> -l <lna> -g <vga> [-1]`.
- `start_continuous(callback, duration_s)` / `stop()` : balayage **continu** en thread ;
  un nouveau passage est détecté quand la fréquence « repart » au début.
- **Mode simulation** : si `hackrf_sweep` est absent du PATH (ou timeout/erreur), le
  wrapper génère un spectre **synthétique** réaliste (plancher de bruit ≈ −85 dBm,
  signaux WiFi sur canaux 1/6/11, BLE sur 2402/2426/2480, LoRa autour de 868 MHz). Cela
  permet de **démontrer** la chaîne sans matériel.

## 7. Intégration dans la plateforme

### Module `spectrum.sweep`
Le module passif (`src/srt/recon/spectrum_sweep.py`) :
- valide la plage en `precheck` (1–6000 MHz, début < fin) ;
- exécute un sweep unique (si `duration_s ≤ 0`) ou continu ;
- agrège les passages (bins, crête, plancher), **classe les bandes**, compte les signaux
  au-dessus du bruit ;
- **publie** chaque résultat sur MQTT (`srt/spectrum/sweep`) et en **WebSocket**
  (`spectrum_update`) ;
- renvoie un `AttackResult` avec métriques et un artefact `spectrum_data`.

### API web (`/api/spectrum/*`)
| Endpoint | Rôle |
|---|---|
| `POST /api/spectrum/sweep?freq_start_mhz=…&freq_end_mhz=…` | Déclenche un sweep (en thread), renvoie le spectre + diffuse `spectrum_update`. |
| `GET /api/spectrum/live` | Dernier spectre en mémoire. |
| `GET /api/spectrum/bands` | Occupation par bande (résumé du dernier sweep). |
| `GET /api/spectrum/history?limit=N` | Historique des derniers sweeps (50 max). |

## 8. Comment lire un résultat de spectre / d'occupation

Quelques repères de lecture pour la soutenance :

- **Plancher de bruit** : niveau « de fond » (médiane). Un signal réel est nettement
  au-dessus (le code retient « > bruit + 10 dB »).
- **Puissance crête** : le pic le plus fort de la bande — un fort niveau peut indiquer un
  émetteur proche ou puissant.
- **Signals above noise** : densité d'activité ; plus c'est élevé, plus la bande est
  occupée.
- **Occupation par bande** : permet de comparer 2,4 GHz (souvent saturée par le WiFi) à
  868 MHz (LoRa, plus calme) — utile pour expliquer pourquoi tel protocole « souffre »
  d'interférences.
- **Largeur de bin (`bin_width_hz`)** : compromis résolution/vitesse. 1 MHz balaie vite
  mais distingue mal des signaux proches ; 500 kHz (utilisé pour 868/433 MHz dans le
  scénario `survey_spectral`) affine la lecture des canaux LoRa étroits.

Exemple de lecture : un sweep 2400–2500 MHz montrant trois pics marqués autour de 2412,
2437 et 2462 MHz correspond aux **canaux WiFi 1/6/11** ; des pics fins à 2402/2426/2480
MHz évoquent les **canaux d'advertising BLE**.
