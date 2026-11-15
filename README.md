# LuckyKiller

Outil Windows de **détection, neutralisation et blocage** de l'infection **Luckyware** (RAT / infostealer diffusé via des projets Visual Studio piégés).

Il scanne les disques, identifie les fichiers infectés (exécutables patchés, projets `.vcxproj` modifiés, en-têtes SDK empoisonnés, sources ImGui obfusquées), nettoie ce qui peut l'être, supprime les droppers, tue les processus malveillants et bloque l'infrastructure C2 au niveau du fichier `HOSTS` et du pare-feu Windows.

> ⚠️ **Usage strictement personnel et défensif.** À lancer uniquement sur une machine que tu possèdes ou pour laquelle tu as une autorisation écrite. L'outil modifie des fichiers système (HOSTS, pare-feu), patche des binaires et supprime des fichiers : **aucune sauvegarde n'est créée automatiquement**.

---

## Sommaire

- [Fonctionnalités](#fonctionnalités)
- [Domaines C2 bloqués](#domaines-c2-bloqués)
- [Adresses IP bloquées](#adresses-ip-bloquées)
- [Processus malveillants ciblés](#processus-malveillants-ciblés)
- [Ce que le scanner détecte](#ce-que-le-scanner-détecte)
- [Ce que le nettoyage fait concrètement](#ce-que-le-nettoyage-fait-concrètement)
- [Utilisation](#utilisation)
- [Prérequis et installation](#prérequis-et-installation)
- [Ce que l'outil modifie sur le système](#ce-que-loutil-modifie-sur-le-système)
- [Annuler les modifications](#annuler-les-modifications)
- [Limites et faux positifs](#limites-et-faux-positifs)
- [Structure du code](#structure-du-code)
- [Avertissement](#avertissement)

---

## Fonctionnalités

- 🔍 **Scan multi-disques** — parcourt tous les lecteurs présents (`C:` → `Z:`) ou un dossier précis, en multithread (4 × nombre de cœurs).
- 🧬 **Détection multi-couches** — signature PE, projets Visual Studio, en-têtes SDK, sources ImGui, clé XOR, règles YARA.
- 🧹 **Nettoyage automatique** — suppression ciblée des lignes/injections malveillantes plutôt que destruction du fichier entier quand c'est réparable.
- 💀 **Suppression des droppers** — fichiers à nom chrono dans `%TEMP%`, `%TMP%`, `%LOCALAPPDATA%\Temp`, `%APPDATA%`.
- 🛑 **Blocage réseau** — 23 domaines C2 + 2 IP injectés dans le fichier `HOSTS`, règles de pare-feu sortantes, purge du cache DNS.
- ⚔️ **Neutralisation des processus** — `taskkill /F` sur les processus Luckyware connus.
- 🧪 **Mode simulation** — affiche ce qui serait détecté/supprimé sans toucher à rien.
- 📊 **Rapport final** — progression en temps réel, débit (fichiers/s), ETA, liste des fichiers infectés par catégorie avec l'action effectuée.

---

## Domaines C2 bloqués

Ces 23 domaines sont ajoutés au fichier `HOSTS` avec l'adresse `0.0.0.0`, ce qui les rend inaccessibles :

| # | Domaine | # | Domaine |
|---|---------|---|---------|
| 1 | `i-like.boats` | 13 | `vcc-library.uk` |
| 2 | `powercat.dog` | 14 | `luckyware.co` |
| 3 | `devruntime.cy` | 15 | `luckyware.cc` |
| 4 | `zetolacs-cloud.top` | 16 | `luckyware.pw` |
| 5 | `frozi.cc` | 17 | `dhszo.darkside.cy` |
| 6 | `exo-api.tf` | 18 | `risesmp.net` |
| 7 | `nuzzyservices.com` | 19 | `luckystrike.pw` |
| 8 | `darkside.cy` | 20 | `krispykreme.top` |
| 9 | `balista.lol` | 21 | `vcc-redistrbutable.help` |
| 10 | `phobos.top` | 22 | `i-slept-with-ur.mom` |
| 11 | `phobosransom.com` | 23 | `luckyware.queenmc.pl` |
| 12 | `pee-files.nl` | | |

**Lignes ajoutées au HOSTS :**

```text
0.0.0.0 i-like.boats
0.0.0.0 powercat.dog
0.0.0.0 devruntime.cy
0.0.0.0 zetolacs-cloud.top
0.0.0.0 frozi.cc
0.0.0.0 exo-api.tf
0.0.0.0 nuzzyservices.com
0.0.0.0 darkside.cy
0.0.0.0 balista.lol
0.0.0.0 phobos.top
0.0.0.0 phobosransom.com
0.0.0.0 pee-files.nl
0.0.0.0 vcc-library.uk
0.0.0.0 luckyware.co
0.0.0.0 luckyware.cc
0.0.0.0 luckyware.pw
0.0.0.0 dhszo.darkside.cy
0.0.0.0 risesmp.net
0.0.0.0 luckystrike.pw
0.0.0.0 krispykreme.top
0.0.0.0 vcc-redistrbutable.help
0.0.0.0 i-slept-with-ur.mom
0.0.0.0 luckyware.queenmc.pl
```

> Les doublons sont ignorés : le script compte uniquement les domaines réellement absents du `HOSTS`.

---

## Adresses IP bloquées

Deux règles de pare-feu **sortantes** sont créées via `netsh advfirewall` (nommées `LUCKYKILLER_BLOCK_<ip>`) :

| IP | Règle pare-feu |
|----|----------------|
| `91.92.243.218` | `LUCKYKILLER_BLOCK_91_92_243_218` |
| `188.114.96.11` | `LUCKYKILLER_BLOCK_188_114_96_11` |

Une purge du cache DNS est effectuée à la fin (`ipconfig /flushdns`).

---

## Processus malveillants ciblés

| Processus | Action |
|-----------|--------|
| `Berok.exe` | `taskkill /F /IM` |
| `Retev.exe` | `taskkill /F /IM` |
| `Zetolac.exe` | `taskkill /F /IM` |
| `HPSR.exe` | `taskkill /F /IM` |

---

## Ce que le scanner détecte

### Fichiers analysés

| Extension | Traitement |
|-----------|-----------|
| `.exe`, `.dll` | Analyse PE + règles YARA |
| `.vcxproj`, `.csproj` | Événements de build malveillants |
| `.suo` | Clé XOR cachée dans les options Visual Studio |
| `.h`, `.hpp` | Empoisonnement d'en-têtes SDK |
| `.cpp` | Sources ImGui / code obfusqué |

Fichiers ImGui traités en priorité : `imgui_impl_win32.cpp`, `imgui_impl_win32.h`, `imgui.cpp`, `imgui_widgets.cpp`, `imgui_draw.cpp`.

### Techniques de détection

| # | Cible | Signature détectée | Catégorie du rapport |
|---|-------|--------------------|----------------------|
| 1 | PE (`.exe`, `.dll`) | Section au nom commençant par `.rcd` **sauf** `.rcdata` (ex. `.rcdat`) : section injectée typique des copies patchées. L'entropie et le bit exécutable sont affichés. | `Infection PE` |
| 2 | PE (`.exe`, `.dll`) | Plusieurs en-têtes `MZ` dans un même binaire → exécutable « dropper » qui embarque une charge. | `Infection PE` |
| 3 | `.vcxproj`, `.csproj` | `powershell -WindowStyle Hidden`, `iwr -Uri`, `cmd.exe /b /c`, `cmd.exe /c /b`, `Invoke-WebRequest` (insensible à la casse). | `Infection VCXPROJ` |
| 4 | `.suo` | Octets `NtExploreProcess` (clé XOR) dans les 4 premiers Ko. | `Détournement SUO` |
| 5 | Sources / ImGui | Blob hexadécimal obfusqué : `std::string Fxxxxx = "\x..\x..…"` (≥ 20 octets échappés). | `Infection ImGui` |
| 6 | Sources / ImGui | Combinaison blob + `system(<identifiant>)` ou blob + clé XOR → dropper généré à la compilation. | `Infection ImGui` |
| 7 | Sources (hors chemins bruyants) | Clé XOR `NtExploreProcess` seule. | `Infection source` |
| 8 | En-têtes `.h` / `.hpp` | `namespace VccLibaries`, `namespace SDKInfector`, `Bombakla`, `Rundollay`, `InfectSDK`, `InfectINIT`. | `Empoisonnement SDK` |
| 9 | `%TEMP%`, `%TMP%`, `%LOCALAPPDATA%\Temp`, `%APPDATA%` | Noms de fichiers de type `^[A-Z]{2,3}\d{10,13}(\.exe)?$` (ex. `AB1234567890123.exe`). | `Dropper Temp` |
| 10 | Tous les fichiers ciblés | 5 règles YARA : `Luckyware_C2`, `Luckyware_XOR_Key`, `Luckyware_SDK`, `Luckyware_BuildEvent`, `Luckyware_ImGui`. | `YARA` |

La détection YARA (ainsi que la lecture PE fine) est **optionnelle** : elle est active si `yara-python` / `pefile` sont installés.

### Chemins ignorés

- Dossiers : `quarantine`, `luckykiller`, `.git`, `node_modules`, `__pycache__`, `.vs`
- Fragments de chemin : `\Windows Kits\`, `\Microsoft Visual Studio\`, `\Qt\Tools\`, `\Qt\Examples\`, `\PySide`, `\Luau\CLI\`

Ces exclusions évitent de traiter les faux positifs liés aux SDK officiels (qui contiennent eux aussi des `system()` et des en-têtes de namespace).

> Nuance importante : `\Windows Kits\` est exclu du parcours général, mais une passe dédiée (`_scan_windows_sdk`) analyse quand même ses en-têtes `.h` / `.hpp` — c'est précisément là que l'infection SDK dépose son `namespace VccLibaries`. Seule la détection « clé XOR / blob hexadécimal » est désactivée sur ces chemins.

---

## Ce que le nettoyage fait concrètement

| Cas détecté | Action |
|-------------|--------|
| Section PE `.rcd*` / MZ multiples | **Patch du PE** : le bit exécutable (`0x20000000`) des sections `.rcd*` est retiré, le binaire reste utilisable mais la charge ne peut plus s'exécuter. |
| Lignes malveillantes dans `.vcxproj` / `.csproj` | **Suppression des lignes** contenant les commandes de build malveillantes (le reste du projet est conservé). |
| Fichier `.suo` infecté | **Effacement sécurisé** : le fichier est rempli d'octets nuls puis supprimé (Visual Studio le régénère). |
| Blob hexadécimal / `system()` dans les sources | **Remplacement** des motifs par le commentaire `/* LUCKYKILLER_REMOVED */`. |
| En-tête SDK empoisonné | **Suppression de la seule ligne injectée**, en conservant l'en-tête d'origine. |
| Dropper dans les dossiers temporaires | **Effacement sécurisé** (zéros + suppression). |

Chaque action est journalisée et affichée dans le rapport final, avec une couleur : vert = action appliquée, jaune = échec ou simulation.

---

## Utilisation

```powershell
python luckykiller.py
```

Le script demande l'élévation UAC au démarrage (relance automatique via `ShellExecuteW` avec `runas`).

### Menu

| Option | Libellé | Effet |
|--------|---------|-------|
| `1` | Scan complet + suppression auto + blocage C2 | Analyse tous les disques, nettoie, tue les processus, bloque le réseau (**recommandé**) |
| `2` | Scan complet seulement | Détecte et affiche le rapport, **aucune** modification |
| `3` | Bloquer seulement les domaines et IP C2 | Met à jour `HOSTS` + règles de pare-feu, sans scan |
| `4` | Tuer seulement les processus Luckyware | `taskkill` sur les 4 processus connus |
| `5` | Analyser un dossier précis | Choix du dossier, puis avec ou sans suppression |
| `6` | Simulation (aperçu seulement) | Montre les détections et les actions prévues, sans rien écrire |

Pendant le scan, l'interface affiche :

```text
  [██████████████░░░░░░░░░░]   42.7%   100 231/234 522   612 f/s   Reste 0:03:39   menaces : 2

  Fichiers infectés :
    • C:\Jeux\MonProjet\bin\Release\client.exe
```

---

## Prérequis et installation

```powershell
git clone https://github.com/<ton-compte>/LuckyKiller.git
cd LuckyKiller
pip install -r requirements.txt
python luckykiller.py
```

| Élément | Détail |
|---------|--------|
| OS | Windows 10 / 11 (utilise `taskkill`, `netsh`, `ipconfig`, API console Win32) |
| Python | 3.9 ou plus récent |
| Droits | Administrateur (élévation automatique au lancement) |
| Dépendances | `pefile`, `yara-python`, `colorama` — **installées automatiquement** via `pip` au premier lancement |

Installation manuelle des dépendances (recommandé — voir `requirements.txt`) :

```powershell
pip install -r requirements.txt
```

> Équivalent sans le fichier : `pip install pefile yara-python colorama`.
>
> Le script exécute `pip install` **sans demander confirmation** au démarrage. Si tu ne veux pas de ça, installe les trois paquets toi-même avant le premier lancement.

Aucun fichier de configuration : les listes de domaines, IP et processus sont en haut du script (`C2_DOMAINS`, `C2_IPS`, `MALICIOUS_PROCESSES`).

---

## Ce que l'outil modifie sur le système

Transparence complète, parce que ce sont des changements persistants :

| Élément | Emplacement / commande | Réversible |
|---------|------------------------|-----------|
| Domaines C2 | `C:\Windows\System32\drivers\etc\hosts` (ajout de lignes `0.0.0.0 …`) | Oui, manuellement |
| Règles pare-feu | `netsh advfirewall firewall add rule name=LUCKYKILLER_BLOCK_<ip> dir=out action=block` | Oui, via `netsh` |
| Cache DNS | `ipconfig /flushdns` | Sans objet |
| Processus | `taskkill /F /IM <nom>` | Sans objet |
| Binaires PE | Bit exécutable retiré sur les sections `.rcd*` | Non (patch en place) |
| Projets / sources / en-têtes | Lignes ou motifs malveillants supprimés / commentés | Non |
| Fichiers `.suo` et droppers Temp | Écrasés puis supprimés | Non |

**Aucune sauvegarde ni quarantaine n'est créée.** Avant un scan complet avec suppression, fais une copie de tes projets ou un commit Git : un faux positif sur un `.cpp` retire du code de façon définitive.

---

## Annuler les modifications

**Retirer le blocage HOSTS** — ouvre `C:\Windows\System32\drivers\etc\hosts` en administrateur et supprime les lignes commençant par `0.0.0.0` correspondant aux domaines listés plus haut.

**Retirer les règles de pare-feu :**

```powershell
netsh advfirewall firewall delete rule name="LUCKYKILLER_BLOCK_91_92_243_218"
netsh advfirewall firewall delete rule name="LUCKYKILLER_BLOCK_188_114_96_11"
```

**Restaurer des fichiers nettoyés** — impossible sans sauvegarde. Les sources retouchées contiennent le marqueur `/* LUCKYKILLER_REMOVED */` aux emplacements nettoyés, ce qui permet d'identifier ce qui a été retiré.

---

## Limites et faux positifs

- Les mots-clés `system(` et les namespaces type `Vcc…` existent dans du code légitime : des exclusions de chemins limitent le bruit, mais un faux positif reste possible sur un projet personnel qui implémente `system()` dans une source à la racine d'un disque.
- L'analyse PE ne reconstruit pas un binaire sain : elle neutralise la section injectée. Un exécutable patché peut rester instable → réinstallation du logiciel concerné recommandée.
- Les listes de domaines/IP/processus sont **statiques**. Une nouvelle infrastructure C2 nécessite une mise à jour du script.
- Le scan complet de tous les disques peut durer de plusieurs minutes à plus d'une heure selon le nombre de fichiers (≈ 600 fichiers/s en moyenne).
- L'outil ne désinfecte pas un système noyau compromis : en cas d'infection profonde, une réinstallation propre de Windows reste la seule garantie.

Après nettoyage, un second scan antivirus (Bitdefender, Defender hors ligne, Malwarebytes) est fortement conseillé.

---

## Structure du code

| Élément | Rôle |
|---------|------|
| `_ensure_admin()` | Élévation UAC automatique |
| `install_deps()` | Installation silencieuse de `pefile`, `yara-python`, `colorama` |
| `LuckyKiller` | Classe principale : scan, détection, nettoyage, rapport |
| `LuckyKiller._compile_yara()` | Compilation des 5 règles YARA embarquées |
| `LuckyKiller.block_network()` | `HOSTS` + pare-feu + purge DNS |
| `LuckyKiller._collect_files_with_spinner()` | Collecte multithread des fichiers cibles |
| `LuckyKiller.run()` | Orchestration : processus → blocage → collecte → scan → rapport |
| `_fast_walk()` | Parcours récursif tolérant aux erreurs (dossiers supprimés, accès refusés, liens) |
| `_scan_pe`, `_scan_vcxproj`, `_scan_suo`, `_scan_imgui`, `_scan_sdk_header`, `_scan_yara` | Détecteurs par type de fichier |
| `_patch_pe`, `_clean_vcxproj`, `_wipe_file`, `_clean_imgui`, `_remove_sdk_injection` | Actions de nettoyage |
| `menu()` | Interface du menu principal |

---

## Avertissement

Ce projet est fourni **à des fins de défense et d'analyse**. Il n'embarque aucune charge malveillante, mais il modifie des fichiers système et supprime des fichiers de façon irréversible.

- Ne l'exécute pas sur une machine qui n'est pas la tienne.
- Ne l'utilise pas comme unique remède sur un système en production sans sauvegarde.
- Les noms de domaines, d'exécutables et de familles de malwares sont cités uniquement pour permettre la détection et le blocage.

Aucune garantie n'est fournie quant à l'exhaustivité des détections ou à l'absence de dommage. Utilisation à tes risques.

---

## Licence

Ce projet est distribué sous licence **MIT** — voir le fichier [LICENSE](LICENSE).

Tu peux l'utiliser, le modifier et le redistribuer, y compris commercialement, à condition de conserver l'avis de copyright et la licence. Le logiciel est fourni « tel quel », sans garantie.

```
Copyright (c) 2026 layzen
```
