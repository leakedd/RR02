# RR02 — Radar Rust macOS : Transfert Complet (A à Z)

> **À lire intégralement par tout nouvel agent.** Document auto-suffisant.
> **Date :** 2026-08-12 · **Build Rust :** 24614784 · **OS :** macOS Tahoe 26.5.2 ARM64 (M1 Pro)
> **Machine :** MacBook Air M1 · **RAM :** 8GB · **SIP :** DÉSACTIVÉ · **Action :** lecteur root `sudo`

---

## 1. OBJECTIF

Radar temps réel pour Rust (macOS) :
- **Ta position** (local player) → point vert, live, centre de l'écran.
- **Les joueurs distants** → points rouges, positions live.
- **Zéro bruit** (pas de props/spawns/animations/UI).
- **100% externe** : lecture mémoire via `task_for_pid`. **AUCUNE injection.**

Livrable final : un daemon C++ qui lit la mémoire + une GUI (tkinter natif) qui affiche le radar.

---

## 2. CONTRAINTES CLI & FAITS D'ENVIRONNEMENT

- **Mot de passe sudo :** non versionné — fourni par l'opérateur (`printf '%s\n' "$SUDO_PWD" | sudo -S <cmd>`).
- **Compilation C++ :** `c++ -O2 -std=c++17 -o <bin> <src>.cpp`
- **SIP** est **désactivé** → `task_for_pid` fonctionne en root. Le problème n'a JAMAIS été l'accès mémoire.
- **Processus Rust :** nommé `RustClient`, PID trouvé via `proc_listpids`.
- **GameAssembly.dylib path :**
  `/Users/mac/Library/Application Support/Steam/steamapps/common/Rust/RustClient.app/Contents/Frameworks/GameAssembly.dylib`
- **GameAssembly base (build 24614784) :** `0x13308c000` (taille `0x8434000`), trouvée par scan région READ+EXEC.
- **SteamID toi (local) :** `76561198984296471`
- **SteamID ennemi connu (Tinnke) :** `76561198278646202`
- **SteamID ennemi connu (BeenChilling™ぷ) :** `76561199829570458`
- **Ta position de départ :** `(-342.11, 7.48, 1590.95)` approximativement `(-341, 7, 1593)`.

---

## 3. CE QUI MARCHE (VALIDÉ SUR CE BUILD) — NE PAS REFAIRE

| Méthode | Résultat | Statut |
|---|---|---|
| `task_for_pid` + `vm_read_overwrite` | Lecture mémoire | ✅ MARCHE |
| Trouver GameAssembly base | `0x13308c000` | ✅ MARCHE |
| Scan SteamID (uint64 range `76561198000000000–76561200000000000`) | Trouve les vrais joueurs en RAM | ✅ MARCHE (0 faux positifs, ~2s) |
| Position distante `obj + 0x260 → ptr → +0x1a0` | Tinnke = `(-462, 15, 1410)` live | ✅ MARCHE |
| vtable à `obj+0` + klass à `vt+0` (signature objet managé) | Filtre les vrais objets | ✅ MARCHE |

**DÉTAIL IMPORTANT sur la position distante :**
`read_distant(base)` fait :
```cpp
uint64_t p = read<uint64_t>(base + 0x260);
x = read<float>(p + 0x1a0); y = read<float>(p + 0x1a4); z = read<float>(p + 0x1a8);
```
Cela ne fonctionne que pour les joueurs **actuellement rendus** (dans le champ de vision). Pour les autres, `base+0x260` vaut `0`. **Ce n'est PAS un bug** : Rust ne charge que les entités proches. Pour un radar de proximité c'est suffisant.

---

## 4. CE QUI NE MARCHE PAS (6 MOIS d'ÉCHEC — NE JAMAIS REFAIRE)

### ❌ Brute-force float3 (pis-allon historique)
Scanner la RAM pour des triplets float3 → **100% de bruit** (props, spawns, animations, caméra, UI). Tous les pools/containers/ring buffers ont donné "n'importe quoi". **Abandonné pour toujours.**

### ❌ Filtres quantitatifs (y<X, distance<Y, coord non-rondes, vitesse 1.5-15m)
Réduisent le bruit mais ne l'éliminent jamais. Chaque filtre ajouté = nouveau cas bizarre. **Seul le filtrage SteamID/vtable est fiable.**

### ❌ vtable/klass seul pour énumérer les joueurs
Sur macOS ARM64, scanner les objets par vtable directe échoue (layout différent, pointeurs dans le heap).

### ❌ GCHandle table méthode "tonymontana1esh" (forum, déc 2024)
Offsets statiques `game_assembly + 0x56c3fb8`, `+0x5497f00`, `+0x5497ed8`, `+0x549d448` **MORTS** sur 24614784. Scan de la table = 0 résultat. La structure GCHandle il2cpp a changé de layout en 2026. **Ne pas réutiliser ces offsets.**

### ❌ Il2CppDumper sur GameAssembly.dylib
Le dylib est **strippé** (0 symbole il2cpp exporté) et les métadonnées sont **chiffrées** → "Metadata file not found or encrypted".

### ❌ serve.py séparé / serveur HTTP embarqué
`serve.py` crashait silencieusement. GUI tkinter natif choisi à la place (JSON fichier partagé).

---

## 5. CE QU'IL RESTE À FAIRE (LE VRAI BLOCAGE)

### 🎯 Problème #1 : Trouver le LOCAL (ta position) de façon fiable

Le mover-scan (snapshot A → pause 1.5s → snapshot B, garder les float3 qui ont bougé >1m) **échoue** : il choisit parfois un mauvais float (`1545,6,8` au lieu de `-341,7,1593`), ou rien si tu es immobile.

**Piste en cours (à terminer) :** chercher le local par **structure d'objet** — un objet managé (vtable valide à `+0` ET klass valide à `vt+0`) dont une **position inline** (offset ∈ {`0x1c0,0x1c8,0x1d0,0x1d8,0x1e0,0x1e8,0x1f0`}) est proche du seed (`(-341,7,1593)`). Fichier : `/tmp/find_local_fast.cpp`.

**Pourquoi ça marcherait :** le vrai joueur local est un objet managed comme les autres (avec vtable). Les faux floats (UI, caméra, props) n'ont PAS de vtable valide à `+0`, donc ils sont filtrés par construction.

### 🎯 Problème #2 : La GCHandle table / liste complète des joueurs

La méthode moderne (skill il2cpp-macos-re) :
```
Il2CppGetHandle (gchandle_get_target) est universel :
  page_base = handle & ~0x1FFF
  type      = read(page_base + 0x20)
  capacity  = read(page_base + 0x1C)
  bitmap    = read(page_base + 0x10)
  slot      = read(page_base + 0x28)
```
C'est le **schéma à pages d'il2cpp 2025-2026**, plus fiable que la table inline de 2024. **NON TERMINÉ** — c'est la voie prio pour lister TOUS les joueurs (pas juste ceux rendus).

---

## 6. ARCHITECTURE CIBLE / FICHIERS

### 6.1 Daemon C++ : `/Users/mac/Desktop/RR02/src/radar_daemon.cpp`
- Trouve RustClient PID + task_for_pid.
- Énumère les joueurs (scan SID + vtable, chain distante `+0x260→+0x1a0`).
- Trouve le local (mover-scan OU struct-scan).
- Écrit JSON dans `/tmp/rr02_radar.json` 10x/sec (atomique).

**Compilation :**
```bash
cd /Users/mac/Desktop/RR02/src && c++ -O2 -std=c++17 -o radar_daemon radar_daemon.cpp
```
**Lancement :**
```bash
echo '<sudo-pwd>' | sudo -S ./radar_daemon
```

### 6.2 GUI : `/Users/mac/Desktop/RR02/radar_gui.py`
- tkinter natif, lit `/tmp/rr02_radar.json` toutes les 100ms.
- Point vert au centre (toi), points rouges (joueurs).
- Échelle auto (fit max distance / rayon canvas).

**Lancement :**
```bash
cd /Users/mac/Desktop/RR02 && python3 radar_gui.py
```

### 6.3 JSON partagé : `/tmp/rr02_radar.json`
Format :
```json
{"local":{"x":-341.2,"y":7.5,"z":1593.5},"players":[{"id":1,"x":-462,"y":15,"z":1410,"dist":120,"sid":765611...}]}
```

---

## 7. CYCLE DE VALIDATION (FONDAMENTAL — TOUJOURS FAIRE ÇA)

1. Compiler le test/daemon.
2. Lancer avec `sudo`, vérifier le log.
3. **BOUGER en jeu** puis vérifier que la position change en live.
4. **Position réelle connue** : l'utilisateur donne sa position (ex: `(-342, 7, 1590)`). Si le "local" lu ne matche pas ≈ ça → c'est un faux.
5. Vérifier QUE le point bouge avec toi (pas juste "présent").

**⚠️ Test critique anti-faux :** un float statique (UI, spawn, prop) reste figé. Un vrai local bouge quand tu bouges. Ne jamais accepter un local qui ne bouge pas.

---

## 8. OUTILS CRÉÉS (dans `/tmp/`)

| Fichier | Rôle | Statut |
|---|---|---|
| `find_ga.cpp` | Trouve base GameAssembly | ✅ marche (`0x13308c000`) |
| `scan_gchandle.cpp` | Scan GCHandle table (méthode 2024) | ❌ 0 résultat (layout changé) |
| `find_local_fast.cpp` | Cherche local par structure d'objet | ⏳ à compiler/tester |
| `find_local_struct.cpp` | Version lente (timeout) | ⏳ abandonnée pour `_fast` |
| `diag_chain.cpp` | Teste `+0x260→+0x1a0` sur tous les SID | ✅ marche (Tinnke seul) |
| `diag_deep.cpp` | Cherche tous les objets rendus | ✅ marche |

Fichiers projet :
- `/Users/mac/Desktop/RR02/src/radar_daemon.cpp` — daemon v17 (à réparer pour le local)
- `/Users/mac/Desktop/RR02/radar_gui.py` — GUI tkinter (bon, stable)
- `/Users/mac/Desktop/RR02/PLAN_FINAL.md` — plan détaillé (à lire aussi)
- `/Users/mac/Desktop/RR02/PLAN.md` — ancien plan (vtable/SID)
- `/Users/mac/Desktop/RR01/archive/old_root/esp_engine.cpp` — référence RR01 (vtable `0x103e585e0`, SID `+0x6a8`, nom `+0x6c8`, pos locale `+0x178`, chaînes `+0x650→+0x1d8`/`+0x128`, `+0x518→+0x1c0`, `+0x360→+0x164`, statique `+0x1c8`)

---

## 9. RÉFÉRENCES UTILES (FORUM UNKNOWNCHEATS)

- **"[Coding] Rust Reversal, Structs and Offsets"** — thread sticky (26k posts), LA bible. Offsets non-chiffrés sur macOS.
- **"MacOS Rust External ESP w/ Bypass"** (tonymontana1esh) — ESP externe macOS ARM64. Code complet (GCHandle, vtable check, PlayerModel `+0x2c0`→`+0x1d0`). Offsets datés déc 2024 mais **architecture** valable.
- **"Rust Parser"** (ryse933) + **ChaosSDKGenerator** — génère SDK dynamique. Dans `/Users/mac/Downloads/ChaosSDKGenerator_[unknowncheats.me]_/`.
- **"il2cpp-external"** (cloudyfaith/Itsumekoi) — lib externe il2cpp, mais **Windows x64** (émulateur x86-64). Idée bonne, pas portable tel quel sur macOS ARM64.

---

## 10. PLAN D'ACTION RECOMMANDÉ (POUR LE NOUVEL AGENT)

### Étape 1 — Réparer le LOCAL (bloque tout)
1. Lancer `/tmp/find_local_fast.cpp` (compiler + run sudo) pendant que l'utilisateur est à `(-341,7,1593)`.
2. S'il trouve un objet avec position ≈ `(-341,7,1593)` → **c'est le local**. Noter l'offset.
3. Y a-t-il plusieurs candidats ? Prendre celui qui **bouge** en re-testant.
4. Intégrer dans `radar_daemon.cpp` (remplacer le mover-scan fragile).

### Étape 2 — Valider la chaîne distante sur le build
- Tinnke `obj+0x260→+0x1a0` marche. Tester si ça généralise.
- Sinon : implémenter `Il2CppGetHandle` à pages (section 5, Problème #2) pour la liste complète.

### Étape 3 — Assembler le daemon propre
- Local (struct-scan) + joueurs (SID scan + chain distante) + JSON 10Hz.

### Étape 4 — Validation finale
- Bouger en jeu → vert suit.
- Serveur avec au moins 1 adversaire → point rouge apparaît/bouge.
- **Aucun point fixe absurde** = filtre OK.

### Étape 5 — (Option) Héberger son propre serveur Rust
- Utile UNIQUEMENT pour la validation (contrôle total des entités, 2 comptes contrôlables). Ne change PAS le RE client.
- ⚠️ RAM serrée sur 8GB.

---

## 11. PIÈGES À NE JAMAIS REFAIRE (LISTE DE CONTRÔLE)

- [ ] Ne JAMAIS scanner la RAM pour des float3 bruts → toujours bruit.
- [ ] Ne JAMAIS hardcoder des offsets Windows → macOS ARM64 diffère (ex: `PlayerInventory` 0x618 PC vs 0x5B8 Mac).
- [ ] Ne PAS accepter un "local" qui ne bouge pas.
- [ ] Ne PAS utiliser le vtable seul pour énumérer → pointeurs dans heap.
- [ ] Ne PAS utiliser les offsets GCHandle de 2024 (morts).
- [ ] Ne PAS refaire Il2CppDumper (stripé + chiffré).
- [ ] **Seed du local** : si le mover-scan échoue, vérifier que le SEED ≈ position réelle actuelle.

---

## 12. COMMANDES RAPIDES (> copier-coller)

```bash
# Compiler daemon
cd /Users/mac/Desktop/RR02/src && c++ -O2 -std=c++17 -o radar_daemon radar_daemon.cpp
# Lancer daemon (root)
echo '<sudo-pwd>' | sudo -S ./radar_daemon
# Lancer GUI
cd /Users/mac/Desktop/RR02 && python3 radar_gui.py
# Vérifier sortie
cat /tmp/rr02_radar.json
# Vérifier logs
grep -v Password /tmp/rd_*.txt | tail
# Trouver PID Rust + base GA
ps aux | grep -i RustClient | grep -v grep
```

**FIN DU TRANSFERT.** Le projet est mûr : la méthode est trouvée (SID + vtable + struct-scan local), il reste principalement à **réparer le local** (étape 1) puis assembler et valider.