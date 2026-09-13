# RR02 — Plan d'exécution (BUILD 24614784, macOS ARM64)

## Cause racine des 6 mois d'échec
RR01 `archive/old_root/esp_engine.cpp` marchait : vtable → scan SID → position par chaîne de ptrs.
RR02 a jeté ça pour du **brute-force float3 à l'aveugle** → pool pollué par props/spawns/animations.
**Filtre SteamID = tueur de bruit à 100%** (seuls les vrais joueurs ont un SID dans la range).

## Preuves déjà établies cette session
- `task_for_pid` OK (root + SIP off).
- Scan SID trouve SELF `76561198984296471 @ 0x1476d0c30` et ENEMY `76561199829570458 @ 0x11af530b0` en 2s.
- Pos locale live trackée `0x16d6cf5e0` = (-311.23,13.35,1530.48) validée user.
- RR01 old_root a la chaîne complète (vtable `0x103e585e0`, SID `+0x6a8`, pos via ptr chains).

## Le plan (exécuté dès que Rust est up)

### Phase 0 — Boot
- Trouver PID `RustClient`, `task_for_pid`.
- Confirmer accès mémoire (read 8 bytes à une addr connue).

### Phase 1 — Auto-dérivation des ancrages (1 fois au démarrage)
1. **Self SID** → scan uint64 range `76561198000000000–76561200000000000` → trouve `self_obj + SID_OFF = self_sid_addr`.
2. **SID_OFF** : pour k=0x600..0x780 step 8, si `r64(candidate_obj + k) == self_sid` → `SID_OFF = k`, `self_obj = sid_addr - k`.
3. **VTable/klass joueur** : `vtable = r64(self_obj+0)` ; `klass = r64(vtable+0)` (obj→vtable→klass).
4. **Local pos offset** : scanner `self_obj+0x100..0x800` pour le float3 inline = pos live connue (lue à `0x16d6cf5e0`). Le offset où `rf==x && rf+4==y && rf+8==z` = `LOCAL_OFF`.
5. **Remote pos chain** : pour l'ENEMY (SID connu), tester chaînes de ptrs : pour off=0x100..0x760 step 8, `ptr=r64(enemy_obj+off)`, puis `rf(ptr+0/+4/+8)` = Vec3 valide proche de local (<2000m) → `REMOTE_OFF` / `REMOTE_PTR_OFF`. Fallback = brute-force tous les ptrs de l'objet.

### Phase 2 — Énumération joueurs (zéro bruit)
- Scan RAM complet pour `uint64 == vtable` (toutes les instances de la classe joueur).
- Pour chaque hit `obj` : lire SID à `obj+SID_OFF`, nom (Unity string à `obj+NAME_OFF`, dérivé comme SID_OFF), pos via Phase 1.
- Rejeter si SID hors range, si pos invalide, si dist > 3000m.

### Phase 3 — Lecture positions
- Local : `rf(self_obj + LOCAL_OFF)` (inline float3, live).
- Distants : `ptr=r64(obj+REMOTE_PTR_OFF); rf(ptr+REMOTE_OFF)`.
- Filtre final : `|x|>5 && |z|>5 && |x|<5000 && y∈[-200,2000] && dist<3000`.

### Phase 4 — Serveur HTTP EMBARQUÉ dans le daemon (1 seul process)
- Le daemon C++ ouvre un socket TCP :8080.
- `GET /radar.html` → sert le HTML (hardcodé en string).
- `GET /data` → sert `radar_data.json` avec headers `no-cache`.
- **Élimine le bug serve.py qui meurt** → plus de process séparé à gérer.

### Phase 5 — radar.html (canvas, robuste)
- `fetch('/data')` toutes les 100ms.
- Local au centre, joueurs en dots relatifs (x-z map), échelle auto (fit max dist / rayon canvas).
- Dist players = `sqrt((px-lx)²+(pz-lz)²)`, filtre distance réglable.
- Affiche "en attente" si data vide. Gère `NaN`/pos nulle.

### Phase 6 — Stabilité
- Re-dériver les ancrages si le scan trouve 0 joueur (respawn change les addresses).
- Scan complet tous les ~3s, lecture positions à 10Hz entre deux scans.
- Garder dernière pos valide si lecture échoue (anti-clignotement).

## Pourquoi ça marchera cette fois
1. **Filtre SteamID** → 0 props/spawns (eux n'ont pas de SID valide).
2. **Auto-dérivation** → survive au changement d'offsets du build 24614784.
3. **Serveur embarqué** → fini les serve.py morts.
4. **Validé sur tes 2 SID** → la méthode est prouvée, pas du théorique.

## Sortie attendue
URL `http://localhost:8080/radar.html` : ta pos live au centre + tous les joueurs du serveur en dots rouges, distances correctes, PAS de point "n'importe quoi".
