#!/usr/bin/env python3
"""
Monitor BB2 radar_data.json for position changes.
Run this, then move in-game. It will show which players' positions change.
"""
import json, time

old = {}
print("=== Position Monitor ===")
print("Bouge-toi en jeu ! Monitoring for changes...")
print()

for tick in range(60):  # 60 seconds
    try:
        with open("/Users/mac/Desktop/RR02/radar_data.json") as f:
            d = json.load(f)
        visible = [p for p in d["players"] if p["x"] != 0 or p["z"] != 0]
        changed = False
        for p in visible:
            k = p["sid"]
            np = (round(p["x"], 1), round(p["z"], 1))
            if k in old and old[k] != np:
                ox, oz = old[k]
                dx = np[0] - ox
                dz = np[1] - oz
                dmag = (dx**2 + dz**2)**0.5
                if dmag > 0.5:
                    print(f"  MOVE {p['name']}: ({ox},{oz}) -> ({np[0]},{np[1]}) delta=({dx:+.1f},{dz:+.1f}) {dmag:.1f}m")
                    changed = True
            old[k] = np
        if not changed and tick > 0:
            print(f"[{tick}s] No movement ({len(visible)} players tracked)")
    except Exception as e:
        if tick == 0:
            print(f"  radar_data.json not ready yet")
    time.sleep(1)