import json, time

old = {}
for attempt in range(10):
    try:
        with open('/Users/mac/Desktop/RR02/radar_data.json') as f:
            d = json.load(f)
        visible = [p for p in d['players'] if p['x']!=0 or p['z']!=0]
        changed = False
        for p in visible:
            k = p['sid']
            np = (p['x'], p['z'])
            if k in old and old[k] != np:
                ox, oz = old[k]
                print(f"  CHANGED! {p['name']}: ({ox:.1f},{oz:.1f}) -> ({p['x']:.1f},{p['z']:.1f})")
                changed = True
            old[k] = np
        if not changed and attempt > 0:
            print(f"[{attempt}] No change ({len(visible)} players)")
        elif attempt == 0:
            print(f"[0] Baseline: {len(visible)} players with pos")
    except Exception as e:
        print(f"[{attempt}] Error: {e}")
    time.sleep(2)