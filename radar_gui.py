#!/usr/bin/env python3
# RR02 radar GUI - native macOS (tkinter). Reads /tmp/rr02_radar.json.
import json, os, tkinter as tk

JSON_PATH = "/tmp/rr02_radar.json"

class Radar:
    def __init__(self, root):
        self.root = root
        root.title("RR02 Radar")
        root.configure(bg="#0a0a0a")
        root.geometry("700x700")
        self.canvas = tk.Canvas(root, bg="#0a0a0a", highlightthickness=0)
        self.canvas.pack(fill="both", expand=True)
        self.label = tk.Label(root, text="RR02 — en attente...", fg="#0f0", bg="#0a0a0a",
                              font=("Monospace", 11), anchor="w")
        self.label.place(x=8, y=4)
        self.root.after(100, self.update)

    def update(self):
        try:
            if os.path.exists(JSON_PATH):
                with open(JSON_PATH) as f:
                    d = json.load(f)
            else:
                d = None
        except Exception:
            d = None

        self.canvas.delete("all")
        W = self.canvas.winfo_width()
        H = self.canvas.winfo_height()
        if W < 10: W = 700
        if H < 10: H = 700
        cxp, cyp = W // 2, H // 2
        R = min(W, H) * 0.46

        # grid rings
        self.canvas.create_oval(cxp - R, cyp - R, cxp + R, cyp + R, outline="#222", width=1)
        self.canvas.create_oval(cxp - R*0.75, cyp - R*0.75, cxp + R*0.75, cyp + R*0.75, outline="#222", width=1)
        self.canvas.create_oval(cxp - R*0.5, cyp - R*0.5, cxp + R*0.5, cyp + R*0.5, outline="#222", width=1)
        self.canvas.create_oval(cxp - R*0.25, cyp - R*0.25, cxp + R*0.25, cyp + R*0.25, outline="#222", width=1)
        self.canvas.create_line(cxp - R, cyp, cxp + R, cyp, fill="#333", width=1)
        self.canvas.create_line(cxp, cyp - R, cxp, cyp + R, fill="#333", width=1)

        if not d:
            self.label.config(text="RR02 — pas de données (daemon ?)")
            self.root.after(100, self.update)
            return

        L = d.get("local", {"x": 0, "y": 0, "z": 0})
        players = d.get("players", [])
        maxd = 50.0
        for p in players:
            dist = ((p["x"] - L["x"])**2 + (p["z"] - L["z"])**2)**0.5
            if dist > maxd: maxd = dist
        sc = R / maxd

        # local (green)
        self.canvas.create_oval(cxp - 5, cyp - 5, cxp + 5, cyp + 5, fill="#0f0", outline="#0f0")
        self.canvas.create_text(cxp + 8, cyp - 8, text="YOU", fill="#0f0", font=("Monospace", 11))

        # players (red)
        for p in players:
            dx = (p["x"] - L["x"]) * sc
            dz = (p["z"] - L["z"]) * sc
            px, py = cxp + dx, cyp + dz
            self.canvas.create_oval(px - 4, py - 4, px + 4, py + 4, fill="#f33", outline="#f33")

        self.label.config(text=f"RR02 — local ({L['x']:.0f},{L['z']:.0f})  {len(players)} joueurs  R={maxd:.0f}m")
        self.root.after(100, self.update)

if __name__ == "__main__":
    root = tk.Tk()
    Radar(root)
    root.mainloop()
