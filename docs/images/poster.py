"""Poster for the README: one phone, one capture, split into apps and flows, joined with metadata.
Run: python3 docs/images/poster.py docs/images/poster.svg (deterministic, illustrative data)."""
import math, random, sys
from xml.sax.saxutils import escape as E

W, H = 1200, 730
rnd = random.Random(7)
o = []
SANS = "font-family='-apple-system,Segoe UI,Helvetica,Arial,sans-serif'"
MONO = "font-family='ui-monospace,Menlo,Consolas,monospace'"
APPS = [("Maps", "#4cc38a", ["QUIC :443", "TCP :443"]),
        ("Music", "#f2b84b", ["TCP :443", "TCP :443", "UDP :443"]),
        ("Browser", "#5aa9ff", ["QUIC :443", "TCP :443"]),
        ("Chat", "#c78bff", ["TCP :443"])]
T0, T1 = 520, 1150          # time axis (x) shared by flows and metadata
FLOW_END = 1040             # flows stop here to leave room for their labels


def t(x, y, s, size=13, fill="#cfd8e6", weight=400, anchor="start", font=SANS, extra=""):
    o.append(f"<text x='{x}' y='{y}' font-size='{size}' font-weight='{weight}' fill='{fill}' text-anchor='{anchor}' {font} {extra}>{E(s)}</text>")


# ---- background and title
o.append("<defs>"
         "<linearGradient id='bg' x1='0' y1='0' x2='1' y2='1'><stop offset='0' stop-color='#0d1b2e'/><stop offset='1' stop-color='#14294a'/></linearGradient>"
         "<linearGradient id='pipe' x1='0' y1='0' x2='1' y2='0'><stop offset='0' stop-color='#2b4a74'/><stop offset='1' stop-color='#3b6aa5'/></linearGradient>"
         "<filter id='glow' x='-50%' y='-50%' width='200%' height='200%'><feGaussianBlur stdDeviation='4' result='b'/><feMerge><feMergeNode in='b'/><feMergeNode in='SourceGraphic'/></feMerge></filter>"
         "</defs>")
o.append(f"<rect width='{W}' height='{H}' rx='18' fill='url(#bg)'/>")
t(40, 64, "MiniPcap", 42, "#ffffff", 800)
t(232, 64, "Every packet. Every app. In context.", 24, "#8cc4ff", 500)
x = 40
for b in ("No root", "Android 10+", "Wireshark-ready PCAP", "GPS · radio · motion", "Open source · MIT"):
    w = 14 + len(b) * 7.4
    o.append(f"<rect x='{x}' y='84' width='{w}' height='26' rx='13' fill='#1f3a60' stroke='#3b6aa5'/>")
    t(x + w / 2, 102, b, 12.5, "#d9e7fb", 600, "middle")
    x += w + 10

# ---- phone
px, py, pw, ph = 52, 150, 190, 380
o.append(f"<rect x='{px}' y='{py}' width='{pw}' height='{ph}' rx='28' fill='#0a1424' stroke='#6b8bb5' stroke-width='3'/>")
o.append(f"<rect x='{px + 12}' y='{py + 36}' width='{pw - 24}' height='{ph - 60}' rx='10' fill='#122440'/>")
o.append(f"<rect x='{px + pw / 2 - 22}' y='{py + 14}' width='44' height='8' rx='4' fill='#33496b'/>")
for i, (name, col, _) in enumerate(APPS):
    cx = px + 30 + (i % 2) * 80; cy = py + 60 + (i // 2) * 92
    o.append(f"<rect x='{cx}' y='{cy}' width='50' height='50' rx='14' fill='{col}'/>")
    t(cx + 25, cy + 33, name[0], 22, "#0d1b2e", 800, "middle")
    t(cx + 25, cy + 68, name, 12, "#d9e7fb", 500, "middle")
o.append(f"<rect x='{px + 26}' y='{py + 252}' width='{pw - 52}' height='34' rx='17' fill='#e5484d'/>")
t(px + pw / 2, py + 274, "■  Stop logging", 13, "#fff", 700, "middle")
t(px + pw / 2, py + 312, "VPN on the phone", 12, "#8fa6c8", 400, "middle")
t(px + pw / 2, py + 330, "captures all apps", 12, "#8fa6c8", 400, "middle")

# ---- one capture pipe with mixed packets
y0 = 340
o.append(f"<rect x='{px + pw - 4}' y='{y0 - 22}' width='{372 - (px + pw)}' height='44' rx='22' fill='url(#pipe)'/>")
xx = px + pw + 14
while xx < 352:
    col = rnd.choice(APPS)[2 - 1]
    up = rnd.random() < 0.45
    h = rnd.choice((8, 12, 16))
    o.append(f"<rect x='{xx}' y='{y0 - h if up else y0 + 1}' width='5' height='{h}' rx='1.5' fill='{col}' opacity='0.95'/>")
    xx += 9
o.append(f"<line x1='{px + pw + 8}' y1='{y0}' x2='358' y2='{y0}' stroke='#9fb8da' stroke-width='1'/>")
t(305, y0 - 34, "ONE capture · all traffic", 12.5, "#d9e7fb", 700, "middle")
t(305, y0 + 42, "▲ uplink   ▼ downlink", 12, "#9fb8da", 400, "middle")

# ---- splitter
sx, sy = 400, y0
o.append(f"<circle cx='{sx}' cy='{sy}' r='34' fill='#1f3a60' stroke='#8cc4ff' stroke-width='2' filter='url(#glow)'/>")
t(sx, sy - 3, "flow →", 11.5, "#ffffff", 700, "middle")
t(sx, sy + 12, "app", 11.5, "#ffffff", 700, "middle")

# ---- app lanes with flows
lane_y = [168, 252, 346, 430]
for (name, col, flows), ly in zip(APPS, lane_y):
    o.append(f"<path d='M{sx + 34},{sy} C{sx + 70},{sy} {sx + 60},{ly} {T0 - 50},{ly}' fill='none' stroke='{col}' stroke-width='3' opacity='0.85'/>")
    o.append(f"<rect x='{T0 - 52}' y='{ly - 13}' width='86' height='26' rx='13' fill='{col}'/>")
    t(T0 - 9, ly + 5, name, 13, "#0d1b2e", 800, "middle")
    n = len(flows)
    for k, label in enumerate(flows):
        fy = ly + (k - (n - 1) / 2) * 24
        xs = T0 + 48 + rnd.randint(0, 90) * (k > 0)
        xe = FLOW_END - rnd.randint(0, 110) * (k > 0)
        o.append(f"<path d='M{T0 + 34},{ly} C{T0 + 44},{ly} {T0 + 38},{fy} {xs},{fy}' fill='none' stroke='{col}' stroke-width='1.2' opacity='0.6'/>")
        o.append(f"<line x1='{xs}' y1='{fy}' x2='{xe}' y2='{fy}' stroke='{col}' stroke-width='1.2' opacity='0.5'/>")
        xx = xs + 4
        dense = 0.75 if name in ("Maps", "Music") else 0.45
        while xx < xe - 4:
            if rnd.random() < dense:
                up = rnd.random() < 0.4
                h = rnd.choice((3, 5, 8, 9)) if up else rnd.choice((4, 9, 10, 10))
                o.append(f"<rect x='{xx:.1f}' y='{fy - h if up else fy}' width='2.6' height='{h}' fill='{col}'/>")
            xx += 4.4
        t(xe + 8, fy + 4, f"flow {k + 1} · {label}", 10.5, "#9fb8da")

# ---- metadata tracks (same time axis)
my = 500
o.append(f"<rect x='{T0 - 60}' y='{my - 18}' width='{W - T0 + 30}' height='196' rx='12' fill='#0f223d' stroke='#2b4a74'/>")
t(T0 - 44, my + 2, "+ METADATA, timestamped, each source at its own rate", 12, "#8cc4ff", 700)
tracks = [("Position", "#4cc38a"), ("Signal", "#f2b84b"), ("Cell", "#c78bff"), ("Motion", "#5aa9ff")]
ty = [my + 30, my + 68, my + 106, my + 140]
for (lbl, col), yy in zip(tracks, ty):
    t(T0 - 44, yy + 4, lbl, 12, "#d9e7fb", 600)
# position: fixes as dots on a gentle route line
pts = [(T0 + 40 + i * 19, ty[0] + 6 * math.sin(i / 3.2)) for i in range(int((T1 - T0 - 40) / 19))]
o.append("<polyline points='" + " ".join(f"{a:.1f},{b:.1f}" for a, b in pts) + "' fill='none' stroke='#4cc38a' stroke-width='1.5' opacity='0.6'/>")
for a, b in pts:
    o.append(f"<circle cx='{a:.1f}' cy='{b:.1f}' r='2.6' fill='#4cc38a'/>")
# signal: RSRP sparkline with samples
sig, v = [], -90.0
for i in range(46):
    v = max(-118, min(-64, v + rnd.uniform(-5, 5)))
    sig.append((T0 + 40 + i * 13.2, ty[1] + (v + 91) * 0.55))
o.append("<polyline points='" + " ".join(f"{a:.1f},{b:.1f}" for a, b in sig) + "' fill='none' stroke='#f2b84b' stroke-width='1.8'/>")
t(T1 - 2, ty[1] - 10, "RSRP · RSRQ · SINR", 10.5, "#9fb8da", 400, "end")
# cell: serving-cell segments with handovers
segs = [(T0 + 40, 700, "LTE 37", "#7a5bb5"), (700, 815, "LTE 68", "#9a74d6"), (815, 990, "LTE + 5G NSA", "#c78bff"), (990, T1, "LTE 158", "#9a74d6")]
for a, b, name, col in segs:
    o.append(f"<rect x='{a}' y='{ty[2] - 9}' width='{b - a - 3}' height='18' rx='4' fill='{col}'/>")
    t((a + b) / 2, ty[2] + 4, name, 10.5, "#0d1b2e", 700, "middle")
for a in (700, 815, 990):
    t(a - 1.5, ty[2] - 13, "↔", 11, "#e5d4ff", 700, "middle")
# motion: accelerometer wiggle
mpts = [(T0 + 40 + i * 2.5, ty[3] + 7 * math.sin(i * 0.9) * (0.4 + 0.6 * abs(math.sin(i / 23))) + rnd.uniform(-1.5, 1.5))
        for i in range(int((T1 - T0 - 40) / 2.5))]
o.append("<polyline points='" + " ".join(f"{a:.1f},{b:.1f}" for a, b in mpts) + "' fill='none' stroke='#5aa9ff' stroke-width='1.2'/>")

# ---- time cursor and callout
cx = 862
o.append(f"<line x1='{cx}' y1='140' x2='{cx}' y2='694' stroke='#ffffff' stroke-width='1.2' stroke-dasharray='5 4' opacity='0.8'/>")
for yy in (ty[0] + 6 * math.sin((cx - T0 - 40) / 19 / 3.2), ty[2], ty[3]):
    o.append(f"<circle cx='{cx}' cy='{yy:.1f}' r='4' fill='#fff' filter='url(#glow)'/>")
sy_ = min(sig, key=lambda p: abs(p[0] - cx))[1]
o.append(f"<circle cx='{cx}' cy='{sy_:.1f}' r='4' fill='#fff' filter='url(#glow)'/>")
o.append(f"<circle cx='{cx}' cy='{lane_y[0]}' r='5' fill='#fff' filter='url(#glow)'/>")
bx, by = 40, 568
o.append(f"<rect x='{bx}' y='{by}' width='380' height='118' rx='12' fill='#ffffff'/>")
t(bx + 16, by + 26, "One packet, fully explained", 14, "#0d1b2e", 800)
rows = [("16:38:30.506", "DL 1273 B, captured 128 B"), ("App", "Maps · flow 1 (QUIC :443)"),
        ("Radio", "LTE + 5G NSA · RSRP −93 dBm"), ("Position", "fix 2.5 m · 32 km/h · bumps 10 m/s²")]
for i, (k, v) in enumerate(rows):
    t(bx + 16, by + 50 + i * 18, k, 12, "#2f6db5", 700, font=MONO)
    t(bx + 130, by + 50 + i * 18, v, 12, "#1d1d1f", 500)
o.append(f"<path d='M{bx + 380},{by + 100} H{bx + 400} V694 H{cx}' fill='none' stroke='#ffffff' stroke-width='1.2' opacity='0.7'/>")
o.append(f"<circle cx='{cx}' cy='694' r='3' fill='#fff'/>")

t(W - 30, H - 8, "packets: .pcap  ·  measurements and app mappings: .meta  ·  joined by timestamp in the analyzer", 11.5, "#8fa6c8", 400, "end")

svg = (f"<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 {W} {H}' width='{W}' height='{H}' role='img' "
       f"aria-label='MiniPcap: one phone, one capture, split into apps and flows, joined with position, signal, cell and motion data'>\n"
       + "\n".join(o) + "\n</svg>\n")
open(sys.argv[1], "w").write(svg)
