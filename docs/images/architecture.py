import sys
from xml.sax.saxutils import escape as E
W, H = 1000, 760
o = []
FONT = "font-family='-apple-system,Segoe UI,Helvetica,Arial,sans-serif'"
C = {"pkt": ("#e8f1fb", "#2f6db5"), "meta": ("#eaf6ec", "#2e8b4a"), "post": ("#fdf1e3", "#c46f12"), "ext": ("#f3f3f3", "#777")}

def box(x, y, w, h, lines, kind, bold_first=True, rx=8):
    f, s = C[kind]
    o.append(f"<rect x='{x}' y='{y}' width='{w}' height='{h}' rx='{rx}' fill='{f}' stroke='{s}' stroke-width='1.5'/>")
    n = len(lines); lh = 15
    y0 = y + h / 2 - (n - 1) * lh / 2 + 4.5
    for i, t in enumerate(lines):
        wgt = "600" if (i == 0 and bold_first) else "400"
        size = 13 if i == 0 else 11.5
        col = "#1d1d1f" if i == 0 else "#444"
        o.append(f"<text x='{x + w / 2}' y='{y0 + i * lh}' text-anchor='middle' font-size='{size}' font-weight='{wgt}' fill='{col}'>{E(t)}</text>")

def doc(x, y, w, h, name, sub, kind):
    f, s = C[kind]; c = 12
    o.append(f"<path d='M{x},{y} h{w - c} l{c},{c} v{h - c} h{-w} z' fill='#fff' stroke='{s}' stroke-width='1.5'/>")
    o.append(f"<path d='M{x + w - c},{y} v{c} h{c}' fill='none' stroke='{s}' stroke-width='1.5'/>")
    o.append(f"<text x='{x + w / 2}' y='{y + h / 2}' text-anchor='middle' font-size='13' font-weight='600' font-family='ui-monospace,Menlo,Consolas,monospace' fill='#1d1d1f'>{E(name)}</text>")
    o.append(f"<text x='{x + w / 2}' y='{y + h / 2 + 15}' text-anchor='middle' font-size='11' fill='#444'>{E(sub)}</text>")

def arrow(x1, y1, x2, y2, color="#555", label=None, dash=False):
    d = " stroke-dasharray='4 3'" if dash else ""
    o.append(f"<line x1='{x1}' y1='{y1}' x2='{x2}' y2='{y2}' stroke='{color}' stroke-width='1.6' marker-end='url(#a)'{d}/>")
    if label:
        o.append(f"<text x='{(x1 + x2) / 2}' y='{min(y1, y2) - 6}' text-anchor='middle' font-size='10.5' fill='#555'>{E(label)}</text>")

def lane(y, h, title, sub, kind):
    f, s = C[kind]
    o.append(f"<rect x='10' y='{y}' width='{W - 20}' height='{h}' rx='12' fill='#fff' stroke='{s}' stroke-width='1' stroke-dasharray='6 4'/>")
    o.append(f"<text x='26' y='{y + 24}' font-size='15' font-weight='700' fill='{s}'>{E(title)} <tspan font-weight='400' font-size='12' fill='#555'>{E(sub)}</tspan></text>")

# --- packet path
lane(10, 300, "Packet path", "native C, highest priority; forwarding never waits for logging", "pkt")
Y = 50; h = 60
box(30, Y, 130, h, ["Selected apps", "All / Include / Exclude"], "ext")
box(200, Y, 140, h, ["TUN interface", "VpnService"], "pkt")
box(380, Y, 220, h, ["Engine thread", "lwIP TCP/IP stack + socket relay"], "pkt")
box(640, Y, 140, h, ["Sockets", "protected from the VPN"], "pkt")
box(820, Y, 150, h, ["Network", "Wi-Fi / mobile data"], "ext")
for a, b in ((160, 200), (340, 380), (600, 640), (780, 820)):
    arrow(a, Y + h / 2 - 7, b, Y + h / 2 - 7, "#2f6db5")
    arrow(b, Y + h / 2 + 7, a, Y + h / 2 + 7, "#2f6db5")
Y2 = 160
box(380, Y2, 220, 70, ["Tap (every packet)", "timestamp, direction, lengths,", "IP + transport header (+ payload)"], "pkt")
arrow(490, Y + h, 490, Y2, "#2f6db5")
box(640, Y2, 140, 70, ["Lock-free ring", "preallocated;", "full → drop + count"], "pkt")
arrow(600, Y2 + 35, 640, Y2 + 35, "#2f6db5")
box(820, Y2, 150, 70, ["Writer thread", "adds SLL header,", "1 MiB writes"], "pkt")
arrow(780, Y2 + 35, 820, Y2 + 35, "#2f6db5")
doc(840, 248, 110, 50, "<id>.pcap", "Wireshark", "pkt")
arrow(895, Y2 + 70, 895, 248, "#2f6db5")

# --- metadata path
lane(325, 300, "Metadata path", "Kotlin, independent of the packet path", "meta")
srcs = [["GPS / GNSS", "fused location, satellites"], ["Accelerometer, gyroscope", "all / max rate / threshold"],
        ["Telephony", "technology, cells, RSRP/RSRQ/SINR"], ["Network, Wi-Fi", "transport, RSSI"],
        ["Flow worker", "flow → UID → app"]]
sy = 362; sh = 44; gap = 7
for i, s in enumerate(srcs):
    yy = sy + i * (sh + gap)
    box(30, yy, 220, sh, s, "meta")
    arrow(250, yy + sh / 2, 300, 470 + (i - 2) * 9, "#2e8b4a")
box(300, 420, 170, 100, ["Collectors", "each on its own schedule;", "a record only on new data,", "source timestamps"], "meta")
box(510, 430, 160, 80, ["Record pool + queue", "bounded, no per-sample", "allocation, drops counted"], "meta")
arrow(470, 470, 510, 470, "#2e8b4a")
box(710, 430, 120, 80, ["Writer thread", "binary records,", "flush every 1 s"], "meta")
arrow(670, 470, 710, 470, "#2e8b4a")
doc(855, 445, 115, 50, "<id>.meta", "measurements, apps", "meta")
arrow(830, 470, 855, 470, "#2e8b4a")
fy = 362 + 4 * 51 + 22
o.append(f"<path d='M380,195 H19 V{fy} H30' fill='none' stroke='#888' stroke-width='1.6' stroke-dasharray='4 3' marker-end='url(#a)'/>")
o.append("<text x='34' y='188' font-size='10.5' fill='#555'>each new TCP/UDP flow announced to the flow worker</text>")
o.append("<text x='34' y='212' font-size='10.5' fill='#555'>(5-tuple + first-packet time; no per-packet app data)</text>")

# --- post-processing
lane(640, 110, "Post-processing", "on your computer", "post")
box(30, 680, 220, 52, ["<id>.pcap + <id>.meta", "matched by timestamp"], "ext")
box(300, 680, 260, 52, ["analyzer/mpcanalyze.py", "Python, standard library only"], "post")
box(610, 680, 360, 52, ["Per-packet timeline CSV · context-at", "summary · validate · enriched PCAPNG"], "post")
arrow(250, 706, 300, 706, "#c46f12"); arrow(560, 706, 610, 706, "#c46f12")

svg = f"""<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 {W} {H}' width='{W}' height='{H}' {FONT}>
<defs><marker id='a' viewBox='0 0 10 10' refX='9' refY='5' markerWidth='7' markerHeight='7' orient='auto-start-reverse'><path d='M0,0 L10,5 L0,10 z' fill='context-stroke'/></marker></defs>
<rect width='{W}' height='{H}' rx='14' fill='#ffffff'/>
{chr(10).join(o)}
</svg>
"""
open(sys.argv[1], "w").write(svg)
