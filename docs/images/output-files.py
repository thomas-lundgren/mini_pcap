import sys
from xml.sax.saxutils import escape as E
W, H = 1000, 225
o = []
MONO = "font-family='ui-monospace,Menlo,Consolas,monospace'"
def doc(x, y, w, h, name, title, lines, f, s):
    c = 16
    o.append(f"<path d='M{x},{y} h{w - c} l{c},{c} v{h - c} h{-w} z' fill='{f}' stroke='{s}' stroke-width='1.5'/>")
    o.append(f"<path d='M{x + w - c},{y} v{c} h{c}' fill='none' stroke='{s}' stroke-width='1.5'/>")
    o.append(f"<text x='{x + 18}' y='{y + 30}' font-size='14' font-weight='700' {MONO} fill='#1d1d1f'>{E(name)}</text>")
    o.append(f"<text x='{x + 18}' y='{y + 50}' font-size='12.5' font-weight='600' fill='{s}'>{E(title)}</text>")
    for i, t in enumerate(lines):
        o.append(f"<text x='{x + 18}' y='{y + 74 + i * 18}' font-size='12' fill='#333'>• {E(t)}</text>")
o.append(f"<text x='20' y='30' font-size='14' font-weight='700' {MONO} fill='#555'>Download/MiniPcap/</text>")
doc(20, 48, 445, 165, "<session-id>.pcap", "Packets: opens in Wireshark", [
    "one record per packet, in capture order",
    "nanosecond timestamp at the capture point",
    "direction: uplink (SLL type 4) / downlink (0)",
    "original + captured length",
    "full IP + transport header, payload up to the set size"], "#e8f1fb", "#2f6db5")
doc(535, 48, 445, 165, "<session-id>.meta", "Measurements and apps: binary, timestamped", [
    "position, GNSS, accelerometer, gyroscope",
    "radio technology, serving + neighbor cells, signal",
    "network and Wi-Fi state",
    "flow → UID → app mappings",
    "clock sync, drop counters, session start / end"], "#eaf6ec", "#2e8b4a")
o.append("<line x1='465' y1='135' x2='535' y2='135' stroke='#888' stroke-width='1.5' stroke-dasharray='4 3'/>")
o.append("<text x='500' y='126' text-anchor='middle' font-size='10.5' fill='#666'>same ID</text>")
svg = f"""<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 {W} {H}' width='{W}' height='{H}' font-family='-apple-system,Segoe UI,Helvetica,Arial,sans-serif'>
<rect width='{W}' height='{H}' rx='14' fill='#ffffff'/>
{chr(10).join(o)}
</svg>
"""
open(sys.argv[1], "w").write(svg)
