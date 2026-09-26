"""make_demo.py — generate an authentic terminal demo GIF for pcap-triage.

Renders the REAL main.py output (the local-LLM triage run) as a typing-out
terminal animation: command typed, then output streaming in, with the two
threat flows (C2 beacon on 4444, exfil on 80) highlighted amber/red and the
benign flow left in plain white. Stdlib + Pillow only.

  python make_demo.py            ->  writes ./demo.gif
"""
from __future__ import annotations

from PIL import Image, ImageDraw, ImageFont
import io
import sys

# --- terminal palette (GitHub dark) ------------------------------------
BG        = (13, 17, 23)     # #0d1117
TITLE_BG  = (22, 27, 34)     # #161b22
TITLE_TXT = (139, 148, 158)  # #8b949e
NORMAL    = (201, 209, 217)  # #c9d1d9
HEADER    = (88, 166, 255)   # #58a6ff  (blue, for "##" headers)
MUTED     = (48, 54, 61)     # #30363d (separators)
COMMAND   = (166, 212, 190)  # #a6d4be (typed command)
AMBER     = (210, 153, 34)   # #d29922 (beacon / C2)
RED       = (248, 81, 73)    # #f85149 (exfil / threat)
GREEN     = (63, 185, 80)    # #3fb950
BORDER    = (38, 44, 51)     # #262c33
CURSOR    = (201, 209, 217)

WINDOW_W, WINDOW_H = 860, 620
TITLE_H = 38
MARGIN = 22
FONT_SIZE = 17
FPS = 16


def load_font(size, bold=False):
    candidates = [
        "C:/Windows/Fonts/consola.ttf",
        "C:/Windows/Fonts/consola.bol.ttf" if bold else None,
        "C:/Windows/Fonts/Courier New.ttf",
        "/System/Library/Fonts/Consolas.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
        "DejaVuSansMono.ttf",
        "Courier New.ttf",
    ]
    for p in candidates:
        if p:
            try:
                return ImageFont.truetype(p, size)
            except Exception:
                pass
    return ImageFont.load_default()


def wrap_lines(draw, font, text, max_w):
    """Wrap text to fit max_w pixels using measured text length."""
    words = text.replace("→", "->").split()
    out, line = [], ""
    for w in words:
        trial = (line + " " + w) if line else w
        if draw.textlength(trial, font=font) <= max_w:
            line = trial
        else:
            if line:
                out.append(line)
                line = w
            else:
                # word itself is wider than the window (very long); hard-wrap
                while draw.textlength(w, font=font) > max_w:
                    cut = max(2, int(max_w / draw.textlength(w, font=font) * 30))
                    out.append(w[:cut]); w = w[cut:]
                line = w
    if line:
        out.append(line)
    return out or [""]


def frame_shown(draw, font, lines_state, cursor_col, show_cursor):
    """Draw the terminal given a list of (text, color, left_bar) lines."""
    x, y = MARGIN, TITLE_H + MARGIN
    for text, color, bar in lines_state:
        if bar:
            draw.rectangle([(MARGIN - 4, y - 3), (MARGIN + 2, y + FONT_SIZE + 1)],
                           fill=bar)
        draw.text((x, y), text, font=font, fill=color)
        y += FONT_SIZE + 2


def main():
    font = load_font(FONT_SIZE)
    draw = ImageDraw.Draw(Image.new("RGB", (WINDOW_W, WINDOW_H), BG))

    # Build the display lines as (text, color, bar).
    # These are the REAL output strings from main.py demo_combined.pcap.
    raw = [
        ("$", COMMAND, None),
        ("", NORMAL, None),
        ("=" * 72, MUTED, None),
        ("pcap-triage  —  autonomous network capture triage", NORMAL, None),
        ("=" * 72, MUTED, None),
        ("capture: 43 packets parsed in 0.00s", NORMAL, None),
        ("flows: 3 distinct 5-tuple flows", NORMAL, None),
        ("", NORMAL, None),
        ("## Model analysis (local LLM)", HEADER, None),
        ("-" * 72, MUTED, None),
        ("**Flow 1 (10.0.0.9 -> 185.220.101.43:4444):** This is a periodic, low-volume connection to the default Metasploit reverse-shell port (4444) with a perfectly regular 45-second IAT (std = 0.0), 180 total bytes, no TLS/SNI/domain, and near-zero symmetry — a textbook C2 beacon. **Recommended action:** Isolate 10.0.0.9, block 185.220.101.43 at the perimeter, and capture the host for forensic analysis.", AMBER, AMBER),
        ("", NORMAL, None),
        ("**Flow 2 (10.0.0.14 -> 209.12.23.111:80):** A perfectly periodic (0.5 s, std = 0.0) HTTP connection carrying high-entropy (7.19) payloads with no TLS, SNI, or domain resolution and zero symmetry, which is inconsistent with normal web browsing and points to C2 or exfiltration over plain HTTP. **Recommended action:** Block the destination IP, capture full packet payloads for content analysis, and investigate 10.0.0.14 for malware or data-staging activity.", RED, RED),
        ("", NORMAL, None),
        ("**Flow 3 (10.0.0.14 -> 142.250.180.206:443):** A small (296 B), irregularly-timed (IAT std 16.5 s) connection to a port-443 destination with low entropy and no beaconing; the only oddities are the \"rare domain\" flag on *example.com* and the absence of TLS on port 443, both inconclusive. **Recommended action:** Monitor for recurrence; no immediate block is warranted.", NORMAL, None),
        ("", NORMAL, None),
        ("## Deterministic signals", HEADER, None),
        ("-" * 72, MUTED, None),
        ("[BEACON, SUSP_PORT] 10.0.0.9:45220 -> 185.220.101.43:4444 (tcp, 20 pkts, 180 B)", AMBER, AMBER),
        ("    IAT=45.0s/0.0s  entropy=3.16  beacon=0.9", AMBER, None),
        ("", NORMAL, None),
        ("[BEACON, HIGH_ENTROPY] 10.0.0.14:51300 -> 209.12.23.111:80 (tcp, 15 pkts, 3840 B)", RED, RED),
        ("    IAT=0.5s/0.0s  entropy=7.19  beacon=0.9", RED, None),
        ("", NORMAL, None),
        ("[RARE_DOM] 10.0.0.14:51301 -> 142.250.180.206:443 (tcp, 8 pkts, 296 B)", NORMAL, None),
        ("    IAT=20.143s/16.507s  entropy=4.32  beacon=0.0", NORMAL, None),
        ("    domains=example.com", NORMAL, None),
    ]
    max_w = WINDOW_W - 2 * MARGIN
    display = []
    for text, color, bar in raw:
        if text == "":
            display.append(("", color, bar))
            continue
        for piece in wrap_lines(draw, font, text, max_w):
            display.append((piece, color, bar if display and display[-1][0] else (bar if text.startswith(("[BEACON", "Flow 1", "Flow 2")) else None)))

    # The command line (typed) is drawn separately at the top.
    cmd = "python main.py demo_combined.pcap"

    # --- build frame timeline ---
    frames = []
    hold_per_line = 3  # how many frames to dwell on each output line

    def make_state(n_out_lines, cmd_partial, cursor):
        """Build a list of drawn lines given how many output lines are shown
        and how many chars of the command are typed."""
        lines_state = []
        typed_cmd = cmd[:cmd_partial]
        lines_state.append(("$ " + typed_cmd, COMMAND, None))
        for i in range(n_out_lines):
            lines_state.append(display[i])
        return lines_state

    def render(lines_state):
        img = Image.new("RGB", (WINDOW_W, WINDOW_H), BG)
        d = ImageDraw.Draw(img)
        # title bar
        d.rectangle([(0, 0), (WINDOW_W, TITLE_H)], fill=TITLE_BG)
        d.rectangle([(0, 0), (WINDOW_W - 1, TITLE_H - 1)], outline=BORDER)
        d.text((16, TITLE_H // 2 - 9), "pcap-triage", font=font, fill=GREEN)
        d.text((170, TITLE_H // 2 - 9), "·  local LLM triage  (bonsai2)", font=font, fill=TITLE_TXT)
        # window border
        d.rectangle([(1, 1), (WINDOW_W - 2, WINDOW_H - 2)], outline=BORDER, width=2)
        frame_shown(d, font, lines_state, 0, False)
        # blinking cursor at end of the command (only during typing phase)
        return img

    # typing the command
    for i in range(1, len(cmd) + 1):
        frames.append(render(make_state(0, i, True)))
    # a beat before output
    frames.append(render(make_state(0, len(cmd), True)))

    # stream output line by line
    for i in range(len(display)):
        for _ in range(hold_per_line):
            frames.append(render(make_state(i + 1, len(cmd), True)))

    # hold at the end so the two highlighted threats "land"
    for _ in range(10):
        frames.append(render(make_state(len(display), len(cmd), True)))

    out_path = sys.argv[1] if len(sys.argv) > 1 else "demo.gif"
    frames[0].save(out_path, save_all=True, append_images=frames[1:],
                   fps=FPS, loop=0, duration=round(1000 / FPS))
    print(f"wrote {out_path}: {len(frames)} frames @ {FPS}fps "
          f"= {len(frames)/FPS:.1f}s")


if __name__ == "__main__":
    main()
