"""Generate the profile README's animated SVGs.

    python assets/generate.py

Writes assets/soc-console.svg and assets/attack-coverage.svg. Edit LOG_LINES,
COVERAGE or TACTICS below and re-run; everything shown must be something that
actually happened in the lab.
"""
from pathlib import Path
from xml.sax.saxutils import escape

OUT = Path(__file__).parent
MONO = "'JetBrains Mono','Cascadia Code',Consolas,'Courier New',monospace"
SANS = "'Segoe UI','Inter',Helvetica,Arial,sans-serif"

GREEN = "#35ff9e"
RED = "#ff4d5e"
AMBER = "#ffb547"
CYAN = "#38bdf8"
DIM = "#5b6673"
TEXT = "#c9d1d9"

# ---------------------------------------------------------------- SOC console
# Replay of the Silent Operator run on 5 Sep 2026, timestamps from the Wazuh
# capture (detection-rules/evidence/bruteforce-100211.png): isolated 60122
# failures stay quiet, a burst from one source trips 100211 (level 12, T1110).
# (seconds into the loop, kind, time, rule, level, text)
LOG_LINES = [
    (0.6, "noise", "21:31:39", "60122", "5", "Logon failure 4625 · WIN-SERVER-2022 · isolated → no alert"),
    (1.6, "noise", "21:34:21", "60122", "5", "Logon failure 4625 · WIN-SERVER-2022 · isolated → no alert"),
    (3.0, "fail", "21:38:55", "60122", "5", "Logon failure 4625 · WIN-SERVER-2022 · same source"),
    (3.5, "fail", "21:38:58", "60122", "5", "Logon failure 4625 · WIN-SERVER-2022 · same source"),
    (4.0, "fail", "21:39:02", "60122", "5", "Logon failure 4625 · WIN-SERVER-2022 · same source"),
    (4.5, "fail", "21:39:04", "60122", "5", "Logon failure 4625 · WIN-SERVER-2022 · same source"),
    (5.6, "alert", "21:39:08", "100211", "12", "BRUTE FORCE DETECTED · same_source_ip · T1110"),
    (7.0, "step", "", "", "", "▶ triage   one source · burst inside 60s · true positive"),
    (8.3, "step", "", "", "", "▶ respond  isolate source · open case · write report"),
]
LOOP = 16.0
HOLD_END = 15.0


def pct(t):
    return round(t / LOOP * 100, 2)


def soc_console():
    w, h = 1000, 360
    css = [
        f"text{{font-family:{MONO};}}",
        ".blink{animation:blink 1.2s steps(2,start) infinite}",
        "@keyframes blink{to{visibility:hidden}}",
    ]
    rows = []
    y0, step = 84, 27
    for i, (t, kind, ts, rule, lvl, msg) in enumerate(LOG_LINES):
        a, b = pct(t), pct(t + 0.15)
        css.append(
            f"@keyframes l{i}{{0%,{a}%{{opacity:0}}{b}%,{pct(HOLD_END)}%{{opacity:1}}100%{{opacity:0}}}}"
            f".l{i}{{opacity:0;animation:l{i} {LOOP}s linear infinite}}"
        )
        y = y0 + i * step
        g = [f'<g class="l{i}">']
        if kind == "alert":
            g.append(f'<rect x="22" y="{y - 17}" width="664" height="24" rx="4" fill="{RED}" fill-opacity=".13" stroke="{RED}" stroke-opacity=".55"/>')
        if kind == "step":
            verb, rest = msg.split(" ", 2)[1], msg.split(" ", 2)[2].strip()
            g.append(f'<text x="34" y="{y}" font-size="13" fill="{CYAN}">▶</text>')
            g.append(f'<text x="54" y="{y}" font-size="13" font-weight="700" fill="{CYAN}">{verb}</text>')
            g.append(f'<text x="136" y="{y}" font-size="13" fill="{TEXT}">{escape(rest)}</text>')
        else:
            col = {"noise": DIM, "fail": AMBER, "alert": RED}[kind]
            msg_col = {"noise": DIM, "fail": TEXT, "alert": RED}[kind]
            weight = ' font-weight="700"' if kind == "alert" else ""
            g.append(f'<text x="34" y="{y}" font-size="13" fill="{DIM}">{ts}</text>')
            g.append(f'<text x="112" y="{y}" font-size="13" fill="{TEXT}">{rule}</text>')
            g.append(f'<rect x="172" y="{y - 13}" width="34" height="17" rx="3" fill="{col}" fill-opacity=".18" stroke="{col}" stroke-opacity=".7"/>')
            g.append(f'<text x="189" y="{y}" font-size="11" fill="{col}" text-anchor="middle"{weight}>L{lvl}</text>')
            g.append(f'<text x="218" y="{y}" font-size="13" fill="{msg_col}"{weight}>{escape(msg)}</text>')
        g.append("</g>")
        rows.append("".join(g))

    # Right-hand detection card appears with the alert line.
    t_alert = next(t for t, k, *_ in LOG_LINES if k == "alert")
    a, b = pct(t_alert), pct(t_alert + 0.3)
    css.append(
        f"@keyframes card{{0%,{a}%{{opacity:.18}}{b}%,{pct(HOLD_END)}%{{opacity:1}}100%{{opacity:.18}}}}"
        f".card{{animation:card {LOOP}s linear infinite}}"
    )
    ring_len = 2 * 3.14159 * 44
    filled = ring_len * (1 - 12 / 15)
    css.append(
        f"@keyframes ring{{0%,{a}%{{stroke-dashoffset:{ring_len:.1f}}}{pct(t_alert + 1.2)}%,{pct(HOLD_END)}%{{stroke-dashoffset:{filled:.1f}}}100%{{stroke-dashoffset:{ring_len:.1f}}}}}"
        f".ring{{stroke-dasharray:{ring_len:.1f};animation:ring {LOOP}s ease-out infinite}}"
    )
    card = f"""
  <g class="card">
    <rect x="712" y="56" width="268" height="250" rx="10" fill="#0f1a16" stroke="{GREEN}" stroke-opacity=".35"/>
    <text x="732" y="84" font-size="11" fill="{DIM}" letter-spacing="2">DETECTION</text>
    <circle cx="790" cy="150" r="44" fill="none" stroke="#1f2937" stroke-width="9"/>
    <circle class="ring" cx="790" cy="150" r="44" fill="none" stroke="{RED}" stroke-width="9" stroke-linecap="round" transform="rotate(-90 790 150)"/>
    <text x="790" y="148" font-size="26" font-weight="700" fill="{TEXT}" text-anchor="middle">12</text>
    <text x="790" y="168" font-size="10" fill="{DIM}" text-anchor="middle">LEVEL / 15</text>
    <text x="852" y="132" font-size="22" font-weight="700" fill="{GREEN}">T1110</text>
    <text x="852" y="152" font-size="11" fill="{TEXT}">Brute Force</text>
    <text x="852" y="168" font-size="11" fill="{DIM}">Credential Access</text>
    <text x="732" y="224" font-size="11" fill="{DIM}">rule</text><text x="800" y="224" font-size="11" fill="{TEXT}">100211 · wazuh</text>
    <text x="732" y="244" font-size="11" fill="{DIM}">window</text><text x="800" y="244" font-size="11" fill="{TEXT}">5 fails / 60s</text>
    <text x="732" y="264" font-size="11" fill="{DIM}">key</text><text x="800" y="264" font-size="11" fill="{TEXT}">same_source_ip</text>
    <rect x="732" y="276" width="96" height="20" rx="10" fill="{GREEN}" fill-opacity=".15" stroke="{GREEN}"/>
    <text x="780" y="290" font-size="10.5" font-weight="700" fill="{GREEN}" text-anchor="middle">✔ VALIDATED</text>
  </g>"""

    svg = f"""<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" viewBox="0 0 {w} {h}" role="img" aria-label="SOC console replay: isolated logon failures stay quiet, a burst from one source fires Wazuh rule 100211 for T1110 brute force">
  <style>{''.join(css)}</style>
  <defs>
    <linearGradient id="bg" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#0d1117"/><stop offset="1" stop-color="#0a0f0d"/></linearGradient>
    <pattern id="grid" width="24" height="24" patternUnits="userSpaceOnUse"><path d="M24 0H0V24" fill="none" stroke="{GREEN}" stroke-opacity=".04"/></pattern>
  </defs>
  <rect x="1" y="1" width="{w - 2}" height="{h - 2}" rx="14" fill="url(#bg)" stroke="{GREEN}" stroke-opacity=".28"/>
  <rect x="1" y="1" width="{w - 2}" height="{h - 2}" rx="14" fill="url(#grid)"/>
  <path d="M1 38H{w - 1}" stroke="{GREEN}" stroke-opacity=".18"/>
  <circle cx="24" cy="20" r="6" fill="#ff5f57"/><circle cx="44" cy="20" r="6" fill="#febc2e"/><circle cx="64" cy="20" r="6" fill="#28c840"/>
  <text x="90" y="25" font-size="13" fill="{DIM}">wazuh-manager</text>
  <text x="206" y="25" font-size="13" fill="{TEXT}">~/alerts $ tail -f alerts.json | triage</text>
  <circle class="blink" cx="{w - 76}" cy="20" r="5" fill="{RED}"/>
  <text x="{w - 64}" y="25" font-size="12" font-weight="700" fill="{RED}">LIVE</text>
  <g font-size="11" fill="{DIM}" letter-spacing="1"><text x="34" y="60">TIME</text><text x="112" y="60">RULE</text><text x="176" y="60">LVL</text><text x="218" y="60">EVENT</text></g>
  {''.join(rows)}
  {card}
  <path d="M1 {h - 36}H{w - 1}" stroke="{GREEN}" stroke-opacity=".18"/>
  <text x="24" y="{h - 14}" font-size="11.5" fill="{DIM}">Silent Operator lab · replay of 5 Sep 2026 run · noise stays quiet, the burst fires</text>
  <text x="{w - 24}" y="{h - 14}" font-size="11.5" fill="{GREEN}" text-anchor="end">github.com/sahilnikam2410</text>
</svg>
"""
    (OUT / "soc-console.svg").write_text(svg, encoding="utf-8")


# ------------------------------------------------------- ATT&CK coverage map
TACTICS = [
    "Reconnaissance", "Resource Development", "Initial Access", "Execution",
    "Persistence", "Privilege Escalation", "Defense Evasion",
    "Credential Access", "Discovery", "Lateral Movement", "Collection",
    "Command and Control", "Exfiltration", "Impact",
]
# tactic -> [(technique id, short name, status)]
COVERAGE = {
    "Initial Access": [("T1566", "Phishing", "detected"), ("T1190", "Exploit Public-Facing App", "assessed")],
    "Execution": [("T1059", "Cmd & Scripting Interp.", "detected")],
    "Credential Access": [("T1110", "Brute Force", "validated")],
    "Discovery": [("T1046", "Network Service Discovery", "detected")],
    "Command and Control": [("T1071.001", "App Layer Protocol: Web", "research")],
}
STATUS = {
    "validated": (GREEN, "validated in lab"),
    "detected": ("#22c55e", "detected"),
    "assessed": (AMBER, "assessed"),
    "research": (CYAN, "research"),
}


def wrap(name, width=16):
    words, lines, cur = name.upper().split(), [], ""
    for wd in words:
        if cur and len(cur) + 1 + len(wd) > width:
            lines.append(cur)
            cur = wd
        else:
            cur = f"{cur} {wd}".strip()
    return lines + [cur]


def attack_coverage():
    w, h = 1000, 372
    tw, th, gap, x0, y0 = 132, 118, 8, 14, 64
    tiles = []
    for i, tactic in enumerate(TACTICS):
        col, row = i % 7, i // 7
        x, y = x0 + col * (tw + gap), y0 + row * (th + gap)
        techs = COVERAGE.get(tactic, [])
        best = techs[0][2] if techs else None
        if any(s == "validated" for *_, s in techs):
            best = "validated"
        stroke = STATUS[best][0] if best else "#1f2937"
        fill = STATUS[best][0] if best else "#0f141a"
        fop = ".08" if best else "1"
        g = [f'<g><rect x="{x}" y="{y}" width="{tw}" height="{th}" rx="8" fill="{fill}" fill-opacity="{fop}" stroke="{stroke}" stroke-opacity="{".7" if best else "1"}">']
        if best == "validated":
            g.append('<animate attributeName="stroke-opacity" values=".35;1;.35" dur="2.4s" repeatCount="indefinite"/>')
        g.append("</rect>")
        for j, ln in enumerate(wrap(tactic)):
            g.append(f'<text x="{x + 10}" y="{y + 18 + j * 12}" font-size="9.5" letter-spacing=".8" font-weight="700" fill="{TEXT if best else DIM}">{escape(ln)}</text>')
        ty = y + (46 if len(wrap(tactic)) > 1 else 40)
        if not techs:
            g.append(f'<text x="{x + 10}" y="{ty + 8}" font-size="11" fill="#374151">—</text>')
        for tid, name, st in techs:
            c = STATUS[st][0]
            g.append(f'<circle cx="{x + 14}" cy="{ty - 4}" r="3.5" fill="{c}"/>')
            g.append(f'<text x="{x + 22}" y="{ty}" font-size="12" font-weight="700" fill="{c}" font-family="{MONO}">{tid}</text>')
            g.append(f'<text x="{x + 10}" y="{ty + 14}" font-size="9.5" fill="{TEXT}">{escape(name)}</text>')
            if st == "validated":
                g.append(f'<rect x="{x + 10}" y="{y + th - 30}" width="{tw - 20}" height="19" rx="9.5" fill="{c}" fill-opacity=".15" stroke="{c}"/>')
                g.append(f'<text x="{x + tw / 2}" y="{y + th - 17}" font-size="9.5" font-weight="700" fill="{c}" text-anchor="middle">✔ RULE 100211 FIRED</text>')
            ty += 34
        g.append("</g>")
        tiles.append("".join(g))

    legend, lx = [], 14
    for key in ("validated", "detected", "assessed", "research"):
        c, label = STATUS[key]
        legend.append(f'<circle cx="{lx + 5}" cy="{h - 18}" r="4.5" fill="{c}"/><text x="{lx + 15}" y="{h - 14}" font-size="11" fill="{TEXT}">{label}</text>')
        lx += 30 + len(label) * 6.4
    n_tech = sum(len(v) for v in COVERAGE.values())

    svg = f"""<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" viewBox="0 0 {w} {h}" role="img" aria-label="MITRE ATT&amp;CK Enterprise coverage: {n_tech} techniques across {len(COVERAGE)} tactics, T1110 brute force validated in lab">
  <style>text{{font-family:{SANS};}}</style>
  <defs>
    <linearGradient id="scan" x1="0" x2="1"><stop offset="0" stop-color="{GREEN}" stop-opacity="0"/><stop offset=".5" stop-color="{GREEN}" stop-opacity=".10"/><stop offset="1" stop-color="{GREEN}" stop-opacity="0"/></linearGradient>
    <clipPath id="clip"><rect x="1" y="1" width="{w - 2}" height="{h - 2}" rx="14"/></clipPath>
  </defs>
  <rect x="1" y="1" width="{w - 2}" height="{h - 2}" rx="14" fill="#0d1117" stroke="{GREEN}" stroke-opacity=".28"/>
  <text x="18" y="32" font-size="16" font-weight="700" fill="{TEXT}">MITRE ATT&amp;CK · Enterprise coverage</text>
  <text x="{w - 18}" y="32" font-size="12" fill="{DIM}" text-anchor="end" font-family="{MONO}">{n_tech} techniques · {len(COVERAGE)}/14 tactics · 1 validated rule</text>
  {''.join(tiles)}
  <g clip-path="url(#clip)"><rect y="0" width="160" height="{h}" fill="url(#scan)"><animate attributeName="x" values="-160;{w};{w}" keyTimes="0;.7;1" dur="6s" repeatCount="indefinite"/></rect></g>
  {''.join(legend)}
  <text x="{w - 18}" y="{h - 14}" font-size="11" fill="{DIM}" text-anchor="end">only techniques actually run in the lab are lit</text>
</svg>
"""
    (OUT / "attack-coverage.svg").write_text(svg, encoding="utf-8")


if __name__ == "__main__":
    soc_console()
    attack_coverage()
    print("wrote soc-console.svg, attack-coverage.svg")
