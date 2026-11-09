"""Render eval results as a dependency-free SVG bar chart for the README.

    python scripts/make_chart.py eval/results/results_dev.json docs/img/catch_rate_dev.svg
"""

from __future__ import annotations

import json
import sys
from pathlib import Path


def main(src: str, dst: str) -> None:
    s = json.loads(Path(src).read_text())["summary"]
    cats = sorted(s["by_category"].items())
    rows = [(c, 100.0 * v["caught"] / v["n"], v["n"]) for c, v in cats]
    W, bar_h, gap, left, top = 720, 22, 8, 190, 50
    H = top + len(rows) * (bar_h + gap) + 60
    scale = (W - left - 70) / 100.0
    out = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" font-family="Helvetica,Arial,sans-serif" font-size="13">',
           f'<rect width="{W}" height="{H}" fill="#ffffff"/>',
           f'<text x="{left}" y="28" font-size="16" font-weight="bold">ShipGuard catch rate by attack category (dev corpus)</text>']
    x85 = left + 85 * scale
    for i, (cat, pct, n) in enumerate(rows):
        y = top + i * (bar_h + gap)
        color = "#2e7d32" if pct >= 85 else "#c62828"
        out.append(f'<text x="{left - 10}" y="{y + 16}" text-anchor="end">{cat} (n={n})</text>')
        out.append(f'<rect x="{left}" y="{y}" width="{100 * scale:.1f}" height="{bar_h}" fill="#eeeeee"/>')
        out.append(f'<rect x="{left}" y="{y}" width="{pct * scale:.1f}" height="{bar_h}" fill="{color}"/>')
        out.append(f'<text x="{left + pct * scale + 6:.1f}" y="{y + 16}">{pct:.0f}%</text>')
    yb = top + len(rows) * (bar_h + gap)
    out.append(f'<line x1="{x85:.1f}" y1="{top - 6}" x2="{x85:.1f}" y2="{yb}" stroke="#555" stroke-dasharray="4,3"/>')
    out.append(f'<text x="{x85:.1f}" y="{top - 10}" text-anchor="middle" font-size="11">85% target</text>')
    out.append(f'<text x="{left}" y="{yb + 30}">Overall catch {s["catch_rate"]}% · benign FPR {s["false_positive_rate"]}% · '
               f'gateway p95 overhead {s["overhead_ms_p95"]} ms</text>')
    out.append("</svg>")
    Path(dst).parent.mkdir(parents=True, exist_ok=True)
    Path(dst).write_text("\n".join(out))


if __name__ == "__main__":
    main(*(sys.argv[1:3] if len(sys.argv) >= 3 else ["eval/results/results_dev.json", "docs/img/catch_rate_dev.svg"]))
