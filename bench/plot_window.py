"""Draw the windows from bench/window.py as an SVG chart, with no extra packages.

    python bench/plot_window.py window-wifi.json window-lte.json --out window.svg

Each input is a file written by ``window.py --out``. For every export interval the chart shows
the worst case of two windows, both on logarithmic axes:

    solid   how far back a change goes unnoticed with throw-away keys
    dashed  how far back a change goes unnoticed with one key, which is also how much can be
            removed with either kind of key

Each input file gets one colour, named in the legend by its file name.
"""

from __future__ import annotations

import argparse
import json
import math
from pathlib import Path
from xml.sax.saxutils import escape

WIDTH, HEIGHT = 760, 440
LEFT, RIGHT, TOP, BOTTOM = 70, 30, 56, 96
COLOURS = ("#0072B2", "#D55E00", "#009E73", "#CC79A7")  # told apart with colour-blind vision
INK, MUTED, GRID = "#1f2933", "#52606d", "#d9e2ec"
SERIES = (
    ("can_alter_throwaway_worst_s", "", "change unnoticed, throw-away keys"),
    ("can_delete_worst_s", "6 4", "change unnoticed with one key, or remove"),
)


def _ticks(low: float, high: float) -> list[float]:
    """1, 2 and 5 times each power of ten between *low* and *high*."""
    ticks = []
    for power in range(math.floor(math.log10(low)), math.ceil(math.log10(high)) + 1):
        ticks += [step * 10.0**power for step in (1, 2, 5)]
    return [tick for tick in ticks if low <= tick <= high]


def _bounds(values: list[float]) -> tuple[float, float]:
    """A range that holds *values*, widened to the 1-2-5 steps around them."""
    low, high = min(values), max(values)
    below = [t for t in _ticks(low / 10, low) if t <= low]
    above = [t for t in _ticks(high, high * 10) if t >= high]
    low, high = below[-1], above[0]
    return (low, high) if high > low else (low / 2, high * 2)


def _label(seconds: float) -> str:
    if seconds >= 60 and seconds % 60 == 0:
        return f"{seconds / 60:g} min"
    return f"{seconds * 1000:g} ms" if seconds < 1 else f"{seconds:g} s"


def chart(runs: list[tuple[str, list[dict]]], title: str) -> str:
    """Return the SVG for *runs*: each a name and the rows of one window.py report."""
    if not 0 < len(runs) <= len(COLOURS):
        raise ValueError(f"give between 1 and {len(COLOURS)} files")
    xs = [row["export_s"] for _, rows in runs for row in rows]
    ys = [row[key] for _, rows in runs for row in rows for key, _, _ in SERIES]
    if min(xs + ys) <= 0:
        raise ValueError("every interval and window must be above zero for a logarithmic axis")
    (x_low, x_high), (y_low, y_high) = _bounds(xs), _bounds(ys)
    plot_w, plot_h = WIDTH - LEFT - RIGHT, HEIGHT - TOP - BOTTOM

    def x_at(value: float) -> float:
        return LEFT + plot_w * math.log(value / x_low) / math.log(x_high / x_low)

    def y_at(value: float) -> float:
        return TOP + plot_h * (1 - math.log(value / y_low) / math.log(y_high / y_low))

    text = f'font-family="system-ui, sans-serif" fill="{INK}"'
    out = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {WIDTH} {HEIGHT}" '
        f'width="{WIDTH}" height="{HEIGHT}" role="img" aria-label="{escape(title)}">',
        f'<rect width="{WIDTH}" height="{HEIGHT}" fill="#ffffff"/>',
        f'<text x="{LEFT}" y="28" font-size="16" font-weight="600" {text}>{escape(title)}</text>',
        f'<text x="{LEFT}" y="46" font-size="12" font-family="system-ui, sans-serif" '
        f'fill="{MUTED}">Worst case over the task. Both axes are logarithmic.</text>',
    ]
    for tick in _ticks(y_low, y_high):
        y = y_at(tick)
        out.append(
            f'<line x1="{LEFT}" x2="{WIDTH - RIGHT}" y1="{y:.1f}" y2="{y:.1f}" stroke="{GRID}"/>'
        )
        out.append(
            f'<text x="{LEFT - 8}" y="{y + 4:.1f}" font-size="11" text-anchor="end" '
            f'font-family="system-ui, sans-serif" fill="{MUTED}">{_label(tick)}</text>'
        )
    for tick in _ticks(x_low, x_high):
        x = x_at(tick)
        out.append(
            f'<line x1="{x:.1f}" x2="{x:.1f}" y1="{TOP}" y2="{TOP + plot_h}" stroke="{GRID}"/>'
        )
        out.append(
            f'<text x="{x:.1f}" y="{TOP + plot_h + 16}" font-size="11" text-anchor="middle" '
            f'font-family="system-ui, sans-serif" fill="{MUTED}">{_label(tick)}</text>'
        )
    out.append(
        f'<text x="{LEFT + plot_w / 2}" y="{TOP + plot_h + 36}" font-size="12" '
        f'text-anchor="middle" {text}>Time between sends to the witness</text>'
    )
    out.append(
        f'<text transform="translate(16 {TOP + plot_h / 2}) rotate(-90)" font-size="12" '
        f'text-anchor="middle" {text}>Window</text>'
    )
    for (_, rows), colour in zip(runs, COLOURS, strict=False):
        rows = sorted(rows, key=lambda row: row["export_s"])
        for key, dash, _ in SERIES:
            points = [(x_at(row["export_s"]), y_at(row[key])) for row in rows]
            path = " ".join(f"{x:.1f},{y:.1f}" for x, y in points)
            dashed = f' stroke-dasharray="{dash}"' if dash else ""
            style = f'fill="none" stroke="{colour}" stroke-width="2"{dashed}'
            out.append(f'<polyline points="{path}" {style}/>')
            out += [
                f'<circle cx="{x:.1f}" cy="{y:.1f}" r="3.5" fill="{colour}" stroke="#ffffff"/>'
                for x, y in points
            ]
    legend_y = HEIGHT - 38
    x = LEFT
    for (name, _), colour in zip(runs, COLOURS, strict=False):
        out.append(
            f'<rect x="{x}" y="{legend_y - 9}" width="12" height="12" rx="2" fill="{colour}"/>'
        )
        out.append(
            f'<text x="{x + 18}" y="{legend_y + 1}" font-size="12" {text}>{escape(name)}</text>'
        )
        x += 30 + 7 * len(name)
    x = LEFT
    for _, dash, meaning in SERIES:
        dashed = f' stroke-dasharray="{dash}"' if dash else ""
        out.append(
            f'<line x1="{x}" x2="{x + 28}" y1="{legend_y + 18}" y2="{legend_y + 18}" '
            f'stroke="{INK}" stroke-width="2"{dashed}/>'
        )
        out.append(f'<text x="{x + 34}" y="{legend_y + 22}" font-size="12" {text}>{meaning}</text>')
        x += 50 + 6.4 * len(meaning)
    out.append("</svg>")
    return "\n".join(out) + "\n"


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("reports", nargs="+", type=Path, help="files from window.py --out")
    parser.add_argument("--out", type=Path, required=True, help="the SVG file to write")
    parser.add_argument("--title", default="How far back a hacked robot could reach")
    args = parser.parse_args(argv)
    runs = [(path.stem, json.loads(path.read_text())["rows"]) for path in args.reports]
    args.out.write_text(chart(runs, args.title), encoding="utf-8")
    print(f"wrote {args.out}")


if __name__ == "__main__":
    main()
