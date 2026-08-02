#!/usr/bin/env python3
"""
Regenerate purragent's banner logo from its source PNG (scripts/purragent_logo_src.png).

Converts a PNG into half-block art (each character cell holds two vertical pixels
via ▀/▄), auto-cropping the uniform border first. Default is monochrome mode: a
shape-only silhouette that purragent paints a single violet colour at startup.
Pass --color for a truecolor render (only sensible for images with real colour on
a transparent background).

Usage:
    python3 scripts/render_purragent_logo.py            # default: mono, 22 cols
    python3 scripts/render_purragent_logo.py --cols 18  # smaller
    python3 scripts/render_purragent_logo.py --color --src icons/__app_icon.png

Output: appdata/terminal_modules/purragent_logo.ans (loaded at startup by
purragent.py — no Pillow dependency at runtime).
"""

import argparse
import os

from PIL import Image

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _crop_to_content(img: Image.Image) -> Image.Image:
    """Trim a uniform border (transparent OR near-white) down to the artwork."""
    px = img.load()
    w, h = img.size
    mask = Image.new("L", (w, h), 0)
    mpx = mask.load()
    for y in range(h):
        for x in range(w):
            r, g, b, a = px[x, y]
            near_white = a >= 40 and (0.299 * r + 0.587 * g + 0.114 * b) > 230
            mpx[x, y] = 255 if (a >= 40 and not near_white) else 0
    bbox = mask.getbbox()
    return img.crop(bbox) if bbox else img


def render(src: str, cols: int, mono: bool = False) -> str:
    img = Image.open(src).convert("RGBA")
    img = _crop_to_content(img)
    w, h = img.size
    # Half-block: 1 px per column horizontally, 2 px per row vertically. A square
    # image reads as square in a terminal when cols == 2 * rows.
    rows = max(1, round(cols * (h / w) / 2))
    img = img.resize((cols, rows * 2), Image.LANCZOS)
    px = img.load()

    def opaque(a):
        return a >= 40

    def fg(p):
        # Foreground = a visible, dark pixel. Works for silhouettes on either a
        # transparent OR an opaque (e.g. white) background.
        r, g, b, a = p
        return opaque(a) and (0.299 * r + 0.587 * g + 0.114 * b) < 140

    lines = []
    for r in range(rows):
        cells = []
        for c in range(cols):
            tp, bp = px[c, 2 * r], px[c, 2 * r + 1]
            tr, tg, tb, ta = tp
            br, bg, bb, ba = bp
            to, bo = opaque(ta), opaque(ba)
            if mono:
                # Shape only (no colour) — the caller paints it a single colour.
                t, b_ = fg(tp), fg(bp)
                cells.append("█" if (t and b_) else "▀" if t else "▄" if b_ else " ")
            elif to and bo:
                cells.append(f"\x1b[38;2;{tr};{tg};{tb}m\x1b[48;2;{br};{bg};{bb}m▀\x1b[0m")
            elif to:
                cells.append(f"\x1b[38;2;{tr};{tg};{tb}m▀\x1b[0m")
            elif bo:
                cells.append(f"\x1b[38;2;{br};{bg};{bb}m▄\x1b[0m")
            else:
                cells.append(" ")
        lines.append("".join(cells).rstrip() if mono else "".join(cells))
    return "\n".join(lines) + "\n"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--cols", type=int, default=22)
    ap.add_argument("--color", action="store_true",
                    help="truecolor render (default is mono shape-only)")
    ap.add_argument("--src", default=os.path.join(
        ROOT, "scripts", "purragent_logo_src.png"))
    ap.add_argument("--out", default=os.path.join(
        ROOT, "appdata", "terminal_modules", "purragent_logo.ans"))
    args = ap.parse_args()

    art = render(args.src, args.cols, mono=not args.color)
    with open(args.out, "w", encoding="utf-8") as f:
        f.write(art)
    print(f"[ok] rendered {args.cols}-col logo -> {args.out}")


if __name__ == "__main__":
    main()
