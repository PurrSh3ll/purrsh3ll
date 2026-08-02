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
    python3 scripts/render_purragent_logo.py --blink    # eyes-closed blink frame
    python3 scripts/render_purragent_logo.py --color --src icons/__app_icon.png

Output: appdata/terminal_modules/purragent_logo.ans  (+ purragent_logo_blink.ans
with --blink), loaded at startup by purragent.py — no Pillow dependency at runtime.
"""

import argparse
import os
from collections import deque

from PIL import Image

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _eye_holes(img: Image.Image):
    """Return the eyes as a list of pixel-lists.

    Eyes are interior white holes (white not reachable from the border). Ear
    notches are holes too, so we keep only holes below the artwork's vertical
    midline — i.e. the eyes, not the ears.
    """
    px = img.load()
    w, h = img.size

    def dark(x, y):
        r, g, b, a = px[x, y]
        return a >= 40 and (0.299 * r + 0.587 * g + 0.114 * b) < 140

    ys = [y for y in range(h) for x in range(w) if dark(x, y)]
    if not ys:
        return []
    midline = (min(ys) + max(ys)) / 2

    bg = [[False] * w for _ in range(h)]
    dq = deque()
    for x in range(w):
        for yy in (0, h - 1):
            if not dark(x, yy):
                bg[yy][x] = True; dq.append((x, yy))
    for y in range(h):
        for xx in (0, w - 1):
            if not dark(xx, y) and not bg[y][xx]:
                bg[y][xx] = True; dq.append((xx, y))
    while dq:
        x, y = dq.popleft()
        for dx, dy in ((1, 0), (-1, 0), (0, 1), (0, -1)):
            nx, ny = x + dx, y + dy
            if 0 <= nx < w and 0 <= ny < h and not bg[ny][nx] and not dark(nx, ny):
                bg[ny][nx] = True; dq.append((nx, ny))

    # connected components of interior white below the midline
    seen = [[False] * w for _ in range(h)]
    holes = []
    for y in range(h):
        for x in range(w):
            if (not dark(x, y) and not bg[y][x] and y > midline and not seen[y][x]):
                comp = []; q = deque([(x, y)]); seen[y][x] = True
                while q:
                    cx, cy = q.popleft(); comp.append((cx, cy))
                    for dx, dy in ((1, 0), (-1, 0), (0, 1), (0, -1)):
                        nx, ny = cx + dx, cy + dy
                        if (0 <= nx < w and 0 <= ny < h and not seen[ny][nx]
                                and not dark(nx, ny) and not bg[ny][nx]):
                            seen[ny][nx] = True; q.append((nx, ny))
                holes.append(comp)
    return holes


def _close_eyes(img: Image.Image, squint: bool = False) -> Image.Image:
    """Blink (fill eyes fully) or squint (fill all but a thin central slit)."""
    img = img.copy()
    px = img.load()
    B = (0, 0, 0, 255)
    for comp in _eye_holes(img):
        ys = [y for _, y in comp]
        lo, hi = min(ys), max(ys)
        band = max(1, round((hi - lo + 1) / 6))     # central slit half-height
        mid = (lo + hi) / 2
        for (x, y) in comp:
            if not squint or not (mid - band <= y <= mid + band):
                px[x, y] = B
    return img


def render(src: str, cols: int, mono: bool = False,
           blink: bool = False, squint: bool = False) -> str:
    img = Image.open(src).convert("RGBA")
    if blink or squint:
        img = _close_eyes(img, squint=squint)
    w, h = img.size
    # Half-block: 1 px per column horizontally, 2 px per row vertically. The source
    # is authored on the terminal's own grid (each source block = one target pixel),
    # so we scale the WHOLE image with NEAREST — no crop, no blur. Cropping/LANCZOS
    # shifted the grid and squished the art vertically. Blank border rows/cols are
    # trimmed afterwards from the finished glyph lines instead.
    rows = max(1, round(cols * (h / w) / 2))
    img = img.resize((cols, rows * 2), Image.NEAREST)
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
    # Drop fully-blank leading/trailing lines (image margins) without disturbing
    # the grid alignment of the artwork itself.
    while lines and not lines[0].strip():
        lines.pop(0)
    while lines and not lines[-1].strip():
        lines.pop()
    return "\n".join(lines) + "\n"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--cols", type=int, default=22)
    ap.add_argument("--color", action="store_true",
                    help="truecolor render (default is mono shape-only)")
    ap.add_argument("--blink", action="store_true",
                    help="render the eyes-closed blink frame (-> _blink.ans)")
    ap.add_argument("--squint", action="store_true",
                    help="render the eyes-squinted frame (-> _squint.ans)")
    ap.add_argument("--src", default=os.path.join(
        ROOT, "scripts", "purragent_logo_src.png"))
    ap.add_argument("--out", default=None)
    args = ap.parse_args()

    variant = "_blink" if args.blink else "_squint" if args.squint else ""
    out = args.out or os.path.join(
        ROOT, "appdata", "terminal_modules", f"purragent_logo{variant}.ans")

    art = render(args.src, args.cols, mono=not args.color,
                 blink=args.blink, squint=args.squint)
    with open(out, "w", encoding="utf-8") as f:
        f.write(art)
    print(f"[ok] rendered {args.cols}-col logo -> {out}")


if __name__ == "__main__":
    main()
