#!/usr/bin/env python3
"""Deterministic generator for the Mirage site's raster assets.

Re-draws the diamond mark from docs/assets/img/mark.svg as geometry
(never a raster copy of the SVG) and renders the four PNG deliverables:

  favicon-32.png        32x32    rounded-square favicon; the outer stroke is
                               drawn at 2.2 px instead of the proportional
                               1.87 px so the geometry stays >= 2 px at
                               favicon size
  icon-192.png          192x192  rounded-square icon, mark.svg proportions
  apple-touch-icon.png  180x180  solid navy square (iOS masks its own
                               corners), centered mark with more padding
  og-image.png          1200x630 social card: deep navy, a faint blueprint
                               hairline grid (~8% alpha), the mark large and
                               centered-left, the MIRAGE wordmark in tracked
                               caps and one mono eyebrow line

Determinism: fixed geometry, fixed colors, fixed font paths, no
timestamps, no randomness -- the only resampling is supersample +
LANCZOS downscale. Re-running produces byte-identical files (verify with
the sha256 this script prints on two consecutive runs).
"""

from __future__ import annotations

import argparse
import hashlib
import math
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

REPO = Path(__file__).resolve().parent.parent

# Palette, straight from mark.svg / the site's design tokens.
NAVY = (10, 15, 26)       # #0a0f1a --bg
TEAL = (69, 214, 196)     # #45d6c4 --accent
TEXT = (242, 246, 252)    # #f2f6fc --text-strong
TEAL_MID = (40, 115, 111) # teal at 50% over the navy bg (pre-blended)

# Fonts shipped with the environment (DejaVu family, no webfonts).
FONT_BOLD = "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"
FONT_MONO = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"

# mark.svg geometry, in its 24-unit viewBox:
#   outer diamond  M12 4.5 … half-diagonal 7.5, stroke-width 1.4, no fill
#   middle diamond half-diagonals rx 3.5 / ry 3.65, teal at 50% opacity
#   inner diamond  half-diagonals rx 1.8 / ry 1.9, solid teal
#   background     24x24 rounded rect, rx 5, navy
VIEWBOX = 24.0
OUTER_HALF = 7.5
MID_RX, MID_RY = 3.5, 3.65
INNER_RX, INNER_RY = 1.8, 1.9
SVG_STROKE = 1.4
BG_RADIUS = 5.0

# Supersampling: geometry is drawn Sx larger and LANCZOS-downscaled, which
# is the anti-aliasing (and the only resampling anywhere in this script).
SS_ICON = 8
SS_SPRITE = 4

GRID_STEP = 60          # px between blueprint grid lines on the og image
GRID_ALPHA = 20         # ~8% of 255 -- faint hairlines, not a texture


def _diamond(cx: float, cy: float, rx: float, ry: float) -> list[tuple[float, float]]:
    return [(cx, cy - ry), (cx + rx, cy), (cx, cy + ry), (cx - rx, cy)]


def draw_mark(
    d: ImageDraw.ImageDraw,
    cx: float,
    cy: float,
    unit: float,
    stroke: float,
) -> None:
    """Draw the three nested diamonds of mark.svg at the given scale.

    `unit` is the size of one mark.svg viewBox unit in pixels; `stroke` is
    the outer diamond's stroke width in pixels. The outer outline is drawn
    as the ring between two similar diamonds, which pins the perpendicular
    stroke width exactly: a diamond vertex sits on a diagonal axis, and
    offsetting a vertex by delta moves the 45-degree edges by delta /
    sqrt(2), so a centered half-stroke of h needs a vertex offset of
    h * sqrt(2). The ring interior is re-filled with the navy background,
    matching the SVG's miter joins.
    """
    r = OUTER_HALF * unit
    dv = (stroke / 2.0) * math.sqrt(2.0)
    d.polygon(_diamond(cx, cy, r + dv, r + dv), fill=TEAL)
    d.polygon(_diamond(cx, cy, r - dv, r - dv), fill=NAVY)
    d.polygon(_diamond(cx, cy, MID_RX * unit, MID_RY * unit), fill=TEAL_MID)
    d.polygon(_diamond(cx, cy, INNER_RX * unit, INNER_RY * unit), fill=TEAL)


def render_icon(size: int, mark_diag: float, stroke: float, rounded: bool) -> Image.Image:
    """One square icon: navy (rounded) square bg + the mark, supersampled."""
    w = size * SS_ICON
    img = Image.new("RGBA", (w, w), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    if rounded:
        d.rounded_rectangle([0, 0, w - 1, w - 1], radius=BG_RADIUS / VIEWBOX * w, fill=NAVY)
    else:
        d.rectangle([0, 0, w - 1, w - 1], fill=NAVY)
    # The outer diamond spans 15 viewBox units edge to edge.
    draw_mark(d, w / 2, w / 2, mark_diag * SS_ICON / 15.0, stroke * SS_ICON)
    return img.resize((size, size), Image.Resampling.LANCZOS)


def mark_sprite(diag: float, stroke: float) -> Image.Image:
    """The bare mark with a transparent margin, supersampled.

    Used where the mark sits on the og image: its interior is opaque
    navy, so the blueprint grid reads as passing behind the mark.
    """
    box = math.ceil(diag + 2.0 * stroke) + 4
    w = box * SS_SPRITE
    img = Image.new("RGBA", (w, w), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    draw_mark(d, w / 2, w / 2, diag / 15.0 * SS_SPRITE, stroke * SS_SPRITE)
    return img.resize((box, box), Image.Resampling.LANCZOS)


def _tracked_width(font: ImageFont.FreeTypeFont, text: str, tracking: float) -> float:
    return sum(font.getlength(c) for c in text) + tracking * (len(text) - 1)


def _draw_tracked(
    d: ImageDraw.ImageDraw,
    xy: tuple[float, float],
    text: str,
    font: ImageFont.FreeTypeFont,
    tracking: float,
    fill: tuple[int, int, int],
) -> None:
    """Draw text with per-glyph letter-spacing (PIL has no tracking knob)."""
    x, y = xy
    for c in text:
        d.text((x, y), c, font=font, fill=fill)
        x += font.getlength(c) + tracking


def _ink_left(font: ImageFont.FreeTypeFont, ch: str) -> int:
    """Ink-left offset of one glyph relative to its draw origin.

    FreeTypeFont.getbbox is layout-based (x0 is always 0, x1 is the
    advance), so the true side bearing has to be measured: render the
    glyph on a scratch canvas and read where its ink starts.
    """
    w = math.ceil(font.getlength(ch)) + 4
    scratch = Image.new("L", (w + 4, font.size * 2 + 8), 0)
    ImageDraw.Draw(scratch).text((2, 4), ch, font=font, fill=255)
    return scratch.getbbox()[0] - 2


def render_og() -> Image.Image:
    """1200x630 social card: navy, hairline grid, big mark, wordmark."""
    width, height = 1200, 630

    # Deep navy base with a faint blueprint hairline grid at ~8% alpha.
    img = Image.new("RGB", (width, height), NAVY)
    grid = Image.new("RGBA", (width, height), (0, 0, 0, 0))
    gd = ImageDraw.Draw(grid)
    for x in range(GRID_STEP, width, GRID_STEP):
        gd.line([(x, 0), (x, height)], fill=TEAL + (GRID_ALPHA,), width=1)
    for y in range(GRID_STEP, height, GRID_STEP):
        gd.line([(0, y), (width, y)], fill=TEAL + (GRID_ALPHA,), width=1)
    img = Image.alpha_composite(img.convert("RGBA"), grid).convert("RGB")

    # The mark, large, centered vertically on the left third.
    diag = 290.0
    sprite = mark_sprite(diag, SVG_STROKE * diag / 15.0)
    cx, cy = 240, height // 2
    img.paste(sprite, (round(cx - sprite.width / 2), round(cy - sprite.height / 2)), sprite)

    # Eyebrow (mono) above the wordmark (bold caps), both tracked.
    d = ImageDraw.Draw(img)
    eyebrow = "DECEPTION LAYER · SIGNAL SPEC v1.1.0"
    wordmark = "MIRAGE"
    eb_font = ImageFont.truetype(FONT_MONO, 25)
    wm_font = ImageFont.truetype(FONT_BOLD, 110)
    eb_track, wm_track, gap = 4.0, 26.0, 38.0

    eb_box = eb_font.getbbox(eyebrow)
    wm_box = wm_font.getbbox(wordmark)
    eb_h = eb_box[3] - eb_box[1]
    wm_h = wm_box[3] - wm_box[1]
    text_x = 460
    top = (height - (eb_h + gap + wm_h)) / 2

    # Align the ink (not the glyph origins or advances): each font's side
    # bearing would otherwise stagger the eyebrow and wordmark left edges.
    eb_x = text_x - _ink_left(eb_font, eyebrow[0])
    wm_x = text_x - _ink_left(wm_font, wordmark[0])
    _draw_tracked(d, (eb_x, top - eb_box[1]), eyebrow, eb_font, eb_track, TEAL)
    _draw_tracked(
        d, (wm_x, top + eb_h + gap - wm_box[1]), wordmark, wm_font, wm_track, TEXT
    )
    return img


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate the Mirage site's favicon/icon/og-image PNGs."
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=REPO / "docs" / "assets" / "img",
        help="output directory (default: docs/assets/img next to the repo root)",
    )
    args = parser.parse_args()

    out: Path = args.out
    out.mkdir(parents=True, exist_ok=True)

    outputs = [
        # (name, image) -- the mark keeps mark.svg's proportions (15/24 of
        # the canvas) on the two rounded squares; the apple-touch icon
        # pads it out (96/180) as touch icons should.
        ("favicon-32.png", render_icon(32, 20.0, 2.2, rounded=True)),
        ("icon-192.png", render_icon(192, 120.0, 11.2, rounded=True)),
        ("apple-touch-icon.png", render_icon(180, 96.0, 10.5, rounded=False)),
        ("og-image.png", render_og()),
    ]
    for name, image in outputs:
        path = out / name
        image.save(path, "PNG")
        data = path.read_bytes()
        print(f"{path}  {len(data):,} bytes  sha256 {hashlib.sha256(data).hexdigest()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
