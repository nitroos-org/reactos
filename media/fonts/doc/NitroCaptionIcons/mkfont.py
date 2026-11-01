#!/usr/bin/env python3
"""Generate NitroCaptionIcons.ttf: the four window caption-button glyphs that
Firefox (and other apps) draw from the "Segoe MDL2 Assets" / "Segoe Fluent Icons"
symbol fonts on Windows 10/11 (minimize, maximize, restore, close, plus their
high-contrast code points).  The glyphs are plain geometric shapes drawn from
scratch for this font: 1 px strokes on a 10 px em (1000 units per em, 100 units
per pixel at 10 px).  Dedicated to the public domain under CC0-1.0.

Usage: mkfont.py OUT.ttf
Needs fontTools (pip install fonttools).
"""
import sys
from fontTools.fontBuilder import FontBuilder
from fontTools.pens.ttGlyphPen import TTGlyphPen

UPM = 1000
S = 100  # one pixel at 10 px


DESC = 200  # descent in font units: the cell is 800 above and 200 below the baseline


def rect(x0, y0, x1, y1, hole=False):
    # TrueType: outer contours clockwise, counters counter-clockwise.
    # y is given in the 0..1000 glyph cell and moved down by the descent.
    y0 -= DESC
    y1 -= DESC
    pts = [(x0, y0), (x0, y1), (x1, y1), (x1, y0)]
    return pts[::-1] if hole else pts


def glyph(contours):
    pen = TTGlyphPen(None)
    for c in contours:
        c = [(x, y - DESC) for x, y in c] if c in DIAG else c
        pen.moveTo(c[0])
        for p in c[1:]:
            pen.lineTo(p)
        pen.closePath()
    return pen.glyph()


def empty():
    return TTGlyphPen(None).glyph()


W = UPM
minimize = [rect(0, 5 * S, W, 6 * S)]
maximize = [rect(0, 0, W, W), rect(S, S, W - S, W - S, hole=True)]
restore = [
    rect(0, 0, 8 * S, 8 * S), rect(S, S, 7 * S, 7 * S, hole=True),  # front window
    rect(2 * S, 9 * S, W, W),                                        # back window, top edge
    rect(9 * S, 2 * S, W, 9 * S),                                    # back window, right edge
]
d = 141  # horizontal offset of a 1 px (perpendicular) diagonal stroke
close = [
    [(0, 0), (d, 0), (W, W - d), (W, W), (W - d, W), (0, d)],
    [(0, W), (0, W - d), (W - d, 0), (W, 0), (W, d), (d, W)],
]
DIAG = close  # polygons given directly (not through rect()) are shifted in glyph()
notdef = [rect(0, 0, W, W), rect(S, S, W - S, W - S, hole=True)]

# code point -> glyph name.  The EF2x code points are the high-contrast
# variants (Firefox uses them under prefers-contrast); same shapes.
cmap = {
    0x20: "space",
    0xE921: "ChromeMinimize", 0xE922: "ChromeMaximize",
    0xE923: "ChromeRestore", 0xE8BB: "ChromeClose",
    0xEF2D: "ChromeMinimize", 0xEF2E: "ChromeMaximize",
    0xEF2F: "ChromeRestore", 0xEF2C: "ChromeClose",
}
glyphs = {
    ".notdef": glyph(notdef), "space": empty(),
    "ChromeMinimize": glyph(minimize), "ChromeMaximize": glyph(maximize),
    "ChromeRestore": glyph(restore), "ChromeClose": glyph(close),
}
order = list(glyphs)

fb = FontBuilder(UPM, isTTF=True)
fb.setupGlyphOrder(order)
fb.setupCharacterMap(cmap)
fb.setupGlyf(glyphs)
fb.setupHorizontalMetrics({n: (UPM if n != "space" else 500, 0) for n in order})
# Ascent + descent = 1 em, so a line box of 1 em (Firefox: font-size 10px,
# line-height 1) frames the 10 px glyph cell exactly.
fb.setupHorizontalHeader(ascent=UPM - DESC, descent=-DESC)
fb.setupNameTable({
    "familyName": "Nitro Caption Icons", "styleName": "Regular",
    "uniqueFontIdentifier": "NitroCaptionIcons-Regular-1.0",
    "fullName": "Nitro Caption Icons", "psName": "NitroCaptionIcons-Regular",
    "version": "Version 1.0",
    "copyright": "Public domain (CC0-1.0). Geometric caption-button glyphs drawn for reactos-nitro.",
    "licenseDescription": "CC0 1.0 Universal Public Domain Dedication",
    "licenseInfoURL": "https://creativecommons.org/publicdomain/zero/1.0/",
})
fb.setupOS2(sTypoAscender=UPM - DESC, sTypoDescender=-DESC, sTypoLineGap=0,
            usWinAscent=UPM - DESC, usWinDescent=DESC, xAvgCharWidth=UPM, fsType=0, achVendID="NTRO",
            usWeightClass=400, fsSelection=0x40)
fb.setupPost()
fb.font["head"].flags |= 0x8  # ppem rounded to integer
fb.save(sys.argv[1])
