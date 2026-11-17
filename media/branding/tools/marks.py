#!/usr/bin/env python3
"""marks.py SRCDIR: write the NitroOS mark (brand v7, concept "N + flame") into SRCDIR.

The mark is a dark navy squircle holding an N: two stems that run cyan to violet and a diagonal "flame" that
runs orange to yellow, with a narrow navy gap where the flame crosses the stems.

  mark.svg             master, 512 grid, gradients (used from 48 px up)
  mark-flat.svg        the master geometry in flat colours, no gradients (16-colour boot screen, print, 1-bit-alpha uses)
  mark-mono.svg        one colour, the N only (black); mark-mono-white.svg the same in white
  mark-mono-tile.svg   one colour: a solid tile with the N knocked out
  mark-NN.svg          hand-fitted for NN = 16, 20, 24, 32 px: whole-pixel stems, thicker strokes, flat colours
                       (no gradient, so no banding in 4-bit and 8-bit icon frames), slope 1:2 so the diagonal steps evenly;
                       16 and 20 use crispEdges on the N (no antialiasing: every pixel is one of five exact colours)
  mark-glyph-NN.svg    one-colour small marks for the themed Start buttons (NN = 16, 20, 24): white, tile faint
  mark-mono-NN.svg     small N only, white (NN = 16, 20, 24, 32)

Edit the tables, then rerun. Colours are written as hex so every file is standalone."""
import math, os, sys

CYAN, VIOLET, ORANGE, YELLOW = '#00c2ff', '#7b5cff', '#ff7a18', '#ffd23f'
NAVY1, NAVY2, NAVY_FLAT = '#1b1f3b', '#0b0e1f', '#151a33'

# ---- master geometry (512 grid). The N is centred on the tile; the diagonal is a little wider than the stems
# horizontally (80 against 66) so that its thickness measured across the stroke (65) matches the stems, since a
# diagonal looks thinner than a vertical of the same width.
X0, X1, Y0, Y1 = 133, 379, 122, 390
STEM, DIAG, GAP = 66, 80, 8
TILE = (16, 16, 496, 496)
TILE_N = 6.5                      # superellipse exponent of the tile: flat sides, tight smooth corners (about 20 % of the width)

def squircle(x0, y0, x1, y1, n=TILE_N, steps=96):
    cx, cy, a, b = (x0 + x1) / 2, (y0 + y1) / 2, (x1 - x0) / 2, (y1 - y0) / 2
    pts = []
    for i in range(4 * steps):
        t = 2 * math.pi * i / (4 * steps)
        c, s = math.cos(t), math.sin(t)
        pts.append((cx + a * math.copysign(abs(c) ** (2 / n), c), cy + b * math.copysign(abs(s) ** (2 / n), s)))
    return 'M' + ' L'.join(f'{x:.2f} {y:.2f}' for x, y in pts) + ' Z'

def rrect(x0, y0, x1, y1, r):
    return (f'M{x0 + r} {y0} H{x1 - r} A{r} {r} 0 0 1 {x1} {y0 + r} V{y1 - r} A{r} {r} 0 0 1 {x1 - r} {y1} '
            f'H{x0 + r} A{r} {r} 0 0 1 {x0} {y1 - r} V{y0 + r} A{r} {r} 0 0 1 {x0 + r} {y0} Z')

def pts(p): return ' '.join(f'{x:g},{y:g}' for x, y in p)

def n_parts(x0, x1, y0, y1, s, d):
    left = [(x0, y0), (x0 + s, y0), (x0 + s, y1), (x0, y1)]
    right = [(x1 - s, y0), (x1, y0), (x1, y1), (x1 - s, y1)]
    diag = [(x0, y0), (x0 + d, y0), (x1, y1), (x1 - d, y1)]
    return left, right, diag

def n_outline(x0, x1, y0, y1, s, d):
    """Single outline of the N (stems and diagonal united, no gap)."""
    H = y1 - y0; W = x1 - x0; k = (W - d) / H             # horizontal run of the diagonal per unit of height
    ya = y0 + (x0 + s - x0) / k                           # diagonal lower-left edge meets the left stem's right edge
    yb = y0 + (x1 - s - (x0 + d)) / k                     # diagonal upper-right edge meets the right stem's left edge
    P = [(x0, y0), (x0 + d, y0), (x1 - s, yb), (x1 - s, y0), (x1, y0), (x1, y1), (x1 - d, y1), (x0 + s, ya),
         (x0 + s, y1), (x0, y1)]
    return 'M' + ' L'.join(f'{x:.2f} {y:.2f}' for x, y in P) + ' Z'

def flame_axis():
    """Gradient axis across the diagonal (from its lower-left edge to its upper-right edge)."""
    dx, dy = (X1 - X0) - DIAG, Y1 - Y0
    L = math.hypot(dx, dy); nx, ny = dy / L, -dx / L       # normal, pointing up and to the right
    half = DIAG * (dy / L) / 2                             # half thickness across the stroke
    cx, cy = (X0 + X1) / 2, (Y0 + Y1) / 2
    return cx - nx * half, cy - ny * half, cx + nx * half, cy + ny * half

HEAD = '<?xml version="1.0" encoding="UTF-8"?>\n'

def master(idp=''):
    L, R, D = n_parts(X0, X1, Y0, Y1, STEM, DIAG)
    fx1, fy1, fx2, fy2 = flame_axis(); i = idp
    t = squircle(*TILE)
    return f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512" width="512" height="512">
  <defs>
    <linearGradient id="{i}bg" gradientUnits="userSpaceOnUse" x1="16" y1="16" x2="496" y2="496"><stop offset="0" stop-color="{NAVY1}"/><stop offset="1" stop-color="{NAVY2}"/></linearGradient>
    <linearGradient id="{i}sl" gradientUnits="userSpaceOnUse" x1="{X0}" y1="{Y1}" x2="{X0 + STEM}" y2="{Y0}"><stop offset="0" stop-color="{CYAN}"/><stop offset="1" stop-color="{VIOLET}"/></linearGradient>
    <linearGradient id="{i}sr" gradientUnits="userSpaceOnUse" x1="{X1 - STEM}" y1="{Y1}" x2="{X1}" y2="{Y0}"><stop offset="0" stop-color="{CYAN}"/><stop offset="1" stop-color="{VIOLET}"/></linearGradient>
    <linearGradient id="{i}fl" gradientUnits="userSpaceOnUse" x1="{fx1:.1f}" y1="{fy1:.1f}" x2="{fx2:.1f}" y2="{fy2:.1f}"><stop offset="0" stop-color="{ORANGE}"/><stop offset="1" stop-color="{YELLOW}"/></linearGradient>
    <linearGradient id="{i}rim" gradientUnits="userSpaceOnUse" x1="16" y1="16" x2="496" y2="496"><stop offset="0" stop-color="#fff" stop-opacity="0.26"/><stop offset="0.55" stop-color="#fff" stop-opacity="0.05"/><stop offset="1" stop-color="#fff" stop-opacity="0.10"/></linearGradient>
    <radialGradient id="{i}gl" gradientUnits="userSpaceOnUse" cx="256" cy="256" r="236"><stop offset="0" stop-color="{VIOLET}" stop-opacity="0.22"/><stop offset="1" stop-color="{VIOLET}" stop-opacity="0"/></radialGradient>
    <clipPath id="{i}t"><path d="{t}"/></clipPath>
    <mask id="{i}k" maskUnits="userSpaceOnUse" x="0" y="0" width="512" height="512"><rect width="512" height="512" fill="#fff"/><polygon points="{pts(D)}" fill="#000" stroke="#000" stroke-width="{2 * GAP}" stroke-linejoin="miter"/></mask>
  </defs>
  <path d="{t}" fill="url(#{i}bg)"/>
  <path d="{t}" fill="url(#{i}gl)"/>
  <g mask="url(#{i}k)">
    <polygon points="{pts(L)}" fill="url(#{i}sl)"/>
    <polygon points="{pts(R)}" fill="url(#{i}sr)"/>
  </g>
  <polygon points="{pts(D)}" fill="url(#{i}fl)"/>
  <path d="{t}" fill="none" stroke="url(#{i}rim)" stroke-width="4" clip-path="url(#{i}t)"/>
</svg>
'''

def flat():
    L, R, D = n_parts(X0, X1, Y0, Y1, STEM, DIAG)
    strip = [(X0 + DIAG - 22, Y0), (X0 + DIAG, Y0), (X1, Y1), (X1 - 22, Y1)]      # yellow leading edge of the flame
    t = squircle(*TILE)
    return f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512" width="512" height="512">
  <!-- flat variant: no gradients, six colours (the sixth is the tile rim) -->
  <clipPath id="t"><path d="{t}"/></clipPath>
  <path d="{t}" fill="{NAVY_FLAT}"/>
  <path d="{t}" fill="none" stroke="#2a2f66" stroke-width="8" clip-path="url(#t)"/>
  <polygon points="{pts(L)}" fill="{CYAN}"/>
  <polygon points="{pts(R)}" fill="{VIOLET}"/>
  <polygon points="{pts(D)}" fill="{NAVY_FLAT}" stroke="{NAVY_FLAT}" stroke-width="{2 * GAP}" stroke-linejoin="miter"/>
  <polygon points="{pts(D)}" fill="{ORANGE}"/>
  <clipPath id="d"><polygon points="{pts(D)}"/></clipPath>
  <polygon points="{pts(strip)}" fill="{YELLOW}" clip-path="url(#d)"/>
</svg>
'''

def mono(fill, tile=False):
    L, R, D = n_parts(X0, X1, Y0, Y1, STEM, DIAG)
    if not tile:
        return f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512" width="512" height="512">
  <!-- one colour, N only: stems and diagonal are separated by the same gap as in the colour mark -->
  <defs><mask id="k" maskUnits="userSpaceOnUse" x="0" y="0" width="512" height="512"><rect width="512" height="512" fill="#fff"/><polygon points="{pts(D)}" fill="#000" stroke="#000" stroke-width="{2 * GAP}"/></mask></defs>
  <g fill="{fill}"><g mask="url(#k)"><polygon points="{pts(L)}"/><polygon points="{pts(R)}"/></g><polygon points="{pts(D)}"/></g>
</svg>
'''
    t = squircle(*TILE)
    return f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512" width="512" height="512">
  <!-- one colour: solid tile, the N knocked out (transparent) -->
  <defs><mask id="k" maskUnits="userSpaceOnUse" x="0" y="0" width="512" height="512"><rect width="512" height="512" fill="#fff"/>
    <g fill="#000"><g><polygon points="{pts(L)}"/><polygon points="{pts(R)}"/></g></g>
    <polygon points="{pts(D)}" fill="#fff" stroke="#fff" stroke-width="{2 * GAP}"/><polygon points="{pts(D)}" fill="#000"/></mask></defs>
  <path d="{t}" fill="{fill}" mask="url(#k)"/>
</svg>
'''

# ---- small sizes. size: (tile radius, N x0, x1, y0, y1, stem, diag, yellow edge width).
# Rules: whole-pixel stems and N bounds; diagonal run (W - d) is half of the height, so it steps 2 px per pixel row
# evenly; the diagonal is wider than the stems horizontally (its slant makes it look thinner); tile fills the grid.
SMALL = {
    16: (3.5, 3, 13, 2, 14, 3, 4, 0),
    20: (4.5, 4, 16, 3, 17, 4, 5, 0),
    24: (5.5, 5, 19, 3, 21, 4, 5, 1),
    32: (7.0, 7, 25, 4, 28, 5, 6, 2),
}
for _n, (_r, _x0, _x1, _y0, _y1, _s, _d, _e) in SMALL.items():
    assert (_x1 - _x0 - _d) * 2 == (_y1 - _y0), _n

def small(n):
    r, x0, x1, y0, y1, s, d, e = SMALL[n]
    L, R, D = n_parts(x0, x1, y0, y1, s, d)
    ce = ' shape-rendering="crispEdges"' if n <= 20 else ''       # 16 and 20: hinted, every pixel one of the five flat colours
    edge = ''
    if e:
        st = [(x0 + d - e, y0), (x0 + d, y0), (x1, y1), (x1 - e, y1)]
        edge = f'\n  <polygon{ce} points="{pts(st)}" fill="{YELLOW}" clip-path="url(#d)"/>'
    return f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {n} {n}" width="{n}" height="{n}" shape-rendering="geometricPrecision">
  <!-- NitroOS mark fitted to the {n} px grid (flat colours, whole-pixel stems); generated by media/branding/tools/marks.py -->
  <path d="{rrect(0, 0, n, n, r)}" fill="{NAVY_FLAT}"/>
  <polygon{ce} points="{pts(L)}" fill="{CYAN}"/>
  <polygon{ce} points="{pts(R)}" fill="{VIOLET}"/>
  <clipPath id="d"><polygon points="{pts(D)}"/></clipPath>
  <polygon{ce} points="{pts(D)}" fill="{ORANGE}"/>{edge}
</svg>
'''

def small_mono(n):
    r, x0, x1, y0, y1, s, d, e = SMALL[n]
    L, R, D = n_parts(x0, x1, y0, y1, s, d)
    return f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {n} {n}" width="{n}" height="{n}">
  <!-- NitroOS N, one colour, fitted to the {n} px grid; generated by media/branding/tools/marks.py -->
  <g fill="#fff"><polygon points="{pts(L)}"/><polygon points="{pts(R)}"/><polygon points="{pts(D)}"/></g>
</svg>
'''

def glyph(n):
    """One-colour small mark for theme Start buttons: white; tile faint, stems 60 %, flame full."""
    r, x0, x1, y0, y1, s, d, e = SMALL[n]
    L, R, D = n_parts(x0, x1, y0, y1, s, d)
    return f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {n} {n}" width="{n}" height="{n}">
  <!-- NitroOS one-colour mark fitted to the {n} px grid; generated by media/branding/tools/marks.py -->
  <path d="{rrect(0, 0, n, n, r)}" fill="#fff" opacity="0.3"/>
  <g fill="#fff" opacity="0.65"><polygon points="{pts(L)}"/><polygon points="{pts(R)}"/></g>
  <polygon points="{pts(D)}" fill="#fff"/>
</svg>
'''

if __name__ == '__main__':
    d = sys.argv[1]
    def w(name, body):
        open(os.path.join(d, name), 'w').write(HEAD + body); print(name)
    w('mark.svg', master()); w('mark-flat.svg', flat())
    w('mark-mono.svg', mono('#000')); w('mark-mono-white.svg', mono('#fff')); w('mark-mono-tile.svg', mono(NAVY1, True))
    for n in SMALL:
        w(f'mark-{n}.svg', small(n)); w(f'mark-mono-{n}.svg', small_mono(n))
        if n <= 24: w(f'mark-glyph-{n}.svg', glyph(n))
