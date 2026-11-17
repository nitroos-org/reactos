#!/usr/bin/env python3
"""render.py TREE [--orig REV] [--only NAME,...] [--sheet DIR]

Render the Nitro artwork from the SVG masters in TREE/media/branding/src into the files the system builds,
in the exact format of each file it replaces (size, bit depth, compression, palette rules). The format of each
target is read from its upstream original at REV (default: the branch's upstream base), so the output does not
depend on what a previous run wrote. --sheet writes a contact sheet and per-asset previews into DIR.
Needs: rsvg-convert, Python 3 with Pillow and numpy; fonts come from media/branding/src/fonts."""
import argparse, io, os, re, struct, subprocess, sys
import numpy as np
from PIL import Image, ImageDraw, ImageFont, ImageFilter

ap = argparse.ArgumentParser()
ap.add_argument('tree'); ap.add_argument('--orig', default='2d0604e543')
ap.add_argument('--only', default=''); ap.add_argument('--sheet', default='')
A = ap.parse_args()
ROOT = os.path.abspath(A.tree); SRC = os.path.join(ROOT, 'media/branding/src')
FONT = os.path.join(SRC, 'fonts/Inter-Regular.ttf')

# ---- palette (palette.css is the one definition) -------------------------------------------------------
PAL = {m.group(1): tuple(int(m.group(2)[i:i + 2], 16) for i in (0, 2, 4))
       for m in re.finditer(r'\.f-(\w+)\{fill:#([0-9A-Fa-f]{6})\}', open(os.path.join(SRC, 'palette.css')).read())}
def C(name, a=None): return PAL[name] if a is None else PAL[name] + (a,)
def mix(c1, c2, t): return tuple(round(c1[i] + (c2[i] - c1[i]) * t) for i in range(3))

# ---- inputs -----------------------------------------------------------------------------------------------
def orig(path): return subprocess.check_output(['git', '-C', ROOT, 'show', f'{A.orig}:{path}'])
def orig_img(path): return Image.open(io.BytesIO(orig(path)))
def svg(name, w=None, h=None):
    cmd = ['rsvg-convert'] + (['-w', str(w)] if w else []) + (['-h', str(h)] if h else []) + [os.path.join(SRC, name)]
    return Image.open(io.BytesIO(subprocess.check_output(cmd))).convert('RGBA')
def mark(n):
    f = f'mark-{n}.svg'
    return svg(f if os.path.exists(os.path.join(SRC, f)) else 'mark.svg', n, n)
def mark_rev(n):
    return mark(n)                       # v7: the navy tile reads on light and dark grounds, one mark for both
def glyph(n, rgb):
    a = svg(f'mark-glyph-{n}.svg', n, n).getchannel('A')
    im = Image.new('RGBA', (n, n), rgb + (0,)); im.putalpha(a); return im
def wordmark(w=None, h=None, reverse=False): return svg('wordmark-reverse.svg' if reverse else 'wordmark.svg', w, h)
def font(px, wght=400):
    return ImageFont.truetype(FONT, px)      # Inter Regular; the weight argument of the v6 variable font is ignored
def text(img, xy, s, px, wght, rgba, anchor='ls'):
    lay = Image.new('RGBA', img.size, (0, 0, 0, 0))
    ImageDraw.Draw(lay).text(xy, s, font=font(px, wght), fill=rgba, anchor=anchor)
    img.alpha_composite(lay)
def paste(dst, src, xy): dst.alpha_composite(src, (int(xy[0]), int(xy[1])))
def canvas(w, h, rgb=(0, 0, 0), a=255): return Image.new('RGBA', (w, h), tuple(rgb) + (a,))
def vgrad(w, h, stops):
    """stops: [(t, rgb), ...] top to bottom"""
    arr = np.zeros((h, w, 3)); ys = np.linspace(0, 1, h)
    for c in range(3):
        arr[:, :, c] = np.interp(ys, [t for t, _ in stops], [s[c] for _, s in stops])[:, None]
    return Image.fromarray(arr.round().astype('uint8'), 'RGB').convert('RGBA')
def hgrad(w, h, stops): return vgrad(h, w, stops).transpose(Image.Transpose.TRANSPOSE)
def glowspot(w, h, cx, cy, rx, ry, rgb, amax):
    yy, xx = np.mgrid[0:h, 0:w]
    d = ((xx - cx) / rx) ** 2 + ((yy - cy) / ry) ** 2
    a = (np.clip(1 - d, 0, 1) ** 2 * amax * 255).astype('uint8')
    im = Image.new('RGBA', (w, h), rgb + (0,)); im.putalpha(Image.fromarray(a, 'L')); return im
def flatten(img, bg):
    out = Image.new('RGBA', img.size, tuple(bg) + (255,)); out.alpha_composite(img); return out.convert('RGB')

# ---- BMP and ICO writers ----------------------------------------------------------------------------------
def bmp_info(b):
    off = struct.unpack('<I', b[10:14])[0]; hs = struct.unpack('<I', b[14:18])[0]
    w, h, pl, bc, comp, isz = struct.unpack('<iiHHII', b[18:38])
    clr = struct.unpack('<I', b[46:50])[0] if hs >= 40 else 0
    pal_off = 14 + hs + (12 if comp == 3 and hs == 40 else 0)
    return dict(off=off, hs=hs, w=w, h=h, bc=bc, comp=comp, isz=isz, clr=clr, pal_off=pal_off,
                pal=[(b[i + 2], b[i + 1], b[i]) for i in range(pal_off, off, 4)])
OUT = []                                    # (tree path, preview image) for the sheet
def write_like(path, ob, data, pal=None, preview=None):
    """Write TREE/path with the headers of the original bytes ob, new pixel data and (optionally) a new palette."""
    H = bmp_info(ob); head = bytearray(ob[:H['off']])
    if H['comp'] in (0, 3):
        stride = ((H['w'] * H['bc'] + 31) // 32) * 4
        assert len(data) == stride * abs(H['h']), (path, 'pixel data does not match the original format', H['bc'])
    if pal is not None:
        n = (H['off'] - H['pal_off']) // 4
        assert len(pal) <= n, (path, len(pal), n)
        pal = list(pal) + [(0, 0, 0)] * (n - len(pal))
        head[H['pal_off']:H['off']] = b''.join(bytes((c[2], c[1], c[0], 0)) for c in pal)
    struct.pack_into('<I', head, 2, len(head) + len(data))
    if H['comp'] or H['isz']: struct.pack_into('<I', head, 34, len(data))
    p = os.path.join(ROOT, path); open(p, 'wb').write(bytes(head) + data)
    OUT.append((path, preview if preview is not None else Image.open(p).convert('RGBA')))
def pad4(b): return b + b'\0' * ((4 - len(b) % 4) % 4)
def rows24(img):
    a = np.asarray(img.convert('RGB'))[:, :, ::-1]
    return b''.join(pad4(a[y].tobytes()) for y in range(a.shape[0] - 1, -1, -1))
def rows32(img):
    a = np.asarray(img.convert('RGBA'))[:, :, [2, 1, 0, 3]]
    return b''.join(a[y].tobytes() for y in range(a.shape[0] - 1, -1, -1))
def nearest_idx(img, pal, weights=(3, 4, 2)):
    a = np.asarray(img.convert('RGB')).astype(int); p = np.array(pal, int); wv = np.array(weights)
    d = (((a[:, :, None, :] - p[None, None, :, :]) ** 2) * wv).sum(-1)
    return d.argmin(-1)
def rows8(idx):
    return b''.join(pad4(bytes(idx[y].astype('uint8').tolist())) for y in range(idx.shape[0] - 1, -1, -1))
def rle4(idx):
    """BI_RLE4 with encoded runs only, end of line after each row, end of bitmap at the end (as bootvid reads)."""
    out = bytearray()
    for y in range(idx.shape[0] - 1, -1, -1):
        r = idx[y].tolist(); x = 0
        while x < len(r):
            n = 1
            while x + n < len(r) and r[x + n] == r[x] and n < 255: n += 1
            out += bytes((n, (r[x] << 4) | r[x])); x += n
        out += b'\0\0'
    out[-2:] = b'\0\1'
    return bytes(out)
def decode_rle4(b, w, h):
    off = struct.unpack('<I', b[10:14])[0]; d = b[off:]; i = 0; y = h - 1; x = 0
    out = np.full((h, w), -1)
    while True:
        n = d[i]; i += 1
        if n:
            v = d[i]; i += 1
            for k in range(n):
                if x < w: out[y, x] = (v >> 4) if k % 2 == 0 else (v & 15)
                x += 1
            continue
        c = d[i]; i += 1
        if c == 0: x = 0; y -= 1
        elif c == 1: return out
        elif c == 2: x += d[i]; y -= d[i + 1]; i += 2
        else:                                                   # absolute run, padded to a 16-bit boundary
            nb = (c + 1) // 2
            for k in range(c):
                v = d[i + k // 2]
                if x < w: out[y, x] = (v >> 4) if k % 2 == 0 else (v & 15)
                x += 1
            i += nb + (nb & 1)
def pal_image(idx, pal):
    im = Image.fromarray(idx.astype('uint8'), 'P'); im.putpalette([v for c in pal for v in c] + [0] * (768 - 3 * len(pal)))
    return im.convert('RGBA')

VGA16 = [(0, 0, 0), (128, 0, 0), (0, 128, 0), (128, 128, 0), (0, 0, 128), (128, 0, 128), (0, 128, 128), (192, 192, 192),
         (128, 128, 128), (255, 0, 0), (0, 255, 0), (255, 255, 0), (0, 0, 255), (255, 0, 255), (0, 255, 255), (255, 255, 255)]
def ico_frame(img, bpp):
    n = img.width; a = np.asarray(img.convert('RGBA'))
    andm = b''.join(pad4(np.packbits(a[y, :, 3] < 128).tobytes()) for y in range(n - 1, -1, -1))
    if bpp == 32:
        return struct.pack('<IiiHHIIiiII', 40, n, 2 * n, 1, 32, 0, 0, 0, 0, 0, 0) + rows32(img) + andm, 0
    if bpp == 8:
        rgb = flatten(img, (0, 0, 0)); q = rgb.quantize(255, method=Image.Quantize.MEDIANCUT, dither=Image.Dither.NONE)
        qp = q.getpalette() + [0] * 768
        pal = [tuple(qp[i * 3:i * 3 + 3]) for i in range(255)]
        idx = np.asarray(q).astype(int) + 1; idx[a[:, :, 3] < 128] = 0; pal = [(0, 0, 0)] + pal
        body = rows8(idx); ncol = 256
    else:
        # 16 colours: map each pixel to the nearest of the brand colours, then to its VGA16 stand-in (hard edges, no dither)
        pal = VGA16; anchors = [(C('deep'), 4), (C('sky'), 14), (C('violet'), 13), (C('lamp'), 11), (C('glow'), 11), ((255, 255, 255), 15), ((0, 0, 0), 0)]
        ai = nearest_idx(flatten(img, (0, 0, 0)), [c for c, _ in anchors]); idx = np.array([v for _, v in anchors])[ai]
        idx[a[:, :, 3] < 128] = 0; ncol = 16
        body = b''.join(pad4(bytes(((idx[y, x] << 4) | idx[y, x + 1]) for x in range(0, n, 2))) for y in range(n - 1, -1, -1))
    palb = b''.join(bytes((c[2], c[1], c[0], 0)) for c in pal)
    return struct.pack('<IiiHHIIiiII', 40, n, 2 * n, 1, bpp, 0, 0, 0, 0, ncol, 0) + palb + body + andm, ncol % 256
def write_ico(path, frames):
    """frames: [(img, bpp)]; 256 px frames are stored as PNG."""
    blobs = []
    for img, bpp in frames:
        if img.width >= 256:
            b = io.BytesIO(); img.save(b, 'PNG', optimize=True); blobs.append((img.width, bpp, b.getvalue(), 0))
        else:
            data, ncol = ico_frame(img, bpp); blobs.append((img.width, bpp, data, ncol if bpp < 8 else 0))
    out = bytearray(struct.pack('<HHH', 0, 1, len(blobs))); off = 6 + 16 * len(blobs); body = b''
    for n, bpp, data, ncol in blobs:
        out += struct.pack('<BBBBHHII', n % 256, n % 256, ncol, 0, 1, bpp, len(data), off + len(body)); body += data
    open(os.path.join(ROOT, path), 'wb').write(bytes(out) + body)
    prev = canvas(sum(f[0].width + 4 for f in frames if f[0].width < 256) + 132, 132, (200, 200, 200)); x = 2
    for img, bpp in frames:
        im = img if img.width < 256 else img.resize((128, 128), Image.LANCZOS)
        if bpp == 32 or img.width >= 256: paste(prev, im, (x, 2)); x += im.width + 4
    OUT.append((path, prev))
def ico_sizes(b):
    n = struct.unpack('<H', b[4:6])[0]; out = []
    for i in range(n):
        w, h, nc, _, pl, bpp, sz, off = struct.unpack('<BBBBHHII', b[6 + 16 * i:22 + 16 * i])
        if b[off:off + 4] == b'\x89PNG': bpp = 32
        elif not bpp: bpp = struct.unpack('<H', b[off + 14:off + 16])[0]
        out.append((w or 256, bpp))
    return out

# ---- the boot screen (16 colours) -------------------------------------------------------------------------
# The kernel takes the VGA palette from logo.bmp, and every other boot bitmap indexes into it. Indices that the
# kept bitmaps (copyright, shutdown and hibernate text) use as antialiasing levels keep their brightness order
# (0 black, 1, 2, 3, 6, 8, 9, 12, 14, 15 greys); 4, 5, 7, 10, 11 and 13 are free in them and carry the brand colours:
# 4 flame orange, 5 navy tile, 7 violet, 10 cyan, 11 flame yellow, 13 tile rim. 15 is also the progress bar fill (BV_COLOR_WHITE).
BOOT = [(0, 0, 0), (12, 15, 28), C('ink'), (40, 44, 60), C('lamp'), C('deep'), (88, 92, 108), C('violet'),
        (120, 126, 145), (156, 160, 175), C('sky'), C('glow'), (200, 203, 214), C('harbor'), (226, 228, 236), (246, 247, 250)]
INBV = 'ntoskrnl/inbv/resources/'
BOOT_SAMEPAL = ['copyright.bmp', 'hibernate.bmp', 'shutdown.bmp', 'barwksta.bmp', 'barserver.bmp']

def boot_logo():
    p = INBV + 'logo.bmp'; ob = orig(p); H = bmp_info(ob)
    img = canvas(190, 224)
    paste(img, svg('mark-flat.svg', 128, 128), (31, 14))
    wm = wordmark(w=172, reverse=True); paste(img, wm, ((190 - wm.width) // 2, 158))
    idx = nearest_idx(img, BOOT); data = rle4(idx)
    write_like(p, ob, data, BOOT, pal_image(idx, BOOT))
    assert (decode_rle4(open(os.path.join(ROOT, p), 'rb').read(), H['w'], H['h']) == idx).all()
    return idx

def boot_progress():
    # frame at (251,351); the kernel fills x 259..380, y 352..364 with index 15, i.e. x 8..129, y 1..13 here
    p = INBV + 'progress.bmp'; ob = orig(p); S = 8
    big = Image.new('RGB', (138 * S, 15 * S), (0, 0, 0)); d = ImageDraw.Draw(big)
    d.rounded_rectangle([0, 0, 138 * S - 1, 15 * S - 1], radius=int(7.5 * S), fill=C('violet'))
    d.rounded_rectangle([S, S, 137 * S - 1, 14 * S - 1], radius=int(6.5 * S), fill=C('deep'))
    d.rectangle([8 * S, S, 130 * S - 1, 14 * S - 1], fill=(0, 0, 0))     # the track the kernel fills
    img = big.resize((138, 15), Image.LANCZOS)
    idx = nearest_idx(img, BOOT); idx[1:14, 8:130] = 0
    write_like(p, ob, rle4(idx), BOOT, pal_image(idx, BOOT))

def boot_line():
    # rotating line along the bottom edge: a cyan and violet gleam with a flame core
    p = INBV + 'line.bmp'; ob = orig(p)
    ramp = [0, 5, 5, 7, 7, 10]; idx = np.zeros((6, 640), int)
    for x in range(640):
        t = max(0.0, 1 - abs(x - 320) / 230.0); lvl = min(5, int(t ** 1.4 * 6))
        for y in range(6):
            v = ramp[max(0, lvl - (1 if y in (0, 5) else 0))]
            if abs(x - 320) < 14 and 1 <= y <= 4: v = 11
            elif abs(x - 320) < 26 and 1 <= y <= 4: v = 4
            idx[y, x] = v
    write_like(p, ob, rle4(idx), BOOT, pal_image(idx, BOOT))

GREYS = [0, 1, 2, 3, 6, 8, 9, 12, 14, 15]          # indices of BOOT that are neutral greys (the antialiasing levels of text)
def boot_repalette():
    """The kept text bitmaps use some of the indices that carry brand colours (5, 7, 10 and 13 as light-grey
    antialiasing levels). Their pixels are moved to the nearest grey by brightness, so the text stays grey and the
    brand colours are free to use."""
    lum = lambda c: 0.299 * c[0] + 0.587 * c[1] + 0.114 * c[2]
    opal = bmp_info(orig(INBV + 'logo.bmp'))['pal'][:16]
    remap = np.array([min(GREYS, key=lambda g: abs(lum(BOOT[g]) - lum(opal[i]))) for i in range(16)])
    for f in BOOT_SAMEPAL:
        p = INBV + f; ob = orig(p); H = bmp_info(ob)
        idx = remap[np.maximum(decode_rle4(ob, H['w'], H['h']), 0)]
        write_like(p, ob, rle4(idx), BOOT, pal_image(idx, BOOT))

def sos_band(server):
    """SOS (text) boot mode: header and footer line with their own palette. The header's palette becomes the
    screen palette: workstation background is index 7, text 15; server background 6, text 14; footer band 1."""
    hp = INBV + ('hserver.bmp' if server else 'hwksta.bmp'); fp = INBV + ('fserver.bmp' if server else 'fwksta.bmp')
    ob, fb = orig(hp), orig(fp)
    roles = {1: C('ink'), 6 if server else 7: C('deep'), 14 if server else 15: (255, 255, 255)}
    hdr = canvas(640, 55); hdr.alpha_composite(hgrad(640, 52, [(0, mix(C('deep'), C('harbor'), 0.5)), (1, C('deep'))]), (0, 0))
    hdr.alpha_composite(glowspot(640, 52, 40, 26, 160, 60, C('violet'), 0.22))
    paste(hdr, svg('mark-flat.svg', 40, 40), (16, 6))
    wm = wordmark(h=30, reverse=True); paste(hdr, wm, (66, 13))
    line = hgrad(640, 3, [(0, C('lamp')), (0.5, C('glow')), (1, C('lamp'))]); hdr.alpha_composite(line, (0, 52))
    rgb = hdr.convert('RGB')
    free = [i for i in range(16) if i not in roles and i != 0]
    q = rgb.quantize(len(free), method=Image.Quantize.MEDIANCUT, dither=Image.Dither.NONE)
    qq = q.getpalette() + [0] * 768
    qp = [tuple(qq[i * 3:i * 3 + 3]) for i in range(len(free))]
    pal = [(0, 0, 0)] * 16
    for i, c in zip(free, qp): pal[i] = c
    for i, c in roles.items(): pal[i] = c
    idx = nearest_idx(rgb, pal)
    write_like(hp, ob, rle4(idx), pal, pal_image(idx, pal))
    FH = bmp_info(fb); fh = FH['h']
    foot = hgrad(640, fh, [(0, C('lamp')), (0.5, C('glow')), (1, C('lamp'))])
    fidx = nearest_idx(foot, pal)
    write_like(fp, fb, rle4(fidx), pal, pal_image(fidx, pal))

# ---- banners and logos ------------------------------------------------------------------------------------
COPY = 'Copyright © 1996-2026 ReactOS Team & Contributors'
def about_banner():
    p = 'dll/branding/rosbrand/resources/bmp/brand_banner.bmp'; ob = orig(p)
    img = hgrad(413, 72, [(0, C('deep')), (1, mix(C('deep'), C('ink'), 0.85))])
    img.alpha_composite(glowspot(413, 72, 40, 30, 120, 70, C('violet'), 0.30))
    paste(img, mark_rev(48), (14, 5))
    wm = wordmark(h=30, reverse=True); paste(img, wm, (74, 11))
    text(img, (74 + wm.width + 10, 34), 'based on ReactOS', 12, 450, C('sky', 255))
    text(img, (14, 66), COPY, 10, 400, C('mist', 210))
    write_like(p, ob, rows24(img), preview=img)

def about_bannerline():
    p = 'dll/branding/rosbrand/resources/bmp/brand_bannerline.bmp'; ob = orig(p); H = bmp_info(ob)
    w, h = H['w'], abs(H['h']); xs = np.arange(w)
    t = (1 - np.cos(2 * np.pi * xs / w)) / 2                                   # seamless when scrolled
    arr = np.zeros((h, w, 3))
    for y in range(h):
        base = np.array(C('lamp')) * (0.82 if y == h - 1 else 1.0)
        hi = np.array(C('glow')) if y < h - 1 else np.array(C('lamp'))
        arr[y] = base[None, :] * (1 - t[:, None]) + hi[None, :] * t[:, None]
    img = Image.fromarray(arr.round().astype('uint8'), 'RGB').convert('RGBA')
    write_like(p, ob, rows24(img), preview=img)

def sysdm_logo():
    for base, (logo, mask) in (('dll/cpl/sysdm/resources/', ('rosbitmap.bmp', 'rosbitmap_mask.bmp')),
                               ('base/system/userinit/res/', ('rosbitmap.bmp', 'rosbitmap_mask.bmp'))):
        lay = canvas(320, 159, (0, 0, 0), 0)
        paste(lay, mark(112), (10, 20))
        wm = wordmark(w=176); paste(lay, wm, (132, 44))
        text(lay, (134, 44 + wm.height + 20), 'based on ReactOS', 16, 450, C('slate', 255))
        a = np.asarray(lay); rgb = a[:, :, :3].copy(); rgb[a[:, :, 3] == 0] = 255
        col = Image.fromarray(rgb, 'RGB'); alpha = Image.fromarray(a[:, :, 3], 'L')
        ob = orig(base + logo); write_like(base + logo, ob, rows24(col), preview=flatten(lay, (212, 208, 200)).convert('RGBA'))
        mb = orig(base + mask); MH = bmp_info(mb)
        midx = nearest_idx(Image.merge('RGB', (alpha, alpha, alpha)), MH['pal'][:MH['clr'] or 256])
        write_like(base + mask, mb, rows8(midx), preview=Image.merge('RGB', (alpha,) * 3).convert('RGBA'))

def setup_header():
    for p in ('base/setup/reactos/res/header.bmp', 'dll/win32/syssetup/resources/header.bmp'):
        img = canvas(49, 49, (255, 255, 255)); paste(img, mark(40), (5, 4))
        write_like(p, orig(p), rows24(img), preview=img)

def setup_watermark():
    for p in ('base/setup/reactos/res/watermark.bmp', 'dll/win32/syssetup/resources/watermark.bmp'):
        ob = orig(p); H = bmp_info(ob); w, h = H['w'], abs(H['h'])
        img = vgrad(w, h, [(0, mix(C('deep'), C('harbor'), 0.25)), (0.45, C('deep')), (1, mix(C('ink'), (0, 0, 0), 0.35))])
        beam = Image.new('L', (w, h), 0); ImageDraw.Draw(beam).polygon([(w * 0.62, 0), (w, 0), (w * 0.55, h), (-w * 0.25, h)], fill=60)
        beam = beam.filter(ImageFilter.GaussianBlur(18)); glowl = Image.new('RGBA', (w, h), C('violet') + (0,)); glowl.putalpha(beam)
        img.alpha_composite(glowl)
        img.alpha_composite(glowspot(w, h, w / 2, 76, 70, 60, C('violet'), 0.35))
        paste(img, mark_rev(72), ((w - 72) // 2, 40))
        wm = wordmark(w=118, reverse=True); paste(img, wm, ((w - wm.width) // 2, 128))
        text(img, (w // 2, h - 16), 'based on ReactOS', 11, 450, C('sky', 220), anchor='ms')
        rgb = np.asarray(img.convert('RGB')).astype(int)
        rgb = np.clip(rgb + np.random.default_rng(7).integers(-2, 3, rgb.shape), 0, 255).astype('uint8')
        q = Image.fromarray(rgb, 'RGB').quantize(256, method=Image.Quantize.MEDIANCUT, dither=Image.Dither.FLOYDSTEINBERG)
        qp = q.getpalette() + [0] * 768
        pal = [tuple(qp[i * 3:i * 3 + 3]) for i in range(256)]
        idx = np.asarray(q).astype(int)
        assert H['bc'] == 8 and H['comp'] == 0
        write_like(p, ob, rows8(idx), pal, pal_image(idx, pal))

def welcome_title():
    p = 'base/setup/welcome/res/title.bmp'; ob = orig(p)
    img = hgrad(558, 79, [(0, (255, 255, 255)), (0.55, C('cloud')), (1, C('mist'))])
    ghost = mark(160); a = np.asarray(ghost).copy(); a[:, :, 3] = (a[:, :, 3] * 0.10).astype('uint8')
    paste(img, Image.fromarray(a, 'RGBA'), (430, -30))
    paste(img, mark(56), (14, 11))
    wm = wordmark(h=42); paste(img, wm, (82, 8))
    text(img, (84, 69), 'an unofficial build based on ReactOS', 13, 450, C('slate', 255))
    write_like(p, ob, rows24(img), preview=img)

def shutdown_flag():
    for p in ('dll/win32/msgina/resources/reactos_flag.bmp', 'dll/win32/shell32/res/bitmaps/reactos_flag.bmp'):
        o = np.asarray(orig_img(p).convert('RGB')).astype(float); h, w = o.shape[:2]
        t = np.linspace(0, 1, w)[None, :, None]
        bg = o[:, :1, :] * (1 - t) + o[:, -1:, :] * t
        img = Image.fromarray(bg.round().astype('uint8'), 'RGB').convert('RGBA')
        paste(img, mark_rev(32), ((w - 32) // 2, (h - 32) // 2))
        write_like(p, orig(p), rows24(img), preview=img)

def logon_logo():
    p = 'base/system/logonui/res/123.bmp'; o = orig_img(p).convert('RGB')
    img = canvas(137, 86, o.getpixel((0, 0)))
    paste(img, mark_rev(48), ((137 - 48) // 2, 2))
    wm = wordmark(w=112, reverse=True); paste(img, wm, ((137 - wm.width) // 2, 54))
    write_like(p, orig(p), rows24(img), preview=img)

def startmenu_banner():
    p = 'base/shell/explorer/res/bmp/158.bmp'
    img = vgrad(21, 233, [(0, C('harbor')), (0.35, C('harbor')), (1, C('deep'))])
    wm = wordmark(h=15, reverse=True).rotate(90, expand=True)
    paste(img, wm, ((21 - wm.width) // 2, 233 - 22 - wm.height - 6))
    paste(img, mark(16), (2, 233 - 19))
    write_like(p, orig(p), rows24(img), preview=img)

def logon_saver():
    p = 'base/applications/screensavers/logon/res/0.bmp'; ob = orig(p); H = bmp_info(ob)
    img = canvas(H['w'], abs(H['h']))
    paste(img, mark(96), ((H['w'] - 96) // 2, 12))
    wm = wordmark(w=150, reverse=True); paste(img, wm, ((H['w'] - wm.width) // 2, 120))
    write_like(p, ob, rows24(img), preview=img)

# ---- Start buttons and screenshots that show the old Start button ----------------------------------------
def start_button():
    p = 'base/shell/explorer/res/bmp/143.bmp'                 # 32 bpp with straight alpha, transparent is 0,0,0,0
    img = canvas(25, 20, (0, 0, 0), 0); paste(img, mark(16), (2, 2))
    a = np.asarray(img).copy(); a[a[:, :, 3] == 0] = 0
    img = Image.fromarray(a, 'RGBA')
    write_like(p, orig(p), rows32(img), preview=flatten(img, (212, 208, 200)).convert('RGBA'))

def erase(img, box):
    """Fill box (x0, y0, x1, y1 inclusive) by interpolating each row between the pixels left and right of it."""
    a = np.asarray(img).astype(float).copy(); x0, y0, x1, y1 = box
    for y in range(y0, y1 + 1):
        l, r = a[y, x0 - 1], a[y, x1 + 1]; n = x1 - x0 + 2
        for x in range(x0, x1 + 1):
            t = (x - x0 + 1) / n; a[y, x] = l * (1 - t) + r * t
    return Image.fromarray(a.round().astype('uint8'), img.mode)

def brightest(img, box):
    a = np.asarray(img.convert('RGB').crop((box[0], box[1], box[2] + 1, box[3] + 1))).reshape(-1, 3)
    return tuple(int(v) for v in a[a.sum(1).argmax()])

def put_mark(img, kind, n, xy, colour_from=None):
    im = img.convert('RGBA')
    if kind == 'colour': im.alpha_composite(mark(n), xy)
    else: im.alpha_composite(glyph(n, colour_from), xy)
    return im

THEME_BUTTONS = [  # path, tile height, orb box in a tile, kind, size, position in a tile
    ('media/themes/Lautus/lautus.msstyles/bitmaps/NORMAL_STARTBUTTON.bmp', 25, (14, 5, 29, 21), 'glyph', 16, (14, 5)),
    ('media/themes/Lunar/lunar.msstyles/bitmaps/REACTOS_STARTBUTTON.bmp', 26, (12, 6, 30, 20), 'colour', 16, (13, 5)),
    ('media/themes/Mizu/mizu.msstyles/bitmaps/NORMAL_STARTBUTTON.bmp', 26, (11, 4, 30, 21), 'glyph', 16, (13, 5)),
    ('media/themes/Modern/modern.msstyles/bitmaps/Dark/DARK_STARTBUTTON.bmp', 30, (12, 4, 39, 25), 'glyph', 20, (16, 5)),
    ('media/themes/Modern/modern.msstyles/bitmaps/Light/LIGHT_STARTBUTTON.bmp', 30, (12, 4, 39, 25), 'glyph', 20, (16, 5)),
]
def theme_buttons():
    for p, th, box, kind, n, pos in THEME_BUTTONS:
        ob = orig(p); H = bmp_info(ob); src = Image.open(io.BytesIO(ob))
        rgba = src.convert('RGBA') if H['bc'] == 32 else src.convert('RGB')
        out = rgba.copy()
        for k in range(abs(H['h']) // th):
            oy = k * th; bb = (box[0], box[1] + oy, box[2], box[3] + oy)
            col = brightest(rgba, bb)
            tile = erase(rgba.crop((0, oy, rgba.width, oy + th)), box)
            tile = put_mark(tile, kind, n, pos, col)
            out.paste(tile.convert(rgba.mode), (0, oy))
        if H['bc'] == 32:
            a = np.asarray(out.convert('RGBA')).copy(); oa = np.asarray(rgba.convert('RGBA'))
            a[:, :, 3] = np.maximum(oa[:, :, 3], a[:, :, 3]); write_like(p, ob, rows32(Image.fromarray(a, 'RGBA')))
        else:
            write_like(p, ob, rows24(out))
        if p.endswith('lautus.msstyles/bitmaps/NORMAL_STARTBUTTON.bmp'):
            # the PNG twin (grey + alpha) follows the bitmap: magenta is transparent
            a = np.asarray(out.convert('RGB')).astype(int)
            lum = (a @ np.array([299, 587, 114]) // 1000).astype('uint8')
            alpha = np.where((a == [255, 0, 255]).all(-1), 0, 255).astype('uint8')
            png = Image.merge('LA', (Image.fromarray(lum, 'L'), Image.fromarray(alpha, 'L')))
            pp = p[:-4] + '.png'; png.save(os.path.join(ROOT, pp), optimize=True); OUT.append((pp, png.convert('RGBA')))

THUMBS = [  # setup theme previews: orb box, kind, size, position
    ('dll/win32/syssetup/resources/thmclassic.bmp', (4, 142, 22, 157), 'colour', 16, (5, 142)),
    ('dll/win32/syssetup/resources/thmlunar.bmp', (12, 141, 30, 156), 'colour', 16, (13, 141)),
    ('dll/win32/syssetup/resources/thmlautus.bmp', (14, 141, 29, 157), 'glyph', 16, (14, 141)),
    ('dll/win32/syssetup/resources/thmmizu.bmp', (12, 141, 33, 160), 'glyph', 16, (15, 143)),
]
def theme_thumbs():
    for p, box, kind, n, pos in THUMBS:
        src = orig_img(p).convert('RGB'); col = brightest(src, box)
        img = put_mark(erase(src, box), kind, n, pos, col)
        write_like(p, orig(p), rows24(img), preview=img)

def startmenu_previews():
    """Taskbar properties, Start Menu page: the Start button and, in the classic preview, the menu banner."""
    for p in ('base/shell/explorer/res/bmp/170.bmp', 'base/shell/explorer/res/bmp/171.bmp'):
        ob = orig(p); H = bmp_info(ob); src = Image.open(io.BytesIO(ob)); idx = np.asarray(src).astype(int)
        pal = H['pal'][:256]; rgb = src.convert('RGB')
        patch = erase(rgb, (4, 172, 11, 177)).convert('RGBA')
        patch.alpha_composite(mark(16).resize((7, 7), Image.LANCZOS), (4, 171))
        idx[170:179, 2:13] = nearest_idx(patch.crop((2, 170, 13, 179)), pal)
        if p.endswith('171.bmp'):
            banner = Image.open(os.path.join(ROOT, 'base/shell/explorer/res/bmp/158.bmp')).convert('RGB').resize((11, 102), Image.LANCZOS)
            idx[68:170, 1:12] = nearest_idx(banner, pal)
        write_like(p, ob, rows8(idx), preview=pal_image(idx, pal))

def taskbar_previews():
    """Taskbar properties, Taskbar page: the Start button, and the window button that read "ReactOS Explorer"."""
    face = (212, 208, 200)
    f = ImageFont.truetype(os.path.join(ROOT, 'media/fonts/tahoma.ttf'), 11)
    def label(text):
        t = Image.new('L', (160, 24), 0); d = ImageDraw.Draw(t); d.fontmode = '1'; d.text((10, 5), text, font=f, fill=255)
        return np.asarray(t) > 0
    old = label('ReactOS Explorer'); new = label('NitroOS Explorer')
    ys, xs = np.where(old); oy0, oy1, ox0, ox1 = ys.min(), ys.max(), xs.min(), xs.max()
    tmpl = old[oy0:oy1 + 1, ox0:ox1 + 1]
    for n in range(146, 154):
        p = f'base/shell/explorer/res/bmp/{n}.bmp'; ob = orig(p)
        img = erase(orig_img(p).convert('RGB'), (4, 14, 18, 27)).convert('RGBA')
        img.alpha_composite(mark(16), (3, 13))
        a = np.asarray(img.convert('RGB')).astype(int); ink = a.max(-1) < 60
        best = (0, 0, 0)
        th, tw = tmpl.shape
        for y in range(10, 22):
            for x in range(60, a.shape[1] - tw):
                sub = ink[y:y + th, x:x + tw]; u = (sub | tmpl).sum()
                if u:
                    sc = (sub & tmpl).sum() / u
                    if sc > best[0]: best = (sc, x, y)
        if best[0] > 0.6:
            sc, x, y = best; out = a.copy()
            out[y - 1:y + th + 1, x - 1:x + tw + 1] = face
            ny, nx = np.where(new); out[ny - oy0 + y, nx - ox0 + x] = 0
            img = Image.fromarray(out.astype('uint8'), 'RGB').convert('RGBA')
        write_like(p, ob, rows24(img), preview=img)

def logon_saver_icon():
    p = 'base/applications/screensavers/logon/res/icon_logon.ico'; ob = orig(p); frames = []
    ref = None                                         # screen box of the largest frame, as fractions
    for n, bpp in sorted(ico_sizes(ob), reverse=True):
        fr = Image.open(io.BytesIO(ob)).ico.getimage((n, n)).convert('RGBA'); a = np.asarray(fr).copy()
        dark = (a[:, :, :3].max(-1) < 24) & (a[:, :, 3] > 200)
        ys, xs = np.where(dark)
        if len(ys) > n * n // 8:
            y0, y1, x0, x1 = ys.min(), ys.max(), xs.min(), xs.max()
            if ref is None: ref = (y0 / n, (y1 + 1) / n, x0 / n, (x1 + 1) / n)
        else:
            y0, y1, x0, x1 = round(ref[0] * n), round(ref[1] * n) - 1, round(ref[2] * n), round(ref[3] * n) - 1
        a[y0:y1 + 1, x0:x1 + 1] = (0, 0, 0, 255); fr = Image.fromarray(a, 'RGBA')
        s = int(min(x1 - x0 + 1, y1 - y0 + 1) * 0.8)
        m = mark(16) if s >= 16 else mark(16).resize((s, s), Image.LANCZOS)
        if s >= 16: s = 16
        fr.alpha_composite(m, (int(x0 + (x1 - x0 + 1 - s) / 2), int(y0 + (y1 - y0 + 1 - s) / 2)))
        frames.append((fr, bpp))
    write_ico(p, sorted(frames, key=lambda f: (f[0].width, f[1])))

# ---- icons ------------------------------------------------------------------------------------------------
ICONS = ['win32ss/user/user32/resources/oic_reactos.ico', 'base/setup/reactos/res/roslogo.ico',
         'base/setup/reactos/res/roslogo_2.ico', 'base/setup/welcome/res/welcome.ico',
         'base/shell/progman/res/roslogo.ico', 'boot/bootdata/icon.ico', 'base/applications/osk/res/reactos.ico']
def icons():
    for p in ICONS:
        have = ico_sizes(orig(p)); sizes = sorted({n for n, _ in have})
        add = [] if p.endswith('osk/res/reactos.ico') else [n for n in (16, 20, 24, 32, 48, 256) if n not in sizes]
        frames = []
        for n in sorted(set(sizes + add)):
            img = mark(n)
            bpps = sorted({b for m, b in have if m == n}) or [32]
            if 32 not in bpps: bpps.append(32)
            for b in bpps: frames.append((img, b))
        write_ico(p, frames)

# ---- wallpaper --------------------------------------------------------------------------------------------
def screen(base, rgb, alpha):
    """Screen-blend light of colour rgb with an alpha map (0..1) onto a float RGB array."""
    l = np.array(rgb, float)[None, None, :] / 255 * alpha[..., None]
    return 255 - (255 - base) * (1 - l)

def wallpaper():
    """Default wallpaper: navy deepening to ink, with the flame of the mark running up the right-hand side:
    a thin cyan stripe and a broad orange one with a yellow edge, with a soft halo, and a violet beam behind."""
    W, H = 1920, 1080; p = 'media/branding/wallpaper/Nitro.bmp'
    os.makedirs(os.path.dirname(os.path.join(ROOT, p)), exist_ok=True)
    yy, xx = np.mgrid[0:H, 0:W].astype(float)
    t = np.clip((xx / W) * 0.5 + (yy / H) * 0.8, 0, 1.3) / 1.3
    c0, c1, c2 = np.array(mix(C('deep'), C('harbor'), 0.55), float), np.array(C('deep'), float), np.array(C('ink'), float)
    k = t[..., None]
    base = np.where(k < 0.5, c0 + (c1 - c0) * (k / 0.5), c1 + (c2 - c1) * ((k - 0.5) / 0.5))
    def mask(polys, blur):
        m = Image.new('L', (W, H), 0); d = ImageDraw.Draw(m)
        for pts, v in polys: d.polygon(pts, fill=v)
        return np.asarray(m.filter(ImageFilter.GaussianBlur(blur))).astype(float) / 255
    def band(c1_, c2_):   # between the lines x+y=c1_ and x+y=c2_
        return [(c1_ + 100, -100), (c2_ + 100, -100), (c2_ - H - 100, H + 100), (c1_ - H - 100, H + 100)]
    beam = mask([(band(1500, 2500), 255)], 160)
    base = screen(base, C('violet'), beam * 0.22)
    fade = np.clip(1.1 - (xx + yy - 1200) / 1700, 0.3, 1)             # strongest at the lower left of the stripes
    thin = mask([(band(1840, 1890), 255)], 2.5)
    broad = mask([(band(1960, 2090), 255)], 2.5)
    halo = mask([(band(1930, 2130), 255)], 38)
    base = base * (1 - (thin * 0.80 * fade)[..., None]) + np.array(C('sky'), float) * (thin * 0.80 * fade)[..., None]
    base = screen(base, (255, 150, 60), halo * 0.22 * fade)
    base = base * (1 - (broad * 0.95 * fade)[..., None]) + np.array(C('lamp'), float) * (broad * 0.95 * fade)[..., None]
    edge = mask([(band(2062, 2090), 255)], 2.0)
    base = base * (1 - (edge * 0.9 * fade)[..., None]) + np.array(C('glow'), float) * (edge * 0.9 * fade)[..., None]
    vig = 1 - 0.14 * np.clip(((xx - W / 2) / (W / 2)) ** 2 + ((yy - H / 2) / (H / 2)) ** 2 - 0.3, 0, 1)
    base = base * vig[..., None]
    # drawn at 1920x1080, stored at 1600x900 to keep the medium small; the desktop fills the screen with it
    big = Image.fromarray(np.clip(base, 0, 255).round().astype('uint8'), 'RGB').resize((1600, 900), Image.LANCZOS)
    W, H = big.size; base = np.asarray(big).astype(float)
    rgb = np.clip(base + np.random.default_rng(11).uniform(-1.5, 1.5, base.shape), 0, 255).round().astype('uint8')
    img = Image.fromarray(rgb, 'RGB')
    hdr = struct.pack('<IiiHHIIiiII', 40, W, H, 1, 24, 0, 0, 2835, 2835, 0, 0)
    data = rows24(img); fh = b'BM' + struct.pack('<IHHI', 14 + 40 + len(data), 0, 0, 54)
    open(os.path.join(ROOT, p), 'wb').write(fh + hdr + data)
    OUT.append((p, img.convert('RGBA')))

ASSETS = dict(boot_logo=boot_logo, boot_progress=boot_progress, boot_line=boot_line, boot_repalette=boot_repalette,
              sos_wksta=lambda: sos_band(False), sos_server=lambda: sos_band(True), about_banner=about_banner,
              about_bannerline=about_bannerline, sysdm_logo=sysdm_logo, setup_header=setup_header,
              setup_watermark=setup_watermark, welcome_title=welcome_title, shutdown_flag=shutdown_flag,
              logon_logo=logon_logo, startmenu_banner=startmenu_banner, logon_saver=logon_saver,
              start_button=start_button, theme_buttons=theme_buttons, theme_thumbs=theme_thumbs,
              startmenu_previews=startmenu_previews, taskbar_previews=taskbar_previews, logon_saver_icon=logon_saver_icon, icons=icons, wallpaper=wallpaper)

def boot_screen_preview():
    """The boot screen as the kernel composes it, from the written files."""
    scr = np.zeros((480, 640), int)
    def blit(f, x, y):
        b = open(os.path.join(ROOT, INBV + f), 'rb').read(); H = bmp_info(b); i = decode_rle4(b, H['w'], H['h'])
        m = i >= 0; scr[y:y + H['h'], x:x + H['w']][m] = i[m]
    blit('logo.bmp', 225, 94); blit('progress.bmp', 251, 351); scr[352:365, 259:320] = 15
    blit('copyright.bmp', 22, 480 - 26 - 20); blit('line.bmp', 0, 474)
    return pal_image(scr, BOOT)

if __name__ == '__main__':
    sel = [s for s in A.only.split(',') if s] or list(ASSETS)
    for name in sel:
        ASSETS[name](); print('rendered', name)
    if A.sheet:
        os.makedirs(A.sheet, exist_ok=True)
        if 'boot_logo' in sel: OUT.append(('boot screen (composed)', boot_screen_preview()))
        items = []
        for path, im in OUT:
            im = im.convert('RGBA'); z = 1
            if im.width <= 64 and im.height <= 64: z = 4
            elif im.width <= 200 and im.height <= 100: z = 2
            if im.width > 900: im = im.resize((640, int(im.height * 640 / im.width)), Image.LANCZOS)
            elif z > 1: im = im.resize((im.width * z, im.height * z), Image.NEAREST)
            items.append((path, im))
            im.save(os.path.join(A.sheet, path.replace('/', '_').replace(' ', '_') + '.png'))
        W = 1500; x = y = 0; rowh = 0; placed = []
        for path, im in items:
            w, h = max(im.width, 220), im.height + 16
            if x + w > W: x = 0; y += rowh + 10; rowh = 0
            placed.append((path, im, x, y)); x += w + 12; rowh = max(rowh, h)
        sheet = Image.new('RGB', (W, y + rowh + 10), (150, 150, 155)); d = ImageDraw.Draw(sheet)
        for path, im, x, y in placed:
            d.text((x, y), path.split('/')[-1] if '/' in path else path, fill=(0, 0, 0)); sheet.paste(im, (x, y + 14), im)
        sheet.save(os.path.join(A.sheet, 'contact-sheet.png')); print('sheet', os.path.join(A.sheet, 'contact-sheet.png'))
