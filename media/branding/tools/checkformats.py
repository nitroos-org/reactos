#!/usr/bin/env python3
"""checkformats.py TREE [REV]: compare every changed bitmap and icon with its upstream original at REV:
size, bit depth, compression, colours used, palette size and the pixel data size must match;
new bitmaps must have a consistent header; icons must keep every original (size, depth) frame."""
import io, struct, subprocess, sys
from PIL import Image
tree = sys.argv[1]; rev = sys.argv[2] if len(sys.argv) > 2 else '2d0604e543'
files = subprocess.check_output(['git', '-C', tree, 'diff', '--name-only', rev, '--', '*.bmp', '*.ico', '*.png']).decode().split()
def bmp(b):
    off = struct.unpack('<I', b[10:14])[0]; hs = struct.unpack('<I', b[14:18])[0]
    w, h, pl, bc, comp = struct.unpack('<iiHHI', b[18:34]); clr = struct.unpack('<I', b[46:50])[0]
    return (w, h, bc, comp, off, clr)
def ico(b):
    n = struct.unpack('<H', b[4:6])[0]; out = set()
    for i in range(n):
        w, hh, nc, _, pl, bpp, sz, off = struct.unpack('<BBBBHHII', b[6 + 16 * i:22 + 16 * i])
        if b[off:off + 4] == b'\x89PNG': bpp = 32
        elif not bpp: bpp = struct.unpack('<H', b[off + 14:off + 16])[0]
        out.add((w or 256, bpp))
    return out
bad = 0
for f in files:
    new = open(f'{tree}/{f}', 'rb').read()
    try: old = subprocess.check_output(['git', '-C', tree, 'show', f'{rev}:{f}'], stderr=subprocess.DEVNULL)
    except subprocess.CalledProcessError:
        ok = True
        if f.endswith('.bmp'):
            w, h, bc, comp, off, clr = bmp(new)
            ok = new[:2] == b'BM' and comp == 0 and len(new) == off + ((w * bc + 31) // 32) * 4 * abs(h)
        bad += not ok; print('NEW ' if ok else 'BAD ', f); continue
    if f.endswith('.bmp'):
        o, n = bmp(old), bmp(new); ok = o == n; extra = ''
        w, h, bc, comp, off, clr = n
        if comp in (0, 3) and len(new) != off + ((w * bc + 31) // 32) * 4 * abs(h): ok = False; o = ('pixel data size', len(new))
    elif f.endswith('.ico'): o, n = ico(old), ico(new); ok = o <= n; extra = ' added %s' % sorted(n - o)
    else:
        oi, ni = Image.open(io.BytesIO(old)), Image.open(io.BytesIO(new)); o, n = (oi.size, oi.mode), (ni.size, ni.mode); ok = o == n; extra = ''
    bad += not ok
    print('OK  ' if ok else 'BAD ', f, o if not ok else '', extra if ok and f.endswith('.ico') else '')
print('bad', bad); sys.exit(1 if bad else 0)
