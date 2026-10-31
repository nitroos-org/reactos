#!/usr/bin/env python3
# PROJECT:     ReactOS system libraries
# LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
# PURPOSE:     Generate normdata.c (the Unicode normalization, case folding and assignment tables of kernel32's
#              NormalizeString and nameprep) from the Unicode Character Database
# COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
#
# usage: mknormdata.py UCD_DIR > normdata.c
#
# UCD_DIR holds UnicodeData.txt, CompositionExclusions.txt and CaseFolding.txt of Unicode 11.0.0
# (https://www.unicode.org/Public/11.0.0/ucd/). Windows 10 22H2 normalizes with the data of Unicode 11.0 (every
# code point of the Basic and the supplementary planes was compared with this data, see the apitest).
# The UCD files are distributed under the Unicode License (https://www.unicode.org/license.txt), which
# is compatible with the LGPL.

import os
import sys

UCD = sys.argv[1]
SB, LB, VB, TB = 0xAC00, 0x1100, 0x1161, 0x11A7
LC, VC, TC = 19, 21, 28
SC = LC * VC * TC


def read(name):
    return open(os.path.join(UCD, name), encoding='utf-8')


ccc = {}
canon = {}
compat = {}
assigned = {}
first = None
for line in read('UnicodeData.txt'):
    f = line.rstrip('\n').split(';')
    cp = int(f[0], 16)
    if f[1].endswith(', First>'):
        first = cp
        continue
    if f[1].endswith(', Last>'):
        for c in range(first, cp + 1):
            assigned[c] = f[2]
        continue
    assigned[cp] = f[2]
    if int(f[3]):
        ccc[cp] = int(f[3])
    d = f[5]
    if d:
        if d.startswith('<'):
            compat[cp] = tuple(int(x, 16) for x in d.split()[1:])
        else:
            canon[cp] = tuple(int(x, 16) for x in d.split())

exclusions = set()
for line in read('CompositionExclusions.txt'):
    line = line.split('#')[0].strip()
    if line:
        exclusions.add(int(line.split()[0], 16))

fold = {}
for line in read('CaseFolding.txt'):
    line = line.split('#')[0].strip()
    if not line:
        continue
    f = [x.strip() for x in line.split(';')]
    if f[1] in ('C', 'F'):
        fold[int(f[0], 16)] = tuple(int(x, 16) for x in f[2].split())


def decomp(cp, use_compat):
    if SB <= cp < SB + SC:
        return (cp,)
    t = canon.get(cp)
    if t is None and use_compat:
        t = compat.get(cp)
    if t is None:
        return (cp,)
    out = ()
    for x in t:
        out += decomp(x, use_compat)
    return out


full_canon = {}
full_compat = {}
for cp in sorted(set(canon) | set(compat)):
    if SB <= cp < SB + SC:
        continue
    d = decomp(cp, False)
    if d != (cp,):
        full_canon[cp] = d
    k = decomp(cp, True)
    if k != (cp,) and k != d:
        full_compat[cp] = k

compose = {}
for cp, t in canon.items():
    if len(t) != 2 or cp in exclusions or ccc.get(cp, 0) or ccc.get(t[0], 0):
        continue
    compose[t] = cp

# code points without an assignment: unassigned, private use and the Hangul fillers
unassigned = []
for cp in range(0x110000):
    if 0xD800 <= cp < 0xE000:
        continue
    if cp not in assigned or assigned[cp] == 'Co' or cp in (0x115F, 0x1160):
        unassigned.append(cp)


def ranges(cps):
    out = []
    s = p = None
    for c in sorted(cps):
        if s is None:
            s = p = c
        elif c == p + 1:
            p = c
        else:
            out.append((s, p))
            s = p = c
    if s is not None:
        out.append((s, p))
    return out


def utf16(cps):
    out = []
    for cp in cps:
        if cp >= 0x10000:
            cp -= 0x10000
            out += [0xD800 + (cp >> 10), 0xDC00 + (cp & 0x3FF)]
        else:
            out.append(cp)
    return out


pool = []
pool_index = {}


def pool_add(cps):
    units = tuple(cps)
    if units in pool_index:
        return pool_index[units]
    # reuse the tail of an earlier string where possible
    off = len(pool)
    pool.extend(units)
    pool_index[units] = off
    return off


def table(name, mapping, as_utf16):
    rows = []
    for cp in sorted(mapping):
        units = utf16(mapping[cp]) if as_utf16 else list(mapping[cp])
        rows.append((cp, pool_add(units), len(units)))
    return rows


# the strings of the decompositions and foldings are UTF-16
canon_rows = table('canon', full_canon, True)
compat_rows = table('compat', full_compat, True)
fold_rows = table('fold', fold, True)
assert max(r[1] for r in canon_rows + compat_rows + fold_rows) < 0x10000 and len(pool) < 0x10000
assert max(max(len(utf16(v)) for v in full_canon.values()), max(len(utf16(v)) for v in full_compat.values())) <= 20
assert max(len(utf16(v)) for v in fold.values()) <= 4

# ranges of equal ccc
ccc_rows = []
cps = sorted(ccc)
i = 0
while i < len(cps):
    j = i
    while j + 1 < len(cps) and cps[j + 1] == cps[j] + 1 and ccc[cps[j + 1]] == ccc[cps[i]]:
        j += 1
    ccc_rows.append((cps[i], cps[j], ccc[cps[i]]))
    i = j + 1

comp_rows = sorted((a, b, r) for (a, b), r in compose.items())
una_rows = ranges(unassigned)

o = []
w = o.append
w('/*')
w(' * PROJECT:     ReactOS system libraries')
w(' * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)')
w(' * PURPOSE:     Unicode 11.0 normalization (NFC, NFD, NFKC, NFKD), case folding and assignment tables of')
w(' *              NormalizeString and the nameprep of IdnToAscii')
w(' * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>')
w(' *')
w(' * Generated by mknormdata.py from UnicodeData.txt, CompositionExclusions.txt and CaseFolding.txt of Unicode')
w(' * 11.0.0. Do not edit. The Unicode data files are distributed under the Unicode License')
w(' * (https://www.unicode.org/license.txt).')
w(' */')
w('')
w('#include "normdata.h"')
w('')
w('/* the decompositions and foldings of one code point, as an offset and a length in norm_pool */')
w('const USHORT norm_pool[%d] =' % len(pool))
w('{')
for i in range(0, len(pool), 12):
    w('    ' + ', '.join('0x%04X' % x for x in pool[i:i + 12]) + ',')
w('};')
w('')


def emit_rows(typ, name, rows, fmt):
    w('const %s %s[%d] =' % (typ, name, len(rows)))
    w('{')
    for r in rows:
        w('    ' + fmt % r + ',')
    w('};')
    w('const ULONG %s_count = %d;' % (name, len(rows)))
    w('')


emit_rows('NORM_MAP', 'norm_canon', canon_rows, '{ 0x%05X, %d, %d }')
emit_rows('NORM_MAP', 'norm_compat', compat_rows, '{ 0x%05X, %d, %d }')
emit_rows('NORM_MAP', 'norm_fold', fold_rows, '{ 0x%05X, %d, %d }')
emit_rows('NORM_CCC', 'norm_ccc', ccc_rows, '{ 0x%05X, 0x%05X, %d }')
emit_rows('NORM_COMP', 'norm_comp', comp_rows, '{ 0x%05X, 0x%05X, 0x%05X }')
emit_rows('NORM_RANGE', 'norm_unassigned', una_rows, '{ 0x%05X, 0x%05X }')
sys.stdout.write('\n'.join(o) + '\n')
sys.stderr.write('canon %d compat %d fold %d ccc %d comp %d unassigned %d pool %d\n' % (
    len(canon_rows), len(compat_rows), len(fold_rows), len(ccc_rows), len(comp_rows), len(una_rows), len(pool)))
