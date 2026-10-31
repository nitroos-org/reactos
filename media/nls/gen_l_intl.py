#!/usr/bin/env python3
# PROJECT:     ReactOS NLS
# LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
# PURPOSE:     Generate media/nls/l_intl.nls (the Unicode upcase and lowcase
#              tables used by RtlUpcaseUnicodeChar and RtlDowncaseUnicodeChar)
#              from the Unicode Character Database.
#
# Usage:
#   gen_l_intl.py --ucd UnicodeData.txt [-o l_intl.nls] [--check l_intl.nls]
#
# The input is the UnicodeData.txt of Unicode 5.1.0
#   https://www.unicode.org/Public/5.1.0/ucd/UnicodeData.txt
# The case tables of Windows (measured on a Windows oracle through
# RtlUpcaseUnicodeChar and RtlDowncaseUnicodeChar, U+0000-U+FFFF) are exactly
# the simple case mappings of that version with one rule on top: a mapping
# is only kept if it is a pair, that is if upcase(c) = u then downcase(u) = c,
# and the other way round for downcase. That leaves unmapped
#   U+00B5 U+0131 U+017F U+03C2 (their uppercase has another lowercase),
#   U+01C5 U+01C8 U+01CB U+01F2 (titlecase digraphs), U+0345 U+1FBE,
#   U+03D0 U+03D1 U+03D5 U+03D6 U+03F0 U+03F1 U+03F5 U+1E9B,
# and for downcase U+0130 U+03F4 U+1E9E U+2126 U+212A U+212B.
# Later Unicode versions add mappings Windows does not have (U+023F, U+0525,
# U+2CEC and more): with another UnicodeData.txt the output differs and the
# differing code points are listed, which is what --check is for.
#
# The file is: WORD 1, WORD (1 + size of the upcase table in words), the upcase
# table, WORD (1 + size of the lowcase table), the lowcase table. A table
# maps a character in three steps (high byte, next nibble, low nibble) to a
# 16-bit delta that is added to the character; equal blocks are shared and
# placed in order of first use: the 256 first-level words, the second-level
# blocks, the third-level (delta) blocks.
#
# Pure Python 3 standard library.

import argparse
import hashlib
import struct
import sys

UCD_VERSION = "5.1.0"
UCD_SHA256 = "8bd83e9c4e339728ecd532c5b174de5beb9cb4bab5db14e44fcd03ccb2e2c1b5"

# Windows leaves these without an upcase mapping (they follow from the pair
# rule; the generator checks that they do)
WINDOWS_UPCASE_UNMAPPED = (0x00B5, 0x0131, 0x017F, 0x03C2)


def read_ucd(path):
    """Simple uppercase and lowercase mappings of the BMP: ({c: u}, {c: l})."""
    upper, lower = {}, {}
    with open(path, "rb") as f:
        raw = f.read()
    digest = hashlib.sha256(raw).hexdigest()
    if digest != UCD_SHA256:
        print("gen_l_intl: note: %s is not the UnicodeData.txt of Unicode %s "
              "(sha256 %s)" % (path, UCD_VERSION, digest), file=sys.stderr)
    for line in raw.decode("utf-8").splitlines():
        if not line:
            continue
        fields = line.split(";")
        c = int(fields[0], 16)
        if c > 0xFFFF:
            continue
        if fields[12]:
            upper[c] = int(fields[12], 16)
        if fields[13]:
            lower[c] = int(fields[13], 16)
    return upper, lower


def build_deltas(upper, lower):
    """The two delta arrays (65536 signed 16-bit values) with the pair rule."""
    up = [0] * 65536
    lo = [0] * 65536
    for c, u in upper.items():
        if u <= 0xFFFF and lower.get(u) == c:
            up[c] = u - c
    for c, l in lower.items():
        if l <= 0xFFFF and upper.get(l) == c:
            lo[c] = l - c
    for c in WINDOWS_UPCASE_UNMAPPED:
        assert up[c] == 0, "U+%04X must stay unmapped" % c
    wrap = lambda t: [((x + 0x8000) & 0xFFFF) - 0x8000 for x in t]
    return wrap(up), wrap(lo)


def layout(delta):
    """Words of one three-level table for 65536 deltas."""
    l3_blocks, l3_index = [], {}
    l2_blocks, l2_index = [], {}
    l1 = []
    for hi in range(256):
        l2 = []
        for mid in range(16):
            base = (hi << 8) | (mid << 4)
            block = tuple(delta[base + lo] & 0xFFFF for lo in range(16))
            if block not in l3_index:
                l3_index[block] = len(l3_blocks)
                l3_blocks.append(block)
            l2.append(l3_index[block])
        l2 = tuple(l2)
        if l2 not in l2_index:
            l2_index[l2] = len(l2_blocks)
            l2_blocks.append(l2)
        l1.append(l2_index[l2])
    base2 = 256
    base3 = base2 + 16 * len(l2_blocks)
    words = [base2 + 16 * i for i in l1]
    for l2 in l2_blocks:
        words += [base3 + 16 * i for i in l2]
    for block in l3_blocks:
        words += list(block)
    return words


def build_file(up, lo):
    up_words = layout(up)
    lo_words = layout(lo)
    words = [1, 1 + len(up_words)] + up_words + [1 + len(lo_words)] + lo_words
    return struct.pack("<%dH" % len(words), *words)


def parse_tables(data):
    """The delta arrays stored in an l_intl.nls image."""
    words = struct.unpack("<%dH" % (len(data) // 2), data[: len(data) // 2 * 2])
    if words[0] != 1:
        raise ValueError("unexpected version word %u" % words[0])
    tables = []
    for start in (2, words[1] + 2):
        t = words[start:]
        out = [0] * 65536
        for hi in range(256):
            o2 = t[hi]
            for mid in range(16):
                o3 = t[o2 + mid]
                for lo_ in range(16):
                    v = t[o3 + lo_]
                    out[(hi << 8) | (mid << 4) | lo_] = v - 0x10000 if v >= 0x8000 else v
        tables.append(out)
    return tables


def report_diff(name, a, b, label_a, label_b):
    diffs = [c for c in range(65536) if a[c] != b[c]]
    for c in diffs:
        print("  %s U+%04X: %s -> U+%04X, %s -> U+%04X" % (
            name, c, label_a, (c + a[c]) & 0xFFFF, label_b, (c + b[c]) & 0xFFFF))
    return len(diffs)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0] if __doc__ else None)
    ap.add_argument("--ucd", required=True, metavar="UnicodeData.txt",
                    help="UnicodeData.txt of Unicode %s" % UCD_VERSION)
    ap.add_argument("-o", "--output", metavar="FILE", help="write the generated l_intl.nls")
    ap.add_argument("--check", metavar="FILE",
                    help="compare the generated image with FILE; exit 1 and list the "
                         "differing code points if it is not byte-identical")
    args = ap.parse_args()
    if not args.output and not args.check:
        ap.error("give --output and/or --check")

    upper, lower = read_ucd(args.ucd)
    up, lo = build_deltas(upper, lower)
    image = build_file(up, lo)
    if args.output:
        with open(args.output, "wb") as f:
            f.write(image)
        print("wrote %s (%u bytes, sha256 %s)" % (
            args.output, len(image), hashlib.sha256(image).hexdigest()))
    if args.check:
        with open(args.check, "rb") as f:
            ref = f.read()
        if ref == image:
            print("%s: byte-identical (%u bytes)" % (args.check, len(ref)))
            return 0
        print("%s: DIFFERS (generated %u bytes, file %u bytes)" % (args.check, len(image), len(ref)))
        ref_up, ref_lo = parse_tables(ref)
        n = report_diff("upcase", up, ref_up, "generated", "file")
        n += report_diff("lowcase", lo, ref_lo, "generated", "file")
        if n == 0:
            print("  the mappings are equal; only the layout of the file differs")
        else:
            print("  %u differing mappings" % n)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
