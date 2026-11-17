#!/usr/bin/env python3
"""Rename the product name in the literal (non-macro) branding text.

The product name has ONE source of truth for everything that is compiled from C/C++/RC code: NITRO_NAME in
sdk/include/reactos/version.cmake (-> BRAND_PRODUCT_NAME / BRAND_PRODUCT_NAME_W in buildno.h).  Text that cannot
use the macro (translated .rc string tables, .inf/.ini/.mc message files, setup .h language tables, boot sector
assembly, CMake shortcut names) still spells the name out.  After changing NITRO_NAME run, from the repo root:

    python3 media/branding/rename-product.py OLD NEW          # rewrite
    python3 media/branding/rename-product.py OLD NEW --check  # list what would change, exit 1 if any
    python3 media/branding/rename-product.py --new-since FROM [TO]  # after merging main: list lines added FROM..TO (TO default HEAD) that
                                                              # spell "ReactOS"/"Nitro" outside comments (review by hand)

Only whole-word occurrences are rewritten.  Not touched: identifiers/ProgIds (OLD.xxx, OLD\\path), the
"ReactOS-OLD" project tags, the font family "OLD Caption Icons", third-party data (pci_vendors.ids), the
PowerShell modules, featmgr fixtures/catalog, harness docs.
"""
import os, re, subprocess, sys

if len(sys.argv) in (3, 4) and sys.argv[1] == '--new-since':
    # Lines added FROM..TO (FROM = the brand head before the merge, TO = the merge commit) that spell the product name out.
    # Comment lines and "PROJECT:" headers are ignored (not shown to users), as are vendored/test trees; whatever is
    # left is a candidate display literal: use BRAND_PRODUCT_NAME(_W) in C/C++, or rewrite the text (OLD NEW above).
    ref = sys.argv[2]
    to = sys.argv[3] if len(sys.argv) == 4 else 'HEAD'
    skip = ('dll/3rdparty/', 'modules/rostests/', 'media/doc/', 'sdk/include/ndk/', 'sdk/include/xdk/', 'media/branding/')
    cur, n = None, 0
    for line in subprocess.check_output(['git', 'diff', '-U0', '--no-color', ref, to]).decode('utf8', 'replace').splitlines():
        if line.startswith('+++ '):
            cur = line[6:] if line.startswith('+++ b/') else None
        elif cur and line.startswith('+') and not cur.startswith(skip) and re.search(r'ReactOS|Nitro', line):
            t = line[1:].strip()
            if t.startswith(('//', '/*', '*', ';', '#', '<!--')) or 'PROJECT:' in t or '\\ReactOS\\' in t:
                continue
            print('%s: %s' % (cur, t[:160]))
            n += 1
    print('%d candidate line(s)' % n)
    sys.exit(0)

old, new = sys.argv[1].encode(), sys.argv[2].encode()
check = '--check' in sys.argv
word = re.compile(rb'(?:(?<![\w\\])|(?<=\\[nrt]))(?<!ReactOS-)' + re.escape(old) + rb'(?!\w|\.\w|\\\\|\\[A-Z]| Caption Icons)')
EXT = ('.rc', '.h', '.inf', '.ini', '.mc', '.po', '.pot', '.S', '.txt')
SKIP = ('media/psmodules/', 'media/fonts/', 'media/doc/', 'media/branding/', 'hal/halx86/legacy/bus/pci_vendors.ids',
        'base/applications/featmgr/tests/', 'base/applications/featmgr/catalog/', 'base/applications/featmgr/payload/',
        'sdk/include/reactos/version.cmake', 'sdk/include/reactos/buildno.h.cmake', 'modules/rostests/')
files = subprocess.check_output(['git', 'ls-files', '-z']).decode().split('\0')
SUFFIX = {b'Nitroren': b'NitroOSen', b'Nitrok': b'NitroOSek', b'Nitrost': b'NitroOS-ist', b'Nitrorik': b'NitroOSik', b'Nitrol': b'NitroOS-il', b'Nitroko': b'NitroOSeko'}
suf = re.compile(rb'(?<![\w\\.])(' + b'|'.join(sorted(map(re.escape, SUFFIX), key=len, reverse=True)) + rb')(?![\w])') if old == b'Nitro' else None
hits = 0
for f in files:
    if not f or f.startswith(SKIP) or not (f.endswith(EXT) or os.path.basename(f) == 'CMakeLists.txt'):
        continue
    if f.endswith('.txt') and os.path.basename(f) != 'CMakeLists.txt':
        continue
    try:
        d = open(f, 'rb').read()
    except OSError:
        continue
    n = len(word.findall(d)) + (len(suf.findall(d)) if suf else 0)
    if not n:
        continue
    hits += n
    if check:
        print('%s: %d' % (f, n))
    else:
        d = word.sub(new, d)
        if suf and new == b'NitroOS':
            d = suf.sub(lambda m: SUFFIX[m.group(1)], d)
        open(f, 'wb').write(d)
print('%d occurrence(s)%s' % (hits, '' if check else ' rewritten'))
sys.exit(1 if (check and hits) else 0)
