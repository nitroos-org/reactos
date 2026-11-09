#!/usr/bin/env python3
"""Rename the two ntoskrnl imports of missimp.sys to names that do not exist.

usage: patchimports.py missimp.sys missimp-bad.sys

The built driver imports IoWMISuggestInstanceName and
KeRegisterBugCheckReasonCallback. Both are replaced in the import name table
(the new names are shorter, padded with NULs) so the kernel loader cannot
resolve them. The result is the input of the missing driver import log test.
"""
import sys

RENAMES = {
    b"IoWMISuggestInstanceName": b"NitroNoSuchExportOne",
    b"KeRegisterBugCheckReasonCallback": b"NitroNoSuchExportTwo",
}

data = open(sys.argv[1], "rb").read()
for old, new in RENAMES.items():
    pat = old + b"\0"
    n = data.count(pat)
    if n == 0:
        sys.exit("import name %s not found" % old.decode())
    data = data.replace(pat, new + b"\0" * (len(pat) - len(new)))
    print("renamed %s -> %s (%d place(s))" % (old.decode(), new.decode(), n))
open(sys.argv[2], "wb").write(data)
