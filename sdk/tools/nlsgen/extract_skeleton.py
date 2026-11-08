#!/usr/bin/env python3
"""One-off provenance tool: extract the locale identity skeleton (data/skeleton.json) of nlsgen.

The skeleton holds the fields of a locale that Unicode CLDR does not carry: the Wine-era identity of the locale
(LANGUAGE/SUBLANG, LCID, ANSI/OEM/MAC/EBCDIC code pages, GEOID, calling code, Windows 3-letter abbreviations, OpenType
tag, sort name, font signature, the localized language group names). They are read from the locale resource files as
they were BEFORE any value was measured on Windows (the parent of commit afb57812d6b, the Wine 6.7 sync of ReactOS), so
nothing in it comes from a Windows query.

  extract_skeleton.py REPO_DIR OUT.json
"""
import json, re, subprocess, sys

REPO, OUT = sys.argv[1], sys.argv[2]
BASE = "afb57812d6b^"          # last state before the Windows 10 measurements
NLS = "dll/win32/kernel32/winnls/nls"
KEEP = ["LOCALE_SNAME", "LOCALE_FONTSIGNATURE", "LOCALE_ICOUNTRY", "LOCALE_IDEFAULTANSICODEPAGE", "LOCALE_IDEFAULTCODEPAGE",
        "LOCALE_IDEFAULTCOUNTRY", "LOCALE_IDEFAULTEBCDICCODEPAGE", "LOCALE_IDEFAULTLANGUAGE",
        "LOCALE_IDEFAULTMACCODEPAGE", "LOCALE_IGEOID", "LOCALE_ILANGUAGE", "LOCALE_SABBREVCTRYNAME",
        "LOCALE_SABBREVLANGNAME", "LOCALE_SOPENTYPELANGUAGETAG", "LOCALE_SSORTNAME"]

def git(*a):
    return subprocess.run(["git", "-C", REPO] + list(a), check=True, capture_output=True).stdout.decode("utf-8")

# Files that never held Windows data (hand written by Wine/ReactOS): not regenerated, not in the skeleton.
EXCLUDE = {"ivl", "eoa", "eox", "ast", "cor", "gdv", "wal"}
out = {}
names = [n.split("/")[-1][:-4] for n in git("ls-tree", "--name-only", BASE, NLS + "/").split() if n.endswith(".nls")]
for n in sorted(names):
    if n in EXCLUDE:
        continue
    t = git("show", "%s:%s/%s.nls" % (BASE, NLS, n))
    m = re.search(r"STRINGTABLE LANGUAGE (\w+), (\w+)", t)
    title = re.search(r"Locale definitions for (.*)", t)
    e = {"language": m.group(1), "sublang": m.group(2), "title": title.group(1) if title else "", "fixed": {}, "lgrp": [],
         "header": t[:t.index("#pragma code_page")].rstrip("\n") + "\n"}
    for line in t.splitlines():
        mm = re.match(r"\s+(LOCALE_\w+) (.*)$", line)
        if mm and mm.group(1) in KEEP:
            e["fixed"][mm.group(1)] = mm.group(2)
        mm = re.match(r"\s+(LGRPID_\w+\+LGRPID_RES_BASE) (.*)$", line)
        if mm:
            e["lgrp"].append([mm.group(1), mm.group(2)])
    out[n] = e
# srb.nls was the Serbia and Montenegro locale 0x0c1a; sr-Cyrl-RS is 0x281a (SUBLANG_SERBIAN_SERBIA_CYRILLIC) and the
# former locale keeps its own file sbc.nls. The LCID and the GEOID of Serbia (271) are published identifiers
# (MS-LCID, the Windows GEO table).
sbc = json.loads(json.dumps(out["srb"]))
sbc["title"] = "Serbian (Cyrillic, Serbia and Montenegro)"
sbc["fixed"]["LOCALE_SNAME"] = '"sr-Cyrl-CS"'
out["sbc"] = sbc
out["srb"]["sublang"] = "SUBLANG_SERBIAN_SERBIA_CYRILLIC"
out["srb"]["title"] = "Serbian (Cyrillic, Serbia)"
out["srb"]["fixed"]["LOCALE_ILANGUAGE"] = '"281a"'
out["srb"]["fixed"]["LOCALE_SNAME"] = '"sr-Cyrl-RS"'
out["srb"]["fixed"]["LOCALE_IDEFAULTLANGUAGE"] = '"281a"'
out["srb"]["fixed"]["LOCALE_IGEOID"] = '"271"'
# the LCID is MAKELANGID(LANG_x, SUBLANG_y) -> y << 10 | x, from the public winnt.h macros of the tree
wn = open(REPO + "/sdk/include/xdk/ntbasedef.h", encoding="utf-8", errors="replace").read()
def macro(name):
    mm = re.search(r"#define\s+%s\s+(0x[0-9a-fA-F]+|\d+)\b" % name, wn)
    return int(mm.group(1), 0) if mm else None
for n, e in out.items():
    l, s2 = macro(e["language"]), macro(e["sublang"])
    e["lcid"] = (s2 << 10 | l) if l is not None and s2 is not None else None
    print(n, e["language"], e["sublang"], hex(e["lcid"]) if e["lcid"] is not None else "UNRESOLVED") if e["lcid"] is None else None
# The calling code (ICOUNTRY) and the default ANSI code page of a few locales were wrong in the Wine data; the values are
# public (ITU-T E.164 country calling codes; Windows uses 1252 for Welsh).
FIX = {"dec": {"LOCALE_ICOUNTRY": '"423"', "LOCALE_IDEFAULTCOUNTRY": '"423"'},
       "enc": {"LOCALE_ICOUNTRY": '"1"', "LOCALE_IDEFAULTCOUNTRY": '"1"'},
       "frc": {"LOCALE_ICOUNTRY": '"1"', "LOCALE_IDEFAULTCOUNTRY": '"1"'},
       "far": {"LOCALE_ICOUNTRY": '"98"', "LOCALE_IDEFAULTCOUNTRY": '"98"'},
       "uzb": {"LOCALE_ICOUNTRY": '"998"', "LOCALE_IDEFAULTCOUNTRY": '"998"'},
       "uzl": {"LOCALE_ICOUNTRY": '"998"', "LOCALE_IDEFAULTCOUNTRY": '"998"'},
       "cym": {"LOCALE_IDEFAULTANSICODEPAGE": '"1252"'}}
for n, f in FIX.items():
    out[n]["fixed"].update(f)
json.dump(out, open(OUT, "w"), indent=1, ensure_ascii=False, sort_keys=True)
print(len(out), "locales")
