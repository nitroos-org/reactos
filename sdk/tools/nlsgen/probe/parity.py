#!/usr/bin/env python3
"""Parity report: lcprobe dumps of the oracle (Windows 10 22H2), NitroOS before (Windows-derived tables) and after (CLDR).

  parity.py ORACLE.txt BEFORE.txt AFTER.txt WINNLS.H OUT.md [OUT.tsv]
"""
import re, sys, collections

def parse(path):
    d = collections.OrderedDict(); loc = None; txt = open(path, encoding="utf-8", errors="replace").read().replace("\r", "")
    for line in txt.split("\n"):
        m = re.match(r'== "(.*)"', line)
        if m:
            loc = m.group(1); d[loc] = collections.OrderedDict(); continue
        if loc is None: continue
        m = re.match(r'(LI) (G?0x[0-9a-f]+) (".*")$', line)
        if m: d[loc]["LI " + m.group(2)] = m.group(3); continue
        m = re.match(r'(DATE\d|TIME\d|NUM|CUR|CAL) (\S+(?: name)?) (.*)$', line)
        if m: d[loc][m.group(1) + " " + m.group(2)] = m.group(3); continue
        m = re.match(r'(SORT) (.*)$', line)
        if m: d[loc]["SORT"] = m.group(2)
    return d

names = {}
for l in open(sys.argv[4], encoding="utf-8", errors="replace"):
    m = re.match(r"#define\s+(LOCALE_[SI]\w+|LOCALE_FONTSIGNATURE)\s+(0x[0-9a-fA-F]+|\d+)\b", l)
    if m and m.group(1) not in ("LOCALE_SPECIFICDATA",):
        names.setdefault(int(m.group(2), 0), m.group(1))
extra = {0x5d: "LOCALE_SDURATION", 0x5e: "LOCALE_SKEYBOARDSTOINSTALL", 0x67: "LOCALE_SISO639LANGNAME2", 0x68: "LOCALE_SISO3166CTRYNAME2",
         0x6e: "LOCALE_SCONSOLEFALLBACKNAME", 0x6f: "LOCALE_SLOCALIZEDLANGUAGENAME", 0x72: "LOCALE_SENGLISHDISPLAYNAME",
         0x73: "LOCALE_SNATIVEDISPLAYNAME", 0x78: "LOCALE_SMONTHDAY", 0x7b: "LOCALE_SSORTLOCALE", 0x7c: "LOCALE_SRELATIVELONGDATE",
         0x7d: "LOCALE_ICONSTRUCTEDLOCALE", 0x7e: "LOCALE_SSHORTESTAM", 0x7f: "LOCALE_SSHORTESTPM", 0x5f: "LOCALE_SPARENT",
         0x60: "LOCALE_SSHORTESTDAYNAME1", 0x61: "LOCALE_SSHORTESTDAYNAME2", 0x62: "LOCALE_SSHORTESTDAYNAME3", 0x63: "LOCALE_SSHORTESTDAYNAME4",
         0x64: "LOCALE_SSHORTESTDAYNAME5", 0x65: "LOCALE_SSHORTESTDAYNAME6", 0x66: "LOCALE_SSHORTESTDAYNAME7", 0x69: "LOCALE_SNAN",
         0x6a: "LOCALE_SPOSINFINITY", 0x6b: "LOCALE_SNEGINFINITY", 0x6c: "LOCALE_SSCRIPTS", 0x6d: "LOCALE_SOPENTYPELANGUAGETAG",
         0x70: "LOCALE_SENGLANGUAGE?", 0x74: "LOCALE_SSORTNAME", 0x75: "LOCALE_SRELATIVELONGDATE?", 0x76: "LOCALE_IREADINGLAYOUT?"}
for k, v in extra.items():
    if k not in names: names[k] = v

def label(key):
    m = re.match(r"LI (G?)0x([0-9a-f]+)", key)
    if m:
        n = int(m.group(2), 16)
        return ("genitive " if m.group(1) else "") + names.get(n, "LCTYPE 0x%04x" % n)
    return key

ora, bef, aft = parse(sys.argv[1]), parse(sys.argv[2]), parse(sys.argv[3])
out = ["# Locale parity report: oracle (Windows 10 22H2) vs NitroOS before (Windows-derived tables) and after (CLDR)\n",
       "Probe: sdk/tools/nlsgen/probe/lcprobe.c (read-only: GetLocaleInfoEx for every LCTYPE 0-0xff, genitive month names, GetDateFormatEx, GetTimeFormatEx, GetNumberFormatEx, GetCurrencyFormatEx, GetCalendarInfoEx names, CompareStringEx order of a word list) for the 10 main locales. One run on the oracle, one on each NitroOS build.\n",
       "A field is listed when the CLDR-generated value (after) differs from Windows. `before` is the value of the Windows-derived tables, shown only where it differs from `after` (it was measured on the same Windows, so it normally equals the oracle; where it does not, the old value was wrong or the old code path returned something else).\n"]
tsv = ["locale\tfield\toracle\tbefore\tafter"]
summ = []
for loc in ora:
    o, b, a = ora[loc], bef.get(loc, {}), aft.get(loc, {})
    keys = [k for k in o if k in a or k in b]
    for k in a:
        if k not in o and k not in keys: keys.append(k)
    db = [k for k in keys if o.get(k) != b.get(k)]
    da = [k for k in keys if o.get(k) != a.get(k)]
    new = [k for k in da if o.get(k) == b.get(k)]       # equal to Windows before, different now
    fixed = [k for k in db if o.get(k) == a.get(k)]     # different before, equal to Windows now
    summ.append((loc, len(keys), len(db), len(da), len(new), len(fixed)))
    out.append("\n## %s: %d fields compared; differs from Windows: before %d, after %d (%d new, %d repaired)\n" % (loc, len(keys), len(db), len(da), len(new), len(fixed)))
    out.append("| field | Windows | before | after |\n|---|---|---|---|")
    for k in da:
        f = lambda s: ("`%s`" % s.replace("|", "\\|")) if s is not None else "(absent)"
        out.append("| %s | %s | %s | %s |" % (label(k), f(o.get(k)), f(b.get(k)) if b.get(k) != a.get(k) else "same as after", f(a.get(k))))
        tsv.append("\t".join([loc, label(k), o.get(k) or "", b.get(k) or "", a.get(k) or ""]))
hdr = ["\n## Summary\n", "`before` = the Windows-derived tables, `after` = CLDR. `new` = equal to Windows before, different now (the accepted cost); `repaired` = different before, equal to Windows now. The rows that differ both before and after (for example calendar names that Windows does not have, LCTYPE 0 and the font signature) are not caused by the data.\n",
       "| locale | fields | differ before | differ after | new | repaired |", "|---|---|---|---|---|---|"]
tot = [0, 0, 0, 0, 0]
for loc, n, db_, da_, nw_, fx_ in summ:
    hdr.append("| %s | %d | %d | %d | %d | %d |" % (loc, n, db_, da_, nw_, fx_)); tot = [tot[0] + n, tot[1] + db_, tot[2] + da_, tot[3] + nw_, tot[4] + fx_]
hdr.append("| total | %d | %d | %d | %d | %d |" % tuple(tot))
out = out[:3] + hdr + out[3:]
open(sys.argv[5], "w", encoding="utf-8").write("\n".join(out) + "\n")
if len(sys.argv) > 6:
    open(sys.argv[6], "w", encoding="utf-8").write("\n".join(tsv) + "\n")
print("\n".join(hdr))
