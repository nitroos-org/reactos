#!/usr/bin/env python3
"""Scorer for nlsgen mapping rules (lane cldr2). Builds the locales with the given nlsgen.py, models the sweep11 .NET
Framework culture test (loc.cs) from the generated values and scores it against a recorded Windows output, and compares
the generated GetLocaleInfoEx values with the recorded probe dump of 10 locales. Windows data is used ONLY here, to
count matches; nothing of it is written into the generator.

  score.py NLSGEN_DIR CLDR.zip NET_TARGET.txt PROBE_ORACLE.txt WINNLS.H [-v] [--dump OUT.json]
"""
import json, sys, re, importlib.util, os

CS = ["en-US","en-GB","cs-CZ","de-DE","fr-FR","ja-JP","ru-RU","ar-SA","hi-IN","tr-TR","zh-CN","ko-KR","pt-BR","es-ES","pl-PL","sk-SK","he-IL","th-TH","fa-IR","de-CH"]
PROBE = ["en-US","en-GB","cs-CZ","de-DE","fr-FR","es-ES","ja-JP","zh-CN","ru-RU","ar-SA"]
# 2026-11-08 (a Sunday) in the calendars that are a default calendar of a tested culture: year, month, day
# (arithmetic facts of those calendars: Buddhist = Gregorian + 543; Persian 1405-08-17; Umm al-Qura 1448-05-28)
CALDATE = {1: (2026, 11, 8, "A.D."), 7: (2569, 11, 8, None), 22: (1405, 8, 17, None), 23: (1448, 5, 28, None), 6: (1448, 5, 28, None)}


def H(s):
    return "".join(c if 32 <= ord(c) < 128 else "<%04X>" % ord(c) for c in s)


def load_gen(d):
    spec = importlib.util.spec_from_file_location("nlsgen", os.path.join(d, "nlsgen.py"))
    m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
    return m


def grp(g):
    parts = [int(x) for x in g.split(";") if x != ""]
    if parts and parts[-1] == 0:
        return parts[:-1], True
    return parts, False


def fmtnum(n, g, sep):
    s = str(n); parts, rep = grp(g)
    if not parts:
        return s
    out = []; i = len(s); idx = 0
    while i > 0:
        sz = parts[idx] if idx < len(parts) else (parts[-1] if rep else i)
        out.insert(0, s[max(0, i - sz):i]); i -= sz; idx += 1
    return sep.join(out)


def render(pat, v, cal, mnames, era):
    y, mo, d, e = CALDATE[cal]
    out = []; i = 0; n = len(pat); toks = []
    while i < n:
        c = pat[i]
        if c == "'":
            j = pat.find("'", i + 1)
            if j < 0:
                j = n
            toks.append(("L", pat[i + 1:j])); i = j + 1; continue
        if c in "dMyghHmst/:":
            j = i
            while j < n and pat[j] == c:
                j += 1
            toks.append((c, j - i)); i = j; continue
        toks.append(("L", c)); i += 1
    haveday = any(t == "d" and k <= 2 for t, k in toks)
    for t, k in toks:
        if t == "L": out.append(k)
        elif t == "/": out.append(v["LOCALE_SDATE"] * k)
        elif t == ":": out.append(v["LOCALE_STIME"] * k)
        elif t == "d": out.append(("%d" if k == 1 else "%02d") % d if k <= 2 else (v["LOCALE_SABBREVDAYNAME7"] if k == 3 else v["LOCALE_SDAYNAME7"]))
        elif t == "M":
            if k <= 2: out.append(("%d" if k == 1 else "%02d") % mo)
            else:
                nm = (mnames[0] if k >= 4 else mnames[1])[mo - 1].split("\0")
                out.append(nm[1] if (haveday and len(nm) > 1) else nm[0])
        elif t == "y": out.append(("%d" % (y % 100) if k == 1 else "%02d" % (y % 100)) if k <= 2 else "%d" % y)
        elif t == "g": out.append(era or "")
        elif t == "h": out.append(("%d" if k == 1 else "%02d") % 2)
        elif t == "H": out.append(("%d" if k == 1 else "%02d") % 14)
        elif t == "m": out.append("05")
        elif t == "s": out.append("09")
        elif t == "t": out.append(v["LOCALE_S2359"])
    return "".join(out)


def net_line(gen, c, v, cals, rows, enum):
    dec = v["LOCALE_SDECIMAL"]; th = v["LOCALE_STHOUSAND"]
    n2 = fmtnum(1234567, v["LOCALE_SGROUPING"], th) + dec + "89"
    cd = int(v["LOCALE_ICURRDIGITS"]); sym = v["LOCALE_SCURRENCY"]
    if cd == 0:
        body = fmtnum(1235, v["LOCALE_SMONGROUPING"], v["LOCALE_SMONTHOUSANDSEP"])
    else:
        body = fmtnum(1234, v["LOCALE_SMONGROUPING"], v["LOCALE_SMONTHOUSANDSEP"]) + v["LOCALE_SMONDECIMALSEP"] + "50"
    cur = [sym + body, body + sym, sym + " " + body, body + " " + sym][int(v["LOCALE_ICURRENCY"])]
    cal = int(v["LOCALE_ICALENDARTYPE"])
    gm = ([v["LOCALE_SMONTHNAME%d" % i] for i in range(1, 13)], [v["LOCALE_SABBREVMONTHNAME%d" % i] for i in range(1, 13)])
    sd, ld = v["LOCALE_SSHORTDATE"], v["LOCALE_SLONGDATE"]
    mnames, era = gm, CALDATE[cal][3]
    if cal != 1:
        sd = enum.get((cal, gen.CAL_SSHORTDATE), [sd])[0]
        ld = enum.get((cal, gen.CAL_SLONGDATE), [ld])[0]
        mn = [rows.get((cal, gen.CAL_SMONTHNAME1 + i)) for i in range(12)]
        ma = [rows.get((cal, gen.CAL_SABBREVMONTHNAME1 + i)) for i in range(12)]
        mnames = (mn if None not in mn else gm[0], ma if None not in ma else gm[1])
        era = rows.get((cal, gen.CAL_SERASTRING), "")
    d = render(sd, v, cal, mnames, era); D = render(ld, v, cal, mnames, era); t = render(v["LOCALE_SSHORTTIME"], v, 1, gm, "")
    am, pm = v["LOCALE_S1159"], v["LOCALE_S2359"]
    return ("%s | %s | %s | %s | %s | %s | %s | %s/%s | month=%s | day=%s | native=%s | win32 shortdate=%s decimal=%s thousand=%s curr=%s" % (
        c, H(n2), H(cur), H(d), H(D), H(t), H(sym), H(am), H(pm), H(mnames[0][10].split("\0")[0]), H(v["LOCALE_SDAYNAME7"]),
        H(v["LOCALE_SNATIVEDISPLAYNAME"]), H(v["LOCALE_SSHORTDATE"]), H(dec), H(th), H(sym)))


def parse_probe(path):
    d = {}; loc = None
    for line in open(path, encoding="utf-8", errors="replace").read().replace("\r", "").split("\n"):
        m = re.match(r'== "(.*)"', line)
        if m:
            loc = m.group(1); d[loc] = {}; continue
        m = re.match(r'LI (0x[0-9a-f]+) "(.*)"$', line)
        if m and loc:
            d[loc][int(m.group(1), 16)] = m.group(2)
    return d


def unesc(s):
    return re.sub(r"\\u([0-9A-F]{4})", lambda m: chr(int(m.group(1), 16)), s)


def main():
    a = [x for x in sys.argv[1:] if not x.startswith("-")]
    verbose = "-v" in sys.argv
    gen = load_gen(a[0])
    cldr = gen.Cldr(a[1])
    gen.ISO639_2 = json.load(open(os.path.join(a[0], "data", "iso639-2.json"), encoding="utf-8"))
    skel = json.load(open(os.path.join(a[0], "data", "skeleton.json"), encoding="utf-8"))
    built = {}
    for name in sorted(skel):
        tag, ch, v, cals, region = gen.build_locale(cldr, name, skel[name])
        built[v["LOCALE_SNAME"]] = (tag, ch, v, cals)
    if "--dump" in sys.argv:
        json.dump({k: b[2] for k, b in built.items()}, open(sys.argv[sys.argv.index("--dump") + 1], "w"), ensure_ascii=False, indent=1, sort_keys=True)
    tgt = {}
    for l in open(a[2], encoding="utf-8", errors="replace").read().replace("\r", "").split("\n"):
        m = re.match(r"([a-z]{2}-[A-Z]{2}) \| ", l)
        if m: tgt[m.group(1)] = l
    ok = 0; segn = segok = 0; okl = []
    for c in CS:
        tag, ch, v, cals = built[c]
        rows, enum = gen.build_calendar_rows(cldr, tag, ch, cals, v)
        l = net_line(gen, c, v, cals, rows, enum); t = tgt.get(c, "")
        x, y = l.split(" | "), t.split(" | ")
        if l == t: ok += 1; okl.append(c)
        segn += len(y); segok += sum(1 for p, q in zip(x, y) if p == q)
        if verbose and l != t:
            print("DIFF", c)
            for p, q in zip(x, y):
                if p != q: print("   sim:", p[:130]); print("   tgt:", q[:130])
    print("NET culture lines identical: %d/20 (%s); segments %d/%d" % (ok, ",".join(okl), segok, segn))
    # GetLocaleInfoEx parity over the probe locales (LI fields that the generator produces)
    h = open(a[4], encoding="utf-8", errors="replace").read()
    names = {}
    for m in re.finditer(r"#define\s+(LOCALE_[SI]\w+)\s+(0x[0-9a-fA-F]+|\d+)\b", h):
        names.setdefault(int(m.group(2), 0), m.group(1))
    names.update({0x5d: "LOCALE_SDURATION", 0x5e: "LOCALE_SKEYBOARDSTOINSTALL", 0x67: "LOCALE_SISO639LANGNAME2", 0x68: "LOCALE_SISO3166CTRYNAME2",
        0x6e: "LOCALE_SCONSOLEFALLBACKNAME", 0x6f: "LOCALE_SLOCALIZEDLANGUAGENAME", 0x72: "LOCALE_SENGLISHDISPLAYNAME", 0x73: "LOCALE_SNATIVEDISPLAYNAME",
        0x78: "LOCALE_SMONTHDAY", 0x7b: "LOCALE_SSORTLOCALE", 0x7c: "LOCALE_SRELATIVELONGDATE", 0x7e: "LOCALE_SSHORTESTAM", 0x7f: "LOCALE_SSHORTESTPM",
        0x5f: "LOCALE_SPARENT", 0x69: "LOCALE_SNAN", 0x6a: "LOCALE_SPOSINFINITY", 0x6b: "LOCALE_SNEGINFINITY", 0x6c: "LOCALE_SSCRIPTS", 0x6d: "LOCALE_SOPENTYPELANGUAGETAG"})
    for i in range(7): names[0x60 + i] = "LOCALE_SSHORTESTDAYNAME%d" % (i + 1)
    ora = parse_probe(a[3])
    tot = bad = 0; byf = {}
    for loc in PROBE:
        v = built[loc][2]
        for n, ov in ora[loc].items():
            k = names.get(n)
            if k is None or k not in v or k in ("LOCALE_SPARENT",):
                continue
            gv = v[k].split("\0")[0] if k.startswith("LOCALE_S") and ("MONTHNAME" in k) else v[k]
            tot += 1
            if gv != unesc(ov):
                bad += 1; byf.setdefault(k, []).append(loc)
                if verbose: print("  LI", loc, k, repr(gv)[:60], "!=", repr(unesc(ov))[:60])
    print("LI parity (10 locales): %d of %d compared fields differ" % (bad, tot))
    if verbose:
        for k, l in sorted(byf.items(), key=lambda x: -len(x[1])): print("   ", len(l), k)


main()
