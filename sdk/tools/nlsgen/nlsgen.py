#!/usr/bin/env python3
"""nlsgen: generate the ReactOS locale tables from Unicode CLDR.

  nlsgen.py [--cache DIR | --cldr-zip FILE] --nls-dir DIR --calendar-c FILE

Writes, deterministically (same CLDR release and same skeleton: same bytes):
  DIR/<name>.nls      one locale resource file per locale of data/skeleton.json (dll/win32/kernel32/winnls/nls)
  FILE                calendar_data.c: calendar names, eras, month names and date/time format lists
                      (dll/win32/kernel32/winnls/string/calendar_data.c)

Source of the data: ONE pinned Unicode CLDR release (cldr-json "full" package, URL and SHA-256 below). Nothing is read
from a Windows system. What CLDR does not carry comes from data/skeleton.json (the Wine-era identity of each locale:
LCID, code pages, GEOID, calling code, Windows abbreviations, font signature; see extract_skeleton.py) or is derived by a
documented rule (README.md, "Fields CLDR lacks"). Python 3, standard library only.
"""
import argparse, hashlib, json, os, re, sys, unicodedata, urllib.request, zipfile

CLDR_VERSION = "49.0.0"
CLDR_URL = "https://github.com/unicode-org/cldr-json/releases/download/49.0.0/cldr-49.0.0-json-full.zip"
CLDR_SHA256 = "3b1f5d684d29c541d3acf91fe834b3fe36ae0f34775e3ee50e93558bf14ca174"
HERE = os.path.dirname(os.path.abspath(__file__))

# ---------------------------------------------------------------------------------------------------------------------
# CLDR access
# ---------------------------------------------------------------------------------------------------------------------

def fetch_zip(cache_dir):
    """Download the pinned release into cache_dir (if absent) and verify its SHA-256."""
    os.makedirs(cache_dir, exist_ok=True)
    path = os.path.join(cache_dir, os.path.basename(CLDR_URL))
    if not os.path.exists(path):
        tmp = path + ".part"
        with urllib.request.urlopen(CLDR_URL) as r, open(tmp, "wb") as f:
            while True:
                b = r.read(1 << 20)
                if not b:
                    break
                f.write(b)
        os.replace(tmp, path)
    return path


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


class Cldr:
    def __init__(self, zip_path):
        got = sha256_file(zip_path)
        if got != CLDR_SHA256:
            sys.exit("nlsgen: %s has sha256 %s, expected %s (CLDR %s)" % (zip_path, got, CLDR_SHA256, CLDR_VERSION))
        self.z = zipfile.ZipFile(zip_path)
        self.names = set(self.z.namelist())
        self.cache = {}
        self.likely = self.sup("likelySubtags")["likelySubtags"]
        self.parent = self.sup("parentLocales")["parentLocales"]["parentLocale"]
        self.alias_terr = self.sup("aliases")["metadata"]["alias"]["territoryAlias"]
        self.week = self.sup("weekData")["weekData"]
        self.meas = self.sup("measurementData")["measurementData"]
        self.curdata = self.sup("currencyData")["currencyData"]
        self.calpref = self.sup("calendarPreferenceData")["calendarPreferenceData"]
        self.caldata = self.sup("calendarData")["calendarData"]
        self.codemap = self.sup("codeMappings")["codeMappings"]
        self.numsys = self.sup("numberingSystems")["numberingSystems"]
        self.timedata = self.sup("timeData")["timeData"]
        self.avail = set(self.load("cldr-core/availableLocales.json")["availableLocales"]["full"]) | {"root"}

    def load(self, name):
        if name not in self.cache:
            self.cache[name] = json.loads(self.z.read(name).decode("utf-8")) if name in self.names else None
        return self.cache[name]

    def sup(self, f):
        return self.load("cldr-core/supplemental/%s.json" % f)["supplemental"]

    def main(self, pkg, loc, f):
        d = self.load("%s/main/%s/%s.json" % (pkg, loc, f))
        return d["main"][loc] if d else None

    # --- locale chain ------------------------------------------------------------------------------------------
    def canonical(self, tag):
        """tag 'de-DE' -> (lang, script, region, cldr id without a default script)"""
        parts = tag.split("-")
        lang, script, region = parts[0], None, None
        for p in parts[1:]:
            if len(p) == 4:
                script = p.title()
            elif len(p) == 2 or (len(p) == 3 and p.isdigit()):
                region = p.upper()
        lt = self.likely.get(lang, "")
        lt_script = lt.split("-")[1] if lt.count("-") >= 2 else None
        eff_script = script
        if eff_script is None:
            # the script of language + region (zh-TW is Hant), else that of the language
            lr = self.likely.get(lang + "-" + region, "") if region else ""
            eff_script = lr.split("-")[1] if lr.count("-") >= 2 else lt_script
        if region is None and lt:
            region = lt.split("-")[-1]
        return lang, script, eff_script, region, lt_script

    def chain(self, tag):
        lang, script, eff_script, region, lt_script = self.canonical(tag)
        cur = lang
        if eff_script and eff_script != lt_script:
            cur += "-" + eff_script
        if region:
            cur += "-" + region
        out = []
        while cur and cur != "root":
            if cur in self.avail:
                out.append(cur)
            nxt = self.parent.get(cur)
            if nxt is None:
                nxt = cur.rsplit("-", 1)[0] if "-" in cur else "root"
            cur = nxt
        out.append("root")
        return out

    def region_of(self, tag):
        r = self.canonical(tag)[3]
        a = self.alias_terr.get(r)
        if a and a.get("_replacement"):
            r = a["_replacement"].split()[0]     # a deprecated territory (CS) is its first successor
        return r

    def region_value(self, table, region, default_key="001"):
        if region in table:
            return table[region]
        return table.get(default_key)

    # --- inherited lookup ----------------------------------------------------------------------------------------
    def get(self, pkg, f, tag, *path, skip_root=False, chain=None):
        for loc in (chain or self.chain(tag)):
            if skip_root and loc == "root":
                continue
            d = self.main(pkg, loc, f)
            if d is None:
                continue
            for k in path:
                if not isinstance(d, dict) or k not in d:
                    d = None
                    break
                d = d[k]
            if d is not None:
                return d
        return None


# ---------------------------------------------------------------------------------------------------------------------
# helpers: patterns
# ---------------------------------------------------------------------------------------------------------------------

BIDI = "‎‏؜"
SPACES = "    "


def fullwidth(s):
    """Fullwidth ASCII and fullwidth currency signs (U+FF01-FF5E, U+FFE0-FFE6) to their compatibility forms (Unicode NFKC): the
    legacy ANSI code pages have no fullwidth yen or parenthesis. Halfwidth katakana and Hangul are left alone."""
    return "".join(unicodedata.normalize("NFKC", c) if (0xff01 <= ord(c) <= 0xff5e or 0xffe0 <= ord(c) <= 0xffe6) else c for c in s)


def strip_bidi(s):
    if s is None:
        return None
    for c in BIDI:
        s = s.replace(c, "")
    return s


def sym_latn_ok(N):
    """The locale chain (or root) has Latin-numbering-system symbols."""
    return N("symbols-numberSystem-latn", "decimal") is not None


def nospace(s):
    for c in SPACES:
        s = s.replace(c, " ")
    return s


def ldml_to_win(p, era_year=False):
    """An LDML date/time pattern in the pattern letters GetDateFormat/GetTimeFormat know."""
    p = p.replace("\u202f", " ")      # CLDR uses a narrow no-break space in some patterns; consoles and old fonts have no glyph
    for c in BIDI:                    # RLM/LRM/ALM are display controls, not part of the pattern
        p = p.replace(c, "")
    out = []
    i = 0
    n = len(p)
    while i < n:
        c = p[i]
        if c == "'":
            j = i + 1
            lit = []
            while j < n:
                if p[j] == "'":
                    if j + 1 < n and p[j + 1] == "'":
                        lit.append("''")
                        j += 2
                        continue
                    break
                lit.append(p[j])
                j += 1
            s = "".join(lit)
            out.append("'" + s + "'" if s and "''" not in s else s)
            i = j + 1
            continue
        if c.isascii() and c.isalpha():
            j = i
            while j < n and p[j] == c:
                j += 1
            k = j - i
            i = j
            if c in "yYuUr":
                # the year of an era (Japanese, Minguo) has one or two digits; elsewhere the year has four
                out.append("y" if (era_year and c == "y" and k == 1) else "yy" if (c == "y" and k == 2) else "yyyy")
            elif c in "ML":
                out.append({1: "M", 2: "MM", 3: "MMM"}.get(k, "MMMM"))
            elif c == "d":
                out.append("d" if k == 1 else "dd")
            elif c in "Ec":
                out.append("dddd" if k == 4 else "ddd") if k >= 3 or c == "E" else out.append("d" if k == 1 else "dd")
            elif c == "e":
                out.append("dddd" if k == 4 else "ddd" if k >= 3 else "d")
            elif c in "Hhk":
                out.append(("H" if c in "Hk" else "h") * (1 if k == 1 else 2))
            elif c == "K":
                out.append("h" * (1 if k == 1 else 2))
            elif c in "ms":
                out.append(c * (1 if k == 1 else 2))
            elif c in "abB":
                out.append("tt")
            elif c == "G":
                out.append("gg")
            # zone, week, quarter, fractional seconds and the like have no Windows pattern letter: dropped
            continue
        if c.isalpha() or unicodedata.category(c).startswith("M"):
            j = i
            while j < n and p[j] != "'" and not (p[j].isascii() and p[j].isalpha()) and (p[j].isalpha() or unicodedata.category(p[j]).startswith("M")):
                j += 1
            out.append("'" + p[i:j] + "'")
            i = j
            continue
        out.append(c)
        i += 1
    s = "".join(out)
    s = s.replace("''", "")       # an empty quoted run
    s = re.sub(r"(?<=[^'])''(?=[^'])", "'", s)
    return s.strip(" \t")


def canon_quotes(s):
    """Rule QUOTE-CANON (round 4), applied to the long date patterns only (SLONGDATE, SRELATIVELONGDATE, the long date lists):
    one quoted literal per literal phrase. A quoted word between two date fields takes the
    spaces around it into the quotes (CLDR `d 'de' MMMM 'de' y` -> `d' de 'MMMM' de 'yyyy`), and a quoted word at the end of the
    pattern takes its trailing punctuation (`y 'г'.` -> `y 'г.'`). The formatted text is identical; only the quoting differs."""
    toks = [m.group(0) for m in re.finditer(r"'[^']*'|([A-Za-z])\1*|.", s, flags=re.S)]
    isfield = lambda t: bool(t) and t[0].isascii() and t[0].isalpha()
    out = []
    i = 0
    n = len(toks)
    while i < n:
        t = toks[i]
        if len(t) > 2 and t[0] == "'" and t[-1] == "'":
            lit = t[1:-1]
            j = i + 1
            if len(out) > 1 and out[-1] == " " and isfield(out[-2]) and j + 1 < n and toks[j] == " " and isfield(toks[j + 1]):
                out.pop()
                lit = " " + lit + " "
                j += 1
            elif j == n - 1 and len(toks[j]) == 1 and not toks[j].isalnum() and toks[j] not in " '":
                lit = lit + toks[j]
                j += 1
            out.append("'" + lit + "'")
            i = j
            continue
        out.append(t)
        i += 1
    return "".join(out)


def pattern_order(p):
    """IDATE style: 0 month-day-year, 1 day-month-year, 2 year-month-day, from the first appearance in the pattern."""
    seen = []
    for m in re.finditer(r"'[^']*'|d{3,}|([dMy])", p):       # 'ddd'/'dddd' is the weekday, not the day of the month
        if m.group(1) and m.group(1) not in seen:
            seen.append(m.group(1))
    s = "".join(seen)
    return {"Mdy": 0, "dMy": 1, "yMd": 2, "ydM": 2, "Myd": 0, "dyM": 1, "yM": 2, "My": 0, "dM": 1, "Md": 0, "yd": 2}.get(s, 1 if s.startswith("d") else 0 if s.startswith("M") else 2)


def strip_quoted(p):
    return re.sub(r"'[^']*'", "", p)


def date_separator(short):
    """SDATE: the literal between the first two date fields of the short date, trimmed."""
    m = re.search(r"(?:d+|M+|y+)((?:'[^']*'|[^dMy'a-zA-Z])+)(?:d+|M+|y+)", short)
    if not m:
        return "/"
    s = m.group(1).replace("'", "").strip()
    return s if s else m.group(1).replace("'", "")[:1] or "/"


def grouping(pattern):
    """'#,##,##0.###' -> '3;2;0', '#0.###' -> '0'"""
    ip = pattern.split(";")[0].split(".")[0]
    segs = ip.split(",")
    if len(segs) < 2:
        return "0"
    prim = len(segs[-1])
    sec = len(segs[-2]) if len(segs) > 2 else 0
    return "%d;%d;0" % (prim, sec) if sec and sec != prim else "%d;0" % prim


def canon_money(pat, sym):
    """A currency pattern in the canonical Windows notation: '$' symbol, '1.1' number."""
    pat = nospace(pat.replace("¤¤", "¤"))
    for c in BIDI:
        pat = pat.replace(c, "")
    pat = re.sub(r"'([^']*)'", lambda m: m.group(1), pat)
    pat = re.sub(r"[#0,.]+", "1.1", pat, count=1)
    return pat.replace("¤", sym)


NEGCURR = ["($1.1)", "-$1.1", "$-1.1", "$1.1-", "(1.1$)", "-1.1$", "1.1-$", "1.1$-", "-1.1 $", "-$ 1.1", "1.1 $-", "$ 1.1-",
           "$ -1.1", "1.1- $", "($ 1.1)", "(1.1 $)"]
POSCURR = {"$1.1": 0, "1.1$": 1, "$ 1.1": 2, "1.1 $": 3}
NEGPCT = ["-n %", "-n%", "-%n", "%-n", "%n-", "n-%", "n%-", "-% n", "n %-", "% n-", "% -n", "n- %"]
POSPCT = {"n %": 0, "n%": 1, "%n": 2, "% n": 3}
NEGNUM = ["(1.1)", "-1.1", "- 1.1", "1.1-", "1.1 -"]


def canon_pct(pat):
    pat = nospace(pat)
    for c in BIDI:
        pat = pat.replace(c, "")
    pat = re.sub(r"'([^']*)'", lambda m: m.group(1), pat)
    return re.sub(r"[#0,.]+", "n", pat, count=1)


def split_pattern(pat):
    parts = re.split(r";(?=(?:[^']*'[^']*')*[^']*$)", pat)
    return parts[0], (parts[1] if len(parts) > 1 else None)


# ---------------------------------------------------------------------------------------------------------------------
# helpers: output
# ---------------------------------------------------------------------------------------------------------------------

def rc_str(s):
    """A resource-script string literal for s (raw UTF-8 unless that is not safe, then L"" with \\x escapes)."""
    special = any(ord(c) > 0xffff or unicodedata.category(c) in ("Cf", "Zs", "Cc", "Co", "Cn", "Zl", "Zp") and c != " " for c in s)
    esc = []
    for c in s:
        if c == "\\":
            esc.append("\\\\")
        elif c == '"':
            esc.append('\\"')
        elif c == "\0":
            esc.append("\\000")
        elif special and ord(c) > 0x7f:
            if ord(c) > 0xffff:
                v = ord(c) - 0x10000
                esc.append("\\x%04x\\x%04x" % (0xd800 + (v >> 10), 0xdc00 + (v & 0x3ff)))
            else:
                esc.append("\\x%04x" % ord(c))
        else:
            esc.append(c)
    return ("L" if special else "") + '"' + "".join(esc) + '"'


def c_str(s):
    """The body of a C string literal; a \\x escape is closed before a following hex digit."""
    out = []
    pend = False
    for c in s:
        o = ord(c)
        if pend and c in "0123456789abcdefABCDEF":
            out.append('" L"')
        pend = False
        if c == "\\":
            out.append("\\\\")
        elif c == '"':
            out.append('\\"')
        elif o < 0x20 or o > 0x7e:
            if o > 0xffff:
                v = o - 0x10000
                out.append("\\x%04x\\x%04x" % (0xd800 + (v >> 10), 0xdc00 + (v & 0x3ff)))
            else:
                out.append("\\x%04x" % o)
            pend = True
        else:
            out.append(c)
    return "".join(out)


# ---------------------------------------------------------------------------------------------------------------------
# locale data
# ---------------------------------------------------------------------------------------------------------------------

ISO639_2 = None   # filled from data/iso639-2.json
WINCAL = {"gregorian": 1, "japanese": 3, "roc": 4, "islamic": 6, "buddhist": 7, "hebrew": 8, "persian": 22, "islamic-umalqura": 23}
DAYKEYS = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"]
FIRSTDAY = {"mon": 0, "tue": 1, "wed": 2, "thu": 3, "fri": 4, "sat": 5, "sun": 6}
SCRIPT_EXPAND = {"Jpan": "Hani;Hira;Jpan;Kana", "Hans": "Hani;Hans", "Hant": "Hani;Hant", "Kore": "Hang;Hani;Kore", "Hanb": "Bopo;Hanb;Hani"}
MULTI_SCRIPT_LANGS = {"az", "bs", "mn", "pa", "sr", "tg", "uz", "zh", "ha", "ks", "ku", "ms", "sd", "shi", "ff"}


def names12(cldr, tag, ch, cal, kind, width, standalone, n):
    """Names of the months (kind 'months', n=12 or 13) or days of a CLDR calendar; the context falls back to 'format'."""
    pkg, f = cal_source(cal)
    ctxs = ["stand-alone", "format"] if standalone else ["format"]
    widths = [width] + {"narrow": ["short", "abbreviated"], "short": ["abbreviated", "wide"], "abbreviated": ["wide"], "wide": ["abbreviated"]}.get(width, [])
    out = []
    keys = [str(i + 1) for i in range(n)] if kind == "months" else DAYKEYS
    for key in keys:
        val = None
        for loc in ch:
            if loc == "root":
                continue
            d = cldr.main(pkg, loc, f)
            if d is None:
                continue
            cd = d["dates"]["calendars"][cal].get(kind, {})
            for w in widths:
                for cx in ctxs:
                    v = cd.get(cx, {}).get(w, {}).get(key)
                    if v is not None:
                        val = v
                        break
                if val is not None:
                    break
            if val is not None:
                break
        # Rule NAME-NBSP: the words of a multi-word month or day name are joined by a no-break space (the name stays on one line)
        out.append(val.replace(" ", "\u00a0") if val else val)
    return out


def cal_source(cal):
    if cal == "gregorian":
        return "cldr-dates-full", "ca-gregorian"
    return "cldr-cal-%s-full" % ("islamic" if cal.startswith("islamic") else cal), "ca-" + cal


def cal_get(cldr, tag, ch, cal, *path):
    pkg, f = cal_source(cal)
    for loc in ch:
        if loc == "root":
            continue
        d = cldr.main(pkg, loc, f)
        if d is None:
            continue
        d = d["dates"]["calendars"].get(cal)
        for k in path:
            if not isinstance(d, dict) or k not in d:
                d = None
                break
            d = d[k]
        if isinstance(d, dict) and "_value" in d:
            d = d["_value"]
        if d is not None:
            return d
    return None


def terr_name(cldr, tag, code, chain, ch_en=None):
    """The name of a territory; a deprecated one (CS) takes the names of its successors, joined in English."""
    n = cldr.get("cldr-localenames-full", "territories", tag, "localeDisplayNames", "territories", code, chain=chain)
    if n is None and chain is ch_en and cldr.alias_terr.get(code, {}).get("_replacement"):
        names = [cldr.get("cldr-localenames-full", "territories", tag, "localeDisplayNames", "territories", r, chain=chain)
                 for r in cldr.alias_terr[code]["_replacement"].split()]
        n = " and ".join(x for x in names if x) or None
    return n


def time_format(cldr, ch, w):
    """The CLDR gregorian time format w of the locale chain. The -alt-ascii variants are not used: in en-GB, for one, that
    variant is the 12-hour format of a 24-hour locale."""
    return cldr.get("cldr-dates-full", "ca-gregorian", "", "dates", "calendars", "gregorian", "timeFormats", w, skip_root=True, chain=ch)


def display_name(cldr, tag, ch_en, ch_loc, with_script, force_script=False):
    """'German (Germany)' in the language of ch_loc (the CLDR localePattern rule); force_script names the script that the
    tag leaves implicit ('Chinese (Simplified, China)')."""
    lang, script, eff_script, region, lt_script = cldr.canonical(tag)
    if force_script and script is None:
        script = eff_script
    lname = cldr.get("cldr-localenames-full", "languages", tag, "localeDisplayNames", "languages", lang, chain=ch_loc) \
        or cldr.get("cldr-localenames-full", "languages", tag, "localeDisplayNames", "languages", lang, chain=ch_en) or lang
    extras = []
    if script and with_script:
        extras.append(cldr.get("cldr-localenames-full", "scripts", tag, "localeDisplayNames", "scripts", script, chain=ch_loc)
                      or cldr.get("cldr-localenames-full", "scripts", tag, "localeDisplayNames", "scripts", script, chain=ch_en) or script)
    reg = [p for p in tag.split("-")[1:] if len(p) == 2 or (len(p) == 3 and p.isdigit())]
    if reg:
        r = reg[0].upper()
        extras.append(terr_name(cldr, tag, r, ch_loc, ch_en) or terr_name(cldr, tag, r, ch_en, ch_en) or r)
    if not extras:
        return lname
    pat = cldr.get("cldr-localenames-full", "localeDisplayNames", tag, "localeDisplayNames", "localeDisplayPattern", chain=ch_loc) or {}
    sep = pat.get("localeSeparator", "{0}, {1}")
    joined = extras[0]
    for e in extras[1:]:
        joined = sep.replace("{0}", joined).replace("{1}", e)
    return pat.get("localePattern", "{0} ({1})").replace("{0}", lname).replace("{1}", joined)


# Mapping-rule selections of ANOTHER CLDR field for a language (see README.md, "Measured field selections"). Each entry picks a
# different pattern of the same locale's own CLDR data; no value is written here.
#  LONG_DATE_NO_WEEKDAY: the long date is CLDR dateFormats `long` (no weekday) instead of `full`.
#  SHORT_DATE_ISO: the short date is the locale's ISO 8601 calendar short date (ca-generic, iso8601) instead of `short`.
LONG_DATE_NO_WEEKDAY = {"ja", "zh", "ru"}
SHORT_DATE_ISO = {"ko"}


def iso_short_date(cldr, ch):
    return cldr.get("cldr-dates-full", "ca-generic", "", "dates", "calendars", "iso8601", "dateFormats", "short", skip_root=True, chain=ch)


def build_locale(cldr, name, sk):
    """All LCTYPE values (key -> value string, a '\\0' separates the nominative and genitive forms) of a locale, plus
    the calendar information, from CLDR and the skeleton."""
    sname = sk["fixed"]["LOCALE_SNAME"].strip('"')
    tag = sname.split("_")[0]            # es-ES_tradnl: the traditional sort of es-ES
    ch = cldr.chain(tag)
    ch_en = cldr.chain("en")
    if ch == ["root"]:
        # CLDR has no data for the language (dv): its own territory data, the English names (no Windows data)
        ch = ch_en
    lang, script, eff_script, region_tag, lt_script = cldr.canonical(tag)
    region = cldr.region_of(tag)
    v = {}
    fixed = sk["fixed"]
    lcid = sk["lcid"] if sk["lcid"] is not None else int(fixed["LOCALE_ILANGUAGE"].strip('"'), 16)
    lcid_s = "%04x" % lcid

    def G(pkg, f, *path, **kw):
        return cldr.get(pkg, f, tag, *path, chain=ch, **kw)

    # ---- identity -----------------------------------------------------------------------------------------------
    v["LOCALE_SNAME"] = sname
    v["LOCALE_ILANGUAGE"] = lcid_s
    v["LOCALE_IDEFAULTLANGUAGE"] = lcid_s
    v["LOCALE_SISO639LANGNAME"] = lang
    v["LOCALE_SISO639LANGNAME2"] = ISO639_2.get(lang, lang if len(lang) == 3 else "")
    tcode = cldr.codemap["territoryCodes"] if "territoryCodes" in cldr.codemap else cldr.codemap
    v["LOCALE_SISO3166CTRYNAME"] = [p for p in tag.split("-")[1:] if len(p) == 2][0].upper() if any(len(p) == 2 for p in tag.split("-")[1:]) else region
    v["LOCALE_SISO3166CTRYNAME2"] = tcode.get(v["LOCALE_SISO3166CTRYNAME"], {}).get("_alpha3", "")
    v["LOCALE_ICONSTRUCTEDLOCALE"] = "0"
    v["LOCALE_INEUTRAL"] = "0"
    v["LOCALE_SKEYBOARDSTOINSTALL"] = "%s:0000%s" % (lcid_s, lcid_s)
    v["LOCALE_SSORTLOCALE"] = tag
    # the parent: the language, with the script where the language has several
    par = lang + ("-" + eff_script if (lang in MULTI_SCRIPT_LANGS and eff_script) else "")
    v["LOCALE_SPARENT"] = par
    scr = eff_script or ""
    v["LOCALE_SSCRIPTS"] = "".join(s + ";" for s in SCRIPT_EXPAND.get(scr, scr).split(";") if s)
    v["LOCALE_SCONSOLEFALLBACKNAME"] = sname if scr in ("Latn", "Cyrl", "Grek", "Hani", "Hans", "Hant", "Jpan", "Kore") else "en-US"

    # ---- names --------------------------------------------------------------------------------------------------
    cm = lambda c: c
    v["LOCALE_SENGLANGUAGE"] = cldr.get("cldr-localenames-full", "languages", tag, "localeDisplayNames", "languages", lang, chain=ch_en) or lang
    v["LOCALE_SNATIVELANGNAME"] = G("cldr-localenames-full", "languages", "localeDisplayNames", "languages", lang) or v["LOCALE_SENGLANGUAGE"]
    v["LOCALE_SLOCALIZEDLANGUAGENAME"] = v["LOCALE_SENGLANGUAGE"]
    if lang in MULTI_SCRIPT_LANGS and eff_script:
        # a language written in several scripts is named with its script ("Chinese (Simplified)"), CLDR localePattern
        v["LOCALE_SNATIVELANGNAME"] = display_name(cldr, lang + "-" + eff_script, ch_en, ch, True, False)
        v["LOCALE_SLOCALIZEDLANGUAGENAME"] = display_name(cldr, lang + "-" + eff_script, ch_en, ch_en, True, False)
    rtag = [p for p in tag.split("-")[1:] if len(p) == 2 or (len(p) == 3 and p.isdigit())]
    rcode = rtag[0].upper() if rtag else region
    terr = lambda code, chain: terr_name(cldr, tag, code, chain, ch_en)
    v["LOCALE_SENGCOUNTRY"] = terr(rcode, ch_en) or rcode
    v["LOCALE_SCOUNTRY"] = v["LOCALE_SENGCOUNTRY"]
    v["LOCALE_SNATIVECTRYNAME"] = terr(rcode, ch) or v["LOCALE_SENGCOUNTRY"]
    v["LOCALE_SENGLISHDISPLAYNAME"] = display_name(cldr, tag, ch_en, ch_en, True, lang in MULTI_SCRIPT_LANGS)
    v["LOCALE_SLANGUAGE"] = v["LOCALE_SENGLISHDISPLAYNAME"]
    v["LOCALE_SNATIVEDISPLAYNAME"] = display_name(cldr, tag, ch_en, ch, True)

    # ---- numbers ------------------------------------------------------------------------------------------------
    nsys = G("cldr-numbers-full", "numbers", "numbers", "defaultNumberingSystem") or "latn"
    if nsys not in cldr.numsys or cldr.numsys[nsys].get("_type") != "numeric":
        nsys = "latn"
    digits = cldr.numsys[nsys]["_digits"]

    def num(*path):
        return G("cldr-numbers-full", "numbers", "main-numbers", *path)

    def N(*path):
        return cldr.get("cldr-numbers-full", "numbers", tag, "numbers", *path, chain=ch)

    # Rule NUM-LATN: the separators and the number/currency/percent patterns are those of the Latin numbering system, the
    # digits shown to the user are the default numbering system's (LOCALE_SNATIVEDIGITS, LOCALE_IDIGITSUBSTITUTION): the
    # Control Panel format of an ar or fa locale is "1,234.56" with national digit shaping, not "١٬٢٣٤٫٥٦".
    # The bidi controls of the CLDR symbols (ALM, RLM, LRM) are display hints, not part of the value.
    if sym_latn_ok(N):
        psys = "latn"
    else:
        psys = nsys
    sym = lambda k: strip_bidi(N("symbols-numberSystem-" + psys, k))
    if N("symbols-numberSystem-" + nsys, "decimal") is None:
        nsys, digits, psys = "latn", "0123456789", "latn"
    v["LOCALE_SNATIVEDIGITS"] = digits
    v["LOCALE_IDIGITSUBSTITUTION"] = "1" if digits == "0123456789" else "2"
    v["LOCALE_SDECIMAL"] = sym("decimal") or "."
    # a narrow no-break space as the group separator (fr, ...) is a no-break space: it converts to every ANSI code page
    # Rule APOS-TYPO (round 4): a group separator that is the bare ASCII apostrophe (de-CH, de-LI, it-CH, fr-CH, ...) is the
    # typographic apostrophe U+2019 (the Unicode Standard's character for the apostrophe in running text; U+0027 is the neutral
    # typewriter form). It is in the Windows ANSI code pages 1250-1258.
    v["LOCALE_STHOUSAND"] = (sym("group") or ",").replace("\u202f", "\u00a0").replace("'", "\u2019")
    # Rule LIST-CSV: CLDR's `list` symbol is the separator of a list of numbers in running text (";" nearly everywhere).
    # LOCALE_SLIST is the separator of tabular data (CSV): a comma, unless the comma is the decimal separator.
    v["LOCALE_SLIST"] = ";" if v["LOCALE_SDECIMAL"] == "," else ","
    v["LOCALE_SPERCENT"] = sym("percentSign") or "%"
    v["LOCALE_SPERMILLE"] = sym("perMille") or "‰"
    v["LOCALE_SNEGATIVESIGN"] = sym("minusSign") or "-"
    v["LOCALE_SPOSITIVESIGN"] = ""
    v["LOCALE_SNAN"] = sym("nan") or "NaN"
    v["LOCALE_SPOSINFINITY"] = sym("infinity") or "∞"
    v["LOCALE_SNEGINFINITY"] = v["LOCALE_SNEGATIVESIGN"] + v["LOCALE_SPOSINFINITY"]
    v["LOCALE_STIME"] = sym("timeSeparator") or ":"
    dfmt = N("decimalFormats-numberSystem-" + psys, "standard") or "#,##0.###"
    v["LOCALE_SGROUPING"] = grouping(dfmt)
    v["LOCALE_IDIGITS"] = "2"          # CLDR gives a maximum of fraction digits only; the control-panel default is 2
    v["LOCALE_ILZERO"] = "1"
    ncan = canon_money(dfmt, "$")
    neg = dfmt.split(";")[1] if ";" in dfmt else "-" + dfmt.split(";")[0]
    nneg = canon_money(neg, "$").replace("-", "-")
    v["LOCALE_INEGNUMBER"] = str(NEGNUM.index(nneg)) if nneg in NEGNUM else "1"
    pct = N("percentFormats-numberSystem-" + psys, "standard") or "#,##0%"
    pp, pn = split_pattern(pct)
    pc = canon_pct(pp)
    v["LOCALE_IPOSITIVEPERCENT"] = str(POSPCT.get(pc, 1))
    nc = canon_pct(pn) if pn else "-" + pc
    v["LOCALE_INEGATIVEPERCENT"] = str(NEGPCT.index(nc)) if nc in NEGPCT else "1"

    # ---- currency -----------------------------------------------------------------------------------------------
    cur = None
    for ent in cldr.region_value(cldr.curdata["region"], region, "001") or []:
        for code, info in ent.items():
            if "_to" not in info and info.get("_tender", "true") != "false":
                cur = code
                break
        if cur:
            break
    cur = cur or "USD"
    v["LOCALE_SINTLSYMBOL"] = cur
    csym = N("currencies", cur, "symbol") if False else cldr.get("cldr-numbers-full", "currencies", tag, "numbers", "currencies", cur, "symbol", chain=ch)
    v["LOCALE_SCURRENCY"] = fullwidth(csym or cur)
    v["LOCALE_SENGCURRNAME"] = cldr.get("cldr-numbers-full", "currencies", tag, "numbers", "currencies", cur, "displayName", chain=ch_en) or cur
    v["LOCALE_SNATIVECURRNAME"] = cldr.get("cldr-numbers-full", "currencies", tag, "numbers", "currencies", cur, "displayName", chain=ch) or v["LOCALE_SENGCURRNAME"]
    fr = cldr.curdata["fractions"].get(cur, cldr.curdata["fractions"]["DEFAULT"])
    v["LOCALE_ICURRDIGITS"] = fr["_digits"]
    v["LOCALE_IINTLCURRDIGITS"] = fr["_digits"]
    cpat = N("currencyFormats-numberSystem-" + psys, "standard") or "¤#,##0.00"
    cp, cn = split_pattern(cpat)
    v["LOCALE_SMONGROUPING"] = grouping(cp)
    cdec = sym("currencyDecimal") or v["LOCALE_SDECIMAL"]
    cgrp = (sym("currencyGroup") or v["LOCALE_STHOUSAND"]).replace("\u202f", "\u00a0").replace("'", "\u2019")
    v["LOCALE_SMONDECIMALSEP"] = cdec
    v["LOCALE_SMONTHOUSANDSEP"] = cgrp
    pcan = canon_money(cp, "$")
    v["LOCALE_ICURRENCY"] = str(POSCURR.get(pcan, 0))
    ncan = canon_money(cn, "$") if cn else "-" + pcan
    v["LOCALE_INEGCURR"] = str(NEGCURR.index(ncan)) if ncan in NEGCURR else "1"
    # ISO 4217 style sign/symbol position fields from the canonical patterns
    pbefore = pcan.find("$") < pcan.find("1.1")
    v["LOCALE_IPOSSYMPRECEDES"] = "1" if pbefore else "0"
    v["LOCALE_IPOSSEPBYSPACE"] = "1" if re.search(r"\$ 1\.1|1\.1 \$", pcan) else "0"
    # Rule SIGNPOSN: the sign sits "immediately before the currency symbol" (3) when the symbol leads the amount, and "before
    # the whole string" (1) when the amount leads; a trailing sign is 2, a sign after the symbol 4, parentheses 0.
    v["LOCALE_IPOSSIGNPOSN"] = "3" if pbefore else "1"
    nbefore = ncan.find("$") < ncan.find("1.1")
    v["LOCALE_INEGSYMPRECEDES"] = "1" if nbefore else "0"
    v["LOCALE_INEGSEPBYSPACE"] = "1" if re.search(r"\$ [-]?1\.1|1\.1[-]? \$", ncan) else "0"
    if ncan.startswith("("):
        sp = "0"
    elif ncan.startswith("-$"):
        sp = "3"
    elif ncan.startswith("-"):
        sp = "1"
    elif ncan.endswith("-"):
        sp = "2"
    elif re.search(r"-\$|-\s\$", ncan):
        sp = "3"
    else:
        sp = "4"
    v["LOCALE_INEGSIGNPOSN"] = sp

    # ---- dates and times ----------------------------------------------------------------------------------------
    gdf = lambda *p: cal_get(cldr, tag, ch, "gregorian", *p)
    dfm = lambda w: ldml_to_win(gdf("dateFormats", w) or "")
    tfm = lambda w: ldml_to_win(time_format(cldr, ch, w) or "")
    avail = lambda k: gdf("dateTimeFormats", "availableFormats", k) or ""
    short = dfm("short")
    if lang in SHORT_DATE_ISO and iso_short_date(cldr, ch):
        short = ldml_to_win(iso_short_date(cldr, ch))
    # CLDR short dates have a two-digit year, Windows short dates a four-digit one (an ambiguous short year is a regression)
    short = re.sub(r"(?<![y'])yy(?![y'])", "yyyy", short)
    longd = canon_quotes(dfm("long") if (lang in LONG_DATE_NO_WEEKDAY and dfm("long")) else dfm("full"))
    v["LOCALE_SSHORTDATE"] = short
    v["LOCALE_SLONGDATE"] = longd
    v["LOCALE_SYEARMONTH"] = ldml_to_win(avail("yMMMM"))
    v["LOCALE_SMONTHDAY"] = ldml_to_win(avail("MMMMd"))
    rel = avail("MMMMEd") or avail("MMMEd").replace("MMM", "MMMM").replace("MMMMM", "MMMM")
    rel = re.sub(r"(?<!')\b[Ec]{1,6}\b(?!')", "EEEE", rel) if rel else rel     # the long weekday name
    v["LOCALE_SRELATIVELONGDATE"] = canon_quotes(ldml_to_win(rel))
    v["LOCALE_SSHORTTIME"] = tfm("short")
    v["LOCALE_STIMEFORMAT"] = tfm("medium")
    sp_ = strip_quoted(v["LOCALE_SSHORTDATE"])
    v["LOCALE_SDATE"] = date_separator(v["LOCALE_SSHORTDATE"])
    v["LOCALE_IDATE"] = str(pattern_order(v["LOCALE_SSHORTDATE"]))
    v["LOCALE_ILDATE"] = str(pattern_order(v["LOCALE_SLONGDATE"]))
    v["LOCALE_ICENTURY"] = "1" if "yyyy" in sp_ else "0"
    v["LOCALE_IDAYLZERO"] = "1" if "dd" in sp_ else "0"
    v["LOCALE_IMONLZERO"] = "1" if "MM" in sp_ else "0"
    tf = strip_quoted(v["LOCALE_STIMEFORMAT"])
    v["LOCALE_ITIME"] = "1" if "H" in strip_quoted(v["LOCALE_SSHORTTIME"]) else "0"
    v["LOCALE_ITLZERO"] = "1" if ("HH" in tf or "hh" in tf) else "0"
    mark = tf.find("tt")
    hour = min([i for i in (tf.find("h"), tf.find("H")) if i >= 0] or [0])
    v["LOCALE_ITIMEMARKPOSN"] = "1" if (mark >= 0 and mark < hour) else "0"
    am = gdf("dayPeriods", "format", "abbreviated", "am") or "AM"
    pm = gdf("dayPeriods", "format", "abbreviated", "pm") or "PM"
    v["LOCALE_S1159"] = am
    v["LOCALE_S2359"] = pm
    # Rule AMPM: a locale whose time patterns have no day-period field and whose CLDR marker is only the default ("AM", "PM" of
    # the CLDR root/English data: not localized) has no marker; a locale with its own marker (cs "dop.", ja, zh, tr) keeps it.
    ram = cldr.get("cldr-dates-full", "ca-gregorian", "", "dates", "calendars", "gregorian", "dayPeriods", "format", "abbreviated", "am", chain=ch_en) or "AM"
    rpm = cldr.get("cldr-dates-full", "ca-gregorian", "", "dates", "calendars", "gregorian", "dayPeriods", "format", "abbreviated", "pm", chain=ch_en) or "PM"
    if "tt" not in v["LOCALE_STIMEFORMAT"] + v["LOCALE_SSHORTTIME"] and am == ram and pm == rpm:
        v["LOCALE_S1159"] = v["LOCALE_S2359"] = ""
    v["LOCALE_SSHORTESTAM"] = gdf("dayPeriods", "format", "narrow", "am") or am[:1]
    v["LOCALE_SSHORTESTPM"] = gdf("dayPeriods", "format", "narrow", "pm") or pm[:1]
    # duration
    dur = cldr.get("cldr-units-full", "units", tag, "units", "durationUnit-type-hms", chain=ch) if False else None
    for loc in ch:
        d = cldr.main("cldr-units-full", loc, "units")
        if d and "durationUnit-type-hms" in d["units"]:
            dur = d["units"]["durationUnit-type-hms"]["durationUnitPattern"]
            break
    if dur is None:
        for loc in ch_en:
            d = cldr.main("cldr-units-full", loc, "units")
            if d and "durationUnit-type-hms" in d["units"]:
                dur = d["units"]["durationUnit-type-hms"]["durationUnitPattern"]
                break
    v["LOCALE_SDURATION"] = ldml_to_win(dur or "h:mm:ss").replace("ss", "ss")

    # day and month names
    mw = names12(cldr, tag, ch, "gregorian", "months", "wide", True, 12)
    mwf = names12(cldr, tag, ch, "gregorian", "months", "wide", False, 12)
    ma = names12(cldr, tag, ch, "gregorian", "months", "abbreviated", True, 12)
    maf = names12(cldr, tag, ch, "gregorian", "months", "abbreviated", False, 12)
    for i in range(12):
        nom, gen = mw[i], mwf[i]
        v["LOCALE_SMONTHNAME%d" % (i + 1)] = nom if nom == gen else nom + "\0" + gen
        nom, gen = ma[i], maf[i]
        v["LOCALE_SABBREVMONTHNAME%d" % (i + 1)] = nom if nom == gen else nom + "\0" + gen
    v["LOCALE_SMONTHNAME13"] = ""
    v["LOCALE_SABBREVMONTHNAME13"] = ""
    dw = names12(cldr, tag, ch, "gregorian", "days", "wide", True, 7)
    da = names12(cldr, tag, ch, "gregorian", "days", "abbreviated", True, 7)
    ds = [x[:-1] if x.endswith(".") and len(x) > 2 else x for x in names12(cldr, tag, ch, "gregorian", "days", "short", True, 7)]
    dn = names12(cldr, tag, ch, "gregorian", "days", "narrow", True, 7)
    ds = [n if (len(x) > 3 and n) else x for x, n in zip(ds, dn)]      # where CLDR's short name is a whole word, the narrow one
    for i in range(7):
        v["LOCALE_SDAYNAME%d" % (i + 1)] = dw[i]
        v["LOCALE_SABBREVDAYNAME%d" % (i + 1)] = da[i]
        v["LOCALE_SSHORTESTDAYNAME%d" % (i + 1)] = ds[i]

    # ---- regional ------------------------------------------------------------------------------------------------
    fd = cldr.region_value(cldr.week["firstDay"], region)
    v["LOCALE_IFIRSTDAYOFWEEK"] = str(FIRSTDAY[fd])
    md = cldr.region_value(cldr.week["minDays"], region)
    v["LOCALE_IFIRSTWEEKOFYEAR"] = {"1": "0", "4": "2", "7": "1"}.get(md, "0")
    ms = cldr.region_value(cldr.meas["measurementSystem"], region)
    v["LOCALE_IMEASURE"] = "1" if ms == "US" else "0"
    ps = cldr.region_value(cldr.meas["paperSize"], region)
    v["LOCALE_IPAPERSIZE"] = "1" if ps == "US-Letter" else "9"
    co = G("cldr-misc-full", "layout", "layout", "orientation", "characterOrder")
    v["LOCALE_IREADINGLAYOUT"] = "1" if co == "right-to-left" else "0"

    # ---- calendars ------------------------------------------------------------------------------------------------
    pref = cldr.region_value(cldr.calpref, region) or ["gregorian"]
    # Rule CAL-UMALQURA: CLDR lists the business calendar (gregorian) first for Saudi Arabia but also names Umm al-Qura, the
    # official civil calendar of the kingdom (the only territory with that variant): it is the default calendar there.
    if pref and pref[0] == "gregorian" and "islamic-umalqura" in pref:
        pref = ["islamic-umalqura"] + [c for c in pref if c != "islamic-umalqura"]
    cals = []
    for c in pref:
        w = WINCAL.get(c)
        if w and w not in cals:
            cals.append(w)
    if 1 not in cals:
        cals.append(1)
    v["LOCALE_ICALENDARTYPE"] = str(cals[0])
    opts = [c for c in cals[1:]]
    v["LOCALE_IOPTIONALCALENDAR"] = "\0".join(str(c) for c in opts) if opts else "0"
    for k in ("LOCALE_SNATIVELANGNAME", "LOCALE_SNATIVECTRYNAME", "LOCALE_SNATIVEDISPLAYNAME", "LOCALE_SNATIVECURRNAME"):
        v[k] = fullwidth(v[k])
    # no narrow no-break space (U+202F) in any value: it has no glyph in console fonts and becomes '?' in an ANSI code page
    for k in v:
        if v[k] and "\u202f" in v[k]:
            v[k] = v[k].replace("\u202f", "\u00a0")
    return sname, ch, v, cals, region


# ---------------------------------------------------------------------------------------------------------------------
# .nls output
# ---------------------------------------------------------------------------------------------------------------------

KEY_ORDER = """FONTSIGNATURE ICALENDARTYPE ICENTURY ICONSTRUCTEDLOCALE ICOUNTRY ICURRDIGITS ICURRENCY IDATE IDAYLZERO
IDEFAULTANSICODEPAGE IDEFAULTCODEPAGE IDEFAULTCOUNTRY IDEFAULTEBCDICCODEPAGE IDEFAULTLANGUAGE IDEFAULTMACCODEPAGE IDIGITS
IDIGITSUBSTITUTION IFIRSTDAYOFWEEK IFIRSTWEEKOFYEAR IGEOID IINTLCURRDIGITS ILANGUAGE ILDATE ILZERO IMEASURE IMONLZERO
INEGATIVEPERCENT INEGCURR INEGNUMBER INEGSEPBYSPACE INEGSIGNPOSN INEGSYMPRECEDES INEUTRAL IOPTIONALCALENDAR IPAPERSIZE
IPOSITIVEPERCENT IPOSSEPBYSPACE IPOSSIGNPOSN IPOSSYMPRECEDES IREADINGLAYOUT ITIME ITIMEMARKPOSN ITLZERO S1159 S2359
SABBREVCTRYNAME SABBREVDAYNAME1 SABBREVDAYNAME2 SABBREVDAYNAME3 SABBREVDAYNAME4 SABBREVDAYNAME5 SABBREVDAYNAME6
SABBREVDAYNAME7 SABBREVLANGNAME SABBREVMONTHNAME1 SABBREVMONTHNAME2 SABBREVMONTHNAME3 SABBREVMONTHNAME4 SABBREVMONTHNAME5
SABBREVMONTHNAME6 SABBREVMONTHNAME7 SABBREVMONTHNAME8 SABBREVMONTHNAME9 SABBREVMONTHNAME10 SABBREVMONTHNAME11
SABBREVMONTHNAME12 SABBREVMONTHNAME13 SCONSOLEFALLBACKNAME SCOUNTRY SCURRENCY SDATE SDAYNAME1 SDAYNAME2 SDAYNAME3
SDAYNAME4 SDAYNAME5 SDAYNAME6 SDAYNAME7 SDECIMAL SDURATION SENGCOUNTRY SENGCURRNAME SENGLANGUAGE SENGLISHDISPLAYNAME
SGROUPING SINTLSYMBOL SISO3166CTRYNAME SISO3166CTRYNAME2 SISO639LANGNAME SISO639LANGNAME2 SKEYBOARDSTOINSTALL SLANGUAGE
SLIST SLOCALIZEDLANGUAGENAME SLONGDATE SMONDECIMALSEP SMONGROUPING SMONTHDAY SMONTHNAME1 SMONTHNAME2 SMONTHNAME3
SMONTHNAME4 SMONTHNAME5 SMONTHNAME6 SMONTHNAME7 SMONTHNAME8 SMONTHNAME9 SMONTHNAME10 SMONTHNAME11 SMONTHNAME12
SMONTHNAME13 SMONTHOUSANDSEP SNAME SNAN SNATIVECTRYNAME SNATIVECURRNAME SNATIVEDIGITS SNATIVEDISPLAYNAME SNATIVELANGNAME
SNEGATIVESIGN SNEGINFINITY SOPENTYPELANGUAGETAG SPERCENT SPERMILLE SPOSINFINITY SPOSITIVESIGN SRELATIVELONGDATE SSCRIPTS
SPARENT SSHORTDATE SSHORTESTAM SSHORTESTDAYNAME1 SSHORTESTDAYNAME2 SSHORTESTDAYNAME3 SSHORTESTDAYNAME4 SSHORTESTDAYNAME5
SSHORTESTDAYNAME6 SSHORTESTDAYNAME7 SSHORTESTPM SSHORTTIME SSORTLOCALE SSORTNAME STHOUSAND STIME STIMEFORMAT SYEARMONTH""".split()


def write_nls(path, name, sk, v):
    header = sk["header"]
    note = ("/*\n * Generated by sdk/tools/nlsgen from Unicode CLDR %s (https://cldr.unicode.org/, Unicode License v3);\n"
            " * do not edit, run sdk/tools/nlsgen/nlsgen.py. The locale identity (code pages, GEOID, font signature,\n"
            " * abbreviations) is the skeleton of sdk/tools/nlsgen/data/skeleton.json.\n */\n\n") % CLDR_VERSION
    lines = [header.rstrip("\n"), "", note.rstrip("\n"), "", "#pragma code_page(65001) /* UTF-8 */", "",
             "STRINGTABLE LANGUAGE %s, %s" % (sk["language"], sk["sublang"]), "{"]
    vals = {}
    for k, s in sk["fixed"].items():
        vals[k] = s          # already an RC literal
    for k, s in v.items():
        if s is None:
            sys.exit("nlsgen: %s (%s): CLDR has no value for %s" % (name, v["LOCALE_SNAME"], k))
        if k not in vals:
            vals[k] = rc_str(s)
    vals["LOCALE_ILANGUAGE"] = rc_str(v["LOCALE_ILANGUAGE"])
    vals["LOCALE_IDEFAULTLANGUAGE"] = rc_str(v["LOCALE_IDEFAULTLANGUAGE"])
    vals["LOCALE_SNAME"] = rc_str(v["LOCALE_SNAME"])
    for k in KEY_ORDER:
        key = "LOCALE_" + k
        if key in vals:
            lines.append("  %s %s" % (key, vals[key]))
        else:
            sys.exit("nlsgen: %s: no value for %s" % (name, key))
    extra = set(vals) - {"LOCALE_" + k for k in KEY_ORDER}
    if extra:
        sys.exit("nlsgen: %s: values not in KEY_ORDER: %s" % (name, sorted(extra)))
    lines.append("")
    for k, s in sk["lgrp"]:
        lines.append("  %s %s" % (k, s))
    lines.append("}")
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(lines) + "\n")


# ---------------------------------------------------------------------------------------------------------------------
# calendar_data.c
# ---------------------------------------------------------------------------------------------------------------------

CAL_ICALINTVALUE, CAL_SCALNAME, CAL_IYEAROFFSETRANGE, CAL_SERASTRING = 1, 2, 3, 4
CAL_SSHORTDATE, CAL_SLONGDATE = 5, 6
CAL_SDAYNAME1, CAL_SABBREVDAYNAME1, CAL_SMONTHNAME1, CAL_SABBREVMONTHNAME1 = 7, 14, 21, 34
CAL_SYEARMONTH, CAL_SMONTHDAY, CAL_SABBREVERASTRING, CAL_SRELATIVELONGDATE = 47, 56, 57, 58
CLDR_CAL = {1: "gregorian", 3: "japanese", 4: "roc", 6: "islamic", 7: "buddhist", 8: "hebrew", 22: "persian", 23: "islamic-umalqura"}


def current_era(cldr, cal):
    eras = cldr.caldata.get(cal, {}).get("eras", {})
    best = None
    for k, e in eras.items():
        if "_end" not in e:
            best = k
    return best if best is not None else (sorted(eras)[-1] if eras else "0")


def build_calendar_rows(cldr, tag, ch, cals, gv):
    """rows {(cal, type): string}, enum {(cal, type): [strings]} for one locale."""
    rows, enum = {}, {}
    en_ch = cldr.chain("en")
    gcal_names = {}
    for c in cals:
        cal = CLDR_CAL[c]
        # calendar name
        nm = cldr.get("cldr-localenames-full", "localeDisplayNames", tag, "localeDisplayNames", "types", "calendar", cal, chain=ch) \
            or cldr.get("cldr-localenames-full", "localeDisplayNames", tag, "localeDisplayNames", "types", "calendar", cal, chain=en_ch)
        if nm:
            rows[(c, CAL_SCALNAME)] = nm
        ek = current_era(cldr, cal)
        era = cal_get(cldr, tag, ch, cal, "eras", "eraAbbr", ek)
        if era is not None:
            rows[(c, CAL_SERASTRING)] = era
            rows[(c, CAL_SABBREVERASTRING)] = era
        # first year offset of the era
        st = cldr.caldata.get(cal, {}).get("eras", {}).get(ek, {}).get("_start")
        if cal == "buddhist" and st:
            rows[(c, CAL_IYEAROFFSETRANGE)] = str(1 - int(st.split("-01-01")[0]))
        elif cal == "roc" and st:
            rows[(c, CAL_IYEAROFFSETRANGE)] = st.split("-")[0]
        # formats of the calendar
        def f(k, w):
            return ldml_to_win(cal_get(cldr, tag, ch, cal, "dateFormats", w) or "", cal in ("japanese", "roc")) if k == "d" else ""
        pkg, fn = cal_source(cal)

        def avail(k):
            return ldml_to_win(cal_get(cldr, tag, ch, cal, "dateTimeFormats", "availableFormats", k) or "", cal in ("japanese", "roc"))

        def uniq(seq):
            out = []
            for s in seq:
                if s and s not in out:
                    out.append(s)
            return out
        lang = cldr.canonical(tag)[0]
        shortf = f("d", "short")
        if c == 1 and lang in SHORT_DATE_ISO and iso_short_date(cldr, ch):
            shortf = ldml_to_win(iso_short_date(cldr, ch))
        sd = uniq([re.sub(r"(?<![y'])yy(?![y'])", "yyyy", shortf), f("d", "medium")])
        ld = uniq([canon_quotes(x) for x in ([f("d", "long"), f("d", "full")] if (c == 1 and lang in LONG_DATE_NO_WEEKDAY) else [f("d", "full"), f("d", "long")])])
        md = uniq([avail("MMMMd"), avail("Md")])
        ym = uniq([avail("yMMMM")])
        # the values of the default Gregorian calendar are those of the locale data (LOCALE_SSHORTDATE...): no rows
        if sd:
            if c != 1:
                rows[(c, CAL_SSHORTDATE)] = sd[0]
            enum[(c, CAL_SSHORTDATE)] = sd
        if ld:
            if c != 1:
                rows[(c, CAL_SLONGDATE)] = ld[0]
            enum[(c, CAL_SLONGDATE)] = ld
        if md:
            if c != 1:
                rows[(c, CAL_SMONTHDAY)] = md[0]
            enum[(c, CAL_SMONTHDAY)] = md
        if ym:
            if c != 1:
                rows[(c, CAL_SYEARMONTH)] = ym[0]
            enum[(c, 0xf0 + 0)] = ym        # staged for the 0xff pseudo calendar
        if c != 1:
            # month names of the calendar, where they are not those of the Gregorian one
            n = 13 if cal == "hebrew" else 12
            for kind, base_t, width in (("wide", CAL_SMONTHNAME1, "wide"), ("abbr", CAL_SABBREVMONTHNAME1, "abbreviated")):
                names = names12(cldr, tag, ch, cal, "months", width, True, n)
                if None in names:
                    continue
                if cal not in ("buddhist", "japanese", "roc"):
                    for i, s in enumerate(names):
                        rows[(c, base_t + i)] = s
    return rows, enum


def write_calendar_c(path, cldr, locales):
    """locales: list of (langid, tag, ch, v, cals)"""
    pool = ["\0"]
    pool_idx = {"": 0}
    off = 1

    def intern(s):
        nonlocal off
        if s in pool_idx:
            return pool_idx[s]
        pool_idx[s] = off
        pool.append(s + "\0")
        o = off
        off += len(s) + 1
        return o

    def intern_list(items):
        nonlocal off
        s = "".join(i + "\0" for i in items)
        key = "\x01LIST" + s
        if key in pool_idx:
            return pool_idx[key]
        pool_idx[key] = off
        pool.append(s + "\0")
        o = off
        off += len(s) + 1
        return o

    rows, enumrows, lists = [], [], []
    for lid, tag, ch, v, cals in sorted(locales, key=lambda x: x[0]):
        r, e = build_calendar_rows(cldr, tag, ch, cals, v)
        for (c, t), s in sorted(r.items()):
            rows.append(((lid << 16) | (c << 8) | t, intern(s)))
        # enumerations of each calendar, then the 0xff (all calendars, with the calendar number) and 0xfe (time) lists
        for (c, t), items in sorted(e.items()):
            if t == 0xf0:
                continue
            enumrows.append(((lid << 16) | (c << 8) | t, intern_list(items)))
        for t in (CAL_SSHORTDATE, CAL_SLONGDATE, 0xf0):
            allf = []
            for c in cals:
                for s in e.get((c, t), []):
                    allf.append(chr(c) + s)
            if allf:
                enumrows.append(((lid << 16) | (0xff << 8) | (CAL_SYEARMONTH if t == 0xf0 else t), intern_list(allf)))
        # time formats of the locale
        gdf = lambda *p: cal_get(cldr, tag, ch, "gregorian", *p)
        tl = []
        for k in ("medium", "short"):
            s = ldml_to_win(time_format(cldr, ch, k) or "")
            if s and s not in tl:
                tl.append(s)
        for k in ("Hms", "hms"):
            s = ldml_to_win(gdf("dateTimeFormats", "availableFormats", k) or "")
            if s and s not in tl and len(tl) < 3:
                tl.append(s)
        enumrows.append(((lid << 16) | (0xfe << 8) | 0, intern_list(tl)))
        lists.append((lid, cals))
    rows.sort()
    enumrows.sort()
    out = []
    out.append("/*\n * PROJECT:     ReactOS system libraries\n * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)\n"
               " * PURPOSE:     Calendar data of the locales (generated by sdk/tools/nlsgen from Unicode CLDR %s; do not edit)\n"
               " * COPYRIGHT:   Copyright 2026 Tomas Srnka (tomas.srnka@e2b.dev)\n"
               " *              Contains data of the Unicode Common Locale Data Repository, Copyright Unicode, Inc., Unicode License v3\n */\n\n" % CLDR_VERSION)
    out.append('#include "calendar_data.h"\n')
    out.append("/* Strings of the tables below, NUL-terminated and concatenated; offset 0 is the empty string. */")
    out.append("static const WCHAR NlsCalPool[] =")
    for s in pool:
        parts = s.split("\0")[:-1]
        out.append("    " + " ".join('L"%s\\0"' % c_str(p) for p in parts))
    out[-1] += ";"
    out.append("")
    out.append("/* Values of a locale and calendar: key is (LANGID << 16) | (calendar << 8) | CALTYPE */")
    out.append("static const NLS_CAL_ROW NlsCalRows[] =\n{")
    for k, o in rows:
        out.append("    { 0x%08x, %d }," % (k, o))
    out.append("};\n")
    out.append("/* The NUL-separated lists of EnumCalendarInfo, EnumDateFormats and EnumTimeFormats (calendar 0xff: all date\n * formats, each preceded by the number of its calendar; 0xfe: time formats) */")
    out.append("static const NLS_CAL_ROW NlsCalEnumRows[] =\n{")
    for k, o in enumrows:
        out.append("    { 0x%08x, %d }," % (k, o))
    out.append("};\n")
    out.append("/* The calendars of a locale, the default one first */")
    out.append("static const NLS_CAL_LIST NlsCalLists[] =\n{")
    for lid, cals in lists:
        out.append("    { 0x%04x, %d, { %s } }," % (lid, len(cals), ", ".join(str(c) for c in cals)))
    out.append("};\n")
    out.append("const WCHAR *NlsCalPoolBase(void) { return NlsCalPool; }")
    out.append("const NLS_CAL_ROW *NlsCalRowTable(ULONG *Count) { *Count = ARRAYSIZE(NlsCalRows); return NlsCalRows; }")
    out.append("const NLS_CAL_ROW *NlsCalEnumRowTable(ULONG *Count) { *Count = ARRAYSIZE(NlsCalEnumRows); return NlsCalEnumRows; }")
    out.append("const NLS_CAL_LIST *NlsCalListTable(ULONG *Count) { *Count = ARRAYSIZE(NlsCalLists); return NlsCalLists; }")
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(out) + "\n")


# ---------------------------------------------------------------------------------------------------------------------

def main():
    global ISO639_2
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--cache", help="directory for the downloaded CLDR zip (default: ./cldr-cache)")
    ap.add_argument("--cldr-zip", help="an already downloaded %s" % os.path.basename(CLDR_URL))
    ap.add_argument("--nls-dir", required=True, help="output directory of the .nls files")
    ap.add_argument("--calendar-c", required=True, help="output path of calendar_data.c")
    ap.add_argument("--skeleton", default=os.path.join(HERE, "data", "skeleton.json"))
    ap.add_argument("--only", help="comma separated .nls base names (debugging)")
    ap.add_argument("--dump", help="write the values of every locale as JSON to this file (the parity report reads it)")
    a = ap.parse_args()
    zp = a.cldr_zip or fetch_zip(a.cache or "cldr-cache")
    cldr = Cldr(zp)
    ISO639_2 = json.load(open(os.path.join(HERE, "data", "iso639-2.json"), encoding="utf-8"))
    skel = json.load(open(a.skeleton, encoding="utf-8"))
    only = set(a.only.split(",")) if a.only else None
    locales, dump = [], {}
    for name in sorted(skel):
        if only and name not in only:
            continue
        sk = skel[name]
        tag, ch, v, cals, region = build_locale(cldr, name, sk)
        write_nls(os.path.join(a.nls_dir, name + ".nls"), name, sk, v)
        lid = int(v["LOCALE_ILANGUAGE"], 16)
        locales.append((lid, tag, ch, v, cals))
        dump[tag] = v
    write_calendar_c(a.calendar_c, cldr, locales)
    if a.dump:
        json.dump(dump, open(a.dump, "w", encoding="utf-8"), indent=1, ensure_ascii=False, sort_keys=True)
    print("nlsgen: %d locales from CLDR %s" % (len(locales), CLDR_VERSION))


if __name__ == "__main__":
    main()
