#!/usr/bin/env python3
"""Provenance tool: add the locales of [MS-LCID] that CLDR 49.0.0 has data for to data/skeleton.json.

A new locale gets an identity entry (name, LCID, LANGUAGE/SUBLANG, default code pages, GEOID, calling code,
abbreviations, OpenType tag, font signature) that nlsgen.py turns, together with the CLDR data, into
nls/<tag>.nls. Sources (no Windows binary or measured Windows value is read):
  data/ms-lcid.tsv   [MS-LCID] Language ID table (LCID and language tag), revision 2024-04-23
  data/geo-ids.tsv   Windows "Table of Geographical Locations" (GEOID by country name)
  CLDR               territory names (to match the GEO table), ISO 3166 alpha-3 (codeMappings), likely scripts
  REGION_CALLING     ITU-T E.164 country calling codes (public)
  the skeleton       code pages, abbreviations, OpenType tag and font signature of an existing locale of the same
                     language and script (a region variant has the language's); a language without an entry gets the
                     defaults of its script (SCRIPT_DEFAULTS), ISO 639-2/T for the abbreviation and the OpenType tag
                     derived from the ISO code; font signature = the signature of an entry with the same ANSI code page
                     plus the OpenType OS/2 ulUnicodeRange bit of the script (OpenType spec, OS/2 table).
  add_locales.py REPO_NLSGEN_DIR CLDR_ZIP        (rewrites data/skeleton.json; idempotent: entries it wrote have "added": true)
"""
import json, os, re, sys, zipfile

HERE = sys.argv[1]
ZIP = sys.argv[2]
SK = os.path.join(HERE, "data", "skeleton.json")
z = zipfile.ZipFile(ZIP)
cl = lambda n: json.loads(z.read(n).decode("utf-8"))
avail = set(cl("cldr-core/availableLocales.json")["availableLocales"]["full"])
likely = cl("cldr-core/supplemental/likelySubtags.json")["supplemental"]["likelySubtags"]
codemap = cl("cldr-core/supplemental/codeMappings.json")["supplemental"]["codeMappings"]
terr = cl("cldr-localenames-full/main/en/territories.json")["main"]["en"]["localeDisplayNames"]["territories"]
iso2 = json.load(open(os.path.join(HERE, "data", "iso639-2.json"), encoding="utf-8"))

# ITU-T E.164 country calling codes of the territories that no existing locale has (public facts)
REGION_CALLING = {"AF": 93, "BA": 387, "BD": 880, "BT": 975, "BW": 267, "CD": 243, "CI": 225, "CM": 237, "CU": 53, "ER": 291,
                  "ET": 251, "GL": 299, "HT": 509, "KH": 855, "LA": 856, "MD": 373, "ME": 382, "ML": 223, "MM": 95, "MT": 356,
                  "NG": 234, "RE": 262, "RW": 250, "SN": 221, "SO": 252, "TJ": 992, "TM": 993}
# CLDR English territory name -> Windows GEO table short name where they differ
GEO_NAME = {"BA": "Bosnia and Herzegovina", "CD": "Congo (DRC)", "CI": "Côte d'Ivoire", "MM": "Myanmar", "LA": "Laos",
            "MD": "Moldova", "RE": "Réunion", "HK": "Hong Kong SAR", "MO": "Macao SAR", "ME": "Montenegro"}

# defaults of a language that has no entry yet: (ANSI, OEM, MAC, EBCDIC) by script (the code pages of the entries
# of the same script in the skeleton); ANSI 0 = no ANSI code page (Unicode only), as hi-IN, ka-GE, si-LK.
SCRIPT_DEFAULTS = {"Latn": (1252, 850, 10000, 500), "Cyrl": (1251, 866, 10007, 20880), "Arab": (1256, 720, 10004, 20420)}
NOCP = (0, 1, 2, 500)
# per language exceptions (documented choices, see the README): Turkmen and Philippine/West African languages
LANG_CP = {"tk": (1250, 852, 10029, 500), "fil": (1252, 437, 10000, 500), "ii": (936, 936, 10008, 500),
           ("bs", "Latn"): (1250, 852, 10029, 500), ("bs", "Cyrl"): (1251, 855, 10007, 21025)}
# OS/2 ulUnicodeRange bit of a script without an entry (OpenType OS/2 table)
SCRIPT_BIT = {"Orya": 19, "Mlym": 23, "Laoo": 25, "Tibt": 70, "Mymr": 74, "Ethi": 75, "Cher": 76, "Khmr": 80, "Mong": 81,
              "Yiii": 83, "Tfng": 98, "Beng": 16, "Deva": 15}
LANG_SCRIPT_FB = {"or": "Orya", "ml": "Mlym", "lo": "Laoo", "bo": "Tibt", "dz": "Tibt", "my": "Mymr", "am": "Ethi", "ti": "Ethi",
                  "chr": "Cher", "km": "Khmr", "mn": "Mong", "ii": "Yiii", "tzm": "Tfng", "as": "Beng", "ks": "Deva"}
# ISO 639-2/T of the languages that are new in the skeleton (Library of Congress)
ISO_NEW = {"hsb": "hsb", "dsb": "dsb", "st": "sot", "tn": "tsn", "xh": "xho", "zu": "zul", "nso": "nso", "mt": "mlt", "se": "sme",
           "smn": "smn", "tk": "tuk", "or": "ori", "ml": "mal", "as": "asm", "bo": "bod", "km": "khm", "lo": "lao", "my": "mya",
           "am": "amh", "ti": "tir", "om": "orm", "fy": "fry", "ps": "pus", "fil": "fil", "ff": "ful", "yo": "yor", "ba": "bak",
           "lb": "ltz", "kl": "kal", "ig": "ibo", "haw": "haw", "so": "som", "ii": "iii", "ug": "uig", "mi": "mri", "oc": "oci",
           "gsw": "gsw", "sah": "sah", "rw": "kin", "wo": "wol", "dz": "dzo", "tg": "tgk", "chr": "chr", "tzm": "tzm", "ks": "kas",
           "sd": "snd", "ha": "hau", "bs": "bos", "ca": "cat", "mn": "mon", "pa": "pan"}

sk = json.load(open(SK, encoding="utf-8"))
sk = {k: v for k, v in sk.items() if not v.get("added")}          # idempotent
geo = {}
for l in open(os.path.join(HERE, "data", "geo-ids.tsv"), encoding="utf-8"):
    if l.startswith("#"):
        continue
    i, s, _ = l.rstrip("\n").split("\t")
    geo[s] = int(i)

def sname(e):
    return e["fixed"]["LOCALE_SNAME"].strip('"').split("_")[0]
def parse(tag):
    p = tag.split("-")
    lang, scr, reg, var = p[0], None, None, None
    for x in p[1:]:
        if len(x) == 4 and x.isalpha():
            scr = x.title()
        elif len(x) == 2 and x.isalpha():
            reg = x.upper()
        elif len(x) >= 5:
            var = x
    return lang, scr, reg, var
def script_of(lang, scr):
    if scr:
        return scr
    lt = likely.get(lang, "")
    return lt.split("-")[1] if lt.count("-") >= 2 else "Latn"

have_by_lang = {}
for k, e in sk.items():
    lang, scr, reg, var = parse(sname(e))
    have_by_lang.setdefault(lang, []).append((script_of(lang, scr), int(e["lcid"]), k))
have_region = {}
for k, e in sk.items():
    lang, scr, reg, var = parse(sname(e))
    if reg and reg not in have_region:
        have_region[reg] = e["fixed"]
def unq(s):
    return s.strip('"')

# LANGIDs of the hand-written locale files that are not in the skeleton (Wine extensions): a second resource with the same
# language id would be ambiguous, so the [MS-LCID] locale of that id (0x0492 ku-Arab-IQ) is listed and skipped
HANDWRITTEN = {0x047f, 0x048f, 0x0490, 0x0492, 0x0494, 0x04a5}
rows = []
for l in open(os.path.join(HERE, "data", "ms-lcid.tsv"), encoding="utf-8"):
    if l.startswith("#"):
        continue
    a, b = l.rstrip("\n").split("\t")
    lcid = int(a, 16)
    # "ff-NG, ff-Latn-NG": a row with two names (and no `reserved`) is named by the last one (the name Windows lists)
    tag = b.split(",")[-1].strip().replace("\\_", "_")
    if lcid < 0x400 or lcid > 0xFFFF or "_" in tag or " " in tag or "reserved" in b.lower() or "Neither" in b:
        continue
    lang, scr, reg, var = parse(tag)
    if not reg or not reg.isalpha():           # neutral (language or language+script) and 3-digit regions (001, 029, 015)
        continue
    if lcid in HANDWRITTEN:
        print("skip (language id used by a hand-written locale file):", hex(lcid), tag)
        continue
    if any(int(e["lcid"]) == lcid for e in sk.values()) or tag.lower() in {sname(e).lower() for e in sk.values()}:
        continue
    cldr_id = tag.replace("-valencia", "-valencia")
    if not (cldr_id in avail or lang in avail):
        print("skip (no CLDR data):", hex(lcid), tag)
        continue
    rows.append((lcid, tag, lang, scr, reg, var))

fixed_order = ["LOCALE_FONTSIGNATURE", "LOCALE_ICOUNTRY", "LOCALE_IDEFAULTANSICODEPAGE", "LOCALE_IDEFAULTCODEPAGE", "LOCALE_IDEFAULTCOUNTRY",
               "LOCALE_IDEFAULTEBCDICCODEPAGE", "LOCALE_IDEFAULTLANGUAGE", "LOCALE_IDEFAULTMACCODEPAGE", "LOCALE_IGEOID",
               "LOCALE_ILANGUAGE", "LOCALE_SABBREVCTRYNAME", "LOCALE_SABBREVLANGNAME", "LOCALE_SNAME", "LOCALE_SOPENTYPELANGUAGETAG",
               "LOCALE_SSORTNAME"]
lgrp = next(iter(sk.values()))["lgrp"]
sig_by_ansi = {}
for e in sk.values():
    sig_by_ansi.setdefault(unq(e["fixed"]["LOCALE_IDEFAULTANSICODEPAGE"]), e["fixed"]["LOCALE_FONTSIGNATURE"])
sig_by_ansi["1252"] = sk["enu"]["fixed"]["LOCALE_FONTSIGNATURE"]
sig_by_ansi["1250"] = sk["csy"]["fixed"]["LOCALE_FONTSIGNATURE"]
sig_by_ansi["0"] = sk["hin"]["fixed"]["LOCALE_FONTSIGNATURE"]

def set_bit(sig, bit):
    w = [int(x, 16) for x in re.findall(r"\\x([0-9a-fA-F]{4})", sig)]
    w[bit // 16] |= 1 << (bit % 16)
    return 'L"' + "".join("\\x%04x" % x for x in w) + '"'

def fname(tag):
    return tag.lower()
added = 0
for lcid, tag, lang, scr, reg, var in sorted(rows):
    s = script_of(lang, scr)
    sib = [x for x in have_by_lang.get(lang, []) if x[0] == s]
    base = sk[sorted(sib, key=lambda x: x[1])[0][2]]["fixed"] if sib else None
    # a language entry of another script (mn-Mong, pa-Arab) lends only its abbreviation and OpenType tag
    other = have_by_lang.get(lang)
    obase = sk[sorted(other, key=lambda x: x[1])[0][2]]["fixed"] if other else None
    if base:
        cps = tuple(int(unq(base[k])) for k in ("LOCALE_IDEFAULTANSICODEPAGE", "LOCALE_IDEFAULTCODEPAGE", "LOCALE_IDEFAULTMACCODEPAGE"))
        ebc = unq(base["LOCALE_IDEFAULTEBCDICCODEPAGE"])
        sig = base["LOCALE_FONTSIGNATURE"]
        ablang, otag = unq(base["LOCALE_SABBREVLANGNAME"]), unq(base["LOCALE_SOPENTYPELANGUAGETAG"])
    else:
        c = LANG_CP.get((lang, s)) or LANG_CP.get(lang) or SCRIPT_DEFAULTS.get(s) or NOCP
        cps, ebc = c[:3], str(c[3])
        iso = iso2.get(lang) or ISO_NEW.get(lang) or (lang if len(lang) == 3 else lang)
        ablang, otag = iso.upper(), (iso.upper() + " ")[:4]
        if obase:
            ablang, otag = unq(obase["LOCALE_SABBREVLANGNAME"]), unq(obase["LOCALE_SOPENTYPELANGUAGETAG"])
        sig = sig_by_ansi.get(str(c[0])) or sig_by_ansi["1252"]
        bit = SCRIPT_BIT.get(s) or SCRIPT_BIT.get(LANG_SCRIPT_FB.get(lang, ""))
        if c[0] == 0 and bit:
            sig = set_bit(sig, bit)
    if reg in have_region:
        r = have_region[reg]
        geoid, calling, a3 = unq(r["LOCALE_IGEOID"]), unq(r["LOCALE_ICOUNTRY"]), unq(r["LOCALE_SABBREVCTRYNAME"])
        if len(a3) != 3:                  # si-LK carries "LK" from the Wine data: ISO 3166 alpha-3 for the new locale
            a3 = codemap[reg]["_alpha3"]
    else:
        name = GEO_NAME.get(reg) or terr[reg]
        if name not in geo:
            sys.exit("add_locales: no GEO id for %s (%s)" % (reg, name))
        geoid, calling = str(geo[name]), str(REGION_CALLING[reg])
        a3 = codemap[reg]["_alpha3"]
    english = terr.get(reg, reg)
    fx = {"LOCALE_FONTSIGNATURE": sig, "LOCALE_ICOUNTRY": '"%s"' % calling, "LOCALE_IDEFAULTANSICODEPAGE": '"%d"' % cps[0],
          "LOCALE_IDEFAULTCODEPAGE": '"%d"' % cps[1], "LOCALE_IDEFAULTCOUNTRY": '"%s"' % calling,
          "LOCALE_IDEFAULTEBCDICCODEPAGE": '"%s"' % ebc, "LOCALE_IDEFAULTLANGUAGE": '"%04x"' % lcid,
          "LOCALE_IDEFAULTMACCODEPAGE": '"%d"' % cps[2], "LOCALE_IGEOID": '"%s"' % geoid, "LOCALE_ILANGUAGE": '"%04x"' % lcid,
          "LOCALE_SABBREVCTRYNAME": '"%s"' % a3, "LOCALE_SABBREVLANGNAME": '"%s"' % ablang, "LOCALE_SNAME": '"%s"' % tag,
          "LOCALE_SOPENTYPELANGUAGETAG": '"%s"' % otag, "LOCALE_SSORTNAME": '"Default"'}
    sk[fname(tag)] = {"added": True, "fixed": fx, "lcid": lcid, "language": "0x%02x" % (lcid & 0x3ff), "sublang": "0x%02x" % (lcid >> 10),
                      "header": "/*\n * Locale definitions for %s (%s, MS-LCID 0x%04X)\n */\n" % (tag, english, lcid),
                      "lgrp": lgrp, "title": tag}
    added += 1
json.dump(sk, open(SK, "w", encoding="utf-8"), indent=1, ensure_ascii=False, sort_keys=True)
print("added", added, "locales; skeleton now", len(sk))
