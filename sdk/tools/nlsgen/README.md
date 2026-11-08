# nlsgen: the locale tables from Unicode CLDR

`nlsgen.py` generates the locale data of kernel32 from ONE pinned Unicode CLDR release. Nothing in the output is read from
a Windows system.

    python3 sdk/tools/nlsgen/nlsgen.py --cache /var/tmp/cldr \
        --nls-dir dll/win32/kernel32/winnls/nls \
        --calendar-c dll/win32/kernel32/winnls/string/calendar_data.c

* Source: `cldr-49.0.0-json-full.zip` (https://github.com/unicode-org/cldr-json/releases/tag/49.0.0),
  sha256 `3b1f5d684d29c541d3acf91fe834b3fe36ae0f34775e3ee50e93558bf14ca174`. URL and hash are constants of the script; it
  downloads into `--cache` (or takes `--cldr-zip FILE`) and refuses a file with another hash. Standard library only.
* Deterministic: the same CLDR zip and the same `data/skeleton.json` give the same bytes (`make check`-style: run twice,
  `sha256sum` the output). The generated files name the CLDR version in a comment.
* Output: the 146 `nls/*.nls` locale resource files that held Windows 10 values, and `string/calendar_data.c` (calendar
  names, eras, month names, date and time format lists, the calendars of each locale). Seven hand-written files that never held
  Windows data (`ast`, `cor`, `eoa`, `eox`, `gdv`, `ivl`, `wal`) are untouched.
* Licence: CLDR data is Unicode License v3 (`media/doc/3rd Party Files.txt`).

## What comes from where

CLDR (resolved through the locale's parents, `parentLocales`, then root; region data through the locale's territory):
language, script, territory and currency names, month and day names (stand-alone and format forms: the second form of a
month name after a NUL is the genitive), date and time patterns, AM/PM, number symbols and patterns, currency symbol, code and
fraction digits, first day of the week, minimum days of the first week, measurement system, paper size, reading direction,
the calendars of a territory, calendar names, eras, numbering system and digits, parent locale, script, duration pattern.

`data/skeleton.json` (written by `extract_skeleton.py`, a one-off provenance tool): the Wine-era identity of a locale that CLDR
does not carry: LANGUAGE/SUBLANG, the LCID name, default ANSI/OEM/MAC/EBCDIC code pages, GEOID, calling code, Windows
three-letter abbreviations (`SABBREVLANGNAME`, `SABBREVCTRYNAME`), OpenType language tag, sort name, font signature and the
localized language-group names. They are read from the locale files as they were BEFORE any Windows measurement (the parent of
afb57812d6b, the Wine 6.7 sync). The LCID is recomputed from the LANGUAGE/SUBLANG macros of the tree, the calling codes of
seven locales and the Welsh ANSI code page are corrected from public facts (ITU-T E.164, MS-LCID); see `extract_skeleton.py`.
`data/iso639-2.json`: the ISO 639-2/T three-letter language codes (ISO 639-2, Library of Congress).

## Fields CLDR lacks: documented defaults and derivations

| Field | Rule |
|---|---|
| `LOCALE_IDIGITS` | 2 (CLDR gives a maximum of fraction digits, not the control-panel default) |
| `LOCALE_ILZERO`, `LOCALE_SPOSITIVESIGN` | 1, empty |
| `LOCALE_INEGNUMBER`, `INEGCURR`, `ICURRENCY`, `IPOSITIVEPERCENT`, `INEGATIVEPERCENT`, `IPOSSEPBYSPACE`... | classified from the CLDR standard number, currency and percent patterns (the negative form of a pattern without a second part is the minus sign in front); a pattern that matches none of the Windows layouts gives the default 1 |
| `LOCALE_IPOSSIGNPOSN` | 1 |
| `LOCALE_SKEYBOARDSTOINSTALL` | `LCID:0000LCID` (Windows keyboard layouts are not CLDR data) |
| `LOCALE_SCONSOLEFALLBACKNAME` | the locale itself for Latin, Cyrillic and Greek locales (the console fonts have those glyphs), else `en-US` |
| `LOCALE_SSORTLOCALE`, `LOCALE_IDEFAULTLANGUAGE` | the locale name, the LCID |
| `LOCALE_SPARENT` | the language, with the script for languages that have several (zh, sr, uz, az, ...) |
| `LOCALE_SSCRIPTS` | the likely script; the composite codes (Jpan, Hans, Hant, Kore) are listed with the scripts they combine (ISO 15924) |
| `LOCALE_IDIGITSUBSTITUTION` | 1 (none) for Latin digits, 2 (national) when CLDR's default numbering system is not Latin |
| `LOCALE_SSHORTESTDAYNAME1-7` | the CLDR stand-alone `short` day names, without a trailing abbreviation period; the `narrow` ones where `short` is longer than 3 characters |
| `LOCALE_SRELATIVELONGDATE` | CLDR `MMMMEd` with the long weekday |
| `LOCALE_SSHORTDATE` | the CLDR short date with a four-digit year (CLDR's two-digit year is ambiguous) |
| patterns, names | a narrow no-break space (U+202F) in a CLDR date or time pattern becomes a space, in any other value a no-break space (U+00A0); the `-alt-ascii` CLDR time formats are not used (in en-GB that variant is a 12-hour format) |
| `LOCALE_SLANGUAGE`, `SLOCALIZEDLANGUAGENAME`, `SENGLISHDISPLAYNAME` | English names (the only UI language) |
| calendars | Windows calendar ids for the CLDR calendars: gregorian 1, japanese 3, roc 4, islamic 6, buddhist 7, hebrew 8, persian 22, islamic-umalqura 23. The Windows-only variants (2 and 9-12: localized/transliterated Gregorian) and the lunisolar ones CLDR calls `chinese`/`dangi` are not generated |
| `dv-MV` | CLDR has no Divehi data: the English names with the territory data of the Maldives |
| invariant, Esperanto, Asturian, Cornish, Manx, Walloon files | not generated (hand-written, never held Windows data) |

## icudtl.dat

`dll/3rdparty/icu/data/icudtl.dat` is not generated from this CLDR: it is the ICU 64.2 data package (CLDR 35.1 inside),
filtered by `dll/3rdparty/icu/data/build-filtered-data.sh` from the upstream ICU 64.2 source and data zip (sha256 of the
tarball in the script) for the locale names in `nls-locales.txt`. That list is the set of locales kernel32's tables know, so it
does not change with the CLDR regeneration. See `dll/3rdparty/icu/README.ReactOS`, "Data file".
