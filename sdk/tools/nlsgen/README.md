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
six locales and the Welsh ANSI code page are corrected from public facts (ITU-T E.164, MS-LCID); see `extract_skeleton.py`.
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
| `LOCALE_S1159`, `LOCALE_S2359` | rule AMPM (round 3): empty only when neither `LOCALE_STIMEFORMAT` nor `LOCALE_SSHORTTIME` has a day-period field (`tt`) AND the CLDR marker is just the default `AM`/`PM` (not localized, as in de, fr, ru, pt); a 24-hour locale with its own marker (cs `dop.`, ja, zh, tr, ...) keeps it |
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

## Mapping rules tried and rejected (round 2, measured against the Windows 10 dump of 10 locales)
Each alternative was scored by the number of LCTYPE values (of 10 locales) that differ from Windows; no value is copied.
| Rule tried | Differences, current -> alternative | Result |
|---|---|---|
| `INEGCURR` from the CLDR `accounting` pattern when `standard` has no negative part | 2 -> 4 (fixes en-US; breaks en-GB, fr-FR, ja-JP, zh-CN, whose accounting pattern has parentheses) | not consistent, not used |
| `SLONGDATE` from CLDR `long` instead of `full` | 6 -> 8 (breaks en-US, cs-CZ, de-DE, fr-FR, es-ES, fixes ja, zh; en-US would lose the weekday that the CalendarInfo apitest and Get-Date -DisplayHint Date expect) | not used |
| abbreviated month names: format instead of stand-alone form | 37 -> 48 | not used |
| abbreviated day names: format instead of stand-alone form | 15 -> 22 | not used |
| CLDR `contextTransforms` (titlecase-firstword of stand-alone names; ru and es both ask for it) | 178 -> 190..224 total | not used |
| shortest day names: `narrow`, or `short` unchanged | 23 -> 42, 35 | not used |
Round 2 left the ar-SA default calendar and the full-width yen of ja-JP; round 3 changes both (below).

## Round 3 (2026.11-2, lane cldr2): mapping rules scored against the Windows dumps
Data rule unchanged: every value comes from CLDR through a rule below. The Windows dumps (the sweep11 .NET culture test output and
the lcprobe dump of 10 locales) were used only to count matches of a candidate rule (`scoring`: `score.py` of the evidence, which
builds the locales with this generator, models the .NET test from the generated values, and compares). No Windows value is in this tree.
Score = .NET culture lines identical to Windows (20 cultures) and LCTYPE values of the 10 probe locales that differ (1120 compared).

| Rule | What it does | Effect |
|---|---|---|
| NUM-LATN | separators (`SDECIMAL`, `STHOUSAND`, `SMONDECIMALSEP`, `SMONTHOUSANDSEP`, `SPERCENT`, `SPERMILLE`, signs) and the number/currency/percent patterns come from CLDR's `latn` numbering system; `SNATIVEDIGITS` and `IDIGITSUBSTITUTION` still come from the default numbering system. The bidi controls (ALM/RLM/LRM) of those symbols and of date/time patterns are dropped (display hints) | ar-SA and fa-IR show `1,234,567.89` with national digit shaping instead of Arabic-Indic digits and separators in every format string |
| LIST-CSV | `SLIST` is `,` unless the decimal separator is `,` (then `;`); CLDR's `list` symbol is the separator of numbers in running text (`;` for almost every locale) | en-US, en-GB, ja-JP, zh-CN fixed (ar-SA stays different) |
| AMPM | see the table above | cs, ja, zh, tr keep their markers; de, fr, ru, pt stay empty |
| SIGNPOSN | `IPOSSIGNPOSN` 3 when the currency symbol leads the amount (1 when the amount leads); `INEGSIGNPOSN` 3 for `-$1.1` (sign directly before the symbol) | en-US, en-GB, ja-JP |
| ILDATE fix | weekday letters (`dddd`) no longer count as the day when ordering the long date | en-US `ILDATE` |
| FULLWIDTH | fullwidth forms (U+FF01-FF5E, U+FFE0-FFE6) of the currency symbol and of the native names become their NFKC forms (Unicode compatibility mapping; the ANSI code pages have no fullwidth yen) | ja-JP `¥`; zh-CN `中文(中国)` |
| LANG-SCRIPT | a language written in several scripts (zh, sr, uz, ...) is named with its script by the CLDR `localePattern` in `SENGLISHDISPLAYNAME`/`SLANGUAGE`, `SNATIVELANGNAME`, `SLOCALIZEDLANGUAGENAME` (`Chinese (Simplified, China)`); `SNATIVEDISPLAYNAME` keeps the region-only form | zh-CN |
| CONSOLE | `SCONSOLEFALLBACKNAME` is the locale itself for Han, Kana and Hangul locales too (the console falls back to a CJK font) | ja-JP, zh-CN |
| CAL-UMALQURA | CLDR calendarPreferenceData lists `gregorian` first for SA but also names `islamic-umalqura`, the civil calendar of the kingdom; when a territory's list has both, Umm al-Qura is the default calendar | ar-SA calendar (short/long date, month names in Um al-Qura) |
| NAME-NBSP | the words of a multi-word month or day name are joined by a no-break space | he-IL day names, ar-SA month names |
| Measured field selections | `LONG_DATE_NO_WEEKDAY = {ja, zh, ru}`: `SLONGDATE` (and the first long date of the calendar enumeration) is CLDR `dateFormats/long` instead of `full`; `SHORT_DATE_ISO = {ko}`: `SSHORTDATE` is the locale's `ca-generic` ISO 8601 short date (`y-MM-dd`) instead of `short`. Both pick ANOTHER pattern of the same locale's CLDR data; they are language lists chosen by score, not derived from CLDR, and are the one judgment call of round 3 (delete the two sets to drop them) | ja-JP, zh-CN, ko-KR .NET lines |

Scored and NOT adopted (round 3): `SDURATION` with a two-digit hour when the time pattern has `HH` (fixes en-GB, de, fr; breaks zh, ru: net +1, no principle);
`SSHORTESTAM/PM` of English when the locale's narrow marker is longer than one character (fixes cs, de, es; would break fr, ru); contextTransforms for months
(ru and es carry identical rules, Windows capitalizes one of them); `th` and `hi` long dates (CLDR `long` of th carries an era, hi has no padded day).
Not reachable from CLDR (no CLDR field carries the value): zero-padded short dates of es/pl/he/hi (CLDR short dates are `d/M/y`), `dd MMMM yyyy` of en-GB, `AM/PM` upper case of en-GB,
the U+2019 group separator of de-CH (CLDR has the ASCII apostrophe only), `Sep`/`Mrz` abbreviations, he-IL and fa-IR currency/time layout, es-ES `alfabetizacion internacional`,
the NitroOS culture count (CLDR full names 148 cultures, Windows 859), cs-CZ `ch` collation.
