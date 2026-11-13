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

## Round 4 (2026.11-2, lane cldr3): what else CLDR can give, and what it cannot
Same data rule and same scorer as round 3 (Windows dumps only count matches; no Windows value in this tree). Two rules were added; every other
candidate that was examined has no CLDR source or would regress a field that matches today (list below).

| Rule | What it does | Effect (10 probe locales: 1120 LCTYPE values; 20 .NET culture lines) |
|---|---|---|
| QUOTE-CANON | the quoting of literal text in a LONG date pattern is canonical (`SLONGDATE`, `SRELATIVELONGDATE`, the long date lists of the calendars): a quoted word between two date fields takes the spaces around it into the quotes (CLDR `d 'de' MMMM 'de' y` becomes `d' de 'MMMM' de 'yyyy`), and a quoted word at the end of a pattern takes its trailing punctuation (`y 'г'.` becomes `y 'г.'`). The formatted text is identical (no pattern letter, order or width changes); it keeps a literal phrase in one quoted string, which is how the GetDateFormat custom-format syntax is documented. `SMONTHDAY`, `SYEARMONTH`, the short date and the time patterns keep CLDR's own quoting: a first version of the rule applied to every pattern and the oracle probe showed es-ES `SMONTHDAY` (`d 'de' MMMM`, spaces outside) getting worse while the two long dates improved, so the rule is a measured field selection (long dates), not a global one | LCTYPE differences 146 -> 143 (es-ES `SLONGDATE`, `SRELATIVELONGDATE`, ru-RU `SLONGDATE`), no field worse |
| APOS-TYPO | a number group separator that is the bare ASCII apostrophe (CLDR: de-CH, de-LI, fr-CH, it-CH, gsw, ...) becomes U+2019, the typographic apostrophe (the Unicode Standard's character for the apostrophe in text; U+0027 is the neutral typewriter form; U+2019 is in code pages 1250-1258). Not a CLDR value: a documented typographic mapping of one. Applies to `STHOUSAND` and `SMONTHOUSANDSEP` | de-CH number segments (3 of 5 differing segments of its .NET line) |

Examined and NOT adopted (the reason is the finding; each was checked against the CLDR data of the locale and its parents):
| Candidate | Why not |
|---|---|
| en-GB `AM/PM`, `dd MMMM yyyy` | CLDR en-GB has `am`/`pm` (lower case) in every width and its `alt-variant` forms are the same; its long date is `d MMMM y`. No field carries the value |
| `AM/PM` kept for pl, sk, he, th, de-CH but empty for de, fr, ru, pt, es | CLDR data of de and de-CH is identical (`AM`/`PM`, `HH:mm`); pl, sk, ru differ in nothing the generator reads. Only a per-language list would produce it |
| ru capitalised month names | CLDR `contextTransforms` for ru and es are identical (and also say capitalise the day names, which Windows does not for ru; fr and pl carry the same rule and Windows lowercases them) |
| ar-SA short date `dd/MM/yy`, hi-IN padded/24-hour, es/pl/he padded short dates | CLDR short dates are `d/M/y`; no padded pattern exists in the locales' data |
| ar-SA digits | already Latin separators with national digit substitution (round 3); CLDR's default numbering system for ar-SA is `arab`, the `latn` one is used for the formats |
| `SDURATION` hour width from the time pattern | fixes en-GB, de, fr, ar-SA, breaks zh and ru (their CLDR time pattern is `HH:mm` too): 4 fixed, 2 regressed, rejected again |
| `SSHORTESTDAYNAME` narrow vs short, `SABBREVMONTHNAME` period/no period, `SKEYBOARDSTOINSTALL`, `IREADINGLAYOUT` (ja, zh = 2), `INEGCURR`/`IPOSITIVEPERCENT` of ru, zh, en-US | opposite or no CLDR signal between locales (es keeps the period that ru drops; zh-CN narrow day `一` but en/ru need `short`), or Windows-only (keyboards, vertical layout) |
| `SMONTHDAY` unquoted CJK literals (`M月d日`) | Windows quotes the same literals in the long date, so no consistent rule exists |

Measured note, culture count (148 here, 859 on Windows 10; the .NET test prints `cultures=` and `specific=`): the 146 `.nls` files cover 76 languages. CLDR 49 full has 657
locale ids (a default region is not its own id: `cs`, not `cs-CZ`). Not generated: 222 language-region variants of languages we have, 37 of languages we lack, 79 script
variants (Hans/Hant/Cyrl/Latn...), 28 neutral languages with modern coverage. Reason: a locale needs an identity that CLDR does not carry (LCID, code pages, GEOID, calling code,
Windows abbreviations: `data/skeleton.json`, taken from the Wine-era tables of those 146 files), and the public source for it (MS-LCID, ISO 3166) was not applied in this round. Adding locales is a
data-entry job on `skeleton.json` plus the registry/LCID tables; it is not a mapping-rule change and does not move the .NET culture lines of the 20 test cultures.

## Round 5 (2026.11-2, lane nlsloc): more locales, from the [MS-LCID] Language ID table
The identity of a locale that CLDR does not carry (LCID, LANGUAGE/SUBLANG, default code pages, GEOID, calling code, abbreviations,
OpenType tag, font signature) comes from `add_locales.py`, which appends entries (`"added": true`) to `data/skeleton.json`; `nlsgen.py` then
generates `nls/<tag>.nls` (lower-case tag, e.g. `en-in.nls`) like for the first 146, and the `#include` list `winnls/locale_rc_added.rc`
(`--rc-list`). 85 locales were added (231 generated, 238 `.nls` files with the 7 hand-written ones); the 146 earlier files are byte-identical.

* LCID and name: `data/ms-lcid.tsv` = the Language ID table of [MS-LCID] (revision 2024-04-23, learn.microsoft.com/en-us/openspecs/windows_protocols/ms-lcid/63d3d639-7fd2-4afb-abbe-0d5b5551eef8,
  retrieved 2026-11-12). Rule: an entry with a language-region(-script) tag, a 16-bit LCID, no `reserved`/sort-order marker, for which CLDR has data for
  the language (or the tag itself), and whose LCID/name is not in the skeleton yet. LANGUAGE/SUBLANG are the numeric low 10 / high 6 bits of the LCID.
* GEOID: `data/geo-ids.tsv` (Windows "Table of Geographical Locations", page of 2025-03-11) matched by the CLDR English territory name (five names mapped by hand in `GEO_NAME`);
  the region of an existing locale keeps that locale's GEOID, calling code and ISO 3166 alpha-3 (CLDR `codeMappings` otherwise). Calling codes of the 27 new territories: ITU-T E.164 (`REGION_CALLING`).
* Default code pages (ANSI/OEM/MAC/EBCDIC), abbreviations, OpenType tag: **[MS-LCID] does not list code pages** (it maps LCID to tag only). A new locale of a language that has an entry
  (same script) takes the values of that entry (a region variant has the language's code pages); a new language gets the defaults of its script
  (Latin 1252/850/10000/500, Cyrillic 1251/866/10007/20880, Arabic 1256/720/10004/20420, scripts without an ANSI page 0/1/2/500 as hi-IN, ka-GE, si-LK; `tk`, `fil`, `ii` have their own),
  the ISO 639-2/T code (Library of Congress) in upper case as `SABBREVLANGNAME` and as OpenType tag. These are derived, not measured: see "VERIFY ON ORACLE" in the lane evidence.
* `LOCALE_FONTSIGNATURE`: the signature of an existing locale with the same ANSI code page (language sibling first); for scripts without a sibling the bit of the script in the Unicode subset
  (OpenType OS/2 `ulUnicodeRange`) is added.
* Not added (listed in the evidence): CLDR ids without an [MS-LCID] entry (Windows gives them LOCALE_CUSTOM_UNSPECIFIED 0x1000; the lane brief says to skip them unless Windows is shown to enumerate them by name; 417 ids, e.g. `en-AG`, `fr-GP`,
  `de-BE`); [MS-LCID] entries without CLDR data (`ts-ZA`, `ve-ZA`, `iu-*`, `quz-*`, `kr-Latn-NG`, `gn-PY`, `la-VA`, `arn-CL`, `moh-CA`, `co-FR`, `prs-AF`, `smj-*`, `sma-*`, `sms-FI`);
  `ku-Arab-IQ` (0x0492 is the language id of the hand-written Cornish file `cor.nls`: two resources with one id are ambiguous); regions without an ISO 3166 code (`yi-001`, `fr-029`, `es-419`);
  neutral locales (language or language+script tags: `zh-Hant`, `sr-Cyrl`, ...), which the rtl locale table (`sdk/lib/rtl/locale.c`) already names.
* `ca-ES-valencia`: the CLDR variant `ca-ES-valencia` is the first element of the locale chain.
* i386 images: kernel32 grows by 0x37000 bytes of `SizeOfImage` (0x3ae000 -> 0x3e5000, i386 Debug), about 2.6 KB per locale (string table + `calendar_data.c`); see `sdk/cmake/baseaddress.cmake`.
* The ICU data package (`dll/3rdparty/icu/data/icudtl.dat`) was regenerated after this round with `build-filtered-data.sh`: 335 names (253 + 82; 71 of the 85 new kernel32 locales have an ICU 64.2 locale of the same tag, the other 14 are listed in `dll/3rdparty/icu/README.ReactOS`).
