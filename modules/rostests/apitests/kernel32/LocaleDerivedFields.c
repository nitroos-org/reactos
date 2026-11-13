/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Derived locale fields (default code pages, abbreviations, OpenType tag) of the locales added in round 5
 * COPYRIGHT:   Copyright 2026 Tomas Srnka (tomas.srnka@e2b.dev)
 *
 * The expected values were measured on Windows 10 22H2 (build 19045) with GetLocaleInfoEx. The first five rows
 * (en-US, de-DE, ja-JP, ru-RU, ar-SA) are older locales that were measured with them as a control.
 */

#include "precomp.h"

#include <winnls.h>

#ifndef LOCALE_SOPENTYPELANGUAGETAG
#define LOCALE_SOPENTYPELANGUAGETAG 0x0000007a
#endif

static const struct
{
    PCWSTR Name;
    PCWSTR ILanguage;
    PCWSTR Ansi;
    PCWSTR Oem;
    PCWSTR Mac;
    PCWSTR Ebcdic;
    PCWSTR AbbrevLang;
    PCWSTR AbbrevCtry;
    PCWSTR OpenType;
} Expected[] =
{
    { L"en-US", L"0409", L"1252", L"437", L"10000", L"037", L"ENU", L"USA", L"ENG " },
    { L"de-DE", L"0407", L"1252", L"850", L"10000", L"20273", L"DEU", L"DEU", L"DEU " },
    { L"ja-JP", L"0411", L"932", L"932", L"10001", L"20290", L"JPN", L"JPN", L"JAN " },
    { L"ru-RU", L"0419", L"1251", L"866", L"10007", L"20880", L"RUS", L"RUS", L"RUS " },
    { L"ar-SA", L"0401", L"1256", L"720", L"10004", L"20420", L"ARA", L"SAU", L"ARA " },
    { L"tg-Cyrl-TJ", L"0428", L"1251", L"866", L"10007", L"20880", L"TAJ", L"TJK", L"TAJ " },
    { L"hsb-DE", L"042e", L"1252", L"850", L"10000", L"870", L"HSB", L"DEU", L"USB " },
    { L"st-ZA", L"0430", L"0", L"1", L"2", L"500", L"SOT", L"ZAF", L"SOT " },
    { L"tn-ZA", L"0432", L"1252", L"850", L"10000", L"500", L"TSN", L"ZAF", L"TNA " },
    { L"xh-ZA", L"0434", L"1252", L"850", L"10000", L"500", L"XHO", L"ZAF", L"XHS " },
    { L"zu-ZA", L"0435", L"1252", L"850", L"10000", L"500", L"ZUL", L"ZAF", L"ZUL " },
    { L"mt-MT", L"043a", L"0", L"1", L"2", L"500", L"MLT", L"MLT", L"MTS " },
    { L"se-NO", L"043b", L"1252", L"850", L"10000", L"20277", L"SME", L"NOR", L"NSM " },
    { L"tk-TM", L"0442", L"1250", L"852", L"10029", L"20880", L"TUK", L"TKM", L"TKM " },
    { L"or-IN", L"0448", L"0", L"1", L"2", L"500", L"ORI", L"IND", L"ORI " },
    { L"ml-IN", L"044c", L"0", L"1", L"2", L"500", L"MYM", L"IND", L"MLR " },
    { L"as-IN", L"044d", L"0", L"1", L"2", L"500", L"ASM", L"IND", L"ASM " },
    { L"bo-CN", L"0451", L"0", L"1", L"2", L"500", L"BOB", L"CHN", L"TIB " },
    { L"km-KH", L"0453", L"0", L"1", L"2", L"500", L"KHM", L"KHM", L"KHM " },
    { L"lo-LA", L"0454", L"0", L"1", L"2", L"500", L"LAO", L"LAO", L"LAO " },
    { L"my-MM", L"0455", L"0", L"1", L"2", L"500", L"MYA", L"MMR", L"BRM " },
    { L"chr-Cher-US", L"045c", L"0", L"1", L"2", L"500", L"CRE", L"USA", L"CHR " },
    { L"am-ET", L"045e", L"0", L"1", L"2", L"500", L"AMH", L"ETH", L"AMH " },
    { L"tzm-Arab-MA", L"045f", L"1256", L"720", L"10004", L"20420", L"ZZZ", L"MAR", L"ARA " },
    { L"fy-NL", L"0462", L"1252", L"850", L"10000", L"500", L"FYN", L"NLD", L"FRI " },
    { L"ps-AF", L"0463", L"0", L"1", L"2", L"500", L"PAS", L"AFG", L"PAS " },
    { L"fil-PH", L"0464", L"1252", L"437", L"10000", L"500", L"FPO", L"PHL", L"PIL " },
    { L"ff-Latn-NG", L"0467", L"1252", L"850", L"10000", L"20297", L"ZZZ", L"NGA", L"FUL " },
    { L"ha-Latn-NG", L"0468", L"1252", L"437", L"10000", L"037", L"HAU", L"NGA", L"HAU " },
    { L"yo-NG", L"046a", L"1252", L"437", L"10000", L"037", L"YOR", L"NGA", L"YBA " },
    { L"nso-ZA", L"046c", L"1252", L"850", L"10000", L"500", L"NSO", L"ZAF", L"SOT " },
    { L"ba-RU", L"046d", L"1251", L"866", L"10007", L"20880", L"BAS", L"RUS", L"BSH " },
    { L"lb-LU", L"046e", L"1252", L"850", L"10000", L"20297", L"LBX", L"LUX", L"LTZ " },
    { L"kl-GL", L"046f", L"1252", L"850", L"10000", L"20277", L"KAL", L"GRL", L"GRN " },
    { L"ig-NG", L"0470", L"1252", L"437", L"10000", L"037", L"IBO", L"NGA", L"IBO " },
    { L"om-ET", L"0472", L"0", L"1", L"2", L"500", L"ORM", L"ETH", L"ORO " },
    { L"ti-ET", L"0473", L"0", L"1", L"2", L"500", L"TIE", L"ETH", L"TGY " },
    { L"haw-US", L"0475", L"1252", L"437", L"10000", L"037", L"HAW", L"USA", L"HAW " },
    { L"so-SO", L"0477", L"0", L"1", L"2", L"500", L"SOM", L"SOM", L"SML " },
    { L"ii-CN", L"0478", L"0", L"1", L"2", L"500", L"III", L"CHN", L"YIM " },
    { L"ug-CN", L"0480", L"1256", L"720", L"10004", L"20420", L"UIG", L"CHN", L"UYG " },
    { L"mi-NZ", L"0481", L"0", L"1", L"2", L"500", L"MRI", L"NZL", L"MRI " },
    { L"oc-FR", L"0482", L"1252", L"850", L"10000", L"20297", L"OCI", L"FRA", L"OCI " },
    { L"gsw-FR", L"0484", L"1252", L"850", L"10000", L"20297", L"GSW", L"FRA", L"ALS " },
    { L"sah-RU", L"0485", L"1251", L"866", L"10007", L"20880", L"SAH", L"RUS", L"YAK " },
    { L"rw-RW", L"0487", L"1252", L"437", L"10000", L"037", L"KIN", L"RWA", L"RUA " },
    { L"wo-SN", L"0488", L"1252", L"850", L"10000", L"20297", L"WOL", L"SEN", L"WLF " },
    { L"ca-ES-valencia", L"0803", L"1252", L"850", L"10000", L"500", L"VAL", L"ESP", L"CAT " },
    { L"ro-MD", L"0818", L"1250", L"852", L"2", L"500", L"ROD", L"MDA", L"ROM " },
    { L"ru-MD", L"0819", L"1251", L"866", L"2", L"500", L"RUM", L"MDA", L"RUS " },
    { L"ur-IN", L"0820", L"1256", L"720", L"2", L"500", L"URI", L"IND", L"URD " },
    { L"dsb-DE", L"082e", L"1252", L"850", L"10000", L"870", L"DSB", L"DEU", L"LSB " },
    { L"tn-BW", L"0832", L"1252", L"850", L"10000", L"500", L"TSB", L"BWA", L"TNA " },
    { L"se-SE", L"083b", L"1252", L"850", L"10000", L"20278", L"SMF", L"SWE", L"NSM " },
    { L"bn-BD", L"0845", L"0", L"1", L"2", L"500", L"BNB", L"BGD", L"BEN " },
    { L"pa-Arab-PK", L"0846", L"1256", L"720", L"10004", L"20420", L"PAP", L"PAK", L"PAN " },
    { L"ta-LK", L"0849", L"0", L"1", L"2", L"500", L"TAM", L"LKA", L"TAM " },
    { L"sd-Arab-PK", L"0859", L"1256", L"720", L"10004", L"20420", L"SIP", L"PAK", L"SND " },
    { L"tzm-Latn-DZ", L"085f", L"1252", L"850", L"10000", L"20297", L"TZA", L"DZA", L"TZM " },
    { L"ks-Deva-IN", L"0860", L"0", L"1", L"2", L"500", L"ZZZ", L"IND", L"KSH " },
    { L"ne-IN", L"0861", L"0", L"1", L"2", L"500", L"NEI", L"IND", L"NEP " },
    { L"ff-Latn-SN", L"0867", L"1252", L"850", L"10000", L"20297", L"FUL", L"SEN", L"FUL " },
    { L"ti-ER", L"0873", L"0", L"1", L"2", L"500", L"TIR", L"ERI", L"TGY " },
    { L"se-FI", L"0c3b", L"1252", L"850", L"10000", L"20278", L"SMG", L"FIN", L"NSM " },
    { L"mn-Mong-MN", L"0c50", L"0", L"1", L"2", L"500", L"MNM", L"MNG", L"MNG " },
    { L"dz-BT", L"0c51", L"0", L"1", L"2", L"500", L"ZZZ", L"BTN", L"DZN " },
    { L"hr-BA", L"101a", L"1250", L"852", L"10082", L"870", L"HRB", L"BIH", L"HRV " },
    { L"tzm-Tfng-MA", L"105f", L"0", L"1", L"2", L"500", L"TZM", L"MAR", L"TZM " },
    { L"bs-Latn-BA", L"141a", L"1250", L"852", L"10082", L"870", L"BSB", L"BIH", L"BOS " },
    { L"sr-Latn-BA", L"181a", L"1250", L"852", L"10082", L"870", L"SRS", L"BIH", L"SRB " },
    { L"sr-Cyrl-BA", L"1c1a", L"1251", L"855", L"10007", L"21025", L"SRN", L"BIH", L"SRB " },
    { L"fr-RE", L"200c", L"1252", L"850", L"10000", L"20297", L"FRR", L"REU", L"FRA " },
    { L"bs-Cyrl-BA", L"201a", L"1251", L"855", L"10082", L"870", L"BSC", L"BIH", L"BOS " },
    { L"fr-CD", L"240c", L"1252", L"850", L"10000", L"20297", L"FRD", L"COD", L"FRA " },
    { L"smn-FI", L"243b", L"1252", L"850", L"10000", L"20278", L"SMN", L"FIN", L"ISM " },
    { L"fr-SN", L"280c", L"1252", L"850", L"10000", L"20297", L"FRN", L"SEN", L"FRA " },
    { L"fr-CM", L"2c0c", L"1252", L"850", L"10000", L"20297", L"FRE", L"CMR", L"FRA " },
    { L"sr-Latn-ME", L"2c1a", L"1250", L"852", L"10029", L"500", L"SRP", L"MNE", L"SRB " },
    { L"fr-CI", L"300c", L"1252", L"850", L"10000", L"20297", L"FRI", L"CIV", L"FRA " },
    { L"sr-Cyrl-ME", L"301a", L"1251", L"855", L"10007", L"21025", L"SRQ", L"MNE", L"SRB " },
    { L"fr-ML", L"340c", L"1252", L"850", L"10000", L"20297", L"FRF", L"MLI", L"FRA " },
    { L"fr-MA", L"380c", L"1252", L"850", L"10000", L"20297", L"FRO", L"MAR", L"FRA " },
    { L"en-HK", L"3c09", L"1252", L"850", L"10000", L"500", L"ENH", L"HKG", L"ENG " },
    { L"fr-HT", L"3c0c", L"1252", L"850", L"10000", L"20297", L"FRH", L"HTI", L"FRA " },
    { L"en-IN", L"4009", L"1252", L"437", L"10000", L"037", L"ENN", L"IND", L"ENG " },
    { L"en-MY", L"4409", L"1252", L"437", L"10000", L"037", L"ENM", L"MYS", L"ENG " },
    { L"en-SG", L"4809", L"1252", L"437", L"10000", L"037", L"ENE", L"SGP", L"ENG " },
    { L"en-AE", L"4c09", L"0", L"1", L"2", L"500", L"ZZZ", L"ARE", L"ENG " },
    { L"es-US", L"540a", L"1252", L"850", L"10000", L"20284", L"EST", L"USA", L"ESP " },
    { L"es-CU", L"5c0a", L"1252", L"850", L"10000", L"20284", L"ESK", L"CUB", L"ESP " },
};

static
void
ExpectInfo(
    _In_ PCWSTR Name,
    _In_ LCTYPE Type,
    _In_ PCSTR Field,
    _In_ PCWSTR Value)
{
    WCHAR Buffer[64];
    int Ret;

    RtlFillMemory(Buffer, sizeof(Buffer), 0xcc);
    SetLastError(0xdeadbeef);
    Ret = GetLocaleInfoEx(Name, Type, Buffer, ARRAYSIZE(Buffer));
    ok(Ret == (int)wcslen(Value) + 1, "%ls %s: returned %d, expected %d (error %lu)\n",
       Name, Field, Ret, (int)wcslen(Value) + 1, GetLastError());
    if (Ret > 0)
        ok(!wcscmp(Buffer, Value), "%ls %s: got '%ls', expected '%ls'\n", Name, Field, Buffer, Value);
}

START_TEST(LocaleDerivedFields)
{
    ULONG i;

    for (i = 0; i < ARRAYSIZE(Expected); i++)
    {
        PCWSTR Name = Expected[i].Name;

        ExpectInfo(Name, LOCALE_SNAME, "SNAME", Name);
        ExpectInfo(Name, LOCALE_ILANGUAGE, "ILANGUAGE", Expected[i].ILanguage);
        ExpectInfo(Name, LOCALE_IDEFAULTANSICODEPAGE, "IDEFAULTANSICODEPAGE", Expected[i].Ansi);
        ExpectInfo(Name, LOCALE_IDEFAULTCODEPAGE, "IDEFAULTCODEPAGE", Expected[i].Oem);
        ExpectInfo(Name, LOCALE_IDEFAULTMACCODEPAGE, "IDEFAULTMACCODEPAGE", Expected[i].Mac);
        ExpectInfo(Name, LOCALE_IDEFAULTEBCDICCODEPAGE, "IDEFAULTEBCDICCODEPAGE", Expected[i].Ebcdic);
        ExpectInfo(Name, LOCALE_SABBREVLANGNAME, "SABBREVLANGNAME", Expected[i].AbbrevLang);
        ExpectInfo(Name, LOCALE_SABBREVCTRYNAME, "SABBREVCTRYNAME", Expected[i].AbbrevCtry);
        ExpectInfo(Name, LOCALE_SOPENTYPELANGUAGETAG, "SOPENTYPELANGUAGETAG", Expected[i].OpenType);
    }
}
