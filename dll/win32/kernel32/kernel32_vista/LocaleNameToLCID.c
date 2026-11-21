/*
 * PROJECT:     ReactOS Win32 Base API
 * LICENSE:     MIT (https://spdx.org/licenses/MIT)
 * PURPOSE:     Implementation of LocaleNameToLCID
 * COPYRIGHT:   Copyright 2025 Timo Kreuzer <timo.kreuzer@reactos.org>
 */

#include "k32_vista.h"
#include <ndk/rtlfuncs.h>

#define NDEBUG
#include <debug.h>

/* The specific locale of a neutral locale whose sublanguage is not SUBLANG_NEUTRAL, or 0 if unknown */
LCID
BasepSpecialNeutralLcidToSpecific(
    _In_ LCID Lcid)
{
    switch (Lcid)
    {
        case 0x0742C: return 0x0082C; // "az-Cyrl" -> "az-Cyrl-AZ"
        case 0x0782C: return 0x0042C; // "az-Latn" -> "az-Latn-AZ"
        case 0x07C67: return 0x00867; // "ff-Latn" -> "ff-Latn-SN"
        case 0x0781A: return 0x0141A; // "bs" -> "bs-Latn-BA"
        case 0x0641A: return 0x0201A; // "bs-Cyrl" -> "bs-Cyrl-BA"
        case 0x0681A: return 0x0141A; // "bs-Latn" -> "bs-Latn-BA"
        case 0x07C5C: return 0x0045C; // "chr-Cher" -> "chr-Cher-US"
        case 0x07C2E: return 0x0082E; // "dsb" -> "dsb-DE"
        case 0x07C68: return 0x00468; // "ha-Latn" -> "ha-Latn-NG"
        case 0x0785D: return 0x0045D; // "iu-Cans" -> "iu-Cans-CA"
        case 0x07C5D: return 0x0085D; // "iu-Latn" -> "iu-Latn-CA"
        case 0x07C92: return 0x00492; // "ku-Arab" -> "ku-Arab-IQ"
        case 0x07850: return 0x00450; // "mn-Cyrl" -> "mn-MN"
        case 0x07C50: return 0x00850; // "mn-Mong" -> "mn-Mong-CN"
        case 0x07C14: return 0x00414; // "nb" -> "nb-NO"
        case 0x07814: return 0x00814; // "nn" -> "nn-NO"
        case 0x07C46: return 0x00846; // "pa-Arab" -> "pa-Arab-PK"
        case 0x0703B: return 0x0243B; // "smn" -> "smn-FI"
        case 0x07C59: return 0x00859; // "sd-Arab" -> "sd-Arab-PK"
        case 0x0783B: return 0x01C3B; // "sma" -> "sma-SE"
        case 0x07C3B: return 0x0143B; // "smj" -> "smj-SE"
        case 0x0743B: return 0x0203B; // "sms" -> "sms-FI"
        case 0x06C1A: return 0x0281A; // "sr-Cyrl" -> "sr-Cyrl-RS"
        case 0x0701A: return 0x0241A; // "sr-Latn" -> "sr-Latn-RS"
        case 0x07C28: return 0x00428; // "tg-Cyrl" -> "tg-Cyrl-TJ"
        case 0x07C5F: return 0x0085F; // "tzm-Latn" -> "tzm-Latn-DZ"
        case 0x0785F: return 0x0105F; // "tzm-Tfng" -> "tzm-Tfng-MA"
        case 0x07843: return 0x00843; // "uz-Cyrl" -> "uz-Cyrl-UZ"
        case 0x07C43: return 0x00443; // "uz-Latn" -> "uz-Latn-UZ"
        case 0x07804: return 0x00804; // "zh" -> "zh-CN"
        case 0x07C04: return 0x00C04; // "zh-Hant" -> "zh-HK"
    }

    return 0;
}

LCID
BasepNeutralLcidToSpecific(
    _In_ LCID Lcid)
{
    switch (Lcid)
    {
        /* Neutral locales whose SUBLANG_DEFAULT locale is not the one Windows picks, or does not exist */
        case 0x00004: return 0x00804; // "zh-Hans" -> "zh-CN" (SUBLANG_DEFAULT is zh-TW)
        case 0x0000A: return 0x00C0A; // "es" -> "es-ES" (SUBLANG_DEFAULT is es-ES_tradnl)
        case 0x0003C: return 0x0083C; // "ga" -> "ga-IE"
        case 0x00045: return 0x00845; // "bn" -> "bn-BD"
        case 0x00059: return 0x00859; // "sd" -> "sd-Arab-PK"
        case 0x0005D: return 0x0085D; // "iu" -> "iu-Latn-CA"
        case 0x0005F: return 0x0085F; // "tzm" -> "tzm-Latn-DZ"
        case 0x00067: return 0x00867; // "ff" -> "ff-Latn-SN"
        case 0x00073: return 0x00873; // "ti" -> "ti-ER"
        case 0x07C1A: return 0x0241A; // "sr" -> "sr-Latn-RS"
    }

    if (SUBLANGID(LANGIDFROMLCID(Lcid)) == SUBLANG_NEUTRAL)
        return MAKELCID(MAKELANGID(PRIMARYLANGID(LANGIDFROMLCID(Lcid)), SUBLANG_DEFAULT), SORT_DEFAULT);

    return BasepSpecialNeutralLcidToSpecific(Lcid);
}

PCWSTR
BasepLocaleNameAlias(
    _In_ PCWSTR Name)
{
    static const struct { PCWSTR Alias; PCWSTR Name; } Aliases[] =
    {
        { L"zh-Hans-CN", L"zh-CN" },
        { L"zh-Hans-SG", L"zh-SG" },
        { L"zh-Hant-TW", L"zh-TW" },
        { L"zh-Hant-HK", L"zh-HK" },
        { L"zh-Hant-MO", L"zh-MO" },
    };
    ULONG i;

    for (i = 0; i < RTL_NUMBER_OF(Aliases); i++)
    {
        if (_wcsicmp(Name, Aliases[i].Alias) == 0)
            return Aliases[i].Name;
    }
    return NULL;
}

LCID
WINAPI
LocaleNameToLCID(
    _In_ LPCWSTR lpName,
    _In_ DWORD dwFlags)
{
    NTSTATUS Status;
    PCWSTR Alias;
    LCID Lcid;

    /* Validate flags */
    if (dwFlags & ~LOCALE_ALLOW_NEUTRAL_NAMES)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return 0;
    }

    /* Check for LOCALE_NAME_USER_DEFAULT (NULL) */
    if (lpName == NULL)
    {
        return GetUserDefaultLCID();
    }

    /* Check for LOCALE_NAME_INVARIANT (L"") */
    if (lpName[0] == L'\0')
    {
        return MAKELCID(MAKELANGID(LANG_INVARIANT, SUBLANG_NEUTRAL), SORT_DEFAULT);
    }

    /* Script-tagged names of the Chinese locales are not in the RTL table */
    Alias = BasepLocaleNameAlias(lpName);
    if (Alias)
        lpName = Alias;

    /* Call the RTL function (include neutral names) */
    Status = RtlLocaleNameToLcid(lpName, &Lcid, RTL_LOCALE_ALLOW_NEUTRAL_NAMES);
    if (!NT_SUCCESS(Status))
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return 0;
    }

    /* Are neutral locales allowed? */
    if ((dwFlags & LOCALE_ALLOW_NEUTRAL_NAMES) == 0)
    {
        /* Check if we got a neutral locale */
        LCID SpecificLcid = BasepNeutralLcidToSpecific(Lcid);

        if (SpecificLcid)
            return SpecificLcid;
        if (SUBLANGID(LANGIDFROMLCID(Lcid)) == SUBLANG_NEUTRAL ||
            SUBLANGID(LANGIDFROMLCID(Lcid)) >= 0x18)
        {
            /* Should not happen */
            DPRINT1("Unandled neutral LCID %x\n", Lcid);
            return 0;
        }
    }

    return Lcid;
}

/*
 * Whether CompareStringEx and FindNLSStringEx take a locale name. Windows takes every well-formed tag, not only the names it has a locale
 * for (measured on Windows Server 2022, 6000 names): "en-AT", "en-001", "und", "iw-IL", "en-US-x-foo" and "x-private"
 * are all taken, and compare like the invariant locale when no locale is installed for them. The grammar measured:
 *   - 1 to 84 characters; tokens of 1 to 8 ASCII letters or digits, separated by '-'; an '_' is a '-' in a name that
 *     starts with one letter ("x_foo"), else only once as the last separator behind at least two tokens
 *     ("de-DE_phoneb", "en-US_foo"; "en_US_foo", "de_phoneb" and "de_AB" are refused, "en_US" is a known name);
 *   - the first token is a language of 2 or 3 letters, optionally a script of 4 letters, then a region of 2 letters
 *     or 3 digits, then any tokens; or it is one letter followed by at least one more token ("x-private");
 *   - after the language (and the script) one letter followed by at least one token is an extension ("en-u-co-phonebk",
 *     "en-Latn-x-foo"); anything else there ("en-aaa", "en-Latn-foo", "xx-invalid", "de-1901") is refused.
 * "Invariant", "zh-CHS" and "de_phoneb" are refused by Windows as well.
 */
static BOOL BasepIsLocaleNameWellFormed(LPCWSTR name)
{
    BYTE len[48], alpha[48], digit[48];
    ULONG count = 0, total = 0, i, n, underscores = 0;
    BOOL scripted = FALSE;
    WCHAR last_sep = 0;

    for (;;)
    {
        ULONG tl = 0, a = 0, d = 0;

        while (name[total] && name[total] != '-' && name[total] != '_')
        {
            WCHAR c = name[total];

            if (c >= 'A' && c <= 'Z') c += 'a' - 'A';
            if (c >= 'a' && c <= 'z') a++;
            else if (c >= '0' && c <= '9') d++;
            else return FALSE;
            if (++tl > 8) return FALSE;
            total++;
        }
        if (!tl || count >= RTL_NUMBER_OF(len)) return FALSE;
        len[count] = (BYTE)tl; alpha[count] = (a == tl); digit[count] = (d == tl);
        count++;
        if (!name[total]) break;
        last_sep = name[total];
        if (last_sep == '_') underscores++;
        total++;
    }
    /* the name is at most 84 characters (LOCALE_NAME_MAX_LENGTH is 85 with the terminator) */
    if (total > 84) return FALSE;
    if (len[0] == 1 && alpha[0]) return count > 1;
    /* a sort order after '_' needs a region or more before it ("en-US_foo"); "en_foo" is refused */
    if (underscores && (underscores > 1 || last_sep != '_' || count < 3)) return FALSE;
    if (!alpha[0] || len[0] < 2 || len[0] > 3) return FALSE;

    /* the sort order behind an '_' is no script and no region */
    n = underscores ? count - 1 : count;
    i = 1;
    if (i < n && len[i] == 4 && alpha[i]) { i++; scripted = TRUE; }
    if (i == n) return !underscores;
    if ((len[i] == 2 && alpha[i]) || (len[i] == 3 && digit[i])) return TRUE;
    return len[i] == 1 && alpha[i] && (i == 1 || scripted) && count - i >= 2;
}

/*
 * Names accepted lately. Sorting and searching call CompareStringEx with the same name again and again, and the checks cost
 * several times the comparison of short strings (measured: 25 ns per call before, 110 ns with the checks). Each slot is a
 * seqlock: a reader takes the name only when the counter was even and did not change while it compared.
 */
#define ACCEPTED_SLOTS 4
static volatile LONG g_AcceptedSeq[ACCEPTED_SLOTS];
static WCHAR g_AcceptedName[ACCEPTED_SLOTS][LOCALE_NAME_MAX_LENGTH];

static ULONG
BasepAcceptedSlot(
    _In_ LPCWSTR name)
{
    return ((ULONG)name[0] * 31 + (name[0] ? name[1] : 0) * 7 + (name[0] && name[1] ? name[2] : 0)) % ACCEPTED_SLOTS;
}

static BOOL
BasepIsAcceptedNameCached(
    _In_ LPCWSTR name,
    _In_ ULONG slot)
{
    LONG seq = g_AcceptedSeq[slot];
    ULONG i;

    if (seq & 1)
        return FALSE;
    for (i = 0; i < LOCALE_NAME_MAX_LENGTH; i++)
    {
        WCHAR c = g_AcceptedName[slot][i];

        if (c != name[i])
            return FALSE;
        if (!c)
            break;
    }
    /* the full barrier keeps the reads above before this one */
    return i < LOCALE_NAME_MAX_LENGTH && InterlockedCompareExchange(&g_AcceptedSeq[slot], seq, seq) == seq;
}

static VOID
BasepCacheAcceptedName(
    _In_ LPCWSTR name,
    _In_ ULONG slot)
{
    LONG seq = g_AcceptedSeq[slot];
    ULONG i;

    if ((seq & 1) || InterlockedCompareExchange(&g_AcceptedSeq[slot], seq + 1, seq) != seq)
        return;
    for (i = 0; name[i] && i < LOCALE_NAME_MAX_LENGTH - 1; i++)
        g_AcceptedName[slot][i] = name[i];
    g_AcceptedName[slot][i] = 0;
    if (name[i])
        g_AcceptedName[slot][0] = 0xffff; /* too long to be a name: matches nothing */
    InterlockedIncrement(&g_AcceptedSeq[slot]);
}

BOOL
BasepIsLocaleNameAccepted(
    _In_opt_ LPCWSTR name)
{
    WCHAR buffer[LOCALE_NAME_MAX_LENGTH];
    DWORD error;
    ULONG i, slot;

    /* NULL is the user default locale, "" the invariant locale, and the system default has its own name */
    if (!name || !name[0])
        return TRUE;
    slot = BasepAcceptedSlot(name);
    if (BasepIsAcceptedNameCached(name, slot))
        return TRUE;
    if (_wcsicmp(name, L"!x-sys-default-locale") == 0)
        return TRUE;

    /* A name that is taken leaves the last error alone (the lookups below set it when they find no locale). Every name
       of the locale table but the pseudo-locales is well-formed, so the cheap scan comes first. */
    error = GetLastError();
    if (BasepIsLocaleNameWellFormed(name))
        goto done;
    /* the pseudo-locales and the names a locale has when '_' is read as '-' ("zh_Hant_TW") */
    if (_wcsicmp(name, L"qps-ploca") == 0 || _wcsicmp(name, L"qps-plocm") == 0)
        goto done;
    for (i = 0; name[i] && i < RTL_NUMBER_OF(buffer) - 1; i++)
        buffer[i] = name[i] == L'_' ? L'-' : name[i];
    if (!name[i])
    {
        buffer[i] = 0;
        if (LocaleNameToLCID(buffer, LOCALE_ALLOW_NEUTRAL_NAMES))
            goto done;
    }
    SetLastError(error);
    return FALSE;

done:
    SetLastError(error);
    BasepCacheAcceptedName(name, slot);
    return TRUE;
}
