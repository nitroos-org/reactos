/*
 * PROJECT:     ReactOS
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Service SIDs: the SID of a service, and the services that exist, shared by
 *              the LSA (name and SID lookups) and MSV1_0 (the logon of NT SERVICE\<service>)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Include after the NT and Win32 registry headers. The functions are static inline: each
 * module that includes this file has its own copy and none warns when it uses only some of them.
 */

#pragma once

/*
 * Service SIDs and virtual service accounts ("NT SERVICE\<service>").
 *
 * The SID of a service is S-1-5-80-a-b-c-d-e where a..e are the five little-endian
 * DWORDs of the SHA-1 digest of the upper-case service name in UTF-16LE (no terminator),
 * the same value the SCM puts into the token of a service that has a service SID.
 * The account name resolves for the services that exist: the key of the service
 * under HKLM\SYSTEM\CurrentControlSet\Services is the existence check (the SCM is not
 * called from here, it can hold its database lock while it waits for this server).
 */
#define LSAP_SERVICES_KEY L"SYSTEM\\CurrentControlSet\\Services"
#define LSAP_SERVICE_SID_SUBAUTHS 6

static inline ULONG
LsapRol32(ULONG x, ULONG n)
{
    return (x << n) | (x >> (32 - n));
}

static inline VOID
LsapSha1(const UCHAR *Data, ULONG Length, UCHAR Digest[20])
{
    ULONG h[5] = {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0};
    UCHAR Block[576];
    ULONG Total, Pos, w[80], a, b, c, d, e, f, k, t, i, j;
    ULONGLONG Bits = (ULONGLONG)Length * 8;

    /* the caller passes at most 2 * 256 chars: copy into a padded buffer of whole blocks */
    Total = ((Length + 8) / 64 + 1) * 64;
    if (Total > sizeof(Block))
    {
        RtlZeroMemory(Digest, 20);
        return;
    }
    RtlZeroMemory(Block, sizeof(Block));
    RtlCopyMemory(Block, Data, Length);
    Block[Length] = 0x80;
    for (i = 0; i < 8; i++)
        Block[Total - 1 - i] = (UCHAR)(Bits >> (8 * i));

    for (Pos = 0; Pos < Total; Pos += 64)
    {
        for (i = 0; i < 16; i++)
            w[i] = ((ULONG)Block[Pos + 4 * i] << 24) | ((ULONG)Block[Pos + 4 * i + 1] << 16) |
                   ((ULONG)Block[Pos + 4 * i + 2] << 8) | Block[Pos + 4 * i + 3];
        for (i = 16; i < 80; i++)
            w[i] = LsapRol32(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);

        a = h[0]; b = h[1]; c = h[2]; d = h[3]; e = h[4];
        for (i = 0; i < 80; i++)
        {
            if (i < 20)      { f = (b & c) | (~b & d);          k = 0x5A827999; }
            else if (i < 40) { f = b ^ c ^ d;                   k = 0x6ED9EBA1; }
            else if (i < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8F1BBCDC; }
            else             { f = b ^ c ^ d;                   k = 0xCA62C1D6; }
            t = LsapRol32(a, 5) + f + e + k + w[i];
            e = d; d = c; c = LsapRol32(b, 30); b = a; a = t;
        }
        h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e;
    }

    for (j = 0; j < 5; j++)
        for (i = 0; i < 4; i++)
            Digest[4 * j + i] = (UCHAR)(h[j] >> (24 - 8 * i));
}

/* The five sub-authorities that follow 80 in the SID of the service with this name */
static inline BOOLEAN
LsapServiceNameToSubAuthorities(PCWSTR Name, ULONG Chars, ULONG SubAuthorities[5])
{
    UCHAR Upper[2 * 256];
    UCHAR Digest[20];
    ULONG i;

    if (Chars == 0 || Chars > 256)
        return FALSE;

    for (i = 0; i < Chars; i++)
    {
        WCHAR c = RtlUpcaseUnicodeChar(Name[i]);
        Upper[2 * i] = (UCHAR)(c & 0xFF);
        Upper[2 * i + 1] = (UCHAR)(c >> 8);
    }

    LsapSha1(Upper, Chars * sizeof(WCHAR), Digest);

    for (i = 0; i < 5; i++)
    {
        SubAuthorities[i] = (ULONG)Digest[4 * i] | ((ULONG)Digest[4 * i + 1] << 8) |
                            ((ULONG)Digest[4 * i + 2] << 16) | ((ULONG)Digest[4 * i + 3] << 24);
    }

    return TRUE;
}

static inline BOOLEAN
LsapServiceExists(PCWSTR Name, ULONG Chars)
{
    WCHAR Path[ARRAYSIZE(LSAP_SERVICES_KEY) + 1 + 257];
    HKEY hKey;
    ULONG i;
    LONG Error;

    if (Chars == 0 || Chars > 256)
        return FALSE;

    for (i = 0; i < Chars; i++)
        if (Name[i] == L'\\' || Name[i] == L'/' || Name[i] == UNICODE_NULL)
            return FALSE;

    wcscpy(Path, LSAP_SERVICES_KEY L"\\");
    RtlCopyMemory(Path + ARRAYSIZE(LSAP_SERVICES_KEY), Name, Chars * sizeof(WCHAR));
    Path[ARRAYSIZE(LSAP_SERVICES_KEY) + Chars] = UNICODE_NULL;

    Error = RegOpenKeyExW(HKEY_LOCAL_MACHINE, Path, 0, KEY_QUERY_VALUE, &hKey);
    if (Error != ERROR_SUCCESS)
        return FALSE;

    /* a service has a Type value; a bare key (or one left by a deleted service) has none */
    Error = RegQueryValueExW(hKey, L"Type", NULL, NULL, NULL, NULL);
    RegCloseKey(hKey);
    return (Error == ERROR_SUCCESS);
}

/* The name of the service (as its key is spelled) that has this service SID; 0 if there is none */
static inline ULONG
LsapFindServiceBySid(PSID Sid, PWSTR NameBuffer, ULONG NameChars)
{
    PISID Isid = Sid;
    HKEY hKey;
    ULONG Index, Chars, Sub[5], j;
    LONG Error;

    if (Isid->SubAuthorityCount != LSAP_SERVICE_SID_SUBAUTHS ||
        Isid->SubAuthority[0] != SECURITY_SERVICE_ID_BASE_RID)
        return 0;

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, LSAP_SERVICES_KEY, 0, KEY_ENUMERATE_SUB_KEYS, &hKey) != ERROR_SUCCESS)
        return 0;

    for (Index = 0; ; Index++)
    {
        Chars = NameChars;
        Error = RegEnumKeyExW(hKey, Index, NameBuffer, &Chars, NULL, NULL, NULL, NULL);
        if (Error == ERROR_MORE_DATA)
            continue;
        if (Error != ERROR_SUCCESS)
            break;

        if (!LsapServiceNameToSubAuthorities(NameBuffer, Chars, Sub))
            continue;

        for (j = 0; j < 5; j++)
            if (Sub[j] != Isid->SubAuthority[j + 1])
                break;
        if (j == 5 && LsapServiceExists(NameBuffer, Chars))
        {
            RegCloseKey(hKey);
            return Chars;
        }
    }

    RegCloseKey(hKey);
    return 0;
}

