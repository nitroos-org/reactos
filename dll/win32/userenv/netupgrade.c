/*
 * PROJECT:     ReactOS system libraries
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     The IPv6 transport and Winsock catalog entries on an install that predates them
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * A new install gets the Tcpip6 transport (Services\Tcpip6\Parameters\WinSock, its name in
 * Winsock\Parameters\Transports) and the AF_INET6 entries of the Winsock protocol catalog from nettcpip.inf.
 * An install made before they were added has neither, so IPv6 sockets could not be made on it with the stack's
 * switch (Tcpip\Parameters\Ipv6Enable) on.
 *
 * Winlogon calls UpgradeNetworkCatalog at every start, in the SYSTEM context. It does nothing while the switch is
 * off (nothing is read from the INF, nothing is written), and nothing once it has settled the INF that is on the
 * disk: the size and last write time of nettcpip.inf are kept in the registry (Winsock2\Parameters\Ipv6CatalogInf)
 * when the catalog holds every entry of the INF section TCPIP_AddReg_Ipv6.NT or was left alone on purpose. So the
 * one-shot is per version of the INF: a later INF with more entries is looked at once.
 *
 * What the section holds is read from the INF itself (table-driven): the provider id, address family and
 * protocol inside each PackedCatalogItem it defines are looked for in the catalog, by entry key (the six MSAFD
 * entries share one provider id, so the family and protocol tell them apart). When an entry is missing
 * and no entry the INF defines holds something else, and the catalog's next id does not exceed the INF's
 * (no provider that is not ours was added since), the section MS_TCPIP.Ipv6Upgrade (the same AddReg lines a
 * new install runs; idempotent) is installed and the catalog serial number is raised, which makes the
 * processes that cached the catalog read it again. Setupapi is loaded only then, and only here.
 */

#include "precomp.h"

#include <setupapi.h>

#define NDEBUG
#include <debug.h>

#define NU_SERVICES_KEY     L"SYSTEM\\CurrentControlSet\\Services"
#define NU_TCPIP_KEY        NU_SERVICES_KEY L"\\Tcpip\\Parameters"
#define NU_WINSOCK2_KEY     NU_SERVICES_KEY L"\\Winsock2\\Parameters"
#define NU_CATALOG_KEY      NU_WINSOCK2_KEY L"\\Protocol_Catalog9"
#define NU_ENTRIES_KEY      NU_CATALOG_KEY L"\\Catalog_Entries"
#define NU_STAMP_VALUE      L"Ipv6CatalogInf"
#define NU_INF_NAME         L"\\inf\\nettcpip.inf"
#define NU_ADDREG_SECTION   L"TCPIP_AddReg_Ipv6.NT"
#define NU_INSTALL_SECTION  L"MS_TCPIP.Ipv6Upgrade"
#define NU_ENTRY_MARK       L"\\Catalog_Entries\\"

/* A PackedCatalogItem is the library path (CHAR[MAX_PATH]) and a WSAPROTOCOL_INFOW, whose provider id is
   after four service flags and the provider flags; the address family follows the provider id, the catalog
   entry id, the protocol chain (a count and seven ids) and the version; the protocol is three ints after that */
#define NU_PACKED_PATH_SIZE     MAX_PATH
#define NU_PROVIDER_ID_OFFSET   (NU_PACKED_PATH_SIZE + 5 * sizeof(DWORD))
#define NU_FAMILY_OFFSET        (NU_PROVIDER_ID_OFFSET + sizeof(GUID) + sizeof(DWORD) + 8 * sizeof(DWORD) + sizeof(INT))
#define NU_PROTOCOL_OFFSET      (NU_FAMILY_OFFSET + 4 * sizeof(INT))
#define NU_PACKED_MIN_SIZE      (NU_PROTOCOL_OFFSET + sizeof(INT))
#define NU_PACKED_MAX_SIZE      1024
#define NU_MAX_ENTRIES          32

typedef struct _NU_ENTRY
{
    WCHAR Name[16];     /* key name under Catalog_Entries (000000000004) */
    GUID Provider;
    INT Family;         /* iAddressFamily and iProtocol: all six MSAFD entries share the provider id */
    INT Protocol;
} NU_ENTRY;

typedef struct _NU_STAMP
{
    DWORD Size;
    FILETIME Written;
} NU_STAMP;

typedef HINF (WINAPI *PFN_OPENINF)(PCWSTR, PCWSTR, DWORD, PUINT);
typedef VOID (WINAPI *PFN_CLOSEINF)(HINF);
typedef BOOL (WINAPI *PFN_FINDFIRST)(HINF, PCWSTR, PCWSTR, PINFCONTEXT);
typedef BOOL (WINAPI *PFN_FINDNEXT)(PINFCONTEXT, PINFCONTEXT);
typedef BOOL (WINAPI *PFN_GETSTRING)(PINFCONTEXT, DWORD, PWSTR, DWORD, PDWORD);
typedef BOOL (WINAPI *PFN_GETINT)(PINFCONTEXT, DWORD, PINT);
typedef BOOL (WINAPI *PFN_GETBINARY)(PINFCONTEXT, DWORD, PBYTE, DWORD, PDWORD);
typedef BOOL (WINAPI *PFN_INSTALL)(HWND, HINF, PCWSTR, UINT, HKEY, PCWSTR, UINT, PVOID, PVOID, HDEVINFO, PSP_DEVINFO_DATA);

static
BOOL
NuSwitchOn(VOID)
{
    HKEY hKey;
    DWORD Value = 0, Size = sizeof(Value), Type;
    BOOL On = FALSE;

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, NU_TCPIP_KEY, 0, KEY_QUERY_VALUE, &hKey) != ERROR_SUCCESS)
        return FALSE;
    if (RegQueryValueExW(hKey, L"Ipv6Enable", NULL, &Type, (LPBYTE)&Value, &Size) == ERROR_SUCCESS &&
        Type == REG_DWORD)
        On = (Value != 0);
    RegCloseKey(hKey);
    return On;
}

static
BOOL
NuQueryStamp(PCWSTR pszInf, NU_STAMP *Stamp)
{
    WIN32_FILE_ATTRIBUTE_DATA Data;

    if (!GetFileAttributesExW(pszInf, GetFileExInfoStandard, &Data))
        return FALSE;
    Stamp->Size = Data.nFileSizeLow;
    Stamp->Written = Data.ftLastWriteTime;
    return TRUE;
}

static
BOOL
NuStampIsCurrent(const NU_STAMP *Stamp)
{
    HKEY hKey;
    NU_STAMP Kept;
    DWORD Size = sizeof(Kept), Type;
    BOOL Same = FALSE;

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, NU_WINSOCK2_KEY, 0, KEY_QUERY_VALUE, &hKey) != ERROR_SUCCESS)
        return FALSE;
    if (RegQueryValueExW(hKey, NU_STAMP_VALUE, NULL, &Type, (LPBYTE)&Kept, &Size) == ERROR_SUCCESS &&
        Type == REG_BINARY && Size == sizeof(Kept))
        Same = (RtlCompareMemory(&Kept, Stamp, sizeof(Kept)) == sizeof(Kept));
    RegCloseKey(hKey);
    return Same;
}

static
VOID
NuWriteStamp(const NU_STAMP *Stamp)
{
    HKEY hKey;

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, NU_WINSOCK2_KEY, 0, KEY_SET_VALUE, &hKey) != ERROR_SUCCESS)
        return;
    RegSetValueExW(hKey, NU_STAMP_VALUE, 0, REG_BINARY, (const BYTE *)Stamp, sizeof(*Stamp));
    RegCloseKey(hKey);
}

/* The last component of a registry path (the entry key), and whether the path is a catalog entry */
static
PCWSTR
NuEntryName(PCWSTR pszPath)
{
    PCWSTR p = wcsstr(pszPath, NU_ENTRY_MARK);

    if (!p)
        return NULL;
    p += wcslen(NU_ENTRY_MARK);
    return (*p && !wcschr(p, L'\\')) ? p : NULL;
}

/* The provider id, address family and protocol of a packed catalog item of at least NU_PACKED_MIN_SIZE bytes */
static
VOID
NuUnpackEntry(NU_ENTRY *Entry, const BYTE *Blob)
{
    RtlCopyMemory(&Entry->Provider, Blob + NU_PROVIDER_ID_OFFSET, sizeof(GUID));
    RtlCopyMemory(&Entry->Family, Blob + NU_FAMILY_OFFSET, sizeof(INT));
    RtlCopyMemory(&Entry->Protocol, Blob + NU_PROTOCOL_OFFSET, sizeof(INT));
}

/* The entries (key name, provider id, family, protocol) of the AddReg section, and the next entry id it sets */
static
BOOL
NuReadInf(
    HMODULE Setupapi,
    PCWSTR pszInf,
    NU_ENTRY *Entries,
    DWORD *pCount,
    DWORD *pNextId)
{
    PFN_OPENINF OpenInf = (PFN_OPENINF)GetProcAddress(Setupapi, "SetupOpenInfFileW");
    PFN_CLOSEINF CloseInf = (PFN_CLOSEINF)GetProcAddress(Setupapi, "SetupCloseInfFile");
    PFN_FINDFIRST FindFirst = (PFN_FINDFIRST)GetProcAddress(Setupapi, "SetupFindFirstLineW");
    PFN_FINDNEXT FindNext = (PFN_FINDNEXT)GetProcAddress(Setupapi, "SetupFindNextLine");
    PFN_GETSTRING GetString = (PFN_GETSTRING)GetProcAddress(Setupapi, "SetupGetStringFieldW");
    PFN_GETINT GetInt = (PFN_GETINT)GetProcAddress(Setupapi, "SetupGetIntField");
    PFN_GETBINARY GetBinary = (PFN_GETBINARY)GetProcAddress(Setupapi, "SetupGetBinaryField");
    HINF Inf;
    INFCONTEXT Ctx;
    BYTE Blob[NU_PACKED_MAX_SIZE];
    WCHAR Key[320], Value[64];
    DWORD Required;
    BOOL More, Ok = FALSE;

    *pCount = 0;
    *pNextId = 0;
    if (!OpenInf || !CloseInf || !FindFirst || !FindNext || !GetString || !GetInt || !GetBinary)
        return FALSE;

    Inf = OpenInf(pszInf, NULL, INF_STYLE_WIN4, NULL);
    if (Inf == INVALID_HANDLE_VALUE)
        return FALSE;

    Ok = TRUE;
    for (More = FindFirst(Inf, NU_ADDREG_SECTION, NULL, &Ctx); More; More = FindNext(&Ctx, &Ctx))
    {
        PCWSTR pszEntry;

        /* AddReg line: root, subkey, value name, flags, data... */
        if (!GetString(&Ctx, 2, Key, ARRAYSIZE(Key), NULL) || !GetString(&Ctx, 3, Value, ARRAYSIZE(Value), NULL))
            continue;

        if (!_wcsicmp(Key, L"SYSTEM\\CurrentControlSet\\Services\\Winsock2\\Parameters\\Protocol_Catalog9") &&
            !_wcsicmp(Value, L"Next_Catalog_Entry_ID"))
        {
            INT Next;

            if (GetInt(&Ctx, 5, &Next))
                *pNextId = (DWORD)Next;
            continue;
        }

        pszEntry = NuEntryName(Key);
        if (!pszEntry || _wcsicmp(Value, L"PackedCatalogItem"))
            continue;

        if (!GetBinary(&Ctx, 5, Blob, sizeof(Blob), &Required) || Required < NU_PACKED_MIN_SIZE ||
            *pCount >= NU_MAX_ENTRIES || wcslen(pszEntry) >= ARRAYSIZE(Entries[0].Name))
        {
            /* An entry we cannot read: leave everything alone */
            Ok = FALSE;
            break;
        }
        wcscpy(Entries[*pCount].Name, pszEntry);
        NuUnpackEntry(&Entries[*pCount], Blob);
        (*pCount)++;
    }
    CloseInf(Inf);
    return Ok && *pCount != 0 && *pNextId != 0;
}

/* Reads the provider id, family and protocol of a catalog entry; FALSE when there is no such entry */
static
BOOL
NuReadCatalogEntry(HKEY hEntries, PCWSTR pszName, NU_ENTRY *Found)
{
    HKEY hKey;
    BYTE Blob[NU_PACKED_MAX_SIZE];
    DWORD Size = sizeof(Blob), Type;
    BOOL Exists = FALSE;

    if (RegOpenKeyExW(hEntries, pszName, 0, KEY_QUERY_VALUE, &hKey) != ERROR_SUCCESS)
        return FALSE;
    if (RegQueryValueExW(hKey, L"PackedCatalogItem", NULL, &Type, Blob, &Size) == ERROR_SUCCESS &&
        Type == REG_BINARY && Size >= NU_PACKED_MIN_SIZE)
    {
        NuUnpackEntry(Found, Blob);
        Exists = TRUE;
    }
    else
    {
        /* An entry key we cannot make sense of counts as a different provider */
        RtlZeroMemory(&Found->Provider, sizeof(GUID));
        Found->Family = 0;
        Found->Protocol = 0;
        Exists = TRUE;
    }
    RegCloseKey(hKey);
    return Exists;
}

typedef enum _NU_VERDICT
{
    NuComplete,         /* every entry of the INF is in the catalog */
    NuMissing,          /* entries are missing and the section can be installed */
    NuLeaveAlone        /* the catalog holds other providers where the INF has entries, or ids past the INF's */
} NU_VERDICT;

static
NU_VERDICT
NuJudge(const NU_ENTRY *Entries, DWORD Count, DWORD InfNextId)
{
    HKEY hCatalog, hEntries;
    DWORD i, Next = 0, Size = sizeof(Next), Type;
    BOOL Missing = FALSE;
    NU_VERDICT Verdict;

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, NU_CATALOG_KEY, 0, KEY_QUERY_VALUE, &hCatalog) != ERROR_SUCCESS)
        return NuLeaveAlone;
    if (RegQueryValueExW(hCatalog, L"Next_Catalog_Entry_ID", NULL, &Type, (LPBYTE)&Next, &Size) != ERROR_SUCCESS ||
        Type != REG_DWORD)
    {
        RegCloseKey(hCatalog);
        return NuLeaveAlone;
    }
    RegCloseKey(hCatalog);

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, NU_ENTRIES_KEY, 0, KEY_QUERY_VALUE, &hEntries) != ERROR_SUCCESS)
        return NuLeaveAlone;

    Verdict = NuComplete;
    for (i = 0; i < Count; i++)
    {
        NU_ENTRY Found;

        if (!NuReadCatalogEntry(hEntries, Entries[i].Name, &Found))
        {
            Missing = TRUE;
        }
        else if (!IsEqualGUID(&Found.Provider, &Entries[i].Provider) ||
                 Found.Family != Entries[i].Family || Found.Protocol != Entries[i].Protocol)
        {
            Verdict = NuLeaveAlone;
            break;
        }
    }
    RegCloseKey(hEntries);

    if (Verdict == NuLeaveAlone)
        return NuLeaveAlone;
    if (!Missing)
        return NuComplete;
    /* Entries are to be added: the catalog must not have ids the INF's next id would hand out again */
    return (Next <= InfNextId) ? NuMissing : NuLeaveAlone;
}

static
VOID
NuRaiseSerial(DWORD Before)
{
    HKEY hKey;
    DWORD Value = Before + 1;

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, NU_CATALOG_KEY, 0, KEY_SET_VALUE, &hKey) != ERROR_SUCCESS)
        return;
    RegSetValueExW(hKey, L"Serial_Access_Num", 0, REG_DWORD, (const BYTE *)&Value, sizeof(Value));
    RegCloseKey(hKey);
}

static
DWORD
NuReadSerial(VOID)
{
    HKEY hKey;
    DWORD Value = 0, Size = sizeof(Value), Type;

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, NU_CATALOG_KEY, 0, KEY_QUERY_VALUE, &hKey) != ERROR_SUCCESS)
        return 0;
    if (RegQueryValueExW(hKey, L"Serial_Access_Num", NULL, &Type, (LPBYTE)&Value, &Size) != ERROR_SUCCESS ||
        Type != REG_DWORD)
        Value = 0;
    RegCloseKey(hKey);
    return Value;
}

/*
 * Called by winlogon at every start (SYSTEM context). Cheap when there is nothing to do: the switch is
 * read, and the INF's size and time compared to the ones kept.
 */
BOOL
WINAPI
UpgradeNetworkCatalog(VOID)
{
    WCHAR szInf[MAX_PATH + 32];
    NU_STAMP Stamp;
    NU_ENTRY Entries[NU_MAX_ENTRIES];
    DWORD Count, InfNextId, Serial;
    HMODULE Setupapi;
    NU_VERDICT Verdict;
    UINT Length;
    BOOL Read, Installed = FALSE;

    if (!NuSwitchOn())
        return TRUE;

    Length = GetSystemWindowsDirectoryW(szInf, MAX_PATH);
    if (Length == 0 || Length > MAX_PATH - 1)
        return FALSE;
    wcscpy(szInf + Length, NU_INF_NAME);

    if (!NuQueryStamp(szInf, &Stamp))
        return TRUE;
    if (NuStampIsCurrent(&Stamp))
        return TRUE;

    Setupapi = LoadLibraryW(L"setupapi.dll");
    if (!Setupapi)
        return FALSE;

    Read = NuReadInf(Setupapi, szInf, Entries, &Count, &InfNextId);
    if (!Read)
    {
        /* An INF that cannot be read is tried again at the next start */
        FreeLibrary(Setupapi);
        return FALSE;
    }

    Verdict = NuJudge(Entries, Count, InfNextId);
    if (Verdict == NuMissing)
    {
        PFN_OPENINF OpenInf = (PFN_OPENINF)GetProcAddress(Setupapi, "SetupOpenInfFileW");
        PFN_CLOSEINF CloseInf = (PFN_CLOSEINF)GetProcAddress(Setupapi, "SetupCloseInfFile");
        PFN_INSTALL Install = (PFN_INSTALL)GetProcAddress(Setupapi, "SetupInstallFromInfSectionW");
        HINF Inf;

        if (OpenInf && CloseInf && Install)
        {
            Serial = NuReadSerial();
            Inf = OpenInf(szInf, NULL, INF_STYLE_WIN4, NULL);
            if (Inf != INVALID_HANDLE_VALUE)
            {
                Installed = Install(NULL, Inf, NU_INSTALL_SECTION, SPINST_REGISTRY, NULL, NULL, 0,
                                    NULL, NULL, NULL, NULL);
                CloseInf(Inf);
            }
            if (Installed)
            {
                /* The INF holds a serial number of its own: the catalog's goes up so that every process reads it again */
                NuRaiseSerial(Serial);
                Installed = (NuJudge(Entries, Count, InfNextId) == NuComplete);
            }
        }
        if (!Installed)
        {
            DPRINT1("The IPv6 catalog entries could not be added\n");
            FreeLibrary(Setupapi);
            return FALSE;
        }
    }
    FreeLibrary(Setupapi);

    /* Complete, added, or left alone on purpose: settled for this INF */
    NuWriteStamp(&Stamp);
    return TRUE;
}

/* EOF */
