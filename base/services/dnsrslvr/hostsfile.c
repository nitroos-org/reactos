/*
 * COPYRIGHT:   See COPYING in the top level directory
 * PROJECT:     ReactOS system libraries
 * FILE:        base/services/dnsrslvr/hostsfile.c
 * PURPOSE:     HOSTS file routines
 * PROGRAMERS:  Art Yerkes
 *              Eric Kohl
 */

#include "precomp.h"
#include <inaddr.h>
#include <in6addr.h>
#include <ctype.h>
#include <string.h>


#define NDEBUG
#include <debug.h>

static WCHAR szHexChar[] = L"0123456789abcdef";

static
PWSTR
AnsiToUnicode(
    PSTR NarrowString)
{
    PWSTR WideString;
    int WideLen;

    WideLen = MultiByteToWideChar(CP_ACP,
                                  0,
                                  NarrowString,
                                  -1,
                                  NULL,
                                  0);
    if (WideLen == 0)
        return NULL;

    WideString = HeapAlloc(GetProcessHeap(),
                           0,
                           WideLen * sizeof(WCHAR));
    if (WideString == NULL)
        return NULL;

    MultiByteToWideChar(CP_ACP,
                        0,
                        NarrowString,
                        -1,
                        WideString,
                        WideLen);

    return WideString;
}


static
BOOL
ParseIpv4Address(
    _In_ PCSTR AddressString,
    _Out_ PIN_ADDR pAddress)
{
    PCSTR pTerminator = NULL;
    NTSTATUS Status;

    Status = RtlIpv4StringToAddressA(AddressString,
                                     TRUE,
                                     &pTerminator,
                                     pAddress);
    if (NT_SUCCESS(Status) && pTerminator != NULL && *pTerminator == '\0')
        return TRUE;

    return FALSE;
}


static
BOOL
ParseIpv6Address(
    _In_ LPCSTR AddressString,
    _Out_ PIN6_ADDR pAddress)
{
    PCSTR pTerminator = NULL;
    NTSTATUS Status;

    Status = RtlIpv6StringToAddressA(AddressString,
                                     &pTerminator,
                                     pAddress);
    if (NT_SUCCESS(Status) && pTerminator != NULL && *pTerminator == '\0')
        return TRUE;

    return FALSE;
}


static
VOID
AddIpv4HostEntries(
    PWSTR pszHostName,
    PIN_ADDR pAddress)
{
    DNS_RECORDW ARecord, PtrRecord;
    WCHAR szReverseName[32];

    /* Prepare the A record */
    ZeroMemory(&ARecord, sizeof(DNS_RECORDW));

    ARecord.pName = pszHostName;
    ARecord.wType = DNS_TYPE_A;
    ARecord.wDataLength = sizeof(DNS_A_DATA);
    ARecord.Flags.S.Section = DnsSectionAnswer;
    ARecord.Flags.S.CharSet = DnsCharSetUnicode;
    ARecord.dwTtl = 86400;

    ARecord.Data.A.IpAddress = pAddress->S_un.S_addr;

    /* Prepare the PTR record */
    _swprintf(szReverseName,
              L"%u.%u.%u.%u.in-addr.arpa.",
              pAddress->S_un.S_un_b.s_b4,
              pAddress->S_un.S_un_b.s_b3,
              pAddress->S_un.S_un_b.s_b2,
              pAddress->S_un.S_un_b.s_b1);

    ZeroMemory(&PtrRecord, sizeof(DNS_RECORDW));

    PtrRecord.pName = szReverseName;
    PtrRecord.wType = DNS_TYPE_PTR;
    PtrRecord.wDataLength = sizeof(DNS_PTR_DATA);
    PtrRecord.Flags.S.Section = DnsSectionAnswer;
    PtrRecord.Flags.S.CharSet = DnsCharSetUnicode;
    PtrRecord.dwTtl = 86400;

    PtrRecord.Data.PTR.pNameHost = pszHostName;

    DnsIntCacheAddEntry(&ARecord, TRUE);
    DnsIntCacheAddEntry(&PtrRecord, TRUE);
}


static
VOID
AddIpv6HostEntries(
    PWSTR pszHostName,
    PIN6_ADDR pAddress)
{
    DNS_RECORDW AAAARecord, PtrRecord;
    WCHAR szReverseName[80];
    DWORD i, j, k;

    /* Prepare the AAAA record */
    ZeroMemory(&AAAARecord, sizeof(DNS_RECORDW));

    AAAARecord.pName = pszHostName;
    AAAARecord.wType = DNS_TYPE_AAAA;
    AAAARecord.wDataLength = sizeof(DNS_AAAA_DATA);
    AAAARecord.Flags.S.Section = DnsSectionAnswer;
    AAAARecord.Flags.S.CharSet = DnsCharSetUnicode;
    AAAARecord.dwTtl = 86400;

    CopyMemory(&AAAARecord.Data.AAAA.Ip6Address,
               &pAddress->u.Byte,
               sizeof(IN6_ADDR));

    /* Prepare the PTR record */
    ZeroMemory(szReverseName, sizeof(szReverseName));

    for (i = 0; i < sizeof(IN6_ADDR); i++)
    {
        j = 4 * i;
        k = sizeof(IN6_ADDR) - 1 - i;
        szReverseName[j] = szHexChar[pAddress->u.Byte[k] & 0xF];
        szReverseName[j + 1] = L'.';
        szReverseName[j + 2] = szHexChar[(pAddress->u.Byte[k] >> 4) & 0xF];
        szReverseName[j + 3] = L'.';
    }
    wcscat(szReverseName, L"ip6.arpa.");

    ZeroMemory(&PtrRecord, sizeof(DNS_RECORDW));

    PtrRecord.pName = szReverseName;
    PtrRecord.wType = DNS_TYPE_PTR;
    PtrRecord.wDataLength = sizeof(DNS_PTR_DATA);
    PtrRecord.Flags.S.Section = DnsSectionAnswer;
    PtrRecord.Flags.S.CharSet = DnsCharSetUnicode;
    PtrRecord.dwTtl = 86400;

    PtrRecord.Data.PTR.pNameHost = pszHostName;

    DnsIntCacheAddEntry(&AAAARecord, TRUE);
    DnsIntCacheAddEntry(&PtrRecord, TRUE);
}

/*
 * The path of the hosts file: DataBasePath of Tcpip\Parameters (REG_EXPAND_SZ, usually
 * %SystemRoot%\System32\drivers\etc) + "hosts", else <system directory>\drivers\etc\hosts.
 */
static
BOOL
GetHostsFilePath(
    _Out_writes_(MAX_PATH) PWSTR ExpandedPath)
{
    WCHAR szRawPath[MAX_PATH];
    HKEY DatabaseKey;
    DWORD RegSize, RegType;
    size_t StringLength;
    BOOL bHavePath = FALSE;

    ExpandedPath[0] = UNICODE_NULL;

    /* Open the database path key */
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                      L"System\\CurrentControlSet\\Services\\Tcpip\\Parameters",
                      0,
                      KEY_READ,
                      &DatabaseKey) == ERROR_SUCCESS)
    {
        /* Read the actual path (the size leaves room for the terminator) */
        RegSize = sizeof(szRawPath) - sizeof(WCHAR);
        if (RegQueryValueExW(DatabaseKey,
                             L"DatabasePath",
                             NULL,
                             &RegType,
                             (LPBYTE)szRawPath,
                             &RegSize) == ERROR_SUCCESS &&
            (RegType == REG_SZ || RegType == REG_EXPAND_SZ))
        {
            szRawPath[RegSize / sizeof(WCHAR)] = UNICODE_NULL;
            if (szRawPath[0] != UNICODE_NULL)
            {
                /* Expand the name */
                if (ExpandEnvironmentStringsW(szRawPath, ExpandedPath, MAX_PATH) != 0 &&
                    ExpandedPath[0] != UNICODE_NULL)
                    bHavePath = TRUE;
            }
        }

        RegCloseKey(DatabaseKey);
    }

    if (!bHavePath)
    {
        /* Use default path */
        if (GetSystemDirectoryW(ExpandedPath, MAX_PATH) == 0)
            return FALSE;

        StringCchCatW(ExpandedPath, MAX_PATH, L"\\drivers\\etc");
    }

    /* Make sure that the path is backslash-terminated */
    StringCchLengthW(ExpandedPath, MAX_PATH, &StringLength);
    if (StringLength == 0)
        return FALSE;
    if (ExpandedPath[StringLength - 1] != L'\\')
    {
        /* It isn't, so add it ourselves */
        StringCchCatW(ExpandedPath, MAX_PATH, L"\\");
    }

    /* Add the database name */
    return SUCCEEDED(StringCchCatW(ExpandedPath, MAX_PATH, L"hosts"));
}


static
FILE *
OpenHostsFile(VOID)
{
    WCHAR szPath[MAX_PATH];

    if (!GetHostsFilePath(szPath))
        return NULL;

    /* Binary mode: the CR of a CRLF line end is a blank for the parser */
    return _wfopen(szPath, L"rb");
}


/*
 * One address followed by one or more names. Everything from a '#' on is a comment; blanks and tabs
 * separate the fields (a CR of a CRLF line end is a blank).
 */
static
VOID
ParseHostsLine(
    _Inout_ PSTR Line)
{
    PSTR Ptr = Line, AddressStart, Token;
    struct in_addr Ipv4Address;
    struct in6_addr Ipv6Address;
    BOOL bIpv4;
    PWSTR pszHostName;

    for (Ptr = Line; *Ptr != 0; Ptr++)
    {
        if (*Ptr == '#')
        {
            *Ptr = 0;
            break;
        }
    }

    /* The address */
    Ptr = Line;
    while (*Ptr != 0 && isspace((UCHAR)*Ptr))
        Ptr++;
    if (*Ptr == 0)
        return;
    AddressStart = Ptr;
    while (*Ptr != 0 && !isspace((UCHAR)*Ptr))
        Ptr++;
    if (*Ptr == 0)
        return;     /* an address without a name */
    *Ptr++ = 0;

    if (ParseIpv4Address(AddressStart, &Ipv4Address))
        bIpv4 = TRUE;
    else if (ParseIpv6Address(AddressStart, &Ipv6Address))
        bIpv4 = FALSE;
    else
        return;

    /* Every name of the line */
    for (;;)
    {
        while (*Ptr != 0 && isspace((UCHAR)*Ptr))
            Ptr++;
        if (*Ptr == 0)
            break;

        Token = Ptr;
        while (*Ptr != 0 && !isspace((UCHAR)*Ptr))
            Ptr++;
        if (*Ptr != 0)
            *Ptr++ = 0;

        DPRINT("%s ==> %s\n", Token, AddressStart);

        pszHostName = AnsiToUnicode(Token);
        if (pszHostName != NULL)
        {
            if (bIpv4)
                AddIpv4HostEntries(pszHostName, &Ipv4Address);
            else
                AddIpv6HostEntries(pszHostName, &Ipv6Address);
            HeapFree(GetProcessHeap(), 0, pszHostName);
        }
    }
}


BOOL
ReadHostsFile(VOID)
{
    CHAR szLineBuffer[1024];
    FILE *pHostFile = NULL;
    PSTR Ptr;
    BOOL bFirst = TRUE, bSkipRest = FALSE;
    size_t Length;

    pHostFile = OpenHostsFile();
    if (pHostFile == NULL)
        return FALSE;

    for (;;)
    {
        /* Read a line */
        if (fgets(szLineBuffer, sizeof(szLineBuffer), pHostFile) == NULL)
            break;

        Ptr = szLineBuffer;
        if (bFirst)
        {
            bFirst = FALSE;
            /* skip an UTF-8 byte order mark */
            if ((UCHAR)Ptr[0] == 0xEF && (UCHAR)Ptr[1] == 0xBB && (UCHAR)Ptr[2] == 0xBF)
                Ptr += 3;
        }

        /* the rest of a line that did not fit is not a line of its own */
        Length = strlen(Ptr);
        if (bSkipRest)
        {
            bSkipRest = (Length == 0 || Ptr[Length - 1] != '\n');
            continue;
        }
        if (Length > 0 && Ptr[Length - 1] != '\n' && Length == strlen(szLineBuffer) &&
            Length == sizeof(szLineBuffer) - 1)
        {
            /* too long for the buffer: the whole line is ignored (a cut name would be a wrong name) */
            bSkipRest = TRUE;
            continue;
        }

        ParseHostsLine(Ptr);
    }

    fclose(pHostFile);

    return TRUE;
}


/*
 * The resolver keeps the rows of the hosts file in its cache. Windows reads the file again when it
 * changes: the last write time and the size of the file are compared on every query, and a change (or the
 * file appearing / disappearing) replaces the rows of the hosts file in the cache.
 */
static CRITICAL_SECTION HostsReloadLock;
static BOOL HostsReloadLockInitialized = FALSE;
static BOOL HostsStateValid = FALSE;
static BOOL HostsFileExists = FALSE;
static FILETIME HostsLastWrite;
static DWORD HostsSizeHigh, HostsSizeLow;
static ULONGLONG HostsLoadedAt;     /* system time of the last read, 100 ns units */

/*
 * The write time of a file has the resolution of the system clock: two edits of the same length in one
 * tick look alike. A file written in the 2 seconds before the last read is read again.
 */
#define HOSTS_FRESH_WINDOW (2ULL * 10000000ULL)

static
ULONGLONG
HostsNow(VOID)
{
    FILETIME Now;
    ULARGE_INTEGER Value;

    GetSystemTimeAsFileTime(&Now);
    Value.LowPart = Now.dwLowDateTime;
    Value.HighPart = Now.dwHighDateTime;
    return Value.QuadPart;
}

static
ULONGLONG
HostsFileTime(const FILETIME *pTime)
{
    ULARGE_INTEGER Value;

    Value.LowPart = pTime->dwLowDateTime;
    Value.HighPart = pTime->dwHighDateTime;
    return Value.QuadPart;
}

static
BOOL
GetHostsFileState(
    _Out_ PBOOL pbExists,
    _Out_ PFILETIME pLastWrite,
    _Out_ PDWORD pSizeHigh,
    _Out_ PDWORD pSizeLow)
{
    WCHAR szPath[MAX_PATH];
    WIN32_FILE_ATTRIBUTE_DATA Data;

    *pbExists = FALSE;
    pLastWrite->dwLowDateTime = pLastWrite->dwHighDateTime = 0;
    *pSizeHigh = *pSizeLow = 0;

    if (!GetHostsFilePath(szPath))
        return FALSE;

    if (GetFileAttributesExW(szPath, GetFileExInfoStandard, &Data))
    {
        *pbExists = TRUE;
        *pLastWrite = Data.ftLastWriteTime;
        *pSizeHigh = Data.nFileSizeHigh;
        *pSizeLow = Data.nFileSizeLow;
    }

    return TRUE;
}

VOID
HostsFileInitialize(VOID)
{
    InitializeCriticalSection(&HostsReloadLock);
    HostsReloadLockInitialized = TRUE;

    /* the state is taken before the read: a write in between is seen by the next check */
    HostsLoadedAt = HostsNow();
    HostsStateValid = GetHostsFileState(&HostsFileExists, &HostsLastWrite, &HostsSizeHigh, &HostsSizeLow);
    ReadHostsFile();
}

VOID
HostsFileReloadIfChanged(VOID)
{
    BOOL bExists;
    FILETIME LastWrite;
    DWORD SizeHigh, SizeLow;

    if (!HostsReloadLockInitialized)
        return;

    if (!GetHostsFileState(&bExists, &LastWrite, &SizeHigh, &SizeLow))
        return;

    EnterCriticalSection(&HostsReloadLock);

    if (!HostsStateValid ||
        bExists != HostsFileExists ||
        CompareFileTime(&LastWrite, &HostsLastWrite) != 0 ||
        SizeHigh != HostsSizeHigh ||
        SizeLow != HostsSizeLow ||
        (bExists && HostsFileTime(&LastWrite) + HOSTS_FRESH_WINDOW > HostsLoadedAt))
    {
        HostsStateValid = TRUE;
        HostsFileExists = bExists;
        HostsLastWrite = LastWrite;
        HostsSizeHigh = SizeHigh;
        HostsSizeLow = SizeLow;
        HostsLoadedAt = HostsNow();

        /* the swap is one step for the queries: they wait on the cache lock */
        DnsIntCacheLock();
        DnsIntCacheFlush(CACHE_FLUSH_HOSTS_FILE_ENTRIES);
        ReadHostsFile();
        DnsIntCacheUnlock();
    }

    LeaveCriticalSection(&HostsReloadLock);
}

/* EOF */
