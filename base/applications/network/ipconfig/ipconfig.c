/*
 * PROJECT:     ReactOS ipconfig utility
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Display IP info for net adapters
 * COPYRIGHT:   Copyright 2005-2006 Ged Murphy <gedmurphy@gmail.com>
 */

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

#define WIN32_NO_STATUS
#include <windef.h>
#include <winbase.h>
#include <winnls.h>
#include <winreg.h>
#include <iphlpapi.h>
#include <ndk/rtlfuncs.h>
#include <inaddr.h>
#include <windns.h>
#include <windns_undoc.h>
#include <dhcpcsdk.h>
#include <dhcpcapi.h>
#include <strsafe.h>
#include <conutils.h>

#include "resource.h"

typedef struct _RECORDTYPE
{
    WORD wRecordType;
    PCWSTR pszRecordName;
} RECORDTYPE, *PRECORDTYPE;

#define GUID_LEN 40

HINSTANCE hInstance;
HANDLE ProcessHeap;

RECORDTYPE TypeArray[] =
{
    {DNS_TYPE_ZERO,    L"ZERO"},
    {DNS_TYPE_A,       L"A"},
    {DNS_TYPE_NS,      L"NS"},
    {DNS_TYPE_MD,      L"MD"},
    {DNS_TYPE_MF,      L"MF"},
    {DNS_TYPE_CNAME,   L"CNAME"},
    {DNS_TYPE_SOA,     L"SOA"},
    {DNS_TYPE_MB,      L"MB"},
    {DNS_TYPE_MG,      L"MG"},
    {DNS_TYPE_MR,      L"MR"},
    {DNS_TYPE_NULL,    L"NULL"},
    {DNS_TYPE_WKS,     L"WKS"},
    {DNS_TYPE_PTR,     L"PTR"},
    {DNS_TYPE_HINFO,   L"HINFO"},
    {DNS_TYPE_MINFO,   L"MINFO"},
    {DNS_TYPE_MX,      L"MX"},
    {DNS_TYPE_TEXT,    L"TXT"},
    {DNS_TYPE_RP,      L"RP"},
    {DNS_TYPE_AFSDB,   L"AFSDB"},
    {DNS_TYPE_X25,     L"X25"},
    {DNS_TYPE_ISDN,    L"ISDN"},
    {DNS_TYPE_RT,      L"RT"},
    {DNS_TYPE_NSAP,    L"NSAP"},
    {DNS_TYPE_NSAPPTR, L"NSAPPTR"},
    {DNS_TYPE_SIG,     L"SIG"},
    {DNS_TYPE_KEY,     L"KEY"},
    {DNS_TYPE_PX,      L"PX"},
    {DNS_TYPE_GPOS,    L"GPOS"},
    {DNS_TYPE_AAAA,    L"AAAA"},
    {DNS_TYPE_LOC,     L"LOC"},
    {DNS_TYPE_NXT,     L"NXT"},
    {DNS_TYPE_EID,     L"EID"},
    {DNS_TYPE_NIMLOC,  L"NIMLOC"},
    {DNS_TYPE_SRV,     L"SRV"},
    {DNS_TYPE_ATMA,    L"ATMA"},
    {DNS_TYPE_NAPTR,   L"NAPTR"},
    {DNS_TYPE_KX,      L"KX"},
    {DNS_TYPE_CERT,    L"CERT"},
    {DNS_TYPE_A6,      L"A6"},
    {DNS_TYPE_DNAME,   L"DNAME"},
    {DNS_TYPE_SINK,    L"SINK"},
    {DNS_TYPE_OPT,     L"OPT"},
    {DNS_TYPE_UINFO,   L"UINFO"},
    {DNS_TYPE_UID,     L"UID"},
    {DNS_TYPE_GID,     L"GID"},
    {DNS_TYPE_UNSPEC,  L"UNSPEC"},
    {DNS_TYPE_ADDRS,   L"ADDRS"},
    {DNS_TYPE_TKEY,    L"TKEY"},
    {DNS_TYPE_TSIG,    L"TSIG"},
    {DNS_TYPE_IXFR,    L"IXFR"},
    {DNS_TYPE_AXFR,    L"AXFR"},
    {DNS_TYPE_MAILB,   L"MAILB"},
    {DNS_TYPE_MAILA,   L"MAILA"},
    {DNS_TYPE_ALL,     L"ALL"},
    {0, NULL}
};

PCWSTR
GetRecordTypeName(WORD wType)
{
    static WCHAR szType[8];
    INT i;

    for (i = 0; ; i++)
    {
         if (TypeArray[i].pszRecordName == NULL)
             break;

         if (TypeArray[i].wRecordType == wType)
             return TypeArray[i].pszRecordName;
    }

    _swprintf(szType, L"%hu", wType);

    return szType;
}

/* print MAC address */
PCSTR PrintMacAddr(PBYTE Mac)
{
    static CHAR MacAddr[20];

    sprintf(MacAddr, "%02X-%02X-%02X-%02X-%02X-%02X",
        Mac[0], Mac[1], Mac[2], Mac[3], Mac[4],  Mac[5]);

    return MacAddr;
}

/* convert time_t to localized string */
_Ret_opt_z_ PWSTR timeToStr(_In_ time_t TimeStamp)
{
    struct tm* ptm;
    SYSTEMTIME SystemTime;
    INT DateCchSize, TimeCchSize, TotalCchSize, i;
    PWSTR DateTimeString, psz;

    /* Convert Unix time to SYSTEMTIME */
    /* localtime_s may be preferred if available */
    ptm = localtime(&TimeStamp);
    if (!ptm)
    {
        return NULL;
    }
    SystemTime.wYear = ptm->tm_year + 1900;
    SystemTime.wMonth = ptm->tm_mon + 1;
    SystemTime.wDay = ptm->tm_mday;
    SystemTime.wHour = ptm->tm_hour;
    SystemTime.wMinute = ptm->tm_min;
    SystemTime.wSecond = ptm->tm_sec;

    /* Get total size in characters required of buffer */
    DateCchSize = GetDateFormatW(LOCALE_USER_DEFAULT, DATE_LONGDATE, &SystemTime, NULL, NULL, 0);
    if (!DateCchSize)
    {
        return NULL;
    }
    TimeCchSize = GetTimeFormatW(LOCALE_USER_DEFAULT, 0, &SystemTime, NULL, NULL, 0);
    if (!TimeCchSize)
    {
        return NULL;
    }
    /* Two terminating null are included, the first one will be replaced by space */
    TotalCchSize = DateCchSize + TimeCchSize;

    /* Allocate buffer and format datetime string */
    DateTimeString = (PWSTR)HeapAlloc(ProcessHeap, 0, TotalCchSize * sizeof(WCHAR));
    if (!DateTimeString)
    {
        return NULL;
    }

    /* Get date string */
    i = GetDateFormatW(LOCALE_USER_DEFAULT, DATE_LONGDATE, &SystemTime, NULL, DateTimeString, TotalCchSize);
    if (i)
    {
        /* Append space and move pointer */
        DateTimeString[i - 1] = L' ';
        psz = DateTimeString + i;
        TotalCchSize -= i;

        /* Get time string */
        if (GetTimeFormatW(LOCALE_USER_DEFAULT, 0, &SystemTime, NULL, psz, TotalCchSize))
        {
            return DateTimeString;
        }
    }

    HeapFree(ProcessHeap, 0, DateTimeString);
    return NULL;
}

VOID
DoFormatMessage(
    _In_ LONG ErrorCode)
{
    if (ErrorCode == 0)
        ErrorCode = GetLastError();

    ConMsgPuts(StdOut,
               FORMAT_MESSAGE_FROM_SYSTEM,
               NULL,
               ErrorCode,
               LANG_USER_DEFAULT);
}

PWSTR
GetUnicodeAdapterName(
    _In_ PSTR pszAnsiName)
{
    PWSTR pszUnicodeName;
    size_t i, len;

    len = strlen(pszAnsiName);
    pszUnicodeName = HeapAlloc(GetProcessHeap(), 0, (len + 1) * sizeof(WCHAR));
    if (pszUnicodeName == NULL)
        return NULL;

    for (i = 0; i < len; i++)
        pszUnicodeName[i] = (WCHAR)pszAnsiName[i];
    pszUnicodeName[i] = UNICODE_NULL;

    return pszUnicodeName;
}

VOID
GetAdapterFriendlyName(
    _In_ PSTR lpClass,
    _In_ DWORD cchFriendlyNameLength,
    _Out_ PWSTR pszFriendlyName)
{
    HKEY hKey = NULL;
    CHAR Path[256];
    PCSTR PrePath = "SYSTEM\\CurrentControlSet\\Control\\Network\\{4D36E972-E325-11CE-BFC1-08002BE10318}\\";
    PCSTR PostPath = "\\Connection";
    size_t PathSize;
    DWORD dwType;
    DWORD dwDataSize;

    pszFriendlyName[0] = UNICODE_NULL;

    /* don't overflow the buffer */
    PathSize = strlen(PrePath) + strlen(lpClass) + strlen(PostPath) + 1;
    if (PathSize > _countof(Path))
        return;

    sprintf(Path, "%s%s%s", PrePath, lpClass, PostPath);

    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                      Path,
                      0,
                      KEY_READ,
                      &hKey) == ERROR_SUCCESS)
    {
        dwDataSize = (cchFriendlyNameLength - 1) * sizeof(WCHAR);
        if (RegQueryValueExW(hKey,
                             L"Name",
                             NULL,
                             &dwType,
                             (PBYTE)pszFriendlyName,
                             &dwDataSize) != ERROR_SUCCESS)
        {
            pszFriendlyName[0] = UNICODE_NULL;
        }
        else
        {
            pszFriendlyName[dwDataSize / sizeof(WCHAR) < cchFriendlyNameLength ? dwDataSize / sizeof(WCHAR) : cchFriendlyNameLength - 1] = UNICODE_NULL;
        }
    }

    if (hKey != NULL)
        RegCloseKey(hKey);
}

VOID
GetInterfaceFriendlyName(
    _In_ PCWSTR lpDeviceName,
    _In_ DWORD cchFriendlyNameLength,
    _Out_ PWSTR pszFriendlyName)
{
    HKEY hKey = NULL;
    WCHAR Path[256];
    PCWSTR PrePath = L"SYSTEM\\CurrentControlSet\\Control\\Network\\{4D36E972-E325-11CE-BFC1-08002BE10318}\\";
    PCWSTR PostPath = L"\\Connection";
    PCWSTR DevicePrefix = L"\\DEVICE\\TCPIP_";
    size_t PathSize;
    DWORD dwType;
    DWORD dwDataSize;

    size_t dwPrefixLength = wcslen(DevicePrefix);

    /* don't overflow the buffer */
    PathSize = wcslen(PrePath) + wcslen(lpDeviceName) - dwPrefixLength + wcslen(PostPath) + 1;
    if (PathSize > _countof(Path))
        return;

    _swprintf(Path, L"%s%s%s", PrePath, &lpDeviceName[dwPrefixLength], PostPath);

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                      Path,
                      0,
                      KEY_READ,
                      &hKey) == ERROR_SUCCESS)
    {
        dwDataSize = cchFriendlyNameLength * sizeof(WCHAR);
        RegQueryValueExW(hKey,
                         L"Name",
                         NULL,
                         &dwType,
                         (PBYTE)pszFriendlyName,
                         &dwDataSize);
    }

    if (hKey != NULL)
        RegCloseKey(hKey);
}

/* Read a REG_SZ value of an adapter's Tcpip interface key into an ANSI buffer. */
static
BOOL
GetTcpipInterfaceString(
    _In_ PCSTR pszAdapterName,
    _In_ PCSTR pszValue,
    _Out_writes_(cchBuffer) PSTR pszBuffer,
    _In_ DWORD cchBuffer)
{
    CHAR szKey[256];
    HKEY hKey;
    DWORD dwType, dwSize = cchBuffer - 1;
    BOOL bRet = FALSE;

    pszBuffer[0] = ANSI_NULL;
    if (strlen(pszAdapterName) > 100)
        return FALSE;
    sprintf(szKey, "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\%s", pszAdapterName);
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, szKey, 0, KEY_READ, &hKey) != ERROR_SUCCESS)
        return FALSE;
    if (RegQueryValueExA(hKey, pszValue, NULL, &dwType, (PBYTE)pszBuffer, &dwSize) == ERROR_SUCCESS &&
        dwType == REG_SZ)
    {
        pszBuffer[dwSize < cchBuffer ? dwSize : cchBuffer - 1] = ANSI_NULL;
        bRet = (pszBuffer[0] != ANSI_NULL);
    }
    else
    {
        pszBuffer[0] = ANSI_NULL;
    }
    RegCloseKey(hKey);
    return bRet;
}

/* Connection-specific DNS suffix: static value first, then the one from DHCP. */
static
VOID
GetConnectionDnsSuffix(
    _In_ PCSTR pszAdapterName,
    _Out_writes_(cchBuffer) PSTR pszBuffer,
    _In_ DWORD cchBuffer)
{
    if (!GetTcpipInterfaceString(pszAdapterName, "Domain", pszBuffer, cchBuffer))
        GetTcpipInterfaceString(pszAdapterName, "DhcpDomain", pszBuffer, cchBuffer);
}

/* NetBIOS over TCP/IP: enabled unless the interface (or the DHCP default) says 2 = disabled. */
static
BOOL
IsNetbiosEnabled(
    _In_ PCSTR pszAdapterName)
{
    CHAR szKey[256];
    HKEY hKey;
    DWORD dwType, dwValue = 0, dwSize = sizeof(dwValue);
    BOOL bEnabled = TRUE;

    if (strlen(pszAdapterName) > 100)
        return TRUE;
    sprintf(szKey, "SYSTEM\\CurrentControlSet\\Services\\NetBT\\Parameters\\Interfaces\\Tcpip_%s", pszAdapterName);
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, szKey, 0, KEY_READ, &hKey) != ERROR_SUCCESS)
        return TRUE;
    if (RegQueryValueExA(hKey, "NetbiosOptions", NULL, &dwType, (PBYTE)&dwValue, &dwSize) == ERROR_SUCCESS &&
        dwType == REG_DWORD && dwValue == 2)
    {
        bEnabled = FALSE;
    }
    RegCloseKey(hKey);
    return bEnabled;
}

/* The adapter description is the DriverDesc of the network class key whose NetCfgInstanceId matches. */
static
BOOL
GetAdapterDescription(
    _In_ PCSTR pszAdapterName,
    _Out_writes_(cchBuffer) PSTR pszBuffer,
    _In_ DWORD cchBuffer)
{
    HKEY hBaseKey = NULL, hClassKey;
    PCSTR pszBasePath = "SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002bE10318}";
    CHAR szName[16], szId[128];
    DWORD i, dwType, dwSize, dwNameLen;
    BOOL bFound = FALSE;

    pszBuffer[0] = ANSI_NULL;

    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, pszBasePath, 0, KEY_READ, &hBaseKey) != ERROR_SUCCESS)
        return FALSE;

    for (i = 0; !bFound; i++)
    {
        LONG Status;

        dwNameLen = _countof(szName);
        Status = RegEnumKeyExA(hBaseKey, i, szName, &dwNameLen, NULL, NULL, NULL, NULL);
        if (Status == ERROR_NO_MORE_ITEMS)
            break;
        if (Status != ERROR_SUCCESS)
            continue;

        if (RegOpenKeyExA(hBaseKey, szName, 0, KEY_READ, &hClassKey) != ERROR_SUCCESS)
            continue;

        dwSize = sizeof(szId) - 1;
        if (RegQueryValueExA(hClassKey, "NetCfgInstanceId", NULL, &dwType, (PBYTE)szId, &dwSize) == ERROR_SUCCESS &&
            dwType == REG_SZ)
        {
            szId[dwSize < sizeof(szId) ? dwSize : sizeof(szId) - 1] = ANSI_NULL;
            if (!_stricmp(szId, pszAdapterName))
            {
                dwSize = cchBuffer - 1;
                if (RegQueryValueExA(hClassKey, "DriverDesc", NULL, &dwType, (PBYTE)pszBuffer, &dwSize) == ERROR_SUCCESS)
                {
                    pszBuffer[dwSize < cchBuffer ? dwSize : cchBuffer - 1] = ANSI_NULL;
                    bFound = TRUE;
                }
                else
                {
                    pszBuffer[0] = ANSI_NULL;
                }
            }
        }
        RegCloseKey(hClassKey);
    }

    RegCloseKey(hBaseKey);
    return bFound;
}

static
VOID
PrintNodeType(
    _In_ UINT NodeType)
{
    switch (NodeType)
    {
        case BROADCAST_NODETYPE:
            ConResPrintf(StdOut, IDS_NODETYPEBCAST);
            break;

        case PEER_TO_PEER_NODETYPE:
            ConResPrintf(StdOut, IDS_NODETYPEP2P);
            break;

        case MIXED_NODETYPE:
            ConResPrintf(StdOut, IDS_NODETYPEMIXED);
            break;

        case HYBRID_NODETYPE:
            ConResPrintf(StdOut, IDS_NODETYPEHYBRID);
            break;

        default :
            ConResPrintf(StdOut, IDS_NODETYPEUNKNOWN);
            break;
    }
}

static
VOID
PrintAdapterTypeAndName(
    PIP_ADAPTER_INFO pAdapterInfo)
{
    WCHAR szFriendlyName[MAX_PATH];

    GetAdapterFriendlyName(pAdapterInfo->AdapterName, MAX_PATH, szFriendlyName);

    switch (pAdapterInfo->Type)
    {
        case MIB_IF_TYPE_OTHER:
            ConResPrintf(StdOut, IDS_OTHER, szFriendlyName);
            break;

        case MIB_IF_TYPE_ETHERNET:
            ConResPrintf(StdOut, IDS_ETH, szFriendlyName);
            break;

        case MIB_IF_TYPE_TOKENRING:
            ConResPrintf(StdOut, IDS_TOKEN, szFriendlyName);
            break;

        case MIB_IF_TYPE_FDDI:
            ConResPrintf(StdOut, IDS_FDDI, szFriendlyName);
            break;

        case MIB_IF_TYPE_PPP:
            ConResPrintf(StdOut, IDS_PPP, szFriendlyName);
            break;

        case MIB_IF_TYPE_LOOPBACK:
            ConResPrintf(StdOut, IDS_LOOP, szFriendlyName);
            break;

        case MIB_IF_TYPE_SLIP:
            ConResPrintf(StdOut, IDS_SLIP, szFriendlyName);
            break;

        case IF_TYPE_IEEE80211:
            ConResPrintf(StdOut, IDS_WIFI, szFriendlyName);
            break;

        default:
            ConResPrintf(StdOut, IDS_UNKNOWNADAPTER, szFriendlyName);
            break;
    }
}

static
VOID
PrintHeader(VOID)
{
    ConResPrintf(StdOut, IDS_HEADER);
}

/* Print the list entries: the first with the label string, the rest as continuation lines. */
static
VOID
PrintAddrList(
    _In_ UINT LabelId,
    _In_ PIP_ADDR_STRING pList,
    _In_ BOOL bSkipZero)
{
    BOOL bFirst = TRUE;

    for (; pList != NULL; pList = pList->Next)
    {
        if (pList->IpAddress.String[0] == ANSI_NULL ||
            (bSkipZero && !strcmp(pList->IpAddress.String, "0.0.0.0")))
            continue;

        ConResPrintf(StdOut, bFirst ? LabelId : IDS_EMPTYLINE, pList->IpAddress.String);
        bFirst = FALSE;
    }
}

/* Split a comma/space separated search list and print it as label + continuation lines. */
static
VOID
PrintSearchList(
    _In_ PCSTR pszList)
{
    CHAR szCopy[1024];
    PSTR p, tok;
    BOOL bFirst = TRUE;

    StringCchCopyA(szCopy, _countof(szCopy), pszList);
    for (p = szCopy; *p; )
    {
        while (*p == ',' || *p == ' ')
            p++;
        if (!*p)
            break;
        tok = p;
        while (*p && *p != ',' && *p != ' ')
            p++;
        if (*p)
            *p++ = ANSI_NULL;
        ConResPrintf(StdOut, bFirst ? IDS_DNSSUFFIXLIST : IDS_EMPTYLINE, tok);
        bFirst = FALSE;
    }
}

static
BOOL
IsAdapterConnected(
    _In_ PIP_ADAPTER_INFO pAdapter)
{
    MIB_IFROW mibEntry;

    ZeroMemory(&mibEntry, sizeof(mibEntry));
    mibEntry.dwIndex = pAdapter->Index;
    GetIfEntry(&mibEntry);
    return (mibEntry.dwOperStatus == MIB_IF_OPER_STATUS_CONNECTED ||
            mibEntry.dwOperStatus == MIB_IF_OPER_STATUS_OPERATIONAL);
}

static
INT
ShowInfo(
    BOOL bAll)
{
    PIP_ADAPTER_INFO pAdapterInfo = NULL;
    PIP_ADAPTER_INFO pAdapter = NULL;
    ULONG adaptOutBufLen = 0;
    PFIXED_INFO pFixedInfo = NULL;
    ULONG netOutBufLen = 0;
    PIP_PER_ADAPTER_INFO pPerAdapterInfo = NULL;
    ULONG ulPerAdapterInfoLength = 0;
    PSTR pszDomainName = NULL;
    DWORD dwDomainNameSize = 0;
    ULONG ret = 0;
    INT Result = 0;
    CHAR szBuffer[512];

    GetComputerNameExA(ComputerNameDnsDomain,
                       NULL,
                       &dwDomainNameSize);
    if (dwDomainNameSize > 0)
    {
        pszDomainName = HeapAlloc(ProcessHeap,
                                  0,
                                  dwDomainNameSize * sizeof(CHAR));
        if (pszDomainName != NULL)
            GetComputerNameExA(ComputerNameDnsDomain,
                               pszDomainName,
                               &dwDomainNameSize);
    }

    /* call GetAdaptersInfo to obtain the adapter info */
    ret = GetAdaptersInfo(pAdapterInfo, &adaptOutBufLen);
    if (ret == ERROR_BUFFER_OVERFLOW)
    {
        pAdapterInfo = (IP_ADAPTER_INFO *)HeapAlloc(ProcessHeap, 0, adaptOutBufLen);
        if (pAdapterInfo == NULL)
            goto done;

        ret = GetAdaptersInfo(pAdapterInfo, &adaptOutBufLen);
        if (ret != NO_ERROR)
        {
            DoFormatMessage(0);
            Result = 1;
            goto done;
        }
    }
    else
    {
        if (ret != ERROR_NO_DATA)
        {
            DoFormatMessage(0);
            Result = 1;
            goto done;
        }
    }

    /* call GetNetworkParams to obtain the network info */
    if (GetNetworkParams(pFixedInfo, &netOutBufLen) == ERROR_BUFFER_OVERFLOW)
    {
        pFixedInfo = (FIXED_INFO *)HeapAlloc(ProcessHeap, 0, netOutBufLen);
        if (pFixedInfo == NULL)
        {
            goto done;
        }
        if (GetNetworkParams(pFixedInfo, &netOutBufLen) != NO_ERROR)
        {
            DoFormatMessage(0);
            Result = 1;
            goto done;
        }
    }
    else
    {
        DoFormatMessage(0);
        Result = 1;
        goto done;
    }

    pAdapter = pAdapterInfo;

    if (bAll)
    {
        ConResPrintf(StdOut, IDS_HOSTNAME, pFixedInfo->HostName);
        ConResPrintf(StdOut, IDS_PRIMARYDNSSUFFIX, (pszDomainName != NULL) ? pszDomainName : "");

        PrintNodeType(pFixedInfo->NodeType);

        if (pFixedInfo->EnableRouting)
            ConResPrintf(StdOut, IDS_IPROUTINGYES);
        else
            ConResPrintf(StdOut, IDS_IPROUTINGNO);

        if (pAdapter && pAdapter->HaveWins)
            ConResPrintf(StdOut, IDS_WINSPROXYYES);
        else
            ConResPrintf(StdOut, IDS_WINSPROXYNO);

        /* The search list is the registry list; without one the primary suffix is the list. */
        szBuffer[0] = ANSI_NULL;
        {
            HKEY hKey;
            DWORD dwType, dwSize = sizeof(szBuffer) - 1;

            if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                              "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters",
                              0, KEY_READ, &hKey) == ERROR_SUCCESS)
            {
                if (RegQueryValueExA(hKey, "SearchList", NULL, &dwType, (PBYTE)szBuffer, &dwSize) != ERROR_SUCCESS ||
                    dwType != REG_SZ)
                    szBuffer[0] = ANSI_NULL;
                else
                    szBuffer[dwSize < sizeof(szBuffer) ? dwSize : sizeof(szBuffer) - 1] = ANSI_NULL;
                RegCloseKey(hKey);
            }
        }
        if (szBuffer[0] != ANSI_NULL)
            PrintSearchList(szBuffer);
        else if (pszDomainName != NULL && pszDomainName[0] != ANSI_NULL)
            PrintSearchList(pszDomainName);
    }

    while (pAdapter)
    {
        BOOLEAN bConnected = IsAdapterConnected(pAdapter);
        PIP_ADDR_STRING pIPAddr;
        CHAR szSuffix[256];
        CHAR szDescription[256];

        PrintAdapterTypeAndName(pAdapter);

        if (GetPerAdapterInfo(pAdapter->Index, pPerAdapterInfo, &ulPerAdapterInfoLength) == ERROR_BUFFER_OVERFLOW)
        {
            pPerAdapterInfo = (PIP_PER_ADAPTER_INFO)HeapAlloc(ProcessHeap, 0, ulPerAdapterInfoLength);
            if (pPerAdapterInfo != NULL)
            {
                if (GetPerAdapterInfo(pAdapter->Index, pPerAdapterInfo, &ulPerAdapterInfoLength) != NO_ERROR)
                {
                    HeapFree(ProcessHeap, 0, pPerAdapterInfo);
                    pPerAdapterInfo = NULL;
                }
            }
        }

        GetConnectionDnsSuffix(pAdapter->AdapterName, szSuffix, _countof(szSuffix));

        if (!bConnected)
            ConResPrintf(StdOut, IDS_MEDIADISCONNECTED);
        ConResPrintf(StdOut, IDS_CONNECTIONDNSSUFFIX, szSuffix);

        if (bAll)
        {
            GetAdapterDescription(pAdapter->AdapterName, szDescription, _countof(szDescription));
            ConResPrintf(StdOut, IDS_DESCRIPTIONFMT, szDescription);

            ConResPrintf(StdOut, IDS_PHYSICALADDRESS, PrintMacAddr(pAdapter->Address));

            ConResPrintf(StdOut, pAdapter->DhcpEnabled ? IDS_DHCPYES : IDS_DHCPNO);

            if (pPerAdapterInfo != NULL)
                ConResPrintf(StdOut, pPerAdapterInfo->AutoconfigEnabled ? IDS_AUTOCONFIGYES : IDS_AUTOCONFIGNO);
        }

        if (bConnected)
        {
            /* IPv4 address and mask pairs */
            for (pIPAddr = &pAdapter->IpAddressList; pIPAddr != NULL; pIPAddr = pIPAddr->Next)
            {
                BOOL bAutoIp = !strncmp(pIPAddr->IpAddress.String, "169.254.", 8);

                if (!strcmp(pIPAddr->IpAddress.String, "0.0.0.0"))
                    continue;

                if (bAll)
                    StringCchPrintfA(szBuffer, _countof(szBuffer), "%s(Preferred) ", pIPAddr->IpAddress.String);
                else
                    StringCchCopyA(szBuffer, _countof(szBuffer), pIPAddr->IpAddress.String);

                ConResPrintf(StdOut, (bAutoIp && pAdapter->DhcpEnabled) ? IDS_AUTOIPV4 : IDS_IPADDRESS, szBuffer);
                ConResPrintf(StdOut, IDS_SUBNETMASK, pIPAddr->IpMask.String);
            }

            if (bAll && pAdapter->DhcpEnabled && strcmp(pAdapter->DhcpServer.IpAddress.String, "255.255.255.255"))
            {
                PWSTR DateTimeString;

                DateTimeString = timeToStr(pAdapter->LeaseObtained);
                ConResPrintf(StdOut, IDS_LEASEOBTAINED, DateTimeString ? DateTimeString : L"N/A");
                if (DateTimeString)
                    HeapFree(ProcessHeap, 0, DateTimeString);

                DateTimeString = timeToStr(pAdapter->LeaseExpires);
                ConResPrintf(StdOut, IDS_LEASEEXPIRES, DateTimeString ? DateTimeString : L"N/A");
                if (DateTimeString)
                    HeapFree(ProcessHeap, 0, DateTimeString);
            }

            if (strcmp(pAdapter->GatewayList.IpAddress.String, "0.0.0.0") &&
                pAdapter->GatewayList.IpAddress.String[0] != ANSI_NULL)
                PrintAddrList(IDS_DEFAULTGATEWAY, &pAdapter->GatewayList, TRUE);
            else
                ConResPrintf(StdOut, IDS_DEFAULTGATEWAY, "");

            if (bAll)
            {
                if (pAdapter->DhcpEnabled &&
                    strcmp(pAdapter->DhcpServer.IpAddress.String, "255.255.255.255") &&
                    strcmp(pAdapter->DhcpServer.IpAddress.String, "0.0.0.0"))
                    ConResPrintf(StdOut, IDS_DHCPSERVER, pAdapter->DhcpServer.IpAddress.String);

                if (pPerAdapterInfo != NULL && pPerAdapterInfo->DnsServerList.IpAddress.String[0] != ANSI_NULL &&
                    strcmp(pPerAdapterInfo->DnsServerList.IpAddress.String, "0.0.0.0"))
                    PrintAddrList(IDS_DNSSERVERS, &pPerAdapterInfo->DnsServerList, TRUE);
                else
                    PrintAddrList(IDS_DNSSERVERS, &pFixedInfo->DnsServerList, TRUE);

                if (pAdapter->HaveWins)
                {
                    ConResPrintf(StdOut, IDS_PRIMARYWINSSERVER, pAdapter->PrimaryWinsServer.IpAddress.String);
                    ConResPrintf(StdOut, IDS_SECONDARYWINSSERVER, pAdapter->SecondaryWinsServer.IpAddress.String);
                }

                ConResPrintf(StdOut, IsNetbiosEnabled(pAdapter->AdapterName) ? IDS_NETBIOSEN : IDS_NETBIOSDIS);
            }
        }

        if (pPerAdapterInfo)
            HeapFree(ProcessHeap, 0, pPerAdapterInfo);
        pPerAdapterInfo = NULL;
        ulPerAdapterInfoLength = 0;

        pAdapter = pAdapter->Next;
    }

done:
    if (pszDomainName)
        HeapFree(ProcessHeap, 0, pszDomainName);
    if (pFixedInfo)
        HeapFree(ProcessHeap, 0, pFixedInfo);
    if (pAdapterInfo)
        HeapFree(ProcessHeap, 0, pAdapterInfo);
    return Result;
}

/* Case-insensitive full match; '*' matches any run of characters, '?' exactly one. */
static
BOOL
MatchWildcard(
    _In_opt_ PCWSTR pszExpression,
    _In_opt_ PCWSTR pszName)
{
    PCWSTR pStar = NULL, pRetry = NULL;

    if (pszExpression == NULL)
        return TRUE;

    if (pszName == NULL)
        return FALSE;

    while (*pszName != UNICODE_NULL)
    {
        if (*pszExpression == L'*')
        {
            pStar = pszExpression++;
            pRetry = pszName;
        }
        else if (*pszExpression == L'?' ||
                 (*pszExpression != UNICODE_NULL && towlower(*pszExpression) == towlower(*pszName)))
        {
            pszExpression++;
            pszName++;
        }
        else if (pStar != NULL)
        {
            pszExpression = pStar + 1;
            pszName = ++pRetry;
        }
        else
        {
            return FALSE;
        }
    }

    while (*pszExpression == L'*')
        pszExpression++;

    return (*pszExpression == UNICODE_NULL);
}

/* Fetch the adapter list. Returns FALSE when there is none (message already printed). */
static
BOOL
GetAdapters(
    _Out_ PIP_ADAPTER_INFO *ppAdapterInfo,
    _Out_ PINT pResult)
{
    ULONG adaptOutBufLen = 0;
    ULONG ret;

    *ppAdapterInfo = NULL;
    *pResult = 0;

    ret = GetAdaptersInfo(NULL, &adaptOutBufLen);
    if (ret == ERROR_NO_DATA)
    {
        ConResPrintf(StdOut, IDS_DHCPNOADAPTER);
        return FALSE;
    }
    if (ret != ERROR_BUFFER_OVERFLOW)
    {
        DoFormatMessage(ret);
        *pResult = 1;
        return FALSE;
    }

    *ppAdapterInfo = (IP_ADAPTER_INFO *)HeapAlloc(ProcessHeap, 0, adaptOutBufLen);
    if (*ppAdapterInfo == NULL)
    {
        DoFormatMessage(ERROR_NOT_ENOUGH_MEMORY);
        *pResult = 1;
        return FALSE;
    }

    ret = GetAdaptersInfo(*ppAdapterInfo, &adaptOutBufLen);
    if (ret != NO_ERROR)
    {
        DoFormatMessage(ret);
        HeapFree(ProcessHeap, 0, *ppAdapterInfo);
        *ppAdapterInfo = NULL;
        *pResult = 1;
        return FALSE;
    }

    return TRUE;
}

/* /release and /renew [adapter] */
static
INT
DhcpOperation(
    PWSTR pszAdapterName,
    BOOL bRelease)
{
    PIP_ADAPTER_INFO pAdapterInfo = NULL;
    PIP_ADAPTER_INFO pAdapter = NULL;
    ULONG ret = 0;
    WCHAR szFriendlyName[MAX_PATH];
    WCHAR szUnicodeAdapterName[MAX_ADAPTER_NAME_LENGTH + 4];
    BOOL bFoundAdapter = FALSE;
    DWORD dwVersion;
    INT Result = 0;

    PrintHeader();

    if (!GetAdapters(&pAdapterInfo, &Result))
        return Result;

    DhcpCApiInitialize(&dwVersion);

    for (pAdapter = pAdapterInfo; pAdapter; pAdapter = pAdapter->Next)
    {
        GetAdapterFriendlyName(pAdapter->AdapterName, MAX_PATH, szFriendlyName);

        if (!MatchWildcard(pszAdapterName, szFriendlyName))
            continue;

        bFoundAdapter = TRUE;

        if (!IsAdapterConnected(pAdapter))
        {
            ConResPrintf(StdOut, IDS_DHCPNOTCONNECTED, szFriendlyName);
        }
        else if (!pAdapter->DhcpEnabled)
        {
            ConResPrintf(StdOut, IDS_DHCPNOTENABLED, szFriendlyName);
        }
        else if (bRelease)
        {
            if (strcmp(pAdapter->IpAddressList.IpAddress.String, "0.0.0.0"))
            {
                mbstowcs(szUnicodeAdapterName, pAdapter->AdapterName, strlen(pAdapter->AdapterName) + 1);

                /* Call DhcpReleaseParameters to release the IP address on the specified adapter. */
                ret = DhcpReleaseParameters(szUnicodeAdapterName);
                if (ret != NO_ERROR)
                {
                    ConResPrintf(StdOut, IDS_DHCPRELEASEERROR, szFriendlyName);
                    DoFormatMessage(ret);
                    Result = 1;
                }
            }
            else
            {
                ConResPrintf(StdOut, IDS_DHCPRELEASED, szFriendlyName);
            }
        }
        else
        {
            mbstowcs(szUnicodeAdapterName, pAdapter->AdapterName, strlen(pAdapter->AdapterName) + 1);

            /* Call DhcpAcquireParameters to renew the IP address on the specified adapter. */
            ret = DhcpAcquireParameters(szUnicodeAdapterName);
            if (ret != NO_ERROR)
            {
                ConResPrintf(StdOut, IDS_DHCPRENEWERROR, szFriendlyName);
                DoFormatMessage(ret);
                Result = 1;
            }
        }
    }

    DhcpCApiCleanup();

    if (!bFoundAdapter)
        ConResPrintf(StdOut, IDS_DHCPNOADAPTER);
    else if (ShowInfo(FALSE) != 0)
        Result = 1;

    HeapFree(ProcessHeap, 0, pAdapterInfo);
    return Result;
}

/* /release6 and /renew6: there are no DHCPv6 adapters. */
static
INT
Dhcp6Operation(
    PWSTR pszAdapterName)
{
    PrintHeader();
    ConResPrintf(StdOut, IDS_DHCPNOADAPTER);
    return 0;
}

static
INT
FlushDns(VOID)
{
    PrintHeader();

    if (DnsFlushResolverCache())
    {
        ConResPrintf(StdOut, IDS_DNSFLUSHSUCCESS);
        return 0;
    }

    ConResPrintf(StdOut, IDS_DNSFLUSHERROR);
    DoFormatMessage(GetLastError());
    return 1;
}

/* Refresh the DHCP leases of the connected DHCP adapters, then report like Windows. */
static
INT
RegisterDns(VOID)
{
    PIP_ADAPTER_INFO pAdapterInfo = NULL, pAdapter;
    WCHAR szUnicodeAdapterName[MAX_ADAPTER_NAME_LENGTH + 4];
    DWORD dwVersion;
    INT Result = 0;
    ULONG adaptOutBufLen = 0;

    PrintHeader();

    if (GetAdaptersInfo(NULL, &adaptOutBufLen) == ERROR_BUFFER_OVERFLOW)
    {
        pAdapterInfo = (IP_ADAPTER_INFO *)HeapAlloc(ProcessHeap, 0, adaptOutBufLen);
        if (pAdapterInfo && GetAdaptersInfo(pAdapterInfo, &adaptOutBufLen) == NO_ERROR)
        {
            DhcpCApiInitialize(&dwVersion);
            for (pAdapter = pAdapterInfo; pAdapter; pAdapter = pAdapter->Next)
            {
                if (pAdapter->DhcpEnabled && IsAdapterConnected(pAdapter))
                {
                    mbstowcs(szUnicodeAdapterName, pAdapter->AdapterName, strlen(pAdapter->AdapterName) + 1);
                    DhcpAcquireParameters(szUnicodeAdapterName);
                }
            }
            DhcpCApiCleanup();
        }
        if (pAdapterInfo)
            HeapFree(ProcessHeap, 0, pAdapterInfo);
    }

    ConResPrintf(StdOut, IDS_DNSREGISTER);
    return Result;
}


static
VOID
DisplayDnsRecord(
    PWSTR pszName,
    WORD wType)
{
    PDNS_RECORDW pQueryResults = NULL, pThisRecord, pNextRecord;
    WCHAR szBuffer[48];
    IN_ADDR Addr4;
    IN6_ADDR Addr6;
    DNS_STATUS Status;

    ConResPrintf(StdOut, IDS_DNSNAME, pszName);
    ConResPrintf(StdOut, IDS_DNSLINE);

    pQueryResults = NULL;
    Status = DnsQuery_W(pszName,
                        wType,
                        DNS_QUERY_NO_WIRE_QUERY,
                        NULL,
                        (PDNS_RECORD *)&pQueryResults,
                        NULL);
    if (Status != ERROR_SUCCESS)
    {
        if (Status == DNS_ERROR_RCODE_NAME_ERROR)
        {
            ConResPrintf(StdOut, IDS_DNSNONAME);
        }
        else if (Status == DNS_INFO_NO_RECORDS)
        {
            ConResPrintf(StdOut, IDS_DNSNORECORD, GetRecordTypeName(wType));
        }
        return;
    }

    pThisRecord = pQueryResults;
    while (pThisRecord != NULL)
    {
        pNextRecord = pThisRecord->pNext;

        ConResPrintf(StdOut, IDS_DNSRECORDNAME, pThisRecord->pName);
        ConResPrintf(StdOut, IDS_DNSRECORDTYPE, pThisRecord->wType);
        ConResPrintf(StdOut, IDS_DNSRECORDTTL, pThisRecord->dwTtl);
        ConResPrintf(StdOut, IDS_DNSRECORDLENGTH, pThisRecord->wDataLength);

        switch (pThisRecord->Flags.S.Section)
        {
            case DnsSectionQuestion:
                ConResPrintf(StdOut, IDS_DNSSECTIONQUESTION);
                break;

            case DnsSectionAnswer:
                ConResPrintf(StdOut, IDS_DNSSECTIONANSWER);
                break;

            case DnsSectionAuthority:
                ConResPrintf(StdOut, IDS_DNSSECTIONAUTHORITY);
                break;

            case DnsSectionAdditional:
                ConResPrintf(StdOut, IDS_DNSSECTIONADDITIONAL);
                break;
        }

        switch (pThisRecord->wType)
        {
            case DNS_TYPE_A:
                Addr4.S_un.S_addr = pThisRecord->Data.A.IpAddress;
                RtlIpv4AddressToStringW(&Addr4, szBuffer);
                ConResPrintf(StdOut, IDS_DNSTYPEA, szBuffer);
                break;

            case DNS_TYPE_NS:
                ConResPrintf(StdOut, IDS_DNSTYPENS, pThisRecord->Data.NS.pNameHost);
                break;

            case DNS_TYPE_CNAME:
                ConResPrintf(StdOut, IDS_DNSTYPECNAME, pThisRecord->Data.CNAME.pNameHost);
                break;

            case DNS_TYPE_SOA:
                ConResPrintf(StdOut, IDS_DNSTYPESOA1,
                             pThisRecord->Data.SOA.pNamePrimaryServer,
                             pThisRecord->Data.SOA.pNameAdministrator,
                             pThisRecord->Data.SOA.dwSerialNo);
                ConResPrintf(StdOut, IDS_DNSTYPESOA2,
                             pThisRecord->Data.SOA.dwRefresh,
                             pThisRecord->Data.SOA.dwRetry,
                             pThisRecord->Data.SOA.dwExpire,
                             pThisRecord->Data.SOA.dwDefaultTtl);
                break;

            case DNS_TYPE_PTR:
                ConResPrintf(StdOut, IDS_DNSTYPEPTR, pThisRecord->Data.PTR.pNameHost);
                break;

            case DNS_TYPE_MX:
                ConResPrintf(StdOut, IDS_DNSTYPEMX,
                             pThisRecord->Data.MX.pNameExchange,
                             pThisRecord->Data.MX.wPreference,
                             pThisRecord->Data.MX.Pad);
                break;

            case DNS_TYPE_AAAA:
                RtlCopyMemory(&Addr6, &pThisRecord->Data.AAAA.Ip6Address, sizeof(Addr6));
                RtlIpv6AddressToStringW(&Addr6, szBuffer);
                ConResPrintf(StdOut, IDS_DNSTYPEAAAA, szBuffer);
                break;

            case DNS_TYPE_ATMA:
                ConResPrintf(StdOut, IDS_DNSTYPEATMA);
                break;

            case DNS_TYPE_SRV:
                ConResPrintf(StdOut, IDS_DNSTYPESRV,
                             pThisRecord->Data.SRV.pNameTarget,
                             pThisRecord->Data.SRV.wPriority,
                             pThisRecord->Data.SRV.wWeight,
                             pThisRecord->Data.SRV.wPort);
                break;
        }
        ConPuts(StdOut, L"\n\n");

        pThisRecord = pNextRecord;
    }

    DnsRecordListFree((PDNS_RECORD)pQueryResults, DnsFreeRecordList);
}

static
INT
DisplayDns(VOID)
{
    PDNS_CACHE_ENTRY DnsEntry = NULL, pThisEntry, pNextEntry;

    PrintHeader();

    if (!DnsGetCacheDataTable(&DnsEntry))
    {
        ConResPrintf(StdOut, IDS_DNSDISPLAYERROR);
        return 1;
    }

    if (DnsEntry == NULL)
        return 0;

    pThisEntry = DnsEntry;
    while (pThisEntry != NULL)
    {
        pNextEntry = pThisEntry->pNext;

        if (pThisEntry->wType1 != DNS_TYPE_ZERO)
            DisplayDnsRecord(pThisEntry->pszName, pThisEntry->wType1);

        if (pThisEntry->wType2 != DNS_TYPE_ZERO)
            DisplayDnsRecord(pThisEntry->pszName, pThisEntry->wType2);

        if (pThisEntry->pszName)
            LocalFree(pThisEntry->pszName);
        LocalFree(pThisEntry);

        pThisEntry = pNextEntry;
    }

    return 0;
}

/* /showclassid adapter and /showclassid6 adapter */
static
INT
ShowClassId(
    PWSTR pszAdapterName,
    BOOL bIpv6)
{
    PIP_ADAPTER_INFO pAdapterInfo = NULL, pAdapter;
    WCHAR szFriendlyName[MAX_PATH];
    CHAR szClassId[256];
    BOOL bFound = FALSE;
    INT Result = 0;

    PrintHeader();

    if (!GetAdapters(&pAdapterInfo, &Result))
        return Result;

    for (pAdapter = pAdapterInfo; pAdapter; pAdapter = pAdapter->Next)
    {
        GetAdapterFriendlyName(pAdapter->AdapterName, MAX_PATH, szFriendlyName);

        if (!MatchWildcard(pszAdapterName, szFriendlyName))
            continue;

        bFound = TRUE;

        if (bIpv6)
        {
            ConResPrintf(StdOut, IDS_CLASSV6NONE, szFriendlyName);
        }
        else if (GetTcpipInterfaceString(pAdapter->AdapterName, "DhcpClassId", szClassId, _countof(szClassId)))
        {
            WCHAR szClassIdW[256];

            mbstowcs(szClassIdW, szClassId, _countof(szClassIdW) - 1);
            szClassIdW[_countof(szClassIdW) - 1] = UNICODE_NULL;
            ConResPrintf(StdOut, IDS_CLASSV4LIST, szFriendlyName, szClassIdW);
        }
        else
        {
            ConResPrintf(StdOut, IDS_CLASSV4NONE, szFriendlyName);
        }
    }

    if (!bFound)
        ConResPrintf(StdOut, IDS_DHCPNOADAPTER);

    HeapFree(ProcessHeap, 0, pAdapterInfo);
    return 0;
}

static
INT
SetClassId(
    PWSTR pszAdapterName,
    PWSTR pszClassId)
{
    PIP_ADAPTER_INFO pAdapterInfo = NULL;
    PIP_ADAPTER_INFO pAdapter = NULL, pFoundAdapter = NULL;
    ULONG ret = 0;
    WCHAR szFriendlyName[MAX_PATH];
    WCHAR szKeyName[256];
    WCHAR szFoundName[MAX_PATH];
    WCHAR szUnicodeAdapterName[MAX_ADAPTER_NAME_LENGTH + 4];
    HKEY hKey;
    DHCP_PNP_EVENT PnpEvent;
    INT Result = 0;

    PrintHeader();

    if (!GetAdapters(&pAdapterInfo, &Result))
        return Result;

    szFoundName[0] = UNICODE_NULL;
    for (pAdapter = pAdapterInfo; pAdapter; pAdapter = pAdapter->Next)
    {
        GetAdapterFriendlyName(pAdapter->AdapterName, MAX_PATH, szFriendlyName);

        if (MatchWildcard(pszAdapterName, szFriendlyName) && IsAdapterConnected(pAdapter))
        {
            pFoundAdapter = pAdapter;
            wcscpy(szFoundName, szFriendlyName);
            break;
        }
    }

    if (pFoundAdapter)
    {
        _swprintf(szKeyName,
                  L"System\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\%S",
                  pFoundAdapter->AdapterName);

        ret = RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                            szKeyName,
                            0,
                            KEY_WRITE,
                            &hKey);
        if (ret != ERROR_SUCCESS)
        {
            ConResPrintf(StdOut, IDS_DHCPSETIDERROR, szFoundName);
            DoFormatMessage(ret);
            Result = 1;
            goto done;
        }

        if (pszClassId == NULL)
            pszClassId = L"";

        ret = RegSetValueExW(hKey,
                             L"DhcpClassId",
                             0, REG_SZ,
                             (PBYTE)pszClassId,
                             (DWORD)((wcslen(pszClassId) + 1) * sizeof(WCHAR)));
        RegCloseKey(hKey);
        if (ret != ERROR_SUCCESS)
        {
            ConResPrintf(StdOut, IDS_DHCPSETIDERROR, szFoundName);
            DoFormatMessage(ret);
            Result = 1;
            goto done;
        }

        mbstowcs(szUnicodeAdapterName, pFoundAdapter->AdapterName, strlen(pFoundAdapter->AdapterName) + 1);

        ZeroMemory(&PnpEvent, sizeof(PnpEvent));
        PnpEvent.Unknown5 = 1;

        ret = DhcpHandlePnPEvent(0,
                                 1,
                                 szUnicodeAdapterName,
                                 &PnpEvent,
                                 0);
        if (ret != ERROR_SUCCESS)
        {
            ConResPrintf(StdOut, IDS_DHCPSETIDERROR, szFoundName);
            DoFormatMessage(ret);
            Result = 1;
            goto done;
        }

        ConResPrintf(StdOut, IDS_DHCPSETIDSUCCESS, szFoundName);
    }
    else
    {
        ConResPrintf(StdOut, IDS_DHCPNOADAPTER);
    }

done:
    HeapFree(ProcessHeap, 0, pAdapterInfo);
    return Result;
}

/* /setclassid6: there are no DHCPv6 adapters. */
static
INT
SetClassId6(VOID)
{
    PrintHeader();
    ConResPrintf(StdOut, IDS_DHCPNOADAPTER);
    return 0;
}

static
INT
Usage(
    _In_ BOOL Error)
{
    if (Error)
        ConResPrintf(StdOut, IDS_CMDLINEERROR);
    ConResPrintf(StdOut, IDS_USAGE);
    return 1;
}

/* Switches start with '/' or '-' and are matched whole, ignoring case. */
static
BOOL
IsSwitch(
    _In_ PCWSTR pszArg,
    _In_ PCWSTR pszName)
{
    return ((pszArg[0] == L'/' || pszArg[0] == L'-') && !_wcsicmp(&pszArg[1], pszName));
}

int wmain(int argc, wchar_t *argv[])
{
    BOOL DoAllCompartments = FALSE;
    INT i = 1, nArgs, Result;
    PWSTR pszVerb;

    /* Initialize the Console Standard Streams */
    ConInitStdStreams();

    hInstance = GetModuleHandle(NULL);
    ProcessHeap = GetProcessHeap();

    if (argc > 1 && IsSwitch(argv[1], L"allcompartments"))
    {
        DoAllCompartments = TRUE;
        i++;
    }

    nArgs = argc - i;
    pszVerb = (nArgs > 0) ? argv[i] : NULL;

    if (pszVerb == NULL)
    {
        /* Default behaviour if no options are given */
        PrintHeader();
        if (DoAllCompartments)
            ConResPrintf(StdOut, IDS_COMPARTMENT);
        return ShowInfo(FALSE);
    }

    if (IsSwitch(pszVerb, L"?"))
        return Usage(DoAllCompartments || nArgs != 1 ? TRUE : FALSE);

    if (IsSwitch(pszVerb, L"all"))
    {
        if (nArgs != 1)
            return Usage(TRUE);

        PrintHeader();
        if (DoAllCompartments)
            ConResPrintf(StdOut, IDS_COMPARTMENT);
        return ShowInfo(TRUE);
    }

    /* /allcompartments only goes with the default view and /all */
    if (DoAllCompartments)
        return Usage(TRUE);

    if (IsSwitch(pszVerb, L"release") || IsSwitch(pszVerb, L"renew"))
    {
        if (nArgs > 2)
            return Usage(TRUE);
        return DhcpOperation(nArgs == 2 ? argv[i + 1] : NULL, IsSwitch(pszVerb, L"release"));
    }

    if (IsSwitch(pszVerb, L"release6") || IsSwitch(pszVerb, L"renew6"))
    {
        if (nArgs > 2)
            return Usage(TRUE);
        return Dhcp6Operation(nArgs == 2 ? argv[i + 1] : NULL);
    }

    if (IsSwitch(pszVerb, L"flushdns"))
        return (nArgs == 1) ? FlushDns() : Usage(TRUE);

    if (IsSwitch(pszVerb, L"registerdns"))
        return (nArgs == 1) ? RegisterDns() : Usage(TRUE);

    if (IsSwitch(pszVerb, L"displaydns"))
        return (nArgs == 1) ? DisplayDns() : Usage(TRUE);

    if (IsSwitch(pszVerb, L"showclassid") || IsSwitch(pszVerb, L"showclassid6"))
    {
        if (nArgs != 2)
            return Usage(TRUE);
        return ShowClassId(argv[i + 1], IsSwitch(pszVerb, L"showclassid6"));
    }

    if (IsSwitch(pszVerb, L"setclassid"))
    {
        if (nArgs != 2 && nArgs != 3)
            return Usage(TRUE);
        Result = SetClassId(argv[i + 1], nArgs == 3 ? argv[i + 2] : NULL);
        return Result;
    }

    if (IsSwitch(pszVerb, L"setclassid6"))
    {
        if (nArgs != 2 && nArgs != 3)
            return Usage(TRUE);
        return SetClassId6();
    }

    return Usage(TRUE);
}
