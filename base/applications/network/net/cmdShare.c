/*
 * COPYRIGHT:       See COPYING in the top level directory
 * PROJECT:         ReactOS net command
 * FILE:            base/applications/network/net/cmdShare.c
 * PROGRAMMERS:     Eric Kohl <eric.kohl@reactos.org>
 */

#include "net.h"

#include <aclapi.h>
#include <sddl.h>

#ifndef _SHARE_INFO_1005_DEFINED
#define _SHARE_INFO_1005_DEFINED
typedef struct _SHARE_INFO_1005
{
    DWORD shi1005_flags;
} SHARE_INFO_1005, *PSHARE_INFO_1005, *LPSHARE_INFO_1005;
#endif

/* Share caching flags (SHI1005_FLAGS_*) */
#define CACHE_MANUAL        0x0000
#define CACHE_DOCUMENTS     0x0010
#define CACHE_PROGRAMS      0x0020
#define CACHE_NONE          0x0030
#define CACHE_BRANCHCACHE   0x2000
#define CACHE_MASK          0x2030

#define ACCESS_READ_MASK    0x001200A9
#define ACCESS_CHANGE_MASK  0x001301BF
#define ACCESS_FULL_MASK    0x001F01FF

#define MAX_GRANTS          16
#define MAX_SHARE_NAME      80

#define MSG_MISSING_VALUE   3505
#define MSG_OPTION_UNKNOWN  3506
#define MSG_INVALID_VALUE   3952
#define MSG_NO_MATCH        3719

typedef struct _GRANT
{
    PWSTR pszUser;
    DWORD dwMask;
} GRANT;

typedef struct _SHARE_OPTIONS
{
    PWSTR pszServer;
    PWSTR pszName;
    PWSTR pszPath;
    PWSTR pszRemark;
    DWORD dwMaxUses;
    DWORD dwCache;
    BOOL bDelete;
    BOOL bHaveRemark;
    BOOL bHaveUsers;
    BOOL bHaveCache;
    GRANT Grants[MAX_GRANTS];
    DWORD cGrants;
} SHARE_OPTIONS;


static
INT
SyntaxError(VOID)
{
    return PrintCommandSyntax(MSG_SHARE_SYNTAX, 0, NULL);
}


static
INT
UnknownOption(
    PCWSTR pszOption)
{
    WCHAR szOption[64];
    PWSTR pColon;

    StringCchCopyW(szOption, ARRAYSIZE(szOption), pszOption);
    pColon = wcschr(szOption, L':');
    if (pColon)
        *pColon = UNICODE_NULL;
    _wcsupr(szOption);

    return PrintCommandSyntax(MSG_SHARE_SYNTAX, MSG_OPTION_UNKNOWN, szOption);
}


static
INT
MissingValue(VOID)
{
    return PrintCommandSyntax(MSG_SHARE_SYNTAX, MSG_MISSING_VALUE, NULL);
}


static
INT
InvalidValue(
    PCWSTR pszOption)
{
    return PrintCommandError(MSG_INVALID_VALUE, pszOption);
}


static
INT
ShareError(
    NET_API_STATUS Status)
{
    PrintErrorMessage(Status);
    return 2;
}


static
BOOL
IsOption(
    PCWSTR pszArg,
    PCWSTR pszName,
    DWORD dwMinLength,
    PCWSTR *ppszValue)
{
    PCWSTR pColon;
    size_t len;

    if (pszArg[0] != L'/')
        return FALSE;

    pColon = wcschr(pszArg, L':');
    len = pColon ? (size_t)(pColon - pszArg - 1) : wcslen(pszArg + 1);
    if (len < dwMinLength || len > wcslen(pszName))
        return FALSE;

    if (_wcsnicmp(pszArg + 1, pszName, len) != 0)
        return FALSE;

    *ppszValue = pColon ? pColon + 1 : NULL;
    return TRUE;
}


static
BOOL
ParseNumber(
    PCWSTR pszValue,
    PDWORD pdwNumber)
{
    PWSTR pEnd;
    unsigned long long value;

    if (pszValue == NULL || *pszValue < L'0' || *pszValue > L'9')
        return FALSE;

    value = _wcstoui64(pszValue, &pEnd, 10);
    if (*pEnd != UNICODE_NULL || value == 0 || value >= 0xFFFFFFFFULL)
        return FALSE;

    *pdwNumber = (DWORD)value;
    return TRUE;
}


static
BOOL
IsAsciiLetter(
    WCHAR ch)
{
    return (ch >= L'A' && ch <= L'Z') || (ch >= L'a' && ch <= L'z');
}


/* A drive letter with a colon, or LPT1 to LPT9 and COM1 to COM9 with trailing dots and a final colon allowed */
static
BOOL
IsDeviceName(
    PCWSTR pszName)
{
    PCWSTR p;

    if (IsAsciiLetter(pszName[0]) && pszName[1] == L':' && pszName[2] == UNICODE_NULL)
        return TRUE;

    if (_wcsnicmp(pszName, L"LPT", 3) != 0 && _wcsnicmp(pszName, L"COM", 3) != 0)
        return FALSE;

    if (pszName[3] < L'1' || pszName[3] > L'9')
        return FALSE;

    p = &pszName[4];
    while (*p == L'.')
        p++;
    if (*p == L':')
        p++;

    return *p == UNICODE_NULL;
}


/* The characters a share name may not have: the command prints its usage text for such a name */
static
BOOL
HasIllegalNameChar(
    PCWSTR pszName)
{
    PCWSTR p;

    for (p = pszName; *p != UNICODE_NULL; p++)
    {
        if (*p < L' ' || wcschr(L"\"/\\[]:|<>+=;,?*", *p) != NULL)
            return TRUE;
    }

    return FALSE;
}


/* What the command takes as the resource of a share: a device, or a path that has no wildcards and no trailing separator */
static
BOOL
IsSharePath(
    PCWSTR pszPath)
{
    SIZE_T Length = wcslen(pszPath);

    if (IsDeviceName(pszPath))
        return TRUE;

    if (wcspbrk(pszPath, L"*?") != NULL)
        return FALSE;

    if (IsAsciiLetter(pszPath[0]) && pszPath[1] == L':' && (pszPath[2] == L'\\' || pszPath[2] == L'/'))
    {
        /* Another colon makes it a path the server has to judge */
        if (wcschr(&pszPath[2], L':') != NULL)
            return TRUE;

        return Length == 3 || (pszPath[Length - 1] != L'\\' && pszPath[Length - 1] != L'/');
    }

    /* \\.\ names a device or a drive path directly */
    if (_wcsnicmp(pszPath, L"\\\\.\\", 4) == 0)
        return Length > 4 && pszPath[Length - 1] != L'\\' && pszPath[Length - 1] != L'/';

    return FALSE;
}


static
VOID
PrintExeText(
    DWORD dwMessage)
{
    PWSTR pText = GetExeMessage(dwMessage);

    if (pText)
    {
        ConPuts(StdOut, pText);
        LocalFree(pText);
    }
}


static
VOID
CachingMessage(
    DWORD dwFlags,
    PDWORD pdwMessage)
{
    switch (dwFlags & CACHE_MASK)
    {
        case CACHE_DOCUMENTS:
            *pdwMessage = MSG_SHARE_CACHE_DOCUMENTS;
            break;

        case CACHE_PROGRAMS:
            *pdwMessage = MSG_SHARE_CACHE_PROGRAMS;
            break;

        case CACHE_NONE:
            *pdwMessage = MSG_SHARE_CACHE_NONE;
            break;

        default:
            *pdwMessage = (dwFlags & CACHE_BRANCHCACHE) ? MSG_SHARE_CACHE_BRANCHCACHE : MSG_SHARE_CACHE_MANUAL;
            break;
    }
}


static
NET_API_STATUS
QueryCaching(
    PWSTR pszServer,
    PWSTR pszName,
    PDWORD pdwFlags)
{
    PSHARE_INFO_1005 pInfo = NULL;
    NET_API_STATUS Status;

    *pdwFlags = CACHE_MANUAL;

    Status = NetShareGetInfo(pszServer, pszName, 1005, (LPBYTE*)&pInfo);
    if (Status == NERR_Success)
    {
        *pdwFlags = pInfo->shi1005_flags;
        NetApiBufferFree(pInfo);
    }

    return Status;
}


/* For display: a share whose caching cannot be read shows the default */
static
DWORD
GetCaching(
    PWSTR pszServer,
    PWSTR pszName)
{
    DWORD dwFlags;

    QueryCaching(pszServer, pszName, &dwFlags);
    return dwFlags;
}


static
VOID
PrintShareRow(
    PWSTR pszServer,
    PSHARE_INFO_2 pInfo)
{
    DWORD dwFlags = GetCaching(pszServer, pInfo->shi2_netname);
    DWORD dwMessage;
    BOOL bCache = ((dwFlags & CACHE_MASK) != CACHE_MANUAL);
    PCWSTR pszPath = pInfo->shi2_path ? pInfo->shi2_path : L"";
    PCWSTR pszRemark = pInfo->shi2_remark ? pInfo->shi2_remark : L"";
    size_t lenRemark = wcslen(pszRemark);

    CachingMessage(dwFlags, &dwMessage);

    /* The columns are 12, 31 and 34 wide; a longer name or path continues on the next line */
    if (wcslen(pInfo->shi2_netname) > 12)
    {
        ConPrintf(StdOut, L"%s\n", pInfo->shi2_netname);
        PrintPadding(L' ', 13);
    }
    else
    {
        ConPrintf(StdOut, L"%-12s ", pInfo->shi2_netname);
    }

    if (wcslen(pszPath) > 31)
    {
        ConPrintf(StdOut, L"%s\n", pszPath);
        PrintPadding(L' ', 45);
    }
    else
    {
        ConPrintf(StdOut, L"%-31s ", pszPath);
    }

    if (lenRemark > 34)
        ConPrintf(StdOut, L"%.31s...", pszRemark);
    else if (lenRemark > 0)
        ConPrintf(StdOut, L"%-34s", pszRemark);

    if (bCache)
    {
        if (lenRemark > 0)
        {
            ConPuts(StdOut, L"\n");
            PrintPadding(L' ', 45);
        }
        PrintExeText(dwMessage);
    }

    ConPuts(StdOut, L"\n");
}


static
INT
EnumerateShares(
    PWSTR pszServer)
{
    PSHARE_INFO_2 pBuffer = NULL;
    DWORD dwRead = 0, dwTotal = 0;
    DWORD ResumeHandle = 0, i;
    NET_API_STATUS Status;
    BOOL bHeader = FALSE;

    do
    {
        Status = NetShareEnum(pszServer,
                              2,
                              (LPBYTE*)&pBuffer,
                              MAX_PREFERRED_LENGTH,
                              &dwRead,
                              &dwTotal,
                              &ResumeHandle);
        if ((Status != NERR_Success) && (Status != ERROR_MORE_DATA))
            return ShareError(Status);

        if (!bHeader)
        {
            ConPuts(StdOut, L"\n");
            PrintMessageString(4730);
            ConPuts(StdOut, L"\n");
            PrintPadding(L'-', 79);
            ConPuts(StdOut, L"\n");
            bHeader = TRUE;
        }

        for (i = 0; i < dwRead; i++)
            PrintShareRow(pszServer, &pBuffer[i]);

        NetApiBufferFree(pBuffer);
        pBuffer = NULL;
    }
    while (Status == ERROR_MORE_DATA);

    PrintMessageString(3500);
    ConPuts(StdOut, L"\n");

    return 0;
}


static
VOID
PrintPermissions(
    PWSTR pszServer,
    PWSTR pszName,
    DWORD nPaddedLength)
{
    PSHARE_INFO_502 pInfo = NULL;
    PACL pDacl = NULL;
    BOOL bPresent = FALSE, bDefaulted = FALSE;
    BOOL bFirst = TRUE;
    DWORD i;

    if (NetShareGetInfo(pszServer, pszName, 502, (LPBYTE*)&pInfo) != NERR_Success)
        return;

    if (pInfo->shi502_security_descriptor == NULL)
    {
        /* The server returns no descriptor for a share created without one: Everyone, full for the special shares, read for the others */
        SID_IDENTIFIER_AUTHORITY WorldAuthority = {SECURITY_WORLD_SID_AUTHORITY};
        PSID pWorld = NULL;
        WCHAR szName[256] = L"Everyone", szDomain[256];
        DWORD cchName = ARRAYSIZE(szName), cchDomain = ARRAYSIZE(szDomain);
        SID_NAME_USE Use;

        if (AllocateAndInitializeSid(&WorldAuthority, 1, SECURITY_WORLD_RID, 0, 0, 0, 0, 0, 0, 0, &pWorld))
        {
            if (!LookupAccountSidW(pszServer, pWorld, szName, &cchName, szDomain, &cchDomain, &Use))
                StringCchCopyW(szName, ARRAYSIZE(szName), L"Everyone");
            FreeSid(pWorld);
        }

        PrintPaddedMessageString(4734, nPaddedLength);
        ConPrintf(StdOut, L"%s, %s\n", szName, (pInfo->shi502_type & STYPE_SPECIAL) ? L"FULL" : L"READ");
        NetApiBufferFree(pInfo);
        return;
    }

    if (!GetSecurityDescriptorDacl(pInfo->shi502_security_descriptor, &bPresent, &pDacl, &bDefaulted) ||
        !bPresent || pDacl == NULL)
    {
        NetApiBufferFree(pInfo);
        return;
    }

    for (i = 0; i < pDacl->AceCount; i++)
    {
        PACCESS_ALLOWED_ACE pAce;
        WCHAR szName[256], szDomain[256];
        DWORD cchName = ARRAYSIZE(szName), cchDomain = ARRAYSIZE(szDomain);
        SID_NAME_USE Use;
        PCWSTR pszRight;

        if (!GetAce(pDacl, i, (PVOID*)&pAce) || pAce->Header.AceType != ACCESS_ALLOWED_ACE_TYPE)
            continue;

        if (!LookupAccountSidW(pszServer, (PSID)&pAce->SidStart, szName, &cchName, szDomain, &cchDomain, &Use))
        {
            /* An account that no longer exists is shown by its SID */
            PWSTR pszSid = NULL;

            if (!ConvertSidToStringSidW((PSID)&pAce->SidStart, &pszSid))
                continue;
            StringCchCopyW(szName, ARRAYSIZE(szName), pszSid);
            szDomain[0] = UNICODE_NULL;
            LocalFree(pszSid);
        }

        switch (pAce->Mask)
        {
            case ACCESS_FULL_MASK:
                pszRight = L"FULL";
                break;

            case ACCESS_CHANGE_MASK:
                pszRight = L"CHANGE";
                break;

            case ACCESS_READ_MASK:
                pszRight = L"READ";
                break;

            default:
                pszRight = L"";
                break;
        }

        if (bFirst)
            PrintPaddedMessageString(4734, nPaddedLength);
        else
            PrintPadding(L' ', nPaddedLength);
        bFirst = FALSE;

        /* A mask that is none of the three named rights prints the account alone */
        ConPrintf(StdOut, L"%s%s%s%s%s\n",
                  szDomain, szDomain[0] ? L"\\" : L"", szName,
                  pszRight[0] ? L", " : L"", pszRight);
    }

    NetApiBufferFree(pInfo);
}


static
INT
DisplayShare(
    PWSTR pszServer,
    PWSTR pszName)
{
    PSHARE_INFO_2 pBuffer = NULL;
    const DWORD nPaddedLength = 18;
    DWORD dwMessage;
    NET_API_STATUS Status;

    Status = NetShareGetInfo(pszServer, pszName, 2, (LPBYTE*)&pBuffer);
    if (Status != NERR_Success)
        return ShareError(Status);

    PrintPaddedMessageString(4731, nPaddedLength);
    ConPrintf(StdOut, L"%s\n", pBuffer->shi2_netname);

    PrintPaddedMessageString(4339, nPaddedLength);
    ConPrintf(StdOut, L"%s\n", pBuffer->shi2_path ? pBuffer->shi2_path : L"");

    PrintPaddedMessageString(4334, nPaddedLength);
    ConPrintf(StdOut, L"%s\n", pBuffer->shi2_remark ? pBuffer->shi2_remark : L"");

    PrintPaddedMessageString(4735, nPaddedLength);
    if (pBuffer->shi2_max_uses == (DWORD)-1)
        PrintMessageString(4736);
    else
        ConPrintf(StdOut, L"%lu", pBuffer->shi2_max_uses);
    ConPuts(StdOut, L"\n");

    PrintPaddedMessageString(4737, nPaddedLength);
    if (pBuffer->shi2_current_uses > 0)
        ConPrintf(StdOut, L"%lu", pBuffer->shi2_current_uses);
    ConPuts(StdOut, L"\n");

    PrintPaddedMessageString(4739, nPaddedLength);
    CachingMessage(GetCaching(pszServer, pszName), &dwMessage);
    PrintExeText(dwMessage);
    ConPuts(StdOut, L"\n");

    NetApiBufferFree(pBuffer);

    PrintPermissions(pszServer, pszName, nPaddedLength);

    ConPuts(StdOut, L"\n");
    PrintMessageString(3500);
    ConPuts(StdOut, L"\n");

    return 0;
}


static
NET_API_STATUS
MakeShareDescriptor(
    SHARE_OPTIONS *pOptions,
    PSECURITY_DESCRIPTOR *ppDescriptor,
    PACL *ppAcl)
{
    EXPLICIT_ACCESS_W Access[MAX_GRANTS];
    PSECURITY_DESCRIPTOR pDescriptor;
    DWORD i, dwError;

    ZeroMemory(Access, sizeof(Access));
    for (i = 0; i < pOptions->cGrants; i++)
    {
        BuildExplicitAccessWithNameW(&Access[i],
                                     pOptions->Grants[i].pszUser,
                                     pOptions->Grants[i].dwMask,
                                     GRANT_ACCESS,
                                     NO_INHERITANCE);
    }

    dwError = SetEntriesInAclW(pOptions->cGrants, Access, NULL, ppAcl);
    if (dwError != ERROR_SUCCESS)
        return dwError;

    /* No grants give no ACL at all, which would be a NULL DACL (full access
     * for everyone): a share without grants gets an empty DACL */
    if (*ppAcl == NULL)
    {
        *ppAcl = LocalAlloc(LPTR, sizeof(ACL));
        if (*ppAcl == NULL || !InitializeAcl(*ppAcl, sizeof(ACL), ACL_REVISION))
        {
            dwError = *ppAcl ? GetLastError() : ERROR_NOT_ENOUGH_MEMORY;
            if (*ppAcl)
                LocalFree(*ppAcl);
            *ppAcl = NULL;
            return dwError;
        }
    }

    pDescriptor = LocalAlloc(LPTR, SECURITY_DESCRIPTOR_MIN_LENGTH);
    if (pDescriptor == NULL ||
        !InitializeSecurityDescriptor(pDescriptor, SECURITY_DESCRIPTOR_REVISION) ||
        !SetSecurityDescriptorDacl(pDescriptor, TRUE, *ppAcl, FALSE))
    {
        dwError = GetLastError();
        if (pDescriptor)
            LocalFree(pDescriptor);
        LocalFree(*ppAcl);
        *ppAcl = NULL;
        return dwError ? dwError : ERROR_NOT_ENOUGH_MEMORY;
    }

    *ppDescriptor = pDescriptor;
    return ERROR_SUCCESS;
}


static
INT
AddShare(
    SHARE_OPTIONS *pOptions)
{
    SHARE_INFO_502 Info;
    SHARE_INFO_1005 Flags;
    PSECURITY_DESCRIPTOR pDescriptor = NULL;
    PACL pAcl = NULL;
    NET_API_STATUS Status;
    DWORD dwLevel = 2;

    ZeroMemory(&Info, sizeof(Info));
    Info.shi502_netname = pOptions->pszName;
    Info.shi502_type = STYPE_DISKTREE;
    Info.shi502_remark = pOptions->pszRemark;
    Info.shi502_max_uses = pOptions->bHaveUsers ? pOptions->dwMaxUses : (DWORD)-1;
    Info.shi502_path = pOptions->pszPath;

    if (pOptions->cGrants > 0)
    {
        Status = MakeShareDescriptor(pOptions, &pDescriptor, &pAcl);
        if (Status != ERROR_SUCCESS)
            return ShareError(Status);

        Info.shi502_security_descriptor = pDescriptor;
        dwLevel = 502;
    }

    Status = NetShareAdd(pOptions->pszServer, dwLevel, (LPBYTE)&Info, NULL);

    if (pDescriptor)
        LocalFree(pDescriptor);
    if (pAcl)
        LocalFree(pAcl);

    if (Status != NERR_Success)
        return ShareError(Status);

    if (pOptions->bHaveCache && pOptions->dwCache != CACHE_MANUAL)
    {
        Flags.shi1005_flags = pOptions->dwCache;
        Status = NetShareSetInfo(pOptions->pszServer, pOptions->pszName, 1005, (LPBYTE)&Flags, NULL);
        if (Status != NERR_Success)
        {
            /* Without the caching setting the share is not what was asked for, and a retry would find its name taken */
            NetShareDel(pOptions->pszServer, pOptions->pszName, 0);
            return ShareError(Status);
        }
    }

    PrintMessageStringV(4656, pOptions->pszName);
    ConPuts(StdOut, L"\n");
    return 0;
}


static
INT
ModifyShare(
    SHARE_OPTIONS *pOptions)
{
    NET_API_STATUS Status;

    if (pOptions->bHaveRemark || pOptions->bHaveUsers)
    {
        PSHARE_INFO_2 pInfo = NULL;
        DWORD dwParmErr = 0;

        /* The server replaces all fields, so the unchanged ones are passed back */
        Status = NetShareGetInfo(pOptions->pszServer, pOptions->pszName, 2, (LPBYTE*)&pInfo);
        if (Status != NERR_Success)
            return ShareError(Status);

        if (pOptions->bHaveRemark)
            pInfo->shi2_remark = pOptions->pszRemark;
        if (pOptions->bHaveUsers)
            pInfo->shi2_max_uses = pOptions->dwMaxUses;

        Status = NetShareSetInfo(pOptions->pszServer, pOptions->pszName, 2, (LPBYTE)pInfo, &dwParmErr);
        NetApiBufferFree(pInfo);
        if (Status != NERR_Success)
            return ShareError(Status);
    }

    if (pOptions->bHaveCache)
    {
        SHARE_INFO_1005 Info;

        DWORD dwOld;

        /* The call sets the whole flags word: keep the settings that are not about caching */
        Status = QueryCaching(pOptions->pszServer, pOptions->pszName, &dwOld);
        if (Status != NERR_Success)
            return ShareError(Status);

        Info.shi1005_flags = (dwOld & ~CACHE_MASK) | pOptions->dwCache;
        Status = NetShareSetInfo(pOptions->pszServer, pOptions->pszName, 1005, (LPBYTE)&Info, NULL);
        if (Status != NERR_Success)
            return ShareError(Status);
    }

    PrintMessageString(3500);
    ConPuts(StdOut, L"\n");
    return 0;
}


static
INT
DeleteShare(
    SHARE_OPTIONS *pOptions)
{
    NET_API_STATUS Status;

    if (IsDeviceName(pOptions->pszName))
    {
        DWORD dwType;

        /* A device that is not shared is reported before anything is looked up by path */
        Status = NetShareCheck(pOptions->pszServer, pOptions->pszName, &dwType);
        if (Status != NERR_Success)
            return ShareError(Status);
    }

    if (IsSharePath(pOptions->pszName))
    {
        PSHARE_INFO_2 pBuffer = NULL;
        PWSTR *ppszNames = NULL, *ppszNew;
        DWORD dwRead = 0, dwTotal = 0, ResumeHandle = 0, i, cNames = 0;
        INT result = 0;

        /* The matching shares are collected first: deleting while enumerating would move the resume position */
        do
        {
            Status = NetShareEnum(pOptions->pszServer, 2, (LPBYTE*)&pBuffer, MAX_PREFERRED_LENGTH,
                                  &dwRead, &dwTotal, &ResumeHandle);
            if ((Status != NERR_Success) && (Status != ERROR_MORE_DATA))
            {
                result = ShareError(Status);
                goto done;
            }

            for (i = 0; i < dwRead; i++)
            {
                if (pBuffer[i].shi2_path == NULL ||
                    _wcsicmp(pBuffer[i].shi2_path, pOptions->pszName) != 0)
                    continue;

                if (ppszNames == NULL)
                    ppszNew = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (cNames + 1) * sizeof(PWSTR));
                else
                    ppszNew = HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, ppszNames, (cNames + 1) * sizeof(PWSTR));
                if (ppszNew == NULL)
                {
                    NetApiBufferFree(pBuffer);
                    result = ShareError(ERROR_NOT_ENOUGH_MEMORY);
                    goto done;
                }
                ppszNames = ppszNew;
                ppszNames[cNames] = _wcsdup(pBuffer[i].shi2_netname);
                if (ppszNames[cNames] == NULL)
                {
                    NetApiBufferFree(pBuffer);
                    result = ShareError(ERROR_NOT_ENOUGH_MEMORY);
                    goto done;
                }
                cNames++;
            }

            NetApiBufferFree(pBuffer);
            pBuffer = NULL;
        }
        while (Status == ERROR_MORE_DATA);

        if (cNames == 0)
        {
            result = PrintCommandError(MSG_NO_MATCH, NULL);
            goto done;
        }

        for (i = 0; i < cNames; i++)
        {
            Status = NetShareDel(pOptions->pszServer, ppszNames[i], 0);
            if (Status != NERR_Success)
            {
                result = ShareError(Status);
                goto done;
            }

            PrintMessageStringV(4650, ppszNames[i]);
            ConPuts(StdOut, L"\n");
        }

        /* The command repeats the argument after the shares it deleted */
        PrintMessageStringV(4650, pOptions->pszName);
        ConPuts(StdOut, L"\n");

done:
        for (i = 0; i < cNames; i++)
            free(ppszNames[i]);
        if (ppszNames)
            HeapFree(GetProcessHeap(), 0, ppszNames);
        return result;
    }

    /* A colon is not asked of the server: the name is not a device or a path */
    if (wcschr(pOptions->pszName, L':') != NULL)
        return ShareError(ERROR_INVALID_NAME);

    Status = NetShareDel(pOptions->pszServer, pOptions->pszName, 0);
    if (Status != NERR_Success)
        return ShareError(Status);

    PrintMessageStringV(4650, pOptions->pszName);
    ConPuts(StdOut, L"\n");
    return 0;
}


static
BOOL
ParseGrant(
    PWSTR pszValue,
    GRANT *pGrant)
{
    PWSTR pComma;

    if (pszValue == NULL)
        return FALSE;

    pComma = wcsrchr(pszValue, L',');
    if (pComma == NULL)
        return FALSE;

    *pComma++ = UNICODE_NULL;
    pGrant->pszUser = pszValue;

    if (_wcsicmp(pComma, L"READ") == 0)
        pGrant->dwMask = ACCESS_READ_MASK;
    else if (_wcsicmp(pComma, L"CHANGE") == 0)
        pGrant->dwMask = ACCESS_CHANGE_MASK;
    else if (_wcsicmp(pComma, L"FULL") == 0)
        pGrant->dwMask = ACCESS_FULL_MASK;
    else
        return FALSE;

    return TRUE;
}


INT
cmdShare(
    INT argc,
    WCHAR **argv)
{
    SHARE_OPTIONS Options;
    WCHAR szRoot[4];
    PWSTR pszSpec = NULL;
    BOOL bExtra = FALSE;
    INT nPositional = 0;
    PWSTR ptr;
    PCWSTR pszValue;
    INT i;

    ZeroMemory(&Options, sizeof(Options));

    for (i = 2; i < argc; i++)
    {
        if (argv[i][0] == L'/')
        {
            if (wcscmp(argv[i], L"/?") == 0)
            {
                return PrintCommandSyntax(MSG_SHARE_SYNTAX, 0, NULL);
            }
            else if (_wcsicmp(argv[i], L"/help") == 0)
            {
                PrintCommandHelp(MSG_SHARE_SYNTAX, MSG_SHARE_HELP);
                return 1;
            }
            else if (IsOption(argv[i], L"delete", 1, &pszValue))
            {
                Options.bDelete = TRUE;
            }
            else if (IsOption(argv[i], L"unlimited", 2, &pszValue))
            {
                Options.dwMaxUses = (DWORD)-1;
                Options.bHaveUsers = TRUE;
            }
            else if (IsOption(argv[i], L"users", 2, &pszValue))
            {
                if (pszValue == NULL)
                    return MissingValue();
                if (!ParseNumber(pszValue, &Options.dwMaxUses))
                    return InvalidValue(L"/USERS");
                Options.bHaveUsers = TRUE;
            }
            else if (IsOption(argv[i], L"remark", 1, &pszValue))
            {
                if (pszValue == NULL)
                    return MissingValue();
                Options.pszRemark = (PWSTR)pszValue;
                Options.bHaveRemark = TRUE;
            }
            else if (IsOption(argv[i], L"cache", 1, &pszValue))
            {
                if (pszValue == NULL)
                    return MissingValue();
                else if (_wcsicmp(pszValue, L"manual") == 0)
                    Options.dwCache = CACHE_MANUAL;
                else if (_wcsicmp(pszValue, L"documents") == 0)
                    Options.dwCache = CACHE_DOCUMENTS;
                else if (_wcsicmp(pszValue, L"programs") == 0)
                    Options.dwCache = CACHE_PROGRAMS;
                else if (_wcsicmp(pszValue, L"branchcache") == 0)
                    Options.dwCache = CACHE_BRANCHCACHE;
                else if (_wcsicmp(pszValue, L"none") == 0)
                    Options.dwCache = CACHE_NONE;
                else
                    return InvalidValue(L"/CACHE");
                Options.bHaveCache = TRUE;
            }
            else if (IsOption(argv[i], L"grant", 1, &pszValue))
            {
                GRANT Grant;

                if (pszValue == NULL)
                    return MissingValue();
                if (Options.cGrants >= MAX_GRANTS ||
                    !ParseGrant((PWSTR)pszValue, &Grant))
                    return InvalidValue(L"/GRANT");

                /* A grant without a user changes nothing */
                if (Grant.pszUser[0] != UNICODE_NULL)
                    Options.Grants[Options.cGrants++] = Grant;
            }
            else
            {
                return UnknownOption(argv[i]);
            }
        }
        else if (argv[i][0] == L'\\' && argv[i][1] == L'\\' && wcschr(&argv[i][2], L'\\') == NULL &&
                 Options.pszServer == NULL && nPositional <= 1)
        {
            Options.pszServer = argv[i];
            nPositional++;
        }
        else if (pszSpec == NULL)
        {
            pszSpec = argv[i];
            nPositional++;
        }
        else
        {
            /* Deleting a share ignores what follows the name and the computer */
            bExtra = TRUE;
            nPositional++;
        }
    }

    if (bExtra && !Options.bDelete)
        return SyntaxError();

    /* A computer name is only accepted to delete a share there */
    if (Options.pszServer != NULL && (pszSpec == NULL || !Options.bDelete))
        return SyntaxError();

    if (pszSpec == NULL)
    {
        if (Options.bDelete || Options.bHaveRemark || Options.bHaveUsers ||
            Options.bHaveCache || Options.cGrants)
            return SyntaxError();

        return EnumerateShares(NULL);
    }

    if (wcslen(pszSpec) > MAX_SHARE_NAME + 1 + MAX_PATH)
        return SyntaxError();

    /* To delete, the whole argument is the name of the share */
    ptr = Options.bDelete ? NULL : wcschr(pszSpec, L'=');
    if (ptr != NULL)
    {
        if (ptr == pszSpec || ptr[1] == UNICODE_NULL || !IsSharePath(&ptr[1]) ||
            (size_t)(ptr - pszSpec) > MAX_SHARE_NAME)
            return SyntaxError();

        *ptr++ = UNICODE_NULL;
        if (HasIllegalNameChar(pszSpec))
            return SyntaxError();
        Options.pszPath = ptr;

        /* A drive letter alone names the root of the drive */
        if (IsAsciiLetter(ptr[0]) && ptr[1] == L':' && ptr[2] == UNICODE_NULL)
        {
            szRoot[0] = ptr[0];
            szRoot[1] = L':';
            szRoot[2] = L'\\';
            szRoot[3] = UNICODE_NULL;
            Options.pszPath = szRoot;
        }
    }
    else if (!Options.bDelete)
    {
        if (HasIllegalNameChar(pszSpec))
            return SyntaxError();
    }
    else if (wcschr(pszSpec, L'/') != NULL && !IsSharePath(pszSpec))
    {
        /* A slash starts an option, except in the path of a share that is deleted by its path */
        return SyntaxError();
    }

    Options.pszName = pszSpec;

    if (Options.pszPath != NULL)
    {
        return AddShare(&Options);
    }
    else if (Options.bDelete)
    {
        if (Options.bHaveRemark || Options.bHaveUsers || Options.bHaveCache || Options.cGrants)
            return SyntaxError();
        return DeleteShare(&Options);
    }
    else if (Options.bHaveRemark || Options.bHaveUsers || Options.bHaveCache)
    {
        if (Options.cGrants)
            return SyntaxError();
        return ModifyShare(&Options);
    }
    else if (Options.cGrants)
    {
        return SyntaxError();
    }

    return DisplayShare(Options.pszServer, Options.pszName);
}

/* EOF */
