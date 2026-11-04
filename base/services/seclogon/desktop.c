/*
 * PROJECT:     ReactOS Secondary Logon Service
 * LICENSE:     GPL-2.0+ (https://spdx.org/licenses/GPL-2.0+)
 * PURPOSE:     Access to the window station and the desktop for the logon of a new process
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * The process of another user is started on the window station and desktop of the caller. The new logon
 * session is not in the DACL of the window station and the desktop, so the process could not create a
 * window there. The service adds the logon SID of the new token to both for the lifetime of the
 * process and removes it again when the process has exited.
 */

#include "precomp.h"

WINE_DEFAULT_DEBUG_CHANNEL(seclogon);

/* Rights of the logon SID */
#define SECL_WINSTA_RIGHTS  (WINSTA_ENUMDESKTOPS | WINSTA_READATTRIBUTES | WINSTA_ACCESSCLIPBOARD | \
                             WINSTA_CREATEDESKTOP | WINSTA_WRITEATTRIBUTES | WINSTA_ACCESSGLOBALATOMS | \
                             WINSTA_EXITWINDOWS | WINSTA_ENUMERATE | WINSTA_READSCREEN | \
                             STANDARD_RIGHTS_REQUIRED)
#define SECL_DESKTOP_RIGHTS (DESKTOP_READOBJECTS | DESKTOP_CREATEWINDOW | DESKTOP_CREATEMENU | \
                             DESKTOP_HOOKCONTROL | DESKTOP_JOURNALRECORD | DESKTOP_JOURNALPLAYBACK | \
                             DESKTOP_ENUMERATE | DESKTOP_WRITEOBJECTS | DESKTOP_SWITCHDESKTOP | \
                             STANDARD_RIGHTS_REQUIRED)

struct _SECL_DESKTOP_ACCESS
{
    PSID LogonSid;
    HWINSTA hWinSta;
    HDESK hDesktop;
    BOOL WinStaChanged;
    BOOL DesktopChanged;
};

/* SetProcessWindowStation is the only way to open a desktop of another window station: one at a time */
static CRITICAL_SECTION DesktopLock;
static BOOL DesktopLockInitialized = FALSE;

/* FUNCTIONS *****************************************************************/

static PSID
GetLogonSid(
    _In_ HANDLE hToken)
{
    PTOKEN_GROUPS Groups = NULL;
    PSID Sid = NULL;
    DWORD Size = 0, i;

    GetTokenInformation(hToken, TokenGroups, NULL, 0, &Size);
    if (Size == 0)
        return NULL;

    Groups = HeapAlloc(GetProcessHeap(), 0, Size);
    if (Groups == NULL)
        return NULL;

    if (GetTokenInformation(hToken, TokenGroups, Groups, Size, &Size))
    {
        for (i = 0; i < Groups->GroupCount; i++)
        {
            if ((Groups->Groups[i].Attributes & SE_GROUP_LOGON_ID) == SE_GROUP_LOGON_ID)
            {
                Size = GetLengthSid(Groups->Groups[i].Sid);
                Sid = HeapAlloc(GetProcessHeap(), 0, Size);
                if (Sid != NULL && !CopySid(Size, Sid, Groups->Groups[i].Sid))
                {
                    HeapFree(GetProcessHeap(), 0, Sid);
                    Sid = NULL;
                }
                break;
            }
        }
    }

    HeapFree(GetProcessHeap(), 0, Groups);
    return Sid;
}


/* Adds an access allowed ACE for Sid to the DACL of the object, or removes the ACEs of Sid from it. */
static BOOL
ChangeObjectDacl(
    _In_ HANDLE hObject,
    _In_ PSID Sid,
    _In_ ACCESS_MASK Mask,
    _In_ BOOL Add,
    _Out_ PBOOL Changed)
{
    SECURITY_INFORMATION SecurityInfo = DACL_SECURITY_INFORMATION;
    SECURITY_DESCRIPTOR NewSd;
    PSECURITY_DESCRIPTOR Sd = NULL;
    PACL Dacl, NewDacl = NULL;
    BOOL Present, Defaulted, Result = FALSE;
    DWORD Length = 0, NewSize, i;
    ACL_SIZE_INFORMATION AclInfo;
    PVOID Ace;

    *Changed = FALSE;

    GetUserObjectSecurity(hObject, &SecurityInfo, NULL, 0, &Length);
    if (Length == 0)
        return FALSE;

    Sd = HeapAlloc(GetProcessHeap(), 0, Length);
    if (Sd == NULL)
        return FALSE;

    if (!GetUserObjectSecurity(hObject, &SecurityInfo, Sd, Length, &Length))
        goto done;

    if (!GetSecurityDescriptorDacl(Sd, &Present, &Dacl, &Defaulted))
        goto done;

    /* A NULL DACL gives everyone full access: nothing to add or to remove */
    if (!Present || Dacl == NULL)
    {
        Result = TRUE;
        goto done;
    }

    if (!GetAclInformation(Dacl, &AclInfo, sizeof(AclInfo), AclSizeInformation))
        goto done;

    NewSize = AclInfo.AclBytesInUse + sizeof(ACCESS_ALLOWED_ACE) + GetLengthSid(Sid);
    NewDacl = HeapAlloc(GetProcessHeap(), 0, NewSize);
    if (NewDacl == NULL)
        goto done;

    if (!InitializeAcl(NewDacl, NewSize, ACL_REVISION))
        goto done;

    for (i = 0; i < AclInfo.AceCount; i++)
    {
        if (!GetAce(Dacl, i, &Ace))
            goto done;

        if (!Add && ((PACE_HEADER)Ace)->AceType == ACCESS_ALLOWED_ACE_TYPE &&
            EqualSid(Sid, &((PACCESS_ALLOWED_ACE)Ace)->SidStart))
        {
            *Changed = TRUE;
            continue;
        }

        if (!AddAce(NewDacl, ACL_REVISION, MAXDWORD, Ace, ((PACE_HEADER)Ace)->AceSize))
            goto done;
    }

    if (Add)
    {
        if (!AddAccessAllowedAce(NewDacl, ACL_REVISION, Mask, Sid))
            goto done;
        *Changed = TRUE;
    }
    else if (!*Changed)
    {
        Result = TRUE;
        goto done;
    }

    if (!InitializeSecurityDescriptor(&NewSd, SECURITY_DESCRIPTOR_REVISION) ||
        !SetSecurityDescriptorDacl(&NewSd, TRUE, NewDacl, FALSE))
    {
        *Changed = FALSE;
        goto done;
    }

    Result = SetUserObjectSecurity(hObject, &SecurityInfo, &NewSd);
    if (!Result)
        *Changed = FALSE;

done:
    if (NewDacl != NULL)
        HeapFree(GetProcessHeap(), 0, NewDacl);
    if (Sd != NULL)
        HeapFree(GetProcessHeap(), 0, Sd);
    return Result;
}


VOID
SeclInitDesktopAccess(VOID)
{
    InitializeCriticalSection(&DesktopLock);
    DesktopLockInitialized = TRUE;
}


/*
 * Opens the window station and the desktop named for the new process (nothing if none is named) and
 * adds the logon SID of hToken to their DACLs. The result is NULL if there is nothing to undo.
 */
DWORD
SeclGrantDesktopAccess(
    _In_ HANDLE hToken,
    _In_opt_ PCWSTR pszDesktop,
    _Out_ SECL_DESKTOP_ACCESS **ppAccess,
    _Out_ PWSTR *ppszDesktopName)
{
    SECL_DESKTOP_ACCESS *Access;
    WCHAR WinStaName[MAX_PATH];
    PCWSTR DesktopName, Slash;
    HWINSTA hOldWinSta;
    SIZE_T Length;
    PWSTR Full;
    DWORD dwError = ERROR_SUCCESS;

    *ppAccess = NULL;
    *ppszDesktopName = NULL;

    /*
     * No desktop named (the caller has none): leave the choice to the system, the process gets the window
     * station its own logon is entitled to. Never fall back to the interactive WinSta0 here.
     */
    if (pszDesktop == NULL || pszDesktop[0] == UNICODE_NULL)
        return ERROR_SUCCESS;

    /* The new process gets this as its lpDesktop */
    Length = wcslen(pszDesktop) + 1;
    Full = HeapAlloc(GetProcessHeap(), 0, Length * sizeof(WCHAR));
    if (Full == NULL)
        return ERROR_NOT_ENOUGH_MEMORY;
    memcpy(Full, pszDesktop, Length * sizeof(WCHAR));
    *ppszDesktopName = Full;

    Slash = wcschr(pszDesktop, L'\\');
    if (Slash != NULL)
    {
        Length = Slash - pszDesktop;
        if (Length == 0 || Length >= RTL_NUMBER_OF(WinStaName))
            return ERROR_INVALID_PARAMETER;
        memcpy(WinStaName, pszDesktop, Length * sizeof(WCHAR));
        WinStaName[Length] = UNICODE_NULL;
        DesktopName = Slash + 1;
    }
    else
    {
        wcscpy(WinStaName, L"WinSta0");
        DesktopName = pszDesktop;
    }

    Access = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*Access));
    if (Access == NULL)
        return ERROR_NOT_ENOUGH_MEMORY;

    Access->LogonSid = GetLogonSid(hToken);
    if (Access->LogonSid == NULL)
    {
        /* No logon SID, nothing that could be granted */
        HeapFree(GetProcessHeap(), 0, Access);
        return ERROR_SUCCESS;
    }

    Access->hWinSta = OpenWindowStationW(WinStaName, FALSE, READ_CONTROL | WRITE_DAC);
    if (Access->hWinSta == NULL)
    {
        dwError = GetLastError();
        WARN("OpenWindowStation(%S) failed with Error %lu\n", WinStaName, dwError);
        goto fail;
    }

    ChangeObjectDacl(Access->hWinSta, Access->LogonSid, SECL_WINSTA_RIGHTS, TRUE, &Access->WinStaChanged);

    EnterCriticalSection(&DesktopLock);
    hOldWinSta = GetProcessWindowStation();
    if (SetProcessWindowStation(Access->hWinSta))
    {
        Access->hDesktop = OpenDesktopW(DesktopName, 0, FALSE, READ_CONTROL | WRITE_DAC);
        if (Access->hDesktop == NULL)
            dwError = GetLastError();
        SetProcessWindowStation(hOldWinSta);
    }
    else
    {
        dwError = GetLastError();
    }
    LeaveCriticalSection(&DesktopLock);

    if (Access->hDesktop == NULL)
    {
        WARN("OpenDesktop(%S) failed with Error %lu\n", DesktopName, dwError);
        goto fail;
    }

    ChangeObjectDacl(Access->hDesktop, Access->LogonSid, SECL_DESKTOP_RIGHTS, TRUE, &Access->DesktopChanged);

    *ppAccess = Access;
    return ERROR_SUCCESS;

fail:
    /* The process is started anyway, it just has no access to this desktop */
    SeclRevokeDesktopAccess(Access);
    return ERROR_SUCCESS;
}


VOID
SeclRevokeDesktopAccess(
    _In_opt_ SECL_DESKTOP_ACCESS *Access)
{
    BOOL Changed;

    if (Access == NULL)
        return;

    if (Access->hDesktop != NULL)
    {
        if (Access->DesktopChanged)
            ChangeObjectDacl(Access->hDesktop, Access->LogonSid, 0, FALSE, &Changed);
        CloseDesktop(Access->hDesktop);
    }

    if (Access->hWinSta != NULL)
    {
        if (Access->WinStaChanged)
            ChangeObjectDacl(Access->hWinSta, Access->LogonSid, 0, FALSE, &Changed);
        CloseWindowStation(Access->hWinSta);
    }

    if (Access->LogonSid != NULL)
        HeapFree(GetProcessHeap(), 0, Access->LogonSid);

    HeapFree(GetProcessHeap(), 0, Access);
}
