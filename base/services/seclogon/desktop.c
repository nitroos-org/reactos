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
#include <ndk/exfuncs.h>
#include <ndk/obfuncs.h>
#include <sddl.h>
#include <strsafe.h>

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

/* A heap copy of the logon SID of the token, or NULL */
PSID
SeclGetLogonSid(
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


/*
 * The lock every changer of a window station or desktop DACL for a secondary logon takes. Only SYSTEM code changes
 * them: this service in its own session, its helper (seclhelp.exe) in another one. In session 0 that is this process
 * alone: a critical section. In another session it is a mutex in \Sessions\<n>\Windows, where only SYSTEM may create
 * objects, that only SYSTEM may open: no program of the session can hold it. Without it, a grant made at the same
 * time as a revoke could put back the entry the revoke had just taken out. Returns what UnlockDesktopAccess takes;
 * NULL when the mutex could not be had (the change is made anyway).
 */
static CRITICAL_SECTION DesktopDaclLock;
#define LOCKED_BY_SECTION ((HANDLE)(ULONG_PTR)1)

static HANDLE
LockDesktopAccess(VOID)
{
    static SID_IDENTIFIER_AUTHORITY NtAuthority = {SECURITY_NT_AUTHORITY};
    UCHAR AclBuffer[sizeof(ACL) + sizeof(ACCESS_ALLOWED_ACE) + SECURITY_MAX_SID_SIZE];
    PACL Dacl = (PACL)AclBuffer;
    SECURITY_DESCRIPTOR Sd;
    PSID SystemSid = NULL;
    WCHAR Path[64];
    UNICODE_STRING Name;
    OBJECT_ATTRIBUTES ObjectAttributes;
    HANDLE Mutant = NULL;
    DWORD Session = 0, Wait;
    NTSTATUS Status;

    ProcessIdToSessionId(GetCurrentProcessId(), &Session);
    if (Session == 0)
    {
        EnterCriticalSection(&DesktopDaclLock);
        return LOCKED_BY_SECTION;
    }

    Status = RtlAllocateAndInitializeSid(&NtAuthority, 1, SECURITY_LOCAL_SYSTEM_RID, 0, 0, 0, 0, 0, 0, 0, &SystemSid);
    if (NT_SUCCESS(Status))
        Status = RtlCreateAcl(Dacl, sizeof(AclBuffer), ACL_REVISION);
    if (NT_SUCCESS(Status))
        Status = RtlAddAccessAllowedAce(Dacl, ACL_REVISION, MUTANT_ALL_ACCESS, SystemSid);
    if (NT_SUCCESS(Status))
        Status = RtlCreateSecurityDescriptor(&Sd, SECURITY_DESCRIPTOR_REVISION);
    if (NT_SUCCESS(Status))
        Status = RtlSetDaclSecurityDescriptor(&Sd, TRUE, Dacl, FALSE);
    if (NT_SUCCESS(Status))
    {
        StringCchPrintfW(Path, ARRAYSIZE(Path), L"\\Sessions\\%lu\\Windows\\DesktopAccessLock", Session);
        RtlInitUnicodeString(&Name, Path);
        InitializeObjectAttributes(&ObjectAttributes, &Name, OBJ_CASE_INSENSITIVE | OBJ_OPENIF, NULL, &Sd);
        Status = NtCreateMutant(&Mutant, MUTANT_ALL_ACCESS, &ObjectAttributes, FALSE);
    }
    if (SystemSid)
        RtlFreeSid(SystemSid);
    if (!NT_SUCCESS(Status))
    {
        WARN("No window station and desktop lock in session %lu, Status 0x%08lx\n", Session, Status);
        return NULL;
    }
    Wait = WaitForSingleObject(Mutant, 30000);
    if (Wait == WAIT_OBJECT_0 || Wait == WAIT_ABANDONED)
        return Mutant;
    WARN("The window station and desktop lock of session %lu is not free\n", Session);
    NtClose(Mutant);
    return NULL;
}

static VOID
UnlockDesktopAccess(
    _In_opt_ HANDLE Mutant)
{
    if (Mutant == LOCKED_BY_SECTION)
    {
        LeaveCriticalSection(&DesktopDaclLock);
        return;
    }
    if (Mutant == NULL)
        return;
    NtReleaseMutant(Mutant, NULL);
    NtClose(Mutant);
}

static BOOL
ChangeObjectDaclUnlocked(
    _In_ HANDLE hObject,
    _In_ PSID Sid,
    _In_ ACCESS_MASK Mask,
    _In_ BOOL Add,
    _Out_ PBOOL Changed);

/* Adds an access allowed ACE for Sid to the DACL of the object, or removes the ACEs of Sid from it, under the lock */
static BOOL
ChangeObjectDacl(
    _In_ HANDLE hObject,
    _In_ PSID Sid,
    _In_ ACCESS_MASK Mask,
    _In_ BOOL Add,
    _Out_ PBOOL Changed)
{
    HANDLE Lock = LockDesktopAccess();
    BOOL Result = ChangeObjectDaclUnlocked(hObject, Sid, Mask, Add, Changed);

    UnlockDesktopAccess(Lock);
    return Result;
}

static BOOL
ChangeObjectDaclUnlocked(
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

    /*
     * The new list has the size of the old one, plus the entry that is added or minus the entries that are taken
     * out: an entry added and taken out again leaves the descriptor as it was, byte for byte (the object keeps the
     * size it is given; sizing from the bytes in use would change it, and adding room would let it grow)
     */
    NewSize = Dacl->AclSize;
    if (Add)
    {
        NewSize += sizeof(ACCESS_ALLOWED_ACE) - sizeof(DWORD) + GetLengthSid(Sid);
    }
    else
    {
        for (i = 0; i < AclInfo.AceCount; i++)
        {
            if (GetAce(Dacl, i, &Ace) && ((PACE_HEADER)Ace)->AceType == ACCESS_ALLOWED_ACE_TYPE &&
                EqualSid(Sid, &((PACCESS_ALLOWED_ACE)Ace)->SidStart))
            {
                NewSize -= ((PACE_HEADER)Ace)->AceSize;
            }
        }
    }
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
    InitializeCriticalSection(&DesktopDaclLock);
    DesktopLockInitialized = TRUE;
}


/* "WinSta\Desktop" or "Desktop" (on WinSta0) into its two names */
static BOOL
SplitDesktopName(
    _In_ PCWSTR pszDesktop,
    _Out_writes_(MAX_PATH) PWSTR WinStaName,
    _Out_ PCWSTR *DesktopName)
{
    PCWSTR Slash = wcschr(pszDesktop, L'\\');
    SIZE_T Length;

    if (Slash == NULL)
    {
        wcscpy(WinStaName, L"WinSta0");
        *DesktopName = pszDesktop;
        return TRUE;
    }
    Length = Slash - pszDesktop;
    if (Length == 0 || Length >= MAX_PATH)
        return FALSE;
    memcpy(WinStaName, pszDesktop, Length * sizeof(WCHAR));
    WinStaName[Length] = UNICODE_NULL;
    *DesktopName = Slash + 1;
    return TRUE;
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
    PCWSTR DesktopName;
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

    if (!SplitDesktopName(pszDesktop, WinStaName, &DesktopName))
        return ERROR_INVALID_PARAMETER;

    Access = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*Access));
    if (Access == NULL)
        return ERROR_NOT_ENOUGH_MEMORY;

    Access->LogonSid = SeclGetLogonSid(hToken);
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


/*
 * A window station and desktop name the service passes on to its helper: "WinSta\Desktop" or "Desktop", from the
 * request of the caller of CreateProcessWithLogonW. A name may hold any character but a backslash; here also no
 * control character and no quote (it goes onto a command line), at most one separator (between the window station
 * and the desktop), each part not empty, at most 255 characters in all. Another name gets no entry at all.
 */
BOOL
SeclValidDesktopName(
    _In_opt_ PCWSTR pszDesktop)
{
    size_t Length, i, Separators = 0;

    if (pszDesktop == NULL || FAILED(StringCchLengthW(pszDesktop, 256, &Length)) || Length == 0)
        return FALSE;
    for (i = 0; i < Length; i++)
    {
        if (pszDesktop[i] < L' ' || pszDesktop[i] == L'"' || pszDesktop[i] == 0x7F)
            return FALSE;
        if (pszDesktop[i] == L'\\')
        {
            if (++Separators > 1 || i == 0 || i == Length - 1)
                return FALSE;
        }
    }
    return TRUE;
}

/* Copies the field at p (up to the next space) to Out; returns what follows the space, or NULL */
static PCWSTR
NextField(
    _In_ PCWSTR p,
    _Out_writes_(Size) PWSTR Out,
    _In_ SIZE_T Size)
{
    PCWSTR Space = wcschr(p, L' ');
    SIZE_T Length;

    if (Space == NULL)
        return NULL;
    Length = Space - p;
    if (Length == 0 || Length >= Size)
        return NULL;
    memcpy(Out, p, Length * sizeof(WCHAR));
    Out[Length] = UNICODE_NULL;
    return Space + 1;
}

/* A heap copy of a logon SID (S-1-5-5-x-y, nothing else) from its string form */
static PSID
ParseLogonSid(
    _In_ PCWSTR String)
{
    static SID_IDENTIFIER_AUTHORITY NtAuthority = {SECURITY_NT_AUTHORITY};
    PSID Sid = NULL, Copy = NULL;

    if (!ConvertStringSidToSidW(String, &Sid))
        return NULL;
    if (*GetSidSubAuthorityCount(Sid) == SECURITY_LOGON_IDS_RID_COUNT &&
        !memcmp(GetSidIdentifierAuthority(Sid), &NtAuthority, sizeof(NtAuthority)) &&
        *GetSidSubAuthority(Sid, 0) == SECURITY_LOGON_IDS_RID)
    {
        Copy = HeapAlloc(GetProcessHeap(), 0, GetLengthSid(Sid));
        if (Copy != NULL && !CopySid(GetLengthSid(Sid), Copy, Sid))
        {
            HeapFree(GetProcessHeap(), 0, Copy);
            Copy = NULL;
        }
    }
    LocalFree(Sid);
    return Copy;
}

/* Opens the window station and the desktop of Name for READ_CONTROL | WRITE_DAC, with the thread's token */
static DWORD
OpenDesktopObjects(
    _Inout_ SECL_DESKTOP_ACCESS *Access,
    _In_ PCWSTR Name)
{
    WCHAR WinStaName[MAX_PATH];
    PCWSTR DesktopName;
    HWINSTA hOldWinSta;
    DWORD dwError = ERROR_SUCCESS;

    if (!SplitDesktopName(Name, WinStaName, &DesktopName))
        return ERROR_INVALID_PARAMETER;
    Access->hWinSta = OpenWindowStationW(WinStaName, FALSE, READ_CONTROL | WRITE_DAC);
    if (Access->hWinSta == NULL)
        return GetLastError();
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
    return dwError;
}

/*
 * The helper of the service in another session (seclhelp.exe, started by the service as SYSTEM in that session, on
 * its Winlogon desktop: no program of the session can hook a thread of it or reach a window of it; it makes no
 * window). Command line after the program name:
 *   grant <caller process id> <logon SID> <WinSta\Desktop>
 *       The caller of CreateProcessWithLogonW waits for the service's answer meanwhile. The window station and the
 *       desktop are opened with the CALLER's token (a copy of it, impersonated): only what the caller may change
 *       itself is changed, as when the caller made this change before. Then the entry of the logon SID is added.
 *   revoke <logon SID> <WinSta\Desktop>
 *       When the logon has no process left: the entries of that logon SID (and of nothing else) are taken out.
 * Both under the session's lock (LockDesktopAccess). Returns 0 or a Win32 error.
 */
DWORD
WINAPI
SeclHelperMain(
    _In_ PCWSTR CommandLine)
{
    WCHAR Mode[8], Pid[16], SidString[96];
    PCWSTR Name;
    SECL_DESKTOP_ACCESS *Access;
    HANDLE hProcess = NULL, hPrimary = NULL, hImpersonation = NULL;
    DWORD ProcessId = 0, Session = MAXDWORD, OwnSession = MAXDWORD, dwError;
    BOOL Grant;
    SIZE_T i;

    /* The fields, each followed by one space; the name is the rest of the line */
    if (CommandLine == NULL)
        return ERROR_INVALID_PARAMETER;
    Name = NextField(CommandLine, Mode, ARRAYSIZE(Mode));
    if (Name == NULL)
        return ERROR_INVALID_PARAMETER;
    if (!wcscmp(Mode, L"grant"))
        Grant = TRUE;
    else if (!wcscmp(Mode, L"revoke"))
        Grant = FALSE;
    else
        return ERROR_INVALID_PARAMETER;
    if (Grant)
        Name = NextField(Name, Pid, ARRAYSIZE(Pid));
    if (Name != NULL)
        Name = NextField(Name, SidString, ARRAYSIZE(SidString));
    if (Name == NULL || !SeclValidDesktopName(Name))
        return ERROR_INVALID_PARAMETER;

    Access = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*Access));
    if (Access == NULL)
        return ERROR_NOT_ENOUGH_MEMORY;
    Access->LogonSid = ParseLogonSid(SidString);
    if (Access->LogonSid == NULL)
    {
        HeapFree(GetProcessHeap(), 0, Access);
        return ERROR_INVALID_SID;
    }

    if (!Grant)
    {
        /* Only entries of this logon SID go: whatever the name, nothing else changes */
        OpenDesktopObjects(Access, Name);
        Access->WinStaChanged = Access->DesktopChanged = TRUE;
        SeclRevokeDesktopAccess(Access);
        return ERROR_SUCCESS;
    }

    /* The caller: a process of this session (it waits for the service's answer, so its id is its own) */
    for (i = 0; Pid[i]; i++)
    {
        if (Pid[i] < L'0' || Pid[i] > L'9')
        {
            SeclRevokeDesktopAccess(Access);
            return ERROR_INVALID_PARAMETER;
        }
        ProcessId = ProcessId * 10 + (Pid[i] - L'0');
    }
    ProcessIdToSessionId(GetCurrentProcessId(), &OwnSession);
    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, ProcessId);
    if (hProcess == NULL || !ProcessIdToSessionId(ProcessId, &Session) || Session != OwnSession ||
        !OpenProcessToken(hProcess, TOKEN_DUPLICATE, &hPrimary) ||
        !DuplicateTokenEx(hPrimary, TOKEN_IMPERSONATE | TOKEN_QUERY, NULL, SecurityImpersonation,
                          TokenImpersonation, &hImpersonation))
    {
        dwError = GetLastError();
        if (dwError == ERROR_SUCCESS)
            dwError = ERROR_ACCESS_DENIED;
        goto done;
    }

    /* Opened as the caller: what it may not change itself, it does not get changed */
    if (!SetThreadToken(NULL, hImpersonation))
    {
        dwError = GetLastError();
        goto done;
    }
    dwError = OpenDesktopObjects(Access, Name);
    SetThreadToken(NULL, NULL);
    if (Access->hWinSta != NULL)
        ChangeObjectDacl(Access->hWinSta, Access->LogonSid, SECL_WINSTA_RIGHTS, TRUE, &Access->WinStaChanged);
    if (Access->hDesktop != NULL)
        ChangeObjectDacl(Access->hDesktop, Access->LogonSid, SECL_DESKTOP_RIGHTS, TRUE, &Access->DesktopChanged);
    if (dwError == ERROR_SUCCESS && (!Access->WinStaChanged || !Access->DesktopChanged))
        dwError = ERROR_ACCESS_DENIED;

done:
    /* The entries stay (the service takes them out when the logon ends); the handles go */
    if (Access->hDesktop != NULL)
        CloseDesktop(Access->hDesktop);
    if (Access->hWinSta != NULL)
        CloseWindowStation(Access->hWinSta);
    HeapFree(GetProcessHeap(), 0, Access->LogonSid);
    HeapFree(GetProcessHeap(), 0, Access);
    if (hImpersonation != NULL)
        CloseHandle(hImpersonation);
    if (hPrimary != NULL)
        CloseHandle(hPrimary);
    if (hProcess != NULL)
        CloseHandle(hProcess);
    return dwError;
}
