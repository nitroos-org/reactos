/*
 * PROJECT:     ReactOS Secondary Logon Service
 * LICENSE:     GPL-2.0+ (https://spdx.org/licenses/GPL-2.0+)
 * PURPOSE:     The named-object directories of the caller's session for the logon of a new process
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * A program started for another account in a session other than 0 resolves its unqualified and Local\ names
 * to \Sessions\<n>\BaseNamedObjects, and the names of its packages to \Sessions\<n>\AppContainerNamedObjects.
 * Those directories let SYSTEM and the interactive logon of the session create objects, nobody else. Without
 * an entry the program could create no named event, mutex, semaphore or section (single-instance checks and
 * shared memory fail).
 *
 * Measured on Windows Server 2022 (a standard user runs a program as another standard user with
 * CreateProcessWithLogonW): the program creates plain, Local\ and Global\ named objects; its rights on both
 * directories are query, traverse, create object, create subdirectory and read control (0x2000F); the
 * directories' DACLs do not change before, while or after it runs. Windows gives it those rights through the
 * caller's logon SID, which its token carries. Here the program keeps a logon SID of its own (sharing the
 * caller's would also open the caller's processes and other objects to it), and gets the same rights through
 * an entry for that SID: added by this service before the program runs, taken out by this service when the
 * logon has no process left (see logon.c), whether or not the caller is still there.
 */

#include "precomp.h"
#include <ndk/exfuncs.h>
#include <ndk/obfuncs.h>
#include <strsafe.h>

WINE_DEFAULT_DEBUG_CHANNEL(seclogon);

/* What the program of the secondary logon may do in the directories (Windows: 0x2000F) */
#define SECL_NAMESPACE_RIGHTS (DIRECTORY_QUERY | DIRECTORY_TRAVERSE | DIRECTORY_CREATE_OBJECT | \
                               DIRECTORY_CREATE_SUBDIRECTORY | READ_CONTROL)

#define SECL_NAMESPACE_DIRECTORIES 2
static const PCWSTR SeclNamespaceDirectories[SECL_NAMESPACE_DIRECTORIES] =
{
    L"BaseNamedObjects", L"AppContainerNamedObjects"
};

struct _SECL_NAMESPACE_ACCESS
{
    PSID LogonSid;
    DWORD SessionId;
    BOOL Changed[SECL_NAMESPACE_DIRECTORIES];
};

/* The service changes the DACLs one at a time: two calls must not undo each other's entries */
static CRITICAL_SECTION NamespaceLock;

/* FUNCTIONS *****************************************************************/

VOID
SeclInitNamespaceAccess(VOID)
{
    InitializeCriticalSection(&NamespaceLock);
}

/*
 * Winlogon of the session changes the same two DACLs at logon and logoff, also by read, change, write. Both take
 * this mutex of the session around their change, so that neither loses the other's entry. It is in
 * \Sessions\<n>\Windows, where only SYSTEM may create objects, and only SYSTEM may open it. Returns the owned
 * mutex, or NULL when it could not be had in time (the change is made anyway: a lost entry is better than a
 * blocked logon).
 */
static HANDLE
LockSessionNamespace(
    _In_ DWORD SessionId)
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
    NTSTATUS Status;

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
        StringCchPrintfW(Path, ARRAYSIZE(Path), L"\\Sessions\\%lu\\Windows\\NamedObjectsAccessLock", SessionId);
        RtlInitUnicodeString(&Name, Path);
        InitializeObjectAttributes(&ObjectAttributes, &Name, OBJ_CASE_INSENSITIVE | OBJ_OPENIF, NULL, &Sd);
        Status = NtCreateMutant(&Mutant, MUTANT_ALL_ACCESS, &ObjectAttributes, FALSE);
    }
    if (SystemSid)
        RtlFreeSid(SystemSid);
    if (!NT_SUCCESS(Status))
    {
        WARN("No lock for the named-object directories of session %lu, Status 0x%08lx\n", SessionId, Status);
        return NULL;
    }
    switch (WaitForSingleObject(Mutant, 30000))
    {
        case WAIT_OBJECT_0:
        case WAIT_ABANDONED:
            return Mutant;
        default:
            ERR("The lock of the named-object directories of session %lu is not free\n", SessionId);
            NtClose(Mutant);
            return NULL;
    }
}

static VOID
UnlockSessionNamespace(
    _In_opt_ HANDLE Mutant)
{
    if (Mutant == NULL)
        return;
    NtReleaseMutant(Mutant, NULL);
    NtClose(Mutant);
}

static PSID
CopyLogonSid(
    _In_ HANDLE hToken)
{
    PTOKEN_GROUPS Groups;
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
            if ((Groups->Groups[i].Attributes & SE_GROUP_LOGON_ID) != SE_GROUP_LOGON_ID)
                continue;
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
    HeapFree(GetProcessHeap(), 0, Groups);
    return Sid;
}

static BOOL
IsLogonEntry(
    _In_ PACE_HEADER Ace,
    _In_ PSID LogonSid)
{
    return Ace->AceType == ACCESS_ALLOWED_ACE_TYPE &&
           RtlEqualSid((PSID)&((PACCESS_ALLOWED_ACE)Ace)->SidStart, LogonSid);
}

/* Puts the entry of LogonSid into the DACL of the directory (Grant) or takes every entry of LogonSid out */
static NTSTATUS
SetDirectoryEntry(
    _In_ PCWSTR Path,
    _In_ PSID LogonSid,
    _In_ BOOL Grant)
{
    UNICODE_STRING Name;
    OBJECT_ATTRIBUTES ObjectAttributes;
    HANDLE Directory;
    PSECURITY_DESCRIPTOR OldSd = NULL;
    SECURITY_DESCRIPTOR NewSd;
    PACL OldDacl = NULL, NewDacl = NULL;
    BOOLEAN Present = FALSE, Defaulted;
    PACE_HEADER Ace;
    ULONG Length = 0, AclLength, i;
    NTSTATUS Status;

    RtlInitUnicodeString(&Name, Path);
    InitializeObjectAttributes(&ObjectAttributes, &Name, OBJ_CASE_INSENSITIVE, NULL, NULL);
    Status = NtOpenDirectoryObject(&Directory, READ_CONTROL | WRITE_DAC, &ObjectAttributes);
    if (!NT_SUCCESS(Status))
        return Status;

    Status = NtQuerySecurityObject(Directory, DACL_SECURITY_INFORMATION, NULL, 0, &Length);
    if (Status == STATUS_BUFFER_TOO_SMALL)
    {
        OldSd = HeapAlloc(GetProcessHeap(), 0, Length);
        Status = OldSd ? NtQuerySecurityObject(Directory, DACL_SECURITY_INFORMATION, OldSd, Length, &Length)
                       : STATUS_NO_MEMORY;
    }
    if (NT_SUCCESS(Status))
        Status = RtlGetDaclSecurityDescriptor(OldSd, &Present, &OldDacl, &Defaulted);
    if (NT_SUCCESS(Status) && (!Present || !OldDacl))
        Status = STATUS_INVALID_SECURITY_DESCR;
    if (!NT_SUCCESS(Status))
        goto Quit;

    /*
     * The old entries without any of this logon's, then this logon's one when granting. The new list is sized
     * for exactly what it holds: the object keeps the size it is given, so a list sized from the old one would
     * grow at every change and the descriptor would outgrow an ACL after a few thousand changes.
     */
    AclLength = sizeof(ACL);
    for (i = 0; i < OldDacl->AceCount; i++)
    {
        if (NT_SUCCESS(RtlGetAce(OldDacl, i, (PVOID*)&Ace)) && !IsLogonEntry(Ace, LogonSid))
            AclLength += Ace->AceSize;
    }
    if (Grant)
        AclLength += sizeof(ACCESS_ALLOWED_ACE) - sizeof(ULONG) + RtlLengthSid(LogonSid);
    NewDacl = HeapAlloc(GetProcessHeap(), 0, AclLength);
    if (!NewDacl)
    {
        Status = STATUS_NO_MEMORY;
        goto Quit;
    }
    Status = RtlCreateAcl(NewDacl, AclLength, ACL_REVISION);
    for (i = 0; NT_SUCCESS(Status) && i < OldDacl->AceCount; i++)
    {
        if (!NT_SUCCESS(RtlGetAce(OldDacl, i, (PVOID*)&Ace)) || IsLogonEntry(Ace, LogonSid))
            continue;
        Status = RtlAddAce(NewDacl, ACL_REVISION, MAXULONG, Ace, Ace->AceSize);
    }
    if (NT_SUCCESS(Status) && Grant)
        Status = RtlAddAccessAllowedAceEx(NewDacl, ACL_REVISION, 0, SECL_NAMESPACE_RIGHTS, LogonSid);
    if (NT_SUCCESS(Status))
        Status = RtlCreateSecurityDescriptor(&NewSd, SECURITY_DESCRIPTOR_REVISION);
    if (NT_SUCCESS(Status))
        Status = RtlSetDaclSecurityDescriptor(&NewSd, TRUE, NewDacl, FALSE);
    if (NT_SUCCESS(Status))
        Status = NtSetSecurityObject(Directory, DACL_SECURITY_INFORMATION, &NewSd);

Quit:
    if (NewDacl)
        HeapFree(GetProcessHeap(), 0, NewDacl);
    if (OldSd)
        HeapFree(GetProcessHeap(), 0, OldSd);
    NtClose(Directory);
    return Status;
}

/*
 * Gives the logon of hToken the rights the program of a secondary logon has on Windows in the named-object
 * directories of session SessionId. Session 0 needs nothing (everyone may create there). *ppAccess is what
 * SeclRevokeNamespaceAccess takes out again; NULL when nothing was changed.
 */
DWORD
SeclGrantNamespaceAccess(
    _In_ HANDLE hToken,
    _In_ DWORD SessionId,
    _Out_ SECL_NAMESPACE_ACCESS **ppAccess)
{
    SECL_NAMESPACE_ACCESS *Access;
    WCHAR Path[64];
    NTSTATUS Status;
    HANDLE Lock;
    BOOL Any = FALSE;
    ULONG d;

    *ppAccess = NULL;
    if (SessionId == 0)
        return ERROR_SUCCESS;

    Access = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*Access));
    if (Access == NULL)
        return ERROR_NOT_ENOUGH_MEMORY;
    Access->SessionId = SessionId;
    Access->LogonSid = CopyLogonSid(hToken);
    if (Access->LogonSid == NULL)
    {
        HeapFree(GetProcessHeap(), 0, Access);
        return ERROR_NO_SUCH_LOGON_SESSION;
    }

    EnterCriticalSection(&NamespaceLock);
    Lock = LockSessionNamespace(SessionId);
    for (d = 0; d < ARRAYSIZE(SeclNamespaceDirectories); d++)
    {
        StringCchPrintfW(Path, ARRAYSIZE(Path), L"\\Sessions\\%lu\\%s", SessionId, SeclNamespaceDirectories[d]);
        Status = SetDirectoryEntry(Path, Access->LogonSid, TRUE);
        if (NT_SUCCESS(Status))
            Access->Changed[d] = Any = TRUE;
        else
            WARN("Cannot give the logon access to %S, Status 0x%08lx\n", Path, Status);
    }
    UnlockSessionNamespace(Lock);
    LeaveCriticalSection(&NamespaceLock);

    if (!Any)
    {
        HeapFree(GetProcessHeap(), 0, Access->LogonSid);
        HeapFree(GetProcessHeap(), 0, Access);
        return ERROR_ACCESS_DENIED;
    }
    *ppAccess = Access;
    return ERROR_SUCCESS;
}

/* Takes the entries of the logon out of the directories again and frees Access (may be NULL) */
VOID
SeclRevokeNamespaceAccess(
    _In_opt_ SECL_NAMESPACE_ACCESS *Access)
{
    WCHAR Path[64];
    NTSTATUS Status;
    HANDLE Lock;
    ULONG d;

    if (Access == NULL)
        return;

    EnterCriticalSection(&NamespaceLock);
    Lock = LockSessionNamespace(Access->SessionId);
    for (d = 0; d < ARRAYSIZE(SeclNamespaceDirectories); d++)
    {
        if (!Access->Changed[d])
            continue;
        StringCchPrintfW(Path, ARRAYSIZE(Path), L"\\Sessions\\%lu\\%s", Access->SessionId, SeclNamespaceDirectories[d]);
        Status = SetDirectoryEntry(Path, Access->LogonSid, FALSE);
        if (!NT_SUCCESS(Status))
            ERR("Cannot take the logon out of %S, Status 0x%08lx\n", Path, Status);
    }
    UnlockSessionNamespace(Lock);
    LeaveCriticalSection(&NamespaceLock);

    HeapFree(GetProcessHeap(), 0, Access->LogonSid);
    HeapFree(GetProcessHeap(), 0, Access);
}

/* A logon left by an earlier run of the service: its entries go when its last process is gone */
static DWORD
WINAPI
SweepLogon(
    _In_ PVOID Context)
{
    SECL_NAMESPACE_ACCESS *Access = Context;

    SeclWaitForLogonProcesses(Access->LogonSid);
    SeclRevokeClientDesktop(Access->SessionId, Access->LogonSid, L"WinSta0\\Default");
    SeclRevokeNamespaceAccess(Access);
    return 0;
}

/* An entry this service gives: allowed, no flags, exactly its rights, for a logon SID (S-1-5-5-x-y) */
static BOOL
IsServiceEntry(
    _In_ PACE_HEADER Ace)
{
    PSID Sid = (PSID)&((PACCESS_ALLOWED_ACE)Ace)->SidStart;
    static SID_IDENTIFIER_AUTHORITY NtAuthority = {SECURITY_NT_AUTHORITY};

    return Ace->AceType == ACCESS_ALLOWED_ACE_TYPE && Ace->AceFlags == 0 &&
           ((PACCESS_ALLOWED_ACE)Ace)->Mask == SECL_NAMESPACE_RIGHTS &&
           *RtlSubAuthorityCountSid(Sid) == SECURITY_LOGON_IDS_RID_COUNT &&
           !memcmp(RtlIdentifierAuthoritySid(Sid), &NtAuthority, sizeof(NtAuthority)) &&
           *RtlSubAuthoritySid(Sid, 0) == SECURITY_LOGON_IDS_RID;
}

/* Whether the DACL also has an inherit-only entry for Sid: Winlogon gives the interactive logon one */
static BOOL
HasInheritedEntry(
    _In_ PACL Dacl,
    _In_ PSID Sid)
{
    PACE_HEADER Ace;
    ULONG i;

    for (i = 0; i < Dacl->AceCount; i++)
    {
        if (NT_SUCCESS(RtlGetAce(Dacl, i, (PVOID*)&Ace)) && Ace->AceType == ACCESS_ALLOWED_ACE_TYPE &&
            (Ace->AceFlags & INHERIT_ONLY_ACE) && RtlEqualSid((PSID)&((PACCESS_ALLOWED_ACE)Ace)->SidStart, Sid))
        {
            return TRUE;
        }
    }
    return FALSE;
}

/*
 * At the start of the service: the entries an earlier run of this service gave to secondary logons in the
 * BaseNamedObjects directory of session SessionId and could not take out (its process ended while they ran). A
 * logon with a process left is waited for, the others are taken out now, with the window station and desktop
 * entries of WinSta0\Default (the only desktop that is known without the request).
 */
static VOID
SweepSession(
    _In_ DWORD SessionId)
{
    WCHAR Path[64];
    UNICODE_STRING Name;
    OBJECT_ATTRIBUTES ObjectAttributes;
    HANDLE Directory, hThread;
    PSECURITY_DESCRIPTOR Sd = NULL;
    PACL Dacl = NULL;
    BOOLEAN Present = FALSE, Defaulted;
    PACE_HEADER Ace;
    PSID Sid;
    SECL_NAMESPACE_ACCESS *Access;
    ULONG Length = 0, i;
    NTSTATUS Status;

    StringCchPrintfW(Path, ARRAYSIZE(Path), L"\\Sessions\\%lu\\BaseNamedObjects", SessionId);
    RtlInitUnicodeString(&Name, Path);
    InitializeObjectAttributes(&ObjectAttributes, &Name, OBJ_CASE_INSENSITIVE, NULL, NULL);
    if (!NT_SUCCESS(NtOpenDirectoryObject(&Directory, READ_CONTROL, &ObjectAttributes)))
        return;
    Status = NtQuerySecurityObject(Directory, DACL_SECURITY_INFORMATION, NULL, 0, &Length);
    if (Status == STATUS_BUFFER_TOO_SMALL)
    {
        Sd = HeapAlloc(GetProcessHeap(), 0, Length);
        Status = Sd ? NtQuerySecurityObject(Directory, DACL_SECURITY_INFORMATION, Sd, Length, &Length) : STATUS_NO_MEMORY;
    }
    NtClose(Directory);
    if (NT_SUCCESS(Status))
        Status = RtlGetDaclSecurityDescriptor(Sd, &Present, &Dacl, &Defaulted);
    for (i = 0; NT_SUCCESS(Status) && Present && Dacl && i < Dacl->AceCount; i++)
    {
        if (!NT_SUCCESS(RtlGetAce(Dacl, i, (PVOID*)&Ace)) || !IsServiceEntry(Ace))
            continue;
        Sid = (PSID)&((PACCESS_ALLOWED_ACE)Ace)->SidStart;
        if (HasInheritedEntry(Dacl, Sid))
            continue;
        Access = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*Access));
        if (Access == NULL)
            break;
        Access->SessionId = SessionId;
        Access->Changed[0] = Access->Changed[1] = TRUE;
        Access->LogonSid = HeapAlloc(GetProcessHeap(), 0, RtlLengthSid(Sid));
        if (Access->LogonSid == NULL)
        {
            HeapFree(GetProcessHeap(), 0, Access);
            break;
        }
        RtlCopySid(RtlLengthSid(Sid), Access->LogonSid, Sid);
        WARN("Session %lu has the entry of a secondary logon an earlier run left\n", SessionId);
        hThread = CreateThread(NULL, 0, SweepLogon, Access, 0, NULL);
        if (hThread != NULL)
            CloseHandle(hThread);
        else
            SeclRevokeNamespaceAccess(Access);
    }
    if (Sd)
        HeapFree(GetProcessHeap(), 0, Sd);
}

/* Runs SweepSession for every session that has a session directory (\Sessions\<n>, n > 0) */
static DWORD
WINAPI
SweepSessions(
    _In_ PVOID Context)
{
    UNICODE_STRING Name = RTL_CONSTANT_STRING(L"\\Sessions");
    OBJECT_ATTRIBUTES ObjectAttributes;
    HANDLE Directory;
    UCHAR Buffer[2048];
    POBJECT_DIRECTORY_INFORMATION Info = (POBJECT_DIRECTORY_INFORMATION)Buffer;
    ULONG Context2 = 0, Length, SessionId, i;
    WCHAR Number[16];

    UNREFERENCED_PARAMETER(Context);

    InitializeObjectAttributes(&ObjectAttributes, &Name, OBJ_CASE_INSENSITIVE, NULL, NULL);
    if (!NT_SUCCESS(NtOpenDirectoryObject(&Directory, DIRECTORY_QUERY, &ObjectAttributes)))
        return 0;
    while (NT_SUCCESS(NtQueryDirectoryObject(Directory, Buffer, sizeof(Buffer), TRUE, Context2 == 0, &Context2, &Length)))
    {
        if (Info->Name.Length == 0 || Info->Name.Length >= sizeof(Number))
            continue;
        memcpy(Number, Info->Name.Buffer, Info->Name.Length);
        Number[Info->Name.Length / sizeof(WCHAR)] = UNICODE_NULL;
        if (Number[0] < L'1' || Number[0] > L'9' || wcsspn(Number, L"0123456789") != wcslen(Number) ||
            wcslen(Number) > 9)
        {
            continue;
        }
        for (SessionId = 0, i = 0; Number[i]; i++)
            SessionId = SessionId * 10 + (Number[i] - L'0');
        SweepSession(SessionId);
    }
    NtClose(Directory);
    return 0;
}

/*
 * At the first start of the service in its process, in a thread of its own. A later start in the same process
 * (the service was stopped) finds the waits of the earlier one still running: nothing to do then.
 */
VOID
SeclSweepNamespaceAccess(VOID)
{
    static LONG Swept = 0;
    HANDLE hThread;

    if (InterlockedExchange(&Swept, 1))
        return;
    hThread = CreateThread(NULL, 0, SweepSessions, NULL, 0, NULL);
    if (hThread != NULL)
        CloseHandle(hThread);
}
