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
 * program has exited, whether or not the caller is still there.
 */

#include "precomp.h"
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
    for (d = 0; d < ARRAYSIZE(SeclNamespaceDirectories); d++)
    {
        StringCchPrintfW(Path, ARRAYSIZE(Path), L"\\Sessions\\%lu\\%s", SessionId, SeclNamespaceDirectories[d]);
        Status = SetDirectoryEntry(Path, Access->LogonSid, TRUE);
        if (NT_SUCCESS(Status))
            Access->Changed[d] = Any = TRUE;
        else
            WARN("Cannot give the logon access to %S, Status 0x%08lx\n", Path, Status);
    }
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
    ULONG d;

    if (Access == NULL)
        return;

    EnterCriticalSection(&NamespaceLock);
    for (d = 0; d < ARRAYSIZE(SeclNamespaceDirectories); d++)
    {
        if (!Access->Changed[d])
            continue;
        StringCchPrintfW(Path, ARRAYSIZE(Path), L"\\Sessions\\%lu\\%s", Access->SessionId, SeclNamespaceDirectories[d]);
        Status = SetDirectoryEntry(Path, Access->LogonSid, FALSE);
        if (!NT_SUCCESS(Status))
            ERR("Cannot take the logon out of %S, Status 0x%08lx\n", Path, Status);
    }
    LeaveCriticalSection(&NamespaceLock);

    HeapFree(GetProcessHeap(), 0, Access->LogonSid);
    HeapFree(GetProcessHeap(), 0, Access);
}
