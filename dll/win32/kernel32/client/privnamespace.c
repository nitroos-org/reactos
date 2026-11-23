/*
 * COPYRIGHT:       See COPYING in the top level directory
 * PROJECT:         ReactOS system libraries
 * FILE:            dll/win32/kernel32/client/privnamespace.c
 * PURPOSE:         Boundary Descriptor and Private Namespace functions
 * PROGRAMMER:      Tomas Srnka
 */

/* INCLUDES ******************************************************************/

#include <k32.h>
#include <reactos/boundarydesc.h>

#define NDEBUG
#include <debug.h>

/* GLOBALS *******************************************************************/

/*
 * A boundary descriptor is one heap block in the layout of reactos/boundarydesc.h (the name, the
 * SIDs, the integrity label); the block is the descriptor handle, and adding to it may move it
 * (hence the HANDLE * of AddSIDToBoundaryDescriptor). The kernel keeps the namespaces
 * (NtCreatePrivateNamespace, NtOpenPrivateNamespace; ntoskrnl/ob/obnamesp.c): a namespace is
 * found by its whole boundary, its creator must be within the boundary, and its security
 * descriptor decides who opens it ("Object Namespaces" on Microsoft Learn).
 *
 * The alias prefix is the process's own name for a namespace it created or opened: a name
 * "Alias\Object" given to the named object functions is "Object" in that namespace
 * (BasepAdjustObjectAttributesForPrivateNamespace). A name whose first part is not such an alias
 * stays a name in BaseNamedObjects.
 */

typedef struct _BASEP_NAMESPACE_ALIAS
{
    LIST_ENTRY Link;
    HANDLE Handle;
    UNICODE_STRING Alias;   /* the characters follow the entry */
} BASEP_NAMESPACE_ALIAS, *PBASEP_NAMESPACE_ALIAS;

static LIST_ENTRY BasepNamespaceAliases = { &BasepNamespaceAliases, &BasepNamespaceAliases };
RTL_CRITICAL_SECTION BasepNamespaceLock;

/* PRIVATE FUNCTIONS *********************************************************/

static
PBOUNDARY_DESCRIPTOR_HEADER
BasepGetBoundaryDescriptor(
    _In_opt_ PVOID Descriptor)
{
    PBOUNDARY_DESCRIPTOR_HEADER Header = Descriptor;

    if (!Header || Header->Version != BOUNDARY_DESCRIPTOR_VERSION ||
        Header->TotalSize < sizeof(*Header) || Header->TotalSize > BOUNDARY_DESCRIPTOR_MAX_SIZE)
    {
        return NULL;
    }
    return Header;
}

/* Appends an entry to the descriptor in *BoundaryDescriptor (which may move) */
static
BOOL
BasepAddBoundaryEntry(
    _Inout_ HANDLE *BoundaryDescriptor,
    _In_ ULONG Type,
    _In_reads_bytes_(DataSize) const VOID *Data,
    _In_ ULONG DataSize)
{
    PBOUNDARY_DESCRIPTOR_HEADER Header = *BoundaryDescriptor, New;
    PBOUNDARY_DESCRIPTOR_ENTRY Entry;
    ULONG EntrySize = sizeof(*Entry) + ALIGN_UP_BY(DataSize, sizeof(ULONG));

    if (DataSize > BOUNDARY_DESCRIPTOR_MAX_SIZE || Header->TotalSize + EntrySize > BOUNDARY_DESCRIPTOR_MAX_SIZE)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    New = RtlReAllocateHeap(RtlGetProcessHeap(), 0, Header, Header->TotalSize + EntrySize);
    if (!New)
    {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return FALSE;
    }

    Entry = (PBOUNDARY_DESCRIPTOR_ENTRY)((PUCHAR)New + New->TotalSize);
    RtlZeroMemory(Entry, EntrySize);
    Entry->Type = Type;
    Entry->Size = EntrySize;
    Entry->DataSize = DataSize;
    RtlCopyMemory(Entry + 1, Data, DataSize);
    New->TotalSize += EntrySize;
    New->EntryCount++;
    *BoundaryDescriptor = New;
    return TRUE;
}

/* Remembers the alias of a namespace handle; FALSE (and the handle closed) when there is no memory */
static
BOOL
BasepAddNamespaceAlias(
    _In_ HANDLE Handle,
    _In_ LPCWSTR lpAliasPrefix)
{
    SIZE_T Length = wcslen(lpAliasPrefix) * sizeof(WCHAR);
    PBASEP_NAMESPACE_ALIAS Entry;

    if (Length > UNICODE_STRING_MAX_BYTES ||
        !(Entry = RtlAllocateHeap(RtlGetProcessHeap(), 0, sizeof(*Entry) + Length)))
    {
        NtClose(Handle);
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return FALSE;
    }
    Entry->Handle = Handle;
    Entry->Alias.Buffer = (PWCHAR)(Entry + 1);
    Entry->Alias.Length = Entry->Alias.MaximumLength = (USHORT)Length;
    RtlCopyMemory(Entry->Alias.Buffer, lpAliasPrefix, Length);

    /* The newest first: it is the one a name with that alias goes to */
    RtlEnterCriticalSection(&BasepNamespaceLock);
    InsertHeadList(&BasepNamespaceAliases, &Entry->Link);
    RtlLeaveCriticalSection(&BasepNamespaceLock);
    return TRUE;
}

/*
 * A name "Alias\Object" relative to BaseNamedObjects, where Alias is the alias of a namespace the
 * process created or opened, becomes "Object" relative to that namespace. The UNICODE_STRING of
 * the attributes is changed in place (the callers' strings point into the caller's name).
 */
VOID
BasepAdjustObjectAttributesForPrivateNamespace(
    _Inout_ POBJECT_ATTRIBUTES ObjectAttributes)
{
    PUNICODE_STRING Name = ObjectAttributes->ObjectName;
    PBASEP_NAMESPACE_ALIAS Entry;
    UNICODE_STRING Prefix;
    PLIST_ENTRY Link;
    USHORT i, Skip;

    if (!Name || !Name->Buffer || !ObjectAttributes->RootDirectory ||
        ObjectAttributes->RootDirectory != BaseNamedObjectDirectory)
    {
        return;
    }

    for (i = 0; i < Name->Length / sizeof(WCHAR) && Name->Buffer[i] != L'\\'; i++)
        ;
    if (i == 0 || i == Name->Length / sizeof(WCHAR))
        return;
    Prefix.Buffer = Name->Buffer;
    Prefix.Length = Prefix.MaximumLength = i * sizeof(WCHAR);
    Skip = (i + 1) * sizeof(WCHAR);

    RtlEnterCriticalSection(&BasepNamespaceLock);
    for (Link = BasepNamespaceAliases.Flink; Link != &BasepNamespaceAliases; Link = Link->Flink)
    {
        Entry = CONTAINING_RECORD(Link, BASEP_NAMESPACE_ALIAS, Link);
        /* Object names are case sensitive (no OBJ_CASE_INSENSITIVE here): so are the aliases */
        if (RtlEqualUnicodeString(&Prefix, &Entry->Alias, FALSE))
        {
            ObjectAttributes->RootDirectory = Entry->Handle;
            Name->Buffer += Skip / sizeof(WCHAR);
            Name->Length -= Skip;
            Name->MaximumLength = (Name->MaximumLength > Skip) ? Name->MaximumLength - Skip : Name->Length;
            break;
        }
    }
    RtlLeaveCriticalSection(&BasepNamespaceLock);
}

/* FUNCTIONS *****************************************************************/

/*
 * @implemented
 */
HANDLE
WINAPI
CreateBoundaryDescriptorW(
    _In_ LPCWSTR Name,
    _In_ ULONG Flags)
{
    PBOUNDARY_DESCRIPTOR_HEADER Header;
    HANDLE Descriptor;
    SIZE_T Length = Name ? wcslen(Name) * sizeof(WCHAR) : 0;

    if (Length > BOUNDARY_DESCRIPTOR_MAX_SIZE / 2)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return NULL;
    }

    Header = RtlAllocateHeap(RtlGetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*Header));
    if (!Header)
    {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return NULL;
    }
    Header->Version = BOUNDARY_DESCRIPTOR_VERSION;
    Header->TotalSize = sizeof(*Header);
    Header->Flags = Flags;

    Descriptor = Header;
    if (!BasepAddBoundaryEntry(&Descriptor, BOUNDARY_ENTRY_NAME, Name ? Name : L"", (ULONG)Length))
    {
        RtlFreeHeap(RtlGetProcessHeap(), 0, Header);
        return NULL;
    }
    return Descriptor;
}

/*
 * @implemented
 */
BOOL
WINAPI
AddSIDToBoundaryDescriptor(
    _Inout_ HANDLE *BoundaryDescriptor,
    _In_ PSID RequiredSid)
{
    if (!BoundaryDescriptor ||
        !BasepGetBoundaryDescriptor(*BoundaryDescriptor) ||
        !RequiredSid ||
        !RtlValidSid(RequiredSid))
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    return BasepAddBoundaryEntry(BoundaryDescriptor, BOUNDARY_ENTRY_SID, RequiredSid, RtlLengthSid(RequiredSid));
}

/*
 * AddIntegrityLabelToBoundaryDescriptor. Measured on Windows 10 22H2: any SID with at least one subauthority is
 * taken (Windows does not check that it is an integrity SID); a NULL SID or one without subauthorities is
 * ERROR_INVALID_PARAMETER; a descriptor holds one label, the second one is ERROR_OBJECT_ALREADY_EXISTS. Ordinary SIDs
 * can be added before or after the label. The level is the last sub-authority of the SID; the creator of a
 * namespace must run at or above it.
 */
BOOL
WINAPI
AddIntegrityLabelToBoundaryDescriptor(
    _Inout_ HANDLE *BoundaryDescriptor,
    _In_ PSID IntegrityLabel)
{
    PBOUNDARY_DESCRIPTOR_HEADER Header;
    PBOUNDARY_DESCRIPTOR_ENTRY Entry;
    ULONG i;

    if (!BoundaryDescriptor ||
        !(Header = BasepGetBoundaryDescriptor(*BoundaryDescriptor)) ||
        !IntegrityLabel ||
        !RtlValidSid(IntegrityLabel) ||
        *RtlSubAuthorityCountSid(IntegrityLabel) == 0)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    Entry = (PBOUNDARY_DESCRIPTOR_ENTRY)(Header + 1);
    for (i = 0; i < Header->EntryCount; i++, Entry = (PBOUNDARY_DESCRIPTOR_ENTRY)((PUCHAR)Entry + Entry->Size))
    {
        if (Entry->Type == BOUNDARY_ENTRY_INTEGRITY_LABEL)
        {
            SetLastError(ERROR_OBJECT_ALREADY_EXISTS);
            return FALSE;
        }
    }

    return BasepAddBoundaryEntry(BoundaryDescriptor, BOUNDARY_ENTRY_INTEGRITY_LABEL, IntegrityLabel,
                                 RtlLengthSid(IntegrityLabel));
}

/*
 * @implemented
 */
VOID
WINAPI
DeleteBoundaryDescriptor(
    _In_ HANDLE BoundaryDescriptor)
{
    PBOUNDARY_DESCRIPTOR_HEADER Header = BasepGetBoundaryDescriptor(BoundaryDescriptor);

    if (Header)
    {
        Header->Version = 0;
        RtlFreeHeap(RtlGetProcessHeap(), 0, Header);
    }
}

/*
 * Creating a private namespace that exists already fails with ERROR_ALREADY_EXISTS and does not open it (callers,
 * the CLR among them, then use OpenPrivateNamespace). The creator must be within the boundary (every SID, the label
 * at or below its level): ERROR_ACCESS_DENIED otherwise.
 *
 * @implemented
 */
HANDLE
WINAPI
CreatePrivateNamespaceW(
    _In_opt_ LPSECURITY_ATTRIBUTES lpPrivateNamespaceAttributes,
    _In_ LPVOID lpBoundaryDescriptor,
    _In_ LPCWSTR lpAliasPrefix)
{
    OBJECT_ATTRIBUTES ObjectAttributes;
    NTSTATUS Status;
    HANDLE Handle;

    if (!lpAliasPrefix || !BasepGetBoundaryDescriptor(lpBoundaryDescriptor))
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return NULL;
    }

    InitializeObjectAttributes(&ObjectAttributes,
                               NULL,
                               (lpPrivateNamespaceAttributes && lpPrivateNamespaceAttributes->bInheritHandle) ?
                               OBJ_INHERIT : 0,
                               NULL,
                               lpPrivateNamespaceAttributes ? lpPrivateNamespaceAttributes->lpSecurityDescriptor : NULL);

    Status = NtCreatePrivateNamespace(&Handle, DIRECTORY_ALL_ACCESS, &ObjectAttributes, lpBoundaryDescriptor);
    if (!NT_SUCCESS(Status))
    {
        BaseSetLastNTError(Status);
        return NULL;
    }

    return BasepAddNamespaceAlias(Handle, lpAliasPrefix) ? Handle : NULL;
}

/*
 * Windows grants whatever the namespace's security descriptor allows the caller, also to a caller outside the
 * boundary; asking for DIRECTORY_ALL_ACCESS would fail against the minimal DACLs applications give their namespaces
 * (the CLR grants only DIRECTORY_CREATE_OBJECT).
 *
 * @implemented
 */
HANDLE
WINAPI
OpenPrivateNamespaceW(
    _In_ LPVOID lpBoundaryDescriptor,
    _In_ LPCWSTR lpAliasPrefix)
{
    NTSTATUS Status;
    HANDLE Handle;

    if (!lpAliasPrefix || !BasepGetBoundaryDescriptor(lpBoundaryDescriptor))
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return NULL;
    }

    Status = NtOpenPrivateNamespace(&Handle, MAXIMUM_ALLOWED, NULL, lpBoundaryDescriptor);
    if (!NT_SUCCESS(Status))
    {
        BaseSetLastNTError(Status);
        return NULL;
    }

    return BasepAddNamespaceAlias(Handle, lpAliasPrefix) ? Handle : NULL;
}

/*
 * The alias goes with the handle. PRIVATE_NAMESPACE_FLAG_DESTROY is not applied: the namespace goes away with its
 * last handle.
 *
 * @implemented
 */
BOOLEAN
WINAPI
ClosePrivateNamespace(
    _In_ HANDLE Handle,
    _In_ ULONG Flags)
{
    PBASEP_NAMESPACE_ALIAS Entry = NULL;
    PLIST_ENTRY Link;

    UNREFERENCED_PARAMETER(Flags);

    if (!Handle)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    RtlEnterCriticalSection(&BasepNamespaceLock);
    for (Link = BasepNamespaceAliases.Flink; Link != &BasepNamespaceAliases; Link = Link->Flink)
    {
        if (CONTAINING_RECORD(Link, BASEP_NAMESPACE_ALIAS, Link)->Handle == Handle)
        {
            Entry = CONTAINING_RECORD(Link, BASEP_NAMESPACE_ALIAS, Link);
            RemoveEntryList(&Entry->Link);
            break;
        }
    }
    RtlLeaveCriticalSection(&BasepNamespaceLock);
    if (Entry)
        RtlFreeHeap(RtlGetProcessHeap(), 0, Entry);

    return NT_SUCCESS(NtClose(Handle));
}

/* EOF */
