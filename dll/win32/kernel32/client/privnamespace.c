/*
 * COPYRIGHT:       See COPYING in the top level directory
 * PROJECT:         ReactOS system libraries
 * FILE:            dll/win32/kernel32/client/privnamespace.c
 * PURPOSE:         Boundary Descriptor and Private Namespace functions
 * PROGRAMMER:      Tomas Srnka
 */

/* INCLUDES ******************************************************************/

#include <k32.h>

#define NDEBUG
#include <debug.h>

/* GLOBALS *******************************************************************/

/*
 * Functional (non-isolating) implementation of the Vista boundary-descriptor /
 * private-namespace family.
 *
 * A boundary descriptor is kept as an opaque, process-local heap object.  SID
 * and integrity-level membership is not enforced, so no namespace isolation is
 * provided: a private namespace is simply an object directory created under the
 * caller's BaseNamedObjects directory, named after the alias prefix.  Objects
 * subsequently created as "AliasPrefix\\ObjectName" resolve through the object
 * manager's normal path parsing.
 *
 * This is sufficient for callers (such as the Microsoft CLR's inter-process IPC
 * block) that only rely on the namespace existing within a single process.
 * True cross-process isolation keyed by a boundary descriptor requires object
 * manager support and is not implemented here.
 */

#define BOUNDARY_DESCRIPTOR_MAGIC 0x42444E42 /* 'BNDB' */

typedef struct _BASE_BOUNDARY_DESCRIPTOR
{
    ULONG Magic;
    ULONG Flags;
} BASE_BOUNDARY_DESCRIPTOR, *PBASE_BOUNDARY_DESCRIPTOR;

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
    PBASE_BOUNDARY_DESCRIPTOR Descriptor;

    UNREFERENCED_PARAMETER(Name);

    Descriptor = RtlAllocateHeap(RtlGetProcessHeap(),
                                 HEAP_ZERO_MEMORY,
                                 sizeof(*Descriptor));
    if (!Descriptor)
    {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return NULL;
    }

    Descriptor->Magic = BOUNDARY_DESCRIPTOR_MAGIC;
    Descriptor->Flags = Flags;

    return (HANDLE)Descriptor;
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
    PBASE_BOUNDARY_DESCRIPTOR Descriptor;

    UNREFERENCED_PARAMETER(RequiredSid);

    if (!BoundaryDescriptor ||
        !(Descriptor = *BoundaryDescriptor) ||
        Descriptor->Magic != BOUNDARY_DESCRIPTOR_MAGIC)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    /* Membership is not enforced in this implementation */
    return TRUE;
}

/*
 * @implemented
 */
VOID
WINAPI
DeleteBoundaryDescriptor(
    _In_ HANDLE BoundaryDescriptor)
{
    PBASE_BOUNDARY_DESCRIPTOR Descriptor = BoundaryDescriptor;

    if (Descriptor && Descriptor->Magic == BOUNDARY_DESCRIPTOR_MAGIC)
    {
        Descriptor->Magic = 0;
        RtlFreeHeap(RtlGetProcessHeap(), 0, Descriptor);
    }
}

/*
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
    UNICODE_STRING AliasName;
    NTSTATUS Status;
    HANDLE DirectoryHandle;

    UNREFERENCED_PARAMETER(lpBoundaryDescriptor);

    if (!lpAliasPrefix)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return NULL;
    }

    if (!RtlCreateUnicodeString(&AliasName, lpAliasPrefix))
    {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return NULL;
    }

    /* Back the namespace with an object directory under BaseNamedObjects */
    BaseFormatObjectAttributes(&ObjectAttributes,
                               lpPrivateNamespaceAttributes,
                               &AliasName);

    /*
     * Creating a private namespace that already exists must fail with
     * ERROR_ALREADY_EXISTS on Windows: callers (the CLR among them) then fall
     * back to OpenPrivateNamespace.  BaseFormatObjectAttributes sets OBJ_OPENIF
     * for named objects, which would instead open the existing directory
     * with DIRECTORY_ALL_ACCESS and fail with access denied against the
     * restrictive security descriptor the first creator gave it.
     */
    ObjectAttributes.Attributes &= ~OBJ_OPENIF;

    Status = NtCreateDirectoryObject(&DirectoryHandle,
                                     DIRECTORY_ALL_ACCESS,
                                     &ObjectAttributes);
    RtlFreeUnicodeString(&AliasName);
    if (!NT_SUCCESS(Status))
    {
        BaseSetLastNTError(Status);
        return NULL;
    }

    return DirectoryHandle;
}

/*
 * @implemented
 */
HANDLE
WINAPI
OpenPrivateNamespaceW(
    _In_ LPVOID lpBoundaryDescriptor,
    _In_ LPCWSTR lpAliasPrefix)
{
    OBJECT_ATTRIBUTES ObjectAttributes;
    UNICODE_STRING AliasName;
    NTSTATUS Status;
    HANDLE DirectoryHandle, RootDirectory;

    UNREFERENCED_PARAMETER(lpBoundaryDescriptor);

    if (!lpAliasPrefix)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return NULL;
    }

    RootDirectory = BasepGetNamedObjectDirectory();
    if (!RootDirectory)
    {
        SetLastError(ERROR_PATH_NOT_FOUND);
        return NULL;
    }

    RtlInitUnicodeString(&AliasName, lpAliasPrefix);
    InitializeObjectAttributes(&ObjectAttributes,
                               &AliasName,
                               0,
                               RootDirectory,
                               NULL);

    /*
     * Windows grants whatever the namespace's security descriptor allows
     * the caller; asking for DIRECTORY_ALL_ACCESS would fail against the
     * minimal DACLs applications give their namespaces (the CLR grants only
     * DIRECTORY_CREATE_OBJECT).
     */
    Status = NtOpenDirectoryObject(&DirectoryHandle,
                                   MAXIMUM_ALLOWED,
                                   &ObjectAttributes);
    if (!NT_SUCCESS(Status))
    {
        BaseSetLastNTError(Status);
        return NULL;
    }

    return DirectoryHandle;
}

/*
 * @implemented
 */
BOOLEAN
WINAPI
ClosePrivateNamespace(
    _In_ HANDLE Handle,
    _In_ ULONG Flags)
{
    UNREFERENCED_PARAMETER(Flags);

    if (!Handle)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    return NT_SUCCESS(NtClose(Handle));
}

/* EOF */
