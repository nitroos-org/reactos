/*
 * PROJECT:         Filesystem Filter Manager
 * LICENSE:         GPL - See COPYING in the top level directory
 * FILE:            drivers/filters/fltmgr/Misc.c
 * PURPOSE:         Uncataloged functions
 * PROGRAMMERS:     Ged Murphy (gedmurphy@reactos.org)
 */

/* INCLUDES ******************************************************************/

#include "fltmgr.h"
#include "fltmgrint.h"

#define NDEBUG
#include <debug.h>


/* DATA *********************************************************************/




/* EXPORTED FUNCTIONS ******************************************************/

/*
 * WDK: "a security descriptor whose DACL grants the given access to the system and to the administrators
 * only". Absolute format, the ACL behind the descriptor in the same allocation, no owner or group (whoever
 * assigns it to an object fills those in). Freed with FltFreeSecurityDescriptor.
 */
NTSTATUS
FLTAPI
FltBuildDefaultSecurityDescriptor(
    _Outptr_ PSECURITY_DESCRIPTOR *SecurityDescriptor,
    _In_ ACCESS_MASK DesiredAccess
)
{
    PSECURITY_DESCRIPTOR Descriptor;
    PACL Dacl;
    ULONG AclLength;
    NTSTATUS Status;

    PAGED_CODE();

    *SecurityDescriptor = NULL;

    AclLength = sizeof(ACL) +
                2 * FIELD_OFFSET(ACCESS_ALLOWED_ACE, SidStart) +
                RtlLengthSid(SeExports->SeLocalSystemSid) +
                RtlLengthSid(SeExports->SeAliasAdminsSid);

    Descriptor = ExAllocatePoolWithTag(PagedPool, sizeof(SECURITY_DESCRIPTOR) + AclLength, FM_TAG_SECURITY);
    if (Descriptor == NULL)
        return STATUS_INSUFFICIENT_RESOURCES;

    Dacl = (PACL)((PUCHAR)Descriptor + sizeof(SECURITY_DESCRIPTOR));

    Status = RtlCreateAcl(Dacl, AclLength, ACL_REVISION);
    if (NT_SUCCESS(Status))
        Status = RtlAddAccessAllowedAce(Dacl, ACL_REVISION, DesiredAccess, SeExports->SeLocalSystemSid);
    if (NT_SUCCESS(Status))
        Status = RtlAddAccessAllowedAce(Dacl, ACL_REVISION, DesiredAccess, SeExports->SeAliasAdminsSid);
    if (NT_SUCCESS(Status))
        Status = RtlCreateSecurityDescriptor(Descriptor, SECURITY_DESCRIPTOR_REVISION);
    if (NT_SUCCESS(Status))
        Status = RtlSetDaclSecurityDescriptor(Descriptor, TRUE, Dacl, FALSE);

    if (!NT_SUCCESS(Status))
    {
        ExFreePoolWithTag(Descriptor, FM_TAG_SECURITY);
        return Status;
    }

    *SecurityDescriptor = Descriptor;
    return STATUS_SUCCESS;
}

VOID
FLTAPI
FltFreeSecurityDescriptor(
    _In_ PSECURITY_DESCRIPTOR SecurityDescriptor
)
{
    PAGED_CODE();

    if (SecurityDescriptor)
        ExFreePoolWithTag(SecurityDescriptor, FM_TAG_SECURITY);
}

NTSTATUS
FLTAPI
FltGetFileNameInformationUnsafe(
    _In_ PFILE_OBJECT FileObject,
    _In_opt_ PFLT_INSTANCE Instance,
    _In_ FLT_FILE_NAME_OPTIONS NameOptions,
    _Outptr_ PFLT_FILE_NAME_INFORMATION *FileNameInformation)
{
    UNREFERENCED_PARAMETER(FileObject);
    UNREFERENCED_PARAMETER(Instance);
    UNREFERENCED_PARAMETER(NameOptions);
    *FileNameInformation = NULL;
    return 0;
}

NTSTATUS
FLTAPI
FltGetFileNameInformation(
    _In_ PFLT_CALLBACK_DATA CallbackData,
    _In_ FLT_FILE_NAME_OPTIONS NameOptions,
    _Outptr_ PFLT_FILE_NAME_INFORMATION *FileNameInformation)
{
    UNREFERENCED_PARAMETER(CallbackData);
    UNREFERENCED_PARAMETER(NameOptions);
    *FileNameInformation = NULL;
    return 0;
}

NTSTATUS
FLTAPI
FltGetDestinationFileNameInformation(
    _In_ PFLT_INSTANCE Instance,
    _In_ PFILE_OBJECT FileObject,
    _In_opt_ HANDLE RootDirectory,
    _In_reads_bytes_(FileNameLength) PWSTR FileName,
    _In_ ULONG FileNameLength,
    _In_ FLT_FILE_NAME_OPTIONS NameOptions,
    _Outptr_ PFLT_FILE_NAME_INFORMATION *RetFileNameInformation)
{
    UNREFERENCED_PARAMETER(Instance);
    UNREFERENCED_PARAMETER(FileObject);
    UNREFERENCED_PARAMETER(RootDirectory);
    UNREFERENCED_PARAMETER(FileName);
    UNREFERENCED_PARAMETER(FileNameLength);
    UNREFERENCED_PARAMETER(NameOptions);
    *RetFileNameInformation = NULL;
    return 0;
}

VOID
FLTAPI
FltReleaseFileNameInformation(
    _In_ PFLT_FILE_NAME_INFORMATION FileNameInformation)
{
    UNREFERENCED_PARAMETER(FileNameInformation);
}
