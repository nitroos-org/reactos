/*
 * PROJECT:     ReactOS Kernel
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Lowbox (AppContainer) tokens: NtCreateLowBoxToken
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * A lowbox token is a copy of an existing token that also carries an
 * AppContainer package SID, a set of capability SIDs, the AppContainer number
 * of the package in the token's session and kernel handles to the objects of
 * the handles its creator passed (Windows 8 and later; CreateAppContainerToken
 * and the Chromium sandbox pass the AppContainer named object directory, which
 * so keeps its name as long as the token exists: a named object loses its name
 * with its last handle, not with its last reference). The copy runs at low integrity at most and has
 * TOKEN_LOWBOX set. NtQueryInformationToken reports the AppContainer classes
 * from it (tokencls.c).
 *
 * The package SID and capabilities are reported only: access checks do not
 * apply the AppContainer rules (a lowbox token is granted what its user and
 * groups are granted, as before this existed).
 *
 * Not measured on Windows (the documented contract only): the statuses for
 * a SID that is not a package SID, a NULL capability or handle array with a
 * count, a NULL handle in the array, the handle and capability limits, and
 * the AppContainer numbers Windows hands out.
 */

/* INCLUDES *******************************************************************/

#include <ntoskrnl.h>
#define NDEBUG
#include <debug.h>

/* DEFINES ********************************************************************/

/* At most this many handles are kept with a token (CreateAppContainerToken passes five, Chromium one) */
#define SEP_LOWBOX_MAX_HANDLES 64

/* The AppContainer number of a package in a session, shared by all its lowbox tokens */
typedef struct _SEP_LOWBOX_NUMBER
{
    LIST_ENTRY Link;
    ULONG References;
    ULONG SessionId;
    ULONG Number;
    PSID PackageSid;    /* follows the entry */
} SEP_LOWBOX_NUMBER, *PSEP_LOWBOX_NUMBER;

/* GLOBALS ********************************************************************/

static LIST_ENTRY SepLowboxNumbers = { &SepLowboxNumbers, &SepLowboxNumbers };
static EX_PUSH_LOCK SepLowboxNumberLock; /* zero: unlocked */

/* PRIVATE FUNCTIONS **********************************************************/

/* S-1-15-2 followed by seven sub-authorities (a package) or eleven (a child of one) */
static
BOOLEAN
SepIsPackageSid(
    _In_ PISID Sid)
{
    static const SID_IDENTIFIER_AUTHORITY AppPackageAuthority = { SECURITY_APP_PACKAGE_AUTHORITY };

    return RtlEqualMemory(&Sid->IdentifierAuthority, &AppPackageAuthority, sizeof(AppPackageAuthority)) &&
           (Sid->SubAuthorityCount == SECURITY_APP_PACKAGE_RID_COUNT ||
            Sid->SubAuthorityCount == SECURITY_CHILD_PACKAGE_RID_COUNT) &&
           Sid->SubAuthority[0] == SECURITY_APP_PACKAGE_BASE_RID;
}

/*
 * The number entry of a package in a session, created with the lowest number
 * not in use in that session when there is none. Every call takes a reference.
 */
static
NTSTATUS
SepAcquireLowboxNumber(
    _In_ ULONG SessionId,
    _In_ PSID PackageSid,
    _Out_ PSEP_LOWBOX_NUMBER *Result)
{
    PSEP_LOWBOX_NUMBER Entry, New;
    PLIST_ENTRY Link;
    ULONG SidLength = RtlLengthSid(PackageSid);
    ULONG Number;
    BOOLEAN Taken;

    PAGED_CODE();

    *Result = NULL;
    New = ExAllocatePoolWithTag(PagedPool, sizeof(SEP_LOWBOX_NUMBER) + SidLength, TAG_SE_LOWBOX);
    if (New == NULL)
        return STATUS_INSUFFICIENT_RESOURCES;
    New->PackageSid = (PSID)(New + 1);
    RtlCopyMemory(New->PackageSid, PackageSid, SidLength);
    New->SessionId = SessionId;
    New->References = 1;

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&SepLowboxNumberLock);

    for (Link = SepLowboxNumbers.Flink; Link != &SepLowboxNumbers; Link = Link->Flink)
    {
        Entry = CONTAINING_RECORD(Link, SEP_LOWBOX_NUMBER, Link);
        if (Entry->SessionId == SessionId && RtlEqualSid(Entry->PackageSid, PackageSid))
        {
            Entry->References++;
            ExReleasePushLockExclusive(&SepLowboxNumberLock);
            KeLeaveCriticalRegion();
            ExFreePoolWithTag(New, TAG_SE_LOWBOX);
            *Result = Entry;
            return STATUS_SUCCESS;
        }
    }

    /* The list holds one entry per package in use: the search below ends within its length */
    for (Number = 1; ; Number++)
    {
        Taken = FALSE;
        for (Link = SepLowboxNumbers.Flink; Link != &SepLowboxNumbers; Link = Link->Flink)
        {
            Entry = CONTAINING_RECORD(Link, SEP_LOWBOX_NUMBER, Link);
            if (Entry->SessionId == SessionId && Entry->Number == Number)
            {
                Taken = TRUE;
                break;
            }
        }
        if (!Taken)
            break;
    }
    New->Number = Number;
    InsertTailList(&SepLowboxNumbers, &New->Link);

    ExReleasePushLockExclusive(&SepLowboxNumberLock);
    KeLeaveCriticalRegion();

    *Result = New;
    return STATUS_SUCCESS;
}

static
VOID
SepReleaseLowboxNumber(
    _In_ PSEP_LOWBOX_NUMBER Entry)
{
    BOOLEAN Last;

    PAGED_CODE();

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&SepLowboxNumberLock);
    Last = (--Entry->References == 0);
    if (Last)
        RemoveEntryList(&Entry->Link);
    ExReleasePushLockExclusive(&SepLowboxNumberLock);
    KeLeaveCriticalRegion();

    if (Last)
        ExFreePoolWithTag(Entry, TAG_SE_LOWBOX);
}

/**
 * @brief
 * Takes a reference to the lowbox data of a token, for a copy of the token.
 */
VOID
NTAPI
SepReferenceLowbox(
    _In_ PSEP_LOWBOX Lowbox)
{
    ASSERT(Lowbox->References > 0);
    InterlockedIncrement(&Lowbox->References);
}

/**
 * @brief
 * Drops a reference to the lowbox data of a token. The last one releases the
 * AppContainer number, closes the kept handles and frees the block.
 */
VOID
NTAPI
SepDereferenceLowbox(
    _In_ PSEP_LOWBOX Lowbox)
{
    ULONG i;

    PAGED_CODE();

    ASSERT(Lowbox->References > 0);
    if (InterlockedDecrement(&Lowbox->References) != 0)
        return;

    for (i = 0; i < Lowbox->HandleCount; i++)
        ObCloseHandle(Lowbox->Handles[i], KernelMode);
    if (Lowbox->NumberEntry)
        SepReleaseLowboxNumber(Lowbox->NumberEntry);
    ExFreePoolWithTag(Lowbox, TAG_SE_LOWBOX);
}

/*
 * Builds the lowbox data from captured values: the package SID and the
 * capabilities are copied into the block, the kernel handles are taken over
 * by it. Nothing here touches caller memory.
 */
static
NTSTATUS
SepCreateLowbox(
    _In_ PSID PackageSid,
    _In_ ULONG CapabilityCount,
    _In_reads_opt_(CapabilityCount) PSID_AND_ATTRIBUTES Capabilities,
    _In_ ULONG HandleCount,
    _In_reads_opt_(HandleCount) HANDLE *Handles,
    _In_ ULONG SessionId,
    _Out_ PSEP_LOWBOX *Result)
{
    PSEP_LOWBOX Lowbox;
    ULONG PackageLength, CapabilitiesLength = 0, Size, Left;
    PVOID SidArea, SidEnd;
    NTSTATUS Status;

    PAGED_CODE();

    *Result = NULL;
    PackageLength = RtlLengthSid(PackageSid);
    if (CapabilityCount > 0)
        CapabilitiesLength = CapabilityCount * sizeof(SID_AND_ATTRIBUTES) +
                             RtlLengthSidAndAttributes(CapabilityCount, Capabilities);

    /* The block: header, handles, capability array and SIDs, package SID (pointer-aligned pieces) */
    Size = ALIGN_UP_BY(sizeof(SEP_LOWBOX), sizeof(PVOID)) +
           ALIGN_UP_BY(HandleCount * sizeof(HANDLE), sizeof(PVOID)) +
           ALIGN_UP_BY(CapabilitiesLength, sizeof(PVOID)) +
           PackageLength;
    Lowbox = ExAllocatePoolWithTag(PagedPool, Size, TAG_SE_LOWBOX);
    if (Lowbox == NULL)
        return STATUS_INSUFFICIENT_RESOURCES;
    RtlZeroMemory(Lowbox, Size);
    Lowbox->References = 1;

    Lowbox->Handles = (HANDLE *)((PUCHAR)Lowbox + ALIGN_UP_BY(sizeof(SEP_LOWBOX), sizeof(PVOID)));
    Lowbox->Capabilities = (PSID_AND_ATTRIBUTES)((PUCHAR)Lowbox->Handles +
                                                 ALIGN_UP_BY(HandleCount * sizeof(HANDLE), sizeof(PVOID)));
    Lowbox->PackageSid = (PSID)((PUCHAR)Lowbox->Capabilities + ALIGN_UP_BY(CapabilitiesLength, sizeof(PVOID)));
    RtlCopySid(PackageLength, Lowbox->PackageSid, PackageSid);

    if (CapabilityCount > 0)
    {
        SidArea = &Lowbox->Capabilities[CapabilityCount];
        Status = RtlCopySidAndAttributesArray(CapabilityCount,
                                              Capabilities,
                                              CapabilitiesLength - CapabilityCount * sizeof(SID_AND_ATTRIBUTES),
                                              Lowbox->Capabilities,
                                              SidArea,
                                              &SidEnd,
                                              &Left);
        if (!NT_SUCCESS(Status))
        {
            ExFreePoolWithTag(Lowbox, TAG_SE_LOWBOX);
            return Status;
        }
        Lowbox->CapabilityCount = CapabilityCount;
    }
    else
    {
        Lowbox->Capabilities = NULL;
    }

    Status = SepAcquireLowboxNumber(SessionId, Lowbox->PackageSid, &Lowbox->NumberEntry);
    if (!NT_SUCCESS(Status))
    {
        ExFreePoolWithTag(Lowbox, TAG_SE_LOWBOX);
        return Status;
    }
    Lowbox->Number = Lowbox->NumberEntry->Number;

    /* From here on the block owns the kernel handles */
    if (HandleCount > 0)
        RtlCopyMemory(Lowbox->Handles, Handles, HandleCount * sizeof(HANDLE));
    Lowbox->HandleCount = HandleCount;

    *Result = Lowbox;
    return STATUS_SUCCESS;
}

/* PUBLIC FUNCTIONS ***********************************************************/

/**
 * @brief
 * Creates a lowbox (AppContainer) token from an existing token.
 *
 * @param[out] TokenHandle
 * Receives a handle to the new token.
 *
 * @param[in] ExistingTokenHandle
 * The token to copy, opened with TOKEN_DUPLICATE. The copy keeps its type,
 * impersonation level, user, groups, restricting SIDs and privileges.
 *
 * @param[in] DesiredAccess
 * The access of the new handle; 0 gives the access of ExistingTokenHandle.
 *
 * @param[in] ObjectAttributes
 * Optional attributes of the new token object.
 *
 * @param[in] PackageSid
 * The AppContainer SID: S-1-15-2 and seven more sub-authorities, or eleven for a child AppContainer.
 *
 * @param[in] CapabilityCount, Capabilities
 * The capability SIDs of the token (no more than a token can have groups).
 *
 * @param[in] HandleCount, Handles
 * Handles whose objects the token keeps open (a kernel handle each) while it exists (at most SEP_LOWBOX_MAX_HANDLES).
 *
 * @return
 * STATUS_SUCCESS, STATUS_INVALID_PARAMETER for a SID that is no package SID or too many handles,
 * STATUS_INVALID_SID for a malformed SID, STATUS_ACCESS_VIOLATION for bad caller memory, or the status
 * of referencing a handle or creating the token.
 */
NTSTATUS
NTAPI
NtCreateLowBoxToken(
    _Out_ PHANDLE TokenHandle,
    _In_ HANDLE ExistingTokenHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ PSID PackageSid,
    _In_ ULONG CapabilityCount,
    _In_reads_opt_(CapabilityCount) PSID_AND_ATTRIBUTES Capabilities,
    _In_ ULONG HandleCount,
    _In_reads_opt_(HandleCount) HANDLE *Handles)
{
    KPROCESSOR_MODE PreviousMode = ExGetPreviousMode();
    ULONG PackageBuffer[SECURITY_MAX_SID_SIZE / sizeof(ULONG)];
    PISID Package = (PISID)PackageBuffer;
    HANDLE CapturedHandles[SEP_LOWBOX_MAX_HANDLES];
    HANDLE KernelHandles[SEP_LOWBOX_MAX_HANDLES];
    PSID_AND_ATTRIBUTES CapturedCapabilities = NULL;
    ULONG CapturedLength, KernelHandleCount = 0, i;
    PVOID Object;
    UCHAR SubAuthorityCount;
    OBJECT_HANDLE_INFORMATION HandleInformation;
    PTOKEN Token = NULL, NewToken = NULL;
    PSEP_LOWBOX Lowbox = NULL;
    HANDLE NewHandle;
    NTSTATUS Status;

    PAGED_CODE();

    if (PackageSid == NULL || HandleCount > SEP_LOWBOX_MAX_HANDLES)
        return STATUS_INVALID_PARAMETER;

    /* Probe the output and copy the package SID and the handle array once */
    _SEH2_TRY
    {
        if (PreviousMode != KernelMode)
        {
            ProbeForWriteHandle(TokenHandle);
            ProbeForRead(PackageSid, FIELD_OFFSET(SID, SubAuthority), sizeof(UCHAR));
        }
        SubAuthorityCount = ((PISID)PackageSid)->SubAuthorityCount;
        if (SubAuthorityCount > SID_MAX_SUB_AUTHORITIES)
            _SEH2_YIELD(return STATUS_INVALID_SID);
        if (PreviousMode != KernelMode)
            ProbeForRead(PackageSid, RtlLengthRequiredSid(SubAuthorityCount), sizeof(UCHAR));
        RtlCopyMemory(Package, PackageSid, RtlLengthRequiredSid(SubAuthorityCount));

        if (HandleCount > 0)
        {
            if (PreviousMode != KernelMode)
                ProbeForRead(Handles, HandleCount * sizeof(HANDLE), sizeof(ULONG));
            RtlCopyMemory(CapturedHandles, Handles, HandleCount * sizeof(HANDLE));
        }
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        _SEH2_YIELD(return _SEH2_GetExceptionCode());
    }
    _SEH2_END;

    /* Only the copy counts from here on; the caller may have changed the count between the reads */
    if (Package->SubAuthorityCount != SubAuthorityCount || !RtlValidSid(Package))
        return STATUS_INVALID_SID;
    if (!SepIsPackageSid(Package))
        return STATUS_INVALID_PARAMETER;

    /* The capabilities: probed, bounded (SE_MAXIMUM_GROUP_LIMIT) and validated by the capture */
    if (CapabilityCount > 0)
    {
        Status = SeCaptureSidAndAttributesArray(Capabilities,
                                                CapabilityCount,
                                                PreviousMode,
                                                NULL,
                                                0,
                                                PagedPool,
                                                TRUE,
                                                &CapturedCapabilities,
                                                &CapturedLength);
        if (!NT_SUCCESS(Status))
        {
            DPRINT1("NtCreateLowBoxToken(): capturing the capabilities failed (Status 0x%lx)\n", Status);
            return Status;
        }
    }

    Status = ObReferenceObjectByHandle(ExistingTokenHandle,
                                       TOKEN_DUPLICATE,
                                       SeTokenObjectType,
                                       PreviousMode,
                                       (PVOID *)&Token,
                                       &HandleInformation);
    if (!NT_SUCCESS(Status))
        goto Quit;

    /* A kernel handle (no access) to the object of each handle of the captured copy */
    for (i = 0; i < HandleCount; i++)
    {
        Status = ObReferenceObjectByHandle(CapturedHandles[i],
                                           0,
                                           NULL,
                                           PreviousMode,
                                           &Object,
                                           NULL);
        if (!NT_SUCCESS(Status))
        {
            DPRINT1("NtCreateLowBoxToken(): handle %lu is not valid (Status 0x%lx)\n", i, Status);
            goto Quit;
        }
        Status = ObOpenObjectByPointer(Object,
                                       OBJ_KERNEL_HANDLE,
                                       NULL,
                                       0,
                                       NULL,
                                       KernelMode,
                                       &KernelHandles[i]);
        ObDereferenceObject(Object);
        if (!NT_SUCCESS(Status))
        {
            DPRINT1("NtCreateLowBoxToken(): handle %lu could not be kept (Status 0x%lx)\n", i, Status);
            goto Quit;
        }
        KernelHandleCount++;
    }

    /* The copy keeps the type and level of the existing token */
    Status = SepDuplicateToken(Token,
                               ObjectAttributes,
                               FALSE,
                               Token->TokenType,
                               Token->ImpersonationLevel,
                               PreviousMode,
                               &NewToken);
    if (!NT_SUCCESS(Status))
    {
        NewToken = NULL;
        goto Quit;
    }

    /* Nobody else sees the new token yet; it takes over the kernel handles */
    Status = SepCreateLowbox(Package,
                             CapabilityCount,
                             CapturedCapabilities,
                             KernelHandleCount,
                             KernelHandles,
                             NewToken->SessionId,
                             &Lowbox);
    if (!NT_SUCCESS(Status))
        goto Quit;
    KernelHandleCount = 0;

    SepAcquireTokenLockExclusive(NewToken);

    /* A copy of a lowbox token gets the new lowbox data instead of the old one */
    if (NewToken->Lowbox)
        SepDereferenceLowbox(NewToken->Lowbox);
    NewToken->Lowbox = Lowbox;
    Lowbox = NULL;
    NewToken->TokenFlags |= TOKEN_LOWBOX;

    /* A lowbox token runs at low integrity at most; an integrity group follows the level */
    if (NewToken->IntegrityLevel > SECURITY_MANDATORY_LOW_RID)
    {
        NewToken->IntegrityLevel = SECURITY_MANDATORY_LOW_RID;
        for (i = 1; i < NewToken->UserAndGroupCount; i++)
        {
            if ((NewToken->UserAndGroups[i].Attributes & SE_GROUP_INTEGRITY) &&
                SepIsMandatoryLabelSid(NewToken->UserAndGroups[i].Sid, NULL))
            {
                *RtlSubAuthoritySid(NewToken->UserAndGroups[i].Sid, 0) = SECURITY_MANDATORY_LOW_RID;
            }
        }
    }
    ExAllocateLocallyUniqueId(&NewToken->ModifiedId);

    SepReleaseTokenLock(NewToken);

    /* ObInsertObject dereferences the token when it fails */
    Status = ObInsertObject(NewToken,
                            NULL,
                            DesiredAccess ? DesiredAccess : HandleInformation.GrantedAccess,
                            0,
                            NULL,
                            &NewHandle);
    NewToken = NULL;
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("NtCreateLowBoxToken(): inserting the token failed (Status 0x%lx)\n", Status);
        goto Quit;
    }

    _SEH2_TRY
    {
        *TokenHandle = NewHandle;
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        /* As NtDuplicateToken: the handle stays with the process */
        Status = _SEH2_GetExceptionCode();
    }
    _SEH2_END;

Quit:
    if (NewToken)
        ObDereferenceObject(NewToken);
    for (i = 0; i < KernelHandleCount; i++)
        ObCloseHandle(KernelHandles[i], KernelMode);
    if (Token)
        ObDereferenceObject(Token);
    if (CapturedCapabilities)
        SeReleaseSidAndAttributesArray(CapturedCapabilities, PreviousMode, TRUE);

    return Status;
}

/* EOF */
