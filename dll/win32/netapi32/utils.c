/*
 * COPYRIGHT:       See COPYING in the top level directory
 * PROJECT:         NetAPI DLL
 * FILE:            reactos/dll/win32/netapi32/utils.c
 * PURPOSE:         Helper functions
 *
 * PROGRAMMERS:     Eric Kohl
 */

/* INCLUDES ******************************************************************/

#include "netapi32.h"

WINE_DEFAULT_DEBUG_CHANNEL(netapi32);

/* GLOBALS *******************************************************************/

static SID_IDENTIFIER_AUTHORITY NtAuthority = {SECURITY_NT_AUTHORITY};

/* FUNCTIONS *****************************************************************/

NTSTATUS
GetAccountDomainSid(IN PUNICODE_STRING ServerName,
                    OUT PSID *AccountDomainSid)
{
    PPOLICY_ACCOUNT_DOMAIN_INFO AccountDomainInfo = NULL;
    LSA_OBJECT_ATTRIBUTES ObjectAttributes;
    LSA_HANDLE PolicyHandle = NULL;
    ULONG Length = 0;
    NTSTATUS Status;

    memset(&ObjectAttributes, 0, sizeof(LSA_OBJECT_ATTRIBUTES));

    Status = LsaOpenPolicy(ServerName,
                           &ObjectAttributes,
                           POLICY_VIEW_LOCAL_INFORMATION,
                           &PolicyHandle);
    if (!NT_SUCCESS(Status))
    {
        ERR("LsaOpenPolicy failed (Status %08lx)\n", Status);
        return Status;
    }

    Status = LsaQueryInformationPolicy(PolicyHandle,
                                       PolicyAccountDomainInformation,
                                       (PVOID *)&AccountDomainInfo);
    if (!NT_SUCCESS(Status))
    {
        ERR("LsaQueryInformationPolicy failed (Status %08lx)\n", Status);
        goto done;
    }

    Length = RtlLengthSid(AccountDomainInfo->DomainSid);

    *AccountDomainSid = RtlAllocateHeap(RtlGetProcessHeap(), 0, Length);
    if (*AccountDomainSid == NULL)
    {
        ERR("Failed to allocate SID\n");
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto done;
    }

    memcpy(*AccountDomainSid, AccountDomainInfo->DomainSid, Length);

done:
    if (AccountDomainInfo != NULL)
        LsaFreeMemory(AccountDomainInfo);

    LsaClose(PolicyHandle);

    return Status;
}


NTSTATUS
GetBuiltinDomainSid(OUT PSID *BuiltinDomainSid)
{
    PSID Sid = NULL;
    PULONG Ptr;
    NTSTATUS Status = STATUS_SUCCESS;

    *BuiltinDomainSid = NULL;

    Sid = RtlAllocateHeap(RtlGetProcessHeap(),
                          0,
                          RtlLengthRequiredSid(1));
    if (Sid == NULL)
        return STATUS_INSUFFICIENT_RESOURCES;

    Status = RtlInitializeSid(Sid,
                              &NtAuthority,
                              1);
    if (!NT_SUCCESS(Status))
        goto done;

    Ptr = RtlSubAuthoritySid(Sid, 0);
    *Ptr = SECURITY_BUILTIN_DOMAIN_RID;

    *BuiltinDomainSid = Sid;

done:
    if (!NT_SUCCESS(Status))
    {
        if (Sid != NULL)
            RtlFreeHeap(RtlGetProcessHeap(), 0, Sid);
    }

    return Status;
}


NTSTATUS
OpenAccountDomain(IN SAM_HANDLE ServerHandle,
                  IN PUNICODE_STRING ServerName,
                  IN ULONG DesiredAccess,
                  OUT PSAM_HANDLE DomainHandle)
{
    PSID DomainSid = NULL;
    NTSTATUS Status;

    Status = GetAccountDomainSid(ServerName,
                                 &DomainSid);
    if (!NT_SUCCESS(Status))
    {
        ERR("GetAccountDomainSid failed (Status %08lx)\n", Status);
        return Status;
    }

    Status = SamOpenDomain(ServerHandle,
                           DesiredAccess,
                           DomainSid,
                           DomainHandle);

    RtlFreeHeap(RtlGetProcessHeap(), 0, DomainSid);

    if (!NT_SUCCESS(Status))
    {
        ERR("SamOpenDomain failed (Status %08lx)\n", Status);
    }

    return Status;
}


NTSTATUS
OpenBuiltinDomain(IN SAM_HANDLE ServerHandle,
                  IN ULONG DesiredAccess,
                  OUT PSAM_HANDLE DomainHandle)
{
    PSID DomainSid = NULL;
    NTSTATUS Status;

    Status = GetBuiltinDomainSid(&DomainSid);
    if (!NT_SUCCESS(Status))
    {
        ERR("GetBuiltinDomainSid failed (Status %08lx)\n", Status);
        return Status;
    }

    Status = SamOpenDomain(ServerHandle,
                           DesiredAccess,
                           DomainSid,
                           DomainHandle);

    RtlFreeHeap(RtlGetProcessHeap(), 0, DomainSid);

    if (!NT_SUCCESS(Status))
    {
        ERR("SamOpenDomain failed (Status %08lx)\n", Status);
    }

    return Status;
}


NET_API_STATUS
BuildSidFromSidAndRid(IN PSID SrcSid,
                      IN ULONG RelativeId,
                      OUT PSID *DestSid)
{
    UCHAR RidCount;
    PSID DstSid;
    ULONG i;
    ULONG DstSidSize;
    PULONG p, q;
    NET_API_STATUS ApiStatus = NERR_Success;

    RidCount = *RtlSubAuthorityCountSid(SrcSid);
    if (RidCount >= 8)
        return ERROR_INVALID_PARAMETER;

    DstSidSize = RtlLengthRequiredSid(RidCount + 1);

    ApiStatus = NetApiBufferAllocate(DstSidSize,
                                     &DstSid);
    if (ApiStatus != NERR_Success)
        return ApiStatus;

    RtlInitializeSid(DstSid,
                     RtlIdentifierAuthoritySid(SrcSid),
                     RidCount + 1);

    for (i = 0; i < (ULONG)RidCount; i++)
    {
        p = RtlSubAuthoritySid(SrcSid, i);
        q = RtlSubAuthoritySid(DstSid, i);
        *q = *p;
    }

    q = RtlSubAuthoritySid(DstSid, (ULONG)RidCount);
    *q = RelativeId;

    *DestSid = DstSid;

    return NERR_Success;
}


VOID
CopySidFromSidAndRid(
    _Out_ PSID DstSid,
    _In_ PSID SrcSid,
    _In_ ULONG RelativeId)
{
    UCHAR RidCount;
    ULONG i;
    PULONG p, q;

    RidCount = *RtlSubAuthorityCountSid(SrcSid);
    if (RidCount >= 8)
        return;

    RtlInitializeSid(DstSid,
                     RtlIdentifierAuthoritySid(SrcSid),
                     RidCount + 1);

    for (i = 0; i < (ULONG)RidCount; i++)
    {
        p = RtlSubAuthoritySid(SrcSid, i);
        q = RtlSubAuthoritySid(DstSid, i);
        *q = *p;
    }

    q = RtlSubAuthoritySid(DstSid, (ULONG)RidCount);
    *q = RelativeId;
}


/*
 * Packs entries that were built one by one (each a structure followed by its
 * strings, as a separate NetApiBuffer) into the one buffer an enumeration
 * returns: the array of structures first, the strings behind it. The pointer
 * members of every structure (PtrOffsets) that point into its own block are
 * moved to the copy of the strings.
 */
NET_API_STATUS
NetpPackEnumEntries(
    _In_ ULONG Count,
    _In_ PVOID *Blocks,
    _In_ PULONG BlockSizes,   /* size of each block: structure and strings */
    _In_ ULONG FixedSize,
    _In_ const USHORT *PtrOffsets,
    _In_ ULONG OffsetCount,
    _Out_ PVOID *Buffer)
{
    NET_API_STATUS ApiStatus;
    PBYTE Base, Entry, Strings;
    ULONG TotalSize, StringSize, i, j;
    PBYTE *Member;

    *Buffer = NULL;

    if (Count == 0)
        return NERR_Success;

    TotalSize = Count * FixedSize;
    for (i = 0; i < Count; i++)
        TotalSize += (BlockSizes[i] - FixedSize + 7) & ~7;

    ApiStatus = NetApiBufferAllocate(TotalSize, (PVOID*)&Base);
    if (ApiStatus != NERR_Success)
        return ApiStatus;

    ZeroMemory(Base, TotalSize);

    Strings = Base + Count * FixedSize;
    for (i = 0; i < Count; i++)
    {
        Entry = Base + i * FixedSize;
        memcpy(Entry, Blocks[i], FixedSize);

        StringSize = BlockSizes[i] - FixedSize;
        memcpy(Strings, (PBYTE)Blocks[i] + FixedSize, StringSize);

        for (j = 0; j < OffsetCount; j++)
        {
            Member = (PBYTE *)(Entry + PtrOffsets[j]);
            if (*Member != NULL)
                *Member = Strings + (*Member - ((PBYTE)Blocks[i] + FixedSize));
        }

        Strings += (StringSize + 7) & ~7;
    }

    *Buffer = Base;
    return NERR_Success;
}

/* EOF */
