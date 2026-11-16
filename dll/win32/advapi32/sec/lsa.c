/*
 * COPYRIGHT:       See COPYING in the top level directory
 * PROJECT:         ReactOS system libraries
 * FILE:            dll/win32/advapi32/sec/lsa.c
 * PURPOSE:         Local security authority functions
 * PROGRAMMER:      Emanuele Aliberti
 * UPDATE HISTORY:
 *      19990322 EA created
 *      19990515 EA stubs
 *      20030202 KJK compressed stubs
 */

#include <advapi32.h>

#include <lsa_c.h>

WINE_DEFAULT_DEBUG_CHANNEL(advapi);

static
BOOL
LsapIsLocalComputer(PLSA_UNICODE_STRING ServerName)
{
    DWORD dwSize = MAX_COMPUTERNAME_LENGTH + 1;
    BOOL Result;
    LPWSTR buf;
    PCWSTR pSrvName;

    if (ServerName == NULL || ServerName->Length == 0 || ServerName->Buffer == NULL)
        return TRUE;

    pSrvName = ServerName->Buffer;
    buf = HeapAlloc(GetProcessHeap(), 0, dwSize * sizeof(WCHAR));
    Result = GetComputerNameW(buf, &dwSize);
    if (Result && (pSrvName[0] == L'\\') && (pSrvName[1] == L'\\'))
        pSrvName += 2;
    Result = Result && !lstrcmpW(pSrvName, buf);
    HeapFree(GetProcessHeap(), 0, buf);

    return Result;
}


handle_t
__RPC_USER
PLSAPR_SERVER_NAME_bind(PLSAPR_SERVER_NAME pszSystemName)
{
    handle_t hBinding = NULL;
    LPWSTR pszStringBinding;
    RPC_STATUS status;

    TRACE("PLSAPR_SERVER_NAME_bind() called\n");

    status = RpcStringBindingComposeW(NULL,
                                      L"ncacn_np",
                                      pszSystemName,
                                      L"\\pipe\\lsarpc",
                                      NULL,
                                      &pszStringBinding);
    if (status)
    {
        TRACE("RpcStringBindingCompose returned 0x%x\n", status);
        return NULL;
    }

    /* Set the binding handle that will be used to bind to the server. */
    status = RpcBindingFromStringBindingW(pszStringBinding,
                                          &hBinding);
    if (status)
    {
        TRACE("RpcBindingFromStringBinding returned 0x%x\n", status);
    }

    status = RpcStringFreeW(&pszStringBinding);
    if (status)
    {
        TRACE("RpcStringFree returned 0x%x\n", status);
    }

    return hBinding;
}


void
__RPC_USER
PLSAPR_SERVER_NAME_unbind(PLSAPR_SERVER_NAME pszSystemName,
                          handle_t hBinding)
{
    RPC_STATUS status;

    TRACE("PLSAPR_SERVER_NAME_unbind() called\n");

    status = RpcBindingFree(&hBinding);
    if (status)
    {
        TRACE("RpcBindingFree returned 0x%x\n", status);
    }
}


/*
 * @implemented
 */
NTSTATUS
WINAPI
LsaAddAccountRights(IN LSA_HANDLE PolicyHandle,
                    IN PSID AccountSid,
                    IN PLSA_UNICODE_STRING UserRights,
                    IN ULONG CountOfRights)
{
    LSAPR_USER_RIGHT_SET UserRightSet;
    NTSTATUS Status;

    TRACE("LsaAddAccountRights(%p %p %p 0x%08x)\n",
          PolicyHandle, AccountSid, UserRights, CountOfRights);

    UserRightSet.Entries = CountOfRights;
    UserRightSet.UserRights = (PRPC_UNICODE_STRING)UserRights;

    RpcTryExcept
    {
        Status = LsarAddAccountRights((LSAPR_HANDLE)PolicyHandle,
                                      (PRPC_SID)AccountSid,
                                      &UserRightSet);

    }
    RpcExcept(EXCEPTION_EXECUTE_HANDLER)
    {
        Status = I_RpcMapWin32Status(RpcExceptionCode());
    }
    RpcEndExcept;

    return Status;
}


/*
 * @implemented
 */
NTSTATUS
WINAPI
LsaAddPrivilegesToAccount(IN LSA_HANDLE AccountHandle,
                          IN PPRIVILEGE_SET PrivilegeSet)
{
    NTSTATUS Status;

    TRACE("LsaAddPrivilegesToAccount(%p %p)\n",
          AccountHandle, PrivilegeSet);

    RpcTryExcept
    {
        Status = LsarAddPrivilegesToAccount((LSAPR_HANDLE)AccountHandle,
                                            (PLSAPR_PRIVILEGE_SET)PrivilegeSet);
    }
    RpcExcept(EXCEPTION_EXECUTE_HANDLER)
    {
        Status = I_RpcMapWin32Status(RpcExceptionCode());
    }
    RpcEndExcept;

    return Status;
}


/*
 * @implemented
 */
NTSTATUS
WINAPI
LsaClearAuditLog(IN LSA_HANDLE PolicyHandle)
{
    NTSTATUS Status;

    TRACE("LsaClearAuditLog(%p)\n", PolicyHandle);

    RpcTryExcept
    {
        Status = LsarClearAuditLog((LSAPR_HANDLE)PolicyHandle);
    }
    RpcExcept(EXCEPTION_EXECUTE_HANDLER)
    {
        Status = I_RpcMapWin32Status(RpcExceptionCode());
    }
    RpcEndExcept;

    return Status;
}


/*
 * @implemented
 */
NTSTATUS
WINAPI
LsaClose(IN LSA_HANDLE ObjectHandle)
{
    NTSTATUS Status;

    TRACE("LsaClose(%p) called\n", ObjectHandle);

    RpcTryExcept
    {
        Status = LsarClose((PLSAPR_HANDLE)&ObjectHandle);
    }
    RpcExcept(EXCEPTION_EXECUTE_HANDLER)
    {
        Status = I_RpcMapWin32Status(RpcExceptionCode());
    }
    RpcEndExcept;

    return Status;
}


/*
 * @implemented
 */
NTSTATUS
WINAPI
LsaCreateAccount(IN LSA_HANDLE PolicyHandle,
                 IN PSID AccountSid,
                 IN ACCESS_MASK DesiredAccess,
                 OUT PLSA_HANDLE AccountHandle)
{
    NTSTATUS Status;

    TRACE("LsaCreateAccount(%p %p 0x%08lx %p)\n",
          PolicyHandle, AccountSid, DesiredAccess, AccountHandle);

    RpcTryExcept
    {
        Status = LsarCreateAccount((LSAPR_HANDLE)PolicyHandle,
                                   AccountSid,
                                   DesiredAccess,
                                   AccountHandle);
    }
    RpcExcept(EXCEPTION_EXECUTE_HANDLER)
    {
        Status = I_RpcMapWin32Status(RpcExceptionCode());
    }
    RpcEndExcept;

    return Status;
}


/*
 * @implemented
 */
NTSTATUS
WINAPI
LsaCreateSecret(IN LSA_HANDLE PolicyHandle,
                IN PLSA_UNICODE_STRING SecretName,
                IN ACCESS_MASK DesiredAccess,
                OUT PLSA_HANDLE SecretHandle)
{
    NTSTATUS Status;

    TRACE("LsaCreateSecret(%p %p 0x%08lx %p)\n",
          PolicyHandle, SecretName, DesiredAccess, SecretHandle);

    RpcTryExcept
    {
        Status = LsarCreateSecret((LSAPR_HANDLE)PolicyHandle,
                                  (PRPC_UNICODE_STRING)SecretName,
                                  DesiredAccess,
                                  SecretHandle);
    }
    RpcExcept(EXCEPTION_EXECUTE_HANDLER)
    {
        Status = I_RpcMapWin32Status(RpcExceptionCode());
    }
    RpcEndExcept;

    return Status;
}


/*
 * @implemented
 */
NTSTATUS
WINAPI
LsaCreateTrustedDomain(IN LSA_HANDLE PolicyHandle,
                       IN PLSA_TRUST_INFORMATION TrustedDomainInformation,
                       IN ACCESS_MASK DesiredAccess,
                       OUT PLSA_HANDLE TrustedDomainHandle)
{
    NTSTATUS Status;

    TRACE("LsaCreateTrustedDomain(%p %p 0x%08lx %p)\n",
          PolicyHandle, TrustedDomainInformation, DesiredAccess, TrustedDomainHandle);

    RpcTryExcept
    {
        Status = LsarCreateTrustedDomain((LSAPR_HANDLE)PolicyHandle,
                                         (PLSAPR_TRUST_INFORMATION)TrustedDomainInformation,
                                         DesiredAccess,
                                         (PLSAPR_HANDLE)TrustedDomainHandle);
    }
    RpcExcept(EXCEPTION_EXECUTE_HANDLER)
    {
        Status = I_RpcMapWin32Status(RpcExceptionCode());
    }
    RpcEndExcept;

    return Status;
}


/*
 * @unimplemented
 */
NTSTATUS
WINAPI
LsaCreateTrustedDomainEx(IN LSA_HANDLE PolicyHandle,
                         IN PTRUSTED_DOMAIN_INFORMATION_EX TrustedDomainInformation,
                         IN PTRUSTED_DOMAIN_AUTH_INFORMATION AuthenticationInformation,
                         IN ACCESS_MASK DesiredAccess,
                         OUT PLSA_HANDLE TrustedDomainHandle)
{
    PLSAPR_TRUSTED_DOMAIN_AUTH_INFORMATION_INTERNAL EncryptedAuthInfo = NULL;
    NTSTATUS Status;

    TRACE("LsaCreateTrustedDomainEx(%p %p %p 0x%08lx %p) stub\n",
          PolicyHandle, TrustedDomainInformation, AuthenticationInformation,
          DesiredAccess, TrustedDomainHandle);

    RpcTryExcept
    {
        /* FIXME: Encrypt AuthenticationInformation */

        Status = LsarCreateTrustedDomainEx2((LSAPR_HANDLE)PolicyHandle,
                                            (PLSAPR_TRUSTED_DOMAIN_INFORMATION_EX)TrustedDomainInformation,
                                            EncryptedAuthInfo,
                                            DesiredAccess,
                                            (PLSAPR_HANDLE)TrustedDomainHandle);
    }
    RpcExcept(EXCEPTION_EXECUTE_HANDLER)
    {
        Status = I_RpcMapWin32Status(RpcExceptionCode());
    }
    RpcEndExcept;

    return Status;
}


/*
 * @implemented
 */
NTSTATUS
WINAPI
LsaDelete(IN LSA_HANDLE ObjectHandle)
{
    NTSTATUS Status;

    TRACE("LsaDelete(%p)\n", ObjectHandle);

    RpcTryExcept
    {
        Status = LsarDelete((LSAPR_HANDLE)ObjectHandle);
    }
    RpcExcept(EXCEPTION_EXECUTE_HANDLER)
    {
        Status = I_RpcMapWin32Status(RpcExceptionCode());
    }
    RpcEndExcept;

    return Status;
}


/*
 * @implemented
 */
NTSTATUS
WINAPI
LsaDeleteTrustedDomain(IN LSA_HANDLE PolicyHandle,
                       IN PSID TrustedDomainSid)
{
    NTSTATUS Status;

    TRACE("LsaDeleteTrustedDomain(%p %p)\n",
          PolicyHandle, TrustedDomainSid);

    RpcTryExcept
    {
        Status = LsarDeleteTrustedDomain((LSAPR_HANDLE)PolicyHandle,
                                         TrustedDomainSid);
    }
    RpcExcept(EXCEPTION_EXECUTE_HANDLER)
    {
        Status = I_RpcMapWin32Status(RpcExceptionCode());
    }
    RpcEndExcept;

    return Status;
}


/*
 * @implemented
 */
NTSTATUS
WINAPI
LsaEnumerateAccountRights(IN LSA_HANDLE PolicyHandle,
                          IN PSID AccountSid,
                          OUT PLSA_UNICODE_STRING *UserRights,
                          OUT PULONG CountOfRights)
{
    LSAPR_USER_RIGHT_SET UserRightsSet;
    NTSTATUS Status;

    TRACE("LsaEnumerateAccountRights(%p %p %p %p)\n",
          PolicyHandle, AccountSid, UserRights, CountOfRights);

    UserRightsSet.Entries = 0;
    UserRightsSet.UserRights = NULL;

    RpcTryExcept
    {
        Status = LsarEnumerateAccountRights((LSAPR_HANDLE)PolicyHandle,
                                            AccountSid,
                                            &UserRightsSet);

        *UserRights = (PUNICODE_STRING)UserRightsSet.UserRights;
        *CountOfRights = UserRightsSet.Entries;
    }
    RpcExcept(EXCEPTION_EXECUTE_HANDLER)
    {
        Status = I_RpcMapWin32Status(RpcExceptionCode());

        if (UserRightsSet.UserRights != NULL)
            MIDL_user_free(UserRightsSet.UserRights);
    }
    RpcEndExcept;

    return Status;
}


/*
 * @implemented
 */
NTSTATUS
WINAPI
LsaEnumerateAccounts(IN LSA_HANDLE PolicyHandle,
                     IN OUT PLSA_ENUMERATION_HANDLE EnumerationContext,
                     OUT PVOID *Buffer,
                     IN ULONG PreferedMaximumLength,
                     OUT PULONG CountReturned)
{
    LSAPR_ACCOUNT_ENUM_BUFFER AccountEnumBuffer;
    NTSTATUS Status;

    TRACE("LsaEnumerateAccounts(%p %p %p %lu %p)\n",
          PolicyHandle, EnumerationContext, Buffer,
          PreferedMaximumLength, CountReturned);

    AccountEnumBuffer.EntriesRead = 0;
    AccountEnumBuffer.Information = NULL;

    RpcTryExcept
    {
        Status = LsarEnumerateAccounts((LSAPR_HANDLE)PolicyHandle,
                                       EnumerationContext,
                                       &AccountEnumBuffer,
                                       PreferedMaximumLength);

        *Buffer = AccountEnumBuffer.Information;
        *CountReturned = AccountEnumBuffer.EntriesRead;
    }
    RpcExcept(EXCEPTION_EXECUTE_HANDLER)
    {
        if (AccountEnumBuffer.Information != NULL)
            MIDL_user_free(AccountEnumBuffer.Information);

        Status = I_RpcMapWin32Status(RpcExceptionCode());
    }
    RpcEndExcept;

    return Status;
}


/*
 * @implemented
 */
NTSTATUS
WINAPI
LsaEnumerateAccountsWithUserRight(IN LSA_HANDLE PolicyHandle,
                                  IN PLSA_UNICODE_STRING UserRight OPTIONAL,
                                  OUT PVOID *Buffer,
                                  OUT PULONG CountReturned)
{
    LSAPR_ACCOUNT_ENUM_BUFFER AccountEnumBuffer;
    NTSTATUS Status;

    TRACE("LsaEnumerateAccountsWithUserRight(%p %p %p %p) stub\n",
          PolicyHandle, UserRight, Buffer, CountReturned);

    AccountEnumBuffer.EntriesRead = 0;
    AccountEnumBuffer.Information = NULL;

    RpcTryExcept
    {
        Status = LsarEnumerateAccountsWithUserRight((LSAPR_HANDLE)PolicyHandle,
                                                    (PRPC_UNICODE_STRING)UserRight,
                                                    &AccountEnumBuffer);

        *Buffer = AccountEnumBuffer.Information;
        *CountReturned = AccountEnumBuffer.EntriesRead;
    }
    RpcExcept(EXCEPTION_EXECUTE_HANDLER)
    {
        if (AccountEnumBuffer.Information != NULL)
            MIDL_user_free(AccountEnumBuffer.Information);

        Status = I_RpcMapWin32Status(RpcExceptionCode());
    }
    RpcEndExcept;

    return Status;
}


/*
 * @implemented
 */
NTSTATUS
WINAPI
LsaEnumeratePrivileges(IN LSA_HANDLE PolicyHandle,
                       IN OUT PLSA_ENUMERATION_HANDLE EnumerationContext,
                       OUT PVOID *Buffer,
                       IN ULONG PreferedMaximumLength,
                       OUT PULONG CountReturned)
{
    LSAPR_PRIVILEGE_ENUM_BUFFER PrivilegeEnumBuffer;
    NTSTATUS Status;

    TRACE("LsaEnumeratePrivileges(%p %p %p %lu %p)\n",
          PolicyHandle, EnumerationContext, Buffer,
          PreferedMaximumLength, CountReturned);

    PrivilegeEnumBuffer.Entries = 0;
    PrivilegeEnumBuffer.Privileges = NULL;

    RpcTryExcept
    {
        Status = LsarEnumeratePrivileges((LSAPR_HANDLE)PolicyHandle,
                                         EnumerationContext,
                                         &PrivilegeEnumBuffer,
                                         PreferedMaximumLength);

        *Buffer = PrivilegeEnumBuffer.Privileges;
        *CountReturned = PrivilegeEnumBuffer.Entries;

    }
    RpcExcept(EXCEPTION_EXECUTE_HANDLER)
    {
        if (PrivilegeEnumBuffer.Privileges != NULL)
            MIDL_user_free(PrivilegeEnumBuffer.Privileges);

        Status = I_RpcMapWin32Status(RpcExceptionCode());
    }
    RpcEndExcept;

    return Status;
}


/*
 * @implemented
 */
NTSTATUS
WINAPI
LsaEnumeratePrivilegesOfAccount(IN LSA_HANDLE AccountHandle,
                                OUT PPRIVILEGE_SET *Privileges)
{
    NTSTATUS Status;

    TRACE("LsaEnumeratePrivilegesOfAccount(%p %p)\n",
          AccountHandle, Privileges);

    RpcTryExcept
    {
        Status = LsarEnumeratePrivilegesAccount((LSAPR_HANDLE)AccountHandle,
                                                (LSAPR_PRIVILEGE_SET **)Privileges);
    }
    RpcExcept(EXCEPTION_EXECUTE_HANDLER)
    {
        Status = I_RpcMapWin32Status(RpcExceptionCode());
    }
    RpcEndExcept;

    return Status;
}


/*
 * @implemented
 */
NTSTATUS
WINAPI
LsaEnumerateTrustedDomains(IN LSA_HANDLE PolicyHandle,
                           IN OUT PLSA_ENUMERATION_HANDLE EnumerationContext,
                           OUT PVOID *Buffer,
                           IN ULONG PreferedMaximumLength,
                           OUT PULONG CountReturned)
{
    LSAPR_TRUSTED_ENUM_BUFFER TrustedEnumBuffer;
    NTSTATUS Status;

    TRACE("LsaEnumerateTrustedDomains(%p %p %p %lu %p)\n",
          PolicyHandle, EnumerationContext, Buffer,
          PreferedMaximumLength, CountReturned);

    if (Buffer == NULL)
        return STATUS_INVALID_PARAMETER;

    TrustedEnumBuffer.EntriesRead = 0;
    TrustedEnumBuffer.Information = NULL;

    RpcTryExcept
    {
        Status = LsarEnumerateTrustedDomains((LSAPR_HANDLE)PolicyHandle,
                                             EnumerationContext,
                                             &TrustedEnumBuffer,
                                             PreferedMaximumLength);

        *Buffer = TrustedEnumBuffer.Information;
        *CountReturned = TrustedEnumBuffer.EntriesRead;

    }
    RpcExcept(EXCEPTION_EXECUTE_HANDLER)
    {
        if (TrustedEnumBuffer.Information != NULL)
            MIDL_user_free(TrustedEnumBuffer.Information);

        Status = I_RpcMapWin32Status(RpcExceptionCode());
    }
    RpcEndExcept;

    return Status;
}


/*
 * @implemented
 */
NTSTATUS
WINAPI
LsaEnumerateTrustedDomainsEx(IN LSA_HANDLE PolicyHandle,
                             IN OUT PLSA_ENUMERATION_HANDLE EnumerationContext,
                             OUT PVOID *Buffer,
                             IN ULONG PreferedMaximumLength,
                             OUT PULONG CountReturned)
{
    LSAPR_TRUSTED_ENUM_BUFFER_EX TrustedEnumBuffer;
    NTSTATUS Status;

    TRACE("LsaEnumerateTrustedDomainsEx(%p %p %p %lu %p)\n",
          PolicyHandle, EnumerationContext, Buffer,
          PreferedMaximumLength, CountReturned);

    if (Buffer == NULL)
        return STATUS_INVALID_PARAMETER;

    TrustedEnumBuffer.EntriesRead = 0;
    TrustedEnumBuffer.EnumerationBuffer = NULL;

    RpcTryExcept
    {
        Status = LsarEnumerateTrustedDomainsEx((LSAPR_HANDLE)PolicyHandle,
                                               EnumerationContext,
                                               &TrustedEnumBuffer,
                                               PreferedMaximumLength);

        *Buffer = TrustedEnumBuffer.EnumerationBuffer;
        *CountReturned = TrustedEnumBuffer.EntriesRead;

    }
    RpcExcept(EXCEPTION_EXECUTE_HANDLER)
    {
        if (TrustedEnumBuffer.EnumerationBuffer != NULL)
            MIDL_user_free(TrustedEnumBuffer.EnumerationBuffer);

        Status = I_RpcMapWin32Status(RpcExceptionCode());
    }
    RpcEndExcept;

    return Status;
}


/*
 * @implemented
 */
NTSTATUS
WINAPI
LsaFreeMemory(IN PVOID Buffer)
{
    TRACE("LsaFreeMemory(%p)\n", Buffer);

    /* RtlFreeHeap returns a BOOLEAN; Windows returns STATUS_SUCCESS (0), not TRUE (1) */
    if (!RtlFreeHeap(RtlGetProcessHeap(), 0, Buffer))
        return STATUS_INVALID_PARAMETER;
    return STATUS_SUCCESS;
}


/*
 * @implemented
 */
NTSTATUS
WINAPI
LsaGetQuotasForAccount(IN LSA_HANDLE AccountHandle,
                       OUT PQUOTA_LIMITS QuotaLimits)
{
    NTSTATUS Status;

    TRACE("LsaGetQuotasForAccount(%p %p)\n",
          AccountHandle, QuotaLimits);

    RpcTryExcept
    {
        Status = LsarGetQuotasForAccount((LSAPR_HANDLE)AccountHandle,
                                         QuotaLimits);
    }
    RpcExcept(EXCEPTION_EXECUTE_HANDLER)
    {
        Status = I_RpcMapWin32Status(RpcExceptionCode());
    }
    RpcEndExcept;

    return Status;
}


/*
 * @implemented
 */
NTSTATUS
WINAPI
LsaGetRemoteUserName(IN PLSA_UNICODE_STRING SystemName OPTIONAL,
                     OUT PLSA_UNICODE_STRING *UserName,
                     OUT PLSA_UNICODE_STRING *DomainName OPTIONAL)
{
    PRPC_UNICODE_STRING UserNameString = NULL;
    PRPC_UNICODE_STRING DomainNameString = NULL;
    NTSTATUS Status;

    TRACE("LsaGetRemoteUserName(%s %p %p)\n",
          SystemName ? debugstr_w(SystemName->Buffer) : "(null)",
          UserName, DomainName);

    RpcTryExcept
    {
        Status = LsarGetUserName((PLSAPR_SERVER_NAME)SystemName,
                                 &UserNameString,
                                 (DomainName != NULL) ? &DomainNameString : NULL);

        *UserName = (PLSA_UNICODE_STRING)UserNameString;

        if (DomainName != NULL)
            *DomainName = (PLSA_UNICODE_STRING)DomainNameString;
    }
    RpcExcept(EXCEPTION_EXECUTE_HANDLER)
    {
        if (UserNameString != NULL)
            MIDL_user_free(UserNameString);

        if (DomainNameString != NULL)
            MIDL_user_free(DomainNameString);

        Status = I_RpcMapWin32Status(RpcExceptionCode());
    }
    RpcEndExcept;

    return Status;
}


/*
 * @implemented
 */
NTSTATUS
WINAPI
LsaGetSystemAccessAccount(IN LSA_HANDLE AccountHandle,
                          OUT PULONG SystemAccess)
{
    NTSTATUS Status;

    TRACE("LsaGetSystemAccessAccount(%p %p)\n",
          AccountHandle, SystemAccess);

    RpcTryExcept
    {
        Status = LsarGetSystemAccessAccount((LSAPR_HANDLE)AccountHandle,
                                            (ACCESS_MASK *)SystemAccess);
    }
    RpcExcept(EXCEPTION_EXECUTE_HANDLER)
    {
        Status = I_RpcMapWin32Status(RpcExceptionCode());
    }
    RpcEndExcept;

    return Status;
}


/*
 * @implemented
 */
NTSTATUS
WINAPI
LsaGetUserName(OUT PUNICODE_STRING *UserName,
               OUT PUNICODE_STRING *DomainName OPTIONAL)
{
    PRPC_UNICODE_STRING UserNameString = NULL;
    PRPC_UNICODE_STRING DomainNameString = NULL;
    NTSTATUS Status;

    TRACE("LsaGetUserName(%p %p)\n",
          UserName, DomainName);

    RpcTryExcept
    {
        Status = LsarGetUserName(NULL,
                                 &UserNameString,
                                 (DomainName != NULL) ? &DomainNameString : NULL);

        *UserName = (PUNICODE_STRING)UserNameString;

        if (DomainName != NULL)
            *DomainName = (PUNICODE_STRING)DomainNameString;
    }
    RpcExcept(EXCEPTION_EXECUTE_HANDLER)
    {
        if (UserNameString != NULL)
            MIDL_user_free(UserNameString);

        if (DomainNameString != NULL)
            MIDL_user_free(DomainNameString);

        Status = I_RpcMapWin32Status(RpcExceptionCode());
    }
    RpcEndExcept;

    return Status;
}


/*
 * The RPC client stub allocates every piece of an out parameter separately with midl_user_allocate (the process
 * heap, zero filled; only a server points into the RPC buffer): for the referenced domain list the header, the trust
 * array, each domain name and each SID, for the translated names and SIDs the array and each name buffer or SID.
 * Windows returns each of these as ONE block (header or array first, then the data behind it) and callers rely on
 * it: LsaFreeMemory frees one block, and .NET sizes the list for LsaFreeMemory as the distance from the header to
 * the end of the trust array, which wrapped past 4 GB in 32-bit processes (SafeBuffer "numBytes" overflow, about one
 * lookup in eight) when the trust array sat below the header.
 *
 * Each LsapPack function copies the pieces into one process heap block, frees the pieces and the old header with
 * the stub's allocator, and returns the new block. If the new block cannot be allocated the list is returned as the
 * stub made it (then LsaFreeMemory frees only the first block, as before).
 */
#define LSAP_ALIGN(x)   (((ULONGLONG)(x) + sizeof(PVOID) - 1) & ~(ULONGLONG)(sizeof(PVOID) - 1))
#define LSAP_MAX_PACK   0x7FFFFFFFULL

/* The lookup returned data the caller owns: all, some or none of the entries mapped */
static
BOOLEAN
LsapLookupReturnsData(
    _In_ NTSTATUS Status)
{
    return (Status == STATUS_SUCCESS ||
            Status == STATUS_SOME_NOT_MAPPED ||
            Status == STATUS_NONE_MAPPED);
}

/* Free every piece of a list as the stub allocated it */
static
VOID
LsapFreeRpcDomains(
    _In_opt_ PLSA_REFERENCED_DOMAIN_LIST List)
{
    ULONG i;

    if (List == NULL)
        return;

    if (List->Domains != NULL)
    {
        if (List->Entries <= 0x1000)
        {
            for (i = 0; i < List->Entries; i++)
            {
                if (List->Domains[i].Name.Buffer != NULL)
                    MIDL_user_free(List->Domains[i].Name.Buffer);
                if (List->Domains[i].Sid != NULL)
                    MIDL_user_free(List->Domains[i].Sid);
            }
        }
        MIDL_user_free(List->Domains);
    }
    MIDL_user_free(List);
}

static
VOID
LsapPackReferencedDomains(
    _Inout_ PLSA_REFERENCED_DOMAIN_LIST *ReferencedDomains)
{
    PLSA_REFERENCED_DOMAIN_LIST Old = *ReferencedDomains, New;
    PLSA_TRUST_INFORMATION Trust;
    ULONGLONG Size;
    PUCHAR Cursor;
    ULONG i, SidLength;

    if (Old == NULL)
        return;

    if (Old->Entries == 0)
    {
        /* Nothing mapped: the stub still allocates an empty trust array; Windows returns the header alone */
        if (Old->Domains != NULL)
        {
            MIDL_user_free(Old->Domains);
            Old->Domains = NULL;
        }
        return;
    }

    if (Old->Entries > 0x1000 || Old->Domains == NULL)
        return;

    Size = LSAP_ALIGN(sizeof(*Old));
    Size += (ULONGLONG)Old->Entries * sizeof(LSA_TRUST_INFORMATION);
    for (i = 0; i < Old->Entries; i++)
    {
        Size = LSAP_ALIGN(Size);
        Size += Old->Domains[i].Name.MaximumLength;
        Size = LSAP_ALIGN(Size);
        if (Old->Domains[i].Sid != NULL)
            Size += RtlLengthSid(Old->Domains[i].Sid);
    }
    if (Size > LSAP_MAX_PACK)
        return;

    New = HeapAlloc(GetProcessHeap(), 0, (SIZE_T)Size);
    if (New == NULL)
        return;

    Cursor = (PUCHAR)New + (SIZE_T)LSAP_ALIGN(sizeof(*Old));
    Trust = (PLSA_TRUST_INFORMATION)Cursor;
    New->Entries = Old->Entries;
    New->Domains = Trust;
    Cursor += (SIZE_T)Old->Entries * sizeof(LSA_TRUST_INFORMATION);
    for (i = 0; i < Old->Entries; i++)
    {
        Trust[i] = Old->Domains[i];

        Cursor = (PUCHAR)(ULONG_PTR)LSAP_ALIGN((ULONG_PTR)Cursor);
        if (Old->Domains[i].Name.Buffer != NULL && Old->Domains[i].Name.MaximumLength != 0)
        {
            RtlCopyMemory(Cursor, Old->Domains[i].Name.Buffer, Old->Domains[i].Name.MaximumLength);
            Trust[i].Name.Buffer = (PWSTR)Cursor;
            Cursor += Old->Domains[i].Name.MaximumLength;
        }
        else
        {
            Trust[i].Name.Buffer = NULL;
        }

        Cursor = (PUCHAR)(ULONG_PTR)LSAP_ALIGN((ULONG_PTR)Cursor);
        if (Old->Domains[i].Sid != NULL)
        {
            SidLength = RtlLengthSid(Old->Domains[i].Sid);
            RtlCopyMemory(Cursor, Old->Domains[i].Sid, SidLength);
            Trust[i].Sid = (PSID)Cursor;
            Cursor += SidLength;
        }
    }

    LsapFreeRpcDomains(Old);
    *ReferencedDomains = New;
}

/* The translated names array with each name buffer behind it, as one block */
static
VOID
LsapPackTranslatedNames(
    _Inout_ PLSA_TRANSLATED_NAME *Names,
    _In_ ULONG Count)
{
    PLSA_TRANSLATED_NAME Old = *Names, New;
    ULONGLONG Size;
    PUCHAR Cursor;
    ULONG i;

    if (Old == NULL || Count == 0 || Count > 0x100000)
        return;

    Size = LSAP_ALIGN((ULONGLONG)Count * sizeof(LSA_TRANSLATED_NAME));
    for (i = 0; i < Count; i++)
    {
        if (Old[i].Name.Buffer != NULL)
            Size += LSAP_ALIGN(Old[i].Name.MaximumLength);
    }
    if (Size > LSAP_MAX_PACK)
        return;

    New = HeapAlloc(GetProcessHeap(), 0, (SIZE_T)Size);
    if (New == NULL)
        return;

    Cursor = (PUCHAR)New + (SIZE_T)LSAP_ALIGN((SIZE_T)Count * sizeof(LSA_TRANSLATED_NAME));
    for (i = 0; i < Count; i++)
    {
        New[i] = Old[i];
        if (Old[i].Name.Buffer != NULL)
        {
            RtlCopyMemory(Cursor, Old[i].Name.Buffer, Old[i].Name.MaximumLength);
            New[i].Name.Buffer = (PWSTR)Cursor;
            Cursor += (SIZE_T)LSAP_ALIGN(Old[i].Name.MaximumLength);
            MIDL_user_free(Old[i].Name.Buffer);
        }
    }

    MIDL_user_free(Old);
    *Names = New;
}

static
VOID
LsapFreeRpcNames(
    _In_opt_ PLSA_TRANSLATED_NAME Names,
    _In_ ULONG Count)
{
    ULONG i;

    if (Names == NULL)
        return;
    if (Count <= 0x100000)
    {
        for (i = 0; i < Count; i++)
        {
            if (Names[i].Name.Buffer != NULL)
                MIDL_user_free(Names[i].Name.Buffer);
        }
    }
    MIDL_user_free(Names);
}

/* The translated SIDs array with each SID behind it, as one block */
static
VOID
LsapPackTranslatedSids2(
    _Inout_ PLSA_TRANSLATED_SID2 *Sids,
    _In_ ULONG Count)
{
    PLSA_TRANSLATED_SID2 Old = *Sids, New;
    ULONGLONG Size;
    PUCHAR Cursor;
    ULONG i, SidLength;

    if (Old == NULL || Count == 0 || Count > 0x100000)
        return;

    Size = LSAP_ALIGN((ULONGLONG)Count * sizeof(LSA_TRANSLATED_SID2));
    for (i = 0; i < Count; i++)
    {
        if (Old[i].Sid != NULL)
            Size += LSAP_ALIGN(RtlLengthSid(Old[i].Sid));
    }
    if (Size > LSAP_MAX_PACK)
        return;

    New = HeapAlloc(GetProcessHeap(), 0, (SIZE_T)Size);
    if (New == NULL)
        return;

    Cursor = (PUCHAR)New + (SIZE_T)LSAP_ALIGN((SIZE_T)Count * sizeof(LSA_TRANSLATED_SID2));
    for (i = 0; i < Count; i++)
    {
        New[i] = Old[i];
        if (Old[i].Sid != NULL)
        {
            SidLength = RtlLengthSid(Old[i].Sid);
            RtlCopyMemory(Cursor, Old[i].Sid, SidLength);
            New[i].Sid = (PSID)Cursor;
            Cursor += (SIZE_T)LSAP_ALIGN(SidLength);
            MIDL_user_free(Old[i].Sid);
        }
    }

    MIDL_user_free(Old);
    *Sids = New;
}

static
VOID
LsapFreeRpcSids2(
    _In_opt_ PLSA_TRANSLATED_SID2 Sids,
    _In_ ULONG Count)
{
    ULONG i;

    if (Sids == NULL)
        return;
    if (Count <= 0x100000)
    {
        for (i = 0; i < Count; i++)
        {
            if (Sids[i].Sid != NULL)
                MIDL_user_free(Sids[i].Sid);
        }
    }
    MIDL_user_free(Sids);
}


/*
 * @implemented
 */
NTSTATUS
WINAPI
LsaLookupNames(IN LSA_HANDLE PolicyHandle,
               IN ULONG Count,
               IN PLSA_UNICODE_STRING Names,
               OUT PLSA_REFERENCED_DOMAIN_LIST *ReferencedDomains,
               OUT PLSA_TRANSLATED_SID *Sids)
{
    LSAPR_TRANSLATED_SIDS TranslatedSids = {0, NULL};
    ULONG MappedCount = 0;
    NTSTATUS Status;

    TRACE("LsaLookupNames(%p %lu %p %p %p)\n",
          PolicyHandle, Count, Names, ReferencedDomains, Sids);

    if (ReferencedDomains == NULL || Sids == NULL)
        return STATUS_INVALID_PARAMETER;

    RpcTryExcept
    {
        *ReferencedDomains = NULL;
        *Sids = NULL;

        TranslatedSids.Entries = Count;

        Status = LsarLookupNames((LSAPR_HANDLE)PolicyHandle,
                                 Count,
                                 (PRPC_UNICODE_STRING)Names,
                                 (PLSAPR_REFERENCED_DOMAIN_LIST *)ReferencedDomains,
                                 &TranslatedSids,
                                 LsapLookupWksta,
                                 &MappedCount);

        *Sids = (PLSA_TRANSLATED_SID)TranslatedSids.Sids;
        if (LsapLookupReturnsData(Status))
        {
            /* The SID array is one block already; only the domain list needs packing */
            LsapPackReferencedDomains(ReferencedDomains);
        }
        else
        {
            /* Nothing for the caller to free on a failure */
            LsapFreeRpcDomains(*ReferencedDomains);
            *ReferencedDomains = NULL;
            if (*Sids != NULL)
                MIDL_user_free(*Sids);
            *Sids = NULL;
        }
    }
    RpcExcept(EXCEPTION_EXECUTE_HANDLER)
    {
        if (TranslatedSids.Sids != NULL)
            MIDL_user_free(TranslatedSids.Sids);

        Status = I_RpcMapWin32Status(RpcExceptionCode());
    }
    RpcEndExcept;

    return Status;
}


/*
 * @implemented
 */
NTSTATUS
WINAPI
LsaLookupNames2(IN LSA_HANDLE PolicyHandle,
                IN ULONG Flags,
                IN ULONG Count,
                IN PLSA_UNICODE_STRING Names,
                OUT PLSA_REFERENCED_DOMAIN_LIST *ReferencedDomains,
                OUT PLSA_TRANSLATED_SID2 *Sids)
{
    LSAPR_TRANSLATED_SIDS_EX2 TranslatedSids = {0, NULL};
    ULONG MappedCount = 0;
    NTSTATUS Status;

    TRACE("LsaLookupNames2(%p 0x%08x %lu %p %p %p)\n",
          PolicyHandle, Flags, Count, Names, ReferencedDomains, Sids);

    if (ReferencedDomains == NULL || Sids == NULL)
        return STATUS_INVALID_PARAMETER;

    RpcTryExcept
    {
        *ReferencedDomains = NULL;
        *Sids = NULL;

        TranslatedSids.Entries = Count;

        Status = LsarLookupNames3((LSAPR_HANDLE)PolicyHandle,
                                  Count,
                                  (PRPC_UNICODE_STRING)Names,
                                  (PLSAPR_REFERENCED_DOMAIN_LIST *)ReferencedDomains,
                                  &TranslatedSids,
                                  LsapLookupWksta,
                                  &MappedCount,
                                  Flags,
                                  2);

        *Sids = (PLSA_TRANSLATED_SID2)TranslatedSids.Sids;
        if (LsapLookupReturnsData(Status))
        {
            LsapPackReferencedDomains(ReferencedDomains);
            LsapPackTranslatedSids2(Sids, TranslatedSids.Entries);
        }
        else
        {
            /* Nothing for the caller to free on a failure */
            LsapFreeRpcDomains(*ReferencedDomains);
            *ReferencedDomains = NULL;
            LsapFreeRpcSids2(*Sids, TranslatedSids.Entries);
            *Sids = NULL;
        }
    }
    RpcExcept(EXCEPTION_EXECUTE_HANDLER)
    {
        if (TranslatedSids.Sids != NULL)
            MIDL_user_free(TranslatedSids.Sids);

        Status = I_RpcMapWin32Status(RpcExceptionCode());
    }
    RpcEndExcept;

    return Status;
}


/*
 * @implemented
 */
NTSTATUS
WINAPI
LsaLookupPrivilegeDisplayName(IN LSA_HANDLE PolicyHandle,
                              IN PLSA_UNICODE_STRING Name,
                              OUT PLSA_UNICODE_STRING *DisplayName,
                              OUT PUSHORT LanguageReturned)
{
    PRPC_UNICODE_STRING DisplayNameBuffer = NULL;
    NTSTATUS Status;

    TRACE("LsaLookupPrivilegeDisplayName(%p %p %p %p)\n",
          PolicyHandle, Name, DisplayName, LanguageReturned);

    RpcTryExcept
    {
        Status = LsarLookupPrivilegeDisplayName(PolicyHandle,
                                                (PRPC_UNICODE_STRING)Name,
                                                GetUserDefaultUILanguage(),
                                                GetSystemDefaultUILanguage(),
                                                &DisplayNameBuffer,
                                                LanguageReturned);

        *DisplayName = (PUNICODE_STRING)DisplayNameBuffer;
    }
    RpcExcept(EXCEPTION_EXECUTE_HANDLER)
    {
        if (DisplayNameBuffer != NULL)
            MIDL_user_free(DisplayNameBuffer);

        Status = I_RpcMapWin32Status(RpcExceptionCode());
    }
    RpcEndExcept;

    return Status;
}


/*
 * @implemented
 */
NTSTATUS
WINAPI
LsaLookupPrivilegeName(IN LSA_HANDLE PolicyHandle,
                       IN PLUID Value,
                       OUT PUNICODE_STRING *Name)
{
    PRPC_UNICODE_STRING NameBuffer = NULL;
    NTSTATUS Status;

    TRACE("LsaLookupPrivilegeName(%p %p %p)\n",
          PolicyHandle, Value, Name);

    RpcTryExcept
    {
        Status = LsarLookupPrivilegeName(PolicyHandle,
                                         Value,
                                         &NameBuffer);

        *Name = (PUNICODE_STRING)NameBuffer;
    }
    RpcExcept(EXCEPTION_EXECUTE_HANDLER)
    {
        if (NameBuffer != NULL)
            MIDL_user_free(NameBuffer);

        Status = I_RpcMapWin32Status(RpcExceptionCode());
    }
    RpcEndExcept;

    return Status;
}


/*
 * @implemented
 */
NTSTATUS
WINAPI
LsaLookupPrivilegeValue(IN LSA_HANDLE PolicyHandle,
                        IN PLSA_UNICODE_STRING Name,
                        OUT PLUID Value)
{
    LUID Luid;
    NTSTATUS Status;

    TRACE("LsaLookupPrivilegeValue(%p %p %p)\n",
          PolicyHandle, Name, Value);

    RpcTryExcept
    {
        Status = LsarLookupPrivilegeValue(PolicyHandle,
                                          (PRPC_UNICODE_STRING)Name,
                                          &Luid);
        if (Status == STATUS_SUCCESS)
            *Value = Luid;
    }
    RpcExcept(EXCEPTION_EXECUTE_HANDLER)
    {
        Status = I_RpcMapWin32Status(RpcExceptionCode());
    }
    RpcEndExcept;

    return Status;
}


/*
 * @implemented
 */
NTSTATUS
WINAPI
LsaLookupSids(IN LSA_HANDLE PolicyHandle,
              IN ULONG Count,
              IN PSID *Sids,
              OUT PLSA_REFERENCED_DOMAIN_LIST *ReferencedDomains,
              OUT PLSA_TRANSLATED_NAME *Names)
{
    LSAPR_SID_ENUM_BUFFER SidEnumBuffer;
    LSAPR_TRANSLATED_NAMES TranslatedNames;
    ULONG MappedCount = 0;
    NTSTATUS  Status;

    TRACE("LsaLookupSids(%p %lu %p %p %p)\n",
          PolicyHandle, Count, Sids, ReferencedDomains, Names);

    if (Count == 0)
        return STATUS_INVALID_PARAMETER;

    SidEnumBuffer.Entries = Count;
    SidEnumBuffer.SidInfo = (PLSAPR_SID_INFORMATION)Sids;

    RpcTryExcept
    {
        *ReferencedDomains = NULL;
        *Names = NULL;

        TranslatedNames.Entries = 0;
        TranslatedNames.Names = NULL;

        Status = LsarLookupSids((LSAPR_HANDLE)PolicyHandle,
                                &SidEnumBuffer,
                                (PLSAPR_REFERENCED_DOMAIN_LIST *)ReferencedDomains,
                                &TranslatedNames,
                                LsapLookupWksta,
                                &MappedCount);

        *Names = (PLSA_TRANSLATED_NAME)TranslatedNames.Names;
        if (LsapLookupReturnsData(Status))
        {
            LsapPackReferencedDomains(ReferencedDomains);
            LsapPackTranslatedNames(Names, TranslatedNames.Entries);
        }
        else
        {
            /* Nothing for the caller to free on a failure */
            LsapFreeRpcDomains(*ReferencedDomains);
            *ReferencedDomains = NULL;
            LsapFreeRpcNames(*Names, TranslatedNames.Entries);
            *Names = NULL;
        }
    }
    RpcExcept(EXCEPTION_EXECUTE_HANDLER)
    {
        if (TranslatedNames.Names != NULL)
        {
            MIDL_user_free(TranslatedNames.Names);
        }

        Status = I_RpcMapWin32Status(RpcExceptionCode());
    }
    RpcEndExcept;

    return Status;
}


/******************************************************************************
 * LsaNtStatusToWinError
 *
 * PARAMS
 *   Status [I]
 *
 * @implemented
 */
ULONG
WINAPI
LsaNtStatusToWinError(IN NTSTATUS Status)
{
    TRACE("LsaNtStatusToWinError(0x%lx)\n", Status);
    return RtlNtStatusToDosError(Status);
}


/*
 * @implemented
 */
NTSTATUS
WINAPI
LsaOpenAccount(IN LSA_HANDLE PolicyHandle,
               IN PSID AccountSid,
               IN ACCESS_MASK DesiredAccess,
               OUT PLSA_HANDLE AccountHandle)
{
    NTSTATUS Status;

    TRACE("LsaOpenAccount(%p %p 0x%08lx %p)\n",
          PolicyHandle, AccountSid, DesiredAccess, AccountHandle);

    RpcTryExcept
    {
        Status = LsarOpenAccount((LSAPR_HANDLE)PolicyHandle,
                                 AccountSid,
                                 DesiredAccess,
                                 AccountHandle);
    }
    RpcExcept(EXCEPTION_EXECUTE_HANDLER)
    {
        Status = I_RpcMapWin32Status(RpcExceptionCode());
    }
    RpcEndExcept;

    return Status;
}


/******************************************************************************
 * LsaOpenPolicy
 *
 * PARAMS
 *   x1 []
 *   x2 []
 *   x3 []
 *   x4 []
 *
 * @implemented
 */
NTSTATUS
WINAPI
LsaOpenPolicy(IN PLSA_UNICODE_STRING SystemName OPTIONAL,
              IN PLSA_OBJECT_ATTRIBUTES ObjectAttributes,
              IN ACCESS_MASK DesiredAccess,
              OUT PLSA_HANDLE PolicyHandle)
{
    NTSTATUS Status;

    TRACE("LsaOpenPolicy(%s %p 0x%08lx %p)\n",
          SystemName ? debugstr_w(SystemName->Buffer) : "(null)",
          ObjectAttributes, DesiredAccess, PolicyHandle);

    /* FIXME: RPC should take care of this */
    if (!LsapIsLocalComputer(SystemName))
        return RPC_NT_SERVER_UNAVAILABLE;

    RpcTryExcept
    {
        *PolicyHandle = NULL;

        Status = LsarOpenPolicy(SystemName ? SystemName->Buffer : NULL,
                                (PLSAPR_OBJECT_ATTRIBUTES)ObjectAttributes,
                                DesiredAccess,
                                PolicyHandle);
    }
    RpcExcept(EXCEPTION_EXECUTE_HANDLER)
    {
        Status = I_RpcMapWin32Status(RpcExceptionCode());
    }
    RpcEndExcept;

    TRACE("LsaOpenPolicy() done (Status: 0x%08lx)\n", Status);

    return Status;
}


/*
 * @implemented
 */
NTSTATUS
WINAPI
LsaOpenPolicySce(IN PLSA_UNICODE_STRING SystemName OPTIONAL,
                 IN PLSA_OBJECT_ATTRIBUTES ObjectAttributes,
                 IN ACCESS_MASK DesiredAccess,
                 OUT PLSA_HANDLE PolicyHandle)
{
    NTSTATUS Status;

    TRACE("LsaOpenPolicySce(%s %p 0x%08lx %p)\n",
          SystemName ? debugstr_w(SystemName->Buffer) : "(null)",
          ObjectAttributes, DesiredAccess, PolicyHandle);

    /* FIXME: RPC should take care of this */
    if (!LsapIsLocalComputer(SystemName))
        return RPC_NT_SERVER_UNAVAILABLE;

    RpcTryExcept
    {
        *PolicyHandle = NULL;

        Status = LsarOpenPolicySce(SystemName ? SystemName->Buffer : NULL,
                                   (PLSAPR_OBJECT_ATTRIBUTES)ObjectAttributes,
                                   DesiredAccess,
                                   PolicyHandle);
    }
    RpcExcept(EXCEPTION_EXECUTE_HANDLER)
    {
        Status = I_RpcMapWin32Status(RpcExceptionCode());
    }
    RpcEndExcept;

    TRACE("LsaOpenPolicySce() done (Status: 0x%08lx)\n", Status);

    return Status;
}


/*
 * @implemented
 */
NTSTATUS
WINAPI
LsaOpenSecret(IN LSA_HANDLE PolicyHandle,
              IN PLSA_UNICODE_STRING SecretName,
              IN ACCESS_MASK DesiredAccess,
              OUT PLSA_HANDLE SecretHandle)
{
    NTSTATUS Status;

    TRACE("LsaOpenSecret(%p %p 0x%08lx %p)\n",
          PolicyHandle, SecretName, DesiredAccess, SecretHandle);

    RpcTryExcept
    {
        *SecretHandle = NULL;

        Status = LsarOpenSecret((LSAPR_HANDLE)PolicyHandle,
                                (PRPC_UNICODE_STRING)SecretName,
                                DesiredAccess,
                                SecretHandle);
    }
    RpcExcept(EXCEPTION_EXECUTE_HANDLER)
    {
        Status = I_RpcMapWin32Status(RpcExceptionCode());
    }
    RpcEndExcept;

    TRACE("LsaOpenSecret() done (Status: 0x%08lx)\n", Status);

    return Status;
}


/*
 * @implemented
 */
NTSTATUS
WINAPI
LsaOpenTrustedDomain(IN LSA_HANDLE PolicyHandle,
                     IN PSID TrustedDomainSid,
                     IN ACCESS_MASK DesiredAccess,
                     OUT PLSA_HANDLE TrustedDomainHandle)
{
    NTSTATUS Status;

    TRACE("LsaOpenTrustedDomain(%p %p 0x%08lx %p)\n",
          PolicyHandle, TrustedDomainSid, DesiredAccess, TrustedDomainHandle);

    RpcTryExcept
    {
        Status = LsarOpenTrustedDomain((LSAPR_HANDLE)PolicyHandle,
                                       (PRPC_SID)TrustedDomainSid,
                                       DesiredAccess,
                                       (PLSAPR_HANDLE)TrustedDomainHandle);
    }
    RpcExcept(EXCEPTION_EXECUTE_HANDLER)
    {
        Status = I_RpcMapWin32Status(RpcExceptionCode());
    }
    RpcEndExcept;

    return Status;
}


/*
 * @implemented
 */
NTSTATUS
WINAPI
LsaOpenTrustedDomainByName(IN LSA_HANDLE PolicyHandle,
                           IN PLSA_UNICODE_STRING TrustedDomainName,
                           IN ACCESS_MASK DesiredAccess,
                           OUT PLSA_HANDLE TrustedDomainHandle)
{
    NTSTATUS Status;

    TRACE("LsaOpenTrustedDomainByName(%p %p 0x%08lx %p)\n",
          PolicyHandle, TrustedDomainName, DesiredAccess, TrustedDomainHandle);

    RpcTryExcept
    {
        Status = LsarOpenTrustedDomainByName((LSAPR_HANDLE)PolicyHandle,
                                             (PRPC_UNICODE_STRING)TrustedDomainName,
                                             DesiredAccess,
                                             TrustedDomainHandle);
    }
    RpcExcept(EXCEPTION_EXECUTE_HANDLER)
    {
        Status = I_RpcMapWin32Status(RpcExceptionCode());
    }
    RpcEndExcept;

    return Status;
}


/*
 * @implemented
 */
NTSTATUS
WINAPI
LsaQueryDomainInformationPolicy(IN LSA_HANDLE PolicyHandle,
                                IN POLICY_DOMAIN_INFORMATION_CLASS InformationClass,
                                OUT PVOID *Buffer)
{
    PLSAPR_POLICY_DOMAIN_INFORMATION PolicyInformation = NULL;
    NTSTATUS Status;

    TRACE("LsaQueryDomainInformationPolicy(%p %lu %p)\n",
          PolicyHandle, InformationClass, Buffer);

    RpcTryExcept
    {
        Status = LsarQueryDomainInformationPolicy((LSAPR_HANDLE)PolicyHandle,
                                                  InformationClass,
                                                  &PolicyInformation);

        *Buffer = PolicyInformation;
    }
    RpcExcept(EXCEPTION_EXECUTE_HANDLER)
    {
        if (PolicyInformation != NULL)
            MIDL_user_free(PolicyInformation);

        Status = I_RpcMapWin32Status(RpcExceptionCode());
    }
    RpcEndExcept;

    return Status;
}


/*
 * @implemented
 */
NTSTATUS
WINAPI
LsaQueryForestTrustInformation(IN LSA_HANDLE PolicyHandle,
                               IN PLSA_UNICODE_STRING TrustedDomainName,
                               OUT PLSA_FOREST_TRUST_INFORMATION *ForestTrustInfo)
{
    NTSTATUS Status;

    TRACE("LsaQueryForestTrustInformation(%p %p %p)\n",
          PolicyHandle, TrustedDomainName, ForestTrustInfo);

    RpcTryExcept
    {
        Status = LsarQueryForestTrustInformation((LSAPR_HANDLE)PolicyHandle,
                                                 TrustedDomainName,
                                                 ForestTrustDomainInfo,
                                                 ForestTrustInfo);
    }
    RpcExcept(EXCEPTION_EXECUTE_HANDLER)
    {
        Status = I_RpcMapWin32Status(RpcExceptionCode());
    }
    RpcEndExcept;

    return Status;
}


/*
 * @implemented
 */
NTSTATUS
WINAPI
LsaQueryInfoTrustedDomain(IN LSA_HANDLE TrustedDomainHandle,
                          IN TRUSTED_INFORMATION_CLASS InformationClass,
                          OUT PVOID *Buffer)
{
    PLSAPR_TRUSTED_DOMAIN_INFO TrustedDomainInformation = NULL;
    NTSTATUS Status;

    TRACE("LsaQueryInfoTrustedDomain(%p %d %p) stub\n",
          TrustedDomainHandle, InformationClass, Buffer);

    if (InformationClass == TrustedDomainAuthInformationInternal ||
        InformationClass == TrustedDomainFullInformationInternal)
        return STATUS_INVALID_INFO_CLASS;

    RpcTryExcept
    {
        Status = LsarQueryInfoTrustedDomain((LSAPR_HANDLE)TrustedDomainHandle,
                                            InformationClass,
                                            &TrustedDomainInformation);
        *Buffer = TrustedDomainInformation;
    }
    RpcExcept(EXCEPTION_EXECUTE_HANDLER)
    {
        if (TrustedDomainInformation != NULL)
            MIDL_user_free(TrustedDomainInformation);

        Status = I_RpcMapWin32Status(RpcExceptionCode());
    }
    RpcEndExcept;

    TRACE("Done (Status: 0x%08x)\n", Status);

    return Status;
}


/*
 * The policy information structure the stub returns has its strings, SIDs and the audit options array allocated
 * one by one. Windows returns the structure and the data behind it as ONE block; a caller frees it with a single
 * LsaFreeMemory, so the pieces were leaked on every call (a domain name and a SID per LsaQueryInformationPolicy).
 * Same packing as the lookup results above.
 */
typedef struct _LSAP_POLICY_LAYOUT
{
    POLICY_INFORMATION_CLASS Class;
    ULONG StructSize;
    ULONG StringCount;
    ULONG StringOffsets[3];     /* UNICODE_STRING members */
    LONG SidOffset;             /* PSID member, or -1 */
} LSAP_POLICY_LAYOUT;

static const LSAP_POLICY_LAYOUT LsapPolicyLayouts[] =
{
    { PolicyPrimaryDomainInformation, sizeof(LSAPR_POLICY_PRIMARY_DOM_INFO), 1,
      { FIELD_OFFSET(LSAPR_POLICY_PRIMARY_DOM_INFO, Name) },
      FIELD_OFFSET(LSAPR_POLICY_PRIMARY_DOM_INFO, Sid) },
    { PolicyPdAccountInformation, sizeof(LSAPR_POLICY_PD_ACCOUNT_INFO), 1,
      { FIELD_OFFSET(LSAPR_POLICY_PD_ACCOUNT_INFO, Name) }, -1 },
    { PolicyAccountDomainInformation, sizeof(LSAPR_POLICY_ACCOUNT_DOM_INFO), 1,
      { FIELD_OFFSET(LSAPR_POLICY_ACCOUNT_DOM_INFO, DomainName) },
      FIELD_OFFSET(LSAPR_POLICY_ACCOUNT_DOM_INFO, Sid) },
    { PolicyLocalAccountDomainInformation, sizeof(LSAPR_POLICY_ACCOUNT_DOM_INFO), 1,
      { FIELD_OFFSET(LSAPR_POLICY_ACCOUNT_DOM_INFO, DomainName) },
      FIELD_OFFSET(LSAPR_POLICY_ACCOUNT_DOM_INFO, Sid) },
    { PolicyReplicaSourceInformation, sizeof(POLICY_LSA_REPLICA_SRCE_INFO), 2,
      { FIELD_OFFSET(POLICY_LSA_REPLICA_SRCE_INFO, ReplicaSource),
        FIELD_OFFSET(POLICY_LSA_REPLICA_SRCE_INFO, ReplicaAccountName) }, -1 },
    { PolicyDnsDomainInformation, sizeof(LSAPR_POLICY_DNS_DOMAIN_INFO), 3,
      { FIELD_OFFSET(LSAPR_POLICY_DNS_DOMAIN_INFO, Name),
        FIELD_OFFSET(LSAPR_POLICY_DNS_DOMAIN_INFO, DnsDomainName),
        FIELD_OFFSET(LSAPR_POLICY_DNS_DOMAIN_INFO, DnsForestName) },
      FIELD_OFFSET(LSAPR_POLICY_DNS_DOMAIN_INFO, Sid) },
    { PolicyDnsDomainInformationInt, sizeof(LSAPR_POLICY_DNS_DOMAIN_INFO), 3,
      { FIELD_OFFSET(LSAPR_POLICY_DNS_DOMAIN_INFO, Name),
        FIELD_OFFSET(LSAPR_POLICY_DNS_DOMAIN_INFO, DnsDomainName),
        FIELD_OFFSET(LSAPR_POLICY_DNS_DOMAIN_INFO, DnsForestName) },
      FIELD_OFFSET(LSAPR_POLICY_DNS_DOMAIN_INFO, Sid) },
};

static
VOID
LsapPackPolicyInformation(
    _In_ POLICY_INFORMATION_CLASS InformationClass,
    _Inout_ PVOID *PolicyInformation)
{
    PUCHAR Old = *PolicyInformation, New, Cursor;
    const LSAP_POLICY_LAYOUT *Layout = NULL;
    PLSAPR_POLICY_AUDIT_EVENTS_INFO OldAudit, NewAudit;
    PUNICODE_STRING OldString, NewString;
    PSID *OldSid, *NewSid;
    ULONGLONG Size;
    ULONG i, SidLength;

    if (Old == NULL)
        return;

    if (InformationClass == PolicyAuditEventsInformation)
    {
        OldAudit = (PLSAPR_POLICY_AUDIT_EVENTS_INFO)Old;
        if (OldAudit->EventAuditingOptions == NULL || OldAudit->MaximumAuditEventCount == 0 ||
            OldAudit->MaximumAuditEventCount > 0x10000)
            return;

        Size = LSAP_ALIGN(sizeof(*OldAudit)) + (ULONGLONG)OldAudit->MaximumAuditEventCount * sizeof(DWORD);
        New = HeapAlloc(GetProcessHeap(), 0, (SIZE_T)Size);
        if (New == NULL)
            return;

        NewAudit = (PLSAPR_POLICY_AUDIT_EVENTS_INFO)New;
        *NewAudit = *OldAudit;
        NewAudit->EventAuditingOptions = (DWORD *)(New + (SIZE_T)LSAP_ALIGN(sizeof(*OldAudit)));
        RtlCopyMemory(NewAudit->EventAuditingOptions, OldAudit->EventAuditingOptions,
                      OldAudit->MaximumAuditEventCount * sizeof(DWORD));

        MIDL_user_free(OldAudit->EventAuditingOptions);
        MIDL_user_free(Old);
        *PolicyInformation = New;
        return;
    }

    for (i = 0; i < RTL_NUMBER_OF(LsapPolicyLayouts); i++)
    {
        if (LsapPolicyLayouts[i].Class == InformationClass)
        {
            Layout = &LsapPolicyLayouts[i];
            break;
        }
    }
    if (Layout == NULL)
        return;

    /* The structure, then each string (aligned), then the SID */
    Size = LSAP_ALIGN(Layout->StructSize);
    for (i = 0; i < Layout->StringCount; i++)
    {
        OldString = (PUNICODE_STRING)(Old + Layout->StringOffsets[i]);
        if (OldString->Buffer != NULL && OldString->MaximumLength != 0)
            Size += LSAP_ALIGN(OldString->MaximumLength);
    }
    if (Layout->SidOffset >= 0)
    {
        OldSid = (PSID *)(Old + Layout->SidOffset);
        if (*OldSid != NULL)
            Size += LSAP_ALIGN(RtlLengthSid(*OldSid));
    }

    New = HeapAlloc(GetProcessHeap(), 0, (SIZE_T)Size);
    if (New == NULL)
        return;

    RtlCopyMemory(New, Old, Layout->StructSize);
    Cursor = New + (SIZE_T)LSAP_ALIGN(Layout->StructSize);
    for (i = 0; i < Layout->StringCount; i++)
    {
        OldString = (PUNICODE_STRING)(Old + Layout->StringOffsets[i]);
        NewString = (PUNICODE_STRING)(New + Layout->StringOffsets[i]);
        if (OldString->Buffer != NULL && OldString->MaximumLength != 0)
        {
            RtlCopyMemory(Cursor, OldString->Buffer, OldString->MaximumLength);
            NewString->Buffer = (PWSTR)Cursor;
            Cursor += (SIZE_T)LSAP_ALIGN(OldString->MaximumLength);
        }
        else
        {
            NewString->Buffer = NULL;
        }
    }
    if (Layout->SidOffset >= 0)
    {
        OldSid = (PSID *)(Old + Layout->SidOffset);
        NewSid = (PSID *)(New + Layout->SidOffset);
        if (*OldSid != NULL)
        {
            SidLength = RtlLengthSid(*OldSid);
            RtlCopyMemory(Cursor, *OldSid, SidLength);
            *NewSid = (PSID)Cursor;
        }
    }

    /* Free the pieces as the stub allocated them */
    for (i = 0; i < Layout->StringCount; i++)
    {
        OldString = (PUNICODE_STRING)(Old + Layout->StringOffsets[i]);
        if (OldString->Buffer != NULL)
            MIDL_user_free(OldString->Buffer);
    }
    if (Layout->SidOffset >= 0)
    {
        OldSid = (PSID *)(Old + Layout->SidOffset);
        if (*OldSid != NULL)
            MIDL_user_free(*OldSid);
    }
    MIDL_user_free(Old);

    *PolicyInformation = New;
}


/*
 * @implemented
 */
NTSTATUS
WINAPI
LsaQueryInformationPolicy(IN LSA_HANDLE PolicyHandle,
                          IN POLICY_INFORMATION_CLASS InformationClass,
                          OUT PVOID *Buffer)
{
    PLSAPR_POLICY_INFORMATION PolicyInformation = NULL;
    NTSTATUS Status;

    TRACE("LsaQueryInformationPolicy(%p %d %p)\n",
          PolicyHandle, InformationClass, Buffer);

    RpcTryExcept
    {
        Status = LsarQueryInformationPolicy((LSAPR_HANDLE)PolicyHandle,
                                            InformationClass,
                                            &PolicyInformation);
        if (NT_SUCCESS(Status))
            LsapPackPolicyInformation(InformationClass, (PVOID *)&PolicyInformation);
        *Buffer = PolicyInformation;
    }
    RpcExcept(EXCEPTION_EXECUTE_HANDLER)
    {
        if (PolicyInformation != NULL)
            MIDL_user_free(PolicyInformation);

        Status = I_RpcMapWin32Status(RpcExceptionCode());
    }
    RpcEndExcept;

    TRACE("Done (Status: 0x%08x)\n", Status);

    return Status;
}


/*
 * @implemented
 */
NTSTATUS
WINAPI
LsaQuerySecret(IN LSA_HANDLE SecretHandle,
               OUT PLSA_UNICODE_STRING *CurrentValue OPTIONAL,
               OUT PLARGE_INTEGER CurrentValueSetTime OPTIONAL,
               OUT PLSA_UNICODE_STRING *OldValue OPTIONAL,
               OUT PLARGE_INTEGER OldValueSetTime OPTIONAL)
{
    PLSAPR_CR_CIPHER_VALUE EncryptedCurrentValue = NULL;
    PLSAPR_CR_CIPHER_VALUE EncryptedOldValue = NULL;
    PLSA_UNICODE_STRING DecryptedCurrentValue = NULL;
    PLSA_UNICODE_STRING DecryptedOldValue = NULL;
    SIZE_T BufferSize;
    NTSTATUS Status;

    TRACE("LsaQuerySecret(%p %p %p %p %p)\n",
          SecretHandle, CurrentValue, CurrentValueSetTime,
          OldValue, OldValueSetTime);

    RpcTryExcept
    {
        Status = LsarQuerySecret((PLSAPR_HANDLE)SecretHandle,
                                 &EncryptedCurrentValue,
                                 CurrentValueSetTime,
                                 &EncryptedOldValue,
                                 OldValueSetTime);
    }
    RpcExcept(EXCEPTION_EXECUTE_HANDLER)
    {
        Status = I_RpcMapWin32Status(RpcExceptionCode());
    }
    RpcEndExcept;

    if (!NT_SUCCESS(Status))
        goto done;

    /* Decrypt the current value */
    if (CurrentValue != NULL)
    {
         if (EncryptedCurrentValue == NULL)
         {
             *CurrentValue = NULL;
         }
         else
         {
             /* FIXME: Decrypt the current value */
             BufferSize = sizeof(LSA_UNICODE_STRING) + EncryptedCurrentValue->MaximumLength;
             DecryptedCurrentValue = midl_user_allocate(BufferSize);
             if (DecryptedCurrentValue == NULL)
             {
                 Status = STATUS_INSUFFICIENT_RESOURCES;
                 goto done;
             }

             DecryptedCurrentValue->Length = (USHORT)EncryptedCurrentValue->Length;
             DecryptedCurrentValue->MaximumLength = (USHORT)EncryptedCurrentValue->MaximumLength;
             DecryptedCurrentValue->Buffer = (PWSTR)(DecryptedCurrentValue + 1);
             RtlCopyMemory(DecryptedCurrentValue->Buffer,
                           EncryptedCurrentValue->Buffer,
                           EncryptedCurrentValue->Length);

             *CurrentValue = DecryptedCurrentValue;
         }
    }

    /* Decrypt the old value */
    if (OldValue != NULL)
    {
         if (EncryptedOldValue == NULL)
         {
             *OldValue = NULL;
         }
         else
         {
             /* FIXME: Decrypt the old value */
             BufferSize = sizeof(LSA_UNICODE_STRING) + EncryptedOldValue->MaximumLength;
             DecryptedOldValue = midl_user_allocate(BufferSize);
             if (DecryptedOldValue == NULL)
             {
                 Status = STATUS_INSUFFICIENT_RESOURCES;
                 goto done;
             }

             DecryptedOldValue->Length = (USHORT)EncryptedOldValue->Length;
             DecryptedOldValue->MaximumLength = (USHORT)EncryptedOldValue->MaximumLength;
             DecryptedOldValue->Buffer = (PWSTR)(DecryptedOldValue + 1);
             RtlCopyMemory(DecryptedOldValue->Buffer,
                           EncryptedOldValue->Buffer,
                           EncryptedOldValue->Length);

             *OldValue = DecryptedOldValue;
         }
    }

done:
    if (!NT_SUCCESS(Status))
    {
        if (DecryptedCurrentValue != NULL)
            midl_user_free(DecryptedCurrentValue);

        if (DecryptedOldValue != NULL)
            midl_user_free(DecryptedOldValue);

        if (CurrentValue != NULL)
            *CurrentValue = NULL;

        if (OldValue != NULL)
            *OldValue = NULL;
    }

    if (EncryptedCurrentValue != NULL)
        midl_user_free(EncryptedCurrentValue);

    if (EncryptedOldValue != NULL)
        midl_user_free(EncryptedOldValue);

    return Status;
}


/*
 * @implemented
 */
NTSTATUS
WINAPI
LsaQuerySecurityObject(IN LSA_HANDLE ObjectHandle,
                       IN SECURITY_INFORMATION SecurityInformation,
                       OUT PSECURITY_DESCRIPTOR *SecurityDescriptor)
{
    LSAPR_SR_SECURITY_DESCRIPTOR SdBuffer;
    PLSAPR_SR_SECURITY_DESCRIPTOR SdPointer;
    NTSTATUS Status;

    TRACE("LsaQuerySecurityObject(%p %lx %p)\n",
          ObjectHandle, SecurityInformation, SecurityDescriptor);

    SdBuffer.Length = 0;
    SdBuffer.SecurityDescriptor = NULL;

    SdPointer = &SdBuffer;

    RpcTryExcept
    {
        Status = LsarQuerySecurityObject((LSAPR_HANDLE)ObjectHandle,
                                         SecurityInformation,
                                         &SdPointer);
        if (NT_SUCCESS(Status))
        {
            *SecurityDescriptor = SdBuffer.SecurityDescriptor;
        }
        else
        {
            *SecurityDescriptor = NULL;
        }
    }
    RpcExcept(EXCEPTION_EXECUTE_HANDLER)
    {
        Status = I_RpcMapWin32Status(RpcExceptionCode());
    }
    RpcEndExcept;

    return Status;
}


/*
 * @implemented
 */
NTSTATUS
WINAPI
LsaQueryTrustedDomainInfo(IN LSA_HANDLE PolicyHandle,
                          IN PSID TrustedDomainSid,
                          IN TRUSTED_INFORMATION_CLASS InformationClass,
                          OUT PVOID *Buffer)
{
    NTSTATUS Status;

    TRACE("LsaQueryTrustedDomainInfo(%p %p %d %p) stub\n",
          PolicyHandle, TrustedDomainSid, InformationClass, Buffer);

    if (InformationClass == TrustedDomainAuthInformationInternal ||
        InformationClass == TrustedDomainFullInformationInternal)
        return STATUS_INVALID_INFO_CLASS;

    RpcTryExcept
    {
        Status = LsarQueryTrustedDomainInfo((LSAPR_HANDLE)PolicyHandle,
                                            (PRPC_SID)TrustedDomainSid,
                                            InformationClass,
                                            (PLSAPR_TRUSTED_DOMAIN_INFO *)Buffer);
    }
    RpcExcept(EXCEPTION_EXECUTE_HANDLER)
    {
        Status = I_RpcMapWin32Status(RpcExceptionCode());
    }
    RpcEndExcept;

    return Status;
}


/*
 * @implemented
 */
NTSTATUS
WINAPI
LsaQueryTrustedDomainInfoByName(IN LSA_HANDLE PolicyHandle,
                                IN PLSA_UNICODE_STRING TrustedDomainName,
                                IN TRUSTED_INFORMATION_CLASS InformationClass,
                                OUT PVOID *Buffer)
{
    NTSTATUS Status;

    TRACE("LsaQueryTrustedDomainInfoByName(%p %p %d %p)\n",
          PolicyHandle, TrustedDomainName, InformationClass, Buffer);

    if (InformationClass == TrustedDomainAuthInformationInternal ||
        InformationClass == TrustedDomainFullInformationInternal)
        return STATUS_INVALID_INFO_CLASS;

    RpcTryExcept
    {
        Status = LsarQueryTrustedDomainInfoByName((LSAPR_HANDLE)PolicyHandle,
                                                  (PRPC_UNICODE_STRING)TrustedDomainName,
                                                  InformationClass,
                                                  (PLSAPR_TRUSTED_DOMAIN_INFO *)Buffer);
    }
    RpcExcept(EXCEPTION_EXECUTE_HANDLER)
    {
        Status = I_RpcMapWin32Status(RpcExceptionCode());
    }
    RpcEndExcept;

    return Status;
}


/*
 * @implemented
 */
NTSTATUS
WINAPI
LsaRemoveAccountRights(IN LSA_HANDLE PolicyHandle,
                       IN PSID AccountSid,
                       IN BOOLEAN AllRights,
                       IN PLSA_UNICODE_STRING UserRights,
                       IN ULONG CountOfRights)
{
    NTSTATUS Status;
    LSAPR_USER_RIGHT_SET UserRightSet;

    TRACE("LsaRemoveAccountRights(%p %p %d %p %lu)\n",
          PolicyHandle, AccountSid, AllRights, UserRights, CountOfRights);

    UserRightSet.Entries = CountOfRights;
    UserRightSet.UserRights = (PRPC_UNICODE_STRING)UserRights;

    RpcTryExcept
    {
        Status = LsarRemoveAccountRights((LSAPR_HANDLE)PolicyHandle,
                                         (PRPC_SID)AccountSid,
                                         AllRights,
                                         &UserRightSet);
    }
    RpcExcept(EXCEPTION_EXECUTE_HANDLER)
    {
        Status = I_RpcMapWin32Status(RpcExceptionCode());
    }
    RpcEndExcept;

    return Status;
}


/*
 * @implemented
 */
NTSTATUS
WINAPI
LsaRemovePrivilegesFromAccount(IN LSA_HANDLE AccountHandle,
                               IN BOOLEAN AllPrivileges,
                               IN PPRIVILEGE_SET Privileges OPTIONAL)
{
    NTSTATUS Status;

    RpcTryExcept
    {
        Status = LsarRemovePrivilegesFromAccount((LSAPR_HANDLE)AccountHandle,
                                                 AllPrivileges,
                                                 (PLSAPR_PRIVILEGE_SET)Privileges);
    }
    RpcExcept(EXCEPTION_EXECUTE_HANDLER)
    {
        Status = I_RpcMapWin32Status(RpcExceptionCode());
    }
    RpcEndExcept;

    return Status;
}


/*
 * @implemented
 */
NTSTATUS
WINAPI
LsaRetrievePrivateData(IN LSA_HANDLE PolicyHandle,
                       IN PLSA_UNICODE_STRING KeyName,
                       OUT PLSA_UNICODE_STRING *PrivateData)
{
    PLSAPR_CR_CIPHER_VALUE EncryptedData = NULL;
    PLSA_UNICODE_STRING DecryptedData = NULL;
    SIZE_T BufferSize;
    NTSTATUS Status;

    TRACE("LsaRetrievePrivateData(%p %p %p)\n",
          PolicyHandle, KeyName, PrivateData);

    RpcTryExcept
    {
        Status = LsarRetrievePrivateData((LSAPR_HANDLE)PolicyHandle,
                                         (PRPC_UNICODE_STRING)KeyName,
                                         &EncryptedData);
    }
    RpcExcept(EXCEPTION_EXECUTE_HANDLER)
    {
        Status = I_RpcMapWin32Status(RpcExceptionCode());
    }
    RpcEndExcept;

    if (EncryptedData == NULL)
    {
        *PrivateData = NULL;
    }
    else
    {
        BufferSize = sizeof(LSA_UNICODE_STRING) + EncryptedData->MaximumLength;
        DecryptedData = midl_user_allocate(BufferSize);
        if (DecryptedData == NULL)
        {
            Status = STATUS_INSUFFICIENT_RESOURCES;
            goto done;
        }

        DecryptedData->Length = (USHORT)EncryptedData->Length;
        DecryptedData->MaximumLength = (USHORT)EncryptedData->MaximumLength;
        DecryptedData->Buffer = (PWSTR)(DecryptedData + 1);
        RtlCopyMemory(DecryptedData->Buffer,
                      EncryptedData->Buffer,
                      EncryptedData->Length);

        *PrivateData = DecryptedData;
    }

done:
    if (!NT_SUCCESS(Status))
    {
        if (DecryptedData != NULL)
            midl_user_free(DecryptedData);

        *PrivateData = NULL;
    }

    if (EncryptedData != NULL)
    {
        if (EncryptedData->Buffer != NULL)
            midl_user_free(EncryptedData->Buffer);
        midl_user_free(EncryptedData);
    }

    return Status;
}


/*
 * @implemented
 */
NTSTATUS
WINAPI
LsaSetDomainInformationPolicy(IN LSA_HANDLE PolicyHandle,
                              IN POLICY_DOMAIN_INFORMATION_CLASS InformationClass,
                              IN PVOID Buffer OPTIONAL)
{
    NTSTATUS Status;

    TRACE("LsaSetDomainInformationPolicy(%p %d %p)\n",
          PolicyHandle, InformationClass, Buffer);

    RpcTryExcept
    {
        Status = LsarSetDomainInformationPolicy((LSAPR_HANDLE)PolicyHandle,
                                                InformationClass,
                                                (PLSAPR_POLICY_DOMAIN_INFORMATION)Buffer);
    }
    RpcExcept(EXCEPTION_EXECUTE_HANDLER)
    {
        Status = I_RpcMapWin32Status(RpcExceptionCode());
    }
    RpcEndExcept;

    return Status;
}


/*
 * @implemented
 */
NTSTATUS
WINAPI
LsaSetForestTrustInformation(IN LSA_HANDLE PolicyHandle,
                             IN PLSA_UNICODE_STRING TrustedDomainName,
                             IN PLSA_FOREST_TRUST_INFORMATION ForestTrustInfo,
                             IN BOOLEAN CheckOnly,
                             OUT PLSA_FOREST_TRUST_COLLISION_INFORMATION *CollisionInfo)
{
    NTSTATUS Status;

    TRACE("LsaSetForestTrustInformation(%p %p %p %d %p)\n",
          PolicyHandle, TrustedDomainName, ForestTrustInfo, CheckOnly, CollisionInfo);

    RpcTryExcept
    {
        Status = LsarSetForestTrustInformation((LSAPR_HANDLE)PolicyHandle,
                                               TrustedDomainName,
                                               ForestTrustDomainInfo,
                                               ForestTrustInfo,
                                               CheckOnly,
                                               CollisionInfo);
    }
    RpcExcept(EXCEPTION_EXECUTE_HANDLER)
    {
        Status = I_RpcMapWin32Status(RpcExceptionCode());
    }
    RpcEndExcept;

    return Status;
}


/*
 * @implemented
 */
NTSTATUS
WINAPI
LsaSetInformationPolicy(IN LSA_HANDLE PolicyHandle,
                        IN POLICY_INFORMATION_CLASS InformationClass,
                        IN PVOID Buffer)
{
    NTSTATUS Status;

    TRACE("LsaSetInformationPolicy(%p %d %p)\n",
          PolicyHandle, InformationClass, Buffer);

    RpcTryExcept
    {
        Status = LsarSetInformationPolicy((LSAPR_HANDLE)PolicyHandle,
                                          InformationClass,
                                          (PLSAPR_POLICY_INFORMATION)Buffer);
    }
    RpcExcept(EXCEPTION_EXECUTE_HANDLER)
    {
        Status = I_RpcMapWin32Status(RpcExceptionCode());
    }
    RpcEndExcept;

    return Status;
}


/*
 * @unimplemented
 */
NTSTATUS
WINAPI
LsaSetInformationTrustedDomain(IN LSA_HANDLE TrustedDomainHandle,
                               IN TRUSTED_INFORMATION_CLASS InformationClass,
                               IN PVOID Buffer)
{
    FIXME("LsaSetInformationTrustedDomain(%p %d %p)\n",
          TrustedDomainHandle, InformationClass, Buffer);
    return STATUS_NOT_IMPLEMENTED;
}


/*
 * @implemented
 */
NTSTATUS
WINAPI
LsaSetQuotasForAccount(IN LSA_HANDLE AccountHandle,
                       IN PQUOTA_LIMITS QuotaLimits)
{
    NTSTATUS Status;

    TRACE("LsaSetQuotasForAccount(%p %p)\n",
          AccountHandle, QuotaLimits);

    RpcTryExcept
    {
        Status = LsarSetQuotasForAccount((LSAPR_HANDLE)AccountHandle,
                                         QuotaLimits);
    }
    RpcExcept(EXCEPTION_EXECUTE_HANDLER)
    {
        Status = I_RpcMapWin32Status(RpcExceptionCode());
    }
    RpcEndExcept;

    return Status;
}


/*
 * @implemented
 */
NTSTATUS
WINAPI
LsaSetSecret(IN LSA_HANDLE SecretHandle,
             IN PLSA_UNICODE_STRING CurrentValue OPTIONAL,
             IN PLSA_UNICODE_STRING OldValue OPTIONAL)
{
    PLSAPR_CR_CIPHER_VALUE EncryptedCurrentValue = NULL;
    PLSAPR_CR_CIPHER_VALUE EncryptedOldValue = NULL;
    SIZE_T BufferSize;
    NTSTATUS Status;

    TRACE("LsaSetSecret(%p %p %p)\n",
          SecretHandle, EncryptedCurrentValue, EncryptedOldValue);

    if (CurrentValue != NULL)
    {
        BufferSize = sizeof(LSAPR_CR_CIPHER_VALUE) + CurrentValue->MaximumLength;
        EncryptedCurrentValue = midl_user_allocate(BufferSize);
        if (EncryptedCurrentValue == NULL)
        {
            Status = STATUS_INSUFFICIENT_RESOURCES;
            goto done;
        }

        EncryptedCurrentValue->Length = CurrentValue->Length;
        EncryptedCurrentValue->MaximumLength = CurrentValue->MaximumLength;
        EncryptedCurrentValue->Buffer = (BYTE *)(EncryptedCurrentValue + 1);
        if (EncryptedCurrentValue->Buffer != NULL)
            memcpy(EncryptedCurrentValue->Buffer, CurrentValue->Buffer, CurrentValue->Length);
    }

    if (OldValue != NULL)
    {
        BufferSize = sizeof(LSAPR_CR_CIPHER_VALUE) + OldValue->MaximumLength;
        EncryptedOldValue = midl_user_allocate(BufferSize);
        if (EncryptedOldValue == NULL)
        {
            Status = STATUS_INSUFFICIENT_RESOURCES;
            goto done;
        }

        EncryptedOldValue->Length = OldValue->Length;
        EncryptedOldValue->MaximumLength = OldValue->MaximumLength;
        EncryptedOldValue->Buffer = (BYTE*)(EncryptedOldValue + 1);
        if (EncryptedOldValue->Buffer != NULL)
            memcpy(EncryptedOldValue->Buffer, OldValue->Buffer, OldValue->Length);
    }

    RpcTryExcept
    {
        Status = LsarSetSecret((LSAPR_HANDLE)SecretHandle,
                               EncryptedCurrentValue,
                               EncryptedOldValue);
    }
    RpcExcept(EXCEPTION_EXECUTE_HANDLER)
    {
        Status = I_RpcMapWin32Status(RpcExceptionCode());
    }
    RpcEndExcept;

done:
    if (EncryptedCurrentValue != NULL)
        midl_user_free(EncryptedCurrentValue);

    if (EncryptedOldValue != NULL)
        midl_user_free(EncryptedOldValue);

    return Status;
}


/*
 * @implemented
 */
NTSTATUS
WINAPI
LsaSetSecurityObject(IN LSA_HANDLE ObjectHandle,
                     IN SECURITY_INFORMATION SecurityInformation,
                     IN PSECURITY_DESCRIPTOR SecurityDescriptor)
{
    LSAPR_SR_SECURITY_DESCRIPTOR SdBuffer = {0, NULL};
    ULONG SdLength = 0;
    NTSTATUS Status;

    TRACE("LsaSetSecurityObject(%p %lx %p)\n",
          ObjectHandle, SecurityInformation, SecurityDescriptor);

    Status = RtlMakeSelfRelativeSD(SecurityDescriptor,
                                   NULL,
                                   &SdLength);
    if (Status != STATUS_BUFFER_TOO_SMALL)
        return STATUS_INVALID_PARAMETER;

    SdBuffer.SecurityDescriptor = MIDL_user_allocate(SdLength);
    if (SdBuffer.SecurityDescriptor == NULL)
        return STATUS_INSUFFICIENT_RESOURCES;

    Status = RtlMakeSelfRelativeSD(SecurityDescriptor,
                                   (PSECURITY_DESCRIPTOR)SdBuffer.SecurityDescriptor,
                                   &SdLength);
    if (!NT_SUCCESS(Status))
        goto done;

    SdBuffer.Length = SdLength;

    RpcTryExcept
    {
        Status = LsarSetSecurityObject((LSAPR_HANDLE)ObjectHandle,
                                       SecurityInformation,
                                       &SdBuffer);
    }
    RpcExcept(EXCEPTION_EXECUTE_HANDLER)
    {
        Status = I_RpcMapWin32Status(RpcExceptionCode());
    }
    RpcEndExcept;

done:
    if (SdBuffer.SecurityDescriptor != NULL)
        MIDL_user_free(SdBuffer.SecurityDescriptor);

    return Status;
}


/*
 * @implemented
 */
NTSTATUS
WINAPI
LsaSetSystemAccessAccount(IN LSA_HANDLE AccountHandle,
                          IN ULONG SystemAccess)
{
    NTSTATUS Status;

    TRACE("LsaSetSystemAccessAccount(%p 0x%lx)\n",
          AccountHandle, SystemAccess);

    RpcTryExcept
    {
        Status = LsarSetSystemAccessAccount((LSAPR_HANDLE)AccountHandle,
                                            SystemAccess);
    }
    RpcExcept(EXCEPTION_EXECUTE_HANDLER)
    {
        Status = I_RpcMapWin32Status(RpcExceptionCode());
    }
    RpcEndExcept;

    return Status;
}


/*
 * @unimplemented
 */
NTSTATUS
WINAPI
LsaSetTrustedDomainInfoByName(IN LSA_HANDLE PolicyHandle,
                              IN PLSA_UNICODE_STRING TrustedDomainName,
                              IN TRUSTED_INFORMATION_CLASS InformationClass,
                              IN PVOID Buffer)
{
    FIXME("LsaSetTrustedDomainInfoByName(%p %p %d %p) stub\n",
          PolicyHandle, TrustedDomainName, InformationClass, Buffer);
    return STATUS_SUCCESS;
}


/*
 * @unimplemented
 */
NTSTATUS
WINAPI
LsaSetTrustedDomainInformation(IN LSA_HANDLE PolicyHandle,
                               IN PSID TrustedDomainSid,
                               IN TRUSTED_INFORMATION_CLASS InformationClass,
                               IN PVOID Buffer)
{
    FIXME("LsaSetTrustedDomainInformation(%p %p %d %p) stub\n",
          PolicyHandle, TrustedDomainSid, InformationClass, Buffer);
    return STATUS_SUCCESS;
}


/*
 * @implemented
 */
NTSTATUS
WINAPI
LsaStorePrivateData(IN LSA_HANDLE PolicyHandle,
                    IN PLSA_UNICODE_STRING KeyName,
                    IN PLSA_UNICODE_STRING PrivateData OPTIONAL)
{
    PLSAPR_CR_CIPHER_VALUE EncryptedData = NULL;
    SIZE_T BufferSize;
    NTSTATUS Status;

    TRACE("LsaStorePrivateData(%p %p %p)\n",
          PolicyHandle, KeyName, PrivateData);

    if (PrivateData != NULL)
    {
        BufferSize = sizeof(LSAPR_CR_CIPHER_VALUE) + PrivateData->MaximumLength;
        EncryptedData = midl_user_allocate(BufferSize);
        if (EncryptedData == NULL)
        {
            Status = STATUS_INSUFFICIENT_RESOURCES;
            goto done;
        }

        EncryptedData->Length = PrivateData->Length;
        EncryptedData->MaximumLength = PrivateData->MaximumLength;
        EncryptedData->Buffer = (BYTE *)(EncryptedData + 1);
        if (EncryptedData->Buffer != NULL)
            RtlCopyMemory(EncryptedData->Buffer,
                          PrivateData->Buffer,
                          PrivateData->Length);
    }

    RpcTryExcept
    {
        Status = LsarStorePrivateData((LSAPR_HANDLE)PolicyHandle,
                                      (PRPC_UNICODE_STRING)KeyName,
                                      EncryptedData);
    }
    RpcExcept(EXCEPTION_EXECUTE_HANDLER)
    {
        Status = I_RpcMapWin32Status(RpcExceptionCode());
    }
    RpcEndExcept;

done:
    if (EncryptedData != NULL)
        midl_user_free(EncryptedData);

    return Status;
}

/*
 * The SID-name mapping operations are not in the public SDK headers. They manage the virtual accounts
 * (domain "VIRTUAL USERS") that OpenSSH and other services use for accounts without a SAM entry.
 */
typedef struct _LSAP_SID_NAME_MAPPING_OUTPUT
{
    ULONG ErrorCode; /* LSA_SID_NAME_MAPPING_OPERATION_ERROR */
} LSAP_SID_NAME_MAPPING_OUTPUT, *PLSAP_SID_NAME_MAPPING_OUTPUT;

#define LSAP_SID_NAME_MAPPING_NON_MAPPING_ERROR 1
#define LSAP_SID_NAME_MAPPING_OP_ADD            0
#define LSAP_SID_NAME_MAPPING_OP_REMOVE         1
#define LSAP_SID_NAME_MAPPING_OP_ADD_MULTIPLE   2

/*
 * @implemented (the privilege check and reply shape only)
 *
 * There is no LSA virtual account table behind this yet. A caller without SeTcbPrivilege gets
 * STATUS_PRIVILEGE_NOT_HELD, as on Windows; a caller with it gets STATUS_NOT_IMPLEMENTED. Either
 * way an output block (freed with LsaFreeMemory) reports a non-mapping error.
 */
NTSTATUS
WINAPI
LsaManageSidNameMapping(
    _In_ ULONG OperationType,
    _In_ PVOID OperationInput,
    _Outptr_ PLSAP_SID_NAME_MAPPING_OUTPUT *OperationOutput)
{
    PLSAP_SID_NAME_MAPPING_OUTPUT Output;
    PRIVILEGE_SET Privileges;
    HANDLE Token = NULL;
    BOOL HasTcb = FALSE;
    NTSTATUS Status;

    TRACE("LsaManageSidNameMapping(%lu %p %p)\n", OperationType, OperationInput, OperationOutput);

    if (OperationOutput == NULL)
        return STATUS_INVALID_PARAMETER;
    *OperationOutput = NULL;

    if (OperationInput == NULL || OperationType > LSAP_SID_NAME_MAPPING_OP_ADD_MULTIPLE)
        return STATUS_INVALID_PARAMETER;

    Privileges.PrivilegeCount = 1;
    Privileges.Control = PRIVILEGE_SET_ALL_NECESSARY;
    Privileges.Privilege[0].Attributes = 0;
    if (LookupPrivilegeValueW(NULL, SE_TCB_NAME, &Privileges.Privilege[0].Luid) &&
        OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &Token) == FALSE &&
        GetLastError() == ERROR_NO_TOKEN)
    {
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &Token);
    }
    if (Token != NULL)
    {
        if (!PrivilegeCheck(Token, &Privileges, &HasTcb))
            HasTcb = FALSE;
        CloseHandle(Token);
    }

    Output = RtlAllocateHeap(RtlGetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*Output));
    if (Output == NULL)
        return STATUS_INSUFFICIENT_RESOURCES;
    Output->ErrorCode = LSAP_SID_NAME_MAPPING_NON_MAPPING_ERROR;
    *OperationOutput = Output;

    Status = HasTcb ? STATUS_NOT_IMPLEMENTED : STATUS_PRIVILEGE_NOT_HELD;
    return Status;
}

/* EOF */
