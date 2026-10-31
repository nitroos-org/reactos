/*
 * PROJECT:     ReactOS advapi32
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Exports of the advapi32.dll of Windows 10 that were missing: relative security descriptors,
 *              ControlServiceEx, LsaLookupSids2, and a few small ones
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * The results were measured on Windows 10 22H2 (build 19045), x64 and x86; each function says what it does the
 * same way and where it differs.
 */

#include <advapi32.h>

#include <ndk/rtlfuncs.h>
#include <ntsecapi.h>

WINE_DEFAULT_DEBUG_CHANNEL(advapi);

/******************************************************************************
 * IsValidRelativeSecurityDescriptor [ADVAPI32.@]
 *
 * Windows forwards this to kernelbase. A descriptor that is not valid is FALSE with
 * ERROR_INVALID_SECURITY_DESCR as the last error.
 */
BOOL
WINAPI
IsValidRelativeSecurityDescriptor(
    _In_ PSECURITY_DESCRIPTOR SecurityDescriptor,
    _In_ ULONG SecurityDescriptorLength,
    _In_ SECURITY_INFORMATION RequiredInformation)
{
    if (!RtlValidRelativeSecurityDescriptor(SecurityDescriptor, SecurityDescriptorLength, RequiredInformation))
    {
        SetLastError(ERROR_INVALID_SECURITY_DESCR);
        return FALSE;
    }
    return TRUE;
}

/******************************************************************************
 * TreeSetNamedSecurityInfoA [ADVAPI32.@]
 *
 * The ANSI version is not implemented on Windows 10 either: it answers ERROR_CALL_NOT_IMPLEMENTED whatever it is given.
 */
DWORD
WINAPI
TreeSetNamedSecurityInfoA(
    _In_ LPSTR pObjectName,
    _In_ SE_OBJECT_TYPE ObjectType,
    _In_ SECURITY_INFORMATION SecurityInfo,
    _In_opt_ PSID pOwner,
    _In_opt_ PSID pGroup,
    _In_opt_ PACL pDacl,
    _In_opt_ PACL pSacl,
    _In_ DWORD dwAction,
    _In_opt_ PVOID fnProgress,
    _In_ DWORD ProgressInvokeSetting,
    _In_opt_ PVOID Args)
{
    return ERROR_CALL_NOT_IMPLEMENTED;
}

/******************************************************************************
 * FreeEncryptedFileMetadata [ADVAPI32.@]
 *
 * Windows 10 returns at once (the metadata of an encrypted file is not allocated by a call that can be made here).
 */
VOID
WINAPI
FreeEncryptedFileMetadata(
    _In_ PBYTE pbMetadata)
{
    UNREFERENCED_PARAMETER(pbMetadata);
}

/******************************************************************************
 * LsaLookupSids2 [ADVAPI32.@]
 *
 * LookupOptions (LSA_LOOKUP_ISOLATED_AS_LOCAL and the like) change only how a name without a domain is treated on a
 * domain controller, which is not told to the local authority here; the names and domains are those of LsaLookupSids.
 */
NTSTATUS
WINAPI
LsaLookupSids2(
    _In_ LSA_HANDLE PolicyHandle,
    _In_ ULONG LookupOptions,
    _In_ ULONG Count,
    _In_ PSID *Sids,
    _Out_ PLSA_REFERENCED_DOMAIN_LIST *ReferencedDomains,
    _Out_ PLSA_TRANSLATED_NAME *Names)
{
    TRACE("LsaLookupSids2(%p %lx %lu %p %p %p)\n", PolicyHandle, LookupOptions, Count, Sids, ReferencedDomains, Names);

    /* The failures of Windows 10 for these arguments, which the lookup would only see as a marshalling error */
    if (Count == 0)
    {
        *Names = NULL;
        return STATUS_INVALID_PARAMETER;
    }
    if (Sids == NULL)
        return STATUS_INVALID_PARAMETER;
    if (PolicyHandle == NULL)
        return STATUS_INVALID_HANDLE;

    return LsaLookupSids(PolicyHandle, Count, Sids, ReferencedDomains, Names);
}

/******************************************************************************
 * ControlServiceExW and ControlServiceExA [ADVAPI32.@]
 *
 * Information level 1 (SERVICE_CONTROL_STATUS_REASON_INFO) is the only one; its parameters carry the reason and
 * comment of a stop or restart, and the status of the service on return. The control is sent as ControlService sends
 * it and the status is the one the service answered, completed with the process ID and flags that the service
 * control manager has (when the handle may query the status). The reason and the comment are not passed on to the
 * service control manager, which has no call for them.
 */
/* SERVICE_CONTROL_STATUS_REASON_PARAMS of winsvc.h in Windows 10 */
typedef struct _CONTROL_STATUS_REASON_PARAMS
{
    DWORD dwReason;
    PVOID pszComment;
    SERVICE_STATUS_PROCESS ServiceStatus;
} CONTROL_STATUS_REASON_PARAMS, *PCONTROL_STATUS_REASON_PARAMS;

#ifndef SERVICE_CONTROL_STATUS_REASON_INFO
#define SERVICE_CONTROL_STATUS_REASON_INFO 1
#endif

static
BOOL
ControlServiceExCommon(
    _In_ SC_HANDLE hService,
    _In_ DWORD dwControl,
    _In_ DWORD dwInfoLevel,
    _Inout_ PVOID pControlParams)
{
    PCONTROL_STATUS_REASON_PARAMS Params = pControlParams;
    SERVICE_STATUS_PROCESS *Status;
    SERVICE_STATUS ControlStatus;
    SERVICE_STATUS_PROCESS Queried;
    DWORD Needed;

    if (dwInfoLevel != SERVICE_CONTROL_STATUS_REASON_INFO)
    {
        SetLastError(ERROR_INVALID_LEVEL);
        return FALSE;
    }

    if (pControlParams == NULL)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    Status = &Params->ServiceStatus;

    if (!ControlService(hService, dwControl, &ControlStatus))
        return FALSE;

    ZeroMemory(Status, sizeof(*Status));
    memcpy(Status, &ControlStatus, sizeof(ControlStatus));
    if (QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, (LPBYTE)&Queried, sizeof(Queried), &Needed))
    {
        Status->dwProcessId = Queried.dwProcessId;
        Status->dwServiceFlags = Queried.dwServiceFlags;
    }
    SetLastError(ERROR_SUCCESS);
    return TRUE;
}

BOOL
WINAPI
ControlServiceExW(
    _In_ SC_HANDLE hService,
    _In_ DWORD dwControl,
    _In_ DWORD dwInfoLevel,
    _Inout_ PVOID pControlParams)
{
    TRACE("ControlServiceExW(%p %lu %lu %p)\n", hService, dwControl, dwInfoLevel, pControlParams);

    return ControlServiceExCommon(hService, dwControl, dwInfoLevel, pControlParams);
}

BOOL
WINAPI
ControlServiceExA(
    _In_ SC_HANDLE hService,
    _In_ DWORD dwControl,
    _In_ DWORD dwInfoLevel,
    _Inout_ PVOID pControlParams)
{
    TRACE("ControlServiceExA(%p %lu %lu %p)\n", hService, dwControl, dwInfoLevel, pControlParams);

    /* The comment is not sent anywhere, so the ANSI form needs no conversion */
    return ControlServiceExCommon(hService, dwControl, dwInfoLevel, pControlParams);
}

/******************************************************************************
 * EventWriteStartScenario and EventWriteEndScenario [ADVAPI32.@]
 *
 * Windows forwards these to ntdll (EtwEventWriteStartScenario and ...EndScenario), which is a stub here, and which
 * would raise an exception. What Windows 10 22H2 answers was measured with no descriptor (ERROR_INVALID_PARAMETER),
 * and with a descriptor for a null, a bad and a registered handle (all ERROR_INVALID_HANDLE); nothing here makes
 * a provider that Windows would accept, so every call with a descriptor is the second.
 */
ULONG
WINAPI
EventWriteStartScenario(
    _In_ ULONGLONG RegHandle,
    _In_ const VOID *EventDescriptor,
    _In_ ULONG UserDataCount,
    _In_opt_ const VOID *UserData)
{
    if (EventDescriptor == NULL)
        return ERROR_INVALID_PARAMETER;
    return ERROR_INVALID_HANDLE;
}

ULONG
WINAPI
EventWriteEndScenario(
    _In_ ULONGLONG RegHandle,
    _In_ const VOID *EventDescriptor,
    _In_ ULONG UserDataCount,
    _In_opt_ const VOID *UserData)
{
    if (EventDescriptor == NULL)
        return ERROR_INVALID_PARAMETER;
    return ERROR_INVALID_HANDLE;
}
