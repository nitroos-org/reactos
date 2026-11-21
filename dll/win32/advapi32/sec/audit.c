/*
 * COPYRIGHT:       See COPYING in the top level directory
 * PROJECT:         ReactOS system libraries
 * FILE:            lib/advapi32/sec/audit.c
 * PURPOSE:         Audit functions
 * PROGRAMMER:      Eric Kohl
 * UPDATE HISTORY:
 *                  Created 07/19/2003
 */

/* INCLUDES *****************************************************************/

#include <advapi32.h>
WINE_DEFAULT_DEBUG_CHANNEL(advapi);

/* PRIVATE FUNCTIONS ********************************************************/

/* The three names of the ANSI access check and audit alarm functions in Unicode; a NULL name stays NULL */
static BOOL
AuditAlarmNamesFromAnsi(LPCSTR SubsystemName,
                        LPCSTR ObjectTypeName,
                        LPCSTR ObjectName,
                        PUNICODE_STRING Names)
{
    LPCSTR Source[3] = {SubsystemName, ObjectTypeName, ObjectName};
    ULONG i;

    RtlZeroMemory(Names, 3 * sizeof(UNICODE_STRING));
    for (i = 0; i < 3; i++)
    {
        if (Source[i] != NULL && !RtlCreateUnicodeStringFromAsciiz(&Names[i], (PCSZ)Source[i]))
        {
            while (i-- > 0)
                RtlFreeUnicodeString(&Names[i]);
            SetLastError(ERROR_NOT_ENOUGH_MEMORY);
            return FALSE;
        }
    }

    return TRUE;
}

static VOID
AuditAlarmFreeNames(PUNICODE_STRING Names)
{
    ULONG i;

    for (i = 0; i < 3; i++)
        RtlFreeUnicodeString(&Names[i]);
}

/*
 * The result of the access check and audit alarm functions with one result,
 * as AccessCheck reports it (measured on Windows Server 2022): when the check
 * could not run the function fails and leaves GrantedAccess and AccessStatus
 * alone; when it ran the function succeeds and AccessStatus says whether
 * access is granted, a denial with its reason as the last error.
 * pfGenerateOnClose is written in both cases (FALSE when the call failed).
 */
static BOOL
AuditAlarmResult(NTSTATUS Status,
                 NTSTATUS LocalAccessStatus,
                 BOOLEAN GenerateOnClose,
                 LPBOOL AccessStatus,
                 LPBOOL pfGenerateOnClose)
{
    *pfGenerateOnClose = (BOOL)GenerateOnClose;

    if (!NT_SUCCESS(Status))
    {
        SetLastError(RtlNtStatusToDosError(Status));
        return FALSE;
    }

    if (!NT_SUCCESS(LocalAccessStatus))
    {
        *AccessStatus = FALSE;
        SetLastError(RtlNtStatusToDosError(LocalAccessStatus));
        return TRUE;
    }

    *AccessStatus = TRUE;
    return TRUE;
}

/*
 * The result of the result list forms: as AccessCheckByTypeResultList, every
 * entry of AccessStatusList receives a Win32 error code (0 for granted).
 */
static BOOL
AuditAlarmResultList(NTSTATUS Status,
                     DWORD ObjectTypeListLength,
                     BOOLEAN GenerateOnClose,
                     LPDWORD AccessStatusList,
                     LPBOOL pfGenerateOnClose)
{
    PNTSTATUS NtAccessStatusList = (PNTSTATUS)AccessStatusList;
    DWORD i;

    C_ASSERT(sizeof(*AccessStatusList) == sizeof(NTSTATUS));

    /* Written also when the call failed, as Windows does (FALSE then) */
    *pfGenerateOnClose = (BOOL)GenerateOnClose;

    if (!NT_SUCCESS(Status))
    {
        SetLastError(RtlNtStatusToDosError(Status));
        return FALSE;
    }

    /* The kernel has written ObjectTypeListLength entries */
    for (i = 0; i < ObjectTypeListLength; i++)
        AccessStatusList[i] = RtlNtStatusToDosError(NtAccessStatusList[i]);

    return TRUE;
}

/* FUNCTIONS ****************************************************************/

/*
 * @implemented
 */
BOOL WINAPI
AccessCheckAndAuditAlarmA(LPCSTR SubsystemName,
                          LPVOID HandleId,
                          LPSTR ObjectTypeName,
                          LPSTR ObjectName,
                          PSECURITY_DESCRIPTOR SecurityDescriptor,
                          DWORD DesiredAccess,
                          PGENERIC_MAPPING GenericMapping,
                          BOOL ObjectCreation,
                          LPDWORD GrantedAccess,
                          LPBOOL AccessStatus,
                          LPBOOL pfGenerateOnClose)
{
    UNICODE_STRING Names[3];
    BOOL Result;

    if (!AuditAlarmNamesFromAnsi(SubsystemName, ObjectTypeName, ObjectName, Names))
        return FALSE;

    Result = AccessCheckAndAuditAlarmW(Names[0].Buffer,
                                       HandleId,
                                       Names[1].Buffer,
                                       Names[2].Buffer,
                                       SecurityDescriptor,
                                       DesiredAccess,
                                       GenericMapping,
                                       ObjectCreation,
                                       GrantedAccess,
                                       AccessStatus,
                                       pfGenerateOnClose);

    AuditAlarmFreeNames(Names);
    return Result;
}


/*
 * @implemented
 */
BOOL WINAPI
AccessCheckAndAuditAlarmW(LPCWSTR SubsystemName,
                          LPVOID HandleId,
                          LPWSTR ObjectTypeName,
                          LPWSTR ObjectName,
                          PSECURITY_DESCRIPTOR SecurityDescriptor,
                          DWORD DesiredAccess,
                          PGENERIC_MAPPING GenericMapping,
                          BOOL ObjectCreation,
                          LPDWORD GrantedAccess,
                          LPBOOL AccessStatus,
                          LPBOOL pfGenerateOnClose)
{
    UNICODE_STRING SubsystemNameU;
    UNICODE_STRING ObjectTypeNameU;
    UNICODE_STRING ObjectNameU;
    NTSTATUS LocalAccessStatus;
    BOOLEAN GenerateOnClose = FALSE;
    NTSTATUS Status;

    RtlInitUnicodeString(&SubsystemNameU,
                         (PWSTR)SubsystemName);
    RtlInitUnicodeString(&ObjectTypeNameU,
                         (PWSTR)ObjectTypeName);
    RtlInitUnicodeString(&ObjectNameU,
                         (PWSTR)ObjectName);

    Status = NtAccessCheckAndAuditAlarm(&SubsystemNameU,
                                        HandleId,
                                        &ObjectTypeNameU,
                                        &ObjectNameU,
                                        SecurityDescriptor,
                                        DesiredAccess,
                                        GenericMapping,
                                        (BOOLEAN)(ObjectCreation != FALSE),
                                        GrantedAccess,
                                        &LocalAccessStatus,
                                        &GenerateOnClose);

    return AuditAlarmResult(Status,
                            LocalAccessStatus,
                            GenerateOnClose,
                            AccessStatus,
                            pfGenerateOnClose);
}


/*
 * @implemented
 */
BOOL WINAPI
ObjectCloseAuditAlarmA(LPCSTR SubsystemName,
                       LPVOID HandleId,
                       BOOL GenerateOnClose)
{
    UNICODE_STRING Name;
    NTSTATUS Status;

    if (!RtlCreateUnicodeStringFromAsciiz(&Name, SubsystemName))
    {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return FALSE;
    }

    Status = NtCloseObjectAuditAlarm(&Name,
                                     HandleId,
                                     GenerateOnClose);
    RtlFreeUnicodeString(&Name);
    if (!NT_SUCCESS (Status))
    {
        SetLastError(RtlNtStatusToDosError(Status));
        return FALSE;
    }

    return TRUE;
}


/*
 * @implemented
 */
BOOL WINAPI
ObjectCloseAuditAlarmW(LPCWSTR SubsystemName,
                       LPVOID HandleId,
                       BOOL GenerateOnClose)
{
    UNICODE_STRING Name;
    NTSTATUS Status;

    RtlInitUnicodeString(&Name,
                         (PWSTR)SubsystemName);

    Status = NtCloseObjectAuditAlarm(&Name,
                                     HandleId,
                                     GenerateOnClose);
    if (!NT_SUCCESS(Status))
    {
        SetLastError(RtlNtStatusToDosError(Status));
        return FALSE;
    }

    return TRUE;
}


/*
 * @implemented
 */
BOOL WINAPI
ObjectDeleteAuditAlarmA(LPCSTR SubsystemName,
                        LPVOID HandleId,
                        BOOL GenerateOnClose)
{
    UNICODE_STRING Name;
    NTSTATUS Status;

    if (!RtlCreateUnicodeStringFromAsciiz(&Name, SubsystemName))
    {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return FALSE;
    }

    Status = NtDeleteObjectAuditAlarm(&Name,
                                      HandleId,
                                      GenerateOnClose);
    RtlFreeUnicodeString(&Name);
    if (!NT_SUCCESS(Status))
    {
        SetLastError(RtlNtStatusToDosError(Status));
        return FALSE;
    }

    return TRUE;
}


/*
 * @implemented
 */
BOOL WINAPI
ObjectDeleteAuditAlarmW(LPCWSTR SubsystemName,
                        LPVOID HandleId,
                        BOOL GenerateOnClose)
{
    UNICODE_STRING Name;
    NTSTATUS Status;

    RtlInitUnicodeString(&Name,
                         (PWSTR)SubsystemName);

    Status = NtDeleteObjectAuditAlarm(&Name,
                                      HandleId,
                                      GenerateOnClose);
    if (!NT_SUCCESS(Status))
    {
        SetLastError(RtlNtStatusToDosError(Status));
        return FALSE;
    }

    return TRUE;
}


/*
 * @implemented
 */
BOOL WINAPI
ObjectOpenAuditAlarmA(LPCSTR SubsystemName,
                      LPVOID HandleId,
                      LPSTR ObjectTypeName,
                      LPSTR ObjectName,
                      PSECURITY_DESCRIPTOR pSecurityDescriptor,
                      HANDLE ClientToken,
                      DWORD DesiredAccess,
                      DWORD GrantedAccess,
                      PPRIVILEGE_SET Privileges,
                      BOOL ObjectCreation,
                      BOOL AccessGranted,
                      LPBOOL GenerateOnClose)
{
    UNICODE_STRING SubsystemNameU;
    UNICODE_STRING ObjectTypeNameU;
    UNICODE_STRING ObjectNameU;
    NTSTATUS Status;

    RtlCreateUnicodeStringFromAsciiz(&SubsystemNameU,
                                     (PCHAR)SubsystemName);
    RtlCreateUnicodeStringFromAsciiz(&ObjectTypeNameU,
                                     (PCHAR)ObjectTypeName);
    RtlCreateUnicodeStringFromAsciiz(&ObjectNameU,
                                     (PCHAR)ObjectName);

    Status = NtOpenObjectAuditAlarm(&SubsystemNameU,
                                    HandleId,
                                    &ObjectTypeNameU,
                                    &ObjectNameU,
                                    pSecurityDescriptor,
                                    ClientToken,
                                    DesiredAccess,
                                    GrantedAccess,
                                    Privileges,
                                    ObjectCreation,
                                    AccessGranted,
                                    (PBOOLEAN)GenerateOnClose);
    RtlFreeUnicodeString(&SubsystemNameU);
    RtlFreeUnicodeString(&ObjectTypeNameU);
    RtlFreeUnicodeString(&ObjectNameU);
    if (!NT_SUCCESS(Status))
    {
        SetLastError(RtlNtStatusToDosError(Status));
        return FALSE;
    }

    return TRUE;
}


/*
 * @implemented
 */
BOOL WINAPI
ObjectOpenAuditAlarmW(LPCWSTR SubsystemName,
                      LPVOID HandleId,
                      LPWSTR ObjectTypeName,
                      LPWSTR ObjectName,
                      PSECURITY_DESCRIPTOR pSecurityDescriptor,
                      HANDLE ClientToken,
                      DWORD DesiredAccess,
                      DWORD GrantedAccess,
                      PPRIVILEGE_SET Privileges,
                      BOOL ObjectCreation,
                      BOOL AccessGranted,
                      LPBOOL GenerateOnClose)
{
    UNICODE_STRING SubsystemNameU;
    UNICODE_STRING ObjectTypeNameU;
    UNICODE_STRING ObjectNameU;
    NTSTATUS Status;

    RtlInitUnicodeString(&SubsystemNameU,
                         (PWSTR)SubsystemName);
    RtlInitUnicodeString(&ObjectTypeNameU,
                         (PWSTR)ObjectTypeName);
    RtlInitUnicodeString(&ObjectNameU,
                         (PWSTR)ObjectName);

    Status = NtOpenObjectAuditAlarm(&SubsystemNameU,
                                    HandleId,
                                    &ObjectTypeNameU,
                                    &ObjectNameU,
                                    pSecurityDescriptor,
                                    ClientToken,
                                    DesiredAccess,
                                    GrantedAccess,
                                    Privileges,
                                    ObjectCreation,
                                    AccessGranted,
                                    (PBOOLEAN)GenerateOnClose);
    if (!NT_SUCCESS(Status))
    {
        SetLastError(RtlNtStatusToDosError(Status));
        return FALSE;
    }

    return TRUE;
}


/*
 * @implemented
 */
BOOL WINAPI
ObjectPrivilegeAuditAlarmA(LPCSTR SubsystemName,
                           LPVOID HandleId,
                           HANDLE ClientToken,
                           DWORD DesiredAccess,
                           PPRIVILEGE_SET Privileges,
                           BOOL AccessGranted)
{
    UNICODE_STRING SubsystemNameU;
    NTSTATUS Status;

    RtlCreateUnicodeStringFromAsciiz(&SubsystemNameU,
                                     (PCHAR)SubsystemName);

    Status = NtPrivilegeObjectAuditAlarm(&SubsystemNameU,
                                         HandleId,
                                         ClientToken,
                                         DesiredAccess,
                                         Privileges,
                                         AccessGranted);
    RtlFreeUnicodeString (&SubsystemNameU);
    if (!NT_SUCCESS(Status))
    {
        SetLastError(RtlNtStatusToDosError(Status));
        return FALSE;
    }

    return TRUE;
}


/*
 * @implemented
 */
BOOL WINAPI
ObjectPrivilegeAuditAlarmW(LPCWSTR SubsystemName,
                           LPVOID HandleId,
                           HANDLE ClientToken,
                           DWORD DesiredAccess,
                           PPRIVILEGE_SET Privileges,
                           BOOL AccessGranted)
{
    UNICODE_STRING SubsystemNameU;
    NTSTATUS Status;

    RtlInitUnicodeString(&SubsystemNameU,
                         (PWSTR)SubsystemName);

    Status = NtPrivilegeObjectAuditAlarm(&SubsystemNameU,
                                         HandleId,
                                         ClientToken,
                                         DesiredAccess,
                                         Privileges,
                                         AccessGranted);
    if (!NT_SUCCESS(Status))
    {
        SetLastError(RtlNtStatusToDosError(Status));
        return FALSE;
    }

    return TRUE;
}


/*
 * @implemented
 */
BOOL WINAPI
PrivilegedServiceAuditAlarmA(LPCSTR SubsystemName,
                             LPCSTR ServiceName,
                             HANDLE ClientToken,
                             PPRIVILEGE_SET Privileges,
                             BOOL AccessGranted)
{
    UNICODE_STRING SubsystemNameU;
    UNICODE_STRING ServiceNameU;
    NTSTATUS Status;

    RtlCreateUnicodeStringFromAsciiz(&SubsystemNameU,
                                     (PCHAR)SubsystemName);
    RtlCreateUnicodeStringFromAsciiz(&ServiceNameU,
                                     (PCHAR)ServiceName);

    Status = NtPrivilegedServiceAuditAlarm(&SubsystemNameU,
                                           &ServiceNameU,
                                           ClientToken,
                                           Privileges,
                                           AccessGranted);
    RtlFreeUnicodeString(&SubsystemNameU);
    RtlFreeUnicodeString(&ServiceNameU);
    if (!NT_SUCCESS(Status))
    {
        SetLastError(RtlNtStatusToDosError(Status));
        return FALSE;
    }

    return TRUE;
}


/*
 * @implemented
 */
BOOL WINAPI
PrivilegedServiceAuditAlarmW(LPCWSTR SubsystemName,
                             LPCWSTR ServiceName,
                             HANDLE ClientToken,
                             PPRIVILEGE_SET Privileges,
                             BOOL AccessGranted)
{
    UNICODE_STRING SubsystemNameU;
    UNICODE_STRING ServiceNameU;
    NTSTATUS Status;

    RtlInitUnicodeString(&SubsystemNameU,
                         (PWSTR)SubsystemName);
    RtlInitUnicodeString(&ServiceNameU,
                         (PWSTR)ServiceName);

    Status = NtPrivilegedServiceAuditAlarm(&SubsystemNameU,
                                           &ServiceNameU,
                                           ClientToken,
                                           Privileges,
                                           AccessGranted);
    if (!NT_SUCCESS(Status))
    {
        SetLastError(RtlNtStatusToDosError(Status));
        return FALSE;
    }

    return TRUE;
}


/*
 * @implemented
 */
BOOL WINAPI
AccessCheckByTypeResultListAndAuditAlarmByHandleW(IN LPCWSTR SubsystemName,
                                                  IN LPVOID HandleId,
                                                  IN HANDLE ClientToken,
                                                  IN LPCWSTR ObjectTypeName,
                                                  IN LPCWSTR ObjectName,
                                                  IN PSECURITY_DESCRIPTOR pSecurityDescriptor,
                                                  IN PSID PrincipalSelfSid,
                                                  IN DWORD DesiredAccess,
                                                  IN AUDIT_EVENT_TYPE AuditType,
                                                  IN DWORD Flags,
                                                  IN POBJECT_TYPE_LIST ObjectTypeList,
                                                  IN DWORD ObjectTypeListLength,
                                                  IN PGENERIC_MAPPING GenericMapping,
                                                  IN BOOL ObjectCreation,
                                                  OUT LPDWORD GrantedAccess,
                                                  OUT LPDWORD AccessStatusList,
                                                  OUT LPBOOL pfGenerateOnClose)
{
    UNICODE_STRING SubsystemNameU, ObjectTypeNameU, ObjectNameU;
    BOOLEAN GenerateOnClose = FALSE;
    NTSTATUS Status;

    RtlInitUnicodeString(&SubsystemNameU, SubsystemName);
    RtlInitUnicodeString(&ObjectTypeNameU, ObjectTypeName);
    RtlInitUnicodeString(&ObjectNameU, ObjectName);

    Status = NtAccessCheckByTypeResultListAndAuditAlarmByHandle(&SubsystemNameU,
                                                                HandleId,
                                                                ClientToken,
                                                                &ObjectTypeNameU,
                                                                &ObjectNameU,
                                                                pSecurityDescriptor,
                                                                PrincipalSelfSid,
                                                                DesiredAccess,
                                                                AuditType,
                                                                Flags,
                                                                ObjectTypeList,
                                                                ObjectTypeListLength,
                                                                GenericMapping,
                                                                (BOOLEAN)(ObjectCreation != FALSE),
                                                                GrantedAccess,
                                                                (PNTSTATUS)AccessStatusList,
                                                                &GenerateOnClose);

    return AuditAlarmResultList(Status,
                                ObjectTypeListLength,
                                GenerateOnClose,
                                AccessStatusList,
                                pfGenerateOnClose);
}


/*
 * @implemented
 */
BOOL WINAPI
AccessCheckByTypeResultListAndAuditAlarmByHandleA(IN LPCSTR SubsystemName,
                                                  IN LPVOID HandleId,
                                                  IN HANDLE ClientToken,
                                                  IN LPCSTR ObjectTypeName,
                                                  IN LPCSTR ObjectName,
                                                  IN PSECURITY_DESCRIPTOR pSecurityDescriptor,
                                                  IN PSID PrincipalSelfSid,
                                                  IN DWORD DesiredAccess,
                                                  IN AUDIT_EVENT_TYPE AuditType,
                                                  IN DWORD Flags,
                                                  IN POBJECT_TYPE_LIST ObjectTypeList,
                                                  IN DWORD ObjectTypeListLength,
                                                  IN PGENERIC_MAPPING GenericMapping,
                                                  IN BOOL ObjectCreation,
                                                  OUT LPDWORD GrantedAccess,
                                                  OUT LPDWORD AccessStatusList,
                                                  OUT LPBOOL pfGenerateOnClose)
{
    UNICODE_STRING Names[3];
    BOOL Result;

    if (!AuditAlarmNamesFromAnsi(SubsystemName, ObjectTypeName, ObjectName, Names))
        return FALSE;

    Result = AccessCheckByTypeResultListAndAuditAlarmByHandleW(Names[0].Buffer,
                                                               HandleId,
                                                               ClientToken,
                                                               Names[1].Buffer,
                                                               Names[2].Buffer,
                                                               pSecurityDescriptor,
                                                               PrincipalSelfSid,
                                                               DesiredAccess,
                                                               AuditType,
                                                               Flags,
                                                               ObjectTypeList,
                                                               ObjectTypeListLength,
                                                               GenericMapping,
                                                               ObjectCreation,
                                                               GrantedAccess,
                                                               AccessStatusList,
                                                               pfGenerateOnClose);

    AuditAlarmFreeNames(Names);
    return Result;
}


/*
 * @implemented
 */
BOOL WINAPI
AccessCheckByTypeResultListAndAuditAlarmW(IN LPCWSTR SubsystemName,
                                          IN LPVOID HandleId,
                                          IN LPCWSTR ObjectTypeName,
                                          IN LPCWSTR ObjectName,
                                          IN PSECURITY_DESCRIPTOR pSecurityDescriptor,
                                          IN PSID PrincipalSelfSid,
                                          IN DWORD DesiredAccess,
                                          IN AUDIT_EVENT_TYPE AuditType,
                                          IN DWORD Flags,
                                          IN POBJECT_TYPE_LIST ObjectTypeList,
                                          IN DWORD ObjectTypeListLength,
                                          IN PGENERIC_MAPPING GenericMapping,
                                          IN BOOL ObjectCreation,
                                          OUT LPDWORD GrantedAccess,
                                          OUT LPDWORD AccessStatusList,
                                          OUT LPBOOL pfGenerateOnClose)
{
    UNICODE_STRING SubsystemNameU, ObjectTypeNameU, ObjectNameU;
    BOOLEAN GenerateOnClose = FALSE;
    NTSTATUS Status;

    RtlInitUnicodeString(&SubsystemNameU, SubsystemName);
    RtlInitUnicodeString(&ObjectTypeNameU, ObjectTypeName);
    RtlInitUnicodeString(&ObjectNameU, ObjectName);

    Status = NtAccessCheckByTypeResultListAndAuditAlarm(&SubsystemNameU,
                                                        HandleId,
                                                        &ObjectTypeNameU,
                                                        &ObjectNameU,
                                                        pSecurityDescriptor,
                                                        PrincipalSelfSid,
                                                        DesiredAccess,
                                                        AuditType,
                                                        Flags,
                                                        ObjectTypeList,
                                                        ObjectTypeListLength,
                                                        GenericMapping,
                                                        (BOOLEAN)(ObjectCreation != FALSE),
                                                        GrantedAccess,
                                                        (PNTSTATUS)AccessStatusList,
                                                        &GenerateOnClose);

    return AuditAlarmResultList(Status,
                                ObjectTypeListLength,
                                GenerateOnClose,
                                AccessStatusList,
                                pfGenerateOnClose);
}


/*
 * @implemented
 */
BOOL WINAPI
AccessCheckByTypeResultListAndAuditAlarmA(IN LPCSTR SubsystemName,
                                          IN LPVOID HandleId,
                                          IN LPCSTR ObjectTypeName,
                                          IN LPCSTR ObjectName,
                                          IN PSECURITY_DESCRIPTOR pSecurityDescriptor,
                                          IN PSID PrincipalSelfSid,
                                          IN DWORD DesiredAccess,
                                          IN AUDIT_EVENT_TYPE AuditType,
                                          IN DWORD Flags,
                                          IN POBJECT_TYPE_LIST ObjectTypeList,
                                          IN DWORD ObjectTypeListLength,
                                          IN PGENERIC_MAPPING GenericMapping,
                                          IN BOOL ObjectCreation,
                                          OUT LPDWORD GrantedAccess,
                                          OUT LPDWORD AccessStatusList,
                                          OUT LPBOOL pfGenerateOnClose)
{
    UNICODE_STRING Names[3];
    BOOL Result;

    if (!AuditAlarmNamesFromAnsi(SubsystemName, ObjectTypeName, ObjectName, Names))
        return FALSE;

    Result = AccessCheckByTypeResultListAndAuditAlarmW(Names[0].Buffer,
                                                       HandleId,
                                                       Names[1].Buffer,
                                                       Names[2].Buffer,
                                                       pSecurityDescriptor,
                                                       PrincipalSelfSid,
                                                       DesiredAccess,
                                                       AuditType,
                                                       Flags,
                                                       ObjectTypeList,
                                                       ObjectTypeListLength,
                                                       GenericMapping,
                                                       ObjectCreation,
                                                       GrantedAccess,
                                                       AccessStatusList,
                                                       pfGenerateOnClose);

    AuditAlarmFreeNames(Names);
    return Result;
}


/*
 * @implemented
 */
BOOL WINAPI
AccessCheckByTypeAndAuditAlarmW(IN LPCWSTR SubsystemName,
                                IN LPVOID HandleId,
                                IN LPCWSTR ObjectTypeName,
                                IN LPCWSTR ObjectName,
                                IN PSECURITY_DESCRIPTOR pSecurityDescriptor,
                                IN PSID PrincipalSelfSid,
                                IN DWORD DesiredAccess,
                                IN AUDIT_EVENT_TYPE AuditType,
                                IN DWORD Flags,
                                IN POBJECT_TYPE_LIST ObjectTypeList,
                                IN DWORD ObjectTypeListLength,
                                IN PGENERIC_MAPPING GenericMapping,
                                IN BOOL ObjectCreation,
                                OUT LPDWORD GrantedAccess,
                                OUT LPBOOL AccessStatus,
                                OUT LPBOOL pfGenerateOnClose)
{
    UNICODE_STRING SubsystemNameU, ObjectTypeNameU, ObjectNameU;
    NTSTATUS LocalAccessStatus;
    BOOLEAN GenerateOnClose = FALSE;
    NTSTATUS Status;

    RtlInitUnicodeString(&SubsystemNameU, SubsystemName);
    RtlInitUnicodeString(&ObjectTypeNameU, ObjectTypeName);
    RtlInitUnicodeString(&ObjectNameU, ObjectName);

    Status = NtAccessCheckByTypeAndAuditAlarm(&SubsystemNameU,
                                              HandleId,
                                              &ObjectTypeNameU,
                                              &ObjectNameU,
                                              pSecurityDescriptor,
                                              PrincipalSelfSid,
                                              DesiredAccess,
                                              AuditType,
                                              Flags,
                                              ObjectTypeList,
                                              ObjectTypeListLength,
                                              GenericMapping,
                                              (BOOLEAN)(ObjectCreation != FALSE),
                                              GrantedAccess,
                                              &LocalAccessStatus,
                                              &GenerateOnClose);

    return AuditAlarmResult(Status,
                            LocalAccessStatus,
                            GenerateOnClose,
                            AccessStatus,
                            pfGenerateOnClose);
}


/*
 * @implemented
 */
BOOL WINAPI
AccessCheckByTypeAndAuditAlarmA(IN LPCSTR SubsystemName,
                                IN LPVOID HandleId,
                                IN LPCSTR ObjectTypeName,
                                IN LPCSTR ObjectName,
                                IN PSECURITY_DESCRIPTOR pSecurityDescriptor,
                                IN PSID PrincipalSelfSid,
                                IN DWORD DesiredAccess,
                                IN AUDIT_EVENT_TYPE AuditType,
                                IN DWORD Flags,
                                IN POBJECT_TYPE_LIST ObjectTypeList,
                                IN DWORD ObjectTypeListLength,
                                IN PGENERIC_MAPPING GenericMapping,
                                IN BOOL ObjectCreation,
                                OUT LPDWORD GrantedAccess,
                                OUT LPBOOL AccessStatus,
                                OUT LPBOOL pfGenerateOnClose)
{
    UNICODE_STRING Names[3];
    BOOL Result;

    if (!AuditAlarmNamesFromAnsi(SubsystemName, ObjectTypeName, ObjectName, Names))
        return FALSE;

    Result = AccessCheckByTypeAndAuditAlarmW(Names[0].Buffer,
                                             HandleId,
                                             Names[1].Buffer,
                                             Names[2].Buffer,
                                             pSecurityDescriptor,
                                             PrincipalSelfSid,
                                             DesiredAccess,
                                             AuditType,
                                             Flags,
                                             ObjectTypeList,
                                             ObjectTypeListLength,
                                             GenericMapping,
                                             ObjectCreation,
                                             GrantedAccess,
                                             AccessStatus,
                                             pfGenerateOnClose);

    AuditAlarmFreeNames(Names);
    return Result;
}

/* EOF */
