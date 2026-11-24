/*
 * PROJECT:         ReactOS kernel-mode tests
 * LICENSE:         LGPLv2+ - See COPYING.LIB in the top level directory
 * PURPOSE:         Kernel-Mode Test Suite NPFS security test
 * PROGRAMMER:      Thomas Faber <thomas.faber@reactos.org>
 */

#include <kmt_test.h>
#include "../ntos_se/se.h"

/* The owner the keys are expected to have; NULL is the Administrators alias (Windows 8: all keys).
 * Windows 10 gives the master keys of the namespace SYSTEM. */
static PSID ExpectedKeyOwner;

#define CheckKeySecurity(name, AceCount, ...) CheckKeySecurity_(name, AceCount, __FILE__, __LINE__, ##__VA_ARGS__)
#define CheckKeySecurity_(name, AceCount, file, line, ...) CheckKeySecurity__(name, AceCount, file ":" KMT_STRINGIZE(line), ##__VA_ARGS__)
static
VOID
CheckKeySecurity__(
    _In_ PCWSTR KeyName,
    _In_ ULONG AceCount,
    _In_ PCSTR FileAndLine,
    ...)
{
    NTSTATUS Status;
    UNICODE_STRING KeyNameString;
    OBJECT_ATTRIBUTES ObjectAttributes;
    HANDLE KeyHandle;
    PSECURITY_DESCRIPTOR SecurityDescriptor;
    ULONG SecurityDescriptorSize;
    PSID Owner;
    PSID Group;
    PACL Dacl;
    PACL Sacl;
    BOOLEAN Present;
    BOOLEAN Defaulted;
    va_list Arguments;

    RtlInitUnicodeString(&KeyNameString, KeyName);
    InitializeObjectAttributes(&ObjectAttributes,
                               &KeyNameString,
                               OBJ_KERNEL_HANDLE,
                               NULL,
                               NULL);
    Status = ZwOpenKey(&KeyHandle,
                       READ_CONTROL | ACCESS_SYSTEM_SECURITY,
                       &ObjectAttributes);
    ok_eq_hex(Status, STATUS_SUCCESS);
    if (skip(NT_SUCCESS(Status), "No key (%ls)\n", KeyName))
    {
        return;
    }

    Status = ZwQuerySecurityObject(KeyHandle,
                                   OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | SACL_SECURITY_INFORMATION,
                                   NULL,
                                   0,
                                   &SecurityDescriptorSize);
    ok_eq_hex(Status, STATUS_BUFFER_TOO_SMALL);
    if (skip(Status == STATUS_BUFFER_TOO_SMALL, "No security size (%ls)\n", KeyName))
    {
        ObCloseHandle(KeyHandle, KernelMode);
        return;
    }

    SecurityDescriptor = ExAllocatePoolWithTag(PagedPool,
                                               SecurityDescriptorSize,
                                               'dSmK');
    ok(SecurityDescriptor != NULL, "Failed to allocate %lu bytes\n", SecurityDescriptorSize);
    if (skip(SecurityDescriptor != NULL, "No memory for descriptor (%ls)\n", KeyName))
    {
        ObCloseHandle(KeyHandle, KernelMode);
        return;
    }

    Status = ZwQuerySecurityObject(KeyHandle,
                                   OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | SACL_SECURITY_INFORMATION,
                                   SecurityDescriptor,
                                   SecurityDescriptorSize,
                                   &SecurityDescriptorSize);
    ok_eq_hex(Status, STATUS_SUCCESS);
    if (NT_SUCCESS(Status))
    {
        Owner = NULL;
        Status = RtlGetOwnerSecurityDescriptor(SecurityDescriptor,
                                               &Owner,
                                               &Defaulted);
        CheckSid(Owner, NO_SIZE, ExpectedKeyOwner ? ExpectedKeyOwner : SeExports->SeAliasAdminsSid);
        ok(Defaulted == FALSE, "Owner defaulted for %ls\n", KeyName);

        Group = NULL;
        Status = RtlGetGroupSecurityDescriptor(SecurityDescriptor,
                                               &Group,
                                               &Defaulted);
        CheckSid(Group, NO_SIZE, SeExports->SeLocalSystemSid);
        ok(Defaulted == FALSE, "Group defaulted for %ls\n", KeyName);

        Dacl = NULL;
        Status = RtlGetDaclSecurityDescriptor(SecurityDescriptor,
                                              &Present,
                                              &Dacl,
                                              &Defaulted);
        ok_eq_hex(Status, STATUS_SUCCESS);
        ok(Present == TRUE, "DACL not present for %ls\n", KeyName);
        ok(Defaulted == FALSE, "DACL defaulted for %ls\n", KeyName);
        va_start(Arguments, FileAndLine);
        VCheckAcl__(Dacl, AceCount, FileAndLine, Arguments);
        va_end(Arguments);

        /* Windows 8+ has SACLs for:
         * \REGISTRY\MACHINE\SAM
         * \REGISTRY\MACHINE\SECURITY
         * \REGISTRY\MACHINE\SOFTWARE
         * \REGISTRY\MACHINE\SYSTEM
         * \REGISTRY\USER\.DEFAULT
         * \REGISTRY\USER\S-1-5-18
         * \REGISTRY\USER\S-1-5-20
         *
         * TODO: Investigate these SACLs and test accordingly.
         */
        if (GetNTVersion() < _WIN32_WINNT_WIN8)
        {
            Sacl = NULL;
            Status = RtlGetSaclSecurityDescriptor(SecurityDescriptor,
                                                &Present,
                                                &Sacl,
                                                &Defaulted);
            ok_eq_hex(Status, STATUS_SUCCESS);
            ok(Present == FALSE, "SACL present for %ls\n", KeyName);
            ok(Defaulted == FALSE, "SACL defaulted for %ls\n", KeyName);
            ok(Sacl == NULL, "Sacl is %p for %ls\n", Sacl, KeyName);
        }
    }
    ExFreePoolWithTag(SecurityDescriptor, 'dSmK');
    ObCloseHandle(KeyHandle, KernelMode);
}

static void CmSecurity_WS03(PSID TerminalServerSid)
{
    CheckKeySecurity(L"\\REGISTRY",
                     4, ACCESS_ALLOWED_ACE_TYPE, CONTAINER_INHERIT_ACE, SeExports->SeLocalSystemSid, KEY_ALL_ACCESS,
                        ACCESS_ALLOWED_ACE_TYPE, CONTAINER_INHERIT_ACE, SeExports->SeAliasAdminsSid, KEY_ALL_ACCESS,
                        ACCESS_ALLOWED_ACE_TYPE, CONTAINER_INHERIT_ACE, SeExports->SeWorldSid,       KEY_READ,
                        ACCESS_ALLOWED_ACE_TYPE, CONTAINER_INHERIT_ACE, SeExports->SeRestrictedSid,  KEY_READ);

    CheckKeySecurity(L"\\REGISTRY\\MACHINE",
                     4, ACCESS_ALLOWED_ACE_TYPE, CONTAINER_INHERIT_ACE, SeExports->SeLocalSystemSid, KEY_ALL_ACCESS,
                        ACCESS_ALLOWED_ACE_TYPE, CONTAINER_INHERIT_ACE, SeExports->SeAliasAdminsSid, KEY_ALL_ACCESS,
                        ACCESS_ALLOWED_ACE_TYPE, CONTAINER_INHERIT_ACE, SeExports->SeWorldSid,       KEY_READ,
                        ACCESS_ALLOWED_ACE_TYPE, CONTAINER_INHERIT_ACE, SeExports->SeRestrictedSid,  KEY_READ);

    CheckKeySecurity(L"\\REGISTRY\\MACHINE\\HARDWARE",
                     4, ACCESS_ALLOWED_ACE_TYPE, CONTAINER_INHERIT_ACE, SeExports->SeLocalSystemSid, KEY_ALL_ACCESS,
                        ACCESS_ALLOWED_ACE_TYPE, CONTAINER_INHERIT_ACE, SeExports->SeAliasAdminsSid, KEY_ALL_ACCESS,
                        ACCESS_ALLOWED_ACE_TYPE, CONTAINER_INHERIT_ACE, SeExports->SeWorldSid,       KEY_READ,
                        ACCESS_ALLOWED_ACE_TYPE, CONTAINER_INHERIT_ACE, SeExports->SeRestrictedSid,  KEY_READ);

    CheckKeySecurity(L"\\REGISTRY\\MACHINE\\SAM",
                     4, ACCESS_ALLOWED_ACE_TYPE, CONTAINER_INHERIT_ACE, SeExports->SeLocalSystemSid, KEY_ALL_ACCESS,
                        ACCESS_ALLOWED_ACE_TYPE, CONTAINER_INHERIT_ACE, SeExports->SeAliasAdminsSid, KEY_ALL_ACCESS,
                        ACCESS_ALLOWED_ACE_TYPE, CONTAINER_INHERIT_ACE, SeExports->SeWorldSid,       KEY_READ,
                        ACCESS_ALLOWED_ACE_TYPE, CONTAINER_INHERIT_ACE, SeExports->SeRestrictedSid,  KEY_READ);

    CheckKeySecurity(L"\\REGISTRY\\MACHINE\\SECURITY",
                     2, ACCESS_ALLOWED_ACE_TYPE, CONTAINER_INHERIT_ACE, SeExports->SeLocalSystemSid, KEY_ALL_ACCESS,
                        ACCESS_ALLOWED_ACE_TYPE, CONTAINER_INHERIT_ACE, SeExports->SeAliasAdminsSid, WRITE_DAC | READ_CONTROL);

    CheckKeySecurity(L"\\REGISTRY\\MACHINE\\SOFTWARE",
                    12, ACCESS_ALLOWED_ACE_TYPE,                     0, SeExports->SeAliasUsersSid,      KEY_READ,
                        ACCESS_ALLOWED_ACE_TYPE, INHERIT_ONLY_ACE |
                                                 CONTAINER_INHERIT_ACE, SeExports->SeAliasUsersSid,      GENERIC_READ,
                        ACCESS_ALLOWED_ACE_TYPE,                     0, SeExports->SeAliasPowerUsersSid, KEY_READ | KEY_WRITE | DELETE,
                        ACCESS_ALLOWED_ACE_TYPE, INHERIT_ONLY_ACE |
                                                 CONTAINER_INHERIT_ACE, SeExports->SeAliasPowerUsersSid, GENERIC_READ | GENERIC_WRITE | DELETE,
                        ACCESS_ALLOWED_ACE_TYPE,                     0, SeExports->SeAliasAdminsSid,     KEY_ALL_ACCESS,
                        ACCESS_ALLOWED_ACE_TYPE, INHERIT_ONLY_ACE |
                                                 CONTAINER_INHERIT_ACE, SeExports->SeAliasAdminsSid,     GENERIC_ALL,
                        ACCESS_ALLOWED_ACE_TYPE,                     0, SeExports->SeLocalSystemSid,     KEY_ALL_ACCESS,
                        ACCESS_ALLOWED_ACE_TYPE, INHERIT_ONLY_ACE |
                                                 CONTAINER_INHERIT_ACE, SeExports->SeLocalSystemSid,     GENERIC_ALL,
                        ACCESS_ALLOWED_ACE_TYPE,                     0, SeExports->SeAliasAdminsSid,     KEY_ALL_ACCESS,
                        ACCESS_ALLOWED_ACE_TYPE, INHERIT_ONLY_ACE |
                                                 CONTAINER_INHERIT_ACE, SeExports->SeCreatorOwnerSid,    GENERIC_ALL,
                        ACCESS_ALLOWED_ACE_TYPE,                     0, TerminalServerSid,               KEY_READ | KEY_WRITE | DELETE,
                        ACCESS_ALLOWED_ACE_TYPE, INHERIT_ONLY_ACE |
                                                 CONTAINER_INHERIT_ACE, TerminalServerSid,               GENERIC_READ | GENERIC_WRITE | DELETE);

    CheckKeySecurity(L"\\REGISTRY\\MACHINE\\SYSTEM",
                    10, ACCESS_ALLOWED_ACE_TYPE,                     0, SeExports->SeAliasUsersSid,      KEY_READ,
                        ACCESS_ALLOWED_ACE_TYPE, INHERIT_ONLY_ACE |
                                                 CONTAINER_INHERIT_ACE, SeExports->SeAliasUsersSid,      GENERIC_READ,
                        ACCESS_ALLOWED_ACE_TYPE,                     0, SeExports->SeAliasPowerUsersSid, KEY_READ,
                        ACCESS_ALLOWED_ACE_TYPE, INHERIT_ONLY_ACE |
                                                 CONTAINER_INHERIT_ACE, SeExports->SeAliasPowerUsersSid, GENERIC_READ,
                        ACCESS_ALLOWED_ACE_TYPE,                     0, SeExports->SeAliasAdminsSid,     KEY_ALL_ACCESS,
                        ACCESS_ALLOWED_ACE_TYPE, INHERIT_ONLY_ACE |
                                                 CONTAINER_INHERIT_ACE, SeExports->SeAliasAdminsSid,     GENERIC_ALL,
                        ACCESS_ALLOWED_ACE_TYPE,                     0, SeExports->SeLocalSystemSid,     KEY_ALL_ACCESS,
                        ACCESS_ALLOWED_ACE_TYPE, INHERIT_ONLY_ACE |
                                                 CONTAINER_INHERIT_ACE, SeExports->SeLocalSystemSid,     GENERIC_ALL,
                        ACCESS_ALLOWED_ACE_TYPE,                     0, SeExports->SeAliasAdminsSid,     KEY_ALL_ACCESS,
                        ACCESS_ALLOWED_ACE_TYPE, INHERIT_ONLY_ACE |
                                                 CONTAINER_INHERIT_ACE, SeExports->SeCreatorOwnerSid,    GENERIC_ALL);

    CheckKeySecurity(L"\\REGISTRY\\USER",
                     4, ACCESS_ALLOWED_ACE_TYPE, CONTAINER_INHERIT_ACE, SeExports->SeLocalSystemSid, KEY_ALL_ACCESS,
                        ACCESS_ALLOWED_ACE_TYPE, CONTAINER_INHERIT_ACE, SeExports->SeAliasAdminsSid, KEY_ALL_ACCESS,
                        ACCESS_ALLOWED_ACE_TYPE, CONTAINER_INHERIT_ACE, SeExports->SeWorldSid,       KEY_READ,
                        ACCESS_ALLOWED_ACE_TYPE, CONTAINER_INHERIT_ACE, SeExports->SeRestrictedSid,  KEY_READ);

    CheckKeySecurity(L"\\REGISTRY\\USER\\.DEFAULT",
                    10, ACCESS_ALLOWED_ACE_TYPE,                     0, SeExports->SeAliasUsersSid,      KEY_READ,
                        ACCESS_ALLOWED_ACE_TYPE, INHERIT_ONLY_ACE |
                                                 CONTAINER_INHERIT_ACE, SeExports->SeAliasUsersSid,      GENERIC_READ,
                        ACCESS_ALLOWED_ACE_TYPE,                     0, SeExports->SeAliasPowerUsersSid, KEY_READ,
                        ACCESS_ALLOWED_ACE_TYPE, INHERIT_ONLY_ACE |
                                                 CONTAINER_INHERIT_ACE, SeExports->SeAliasPowerUsersSid, GENERIC_READ,
                        ACCESS_ALLOWED_ACE_TYPE,                     0, SeExports->SeAliasAdminsSid,     KEY_ALL_ACCESS,
                        ACCESS_ALLOWED_ACE_TYPE, INHERIT_ONLY_ACE |
                                                 CONTAINER_INHERIT_ACE, SeExports->SeAliasAdminsSid,     GENERIC_ALL,
                        ACCESS_ALLOWED_ACE_TYPE,                     0, SeExports->SeLocalSystemSid,     KEY_ALL_ACCESS,
                        ACCESS_ALLOWED_ACE_TYPE, INHERIT_ONLY_ACE |
                                                 CONTAINER_INHERIT_ACE, SeExports->SeLocalSystemSid,     GENERIC_ALL,
                        ACCESS_ALLOWED_ACE_TYPE,                     0, SeExports->SeAliasAdminsSid,     KEY_ALL_ACCESS,
                        ACCESS_ALLOWED_ACE_TYPE, INHERIT_ONLY_ACE |
                                                 CONTAINER_INHERIT_ACE, SeExports->SeCreatorOwnerSid,    GENERIC_ALL);

    CheckKeySecurity(L"\\REGISTRY\\USER\\S-1-5-18",
                    10, ACCESS_ALLOWED_ACE_TYPE,                     0, SeExports->SeAliasUsersSid,      KEY_READ,
                        ACCESS_ALLOWED_ACE_TYPE, INHERIT_ONLY_ACE |
                                                 CONTAINER_INHERIT_ACE, SeExports->SeAliasUsersSid,      GENERIC_READ,
                        ACCESS_ALLOWED_ACE_TYPE,                     0, SeExports->SeAliasPowerUsersSid, KEY_READ,
                        ACCESS_ALLOWED_ACE_TYPE, INHERIT_ONLY_ACE |
                                                 CONTAINER_INHERIT_ACE, SeExports->SeAliasPowerUsersSid, GENERIC_READ,
                        ACCESS_ALLOWED_ACE_TYPE,                     0, SeExports->SeAliasAdminsSid,     KEY_ALL_ACCESS,
                        ACCESS_ALLOWED_ACE_TYPE, INHERIT_ONLY_ACE |
                                                 CONTAINER_INHERIT_ACE, SeExports->SeAliasAdminsSid,     GENERIC_ALL,
                        ACCESS_ALLOWED_ACE_TYPE,                     0, SeExports->SeLocalSystemSid,     KEY_ALL_ACCESS,
                        ACCESS_ALLOWED_ACE_TYPE, INHERIT_ONLY_ACE |
                                                 CONTAINER_INHERIT_ACE, SeExports->SeLocalSystemSid,     GENERIC_ALL,
                        ACCESS_ALLOWED_ACE_TYPE,                     0, SeExports->SeAliasAdminsSid,     KEY_ALL_ACCESS,
                        ACCESS_ALLOWED_ACE_TYPE, INHERIT_ONLY_ACE |
                                                 CONTAINER_INHERIT_ACE, SeExports->SeCreatorOwnerSid,    GENERIC_ALL);

    CheckKeySecurity(L"\\REGISTRY\\USER\\S-1-5-20",
                     8, ACCESS_ALLOWED_ACE_TYPE,                     0, SeExports->SeNetworkServiceSid,  KEY_ALL_ACCESS,
                        ACCESS_ALLOWED_ACE_TYPE,                     0, SeExports->SeLocalSystemSid,     KEY_ALL_ACCESS,
                        ACCESS_ALLOWED_ACE_TYPE,                     0, SeExports->SeAliasAdminsSid,     KEY_ALL_ACCESS,
                        ACCESS_ALLOWED_ACE_TYPE,                     0, SeExports->SeRestrictedSid,      KEY_READ,
                        ACCESS_ALLOWED_ACE_TYPE, INHERIT_ONLY_ACE |
                                                 CONTAINER_INHERIT_ACE |
                                                 OBJECT_INHERIT_ACE,    SeExports->SeNetworkServiceSid,  GENERIC_ALL,
                        ACCESS_ALLOWED_ACE_TYPE, INHERIT_ONLY_ACE |
                                                 CONTAINER_INHERIT_ACE |
                                                 OBJECT_INHERIT_ACE,    SeExports->SeLocalSystemSid,     GENERIC_ALL,
                        ACCESS_ALLOWED_ACE_TYPE, INHERIT_ONLY_ACE |
                                                 CONTAINER_INHERIT_ACE |
                                                 OBJECT_INHERIT_ACE,    SeExports->SeAliasAdminsSid,     GENERIC_ALL,
                        ACCESS_ALLOWED_ACE_TYPE, INHERIT_ONLY_ACE |
                                                 CONTAINER_INHERIT_ACE |
                                                 OBJECT_INHERIT_ACE,    SeExports->SeRestrictedSid,      GENERIC_READ);
}

static void CmSecurity_Vista(PSID TerminalServerSid)
{
    CheckKeySecurity(L"\\REGISTRY",
                     4, ACCESS_ALLOWED_ACE_TYPE, CONTAINER_INHERIT_ACE, SeExports->SeLocalSystemSid, KEY_ALL_ACCESS,
                        ACCESS_ALLOWED_ACE_TYPE, CONTAINER_INHERIT_ACE, SeExports->SeAliasAdminsSid, KEY_ALL_ACCESS,
                        ACCESS_ALLOWED_ACE_TYPE, CONTAINER_INHERIT_ACE, SeExports->SeWorldSid,       KEY_READ,
                        ACCESS_ALLOWED_ACE_TYPE, CONTAINER_INHERIT_ACE, SeExports->SeRestrictedSid,  KEY_READ);

    CheckKeySecurity(L"\\REGISTRY\\MACHINE",
                     4, ACCESS_ALLOWED_ACE_TYPE, CONTAINER_INHERIT_ACE, SeExports->SeLocalSystemSid, KEY_ALL_ACCESS,
                        ACCESS_ALLOWED_ACE_TYPE, CONTAINER_INHERIT_ACE, SeExports->SeAliasAdminsSid, KEY_ALL_ACCESS,
                        ACCESS_ALLOWED_ACE_TYPE, CONTAINER_INHERIT_ACE, SeExports->SeWorldSid,       KEY_READ,
                        ACCESS_ALLOWED_ACE_TYPE, CONTAINER_INHERIT_ACE, SeExports->SeRestrictedSid,  KEY_READ);

    CheckKeySecurity(L"\\REGISTRY\\MACHINE\\HARDWARE",
                     4, ACCESS_ALLOWED_ACE_TYPE, CONTAINER_INHERIT_ACE, SeExports->SeLocalSystemSid, KEY_ALL_ACCESS,
                        ACCESS_ALLOWED_ACE_TYPE, CONTAINER_INHERIT_ACE, SeExports->SeAliasAdminsSid, KEY_ALL_ACCESS,
                        ACCESS_ALLOWED_ACE_TYPE, CONTAINER_INHERIT_ACE, SeExports->SeWorldSid,       KEY_READ,
                        ACCESS_ALLOWED_ACE_TYPE, CONTAINER_INHERIT_ACE, SeExports->SeRestrictedSid,  KEY_READ);

    CheckKeySecurity(L"\\REGISTRY\\MACHINE\\SAM",
                     8, ACCESS_ALLOWED_ACE_TYPE,                     0, SeExports->SeAliasUsersSid,   KEY_READ,
                        ACCESS_ALLOWED_ACE_TYPE, INHERIT_ONLY_ACE | 
                                                 CONTAINER_INHERIT_ACE, SeExports->SeAliasUsersSid,   GENERIC_READ,
                        ACCESS_ALLOWED_ACE_TYPE,                     0, SeExports->SeAliasAdminsSid,  KEY_ALL_ACCESS,
                        ACCESS_ALLOWED_ACE_TYPE, INHERIT_ONLY_ACE | 
                                                 CONTAINER_INHERIT_ACE, SeExports->SeAliasAdminsSid,  GENERIC_ALL,
                        ACCESS_ALLOWED_ACE_TYPE,                     0, SeExports->SeLocalSystemSid,  KEY_ALL_ACCESS,
                        ACCESS_ALLOWED_ACE_TYPE, INHERIT_ONLY_ACE | 
                                                 CONTAINER_INHERIT_ACE, SeExports->SeLocalSystemSid,  GENERIC_ALL,
                        ACCESS_ALLOWED_ACE_TYPE,                     0, SeExports->SeAliasAdminsSid,  KEY_ALL_ACCESS,
                        ACCESS_ALLOWED_ACE_TYPE, INHERIT_ONLY_ACE | 
                                                 CONTAINER_INHERIT_ACE, SeExports->SeCreatorOwnerSid, GENERIC_ALL);

    CheckKeySecurity(L"\\REGISTRY\\MACHINE\\SECURITY",
                     2, ACCESS_ALLOWED_ACE_TYPE, CONTAINER_INHERIT_ACE, SeExports->SeLocalSystemSid, KEY_ALL_ACCESS,
                        ACCESS_ALLOWED_ACE_TYPE, CONTAINER_INHERIT_ACE, SeExports->SeAliasAdminsSid, WRITE_DAC | READ_CONTROL);

    CheckKeySecurity(L"\\REGISTRY\\MACHINE\\SOFTWARE",
                     8, ACCESS_ALLOWED_ACE_TYPE,                     0, SeExports->SeAliasUsersSid,   KEY_READ,
                        ACCESS_ALLOWED_ACE_TYPE, INHERIT_ONLY_ACE |
                                                 CONTAINER_INHERIT_ACE, SeExports->SeAliasUsersSid,   GENERIC_READ,
                        ACCESS_ALLOWED_ACE_TYPE,                     0, SeExports->SeAliasAdminsSid,  KEY_ALL_ACCESS,
                        ACCESS_ALLOWED_ACE_TYPE, INHERIT_ONLY_ACE |
                                                 CONTAINER_INHERIT_ACE, SeExports->SeAliasAdminsSid,  GENERIC_ALL,
                        ACCESS_ALLOWED_ACE_TYPE,                     0, SeExports->SeLocalSystemSid,  KEY_ALL_ACCESS,
                        ACCESS_ALLOWED_ACE_TYPE, INHERIT_ONLY_ACE |
                                                 CONTAINER_INHERIT_ACE, SeExports->SeLocalSystemSid,  GENERIC_ALL,
                        ACCESS_ALLOWED_ACE_TYPE,                     0, SeExports->SeAliasAdminsSid,  KEY_ALL_ACCESS,
                        ACCESS_ALLOWED_ACE_TYPE, INHERIT_ONLY_ACE |
                                                 CONTAINER_INHERIT_ACE, SeExports->SeCreatorOwnerSid,  GENERIC_ALL);

    CheckKeySecurity(L"\\REGISTRY\\MACHINE\\SYSTEM",
                     8, ACCESS_ALLOWED_ACE_TYPE,                     0, SeExports->SeAliasUsersSid,      KEY_READ,
                        ACCESS_ALLOWED_ACE_TYPE, INHERIT_ONLY_ACE |
                                                 CONTAINER_INHERIT_ACE, SeExports->SeAliasUsersSid,      GENERIC_READ,
                        ACCESS_ALLOWED_ACE_TYPE,                     0, SeExports->SeAliasAdminsSid,     KEY_ALL_ACCESS,
                        ACCESS_ALLOWED_ACE_TYPE, INHERIT_ONLY_ACE |
                                                 CONTAINER_INHERIT_ACE, SeExports->SeAliasAdminsSid,     GENERIC_ALL,
                        ACCESS_ALLOWED_ACE_TYPE,                     0, SeExports->SeLocalSystemSid,     KEY_ALL_ACCESS,
                        ACCESS_ALLOWED_ACE_TYPE, INHERIT_ONLY_ACE |
                                                 CONTAINER_INHERIT_ACE, SeExports->SeLocalSystemSid,     GENERIC_ALL,
                        ACCESS_ALLOWED_ACE_TYPE,                     0, SeExports->SeAliasAdminsSid,     KEY_ALL_ACCESS,
                        ACCESS_ALLOWED_ACE_TYPE, INHERIT_ONLY_ACE |
                                                 CONTAINER_INHERIT_ACE, SeExports->SeCreatorOwnerSid,    GENERIC_ALL);

    CheckKeySecurity(L"\\REGISTRY\\USER",
                     4, ACCESS_ALLOWED_ACE_TYPE, CONTAINER_INHERIT_ACE, SeExports->SeLocalSystemSid, KEY_ALL_ACCESS,
                        ACCESS_ALLOWED_ACE_TYPE, CONTAINER_INHERIT_ACE, SeExports->SeAliasAdminsSid, KEY_ALL_ACCESS,
                        ACCESS_ALLOWED_ACE_TYPE, CONTAINER_INHERIT_ACE, SeExports->SeWorldSid,       KEY_READ,
                        ACCESS_ALLOWED_ACE_TYPE, CONTAINER_INHERIT_ACE, SeExports->SeRestrictedSid,  KEY_READ);

    CheckKeySecurity(L"\\REGISTRY\\USER\\.DEFAULT",
                     8, ACCESS_ALLOWED_ACE_TYPE,                     0, SeExports->SeAliasUsersSid,      KEY_READ,
                        ACCESS_ALLOWED_ACE_TYPE, INHERIT_ONLY_ACE |
                                                 CONTAINER_INHERIT_ACE, SeExports->SeAliasUsersSid,      GENERIC_READ,
                        ACCESS_ALLOWED_ACE_TYPE,                     0, SeExports->SeAliasAdminsSid,     KEY_ALL_ACCESS,
                        ACCESS_ALLOWED_ACE_TYPE, INHERIT_ONLY_ACE |
                                                 CONTAINER_INHERIT_ACE, SeExports->SeAliasAdminsSid,     GENERIC_ALL,
                        ACCESS_ALLOWED_ACE_TYPE,                     0, SeExports->SeLocalSystemSid,     KEY_ALL_ACCESS,
                        ACCESS_ALLOWED_ACE_TYPE, INHERIT_ONLY_ACE |
                                                 CONTAINER_INHERIT_ACE, SeExports->SeLocalSystemSid,     GENERIC_ALL,
                        ACCESS_ALLOWED_ACE_TYPE,                     0, SeExports->SeAliasAdminsSid,     KEY_ALL_ACCESS,
                        ACCESS_ALLOWED_ACE_TYPE, INHERIT_ONLY_ACE |
                                                 CONTAINER_INHERIT_ACE, SeExports->SeCreatorOwnerSid,    GENERIC_ALL);

    CheckKeySecurity(L"\\REGISTRY\\USER\\S-1-5-18",
                     8, ACCESS_ALLOWED_ACE_TYPE,                     0, SeExports->SeAliasUsersSid,      KEY_READ,
                        ACCESS_ALLOWED_ACE_TYPE, INHERIT_ONLY_ACE |
                                                 CONTAINER_INHERIT_ACE, SeExports->SeAliasUsersSid,      GENERIC_READ,
                        ACCESS_ALLOWED_ACE_TYPE,                     0, SeExports->SeAliasAdminsSid,     KEY_ALL_ACCESS,
                        ACCESS_ALLOWED_ACE_TYPE, INHERIT_ONLY_ACE |
                                                 CONTAINER_INHERIT_ACE, SeExports->SeAliasAdminsSid,     GENERIC_ALL,
                        ACCESS_ALLOWED_ACE_TYPE,                     0, SeExports->SeLocalSystemSid,     KEY_ALL_ACCESS,
                        ACCESS_ALLOWED_ACE_TYPE, INHERIT_ONLY_ACE |
                                                 CONTAINER_INHERIT_ACE, SeExports->SeLocalSystemSid,     GENERIC_ALL,
                        ACCESS_ALLOWED_ACE_TYPE,                     0, SeExports->SeAliasAdminsSid,     KEY_ALL_ACCESS,
                        ACCESS_ALLOWED_ACE_TYPE, INHERIT_ONLY_ACE |
                                                 CONTAINER_INHERIT_ACE, SeExports->SeCreatorOwnerSid,    GENERIC_ALL);

    CheckKeySecurity(L"\\REGISTRY\\USER\\S-1-5-20",
                     4, ACCESS_ALLOWED_ACE_TYPE, OBJECT_INHERIT_ACE |
                                                 CONTAINER_INHERIT_ACE, SeExports->SeNetworkServiceSid,  KEY_ALL_ACCESS,
                        ACCESS_ALLOWED_ACE_TYPE, OBJECT_INHERIT_ACE |
                                                 CONTAINER_INHERIT_ACE, SeExports->SeLocalSystemSid,     KEY_ALL_ACCESS,
                        ACCESS_ALLOWED_ACE_TYPE, OBJECT_INHERIT_ACE |
                                                 CONTAINER_INHERIT_ACE, SeExports->SeAliasAdminsSid,     KEY_ALL_ACCESS,
                        ACCESS_ALLOWED_ACE_TYPE, OBJECT_INHERIT_ACE |
                                                 CONTAINER_INHERIT_ACE, SeExports->SeRestrictedSid,      KEY_READ);
}

static void CmSecurity_Win8(PSID TerminalServerSid)
{
    CheckKeySecurity(L"\\REGISTRY",
                     5, ACCESS_ALLOWED_ACE_TYPE, CONTAINER_INHERIT_ACE, SeExports->SeLocalSystemSid,    KEY_ALL_ACCESS,
                        ACCESS_ALLOWED_ACE_TYPE, CONTAINER_INHERIT_ACE, SeExports->SeAliasAdminsSid,    KEY_ALL_ACCESS,
                        ACCESS_ALLOWED_ACE_TYPE, CONTAINER_INHERIT_ACE, SeExports->SeWorldSid,          KEY_READ,
                        ACCESS_ALLOWED_ACE_TYPE, CONTAINER_INHERIT_ACE, SeExports->SeRestrictedSid,     KEY_READ,
                        ACCESS_ALLOWED_ACE_TYPE, CONTAINER_INHERIT_ACE, SeExports->SeAllAppPackagesSid, KEY_READ);

    CheckKeySecurity(L"\\REGISTRY\\MACHINE",
                     5, ACCESS_ALLOWED_ACE_TYPE, CONTAINER_INHERIT_ACE, SeExports->SeLocalSystemSid,    KEY_ALL_ACCESS,
                        ACCESS_ALLOWED_ACE_TYPE, CONTAINER_INHERIT_ACE, SeExports->SeAliasAdminsSid,    KEY_ALL_ACCESS,
                        ACCESS_ALLOWED_ACE_TYPE, CONTAINER_INHERIT_ACE, SeExports->SeWorldSid,          KEY_READ,
                        ACCESS_ALLOWED_ACE_TYPE, CONTAINER_INHERIT_ACE, SeExports->SeRestrictedSid,     KEY_READ,
                        ACCESS_ALLOWED_ACE_TYPE, CONTAINER_INHERIT_ACE, SeExports->SeAllAppPackagesSid, KEY_READ);

    CheckKeySecurity(L"\\REGISTRY\\MACHINE\\HARDWARE",
                     5, ACCESS_ALLOWED_ACE_TYPE, CONTAINER_INHERIT_ACE, SeExports->SeLocalSystemSid,    KEY_ALL_ACCESS,
                        ACCESS_ALLOWED_ACE_TYPE, CONTAINER_INHERIT_ACE, SeExports->SeAliasAdminsSid,    KEY_ALL_ACCESS,
                        ACCESS_ALLOWED_ACE_TYPE, CONTAINER_INHERIT_ACE, SeExports->SeWorldSid,          KEY_READ,
                        ACCESS_ALLOWED_ACE_TYPE, CONTAINER_INHERIT_ACE, SeExports->SeRestrictedSid,     KEY_READ,
                        ACCESS_ALLOWED_ACE_TYPE, CONTAINER_INHERIT_ACE, SeExports->SeAllAppPackagesSid, KEY_READ);

    CheckKeySecurity(L"\\REGISTRY\\MACHINE\\SAM",
                     5, ACCESS_ALLOWED_ACE_TYPE, CONTAINER_INHERIT_ACE, SeExports->SeAliasUsersSid,     KEY_READ,
                        ACCESS_ALLOWED_ACE_TYPE, CONTAINER_INHERIT_ACE, SeExports->SeAliasAdminsSid,    KEY_ALL_ACCESS,
                        ACCESS_ALLOWED_ACE_TYPE, CONTAINER_INHERIT_ACE, SeExports->SeLocalSystemSid,    KEY_ALL_ACCESS,
                        ACCESS_ALLOWED_ACE_TYPE, CONTAINER_INHERIT_ACE, SeExports->SeCreatorOwnerSid,   KEY_ALL_ACCESS,
                        ACCESS_ALLOWED_ACE_TYPE, CONTAINER_INHERIT_ACE, SeExports->SeAllAppPackagesSid, KEY_READ);

    CheckKeySecurity(L"\\REGISTRY\\MACHINE\\SECURITY",
                     2, ACCESS_ALLOWED_ACE_TYPE, CONTAINER_INHERIT_ACE, SeExports->SeLocalSystemSid, KEY_ALL_ACCESS,
                        ACCESS_ALLOWED_ACE_TYPE, CONTAINER_INHERIT_ACE, SeExports->SeAliasAdminsSid, WRITE_DAC | READ_CONTROL);

    CheckKeySecurity(L"\\REGISTRY\\MACHINE\\SOFTWARE",
                     5, ACCESS_ALLOWED_ACE_TYPE, CONTAINER_INHERIT_ACE, SeExports->SeAliasUsersSid,     KEY_READ,
                        ACCESS_ALLOWED_ACE_TYPE, CONTAINER_INHERIT_ACE, SeExports->SeAliasAdminsSid,    KEY_ALL_ACCESS,
                        ACCESS_ALLOWED_ACE_TYPE, CONTAINER_INHERIT_ACE, SeExports->SeLocalSystemSid,    KEY_ALL_ACCESS,
                        ACCESS_ALLOWED_ACE_TYPE, CONTAINER_INHERIT_ACE, SeExports->SeCreatorOwnerSid,   KEY_ALL_ACCESS,
                        ACCESS_ALLOWED_ACE_TYPE, CONTAINER_INHERIT_ACE, SeExports->SeAllAppPackagesSid, KEY_READ);

    CheckKeySecurity(L"\\REGISTRY\\MACHINE\\SYSTEM",
                     5, ACCESS_ALLOWED_ACE_TYPE, CONTAINER_INHERIT_ACE, SeExports->SeAliasUsersSid,     KEY_READ,
                        ACCESS_ALLOWED_ACE_TYPE, CONTAINER_INHERIT_ACE, SeExports->SeAliasAdminsSid,    KEY_ALL_ACCESS,
                        ACCESS_ALLOWED_ACE_TYPE, CONTAINER_INHERIT_ACE, SeExports->SeLocalSystemSid,    KEY_ALL_ACCESS,
                        ACCESS_ALLOWED_ACE_TYPE, CONTAINER_INHERIT_ACE, SeExports->SeCreatorOwnerSid,   KEY_ALL_ACCESS,
                        ACCESS_ALLOWED_ACE_TYPE, CONTAINER_INHERIT_ACE, SeExports->SeAllAppPackagesSid, KEY_READ);

    CheckKeySecurity(L"\\REGISTRY\\USER",
                     5, ACCESS_ALLOWED_ACE_TYPE, CONTAINER_INHERIT_ACE, SeExports->SeLocalSystemSid,    KEY_ALL_ACCESS,
                        ACCESS_ALLOWED_ACE_TYPE, CONTAINER_INHERIT_ACE, SeExports->SeAliasAdminsSid,    KEY_ALL_ACCESS,
                        ACCESS_ALLOWED_ACE_TYPE, CONTAINER_INHERIT_ACE, SeExports->SeWorldSid,          KEY_READ,
                        ACCESS_ALLOWED_ACE_TYPE, CONTAINER_INHERIT_ACE, SeExports->SeRestrictedSid,     KEY_READ,
                        ACCESS_ALLOWED_ACE_TYPE, CONTAINER_INHERIT_ACE, SeExports->SeAllAppPackagesSid, KEY_READ);

    CheckKeySecurity(L"\\REGISTRY\\USER\\.DEFAULT",
                     5, ACCESS_ALLOWED_ACE_TYPE, CONTAINER_INHERIT_ACE, SeExports->SeAliasUsersSid,     KEY_READ,
                        ACCESS_ALLOWED_ACE_TYPE, CONTAINER_INHERIT_ACE, SeExports->SeAliasAdminsSid,    KEY_ALL_ACCESS,
                        ACCESS_ALLOWED_ACE_TYPE, CONTAINER_INHERIT_ACE, SeExports->SeLocalSystemSid,    KEY_ALL_ACCESS,
                        ACCESS_ALLOWED_ACE_TYPE, CONTAINER_INHERIT_ACE, SeExports->SeCreatorOwnerSid,   KEY_ALL_ACCESS,
                        ACCESS_ALLOWED_ACE_TYPE, CONTAINER_INHERIT_ACE, SeExports->SeAllAppPackagesSid, KEY_READ);

    CheckKeySecurity(L"\\REGISTRY\\USER\\S-1-5-18",
                     5, ACCESS_ALLOWED_ACE_TYPE, CONTAINER_INHERIT_ACE, SeExports->SeAliasUsersSid,     KEY_READ,
                        ACCESS_ALLOWED_ACE_TYPE, CONTAINER_INHERIT_ACE, SeExports->SeAliasAdminsSid,    KEY_ALL_ACCESS,
                        ACCESS_ALLOWED_ACE_TYPE, CONTAINER_INHERIT_ACE, SeExports->SeLocalSystemSid,    KEY_ALL_ACCESS,
                        ACCESS_ALLOWED_ACE_TYPE, CONTAINER_INHERIT_ACE, SeExports->SeCreatorOwnerSid,   KEY_ALL_ACCESS,
                        ACCESS_ALLOWED_ACE_TYPE, CONTAINER_INHERIT_ACE, SeExports->SeAllAppPackagesSid, KEY_READ);

    CheckKeySecurity(L"\\REGISTRY\\USER\\S-1-5-20",
                     5, ACCESS_ALLOWED_ACE_TYPE, OBJECT_INHERIT_ACE |
                                                 CONTAINER_INHERIT_ACE, SeExports->SeNetworkServiceSid, KEY_ALL_ACCESS,
                        ACCESS_ALLOWED_ACE_TYPE, OBJECT_INHERIT_ACE |
                                                 CONTAINER_INHERIT_ACE, SeExports->SeLocalSystemSid,    KEY_ALL_ACCESS,
                        ACCESS_ALLOWED_ACE_TYPE, OBJECT_INHERIT_ACE |
                                                 CONTAINER_INHERIT_ACE, SeExports->SeAliasAdminsSid,    KEY_ALL_ACCESS,
                        ACCESS_ALLOWED_ACE_TYPE, OBJECT_INHERIT_ACE |
                                                 CONTAINER_INHERIT_ACE, SeExports->SeRestrictedSid,     KEY_READ,
                        ACCESS_ALLOWED_ACE_TYPE,                     0, SeExports->SeAllAppPackagesSid, KEY_READ);
}

/*
 * Windows 10 (22H2): the namespace keys are owned by SYSTEM and carry the application package SID and the LPAC
 * capability besides; the hive roots are Administrators' with Creator Owner, and the default user and the
 * service accounts differ again. The descriptors are the ones captured on a Windows 10 22H2 system.
 */
static void CmSecurity_Win10(PSID TerminalServerSid)
{
    static const SID_IDENTIFIER_AUTHORITY AppAuthority = {{0, 0, 0, 0, 0, 15}};
    static const ULONG LpacSubAuthorities[10] =
        { 3, 1024, 1065365936, 1281604716, 3511738428u, 1654721687, 432734479, 3232135806u, 4053264122u, 3456934681u };
    PSID LpacSid;
    ULONG i;

    LpacSid = ExAllocatePoolWithTag(PagedPool, RtlLengthRequiredSid(10), 'iSmK');
    if (LpacSid == NULL)
    {
        skip(FALSE, "No memory for the LPAC capability SID\n");
        return;
    }
    RtlInitializeSid(LpacSid, (PSID_IDENTIFIER_AUTHORITY)&AppAuthority, 10);
    for (i = 0; i < 10; i++)
        *RtlSubAuthoritySid(LpacSid, i) = LpacSubAuthorities[i];

    /* The master keys: owner SYSTEM */
    ExpectedKeyOwner = SeExports->SeLocalSystemSid;
#define MASTER_KEY_ACES(Name)                                                                                        \
    CheckKeySecurity(Name,                                                                                           \
                     6, ACCESS_ALLOWED_ACE_TYPE, CONTAINER_INHERIT_ACE, SeExports->SeLocalSystemSid,    KEY_ALL_ACCESS, \
                        ACCESS_ALLOWED_ACE_TYPE, CONTAINER_INHERIT_ACE, SeExports->SeAliasAdminsSid,    KEY_ALL_ACCESS, \
                        ACCESS_ALLOWED_ACE_TYPE, CONTAINER_INHERIT_ACE, SeExports->SeWorldSid,          KEY_READ,       \
                        ACCESS_ALLOWED_ACE_TYPE, CONTAINER_INHERIT_ACE, SeExports->SeRestrictedSid,     KEY_READ,       \
                        ACCESS_ALLOWED_ACE_TYPE, CONTAINER_INHERIT_ACE, SeExports->SeAllAppPackagesSid, KEY_READ,       \
                        ACCESS_ALLOWED_ACE_TYPE, CONTAINER_INHERIT_ACE, LpacSid,                        KEY_READ)
    MASTER_KEY_ACES(L"\\REGISTRY");
    MASTER_KEY_ACES(L"\\REGISTRY\\MACHINE");
    MASTER_KEY_ACES(L"\\REGISTRY\\MACHINE\\HARDWARE");
    MASTER_KEY_ACES(L"\\REGISTRY\\USER");
#undef MASTER_KEY_ACES

    /* The roots of the system hives: Administrators own them */
    ExpectedKeyOwner = NULL;
#define HIVE_ROOT_ACES(Name)                                                                                         \
    CheckKeySecurity(Name,                                                                                           \
                     6, ACCESS_ALLOWED_ACE_TYPE, CONTAINER_INHERIT_ACE, SeExports->SeAliasUsersSid,     KEY_READ,       \
                        ACCESS_ALLOWED_ACE_TYPE, CONTAINER_INHERIT_ACE, SeExports->SeAliasAdminsSid,    KEY_ALL_ACCESS, \
                        ACCESS_ALLOWED_ACE_TYPE, CONTAINER_INHERIT_ACE, SeExports->SeLocalSystemSid,    KEY_ALL_ACCESS, \
                        ACCESS_ALLOWED_ACE_TYPE, CONTAINER_INHERIT_ACE, SeExports->SeCreatorOwnerSid,   KEY_ALL_ACCESS, \
                        ACCESS_ALLOWED_ACE_TYPE, CONTAINER_INHERIT_ACE, SeExports->SeAllAppPackagesSid, KEY_READ,       \
                        ACCESS_ALLOWED_ACE_TYPE, CONTAINER_INHERIT_ACE, LpacSid,                        KEY_READ)
    HIVE_ROOT_ACES(L"\\REGISTRY\\MACHINE\\SAM");
    HIVE_ROOT_ACES(L"\\REGISTRY\\MACHINE\\SOFTWARE");
    HIVE_ROOT_ACES(L"\\REGISTRY\\MACHINE\\SYSTEM");
#undef HIVE_ROOT_ACES

    CheckKeySecurity(L"\\REGISTRY\\MACHINE\\SECURITY",
                     2, ACCESS_ALLOWED_ACE_TYPE, CONTAINER_INHERIT_ACE, SeExports->SeLocalSystemSid, KEY_ALL_ACCESS,
                        ACCESS_ALLOWED_ACE_TYPE, CONTAINER_INHERIT_ACE, SeExports->SeAliasAdminsSid, WRITE_DAC | READ_CONTROL);

    /* The default user: the application package ACEs are not inherited */
#define DEFAULT_USER_ACES(Name)                                                                                      \
    CheckKeySecurity(Name,                                                                                           \
                     6, ACCESS_ALLOWED_ACE_TYPE, CONTAINER_INHERIT_ACE, SeExports->SeAliasUsersSid,     KEY_READ,       \
                        ACCESS_ALLOWED_ACE_TYPE, CONTAINER_INHERIT_ACE, SeExports->SeAliasAdminsSid,    KEY_ALL_ACCESS, \
                        ACCESS_ALLOWED_ACE_TYPE, CONTAINER_INHERIT_ACE, SeExports->SeLocalSystemSid,    KEY_ALL_ACCESS, \
                        ACCESS_ALLOWED_ACE_TYPE, CONTAINER_INHERIT_ACE, SeExports->SeCreatorOwnerSid,   KEY_ALL_ACCESS, \
                        ACCESS_ALLOWED_ACE_TYPE,                     0, SeExports->SeAllAppPackagesSid, KEY_READ,       \
                        ACCESS_ALLOWED_ACE_TYPE,                     0, LpacSid,                        KEY_READ)
    DEFAULT_USER_ACES(L"\\REGISTRY\\USER\\.DEFAULT");
    DEFAULT_USER_ACES(L"\\REGISTRY\\USER\\S-1-5-18");
#undef DEFAULT_USER_ACES

    /* The network service account */
    CheckKeySecurity(L"\\REGISTRY\\USER\\S-1-5-20",
                     6, ACCESS_ALLOWED_ACE_TYPE, OBJECT_INHERIT_ACE |
                                                 CONTAINER_INHERIT_ACE, SeExports->SeNetworkServiceSid, KEY_ALL_ACCESS,
                        ACCESS_ALLOWED_ACE_TYPE, OBJECT_INHERIT_ACE |
                                                 CONTAINER_INHERIT_ACE, SeExports->SeLocalSystemSid,    KEY_ALL_ACCESS,
                        ACCESS_ALLOWED_ACE_TYPE, OBJECT_INHERIT_ACE |
                                                 CONTAINER_INHERIT_ACE, SeExports->SeAliasAdminsSid,    KEY_ALL_ACCESS,
                        ACCESS_ALLOWED_ACE_TYPE, OBJECT_INHERIT_ACE |
                                                 CONTAINER_INHERIT_ACE, SeExports->SeRestrictedSid,     KEY_READ,
                        ACCESS_ALLOWED_ACE_TYPE,                     0, SeExports->SeAllAppPackagesSid, KEY_READ,
                        ACCESS_ALLOWED_ACE_TYPE,                     0, LpacSid,                        KEY_READ);

    ExFreePoolWithTag(LpacSid, 'iSmK');
}

START_TEST(CmSecurity)
{
    SID_IDENTIFIER_AUTHORITY NtSidAuthority = {SECURITY_NT_AUTHORITY};
    PSID TerminalServerSid;

    TerminalServerSid = ExAllocatePoolWithTag(PagedPool,
                                              RtlLengthRequiredSid(1),
                                              'iSmK');
    if (TerminalServerSid != NULL)
    {
        RtlInitializeSid(TerminalServerSid, &NtSidAuthority, 1);
        *RtlSubAuthoritySid(TerminalServerSid, 0) = SECURITY_TERMINAL_SERVER_RID;
    }

    switch (GetNTVersion())
    {
        case _WIN32_WINNT_WS03:
            CmSecurity_WS03(TerminalServerSid);
            break;
        case _WIN32_WINNT_VISTA:
        case _WIN32_WINNT_WIN7:
            CmSecurity_Vista(TerminalServerSid);
            break;
        case _WIN32_WINNT_WIN8:
        case _WIN32_WINNT_WINBLUE:
            CmSecurity_Win8(TerminalServerSid);
            break;
        case _WIN32_WINNT_WIN10:
            CmSecurity_Win10(TerminalServerSid);
            break;
        default:
            if (GetNTVersion() < _WIN32_WINNT_WS03)
            {
                trace("Unknown NT version (0x%X < 0x%X), running WS03 tests...\n", GetNTVersion(), _WIN32_WINNT_WS03);
                CmSecurity_WS03(TerminalServerSid);
            }
            else
            {
                trace("Unknown NT version (0x%X > 0x%X), running latest tests...\n", GetNTVersion(), _WIN32_WINNT_WIN10);
                CmSecurity_Win10(TerminalServerSid);
            }
            break;
    }

    if (TerminalServerSid != NULL)
    {
        ExFreePoolWithTag(TerminalServerSid, 'iSmK');
    }
}
