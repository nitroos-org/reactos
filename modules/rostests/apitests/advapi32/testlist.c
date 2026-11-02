
#define STANDALONE
#include <apitest.h>

extern void func_AddMandatoryAce(void);
extern void func_BuildSecurityDescriptor(void);
extern void func_NamedPipeSD(void);
extern void func_ConvertStringSidToSid(void);
extern void func_CreateService(void);
extern void func_CreateProcessAsUserToken(void);
extern void func_CreateEnvironmentBlockProfile(void);
extern void func_CloseTrace(void);
extern void func_DuplicateTokenEx(void);
extern void func_EnableTraceEx2(void);
extern void func_EncryptFile(void);
extern void func_eventlog_supp(void);
extern void func_EventRegister(void);
extern void func_EventProvider(void);
extern void func_EventSetInformation(void);
extern void func_EventSetInformationFault(void);
extern void func_GetSecurityInfoSequence(void);
extern void func_Hash(void);
extern void func_HKEY_CLASSES_ROOT(void);
extern void func_IsTextUnicode(void);
extern void func_LockServiceDatabase(void);
extern void func_LookupAccountSidCaller(void);
extern void func_LogonUser(void);
extern void func_LogonUserCleartext(void);
extern void func_LogonUserServiceSecret(void);
extern void func_LogonUserUserRights(void);
extern void func_LsaLogonSession(void);
extern void func_LsaLookupLeak(void);
extern void func_LsaLogonUserS4U(void);
extern void func_LsaManageSidNameMapping(void);
extern void func_NetUserChangePassword(void);
extern void func_ProcessThreadLabel(void);
extern void func_QueryServiceConfig(void);
extern void func_QueryServiceConfig2(void);
extern void func_QueryServiceObjectSecurity(void);
extern void func_RegConcurrentWrite(void);
extern void func_RegCreateKeyEx(void);
extern void func_RegCreateKeyTransacted(void);
extern void func_RegDeleteTreeOpenHandles(void);
extern void func_RegEnumKey(void);
extern void func_RegEnumKeyClass(void);
extern void func_RegEnumValueW(void);
extern void func_RegFlushKey(void);
extern void func_RegNotifyChangeKeyValue(void);
extern void func_RegLoadKeyBadBinSize(void);
extern void func_RegLoadKeyBadSecondBin(void);
extern void func_RegLoadKeyZeroBin(void);
extern void func_RegLoadKeyZeroCell(void);
extern void func_RegOpenKeyExW(void);
extern void func_RegPerformanceData(void);
extern void func_RegQueryInfoKey(void);
extern void func_RegQueryValueExW(void);
extern void func_RegKeyNameCase(void);
extern void func_RegRenameKey(void);
extern void func_RegRenameKeyPersist(void);
extern void func_RegRenameKeyStress(void);
extern void func_RegGetValue(void);
extern void func_RegSecurityDump(void);
extern void func_RegSecurityDefaultSd(void);
extern void func_RegSecurityAccess(void);
extern void func_RegSecurityMapping(void);
extern void func_RegSecurityRoundTrip(void);
extern void func_RegSecurityCreate(void);
extern void func_RestrictedSidsCopy(void);
extern void func_RtlEncryptMemory(void);
extern void func_SaferIdentifyLevel(void);
extern void func_TokenDefaultDacl(void);
extern void func_TokenElevation(void);
extern void func_TokenIntegrity(void);
extern void func_TokenLogonSid(void);
extern void func_TokenQueryParity(void);
extern void func_ServiceArgs(void);
extern void func_ServiceControllerQuery(void);
extern void func_ServiceEnv(void);
extern void func_ServiceFailureActions(void);
extern void func_ServiceRecovery(void);
extern void func_ServiceNetwork(void);
extern void func_SetEntriesInAclOld(void);
extern void func_SetSecurityInfoKey(void);
extern void func_SetNamedSecurityInfoInherit(void);
extern void func_SddlRights(void);

extern void func_RegWow64(void);
extern void func_RegWow64Unicode(void);
extern void func_RegWow64Views(void);
extern void func_RegWow64Matrix(void);
extern void func_RegWow64LongName(void);
extern void func_RegWow64SharedLongName(void);
extern void func_RegWow64Volatile(void);
extern void func_RegWow64SharedCreate(void);
extern void func_RegWow64Aliases(void);
extern void func_RegWow64RelativeView(void);
extern void func_ServiceProcess(void);
extern void func_ServiceStructLayout(void);
extern void func_ServiceTriggerPrivileges(void);
extern void func_Saferi(void);
extern void func_SecurityAccessMask(void);
extern void func_Win10Exports(void);
extern void func_ControlServiceEx(void);
extern void func_LsaLookupSids2(void);

const struct test winetest_testlist[] =
{
    { "AddMandatoryAce", func_AddMandatoryAce },
    { "BuildSecurityDescriptor", func_BuildSecurityDescriptor },
    { "NamedPipeSD", func_NamedPipeSD },
    { "ConvertStringSidToSid", func_ConvertStringSidToSid },
    { "RegWow64", func_RegWow64 },
    { "RegWow64Unicode", func_RegWow64Unicode },
    { "RegWow64Views", func_RegWow64Views },
    { "RegWow64SharedCreate", func_RegWow64SharedCreate },
    { "RegWow64Matrix", func_RegWow64Matrix },
    { "RegWow64LongName", func_RegWow64LongName },
    { "RegWow64SharedLongName", func_RegWow64SharedLongName },
    { "RegWow64Volatile", func_RegWow64Volatile },
    { "RegWow64Aliases", func_RegWow64Aliases },
    { "RegWow64RelativeView", func_RegWow64RelativeView },
    { "CreateService", func_CreateService },
    { "CreateProcessAsUserToken", func_CreateProcessAsUserToken },
    { "CreateEnvironmentBlockProfile", func_CreateEnvironmentBlockProfile },
    { "CloseTrace", func_CloseTrace },
    { "DuplicateTokenEx", func_DuplicateTokenEx },
    { "EnableTraceEx2", func_EnableTraceEx2 },
    { "EncryptFile", func_EncryptFile },
    { "eventlog_supp", func_eventlog_supp },
    { "EventRegister", func_EventRegister },
    { "EventProvider", func_EventProvider },
    { "EventSetInformation", func_EventSetInformation },
    { "EventSetInformationFault", func_EventSetInformationFault },
    { "GetSecurityInfoSequence", func_GetSecurityInfoSequence },
    { "Hash", func_Hash },
    { "HKEY_CLASSES_ROOT", func_HKEY_CLASSES_ROOT },
    { "IsTextUnicode" , func_IsTextUnicode },
    { "LockServiceDatabase" , func_LockServiceDatabase },
    { "LookupAccountSidCaller", func_LookupAccountSidCaller },
    { "LogonUser", func_LogonUser },
    { "LogonUserCleartext", func_LogonUserCleartext },
    { "LogonUserServiceSecret", func_LogonUserServiceSecret },
    { "LogonUserUserRights", func_LogonUserUserRights },
    { "LsaLogonSession", func_LsaLogonSession },
    { "LsaLookupLeak", func_LsaLookupLeak },
    { "LsaLogonUserS4U", func_LsaLogonUserS4U },
    { "LsaManageSidNameMapping", func_LsaManageSidNameMapping },
    { "NetUserChangePassword", func_NetUserChangePassword },
    { "ProcessThreadLabel", func_ProcessThreadLabel },
    { "QueryServiceConfig", func_QueryServiceConfig },
    { "QueryServiceConfig2", func_QueryServiceConfig2 },
    { "QueryServiceObjectSecurity", func_QueryServiceObjectSecurity },
    { "RegConcurrentWrite", func_RegConcurrentWrite },
    { "RegCreateKeyEx", func_RegCreateKeyEx },
    { "RegCreateKeyTransacted", func_RegCreateKeyTransacted },
    { "RegDeleteTreeOpenHandles", func_RegDeleteTreeOpenHandles },
    { "RegEnumKey", func_RegEnumKey },
    { "RegEnumKeyClass", func_RegEnumKeyClass },
    { "RegEnumValueW", func_RegEnumValueW },
    { "RegFlushKey", func_RegFlushKey },
    { "RegNotifyChangeKeyValue", func_RegNotifyChangeKeyValue },
    { "RegLoadKeyBadBinSize", func_RegLoadKeyBadBinSize },
    { "RegLoadKeyBadSecondBin", func_RegLoadKeyBadSecondBin },
    { "RegLoadKeyZeroBin", func_RegLoadKeyZeroBin },
    { "RegLoadKeyZeroCell", func_RegLoadKeyZeroCell },
    { "RegQueryInfoKey", func_RegQueryInfoKey },
    { "RegOpenKeyExW", func_RegOpenKeyExW },
    { "RegPerformanceData", func_RegPerformanceData },
    { "RegQueryValueExW", func_RegQueryValueExW },
    { "RegKeyNameCase", func_RegKeyNameCase },
    { "RegRenameKey", func_RegRenameKey },
    { "RegRenameKeyPersist", func_RegRenameKeyPersist },
    { "RegRenameKeyStress", func_RegRenameKeyStress },
    { "RegGetValue", func_RegGetValue },
    { "RegSecurityDump", func_RegSecurityDump },
    { "RegSecurityDefaultSd", func_RegSecurityDefaultSd },
    { "RegSecurityAccess", func_RegSecurityAccess },
    { "RegSecurityMapping", func_RegSecurityMapping },
    { "RegSecurityRoundTrip", func_RegSecurityRoundTrip },
    { "RegSecurityCreate", func_RegSecurityCreate },
    { "RestrictedSidsCopy", func_RestrictedSidsCopy },
    { "RtlEncryptMemory", func_RtlEncryptMemory },
    { "SaferIdentifyLevel", func_SaferIdentifyLevel },
    { "TokenDefaultDacl", func_TokenDefaultDacl },
    { "TokenElevation", func_TokenElevation },
    { "TokenIntegrity", func_TokenIntegrity },
    { "TokenLogonSid", func_TokenLogonSid },
    { "TokenQueryParity", func_TokenQueryParity },
    { "ServiceArgs", func_ServiceArgs },
    { "ServiceControllerQuery", func_ServiceControllerQuery },
    { "ServiceEnv", func_ServiceEnv },
    { "ServiceFailureActions", func_ServiceFailureActions },
    { "ServiceRecovery", func_ServiceRecovery },
    { "ServiceNetwork", func_ServiceNetwork },
    { "SetEntriesInAclOld", func_SetEntriesInAclOld },
    { "SetSecurityInfoKey", func_SetSecurityInfoKey },
    { "SetNamedSecurityInfoInherit", func_SetNamedSecurityInfoInherit },
    { "SddlRights", func_SddlRights },
    { "ServiceProcess", func_ServiceProcess },
    { "ServiceStructLayout", func_ServiceStructLayout },
    { "ServiceTriggerPrivileges", func_ServiceTriggerPrivileges },
    { "Saferi", func_Saferi },
    { "SecurityAccessMask", func_SecurityAccessMask },
    { "Win10Exports", func_Win10Exports },
    { "ControlServiceEx", func_ControlServiceEx },
    { "LsaLookupSids2", func_LsaLookupSids2 },
    { 0, 0 }
};

