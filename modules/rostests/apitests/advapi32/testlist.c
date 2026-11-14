
#define STANDALONE
#include <apitest.h>

extern void func_AccessCheckObjectTypeList(void);
extern void func_AddMandatoryAce(void);
extern void func_AuditCategories(void);
extern void func_CveEventWrite(void);
extern void func_DynamicTimeZone(void);
extern void func_TimeZoneKeys(void);
extern void func_PerfCounterValues(void);
extern void func_BuildSecurityDescriptor(void);
extern void func_NamedPipeSD(void);
extern void func_ConvertStringSidToSid(void);
extern void func_CreateService(void);
extern void func_CreateProcessAsUserToken(void);
extern void func_CreateProcessWithLogon(void);
extern void func_CreateEnvironmentBlockProfile(void);
extern void func_CloseTrace(void);
extern void func_DuplicateTokenEx(void);
extern void func_EnableTraceEx2(void);
extern void func_EncryptFile(void);
extern void func_eventlog_supp(void);
extern void func_eventlog_full(void);
extern void func_EventRegister(void);
extern void func_EventProvider(void);
extern void func_EventSetInformation(void);
extern void func_EventSetInformationFault(void);
extern void func_GetSecurityInfoSequence(void);
extern void func_ObjectLockStress(void);
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
extern void func_LsaLookupNamesUnmapped(void);
extern void func_LsassLeak(void);
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
extern void func_RegValueLookup(void);
extern void func_RegFlushKey(void);
extern void func_RegNotifyChangeKeyValue(void);
extern void func_RegNotifyLeak(void);
extern void func_RegLoadKeyBadBinSize(void);
extern void func_RegLoadKeyBadSecondBin(void);
extern void func_RegLoadKeyUnloadPool(void);
extern void func_RegLoadKeyZeroBin(void);
extern void func_RegLoadKeyZeroCell(void);
extern void func_RegOpenKeyExW(void);
extern void func_PerfProvider(void);
extern void func_RegPerformanceData(void);
extern void func_InitiateShutdown(void);
extern void func_RegQueryInfoKey(void);
extern void func_RegQueryValueExW(void);
extern void func_RegQueryMultipleValues(void);
extern void func_RegKeyNameCase(void);
extern void func_RegRenameKey(void);
extern void func_RegRenameKeyPersist(void);
extern void func_RegRenameKeyStress(void);
extern void func_RegGetValue(void);
extern void func_RegSdTemplates(void);
extern void func_RegSecurityDump(void);
extern void func_RegSecurityDefaultSd(void);
extern void func_RegSecurityAccess(void);
extern void func_RegSecurityMapping(void);
extern void func_RegSecurityRoundTrip(void);
extern void func_RegSecurityCreate(void);
extern void func_RegSharedKeyName(void);
extern void func_RestrictedSidsCopy(void);
extern void func_RestrictedTokenAccess(void);
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
extern void func_ServiceSid(void);
extern void func_ServiceVirtualAccount(void);
extern void func_ServiceNetwork(void);
extern void func_SetEntriesInAclOld(void);
extern void func_SetSecurityInfoKey(void);
extern void func_SetNamedSecurityInfoInherit(void);
extern void func_SddlRights(void);
extern void func_SddlSids(void);

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
    { "AccessCheckObjectTypeList", func_AccessCheckObjectTypeList },
    { "AddMandatoryAce", func_AddMandatoryAce },
    { "AuditCategories", func_AuditCategories },
    { "CveEventWrite", func_CveEventWrite },
    { "DynamicTimeZone", func_DynamicTimeZone },
    { "TimeZoneKeys", func_TimeZoneKeys },
    { "PerfCounterValues", func_PerfCounterValues },
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
    { "CreateProcessWithLogon", func_CreateProcessWithLogon },
    { "CreateEnvironmentBlockProfile", func_CreateEnvironmentBlockProfile },
    { "CloseTrace", func_CloseTrace },
    { "DuplicateTokenEx", func_DuplicateTokenEx },
    { "EnableTraceEx2", func_EnableTraceEx2 },
    { "EncryptFile", func_EncryptFile },
    { "eventlog_supp", func_eventlog_supp },
    { "eventlog_full", func_eventlog_full },
    { "EventRegister", func_EventRegister },
    { "EventProvider", func_EventProvider },
    { "EventSetInformation", func_EventSetInformation },
    { "EventSetInformationFault", func_EventSetInformationFault },
    { "GetSecurityInfoSequence", func_GetSecurityInfoSequence },
    { "ObjectLockStress", func_ObjectLockStress },
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
    { "LsaLookupNamesUnmapped", func_LsaLookupNamesUnmapped },
    { "LsassLeak", func_LsassLeak },
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
    { "RegValueLookup", func_RegValueLookup },
    { "RegFlushKey", func_RegFlushKey },
    { "RegNotifyChangeKeyValue", func_RegNotifyChangeKeyValue },
    { "RegNotifyLeak", func_RegNotifyLeak },
    { "RegLoadKeyBadBinSize", func_RegLoadKeyBadBinSize },
    { "RegLoadKeyBadSecondBin", func_RegLoadKeyBadSecondBin },
    { "RegLoadKeyUnloadPool", func_RegLoadKeyUnloadPool },
    { "RegLoadKeyZeroBin", func_RegLoadKeyZeroBin },
    { "RegLoadKeyZeroCell", func_RegLoadKeyZeroCell },
    { "RegQueryInfoKey", func_RegQueryInfoKey },
    { "RegOpenKeyExW", func_RegOpenKeyExW },
    { "PerfProvider", func_PerfProvider },
    { "RegPerformanceData", func_RegPerformanceData },
    { "InitiateShutdown", func_InitiateShutdown },
    { "RegQueryValueExW", func_RegQueryValueExW },
    { "RegQueryMultipleValues", func_RegQueryMultipleValues },
    { "RegKeyNameCase", func_RegKeyNameCase },
    { "RegRenameKey", func_RegRenameKey },
    { "RegRenameKeyPersist", func_RegRenameKeyPersist },
    { "RegRenameKeyStress", func_RegRenameKeyStress },
    { "RegGetValue", func_RegGetValue },
    { "RegSdTemplates", func_RegSdTemplates },
    { "RegSecurityDump", func_RegSecurityDump },
    { "RegSecurityDefaultSd", func_RegSecurityDefaultSd },
    { "RegSecurityAccess", func_RegSecurityAccess },
    { "RegSecurityMapping", func_RegSecurityMapping },
    { "RegSecurityRoundTrip", func_RegSecurityRoundTrip },
    { "RegSecurityCreate", func_RegSecurityCreate },
    { "RegSharedKeyName", func_RegSharedKeyName },
    { "RestrictedSidsCopy", func_RestrictedSidsCopy },
    { "RestrictedTokenAccess", func_RestrictedTokenAccess },
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
    { "ServiceSid", func_ServiceSid },
    { "ServiceVirtualAccount", func_ServiceVirtualAccount },
    { "ServiceNetwork", func_ServiceNetwork },
    { "SetEntriesInAclOld", func_SetEntriesInAclOld },
    { "SetSecurityInfoKey", func_SetSecurityInfoKey },
    { "SetNamedSecurityInfoInherit", func_SetNamedSecurityInfoInherit },
    { "SddlRights", func_SddlRights },
    { "SddlSids", func_SddlSids },
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

