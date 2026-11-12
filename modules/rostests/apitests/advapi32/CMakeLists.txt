
list(APPEND SOURCE
    AccessCheckObjectTypeList.c
    AddMandatoryAce.c
    AuditCategories.c
    CveEventWrite.c
    DynamicTimeZone.c
    BuildSecurityDescriptor.c
    NamedPipeSD.c
    ConvertStringSidToSid.c
    RegWow64.c
    RegWow64Review.c
    RegWow64RelativeView.c
    RestrictedSidsCopy.c
    RestrictedTokenAccess.c
    CreateService.c
    CreateProcessAsUserToken.c
    CreateProcessWithLogon.c
    CreateEnvironmentBlockProfile.c
    CloseTrace.c
    DuplicateTokenEx.c
    EnableTraceEx2.c
    EncryptFile.c
    eventlog.c
    EventRegister.c
    EventProvider.c
    EventSetInformation.c
    GetSecurityInfoSequence.c
    ObjectLockStress.c
    Hash.c
    HKEY_CLASSES_ROOT.c
    IsTextUnicode.c
    LockServiceDatabase.c
    LookupAccountSidCaller.c
    LogonUser.c
    LogonUserCleartext.c
    LogonUserServiceSecret.c
    LogonUserUserRights.c
    LsaLookupLeak.c
    LsaLookupNamesUnmapped.c
    LsassLeak.c
    LsaLogonUserS4U.c
    LsaManageSidNameMapping.c
    ProcessThreadLabel.c
    QueryServiceConfig.c
    QueryServiceConfig2.c
    QueryServiceObjectSecurity.c
    RegConcurrentWrite.c
    RegCreateKeyEx.c
    RegCreateKeyTransacted.c
    RegDeleteTreeOpenHandles.c
    RegEnumKey.c
    RegEnumKeyClass.c
    RegEnumValueW.c
    RegValueLookup.c
    RegFlushKey.c
    RegNotifyChangeKeyValue.c
    RegNotifyLeak.c
    RegLoadKey.c
    RegOpenKeyExW.c
    RegPerformanceData.c
    InitiateShutdown.c
    RegQueryInfoKey.c
    RegQueryValueExW.c
    RegKeyNameCase.c
    RegRenameKey.c
    RegSecurity.c
    RegGetValue.c
    RtlEncryptMemory.c
    SaferIdentifyLevel.c
    TokenDefaultDacl.c
    TokenElevation.c
    TokenIntegrity.c
    TokenLogonSid.c
    TokenQueryParity.c
    ServiceArgs.c
    ServiceControllerQuery.c
    ServiceEnv.c
    ServiceFailureActions.c
    ServiceRecovery.c
    ServiceSid.c
    ServiceNetwork.c
    SetEntriesInAclOld.c
    SetSecurityInfoKey.c
    SetNamedSecurityInfoInherit.c
    SddlRights.c
    SddlSids.c
    ServiceProcess.c
    PerfCounterValues.c
    PerfProvider.c
    ServiceStructLayout.c
    ServiceTriggerPrivileges.c
    SecurityAccessMask.c
    Win10Exports.c
    ControlServiceEx.c
    LsaLookupSids2.c
    svchlp.c)

list(APPEND PCH_SKIP_SOURCE
    Saferi.c
    testlist.c)

add_executable(advapi32_apitest
    ${SOURCE}
    ${PCH_SKIP_SOURCE})

target_link_libraries(advapi32_apitest wine ${PSEH_LIB})
set_module_type(advapi32_apitest win32cui)
add_importlibs(advapi32_apitest advapi32 user32 iphlpapi ws2_32 netapi32 userenv msvcrt kernel32 ntdll)
add_pch(advapi32_apitest precomp.h "${PCH_SKIP_SOURCE}")
add_rostests_file(TARGET advapi32_apitest)
