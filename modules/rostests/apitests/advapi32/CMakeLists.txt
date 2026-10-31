
list(APPEND SOURCE
    AddMandatoryAce.c
    BuildSecurityDescriptor.c
    NamedPipeSD.c
    ConvertStringSidToSid.c
    RegWow64.c
    RegWow64Review.c
    RegWow64RelativeView.c
    RestrictedSidsCopy.c
    CreateService.c
    CreateProcessAsUserToken.c
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
    RegFlushKey.c
    RegNotifyChangeKeyValue.c
    RegLoadKey.c
    RegOpenKeyExW.c
    RegPerformanceData.c
    RegQueryInfoKey.c
    RegQueryValueExW.c
    RegKeyNameCase.c
    RegRenameKey.c
    RegGetValue.c
    RtlEncryptMemory.c
    SaferIdentifyLevel.c
    TokenDefaultDacl.c
    TokenElevation.c
    TokenIntegrity.c
    TokenLogonSid.c
    ServiceArgs.c
    ServiceControllerQuery.c
    ServiceEnv.c
    ServiceFailureActions.c
    ServiceRecovery.c
    ServiceNetwork.c
    SetEntriesInAclOld.c
    SetSecurityInfoKey.c
    SetNamedSecurityInfoInherit.c
    SddlRights.c
    ServiceProcess.c
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
add_importlibs(advapi32_apitest advapi32 iphlpapi ws2_32 netapi32 userenv msvcrt kernel32 ntdll)
add_pch(advapi32_apitest precomp.h "${PCH_SKIP_SOURCE}")
add_rostests_file(TARGET advapi32_apitest)
