
add_subdirectory(load_notifications)
add_subdirectory(empty_dll)
add_subdirectory(crtkeydtor)
add_subdirectory(apiset_win10)

include_directories($<TARGET_FILE_DIR:load_notifications>)
include_directories($<TARGET_FILE_DIR:empty_dll>)
include_directories($<TARGET_FILE_DIR:crtkeydtor>)
spec2def(ntdll_apitest.exe ntdll_apitest.spec)

list(APPEND SOURCE_CRT_TESTS
    ../crt/_snprintf.c
    ../crt/_snwprintf.c
    ../crt/_stricmp.c
    ../crt/_strlwr.c
    ../crt/_strnicmp.c
    ../crt/_strupr.c
    ../crt/_vscwprintf.c
    ../crt/_vsnprintf.c
    ../crt/_vsnwprintf.c
    ../crt/_wcsicmp.c
    ../crt/_wcslwr.c
    ../crt/_wcsnicmp.c
    ../crt/_wcsupr.c
    ../crt/mbstowcs.c
    ../crt/setjmp.c
    ../crt/sprintf.c
    ../crt/strcpy.c
    ../crt/strlen.c
    ../crt/strtoul.c
    ../crt/wcstombs.c
    ../crt/wcstoul.c
)

add_library(ntdll_crt_test_lib ${SOURCE_CRT_TESTS})
target_compile_definitions(ntdll_crt_test_lib PRIVATE TEST_NTDLL TEST_DLL_NAME="ntdll.dll")
target_link_libraries(ntdll_crt_test_lib ${PSEH_LIB})
add_dependencies(ntdll_crt_test_lib psdk)

list(APPEND SOURCE
    CrtSecure.c
    RtlBitmapRanges.c
    RtlFlsValue.c
    RtlUtf8String.c
    RtlWin10Helpers.c
    ZeroBits.c
    CommitCharge.c
    RtlCurrentTransaction.c
    CreatorAccess.c
    DllLoadNotification.c
    EmptyPxe.c
    ApiSetQueryApiSetPresence.c
    LdrEnumResources.c
    LdrFindResource_U.c
    LdrLoadDll.c
    LdrShutdownThread.c
    load_notifications.c
    locale.c
    LpcCallbackRequest.c
    MxCsrMask.c
    NtAcceptConnectPort.c
    NtAccessCheck.c
    NtAccessCheckByType.c
    NtAccessCheckByTypeResultList.c
    NtAccessCheckByTypeResultListAndAuditAlarmByHandle.c
    NtAdjustGroupsToken.c
    NtAdjustPrivilegesToken.c
    NtAllocateVirtualMemory.c
    NtApphelpCacheControl.c
    NtCompareTokens.c
    NtConnectPortTerminate.c
    NtContinue.c
    Wow64Continue.c
    Wow64ServiceArguments.c
    NtCreateDirectoryObject.c
    NtCreateFile.c
    NtCreateKey.c
    NtCreateProfile.c
    NtCreateSectionImage.c
    NtCreateSectionSize.c
    NtCreateThread.c
    NtDeleteKey.c
    NtDelayExecution.c
    NtDuplicateObject.c
    NtDuplicateToken.c
    NtExtendSection.c
    NtFilterToken.c
    NtFreeVirtualMemory.c
    NtGetCurrentProcessorNumberEx.c
    NtGetNextThread.c
    NtImpersonateAnonymousToken.c
    NtKeyedEvent.c
    NtLoadUnloadKey.c
    NtMapViewOfSection.c
    NtMutant.c
    NtNotifyChangeDirectoryFile.c
    NtNotifyChangeMultipleKeys.c
    NtOpenKey.c
    NtOpenKeyEx.c
    NtOpenProcess.c
    NtOpenProcessToken.c
    NtOpenThreadToken.c
    NtProtectVirtualMemory.c
    NtQueryDirectoryFile.c
    DefineDosDevice.c
    NtFlushBuffersFile.c
    NtFsControlFilePipe.c
    NtFlushVirtualMemory.c
    NtEaFile.c
    VolumeControlCodes.c
    NtQueryInformationFile.c
    NtQueryInformationProcess.c
    NtQueryInformationThread.c
    NtQueryInformationToken.c
    NtQueryKey.c
    NtQueryObject.c
    NtQueryOpenSubKeys.c
    NtQuerySecurityObject.c
    NtQuerySection.c
    NtQuerySystemEnvironmentValue.c
    NtQuerySystemInformation.c
    NtQuerySystemProcessorPerformance.c
    NtQuerySystemProcessInformationTail.c
    NtQueryValueKey.c
    NtQueryVirtualMemory.c
    NtQueryVolumeInformationFile.c
    NtRaiseHardErrorMode.c
    NtReadFile.c
    NtSaveKey.c
    NtSetDefaultLocale.c
    NtSetInformationDebugObject.c
    NtSetInformationFile.c
    NtSetInformationProcess.c
    NtSetInformationThread.c
    NtSetInformationToken.c
    NtSetLdtEntries.c
    NtSetValueKey.c
    NtSetVolumeInformationFile.c
    NtStartProfile.c
    NtUnloadDriver.c
    NtWriteFile.c
    probelib.c
    RtlAllocateHeap.c
    RtlBitmap.c
    RtlComputePrivatizedDllName_U.c
    RtlConditionVariable.c
    RtlCopyMappedMemory.c
    RtlCriticalSection.c
    RtlCriticalSectionRace.c
    RtlDebugInformation.c
    RtlDeleteAce.c
    RtlDetermineDosPathNameType.c
    RtlDoesFileExists.c
    RtlDosApplyFileIsolationRedirection_Ustr.c
    RtlDosApplyFileIsolationRedirection_LoadFrom.c
    RtlDosPathNameToNtPathName_U.c
    RtlDosSearchPath_U.c
    RtlDosSearchPath_Ustr.c
    RtlFailFast.c
    RtlFirstFreeAce.c
    RtlFindMessage.c
    RtlFls.c
    RtlGenerate8dot3Name.c
    RtlGenericTable.c
    RtlGetFullPathName_U.c
    RtlGetFullPathName_Ustr.c
    RtlGetFullPathName_UstrEx.c
    RtlGetLengthWithoutLastFullDosOrNtPathElement.c
    RtlGetLengthWithoutTrailingPathSeperators.c
    RtlGetLongestNtPathLength.c
    RtlGetNtProductType.c
    RtlGrowableFunctionTable.c
    RtlGetProcessHeaps.c
    RtlGetProductInfo.c
    RtlGetUnloadEventTrace.c
    RtlPlaceholderCompatibilityMode.c
    RtlHandle.c
    RtlHeapTailCheck.c
    RtlImageDirectoryEntryToData.c
    RtlImageRvaToVa.c
    RtlInitializeContext.c
    RtlInitializeSidEx.c
    RtlInitializeNtUserPfn.c
    RtlIsNameInExpression.c
    RtlIsEcCode.c
    RtlIsNameLegalDOS8Dot3.c
    RtlLocale.c
    RtlMemIoResource.c
    RtlMemoryStream.c
    RtlMultipleAllocateHeap.c
    RtlNtPathNameToDosPathName.c
    RtlpApplyLengthFunction.c
    RtlpEnsureBufferSize.c
    RtlQueryEnvironmentVariable.c
    RtlQueryEnvironmentVariable_U.c
    RtlQueryProcessDebugModules.c
    RtlQueryRegistryValues.c
    RtlDeriveCapabilitySidsFromName.c
    RtlQueryPerformanceCounter.c
    RtlQueryTimeZoneInfo.c
    RtlSetTimeZoneInformation.c
    RtlReAllocateHeap.c
    RtlRemovePrivileges.c
    RtlSRWLock.c
    RtlSRWLockStress.c
    RtlSRWLockThroughput.c
    RtlSRWLockWait.c
    RtlRetrieveNtUserPfn.c
    RtlUnhandledExceptionFilter.c
    RtlUnwindExConsolidate.c
    RtlVerifyVersionInfo.c
    RtlUnicodeStringToAnsiString.c
    RtlUnicodeStringToCountedOemString.c
    RtlUnicodeToOemN.c
    RtlUnwindIndirect.c
    RtlUTF8.c
    RtlUpcaseUnicodeStringToCountedOemString.c
    RtlValidateUnicodeString.c
    SectionFaultCost.c
    SectionPageLeak.c
    strcpy_s.c
    RtlWaitOnAddress.c
    RtlWow64GetProcessMachines.c
    RtlxUnicodeStringToAnsiSize.c
    RtlxUnicodeStringToOemSize.c
    BadSegmentFault.c
    RaiseExceptionLeak.c
    ExceptionInfoLeak.c
    StackOverflow.c
    StackOverflowDispatch.c
    SystemCallStubs.c
    SystemDllTls.c
    SystemInfo.c
    UserModeException.c
    Timer.c
    precomp.h)

if(ARCH STREQUAL "i386")
    add_asm_files(ntdll_apitest_asm
        ../crt/i386/setjmp_helper.s
        i386/NtContinue.S
        i386/Wow64Continue.S
        i386/NtCreateThread.S
        i386/StackOverflowDispatch.S
    )
elseif(ARCH STREQUAL "amd64")
    add_asm_files(ntdll_apitest_asm
        ../crt/amd64/setjmp_helper.s
        amd64/NtContinue.S
        amd64/Wow64Continue.S
        amd64/NtCreateThread.S
        amd64/StackOverflowDispatch.S
        amd64/BadSegmentFault.S
        amd64/RtlUnwindExConsolidate.S
    )
    if(NOT MSVC)
        # Hand-written unwind data in GAS syntax
        list(APPEND ntdll_apitest_asm amd64/RtlUnwindIndirect.S)
    endif()
endif()

list(APPEND PCH_SKIP_SOURCE
    testlist.c)

# One call: add_rc_deps replaces the list
add_rc_deps(testdata.rc
    ${CMAKE_CURRENT_BINARY_DIR}/load_notifications/load_notifications.dll
    ${CMAKE_CURRENT_BINARY_DIR}/empty_dll/empty_dll.dll
    ${CMAKE_CURRENT_BINARY_DIR}/crtkeydtor/crtkeydtor.dll
    ${CMAKE_CURRENT_BINARY_DIR}/crtkeydtor/crtkeydtor_static.exe
    ${CMAKE_CURRENT_BINARY_DIR}/crtkeydtor/crtkeydtor_tls.dll
    ${CMAKE_CURRENT_BINARY_DIR}/crtkeydtor/crtkeydtor_tls_static.exe)

add_executable(ntdll_apitest
    ${SOURCE}
    ${ntdll_apitest_asm}
    ${PCH_SKIP_SOURCE}
    testdata.rc
    ${CMAKE_CURRENT_BINARY_DIR}/ntdll_apitest.def)
add_pch(ntdll_apitest precomp.h "${PCH_SKIP_SOURCE}")

target_include_directories(ntdll_apitest PRIVATE ${REACTOS_SOURCE_DIR}/ntoskrnl/include)

if(NOT MSVC)
    set_source_files_properties(
        RtlGetFullPathName_UstrEx.c
        RtlLocale.c
        PROPERTIES COMPILE_OPTIONS "-Wno-format")
endif()

set_target_properties(ntdll_apitest
    PROPERTIES
    ENABLE_EXPORTS TRUE
    DEFINE_SYMBOL "")

target_link_libraries(ntdll_apitest ntdll_crt_test_lib rtl_test_lib wine uuid ${PSEH_LIB})
set_module_type(ntdll_apitest win32cui)
add_delay_importlibs(ntdll_apitest advapi32)
add_importlibs(ntdll_apitest msvcrt kernel32 ntdll)
add_dependencies(ntdll_apitest load_notifications empty_dll crtkeydtor crtkeydtor_static crtkeydtor_tls crtkeydtor_tls_static)

add_rostests_file(TARGET ntdll_apitest)
add_rostests_file(TARGET ntdll_apitest SUBDIR testdata)
# These are empty files
add_rostests_file(FILE "${CMAKE_CURRENT_SOURCE_DIR}/ntdll_apitest.exe.local" SUBDIR testdata)
add_rostests_file(FILE "${CMAKE_CURRENT_SOURCE_DIR}/shell32.dll" SUBDIR testdata)
# add_rostests_file(FILE "${CMAKE_CURRENT_SOURCE_DIR}/test.dll" SUBDIR testdata)
add_rostests_file(FILE "${CMAKE_CURRENT_SOURCE_DIR}/ntdlltest.manifest" SUBDIR testdata)
add_rostests_file(FILE "${CMAKE_CURRENT_SOURCE_DIR}/fil1.txt" SUBDIR testdata)

# Convenience target for running from IDE
if(MSVC_IDE)
    set(NTDLL_APITEST_DATADIR $<TARGET_FILE_DIR:ntdll_apitest>/testdata/)
    add_custom_command(TARGET ntdll_apitest
                       POST_BUILD
                       COMMAND "${CMAKE_COMMAND}" -E make_directory ${NTDLL_APITEST_DATADIR}
                       COMMAND "${CMAKE_COMMAND}" -E copy $<TARGET_FILE:ntdll_apitest> ${NTDLL_APITEST_DATADIR}
                       COMMAND "${CMAKE_COMMAND}" -E copy ntdll_apitest.exe.local ${NTDLL_APITEST_DATADIR}
                       COMMAND "${CMAKE_COMMAND}" -E copy shell32.dll ${NTDLL_APITEST_DATADIR}
                       COMMAND "${CMAKE_COMMAND}" -E copy test.dll ${NTDLL_APITEST_DATADIR}
                       COMMAND "${CMAKE_COMMAND}" -E copy ntdlltest.manifest ${NTDLL_APITEST_DATADIR}
                       COMMAND "${CMAKE_COMMAND}" -E copy fil1.txt ${NTDLL_APITEST_DATADIR}
                       WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
endif()
