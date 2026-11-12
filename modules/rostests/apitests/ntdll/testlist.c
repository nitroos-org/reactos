
#define STANDALONE
#include <apitest.h>

extern void func_ZeroBits(void);

extern void func__snprintf(void);
extern void func__snwprintf(void);
extern void func__stricmp(void);
extern void func__strlwr(void);
extern void func__strnicmp(void);
extern void func__strupr(void);
extern void func__vscwprintf(void);
extern void func__vsnprintf(void);
extern void func__vsnwprintf(void);
extern void func__wcsicmp(void);
extern void func__wcslwr(void);
extern void func__wcsnicmp(void);
extern void func__wcsupr(void);
extern void func_mbstowcs(void);
extern void func_setjmp(void);
extern void func_sprintf(void);
extern void func_strcpy(void);
extern void func_strlen(void);
extern void func_strtoul(void);
extern void func_wcstoul(void);
extern void func_wcstombs(void);

extern void func_CommitCharge(void);
extern void func_CommitStress(void);
extern void func_RtlCurrentTransaction(void);
extern void func_CreatorAccess(void);
extern void func_DllLoadNotification(void);
extern void func_EmptyPxeFree(void);
extern void func_EmptyPxeProtect(void);
extern void func_ApiSetQueryApiSetPresence(void);
extern void func_CrtSecure(void);
extern void func_LdrEnumResources(void);
extern void func_LdrFindResource_U(void);
extern void func_LdrGetDllHandleEx(void);
extern void func_LdrLoadDll(void);
extern void func_LdrSharedReadOnlySection(void);
extern void func_LdrShutdownThread(void);
extern void func_load_notifications(void);
extern void func_LpcCallbackRequest(void);
extern void func_MxCsrMask(void);
extern void func_NtAcceptConnectPort(void);
extern void func_NtAccessCheck(void);
extern void func_NtAccessCheckByType(void);
extern void func_NtAccessCheckByTypeResultList(void);
extern void func_NtAccessCheckByTypeResultListAndAuditAlarmByHandle(void);
extern void func_NtAdjustGroupsToken(void);
extern void func_NtAdjustPrivilegesToken(void);
extern void func_NtAllocateVirtualMemory(void);
extern void func_NtApphelpCacheControl(void);
extern void func_NtCompareTokens(void);
extern void func_NtConnectPortTerminate(void);
extern void func_ContextExceptionRequest(void);
extern void func_NtContinue(void);
extern void func_ThreadDebugRegisters(void);
extern void func_ThreadLockStress(void);
extern void func_RtlBitmapRanges(void);
extern void func_RtlFlsValue(void);
extern void func_RtlUtf8String(void);
extern void func_RtlWin10Helpers(void);
extern void func_RtlConvertDeviceFamilyInfo(void);
extern void func_Wow64Continue(void);
extern void func_Wow64ServiceArguments(void);
extern void func_Wow64FloatState(void);
extern void func_Wow64QuerySystemTime(void);
extern void func_NtCreateDirectoryObject(void);
extern void func_NtCreateFile(void);
extern void func_NtCreateKey(void);
extern void func_NtCreateLowBoxToken(void);
extern void func_NtCreateProfile(void);
extern void func_NtCreateSectionImage(void);
extern void func_NtCreateSectionSize(void);
extern void func_NtCreateThread(void);
extern void func_NtCreateTimer2(void);
extern void func_NtGetNextThread(void);
extern void func_NtDeleteKey(void);
extern void func_NtDelayExecution(void);
extern void func_NtDuplicateObject(void);
extern void func_NtDuplicateToken(void);
extern void func_NtExtendSection(void);
extern void func_NtFilterToken(void);
extern void func_NtFreeVirtualMemory(void);
extern void func_NtImpersonateAnonymousToken(void);
extern void func_NtKeyedEvent(void);
extern void func_NtLoadUnloadKey(void);
extern void func_NtMapViewOfSection(void);
extern void func_NtMutant(void);
extern void func_NtNotifyChangeDirectoryFile(void);
extern void func_NtNotifyChangeMultipleKeys(void);
extern void func_NtOpenKey(void);
extern void func_NtOpenKeyConcurrent(void);
extern void func_NtOpenKeyEx(void);
extern void func_NtOpenProcess(void);
extern void func_NtOpenProcessProtected(void);
extern void func_NtOpenProcessToken(void);
extern void func_NtOpenSection(void);
extern void func_NtOpenThreadToken(void);
extern void func_NtProtectVirtualMemory(void);
extern void func_NtQueryDirectoryFile(void);
extern void func_DefineDosDevice(void);
extern void func_NtFlushBuffersFile(void);
extern void func_NtFsControlFilePipe(void);
extern void func_NtFlushVirtualMemory(void);
extern void func_NtEaFile(void);
extern void func_VolumeControlCodes(void);
extern void func_IoctlAllowlist(void);
extern void func_ScsiPassThrough(void);
extern void func_NtQueryInformationFile(void);
extern void func_NtQueryInformationProcess(void);
extern void func_NtQueryInformationThread(void);
extern void func_NtQueryInformationToken(void);
extern void func_NtQueryKey(void);
extern void func_NtSetInformationKey(void);
extern void func_NtQueryObject(void);
extern void func_NtQueryOpenSubKeys(void);
extern void func_NtQueryWnfStateData(void);
extern void func_NtAlertThreadByThreadId(void);
extern void func_NtAllocateReserveObject(void);
extern void func_NtWaitCompletionPacket(void);
extern void func_NtSetIoCompletionEx(void);
extern void func_NtQueryObjectHandleFlags(void);
extern void func_NtOpenKeyTransacted(void);
extern void func_NtQuerySecurityObject(void);
extern void func_NtQuerySection(void);
extern void func_NtQuerySystemEnvironmentValue(void);
extern void func_NtQuerySystemInformation(void);
extern void func_NtQuerySystemTime(void);
extern void func_NtQuerySystemProcessorPerformance(void);
extern void func_NtQuerySystemProcessInformationTail(void);
extern void func_NtQueryValueKey(void);
extern void func_NtQueryVirtualMemory(void);
extern void func_NtQueryVirtualMemoryRegion(void);
extern void func_NtQueryVolumeInformationFile(void);
extern void func_NtRaiseHardErrorMode(void);
extern void func_NtReadFile(void);
extern void func_NtSaveKey(void);
extern void func_NtSaveMergedKeys(void);
extern void func_NtSetDefaultLocale(void);
extern void func_NtSetInformationDebugObject(void);
extern void func_NtSetInformationFile(void);
extern void func_NtSetInformationProcess(void);
extern void func_NtSetInformationThread(void);
extern void func_NtSetInformationToken(void);
extern void func_NtTokenPseudoHandles(void);
extern void func_NtTokenQueryParity(void);
extern void func_NtSetLdtEntries(void);
extern void func_NtSetValueKey(void);
extern void func_NtSetVolumeInformationFile(void);
extern void func_NtStartProfile(void);
extern void func_NtSystemInformation(void);
extern void func_NtUnloadDriver(void);
extern void func_NtWriteFile(void);
extern void func_PagerBasic(void);
extern void func_RtlAllocateHeap(void);
extern void func_RtlBitmapApi(void);
extern void func_RtlCaptureContext(void);
extern void func_RtlComputePrivatizedDllName_U(void);
extern void func_RtlConditionVariable(void);
extern void func_RtlCopyMappedMemory(void);
extern void func_RtlCriticalSection(void);
extern void func_RtlCriticalSectionRace(void);
extern void func_RtlDebugInformation(void);
extern void func_RtlDeleteAce(void);
extern void func_RtlDetermineDosPathNameType(void);
extern void func_RtlDosApplyFileIsolationRedirection_Ustr(void);
extern void func_RtlDosApplyFileIsolationRedirection_LoadFrom(void);
extern void func_RtlDoesFileExists(void);
extern void func_RtlDosPathNameToNtPathName_U(void);
extern void func_RtlDosSearchPath_U(void);
extern void func_RtlDosSearchPath_Ustr(void);
extern void func_RtlFailFast(void);
extern void func_RtlFirstFreeAce(void);
extern void func_RtlFindMessage(void);
extern void func_RtlGenerate8dot3Name(void);
extern void func_RtlGenericTable(void);
extern void func_RtlGetFullPathName_U(void);
extern void func_RtlGetFullPathName_Ustr(void);
extern void func_RtlGetFullPathName_UstrEx(void);
extern void func_RtlGetLengthWithoutLastFullDosOrNtPathElement(void);
extern void func_RtlGetLengthWithoutTrailingPathSeperators(void);
extern void func_RtlGetLongestNtPathLength(void);
extern void func_RtlGetNtProductType(void);
extern void func_RtlGetProcessHeaps(void);
extern void func_RtlGrowableFunctionTable(void);
extern void func_RtlGetProductInfo(void);
extern void func_RtlGetUnloadEventTrace(void);
extern void func_RtlPlaceholderCompatibilityMode(void);
extern void func_RtlHandle(void);
extern void func_RtlHeapFrontEnd(void);
extern void func_RtlHeapTailCheck(void);
extern void func_RtlImageDirectoryEntryToData(void);
extern void func_RtlImageRvaToVa(void);
extern void func_RtlInitializeNtUserPfn(void);
extern void func_RtlRetrieveNtUserPfn(void);
extern void func_RtlInitializeSidEx(void);
extern void func_RtlIntSafe(void);
extern void func_RtlIsNameInExpression(void);
extern void func_RtlIsEcCode(void);
extern void func_RtlIsNameLegalDOS8Dot3(void);
extern void func_RtlLocale(void);
extern void func_RtlMemIoResource(void);
extern void func_RtlMemoryStream(void);
extern void func_RtlMultipleAllocateHeap(void);
extern void func_RtlNtPathNameToDosPathName(void);
extern void func_RtlNtStatusToDosError(void);
extern void func_RtlpApplyLengthFunction(void);
extern void func_RtlpEnsureBufferSize(void);
extern void func_RtlQueryEnvironmentVariable(void);
extern void func_RtlQueryEnvironmentVariable_U(void);
extern void func_RtlQueryProcessDebugModules(void);
extern void func_RtlQueryRegistryValues(void);
extern void func_RtlDeriveCapabilitySidsFromName(void);
extern void func_RtlQueryPerformanceCounter(void);
extern void func_RtlQueryTimeZoneInformation(void);
extern void func_RtlSetTimeZoneInformation(void);
extern void func_RtlReAllocateHeap(void);
extern void func_RtlRemovePrivileges(void);
extern void func_RtlSRWLock(void);
extern void func_RtlSRWLockStress(void);
extern void func_RtlSRWLockThroughput(void);
extern void func_RtlSRWLockWait(void);
extern void func_RtlUnhandledExceptionFilter(void);
extern void func_RtlUnwindExConsolidate(void);
extern void func_RtlUnicodeStringToAnsiString(void);
extern void func_RtlUnicodeStringToCountedOemString(void);
extern void func_RtlUnicodeToOemN(void);
extern void func_RtlUnwindIndirect(void);
extern void func_RtlUTF8(void);
extern void func_RtlUnwind(void);
extern void func_RtlUnwindEx(void);
extern void func_RtlUpcaseUnicodeStringToCountedOemString(void);
extern void func_RtlValidateUnicodeString(void);
extern void func_RtlStringSdBounds(void);
extern void func_RtlVerifyVersionInfo(void);
extern void func_RtlWaitOnAddress(void);
extern void func_RtlVirtualUnwind(void);
extern void func_RtlxUnicodeStringToAnsiSize(void);
extern void func_RtlxUnicodeStringToOemSize(void);
extern void func_FaultContext(void);
extern void func_PageFaultAddress(void);
extern void func_SectionFaultCost(void);
extern void func_SectionPageLeak(void);
extern void func_SectionVirtualLockLeak(void);
extern void func_StackDeepRecursion(void);
extern void func_BadSegmentFault(void);
extern void func_ExceptionInfoLeak(void);
extern void func_X87Fault(void);
extern void func_RaiseExceptionLeak(void);
extern void func_StackOverflow(void);
extern void func_StackOverflowThread(void);
extern void func_SystemCallStubs(void);
extern void func_strcpy_s(void);
extern void func_SystemDllTls(void);
extern void func_TimerResolution(void);
extern void func_UserModeException(void);
extern void func_VectoredHandlerChurn(void);
extern void func_ModuleRangeTable(void);
extern void func_StackOverflowDispatch(void);
extern void func_NtFlushBuffersFileEx(void);
extern void func_NtGetCurrentProcessorNumberEx(void);
extern void func_RtlCrc64(void);
extern void func_RtlExtractBitMap(void);
extern void func_RtlFls(void);
extern void func_RtlGetPreciseTime(void);
extern void func_RtlInitializeContext(void);
extern void func_RtlWow64GetProcessMachines(void);
extern void func_ZwQuerySystemInformationEx(void);

const struct test winetest_testlist[] =
{
    { "ZeroBits", func_ZeroBits },
    // CRT tests from ../crt
    { "_snprintf", func__snprintf },
    { "_snwprintf", func__snwprintf },
    { "_stricmp", func__stricmp },
    { "_strlwr", func__strlwr },
    { "_strnicmp", func__strnicmp },
    { "_strupr", func__strupr },
    { "_vscwprintf", func__vscwprintf },
    { "_vsnprintf", func__vsnprintf },
    { "_vsnwprintf", func__vsnwprintf },
    { "_wcsicmp", func__wcsicmp },
    { "_wcslwr", func__wcslwr },
    { "_wcsnicmp", func__wcsnicmp },
    { "_wcsupr", func__wcsupr },
    { "mbstowcs", func_mbstowcs },
    { "setjmp", func_setjmp },
    { "sprintf", func_sprintf },
    { "strcpy", func_strcpy },
    { "strlen", func_strlen },
    { "strtoul", func_strtoul },
    { "wcstoul", func_wcstoul },
    { "wcstombs", func_wcstombs },

    { "CommitCharge",                   func_CommitCharge },
    { "CommitStress",                   func_CommitStress },
    { "RtlCurrentTransaction",          func_RtlCurrentTransaction },
    { "CreatorAccess",                  func_CreatorAccess },
    { "DllLoadNotification",            func_DllLoadNotification },
    { "EmptyPxeFree",                   func_EmptyPxeFree },
    { "EmptyPxeProtect",                func_EmptyPxeProtect },
    { "ApiSetQueryApiSetPresence",     func_ApiSetQueryApiSetPresence },
    { "CrtSecure",                      func_CrtSecure },
    { "LdrEnumResources",               func_LdrEnumResources },
    { "LdrFindResource_U",              func_LdrFindResource_U },
    { "LdrGetDllHandleEx",             func_LdrGetDllHandleEx },
    { "LdrLoadDll",                     func_LdrLoadDll },
    { "LdrSharedReadOnlySection",      func_LdrSharedReadOnlySection },
    { "LdrShutdownThread",              func_LdrShutdownThread },
    { "load_notifications",             func_load_notifications },
    { "LpcCallbackRequest",             func_LpcCallbackRequest },
    { "MxCsrMask",                      func_MxCsrMask },
    { "NtAcceptConnectPort",            func_NtAcceptConnectPort },
    { "NtAccessCheck",                  func_NtAccessCheck },
    { "NtAccessCheckByType",            func_NtAccessCheckByType },
    { "NtAccessCheckByTypeResultList",  func_NtAccessCheckByTypeResultList },
    { "NtAccessCheckByTypeResultListAndAuditAlarmByHandle", func_NtAccessCheckByTypeResultListAndAuditAlarmByHandle },
    { "NtAdjustGroupsToken",            func_NtAdjustGroupsToken },
    { "NtAdjustPrivilegesToken",        func_NtAdjustPrivilegesToken },
    { "NtAllocateVirtualMemory",        func_NtAllocateVirtualMemory },
    { "NtApphelpCacheControl",          func_NtApphelpCacheControl },
    { "NtCompareTokens",                func_NtCompareTokens },
    { "NtConnectPortTerminate",         func_NtConnectPortTerminate },
    { "ContextExceptionRequest",       func_ContextExceptionRequest },
    { "NtContinue",                     func_NtContinue },
    { "ThreadDebugRegisters",           func_ThreadDebugRegisters },
    { "ThreadLockStress",               func_ThreadLockStress },
    { "RtlBitmapRanges",                func_RtlBitmapRanges },
    { "RtlFlsValue",                    func_RtlFlsValue },
    { "RtlUtf8String",                  func_RtlUtf8String },
    { "RtlWin10Helpers",                func_RtlWin10Helpers },
    { "RtlConvertDeviceFamilyInfo",     func_RtlConvertDeviceFamilyInfo },
    { "Wow64Continue",                  func_Wow64Continue },
    { "Wow64ServiceArguments",          func_Wow64ServiceArguments },
    { "Wow64FloatState",                func_Wow64FloatState },
    { "Wow64QuerySystemTime",           func_Wow64QuerySystemTime },
    { "NtCreateDirectoryObject",        func_NtCreateDirectoryObject },
    { "NtCreateFile",                   func_NtCreateFile },
    { "NtCreateKey",                    func_NtCreateKey },
    { "NtCreateLowBoxToken",            func_NtCreateLowBoxToken },
    { "NtCreateProfile",                func_NtCreateProfile },
    { "NtCreateSectionImage",           func_NtCreateSectionImage },
    { "NtCreateSectionSize",            func_NtCreateSectionSize },
    { "NtCreateThread",                 func_NtCreateThread },
    { "NtCreateTimer2",                 func_NtCreateTimer2 },
    { "NtGetNextThread",                func_NtGetNextThread },
    { "NtDeleteKey",                    func_NtDeleteKey },
    { "NtDelayExecution",               func_NtDelayExecution },
    { "NtDuplicateObject",              func_NtDuplicateObject },
    { "NtDuplicateToken",               func_NtDuplicateToken },
    { "NtExtendSection",                func_NtExtendSection },
    { "NtFilterToken",                  func_NtFilterToken },
    { "NtFreeVirtualMemory",            func_NtFreeVirtualMemory },
    { "NtImpersonateAnonymousToken",    func_NtImpersonateAnonymousToken },
    { "NtKeyedEvent",                   func_NtKeyedEvent },
    { "NtLoadUnloadKey",                func_NtLoadUnloadKey },
    { "NtMapViewOfSection",             func_NtMapViewOfSection },
    { "NtMutant",                       func_NtMutant },
    { "NtNotifyChangeDirectoryFile",    func_NtNotifyChangeDirectoryFile },
    { "NtNotifyChangeMultipleKeys",     func_NtNotifyChangeMultipleKeys },
    { "NtOpenKey",                      func_NtOpenKey },
    { "NtOpenKeyConcurrent",            func_NtOpenKeyConcurrent },
    { "NtOpenKeyEx",                    func_NtOpenKeyEx },
    { "NtOpenProcess",                  func_NtOpenProcess },
    { "NtOpenProcessProtected",         func_NtOpenProcessProtected },
    { "NtOpenProcessToken",             func_NtOpenProcessToken },
    { "NtOpenSection",                  func_NtOpenSection },
    { "NtOpenThreadToken",              func_NtOpenThreadToken },
    { "NtProtectVirtualMemory",         func_NtProtectVirtualMemory },
    { "NtQueryDirectoryFile",           func_NtQueryDirectoryFile },
    { "DefineDosDevice",                func_DefineDosDevice },
    { "NtFlushBuffersFile",             func_NtFlushBuffersFile },
    { "NtFsControlFilePipe",            func_NtFsControlFilePipe },
    { "NtFlushVirtualMemory",           func_NtFlushVirtualMemory },
    { "NtEaFile",                       func_NtEaFile },
    { "VolumeControlCodes",             func_VolumeControlCodes },
    { "IoctlAllowlist",                 func_IoctlAllowlist },
    { "ScsiPassThrough",                func_ScsiPassThrough },
    { "NtQueryInformationFile",         func_NtQueryInformationFile },
    { "NtQueryInformationProcess",      func_NtQueryInformationProcess },
    { "NtQueryInformationThread",       func_NtQueryInformationThread },
    { "NtQueryInformationToken",        func_NtQueryInformationToken },
    { "NtQueryKey",                     func_NtQueryKey },
    { "NtSetInformationKey",            func_NtSetInformationKey },
    { "NtQueryObject",                  func_NtQueryObject },
    { "NtQueryOpenSubKeys",             func_NtQueryOpenSubKeys },
    { "NtQueryWnfStateData",           func_NtQueryWnfStateData },
    { "NtAlertThreadByThreadId",       func_NtAlertThreadByThreadId },
    { "NtAllocateReserveObject",       func_NtAllocateReserveObject },
    { "NtWaitCompletionPacket",         func_NtWaitCompletionPacket },
    { "NtSetIoCompletionEx",            func_NtSetIoCompletionEx },
    { "NtQueryObjectHandleFlags",       func_NtQueryObjectHandleFlags },
    { "NtOpenKeyTransacted",           func_NtOpenKeyTransacted },
    { "NtQuerySecurityObject", func_NtQuerySecurityObject },
    { "NtQuerySection",                 func_NtQuerySection },
    { "NtQuerySystemEnvironmentValue",  func_NtQuerySystemEnvironmentValue },
    { "NtQuerySystemInformation",       func_NtQuerySystemInformation },
    { "NtQuerySystemTime",              func_NtQuerySystemTime },
    { "NtQuerySystemProcessorPerformance", func_NtQuerySystemProcessorPerformance },
    { "NtQuerySystemProcessInformationTail", func_NtQuerySystemProcessInformationTail },
    { "NtQueryValueKey",                func_NtQueryValueKey },
    { "NtQueryVirtualMemory",           func_NtQueryVirtualMemory },
    { "NtQueryVirtualMemoryRegion",     func_NtQueryVirtualMemoryRegion },
    { "NtQueryVolumeInformationFile",   func_NtQueryVolumeInformationFile },
    { "NtRaiseHardErrorMode",           func_NtRaiseHardErrorMode },
    { "NtReadFile",                     func_NtReadFile },
    { "NtSaveKey",                      func_NtSaveKey},
    { "NtSaveMergedKeys",               func_NtSaveMergedKeys },
    { "NtSetDefaultLocale",             func_NtSetDefaultLocale },
    { "NtSetInformationDebugObject",   func_NtSetInformationDebugObject },
    { "NtSetInformationFile",           func_NtSetInformationFile },
    { "NtSetInformationProcess",        func_NtSetInformationProcess },
    { "NtSetInformationThread",         func_NtSetInformationThread },
    { "NtSetInformationToken",          func_NtSetInformationToken },
    { "NtTokenPseudoHandles",          func_NtTokenPseudoHandles },
    { "NtTokenQueryParity",            func_NtTokenQueryParity },
    { "NtSetLdtEntries",                func_NtSetLdtEntries },
    { "NtSetValueKey",                  func_NtSetValueKey},
    { "NtSetVolumeInformationFile",     func_NtSetVolumeInformationFile },
    { "NtStartProfile",                 func_NtStartProfile },
    { "NtSystemInformation",            func_NtSystemInformation },
    { "NtUnloadDriver",                 func_NtUnloadDriver },
    { "NtWriteFile",                    func_NtWriteFile },
    { "PagerBasic",                     func_PagerBasic },
    { "RtlAllocateHeap",                func_RtlAllocateHeap },
    { "RtlBitmapApi",                   func_RtlBitmapApi },
    { "RtlComputePrivatizedDllName_U",  func_RtlComputePrivatizedDllName_U },
    { "RtlConditionVariable",           func_RtlConditionVariable },
    { "RtlCopyMappedMemory",            func_RtlCopyMappedMemory },
    { "RtlCriticalSection",             func_RtlCriticalSection },
    { "RtlCriticalSectionRace",         func_RtlCriticalSectionRace },
    { "RtlDebugInformation",            func_RtlDebugInformation },
    { "RtlDeleteAce",                   func_RtlDeleteAce },
    { "RtlDetermineDosPathNameType",    func_RtlDetermineDosPathNameType },
    { "RtlDosApplyFileIsolationRedirection_LoadFrom",
      func_RtlDosApplyFileIsolationRedirection_LoadFrom },
    { "RtlDosApplyFileIsolationRedirection_Ustr", func_RtlDosApplyFileIsolationRedirection_Ustr },
    { "RtlDoesFileExists",              func_RtlDoesFileExists },
    { "RtlDosPathNameToNtPathName_U",   func_RtlDosPathNameToNtPathName_U },
    { "RtlDosSearchPath_U",             func_RtlDosSearchPath_U },
    { "RtlDosSearchPath_Ustr",          func_RtlDosSearchPath_Ustr },
    { "RtlFailFast",                    func_RtlFailFast },
    { "RtlFirstFreeAce",                func_RtlFirstFreeAce },
    { "RtlFindMessage",                 func_RtlFindMessage },
    { "RtlGenerate8dot3Name",           func_RtlGenerate8dot3Name },
    { "RtlGenericTable",                func_RtlGenericTable },
    { "RtlGetFullPathName_U",           func_RtlGetFullPathName_U },
    { "RtlGetFullPathName_Ustr",        func_RtlGetFullPathName_Ustr },
    { "RtlGetFullPathName_UstrEx",      func_RtlGetFullPathName_UstrEx },
    { "RtlGetLengthWithoutLastFullDosOrNtPathElement", func_RtlGetLengthWithoutLastFullDosOrNtPathElement },
    { "RtlGetLengthWithoutTrailingPathSeperators", func_RtlGetLengthWithoutTrailingPathSeperators },
    { "RtlGetLongestNtPathLength",      func_RtlGetLongestNtPathLength },
    { "RtlGetNtProductType",            func_RtlGetNtProductType },
    { "RtlGetProcessHeaps",             func_RtlGetProcessHeaps },
    { "RtlGrowableFunctionTable",       func_RtlGrowableFunctionTable },
    { "RtlGetProductInfo",              func_RtlGetProductInfo },
    { "RtlGetUnloadEventTrace",         func_RtlGetUnloadEventTrace },
    { "RtlPlaceholderCompatibilityMode", func_RtlPlaceholderCompatibilityMode },
    { "RtlHandle",                      func_RtlHandle },
    { "RtlHeapFrontEnd",                func_RtlHeapFrontEnd },
    { "RtlHeapTailCheck",               func_RtlHeapTailCheck },
    { "RtlImageDirectoryEntryToData",   func_RtlImageDirectoryEntryToData },
    { "RtlImageRvaToVa",                func_RtlImageRvaToVa },
    { "RtlInitializeNtUserPfn",         func_RtlInitializeNtUserPfn },
    { "RtlInitializeSidEx",         func_RtlInitializeSidEx },
    { "RtlIntSafe",                     func_RtlIntSafe },
    { "RtlIsNameInExpression",          func_RtlIsNameInExpression},
    { "RtlIsEcCode",                    func_RtlIsEcCode },
    { "RtlIsNameLegalDOS8Dot3",         func_RtlIsNameLegalDOS8Dot3 },
    { "RtlLocale",                      func_RtlLocale },
    { "RtlMemIoResource",               func_RtlMemIoResource },
    { "RtlMemoryStream",                func_RtlMemoryStream },
    { "RtlMultipleAllocateHeap",        func_RtlMultipleAllocateHeap },
    { "RtlNtPathNameToDosPathName",     func_RtlNtPathNameToDosPathName },
    { "RtlNtStatusToDosError",          func_RtlNtStatusToDosError },
    { "RtlpApplyLengthFunction",        func_RtlpApplyLengthFunction },
    { "RtlpEnsureBufferSize",           func_RtlpEnsureBufferSize },
    { "RtlQueryEnvironmentVariable",    func_RtlQueryEnvironmentVariable },
    { "RtlQueryEnvironmentVariable_U",  func_RtlQueryEnvironmentVariable_U },
    { "RtlQueryProcessDebugModules",    func_RtlQueryProcessDebugModules },
    { "RtlQueryRegistryValues",         func_RtlQueryRegistryValues },
    { "RtlDeriveCapabilitySidsFromName", func_RtlDeriveCapabilitySidsFromName },
    { "RtlQueryPerformanceCounter",     func_RtlQueryPerformanceCounter },
    { "RtlQueryTimeZoneInformation",    func_RtlQueryTimeZoneInformation },
    { "RtlSetTimeZoneInformation",      func_RtlSetTimeZoneInformation },
    { "RtlReAllocateHeap",              func_RtlReAllocateHeap },
    { "RtlRemovePrivileges",            func_RtlRemovePrivileges },
    { "RtlRetrieveNtUserPfn",         func_RtlRetrieveNtUserPfn },
    { "RtlSRWLock",                     func_RtlSRWLock },
    { "RtlSRWLockStress",               func_RtlSRWLockStress },
    { "RtlSRWLockThroughput",          func_RtlSRWLockThroughput },
    { "RtlSRWLockWait",                 func_RtlSRWLockWait },
    { "RtlUnhandledExceptionFilter",    func_RtlUnhandledExceptionFilter },
    { "RtlUnwindExConsolidate",         func_RtlUnwindExConsolidate },
    { "RtlUnicodeStringToAnsiSize",     func_RtlxUnicodeStringToAnsiSize }, /* For some reason, starting test name with Rtlx hides it */
    { "RtlUnicodeStringToAnsiString",   func_RtlUnicodeStringToAnsiString },
    { "RtlUnicodeStringToCountedOemString", func_RtlUnicodeStringToCountedOemString },
    { "RtlUnicodeStringToOemSize",      func_RtlxUnicodeStringToOemSize },
    { "RtlUTF8",                        func_RtlUTF8 },
    { "RtlUnicodeToOemN",               func_RtlUnicodeToOemN },
    { "RtlUnwindIndirect",              func_RtlUnwindIndirect },
    { "RtlUpcaseUnicodeStringToCountedOemString", func_RtlUpcaseUnicodeStringToCountedOemString },
    { "RtlValidateUnicodeString",       func_RtlValidateUnicodeString },
    { "RtlStringSdBounds",              func_RtlStringSdBounds },
    { "RtlVerifyVersionInfo",           func_RtlVerifyVersionInfo },
    { "RtlWaitOnAddress",               func_RtlWaitOnAddress },
    { "FaultContext",                   func_FaultContext },
    { "PageFaultAddress",               func_PageFaultAddress },
    { "SectionFaultCost",               func_SectionFaultCost },
    { "SectionPageLeak",                func_SectionPageLeak },
    { "SectionVirtualLockLeak",         func_SectionVirtualLockLeak },
    { "StackDeepRecursion",             func_StackDeepRecursion },
    { "BadSegmentFault",                func_BadSegmentFault },
    { "ExceptionInfoLeak",              func_ExceptionInfoLeak },
    { "X87Fault",                       func_X87Fault },
    { "RaiseExceptionLeak",             func_RaiseExceptionLeak },
    { "StackOverflow",                  func_StackOverflow },
    { "StackOverflowThread",            func_StackOverflowThread },
    { "SystemCallStubs",                func_SystemCallStubs },
    { "strcpy_s",                       func_strcpy_s },
    { "SystemDllTls",                   func_SystemDllTls },
    { "TimerResolution",                func_TimerResolution },
    { "UserModeException",              func_UserModeException },
    { "VectoredHandlerChurn",           func_VectoredHandlerChurn },
    { "ModuleRangeTable",               func_ModuleRangeTable },
    { "StackOverflowDispatch",          func_StackOverflowDispatch },
    { "NtFlushBuffersFileEx",           func_NtFlushBuffersFileEx },
    { "NtGetCurrentProcessorNumberEx",  func_NtGetCurrentProcessorNumberEx },
    { "RtlCrc64",                       func_RtlCrc64 },
    { "RtlExtractBitMap",               func_RtlExtractBitMap },
    { "RtlFls",                         func_RtlFls },
    { "RtlGetPreciseTime",              func_RtlGetPreciseTime },
    { "RtlInitializeContext",           func_RtlInitializeContext },
    { "RtlWow64GetProcessMachines",     func_RtlWow64GetProcessMachines },
    { "ZwQuerySystemInformationEx",     func_ZwQuerySystemInformationEx },
#ifdef _M_IX86
    { "RtlUnwind",                      func_RtlUnwind },
#endif
#ifdef _M_AMD64
    { "RtlCaptureContext",              func_RtlCaptureContext },
    { "RtlUnwindEx",                    func_RtlUnwindEx },
    { "RtlVirtualUnwind",               func_RtlVirtualUnwind },
#endif

    { 0, 0 }
};
