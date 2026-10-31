
#define STANDALONE
#include <apitest.h>

extern void func_VirtualAlloc2(void);
extern void func_Wow64Process(void);
extern void func_Wow64Threads(void);
extern void func_Wow64CreateThreadAccess(void);
extern void func_Wow64ReviewThreads(void);
extern void func_Wow64RemoteThread(void);
extern void func_Wow64ThreadApc(void);
extern void func_Wow64ThreadLifetime(void);
extern void func_Wow64ThreadExitProcess(void);
extern void func_Wow64Run(void);
extern void func_Wow64SystemDlls(void);
extern void func_Wow64ReviewFixes(void);

extern void func_ActCtxWithXmlNamespaces(void);
extern void func_BindIoCompletionCallback(void);
extern void func_CancelIoEx(void);
extern void func_IocpCancelStatus(void);
extern void func_IocpThreadExit(void);
extern void func_ApplicationRestart(void);
extern void func_AppModel(void);
extern void func_CalendarInfo(void);
extern void func_ConsoleCP(void);
extern void func_CopyFile2(void);
extern void func_CopyFile2Identity(void);
extern void func_CopyFileStreams(void);
extern void func_ConsoleBufferSwitch(void);
extern void func_ConsoleCaret(void);
extern void func_ConsoleCreateRace(void);
extern void func_ConsoleOrphanChild(void);
extern void func_ConsoleCsrRequests(void);
extern void func_ConsoleCtrlEventRace(void);
extern void func_ConsoleCtrlHandler(void);
extern void func_ConsoleDisplayMode(void);
extern void func_ConsoleViewFollow(void);
extern void func_ConsoleVirtualTerminal(void);
extern void func_ConsoleWriteLatency(void);
extern void func_CopyFile2(void);
extern void func_CopyFile2Identity(void);
extern void func_CreateEventMutexEx(void);
extern void func_CreateFile2(void);
extern void func_CreateFileDirectory(void);
extern void func_CreateRemoteThreadEx(void);
extern void func_CreateProcess(void);
extern void func_CreateProcessILOnly(void);
extern void func_CreateProcessRace(void);
extern void func_CreateProcessStdHandles(void);
extern void func_DefaultDllDirectories(void);
extern void func_CreateWaitableTimerEx(void);
extern void func_ThreadImpersonationToken(void);
extern void func_DebugTrapInterrupts(void);
extern void func_ActCtxResDirBound(void);
extern void func_DefaultActCtx(void);
extern void func_DiscardVirtualMemory(void);
extern void func_DeleteTimerQueueEx(void);
extern void func_DeriveCapabilitySidsFromName(void);
extern void func_DeviceIoControl(void);
extern void func_DllInitParentPrecondition(void);
extern void func_dosdev(void);
extern void func_DynamicTls(void);
extern void func_DynamicTimeZone(void);
extern void func_GetTimeZoneInformationForYear(void);
extern void func_EnumSystemCodePages(void);
extern void func_EnumUILanguages(void);
extern void func_ExitThread(void);
extern void func_FindActCtxSectionStringW(void);
extern void func_FindFiles(void);
extern void func_FindFirstFileEx(void);
extern void func_FindFirstStream(void);
extern void func_FindNLSStringEx(void);
extern void func_FindStringOrdinal(void);
extern void func_FlushProcessWriteBuffers(void);
extern void func_FLS(void);
extern void func_ForcedRelocation(void);
extern void func_FormatMessage(void);
extern void func_FormatMessageInsert(void);
extern void func_GetBinaryType(void);
extern void func_GetComputerNameEx(void);
extern void func_GetCurrentThreadStackLimits(void);
extern void func_GetCPInfo(void);
extern void func_GetCurrentDirectory(void);
extern void func_GetDriveType(void);
extern void func_GetEnvironmentVariable(void);
extern void func_GetFileType(void);
extern void func_GetFinalPathNameByHandle(void);
extern void func_GetUserDefaultGeoName(void);
extern void func_GetLocaleInfo(void);
extern void func_GetLogicalProcessorInformationEx(void);
extern void func_GetModuleFileName(void);
extern void func_GetNamedPipeServerProcessId(void);
extern void func_GetNumaProcessorNodeEx(void);
extern void func_GetSystemCpuSetInformation(void);
extern void func_GetOverlappedResultEx(void);
extern void func_GetQueuedCompletionStatusEx(void);
extern void func_GetSystemTimePrecise(void);
extern void func_GetThreadUILanguage(void);
extern void func_DiskPerformance(void);
extern void func_GetVolumeInformation(void);
extern void func_HeapCreateExecute(void);
extern void func_HandleList(void);
extern void func_HeapWalk(void);
extern void func_IdleProcessor(void);
extern void func_InitOnce(void);
extern void func_InterlockedPushListSListEx(void);
extern void func_KernelBaseTime(void);
extern void func_interlck(void);
extern void func_IsApiSetImplemented(void);
extern void func_IsDBCSLeadByteEx(void);
extern void func_JapaneseCalendar(void);
extern void func_JobList(void);
extern void func_JobObject(void);
extern void func_LCMapString(void);
extern void func_LCMapStringHash(void);
extern void func_LoadString(void);
extern void func_LoadLibraryErrorMode(void);
extern void func_LoadLibraryExW(void);
extern void func_LoadLibraryILOnly(void);
extern void func_LoadLibraryMachine(void);
extern void func_LoadLibraryMissingImport(void);
extern void func_LocalDumps(void);
extern void func_CrashDialog(void);
extern void func_LocaleNameToLCID(void);
extern void func_LocaleTable(void);
extern void func_LocalTimeZone(void);
extern void func_lstrcpynW(void);
extern void func_lstrlen(void);
extern void func_MailslotRead(void);
extern void func_MappedFileGrowth(void);
extern void func_MappedViewEvict(void);
extern void func_MultiByteToWideChar(void);
extern void func_NamedPipeInstanceReuse(void);
extern void func_PartialContext(void);
extern void func_PerformanceCounter(void);
extern void func_Pipes(void);
extern void func_PipeSqos(void);
extern void func_PreferredUILanguages(void);
extern void func_PowerRequest(void);
extern void func_PrefetchVirtualMemory(void);
extern void func_PrivMoveFileIdentityW(void);
extern void func_ProcessAffinity(void);
extern void func_ProcessInformation(void);
extern void func_ProcessMitigationPolicy(void);
extern void func_PssSnapshot(void);
extern void func_ProcThreadMitigation(void);
extern void func_QueryCycleTime(void);
extern void func_QueryUnbiasedInterruptTime(void);
extern void func_ProcessToken(void);
extern void func_ProcessorGroups(void);
extern void func_QueueUserAPC(void);
extern void func_QueueUserWorkItem(void);
extern void func_RaiseFailFastException(void);
extern void func_ReadDirectoryChanges(void);
extern void func_RegisterWait(void);
extern void func_ResolveDelayLoadedAPI(void);
extern void func_ResolveLocaleName(void);
extern void func_SetComputerNameExW(void);
extern void func_SetConsoleWindowInfo(void);
extern void func_SetCurrentDirectory(void);
extern void func_SetThreadStackGuarantee(void);
extern void func_SetUnhandledExceptionFilter(void);
extern void func_SuspendThreadContext(void);
extern void func_SetWaitableTimerEx(void);
extern void func_SleepNeverEarly(void);
extern void func_SystemFirmware(void);
extern void func_Toolhelp32(void);
extern void func_TerminateProcess(void);
extern void func_ThreadContextNpx(void);
extern void func_ThreadContextObjects(void);
extern void func_ThreadHandleLeak(void);
extern void func_ThreadInformation(void);
extern void func_TunnelCache(void);
extern void func_VolumeMountPoint(void);
extern void func_TzSetPrivilege(void);
extern void func_UEFIFirmware(void);
extern void func_UnhandledExceptionExit(void);
extern void func_UnmapViewOfFileEx(void);
extern void func_WaitOnAddress(void);
extern void func_WaitQuantum(void);
extern void func_WerFlags(void);
extern void func_WerRegisterMemoryFile(void);
extern void func_WerRuntimeExceptionModule(void);
extern void func_WideCharToMultiByte(void);
extern void func_ReadProcessMemory(void);
extern void func_WriteProcessMemory(void);
extern void func_XState(void);
extern void func_XStateContext(void);
extern void func_SetFileInformationByHandle(void);

extern void func_Wow64Environment(void);
extern void func_Wow64ProgramFiles(void);
extern void func_Wow64EnvironmentBlock(void);

const struct test winetest_testlist[] =
{
    { "VirtualAlloc2",               func_VirtualAlloc2 },
    { "Wow64Environment", func_Wow64Environment },
    { "Wow64ProgramFiles", func_Wow64ProgramFiles },
    { "Wow64EnvironmentBlock", func_Wow64EnvironmentBlock },
    { "Wow64ThreadApc", func_Wow64ThreadApc },
    { "Wow64ThreadLifetime", func_Wow64ThreadLifetime },
    { "Wow64ThreadExitProcess", func_Wow64ThreadExitProcess },
    { "Wow64Threads", func_Wow64Threads },
    { "Wow64CreateThreadAccess", func_Wow64CreateThreadAccess },
    { "Wow64ReviewThreads", func_Wow64ReviewThreads },
    { "Wow64RemoteThread", func_Wow64RemoteThread },
    { "Wow64Process", func_Wow64Process },
    { "Wow64Run", func_Wow64Run },
    { "Wow64SystemDlls", func_Wow64SystemDlls },
    { "Wow64ReviewFixes", func_Wow64ReviewFixes },
    { "ActCtxWithXmlNamespaces",     func_ActCtxWithXmlNamespaces },
    { "BindIoCompletionCallback",    func_BindIoCompletionCallback },
    { "CancelIoEx",                  func_CancelIoEx },
    { "IocpCancelStatus",            func_IocpCancelStatus },
    { "IocpThreadExit",              func_IocpThreadExit },
    { "ApplicationRestart",          func_ApplicationRestart },
    { "AppModel",                    func_AppModel },
    { "CalendarInfo",                func_CalendarInfo },
    { "ConsoleCP",                   func_ConsoleCP },
    { "CopyFile2",                   func_CopyFile2 },
    { "CopyFile2Identity",           func_CopyFile2Identity },
    { "CopyFileStreams",             func_CopyFileStreams },
    { "ConsoleBufferSwitch",         func_ConsoleBufferSwitch },
    { "ConsoleCaret",                func_ConsoleCaret },
    { "ConsoleCreateRace",           func_ConsoleCreateRace },
    { "ConsoleOrphanChild",          func_ConsoleOrphanChild },
    { "ConsoleCsrRequests",          func_ConsoleCsrRequests },
    { "ConsoleCtrlEventRace",        func_ConsoleCtrlEventRace },
    { "ConsoleCtrlHandler",          func_ConsoleCtrlHandler },
    { "ConsoleDisplayMode",          func_ConsoleDisplayMode },
    { "ConsoleViewFollow",           func_ConsoleViewFollow },
    { "ConsoleVirtualTerminal",      func_ConsoleVirtualTerminal },
    { "ConsoleWriteLatency",         func_ConsoleWriteLatency },
    { "CopyFile2",                   func_CopyFile2 },
    { "CopyFile2Identity",           func_CopyFile2Identity },
    { "CreateEventMutexEx",          func_CreateEventMutexEx },
    { "CreateFile2",                 func_CreateFile2 },
    { "CreateFileDirectory",         func_CreateFileDirectory },
    { "CreateRemoteThreadEx",        func_CreateRemoteThreadEx },
    { "CreateProcess",               func_CreateProcess },
    { "CreateProcessILOnly",         func_CreateProcessILOnly },
    { "CreateProcessRace",           func_CreateProcessRace },
    { "CreateProcessStdHandles",     func_CreateProcessStdHandles },
    { "DefaultDllDirectories",      func_DefaultDllDirectories },
    { "CreateWaitableTimerEx",       func_CreateWaitableTimerEx },
    { "ThreadImpersonationToken",    func_ThreadImpersonationToken },
    { "DebugTrapInterrupts",         func_DebugTrapInterrupts },
    { "ActCtxResDirBound",          func_ActCtxResDirBound },
    { "DefaultActCtx",               func_DefaultActCtx },
    { "DiscardVirtualMemory", func_DiscardVirtualMemory },
    { "DeleteTimerQueueEx",          func_DeleteTimerQueueEx },
    { "DeriveCapabilitySidsFromName", func_DeriveCapabilitySidsFromName },
    { "DeviceIoControl",             func_DeviceIoControl },
    { "DllInitParentPrecondition",   func_DllInitParentPrecondition },
    { "dosdev",                      func_dosdev },
    { "DynamicTls",                  func_DynamicTls },
    { "DynamicTimeZone",             func_DynamicTimeZone },
    { "GetTimeZoneInformationForYear", func_GetTimeZoneInformationForYear },
    { "EnumSystemCodePages",         func_EnumSystemCodePages },
    { "EnumUILanguages",             func_EnumUILanguages },
    { "ExitThread",                  func_ExitThread },
    { "FindActCtxSectionStringW",    func_FindActCtxSectionStringW },
    { "FindFiles",                   func_FindFiles },
    { "FindFirstFileEx",             func_FindFirstFileEx },
    { "FindFirstStream",             func_FindFirstStream },
    { "FindNLSStringEx",             func_FindNLSStringEx },
    { "FindStringOrdinal",           func_FindStringOrdinal },
    { "FlushProcessWriteBuffers",     func_FlushProcessWriteBuffers },
    { "FLS",                         func_FLS },
    { "ForcedRelocation",            func_ForcedRelocation },
    { "FormatMessage",               func_FormatMessage },
    { "FormatMessageInsert",          func_FormatMessageInsert },
    { "GetBinaryType",               func_GetBinaryType },
    { "GetComputerNameEx",           func_GetComputerNameEx },
    { "GetCurrentThreadStackLimits", func_GetCurrentThreadStackLimits },
    { "GetCPInfo",                   func_GetCPInfo },
    { "GetCurrentDirectory",         func_GetCurrentDirectory },
    { "GetDriveType",                func_GetDriveType },
    { "GetEnvironmentVariable",      func_GetEnvironmentVariable },
    { "GetFileType",                 func_GetFileType },
    { "GetFinalPathNameByHandle",    func_GetFinalPathNameByHandle },
    { "GetUserDefaultGeoName", func_GetUserDefaultGeoName },
    { "GetLocaleInfo",               func_GetLocaleInfo },
    { "GetLogicalProcessorInformationEx", func_GetLogicalProcessorInformationEx },
    { "GetModuleFileName",           func_GetModuleFileName },
    { "GetNamedPipeServerProcessId", func_GetNamedPipeServerProcessId },
    { "GetSystemCpuSetInformation", func_GetSystemCpuSetInformation },
    { "GetNumaProcessorNodeEx",      func_GetNumaProcessorNodeEx },
    { "GetOverlappedResultEx",       func_GetOverlappedResultEx },
    { "GetQueuedCompletionStatusEx", func_GetQueuedCompletionStatusEx },
    { "GetSystemTimePrecise",        func_GetSystemTimePrecise },
    { "GetThreadUILanguage",         func_GetThreadUILanguage },
    { "DiskPerformance",             func_DiskPerformance },
    { "GetVolumeInformation",        func_GetVolumeInformation },
    { "HeapCreateExecute",           func_HeapCreateExecute },
    { "HandleList",                  func_HandleList },
    { "HeapWalk",                    func_HeapWalk },
    { "IdleProcessor",               func_IdleProcessor },
    { "InitOnce",                    func_InitOnce },
    { "InterlockedPushListSListEx", func_InterlockedPushListSListEx },
    { "KernelBaseTime",              func_KernelBaseTime },
    { "interlck",                    func_interlck },
    { "IsApiSetImplemented",         func_IsApiSetImplemented },
    { "IsDBCSLeadByteEx",            func_IsDBCSLeadByteEx },
    { "JapaneseCalendar",            func_JapaneseCalendar },
    { "JobList",                    func_JobList },
    { "JobObject",                   func_JobObject },
    { "LCMapString",                 func_LCMapString },
    { "LCMapStringHash",             func_LCMapStringHash },
    { "LoadString", func_LoadString },
    { "LoadLibraryErrorMode",        func_LoadLibraryErrorMode },
    { "LoadLibraryExW",              func_LoadLibraryExW },
    { "LoadLibraryILOnly",            func_LoadLibraryILOnly },
    { "LoadLibraryMachine",          func_LoadLibraryMachine },
    { "LoadLibraryMissingImport",     func_LoadLibraryMissingImport },
    { "LocalDumps",                  func_LocalDumps },
    { "CrashDialog",                 func_CrashDialog },
    { "LocaleNameToLCID",            func_LocaleNameToLCID },
    { "LocaleTable",                 func_LocaleTable },
    { "LocalTimeZone",               func_LocalTimeZone },
    { "lstrcpynW",                   func_lstrcpynW },
    { "lstrlen",                     func_lstrlen },
    { "MailslotRead",                func_MailslotRead },
    { "MappedFileGrowth",            func_MappedFileGrowth },
    { "MappedViewEvict",            func_MappedViewEvict },
    { "MultiByteToWideChar",         func_MultiByteToWideChar },
    { "NamedPipeInstanceReuse",     func_NamedPipeInstanceReuse },
    { "PartialContext",             func_PartialContext },
    { "PerformanceCounter",          func_PerformanceCounter },
    { "Pipes",                       func_Pipes },
    { "PipeSqos",                    func_PipeSqos },
    { "PreferredUILanguages",        func_PreferredUILanguages },
    { "PowerRequest",                func_PowerRequest },
    { "PrefetchVirtualMemory",       func_PrefetchVirtualMemory },
    { "PrivMoveFileIdentityW",       func_PrivMoveFileIdentityW },
    { "ProcessMitigationPolicy",     func_ProcessMitigationPolicy },
    { "PssSnapshot",                 func_PssSnapshot },
    { "ProcThreadMitigation",        func_ProcThreadMitigation },
    { "ProcessAffinity",             func_ProcessAffinity },
    { "ProcessInformation",         func_ProcessInformation },
    { "QueryCycleTime",              func_QueryCycleTime },
    { "QueryUnbiasedInterruptTime",  func_QueryUnbiasedInterruptTime },
    { "ProcessToken",                func_ProcessToken },
    { "ProcessorGroups",             func_ProcessorGroups },
    { "QueueUserAPC",                func_QueueUserAPC },
    { "QueueUserWorkItem",           func_QueueUserWorkItem },
    { "RaiseFailFastException",      func_RaiseFailFastException },
    { "ReadDirectoryChanges",       func_ReadDirectoryChanges },
    { "RegisterWait",                func_RegisterWait },
    { "ResolveDelayLoadedAPI",       func_ResolveDelayLoadedAPI },
    { "ResolveLocaleName",           func_ResolveLocaleName },
    { "SetComputerNameExW",          func_SetComputerNameExW },
    { "SetConsoleWindowInfo",        func_SetConsoleWindowInfo },
    { "SetCurrentDirectory",         func_SetCurrentDirectory },
    { "SetThreadStackGuarantee",     func_SetThreadStackGuarantee },
    { "SetUnhandledExceptionFilter", func_SetUnhandledExceptionFilter },
    { "SuspendThreadContext",        func_SuspendThreadContext },
    { "SetWaitableTimerEx",          func_SetWaitableTimerEx },
    { "SleepNeverEarly",             func_SleepNeverEarly },
    { "SystemFirmware",              func_SystemFirmware },
    { "Toolhelp32",                  func_Toolhelp32 },
    { "TerminateProcess",            func_TerminateProcess },
    { "ThreadContextNpx",            func_ThreadContextNpx },
    { "ThreadHandleLeak",            func_ThreadHandleLeak },
    { "ThreadInformation",           func_ThreadInformation },
    { "ThreadContextObjects",        func_ThreadContextObjects },
    { "TunnelCache",                 func_TunnelCache },
    { "VolumeMountPoint",            func_VolumeMountPoint },
    { "TzSetPrivilege",              func_TzSetPrivilege },
    { "UEFIFirmware",                func_UEFIFirmware },
    { "UnhandledExceptionExit",      func_UnhandledExceptionExit },
    { "UnmapViewOfFileEx",           func_UnmapViewOfFileEx },
    { "WaitOnAddress",               func_WaitOnAddress },
    { "WaitQuantum",                 func_WaitQuantum },
    { "WerFlags",                    func_WerFlags },
    { "WerRegisterMemoryFile",      func_WerRegisterMemoryFile },
    { "WerRuntimeExceptionModule",   func_WerRuntimeExceptionModule },
    { "WideCharToMultiByte",         func_WideCharToMultiByte },
    { "ReadProcessMemory",           func_ReadProcessMemory },
    { "WriteProcessMemory",          func_WriteProcessMemory },
    { "XState",                      func_XState },
    { "XStateContext",               func_XStateContext },
    { "SetFileInformationByHandle",  func_SetFileInformationByHandle },
    { 0, 0 }
};
