
add_subdirectory(dllinitdep)
add_subdirectory(redirptest)
add_subdirectory(tlsdyn)

add_message_headers(ANSI FormatMessage.mc)

list(APPEND SOURCE
    VirtualAlloc2.c
    VirtualAllocLarge.c
    Placeholder.c
    PageTargetsFlag.c
    Wow64ReviewThreads.c
    Wow64RemoteThread.c
    Wow64ThreadApc.c
    Wow64ThreadSegments.c
    Wow64Threads.c
    Wow64CreateThreadAccess.c
    Wow64Environment.c
    BindIoCompletionCallback.c
    CancelIoEx.c
    IocpCancelStatus.c
    IocpThreadExit.c
    TerminateProcessWait.c
    ApplicationRestart.c
    AppModel.c
    CalendarInfo.c
    ConsoleCP.c
    CopyFile2.c
    CopyFile2Identity.c
    CopyFileStreams.c
    ConsoleBufferSwitch.c
    ConsoleCaret.c
    ConsoleCreateRace.c
    ConsoleOrphanChild.c
    UnbufferedReadLimit.c
    ConsoleInheritForeign.c
    ConsoleCloseTerminate.c
    ConsoleCsrRequests.c
    ConsoleCtrlEventRace.c
    ConsoleCtrlHandler.c
    ConsoleDisplayMode.c
    ConsoleKeyShortcuts.c
    ConsoleQuickEdit.c
    ConsoleViewFollow.c
    ConsoleFramebufferCommit.c
    ConsoleVirtualTerminal.c
    ConsoleVirtualTerminalInput.c
    ConPty.c
    ConsoleWriteLatency.c
    CopyFile2.c
    CopyFile2Identity.c
    CreateEventMutexEx.c
    CreateFile2.c
    CreateFileDirectory.c
    CreateRemoteThreadEx.c
    CreateThreadFromUserThread.c
    CsrAdoptedThreadChurn.c
    CreateProcess.c
    CreateProcessILOnly.c
    CreateSymbolicLink.c
    CreateProcessRace.c
    CreateProcessStdHandles.c
    CreateWaitableTimerEx.c
    DefaultDllDirectories.c
    ThreadImpersonationToken.c
    DebugApi.c
    DebugTrapInterrupts.c
    ActCtxResDirBound.c
    DefaultActCtx.c
    DiscardVirtualMemory.c
    DeleteFilePosix.c
    OmahaExports.c
    DeleteTimerQueueEx.c
    DeriveCapabilitySidsFromName.c
    CallbackCompletion.c
    GetAppContainerNamedObjectPath.c
    CompareObjectHandles.c
    PrivateNamespaceSecurity.c
    CancelSynchronousIo.c
    IdnTo.c
    NormalizeString.c
    IsWow64Process2.c
    AppPolicy.c
    FileMappingFromApp.c
    ThreadpoolEx.c
    CtrlRoutine.c
    VirtualAllocExNuma.c
    Win10Exports.c
    DeviceIoControl.c
    DllInitParentPrecondition.c
    dosdev.c
    DynamicTls.c
    DynamicTimeZone.c
    GetTimeZoneInformationForYear.c
    EnumSystemCodePages.c
    EnumUILanguages.c
    ExitThread.c
    ThreadReturnClobber.c
    FindActCtxSectionStringW.c
    FindFiles.c
    FindFirstFileEx.c
    FindFirstStream.c
    FindNextBoundary.c
    FindNLSStringEx.c
    FindStringOrdinal.c
    FlushProcessWriteBuffers.c
    RegCurrentVersion.c
    FLS.c
    FlsGetValue2.c
    ForcedRelocation.c
    FormatMessage.c
    FormatMessageInsert.c
    GetBinaryType.c
    GetComputerNameEx.c
    GetCurrentThreadStackLimits.c
    GetCPInfo.c
    GetCurrentDirectory.c
    GetDriveType.c
    GetEnvironmentVariable.c
    GetFileType.c
    GetFinalPathNameByHandle.c
    GetUserDefaultGeoName.c
    GetLocaleInfo.c
    GetLogicalProcessorInformationEx.c
    GetModuleFileName.c
    GetNamedPipeServerProcessId.c
    GetNumaProcessorNodeEx.c
    GetSystemCpuSetInformation.c
    GetOverlappedResultEx.c
    GetQueuedCompletionStatusEx.c
    GetSystemFileCacheSize.c
    GetSystemTimePrecise.c
    GetThreadUILanguage.c
    GetTimeFormat.c
    DiskPerformance.c
    GetVolumeInformation.c
    HandleList.c
    HeapCreateExecute.c
    HeapWalk.c
    IdleProcessor.c
    InitOnce.c
    InterlockedPushListSListEx.c
    KernelBaseForwarders.c
    KernelBaseTime.c
    interlck.c
    IsApiSetImplemented.c
    IsDBCSLeadByteEx.c
    JapaneseCalendar.c
    JobList.c
    JobObject.c
    LCMapString.c
    LCMapStringHash.c
    LoadString.c
    LoadLibraryErrorMode.c
    LoadLibraryExW.c
    LoadLibraryMalformed.c
    LoadLibraryILOnly.c
    LoadLibraryMachine.c
    LoadLibraryForwarder.c
    LoadLibraryMissingImport.c
    LoadLibraryNoExecute.c
    LocalDumps.c
    CrashDialog.c
    LocaleDerivedFields.c
    LocaleNameToLCID.c
    LocaleTable.c
    LocalTimeZone.c
    SetTimeZoneInformation.c
    lstrcpynW.c
    lstrlen.c
    Mailslot.c
    FlushViewOfFile.c
    MappedFileGrowth.c
    FileCloseLockedDup.c
    FileCutAfterClose.c
    FileLockCloseOther.c
    MappedViewEvict.c
    MultiByteToWideChar.c
    NamedPipeInstanceReuse.c
    PerformanceCounter.c
    Pipes.c
    PipeSqos.c
    PreferredUILanguages.c
    PowerRequest.c
    PrefetchVirtualMemory.c
    RelocatedImageProtection.c
    MoveFileReparse.c
    ReparseFollow.c
    PrivMoveFileIdentityW.c
    ProcessAffinity.c
    ProcessorNumber.c
    ProcessInformation.c
    ProcessMitigationPolicy.c
    AdvapiModules.c
    ProcThreadMitigation.c
    QueryCycleTime.c
    QueryUnbiasedInterruptTime.c
    ProcessToken.c
    ProcessorGroups.c
    PssSnapshot.c
    QueueUserAPC.c
    QueueUserWorkItem.c
    QueueUserWorkItemStream.c
    RaiseFailFastException.c
    ReadDirectoryChanges.c
    ReadDirectoryChangesEx.c
    ReadDirectoryChangesRename.c
    ReadFile.c
    RegisterWait.c
    ResolveDelayLoadedAPI.c
    ResolveLocaleName.c
    SetComputerNameExW.c
    SetConsoleWindowInfo.c
    SetCurrentDirectory.c
    SetSearchPathMode.c
    SetThreadStackGuarantee.c
    StackOverflowRearm.c
    ThreadStackCommit.c
    SetUnhandledExceptionFilter.c
    SuspendThreadContext.c
    SetWaitableTimerEx.c
    SleepNeverEarly.c
    SystemFirmware.c
    Toolhelp32.c
    TerminateProcess.c
    ThreadContextNpx.c
    ThreadContextObjects.c
    ThreadFairness.c
    ThreadGroupAffinity.c
    ThreadHandleLeak.c
    ThreadInformation.c
    ThreadStartFrame.c
    ThreadTimesTimerResolution.c
    TunnelCache.c
    VolumeMountPoint.c
    TzPrivilegedWriter.c
    TzSetPrivilege.c
    UEFIFirmware.c
    UnattendedCrash.c
    UnhandledExceptionExit.c
    UnmapViewOfFileEx.c
    WaitOnAddress.c
    WaitQuantum.c
    WerFlags.c
    WorkingSetQuota.c
    WerRegisterMemoryFile.c
    WerRuntimeExceptionModule.c
    WideCharToMultiByte.c
    WindowsDirJunction.c
    Wow64Process.c
    Wow64Run.c
    Wow64StartContext.c
    Wow64SystemDlls.c
    WriteFile.c
    XState.c
    XStateContext.c
    PartialContext.c
    ReadProcessMemory.c
    WriteProcessMemory.c
    SetFileInformationByHandle.c
)

list(APPEND PCH_SKIP_SOURCE
    testlist.c)

add_executable(kernel32_apitest
    ${SOURCE}
    ${PCH_SKIP_SOURCE}
    kernel32_apitest.rc)

target_link_libraries(kernel32_apitest wine ${PSEH_LIB})
set_module_type(kernel32_apitest win32cui)
add_delay_importlibs(kernel32_apitest advapi32 shlwapi user32 gdi32)
add_importlibs(kernel32_apitest netapi32 msvcrt kernel32 ntdll)
add_dependencies(kernel32_apitest FormatMessage uhexit_dll)
set_source_files_properties(CopyFile2Identity.c PROPERTIES INCLUDE_DIRECTORIES "${CMAKE_CURRENT_SOURCE_DIR}/copy2_embedded")
add_pch(kernel32_apitest precomp.h "${PCH_SKIP_SOURCE}")
add_rostests_file(TARGET kernel32_apitest)

add_executable(win32klock_child win32klock_child.c)
set_module_type(win32klock_child win32cui ENTRYPOINT mainCRTStartup)
add_importlibs(win32klock_child kernel32)
add_dependencies(kernel32_apitest win32klock_child)
add_rostests_file(TARGET win32klock_child)

add_executable(advapi32_modules_child advapi32_modules_child.c)
set_module_type(advapi32_modules_child win32cui ENTRYPOINT mainCRTStartup)
add_importlibs(advapi32_modules_child advapi32 kernel32)
add_dependencies(kernel32_apitest advapi32_modules_child)
add_rostests_file(TARGET advapi32_modules_child)

add_executable(wow64_native wow64_native.c)
set_module_type(wow64_native win32cui ENTRYPOINT mainCRTStartup)
add_importlibs(wow64_native kernel32)
add_rostests_file(TARGET wow64_native)

if(ARCH STREQUAL "i386")
    add_executable(wow64_hello wow64_hello.c)
    set_module_type(wow64_hello win32cui ENTRYPOINT mainCRTStartup)
    add_importlibs(wow64_hello kernel32 ntdll)
    add_rostests_file(TARGET wow64_hello)

    add_executable(wow64_errors wow64_errors.c)
    set_module_type(wow64_errors win32cui ENTRYPOINT mainCRTStartup)
    add_importlibs(wow64_errors kernel32 ntdll)
    add_rostests_file(TARGET wow64_errors)

    spec2def(wow64_local.dll wow64_local.spec ADD_IMPORTLIB)
    add_library(wow64_local MODULE wow64_local.c ${CMAKE_CURRENT_BINARY_DIR}/wow64_local.def)
    set_module_type(wow64_local win32dll ENTRYPOINT 0)
    add_rostests_file(TARGET wow64_local)
    add_executable(wow64_localhello wow64_localhello.c)
    set_module_type(wow64_localhello win32cui ENTRYPOINT mainCRTStartup)
    add_importlibs(wow64_localhello wow64_local kernel32)
    add_rostests_file(TARGET wow64_localhello)

    add_executable(wow64_procnum wow64_procnum.c)
    set_module_type(wow64_procnum win32cui ENTRYPOINT mainCRTStartup)
    add_importlibs(wow64_procnum msvcrt kernel32)
    add_rostests_file(TARGET wow64_procnum)
endif()

list(APPEND MANIFEST_FILES
    classtest.manifest
    classtest2.manifest
    comctl32dep.manifest
    dep1.manifest
    deptest.manifest
    xmlns.manifest)

foreach(item ${MANIFEST_FILES})
    add_rostests_file(FILE "${CMAKE_CURRENT_SOURCE_DIR}/${item}")
endforeach(item)

add_executable(handlelist_gui handlelist_gui.c)
set_module_type(handlelist_gui win32gui ENTRYPOINT WinMainCRTStartup)
add_importlibs(handlelist_gui kernel32)
add_dependencies(kernel32_apitest handlelist_gui)
add_rostests_file(TARGET handlelist_gui)
spec2def(wow64_thread.dll wow64_thread.spec ADD_IMPORTLIB)
add_library(wow64_thread MODULE wow64_thread.c ${CMAKE_CURRENT_BINARY_DIR}/wow64_thread.def)
set_module_type(wow64_thread win32dll ENTRYPOINT DllMain 12)
add_importlibs(wow64_thread kernel32)
add_rostests_file(TARGET wow64_thread)

spec2def(uhexit_dll.dll uhexit_dll.spec)
add_library(uhexit_dll MODULE uhexit_dll.c ${CMAKE_CURRENT_BINARY_DIR}/uhexit_dll.def)
set_module_type(uhexit_dll win32dll ENTRYPOINT DllMain 12)
add_importlibs(uhexit_dll kernel32)
add_rostests_file(TARGET uhexit_dll)
