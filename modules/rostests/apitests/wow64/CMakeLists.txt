# Console-only selections of the existing API tests. Compile the original
# sources without changing their assertions; use identical PE32 executables
# for the native i386 and WoW64 comparison. The full suites also import GUI and
# network libraries, whose WoW64 support is a separate gate.
function(add_wow64_apitest library)
    set(sources)
    set(testlist "#define STANDALONE\n#include <apitest.h>\n")
    # LsaLogonSession and NetUserChangePassword are in LogonUser.c, which brings their helpers
    foreach(test ${ARGN})
        if(NOT test MATCHES "^(RegWow64(Unicode|Views|Matrix|LongName|SharedLongName|Volatile|SharedCreate|Aliases)|Wow64ProgramFiles|Wow64EnvironmentBlock|Wow64ChildEnvironment|Wow64Thread(Lifetime|ExitProcess)|StackOverflowThread|StackDeepRecursion|LsaLogonSession|NetUserChangePassword)$")
            list(APPEND sources ../${library}/${test}.c)
        endif()
        string(APPEND testlist "extern void func_${test}(void);\n")
    endforeach()
    string(APPEND testlist "const struct test winetest_testlist[] = {\n")
    foreach(test ${ARGN})
        string(APPEND testlist "    {\"${test}\", func_${test}},\n")
    endforeach()
    string(APPEND testlist "    {0, 0}\n};\n")
    file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/${library}_testlist.c "${testlist}")
    set(target ${library}_wow64_apitest)
    add_executable(${target} ${sources} ${CMAKE_CURRENT_BINARY_DIR}/${library}_testlist.c)
    target_link_libraries(${target} wine ${PSEH_LIB})
    set_module_type(${target} win32cui)
    add_importlibs(${target} advapi32 msvcrt kernel32 ntdll)
    add_rostests_file(TARGET ${target})
endfunction()

add_wow64_apitest(kernel32
    Wow64ReviewThreads Wow64RemoteThread Wow64CreateThreadAccess
    Wow64ThreadApc Wow64ThreadSegments Wow64ThreadLifetime Wow64ThreadExitProcess Wow64Threads ThreadReturnClobber QueueUserAPC
    GetCurrentDirectory GetEnvironmentVariable GetDriveType GetCPInfo
    IsDBCSLeadByteEx lstrlen Wow64Environment Wow64ProgramFiles Wow64EnvironmentBlock Wow64ChildEnvironment Wow64SystemDlls RegCurrentVersion DynamicTls HandleList JobObject JobList
    Wow64Console FindFirstStream ProcThreadMitigation RegisterWait QueueUserWorkItem ResolveDelayLoadedAPI InterlockedPushListSListEx
    ConsoleCsrRequests ConsoleVirtualTerminal ConsoleCP ConsoleBufferSwitch ConsoleCreateRace ConsoleOrphanChild ConsoleInheritForeign UnbufferedReadLimit ConsoleViewFollow
    ConsoleWriteLatency SetConsoleWindowInfo WerRegisterMemoryFile
    CancelIoEx ReadDirectoryChanges GetTimeZoneInformationForYear)
# ConsoleCaret, ConsoleCtrlEventRace, ConsoleCtrlHandler and ConsoleDisplayMode also call user32/gdi32: kernel32_apitest only
add_wow64_apitest(ntdll StackOverflowDispatch FaultContext NtRaiseHardErrorMode
    Wow64Continue ThreadDebugRegisters Wow64ServiceArguments Wow64FloatState Wow64QuerySystemTime NtAccessCheckByType NtAccessCheckByTypeResultList Wow64SystemRangeStart Wow64HandleInformation Wow64QueryVirtualMemory NtQueryVirtualMemoryRegion Wow64PowerInformation Wow64QueryInformationProcess Wow64FailedOpenHandle NtOpenKey NtOpenKeyEx NtQueryKey NtQueryValueKey
    RtlDetermineDosPathNameType RtlUnicodeStringToAnsiString StackOverflow StackOverflowThread StackDeepRecursion SystemCallStubs
    Wow64SystemProcessInformation NtSetInformationFile NtQueryInformationFile NtQueryVolumeInformationFile NtQueryDirectoryFile
    NtFlushBuffersFile NtFsControlFilePipe DefineDosDevice
    NtFlushVirtualMemory NtEaFile VolumeControlCodes IoctlAllowlist ScsiPassThrough NtTokenQueryParity
    NtSetIoCompletionEx NtQueryObjectHandleFlags NtAllocateReserveObject NtWaitCompletionPacket)
add_wow64_apitest(advapi32
    ServiceArgs QueryServiceConfig ServiceStructLayout SetSecurityInfoKey RegCreateKeyEx RegOpenKeyExW RegQueryValueExW RegEnumValueW RegWow64 RegWow64Unicode RegWow64Views RegWow64SharedCreate RegWow64Matrix RegWow64LongName RegWow64SharedLongName RegWow64Volatile RegWow64Aliases RegWow64RelativeView TokenLogonSid TokenQueryParity RestrictedSidsCopy TokenDefaultDacl LogonUser LsaLogonSession NetUserChangePassword
    GetSecurityInfoSequence LsaLogonUserS4U LsaLookupNamesUnmapped RestrictedTokenAccess AccessCheckObjectTypeList TimeZoneKeys)
add_wow64_apitest(wintrust WTHelperGetFileHash)
add_wow64_apitest(iphlpapi NeighborEntry2)
add_wow64_apitest(secur32 SetCredentialsAttributes)

# The D3DKMT calls need a window station, so this one links the GUI libraries
add_wow64_apitest(gdi32 D3DKMTCreateDCFromMemory D3DKMTWow64Thunks)
target_include_directories(gdi32_wow64_apitest PRIVATE ${REACTOS_SOURCE_DIR}/win32ss)
add_importlibs(gdi32_wow64_apitest gdi32 user32)

# WM_GETDLGCODE, the pointer messages (WM_HELP, WM_COMPAREITEM, ...) and friends reach win32k through the 32-bit message thunk
add_wow64_apitest(user32 WmGetDlgCode WmPointerMessages WmMenuDragIme WmDde WmDdeml)
add_importlibs(user32_wow64_apitest imm32 user32)

target_sources(advapi32_wow64_apitest PRIVATE ../advapi32/RegWow64Review.c)
# LogonUser creates its test user through the SAM
add_importlibs(advapi32_wow64_apitest netapi32)

if(ARCH STREQUAL "i386")
    # Explicit smoke-test target; do not change default image contents.
    add_executable(wow64_gui_load EXCLUDE_FROM_ALL gui_load.c)
    set_module_type(wow64_gui_load win32cui)
    add_importlibs(wow64_gui_load msvcrt kernel32)

    add_asm_files(wow64_continue_asm ../ntdll/i386/Wow64Continue.S ../ntdll/i386/StackOverflowDispatch.S ../ntdll/i386/FaultContext.S)
    target_sources(ntdll_wow64_apitest PRIVATE ${wow64_continue_asm})
elseif(ARCH STREQUAL "amd64")
    add_asm_files(wow64_continue_asm ../ntdll/amd64/Wow64Continue.S ../ntdll/amd64/StackOverflowDispatch.S ../ntdll/amd64/FaultContext.S)
    target_sources(ntdll_wow64_apitest PRIVATE ${wow64_continue_asm})
endif()

add_subdirectory(sharedviews)
# Explicit, uninstalled unit fixture for wide guest readers. It compiles the
# production accessors and selected DLL sources, and uses the test-only native
# bridge until guest GUI syscall/callback dispatch is available.
if(ARCH STREQUAL "i386" AND NOT MSVC)
    add_asm_files(gueststate_asm i386/ClientPfn.S i386/GuestState.S)
    add_executable(wow64_guest_state EXCLUDE_FROM_ALL
        GuestState.c GuestStateUser.c GuestStateGdi.c GuestStateImm.c
        gueststate_testlist.c ${gueststate_asm})
    target_compile_definitions(wow64_guest_state PRIVATE W32K_WIDE)
    target_compile_options(wow64_guest_state PRIVATE -ffunction-sections -fdata-sections)
    target_link_options(wow64_guest_state PRIVATE -Wl,--gc-sections)
    target_include_directories(wow64_guest_state PRIVATE
        ${REACTOS_SOURCE_DIR}/win32ss/include
        ${REACTOS_SOURCE_DIR}/win32ss/user/user32/include
        ${REACTOS_SOURCE_DIR}/win32ss/gdi/gdi32/include
        ${REACTOS_SOURCE_DIR}/sdk/include/reactos/subsys
        ${REACTOS_SOURCE_DIR}/sdk/include/wine)
    target_link_libraries(wow64_guest_state wine ${PSEH_LIB})
    set_module_type(wow64_guest_state win32cui)
    add_importlibs(wow64_guest_state msvcrt kernel32 ntdll)
    add_dependencies(wow64_guest_state wow64_syscall_tables)
endif()

# The native syscall bridge is deliberately test-only, and uses GNU .code64
# in a PE32 fixture until wow64win provides the guest GUI entry points.
if(ARCH STREQUAL "amd64" OR (ARCH STREQUAL "i386" AND NOT MSVC))
    if(ARCH STREQUAL "i386")
        add_asm_files(clientpfn_asm i386/ClientPfn.S)
    endif()
    add_executable(win32k_wow64_apitest ClientPfn.c clientpfn_testlist.c ${clientpfn_asm})
    target_include_directories(win32k_wow64_apitest PRIVATE ${REACTOS_SOURCE_DIR}/win32ss/include)
    target_link_libraries(win32k_wow64_apitest wine ${PSEH_LIB})
    set_module_type(win32k_wow64_apitest win32cui)
    add_importlibs(win32k_wow64_apitest msvcrt kernel32 ntdll)
    add_dependencies(win32k_wow64_apitest wow64_syscall_tables)
    add_rostests_file(TARGET win32k_wow64_apitest)
endif()

# Explicit GUI integration fixture; default image contents stay unchanged.
add_executable(wow64_process_create EXCLUDE_FROM_ALL process_create.c)
set_module_type(wow64_process_create win32cui UNICODE)
add_importlibs(wow64_process_create msvcrt kernel32 ntdll)

add_executable(wow64_installer_driver EXCLUDE_FROM_ALL installer_driver.c)
set_module_type(wow64_installer_driver win32cui UNICODE)
add_importlibs(wow64_installer_driver user32 msvcrt kernel32 ntdll)

add_executable(wow64_installer_services EXCLUDE_FROM_ALL installer_services.c)
set_module_type(wow64_installer_services win32cui UNICODE)
add_importlibs(wow64_installer_services advapi32 msvcrt kernel32)

add_executable(wow64_socket EXCLUDE_FROM_ALL socket.c)
set_module_type(wow64_socket win32cui)
add_importlibs(wow64_socket ws2_32 msvcrt kernel32)

add_executable(wow64_root_store EXCLUDE_FROM_ALL root_store.c)
set_module_type(wow64_root_store win32cui)
add_importlibs(wow64_root_store crypt32 msvcrt kernel32)

add_executable(wow64_ownerdraw EXCLUDE_FROM_ALL ownerdraw.c)
set_module_type(wow64_ownerdraw win32cui)
add_importlibs(wow64_ownerdraw user32 gdi32 msvcrt kernel32)

add_executable(wow64_message_hook EXCLUDE_FROM_ALL message_hook.c)
set_module_type(wow64_message_hook win32cui)
add_importlibs(wow64_message_hook user32 msvcrt kernel32)

add_executable(wow64_copydata EXCLUDE_FROM_ALL copydata.c)
set_module_type(wow64_copydata win32cui)
add_importlibs(wow64_copydata user32 msvcrt kernel32)

add_executable(wow64_notify EXCLUDE_FROM_ALL notify.c)
set_module_type(wow64_notify win32cui)
add_importlibs(wow64_notify user32 msvcrt kernel32)

add_executable(wow64_thread_tls EXCLUDE_FROM_ALL thread_tls.c)
set_module_type(wow64_thread_tls win32cui)
add_importlibs(wow64_thread_tls msvcrt kernel32)

add_executable(wow64_relative_pipe EXCLUDE_FROM_ALL relative_pipe.c)
set_module_type(wow64_relative_pipe win32cui)
add_importlibs(wow64_relative_pipe msvcrt kernel32)

add_executable(wow64_unhandled EXCLUDE_FROM_ALL unhandled.c)
set_module_type(wow64_unhandled win32cui)
add_importlibs(wow64_unhandled msvcrt kernel32)

add_executable(wow64_stack_recreate EXCLUDE_FROM_ALL stack_recreate.c)
set_module_type(wow64_stack_recreate win32cui)
add_importlibs(wow64_stack_recreate msvcrt kernel32)

add_executable(wow64_console_create EXCLUDE_FROM_ALL console_create.c)
set_module_type(wow64_console_create win32cui)
add_importlibs(wow64_console_create msvcrt kernel32)

add_executable(wow64_registration EXCLUDE_FROM_ALL registration.c)
set_module_type(wow64_registration win32cui UNICODE)
add_importlibs(wow64_registration msvcrt kernel32)

spec2def(wow64_registration_dll.dll registration_dll.spec)
add_library(wow64_registration_dll MODULE EXCLUDE_FROM_ALL registration_dll.c
    ${CMAKE_CURRENT_BINARY_DIR}/wow64_registration_dll.def)
set_module_type(wow64_registration_dll win32dll UNICODE)
add_importlibs(wow64_registration_dll msvcrt kernel32)

add_executable(wow64_installer_gui EXCLUDE_FROM_ALL installer_gui.c)
set_module_type(wow64_installer_gui win32cui)
add_importlibs(wow64_installer_gui imm32 gdi32 user32 msvcrt kernel32)

add_executable(wow64_framechanged EXCLUDE_FROM_ALL framechanged.c)
set_module_type(wow64_framechanged win32cui)
add_importlibs(wow64_framechanged user32 gdi32 msvcrt kernel32)

add_executable(wow64_dc_cover EXCLUDE_FROM_ALL dc_cover.c)
set_module_type(wow64_dc_cover win32cui)
add_importlibs(wow64_dc_cover user32 gdi32 msvcrt kernel32)

add_executable(wow64_system_timer EXCLUDE_FROM_ALL system_timer.c)
set_module_type(wow64_system_timer win32cui)
add_importlibs(wow64_system_timer user32 gdi32 msvcrt kernel32)

add_executable(wow64_idle_loop EXCLUDE_FROM_ALL idle_loop.c)
set_module_type(wow64_idle_loop win32cui)
add_importlibs(wow64_idle_loop user32 msvcrt kernel32)

add_executable(wow64_mouse_points EXCLUDE_FROM_ALL mouse_points.c)
set_module_type(wow64_mouse_points win32cui)
add_importlibs(wow64_mouse_points user32 msvcrt kernel32)

if(ARCH STREQUAL "i386")
    add_asm_files(segment_return_asm i386/SegmentReturn.S)
    add_executable(wow64_segment_return EXCLUDE_FROM_ALL segment_return.c ${segment_return_asm})
    set_module_type(wow64_segment_return win32cui)
    add_importlibs(wow64_segment_return msvcrt kernel32)

    foreach(aware 0 1)
        set(memory_target wow64_installer_memory${aware})
        add_executable(${memory_target} EXCLUDE_FROM_ALL installer_memory.c)
        target_compile_definitions(${memory_target} PRIVATE EXPECT_LARGE_ADDRESS=${aware})
        set_module_type(${memory_target} win32cui)
        add_importlibs(${memory_target} msvcrt kernel32)
        set(limit_target wow64_guest_limit${aware})
        add_executable(${limit_target} EXCLUDE_FROM_ALL guest_limit.c)
        target_compile_definitions(${limit_target} PRIVATE EXPECT_LARGE_ADDRESS=${aware})
        set_module_type(${limit_target} win32cui)
        add_importlibs(${limit_target} msvcrt kernel32)
        if(MSVC)
            if(aware)
                target_link_options(${memory_target} PRIVATE /LARGEADDRESSAWARE)
                target_link_options(${limit_target} PRIVATE /LARGEADDRESSAWARE)
            else()
                target_link_options(${memory_target} PRIVATE /LARGEADDRESSAWARE:NO)
                target_link_options(${limit_target} PRIVATE /LARGEADDRESSAWARE:NO)
            endif()
        elseif(aware)
            target_link_options(${memory_target} PRIVATE -Wl,--large-address-aware)
            target_link_options(${limit_target} PRIVATE -Wl,--large-address-aware)
        else()
            target_link_options(${memory_target} PRIVATE -Wl,--disable-large-address-aware)
            target_link_options(${limit_target} PRIVATE -Wl,--disable-large-address-aware)
        endif()
    endforeach()
endif()

add_executable(wow64_gui_apps EXCLUDE_FROM_ALL gui_apps.c)
set_module_type(wow64_gui_apps win32cui)
add_importlibs(wow64_gui_apps user32 msvcrt kernel32)

add_executable(wow64_gui_controls EXCLUDE_FROM_ALL gui_controls.c)
set_module_type(wow64_gui_controls win32cui)
add_importlibs(wow64_gui_controls comdlg32 comctl32 user32 gdi32 msvcrt kernel32 ntdll)

add_executable(wow64_callback_unwind EXCLUDE_FROM_ALL callback_unwind.c)
target_link_libraries(wow64_callback_unwind ${PSEH_LIB})
set_module_type(wow64_callback_unwind win32cui)
add_importlibs(wow64_callback_unwind user32 msvcrt kernel32)

add_executable(wow64_first_window EXCLUDE_FROM_ALL first_window.c)
set_module_type(wow64_first_window win32cui)
add_importlibs(wow64_first_window user32 gdi32 msvcrt kernel32)

if(ARCH STREQUAL "i386")
    add_asm_files(wow64_win32k_stubs win32k_stubs.S)
    if(NOT MSVC)
        add_asm_files(wow64_callback_boundary_asm i386/CallbackBoundary.S)
        add_executable(wow64_callback_boundary EXCLUDE_FROM_ALL callback_boundary.c ${wow64_callback_boundary_asm} ${wow64_win32k_stubs})
        target_include_directories(wow64_callback_boundary PRIVATE ${REACTOS_SOURCE_DIR}/win32ss ${REACTOS_SOURCE_DIR}/win32ss/include)
        set_module_type(wow64_callback_boundary win32cui)
        add_importlibs(wow64_callback_boundary user32 msvcrt kernel32 ntdll)
    endif()
    add_executable(wow64_win32k_abi EXCLUDE_FROM_ALL win32k_abi.c ${wow64_win32k_stubs})
    target_include_directories(wow64_win32k_abi PRIVATE ${REACTOS_SOURCE_DIR}/win32ss ${REACTOS_SOURCE_DIR}/win32ss/include)
    set_module_type(wow64_win32k_abi win32cui)
    add_importlibs(wow64_win32k_abi user32 gdi32 msvcrt kernel32 ntdll)
endif()

# Guest-only loader change; keep the fixture out of default native images.
add_executable(wow64_loadfrom EXCLUDE_FROM_ALL loadfrom.c loadfrom_testlist.c)
target_include_directories(wow64_loadfrom PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../ntdll)
set_module_type(wow64_loadfrom win32cui)
target_link_libraries(wow64_loadfrom wine ${PSEH_LIB})
add_importlibs(wow64_loadfrom ntdll msvcrt kernel32)

add_executable(wow64_file_lock EXCLUDE_FROM_ALL file_lock.c)
set_module_type(wow64_file_lock win32cui)
add_importlibs(wow64_file_lock msvcrt kernel32)

add_executable(wow64_job EXCLUDE_FROM_ALL job.c)
set_module_type(wow64_job win32cui)
add_importlibs(wow64_job msvcrt kernel32)

add_executable(wow64_directory EXCLUDE_FROM_ALL wow64_directory.c)
set_module_type(wow64_directory win32cui)
add_importlibs(wow64_directory msvcrt kernel32)

add_executable(wow64_pipe_connect EXCLUDE_FROM_ALL pipe_connect.c)
set_module_type(wow64_pipe_connect win32cui)
add_importlibs(wow64_pipe_connect msvcrt kernel32)

add_executable(wow64_attach_fs EXCLUDE_FROM_ALL attach_fs.c)
set_module_type(wow64_attach_fs win32cui)
add_importlibs(wow64_attach_fs msvcrt kernel32)

add_executable(wow64_time_zone EXCLUDE_FROM_ALL time_zone.c)
set_module_type(wow64_time_zone win32cui)
add_importlibs(wow64_time_zone msvcrt kernel32)

add_executable(wow64_socket_event EXCLUDE_FROM_ALL socket_event.c)
set_module_type(wow64_socket_event win32cui)
add_importlibs(wow64_socket_event ws2_32 msvcrt kernel32 ntdll)

# Explicit fixture: build for amd64 and i386 and run the amd64 file with the i386 file as its child.
add_executable(wow64_command_line EXCLUDE_FROM_ALL command_line.c)
set_module_type(wow64_command_line win32cui UNICODE)
add_importlibs(wow64_command_line msvcrt kernel32)

# A 32-bit WMI client: the locator must be registered in the 32-bit registry view
add_executable(wow64_wbem_locator EXCLUDE_FROM_ALL wbem_locator.c)
set_module_type(wow64_wbem_locator win32cui UNICODE)
target_link_libraries(wow64_wbem_locator uuid)
add_importlibs(wow64_wbem_locator ole32 oleaut32 advapi32 msvcrt kernel32)
