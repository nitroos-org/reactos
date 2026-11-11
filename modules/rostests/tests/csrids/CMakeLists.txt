
include_directories(${REACTOS_SOURCE_DIR}/sdk/include/reactos/subsys)
add_executable(csrids csrids.c)
set_module_type(csrids win32cui UNICODE)
add_importlibs(csrids advapi32 msvcrt kernel32 ntdll)
add_rostests_file(TARGET csrids)
