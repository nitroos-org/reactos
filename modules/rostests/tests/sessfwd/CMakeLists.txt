
include_directories(${REACTOS_SOURCE_DIR}/sdk/include/reactos/subsys)
add_executable(sessfwd sessfwd.c)
set_module_type(sessfwd win32cui UNICODE)
target_link_libraries(sessfwd smlib)
add_importlibs(sessfwd advapi32 msvcrt kernel32 ntdll)
add_rostests_file(TARGET sessfwd)
