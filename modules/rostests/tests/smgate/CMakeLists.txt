
include_directories(${REACTOS_SOURCE_DIR}/sdk/include/reactos/subsys)
add_executable(smgate smgate.c)
set_module_type(smgate win32cui UNICODE)
target_link_libraries(smgate smlib)
add_importlibs(smgate msvcrt kernel32 ntdll)
add_rostests_file(TARGET smgate)
