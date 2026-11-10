
list(APPEND SOURCE
    interface_access.c)

list(APPEND PCH_SKIP_SOURCE
    testlist.c)

add_executable(rpcrt4_apitest
    ${SOURCE}
    testlist.c)

set_module_type(rpcrt4_apitest win32cui)
add_importlibs(rpcrt4_apitest rpcrt4 ws2_32 advapi32 msvcrt kernel32 ntdll)
add_rostests_file(TARGET rpcrt4_apitest)
