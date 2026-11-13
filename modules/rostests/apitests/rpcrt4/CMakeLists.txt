
include_directories(${CMAKE_CURRENT_BINARY_DIR})
set(OLD_IDL_FLAGS ${IDL_FLAGS})
set(IDL_FLAGS ${IDL_FLAGS} -Oif --prefix-client=)
add_rpc_files(client interface_access.idl)
add_rpc_files(client ntlm_auth.idl)
set(IDL_FLAGS ${OLD_IDL_FLAGS})

list(APPEND SOURCE
    interface_access.c
    ntlm_auth.c
    ${CMAKE_CURRENT_BINARY_DIR}/interface_access_c.c
    ${CMAKE_CURRENT_BINARY_DIR}/ntlm_auth_c.c)

list(APPEND PCH_SKIP_SOURCE
    testlist.c)

add_executable(rpcrt4_apitest
    ${SOURCE}
    testlist.c)

set_module_type(rpcrt4_apitest win32cui)
target_link_libraries(rpcrt4_apitest ${PSEH_LIB})
target_link_libraries(rpcrt4_apitest ${PSEH_LIB})
add_importlibs(rpcrt4_apitest rpcrt4 ws2_32 advapi32 netapi32 msvcrt kernel32 ntdll)
add_rostests_file(TARGET rpcrt4_apitest)
