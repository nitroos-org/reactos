
include_directories(${REACTOS_SOURCE_DIR}/sdk/include/reactos/idl)
add_rpc_files(server ${REACTOS_SOURCE_DIR}/sdk/include/reactos/idl/dcomlaunch.idl)
spec2def(dcomlaunch.dll dcomlaunch.spec ADD_IMPORTLIB)

add_library(dcomlaunch MODULE
    dcomlaunch.c
    network.c
    svcstart.c
    dcomlaunch.rc
    ${CMAKE_CURRENT_BINARY_DIR}/dcomlaunch_s.c
    ${CMAKE_CURRENT_BINARY_DIR}/dcomlaunch.def)

set_module_type(dcomlaunch win32dll UNICODE)
add_importlibs(dcomlaunch advapi32 rpcrt4 msvcrt kernel32 ntdll)
add_cd_file(TARGET dcomlaunch DESTINATION reactos/system32 FOR all)
