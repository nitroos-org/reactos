
include_directories(${REACTOS_SOURCE_DIR}/base/services/dhcpcsvc)
spec2def(dhcpcsvc6.dll dhcpcsvc6.spec ADD_IMPORTLIB)

list(APPEND SOURCE
    dhcpcsvc6.c
    ${CMAKE_CURRENT_BINARY_DIR}/dhcpcsvc6_stubs.c)

add_library(dhcpcsvc6 MODULE
    ${SOURCE}
    dhcpcsvc6.rc
    ${CMAKE_CURRENT_BINARY_DIR}/dhcpcsvc6.def)

set_module_type(dhcpcsvc6 win32dll)
add_importlibs(dhcpcsvc6 advapi32 msvcrt kernel32 ntdll)
add_cd_file(TARGET dhcpcsvc6 DESTINATION reactos/system32 FOR all)
