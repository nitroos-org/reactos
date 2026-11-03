
spec2def(iphlpsvc.dll iphlpsvc.spec)

list(APPEND SOURCE
    iphlpsvc.c
    portproxy.c
    precomp.h)

add_library(iphlpsvc MODULE
    ${SOURCE}
    iphlpsvc.rc
    ${CMAKE_CURRENT_BINARY_DIR}/iphlpsvc.def)

set_module_type(iphlpsvc win32dll UNICODE)
add_importlibs(iphlpsvc ws2_32 advapi32 msvcrt kernel32 ntdll)
add_pch(iphlpsvc precomp.h SOURCE)
add_cd_file(TARGET iphlpsvc DESTINATION reactos/system32 FOR all)
