
spec2def(netiohlp.dll netiohlp.spec)

list(APPEND SOURCE
    netiohlp.c
    portproxy.c
    precomp.h
    ${CMAKE_CURRENT_BINARY_DIR}/netiohlp.def)

add_library(netiohlp MODULE ${SOURCE} netiohlp.rc)
set_module_type(netiohlp win32dll UNICODE)
target_link_libraries(netiohlp uuid)
add_importlibs(netiohlp netsh advapi32 msvcrt kernel32 ntdll)
add_pch(netiohlp precomp.h SOURCE)
add_cd_file(TARGET netiohlp DESTINATION reactos/system32 FOR all)
