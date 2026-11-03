
spec2def(scardsvr.dll scardsvr.spec)

list(APPEND SOURCE
    scardsvr.c)

add_library(scardsvr MODULE
    ${SOURCE}
    scardsvr.rc
    ${CMAKE_CURRENT_BINARY_DIR}/scardsvr.def)

set_module_type(scardsvr win32dll UNICODE)
add_importlibs(scardsvr advapi32 msvcrt kernel32 ntdll)
add_cd_file(TARGET scardsvr DESTINATION reactos/system32 FOR all)
