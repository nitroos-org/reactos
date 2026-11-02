
spec2def(httpapi.dll httpapi.spec ADD_IMPORTLIB)

list(APPEND SOURCE
    conn.c
    httpapi.c
    iocp.c
    urls.c
    ${CMAKE_CURRENT_BINARY_DIR}/httpapi_stubs.c
    ${CMAKE_CURRENT_BINARY_DIR}/httpapi.def)

add_library(httpapi MODULE ${SOURCE})
set_module_type(httpapi win32dll)
add_importlibs(httpapi ws2_32 msvcrt kernel32 ntdll)
add_cd_file(TARGET httpapi DESTINATION reactos/system32 FOR all)
