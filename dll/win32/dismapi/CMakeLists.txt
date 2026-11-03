spec2def(dismapi.dll dismapi.spec ADD_IMPORTLIB)

list(APPEND SOURCE
    dismapi.c
    ${CMAKE_CURRENT_BINARY_DIR}/dismapi_stubs.c
    ${CMAKE_CURRENT_BINARY_DIR}/dismapi.def)

add_library(dismapi MODULE ${SOURCE})
set_module_type(dismapi win32dll UNICODE)
add_importlibs(dismapi msvcrt kernel32 ntdll)
add_dependencies(dismapi psdk)
add_cd_file(TARGET dismapi DESTINATION reactos/system32 FOR all)
