spec2def(slc.dll slc.spec ADD_IMPORTLIB)

add_library(slc MODULE
    slc.c
    slc.rc
    ${CMAKE_CURRENT_BINARY_DIR}/slc_stubs.c
    ${CMAKE_CURRENT_BINARY_DIR}/slc.def)

set_module_type(slc win32dll UNICODE)
add_importlibs(slc msvcrt kernel32 ntdll)
add_cd_file(TARGET slc DESTINATION reactos/system32 FOR all)
