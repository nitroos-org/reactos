
spec2def(wsnmp32.dll wsnmp32.spec ADD_IMPORTLIB)

list(APPEND SOURCE
    wsnmp32.c
    ${CMAKE_CURRENT_BINARY_DIR}/wsnmp32_stubs.c
    ${CMAKE_CURRENT_BINARY_DIR}/wsnmp32.def)

add_library(wsnmp32 MODULE ${SOURCE} wsnmp32.rc)
set_module_type(wsnmp32 win32dll)
target_link_libraries(wsnmp32 wine)
add_importlibs(wsnmp32 msvcrt kernel32 ntdll)
add_cd_file(TARGET wsnmp32 DESTINATION reactos/system32 FOR all)
set_wine_module(wsnmp32)
