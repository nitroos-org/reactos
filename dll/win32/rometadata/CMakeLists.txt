
spec2def(rometadata.dll rometadata.spec ADD_IMPORTLIB)

list(APPEND SOURCE
    rometadata.c
    ${CMAKE_CURRENT_BINARY_DIR}/rometadata.def)

add_library(rometadata MODULE ${SOURCE} rometadata.rc)
set_module_type(rometadata win32dll)
add_importlibs(rometadata msvcrt kernel32 ntdll)
add_cd_file(TARGET rometadata DESTINATION reactos/system32 FOR all)
