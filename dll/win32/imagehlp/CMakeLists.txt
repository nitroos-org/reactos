
add_definitions(-D_IMAGEHLP_SOURCE_)
include_directories(BEFORE ${REACTOS_SOURCE_DIR}/sdk/include/wine)
spec2def(imagehlp.dll imagehlp.spec ADD_IMPORTLIB)

list(APPEND SOURCE
    access.c
    imagehlp_main.c
    integrity.c
    modify.c)

list(APPEND PCH_SKIP_SOURCE
    ${CMAKE_CURRENT_BINARY_DIR}/imagehlp_stubs.c)

add_library(imagehlp MODULE
    ${SOURCE}
    ${PCH_SKIP_SOURCE}
    imagehlp.rc
    ${CMAKE_CURRENT_BINARY_DIR}/imagehlp.def)

set_module_type(imagehlp win32dll)
target_link_libraries(imagehlp wine ${PSEH_LIB})
# dbghelp is loaded from the system directory when first needed (see imagehlp_main.c), not imported: an import
# makes it a known DLL through the imports of the known imagehlp, and a program's own dbghelp.dll is then ignored.
add_delay_importlibs(imagehlp dbghelp)
add_importlibs(imagehlp msvcrt kernel32 ntdll)
add_pch(imagehlp precomp.h "${PCH_SKIP_SOURCE}")
add_cd_file(TARGET imagehlp DESTINATION reactos/system32 FOR all)
