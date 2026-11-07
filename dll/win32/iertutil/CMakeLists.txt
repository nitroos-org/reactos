
remove_definitions(-D_WIN32_WINNT=0x502 -DWINVER=0x502)
add_definitions(
    -D__WINESRC__
    -D_WIN32_WINNT=0x601
    -DWINVER=0x601)
include_directories(BEFORE ${REACTOS_SOURCE_DIR}/sdk/include/wine)

spec2def(iertutil.dll iertutil.spec ADD_IMPORTLIB)

list(APPEND SOURCE
    main.c
    uri.c)

add_library(iertutil MODULE
    ${SOURCE}
    version.rc
    ${CMAKE_CURRENT_BINARY_DIR}/iertutil.def
    ${CMAKE_CURRENT_BINARY_DIR}/iertutil_stubs.c)

add_idl_headers(iertutil_idlheader iertutil_classes.idl)
# CLSID_CUri registration (iertutil_classes.idl) and the Windows.Foundation.Uri activatable class (classes.idl)
add_idl_reg_scripts(iertutil registry iertutil_classes.idl)
add_idl_reg_scripts(iertutil winrt classes.idl)

set_module_type(iertutil win32dll)
target_link_libraries(iertutil wine wine_dll_register wine_dll_canunload uuid oldnames)
add_importlibs(iertutil ole32 oleaut32 rpcrt4 shlwapi combase msvcrt kernel32_vista kernel32 ntdll)
add_dependencies(iertutil psdk wineheaders iertutil_idlheader)
add_cd_file(TARGET iertutil DESTINATION reactos/system32 FOR all)
set_wine_module_FIXME(iertutil) # CORE-5743: No ARRAY_SIZE macro
