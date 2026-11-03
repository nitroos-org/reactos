
spec2def(winscard.dll winscard.spec ADD_IMPORTLIB)

list(APPEND SOURCE
    winscard.c
    cards.c
    context.c
    stubs.c
    precomp.h
    ${CMAKE_CURRENT_BINARY_DIR}/winscard_stubs.c)

add_library(winscard MODULE
    ${SOURCE}
    winscard.rc
    ${CMAKE_CURRENT_BINARY_DIR}/winscard.def)

set_module_type(winscard win32dll)
target_link_libraries(winscard wine)
add_importlibs(winscard advapi32 msvcrt kernel32 ntdll)
add_pch(winscard precomp.h SOURCE)
add_cd_file(TARGET winscard DESTINATION reactos/system32 FOR all)
set_wine_module(winscard)
