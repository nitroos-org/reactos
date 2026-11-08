
spec2def(dcomp.dll dcomp.spec ADD_IMPORTLIB)

list(APPEND SOURCE
    device.c
    winrt.c
    composition.c
    compgfx.c
    ${CMAKE_CURRENT_BINARY_DIR}/dcomp_stubs.c)

add_library(dcomp MODULE
    ${SOURCE}
    ${CMAKE_CURRENT_BINARY_DIR}/dcomp.def)

set_module_type(dcomp win32dll)
target_link_libraries(dcomp wine wine_dll_canunload uuid dxguid)
add_importlibs(dcomp combase ole32 user32 advapi32 msvcrt kernel32 ntdll)
add_dependencies(dcomp wineheaders d3d_idl_headers psdk)
add_cd_file(TARGET dcomp DESTINATION reactos/system32 FOR all)
set_wine_module_FIXME(dcomp) # CORE-5743: No ARRAY_SIZE macro
