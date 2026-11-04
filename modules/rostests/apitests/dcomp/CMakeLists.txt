
list(APPEND SOURCE
    DCompositionCreateDevice.c
    testlist.c)

add_executable(dcomp_apitest ${SOURCE})
target_link_libraries(dcomp_apitest wine uuid dxguid)
set_module_type(dcomp_apitest win32cui)
add_importlibs(dcomp_apitest d3d11 dxgi user32 gdi32 msvcrt kernel32 ntdll)
add_dependencies(dcomp_apitest d3d_idl_headers)
add_rostests_file(TARGET dcomp_apitest)
