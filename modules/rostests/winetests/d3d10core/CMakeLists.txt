
add_definitions(-DWINETEST_WINE_DBG_STUBS -DUSE_WINE_TODOS -D_USE_MATH_DEFINES -DWINETEST_USE_DBGSTR_LONGLONG -DCONST_VTABLE)
add_executable(d3d10core_winetest d3d10core.c testlist.c)
target_link_libraries(d3d10core_winetest uuid dxguid dx10guid)
set_module_type(d3d10core_winetest win32cui)
add_importlibs(d3d10core_winetest d3d10 dxgi user32 msvcrt kernel32 ntdll)
add_rostests_file(TARGET d3d10core_winetest)
