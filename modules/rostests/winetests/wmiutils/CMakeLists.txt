
add_definitions(
    -DUSE_WINE_TODOS
    -D__WINESRC__
    -DWINETEST_USE_DBGSTR_LONGLONG)

add_executable(wmiutils_winetest path.c testlist.c)
target_link_libraries(wmiutils_winetest uuid)
set_module_type(wmiutils_winetest win32cui)
add_importlibs(wmiutils_winetest ole32 msvcrt kernel32 ntdll)
add_rostests_file(TARGET wmiutils_winetest)
