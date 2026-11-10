
add_executable(dwrite_apitest dwrite_glyph_leak.c testlist.c)
target_link_libraries(dwrite_apitest wine uuid dxguid)
set_module_type(dwrite_apitest win32cui)
add_importlibs(dwrite_apitest dwrite psapi user32 msvcrt kernel32)
add_rostests_file(TARGET dwrite_apitest)
