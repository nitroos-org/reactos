
add_executable(d2d1_apitest d2d1_present.c d2d1_effects.c d2d1_effect_render.c d2d1_fillbatch.c d2d1_svg.c d2d1_svgdraw.c testlist.c)
target_link_libraries(d2d1_apitest wine uuid dxguid dx10guid)
set_module_type(d2d1_apitest win32cui)
add_importlibs(d2d1_apitest d2d1 d3d11 dxgi gdi32 user32 msvcrt kernel32)
add_rostests_file(TARGET d2d1_apitest)
