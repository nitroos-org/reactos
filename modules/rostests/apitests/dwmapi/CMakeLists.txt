
add_executable(dwmapi_apitest DwmExtendFrame.c DwmFlush.c DwmWindowAttribute.c DwmNcRendering.c testlist.c)
target_link_libraries(dwmapi_apitest wine)
set_module_type(dwmapi_apitest win32cui)
add_importlibs(dwmapi_apitest user32 msvcrt kernel32 ntdll)
add_rostests_file(TARGET dwmapi_apitest)
