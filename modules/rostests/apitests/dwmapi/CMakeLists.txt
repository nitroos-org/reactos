
add_executable(dwmapi_apitest DwmFlush.c testlist.c)
target_link_libraries(dwmapi_apitest wine)
set_module_type(dwmapi_apitest win32cui)
add_importlibs(dwmapi_apitest msvcrt kernel32 ntdll)
add_rostests_file(TARGET dwmapi_apitest)
