add_executable(sppc_apitest licenses.c testlist.c)
set_module_type(sppc_apitest win32cui)
add_importlibs(sppc_apitest msvcrt kernel32)
add_rostests_file(TARGET sppc_apitest)
