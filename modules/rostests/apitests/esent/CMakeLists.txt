
add_executable(esent_apitest DelayImports.c testlist.c)
set_module_type(esent_apitest win32cui)
add_importlibs(esent_apitest msvcrt kernel32 ntdll)
add_rostests_file(TARGET esent_apitest)
