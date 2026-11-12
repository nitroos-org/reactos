
add_executable(wsnmp32_apitest Exports.c testlist.c)
set_module_type(wsnmp32_apitest win32cui)
add_importlibs(wsnmp32_apitest msvcrt kernel32)
add_rostests_file(TARGET wsnmp32_apitest)
