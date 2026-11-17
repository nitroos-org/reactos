
add_executable(netcfgx_apitest Tcpip6Component.c testlist.c)
target_link_libraries(netcfgx_apitest uuid)
set_module_type(netcfgx_apitest win32cui)
add_importlibs(netcfgx_apitest shell32 comctl32 ole32 advapi32 user32 msvcrt kernel32 ntdll)
add_rostests_file(TARGET netcfgx_apitest)
