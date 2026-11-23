add_executable(mcspray mcspray.c)
set_module_type(mcspray win32cui)
add_importlibs(mcspray ws2_32 iphlpapi msvcrt kernel32)
add_rostests_file(TARGET mcspray)
