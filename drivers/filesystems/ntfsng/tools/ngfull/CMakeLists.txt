add_executable(ngfull ngfull.c)
set_module_type(ngfull win32cui)
add_importlibs(ngfull msvcrt kernel32 ntdll)
