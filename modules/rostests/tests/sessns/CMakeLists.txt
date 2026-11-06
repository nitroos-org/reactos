add_executable(sessns sessns.c)
set_module_type(sessns win32gui UNICODE)
add_importlibs(sessns msvcrt kernel32 ntdll)
add_rostests_file(TARGET sessns)
