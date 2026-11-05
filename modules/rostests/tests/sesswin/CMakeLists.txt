
add_executable(sesswin sesswin.c)
set_module_type(sesswin win32gui UNICODE)
add_importlibs(sesswin msvcrt kernel32 ntdll)
add_rostests_file(TARGET sesswin)
