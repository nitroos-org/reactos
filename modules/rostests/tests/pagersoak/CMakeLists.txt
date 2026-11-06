add_executable(pagersoak pagersoak.c)
set_module_type(pagersoak win32cui)
add_importlibs(pagersoak advapi32 msvcrt kernel32 ntdll)
add_rostests_file(TARGET pagersoak)
