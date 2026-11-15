
add_executable(fsngrace fsngrace.c)
set_module_type(fsngrace win32cui UNICODE)
add_importlibs(fsngrace msvcrt kernel32 ntdll)
add_rostests_file(TARGET fsngrace)
