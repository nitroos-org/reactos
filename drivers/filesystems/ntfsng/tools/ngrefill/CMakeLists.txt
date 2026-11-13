add_executable(ngrefill ngrefill.c)
set_module_type(ngrefill win32cui)
add_importlibs(ngrefill msvcrt kernel32)
