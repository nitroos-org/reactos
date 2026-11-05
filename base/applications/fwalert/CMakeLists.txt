add_executable(fwalert fwalert.c fwalert.rc)
set_module_type(fwalert win32gui UNICODE)
add_importlibs(fwalert version shell32 user32 gdi32 advapi32 msvcrt kernel32)
add_cd_file(TARGET fwalert DESTINATION reactos/system32 FOR all)
