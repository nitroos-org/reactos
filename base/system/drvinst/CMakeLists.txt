
add_executable(drvinst drvinst.c drvinst.rc)
set_module_type(drvinst win32gui UNICODE)
add_importlibs(drvinst newdev advapi32 user32 msvcrt kernel32 ntdll)
add_cd_file(TARGET drvinst DESTINATION reactos/system32 FOR all)
