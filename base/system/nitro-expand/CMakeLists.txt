
add_executable(nitro-expand nitro-expand.c nitro-expand.rc)
set_module_type(nitro-expand win32cui UNICODE)
add_importlibs(nitro-expand advapi32 msvcrt kernel32)
add_cd_file(TARGET nitro-expand DESTINATION reactos/system32 FOR all)
