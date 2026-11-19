add_executable(nitro-firstrun nitro-firstrun.c nitro-firstrun.rc)
set_module_type(nitro-firstrun win32cui UNICODE)
add_importlibs(nitro-firstrun advapi32 msvcrt kernel32)
add_cd_file(TARGET nitro-firstrun DESTINATION reactos/system32 FOR all)
