
add_executable(nitro-driverlog nitro-driverlog.c nitro-driverlog.rc)
set_module_type(nitro-driverlog win32cui UNICODE)
add_importlibs(nitro-driverlog advapi32 msvcrt kernel32)
add_cd_file(TARGET nitro-driverlog DESTINATION reactos/system32 FOR all)
