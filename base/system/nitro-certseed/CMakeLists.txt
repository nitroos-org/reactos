add_executable(nitro-certseed nitro-certseed.c nitro-certseed.rc)
set_module_type(nitro-certseed win32cui UNICODE)
add_importlibs(nitro-certseed crypt32 advapi32 msvcrt kernel32)
add_cd_file(TARGET nitro-certseed DESTINATION reactos/system32 FOR all)
