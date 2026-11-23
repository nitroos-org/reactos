
add_executable(svcshutdown svcshutdown.c)
set_module_type(svcshutdown win32cui)
add_importlibs(svcshutdown advapi32 msvcrt kernel32)
add_rostests_file(TARGET svcshutdown)
