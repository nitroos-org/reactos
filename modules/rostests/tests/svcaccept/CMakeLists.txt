add_executable(svcaccept svcaccept.c)
set_module_type(svcaccept win32cui)
add_importlibs(svcaccept advapi32 msvcrt kernel32)
add_rostests_file(TARGET svcaccept)
