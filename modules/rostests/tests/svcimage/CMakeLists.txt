add_executable(svcimage svcimage.c)
set_module_type(svcimage win32cui)
add_importlibs(svcimage advapi32 msvcrt kernel32)
add_rostests_file(TARGET svcimage)
