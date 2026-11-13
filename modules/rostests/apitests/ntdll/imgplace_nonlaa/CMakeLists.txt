
# The helper of the ImagePlacement test (it runs as a copy without IMAGE_FILE_LARGE_ADDRESS_AWARE)
add_executable(imgplace_nonlaa imgplace_nonlaa.c)
set_module_type(imgplace_nonlaa win32cui UNICODE)
# The binutils of the toolchain cannot clear the flag: the test clears it in the copy it writes
add_importlibs(imgplace_nonlaa msvcrt kernel32)
add_dependencies(imgplace_nonlaa psdk)
