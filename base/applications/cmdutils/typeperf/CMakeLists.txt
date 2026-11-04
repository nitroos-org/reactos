
add_executable(typeperf typeperf.c typeperf.rc)
set_module_type(typeperf win32cui UNICODE)
add_importlibs(typeperf pdh advapi32 msvcrt kernel32)
add_cd_file(TARGET typeperf DESTINATION reactos/system32 FOR all)
