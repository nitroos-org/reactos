
add_library(obcbtest MODULE obcbtest.c)
set_module_type(obcbtest kernelmodedriver)
add_importlibs(obcbtest ntoskrnl)
add_rostests_file(TARGET obcbtest)

add_executable(obcbcheck obcbcheck.c)
set_module_type(obcbcheck win32cui)
add_importlibs(obcbcheck msvcrt kernel32 ntdll)
add_rostests_file(TARGET obcbcheck)
