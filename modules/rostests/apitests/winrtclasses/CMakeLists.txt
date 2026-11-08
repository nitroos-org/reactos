
list(APPEND SOURCE
    winrtclasses.c
    testlist.c)

add_executable(winrtclasses_apitest ${SOURCE})
target_link_libraries(winrtclasses_apitest wine uuid)
set_module_type(winrtclasses_apitest win32cui)
add_importlibs(winrtclasses_apitest ole32 advapi32 user32 msvcrt kernel32 ntdll)
add_rostests_file(TARGET winrtclasses_apitest)
