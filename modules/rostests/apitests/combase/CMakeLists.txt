
list(APPEND SOURCE
    RoFailFast.c
    testlist.c)

add_executable(combase_apitest ${SOURCE})
target_link_libraries(combase_apitest wine)
set_module_type(combase_apitest win32cui)
add_importlibs(combase_apitest msvcrt kernel32 ntdll)
add_rostests_file(TARGET combase_apitest)
