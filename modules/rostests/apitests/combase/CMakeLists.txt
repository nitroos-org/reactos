
list(APPEND SOURCE
    ApartmentEndpoint.c
    RoFailFast.c
    testlist.c)

add_executable(combase_apitest ${SOURCE})
target_link_libraries(combase_apitest wine uuid)
set_module_type(combase_apitest win32cui)
add_importlibs(combase_apitest ole32 user32 msvcrt kernel32 ntdll)
add_rostests_file(TARGET combase_apitest)
