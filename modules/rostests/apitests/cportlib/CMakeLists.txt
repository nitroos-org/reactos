
list(APPEND SOURCE
    uart16550.c
    uart16550_mock.c
    testlist.c)

add_executable(cportlib_apitest ${SOURCE})
set_module_type(cportlib_apitest win32cui)
target_link_libraries(cportlib_apitest wine)
add_importlibs(cportlib_apitest msvcrt kernel32 ntdll)
add_rostests_file(TARGET cportlib_apitest)
