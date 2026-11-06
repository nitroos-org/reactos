
list(APPEND SOURCE
    regrow.c)

add_executable(fsregrow_apitest ${SOURCE})
set_module_type(fsregrow_apitest win32cui)
target_link_libraries(fsregrow_apitest winetestlib)
add_importlibs(fsregrow_apitest msvcrt kernel32 ntdll)

add_rostests_file(TARGET fsregrow_apitest)
