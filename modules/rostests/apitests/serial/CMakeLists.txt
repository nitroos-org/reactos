
list(APPEND SOURCE
    PortNames.c)

add_executable(serial_apitest ${SOURCE})
set_module_type(serial_apitest win32cui)
target_link_libraries(serial_apitest winetestlib)
add_importlibs(serial_apitest advapi32 setupapi msvcrt kernel32 ntdll)

add_rostests_file(TARGET serial_apitest)
