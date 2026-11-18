list(APPEND SOURCE
    diskpart_stdin.c
    testlist.c)

add_executable(diskpart_stdin_apitest ${SOURCE})
target_link_libraries(diskpart_stdin_apitest wine ${PSEH_LIB})
set_module_type(diskpart_stdin_apitest win32cui)
add_importlibs(diskpart_stdin_apitest msvcrt kernel32)
add_rostests_file(TARGET diskpart_stdin_apitest)
