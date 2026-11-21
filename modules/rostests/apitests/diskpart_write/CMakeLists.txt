list(APPEND SOURCE
    diskpart_write.c
    testlist.c)

add_executable(diskpart_write_apitest ${SOURCE})
target_link_libraries(diskpart_write_apitest wine ${PSEH_LIB})
set_module_type(diskpart_write_apitest win32cui)
add_importlibs(diskpart_write_apitest msvcrt kernel32)
add_rostests_file(TARGET diskpart_write_apitest)
