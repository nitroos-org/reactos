list(APPEND SOURCE
    diskpart_volumes.c
    testlist.c)

add_executable(diskpart_volumes_apitest ${SOURCE})
target_link_libraries(diskpart_volumes_apitest wine ${PSEH_LIB})
set_module_type(diskpart_volumes_apitest win32cui)
add_importlibs(diskpart_volumes_apitest msvcrt kernel32)
add_rostests_file(TARGET diskpart_volumes_apitest)
