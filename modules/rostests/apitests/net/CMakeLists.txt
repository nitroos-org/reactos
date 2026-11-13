
list(APPEND SOURCE
    NetExit.c
    NetStartArgs.c
    NetShare.c
    testlist.c)

add_executable(net_apitest ${SOURCE})
target_link_libraries(net_apitest wine ${PSEH_LIB})
set_module_type(net_apitest win32cui)
add_importlibs(net_apitest msvcrt advapi32 kernel32)
add_rostests_file(TARGET net_apitest)
