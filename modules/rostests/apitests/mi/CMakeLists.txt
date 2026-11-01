
list(APPEND SOURCE
    mi.c
    testlist.c)

add_executable(mi_apitest ${SOURCE})
set_module_type(mi_apitest win32cui)
target_link_libraries(mi_apitest uuid)
add_importlibs(mi_apitest ole32 oleaut32 advapi32 msvcrt kernel32)
add_rostests_file(TARGET mi_apitest)
