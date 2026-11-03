list(APPEND SOURCE
    output.c)

add_executable(fsutil_apitest ${SOURCE})
set_module_type(fsutil_apitest win32cui)
target_link_libraries(fsutil_apitest winetestlib)
add_importlibs(fsutil_apitest msvcrt kernel32)
add_rostests_file(TARGET fsutil_apitest)
