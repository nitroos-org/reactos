
list(APPEND SOURCE
    umapped.c)

add_executable(umapped_apitest ${SOURCE})
set_module_type(umapped_apitest win32cui)
target_link_libraries(umapped_apitest winetestlib)
add_importlibs(umapped_apitest msvcrt kernel32 ntdll)

add_rostests_file(TARGET umapped_apitest)
