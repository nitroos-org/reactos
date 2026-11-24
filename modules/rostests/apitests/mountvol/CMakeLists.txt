
list(APPEND SOURCE
    output.c)

add_executable(mountvol_apitest ${SOURCE})
set_module_type(mountvol_apitest win32cui)
target_link_libraries(mountvol_apitest winetestlib)
add_importlibs(mountvol_apitest msvcrt kernel32)
add_rostests_file(TARGET mountvol_apitest)
