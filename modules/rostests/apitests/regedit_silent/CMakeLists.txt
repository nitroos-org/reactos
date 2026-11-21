list(APPEND SOURCE
    regedit_silent.c
    testlist.c)

add_executable(regedit_silent_apitest ${SOURCE})
target_link_libraries(regedit_silent_apitest wine ${PSEH_LIB})
set_module_type(regedit_silent_apitest win32cui)
add_importlibs(regedit_silent_apitest user32 advapi32 msvcrt kernel32)
add_rostests_file(TARGET regedit_silent_apitest)
