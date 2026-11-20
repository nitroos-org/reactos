
list(APPEND SOURCE
    StorportRoutines.c
    testlist.c)

include_directories(${REACTOS_SOURCE_DIR}/modules/rostests/drivers/storest)
add_executable(storport_apitest ${SOURCE})
set_module_type(storport_apitest win32cui)
add_importlibs(storport_apitest advapi32 setupapi shlwapi user32 msvcrt kernel32)
add_dependencies(storport_apitest storest)
add_rostests_file(TARGET storport_apitest)
