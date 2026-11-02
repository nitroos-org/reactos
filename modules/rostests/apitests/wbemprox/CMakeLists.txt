
list(APPEND SOURCE
    Win32_Process.c
    testlist.c)

add_executable(wbemprox_apitest ${SOURCE})
target_link_libraries(wbemprox_apitest uuid)
set_module_type(wbemprox_apitest win32cui)
add_importlibs(wbemprox_apitest advapi32 oleaut32 ole32 msvcrt kernel32)
add_rostests_file(TARGET wbemprox_apitest)
