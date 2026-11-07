
list(APPEND SOURCE
    HttpError.c
    TaskQueue.c
    testlist.c)

add_executable(urlmon_apitest ${SOURCE})
set_module_type(urlmon_apitest win32cui)
target_link_libraries(urlmon_apitest uuid)
add_importlibs(urlmon_apitest urlmon ws2_32 ole32 user32 msvcrt kernel32)
add_rostests_file(TARGET urlmon_apitest)
