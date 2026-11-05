
list(APPEND SOURCE
    DispatcherQueue.c
    testlist.c)

add_executable(coremessaging_apitest ${SOURCE})
target_link_libraries(coremessaging_apitest wine uuid)
set_module_type(coremessaging_apitest win32cui)
add_importlibs(coremessaging_apitest user32 ole32 advapi32 msvcrt kernel32 ntdll)
add_rostests_file(TARGET coremessaging_apitest)
