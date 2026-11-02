
list(APPEND SOURCE
    HttpServerApi.c
    HttpServerFlow.c
    testlist.c)

add_executable(httpapi_apitest ${SOURCE})
target_link_libraries(httpapi_apitest wine ${PSEH_LIB})
set_module_type(httpapi_apitest win32cui)
add_importlibs(httpapi_apitest httpapi ws2_32 msvcrt kernel32 ntdll)
add_rostests_file(TARGET httpapi_apitest)
