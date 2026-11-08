
list(APPEND SOURCE
    DOMDocument.c
    SchemaCache.c
    XPathFunc.c
    testlist.c)

add_executable(msxml3_apitest ${SOURCE})
set_module_type(msxml3_apitest win32cui)
target_link_libraries(msxml3_apitest uuid)
add_importlibs(msxml3_apitest oleaut32 ole32 msvcrt kernel32)
add_rostests_file(TARGET msxml3_apitest)
