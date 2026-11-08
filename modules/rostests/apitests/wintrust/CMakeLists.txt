
list(APPEND SOURCE
    SignatureTimeStamp.c
    SpcIndirectData.c
    WTHelperGetFileHash.c
    testlist.c)

add_executable(wintrust_apitest ${SOURCE})
target_link_libraries(wintrust_apitest wine ${PSEH_LIB})
set_module_type(wintrust_apitest win32cui)
add_importlibs(wintrust_apitest wintrust crypt32 advapi32 user32 msvcrt kernel32 ntdll)
add_rostests_file(TARGET wintrust_apitest)
