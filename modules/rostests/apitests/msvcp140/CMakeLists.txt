
list(APPEND SOURCE
    Msvcp140MoneyIds.c
    Msvcp140ThrowCppError.c
    testlist.c)

add_executable(msvcp140_apitest ${SOURCE})
target_link_libraries(msvcp140_apitest wine ${PSEH_LIB})
set_module_type(msvcp140_apitest win32cui)
add_importlibs(msvcp140_apitest  msvcrt kernel32 ntdll)
add_rostests_file(TARGET msvcp140_apitest)
