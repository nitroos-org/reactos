
list(APPEND SOURCE
    BCryptDeriveKey.c
    BCryptKeyExport.c
    testlist.c)

add_executable(bcrypt_apitest ${SOURCE})
target_link_libraries(bcrypt_apitest wine ${PSEH_LIB})
set_module_type(bcrypt_apitest win32cui)
add_importlibs(bcrypt_apitest bcrypt msvcrt kernel32 ntdll)
add_rostests_file(TARGET bcrypt_apitest)
