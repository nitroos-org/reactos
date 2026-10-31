
list(APPEND SOURCE
    SecretAgreement.c
    testlist.c)

add_executable(ncrypt_apitest ${SOURCE})
target_link_libraries(ncrypt_apitest wine)
set_module_type(ncrypt_apitest win32cui)
add_importlibs(ncrypt_apitest ncrypt bcrypt advapi32 msvcrt kernel32 ntdll)
add_rostests_file(TARGET ncrypt_apitest)
