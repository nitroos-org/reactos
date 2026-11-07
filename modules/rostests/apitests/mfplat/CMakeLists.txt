
list(APPEND SOURCE
    MftAac.c
    testlist.c)

add_executable(mfplat_apitest ${SOURCE})
target_link_libraries(mfplat_apitest mfuuid uuid wine ${PSEH_LIB})
set_module_type(mfplat_apitest win32cui)
add_importlibs(mfplat_apitest mfplat ole32 advapi32 msvcrt kernel32 ntdll)
add_rostests_file(TARGET mfplat_apitest)
