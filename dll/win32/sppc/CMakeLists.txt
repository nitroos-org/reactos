spec2def(sppc.dll sppc.spec ADD_IMPORTLIB)

add_library(sppc MODULE
    sppc.c
    sppc.rc
    ${CMAKE_CURRENT_BINARY_DIR}/sppc.def)

set_module_type(sppc win32dll UNICODE)
target_link_libraries(sppc pseh)
add_importlibs(sppc msvcrt kernel32 ntdll)
add_cd_file(TARGET sppc DESTINATION reactos/system32 FOR all)
