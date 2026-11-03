spec2def(mpssvc.dll mpssvc.spec ADD_IMPORTLIB)

add_library(mpssvc MODULE
    mpssvc.c
    mpssvc.rc
    ${CMAKE_CURRENT_BINARY_DIR}/mpssvc.def)

set_module_type(mpssvc win32dll UNICODE)
target_link_libraries(mpssvc fwstore)
add_importlibs(mpssvc iphlpapi rpcrt4 advapi32 msvcrt kernel32 ntdll)
add_cd_file(TARGET mpssvc DESTINATION reactos/system32 FOR all)
