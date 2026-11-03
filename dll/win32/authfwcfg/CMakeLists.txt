spec2def(authfwcfg.dll authfwcfg.spec)

add_library(authfwcfg MODULE
    authfwcfg.c
    authfwcfg.rc
    ${CMAKE_CURRENT_BINARY_DIR}/authfwcfg.def)

set_module_type(authfwcfg win32dll UNICODE)
target_link_libraries(authfwcfg fwstore)
add_importlibs(authfwcfg netsh shlwapi rpcrt4 advapi32 msvcrt kernel32 ntdll)
add_cd_file(TARGET authfwcfg DESTINATION reactos/system32 FOR all)
