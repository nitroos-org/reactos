
spec2def(wintypes.dll wintypes.spec)

list(APPEND SOURCE
    apiinformation.c
    main.c
    propertyvalue.c
    ${CMAKE_CURRENT_BINARY_DIR}/wintypes_stubs.c
    ${CMAKE_CURRENT_BINARY_DIR}/wintypes.def)

add_library(wintypes MODULE ${SOURCE})
set_module_type(wintypes win32dll UNICODE ENTRYPOINT DllMain 12)
target_link_libraries(wintypes wine)
add_importlibs(wintypes combase ole32 advapi32 msvcrt kernel32 ntdll)
add_dependencies(wintypes psdk)
add_cd_file(TARGET wintypes DESTINATION reactos/system32 FOR all)
