
spec2def(coremessaging.dll coremessaging.spec)

list(APPEND SOURCE
    main.c
    ${CMAKE_CURRENT_BINARY_DIR}/coremessaging_stubs.c
    ${CMAKE_CURRENT_BINARY_DIR}/coremessaging.def)

add_library(coremessaging MODULE ${SOURCE})
set_module_type(coremessaging win32dll UNICODE ENTRYPOINT DllMain 12)
target_link_libraries(coremessaging uuid wine)
add_importlibs(coremessaging combase ole32 user32 msvcrt kernel32 ntdll)
add_dependencies(coremessaging psdk)
add_cd_file(TARGET coremessaging DESTINATION reactos/system32 FOR all)
