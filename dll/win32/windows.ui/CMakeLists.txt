
spec2def(windows.ui.dll windows.ui.spec)

list(APPEND SOURCE
    main.c
    ${CMAKE_CURRENT_BINARY_DIR}/windows.ui_stubs.c
    ${CMAKE_CURRENT_BINARY_DIR}/windows.ui.def)

add_library(windows.ui MODULE ${SOURCE})
set_module_type(windows.ui win32dll UNICODE ENTRYPOINT DllMain 12)
target_link_libraries(windows.ui uuid wine)
add_importlibs(windows.ui combase ole32 advapi32 user32 msvcrt kernel32 ntdll)
add_dependencies(windows.ui psdk)
add_cd_file(TARGET windows.ui DESTINATION reactos/system32 FOR all)
