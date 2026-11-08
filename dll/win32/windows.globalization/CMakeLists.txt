remove_definitions(-D_WIN32_WINNT=0x502)
add_definitions(-D_WIN32_WINNT=0x601)

spec2def(windows.globalization.dll windows.globalization.spec)

list(APPEND SOURCE
    main.c
    geographic_region.c
    ${CMAKE_CURRENT_BINARY_DIR}/windows.globalization_stubs.c
    ${CMAKE_CURRENT_BINARY_DIR}/windows.globalization.def)

add_library(windows.globalization MODULE ${SOURCE})
set_module_type(windows.globalization win32dll UNICODE ENTRYPOINT 0)
target_link_libraries(windows.globalization uuid wine)
add_importlibs(windows.globalization combase ole32 user32 msvcrt kernel32 ntdll)
add_dependencies(windows.globalization psdk)
add_cd_file(TARGET windows.globalization DESTINATION reactos/system32 FOR all)
