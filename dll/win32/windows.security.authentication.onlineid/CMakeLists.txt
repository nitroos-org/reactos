remove_definitions(-D_WIN32_WINNT=0x502)
add_definitions(-D_WIN32_WINNT=0x601)

spec2def(windows.security.authentication.onlineid.dll windows.security.authentication.onlineid.spec)

list(APPEND SOURCE
    main.c
    authenticator.c
    ticket.c
    ${CMAKE_CURRENT_BINARY_DIR}/windows.security.authentication.onlineid_stubs.c
    ${CMAKE_CURRENT_BINARY_DIR}/windows.security.authentication.onlineid.def)

add_library(windows.security.authentication.onlineid MODULE ${SOURCE})
set_module_type(windows.security.authentication.onlineid win32dll UNICODE ENTRYPOINT 0)
target_link_libraries(windows.security.authentication.onlineid uuid wine)
add_importlibs(windows.security.authentication.onlineid combase ole32 msvcrt kernel32 ntdll)
add_dependencies(windows.security.authentication.onlineid psdk)
add_cd_file(TARGET windows.security.authentication.onlineid DESTINATION reactos/system32 FOR all)
