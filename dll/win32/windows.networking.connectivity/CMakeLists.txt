remove_definitions(-D_WIN32_WINNT=0x502)
add_definitions(-D_WIN32_WINNT=0x601)

spec2def(windows.networking.connectivity.dll windows.networking.connectivity.spec)

list(APPEND SOURCE
    main.c
    network_information.c
    ${CMAKE_CURRENT_BINARY_DIR}/windows.networking.connectivity_stubs.c
    ${CMAKE_CURRENT_BINARY_DIR}/windows.networking.connectivity.def)

add_library(windows.networking.connectivity MODULE ${SOURCE})
set_module_type(windows.networking.connectivity win32dll UNICODE ENTRYPOINT 0)
target_link_libraries(windows.networking.connectivity uuid wine)
add_importlibs(windows.networking.connectivity combase ole32 oleaut32 msvcrt kernel32 ntdll)
add_dependencies(windows.networking.connectivity psdk)
add_cd_file(TARGET windows.networking.connectivity DESTINATION reactos/system32 FOR all)
