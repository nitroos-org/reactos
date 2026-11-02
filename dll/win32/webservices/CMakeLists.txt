add_definitions(-D__WINESRC__)
remove_definitions(-D_WIN32_WINNT=0x502)
add_definitions(-D_WIN32_WINNT=0x601)

spec2def(webservices.dll webservices.spec ADD_IMPORTLIB)

list(APPEND SOURCE
    channel.c
    error.c
    heap.c
    listener.c
    msg.c
    proxy.c
    reader.c
    string.c
    url.c
    writer.c
    ${CMAKE_CURRENT_BINARY_DIR}/webservices_stubs.c
    ${CMAKE_CURRENT_BINARY_DIR}/webservices.def)

add_library(webservices MODULE ${SOURCE})
set_module_type(webservices win32dll UNICODE)
target_link_libraries(webservices wine uuid)
add_importlibs(webservices winhttp rpcrt4 user32 ws2_32 msvcrt kernel32 ntdll)
add_dependencies(webservices psdk)
add_cd_file(TARGET webservices DESTINATION reactos/system32 FOR all)
set_wine_module_FIXME(webservices)
