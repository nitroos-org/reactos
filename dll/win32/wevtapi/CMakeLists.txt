spec2def(wevtapi.dll wevtapi.spec ADD_IMPORTLIB)

list(APPEND SOURCE
    main.c
    classic.c
    manifest.c
    evtx.c
    evtxw.c
    xpath.c
    wevtapi_private.h
    ${CMAKE_CURRENT_BINARY_DIR}/wevtapi_stubs.c
    ${CMAKE_CURRENT_BINARY_DIR}/wevtapi.def)

add_library(wevtapi MODULE ${SOURCE})
set_module_type(wevtapi win32dll UNICODE ENTRYPOINT DllMain 12)
target_link_libraries(wevtapi wine)
add_importlibs(wevtapi advapi32 version msvcrt kernel32 ntdll)
add_dependencies(wevtapi psdk)
add_cd_file(TARGET wevtapi DESTINATION reactos/system32 FOR all)
set_wine_module_FIXME(wevtapi)
