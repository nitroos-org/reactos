
spec2def(netprofm.dll netprofm.spec)

list(APPEND SOURCE
    main.c
    ${CMAKE_CURRENT_BINARY_DIR}/netprofm_stubs.c
    ${CMAKE_CURRENT_BINARY_DIR}/netprofm.def)

add_library(netprofm MODULE ${SOURCE})
set_module_type(netprofm win32dll UNICODE ENTRYPOINT DllMain 12)
target_link_libraries(netprofm uuid wine)
add_importlibs(netprofm iphlpapi oleaut32 ole32 advapi32 msvcrt kernel32 ntdll)
add_dependencies(netprofm psdk)
add_cd_file(TARGET netprofm DESTINATION reactos/system32 FOR all)
