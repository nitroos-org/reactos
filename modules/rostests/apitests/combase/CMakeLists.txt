
list(APPEND SOURCE
    ActivationFilter.c
    ApartmentEndpoint.c
    InprocLoadFailure.c
    LocalServerStartup.c
    RoFailFast.c
    StubReleaseInCall.c
    WireHandles.c
    testlist.c)

add_executable(combase_apitest ${SOURCE})
target_link_libraries(combase_apitest wine uuid ${PSEH_LIB})
set_module_type(combase_apitest win32cui)
add_importlibs(combase_apitest ole32 advapi32 user32 gdi32 msvcrt kernel32 ntdll)
add_rostests_file(TARGET combase_apitest)
