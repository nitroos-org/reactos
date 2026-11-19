
remove_definitions(-D_WIN32_WINNT=0x502)
add_definitions(-D_WIN32_WINNT=0x600)

list(APPEND SOURCE
    imports.c
    main.c
    report.c
    trace.c
    nitrodiag.h
    resource.h)

add_executable(nitrodiag ${SOURCE} nitrodiag.rc)
set_module_type(nitrodiag win32cui UNICODE)
target_link_libraries(nitrodiag uuid minizip zlib)
add_importlibs(nitrodiag dbghelp advapi32 shell32 shlwapi ole32 comdlg32 version psapi user32 gdi32 msvcrt kernel32 ntdll)
add_cd_file(TARGET nitrodiag DESTINATION reactos/system32 FOR all)
