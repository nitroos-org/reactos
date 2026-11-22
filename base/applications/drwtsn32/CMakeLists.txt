
PROJECT(drwtsn32)

add_message_headers(UNICODE drwtsnmsg.mc)
include_directories(${CMAKE_CURRENT_BINARY_DIR})

list(APPEND CPP_SOURCE
    crashdlg.cpp
    drwtsn32.cpp
    eventlog.cpp
    main.cpp
    stacktrace.cpp
    sysinfo.cpp
    wer.cpp
    drwtsn32.h
    precomp.h)

add_executable(drwtsn32 ${CPP_SOURCE} drwtsn32.rc)
add_dependencies(drwtsn32 drwtsnmsg)
add_message_rc_deps(drwtsn32.rc drwtsnmsg)
add_pch(drwtsn32 precomp.h CPP_SOURCE)
set_module_type(drwtsn32 win32gui UNICODE)
target_link_libraries(drwtsn32 udmihelp cppstl atl_classes)
set_target_cpp_properties(drwtsn32 WITH_EXCEPTIONS)
add_importlibs(drwtsn32 dbghelp psapi advapi32 shell32 shlwapi version rpcrt4 msvcrt user32 gdi32 kernel32 ntdll)
add_cd_file(TARGET drwtsn32 DESTINATION reactos/system32 FOR all)
