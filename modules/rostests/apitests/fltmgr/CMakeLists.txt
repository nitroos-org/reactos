
include_directories(${REACTOS_SOURCE_DIR}/modules/rostests/drivers/fltsample)

list(APPEND SOURCE
    support.c
    instance.c
    operation.c
    context.c
    comms.c
    stress.c
    rvneg.c
    portsec.c
    portrace.c
    testlist.c)

add_executable(fltmgr_apitest ${SOURCE})
set_module_type(fltmgr_apitest win32cui)
target_link_libraries(fltmgr_apitest wine)
add_importlibs(fltmgr_apitest fltlib advapi32 msvcrt kernel32 ntdll)
add_rostests_file(TARGET fltmgr_apitest)
add_dependencies(fltmgr_apitest fltsample)
