
include_directories(BEFORE ${REACTOS_SOURCE_DIR}/sdk/include/wine ${REACTOS_BINARY_DIR}/sdk/include/wine)
add_rpc_files(client schrpc.idl)

list(APPEND SOURCE
    Dispatch.c
    Schtasks.c
    Security.c
    TaskScheduler.c
    TaskSchedulerApi.c
    testlist.c
    ${CMAKE_CURRENT_BINARY_DIR}/schrpc_c.c)

add_executable(taskschd_apitest ${SOURCE})
set_module_type(taskschd_apitest win32cui)
target_link_libraries(taskschd_apitest uuid pseh)
add_dependencies(taskschd_apitest wineheaders)
add_importlibs(taskschd_apitest netapi32 secur32 advapi32 rpcrt4 oleaut32 ole32 msvcrt kernel32)
add_rostests_file(TARGET taskschd_apitest)
