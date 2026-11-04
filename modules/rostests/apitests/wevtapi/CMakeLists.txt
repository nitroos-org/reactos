list(APPEND SOURCE
    wevtapi.c
    functional.c
    testlist.c)

add_executable(wevtapi_apitest ${SOURCE})
set_module_type(wevtapi_apitest win32cui)
add_importlibs(wevtapi_apitest wevtapi advapi32 msvcrt kernel32)
add_rostests_file(TARGET wevtapi_apitest)
target_include_directories(wevtapi_apitest PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../../winetests/wevtapi)

# The resource file of a publisher that the tests make up (the metadata of its events), next to the test program
add_library(wevtapi_testmanifest MODULE testmanifest.rc)
set_module_type(wevtapi_testmanifest module UNICODE ENTRYPOINT 0)
add_rostests_file(TARGET wevtapi_testmanifest)
