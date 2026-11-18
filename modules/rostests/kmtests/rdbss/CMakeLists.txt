
include_directories(../include)

#
# RdbssLoop: loopback network mini-redirector on rdbsslib/rxce (test only)
#
list(APPEND RDBSSLOOP_DRV_SOURCE
    RdbssLoop_drv.c)

add_library(rdbssloop_drv MODULE ${RDBSSLOOP_DRV_SOURCE})
set_module_type(rdbssloop_drv kernelmodedriver)
target_link_libraries(rdbssloop_drv ntoskrnl_vista rdbsslib rxce copysup memcmp ${PSEH_LIB})
add_importlibs(rdbssloop_drv ntoskrnl hal)
target_compile_definitions(rdbssloop_drv PRIVATE RDBSS_TRACKER)
add_rostests_file(TARGET rdbssloop_drv)

#
# rdbsshostile: the second process of the RdbssHostile kmtest (test only)
#
add_executable(rdbsshostile RdbssHostile_child.c)
set_module_type(rdbsshostile win32cui UNICODE)
target_link_libraries(rdbsshostile ${PSEH_LIB})
add_importlibs(rdbsshostile msvcrt kernel32 ntdll)
add_rostests_file(TARGET rdbsshostile)
