
# precomp.h and ip.h here are user mode stand-ins, so that the tcpip receive path compiles into a test
include_directories(BEFORE ${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${REACTOS_SOURCE_DIR}/modules/rostests/apitests/include)

add_executable(tcpip_unittest
    reassembly.c
    iftype.c
    ${REACTOS_SOURCE_DIR}/drivers/network/tcpip/ip/network/receive.c
    testlist.c)

set_module_type(tcpip_unittest win32cui)
add_importlibs(tcpip_unittest msvcrt kernel32 ntdll)
add_rostests_file(TARGET tcpip_unittest)
