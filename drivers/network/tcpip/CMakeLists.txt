
set(LWIP_DIR ${CMAKE_CURRENT_SOURCE_DIR}/lwip)
set(LWIP_INCLUDE_DIRS
    ${LWIP_DIR}/src/include
    ${CMAKE_CURRENT_SOURCE_DIR}/include/lwip
)
include(${LWIP_DIR}/src/Filelists.cmake)
add_dependencies(lwipcore xdk)
# The IPv6 self-test (ip/transport/tcp/selftest6.c, and its hooks in tcpip/nitrofw.c) is in debug builds;
# configure a release build with -DTCPIP_IPV6_SELFTEST=ON to have it there for a test run
if(TCPIP_IPV6_SELFTEST)
    add_definitions(-DTCPIP_IPV6_SELFTEST)
endif()
add_subdirectory(ip)

add_definitions(
    -DNDIS40
    -D_NTDRIVER_)

spec2def(tcpip.sys tcpip.spec)

list(APPEND SOURCE
    chew/workqueue.c
    datalink/lan.c
    tcpip/ainfo.c
    tcpip/addrchange.c
    tcpip/buffer.c
    tcpip/cinfo.c
    tcpip/dispatch.c
    tcpip/fileobjs.c
    tcpip/icmp.c
    tcpip/iinfo.c
    tcpip/info.c
    tcpip/lock.c
    tcpip/main.c
    tcpip/nitrofw.c
    tcpip/ninfo.c
    tcpip/proto.c
    tcpip/tinfo.c
    tcpip/wait.c
    include/lwip/precomp.h)

add_library(tcpip MODULE
    ${SOURCE}
    tcpip.rc
    ${CMAKE_CURRENT_BINARY_DIR}/tcpip.def)

target_include_directories(tcpip BEFORE
    PRIVATE ${LWIP_INCLUDE_DIRS}
    PRIVATE include)

target_link_libraries(tcpip ip ${PSEH_LIB})
set_module_type(tcpip kernelmodedriver)
add_importlibs(tcpip ndis ntoskrnl hal)
add_pch(tcpip include/lwip/precomp.h SOURCE)
add_cd_file(TARGET tcpip DESTINATION reactos/system32/drivers FOR all)
