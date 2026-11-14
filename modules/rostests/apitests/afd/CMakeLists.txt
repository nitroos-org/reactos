
include_directories(
    ${REACTOS_SOURCE_DIR}/sdk/include/reactos/drivers
    ${REACTOS_SOURCE_DIR}/modules/rostests/drivers/afdstub)

list(APPEND SOURCE
    AfdHelpers.c
    select.c
    send.c
    sendcancel.c
    sendtounbound.c
    sendbeforeconnect.c
    windowsize.c
    nonpagedwindow.c
    defensive.c
    dgramstub.c
    tcpnonadmin.c
    tcpsetinfoex.c
    tcpaccept.c
    outputprobe.c
    acceptstate.c
    acceptname.c
    g7lockbuf.c
    g7accept.c
    g7setip.c
    g7setinfoex.c
    g8net.c)

list(APPEND PCH_SKIP_SOURCE
    testlist.c)

add_executable(afd_apitest
    ${SOURCE}
    ${PCH_SKIP_SOURCE})

target_link_libraries(afd_apitest wine)
set_module_type(afd_apitest win32cui)
add_importlibs(afd_apitest ws2_32 msvcrt kernel32 advapi32 netapi32 ntdll)
add_pch(afd_apitest precomp.h "${PCH_SKIP_SOURCE}")
add_dependencies(afd_apitest afdstub)
add_rostests_file(TARGET afd_apitest)
