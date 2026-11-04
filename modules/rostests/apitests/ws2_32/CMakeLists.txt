
list(APPEND SOURCE
    abortiveclose.c
    accept.c
    acceptname.c
    loopbackalias.c
    addresschange.c
    asyncselect.c
    backlog.c
    bindconflict.c
    bind.c
    broadcast.c
    close.c
    closerace.c
    connectex.c
    connectexhandles.c
    updatecontexthandles.c
    connecterror.c
    connectstate.c
    GetAddrInfoEx.c
    gaiconcurrent.c
    getaddrinfo.c
    GetHostNameW.c
    gethostname.c
    getnameinfo.c
    getnameinfoserv.c
    getpeername.c
    getservbyname.c
    getservbyport.c
    getsockname.c
    handleinherit.c
    sendwhole.c
    tcpnodelay.c
    inheritedsocket.c
    helpers.c
    iocpskip.c
    ioctlsocket.c
    killpendingio.c
    listen.c
    udpconnreset.c
    manysockets.c
    nonblocking.c
    nostartup.c
    open_osfhandle.c
    OwnHostname.c
    ReverseLookup.c
    rcvbuf.c
    rcvwindow.c
    recv.c
    WSARecvMsg.c
    WSASendMsg.c
    send.c
    selecttimeval.c
    shutdownrecv.c
    sotimeout.c
    socketscale.c
    stringtoaddress.c
    udpbindretry.c
    udpcancel.c
    udpconnectname.c
    udpevents.c
    udprecv.c
    udpzerolen.c
    timewait.c
    transmitfile.c
    WSAAsync.c
    WSAEnumNameSpaceProviders.c
    WSAIoctl.c
    WSAPoll.c
    WSALookupService.c
    WSARecv.c
    WSARecvFrom.c
    WSAStartup.c)

list(APPEND PCH_SKIP_SOURCE
    WSCGetProviderInfo.c
    testlist.c)

add_executable(ws2_32_apitest
    ${SOURCE}
    ${PCH_SKIP_SOURCE})

target_link_libraries(ws2_32_apitest wine ${PSEH_LIB})
set_module_type(ws2_32_apitest win32cui)
add_importlibs(ws2_32_apitest advapi32 iphlpapi user32 ws2_32 msvcrt kernel32 ntdll)
add_pch(ws2_32_apitest ws2_32.h "${PCH_SKIP_SOURCE}")
add_rostests_file(TARGET ws2_32_apitest)
