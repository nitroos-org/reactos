
#define STANDALONE
#include <apitest.h>

extern void func_abortiveclose(void);
extern void func_accept(void);
extern void func_backlog(void);
extern void func_backlog_listen(void);
extern void func_backlog_open(void);
extern void func_backlog_replace(void);
extern void func_bind(void);
extern void func_broadcast(void);
extern void func_close(void);
extern void func_closerace(void);
extern void func_connectex(void);
extern void func_connecterror(void);
extern void func_GetAddrInfoEx(void);
extern void func_getaddrinfo(void);
extern void func_GetHostNameW(void);
extern void func_addresschange(void);
extern void func_gethostname(void);
extern void func_getnameinfo(void);
extern void func_getnameinfoserv(void);
extern void func_getpeername(void);
extern void func_getservbyname(void);
extern void func_getservbyport(void);
extern void func_getsockname(void);
extern void func_handleinherit(void);
extern void func_sendwhole(void);
extern void func_tcpnodelay(void);
extern void func_inheritedsocket(void);
extern void func_inheritedsocketchild(void);
extern void func_iocpskip(void);
extern void func_ioctlsocket(void);
extern void func_killpendingio(void);
extern void func_listen(void);
extern void func_udpconnreset(void);
extern void func_manysockets(void);
extern void func_nonblocking(void);
extern void func_nostartup(void);
extern void func_OwnHostname(void);
extern void func_ReverseLookup(void);
extern void func_open_osfhandle(void);
extern void func_rcvbuf(void);
extern void func_recv(void);
extern void func_send(void);
extern void func_selecttimeval(void);
extern void func_shutdownrecv(void);
extern void func_sotimeout(void);
extern void func_socketscale(void);
extern void func_stringtoaddress(void);
extern void func_udpbindretry(void);
extern void func_udpcancel(void);
extern void func_udpconnectname(void);
extern void func_udpevents(void);
extern void func_udprecv(void);
extern void func_udpzerolen(void);
extern void func_timewait(void);
extern void func_transmitfile(void);
extern void func_WSAAsync(void);
extern void func_WSAEnumNameSpaceProviders(void);
extern void func_WSAIoctl(void);
extern void func_WSAPoll(void);
extern void func_WSALookupService(void);
extern void func_WSARecv(void);
extern void func_WSARecvFrom(void);
extern void func_WSAStartup(void);
extern void func_WSARecvMsg(void);
extern void func_WSASendMsg(void);
extern void func_WSCGetProviderInfo(void);

const struct test winetest_testlist[] =
{
    { "abortiveclose", func_abortiveclose },
    { "accept", func_accept },
    { "backlog", func_backlog },
    { "backlog_listen", func_backlog_listen },
    { "backlog_open", func_backlog_open },
    { "backlog_replace", func_backlog_replace },
    { "bind", func_bind },
    { "broadcast", func_broadcast },
    { "close", func_close },
    { "closerace", func_closerace },
    { "connectex", func_connectex },
    { "connecterror", func_connecterror },
    { "GetAddrInfoEx", func_GetAddrInfoEx },
    { "getaddrinfo", func_getaddrinfo },
    { "GetHostNameW", func_GetHostNameW },
    { "gethostname", func_gethostname },
    { "getnameinfo", func_getnameinfo },
    { "getnameinfoserv", func_getnameinfoserv },
    { "getpeername", func_getpeername },
    { "getservbyname", func_getservbyname },
    { "getservbyport", func_getservbyport },
    { "getsockname", func_getsockname },
    { "handleinherit", func_handleinherit },
    { "sendwhole", func_sendwhole },
    { "addresschange", func_addresschange },
    { "tcpnodelay", func_tcpnodelay },
    { "inheritedsocket", func_inheritedsocket },
    { "inheritedsocketchild", func_inheritedsocketchild },
    { "iocpskip", func_iocpskip },
    { "ioctlsocket", func_ioctlsocket },
    { "killpendingio", func_killpendingio },
    { "listen", func_listen },
    { "udpconnreset", func_udpconnreset },
    { "manysockets", func_manysockets },
    { "nonblocking", func_nonblocking },
    { "nostartup", func_nostartup },
    { "open_osfhandle", func_open_osfhandle },
    { "OwnHostname", func_OwnHostname },
    { "ReverseLookup", func_ReverseLookup },
    { "rcvbuf", func_rcvbuf },
    { "recv", func_recv },
    { "send", func_send },
    { "selecttimeval", func_selecttimeval },
    { "shutdownrecv", func_shutdownrecv },
    { "sotimeout", func_sotimeout },
    { "socketscale", func_socketscale },
    { "stringtoaddress", func_stringtoaddress },
    { "udpbindretry", func_udpbindretry },
    { "udpcancel", func_udpcancel },
    { "udpconnectname", func_udpconnectname },
    { "udpevents", func_udpevents },
    { "udprecv", func_udprecv },
    { "udpzerolen", func_udpzerolen },
    { "timewait", func_timewait },
    { "transmitfile", func_transmitfile },
    { "WSAAsync", func_WSAAsync },
    { "WSAIoctl", func_WSAIoctl },
    { "WSAPoll", func_WSAPoll },
    { "WSALookupService", func_WSALookupService },
    { "WSARecv", func_WSARecv },
    { "WSARecvFrom", func_WSARecvFrom },
    { "WSAStartup", func_WSAStartup },
    { "WSARecvMsg", func_WSARecvMsg },
    { "WSASendMsg", func_WSASendMsg },
    { "WSCGetProviderInfo", func_WSCGetProviderInfo },
    { 0, 0 }
};

