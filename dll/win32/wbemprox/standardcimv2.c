/*
 * PROJECT:     ReactOS WMI provider (wbemprox)
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     root\StandardCimv2: the network classes (MSFT_NetTCPConnection, MSFT_NetUDPEndpoint,
 *              MSFT_NetIPAddress, MSFT_NetIPInterface, MSFT_NetRoute, MSFT_NetAdapter and
 *              MSFT_DNSClientServerAddress), read only, from the IP helper API
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * The property names, types, order and the key encodings follow the schema and the instances measured on
 * Windows 10 22H2 (scv2_tables.h is generated from that capture). A property that Windows leaves NULL
 * in every instance is a COL_FLAG_NULL column: it is part of the class and always NULL.
 */

#define NONAMELESSUNION
#define NONAMELESSSTRUCT

#include <stdarg.h>
#include <wchar.h>

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winbase.h"
#include "winsock2.h"
#include "ws2tcpip.h"
#include "wbemcli.h"
#include "iphlpapi.h"
#include "netioapi.h"
#include "winreg.h"

#include "wine/debug.h"
#include "wbemprox_private.h"

WINE_DEFAULT_DEBUG_CHANNEL(wbemprox);

#include "scv2_tables.h"

#define AF_V4 2
#define AF_V6 23

/* ---- value helpers ---- */

static WCHAR *dup_str( const WCHAR *s )
{
    return s ? heap_strdupW( s ) : NULL;
}

/* the key encoding of MSFT_NetIPAddress, MSFT_NetIPInterface and MSFT_NetRoute: each character is
 * shifted by 10 */
static WCHAR *encode_key( const WCHAR *s )
{
    WCHAR *ret;
    UINT i, len = lstrlenW( s );

    if (!(ret = heap_alloc( (len + 1) * sizeof(WCHAR) ))) return NULL;
    for (i = 0; i < len; i++) ret[i] = s[i] + 10;
    ret[len] = 0;
    return ret;
}

static WCHAR *ip4_text( DWORD addr_net )
{
    WCHAR buf[16];
    const BYTE *b = (const BYTE *)&addr_net;

    swprintf( buf, L"%u.%u.%u.%u", b[0], b[1], b[2], b[3] );
    return heap_strdupW( buf );
}

static WCHAR *ip6_text( const void *addr, DWORD scope )
{
    SOCKADDR_IN6 sa;
    WCHAR buf[64];
    DWORD len = ARRAY_SIZE(buf);

    memset( &sa, 0, sizeof(sa) );
    sa.sin6_family = AF_V6;
    memcpy( &sa.sin6_addr, addr, 16 );
    sa.sin6_scope_id = scope;
    if (WSAAddressToStringW( (SOCKADDR *)&sa, sizeof(sa), NULL, buf, &len )) return NULL;
    return heap_strdupW( buf );
}

static WCHAR *sockaddr_text( const SOCKADDR_INET *sa )
{
    if (sa->si_family == AF_V4) return ip4_text( sa->Ipv4.sin_addr.s_addr );
    if (sa->si_family == AF_V6) return ip6_text( &sa->Ipv6.sin6_addr, sa->Ipv6.sin6_scope_id );
    return NULL;
}

static WCHAR *format_text( const WCHAR *fmt, ... ) __WINE_PRINTF_ATTR(1,2);
static WCHAR *format_text( const WCHAR *fmt, ... )
{
    WCHAR buf[256];
    va_list args;

    va_start( args, fmt );
    vswprintf( buf, fmt, args );
    va_end( args );
    return heap_strdupW( buf );
}

/* a CIM interval ("ddddddddHHMMSS.mmmmmm:000"); 0xffffffff seconds is infinite, TimeSpan.MaxValue */
static WCHAR *format_interval( UINT32 secs )
{
    if (secs == 0xffffffff) return heap_strdupW( L"10675199024805.477580:000" );
    return format_text( L"%08u%02u%02u%02u.000000:000", secs / 86400, (secs / 3600) % 24, (secs / 60) % 60, secs % 60 );
}

static WCHAR *format_interval_minutes( UINT32 minutes )
{
    return format_interval( minutes * 60 );
}

/* a CIM datetime in local time of a FILETIME (UTC); NULL for 0 */
static WCHAR *format_filetime( LONGLONG ft )
{
    FILETIME utc, local;
    SYSTEMTIME st;
    ULARGE_INTEGER u, l;
    LONG bias;
    UINT usec;

    if (ft <= 0) return NULL;
    u.QuadPart = ft;
    utc.dwLowDateTime = (DWORD)ft;
    utc.dwHighDateTime = (DWORD)((ULONGLONG)ft >> 32);
    if (!FileTimeToLocalFileTime( &utc, &local ) || !FileTimeToSystemTime( &local, &st )) return NULL;
    l.QuadPart = ((ULONGLONG)local.dwHighDateTime << 32) | local.dwLowDateTime;
    bias = (LONG)(((LONGLONG)l.QuadPart - (LONGLONG)u.QuadPart) / 600000000);
    usec = (UINT)((u.QuadPart % 10000000) / 10);
    return format_text( L"%04u%02u%02u%02u%02u%02u.%06u%c%03u", st.wYear, st.wMonth, st.wDay, st.wHour,
                        st.wMinute, st.wSecond, usec, bias < 0 ? '-' : '+', bias < 0 ? -bias : bias );
}

static USHORT port_of( DWORD raw )
{
    return ntohs( (USHORT)raw );
}

/* ---- the adapters (names, indexes, addresses and DNS servers by interface) ---- */

static IP_ADAPTER_ADDRESSES *read_adapters(void)
{
    IP_ADAPTER_ADDRESSES *buf = NULL;
    ULONG size = 32768, ret = ERROR_BUFFER_OVERFLOW;
    UINT i;

    for (i = 0; i < 6 && ret == ERROR_BUFFER_OVERFLOW; i++)
    {
        heap_free( buf );
        if (!(buf = heap_alloc( size ))) return NULL;
        ret = GetAdaptersAddresses( AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX | GAA_FLAG_INCLUDE_GATEWAYS |
                                    GAA_FLAG_INCLUDE_ALL_INTERFACES, NULL, buf, &size );
    }
    if (ret)
    {
        heap_free( buf );
        return NULL;
    }
    return buf;
}

static DWORD adapter_index( const IP_ADAPTER_ADDRESSES *aa )
{
    return aa->u.s.IfIndex ? aa->u.s.IfIndex : aa->Ipv6IfIndex;
}

static const IP_ADAPTER_ADDRESSES *find_adapter( const IP_ADAPTER_ADDRESSES *list, DWORD index )
{
    const IP_ADAPTER_ADDRESSES *aa;

    if (!index) return NULL;
    for (aa = list; aa; aa = aa->Next)
        if (aa->u.s.IfIndex == index || aa->Ipv6IfIndex == index) return aa;
    return NULL;
}

static const WCHAR *alias_of( const IP_ADAPTER_ADDRESSES *list, DWORD index )
{
    const IP_ADAPTER_ADDRESSES *aa = find_adapter( list, index );
    return aa ? aa->FriendlyName : NULL;
}

/* ---- rows ---- */

struct fill_ctx
{
    struct table *table;
    const struct expr *cond;
    UINT row;
    enum fill_status status;
    UINT size;
};

static void begin_fill( struct fill_ctx *ctx, struct table *table, const struct expr *cond, UINT size )
{
    ctx->table = table;
    ctx->cond = cond;
    ctx->row = 0;
    ctx->status = FILL_STATUS_UNFILTERED;
    ctx->size = size;
}

/* a zeroed record at the end of the table, or NULL */
static void *new_record( struct fill_ctx *ctx )
{
    BYTE *rec;

    if (!resize_table( ctx->table, ctx->row + 1, ctx->size ))
    {
        ctx->status = FILL_STATUS_FAILED;
        return NULL;
    }
    rec = ctx->table->data + ctx->row * ctx->size;
    memset( rec, 0, ctx->size );
    return rec;
}

/* keep the record, or drop it when it does not match the condition */
static void add_record( struct fill_ctx *ctx )
{
    enum fill_status status;

    if (!match_row( ctx->table, ctx->row, ctx->cond, &status ))
    {
        free_row_values( ctx->table, ctx->row );
        if (status == FILL_STATUS_FAILED) ctx->status = FILL_STATUS_FAILED;
        return;
    }
    if (ctx->status != FILL_STATUS_FAILED) ctx->status = status;
    ctx->row++;
}

static enum fill_status end_fill( struct fill_ctx *ctx )
{
    TRACE( "created %u rows\n", ctx->row );
    ctx->table->num_rows = ctx->row;
    return ctx->status;
}

static void fill_state_defaults( UINT16 *enabled_default, UINT16 *requested, UINT16 *transitioning, UINT16 req )
{
    *enabled_default = 2;
    *requested = req;
    *transitioning = 12;
}

/* ---- the extended TCP and UDP tables ---- */

static void *read_ext_table( BOOL tcp, ULONG family, int cls_module, int cls_pid, BOOL *module )
{
    void *buf = NULL;
    DWORD size, ret = ERROR_INVALID_PARAMETER;
    UINT pass, i;

    for (pass = 0; pass < 2; pass++)
    {
        int cls = pass ? cls_pid : cls_module;

        size = 16384;
        for (i = 0; i < 8; i++)
        {
            heap_free( buf );
            if (!(buf = heap_alloc( size ))) return NULL;
            ret = tcp ? GetExtendedTcpTable( buf, &size, FALSE, family, cls, 0 )
                      : GetExtendedUdpTable( buf, &size, FALSE, family, cls, 0 );
            if (ret != ERROR_INSUFFICIENT_BUFFER) break;
            size += 4096;
        }
        if (!ret)
        {
            *module = !pass;
            return buf;
        }
    }
    heap_free( buf );
    return NULL;
}

struct endpoint
{
    WCHAR *local, *remote;
    USHORT local_port, remote_port;
    DWORD state, pid;
    LONGLONG created;
};

static void fill_tcp_record( struct fill_ctx *ctx, struct endpoint *e )
{
    struct record_msft_nettcpconnection *rec;

    if (!(rec = new_record( ctx )))
    {
        heap_free( e->local );
        heap_free( e->remote );
        return;
    }
    if (e->state == MIB_TCP_STATE_LISTEN)
    {
        /* a listener has no remote end (the stack reports a stale one) */
        UINT v6 = wcschr( e->local, ':' ) != NULL;
        heap_free( e->remote );
        e->remote = heap_strdupW( v6 ? L"::" : L"0.0.0.0" );
        e->remote_port = 0;
    }
    rec->instanceid = format_text( L"%s++%u++%s++%u", e->local, e->local_port, e->remote, e->remote_port );
    fill_state_defaults( &rec->enableddefault, &rec->requestedstate, &rec->transitioningtostate, 5 );
    rec->creationtime = format_filetime( e->created );
    rec->localaddress = e->local;
    rec->localport = e->local_port;
    rec->owningprocess = e->pid;
    rec->appliedsetting = 0;
    rec->offloadstate = 0;
    rec->remoteaddress = e->remote;
    rec->remoteport = e->remote_port;
    rec->state = e->state;
    add_record( ctx );
}

static enum fill_status fill_nettcpconnection( struct table *table, const struct expr *cond )
{
    static const ULONG families[] = { AF_V6, AF_V4 };
    struct fill_ctx ctx;
    UINT f, i;

    begin_fill( &ctx, table, cond, sizeof(struct record_msft_nettcpconnection) );
    for (f = 0; f < ARRAY_SIZE(families); f++)
    {
        BOOL module;
        void *buf = read_ext_table( TRUE, families[f], TCP_TABLE_OWNER_MODULE_ALL, TCP_TABLE_OWNER_PID_ALL, &module );
        struct endpoint e;

        if (!buf) continue;
        if (families[f] == AF_V4)
        {
            if (module)
            {
                MIB_TCPTABLE_OWNER_MODULE *t = buf;
                for (i = 0; i < t->dwNumEntries; i++)
                {
                    MIB_TCPROW_OWNER_MODULE *r = &t->table[i];
                    e.local = ip4_text( r->dwLocalAddr ); e.remote = ip4_text( r->dwRemoteAddr );
                    e.local_port = port_of( r->dwLocalPort ); e.remote_port = port_of( r->dwRemotePort );
                    e.state = r->dwState; e.pid = r->dwOwningPid; e.created = r->liCreateTimestamp.QuadPart;
                    fill_tcp_record( &ctx, &e );
                }
            }
            else
            {
                MIB_TCPTABLE_OWNER_PID *t = buf;
                for (i = 0; i < t->dwNumEntries; i++)
                {
                    MIB_TCPROW_OWNER_PID *r = &t->table[i];
                    e.local = ip4_text( r->dwLocalAddr ); e.remote = ip4_text( r->dwRemoteAddr );
                    e.local_port = port_of( r->dwLocalPort ); e.remote_port = port_of( r->dwRemotePort );
                    e.state = r->dwState; e.pid = r->dwOwningPid; e.created = 0;
                    fill_tcp_record( &ctx, &e );
                }
            }
        }
        else if (module)
        {
            MIB_TCP6TABLE_OWNER_MODULE *t = buf;
            for (i = 0; i < t->dwNumEntries; i++)
            {
                MIB_TCP6ROW_OWNER_MODULE *r = &t->table[i];
                e.local = ip6_text( r->ucLocalAddr, r->dwLocalScopeId ); e.remote = ip6_text( r->ucRemoteAddr, r->dwRemoteScopeId );
                e.local_port = port_of( r->dwLocalPort ); e.remote_port = port_of( r->dwRemotePort );
                e.state = r->dwState; e.pid = r->dwOwningPid; e.created = r->liCreateTimestamp.QuadPart;
                if (!e.local || !e.remote) { heap_free( e.local ); heap_free( e.remote ); continue; }
                fill_tcp_record( &ctx, &e );
            }
        }
        else
        {
            MIB_TCP6TABLE_OWNER_PID *t = buf;
            for (i = 0; i < t->dwNumEntries; i++)
            {
                MIB_TCP6ROW_OWNER_PID *r = &t->table[i];
                e.local = ip6_text( r->ucLocalAddr, r->dwLocalScopeId ); e.remote = ip6_text( r->ucRemoteAddr, r->dwRemoteScopeId );
                e.local_port = port_of( r->dwLocalPort ); e.remote_port = port_of( r->dwRemotePort );
                e.state = r->dwState; e.pid = r->dwOwningPid; e.created = 0;
                if (!e.local || !e.remote) { heap_free( e.local ); heap_free( e.remote ); continue; }
                fill_tcp_record( &ctx, &e );
            }
        }
        heap_free( buf );
    }
    return end_fill( &ctx );
}

static void fill_udp_record( struct fill_ctx *ctx, WCHAR *local, USHORT port, DWORD pid, LONGLONG created )
{
    struct record_msft_netudpendpoint *rec;

    if (!local) return;
    if (!(rec = new_record( ctx )))
    {
        heap_free( local );
        return;
    }
    rec->instanceid = format_text( L"%s++%u", local, port );
    fill_state_defaults( &rec->enableddefault, &rec->requestedstate, &rec->transitioningtostate, 5 );
    rec->creationtime = format_filetime( created );
    rec->localaddress = local;
    rec->localport = port;
    rec->owningprocess = pid;
    add_record( ctx );
}

static enum fill_status fill_netudpendpoint( struct table *table, const struct expr *cond )
{
    static const ULONG families[] = { AF_V6, AF_V4 };
    struct fill_ctx ctx;
    UINT f, i;

    begin_fill( &ctx, table, cond, sizeof(struct record_msft_netudpendpoint) );
    for (f = 0; f < ARRAY_SIZE(families); f++)
    {
        BOOL module;
        void *buf = read_ext_table( FALSE, families[f], UDP_TABLE_OWNER_MODULE, UDP_TABLE_OWNER_PID, &module );

        if (!buf) continue;
        if (families[f] == AF_V4)
        {
            if (module)
            {
                MIB_UDPTABLE_OWNER_MODULE *t = buf;
                for (i = 0; i < t->dwNumEntries; i++)
                    fill_udp_record( &ctx, ip4_text( t->table[i].dwLocalAddr ), port_of( t->table[i].dwLocalPort ),
                                     t->table[i].dwOwningPid, t->table[i].liCreateTimestamp.QuadPart );
            }
            else
            {
                MIB_UDPTABLE_OWNER_PID *t = buf;
                for (i = 0; i < t->dwNumEntries; i++)
                    fill_udp_record( &ctx, ip4_text( t->table[i].dwLocalAddr ), port_of( t->table[i].dwLocalPort ),
                                     t->table[i].dwOwningPid, 0 );
            }
        }
        else if (module)
        {
            MIB_UDP6TABLE_OWNER_MODULE *t = buf;
            for (i = 0; i < t->dwNumEntries; i++)
                fill_udp_record( &ctx, ip6_text( t->table[i].ucLocalAddr, t->table[i].dwLocalScopeId ),
                                 port_of( t->table[i].dwLocalPort ), t->table[i].dwOwningPid,
                                 t->table[i].liCreateTimestamp.QuadPart );
        }
        else
        {
            MIB_UDP6TABLE_OWNER_PID *t = buf;
            for (i = 0; i < t->dwNumEntries; i++)
                fill_udp_record( &ctx, ip6_text( t->table[i].ucLocalAddr, t->table[i].dwLocalScopeId ),
                                 port_of( t->table[i].dwLocalPort ), t->table[i].dwOwningPid, 0 );
        }
        heap_free( buf );
    }
    return end_fill( &ctx );
}

/* ---- MSFT_NetIPAddress ---- */

/* RequestStateChange and Create are listed with the class; changing the network configuration through
 * this provider is not implemented */
static HRESULT scv2_not_supported( IWbemClassObject *obj, IWbemClassObject *in, IWbemClassObject **out )
{
    return WBEM_E_NOT_SUPPORTED;
}

static enum fill_status fill_netipaddress( struct table *table, const struct expr *cond )
{
    static const ADDRESS_FAMILY families[] = { AF_V6, AF_V4 };
    IP_ADAPTER_ADDRESSES *adapters;
    struct fill_ctx ctx;
    UINT f, i;

    begin_fill( &ctx, table, cond, sizeof(struct record_msft_netipaddress) );
    adapters = read_adapters();
    for (f = 0; f < ARRAY_SIZE(families); f++)
    {
        MIB_UNICASTIPADDRESS_TABLE *t;

        if (GetUnicastIpAddressTable( families[f], &t ) || !t) continue;
        for (i = 0; i < t->NumEntries; i++)
        {
            const MIB_UNICASTIPADDRESS_ROW *r = &t->Table[i];
            struct record_msft_netipaddress *rec;
            WCHAR *text, *plain;

            if (!(text = sockaddr_text( &r->Address ))) continue;
            if (!(rec = new_record( &ctx )))
            {
                heap_free( text );
                break;
            }
            plain = format_text( L"%s++%u++1++1", text, r->InterfaceIndex );
            rec->name = plain ? encode_key( plain ) : NULL;
            heap_free( plain );
            rec->creationclassname = heap_strdupW( L"" );
            rec->systemcreationclassname = heap_strdupW( L"" );
            rec->systemname = heap_strdupW( L"" );
            fill_state_defaults( &rec->enableddefault, &rec->requestedstate, &rec->transitioningtostate, 12 );
            rec->protocoliftype = 4096;
            rec->addressorigin = 0;
            if (r->Address.si_family == AF_V6) rec->ipv6address = dup_str( text );
            else rec->ipv4address = dup_str( text );
            rec->prefixlength = r->OnLinkPrefixLength;
            rec->addressfamily = r->Address.si_family;
            rec->addressstate = r->DadState;
            rec->interfacealias = dup_str( alias_of( adapters, r->InterfaceIndex ) );
            rec->interfaceindex = r->InterfaceIndex;
            rec->ipaddress = text;
            rec->preferredlifetime = format_interval( r->PreferredLifetime );
            rec->prefixorigin = r->PrefixOrigin;
            rec->skipassource = r->SkipAsSource;
            rec->store = 1;
            rec->suffixorigin = r->SuffixOrigin;
            rec->type = 1;
            rec->validlifetime = format_interval( r->ValidLifetime );
            rec->requeststatechange = scv2_not_supported;
            rec->create = scv2_not_supported;
            add_record( &ctx );
        }
        FreeMibTable( t );
    }
    heap_free( adapters );
    return end_fill( &ctx );
}

/* ---- MSFT_NetIPInterface ---- */

static enum fill_status fill_netipinterface( struct table *table, const struct expr *cond )
{
    static const ADDRESS_FAMILY families[] = { AF_V6, AF_V4 };
    IP_ADAPTER_ADDRESSES *adapters;
    struct fill_ctx ctx;
    UINT f, i;

    begin_fill( &ctx, table, cond, sizeof(struct record_msft_netipinterface) );
    adapters = read_adapters();
    for (f = 0; f < ARRAY_SIZE(families); f++)
    {
        MIB_IPINTERFACE_TABLE *t;

        if (GetIpInterfaceTable( families[f], &t ) || !t) continue;
        for (i = 0; i < t->NumEntries; i++)
        {
            const MIB_IPINTERFACE_ROW *r = &t->Table[i];
            const IP_ADAPTER_ADDRESSES *aa = find_adapter( adapters, r->InterfaceIndex );
            struct record_msft_netipinterface *rec;
            WCHAR *plain;

            if (!(rec = new_record( &ctx ))) break;
            plain = format_text( L"%u++%u++1", r->InterfaceIndex, r->Family );
            rec->name = plain ? encode_key( plain ) : NULL;
            heap_free( plain );
            rec->creationclassname = heap_strdupW( L"" );
            rec->systemcreationclassname = heap_strdupW( L"" );
            rec->systemname = heap_strdupW( L"" );
            fill_state_defaults( &rec->enableddefault, &rec->requestedstate, &rec->transitioningtostate, 12 );
            rec->addressfamily = r->Family;
            rec->advertisedefaultroute = r->AdvertiseDefaultRoute;
            rec->advertisedrouterlifetime = format_interval_minutes( 30 );
            rec->advertising = r->AdvertisingEnabled;
            rec->automaticmetric = r->UseAutomaticMetric;
            rec->basereachabletime = r->BaseReachableTime;
            rec->clampmss = 0;
            rec->compartmentid = 1;
            rec->connectionstate = r->Connected;
            rec->currenthoplimit = 0;
            rec->dadretransmittime = 1000;
            rec->dadtransmits = r->DadTransmits;
            rec->dhcp = aa && (aa->u1.Flags & IP_ADAPTER_DHCP_ENABLED) ? 1 : 0;
            rec->directedmacwolpattern = 0;
            rec->ecnmarking = 3;
            rec->forcearpndwolpattern = 0;
            rec->forwarding = r->ForwardingEnabled;
            rec->ignoredefaultroutes = r->DisableDefaultRoutes;
            rec->interfacealias = dup_str( aa ? aa->FriendlyName : NULL );
            rec->interfaceindex = r->InterfaceIndex;
            rec->interfacemetric = r->Metric;
            rec->isolationid = 0;
            rec->lowestifnetluid = r->InterfaceLuid.Value;
            rec->managedaddressconfiguration = r->ManagedAddressConfigurationSupported;
            rec->neighbordiscoverysupported = r->SupportsNeighborDiscovery;
            rec->neighborunreachabilitydetection = r->UseNeighborUnreachabilityDetection;
            rec->nlmtu = r->NlMtu;
            rec->otherstatefulconfiguration = r->OtherStatefulConfigurationSupported;
            rec->reachabletime = r->ReachableTime;
            rec->retransmittime = r->RetransmitTime;
            rec->routerdiscovery = (r->RouterDiscoveryBehavior < 0 || r->RouterDiscoveryBehavior > 2) ? 0 : r->RouterDiscoveryBehavior;
            rec->store = 1;
            rec->weakhostreceive = r->WeakHostReceive;
            rec->weakhostsend = r->WeakHostSend;
            add_record( &ctx );
        }
        FreeMibTable( t );
    }
    heap_free( adapters );
    return end_fill( &ctx );
}

/* ---- MSFT_NetRoute (the IPv4 forwarding table) ---- */

static enum fill_status fill_netroute( struct table *table, const struct expr *cond )
{
    IP_ADAPTER_ADDRESSES *adapters;
    MIB_IPFORWARDTABLE *t = NULL;
    MIB_IPINTERFACE_TABLE *ift = NULL;
    struct fill_ctx ctx;
    DWORD size = 4096, ret = ERROR_INSUFFICIENT_BUFFER;
    UINT i, j;

    begin_fill( &ctx, table, cond, sizeof(struct record_msft_netroute) );
    for (i = 0; i < 6 && ret == ERROR_INSUFFICIENT_BUFFER; i++)
    {
        heap_free( t );
        if (!(t = heap_alloc( size ))) return FILL_STATUS_FAILED;
        ret = GetIpForwardTable( t, &size, FALSE );
    }
    if (ret)
    {
        heap_free( t );
        return end_fill( &ctx );
    }
    adapters = read_adapters();
    if (GetIpInterfaceTable( AF_V4, &ift )) ift = NULL;

    for (i = 0; i < t->dwNumEntries; i++)
    {
        const MIB_IPFORWARDROW *r = &t->table[i];
        const IP_ADAPTER_ADDRESSES *aa = find_adapter( adapters, r->dwForwardIfIndex );
        struct record_msft_netroute *rec;
        UINT32 if_metric = aa ? aa->Ipv4Metric : 0, metric, plen = 0, mask = ntohl( r->dwForwardMask );
        WCHAR *dest, *next, *plain, *prefix;

        if (ift)
            for (j = 0; j < ift->NumEntries; j++)
                if (ift->Table[j].InterfaceIndex == r->dwForwardIfIndex) { if_metric = ift->Table[j].Metric; break; }
        metric = r->dwForwardMetric1 >= if_metric ? r->dwForwardMetric1 - if_metric : r->dwForwardMetric1;
        for (; mask; mask <<= 1) plen++;

        dest = ip4_text( r->dwForwardDest );
        next = ip4_text( r->dwForwardNextHop );
        /* the legacy table gives an on-link route the interface's own address as next hop */
        if (aa && next)
        {
            IP_ADAPTER_UNICAST_ADDRESS *u;
            for (u = aa->FirstUnicastAddress; u; u = u->Next)
                if (u->Address.lpSockaddr && u->Address.lpSockaddr->sa_family == AF_V4 &&
                    ((SOCKADDR_IN *)u->Address.lpSockaddr)->sin_addr.s_addr == r->dwForwardNextHop)
                {
                    heap_free( next );
                    next = heap_strdupW( L"0.0.0.0" );
                    break;
                }
        }
        prefix = format_text( L"%s/%u", dest, plen );
        if (!(rec = new_record( &ctx )))
        {
            heap_free( dest ); heap_free( next ); heap_free( prefix );
            break;
        }
        plain = format_text( L"%s++%u++%s++1", prefix, r->dwForwardIfIndex, next );
        rec->instanceid = plain ? encode_key( plain ) : NULL;
        heap_free( plain );
        heap_free( dest );
        rec->routemetric = metric > 65535 ? 65535 : metric;
        rec->typeofroute = r->u1.dwForwardType;
        rec->addressfamily = AF_V4;
        rec->compartmentid = 1;
        rec->destinationprefix = prefix;
        rec->interfacealias = dup_str( aa ? aa->FriendlyName : NULL );
        rec->interfaceindex = r->dwForwardIfIndex;
        rec->interfacemetric = if_metric;
        rec->nexthop = next;
        rec->preferredlifetime = format_interval( 0xffffffff );
        rec->protocol = r->u2.dwForwardProto ? r->u2.dwForwardProto : 1;
        rec->publish = 0;
        rec->state = 0;
        rec->store = 1;
        rec->validlifetime = format_interval( 0xffffffff );
        add_record( &ctx );
    }
    if (ift) FreeMibTable( ift );
    heap_free( adapters );
    heap_free( t );
    return end_fill( &ctx );
}

/* ---- MSFT_DNSClientServerAddress: one row per interface and address family ---- */

static struct array *dns_array( IP_ADAPTER_DNS_SERVER_ADDRESS *list, int family )
{
    IP_ADAPTER_DNS_SERVER_ADDRESS *d;
    struct array *ret;
    WCHAR **ptr;
    UINT count = 0, n = 0;

    for (d = list; d; d = d->Next)
        if (d->Address.lpSockaddr && d->Address.lpSockaddr->sa_family == family) count++;
    if (!(ret = heap_alloc( sizeof(*ret) ))) return NULL;
    if (!(ptr = heap_alloc( (count ? count : 1) * sizeof(*ptr) )))
    {
        heap_free( ret );
        return NULL;
    }
    for (d = list; d && n < count; d = d->Next)
    {
        SOCKADDR *sa = d->Address.lpSockaddr;

        if (!sa || sa->sa_family != family) continue;
        if (family == AF_V4) ptr[n] = ip4_text( ((SOCKADDR_IN *)sa)->sin_addr.s_addr );
        else ptr[n] = ip6_text( &((SOCKADDR_IN6 *)sa)->sin6_addr, ((SOCKADDR_IN6 *)sa)->sin6_scope_id );
        n++;
    }
    ret->elem_size = sizeof(*ptr);
    ret->count     = n;
    ret->ptr       = ptr;
    return ret;
}

static enum fill_status fill_dnsclientserveraddress( struct table *table, const struct expr *cond )
{
    static const int families[] = { AF_V4, AF_V6 };
    IP_ADAPTER_ADDRESSES *adapters, *aa;
    struct fill_ctx ctx;
    UINT f;

    begin_fill( &ctx, table, cond, sizeof(struct record_msft_dnsclientserveraddress) );
    if (!(adapters = read_adapters())) return end_fill( &ctx );
    for (aa = adapters; aa; aa = aa->Next)
    {
        for (f = 0; f < ARRAY_SIZE(families); f++)
        {
            int fam = families[f];
            DWORD ix = fam == AF_V4 ? aa->u.s.IfIndex : aa->Ipv6IfIndex;
            struct record_msft_dnsclientserveraddress *rec;
            IP_ADAPTER_UNICAST_ADDRESS *u;
            BOOL has_addr = FALSE;

            for (u = aa->FirstUnicastAddress; u; u = u->Next)
                if (u->Address.lpSockaddr && u->Address.lpSockaddr->sa_family == fam) has_addr = TRUE;
            if (!ix && !has_addr) continue;
            if (!(rec = new_record( &ctx ))) break;
            rec->elementname = dup_str( aa->FriendlyName );
            rec->name = format_text( L"%u", adapter_index( aa ) );
            fill_state_defaults( &rec->enableddefault, &rec->requestedstate, &rec->transitioningtostate, 12 );
            rec->enabledstate = 5;
            rec->creationclassname = heap_strdupW( L"" );
            rec->systemcreationclassname = heap_strdupW( L"" );
            rec->systemname = format_text( L"%u", fam );
            rec->accesscontext = 0;
            rec->addressfamily = fam;
            rec->interfacealias = dup_str( aa->FriendlyName );
            rec->interfaceindex = adapter_index( aa );
            rec->serveraddresses = dns_array( aa->FirstDnsServerAddress, fam );
            add_record( &ctx );
        }
    }
    heap_free( adapters );
    return end_fill( &ctx );
}

/* ---- MSFT_NetAdapter ---- */

struct driver_info
{
    WCHAR *desc, *provider, *version, *date, *component, *pnpid, *service, *image;
};

static WCHAR *reg_string( HKEY key, const WCHAR *name )
{
    DWORD type, size = 0;
    WCHAR *ret;

    if (RegQueryValueExW( key, name, NULL, &type, NULL, &size ) || (type != REG_SZ && type != REG_EXPAND_SZ)) return NULL;
    if (!(ret = heap_alloc( size + sizeof(WCHAR) ))) return NULL;
    if (RegQueryValueExW( key, name, NULL, NULL, (BYTE *)ret, &size ))
    {
        heap_free( ret );
        return NULL;
    }
    ret[size / sizeof(WCHAR)] = 0;
    return ret;
}

static WCHAR *reg_string_at( const WCHAR *subkey, const WCHAR *name )
{
    HKEY key;
    WCHAR *ret = NULL;

    if (RegOpenKeyExW( HKEY_LOCAL_MACHINE, subkey, 0, KEY_READ | KEY_WOW64_64KEY, &key )) return NULL;
    ret = reg_string( key, name );
    RegCloseKey( key );
    return ret;
}

static void read_driver( const WCHAR *guid, struct driver_info *di )
{
    static const WCHAR classkey[] = L"SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e972-e325-11ce-bfc1-08002be10318}";
    HKEY cls, sub;
    WCHAR name[64], path[512];
    DWORD i, len;

    memset( di, 0, sizeof(*di) );
    if (!RegOpenKeyExW( HKEY_LOCAL_MACHINE, classkey, 0, KEY_READ | KEY_WOW64_64KEY, &cls ))
    {
        for (i = 0; ; i++)
        {
            WCHAR *id;
            BOOL found;

            len = ARRAY_SIZE(name);
            if (RegEnumKeyExW( cls, i, name, &len, NULL, NULL, NULL, NULL )) break;
            if (RegOpenKeyExW( cls, name, 0, KEY_READ | KEY_WOW64_64KEY, &sub )) continue;
            id = reg_string( sub, L"NetCfgInstanceId" );
            found = id && !wcsicmp( id, guid );
            heap_free( id );
            if (found)
            {
                di->desc = reg_string( sub, L"DriverDesc" );
                di->provider = reg_string( sub, L"ProviderName" );
                di->version = reg_string( sub, L"DriverVersion" );
                di->date = reg_string( sub, L"DriverDate" );
                di->component = reg_string( sub, L"MatchingDeviceId" );
            }
            RegCloseKey( sub );
            if (found) break;
        }
        RegCloseKey( cls );
    }
    swprintf( path, L"SYSTEM\\CurrentControlSet\\Control\\Network\\{4D36E972-E325-11CE-BFC1-08002BE10318}\\%s\\Connection", guid );
    di->pnpid = reg_string_at( path, L"PnpInstanceID" );
    if (di->pnpid && lstrlenW( di->pnpid ) < 400)
    {
        swprintf( path, L"SYSTEM\\CurrentControlSet\\Enum\\%s", di->pnpid );
        di->service = reg_string_at( path, L"Service" );
    }
    if (di->service && lstrlenW( di->service ) < 400)
    {
        swprintf( path, L"SYSTEM\\CurrentControlSet\\Services\\%s", di->service );
        di->image = reg_string_at( path, L"ImagePath" );
    }
}

static void free_driver( struct driver_info *di )
{
    heap_free( di->desc ); heap_free( di->provider ); heap_free( di->version ); heap_free( di->date );
    heap_free( di->component ); heap_free( di->pnpid ); heap_free( di->service ); heap_free( di->image );
}

static BOOL is_visible_type( DWORD t )
{
    return t == 6 || t == 62 || t == 69 || t == 117 || t == 71 || t == 53 || t == 135 || t == 144;
}

static const WCHAR *if_type_name( DWORD t )
{
    switch (t)
    {
    case 6: case 62: case 69: case 117: return L"ethernet";
    case 71: return L"wireless";
    case 24: return L"loopback";
    case 131: return L"tunnel";
    case 23: return L"ppp";
    default: return L"other";
    }
}

static WCHAR *mac_text( const BYTE *mac, UINT len )
{
    WCHAR buf[3 * 32], *p = buf;
    UINT i;

    if (!len || len > 32) return NULL;
    for (i = 0; i < len; i++) p += swprintf( p, L"%02X", mac[i] );
    return heap_strdupW( buf );
}

static WCHAR *upper_guid( const char *name )
{
    WCHAR buf[64];
    UINT i, n = 0;

    if (!name) return NULL;
    if (name[0] != '{') buf[n++] = '{';
    for (i = 0; name[i] && n < ARRAY_SIZE(buf) - 2; i++) buf[n++] = (name[i] >= 'a' && name[i] <= 'z') ? name[i] - 32 : name[i];
    if (n && buf[n - 1] != '}') buf[n++] = '}';
    buf[n] = 0;
    return heap_strdupW( buf );
}

static enum fill_status fill_netadapter( struct table *table, const struct expr *cond )
{
    IP_ADAPTER_ADDRESSES *adapters, *aa;
    MIB_IF_TABLE2 *ift = NULL;
    struct fill_ctx ctx;
    WCHAR *machine;
    DWORD size = MAX_COMPUTERNAME_LENGTH + 1;
    UINT i;

    begin_fill( &ctx, table, cond, sizeof(struct record_msft_netadapter) );
    if (!(adapters = read_adapters())) return end_fill( &ctx );
    if (GetIfTable2( &ift )) ift = NULL;
    machine = heap_alloc( size * sizeof(WCHAR) );
    if (machine && !GetComputerNameW( machine, &size )) machine[0] = 0;

    for (aa = adapters; aa; aa = aa->Next)
    {
        DWORD idx = adapter_index( aa );
        const MIB_IF_ROW2 *ifr = NULL;
        struct record_msft_netadapter *rec;
        struct driver_info di;
        WCHAR *guid, *mac;
        DWORD if_type = aa->IfType, oper = aa->OperStatus, admin = 1, media, mtu = aa->Mtu;
        ULONG64 luid = aa->Luid.Value, tx = aa->TransmitLinkSpeed, rx = aa->ReceiveLinkSpeed;
        UINT32 ndis_medium, phys_medium = 0, lluid;
        BOOL hw, hidden, connector;

        if (ift)
            for (i = 0; i < ift->NumEntries; i++)
                if (ift->Table[i].InterfaceIndex == idx) { ifr = &ift->Table[i]; break; }
        if (ifr)
        {
            if_type = ifr->Type;
            if (ifr->InterfaceLuid.Value) luid = ifr->InterfaceLuid.Value;
            oper = ifr->OperStatus;
            if (ifr->AdminStatus) admin = ifr->AdminStatus;
            if (ifr->Mtu) mtu = ifr->Mtu;
            if (ifr->TransmitLinkSpeed) tx = ifr->TransmitLinkSpeed;
            if (ifr->ReceiveLinkSpeed) rx = ifr->ReceiveLinkSpeed;
            phys_medium = ifr->PhysicalMediumType;
        }
        if (!is_visible_type( if_type )) continue;
        if (tx == ~(ULONG64)0) tx = 0;
        if (rx == ~(ULONG64)0) rx = 0;
        media = oper == IfOperStatusUp ? 1 : 2;
        ndis_medium = ifr ? ifr->MediaType : (if_type == 71 ? 16 : 0);
        hw = if_type == 6 || if_type == 71;
        hidden = FALSE;
        connector = oper != IfOperStatusNotPresent;
        lluid = (UINT32)((luid >> 24) & 0xffffff);

        if (!(rec = new_record( &ctx ))) break;
        guid = upper_guid( aa->AdapterName );
        read_driver( guid ? guid : L"", &di );
        mac = mac_text( aa->PhysicalAddress, aa->PhysicalAddressLength );

        rec->instanceid = dup_str( guid );
        rec->name = dup_str( aa->FriendlyName );
        fill_state_defaults( &rec->enableddefault, &rec->requestedstate, &rec->transitioningtostate, 12 );
        rec->enabledstate = 5;
        rec->creationclassname = heap_strdupW( L"MSFT_NetAdapter" );
        rec->deviceid = dup_str( guid );
        rec->systemcreationclassname = heap_strdupW( L"CIM_NetworkPort" );
        rec->systemname = dup_str( machine );
        rec->speed = tx;
        rec->activemaximumtransmissionunit = mtu;
        rec->fullduplex = oper == IfOperStatusUp;
        rec->networkaddresses = mac ? new_string_array( 1, (const WCHAR **)&mac ) : NULL;
        rec->permanentaddress = dup_str( mac );
        rec->portnumber = 0;
        rec->adminlocked = FALSE;
        rec->componentid = di.component; di.component = NULL;
        rec->connectorpresent = connector;
        rec->devicename = guid ? format_text( L"\\Device\\%s", guid ) : NULL;
        rec->devicewakeupenable = FALSE;
        if (di.date)
        {
            UINT y, m, d;
            if (swscanf( di.date, L"%u-%u-%u", &m, &d, &y ) == 3 && y > 1600)
            {
                SYSTEMTIME st = { 0 };
                FILETIME ft;
                ULARGE_INTEGER u;

                st.wYear = y; st.wMonth = m; st.wDay = d;
                if (SystemTimeToFileTime( &st, &ft ))
                {
                    u.QuadPart = ((ULONGLONG)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
                    rec->driverdate = format_text( L"%04u-%02u-%02u", y, m, d );
                    rec->driverdatedata = u.QuadPart;
                }
            }
        }
        rec->driverdescription = di.desc ? di.desc : dup_str( aa->Description );
        di.desc = NULL;
        if (di.version)
        {
            UINT a, b, c, e;
            if (swscanf( di.version, L"%u.%u.%u.%u", &a, &b, &c, &e ) == 4)
            {
                rec->majordriverversion = c;
                rec->minordriverversion = e & 0xff;
            }
        }
        if (di.image)
        {
            const WCHAR *leaf = wcsrchr( di.image, '\\' );
            rec->drivername = format_text( L"\\SystemRoot\\System32\\drivers\\%s", leaf ? leaf + 1 : di.image );
        }
        rec->driverprovider = di.provider; di.provider = NULL;
        rec->driverversionstring = di.version; di.version = NULL;
        rec->endpointinterface = ifr && ifr->InterfaceAndOperStatusFlags.EndPointInterface;
        rec->hardwareinterface = hw;
        rec->hidden = hidden;
        rec->imfilter = FALSE;
        rec->interfaceadminstatus = admin;
        rec->interfacedescription = dup_str( aa->Description );
        rec->interfaceguid = dup_str( guid );
        rec->interfaceindex = idx;
        rec->interfacename = format_text( L"%s_%u", if_type_name( if_type ), lluid );
        rec->interfaceoperationalstatus = oper;
        rec->interfacetype = if_type;
        rec->iscsiinterface = FALSE;
        rec->mediaconnectstate = media;
        rec->mediaduplexstate = oper == IfOperStatusUp ? 2 : 0;
        rec->mtusize = mtu;
        rec->ndismedium = ndis_medium;
        rec->ndisphysicalmedium = phys_medium;
        rec->netluid = luid;
        rec->netluidindex = lluid;
        rec->notuserremovable = FALSE;
        rec->operationalstatusdowndefaultportnotauthenticated = FALSE;
        rec->operationalstatusdowninterfacepaused = FALSE;
        rec->operationalstatusdownlowpowerstate = FALSE;
        rec->operationalstatusdownmediadisconnected = oper == IfOperStatusDown && media == 2;
        rec->pnpdeviceid = di.pnpid; di.pnpid = NULL;
        rec->promiscuousmode = FALSE;
        rec->receivelinkspeed = rx;
        rec->state = 2;
        rec->transmitlinkspeed = tx;
        rec->virtual = !hw && !hidden;
        rec->vlanid = 0;
        rec->wdminterface = FALSE;
        free_driver( &di );
        heap_free( mac );
        heap_free( guid );
        add_record( &ctx );
    }
    heap_free( machine );
    if (ift) FreeMibTable( ift );
    heap_free( adapters );
    return end_fill( &ctx );
}

/* ---- the tables ---- */

#define C(c) ARRAY_SIZE(c), c
static struct table scv2_tables[] =
{
    { L"MSFT_NetTCPConnection", C(scv2_cols_msft_nettcpconnection), 0, 0, NULL, fill_nettcpconnection },
    { L"MSFT_NetUDPEndpoint", C(scv2_cols_msft_netudpendpoint), 0, 0, NULL, fill_netudpendpoint },
    { L"MSFT_NetIPAddress", C(scv2_cols_msft_netipaddress), 0, 0, NULL, fill_netipaddress },
    { L"MSFT_NetIPInterface", C(scv2_cols_msft_netipinterface), 0, 0, NULL, fill_netipinterface },
    { L"MSFT_NetRoute", C(scv2_cols_msft_netroute), 0, 0, NULL, fill_netroute },
    { L"MSFT_NetAdapter", C(scv2_cols_msft_netadapter), 0, 0, NULL, fill_netadapter },
    { L"MSFT_DNSClientServerAddress", C(scv2_cols_msft_dnsclientserveraddress), 0, 0, NULL, fill_dnsclientserveraddress },
};
#undef C

void init_scv2_tables( struct list *list )
{
    UINT i;

    for (i = 0; i < ARRAY_SIZE(scv2_tables); i++) list_add_tail( list, &scv2_tables[i].entry );
}
