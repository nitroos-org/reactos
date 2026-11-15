#ifdef __REACTOS__
#include "precomp.h"
#include "inet_ntop.c"
#else
/*
 * Wininet - Utility functions
 *
 * Copyright 1999 Corel Corporation
 * Copyright 2002 CodeWeavers Inc.
 *
 * Ulrich Czekalla
 * Aric Stewart
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

#include "ws2tcpip.h"

#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "windef.h"
#include "winbase.h"
#include "wininet.h"
#include "winnls.h"

#include "wine/debug.h"
#include "internet.h"
#endif /* defined(__REACTOS__) */

WINE_DEFAULT_DEBUG_CHANNEL(wininet);

/* A bracketed IPv6 literal ("[::1]", "[fe80::1%2]", "[fe80::1%252]" with a percent-encoded zone id, RFC 6874) is
 * not a host name for getaddrinfo: take the brackets off and decode the "%25". Other names are used as is. */
static const WCHAR *literal_host(const WCHAR *name, WCHAR *buf, size_t size)
{
    size_t len = lstrlenW(name), i, j;

    if (len < 2 || name[0] != '[' || name[len - 1] != ']' || len - 1 > size)
        return name;
    for (i = 1, j = 0; i < len - 1; i++)
    {
        buf[j++] = name[i];
        if (name[i] == '%' && name[i + 1] == '2' && name[i + 2] == '5' && i + 2 < len - 1) i += 2;
    }
    buf[j] = 0;
    return buf;
}

/* TRUE if name is an IPv6 address, bracketed ("[::1]", "[fe80::1%2]") or not; *loopback is set for ::1.
 * Purely syntactic (no resolver call, no Winsock start-up needed). */
BOOL is_ipv6_literal_host(const WCHAR *name, BOOL *loopback)
{
    WCHAR buf[64];
    IN6_ADDR addr;
    size_t len = lstrlenW(name), i;

    if (loopback) *loopback = FALSE;
    if (len >= 2 && name[0] == '[' && name[len - 1] == ']') { name++; len -= 2; }
    for (i = 0; i < len && name[i] != '%'; i++) if (i >= ARRAY_SIZE(buf) - 1) return FALSE;
    memcpy(buf, name, i * sizeof(WCHAR));
    buf[i] = 0;
    if (!wcschr(buf, ':')) return FALSE;
    if (InetPtonW(AF_INET6, buf, &addr) != 1) return FALSE;
    if (loopback) *loopback = IN6_IS_ADDR_LOOPBACK(&addr);
    return TRUE;
}

/* A bracketed host that is not an IPv6 address ("[localhost]", "[127.0.0.1]"): Windows rejects it as an invalid URL. */
BOOL is_bad_bracketed_host(const WCHAR *name)
{
    size_t len = lstrlenW(name);
    return len >= 2 && name[0] == '[' && name[len - 1] == ']' && !is_ipv6_literal_host(name, NULL);
}

/* All addresses of name in getaddrinfo order (at most max_addrs), each with the port set. Returns the count. */
int GetAddressList(const WCHAR *name, INTERNET_PORT port, struct sockaddr_storage *addrs, int *lens, int max_addrs)
{
    ADDRINFOW *res, *ai, hints;
    WCHAR literal[260];
    int count = 0;

    TRACE("%s\n", debugstr_w(name));

    memset( &hints, 0, sizeof(hints) );
    /* Every address, in the order getaddrinfo returns them: the caller falls back to the next one when a
     * connection attempt fails (a name may have IPv6 addresses on which no server listens). */
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if (name[0] == '[')
    {
        /* brackets hold an IPv6 address (RFC 3986 IP-literal), never a name to look up in DNS or an IPv4 address:
         * "[host.example]" must not reach host.example (a URL filter sees the host "[host.example]") */
        if (literal_host(name, literal, ARRAY_SIZE(literal)) != literal || !wcschr(literal, ':'))
            return 0;
        name = literal;
        hints.ai_family = AF_INET6;
        hints.ai_flags = AI_NUMERICHOST;
    }
    if (GetAddrInfoW(name, NULL, &hints, &res) != 0)
    {
        TRACE("failed to get address of %s\n", debugstr_w(name));
        return 0;
    }
    for (ai = res; ai && count < max_addrs; ai = ai->ai_next)
    {
        if ((ai->ai_family != AF_INET && ai->ai_family != AF_INET6) || ai->ai_addrlen > sizeof(*addrs))
            continue;
        if (hints.ai_family == AF_INET6 && ai->ai_family != AF_INET6)
            continue;
        memset(&addrs[count], 0, sizeof(addrs[count]));
        memcpy(&addrs[count], ai->ai_addr, ai->ai_addrlen);
        if (ai->ai_family == AF_INET)
            ((struct sockaddr_in *)&addrs[count])->sin_port = htons(port);
        else
            ((struct sockaddr_in6 *)&addrs[count])->sin6_port = htons(port);
        lens[count++] = ai->ai_addrlen;
    }
    FreeAddrInfoW(res);
    return count;
}

void address_to_string(const struct sockaddr_storage *addr, char *str)
{
    const void *src = addr->ss_family == AF_INET6 ? (const void *)&((const struct sockaddr_in6 *)addr)->sin6_addr
                                                  : (const void *)&((const struct sockaddr_in *)addr)->sin_addr;
    str[0] = 0;
    inet_ntop(addr->ss_family, (void *)src, str, INET6_ADDRSTRLEN);
}

BOOL GetAddress(const WCHAR *name, INTERNET_PORT port, struct sockaddr *psa, int *sa_len, char *addr_str)
{
    struct sockaddr_storage addrs[1];
    int lens[1];

    if (GetAddressList(name, port, addrs, lens, 1) < 1)
        return FALSE;
    if (*sa_len < lens[0])
    {
        WARN("address too small\n");
        return FALSE;
    }
    *sa_len = lens[0];
    memcpy(psa, &addrs[0], lens[0]);
    if (addr_str)
        address_to_string(&addrs[0], addr_str);
    return TRUE;
}

/*
 * Helper function for sending async Callbacks
 */

static const char *get_callback_name(DWORD dwInternetStatus) {
    static const wininet_flag_info internet_status[] = {
#define FE(x) { x, #x }
	FE(INTERNET_STATUS_RESOLVING_NAME),
	FE(INTERNET_STATUS_NAME_RESOLVED),
	FE(INTERNET_STATUS_CONNECTING_TO_SERVER),
	FE(INTERNET_STATUS_CONNECTED_TO_SERVER),
	FE(INTERNET_STATUS_SENDING_REQUEST),
	FE(INTERNET_STATUS_REQUEST_SENT),
	FE(INTERNET_STATUS_RECEIVING_RESPONSE),
	FE(INTERNET_STATUS_RESPONSE_RECEIVED),
	FE(INTERNET_STATUS_CTL_RESPONSE_RECEIVED),
	FE(INTERNET_STATUS_PREFETCH),
	FE(INTERNET_STATUS_CLOSING_CONNECTION),
	FE(INTERNET_STATUS_CONNECTION_CLOSED),
	FE(INTERNET_STATUS_HANDLE_CREATED),
	FE(INTERNET_STATUS_HANDLE_CLOSING),
	FE(INTERNET_STATUS_REQUEST_COMPLETE),
	FE(INTERNET_STATUS_REDIRECT),
	FE(INTERNET_STATUS_INTERMEDIATE_RESPONSE),
	FE(INTERNET_STATUS_USER_INPUT_REQUIRED),
	FE(INTERNET_STATUS_STATE_CHANGE),
	FE(INTERNET_STATUS_COOKIE_SENT),
	FE(INTERNET_STATUS_COOKIE_RECEIVED),
	FE(INTERNET_STATUS_PRIVACY_IMPACTED),
	FE(INTERNET_STATUS_P3P_HEADER),
	FE(INTERNET_STATUS_P3P_POLICYREF),
	FE(INTERNET_STATUS_COOKIE_HISTORY)
#undef FE
    };
    DWORD i;

    for (i = 0; i < ARRAY_SIZE(internet_status); i++) {
	if (internet_status[i].val == dwInternetStatus) return internet_status[i].name;
    }
    return "Unknown";
}

static const char *debugstr_status_info(DWORD status, void *info)
{
    switch(status) {
    case INTERNET_STATUS_REQUEST_COMPLETE: {
        INTERNET_ASYNC_RESULT *iar = info;
        return wine_dbg_sprintf("{%s, %ld}", wine_dbgstr_longlong(iar->dwResult), iar->dwError);
    }
    default:
        return wine_dbg_sprintf("%p", info);
    }
}

void INTERNET_SendCallback(object_header_t *hdr, DWORD_PTR context, DWORD status, void *info, DWORD info_len)
{
    void *new_info = info;

    if( !hdr->lpfnStatusCB )
        return;

    /* the IE5 version of wininet does not
       send callbacks if dwContext is zero */
    if(!context)
        return;

    switch(status) {
    case INTERNET_STATUS_NAME_RESOLVED:
    case INTERNET_STATUS_CONNECTING_TO_SERVER:
    case INTERNET_STATUS_CONNECTED_TO_SERVER:
        new_info = malloc(info_len);
        if(new_info)
            memcpy(new_info, info, info_len);
        break;
    case INTERNET_STATUS_RESOLVING_NAME:
    case INTERNET_STATUS_REDIRECT:
        if(hdr->dwInternalFlags & INET_CALLBACKW) {
            new_info = wcsdup(info);
            break;
        }else {
            new_info = strdupWtoA(info);
            info_len = strlen(new_info)+1;
            break;
        }
    }
    
    TRACE(" callback(%p) (%p (%p), %08Ix, %ld (%s), %s, %ld)\n",
	  hdr->lpfnStatusCB, hdr->hInternet, hdr, context, status, get_callback_name(status),
	  debugstr_status_info(status, new_info), info_len);
    
    hdr->lpfnStatusCB(hdr->hInternet, context, status, new_info, info_len);

    TRACE(" end callback().\n");

    if(new_info != info)
        free(new_info);
}
