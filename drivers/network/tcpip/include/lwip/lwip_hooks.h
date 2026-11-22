/*
 * PROJECT:     NitroOS
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     lwip_hooks
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#pragma once

/* The lwIP hooks of lwipopts.h, implemented in ip/lwip_glue/tcp.c */

#include <lwip/ip_addr.h>
#include <lwip/err.h>

struct pbuf;
struct netif;
struct tcp_pcb_listen;

int LibTCPReopenTimeWait(struct pbuf *p, struct netif *inp);
void LibTCPApplyListenRoom(struct tcp_pcb_listen *lpcb);
/* ip/transport/tcp/rdnss6.c */
void LibTCPRdnss6Input(struct netif *netif, const ip6_addr_t *addr, u32_t lifetime);
/* ip/transport/tcp/ra6.c */
void LibTCPDnssl6Input(struct netif *netif, struct pbuf *p, u16_t offset, u16_t length);
void LibNd6RaHeader(struct netif *netif, u8_t hop_limit, u8_t flags);
u8_t LibIp6HopLimit(struct netif *netif, u8_t hl);
/* ip/transport/tcp/ifcfg.c */
int LibNd6RaAccept(struct netif *netif);
u8_t LibNd6DadAttempts(struct netif *netif);
/* ip/transport/tcp/iid6.c */
u32_t TCPConnectionHash(const ip_addr_t *LocalIp, u16_t LocalPort, const ip_addr_t *RemoteIp, u16_t RemotePort);
int LibNd6SlaacAddress(struct netif *netif, const ip6_addr_t *prefix, ip6_addr_t *addr);
int LibNd6DadFailed(struct netif *netif, s8_t index);
/* ip/transport/tcp/if6.c */
err_t LibTCPListenerInput6(void);
int LibIcmp6ErrorAllowed(void);
u32_t LibTCPNextIss(const ip_addr_t *LocalIp, u16_t LocalPort, const ip_addr_t *RemoteIp, u16_t RemotePort);
/* ip/transport/tcp/nd6info.c */
int LibIp6CountInput(struct pbuf *p, struct netif *inp);
void LibIp6CountDelivered(struct pbuf *p, struct netif *inp, u8_t nexth);
void LibTCPRoutes6Changed(void);
/* ip/transport/tcp/route6.c */
struct netif *LibIp6Route(const ip6_addr_t *src, const ip6_addr_t *dest);
const ip6_addr_t *LibNd6GetGw(struct netif *netif, const ip6_addr_t *dest);
void LibNd6Timer(void);
void LibNd6RouteInfo(struct netif *netif, const ip6_addr_t *router, const u8_t *prefix, u8_t length, u8_t preference, u32_t lifetime);
/* ip/transport/tcp/addr6.c */
int LibNd6AddrConfigured(struct netif *netif, s8_t Slot);
int LibIp6SkipSource(struct netif *netif, s8_t Slot);
/* ip/transport/tcp/temp6.c */
int LibNd6AddrTemporary(struct netif *netif, s8_t Slot);
int LibIp6SourceTemporary(struct netif *netif, s8_t Slot);
/* ip/transport/tcp/policy6.c */
const ip_addr_t *LibIp6SelectSource(struct netif *netif, const ip6_addr_t *dest);
void LibNd6TemporaryTimer(void);
int LibNd6MakeRoom(struct netif *netif);
/* ip/transport/udp/udp6.c */
int LibIp6NexthInput(struct pbuf *p, struct netif *inp, u8_t nexth);
int LibIp6McastAccept(struct netif *inp, const ip6_addr_t *dest);
u32_t LibMld6Random(void);
