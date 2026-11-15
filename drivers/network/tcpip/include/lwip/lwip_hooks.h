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

int LibTCPReopenTimeWait(struct pbuf *p, struct netif *inp);
/* ip/transport/tcp/rdnss6.c */
void LibTCPRdnss6Input(struct netif *netif, const ip6_addr_t *addr, u32_t lifetime);
/* ip/transport/tcp/iid6.c */
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
/* ip/transport/tcp/addr6.c */
int LibNd6AddrConfigured(struct netif *netif, s8_t Slot);
int LibIp6SkipSource(struct netif *netif, s8_t Slot);
/* ip/transport/udp/udp6.c */
int LibIp6NexthInput(struct pbuf *p, struct netif *inp, u8_t nexth);
int LibIp6McastAccept(struct netif *inp, const ip6_addr_t *dest);
