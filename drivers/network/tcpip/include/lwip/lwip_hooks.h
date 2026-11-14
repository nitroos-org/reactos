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
/* ip/transport/tcp/if6.c */
err_t LibTCPListenerInput6(void);
int LibIcmp6ErrorAllowed(void);
u32_t LibTCPNextIss(const ip_addr_t *LocalIp, u16_t LocalPort, const ip_addr_t *RemoteIp, u16_t RemotePort);
