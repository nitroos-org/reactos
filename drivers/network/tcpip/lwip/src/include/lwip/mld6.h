/**
 * @file
 *
 * Multicast listener discovery for IPv6. Aims to be compliant with RFC 2710.
 * No support for MLDv2.
 */

/*
 * Copyright (c) 2010 Inico Technologies Ltd.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT
 * SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 *
 * This file is part of the lwIP TCP/IP stack.
 *
 * Author: Ivan Delamer <delamer@inicotech.com>
 *
 *
 * Please coordinate changes and requests with Ivan Delamer
 * <delamer@inicotech.com>
 */

#ifndef LWIP_HDR_MLD6_H
#define LWIP_HDR_MLD6_H

#include "lwip/opt.h"

#if LWIP_IPV6_MLD && LWIP_IPV6  /* don't build if not configured for use in lwipopts.h */

#include "lwip/pbuf.h"
#include "lwip/netif.h"

#ifdef __cplusplus
extern "C" {
#endif

/* NitroOS: MLD6_V2 1 = MLDv2 listener reports (RFC 3810) with source filters, and MLDv1 (RFC 2710) while an
 * MLDv1 querier is on the link (RFC 3810 8); 0 = lwIP's MLDv1 only */
#ifndef MLD6_V2
#define MLD6_V2                        0
#endif
#define MLD6_FMODE_INCLUDE             0
#define MLD6_FMODE_EXCLUDE             1
/* The sources of a group's filter MLD reports at most: a larger INCLUDE set is reported as EXCLUDE with none (all
 * sources: more traffic, never less), a larger EXCLUDE set as no exclusion at all, for the same reason */
#define MLD6_MAX_SOURCES               256

/** MLD group */
struct mld_group {
  /** next link */
  struct mld_group *next;
  /** multicast address */
  ip6_addr_t         group_address;
  /** signifies we were the last person to report */
  u8_t               last_reporter_flag;
  /** current state of the group */
  u8_t               group_state;
  /** timer for reporting */
  u16_t              timer;
  /** counter of simultaneous uses */
  u8_t               use;
#if MLD6_V2
  /* NitroOS: the group's filter is that of the any-source joins (use, mld6_joingroup_netif: EXCLUDE with no
   * source) merged with the sockets' filter (mld6_set_filter_netif) */
  u8_t               sock_mode;     /* MLD6_FMODE_*; INCLUDE with no source: no socket listens */
  u16_t              sock_nsrc;
  u8_t             (*sock_srcs)[16];
  /* state change report (RFC 3810 6.1): the pending records, sent at once and rexmit more times */
  u16_t              rtimer;
  u8_t               rexmit;
  u8_t               chg_mode;      /* a filter mode change: CHANGE_TO_INCLUDE / CHANGE_TO_EXCLUDE */
  u16_t              nallow, nblock;
  u8_t             (*allow)[16];
  u8_t             (*block)[16];
  /* a pending answer to a group-and-source specific query (RFC 3810 6.2): the sources asked about */
  u8_t               qsrc_pending;
  u16_t              nqsrc;
  u8_t             (*qsrc)[16];
#endif /* MLD6_V2 */
};

#define MLD6_TMR_INTERVAL              100 /* Milliseconds */

/* NitroOS: MLD6_TMR_ON_DEMAND 1 = no cyclic mld6_tmr (timeouts.c); mld6.c arms one timeout for the earliest
 * pending report and none while nothing is pending, so an idle machine is not woken every MLD6_TMR_INTERVAL */
#ifndef MLD6_TMR_ON_DEMAND
#define MLD6_TMR_ON_DEMAND             0
#endif

err_t  mld6_stop(struct netif *netif);
void   mld6_report_groups(struct netif *netif);
void   mld6_tmr(void);
struct mld_group *mld6_lookfor_group(struct netif *ifp, const ip6_addr_t *addr);
void   mld6_input(struct pbuf *p, struct netif *inp);
err_t  mld6_joingroup(const ip6_addr_t *srcaddr, const ip6_addr_t *groupaddr);
err_t  mld6_joingroup_netif(struct netif *netif, const ip6_addr_t *groupaddr);
err_t  mld6_leavegroup(const ip6_addr_t *srcaddr, const ip6_addr_t *groupaddr);
err_t  mld6_leavegroup_netif(struct netif *netif, const ip6_addr_t *groupaddr);
#if MLD6_V2
err_t  mld6_set_filter_netif(struct netif *netif, const ip6_addr_t *groupaddr, u8_t mode, const u8_t (*srcs)[16], u16_t nsrc);
u8_t   mld6_version(struct netif *netif);
#endif /* MLD6_V2 */

/** @ingroup mld6
 * Get list head of MLD6 groups for netif.
 * Note: The allnodes group IP is NOT in the list, since it must always
 * be received for correct IPv6 operation.
 * @see @ref netif_set_mld_mac_filter()
 */
#define netif_mld6_data(netif) ((struct mld_group *)netif_get_client_data(netif, LWIP_NETIF_CLIENT_DATA_INDEX_MLD6))

#ifdef __cplusplus
}
#endif

#endif /* LWIP_IPV6_MLD && LWIP_IPV6 */

#endif /* LWIP_HDR_MLD6_H */
