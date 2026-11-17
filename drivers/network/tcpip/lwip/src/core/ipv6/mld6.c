/**
 * @file
 * Multicast listener discovery
 *
 * @defgroup mld6 MLD6
 * @ingroup ip6
 * Multicast listener discovery for IPv6. Aims to be compliant with RFC 2710.
 * NitroOS: with MLD6_V2, MLDv2 (RFC 3810): listener reports with source filters, MLDv1 while an MLDv1 querier
 * is present (RFC 3810 8).<br>
 * Note: The allnodes (ff01::1, ff02::1) group is assumed be received by your
 * netif since it must always be received for correct IPv6 operation (e.g. SLAAC).
 * Ensure the netif filters are configured accordingly!<br>
 * The netif flags also need NETIF_FLAG_MLD6 flag set to enable MLD6 on a
 * netif ("netif->flags |= NETIF_FLAG_MLD6;").<br>
 * To be called from TCPIP thread.
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

/* Based on igmp.c implementation of igmp v2 protocol */

#include "lwip/opt.h"

#if LWIP_IPV6 && LWIP_IPV6_MLD  /* don't build if not configured for use in lwipopts.h */

#include "lwip/mld6.h"
#include "lwip/prot/mld6.h"
#include "lwip/icmp6.h"
#include "lwip/ip6.h"
#include "lwip/ip6_addr.h"
#include "lwip/ip.h"
#include "lwip/inet_chksum.h"
#include "lwip/pbuf.h"
#include "lwip/netif.h"
#include "lwip/memp.h"
#include "lwip/stats.h"
#include "lwip/timeouts.h"

#include <string.h>

#ifdef LWIP_HOOK_FILENAME
#include LWIP_HOOK_FILENAME
#endif

/* NitroOS: the random delay of a report (RFC 2710 4) may come from a source of its own (MLD6_RAND), so a port
 * gets it without defining LWIP_RAND for the whole stack */
#if !defined(MLD6_RAND) && defined(LWIP_RAND)
#define MLD6_RAND() LWIP_RAND()
#endif


/*
 * MLD constants
 */
#define MLD6_HL                           1
#define MLD6_JOIN_DELAYING_MEMBER_TMR_MS  (500)

#define MLD6_GROUP_NON_MEMBER             0
#define MLD6_GROUP_DELAYING_MEMBER        1
#define MLD6_GROUP_IDLE_MEMBER            2

#if MLD6_V2
/* NitroOS: MLDv2 (RFC 3810) */
#define MLD6_V2_REPORT                    143
#define MLD6_REC_IS_IN                    1
#define MLD6_REC_IS_EX                    2
#define MLD6_REC_TO_IN                    3
#define MLD6_REC_TO_EX                    4
#define MLD6_REC_ALLOW                    5
#define MLD6_REC_BLOCK                    6
/* A report (the ICMPv6 message) fits the minimum link MTU with its IPv6 and hop-by-hop headers */
#define MLD6_V2_REPORT_MAX                (1280 - IP6_HLEN - MLD6_HBH_HLEN)
#define MLD6_V2_REPORT_HLEN               8
#define MLD6_V2_RECORD_HLEN               20
#define MLD6_V2_QUERY_HLEN                28
/* RFC 3810 9: Robustness Variable, Query Interval (s), Unsolicited Report Interval (ticks) */
#define MLD6_DEFAULT_QRV                  2
#define MLD6_DEFAULT_QI                   125
#define MLD6_URI_TICKS                    (1000 / MLD6_TMR_INTERVAL)

/* Per interface (by netif index): the pending answer to a general query, what the querier said (robustness,
 * query interval), the MLDv1 querier present timer (RFC 3810 8.2.1: a time, so it costs no wake-up) and the groups
 * no longer listened to whose state change report is still being retransmitted */
struct mld6_ifstate {
  u16_t gtimer;
  u8_t  qrv;
  u8_t  v1;
  u32_t qi;
  u32_t v1_until;
  struct mld_group *leaving;
};
static struct mld6_ifstate mld6_ifs[256];
#define MLD6_IFS(netif) (&mld6_ifs[netif_get_index(netif)])

/* A report under construction: records are added until the message is full, then it is sent */
struct mld6_rb {
  struct netif *netif;
  struct pbuf *p;
  u16_t len;
  u16_t nrec;
};

static void mld6_group_free(struct mld_group *group);
static void mld6_v2_changed(struct netif *netif, struct mld_group *group, u8_t omode, const u8_t (*olist)[16], u16_t on);
static void mld6_v2_cancel(struct netif *netif);
#endif /* MLD6_V2 */

/* Forward declarations. */
static struct mld_group *mld6_new_group(struct netif *ifp, const ip6_addr_t *addr);
static err_t mld6_remove_group(struct netif *netif, struct mld_group *group);
static void mld6_delayed_report(struct mld_group *group, u16_t maxresp);
static void mld6_send(struct netif *netif, struct mld_group *group, u8_t type);
static void mld6_tmr_ticks(u32_t ticks);

/* NitroOS: RFC 2710 5: no report or done for the link-scope all-nodes group, nor for a group of the reserved
 * or the interface-local scope */
static int
mld6_reportable(const ip6_addr_t *addr)
{
  return !ip6_addr_isallnodes_linklocal(addr) &&
         ip6_addr_multicast_scope(addr) > IP6_MULTICAST_SCOPE_INTERFACE_LOCAL;
}

#if MLD6_TMR_ON_DEMAND
/* NitroOS: no cyclic timer (timeouts.c). The group timers still count MLD6_TMR_INTERVAL ticks, but one lwIP
 * timeout is armed for the earliest of them, and none while no report is pending: an idle machine gets no
 * wake-up from MLD, a machine on a network with a querier one or two per query. While the timeout is armed,
 * mld6_tmr_base is the time from which whole ticks are counted; a timer set meanwhile first has the elapsed
 * ticks taken off the others (mld6_tmr_settle), so every timer counts from the time it was set. */
static u8_t mld6_tmr_armed;
static u32_t mld6_tmr_base;

static void mld6_tmr_arm(void);

/* One running timer: Sub whole ticks taken off it (a due one stays at 1), and the earliest kept in *Next */
static void
mld6_tmr_adjust(u16_t *timer, u32_t sub, u16_t *next)
{
  if (*timer == 0) {
    return;
  }
  if (sub) {
    *timer = (*timer > sub) ? (u16_t)(*timer - sub) : 1;
  }
  if (next != NULL && (*next == 0 || *timer < *next)) {
    *next = *timer;
  }
}

/* Every timer of MLD: the groups' report timers and, with MLDv2, their retransmission timers, the general query
 * answer of each interface and the retransmissions of the groups no longer listened to */
static void
mld6_tmr_walk(u32_t sub, u16_t *next)
{
  struct netif *netif;

  NETIF_FOREACH(netif) {
    struct mld_group *group;

    for (group = netif_mld6_data(netif); group != NULL; group = group->next) {
      mld6_tmr_adjust(&group->timer, sub, next);
#if MLD6_V2
      mld6_tmr_adjust(&group->rtimer, sub, next);
#endif
    }
#if MLD6_V2
    mld6_tmr_adjust(&MLD6_IFS(netif)->gtimer, sub, next);
    for (group = MLD6_IFS(netif)->leaving; group != NULL; group = group->next) {
      mld6_tmr_adjust(&group->rtimer, sub, next);
    }
#endif
  }
}

/* The timeout: what is due is sent, then the next timeout is armed if a report is still pending */
static void
mld6_tmr_fire(void *arg)
{
  u32_t ticks = (u32_t)(sys_now() - mld6_tmr_base) / MLD6_TMR_INTERVAL;

  LWIP_UNUSED_ARG(arg);

  mld6_tmr_armed = 0;
  mld6_tmr_ticks(ticks);
  mld6_tmr_arm();
}

/* Takes the whole ticks elapsed since mld6_tmr_base off every running timer. A timer that is due stays at 1:
 * mld6_tmr_arm then arms the timeout less than a tick away and mld6_tmr_fire sends the report */
static void
mld6_tmr_settle(void)
{
  u32_t ticks;

  if (!mld6_tmr_armed) {
    return;
  }
  ticks = (u32_t)(sys_now() - mld6_tmr_base) / MLD6_TMR_INTERVAL;
  if (ticks == 0) {
    return;
  }
  mld6_tmr_base += ticks * MLD6_TMR_INTERVAL;
  mld6_tmr_walk(ticks, NULL);
}

/* Arms the timeout for the earliest running timer, or removes it when none runs. Called after mld6_tmr_settle
 * (or with no timeout armed), so less than a tick has passed since mld6_tmr_base */
static void
mld6_tmr_arm(void)
{
  u16_t next = 0;
  u32_t elapsed, delay;

  mld6_tmr_walk(0, &next);

  if (mld6_tmr_armed) {
    sys_untimeout(mld6_tmr_fire, NULL);
    mld6_tmr_armed = 0;
  } else {
    mld6_tmr_base = sys_now();
  }
  if (next == 0) {
    return;
  }

  elapsed = (u32_t)(sys_now() - mld6_tmr_base);
  delay = (u32_t)next * MLD6_TMR_INTERVAL;
  delay = (delay > elapsed) ? delay - elapsed : 1;
  sys_timeout(delay, mld6_tmr_fire, NULL);
  mld6_tmr_armed = 1;
}
#endif /* MLD6_TMR_ON_DEMAND */

#if MLD6_TMR_ON_DEMAND
#define MLD6_TMR_SETTLE() mld6_tmr_settle()
#define MLD6_TMR_ARM()    mld6_tmr_arm()
#else
#define MLD6_TMR_SETTLE()
#define MLD6_TMR_ARM()
#endif

#if MLD6_V2
/* A random delay of 1 to max ticks */
static u16_t
mld6_rand_ticks(u32_t max)
{
  u16_t t;

  if (max > 0xFFFF) {
    max = 0xFFFF;
  }
  if (max <= 1) {
    return 1;
  }
#ifdef MLD6_RAND
  t = (u16_t)(MLD6_RAND() % max);
#else
  t = (u16_t)max;
#endif
  return t ? t : 1;
}

/* The MLD version the interface speaks: 1 while an MLDv1 querier was heard within the Older Version Querier Present
 * Timeout (RFC 3810 8.2.1), else 2 */
u8_t
mld6_version(struct netif *netif)
{
  struct mld6_ifstate *ifs = MLD6_IFS(netif);

  if (ifs->v1 && (s32_t)(ifs->v1_until - sys_now()) > 0) {
    return 1;
  }
  ifs->v1 = 0;
  return 2;
}

/* (the kernel's C library of this port has no memcmp/memmove on every architecture: plain loops) */
static int
mld6_src_find(const u8_t (*list)[16], u16_t n, const u8_t *a)
{
  u16_t i, k;

  for (i = 0; i < n; i++) {
    for (k = 0; k < 16 && list[i][k] == a[k]; k++) {
    }
    if (k == 16) {
      return i;
    }
  }
  return -1;
}

/* A source list with room for 16 more whenever it is full; 0 when there is no memory or the list is at
 * MLD6_MAX_SOURCES */
static int
mld6_list_add(u8_t (**list)[16], u16_t *n, const u8_t *a)
{
  if (mld6_src_find((const u8_t (*)[16])*list, *n, a) >= 0) {
    return 1;
  }
  if (*n >= MLD6_MAX_SOURCES) {
    return 0;
  }
  if ((*n & 15) == 0) {
    u8_t (*grown)[16] = (u8_t (*)[16])mem_malloc((mem_size_t)((*n + 16) * 16));
    if (grown == NULL) {
      return 0;
    }
    if (*n) {
      MEMCPY(grown, *list, (size_t)*n * 16);
    }
    if (*list) {
      mem_free(*list);
    }
    *list = grown;
  }
  MEMCPY((*list)[*n], a, 16);
  (*n)++;
  return 1;
}

static void
mld6_list_del(u8_t (**list)[16], u16_t *n, const u8_t *a)
{
  int i = mld6_src_find((const u8_t (*)[16])*list, *n, a);

  if (i < 0) {
    return;
  }
  for (; (u16_t)i + 1 < *n; i++) {
    MEMCPY((*list)[i], (*list)[i + 1], 16);
  }
  if (--(*n) == 0) {
    mem_free(*list);
    *list = NULL;
  }
}

static void
mld6_list_free(u8_t (**list)[16], u16_t *n)
{
  if (*list) {
    mem_free(*list);
  }
  *list = NULL;
  *n = 0;
}

/* The pending state change and query answer of a group are forgotten */
static void
mld6_pending_clear(struct mld_group *group)
{
  group->rtimer = 0;
  group->rexmit = 0;
  group->chg_mode = 0;
  mld6_list_free(&group->allow, &group->nallow);
  mld6_list_free(&group->block, &group->nblock);
}

static void
mld6_group_free(struct mld_group *group)
{
  mld6_pending_clear(group);
  mld6_list_free(&group->sock_srcs, &group->sock_nsrc);
  mld6_list_free(&group->qsrc, &group->nqsrc);
  memp_free(MEMP_MLD6_GROUP, group);
}

/* The filter MLD reports for a group (RFC 3810 4.2): an any-source join (use) makes it EXCLUDE with no source,
 * whatever the sockets want; otherwise the sockets' merged filter. Beyond MLD6_MAX_SOURCES: EXCLUDE with none */
static void
mld6_filter(const struct mld_group *group, u8_t *mode, const u8_t (**list)[16], u16_t *n)
{
  if (group->use > 0 || group->sock_nsrc > MLD6_MAX_SOURCES) {
    *mode = MLD6_FMODE_EXCLUDE;
    *list = NULL;
    *n = 0;
  } else {
    *mode = group->sock_mode;
    *list = (const u8_t (*)[16])group->sock_srcs;
    *n = group->sock_nsrc;
  }
}

#define mld6_listening(mode, n) ((mode) == MLD6_FMODE_EXCLUDE || (n) > 0)

static int
mld6_group_listening(const struct mld_group *group)
{
  u8_t mode;
  const u8_t (*list)[16];
  u16_t n;

  mld6_filter(group, &mode, &list, &n);
  return mld6_listening(mode, n);
}

static void
mld6_rb_init(struct mld6_rb *rb, struct netif *netif)
{
  rb->netif = netif;
  rb->p = NULL;
  rb->len = 0;
  rb->nrec = 0;
}

static int
mld6_rb_alloc(struct mld6_rb *rb)
{
  u8_t *b;

  rb->p = pbuf_alloc(PBUF_IP, MLD6_HBH_HLEN + MLD6_V2_REPORT_MAX, PBUF_RAM);
  if (rb->p == NULL) {
    MLD6_STATS_INC(mld6.memerr);
    return 0;
  }
  /* room for the hop-by-hop options header in front, as mld6_send */
  if (pbuf_remove_header(rb->p, MLD6_HBH_HLEN)) {
    pbuf_free(rb->p);
    rb->p = NULL;
    return 0;
  }
  b = (u8_t *)rb->p->payload;
  memset(b, 0, MLD6_V2_REPORT_HLEN);
  b[0] = MLD6_V2_REPORT;
  rb->len = MLD6_V2_REPORT_HLEN;
  rb->nrec = 0;
  return 1;
}

/* Sends the report built so far (RFC 3810 5.2): to all MLDv2-capable routers (ff02::16) from the link-local
 * address (:: while it is tentative), hop limit 1, router alert */
static void
mld6_rb_flush(struct mld6_rb *rb)
{
  struct netif *netif = rb->netif;
  const ip6_addr_t *src_addr;
  ip6_addr_t dest_addr;
  u8_t *b;
  u16_t chksum;

  if (rb->p == NULL) {
    return;
  }
  if (rb->nrec == 0) {
    pbuf_free(rb->p);
    rb->p = NULL;
    return;
  }
  b = (u8_t *)rb->p->payload;
  b[6] = (u8_t)(rb->nrec >> 8);
  b[7] = (u8_t)rb->nrec;
  pbuf_realloc(rb->p, rb->len);

  IP6_ADDR(&dest_addr, PP_HTONL(0xff020000UL), 0, 0, PP_HTONL(0x00000016UL));
  ip6_addr_assign_zone(&dest_addr, IP6_MULTICAST, netif);
  if (!ip6_addr_isvalid(netif_ip6_addr_state(netif, 0))) {
    src_addr = IP6_ADDR_ANY6;
  } else {
    src_addr = netif_ip6_addr(netif, 0);
  }
  chksum = 0;
#if CHECKSUM_GEN_ICMP6
  IF__NETIF_CHECKSUM_ENABLED(netif, NETIF_CHECKSUM_GEN_ICMP6) {
    chksum = ip6_chksum_pseudo(rb->p, IP6_NEXTH_ICMP6, rb->p->len, src_addr, &dest_addr);
  }
#endif /* CHECKSUM_GEN_ICMP6 */
  SMEMCPY(&b[2], &chksum, sizeof(chksum));
  ip6_options_add_hbh_ra(rb->p, IP6_NEXTH_ICMP6, IP6_ROUTER_ALERT_VALUE_MLD);

  MLD6_STATS_INC(mld6.tx_report);
  MLD6_STATS_INC(mld6.xmit);
  ip6_output_if(rb->p, (ip6_addr_isany(src_addr)) ? NULL : src_addr, &dest_addr,
      MLD6_HL, 0, IP6_NEXTH_HOPBYHOP, netif);
  pbuf_free(rb->p);
  rb->p = NULL;
}

/* One multicast address record. One that does not fit a report is split into records of the same type, except
 * MODE_IS_EXCLUDE and CHANGE_TO_EXCLUDE_MODE, whose excess sources are left out (RFC 3810 5.2.15) */
static void
mld6_rb_record(struct mld6_rb *rb, u8_t type, const ip6_addr_t *group, const u8_t (*list)[16], u16_t n)
{
  u8_t ex = (type == MLD6_REC_IS_EX || type == MLD6_REC_TO_EX);

  for (;;) {
    u16_t room, take;
    u8_t *b;

    if (rb->p == NULL && !mld6_rb_alloc(rb)) {
      return;
    }
    room = (rb->len + MLD6_V2_RECORD_HLEN <= MLD6_V2_REPORT_MAX) ?
           (u16_t)((MLD6_V2_REPORT_MAX - rb->len - MLD6_V2_RECORD_HLEN) / 16) : 0;
    if (rb->nrec > 0 && (rb->len + MLD6_V2_RECORD_HLEN > MLD6_V2_REPORT_MAX || (room < n && (ex || room == 0)))) {
      /* a fresh report: the whole record, or as much of it as one report holds */
      mld6_rb_flush(rb);
      continue;
    }
    take = (n < room) ? n : room;
    b = (u8_t *)rb->p->payload + rb->len;
    b[0] = type;
    b[1] = 0;
    b[2] = (u8_t)(take >> 8);
    b[3] = (u8_t)take;
    MEMCPY(&b[4], group->addr, 16);
    if (take) {
      MEMCPY(&b[MLD6_V2_RECORD_HLEN], list, (size_t)take * 16);
    }
    rb->len = (u16_t)(rb->len + MLD6_V2_RECORD_HLEN + take * 16);
    rb->nrec++;
    if (ex || take == n) {
      return;
    }
    list += take;
    n = (u16_t)(n - take);
    mld6_rb_flush(rb);
  }
}

/* A Current State Record of a group (answer to a general or group specific query) */
static void
mld6_rb_current(struct mld6_rb *rb, struct mld_group *group)
{
  u8_t mode;
  const u8_t (*list)[16];
  u16_t n;

  if (!mld6_reportable(&group->group_address)) {
    return;
  }
  mld6_filter(group, &mode, &list, &n);
  if (mld6_listening(mode, n)) {
    mld6_rb_record(rb, mode == MLD6_FMODE_INCLUDE ? MLD6_REC_IS_IN : MLD6_REC_IS_EX, &group->group_address, list, n);
  }
}

/* The answer to a group-and-source specific query (RFC 3810 6.3): IS_IN with the sources asked about that are
 * listened to (INCLUDE: those in the list, EXCLUDE: those not in it); none when there is none */
static void
mld6_rb_source_answer(struct mld6_rb *rb, struct mld_group *group)
{
  u8_t mode;
  const u8_t (*list)[16];
  u16_t n, i, k = 0;
  u8_t (*answer)[16];

  mld6_filter(group, &mode, &list, &n);
  if (group->nqsrc == 0) {
    return;
  }
  answer = (u8_t (*)[16])mem_malloc((mem_size_t)(group->nqsrc * 16));
  if (answer == NULL) {
    /* no memory: the whole state, which says at least as much */
    mld6_rb_current(rb, group);
    return;
  }
  for (i = 0; i < group->nqsrc; i++) {
    int in = mld6_src_find(list, n, group->qsrc[i]) >= 0;
    if ((mode == MLD6_FMODE_INCLUDE) == in) {
      MEMCPY(answer[k], group->qsrc[i], 16);
      k++;
    }
  }
  if (k) {
    mld6_rb_record(rb, MLD6_REC_IS_IN, &group->group_address, (const u8_t (*)[16])answer, k);
  }
  mem_free(answer);
}

/* The pending state change records of a group (RFC 3810 6.1): the new mode with its whole list after a mode
 * change, else the sources allowed and blocked since */
static void
mld6_rb_pending(struct mld6_rb *rb, struct mld_group *group)
{
  u8_t mode;
  const u8_t (*list)[16];
  u16_t n;

  mld6_filter(group, &mode, &list, &n);
  if (group->chg_mode) {
    mld6_rb_record(rb, mode == MLD6_FMODE_INCLUDE ? MLD6_REC_TO_IN : MLD6_REC_TO_EX, &group->group_address, list, n);
    return;
  }
  if (group->nallow) {
    mld6_rb_record(rb, MLD6_REC_ALLOW, &group->group_address, (const u8_t (*)[16])group->allow, group->nallow);
  }
  if (group->nblock) {
    mld6_rb_record(rb, MLD6_REC_BLOCK, &group->group_address, (const u8_t (*)[16])group->block, group->nblock);
  }
}

/* The filter of a group changed from (omode, olist): a State Change Report at once and Robustness - 1 more at
 * random times within the Unsolicited Report Interval (RFC 3810 6.1). Changes while one is pending are merged:
 * a mode change sends the whole new state, source changes the sources allowed and blocked since */
static void
mld6_v2_changed(struct netif *netif, struct mld_group *group, u8_t omode, const u8_t (*olist)[16], u16_t on)
{
  struct mld6_ifstate *ifs = MLD6_IFS(netif);
  struct mld6_rb rb;
  u8_t mode;
  const u8_t (*list)[16];
  u16_t n, i;

  if (!mld6_reportable(&group->group_address) || !(netif->flags & NETIF_FLAG_MLD6)) {
    return;
  }
  mld6_filter(group, &mode, &list, &n);

  if (mode != omode) {
    group->chg_mode = 1;
    mld6_list_free(&group->allow, &group->nallow);
    mld6_list_free(&group->block, &group->nblock);
  } else if (!group->chg_mode) {
    /* INCLUDE: a new source is allowed, a removed one blocked; EXCLUDE: the other way round */
    u8_t (**more)[16] = (mode == MLD6_FMODE_INCLUDE) ? &group->allow : &group->block;
    u16_t *nmore = (mode == MLD6_FMODE_INCLUDE) ? &group->nallow : &group->nblock;
    u8_t (**less)[16] = (mode == MLD6_FMODE_INCLUDE) ? &group->block : &group->allow;
    u16_t *nless = (mode == MLD6_FMODE_INCLUDE) ? &group->nblock : &group->nallow;
    int ok = 1;

    for (i = 0; i < n && ok; i++) {
      if (mld6_src_find(olist, on, list[i]) < 0) {
        mld6_list_del(less, nless, list[i]);
        ok = mld6_list_add(more, nmore, list[i]);
      }
    }
    for (i = 0; i < on && ok; i++) {
      if (mld6_src_find(list, n, olist[i]) < 0) {
        mld6_list_del(more, nmore, olist[i]);
        ok = mld6_list_add(less, nless, olist[i]);
      }
    }
    if (!ok) {
      /* no room for the difference: the whole state instead */
      group->chg_mode = 1;
      mld6_list_free(&group->allow, &group->nallow);
      mld6_list_free(&group->block, &group->nblock);
    }
  }
  if (!group->chg_mode && group->nallow == 0 && group->nblock == 0) {
    return;
  }

  mld6_rb_init(&rb, netif);
  mld6_rb_pending(&rb, group);
  mld6_rb_flush(&rb);

  MLD6_TMR_SETTLE();
  group->rexmit = (u8_t)((ifs->qrv ? ifs->qrv : MLD6_DEFAULT_QRV) - 1);
  if (group->rexmit) {
    group->rtimer = mld6_rand_ticks(MLD6_URI_TICKS);
  } else {
    mld6_pending_clear(group);
  }
  MLD6_TMR_ARM();
}

/* An MLDv1 querier was heard (RFC 3810 8.2.1): every pending MLDv2 answer and retransmission is cancelled */
static void
mld6_v2_cancel(struct netif *netif)
{
  struct mld6_ifstate *ifs = MLD6_IFS(netif);
  struct mld_group *group;

  ifs->gtimer = 0;
  while (ifs->leaving != NULL) {
    group = ifs->leaving;
    ifs->leaving = group->next;
    mld6_group_free(group);
  }
  for (group = netif_mld6_data(netif); group != NULL; group = group->next) {
    mld6_pending_clear(group);
    mld6_list_free(&group->qsrc, &group->nqsrc);
    group->qsrc_pending = 0;
    if (group->group_state == MLD6_GROUP_DELAYING_MEMBER) {
      group->timer = 0;
      group->group_state = MLD6_GROUP_IDLE_MEMBER;
    }
  }
}

/* An MLDv2 query (RFC 3810 5.1, 6.2) of Length bytes on netif, the version answered being 2 */
static void
mld6_v2_query(struct netif *netif, struct pbuf *p, u16_t length)
{
  struct mld6_ifstate *ifs = MLD6_IFS(netif);
  u8_t h[MLD6_V2_QUERY_HLEN];
  u32_t maxresp, qi;
  u16_t code, nsrc, delay, i;
  ip6_addr_t addr;
  struct mld_group *group;

  if (pbuf_copy_partial(p, h, MLD6_V2_QUERY_HLEN, 0) != MLD6_V2_QUERY_HLEN) {
    return;
  }
  nsrc = (u16_t)((h[26] << 8) | h[27]);
  if ((u32_t)MLD6_V2_QUERY_HLEN + (u32_t)nsrc * 16 > length) {
    MLD6_STATS_INC(mld6.lenerr);
    return;
  }

  /* Maximum Response Code (5.1.3) in milliseconds, QRV and QQIC (5.1.8, 5.1.9) */
  code = (u16_t)((h[4] << 8) | h[5]);
  maxresp = (code < 32768) ? code : (u32_t)((code & 0x0FFF) | 0x1000) << (((code >> 12) & 7) + 3);
  if (h[24] & 7) {
    ifs->qrv = (u8_t)(h[24] & 7);
  }
  qi = (h[25] < 128) ? h[25] : (u32_t)((h[25] & 0x0F) | 0x10) << (((h[25] >> 4) & 7) + 3);
  ifs->qi = qi;
  delay = mld6_rand_ticks(maxresp / MLD6_TMR_INTERVAL);

  MEMCPY(addr.addr, &h[8], 16);
  ip6_addr_clear_zone(&addr);

  MLD6_TMR_SETTLE();
  if (ip6_addr_isany(&addr)) {
    /* a general query: one answer for every group at a random time, unless one is due earlier */
    if (nsrc == 0 && ip6_addr_isallnodes_linklocal(ip6_current_dest_addr())) {
      MLD6_STATS_INC(mld6.rx_general);
      if (ifs->gtimer == 0 || delay < ifs->gtimer) {
        ifs->gtimer = delay;
      }
    }
  } else if (ifs->gtimer == 0 || delay < ifs->gtimer) {
    ip6_addr_assign_zone(&addr, IP6_MULTICAST, netif);
    group = mld6_lookfor_group(netif, &addr);
    MLD6_STATS_INC(mld6.rx_group);
    if (group != NULL && mld6_reportable(&group->group_address)) {
      u8_t pending = (group->group_state == MLD6_GROUP_DELAYING_MEMBER && group->timer > 0);

      if (nsrc == 0 || (pending && !group->qsrc_pending)) {
        /* group specific, or a group specific answer is pending already */
        group->qsrc_pending = 0;
        mld6_list_free(&group->qsrc, &group->nqsrc);
      } else {
        if (!pending) {
          group->qsrc_pending = 1;
          mld6_list_free(&group->qsrc, &group->nqsrc);
        }
        for (i = 0; i < nsrc; i++) {
          u8_t a[16];

          if (pbuf_copy_partial(p, a, 16, (u16_t)(MLD6_V2_QUERY_HLEN + i * 16)) != 16 ||
              !mld6_list_add(&group->qsrc, &group->nqsrc, a)) {
            /* too many: the group specific answer */
            group->qsrc_pending = 0;
            mld6_list_free(&group->qsrc, &group->nqsrc);
            break;
          }
        }
      }
      if (!pending || delay < group->timer) {
        group->timer = delay;
      }
      group->group_state = MLD6_GROUP_DELAYING_MEMBER;
    }
  }
  MLD6_TMR_ARM();
}

/* The group's revival from the interface's leaving list, if it is there (core lock held) */
static struct mld_group *
mld6_revive_group(struct netif *netif, const ip6_addr_t *addr)
{
  struct mld6_ifstate *ifs = MLD6_IFS(netif);
  struct mld_group **link, *group;

  for (link = &ifs->leaving; (group = *link) != NULL; link = &group->next) {
    if (ip6_addr_eq(&group->group_address, addr)) {
      *link = group->next;
      group->next = netif_mld6_data(netif);
      netif_set_client_data(netif, LWIP_NETIF_CLIENT_DATA_INDEX_MLD6, group);
      return group;
    }
  }
  return NULL;
}
#endif /* MLD6_V2 */


/**
 * Stop MLD processing on interface
 *
 * @param netif network interface on which stop MLD processing
 */
err_t
mld6_stop(struct netif *netif)
{
  struct mld_group *group = netif_mld6_data(netif);

  netif_set_client_data(netif, LWIP_NETIF_CLIENT_DATA_INDEX_MLD6, NULL);

  while (group != NULL) {
    struct mld_group *next = group->next; /* avoid use-after-free below */

    /* disable the group at the MAC level */
    if (netif->mld_mac_filter != NULL) {
      netif->mld_mac_filter(netif, &(group->group_address), NETIF_DEL_MAC_FILTER);
    }

    /* free group */
#if MLD6_V2
    mld6_group_free(group);
#else
    memp_free(MEMP_MLD6_GROUP, group);
#endif

    /* move to "next" */
    group = next;
  }
#if MLD6_V2
  /* NitroOS: the groups whose leave was still being retransmitted, and the interface's MLD state */
  while (MLD6_IFS(netif)->leaving != NULL) {
    group = MLD6_IFS(netif)->leaving;
    MLD6_IFS(netif)->leaving = group->next;
    mld6_group_free(group);
  }
  memset(MLD6_IFS(netif), 0, sizeof(struct mld6_ifstate));
#endif
  return ERR_OK;
}

/**
 * Report MLD memberships for this interface
 *
 * @param netif network interface on which report MLD memberships
 */
void
mld6_report_groups(struct netif *netif)
{
  struct mld_group *group = netif_mld6_data(netif);

#if MLD6_V2
  /* NitroOS: MLDv2 announces every group again with a state change report (its whole state), sent within half a
   * second and retransmitted (RFC 3810 6.1) */
  if (mld6_version(netif) == 2) {
    struct mld6_ifstate *ifs = MLD6_IFS(netif);

    if (!(netif->flags & NETIF_FLAG_MLD6)) {
      return;
    }
    MLD6_TMR_SETTLE();
    for (; group != NULL; group = group->next) {
      if (!mld6_reportable(&group->group_address)) {
        continue;
      }
      mld6_list_free(&group->allow, &group->nallow);
      mld6_list_free(&group->block, &group->nblock);
      group->chg_mode = 1;
      group->rexmit = ifs->qrv ? ifs->qrv : MLD6_DEFAULT_QRV;
      group->rtimer = mld6_rand_ticks(MLD6_JOIN_DELAYING_MEMBER_TMR_MS / MLD6_TMR_INTERVAL);
    }
    MLD6_TMR_ARM();
    return;
  }
#endif

  while (group != NULL) {
    mld6_delayed_report(group, MLD6_JOIN_DELAYING_MEMBER_TMR_MS);
    group = group->next;
  }
}

/**
 * Search for a group that is joined on a netif
 *
 * @param ifp the network interface for which to look
 * @param addr the group ipv6 address to search for
 * @return a struct mld_group* if the group has been found,
 *         NULL if the group wasn't found.
 */
struct mld_group *
mld6_lookfor_group(struct netif *ifp, const ip6_addr_t *addr)
{
  struct mld_group *group = netif_mld6_data(ifp);

  while (group != NULL) {
    if (ip6_addr_eq(&(group->group_address), addr)) {
      return group;
    }
    group = group->next;
  }

  return NULL;
}


/**
 * create a new group
 *
 * @param ifp the network interface for which to create
 * @param addr the new group ipv6
 * @return a struct mld_group*,
 *         NULL on memory error.
 */
static struct mld_group *
mld6_new_group(struct netif *ifp, const ip6_addr_t *addr)
{
  struct mld_group *group;

  group = (struct mld_group *)memp_malloc(MEMP_MLD6_GROUP);
  if (group != NULL) {
    ip6_addr_set(&(group->group_address), addr);
    group->timer              = 0; /* Not running */
    group->group_state        = MLD6_GROUP_IDLE_MEMBER;
    group->last_reporter_flag = 0;
    group->use                = 0;
#if MLD6_V2
    group->sock_mode          = MLD6_FMODE_INCLUDE;
    group->sock_nsrc          = 0;
    group->sock_srcs          = NULL;
    group->rtimer             = 0;
    group->rexmit             = 0;
    group->chg_mode           = 0;
    group->nallow             = 0;
    group->nblock             = 0;
    group->allow              = NULL;
    group->block              = NULL;
    group->qsrc_pending       = 0;
    group->nqsrc              = 0;
    group->qsrc               = NULL;
#endif
    group->next               = netif_mld6_data(ifp);

    netif_set_client_data(ifp, LWIP_NETIF_CLIENT_DATA_INDEX_MLD6, group);
  }

  return group;
}

/**
 * Remove a group from the mld_group_list, but do not free it yet
 *
 * @param group the group to remove
 * @return ERR_OK if group was removed from the list, an err_t otherwise
 */
static err_t
mld6_remove_group(struct netif *netif, struct mld_group *group)
{
  err_t err = ERR_OK;

  /* Is it the first group? */
  if (netif_mld6_data(netif) == group) {
    netif_set_client_data(netif, LWIP_NETIF_CLIENT_DATA_INDEX_MLD6, group->next);
  } else {
    /* look for group further down the list */
    struct mld_group *tmpGroup;
    for (tmpGroup = netif_mld6_data(netif); tmpGroup != NULL; tmpGroup = tmpGroup->next) {
      if (tmpGroup->next == group) {
        tmpGroup->next = group->next;
        break;
      }
    }
    /* Group not find group */
    if (tmpGroup == NULL) {
      err = ERR_ARG;
    }
  }

  return err;
}


/**
 * Process an input MLD message. Called by icmp6_input.
 *
 * @param p the mld packet, p->payload pointing to the icmpv6 header
 * @param inp the netif on which this packet was received
 */
void
mld6_input(struct pbuf *p, struct netif *inp)
{
  struct mld_header *mld_hdr;
  struct mld_group *group;
  u16_t maxresp;

  MLD6_STATS_INC(mld6.recv);

  /* Check that mld header fits in packet. */
  if (p->len < sizeof(struct mld_header)) {
    /* @todo debug message */
    pbuf_free(p);
    MLD6_STATS_INC(mld6.lenerr);
    MLD6_STATS_INC(mld6.drop);
    return;
  }

  mld_hdr = (struct mld_header *)p->payload;

  switch (mld_hdr->type) {
  case ICMP6_TYPE_MLQ: /* Multicast listener query. */
    /* NitroOS: a query comes from a link-local address with hop limit 1 (RFC 2710 3, RFC 3810 5.1.14);
     * any other is ignored, so no sender off the link can have reports sent */
    if (!ip6_addr_islinklocal(ip6_current_src_addr()) || IP6H_HOPLIM(ip6_current_header()) != MLD6_HL) {
      MLD6_STATS_INC(mld6.drop);
      break;
    }
    maxresp = lwip_ntohs(mld_hdr->max_resp_delay);
#if MLD6_V2
    /* NitroOS: the query's version by its length (RFC 3810 8.1): 24 bytes MLDv1, 28 or more MLDv2, others ignored.
     * An MLDv1 query starts (or extends) MLDv1 compatibility for the Older Version Querier Present Timeout
     * (RFC 3810 8.2.1, 9.12), which cancels what MLDv2 had pending; an MLDv2 query is answered with MLDv2 unless
     * MLDv1 compatibility holds, then as an MLDv1 query (its maximum response code decoded) */
    if (p->tot_len >= MLD6_V2_QUERY_HLEN) {
      if (mld6_version(inp) == 2) {
        mld6_v2_query(inp, p, p->tot_len);
        break;
      }
      if (maxresp >= 32768) {
        u32_t decoded = (u32_t)((maxresp & 0x0FFF) | 0x1000) << (((maxresp >> 12) & 7) + 3);
        maxresp = (decoded > 0xFFFF) ? 0xFFFF : (u16_t)decoded;
      }
    } else if (p->tot_len == sizeof(struct mld_header)) {
      struct mld6_ifstate *ifs = MLD6_IFS(inp);

      if (mld6_version(inp) == 2) {
        mld6_v2_cancel(inp);
      }
      ifs->v1 = 1;
      ifs->v1_until = sys_now() + (u32_t)(ifs->qrv ? ifs->qrv : MLD6_DEFAULT_QRV) *
                      (ifs->qi ? ifs->qi : MLD6_DEFAULT_QI) * 1000 + maxresp;
    } else {
      MLD6_STATS_INC(mld6.lenerr);
      MLD6_STATS_INC(mld6.drop);
      break;
    }
#endif /* MLD6_V2 */
    /* Is it a general query? */
    if (ip6_addr_isallnodes_linklocal(ip6_current_dest_addr()) &&
        ip6_addr_isany(&(mld_hdr->multicast_address))) {
      MLD6_STATS_INC(mld6.rx_general);
      /* Report all groups, except all nodes group, and if-local groups. */
      group = netif_mld6_data(inp);
      while (group != NULL) {
        if ((!(ip6_addr_ismulticast_iflocal(&(group->group_address)))) &&
            (!(ip6_addr_isallnodes_linklocal(&(group->group_address))))) {
          mld6_delayed_report(group, maxresp);
        }
        group = group->next;
      }
    } else {
      /* Have we joined this group?
       * We use IP6 destination address to have a memory aligned copy.
       * mld_hdr->multicast_address should be the same. */
      MLD6_STATS_INC(mld6.rx_group);
      group = mld6_lookfor_group(inp, ip6_current_dest_addr());
      if (group != NULL) {
        /* Schedule a report. */
        mld6_delayed_report(group, maxresp);
      }
    }
    break; /* ICMP6_TYPE_MLQ */
  case ICMP6_TYPE_MLR: /* Multicast listener report. */
    /* Have we joined this group?
     * We use IP6 destination address to have a memory aligned copy.
     * mld_hdr->multicast_address should be the same. */
    MLD6_STATS_INC(mld6.rx_report);
    /* NitroOS: another listener's report cancels ours only from the link (link-local source, hop limit 1, as a
     * query), and only in MLDv1: MLDv2 has no report suppression (RFC 3810 7.2.1) */
    if (!ip6_addr_islinklocal(ip6_current_src_addr()) || IP6H_HOPLIM(ip6_current_header()) != MLD6_HL) {
      break;
    }
#if MLD6_V2
    if (mld6_version(inp) == 2) {
      break;
    }
#endif
    group = mld6_lookfor_group(inp, ip6_current_dest_addr());
    if (group != NULL) {
      /* If we are waiting to report, cancel it. */
      if (group->group_state == MLD6_GROUP_DELAYING_MEMBER) {
        group->timer = 0; /* stopped */
        group->group_state = MLD6_GROUP_IDLE_MEMBER;
        group->last_reporter_flag = 0;
      }
    }
    break; /* ICMP6_TYPE_MLR */
  case ICMP6_TYPE_MLD: /* Multicast listener done. */
    /* Do nothing, router will query us. */
    break; /* ICMP6_TYPE_MLD */
  default:
    MLD6_STATS_INC(mld6.proterr);
    MLD6_STATS_INC(mld6.drop);
    break;
  }

  pbuf_free(p);
}

#if MLD6_V2
/* NitroOS: the group of addr on netif, made (or revived from the leaving list) when there is none */
static struct mld_group *
mld6_get_group(struct netif *netif, const ip6_addr_t *addr, u8_t *created)
{
  struct mld_group *group = mld6_lookfor_group(netif, addr);

  *created = 0;
  if (group != NULL) {
    return group;
  }
  group = mld6_revive_group(netif, addr);
  if (group == NULL) {
    group = mld6_new_group(netif, addr);
    if (group == NULL) {
      return NULL;
    }
  }
  *created = 1;
  /* Activate this address on the MAC layer. */
  if (netif->mld_mac_filter != NULL) {
    netif->mld_mac_filter(netif, addr, NETIF_ADD_MAC_FILTER);
  }
  return group;
}

/* NitroOS: the filter of a group changed from (omode, olist): the reports of the MLD version the interface speaks
 * (MLDv1: a report when the group starts to be listened to; MLDv2: a state change report), and the group goes
 * when nothing listens any more (MLDv1: a done message if we reported last; MLDv2: kept on the leaving list while
 * its state change report is retransmitted) */
static void
mld6_after_change(struct netif *netif, struct mld_group *group, u8_t omode, const u8_t (*olist)[16], u16_t on)
{
  u8_t was = mld6_listening(omode, on), is = (u8_t)mld6_group_listening(group);
  u8_t v1 = (mld6_version(netif) == 1);

  if (v1) {
    if (!was && is) {
      MLD6_STATS_INC(mld6.tx_report);
      mld6_send(netif, group, ICMP6_TYPE_MLR);
      mld6_delayed_report(group, MLD6_JOIN_DELAYING_MEMBER_TMR_MS);
    }
  } else {
    mld6_v2_changed(netif, group, omode, olist, on);
  }
  if (is) {
    return;
  }

  mld6_remove_group(netif, group);
  if (v1 && group->last_reporter_flag) {
    MLD6_STATS_INC(mld6.tx_leave);
    mld6_send(netif, group, ICMP6_TYPE_MLD);
  }
  if (netif->mld_mac_filter != NULL) {
    netif->mld_mac_filter(netif, &group->group_address, NETIF_DEL_MAC_FILTER);
  }
  if (!v1 && group->rexmit > 0 && group->rtimer > 0) {
    group->timer = 0;
    group->group_state = MLD6_GROUP_IDLE_MEMBER;
    group->qsrc_pending = 0;
    mld6_list_free(&group->qsrc, &group->nqsrc);
    group->next = MLD6_IFS(netif)->leaving;
    MLD6_IFS(netif)->leaving = group;
  } else {
    mld6_group_free(group);
  }
}

/* NitroOS: one retransmission of a group's pending state change records */
static void
mld6_rexmit(struct mld6_rb *rb, struct mld_group *group)
{
  mld6_rb_pending(rb, group);
  if (group->rexmit) {
    group->rexmit--;
  }
  if (group->rexmit) {
    group->rtimer = mld6_rand_ticks(MLD6_URI_TICKS);
  } else {
    mld6_pending_clear(group);
  }
}

/**
 * NitroOS: set the sockets' filter of a group on a network interface (RFC 3810 4.2: the merge of every socket's
 * filter; INCLUDE with no source = no socket listens). The group's filter is this one unless an any-source join
 * (mld6_joingroup_netif) holds it, which makes it EXCLUDE with no source. A change is reported.
 *
 * @param srcs nsrc source addresses of 16 bytes each (copied)
 * @return ERR_OK, or ERR_MEM
 */
err_t
mld6_set_filter_netif(struct netif *netif, const ip6_addr_t *groupaddr, u8_t mode, const u8_t (*srcs)[16], u16_t nsrc)
{
  struct mld_group *group;
  u8_t created = 0, omode;
  const u8_t (*olist)[16];
  u16_t on;
  u8_t (*copy)[16] = NULL, (*old)[16];
#if LWIP_IPV6_SCOPES
  ip6_addr_t ip6addr;

  if (ip6_addr_lacks_zone(groupaddr, IP6_MULTICAST)) {
    ip6_addr_set(&ip6addr, groupaddr);
    ip6_addr_assign_zone(&ip6addr, IP6_MULTICAST, netif);
    groupaddr = &ip6addr;
  }
  IP6_ADDR_ZONECHECK_NETIF(groupaddr, netif);
#endif /* LWIP_IPV6_SCOPES */

  LWIP_ASSERT_CORE_LOCKED();

  if (!mld6_listening(mode, nsrc)) {
    group = mld6_lookfor_group(netif, groupaddr);
    if (group == NULL) {
      return ERR_OK;
    }
  } else {
    group = mld6_get_group(netif, groupaddr, &created);
    if (group == NULL) {
      return ERR_MEM;
    }
  }
  if (nsrc) {
    copy = (u8_t (*)[16])mem_malloc((mem_size_t)(nsrc * 16));
    if (copy == NULL) {
      if (created) {
        mld6_after_change(netif, group, MLD6_FMODE_INCLUDE, NULL, 0);
      }
      return ERR_MEM;
    }
    MEMCPY(copy, srcs, (size_t)nsrc * 16);
  }
  mld6_filter(group, &omode, &olist, &on);
  old = group->sock_srcs;
  group->sock_srcs = copy;
  group->sock_nsrc = nsrc;
  group->sock_mode = mode;
  mld6_after_change(netif, group, omode, olist, on);
  if (old != NULL) {
    mem_free(old);
  }
  return ERR_OK;
}
#endif /* MLD6_V2 */

/**
 * @ingroup mld6
 * Join a group on one or all network interfaces.
 *
 * If the group is to be joined on all interfaces, the given group address must
 * not have a zone set (i.e., it must have its zone index set to IP6_NO_ZONE).
 * If the group is to be joined on one particular interface, the given group
 * address may or may not have a zone set.
 *
 * @param srcaddr ipv6 address (zoned) of the network interface which should
 *                join a new group. If IP6_ADDR_ANY6, join on all netifs
 * @param groupaddr the ipv6 address of the group to join (possibly but not
 *                  necessarily zoned)
 * @return ERR_OK if group was joined on the netif(s), an err_t otherwise
 */
err_t
mld6_joingroup(const ip6_addr_t *srcaddr, const ip6_addr_t *groupaddr)
{
  err_t         err = ERR_VAL; /* no matching interface */
  struct netif *netif;

  LWIP_ASSERT_CORE_LOCKED();

  /* loop through netif's */
  NETIF_FOREACH(netif) {
    /* Should we join this interface ? */
    if (ip6_addr_isany(srcaddr) ||
        netif_get_ip6_addr_match(netif, srcaddr) >= 0) {
      err = mld6_joingroup_netif(netif, groupaddr);
      if (err != ERR_OK) {
        return err;
      }
    }
  }

  return err;
}

/**
 * @ingroup mld6
 * Join a group on a network interface.
 *
 * @param netif the network interface which should join a new group.
 * @param groupaddr the ipv6 address of the group to join (possibly but not
 *                  necessarily zoned)
 * @return ERR_OK if group was joined on the netif, an err_t otherwise
 */
err_t
mld6_joingroup_netif(struct netif *netif, const ip6_addr_t *groupaddr)
{
  struct mld_group *group;
#if LWIP_IPV6_SCOPES
  ip6_addr_t ip6addr;

  /* If the address has a particular scope but no zone set, use the netif to
   * set one now. Within the mld6 module, all addresses are properly zoned. */
  if (ip6_addr_lacks_zone(groupaddr, IP6_MULTICAST)) {
    ip6_addr_set(&ip6addr, groupaddr);
    ip6_addr_assign_zone(&ip6addr, IP6_MULTICAST, netif);
    groupaddr = &ip6addr;
  }
  IP6_ADDR_ZONECHECK_NETIF(groupaddr, netif);
#endif /* LWIP_IPV6_SCOPES */

  LWIP_ASSERT_CORE_LOCKED();

#if MLD6_V2
  /* NitroOS: an any-source join (EXCLUDE with no source), reported by the version the interface speaks */
  {
    u8_t created, omode;
    const u8_t (*olist)[16];
    u16_t on;

    group = mld6_get_group(netif, groupaddr, &created);
    if (group == NULL) {
      return ERR_MEM;
    }
    mld6_filter(group, &omode, &olist, &on);
    group->use++;
    mld6_after_change(netif, group, omode, olist, on);
    return ERR_OK;
  }
#endif /* MLD6_V2 */

  /* find group or create a new one if not found */
  group = mld6_lookfor_group(netif, groupaddr);

  if (group == NULL) {
    /* Joining a new group. Create a new group entry. */
    group = mld6_new_group(netif, groupaddr);
    if (group == NULL) {
      return ERR_MEM;
    }

    /* Activate this address on the MAC layer. */
    if (netif->mld_mac_filter != NULL) {
      netif->mld_mac_filter(netif, groupaddr, NETIF_ADD_MAC_FILTER);
    }

    /* Report our membership. */
    MLD6_STATS_INC(mld6.tx_report);
    mld6_send(netif, group, ICMP6_TYPE_MLR);
    mld6_delayed_report(group, MLD6_JOIN_DELAYING_MEMBER_TMR_MS);
  }

  /* Increment group use */
  group->use++;
  return ERR_OK;
}

/**
 * @ingroup mld6
 * Leave a group on a network interface.
 *
 * Zoning of address follows the same rules as @ref mld6_joingroup.
 *
 * @param srcaddr ipv6 address (zoned) of the network interface which should
 *                leave the group. If IP6_ADDR_ANY6, leave on all netifs
 * @param groupaddr the ipv6 address of the group to leave (possibly, but not
 *                  necessarily zoned)
 * @return ERR_OK if group was left on the netif(s), an err_t otherwise
 */
err_t
mld6_leavegroup(const ip6_addr_t *srcaddr, const ip6_addr_t *groupaddr)
{
  err_t         err = ERR_VAL; /* no matching interface */
  struct netif *netif;

  LWIP_ASSERT_CORE_LOCKED();

  /* loop through netif's */
  NETIF_FOREACH(netif) {
    /* Should we leave this interface ? */
    if (ip6_addr_isany(srcaddr) ||
        netif_get_ip6_addr_match(netif, srcaddr) >= 0) {
      err_t res = mld6_leavegroup_netif(netif, groupaddr);
      if (err != ERR_OK) {
        /* Store this result if we have not yet gotten a success */
        err = res;
      }
    }
  }

  return err;
}

/**
 * @ingroup mld6
 * Leave a group on a network interface.
 *
 * @param netif the network interface which should leave the group.
 * @param groupaddr the ipv6 address of the group to leave (possibly, but not
 *                  necessarily zoned)
 * @return ERR_OK if group was left on the netif, an err_t otherwise
 */
err_t
mld6_leavegroup_netif(struct netif *netif, const ip6_addr_t *groupaddr)
{
  struct mld_group *group;
#if LWIP_IPV6_SCOPES
  ip6_addr_t ip6addr;

  if (ip6_addr_lacks_zone(groupaddr, IP6_MULTICAST)) {
    ip6_addr_set(&ip6addr, groupaddr);
    ip6_addr_assign_zone(&ip6addr, IP6_MULTICAST, netif);
    groupaddr = &ip6addr;
  }
  IP6_ADDR_ZONECHECK_NETIF(groupaddr, netif);
#endif /* LWIP_IPV6_SCOPES */

  LWIP_ASSERT_CORE_LOCKED();

  /* find group */
  group = mld6_lookfor_group(netif, groupaddr);

#if MLD6_V2
  /* NitroOS: one any-source join less; the group goes when no other join and no socket's filter holds it */
  if (group != NULL && group->use > 0) {
    u8_t omode;
    const u8_t (*olist)[16];
    u16_t on;

    mld6_filter(group, &omode, &olist, &on);
    group->use--;
    mld6_after_change(netif, group, omode, olist, on);
    return ERR_OK;
  }
  return ERR_VAL;
#endif /* MLD6_V2 */

  if (group != NULL) {
    /* Leave if there is no other use of the group */
    if (group->use <= 1) {
      /* Remove the group from the list */
      mld6_remove_group(netif, group);

      /* If we are the last reporter for this group */
      if (group->last_reporter_flag) {
        MLD6_STATS_INC(mld6.tx_leave);
        mld6_send(netif, group, ICMP6_TYPE_MLD);
      }

      /* Disable the group at the MAC level */
      if (netif->mld_mac_filter != NULL) {
        netif->mld_mac_filter(netif, groupaddr, NETIF_DEL_MAC_FILTER);
      }

      /* free group struct */
      memp_free(MEMP_MLD6_GROUP, group);
    } else {
      /* Decrement group use */
      group->use--;
    }

    /* Left group */
    return ERR_OK;
  }

  /* Group not found */
  return ERR_VAL;
}


/**
 * Periodic timer for mld processing. Must be called every
 * MLD6_TMR_INTERVAL milliseconds (100).
 *
 * When a delaying member expires, a membership report is sent.
 */
void
mld6_tmr(void)
{
  mld6_tmr_ticks(1);
}

/* Counts ticks off every running timer; a report is sent for each one that runs out */
static void
mld6_tmr_ticks(u32_t ticks)
{
  struct netif *netif;

  if (ticks == 0) {
    return;
  }

  NETIF_FOREACH(netif) {
    struct mld_group *group = netif_mld6_data(netif);
#if MLD6_V2
    /* NitroOS: MLDv2 records due in this tick go out together, in as few reports as they fit */
    struct mld6_ifstate *ifs = MLD6_IFS(netif);
    struct mld_group **link;
    struct mld6_rb rb;
    u8_t v2 = (mld6_version(netif) == 2);

    mld6_rb_init(&rb, netif);
    if (ifs->gtimer > 0) {
      ifs->gtimer = (ifs->gtimer > ticks) ? (u16_t)(ifs->gtimer - ticks) : 0;
      if (ifs->gtimer == 0 && v2) {
        struct mld_group *g;

        for (g = group; g != NULL; g = g->next) {
          mld6_rb_current(&rb, g);
        }
      }
    }
#endif /* MLD6_V2 */

    while (group != NULL) {
      if (group->timer > 0) {
        group->timer = (group->timer > ticks) ? (u16_t)(group->timer - ticks) : 0;
        if (group->timer == 0) {
          /* If the state is MLD6_GROUP_DELAYING_MEMBER then we send a report for this group */
          if (group->group_state == MLD6_GROUP_DELAYING_MEMBER) {
#if MLD6_V2
            if (v2) {
              /* the answer to a group (and source) specific query */
              if (group->qsrc_pending) {
                mld6_rb_source_answer(&rb, group);
              } else {
                mld6_rb_current(&rb, group);
              }
              group->qsrc_pending = 0;
              mld6_list_free(&group->qsrc, &group->nqsrc);
            } else
#endif /* MLD6_V2 */
            {
              MLD6_STATS_INC(mld6.tx_report);
              mld6_send(netif, group, ICMP6_TYPE_MLR);
            }
            group->group_state = MLD6_GROUP_IDLE_MEMBER;
          }
        }
      }
#if MLD6_V2
      if (group->rtimer > 0) {
        group->rtimer = (group->rtimer > ticks) ? (u16_t)(group->rtimer - ticks) : 0;
        if (group->rtimer == 0) {
          mld6_rexmit(&rb, group);
        }
      }
#endif /* MLD6_V2 */
      group = group->next;
    }

#if MLD6_V2
    /* the groups no longer listened to: their retransmissions, then they go */
    link = &ifs->leaving;
    while ((group = *link) != NULL) {
      if (group->rtimer > 0) {
        group->rtimer = (group->rtimer > ticks) ? (u16_t)(group->rtimer - ticks) : 0;
        if (group->rtimer == 0) {
          mld6_rexmit(&rb, group);
        }
      }
      if (group->rtimer == 0) {
        *link = group->next;
        mld6_group_free(group);
        continue;
      }
      link = &group->next;
    }
    mld6_rb_flush(&rb);
#endif /* MLD6_V2 */
  }
}

/**
 * Schedule a delayed membership report for a group
 *
 * @param group the mld_group for which "delaying" membership report
 *              should be sent
 * @param maxresp_in the max resp delay provided in the query
 */
static void
mld6_delayed_report(struct mld_group *group, u16_t maxresp_in)
{
  /* Convert maxresp from milliseconds to tmr ticks */
  u16_t maxresp = maxresp_in / MLD6_TMR_INTERVAL;

  /* NitroOS: a group that is never reported needs no timer */
  if (!mld6_reportable(&group->group_address)) {
    return;
  }
  if (maxresp == 0) {
    maxresp = 1;
  }

#ifdef MLD6_RAND
  /* Randomize maxresp. (if MLD6_RAND or LWIP_RAND is supported) */
  maxresp = (u16_t)(MLD6_RAND() % maxresp);
  if (maxresp == 0) {
    maxresp = 1;
  }
#endif /* MLD6_RAND */

#if MLD6_TMR_ON_DEMAND
  /* The running timers count from now before this one is compared with them */
  mld6_tmr_settle();
#endif /* MLD6_TMR_ON_DEMAND */

  /* Apply timer value if no report has been scheduled already. */
  if ((group->group_state == MLD6_GROUP_IDLE_MEMBER) ||
     ((group->group_state == MLD6_GROUP_DELAYING_MEMBER) &&
      ((group->timer == 0) || (maxresp < group->timer)))) {
    group->timer = maxresp;
    group->group_state = MLD6_GROUP_DELAYING_MEMBER;
  }

#if MLD6_TMR_ON_DEMAND
  mld6_tmr_arm();
#endif /* MLD6_TMR_ON_DEMAND */
}

/**
 * Send a MLD message (report or done).
 *
 * An IPv6 hop-by-hop options header with a router alert option
 * is prepended.
 *
 * @param group the group to report or quit
 * @param type ICMP6_TYPE_MLR (report) or ICMP6_TYPE_MLD (done)
 */
static void
mld6_send(struct netif *netif, struct mld_group *group, u8_t type)
{
  struct mld_header *mld_hdr;
  struct pbuf *p;
  const ip6_addr_t *src_addr;
  ip6_addr_t dest_addr;

  /* NitroOS: no message for a group that is never reported (mld6_reportable), and none on an interface that
   * does not do MLD (NETIF_FLAG_MLD6 unset: the loopback interface, which still keeps groups to accept them) */
  if (!mld6_reportable(&group->group_address) || !(netif->flags & NETIF_FLAG_MLD6)) {
    return;
  }

  /* NitroOS: a report goes to the group, a done message to the link-scope all-routers group (RFC 2710 3) */
  if (type == ICMP6_TYPE_MLD) {
    ip6_addr_set_allrouters_linklocal(&dest_addr);
    ip6_addr_assign_zone(&dest_addr, IP6_MULTICAST, netif);
  } else {
    ip6_addr_copy(dest_addr, group->group_address);
  }

  /* Allocate a packet. Size is MLD header + IPv6 Hop-by-hop options header. */
  p = pbuf_alloc(PBUF_IP, sizeof(struct mld_header) + MLD6_HBH_HLEN, PBUF_RAM);
  if (p == NULL) {
    MLD6_STATS_INC(mld6.memerr);
    return;
  }

  /* Move to make room for Hop-by-hop options header. */
  if (pbuf_remove_header(p, MLD6_HBH_HLEN)) {
    pbuf_free(p);
    MLD6_STATS_INC(mld6.lenerr);
    return;
  }

  /* Select our source address. */
  if (!ip6_addr_isvalid(netif_ip6_addr_state(netif, 0))) {
    /* This is a special case, when we are performing duplicate address detection.
     * We must join the multicast group, but we don't have a valid address yet. */
    src_addr = IP6_ADDR_ANY6;
  } else {
    /* Use link-local address as source address. */
    src_addr = netif_ip6_addr(netif, 0);
  }

  /* MLD message header pointer. */
  mld_hdr = (struct mld_header *)p->payload;

  /* Set fields. */
  mld_hdr->type = type;
  mld_hdr->code = 0;
  mld_hdr->chksum = 0;
  mld_hdr->max_resp_delay = 0;
  mld_hdr->reserved = 0;
  ip6_addr_copy_to_packed(mld_hdr->multicast_address, group->group_address);

#if CHECKSUM_GEN_ICMP6
  IF__NETIF_CHECKSUM_ENABLED(netif, NETIF_CHECKSUM_GEN_ICMP6) {
    mld_hdr->chksum = ip6_chksum_pseudo(p, IP6_NEXTH_ICMP6, p->len,
      src_addr, &dest_addr);
  }
#endif /* CHECKSUM_GEN_ICMP6 */

  /* Add hop-by-hop headers options: router alert with MLD value. */
  ip6_options_add_hbh_ra(p, IP6_NEXTH_ICMP6, IP6_ROUTER_ALERT_VALUE_MLD);

  if (type == ICMP6_TYPE_MLR) {
    /* Remember we were the last to report */
    group->last_reporter_flag = 1;
  }

  /* Send the packet out. */
  MLD6_STATS_INC(mld6.xmit);
  ip6_output_if(p, (ip6_addr_isany(src_addr)) ? NULL : src_addr, &dest_addr,
      MLD6_HL, 0, IP6_NEXTH_HOPBYHOP, netif);
  pbuf_free(p);
}

#endif /* LWIP_IPV6 */
