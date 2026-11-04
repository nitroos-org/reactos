/*
 * PROJECT:     NitroOS
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     rosdev
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

/*
 * PROJECT:     ReactOS test infrastructure
 * PURPOSE:     rosdev, the test-only guest agent: shared declarations
 *
 * TEST VMS ONLY. This program runs commands and moves files on behalf of whoever answers on
 * 10.0.2.2. It must never be installed on a release, bootcd or livecd image, and it refuses to
 * run unless started with /testvm and the registry marker HKLM\SOFTWARE\ReactOS\ReactOS\RosDevTestVm.
 * It only ever connects out, only to the QEMU user-network host address, and never listens.
 */
#ifndef ROSDEV_H
#define ROSDEV_H

#define WIN32_NO_STATUS
#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ROSDEV_VERSION      "1"
#define ROSDEV_HOST_ADDR    "10.0.2.2"      /* the only address this agent talks to */
#define ROSDEV_NET_PREFIX   0x0A000200UL    /* 10.0.2.0/24: our own address must be inside it */
#define ROSDEV_DEFAULT_PORT 17600
/* an existing, otherwise empty key: ReactOS hives have no security descriptors, so offline tools cannot add keys */
#define ROSDEV_KEY          L"SOFTWARE\\ReactOS\\ReactOS"
#define ROSDEV_MARKER       L"disposable-test-vm"

#define MAX_HDR     16384
#define MAX_KV      32
#define POLL_WAIT   45000   /* ms to wait for the host's NOP or JOB */
#define IO_WAIT     30000   /* ms of silence in the middle of a transfer */

/* ---- sha256.c ---- */
typedef struct { UINT32 h[8]; UINT64 bits; BYTE buf[64]; UINT used; } SHA256_STATE;
void Sha256Init(SHA256_STATE *s);
void Sha256Update(SHA256_STATE *s, const void *p, SIZE_T n);
void Sha256Final(SHA256_STATE *s, BYTE out[32]);
void HmacSha256(const BYTE *key, SIZE_T klen, const BYTE *msg, SIZE_T mlen, BYTE out[32]);
void HexEncode(const BYTE *p, SIZE_T n, char *out);
int  HexDecode(const char *in, BYTE *out, SIZE_T max);

/* ---- proto.c ---- */
typedef struct { SOCKET s; BYTE buf[16384]; int pos, len; BOOL dead; } CONN;
typedef struct { char *key; char *val; } KV;
typedef struct { char verb[24]; KV kv[MAX_KV]; int n; char raw[MAX_HDR]; } RMSG;
typedef struct { char buf[MAX_HDR]; int len; BOOL over; } REPLY;

BOOL  ConnRead(CONN *c, void *dst, int n, DWORD waitMs);          /* exactly n bytes */
BOOL  ConnReadSome(CONN *c, void *dst, int max, int *got, DWORD waitMs);
BOOL  ConnWrite(CONN *c, const void *p, int n);
BOOL  RecvMsg(CONN *c, RMSG *m, DWORD waitMs);
const char *MsgGet(const RMSG *m, const char *key);
UINT64 MsgGetU64(const RMSG *m, const char *key, UINT64 def);
BOOL  MsgGetU64Ex(const RMSG *m, const char *key, UINT64 *out);
void  ReplyInit(REPLY *r, const char *verb);
void  ReplyStr(REPLY *r, const char *key, const char *val);
void  ReplyU64(REPLY *r, const char *key, UINT64 v);
void  ReplyWide(REPLY *r, const char *key, const WCHAR *w);
BOOL  ReplySend(CONN *c, REPLY *r);
char *WideToUtf8(const WCHAR *w);                                  /* HeapAlloc'ed */
WCHAR *Utf8ToWide(const char *s);                                  /* HeapAlloc'ed */

/* ---- jobs.c ---- */
extern BOOL g_Quit;
extern WCHAR g_Args[512];                       /* the command line this agent was started with */
extern BOOL g_PowerPending;                     /* shutdown under way: stop polling */
BOOL RunJob(CONN *c, RMSG *job);                 /* FALSE: drop the connection */
void LocalInfo(char *out, int cap);
void LogLine(const char *fmt, ...);

#endif
