/*
 * PROJECT:     NitroOS basic firewall
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Firewall rule store in Windows' own registry format (shared by mpssvc, hnetcfg, netsh helper)
 */
#pragma once

#include <windef.h>
#include <winbase.h>
#include <winreg.h>

#define FW_KEY_POLICY      L"SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy"
#define FW_KEY_RULES       FW_KEY_POLICY L"\\FirewallRules"
#define FW_KEY_DOMAIN      FW_KEY_POLICY L"\\DomainProfile"
#define FW_KEY_STANDARD    FW_KEY_POLICY L"\\StandardProfile"
#define FW_KEY_PUBLIC      FW_KEY_POLICY L"\\PublicProfile"
#define FW_RULE_VERSION    L"v2.30"

/* NET_FW_PROFILE2_* bits */
#define FWP_DOMAIN   1
#define FWP_PRIVATE  2
#define FWP_PUBLIC   4
#define FWP_ALL      7
#define FWP_ANY_COM  0x7FFFFFFF

/* ---- token model: a rule is "vX.YY|Key=Value|Key=Value|...|" ---- */

typedef struct _FWR_TOKEN { PWSTR Key; PWSTR Val; } FWR_TOKEN;

typedef struct _FWR
{
    PWSTR Id;           /* registry value name, e.g. {GUID} */
    WCHAR Ver[16];      /* "v2.30" */
    FWR_TOKEN *T;
    ULONG N, Cap;
} FWR;

VOID  FwrInit(FWR *r);
VOID  FwrFree(FWR *r);
BOOL  FwrParse(FWR *r, PCWSTR Id, PCWSTR Data);            /* FALSE: not a v2.x rule / oom */
PWSTR FwrFormat(const FWR *r);                              /* HeapAlloc'ed, caller frees with FwFree */
BOOL  FwrClone(FWR *dst, const FWR *src);
PCWSTR FwrGet(const FWR *r, PCWSTR Key, ULONG Index);      /* NULL if absent */
ULONG FwrCount(const FWR *r, PCWSTR Key);
BOOL  FwrAdd(FWR *r, PCWSTR Key, PCWSTR Val);              /* append */
BOOL  FwrSet(FWR *r, PCWSTR Key, PCWSTR Val);              /* replace all occurrences by one (Val NULL: remove) */
VOID  FwrRemove(FWR *r, PCWSTR Key);
VOID  FwrNormalize(FWR *r);                                 /* canonical token order */
VOID  FwFree(PVOID p);

/* ---- typed view of a rule, in the form INetFwRule and netsh use ---- */

typedef struct _FW_RULE
{
    PWSTR Id;
    PWSTR Name, Desc, App, Svc, Group;
    LONG  Action;           /* NET_FW_ACTION: 0 block, 1 allow */
    BOOL  Enabled;
    LONG  Dir;              /* NET_FW_RULE_DIRECTION: 1 in, 2 out */
    LONG  Protocol;         /* 0..255, 256 = any */
    LONG  Profiles;         /* NET_FW_PROFILE2 mask, FWP_ANY_COM = all */
    PWSTR LPorts, RPorts;   /* "80,443,5000-5010" or "*" */
    PWSTR LAddr, RAddr;     /* "10.0.0.1,LocalSubnet" or "*" */
    PWSTR Icmp;             /* "8:*,3:4" or "*" */
    PWSTR IfTypes;          /* "All" or "Lan,Wireless,RemoteAccess" */
    BOOL  Edge;
    FWR   Raw;              /* the stored tokens; tokens not covered above survive a round trip here */
} FW_RULE;

VOID FwRuleInit(FW_RULE *r);
VOID FwRuleFree(FW_RULE *r);
BOOL FwRuleFromRaw(FW_RULE *r, const FWR *raw);          /* takes a copy */
BOOL FwRuleToRaw(const FW_RULE *r, FWR *raw);            /* typed fields override Raw */
BOOL FwRuleCopy(FW_RULE *dst, const FW_RULE *src);
BOOL FwRuleSetStr(PWSTR *field, PCWSTR v);               /* NULL or empty clears */

/* validity checks used by COM and netsh; return a Win32 error (0 = ok) */
DWORD FwCheckPorts(PCWSTR s);
DWORD FwCheckAddrs(PCWSTR s);

/* ---- store ---- */

typedef struct _FW_RULESET { FW_RULE *R; ULONG N; } FW_RULESET;

DWORD FwStoreLoad(FW_RULESET *rs);                       /* ERROR_SUCCESS also when the key is absent */
VOID  FwRuleSetFree(FW_RULESET *rs);
DWORD FwStoreAdd(FW_RULE *r);                            /* allocates r->Id when NULL, writes the value */
DWORD FwStoreUpdate(const FW_RULE *r);                   /* rewrites value r->Id */
DWORD FwStoreDelete(PCWSTR Id);
DWORD FwStoreDeleteAll(VOID);
DWORD FwNewId(PWSTR *pId);

/* ---- profiles ---- */

typedef struct _FW_PROFILE
{
    DWORD Enable;               /* EnableFirewall */
    DWORD DoNotAllowExceptions;
    DWORD DisableNotifications;
    DWORD DefaultInbound;       /* 1 = block, 0 = allow (stored form) */
    DWORD DefaultOutbound;
    DWORD DisableUnicastResponses;
    DWORD LogFileSize;          /* KB */
    DWORD LogDropped;
    DWORD LogSuccess;
    WCHAR LogFile[260];
} FW_PROFILE;

DWORD FwProfileLoad(ULONG ProfileBit, FW_PROFILE *p);   /* missing values give Windows' defaults */
DWORD FwProfileSetDword(ULONG ProfileBit, PCWSTR Name, DWORD Value, BOOL Logging);
DWORD FwProfileSetString(ULONG ProfileBit, PCWSTR Name, PCWSTR Value, BOOL Logging);
DWORD FwProfileReset(ULONG ProfileBit);                  /* write the default values */
DWORD FwResetAll(VOID);                                  /* default profiles and the NitroOS default rules */
ULONG FwCurrentProfiles(VOID);                           /* profile bit(s) in force */
PCWSTR FwProfileKey(ULONG ProfileBit);

/* ---- change notification and kernel push (mpssvc) ---- */

DWORD FwWatchOpen(HKEY *phKey);                          /* handle for RegNotifyChangeKeyValue on the policy subtree */
DWORD FwPushToKernel(ULONGLONG Generation, BOOL *pDevicePresent);
