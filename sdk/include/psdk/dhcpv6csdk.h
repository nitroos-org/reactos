/*
 * PROJECT:     ReactOS PSDK
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     DHCPv6 client API (dhcpcsvc6.dll), as documented in the Windows SDK reference
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#ifndef _DHCPV6CSDK_
#define _DHCPV6CSDK_

#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

#define DHCPV6CAPI_REQUEST_PERSISTENT   0x01
#define DHCPV6CAPI_REQUEST_SYNCHRONOUS  0x02
#define DHCPV6CAPI_REQUEST_ASYNCHRONOUS 0x04
#define DHCPV6CAPI_REQUEST_CANCEL       0x08
#define DHCPV6CAPI_REQUEST_MASK         0x0F

#define DHCPV6_OPTION_CLIENTID          1
#define DHCPV6_OPTION_SERVERID          2
#define DHCPV6_OPTION_DNS_SERVERS       23
#define DHCPV6_OPTION_DOMAIN_LIST       24
#define DHCPV6_OPTION_SNTP_SERVERS      31
#define DHCPV6_OPTION_INFO_REFRESH_TIME 32

typedef struct _DHCPV6CAPI_CLASSID
{
    ULONG Flags;
    LPBYTE Data;
    ULONG nBytesData;
} DHCPV6CAPI_CLASSID, *PDHCPV6CAPI_CLASSID, *LPDHCPV6CAPI_CLASSID;

typedef struct _DHCPV6CAPI_PARAMS
{
    ULONG Flags;
    ULONG OptionId;
    BOOL IsVendor;
    LPBYTE Data;
    DWORD nBytesData;
} DHCPV6CAPI_PARAMS, *PDHCPV6CAPI_PARAMS, *LPDHCPV6CAPI_PARAMS;

typedef struct _DHCPV6CAPI_PARAMS_ARRAY
{
    ULONG nParams;
    LPDHCPV6CAPI_PARAMS Params;
} DHCPV6CAPI_PARAMS_ARRAY, *PDHCPV6CAPI_PARAMS_ARRAY, *LPDHCPV6CAPI_PARAMS_ARRAY;

typedef struct _DHCPV6Prefix
{
    UCHAR prefix[16];
    DWORD prefixLength;
    DWORD preferredLifeTime;
    DWORD validLifeTime;
    int status;
} DHCPV6Prefix, *PDHCPV6Prefix, *LPDHCPV6Prefix;

typedef struct _DHCPV6PrefixLeaseInfo
{
    DWORD nPrefixes;
    LPDHCPV6Prefix prefixArray;
    DWORD iaid;
    time_t T1;
    time_t T2;
    time_t MaxLeaseExpirationTime;
    time_t LastRenewalTime;
    int status;
    LPBYTE ServerId;
    DWORD ServerIdLen;
} DHCPV6PrefixLeaseInfo, *PDHCPV6PrefixLeaseInfo, *LPDHCPV6PrefixLeaseInfo;

DWORD WINAPI Dhcpv6CApiInitialize(_Out_ LPDWORD Version);
VOID WINAPI Dhcpv6CApiCleanup(VOID);

DWORD WINAPI
Dhcpv6RequestParams(
    _In_ BOOL forceNewInform,
    _In_opt_ LPVOID reserved,
    _In_ LPWSTR adapterName,
    _In_opt_ LPDHCPV6CAPI_CLASSID classId,
    _In_ DHCPV6CAPI_PARAMS_ARRAY recdParams,
    _Inout_updates_bytes_to_(*pSize, *pSize) LPBYTE buffer,
    _Inout_ LPDWORD pSize);

DWORD WINAPI
Dhcpv6RequestPrefix(
    _In_ LPWSTR adapterName,
    _In_opt_ LPDHCPV6CAPI_CLASSID classId,
    _Inout_ LPDHCPV6PrefixLeaseInfo prefixleaseInfo,
    _Out_ DWORD *pdwTimeToWait);

DWORD WINAPI
Dhcpv6RenewPrefix(
    _In_ LPWSTR adapterName,
    _In_opt_ LPDHCPV6CAPI_CLASSID pclassId,
    _Inout_ LPDHCPV6PrefixLeaseInfo prefixleaseInfo,
    _Out_ DWORD *pdwTimeToWait,
    _In_ DWORD bValidatePrefix);

DWORD WINAPI
Dhcpv6ReleasePrefix(
    _In_ LPWSTR adapterName,
    _In_opt_ LPDHCPV6CAPI_CLASSID classId,
    _In_ LPDHCPV6PrefixLeaseInfo leaseInfo);

#ifdef __cplusplus
}
#endif

#endif /* _DHCPV6CSDK_ */
