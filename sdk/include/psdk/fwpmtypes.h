/*
 * PROJECT:     NitroOS
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Windows Filtering Platform: management data types (written from the public documentation of fwpmtypes.h)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Only the types of the management functions that fwpuclnt.dll exports and that are in common use are here.
 * The provider context, layer, net event and IPsec types are declared opaque.
 */

#ifndef _FWPMTYPES_H
#define _FWPMTYPES_H

#include <fwptypes.h>

#ifdef __cplusplus
extern "C" {
#endif

#define FWPM_SESSION_FLAG_DYNAMIC 0x00000001
#define FWPM_TXN_READ_ONLY 0x00000001

#define FWPM_PROVIDER_FLAG_PERSISTENT 0x00000001
#define FWPM_PROVIDER_FLAG_DISABLED 0x00000010

#define FWPM_SUBLAYER_FLAG_PERSISTENT 0x00000001

#define FWPM_FILTER_FLAG_NONE 0x00000000
#define FWPM_FILTER_FLAG_PERSISTENT 0x00000001
#define FWPM_FILTER_FLAG_BOOTTIME 0x00000002
#define FWPM_FILTER_FLAG_HAS_PROVIDER_CONTEXT 0x00000004
#define FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT 0x00000008
#define FWPM_FILTER_FLAG_PERMIT_IF_CALLOUT_UNREGISTERED 0x00000010
#define FWPM_FILTER_FLAG_DISABLED 0x00000020

#define FWPM_CALLOUT_FLAG_PERSISTENT 0x00000001
#define FWPM_CALLOUT_FLAG_USES_PROVIDER_CONTEXT 0x00000002
#define FWPM_CALLOUT_FLAG_REGISTERED 0x00000004

#define FWPM_ACTRL_ADD 0x00000001
#define FWPM_ACTRL_ADD_LINK 0x00000002
#define FWPM_ACTRL_BEGIN_READ_TXN 0x00000004
#define FWPM_ACTRL_BEGIN_WRITE_TXN 0x00000008
#define FWPM_ACTRL_CLASSIFY 0x00000010
#define FWPM_ACTRL_ENUM 0x00000020
#define FWPM_ACTRL_OPEN 0x00000040
#define FWPM_ACTRL_READ 0x00000080
#define FWPM_ACTRL_READ_STATS 0x00000100
#define FWPM_ACTRL_SUBSCRIBE 0x00000200
#define FWPM_ACTRL_WRITE 0x00000400

typedef struct FWPM_DISPLAY_DATA0_
{
    wchar_t *name;
    wchar_t *description;
} FWPM_DISPLAY_DATA0;

typedef struct FWPM_SESSION0_
{
    GUID sessionKey;
    FWPM_DISPLAY_DATA0 displayData;
    UINT32 flags;
    UINT32 txnWaitTimeoutInMSec;
    DWORD processId;
    SID *sid;
    wchar_t *username;
    BOOL kernelMode;
} FWPM_SESSION0;

typedef struct FWPM_PROVIDER0_
{
    GUID providerKey;
    FWPM_DISPLAY_DATA0 displayData;
    UINT32 flags;
    FWP_BYTE_BLOB providerData;
    wchar_t *serviceName;
} FWPM_PROVIDER0;

typedef struct FWPM_SUBLAYER0_
{
    GUID subLayerKey;
    FWPM_DISPLAY_DATA0 displayData;
    UINT16 flags;
    GUID *providerKey;
    FWP_BYTE_BLOB providerData;
    UINT16 weight;
} FWPM_SUBLAYER0;

typedef struct FWPM_FILTER_CONDITION0_
{
    GUID fieldKey;
    FWP_MATCH_TYPE matchType;
    FWP_CONDITION_VALUE0 conditionValue;
} FWPM_FILTER_CONDITION0;

typedef struct FWPM_ACTION0_
{
    UINT32 type;
    union
    {
        GUID filterType;
        GUID calloutKey;
    };
} FWPM_ACTION0;

typedef struct FWPM_FILTER0_
{
    GUID filterKey;
    FWPM_DISPLAY_DATA0 displayData;
    UINT32 flags;
    GUID *providerKey;
    FWP_BYTE_BLOB providerData;
    GUID layerKey;
    GUID subLayerKey;
    FWP_VALUE0 weight;
    UINT32 numFilterConditions;
    FWPM_FILTER_CONDITION0 *filterCondition;
    FWPM_ACTION0 action;
    union
    {
        UINT64 rawContext;
        GUID providerContextKey;
    };
    GUID *reserved;
    UINT64 filterId;
    FWP_VALUE0 effectiveWeight;
} FWPM_FILTER0;

typedef struct FWPM_CALLOUT0_
{
    GUID calloutKey;
    FWPM_DISPLAY_DATA0 displayData;
    UINT32 flags;
    GUID *providerKey;
    FWP_BYTE_BLOB providerData;
    GUID applicableLayer;
    UINT32 calloutId;
} FWPM_CALLOUT0;

typedef struct FWPM_PROVIDER_ENUM_TEMPLATE0_
{
    UINT64 reserved;
} FWPM_PROVIDER_ENUM_TEMPLATE0;

typedef struct FWPM_SUBLAYER_ENUM_TEMPLATE0_
{
    GUID *providerKey;
} FWPM_SUBLAYER_ENUM_TEMPLATE0;

typedef struct FWPM_FILTER_ENUM_TEMPLATE0_
{
    GUID *providerKey;
    GUID layerKey;
    FWP_FILTER_ENUM_TYPE enumType;
    UINT32 flags;
    FWPM_FILTER_CONDITION0 *providerContextTemplate;
    UINT32 numFilterConditions;
    FWPM_FILTER_CONDITION0 *filterCondition;
    UINT32 actionMask;
    GUID *calloutKey;
} FWPM_FILTER_ENUM_TEMPLATE0;

typedef struct FWPM_CALLOUT_ENUM_TEMPLATE0_
{
    GUID *providerKey;
    GUID layerKey;
} FWPM_CALLOUT_ENUM_TEMPLATE0;

typedef struct FWPM_PROVIDER_CONTEXT0_ FWPM_PROVIDER_CONTEXT0;
typedef struct FWPM_PROVIDER_CONTEXT_ENUM_TEMPLATE0_ FWPM_PROVIDER_CONTEXT_ENUM_TEMPLATE0;
typedef struct FWPM_LAYER0_ FWPM_LAYER0;
typedef struct FWPM_LAYER_ENUM_TEMPLATE0_ FWPM_LAYER_ENUM_TEMPLATE0;
typedef struct FWPM_SESSION_ENUM_TEMPLATE0_ FWPM_SESSION_ENUM_TEMPLATE0;

typedef enum FWPM_ENGINE_OPTION_
{
    FWPM_ENGINE_COLLECT_NET_EVENTS = 0,
    FWPM_ENGINE_NET_EVENT_MATCH_ANY_KEYWORDS = 1,
    FWPM_ENGINE_NAME_CACHE = 2,
    FWPM_ENGINE_MONITOR_IPSEC_CONNECTIONS = 3,
    FWPM_ENGINE_PACKET_QUEUING = 4,
    FWPM_ENGINE_TXN_WATCHDOG_TIMEOUT_IN_MSEC = 5,
    FWPM_ENGINE_OPTION_MAX = 6
} FWPM_ENGINE_OPTION;

#ifdef __cplusplus
}
#endif

#endif /* _FWPMTYPES_H */
