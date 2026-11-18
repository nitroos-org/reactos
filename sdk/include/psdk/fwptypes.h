/*
 * PROJECT:     NitroOS
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Windows Filtering Platform: basic data types (written from the public documentation of fwptypes.h)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#ifndef _FWPTYPES_H
#define _FWPTYPES_H

#ifdef __cplusplus
extern "C" {
#endif

#define FWP_BYTE_ARRAY6_SIZE 6
#define FWP_BYTE_ARRAY16_SIZE 16

typedef struct FWP_BYTE_ARRAY6_
{
    UINT8 byteArray6[FWP_BYTE_ARRAY6_SIZE];
} FWP_BYTE_ARRAY6;

typedef struct FWP_BYTE_ARRAY16_
{
    UINT8 byteArray16[FWP_BYTE_ARRAY16_SIZE];
} FWP_BYTE_ARRAY16;

typedef struct FWP_BYTE_BLOB_
{
    UINT32 size;
    UINT8 *data;
} FWP_BYTE_BLOB;

typedef struct FWP_TOKEN_INFORMATION_ FWP_TOKEN_INFORMATION;

typedef enum FWP_DATA_TYPE_
{
    FWP_EMPTY = 0,
    FWP_UINT8 = 1,
    FWP_UINT16 = 2,
    FWP_UINT32 = 3,
    FWP_UINT64 = 4,
    FWP_INT8 = 5,
    FWP_INT16 = 6,
    FWP_INT32 = 7,
    FWP_INT64 = 8,
    FWP_FLOAT = 9,
    FWP_DOUBLE = 10,
    FWP_BYTE_ARRAY16_TYPE = 11,
    FWP_BYTE_BLOB_TYPE = 12,
    FWP_SID = 13,
    FWP_SECURITY_DESCRIPTOR_TYPE = 14,
    FWP_TOKEN_INFORMATION_TYPE = 15,
    FWP_TOKEN_ACCESS_INFORMATION_TYPE = 16,
    FWP_UNICODE_STRING_TYPE = 17,
    FWP_BYTE_ARRAY6_TYPE = 18,
    FWP_SINGLE_DATA_TYPE_MAX = 0xff,
    FWP_V4_ADDR_MASK = 0x100,
    FWP_V6_ADDR_MASK = 0x101,
    FWP_RANGE_TYPE = 0x102,
    FWP_DATA_TYPE_MAX = 0x103
} FWP_DATA_TYPE;

typedef struct FWP_VALUE0_
{
    FWP_DATA_TYPE type;
    union
    {
        UINT8 uint8;
        UINT16 uint16;
        UINT32 uint32;
        UINT64 *uint64;
        INT8 int8;
        INT16 int16;
        INT32 int32;
        INT64 *int64;
        float float32;
        double *double64;
        FWP_BYTE_ARRAY16 *byteArray16;
        FWP_BYTE_BLOB *byteBlob;
        SID *sid;
        FWP_BYTE_BLOB *sd;
        FWP_TOKEN_INFORMATION *tokenInformation;
        FWP_BYTE_BLOB *tokenAccessInformation;
        LPWSTR unicodeString;
        FWP_BYTE_ARRAY6 *byteArray6;
    };
} FWP_VALUE0;

typedef enum FWP_MATCH_TYPE_
{
    FWP_MATCH_EQUAL = 0,
    FWP_MATCH_GREATER = 1,
    FWP_MATCH_LESS = 2,
    FWP_MATCH_GREATER_OR_EQUAL = 3,
    FWP_MATCH_LESS_OR_EQUAL = 4,
    FWP_MATCH_RANGE = 5,
    FWP_MATCH_FLAGS_ALL_SET = 6,
    FWP_MATCH_FLAGS_ANY_SET = 7,
    FWP_MATCH_FLAGS_NONE_SET = 8,
    FWP_MATCH_EQUAL_CASE_INSENSITIVE = 9,
    FWP_MATCH_NOT_EQUAL = 10,
    FWP_MATCH_TYPE_MAX = 11
} FWP_MATCH_TYPE;

typedef struct FWP_V4_ADDR_AND_MASK_
{
    UINT32 addr;
    UINT32 mask;
} FWP_V4_ADDR_AND_MASK;

typedef struct FWP_V6_ADDR_AND_MASK_
{
    UINT8 addr[16];
    UINT8 prefixLength;
} FWP_V6_ADDR_AND_MASK;

typedef struct FWP_RANGE0_
{
    FWP_VALUE0 valueLow;
    FWP_VALUE0 valueHigh;
} FWP_RANGE0;

typedef struct FWP_CONDITION_VALUE0_
{
    FWP_DATA_TYPE type;
    union
    {
        UINT8 uint8;
        UINT16 uint16;
        UINT32 uint32;
        UINT64 *uint64;
        INT8 int8;
        INT16 int16;
        INT32 int32;
        INT64 *int64;
        float float32;
        double *double64;
        FWP_BYTE_ARRAY16 *byteArray16;
        FWP_BYTE_BLOB *byteBlob;
        SID *sid;
        FWP_BYTE_BLOB *sd;
        FWP_TOKEN_INFORMATION *tokenInformation;
        FWP_BYTE_BLOB *tokenAccessInformation;
        LPWSTR unicodeString;
        FWP_BYTE_ARRAY6 *byteArray6;
        FWP_V4_ADDR_AND_MASK *v4AddrMask;
        FWP_V6_ADDR_AND_MASK *v6AddrMask;
        FWP_RANGE0 *rangeValue;
    };
} FWP_CONDITION_VALUE0;

typedef enum FWP_IP_VERSION_
{
    FWP_IP_VERSION_V4 = 0,
    FWP_IP_VERSION_V6 = 1,
    FWP_IP_VERSION_NONE = 2,
    FWP_IP_VERSION_MAX = 3
} FWP_IP_VERSION;

typedef enum FWP_DIRECTION_
{
    FWP_DIRECTION_OUTBOUND = 0,
    FWP_DIRECTION_INBOUND = 1,
    FWP_DIRECTION_MAX = 2
} FWP_DIRECTION;

typedef enum FWP_FILTER_ENUM_TYPE_
{
    FWP_FILTER_ENUM_FULLY_CONTAINED = 0,
    FWP_FILTER_ENUM_OVERLAPPING = 1,
    FWP_FILTER_ENUM_TYPE_MAX = 2
} FWP_FILTER_ENUM_TYPE;

#define FWP_FILTER_ENUM_FLAG_BEST_TERMINATING_MATCH 0x00000001
#define FWP_FILTER_ENUM_FLAG_SORTED 0x00000002
#define FWP_FILTER_ENUM_FLAG_BOOTTIME_ONLY 0x00000004
#define FWP_FILTER_ENUM_FLAG_INCLUDE_BOOTTIME 0x00000008
#define FWP_FILTER_ENUM_FLAG_INCLUDE_DISABLED 0x00000010

#define FWP_ACTION_FLAG_TERMINATING 0x00001000
#define FWP_ACTION_FLAG_NON_TERMINATING 0x00002000
#define FWP_ACTION_FLAG_CALLOUT 0x00004000

#define FWP_ACTION_BLOCK (0x00000001 | FWP_ACTION_FLAG_TERMINATING)
#define FWP_ACTION_PERMIT (0x00000002 | FWP_ACTION_FLAG_TERMINATING)
#define FWP_ACTION_CALLOUT_TERMINATING (0x00000003 | FWP_ACTION_FLAG_CALLOUT | FWP_ACTION_FLAG_TERMINATING)
#define FWP_ACTION_CALLOUT_INSPECTION (0x00000004 | FWP_ACTION_FLAG_CALLOUT | FWP_ACTION_FLAG_NON_TERMINATING)
#define FWP_ACTION_CALLOUT_UNKNOWN (0x00000005 | FWP_ACTION_FLAG_CALLOUT)

#ifdef __cplusplus
}
#endif

#endif /* _FWPTYPES_H */
