/*
 * PROJECT:     ReactOS test suite
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Control commands of the Storport test miniport, shared with its test program
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#pragma once

/* CDB: byte 0 = 0xC0, byte 1 = one of these, bytes 2..5 = big endian argument, byte 6/7 = see storest.c.
 * The data buffer (STOREST_CONTROL) is read by the miniport for STOREST_REGISTRY and filled for all. */
#define STOREST_SET_DELAY   1   /* arg = milliseconds a read stays outstanding */
#define STOREST_ARM_BUSY    2   /* arg = RequestsToComplete the next read passes to StorPortBusy */
#define STOREST_GET_LOG     3   /* Value[0] = reads started, then 64-bit start ticks of the first 4 */
#define STOREST_PAUSE       4   /* arg = StorPortPause seconds, byte 6 = resume after n * 100 ms */
#define STOREST_REGISTRY    5   /* what the registry reads of HwFindAdapter returned: Status[i], Value[i] length, Value[8] and [9] the DWORDs, Text the string */
#define STOREST_SYNC        6
#define STOREST_PERF        7
#define STOREST_MISC        8
#define STOREST_STATE       9
#define STOREST_STATE_DONE  10

typedef struct _STOREST_CONTROL
{
    ULONG Status[8];
    ULONG Value[16];
    CHAR Text[64];
} STOREST_CONTROL, *PSTOREST_CONTROL;

typedef struct _STOREST_LOG_ENTRY
{
    LARGE_INTEGER Ticks;
} STOREST_LOG_ENTRY;
