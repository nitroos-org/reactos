/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Tests for EnumerateTraceGuidsEx
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Parameter rows measured on Windows Server 2022. The provider list of a system is not compared.
 */

#include "precomp.h"
#include <wmistr.h>
#include <evntrace.h>

typedef ULONG (WINAPI *PFN_EnumerateTraceGuidsEx)(int, PVOID, ULONG, PVOID, ULONG, PULONG);

START_TEST(EnumerateTraceGuidsEx)
{
    PFN_EnumerateTraceGuidsEx pEnum =
        (PFN_EnumerateTraceGuidsEx)GetProcAddress(LoadLibraryW(L"advapi32.dll"), "EnumerateTraceGuidsEx");
    static const GUID Unknown = { 0xaabbccdd, 0x1111, 0x2222, { 9, 9, 9, 9, 9, 9, 9, 9 } };
    BYTE Buffer[4096];
    ULONG Err, Ret, Class;

    ok(pEnum != NULL, "EnumerateTraceGuidsEx is not exported\n");
    if (!pEnum)
    {
        skip("EnumerateTraceGuidsEx is missing\n");
        return;
    }

    /* classes beyond TraceGuidQueryProcess */
    for (Class = 3; Class <= 5; Class++)
    {
        Ret = 0xabcdef01;
        Err = pEnum(Class, (PVOID)&Unknown, sizeof(Unknown), Buffer, sizeof(Buffer), &Ret);
        ok_dec(Err, ERROR_INVALID_PARAMETER);
        ok_hex(Ret, 0xabcdef01);
    }
    Err = pEnum(7, (PVOID)&Unknown, sizeof(Unknown), Buffer, sizeof(Buffer), &Ret);
    ok_dec(Err, ERROR_INVALID_PARAMETER);
    Err = pEnum(-1, (PVOID)&Unknown, sizeof(Unknown), Buffer, sizeof(Buffer), &Ret);
    ok_dec(Err, ERROR_INVALID_PARAMETER);

    /* ReturnLength is required */
    for (Class = TraceGuidQueryList; Class <= TraceGuidQueryProcess; Class++)
    {
        Err = pEnum(Class, (PVOID)&Unknown, sizeof(Unknown), Buffer, sizeof(Buffer), NULL);
        ok_dec(Err, ERROR_INVALID_PARAMETER);
    }

    /* the information of one provider needs a GUID */
    Ret = 0xabcdef01;
    Err = pEnum(TraceGuidQueryInfo, NULL, 0, Buffer, sizeof(Buffer), &Ret);
    ok_dec(Err, ERROR_INVALID_PARAMETER);
    ok_hex(Ret, 0xabcdef01);
    Err = pEnum(TraceGuidQueryInfo, (PVOID)&Unknown, 4, Buffer, sizeof(Buffer), &Ret);
    ok_dec(Err, ERROR_INVALID_PARAMETER);
    ok_hex(Ret, 0xabcdef01);

    /* a provider nobody registered */
    memset(Buffer, 0xcc, sizeof(Buffer));
    Ret = 0xabcdef01;
    Err = pEnum(TraceGuidQueryInfo, (PVOID)&Unknown, sizeof(Unknown), Buffer, sizeof(Buffer), &Ret);
    ok_dec(Err, ERROR_WMI_GUID_NOT_FOUND);
    ok_dec(Ret, 0);
    ok_hex(Buffer[0], 0xcc);
    Ret = 0xabcdef01;
    Err = pEnum(TraceGuidQueryInfo, (PVOID)&Unknown, sizeof(Unknown), NULL, 0, &Ret);
    ok_dec(Err, ERROR_WMI_GUID_NOT_FOUND);
    ok_dec(Ret, 0);

    /* the lists: whatever the system registered, the size query and the data query agree */
    for (Class = TraceGuidQueryList; Class <= TraceGuidQueryProcess; Class += 2)
    {
        Ret = 0xabcdef01;
        Err = pEnum(Class, NULL, 0, NULL, 0, &Ret);
        ok(Err == ERROR_SUCCESS || Err == ERROR_INSUFFICIENT_BUFFER, "class %lu: %lu\n", Class, Err);
        if (Err == ERROR_SUCCESS)
        {
            ok_dec(Ret, 0);
        }
        else
        {
            ok(Ret != 0 && Ret != 0xabcdef01, "class %lu: ReturnLength %lu\n", Class, Ret);
            if (Ret > sizeof(Buffer))
                continue;
            Err = pEnum(Class, NULL, 0, Buffer, Ret, &Ret);
            ok_dec(Err, ERROR_SUCCESS);
        }
    }
}
