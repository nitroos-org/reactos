/*
 * PROJECT:     ReactOS API Tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Tests for GetPhysicallyInstalledSystemMemory
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"

/*
 * Documented: the value comes from the SMBIOS firmware tables, it is at least
 * the memory GlobalMemoryStatusEx reports, a NULL pointer fails with
 * ERROR_INVALID_PARAMETER and a failure leaves the output untouched.
 * Measured on Windows Server 2022 (QEMU guests): the value equals the sum of the
 * SMBIOS Memory Device (type 17) sizes (4096 MB in one device: 4194304 KB;
 * 16 GB + 4 GB in two: 20971520 KB). The test sums them itself from the raw
 * 'RSMB' table and compares. Without an SMBIOS table (the same guest with only
 * a 64-bit SMBIOS entry point, which that system does not use) both
 * GetSystemFirmwareTable('RSMB') and this function fail with
 * ERROR_INVALID_FUNCTION.
 * Also measured there, with one 4096 MB device plus a second one: a Memory Device
 * with Size 0xFFFF (unknown), or with a formatted area shorter than 0x15 bytes,
 * fails the call with ERROR_INVALID_DATA; Size 0 is skipped; Size with bit 15
 * counts KB; Size 0x7FFF with an extended size counts that many MB (bit 31
 * ignored), and with an extended size of 0 counts 32767 MB. The table of the
 * running system decides which of these the test can exercise.
 */

static BOOL (WINAPI *pGetPhysicallyInstalledSystemMemory)(PULONGLONG);

#define RSMB 0x52534D42

/* Own walk of the raw SMBIOS table (DMTF DSP0134): sum of the type 17 sizes in KB */
static BOOL
SumMemoryDevices(const UCHAR *Table, ULONG Length, ULONGLONG *TotalKb, ULONG *Devices, BOOL *Refused)
{
    ULONG Offset = 0, Next;
    ULONGLONG Total = 0;

    *Devices = 0;
    *Refused = FALSE;
    while (Offset + 4 <= Length)
    {
        UCHAR Type = Table[Offset], Len = Table[Offset + 1];

        if (Len < 4 || Offset + Len > Length)
            return FALSE;
        if (Type == 17 && Len >= 0x0E)
        {
            USHORT Size = *(const USHORT UNALIGNED *)&Table[Offset + 0x0C];

            (*Devices)++;
            if (Len < 0x15 || Size == 0xFFFF)
                *Refused = TRUE;
            else if (Size == 0x7FFF && Len >= 0x20)
            {
                ULONG Extended = *(const ULONG UNALIGNED *)&Table[Offset + 0x1C];

                Total += (ULONGLONG)(Extended ? (Extended & 0x7FFFFFFF) : 0x7FFF) * 1024;
            }
            else if (Size != 0)
                Total += (Size & 0x8000) ? (Size & 0x7FFF) : (ULONGLONG)Size * 1024;
        }
        if (Type == 127)
            break;
        Next = Offset + Len;
        while (Next + 1 < Length && (Table[Next] || Table[Next + 1]))
            Next++;
        if (Next + 1 >= Length)
            return FALSE;
        Offset = Next + 2;
    }
    *TotalKb = Total;
    return TRUE;
}

START_TEST(PhysicallyInstalledMemory)
{
    ULONGLONG Value, SmbiosKb = 0;
    MEMORYSTATUSEX MemStatus;
    UCHAR *Raw;
    UINT Size;
    ULONG Devices = 0;
    BOOL Ret, Parsed = FALSE, Refused = FALSE;

    pGetPhysicallyInstalledSystemMemory = (void *)GetProcAddress(GetModuleHandleW(L"kernel32.dll"),
                                                                 "GetPhysicallyInstalledSystemMemory");
    if (!pGetPhysicallyInstalledSystemMemory)
    {
        skip("GetPhysicallyInstalledSystemMemory is not exported\n");
        return;
    }

    /* NULL pointer */
    SetLastError(0xdeadbeef);
    Ret = pGetPhysicallyInstalledSystemMemory(NULL);
    ok(Ret == FALSE, "NULL: returned %d\n", Ret);
    ok(GetLastError() == ERROR_INVALID_PARAMETER, "NULL: error %lu\n", GetLastError());

    /* The SMBIOS Memory Device structures, read by the test itself */
    SetLastError(0xdeadbeef);
    Size = GetSystemFirmwareTable(RSMB, 0, NULL, 0);
    if (Size == 0)
    {
        DWORD TableError = GetLastError();

        /* Without SMBIOS Windows (x64 and WoW64) fails the query with ERROR_INVALID_FUNCTION;
         * ERROR_NOT_SUPPORTED is what a WoW64 layer that does not forward the class gives */
        ok(TableError != ERROR_NOT_SUPPORTED, "RSMB table query not supported in this process\n");

        /* No SMBIOS: the function fails with the table query's error */
        Value = 0xdeadbeefdeadbeefULL;
        SetLastError(0xdeadbeef);
        Ret = pGetPhysicallyInstalledSystemMemory(&Value);
        ok(Ret == FALSE, "no SMBIOS: returned %d\n", Ret);
        ok(GetLastError() == TableError, "no SMBIOS: error %lu, table query error %lu\n", GetLastError(), TableError);
        ok(Value == 0xdeadbeefdeadbeefULL, "no SMBIOS: output written: %I64u\n", Value);
        skip("no SMBIOS table (error %lu)\n", TableError);
        return;
    }
    ok(Size > 8, "RSMB table size %u\n", Size);
    if (Size > 8)
    {
        Raw = HeapAlloc(GetProcessHeap(), 0, Size);
        ok(Raw != NULL, "HeapAlloc failed\n");
        if (Raw)
        {
            ok(GetSystemFirmwareTable(RSMB, 0, Raw, Size) == Size, "RSMB read failed (%lu)\n", GetLastError());
            if (*(ULONG UNALIGNED *)&Raw[4] <= Size - 8)
                Parsed = SumMemoryDevices(Raw + 8, *(ULONG UNALIGNED *)&Raw[4], &SmbiosKb, &Devices, &Refused);
            HeapFree(GetProcessHeap(), 0, Raw);
        }
    }
    ok(Parsed, "the RSMB table did not parse\n");
    ok(Devices > 0 || Refused, "no SMBIOS Memory Device structure\n");

    MemStatus.dwLength = sizeof(MemStatus);
    ok(GlobalMemoryStatusEx(&MemStatus), "GlobalMemoryStatusEx failed\n");

    Value = 0xdeadbeefdeadbeefULL;
    SetLastError(0xdeadbeef);
    Ret = pGetPhysicallyInstalledSystemMemory(&Value);
    if (Refused || !Parsed)
    {
        /* A device Windows refuses (or a table that does not parse): invalid data, output untouched */
        ok(Ret == FALSE, "refused table: returned %d, value %I64u\n", Ret, Value);
        ok(GetLastError() == ERROR_INVALID_DATA, "refused table: error %lu\n", GetLastError());
        ok(Value == 0xdeadbeefdeadbeefULL, "refused table: output written: %I64u\n", Value);
    }
    else if (Ret)
    {
        ok(Ret == TRUE, "returned %d, error %lu\n", Ret, GetLastError());
        ok(Value != 0 && Value != 0xdeadbeefdeadbeefULL, "value not written: %I64u\n", Value);
        ok(Value >= MemStatus.ullTotalPhys / 1024, "%I64u KB is less than TotalPhys %I64u KB\n",
           Value, MemStatus.ullTotalPhys / 1024);
        ok(Value == SmbiosKb, "%I64u KB, SMBIOS memory devices sum to %I64u KB (%lu devices)\n",
           Value, SmbiosKb, Devices);
    }
    else
    {
        ok(Ret == TRUE, "returned %d, error %lu\n", Ret, GetLastError());
        ok(Value == 0xdeadbeefdeadbeefULL, "failure wrote the output: %I64u\n", Value);
    }
    trace("installed %I64u KB, SMBIOS type 17 sum %I64u KB in %lu devices, TotalPhys %I64u KB\n",
          Ret ? Value : 0, SmbiosKb, Devices, MemStatus.ullTotalPhys / 1024);
}
