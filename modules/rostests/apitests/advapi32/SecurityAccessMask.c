/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Tests for advapi32!QuerySecurityAccessMask and SetSecurityAccessMask
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * The results are those of Windows 10 22H2 (x64 and x86). The rows are single bits and typical sets; the checksum
 * covers every combination of the nine low bits with and without the backup bit.
 */

#include "precomp.h"

#define READ_CONTROL_       0x00020000
#define WRITE_DAC_          0x00040000
#define WRITE_OWNER_        0x00080000
#define ACCESS_SYSSEC       0x01000000

static const struct
{
    DWORD Information;
    DWORD Query;
    DWORD Set;
} Rows[] =
{
    { 0x00000000, 0x00000000, 0x00000000 },
    { 0x00000001, READ_CONTROL_, WRITE_OWNER_ },                   /* owner */
    { 0x00000002, READ_CONTROL_, WRITE_OWNER_ },                   /* group */
    { 0x00000004, READ_CONTROL_, WRITE_DAC_ },                     /* DACL */
    { 0x00000008, ACCESS_SYSSEC, ACCESS_SYSSEC },                  /* SACL */
    { 0x00000010, READ_CONTROL_, WRITE_OWNER_ },                   /* label */
    { 0x00000020, READ_CONTROL_, WRITE_DAC_ },                     /* attribute */
    { 0x00000040, READ_CONTROL_, ACCESS_SYSSEC },                  /* scope */
    { 0x00000080, READ_CONTROL_, WRITE_DAC_ },                     /* process trust label */
    { 0x00000100, READ_CONTROL_, WRITE_DAC_ },                     /* access filter */
    { 0x00000200, 0, 0 },
    { 0x00000400, 0, 0 },
    { 0x00001000, 0, 0 },
    { 0x00010000, ACCESS_SYSSEC | READ_CONTROL_, ACCESS_SYSSEC | WRITE_DAC_ | WRITE_OWNER_ },  /* backup */
    { 0x00020000, 0, 0 },
    { 0x80000000, 0, 0 },
    { 0x00010001, ACCESS_SYSSEC | READ_CONTROL_, ACCESS_SYSSEC | WRITE_DAC_ | WRITE_OWNER_ },
    { 0x000001ff, ACCESS_SYSSEC | READ_CONTROL_, ACCESS_SYSSEC | WRITE_DAC_ | WRITE_OWNER_ },
    { 0x0000001f, ACCESS_SYSSEC | READ_CONTROL_, ACCESS_SYSSEC | WRITE_DAC_ | WRITE_OWNER_ },
    { 0x00020007, READ_CONTROL_, WRITE_DAC_ | WRITE_OWNER_ },
    { 0x0000000f, ACCESS_SYSSEC | READ_CONTROL_, ACCESS_SYSSEC | WRITE_DAC_ | WRITE_OWNER_ },
    { 0x8000000f, ACCESS_SYSSEC | READ_CONTROL_, ACCESS_SYSSEC | WRITE_DAC_ | WRITE_OWNER_ },
};

START_TEST(SecurityAccessMask)
{
    typedef VOID (WINAPI *FN)(DWORD, LPDWORD);
    HMODULE hAdvapi32 = GetModuleHandleW(L"advapi32.dll");
    FN pQuery = (FN)GetProcAddress(hAdvapi32, "QuerySecurityAccessMask");
    FN pSet = (FN)GetProcAddress(hAdvapi32, "SetSecurityAccessMask");
    DWORD Access, Information, Mix = 0, Count = 0;
    ULONG i;

    if (!pQuery || !pSet)
    {
        ok(!is_reactos(), "Query/SetSecurityAccessMask are not exported by advapi32.dll\n");
        skip("QuerySecurityAccessMask is not available\n");
        return;
    }

    for (i = 0; i < ARRAYSIZE(Rows); i++)
    {
        Access = 0xdeadbeef;
        SetLastError(0xdeadf00d);
        pQuery(Rows[i].Information, &Access);
        ok(Access == Rows[i].Query, "Query(%08lx) = %08lx, expected %08lx\n", Rows[i].Information, Access, Rows[i].Query);
        ok(GetLastError() == 0xdeadf00d, "Query(%08lx): last error %lu\n", Rows[i].Information, GetLastError());

        Access = 0xdeadbeef;
        pSet(Rows[i].Information, &Access);
        ok(Access == Rows[i].Set, "Set(%08lx) = %08lx, expected %08lx\n", Rows[i].Information, Access, Rows[i].Set);
    }

    /* Every combination of bits 0 to 8, without the backup bit and with it */
    for (Information = 0; Information < 0x10200; Information++)
    {
        if (Information == 0x200)
            Information = 0x10000;
        Access = 0;
        pQuery(Information, &Access);
        Mix = Mix * 31 + Access;
        Access = 0;
        pSet(Information, &Access);
        Mix = Mix * 31 + Access;
        Count++;
    }
    ok(Count == 1024, "%lu combinations\n", Count);
    ok(Mix == 0x2a040000, "checksum %08lx\n", Mix);
}
