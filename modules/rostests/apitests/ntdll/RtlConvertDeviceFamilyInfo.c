/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     RtlConvertDeviceFamilyInfoToString: names and size handling, measured on Windows 10 22H2 (19045)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Sizes are bytes with the terminator; "Windows.Desktop" is 32, "Unknown" 16. A buffer that is too small gives
 * STATUS_BUFFER_TOO_SMALL, both sizes set, nothing written.
 */

#include "precomp.h"

typedef NTSTATUS (NTAPI *PF_CONVERT)(ULONG *, ULONG *, WCHAR *, WCHAR *);

static void Run(PF_CONVERT pConvert, ULONG FamilySize, ULONG FormSize, BOOL NullBuffers, NTSTATUS Expected)
{
    WCHAR Family[64], Form[64];
    NTSTATUS Status;
    ULONG fs = FamilySize, ms = FormSize, i;

    for (i = 0; i < 64; i++) Family[i] = Form[i] = 0x5555;
    Status = pConvert(&fs, &ms, NullBuffers ? NULL : Family, NullBuffers ? NULL : Form);
    ok(Status == Expected, "(%lu, %lu): status %08lx, expected %08lx\n", FamilySize, FormSize, Status, Expected);
    ok(fs == 32 && ms == 16, "(%lu, %lu): sizes %lu, %lu\n", FamilySize, FormSize, fs, ms);
    if (Expected == STATUS_SUCCESS)
    {
        ok(!wcscmp(Family, L"Windows.Desktop"), "family %ls\n", Family);
        ok(!wcscmp(Form, L"Unknown"), "form %ls\n", Form);
        ok(Family[16] == 0x5555 && Form[8] == 0x5555, "wrote past the names\n");
    }
    else
        ok(Family[0] == 0x5555 && Form[0] == 0x5555, "(%lu, %lu): buffers written\n", FamilySize, FormSize);
}

START_TEST(RtlConvertDeviceFamilyInfo)
{
    PF_CONVERT pConvert = (PF_CONVERT)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlConvertDeviceFamilyInfoToString");

    if (!pConvert)
    {
        skip("RtlConvertDeviceFamilyInfoToString is not exported\n");
        return;
    }
    Run(pConvert, 128, 128, FALSE, STATUS_SUCCESS);
    Run(pConvert, 32, 16, FALSE, STATUS_SUCCESS);
    Run(pConvert, 30, 128, FALSE, STATUS_BUFFER_TOO_SMALL);
    Run(pConvert, 128, 14, FALSE, STATUS_BUFFER_TOO_SMALL);
    Run(pConvert, 0, 0, TRUE, STATUS_BUFFER_TOO_SMALL);
}
