/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Exports Edge Update (Omaha) looks up with GetProcAddress: OOBEComplete, WerRegisterCustomMetadata,
 *              GetTempPath2W/GetTempPath2A (kernel32 and kernelbase)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Windows 10 22H2 (19045, without the GetTempPath2 servicing) measured: OOBEComplete returns TRUE with the flag set,
 * WerRegisterCustomMetadata("key", "value") is S_OK and kernelbase exports it (forwarded here to kernel32).
 * GetTempPath2W is the Windows 11 / later servicing API: GetTempPathW for everyone except LocalSystem.
 */

#include "precomp.h"

typedef BOOL (WINAPI *PF_OOBE)(PBOOL);
typedef DWORD (WINAPI *PF_TP2W)(DWORD, LPWSTR);
typedef DWORD (WINAPI *PF_TP2A)(DWORD, LPSTR);
typedef HRESULT (WINAPI *PF_WER)(PCWSTR, PCWSTR);

static BOOL IsSystemProcess(void)
{
    BYTE Buffer[128];
    DWORD Length;
    HANDLE Token;
    BOOL IsSystem = FALSE;
    SID_IDENTIFIER_AUTHORITY Nt = {SECURITY_NT_AUTHORITY};
    PSID System;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &Token))
        return FALSE;
    if (GetTokenInformation(Token, TokenUser, Buffer, sizeof(Buffer), &Length) &&
        AllocateAndInitializeSid(&Nt, 1, SECURITY_LOCAL_SYSTEM_RID, 0, 0, 0, 0, 0, 0, 0, &System))
    {
        IsSystem = EqualSid(((PTOKEN_USER)Buffer)->User.Sid, System);
        FreeSid(System);
    }
    CloseHandle(Token);
    return IsSystem;
}

static void Test_OOBEComplete(HMODULE Kernel32, HMODULE Kernelbase)
{
    PF_OOBE pOOBEComplete = (PF_OOBE)GetProcAddress(Kernel32, "OOBEComplete");
    BOOL Complete, Ret;

    if (!pOOBEComplete)
    {
        skip("OOBEComplete is not exported\n");
        return;
    }
    Complete = 0x55;
    SetLastError(0xdeadbeef);
    Ret = pOOBEComplete(&Complete);
    ok(Ret == TRUE, "OOBEComplete returned %d, error %lu\n", Ret, GetLastError());
    ok(Complete == TRUE, "complete flag is %d\n", Complete);
    /* kernelbase does not export it on Windows */
    ok(GetProcAddress(Kernelbase, "OOBEComplete") == NULL, "kernelbase exports OOBEComplete\n");
}

static void Test_WerRegisterCustomMetadata(HMODULE Kernel32, HMODULE Kernelbase)
{
    PF_WER pWer = (PF_WER)GetProcAddress(Kernel32, "WerRegisterCustomMetadata");
    PF_WER pWerBase = (PF_WER)GetProcAddress(Kernelbase, "WerRegisterCustomMetadata");
    HRESULT hr;

    if (!pWer)
    {
        skip("WerRegisterCustomMetadata is not exported\n");
        return;
    }
    hr = pWer(L"omaha-test-key", L"omaha-test-value");
    ok(hr == S_OK, "WerRegisterCustomMetadata returned %08lx\n", (ULONG)hr);
    /* registering the same key again replaces the value */
    hr = pWer(L"omaha-test-key", L"other-value");
    ok(hr == S_OK, "second WerRegisterCustomMetadata returned %08lx\n", (ULONG)hr);
    ok(pWerBase != NULL, "kernelbase does not export WerRegisterCustomMetadata\n");
    if (pWerBase)
    {
        hr = pWerBase(L"omaha-test-key2", L"value");
        ok(hr == S_OK, "kernelbase WerRegisterCustomMetadata returned %08lx\n", (ULONG)hr);
    }
}

static void Test_GetTempPath2(HMODULE Kernel32, HMODULE Kernelbase)
{
    PF_TP2W pW = (PF_TP2W)GetProcAddress(Kernelbase, "GetTempPath2W");
    PF_TP2A pA = (PF_TP2A)GetProcAddress(Kernelbase, "GetTempPath2A");
    WCHAR Expected[MAX_PATH], Buffer[MAX_PATH], SystemTemp[MAX_PATH];
    CHAR BufferA[MAX_PATH], ExpectedA[MAX_PATH];
    DWORD Length, ExpectedLength, Ret, i;
    BOOL System = IsSystemProcess();

    if (!pW || !pA)
    {
        skip("GetTempPath2W/A are not exported by kernelbase\n");
        return;
    }
    ok((PF_TP2W)GetProcAddress(Kernel32, "GetTempPath2W") != NULL, "kernel32 does not export GetTempPath2W\n");

    if (System)
    {
        GetWindowsDirectoryW(SystemTemp, MAX_PATH);
        lstrcatW(SystemTemp, L"\\SystemTemp\\");
        if (GetFileAttributesW(SystemTemp) != INVALID_FILE_ATTRIBUTES)
            lstrcpyW(Expected, SystemTemp);
        else
            ExpectedLength = GetTempPathW(MAX_PATH, Expected);
    }
    else
        GetTempPathW(MAX_PATH, Expected);
    ExpectedLength = lstrlenW(Expected);

    Length = pW(MAX_PATH, Buffer);
    ok(Length == ExpectedLength, "GetTempPath2W returned %lu, expected %lu (%ls)\n", Length, ExpectedLength, Expected);
    ok(!lstrcmpiW(Buffer, Expected), "GetTempPath2W returned %ls, expected %ls\n", Buffer, Expected);
    ok(Buffer[Length - 1] == L'\\', "no trailing backslash in %ls\n", Buffer);

    /* too small: the size with the terminator, buffer cleared */
    for (i = 0; i < MAX_PATH; i++) Buffer[i] = 0x5555;
    Ret = pW(Length, Buffer);
    ok(Ret == Length + 1, "short buffer: returned %lu, expected %lu\n", Ret, Length + 1);
    ok(Buffer[0] == 0, "short buffer was not cleared: %04x\n", Buffer[0]);
    Ret = pW(0, NULL);
    ok(Ret == Length + 1, "zero count: returned %lu, expected %lu\n", Ret, Length + 1);

    /* exactly enough: the length without the terminator */
    for (i = 0; i < MAX_PATH; i++) Buffer[i] = 0x5555;
    Ret = pW(Length + 1, Buffer);
    ok(Ret == Length, "exact buffer: returned %lu, expected %lu\n", Ret, Length);
    ok(!lstrcmpiW(Buffer, Expected), "exact buffer: %ls\n", Buffer);

    Ret = pA(MAX_PATH, BufferA);
    ok(Ret == ExpectedLength, "GetTempPath2A returned %lu, expected %lu\n", Ret, ExpectedLength);
    WideCharToMultiByte(CP_ACP, 0, Expected, -1, ExpectedA, sizeof(ExpectedA), NULL, NULL);
    ok(!lstrcmpiA(BufferA, ExpectedA), "GetTempPath2A returned %s, expected %s\n", BufferA, ExpectedA);

    if (!System)
    {
        /* every process that is not LocalSystem gets what GetTempPathW says */
        WCHAR Plain[MAX_PATH];
        GetTempPathW(MAX_PATH, Plain);
        pW(MAX_PATH, Buffer);
        ok(!lstrcmpiW(Plain, Buffer), "GetTempPath2W %ls differs from GetTempPathW %ls\n", Buffer, Plain);
    }
}

START_TEST(OmahaExports)
{
    HMODULE Kernel32 = GetModuleHandleW(L"kernel32.dll");
    HMODULE Kernelbase = LoadLibraryW(L"kernelbase.dll");

    ok(Kernelbase != NULL, "kernelbase.dll did not load\n");
    if (!Kernelbase)
        return;
    Test_OOBEComplete(Kernel32, Kernelbase);
    Test_WerRegisterCustomMetadata(Kernel32, Kernelbase);
    Test_GetTempPath2(Kernel32, Kernelbase);
}
