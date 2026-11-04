/*
 * PROJECT:     NitroOS
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Execute the guest registrar, observe our DLL's callback and exit status
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

/* Execute the guest registrar, observe our DLL's callback and exit status. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>

static unsigned Checks, Failures;
#define CHECK(x) do { ++Checks; if (!(x)) { ++Failures; printf("FAIL line %u: %s error=%lu\n", __LINE__, #x, GetLastError()); } } while (0)

static void Run(PCWSTR Options, unsigned Bits, DWORD ExpectedCode, DWORD ExpectedValue)
{
    WCHAR Registrar[MAX_PATH], Command[1024];
    STARTUPINFOW Startup = {sizeof(Startup)};
    PROCESS_INFORMATION Process;
    HANDLE File;
    DWORD Code = 99, Value = 0, Bytes;
    CHECK(GetWindowsDirectoryW(Registrar, MAX_PATH));
    wcscat(Registrar, L"\\SysWOW64\\regsvr32.exe");
    _snwprintf(Command, 1024, L"\"%ls\" /s %ls C:\\harness\\register%u.dll", Registrar, Options, Bits);
    DeleteFileW(L"C:\\harness\\reg-result.txt");
    printf("REGISTER bits=%u options=%ls\n", Bits, Options);
    if (!CreateProcessW(Registrar, Command, NULL, NULL, FALSE, 0, NULL, NULL, &Startup, &Process))
    {
        CHECK(FALSE);
        return;
    }
    if (WaitForSingleObject(Process.hProcess, 30000) != WAIT_OBJECT_0)
    {
        CHECK(FALSE);
        TerminateProcess(Process.hProcess, 99);
    }
    CHECK(GetExitCodeProcess(Process.hProcess, &Code));
    CHECK(Code == ExpectedCode);
    CloseHandle(Process.hThread);
    CloseHandle(Process.hProcess);
    File = CreateFileW(L"C:\\harness\\reg-result.txt", GENERIC_READ, FILE_SHARE_READ,
                       NULL, OPEN_EXISTING, 0, NULL);
    CHECK(File != INVALID_HANDLE_VALUE);
    if (File != INVALID_HANDLE_VALUE)
    {
        CHECK(ReadFile(File, &Value, sizeof(Value), &Bytes, NULL) && Bytes == sizeof(Value));
        CHECK(Value == ExpectedValue);
        CloseHandle(File);
    }
    DeleteFileW(L"C:\\harness\\reg-result.txt");
    printf("REGISTER code=%lu marker=%lu\n", Code, Value);
}

int wmain(void)
{
    CHECK(SetEnvironmentVariableW(L"W643C_REG_FAIL", NULL));
    Run(L"", 32, 0, 4);
    Run(L"", 64, 0, 8);
    Run(L"/u", 64, 0, 108);
    Run(L"/n /i:\"argument with spaces\"", 64, 0, 208);
    CHECK(SetEnvironmentVariableW(L"W643C_REG_FAIL", L"1"));
    Run(L"", 64, 5, 8);
    CHECK(SetEnvironmentVariableW(L"W643C_REG_FAIL", NULL));
    printf("REGISTRATION checks=%u failures=%u\n", Checks, Failures);
    return Failures ? 1 : 0;
}
