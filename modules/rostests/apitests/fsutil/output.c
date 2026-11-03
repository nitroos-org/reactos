/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     MIT (https://spdx.org/licenses/MIT)
 * PURPOSE:     fsutil.exe output is byte-identical to Windows 10 22H2: stdout and exit code of the
 *              usage, group listing and error paths. The expected text is in cases.h, generated from
 *              a capture taken on real Windows 10 22H2 (harness evidence fsutil-golden).
 *              Only machine-independent cases: no existing drive is named.
 */

#include <apitest.h>
#include <stdio.h>
#include <string.h>

#include "cases.h"

static
BOOL
RunFsutil(const char *Args, char **Output, DWORD *ExitCode)
{
    SECURITY_ATTRIBUTES Sa = { sizeof(Sa), NULL, TRUE };
    STARTUPINFOA Si = { sizeof(Si) };
    PROCESS_INFORMATION Pi;
    HANDLE Read, Write, Nul;
    char Cmd[512];
    char *Buf;
    DWORD Size = 0, Cap = 65536, Got;

    if (!CreatePipe(&Read, &Write, &Sa, 0))
        return FALSE;
    SetHandleInformation(Read, HANDLE_FLAG_INHERIT, 0);
    Nul = CreateFileA("NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, &Sa, OPEN_EXISTING, 0, NULL);
    Si.dwFlags = STARTF_USESTDHANDLES;
    Si.hStdInput = Nul;
    Si.hStdOutput = Write;
    Si.hStdError = Write;
    sprintf(Cmd, "fsutil.exe %s", Args);
    if (!CreateProcessA(NULL, Cmd, NULL, NULL, TRUE, 0, NULL, NULL, &Si, &Pi))
    {
        CloseHandle(Read);
        CloseHandle(Write);
        CloseHandle(Nul);
        return FALSE;
    }
    CloseHandle(Write);
    CloseHandle(Nul);

    Buf = HeapAlloc(GetProcessHeap(), 0, Cap);
    while (Size < Cap - 1 && ReadFile(Read, Buf + Size, Cap - 1 - Size, &Got, NULL) && Got != 0)
        Size += Got;
    Buf[Size] = 0;
    WaitForSingleObject(Pi.hProcess, 30000);
    GetExitCodeProcess(Pi.hProcess, ExitCode);
    CloseHandle(Pi.hProcess);
    CloseHandle(Pi.hThread);
    CloseHandle(Read);
    *Output = Buf;
    return TRUE;
}

/* The file is written in text mode: "\n" in cases.h is "\r\n" on the pipe */
static
void
ExpectedToCrLf(const char *In, char *Out)
{
    for (; *In; In++)
    {
        if (*In == 10)
            *Out++ = 13;
        *Out++ = *In;
    }
    *Out = 0;
}

START_TEST(output)
{
    size_t i;

    if (GetDriveTypeA("Q:\\") != DRIVE_NO_ROOT_DIR)
    {
        skip("Q: exists, the cases name it as a missing drive\n");
        return;
    }

    for (i = 0; i < sizeof(Cases) / sizeof(Cases[0]); i++)
    {
        char Expected[8192];
        char *Output = NULL;
        DWORD ExitCode = 0xDEAD;

        ExpectedToCrLf(Cases[i].Output, Expected);
        if (!RunFsutil(Cases[i].Args, &Output, &ExitCode))
        {
            skip("fsutil.exe cannot be started\n");
            return;
        }
        ok(strcmp(Output, Expected) == 0, "fsutil %s: output differs:\n[%s]\nexpected:\n[%s]\n",
           Cases[i].Args, Output, Expected);
        ok(ExitCode == (DWORD)Cases[i].ExitCode, "fsutil %s: exit code %lu, expected %d\n",
           Cases[i].Args, ExitCode, Cases[i].ExitCode);
        HeapFree(GetProcessHeap(), 0, Output);
    }
}
