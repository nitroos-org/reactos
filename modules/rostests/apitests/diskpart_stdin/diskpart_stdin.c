/*
 * PROJECT:     ReactOS API Tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     diskpart.exe with its standard input redirected from a file, a pipe and an empty
 *              source: it must read the commands, answer them and leave at the end of the input
 *              (read-only commands only)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include <apitest.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define LIMIT_MS 10000
#define SCRIPT   "list disk\r\nlist volume\r\n"

static char *ReadWhole(const char *Path)
{
    HANDLE h;
    DWORD Size, Got = 0;
    char *Buf;

    h = CreateFileA(Path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE)
        return NULL;
    Size = GetFileSize(h, NULL);
    Buf = malloc(Size + 1);
    if (Buf && !ReadFile(h, Buf, Size, &Got, NULL))
        Got = 0;
    if (Buf)
        Buf[Got] = 0;
    CloseHandle(h);
    return Buf;
}

static int CountStr(const char *s, const char *Needle)
{
    int n = 0;
    size_t l = strlen(Needle);

    while ((s = strstr(s, Needle)) != NULL)
    {
        n++;
        s += l;
    }
    return n;
}

/* Runs diskpart.exe with the given stdin handle; returns the output text (malloc'ed) or NULL */
static char *RunDiskpart(HANDLE In, DWORD *pElapsed, BOOL *pTimedOut, DWORD *pExit)
{
    char Tmp[MAX_PATH], Dir[MAX_PATH], Cmd[MAX_PATH + 32], Sys[MAX_PATH];
    SECURITY_ATTRIBUTES Sa = { sizeof(Sa), NULL, TRUE };
    STARTUPINFOA Si = { sizeof(Si) };
    PROCESS_INFORMATION Pi;
    HANDLE Out;
    DWORD Start, Wait;
    char *Text;

    GetTempPathA(sizeof(Dir), Dir);
    GetTempFileNameA(Dir, "dps", 0, Tmp);
    Out = CreateFileA(Tmp, GENERIC_WRITE, FILE_SHARE_READ, &Sa, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (Out == INVALID_HANDLE_VALUE)
        return NULL;

    GetSystemDirectoryA(Sys, sizeof(Sys));
    sprintf(Cmd, "\"%s\\diskpart.exe\"", Sys);
    Si.dwFlags = STARTF_USESTDHANDLES;
    Si.hStdInput = In;
    Si.hStdOutput = Out;
    Si.hStdError = Out;
    *pTimedOut = FALSE;
    *pExit = 0xdeadbeef;
    Start = GetTickCount();
    if (!CreateProcessA(NULL, Cmd, NULL, NULL, TRUE, 0, NULL, NULL, &Si, &Pi))
    {
        ok(0, "cannot start %s: %lu\n", Cmd, GetLastError());
        CloseHandle(Out);
        DeleteFileA(Tmp);
        return NULL;
    }
    Wait = WaitForSingleObject(Pi.hProcess, LIMIT_MS);
    if (Wait != WAIT_OBJECT_0)
    {
        *pTimedOut = TRUE;
        TerminateProcess(Pi.hProcess, 99);   /* our own child, still prompting */
        WaitForSingleObject(Pi.hProcess, 5000);
    }
    *pElapsed = GetTickCount() - Start;
    GetExitCodeProcess(Pi.hProcess, pExit);
    CloseHandle(Pi.hProcess);
    CloseHandle(Pi.hThread);
    CloseHandle(Out);
    Text = ReadWhole(Tmp);
    DeleteFileA(Tmp);
    return Text;
}

static void Check(const char *What, char *Text, DWORD Elapsed, BOOL TimedOut, DWORD Exit, int Commands)
{
    int Prompts;

    ok(!TimedOut, "%s: diskpart did not end within %u ms (still prompting at the end of its input)\n",
       What, LIMIT_MS);
    if (!Text)
    {
        ok(0, "%s: no output\n", What);
        return;
    }
    Prompts = CountStr(Text, "DISKPART> ");
    trace("%s: %lu ms, exit %lu, %d prompts, %lu bytes\n", What, Elapsed, Exit, Prompts,
          (unsigned long)strlen(Text));
    ok(Prompts <= Commands + 1, "%s: %d prompts for %d commands\n", What, Prompts, Commands);
    if (Commands >= 2)
    {
        ok(strstr(Text, "Disk ###") != NULL, "%s: no disk list in the output\n", What);
        ok(strstr(Text, "Volume ###") != NULL, "%s: no volume list in the output\n", What);
    }
    if (!TimedOut)
    {
        ok(strstr(Text, "Leaving DiskPart") != NULL, "%s: does not say it is leaving\n", What);
        ok(Exit == 0, "%s: exit code %lu\n", What, Exit);
    }
    free(Text);
}

START_TEST(diskpart_stdin)
{
    SECURITY_ATTRIBUTES Sa = { sizeof(Sa), NULL, TRUE };
    char Dir[MAX_PATH], Name[MAX_PATH];
    HANDLE In, PipeR, PipeW;
    DWORD Elapsed, Exit, Got;
    BOOL TimedOut;
    char *Text;

    /* 1. stdin redirected from a file with two commands and no "exit" */
    GetTempPathA(sizeof(Dir), Dir);
    GetTempFileNameA(Dir, "dpi", 0, Name);
    In = CreateFileA(Name, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    ok(In != INVALID_HANDLE_VALUE, "cannot create %s\n", Name);
    WriteFile(In, SCRIPT, sizeof(SCRIPT) - 1, &Got, NULL);
    CloseHandle(In);
    In = CreateFileA(Name, GENERIC_READ, FILE_SHARE_READ, &Sa, OPEN_EXISTING, 0, NULL);
    ok(In != INVALID_HANDLE_VALUE, "cannot open %s\n", Name);
    Text = RunDiskpart(In, &Elapsed, &TimedOut, &Exit);
    Check("file", Text, Elapsed, TimedOut, Exit, 2);
    CloseHandle(In);
    DeleteFileA(Name);

    /* 2. stdin is a pipe whose writer sends two commands and closes it */
    ok(CreatePipe(&PipeR, &PipeW, &Sa, 0), "CreatePipe failed\n");
    SetHandleInformation(PipeW, HANDLE_FLAG_INHERIT, 0);
    WriteFile(PipeW, SCRIPT, sizeof(SCRIPT) - 1, &Got, NULL);
    CloseHandle(PipeW);
    Text = RunDiskpart(PipeR, &Elapsed, &TimedOut, &Exit);
    Check("pipe", Text, Elapsed, TimedOut, Exit, 2);
    CloseHandle(PipeR);

    /* 3. stdin is empty (file of length 0): leave at once */
    GetTempFileNameA(Dir, "dpe", 0, Name);
    In = CreateFileA(Name, GENERIC_READ, FILE_SHARE_READ, &Sa, OPEN_EXISTING, 0, NULL);
    ok(In != INVALID_HANDLE_VALUE, "cannot open %s\n", Name);
    Text = RunDiskpart(In, &Elapsed, &TimedOut, &Exit);
    Check("empty", Text, Elapsed, TimedOut, Exit, 0);
    CloseHandle(In);
    DeleteFileA(Name);

    /* 4. stdin is a pipe whose writer closes it at once */
    ok(CreatePipe(&PipeR, &PipeW, &Sa, 0), "CreatePipe failed\n");
    SetHandleInformation(PipeW, HANDLE_FLAG_INHERIT, 0);
    CloseHandle(PipeW);
    Text = RunDiskpart(PipeR, &Elapsed, &TimedOut, &Exit);
    Check("closed pipe", Text, Elapsed, TimedOut, Exit, 0);
    CloseHandle(PipeR);
}
