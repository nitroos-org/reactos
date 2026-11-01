/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 * Pseudoconsole process attachment, output, input, resize and shutdown.
 */

#include "precomp.h"

#ifndef EXTENDED_STARTUPINFO_PRESENT
#define EXTENDED_STARTUPINFO_PRESENT 0x00080000
#endif

typedef HRESULT (WINAPI *CREATE_PTY)(COORD, HANDLE, HANDLE, DWORD, PVOID *);
typedef HRESULT (WINAPI *RESIZE_PTY)(PVOID, COORD);
typedef VOID (WINAPI *CLOSE_PTY)(PVOID);
typedef BOOL (WINAPI *INITIALIZE_LIST)(LPPROC_THREAD_ATTRIBUTE_LIST, DWORD, DWORD, PSIZE_T);
typedef BOOL (WINAPI *UPDATE_ATTRIBUTE)(LPPROC_THREAD_ATTRIBUTE_LIST, DWORD, DWORD_PTR,
                                        PVOID, SIZE_T, PVOID, PSIZE_T);

static CREATE_PTY CreatePty;
static RESIZE_PTY ResizePty;
static CLOSE_PTY ClosePty;
static INITIALIZE_LIST InitializeList;
static UPDATE_ATTRIBUTE UpdateAttribute;

static BOOL
WaitForText(HANDLE Output, PCSTR Expected, DWORD Timeout)
{
    CHAR Text[32768];
    DWORD Start = GetTickCount(), Available, Count, Used = 0;

    Text[0] = 0;
    while (GetTickCount() - Start < Timeout)
    {
        Available = 0;
        if (!PeekNamedPipe(Output, NULL, 0, NULL, &Available, NULL))
            break;
        if (Available)
        {
            if (Available > sizeof(Text) - Used - 1)
                Available = sizeof(Text) - Used - 1;
            if (!Available) return FALSE;
            if (!ReadFile(Output, Text + Used, Available, &Count, NULL))
                break;
            Used += Count;
            Text[Used] = 0;
            if (strstr(Text, Expected)) return TRUE;
        }
        Sleep(10);
    }
    return FALSE;
}

static VOID
CheckSession(BOOL Interactive)
{
    HANDLE InputRead = NULL, InputWrite = NULL, OutputRead = NULL, OutputWrite = NULL;
    STARTUPINFOEXW Startup = {0};
    PROCESS_INFORMATION Process;
    SIZE_T AttributeSize = 0;
    WCHAR Command[MAX_PATH];
    PVOID PseudoConsole = NULL;
    COORD Size = {80, 25};
    DWORD Written;
    BOOL Created;
    HRESULT Status;

    if (!CreatePipe(&InputRead, &InputWrite, NULL, 0) ||
        !CreatePipe(&OutputRead, &OutputWrite, NULL, 0))
    {
        ok(FALSE, "CreatePipe failed: %lu\n", GetLastError());
        goto Cleanup;
    }
    Status = CreatePty(Size, InputRead, OutputWrite, 0, &PseudoConsole);
    ok(Status == S_OK, "CreatePseudoConsole failed: %08lx\n", Status);
    if (Status != S_OK) goto Cleanup;
    CloseHandle(InputRead);
    InputRead = NULL;
    CloseHandle(OutputWrite);
    OutputWrite = NULL;

    ZeroMemory(&Startup, sizeof(Startup));
    Startup.StartupInfo.cb = sizeof(Startup);
    InitializeList(NULL, 1, 0, &AttributeSize);
    Startup.lpAttributeList = HeapAlloc(GetProcessHeap(), 0, AttributeSize);
    if (!Startup.lpAttributeList) goto Cleanup;
    Created = InitializeList(Startup.lpAttributeList, 1, 0, &AttributeSize) &&
              UpdateAttribute(Startup.lpAttributeList, 0,
                              PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE,
                              PseudoConsole, sizeof(PseudoConsole), NULL, NULL);
    ok(Created, "Pseudoconsole attribute failed: %lu\n", GetLastError());
    if (!Created) goto Cleanup;

    if (Interactive)
        lstrcpyW(Command, L"cmd.exe");
    else
        lstrcpyW(Command, L"cmd.exe /c echo hello");
    ZeroMemory(&Process, sizeof(Process));
    Created = CreateProcessW(NULL, Command, NULL, NULL, FALSE,
                             EXTENDED_STARTUPINFO_PRESENT, NULL, NULL,
                             &Startup.StartupInfo, &Process);
    ok(Created, "CreateProcessW with pseudoconsole failed: %lu\n", GetLastError());
    if (Created)
    {
        CloseHandle(Process.hThread);
        if (Interactive)
        {
            Created = WriteFile(InputWrite, "echo world\r", 11, &Written, NULL);
            ok(Created && Written == 11, "Input pipe write failed: %lu\n", GetLastError());
            ok(WaitForText(OutputRead, "world", 10000), "No interactive output\n");
            Size.X = 100;
            Size.Y = 30;
            Status = ResizePty(PseudoConsole, Size);
            ok(Status == S_OK, "ResizePseudoConsole failed: %08lx\n", Status);
            ClosePty(PseudoConsole);
            PseudoConsole = NULL;
            ok(WaitForSingleObject(Process.hProcess, 5000) == WAIT_OBJECT_0,
               "Client remained alive after ClosePseudoConsole\n");
        }
        else
        {
            ok(WaitForText(OutputRead, "hello", 10000), "No command output\n");
            ok(WaitForSingleObject(Process.hProcess, 5000) == WAIT_OBJECT_0,
               "Command did not exit\n");
        }
        CloseHandle(Process.hProcess);
    }
Cleanup:
    if (Startup.lpAttributeList) HeapFree(GetProcessHeap(), 0, Startup.lpAttributeList);
    if (PseudoConsole) ClosePty(PseudoConsole);
    if (InputRead) CloseHandle(InputRead);
    if (InputWrite) CloseHandle(InputWrite);
    if (OutputRead) CloseHandle(OutputRead);
    if (OutputWrite) CloseHandle(OutputWrite);
}

START_TEST(ConPty)
{
    HMODULE Module = GetModuleHandleW(L"kernel32.dll");
    CreatePty = (CREATE_PTY)GetProcAddress(Module, "CreatePseudoConsole");
    ResizePty = (RESIZE_PTY)GetProcAddress(Module, "ResizePseudoConsole");
    ClosePty = (CLOSE_PTY)GetProcAddress(Module, "ClosePseudoConsole");
    InitializeList = (INITIALIZE_LIST)GetProcAddress(Module, "InitializeProcThreadAttributeList");
    UpdateAttribute = (UPDATE_ATTRIBUTE)GetProcAddress(Module, "UpdateProcThreadAttribute");
    ok(CreatePty && ResizePty && ClosePty && InitializeList && UpdateAttribute,
       "Pseudoconsole API exports missing\n");
    if (!CreatePty || !ResizePty || !ClosePty || !InitializeList || !UpdateAttribute) return;
    CheckSession(FALSE);
    CheckSession(TRUE);
}
