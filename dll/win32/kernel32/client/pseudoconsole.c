/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 * Pseudoconsole lifecycle and headless host startup.
 */

#include <k32.h>
#include "pseudoconsole.h"

#if (_WIN32_WINNT < 0x0600)
BOOL WINAPI InitializeProcThreadAttributeList(LPPROC_THREAD_ATTRIBUTE_LIST, DWORD, DWORD, PSIZE_T);
BOOL WINAPI UpdateProcThreadAttribute(LPPROC_THREAD_ATTRIBUTE_LIST, DWORD, DWORD_PTR,
                                      PVOID, SIZE_T, PVOID, PSIZE_T);
#endif

#ifndef EXTENDED_STARTUPINFO_PRESENT
#define EXTENDED_STARTUPINFO_PRESENT 0x00080000
#endif

#ifndef PSEUDOCONSOLE_INHERIT_CURSOR
#define PSEUDOCONSOLE_INHERIT_CURSOR 1
#endif

HRESULT WINAPI
CreatePseudoConsole(COORD Size, HANDLE Input, HANDLE Output, DWORD Flags, PVOID *Result)
{
    SECURITY_ATTRIBUTES Security = {sizeof(Security), NULL, TRUE};
    STARTUPINFOEXW Startup = {0};
    PROCESS_INFORMATION Process;
    PBASE_PSEUDOCONSOLE Console;
    HANDLE SignalRead = NULL, ReadyRead = NULL, ReadyWrite = NULL;
    HANDLE ChildInput = NULL, ChildOutput = NULL;
    HANDLE Inherited[4];
    SIZE_T AttributeSize = 0;
    ULONGLONG Ready[3];
    WCHAR Path[MAX_PATH], Command[2 * MAX_PATH];
    DWORD Error, Read, Start;
    BOOL Created = FALSE, Wow64 = FALSE;
    PVOID OldRedirection = NULL;

    if (!Result || Size.X <= 0 || Size.Y <= 0 || !Input || !Output ||
        (Flags & ~PSEUDOCONSOLE_INHERIT_CURSOR))
        return E_INVALIDARG;
    *Result = NULL;
    Console = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*Console));
    if (!Console) return E_OUTOFMEMORY;

    /* The parent-side ends must not be inherited by other children of the caller
       (a leaked signal write end keeps conhost from ever seeing EOF). */
    if (!CreatePipe(&SignalRead, &Console->Signal, &Security, 0) ||
        !SetHandleInformation(Console->Signal, HANDLE_FLAG_INHERIT, 0) ||
        !CreatePipe(&ReadyRead, &ReadyWrite, &Security, 0) ||
        !SetHandleInformation(ReadyRead, HANDLE_FLAG_INHERIT, 0) ||
        !DuplicateHandle(GetCurrentProcess(), Input, GetCurrentProcess(), &ChildInput,
                         0, TRUE, DUPLICATE_SAME_ACCESS) ||
        !DuplicateHandle(GetCurrentProcess(), Output, GetCurrentProcess(), &ChildOutput,
                         0, TRUE, DUPLICATE_SAME_ACCESS))
        goto Failure;

    if (!GetWindowsDirectoryW(Path, ARRAYSIZE(Path)) ||
        FAILED(RtlStringCchCatW(Path, ARRAYSIZE(Path), L"\\System32\\conhost.exe")))
        goto Failure;
    if (FAILED(RtlStringCchPrintfW(Command, ARRAYSIZE(Command),
                 L"\"%ls\" --headless --width %u --height %u --signal 0x%Ix --ready 0x%Ix %ls",
                 Path, (UINT)Size.X, (UINT)Size.Y, (ULONG_PTR)SignalRead,
                 (ULONG_PTR)ReadyWrite, (Flags & PSEUDOCONSOLE_INHERIT_CURSOR) ? L"--inheritcursor" : L"")))
        goto Failure;

    ZeroMemory(&Startup, sizeof(Startup));
    Startup.StartupInfo.cb = sizeof(Startup);
    Startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    Startup.StartupInfo.hStdInput = ChildInput;
    Startup.StartupInfo.hStdOutput = ChildOutput;
    Startup.StartupInfo.hStdError = ChildOutput;
    Inherited[0] = ChildInput;
    Inherited[1] = ChildOutput;
    Inherited[2] = SignalRead;
    Inherited[3] = ReadyWrite;
    InitializeProcThreadAttributeList(NULL, 1, 0, &AttributeSize);
    Startup.lpAttributeList = HeapAlloc(GetProcessHeap(), 0, AttributeSize);
    if (!Startup.lpAttributeList ||
        !InitializeProcThreadAttributeList(Startup.lpAttributeList, 1, 0, &AttributeSize) ||
        !UpdateProcThreadAttribute(Startup.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                                   Inherited, sizeof(Inherited), NULL, NULL))
        goto Failure;

    if (IsWow64Process(GetCurrentProcess(), &Wow64) && Wow64)
        Wow64DisableWow64FsRedirection(&OldRedirection);
    Created = CreateProcessW(Path, Command, NULL, NULL, TRUE,
                             CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT,
                             NULL, NULL, &Startup.StartupInfo, &Process);
    if (OldRedirection) Wow64RevertWow64FsRedirection(OldRedirection);
    HeapFree(GetProcessHeap(), 0, Startup.lpAttributeList);
    Startup.lpAttributeList = NULL;
    if (!Created) goto Failure;
    Console->Process = Process.hProcess;
    Console->ProcessId = Process.dwProcessId;
    CloseHandle(Process.hThread);
    CloseHandle(ReadyWrite);
    ReadyWrite = NULL;
    CloseHandle(SignalRead);
    SignalRead = NULL;
    CloseHandle(ChildInput);
    ChildInput = NULL;
    CloseHandle(ChildOutput);
    ChildOutput = NULL;

    Start = GetTickCount();
    for (;;)
    {
        DWORD Available = 0;
        if (PeekNamedPipe(ReadyRead, NULL, 0, NULL, &Available, NULL) &&
            Available >= sizeof(Ready))
            break;
        if (WaitForSingleObject(Console->Process, 0) != WAIT_TIMEOUT ||
            GetTickCount() - Start >= 15000)
        {
            SetLastError(ERROR_TIMEOUT);
            goto Failure;
        }
        Sleep(10);
    }
    if (!ReadFile(ReadyRead, Ready, sizeof(Ready), &Read, NULL) || Read != sizeof(Ready))
        goto Failure;
    Console->Console = (HANDLE)(ULONG_PTR)Ready[0];
    Console->Input = (HANDLE)(ULONG_PTR)Ready[1];
    Console->Output = (HANDLE)(ULONG_PTR)Ready[2];
    Console->Magic = BASE_PSEUDOCONSOLE_MAGIC;
    CloseHandle(ReadyRead);
    *Result = Console;
    return S_OK;

Failure:
    Error = GetLastError();
    if (Startup.lpAttributeList) HeapFree(GetProcessHeap(), 0, Startup.lpAttributeList);
    if (ReadyRead) CloseHandle(ReadyRead);
    if (ReadyWrite) CloseHandle(ReadyWrite);
    if (SignalRead) CloseHandle(SignalRead);
    if (ChildInput) CloseHandle(ChildInput);
    if (ChildOutput) CloseHandle(ChildOutput);
    if (Console->Signal) CloseHandle(Console->Signal);
    if (Console->Process)
    {
        TerminateProcess(Console->Process, 1);
        CloseHandle(Console->Process);
    }
    HeapFree(GetProcessHeap(), 0, Console);
    return HRESULT_FROM_WIN32(Error ? Error : ERROR_GEN_FAILURE);
}

HRESULT WINAPI
ResizePseudoConsole(PVOID Handle, COORD Size)
{
    PBASE_PSEUDOCONSOLE Console = Handle;
    DWORD Message[3], Written;

    if (!Console || Console->Magic != BASE_PSEUDOCONSOLE_MAGIC || Size.X <= 0 || Size.Y <= 0)
        return E_INVALIDARG;
    Message[0] = 8;
    Message[1] = Size.X;
    Message[2] = Size.Y;
    if (!WriteFile(Console->Signal, Message, sizeof(Message), &Written, NULL))
        return HRESULT_FROM_WIN32(GetLastError());
    if (Written != sizeof(Message)) return HRESULT_FROM_WIN32(ERROR_WRITE_FAULT);
    return S_OK;
}

VOID WINAPI
ClosePseudoConsole(PVOID Handle)
{
    PBASE_PSEUDOCONSOLE Console = Handle;
    if (!Console || Console->Magic != BASE_PSEUDOCONSOLE_MAGIC) return;
    Console->Magic = 0;
    CloseHandle(Console->Signal);
    if (WaitForSingleObject(Console->Process, 3000) == WAIT_TIMEOUT)
        TerminateProcess(Console->Process, 1);
    CloseHandle(Console->Process);
    HeapFree(GetProcessHeap(), 0, Console);
}
