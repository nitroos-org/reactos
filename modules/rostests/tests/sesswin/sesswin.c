/*
 * PROJECT:     NitroOS tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Windows image (GUI subsystem, kernel32 only) that SMSS starts
 *              in session 1 at NitroSessions=4. It checks that it is served
 *              by its own session's csrss: the csrss it connected to, the
 *              directories and the named-object directory that basesrv hands
 *              out, and a child process created through basesrv. The report
 *              goes to %SystemRoot%\sesswin-<session>.txt.
 * COPYRIGHT:   Copyright 2026 Tomas Srnka
 */

#define WIN32_NO_STATUS
#include <windef.h>
#include <winbase.h>
#include <wincon.h>
#define NTOS_MODE_USER
#include <ndk/exfuncs.h>
#include <ndk/obfuncs.h>
#include <ndk/psfuncs.h>
#include <ndk/rtlfuncs.h>
#include <strsafe.h>

/* ntdll export: the process id of the csrss this process is connected to */
HANDLE NTAPI CsrGetProcessId(VOID);

/* The session of a process, from SystemProcessInformation; MAXULONG if absent */
static
ULONG
SessionOfPid(
    _In_ HANDLE Pid)
{
    PSYSTEM_PROCESS_INFORMATION Entry;
    ULONG Size = 512 * 1024, Length = 0, Offset = 0, Found = MAXULONG;
    PVOID Buffer;
    NTSTATUS Status;

    Buffer = HeapAlloc(GetProcessHeap(), 0, Size);
    if (!Buffer)
        return Found;
    Status = NtQuerySystemInformation(SystemProcessInformation, Buffer, Size, &Length);
    if (NT_SUCCESS(Status) && Length >= sizeof(*Entry))
    {
        for (;;)
        {
            Entry = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)Buffer + Offset);
            if (Entry->UniqueProcessId == Pid)
            {
                Found = Entry->SessionId;
                break;
            }
            if (!Entry->NextEntryOffset)
                break;
            Offset += Entry->NextEntryOffset;
            if (Offset + sizeof(*Entry) > Length)
                break;
        }
    }
    HeapFree(GetProcessHeap(), 0, Buffer);
    return Found;
}

/* The kernel's session of this process */
static
ULONG
OwnSession(VOID)
{
    PROCESS_SESSION_INFORMATION Info;
    NTSTATUS Status;

    Status = NtQueryInformationProcess(NtCurrentProcess(), ProcessSessionInformation,
                                       &Info, sizeof(Info), NULL);
    return NT_SUCCESS(Status) ? Info.SessionId : MAXULONG;
}

/* Child: exit code = (its csrss is in its session ? 0x100 : 0) + its session */
static
int
Child(VOID)
{
    ULONG Session = OwnSession();
    ULONG CsrSession = SessionOfPid(CsrGetProcessId());

    return (int)(((CsrSession == Session) ? 0x100 : 0) + (Session & 0xFF));
}

int
WINAPI
wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPWSTR lpCmdLine, int nShowCmd)
{
    WCHAR WinDir[MAX_PATH], SelfPath[MAX_PATH], ChildCmd[MAX_PATH + 16], ReportPath[MAX_PATH];
    WCHAR EventName[64];
    CHAR Text[1536];
    UCHAR NameBuffer[512];
    POBJECT_NAME_INFORMATION NameInfo = (POBJECT_NAME_INFORMATION)NameBuffer;
    ULONG Session, PebSession, CsrSession, Ignored, Length;
    DWORD Kernel32Session = MAXULONG, ChildExit = MAXULONG, Written;
    HANDLE CsrPid, Event, File;
    STARTUPINFOW Si;
    PROCESS_INFORMATION Pi;
    BOOL Created, ConsoleAllocated;
    DWORD CreateError = 0;
    NTSTATUS Status;

    if (lpCmdLine && wcsstr(lpCmdLine, L"child"))
        return Child();

    Session = OwnSession();
    PebSession = NtCurrentPeb()->SessionId;
    if (!ProcessIdToSessionId(GetCurrentProcessId(), &Kernel32Session))
        Kernel32Session = MAXULONG;

    /* The csrss we are connected to, and its session */
    CsrPid = CsrGetProcessId();
    CsrSession = SessionOfPid(CsrPid);

    /* Data that basesrv hands out */
    if (!GetWindowsDirectoryW(WinDir, RTL_NUMBER_OF(WinDir)))
        StringCbCopyW(WinDir, sizeof(WinDir), L"?");

    /* The named-object directory of this session (from basesrv) */
    StringCbPrintfW(EventName, sizeof(EventName), L"sesswin-%lu", Session);
    Event = CreateEventW(NULL, TRUE, FALSE, EventName);
    RtlZeroMemory(NameBuffer, sizeof(NameBuffer));
    Status = STATUS_UNSUCCESSFUL;
    if (Event)
        Status = NtQueryObject(Event, ObjectNameInformation, NameInfo,
                               sizeof(NameBuffer) - sizeof(WCHAR), &Length);
    if (!NT_SUCCESS(Status))
        RtlInitUnicodeString(&NameInfo->Name, L"?");

    /* A child process: kernel32 registers it with our csrss (basesrv) */
    /* Not GetModuleFileName: SMSS starts us with an NT path */
    if (!GetSystemDirectoryW(SelfPath, RTL_NUMBER_OF(SelfPath)))
        StringCbCopyW(SelfPath, sizeof(SelfPath), L"C:\\ReactOS\\system32");
    StringCbPrintfW(ChildCmd, sizeof(ChildCmd), L"\"%s\\sesswin.exe\" child", SelfPath);
    RtlZeroMemory(&Si, sizeof(Si));
    Si.cb = sizeof(Si);
    Created = CreateProcessW(NULL, ChildCmd, NULL, NULL, FALSE, 0, NULL, NULL, &Si, &Pi);
    if (!Created)
        CreateError = GetLastError();
    if (Created)
    {
        WaitForSingleObject(Pi.hProcess, 60000);
        GetExitCodeProcess(Pi.hProcess, &ChildExit);
        CloseHandle(Pi.hThread);
        CloseHandle(Pi.hProcess);
    }

    /* A console needs the console server, which a headless session has not */
    ConsoleAllocated = AllocConsole();

    StringCbPrintfA(Text, sizeof(Text),
                    "SESSWIN pid=%lu psi=%lu peb=%lu kernel32=%lu csrss=%lu csrss-session=%lu "
                    "windir=%S bno=%.*S child=%s (%lu) child-session=%lu child-csrss-same=%lu "
                    "allocconsole=%d (%lu)\r\n",
                    GetCurrentProcessId(), Session, PebSession, Kernel32Session,
                    HandleToUlong(CsrPid), CsrSession, WinDir,
                    (int)(NameInfo->Name.Length / sizeof(WCHAR)), NameInfo->Name.Buffer,
                    Created ? "ok" : "failed", CreateError,
                    (ChildExit == MAXULONG) ? MAXULONG : (ChildExit & 0xFF),
                    (ChildExit == MAXULONG) ? MAXULONG : ((ChildExit >> 8) & 1),
                    ConsoleAllocated, ConsoleAllocated ? 0 : GetLastError());
    OutputDebugStringA(Text);

    StringCbPrintfW(ReportPath, sizeof(ReportPath), L"%s\\sesswin-%lu.txt", WinDir, Session);
    File = CreateFileW(ReportPath, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS,
                       FILE_ATTRIBUTE_NORMAL, NULL);
    if (File != INVALID_HANDLE_VALUE)
    {
        WriteFile(File, Text, (DWORD)strlen(Text), &Written, NULL);
        CloseHandle(File);
    }

    if (Event)
        CloseHandle(Event);
    UNREFERENCED_PARAMETER(Ignored);
    return 0;
}
