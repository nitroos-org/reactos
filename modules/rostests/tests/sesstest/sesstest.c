/*
 * PROJECT:     NitroOS tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Native image started by SMSS in the NitroSessions test session.
 *              Reports its session id as seen through the PEB, through
 *              ProcessSessionInformation, through SystemProcessInformation
 *              and through SystemSessionProcessInformation, then stays
 *              alive so that kernel tests can attach to its session.
 * COPYRIGHT:   Copyright 2026 Tomas Srnka
 */

#define WIN32_NO_STATUS
#include <windef.h>
#include <winbase.h>
#define NTOS_MODE_USER
#include <ndk/exfuncs.h>
#include <ndk/iofuncs.h>
#include <ndk/kefuncs.h>
#include <ndk/obfuncs.h>
#include <ndk/psfuncs.h>
#include <ndk/rtlfuncs.h>
#include <ntstrsafe.h>

static
ULONG
FindSpiSession(
    _In_ PSYSTEM_PROCESS_INFORMATION Spi,
    _In_ ULONG Length,
    _In_ HANDLE Pid,
    _Out_ PULONG Count)
{
    ULONG Offset = 0, Found = MAXULONG;

    *Count = 0;
    if (Length < sizeof(*Spi))
        return Found;

    for (;;)
    {
        PSYSTEM_PROCESS_INFORMATION Entry = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)Spi + Offset);
        (*Count)++;
        if (Entry->UniqueProcessId == Pid)
            Found = Entry->SessionId;
        if (!Entry->NextEntryOffset)
            break;
        Offset += Entry->NextEntryOffset;
        if (Offset + sizeof(*Entry) > Length)
            break;
    }
    return Found;
}

static
VOID
WriteReport(
    _In_ PCSTR Text,
    _In_ ULONG SessionId)
{
    WCHAR Path[64];
    UNICODE_STRING Name;
    OBJECT_ATTRIBUTES Attributes;
    IO_STATUS_BLOCK Iosb;
    HANDLE File;
    NTSTATUS Status;

    RtlStringCbPrintfW(Path, sizeof(Path), L"\\SystemRoot\\sesstest-%lu.txt", SessionId);
    RtlInitUnicodeString(&Name, Path);
    InitializeObjectAttributes(&Attributes, &Name, OBJ_CASE_INSENSITIVE, NULL, NULL);
    Status = NtCreateFile(&File,
                          FILE_GENERIC_WRITE,
                          &Attributes,
                          &Iosb,
                          NULL,
                          FILE_ATTRIBUTE_NORMAL,
                          FILE_SHARE_READ,
                          FILE_OVERWRITE_IF,
                          FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
                          NULL,
                          0);
    if (!NT_SUCCESS(Status))
    {
        DbgPrint("SESSTEST: cannot write %wZ, Status 0x%lx\n", &Name, Status);
        return;
    }
    NtWriteFile(File, NULL, NULL, NULL, &Iosb, (PVOID)Text, (ULONG)strlen(Text), NULL, NULL);
    NtClose(File);
}

int
__cdecl
_main(int argc, char *argv[], char *envp[], ULONG DebugFlag)
{
    NTSTATUS Status, SpiStatus, SessStatus;
    ULONG PebSession, PsiSession = MAXULONG, SpiSession = MAXULONG, SessSession = MAXULONG;
    ULONG SpiCount = 0, SessCount = 0, Length = 0, SessLength = 0;
    PROCESS_SESSION_INFORMATION SessionInfo;
    SYSTEM_SESSION_PROCESS_INFORMATION SessionProcessInfo;
    PVOID Buffer;
    SIZE_T BufferSize = 512 * 1024;
    HANDLE Pid = NtCurrentTeb()->ClientId.UniqueProcess;
    CHAR Text[512];
    LARGE_INTEGER Interval;

    PebSession = NtCurrentPeb()->SessionId;

    Status = NtQueryInformationProcess(NtCurrentProcess(),
                                       ProcessSessionInformation,
                                       &SessionInfo,
                                       sizeof(SessionInfo),
                                       NULL);
    if (NT_SUCCESS(Status))
        PsiSession = SessionInfo.SessionId;

    Buffer = RtlAllocateHeap(RtlGetProcessHeap(), 0, BufferSize);
    if (!Buffer)
        return STATUS_NO_MEMORY;

    SpiStatus = NtQuerySystemInformation(SystemProcessInformation,
                                         Buffer,
                                         (ULONG)BufferSize,
                                         &Length);
    if (NT_SUCCESS(SpiStatus))
        SpiSession = FindSpiSession(Buffer, Length, Pid, &SpiCount);

    /* Only the processes of our (kernel) session, which must include us */
    SessionProcessInfo.SessionId = PsiSession;
    SessionProcessInfo.SizeOfBuf = (ULONG)BufferSize;
    SessionProcessInfo.Buffer = Buffer;
    SessStatus = NtQuerySystemInformation(SystemSessionProcessInformation,
                                          &SessionProcessInfo,
                                          sizeof(SessionProcessInfo),
                                          &SessLength);
    if (NT_SUCCESS(SessStatus))
        SessSession = FindSpiSession(Buffer, SessLength, Pid, &SessCount);

    RtlStringCbPrintfA(Text, sizeof(Text),
                       "SESSTEST pid=%lu peb=%lu psi=%lu (0x%lx) spi=%lu (0x%lx, %lu procs) "
                       "sessproc=%lu (0x%lx, %lu procs, %lu bytes)\r\n",
                       HandleToUlong(Pid), PebSession, PsiSession, Status,
                       SpiSession, SpiStatus, SpiCount,
                       SessSession, SessStatus, SessCount, SessLength);
    DbgPrint("%s", Text);
    WriteReport(Text, PsiSession);

    RtlFreeHeap(RtlGetProcessHeap(), 0, Buffer);

    /* "exit" as the first argument: do not stay alive */
    if (argc > 1 && !_stricmp(argv[1], "exit"))
        return STATUS_SUCCESS;

    /* Stay alive, so that kernel tests can attach to this session */
    Interval.QuadPart = -600000000LL; /* 60 s */
    for (;;)
        NtDelayExecution(FALSE, &Interval);
}
