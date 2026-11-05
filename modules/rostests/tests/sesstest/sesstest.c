/*
 * PROJECT:     NitroOS tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Native image started by SMSS in the NitroSessions test session.
 *              Reports its session id as seen through the PEB, through
 *              ProcessSessionInformation, through SystemProcessInformation
 *              and through SystemSessionProcessInformation, then stays
 *              alive so that kernel tests can attach to its session.
 *              Arguments: "exit" (do not stay alive), "name=<tag>" (report
 *              file sesstest-<tag>.txt instead of sesstest-<session>.txt).
 *              The report also lists every csrss with its session.
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

/* "csrss=<pid>:<session>,..." for every csrss.exe in the snapshot */
static
VOID
ListCsrss(
    _In_ PSYSTEM_PROCESS_INFORMATION Spi,
    _In_ ULONG Length,
    _Out_writes_(Size) PCHAR Text,
    _In_ SIZE_T Size)
{
    static const WCHAR Csrss[] = L"csrss.exe";
    ULONG Offset = 0;
    UNICODE_STRING Name;
    SIZE_T Used;

    RtlStringCbCopyA(Text, Size, "csrss=");
    if (Length < sizeof(*Spi))
        return;

    RtlInitUnicodeString(&Name, Csrss);
    for (;;)
    {
        PSYSTEM_PROCESS_INFORMATION Entry = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)Spi + Offset);
        if (Entry->ImageName.Buffer && RtlEqualUnicodeString(&Entry->ImageName, &Name, TRUE))
        {
            Used = strlen(Text);
            RtlStringCbPrintfA(Text + Used, Size - Used, "%s%lu:%lu",
                               (Text[Used - 1] == '=') ? "" : ",",
                               HandleToUlong(Entry->UniqueProcessId), Entry->SessionId);
        }
        if (!Entry->NextEntryOffset)
            break;
        Offset += Entry->NextEntryOffset;
        if (Offset + sizeof(*Entry) > Length)
            break;
    }
}

static
VOID
WriteReport(
    _In_ PCSTR Text,
    _In_ ULONG SessionId,
    _In_opt_ PCSTR Tag)
{
    WCHAR Path[64];
    UNICODE_STRING Name;
    OBJECT_ATTRIBUTES Attributes;
    IO_STATUS_BLOCK Iosb;
    HANDLE File;
    NTSTATUS Status;

    if (Tag)
        RtlStringCbPrintfW(Path, sizeof(Path), L"\\SystemRoot\\sesstest-%.16S.txt", Tag);
    else
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
    CHAR Text[768], CsrssText[192];
    LARGE_INTEGER Interval;
    PCSTR Tag = NULL;
    BOOLEAN Exit = FALSE;
    int i;

    for (i = 1; i < argc; i++)
    {
        if (!_stricmp(argv[i], "exit"))
            Exit = TRUE;
        else if (!_strnicmp(argv[i], "name=", 5) && argv[i][5])
            Tag = argv[i] + 5;
    }
    CsrssText[0] = ANSI_NULL;

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
    {
        SpiSession = FindSpiSession(Buffer, Length, Pid, &SpiCount);
        ListCsrss(Buffer, Length, CsrssText, sizeof(CsrssText));
    }

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
                       "sessproc=%lu (0x%lx, %lu procs, %lu bytes) %s\r\n",
                       HandleToUlong(Pid), PebSession, PsiSession, Status,
                       SpiSession, SpiStatus, SpiCount,
                       SessSession, SessStatus, SessCount, SessLength, CsrssText);
    DbgPrint("%s", Text);
    WriteReport(Text, PsiSession, Tag);

    RtlFreeHeap(RtlGetProcessHeap(), 0, Buffer);

    /* "exit": do not stay alive */
    if (Exit)
        return STATUS_SUCCESS;

    /* Stay alive, so that kernel tests can attach to this session */
    Interval.QuadPart = -600000000LL; /* 60 s */
    for (;;)
        NtDelayExecution(FALSE, &Interval);
}
