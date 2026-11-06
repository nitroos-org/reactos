/*
 * PROJECT:     NitroOS tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Sessions P1 (per-session namespace) test. Two modes:
 *
 *              No argument: a GUI-subsystem image that uses only kernel32 and
 *              ntdll, started by SMSS in session 1 (NitroSessions=4). It
 *              creates an event and a section under a plain name and under
 *              the Local\, Global\, Session\0\ and Session\1\ prefixes and
 *              writes the object-manager name each one resolved to, the
 *              targets of the namespace links of its session and the result
 *              of creating a Global\ section without SeCreateGlobalPrivilege
 *              to %SystemRoot%\sessns-<session>.txt. Then it waits for the
 *              session-0 peer's Global\ event and writes
 *              %SystemRoot%\sessns-<session>-peer.txt.
 *
 *              "peer": run from session 0. Checks that the session-1
 *              Global\ and Session\1\ objects are visible, that the plain
 *              name of session 1 is not, and creates Global\sessns-peer-ev
 *              for the session-1 image. Prints one PEER line per check; the
 *              exit code is the number of failed checks.
 *
 * COPYRIGHT:   Copyright 2026 Tomas Srnka
 */

#define WIN32_NO_STATUS
#include <windef.h>
#include <winbase.h>
#define NTOS_MODE_USER
#include <ndk/exfuncs.h>
#include <ndk/obfuncs.h>
#include <ndk/psfuncs.h>
#include <ndk/rtlfuncs.h>
#include <strsafe.h>
#include <stdio.h>

#ifndef SE_CREATE_GLOBAL_PRIVILEGE
#define SE_CREATE_GLOBAL_PRIVILEGE 30
#endif

static CHAR Report[12288];

static
VOID
Add(
    _In_ PCSTR Format,
    ...)
{
    va_list Args;
    size_t Used = strlen(Report);

    va_start(Args, Format);
    StringCbVPrintfA(Report + Used, sizeof(Report) - Used, Format, Args);
    va_end(Args);
}

static
VOID
WriteReportFile(
    _In_ PCWSTR Name,
    _In_ ULONG Session)
{
    WCHAR WinDir[MAX_PATH], Path[MAX_PATH + 48];
    HANDLE File;
    DWORD Written;

    if (!GetWindowsDirectoryW(WinDir, RTL_NUMBER_OF(WinDir)))
        return;
    StringCbPrintfW(Path, sizeof(Path), L"%s\\sessns-%lu%s.txt", WinDir, Session, Name);
    File = CreateFileW(Path, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS,
                       FILE_ATTRIBUTE_NORMAL, NULL);
    if (File == INVALID_HANDLE_VALUE)
        return;
    WriteFile(File, Report, (DWORD)strlen(Report), &Written, NULL);
    CloseHandle(File);
}

static
ULONG
OwnSession(VOID)
{
    PROCESS_SESSION_INFORMATION Info;

    if (!NT_SUCCESS(NtQueryInformationProcess(NtCurrentProcess(), ProcessSessionInformation,
                                              &Info, sizeof(Info), NULL)))
        return MAXULONG;
    return Info.SessionId;
}

/* The object-manager name of a handle, as ANSI text in Out */
static
VOID
NameOf(
    _In_ HANDLE Handle,
    _Out_writes_(OutSize) PSTR Out,
    _In_ size_t OutSize)
{
    UCHAR Buffer[600];
    POBJECT_NAME_INFORMATION Info = (POBJECT_NAME_INFORMATION)Buffer;
    ULONG Length;
    NTSTATUS Status;

    RtlZeroMemory(Buffer, sizeof(Buffer));
    Status = NtQueryObject(Handle, ObjectNameInformation, Info, sizeof(Buffer) - sizeof(WCHAR), &Length);
    if (NT_SUCCESS(Status))
        StringCbPrintfA(Out, OutSize, "%.*S", (int)(Info->Name.Length / sizeof(WCHAR)), Info->Name.Buffer);
    else
        StringCbPrintfA(Out, OutSize, "? (0x%lx)", Status);
}

/* The target of an object-manager symbolic link, as ANSI text */
static
VOID
LinkTarget(
    _In_ PCWSTR Path,
    _Out_writes_(OutSize) PSTR Out,
    _In_ size_t OutSize)
{
    UNICODE_STRING Name, Target;
    OBJECT_ATTRIBUTES Attributes;
    WCHAR Buffer[256];
    HANDLE Link;
    NTSTATUS Status;

    RtlInitUnicodeString(&Name, Path);
    InitializeObjectAttributes(&Attributes, &Name, OBJ_CASE_INSENSITIVE, NULL, NULL);
    Status = NtOpenSymbolicLinkObject(&Link, SYMBOLIC_LINK_QUERY, &Attributes);
    if (!NT_SUCCESS(Status))
    {
        StringCbPrintfA(Out, OutSize, "open 0x%lx", Status);
        return;
    }
    Target.Buffer = Buffer;
    Target.Length = 0;
    Target.MaximumLength = sizeof(Buffer) - sizeof(WCHAR);
    Status = NtQuerySymbolicLinkObject(Link, &Target, NULL);
    if (NT_SUCCESS(Status))
        StringCbPrintfA(Out, OutSize, "%.*S", (int)(Target.Length / sizeof(WCHAR)), Target.Buffer);
    else
        StringCbPrintfA(Out, OutSize, "query 0x%lx", Status);
    NtClose(Link);
}

/* Whether a directory object of that name exists, or what is wrong */
static
VOID
DirState(
    _In_ PCWSTR Path,
    _Out_writes_(OutSize) PSTR Out,
    _In_ size_t OutSize)
{
    UNICODE_STRING Name;
    OBJECT_ATTRIBUTES Attributes;
    HANDLE Dir;
    NTSTATUS Status;

    RtlInitUnicodeString(&Name, Path);
    InitializeObjectAttributes(&Attributes, &Name, OBJ_CASE_INSENSITIVE, NULL, NULL);
    Status = NtOpenDirectoryObject(&Dir, DIRECTORY_QUERY, &Attributes);
    StringCbPrintfA(Out, OutSize, "open 0x%lx", Status);
    if (NT_SUCCESS(Status))
        NtClose(Dir);
}

/* Creates a symbolic link to \\SystemRoot under an absolute object name; returns the status */
static
NTSTATUS
TryLink(
    _In_ PCWSTR Path)
{
    UNICODE_STRING Name, Target = RTL_CONSTANT_STRING(L"\\SystemRoot");
    OBJECT_ATTRIBUTES Attributes;
    HANDLE Link;
    NTSTATUS Status;

    RtlInitUnicodeString(&Name, Path);
    InitializeObjectAttributes(&Attributes, &Name, OBJ_CASE_INSENSITIVE, NULL, NULL);
    Status = NtCreateSymbolicLinkObject(&Link, SYMBOLIC_LINK_ALL_ACCESS, &Attributes, &Target);
    if (NT_SUCCESS(Status))
        NtClose(Link);
    return Status;
}

static
HANDLE
Create(
    _In_ BOOL Section,
    _In_ PCWSTR Name,
    _Out_ PDWORD Error)
{
    HANDLE Handle;

    SetLastError(0);
    if (Section)
        Handle = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, 4096, Name);
    else
        Handle = CreateEventW(NULL, TRUE, FALSE, Name);
    *Error = Handle ? 0 : GetLastError();
    return Handle;
}

static
int
Peer(VOID)
{
    int Failed = 0, i;
    HANDLE Handle;
    DWORD Error = 0;

    printf("PEER session=%lu\n", OwnSession());

    /* The session-1 image creates its objects some seconds after boot */
    for (i = 0; i < 120; i++)
    {
        Handle = OpenEventW(SYNCHRONIZE, FALSE, L"Global\\sessns-ev-global");
        if (Handle)
        {
            CloseHandle(Handle);
            break;
        }
        Sleep(1000);
    }

    /* Global\ is shared between the sessions */
    Handle = OpenEventW(SYNCHRONIZE, FALSE, L"Global\\sessns-ev-global");
    printf("PEER global-event-visible=%d\n", Handle != NULL);
    Failed += (Handle == NULL);
    if (Handle) CloseHandle(Handle);
    Handle = OpenFileMappingW(FILE_MAP_READ, FALSE, L"Global\\sessns-sec-global");
    printf("PEER global-section-visible=%d\n", Handle != NULL);
    Failed += (Handle == NULL);
    if (Handle) CloseHandle(Handle);

    /* Session\0\ is session 0's own directory: same objects as Global\ */
    Handle = OpenEventW(SYNCHRONIZE, FALSE, L"Session\\0\\sessns-ev-s0");
    printf("PEER session0-prefix-event-visible=%d\n", Handle != NULL);
    Failed += (Handle == NULL);
    if (Handle) CloseHandle(Handle);

    /* The plain name of session 1 is session 1's own */
    Handle = OpenEventW(SYNCHRONIZE, FALSE, L"sessns-ev-plain");
    printf("PEER plain-name-isolated=%d (error %lu)\n", Handle == NULL, Handle ? 0 : GetLastError());
    Failed += (Handle != NULL);
    if (Handle) CloseHandle(Handle);
    Handle = OpenEventW(SYNCHRONIZE, FALSE, L"Local\\sessns-ev-local");
    printf("PEER local-name-isolated=%d (error %lu)\n", Handle == NULL, Handle ? 0 : GetLastError());
    Failed += (Handle != NULL);
    if (Handle) CloseHandle(Handle);

    /* Session\1\ reaches session 1's directory through BNOLINKS */
    Handle = OpenEventW(SYNCHRONIZE, FALSE, L"Session\\1\\sessns-ev-plain");
    printf("PEER session1-prefix-event-visible=%d (error %lu)\n", Handle != NULL, Handle ? 0 : GetLastError());
    Failed += (Handle == NULL);
    if (Handle) CloseHandle(Handle);

    /* The peer's own Global\ event, for session 1 to find */
    Handle = Create(FALSE, L"Global\\sessns-peer-ev", &Error);
    printf("PEER created-global-event=%d (error %lu)\n", Handle != NULL, Error);
    Failed += (Handle == NULL);

    /* Give the session-1 image time to see it */
    Sleep(15000);
    if (Handle) CloseHandle(Handle);

    printf("PEER failed=%d\n", Failed);
    return Failed;
}

int
WINAPI
wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPWSTR lpCmdLine, int nShowCmd)
{
    static const struct
    {
        PCWSTR Prefix;
        PCSTR Tag;
        PCSTR Label;
    } Kinds[] =
    {
        { L"",            "plain",  "plain" },
        { L"Local\\",     "local",  "Local\\" },
        { L"Global\\",    "global", "Global\\" },
        { L"Session\\0\\", "s0",    "Session\\0\\" },
        { L"Session\\1\\", "s1",    "Session\\1\\" },
    };
    static const PCWSTR Links[] =
    {
        L"\\Sessions\\1\\BaseNamedObjects\\Global",
        L"\\Sessions\\1\\BaseNamedObjects\\Local",
        L"\\Sessions\\1\\BaseNamedObjects\\Session",
        L"\\Sessions\\1\\BaseNamedObjects\\AppContainerNamedObjects",
        L"\\Sessions\\BNOLINKS\\0",
        L"\\Sessions\\BNOLINKS\\1",
        L"\\Sessions\\0\\Windows",
        L"\\BaseNamedObjects\\Global",
        L"\\BaseNamedObjects\\Local",
        L"\\BaseNamedObjects\\Session",
    };
    static const PCWSTR Dirs[] =
    {
        L"\\Sessions\\1\\BaseNamedObjects\\Restricted",
        L"\\Sessions\\1\\AppContainerNamedObjects",
        L"\\Sessions\\1\\Windows",
        L"\\Sessions\\1\\DosDevices",
        L"\\BaseNamedObjects\\Restricted",
    };
    WCHAR Name[96];
    CHAR Resolved[200];
    ULONG Session, i, Kind;
    DWORD Error;
    HANDLE Handle, Peer0;
    BOOL Priv;
    BOOLEAN Old;
    NTSTATUS Status;

    if (lpCmdLine && wcsstr(lpCmdLine, L"peer"))
        return Peer();

    Session = OwnSession();
    Add("SESSNS session=%lu peb=%lu\r\n", Session, NtCurrentPeb()->SessionId);

    /* Event and section under every prefix: the name each one resolved to */
    for (Kind = 0; Kind < RTL_NUMBER_OF(Kinds); Kind++)
    {
        for (i = 0; i < 2; i++)
        {
            StringCbPrintfW(Name, sizeof(Name), L"%lssessns-%S-%S",
                            Kinds[Kind].Prefix, i ? "sec" : "ev", Kinds[Kind].Tag);
            Handle = Create(i, Name, &Error);
            Resolved[0] = ANSI_NULL;
            if (Handle)
                NameOf(Handle, Resolved, sizeof(Resolved));
            Add("NAME %s %s -> %s (error %lu)\r\n", i ? "section" : "event",
                Kinds[Kind].Label, Handle ? Resolved : "-", Error);
            /* Keep them open: the peer opens them */
        }
    }

    /* Links and directories that make up the session's namespace */
    for (i = 0; i < RTL_NUMBER_OF(Links); i++)
    {
        LinkTarget(Links[i], Resolved, sizeof(Resolved));
        Add("LINK %S -> %s\r\n", Links[i], Resolved);
    }
    for (i = 0; i < RTL_NUMBER_OF(Dirs); i++)
    {
        DirState(Dirs[i], Resolved, sizeof(Resolved));
        Add("DIR %S %s\r\n", Dirs[i], Resolved);
    }

    /*
     * S4: without SeCreateGlobalPrivilege a section cannot be created in
     * another session's directory (Global\ is session 0's); an event can,
     * and the session's own directory is not restricted.
     */
    Status = RtlAdjustPrivilege(SE_CREATE_GLOBAL_PRIVILEGE, FALSE, FALSE, &Old);
    Add("S4 privilege disabled: 0x%lx (was %d)\r\n", Status, Old);
    Priv = NT_SUCCESS(Status);
    if (Priv)
    {
        Handle = Create(TRUE, L"Global\\sessns-sec-denied", &Error);
        Add("S4 Global section without privilege: %s (error %lu)\r\n", Handle ? "created" : "failed", Error);
        if (Handle) CloseHandle(Handle);
        Handle = Create(TRUE, L"Session\\0\\sessns-sec-denied", &Error);
        Add("S4 Session\\0 section without privilege: %s (error %lu)\r\n", Handle ? "created" : "failed", Error);
        if (Handle) CloseHandle(Handle);
        Handle = Create(FALSE, L"Global\\sessns-ev-noprivilege", &Error);
        Add("S4 Global event without privilege: %s (error %lu)\r\n", Handle ? "created" : "failed", Error);
        if (Handle) CloseHandle(Handle);
        Handle = Create(TRUE, L"Local\\sessns-sec-local-noprivilege", &Error);
        Add("S4 Local section without privilege: %s (error %lu)\r\n", Handle ? "created" : "failed", Error);
        if (Handle) CloseHandle(Handle);
        Add("S4 symbolic link in session 0's directory without privilege: 0x%lx\r\n",
            TryLink(L"\\BaseNamedObjects\\sessns-link-global"));
        Add("S4 symbolic link in the session's own directory without privilege: 0x%lx\r\n",
            TryLink(L"\\Sessions\\1\\BaseNamedObjects\\sessns-link-local"));
        Status = RtlAdjustPrivilege(SE_CREATE_GLOBAL_PRIVILEGE, TRUE, FALSE, &Old);
        Add("S4 privilege enabled again: 0x%lx\r\n", Status);
        Add("S4 symbolic link in session 0's directory with privilege: 0x%lx\r\n",
            TryLink(L"\\BaseNamedObjects\\sessns-link-global"));
        Handle = Create(TRUE, L"Global\\sessns-sec-again", &Error);
        Add("S4 Global section with privilege: %s (error %lu)\r\n", Handle ? "created" : "failed", Error);
        if (Handle) CloseHandle(Handle);
    }
    OutputDebugStringA(Report);
    WriteReportFile(L"", Session);

    /* Wait for the session-0 peer's Global\ event: session 0 -> session 1 */
    Report[0] = ANSI_NULL;
    Peer0 = NULL;
    for (i = 0; i < 240 && !Peer0; i++)
    {
        Peer0 = OpenEventW(SYNCHRONIZE, FALSE, L"Global\\sessns-peer-ev");
        if (!Peer0)
            Sleep(1000);
    }
    Add("PEERSEEN global-event-of-session-0-visible=%d\r\n", Peer0 != NULL);
    if (Peer0) CloseHandle(Peer0);
    WriteReportFile(L"-peer", Session);

    /* Stay alive: the objects live as long as their handles */
    for (;;)
        Sleep(60000);

    UNREFERENCED_PARAMETER(hInstance);
    UNREFERENCED_PARAMETER(hPrevInstance);
    UNREFERENCED_PARAMETER(nShowCmd);
    return 0;
}
