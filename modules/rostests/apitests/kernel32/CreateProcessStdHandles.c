/*
 * PROJECT:     ReactOS api tests
 * LICENSE:     LGPL-2.1-or-later
 * PURPOSE:     Standard handles of a child process: when CreateProcess passes them and when it
 *              leaves them NULL (GUI child of a console parent, USESTDHANDLES without handle
 *              inheritance, DETACHED_PROCESS), explicit handle lists, and the call sequence of
 *              Rust's std::process::Command
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * The expected values are what Windows 10 22H2 does. The parent gives itself real console
 * standard handles (CONIN$/CONOUT$) so the result does not depend on how the test is run. The
 * child is this very program; a copy with the GUI subsystem flag set serves as the GUI child.
 */

#include "precomp.h"

#ifndef EXTENDED_STARTUPINFO_PRESENT
#define EXTENDED_STARTUPINFO_PRESENT 0x00080000
#endif

#define MAX_SLOTS 64
#define MODE_REPORT 0
#define MODE_RUST   1

typedef struct
{
    ULONG Done;
    HANDLE Value[3];
    ULONG Type[3];
    ULONG DupError[3];  /* 0 = DuplicateHandle works */
    ULONG ListHandleValid;  /* the parent's event handle value is open in the child */
    ULONG ListHandleSet;    /* ... and SetEvent works on it */
    ULONG ListSignaled;     /* the parent's event was signaled once the child exited (parent side) */
    /* MODE_RUST: the Rust standard library's spawn, run inside the child */
    ULONG RustDupError[3];
    ULONG RustCreateOk, RustCreateError, RustLeafDone;
    ULONG LeafSlot;
} SLOT;

typedef struct
{
    HANDLE ListHandle;      /* an inheritable event the parent may put in a handle list */
    WCHAR Image[MAX_PATH], Mapping[80];  /* the console program, and the name of this mapping */
    SLOT Slot[MAX_SLOTS];
} REPORT;

static REPORT *Report;
static WCHAR Image[MAX_PATH], GuiImage[MAX_PATH], MappingName[80];
static SECURITY_ATTRIBUTES Inheritable = {sizeof(SECURITY_ATTRIBUTES), NULL, TRUE};
static ULONG NextSlot;
static HANDLE ConIn, ConOut, ConErr;   /* the parent's console handles, inheritable */

typedef BOOL (WINAPI *INITIALIZE_LIST)(LPPROC_THREAD_ATTRIBUTE_LIST, DWORD, DWORD, PSIZE_T);
typedef BOOL (WINAPI *UPDATE_LIST)(LPPROC_THREAD_ATTRIBUTE_LIST, DWORD, DWORD_PTR,
                                 PVOID, SIZE_T, PVOID, PSIZE_T);
typedef VOID (WINAPI *DELETE_LIST)(LPPROC_THREAD_ATTRIBUTE_LIST);
static INITIALIZE_LIST pInitialize;
static UPDATE_LIST pUpdate;
static DELETE_LIST pDelete;

static const DWORD StdId[3] = {STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE};

/* ------------------------------------------------------------------ child side */

static VOID RecordStd(SLOT *S)
{
    ULONG i;

    for (i = 0; i < 3; ++i)
    {
        HANDLE h = GetStdHandle(StdId[i]), Copy = NULL;

        S->Value[i] = h;
        S->Type[i] = (h && h != INVALID_HANDLE_VALUE) ? GetFileType(h) : FILE_TYPE_UNKNOWN;
        S->DupError[i] = 0;
        if (h && h != INVALID_HANDLE_VALUE)
        {
            if (DuplicateHandle(GetCurrentProcess(), h, GetCurrentProcess(), &Copy, 0, FALSE,
                                DUPLICATE_SAME_ACCESS))
                CloseHandle(Copy);
            else
                S->DupError[i] = GetLastError();
        }
        else
        {
            S->DupError[i] = ERROR_INVALID_HANDLE;
        }
    }
}

/* What Rust's std::process::Command::spawn does with Stdio::Inherit, step by step */
static VOID RustSpawn(SLOT *S)
{
    HANDLE Dup[3] = {NULL, NULL, NULL};
    STARTUPINFOW si = {sizeof(si)};
    PROCESS_INFORMATION pi;
    WCHAR Cmd[2 * MAX_PATH + 80];
    ULONG i;

    for (i = 0; i < 3; ++i)
    {
        HANDLE h = GetStdHandle(StdId[i]);

        S->RustDupError[i] = 0;
        if (!h || h == INVALID_HANDLE_VALUE)
            continue;   /* no standard handle: Rust propagates a null handle */
        if (!DuplicateHandle(GetCurrentProcess(), h, GetCurrentProcess(), &Dup[i], 0, TRUE,
                             DUPLICATE_SAME_ACCESS))
            S->RustDupError[i] = GetLastError();
    }

    if (Dup[0] || Dup[1] || Dup[2])
    {
        si.dwFlags = STARTF_USESTDHANDLES;
        si.hStdInput = Dup[0];
        si.hStdOutput = Dup[1];
        si.hStdError = Dup[2];
    }
    S->LeafSlot = S - Report->Slot + 1;
    StringCchPrintfW(Cmd, _countof(Cmd), L"\"%s\" CreateProcessStdHandles child %s %lu leaf",
                     Report->Image, Report->Mapping, S->LeafSlot);
    SetLastError(0);
    S->RustCreateOk = CreateProcessW(Report->Image, Cmd, NULL, NULL, TRUE,
                                     CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT,
                                     NULL, NULL, &si, &pi);
    S->RustCreateError = S->RustCreateOk ? 0 : GetLastError();
    if (S->RustCreateOk)
    {
        WaitForSingleObject(pi.hProcess, 30000);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        S->RustLeafDone = Report->Slot[S->LeafSlot].Done;
    }
    for (i = 0; i < 3; ++i)
        if (Dup[i]) CloseHandle(Dup[i]);
}

static VOID Child(PCSTR Name, ULONG SlotIndex, PCSTR Mode)
{
    HANDLE Mapping = OpenFileMappingA(FILE_MAP_ALL_ACCESS, FALSE, Name);
    REPORT *Data;
    SLOT *S;
    DWORD Flags;

    if (!Mapping) ExitProcess(90);
    Data = MapViewOfFile(Mapping, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(*Data));
    if (!Data || SlotIndex >= MAX_SLOTS) ExitProcess(91);
    Report = Data;
    S = &Data->Slot[SlotIndex];
    RecordStd(S);
    /* A handle table that is empty or holds other objects can still have an open handle with the
     * same numeric value, so the handle must also be the parent's event: signal it, the parent
     * looks at the event afterwards. */
    S->ListHandleValid = GetHandleInformation(Data->ListHandle, &Flags);
    S->ListHandleSet = S->ListHandleValid && SetEvent(Data->ListHandle);
    if (!strcmp(Mode, "rust")) RustSpawn(S);
    S->Done = 1;
    ExitProcess(0);
}

/* ----------------------------------------------------------------- parent side */

/* A copy of this program whose PE header says "GUI subsystem" */
static BOOL MakeGuiCopy(VOID)
{
    WCHAR Dir[MAX_PATH];
    UCHAR Header[1024];
    HANDLE File;
    DWORD Read, Written;
    IMAGE_DOS_HEADER *Dos = (IMAGE_DOS_HEADER *)Header;
    IMAGE_NT_HEADERS32 *Nt;

    GetTempPathW(_countof(Dir), Dir);
    StringCchPrintfW(GuiImage, _countof(GuiImage), L"%scpsh%lu-gui.exe", Dir, GetCurrentProcessId());
    if (!CopyFileW(Image, GuiImage, FALSE))
        return FALSE;
    File = CreateFileW(GuiImage, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (File == INVALID_HANDLE_VALUE)
        return FALSE;
    if (!ReadFile(File, Header, sizeof(Header), &Read, NULL) || Read != sizeof(Header) ||
        Dos->e_magic != IMAGE_DOS_SIGNATURE || Dos->e_lfanew > sizeof(Header) - sizeof(*Nt))
    {
        CloseHandle(File);
        return FALSE;
    }
    Nt = (IMAGE_NT_HEADERS32 *)(Header + Dos->e_lfanew);
    /* Subsystem has the same offset in the PE32 and PE32+ optional headers */
    Nt->OptionalHeader.Subsystem = IMAGE_SUBSYSTEM_WINDOWS_GUI;
    SetFilePointer(File, 0, NULL, FILE_BEGIN);
    Written = 0;
    WriteFile(File, Header, sizeof(Header), &Written, NULL);
    CloseHandle(File);
    return Written == sizeof(Header);
}

typedef struct
{
    BOOL Gui;
    DWORD Flags;
    BOOL Inherit;
    BOOL UseStd;
    DWORD StartFlags;   /* more STARTF_* flags; In/Out/Err then carry the shell's values */
    HANDLE In, Out, Err;
    HANDLE *List;
    DWORD ListCount;
    PCSTR Mode;
} SPAWN;

/* Runs the child; returns its slot, or NULL (with *Error) if CreateProcess failed */
static SLOT *Spawn(const SPAWN *P, DWORD *Error)
{
    STARTUPINFOEXW si;
    PROCESS_INFORMATION pi;
    WCHAR Cmd[2 * MAX_PATH + 80];
    ULONG Index = NextSlot++;
    if (!strcmp(P->Mode, "rust")) NextSlot++;  /* the grandchild reports in the slot after it */
    SIZE_T Size = 0;
    DWORD Flags = P->Flags;
    BOOL Ret;

    ZeroMemory(&si, sizeof(si));
    si.StartupInfo.cb = sizeof(si.StartupInfo);
    if (P->UseStd || P->StartFlags)
    {
        si.StartupInfo.dwFlags = (P->UseStd ? STARTF_USESTDHANDLES : 0) | P->StartFlags;
        si.StartupInfo.hStdInput = P->In;
        si.StartupInfo.hStdOutput = P->Out;
        si.StartupInfo.hStdError = P->Err;
    }
    if (P->List)
    {
        pInitialize(NULL, 1, 0, &Size);
        si.lpAttributeList = HeapAlloc(GetProcessHeap(), 0, Size);
        si.StartupInfo.cb = sizeof(si);
        pInitialize(si.lpAttributeList, 1, 0, &Size);
        pUpdate(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, P->List,
                P->ListCount * sizeof(HANDLE), NULL, NULL);
        Flags |= EXTENDED_STARTUPINFO_PRESENT;
    }
    StringCchPrintfW(Cmd, _countof(Cmd), L"\"%s\" CreateProcessStdHandles child %s %lu %S",
                     P->Gui ? GuiImage : Image, MappingName, Index, P->Mode);
    ResetEvent(Report->ListHandle);
    SetLastError(0xdeadbeef);
    Ret = CreateProcessW(P->Gui ? GuiImage : Image, Cmd, NULL, NULL, P->Inherit, Flags, NULL, NULL,
                         &si.StartupInfo, &pi);
    *Error = Ret ? 0 : GetLastError();
    if (P->List)
    {
        pDelete(si.lpAttributeList);
        HeapFree(GetProcessHeap(), 0, si.lpAttributeList);
    }
    if (!Ret)
        return NULL;
    ok(WaitForSingleObject(pi.hProcess, 60000) == WAIT_OBJECT_0, "child did not exit\n");
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    ok(Report->Slot[Index].Done, "child did not report\n");
    Report->Slot[Index].ListSignaled = WaitForSingleObject(Report->ListHandle, 0) == WAIT_OBJECT_0;
    return &Report->Slot[Index];
}

/* Did the child inherit the parent's event (not merely have some handle with the same value)? */
static BOOL ListHandleInherited(const SLOT *S)
{
    return S->ListHandleSet && S->ListSignaled;
}

static BOOL IsValid(const SLOT *S, ULONG i)
{
    return S->Value[i] && S->Value[i] != INVALID_HANDLE_VALUE && S->DupError[i] == 0;
}

#define ExpectNull(S, i, What) \
    ok((S)->Value[i] == NULL, "%s: std handle %lu is %p, expected NULL\n", What, (ULONG)(i), (S)->Value[i])
#define ExpectValid(S, i, What) \
    ok(IsValid(S, i), "%s: std handle %lu is %p (DuplicateHandle error %lu), expected a usable handle\n", \
       What, (ULONG)(i), (S)->Value[i], (S)->DupError[i])

static VOID Run(PCSTR Name, const SPAWN *P, PCSTR Expect /* "NNN", "VVV", "VNN", "VVN" per std handle */)
{
    DWORD Error;
    SLOT *S = Spawn(P, &Error);
    ULONG i;

    ok(S != NULL, "%s: CreateProcess failed with %lu\n", Name, Error);
    if (!S) return;
    for (i = 0; i < 3; ++i)
    {
        if (Expect[i] == 'N') ExpectNull(S, i, Name);
        else if (Expect[i] == 'V') ExpectValid(S, i, Name);
    }
}

static VOID TestStandardHandles(HANDLE Nul)
{
    SPAWN P;
    ULONG Gui;

    for (Gui = 0; Gui < 2; ++Gui)
    {
        PCSTR Kind = Gui ? "GUI child" : "console child";
        char Name[96];

#define BEGIN(Fmt) \
        ZeroMemory(&P, sizeof(P)); P.Gui = Gui; P.Mode = "report"; \
        StringCchPrintfA(Name, sizeof(Name), "%s, " Fmt, Kind)

        /* The parent's standard handles are console handles, handle table inherited */
        BEGIN("inherit, no STARTF_USESTDHANDLES");
        P.Inherit = TRUE;
        Run(Name, &P, Gui ? "NNN" : "VVV");

        BEGIN("no inherit, no STARTF_USESTDHANDLES");
        Run(Name, &P, Gui ? "NNN" : "VVV");   /* a console child attaches to the console anyway */

        BEGIN("DETACHED_PROCESS");
        P.Inherit = TRUE;
        P.Flags = DETACHED_PROCESS;
        Run(Name, &P, "NNN");

        if (Gui)
        {
            BEGIN("CREATE_NO_WINDOW");
            P.Inherit = TRUE;
            P.Flags = CREATE_NO_WINDOW;
            Run(Name, &P, "NNN");

            BEGIN("CREATE_NEW_CONSOLE");
            P.Inherit = TRUE;
            P.Flags = CREATE_NEW_CONSOLE;
            Run(Name, &P, "NNN");
        }
        else
        {
            BEGIN("CREATE_NO_WINDOW");
            P.Inherit = TRUE;
            P.Flags = CREATE_NO_WINDOW;
            Run(Name, &P, "VVV");
        }

        /* Explicit handles */
        BEGIN("USESTDHANDLES (NUL, NUL, NULL), inherit");
        P.Inherit = TRUE;
        P.UseStd = TRUE;
        P.In = P.Out = Nul;
        Run(Name, &P, "VVN");

        BEGIN("USESTDHANDLES (NULL, NULL, NULL), inherit");
        P.Inherit = TRUE;
        P.UseStd = TRUE;
        Run(Name, &P, "NNN");

        BEGIN("USESTDHANDLES (NUL, NUL, NULL), no inherit");
        P.UseStd = TRUE;
        P.In = P.Out = Nul;
        Run(Name, &P, "NNN");   /* Windows 8+: the handle table is not inherited, so no handles */

        if (Gui)
        {
            /* Explorer starts a program with the hot key of its shortcut in the standard
             * input field and its monitor in the standard output field */
            BEGIN("STARTF_USEHOTKEY");
            P.Inherit = TRUE;
            P.StartFlags = 0x200;
            P.In = (HANDLE)(ULONG_PTR)0x141;
            Run(Name, &P, "NNN");

            BEGIN("STARTF_SHELLPRIVATE");
            P.Inherit = TRUE;
            P.StartFlags = 0x400;
            P.Out = (HANDLE)(ULONG_PTR)0x20044;
            Run(Name, &P, "NNN");

            BEGIN("STARTF_USEHOTKEY and STARTF_SHELLPRIVATE");
            P.Inherit = TRUE;
            P.StartFlags = 0x600;
            P.In = (HANDLE)(ULONG_PTR)0x141;
            P.Out = (HANDLE)(ULONG_PTR)0x20044;
            Run(Name, &P, "NNN");
        }

        /* console handles given explicitly: a GUI child has no console to use them with */
        BEGIN("USESTDHANDLES (console x3), inherit");
        P.Inherit = TRUE;
        P.UseStd = TRUE;
        P.In = ConIn;
        P.Out = ConOut;
        P.Err = ConErr;
        Run(Name, &P, Gui ? "NNN" : "VVV");

        BEGIN("USESTDHANDLES (console x3), no inherit");
        P.UseStd = TRUE;
        P.In = ConIn;
        P.Out = ConOut;
        P.Err = ConErr;
        Run(Name, &P, "NNN");

        BEGIN("USESTDHANDLES (NUL, NUL, NUL), CREATE_NO_WINDOW, inherit");
        P.Inherit = TRUE;
        P.UseStd = TRUE;
        P.Flags = CREATE_NO_WINDOW;
        P.In = P.Out = P.Err = Nul;
        Run(Name, &P, "VVV");
#undef BEGIN
    }
}

/* What cmd.exe does for "program < nul": only standard input is replaced */
static VOID TestStdinRedirected(HANDLE Nul)
{
    HANDLE OldIn = GetStdHandle(STD_INPUT_HANDLE);
    SPAWN P;
    ULONG Gui;

    SetStdHandle(STD_INPUT_HANDLE, Nul);
    for (Gui = 0; Gui < 2; ++Gui)
    {
        char Name[96];

        ZeroMemory(&P, sizeof(P));
        P.Gui = Gui;
        P.Mode = "report";
        P.Inherit = TRUE;
        StringCchPrintfA(Name, sizeof(Name), "%s, stdin redirected, console stdout and stderr",
                         Gui ? "GUI child" : "console child");
        /* the GUI child keeps the file handle and loses the console ones */
        Run(Name, &P, Gui ? "VNN" : "VVV");
    }
    SetStdHandle(STD_INPUT_HANDLE, OldIn);
}

static VOID TestRustSequence(HANDLE Nul)
{
    HANDLE OldIn = GetStdHandle(STD_INPUT_HANDLE);
    SPAWN P;
    ULONG Pass, i;

    /* A GUI program started from a console (a Rust launcher run from cmd.exe) spawns a helper
     * with Stdio::Inherit: GetStdHandle, DuplicateHandle(inheritable), CreateProcessW with
     * STARTF_USESTDHANDLES. No step may fail. */
    for (Pass = 0; Pass < 2; ++Pass)
    {
        const char *Name = Pass ? "Rust spawn in a GUI child, stdin redirected"
                                : "Rust spawn in a GUI child";
        DWORD Error;
        SLOT *S;

        if (Pass) SetStdHandle(STD_INPUT_HANDLE, Nul);
        ZeroMemory(&P, sizeof(P));
        P.Gui = TRUE;
        P.Inherit = TRUE;
        P.Mode = "rust";
        S = Spawn(&P, &Error);
        ok(S != NULL, "%s: CreateProcess failed with %lu\n", Name, Error);
        if (S)
        {
            for (i = 0; i < 3; ++i)
                ok(S->RustDupError[i] == 0, "%s: DuplicateHandle(std %lu = %p) failed with %lu\n",
                   Name, i, S->Value[i], S->RustDupError[i]);
            ok(S->RustCreateOk, "%s: CreateProcessW failed with %lu\n", Name, S->RustCreateError);
            ok(S->RustLeafDone, "%s: the grandchild did not run\n", Name);
            if (Pass) ExpectValid(S, 0, Name);
            else ExpectNull(S, 0, Name);
            ExpectNull(S, 1, Name);
            ExpectNull(S, 2, Name);
        }
    }
    SetStdHandle(STD_INPUT_HANDLE, OldIn);
}

static VOID TestHandleList(HANDLE ConOut)
{
    SPAWN P;
    HANDLE List[3], Closed;
    DWORD Error;
    SLOT *S;
    ULONG Gui;

    if (!pInitialize || !pUpdate || !pDelete)
    {
        skip("Process attributes unavailable\n");
        return;
    }
    Closed = CreateEventW(&Inheritable, TRUE, FALSE, NULL);
    CloseHandle(Closed);

    for (Gui = 0; Gui < 2; ++Gui)
    {
        PCSTR Kind = Gui ? "GUI child" : "console child";

#define BEGIN() ZeroMemory(&P, sizeof(P)); P.Gui = Gui; P.Mode = "report"; P.Inherit = TRUE; \
                P.List = List
        /* a real inheritable handle */
        BEGIN();
        List[0] = Report->ListHandle;
        P.ListCount = 1;
        S = Spawn(&P, &Error);
        ok(S != NULL, "%s, list {event}: CreateProcess failed with %lu\n", Kind, Error);
        if (S) ok(ListHandleInherited(S), "%s, list {event}: the handle is not in the child\n", Kind);

        /* a NULL entry is accepted */
        BEGIN();
        List[0] = NULL;
        P.ListCount = 1;
        S = Spawn(&P, &Error);
        ok(S != NULL, "%s, list {NULL}: CreateProcess failed with %lu\n", Kind, Error);

        BEGIN();
        List[0] = Report->ListHandle;
        List[1] = NULL;
        P.ListCount = 2;
        S = Spawn(&P, &Error);
        ok(S != NULL, "%s, list {event, NULL}: CreateProcess failed with %lu\n", Kind, Error);
        if (S) ok(!ListHandleInherited(S), "%s, list {event, NULL}: a NULL entry makes the list empty\n", Kind);

        /* a console handle of the parent */
        BEGIN();
        List[0] = ConOut;
        P.ListCount = 1;
        S = Spawn(&P, &Error);
        ok(S != NULL, "%s, list {CONOUT$}: CreateProcess failed with %lu\n", Kind, Error);

        /* a handle that is not open, and one that is not inheritable */
        BEGIN();
        List[0] = Closed;
        P.ListCount = 1;
        S = Spawn(&P, &Error);
        ok(S == NULL && Error == ERROR_INVALID_PARAMETER,
           "%s, list {closed handle}: CreateProcess %s, error %lu\n", Kind, S ? "succeeded" : "failed", Error);

        List[0] = (HANDLE)(ULONG_PTR)0x7777;
        S = Spawn(&P, &Error);
        ok(S == NULL && Error == ERROR_INVALID_PARAMETER,
           "%s, list {0x7777}: CreateProcess %s, error %lu\n", Kind, S ? "succeeded" : "failed", Error);

        List[0] = CreateEventW(NULL, TRUE, FALSE, NULL);
        S = Spawn(&P, &Error);
        ok(S == NULL && Error == ERROR_INVALID_PARAMETER,
           "%s, list {non-inheritable}: CreateProcess %s, error %lu\n", Kind, S ? "succeeded" : "failed", Error);
        CloseHandle(List[0]);

        /* a list requires handle inheritance */
        BEGIN();
        P.Inherit = FALSE;
        List[0] = Report->ListHandle;
        P.ListCount = 1;
        S = Spawn(&P, &Error);
        ok(S == NULL && Error == ERROR_INVALID_PARAMETER,
           "%s, list without inheritance: CreateProcess %s, error %lu\n", Kind, S ? "succeeded" : "failed", Error);

        /* standard handles outside the list are not usable in the child; ones inside are */
        BEGIN();
        List[0] = Report->ListHandle;
        P.ListCount = 1;
        P.UseStd = TRUE;
        P.In = P.Out = P.Err = NULL;
        Run(Gui ? "GUI child, list and USESTDHANDLES (NULL x3)" : "console child, list and USESTDHANDLES (NULL x3)",
            &P, "NNN");
#undef BEGIN
    }
}

START_TEST(CreateProcessStdHandles)
{
    HMODULE Kernel32 = GetModuleHandleW(L"kernel32.dll");
    HANDLE Mapping, Nul, OldIn, OldOut, OldErr;
    char **Argv;
    int Argc = winetest_get_mainargs(&Argv);

    if (Argc == 6 && !strcmp(Argv[2], "child"))
        Child(Argv[3], (ULONG)atoi(Argv[4]), Argv[5]);

    pInitialize = (INITIALIZE_LIST)GetProcAddress(Kernel32, "InitializeProcThreadAttributeList");
    pUpdate = (UPDATE_LIST)GetProcAddress(Kernel32, "UpdateProcThreadAttribute");
    pDelete = (DELETE_LIST)GetProcAddress(Kernel32, "DeleteProcThreadAttributeList");

    GetModuleFileNameW(NULL, Image, _countof(Image));
    StringCchPrintfW(MappingName, _countof(MappingName), L"Local\\CPSH-%lu", GetCurrentProcessId());
    Mapping = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, sizeof(*Report),
                                 MappingName);
    ok(Mapping != NULL, "CreateFileMapping: %lu\n", GetLastError());
    if (!Mapping) return;
    Report = MapViewOfFile(Mapping, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(*Report));
    if (!Report)
    {
        CloseHandle(Mapping);
        return;
    }
    if (!MakeGuiCopy())
    {
        skip("Cannot make a GUI copy of the test program\n");
        goto Done;
    }

    Report->ListHandle = CreateEventW(&Inheritable, TRUE, FALSE, NULL);
    StringCchCopyW(Report->Image, _countof(Report->Image), Image);
    StringCchCopyW(Report->Mapping, _countof(Report->Mapping), MappingName);
    Nul = CreateFileW(L"NUL", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                      &Inheritable, OPEN_EXISTING, 0, NULL);
    ConIn = CreateFileW(L"CONIN$", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                        &Inheritable, OPEN_EXISTING, 0, NULL);
    ConOut = CreateFileW(L"CONOUT$", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                         &Inheritable, OPEN_EXISTING, 0, NULL);
    /* a handle of its own for standard error: Windows treats one handle in two roles specially */
    ConErr = CreateFileW(L"CONOUT$", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                         &Inheritable, OPEN_EXISTING, 0, NULL);
    if (Nul == INVALID_HANDLE_VALUE || ConIn == INVALID_HANDLE_VALUE || ConOut == INVALID_HANDLE_VALUE ||
        ConErr == INVALID_HANDLE_VALUE)
    {
        skip("No console or NUL device (%lu)\n", GetLastError());
        goto Cleanup;
    }

    OldIn = GetStdHandle(STD_INPUT_HANDLE);
    OldOut = GetStdHandle(STD_OUTPUT_HANDLE);
    OldErr = GetStdHandle(STD_ERROR_HANDLE);
    SetStdHandle(STD_INPUT_HANDLE, ConIn);
    SetStdHandle(STD_OUTPUT_HANDLE, ConOut);
    SetStdHandle(STD_ERROR_HANDLE, ConErr);

    TestStandardHandles(Nul);
    TestStdinRedirected(Nul);
    TestRustSequence(Nul);
    TestHandleList(ConOut);

    SetStdHandle(STD_INPUT_HANDLE, OldIn);
    SetStdHandle(STD_OUTPUT_HANDLE, OldOut);
    SetStdHandle(STD_ERROR_HANDLE, OldErr);

Cleanup:
    if (Nul != INVALID_HANDLE_VALUE) CloseHandle(Nul);
    if (ConIn != INVALID_HANDLE_VALUE) CloseHandle(ConIn);
    if (ConOut != INVALID_HANDLE_VALUE) CloseHandle(ConOut);
    if (ConErr != INVALID_HANDLE_VALUE) CloseHandle(ConErr);
    CloseHandle(Report->ListHandle);
    DeleteFileW(GuiImage);
Done:
    UnmapViewOfFile(Report);
    CloseHandle(Mapping);
}
