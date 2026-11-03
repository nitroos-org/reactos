/* ReactOS WoW64 process queries and filesystem views. SPDX-License-Identifier: LGPL-2.1-or-later */
#include "precomp.h"
#include <ndk/iofuncs.h>

static VOID CheckRelative(HANDLE Directory, CHAR Expected)
{
    UNICODE_STRING Name = RTL_CONSTANT_STRING(L"wow64-view-test.dat");
    OBJECT_ATTRIBUTES Attributes;
    IO_STATUS_BLOCK Io;
    HANDLE File;
    NTSTATUS Status;
    CHAR Value = 0;
    DWORD Bytes;
    InitializeObjectAttributes(&Attributes, &Name, OBJ_CASE_INSENSITIVE, Directory, NULL);
    Status = NtOpenFile(&File, FILE_GENERIC_READ, &Attributes, &Io, FILE_SHARE_READ,
                        FILE_SYNCHRONOUS_IO_NONALERT);
    ok(Status == STATUS_SUCCESS, "root-relative open: %08lx\n", Status);
    if (!NT_SUCCESS(Status)) return;
    ok(ReadFile(File, &Value, 1, &Bytes, NULL), "relative read failed\n");
    ok(Bytes == 1 && Value == Expected, "relative got %c, expected %c\n", Value, Expected);
    CloseHandle(File);
}

static VOID CheckFile(PCWSTR Path, CHAR Expected)
{
    HANDLE File = CreateFileW(Path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    CHAR Value = 0;
    DWORD Bytes = 0;
    ok(File != INVALID_HANDLE_VALUE, "open %S: %lu\n", Path, GetLastError());
    if (File == INVALID_HANDLE_VALUE) return;
    ok(ReadFile(File, &Value, 1, &Bytes, NULL), "read %S: %lu\n", Path, GetLastError());
    ok(Bytes == 1 && Value == Expected, "%S: got %u/%c, expected %c\n", Path, Bytes, Value, Expected);
    CloseHandle(File);
}

static BOOL PutFile(PCWSTR Path, CHAR Value)
{
    HANDLE File = CreateFileW(Path, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, 0, NULL);
    DWORD Bytes = 0;
    BOOL Result;
    ok(File != INVALID_HANDLE_VALUE, "create %S: %lu\n", Path, GetLastError());
    if (File == INVALID_HANDLE_VALUE) return FALSE;
    Result = WriteFile(File, &Value, 1, &Bytes, NULL);
    ok(Result && Bytes == 1, "write %S: %lu\n", Path, GetLastError());
    CloseHandle(File);
    return Result && Bytes == 1;
}


static VOID CheckGuestMachines(VOID)
{
    /* Windows 10 22H2 x64: S_OK, supported only for x86 (0x14c). Native i386 has no WoW64: assumed all unsupported */
    typedef HRESULT (WINAPI *PGUEST)(USHORT, BOOL *);
    static const USHORT machines[] = {0x14c, 0x8664, 0xaa64, 0x1c4};
    PGUEST pGuest = (PGUEST)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "IsWow64GuestMachineSupported");
    SYSTEM_INFO Native;
    BOOL Amd64Host, Supported;
    ULONG i;
    HRESULT Result;

    ok(pGuest != NULL, "IsWow64GuestMachineSupported missing\n");
    if (!pGuest) return;
    GetNativeSystemInfo(&Native);
    Amd64Host = Native.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64;
    for (i = 0; i < _countof(machines); ++i)
    {
        Supported = 0x55;
        Result = pGuest(machines[i], &Supported);
        ok(Result == S_OK, "machine 0x%x: hr 0x%lx\n", machines[i], Result);
        ok(Supported == (Amd64Host && machines[i] == 0x14c), "machine 0x%x: supported %d\n", machines[i], Supported);
    }
}

static VOID CheckEnvironment(BOOL Wow64)
{
    WCHAR Arch[32], Native[32], Program[MAX_PATH], Program32[MAX_PATH], Program64[MAX_PATH];
    WCHAR Common[MAX_PATH], Common32[MAX_PATH], Common64[MAX_PATH];
    DWORD Length;
    Length = GetEnvironmentVariableW(L"PROCESSOR_ARCHITECTURE", Arch, _countof(Arch));
    ok(Length != 0, "processor environment missing\n");
    if (!Wow64) return;
    ok(!wcscmp(Arch, L"x86"), "guest architecture environment: %S\n", Arch);
    Length = GetEnvironmentVariableW(L"PROCESSOR_ARCHITEW6432", Native, _countof(Native));
    ok(Length && !wcscmp(Native, L"AMD64"), "native architecture environment missing/wrong\n");
    Length = GetEnvironmentVariableW(L"ProgramFiles", Program, _countof(Program));
    ok(Length != 0, "ProgramFiles missing\n");
    Length = GetEnvironmentVariableW(L"ProgramFiles(x86)", Program32, _countof(Program32));
    ok(Length && !wcscmp(Program, Program32), "guest ProgramFiles view mismatch\n");
    Length = GetEnvironmentVariableW(L"ProgramW6432", Program64, _countof(Program64));
    ok(Length && wcscmp(Program, Program64), "native ProgramFiles alias missing/not distinct\n");
    Length = GetEnvironmentVariableW(L"CommonProgramFiles", Common, _countof(Common));
    ok(Length != 0, "CommonProgramFiles missing\n");
    Length = GetEnvironmentVariableW(L"CommonProgramFiles(x86)", Common32, _countof(Common32));
    ok(Length && !wcscmp(Common, Common32), "guest CommonProgramFiles view mismatch\n");
    Length = GetEnvironmentVariableW(L"CommonProgramW6432", Common64, _countof(Common64));
    ok(Length && wcscmp(Common, Common64), "native common alias missing/not distinct\n");
}

static VOID MakeParents(PWSTR Path)
{
    PWSTR p;
    for (p = Path + 3; *p; ++p)
    {
        if (*p != L'\\') continue;
        *p = 0;
        CreateDirectoryW(Path, NULL);
        *p = L'\\';
    }
}

static VOID CheckSharedDirectories(BOOL Wow64)
{
    static const PCWSTR names[] = {L"catroot", L"catroot2", L"driverstore", L"drivers\\etc", L"logfiles", L"spool"};
    WCHAR root[MAX_PATH], native[MAX_PATH], guest[MAX_PATH];
    PVOID old = NULL;
    ULONG i;
    GetWindowsDirectoryW(root, _countof(root));
    for (i = 0; i < _countof(names); ++i)
    {
        _snwprintf(native, _countof(native), L"%ls\\System32\\%ls\\wow64-shared-test.dat", root, names[i]);
        _snwprintf(guest, _countof(guest), L"%ls\\SysWOW64\\%ls\\wow64-shared-test.dat", root, names[i]);
        if (Wow64) ok(Wow64DisableWow64FsRedirection(&old), "shared disable\n");
        MakeParents(native); MakeParents(guest);
        if (PutFile(native, 'N') && PutFile(guest, 'G'))
        {
            if (Wow64) ok(Wow64RevertWow64FsRedirection(old), "shared revert\n");
            CheckFile(native, 'N');
            CheckFile(guest, 'G');
            ok(DeleteFileW(native), "shared delete %S: %lu\n", names[i], GetLastError());
            CheckFile(guest, 'G');
            ok(DeleteFileW(guest), "physical guest delete\n");
        }
        else if (Wow64) Wow64RevertWow64FsRedirection(old);
    }
}

static VOID CheckNativeFilesystem(VOID)
{
    WCHAR system[MAX_PATH], guest[MAX_PATH];
    PVOID old = (PVOID)0x1234;
    GetWindowsDirectoryW(system, _countof(system));
    wcscpy(guest, system);
    wcscat(system, L"\\System32\\wow64-native-test.dat");
    wcscat(guest, L"\\SysWOW64\\wow64-native-test.dat");
    MakeParents(guest);
    if (PutFile(system, 'N') && PutFile(guest, 'G'))
    {
        CheckFile(system, 'N'); CheckFile(guest, 'G');
        ok(!Wow64DisableWow64FsRedirection(&old), "native disable unexpectedly succeeded\n");
        ok(old == (PVOID)0x1234, "native failed disable changed token\n");
        CheckFile(system, 'N');
        ok(DeleteFileW(system), "native system delete\n");
        CheckFile(guest, 'G');
        ok(DeleteFileW(guest), "native guest delete\n");
    }
}

START_TEST(Wow64Environment)
{
    SYSTEM_INFO Info, Native;
    BOOL Wow64 = FALSE, Queried = FALSE;
    HANDLE Process, Directory;
    PVOID Old = (PVOID)0xdeadbeef, Nested;
    WCHAR System[MAX_PATH], Guest[MAX_PATH], Alias[MAX_PATH];

    ok(IsWow64Process(GetCurrentProcess(), &Wow64), "self query failed\n");
    Process = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, GetCurrentProcessId());
    ok(Process != NULL, "OpenProcess: %lu\n", GetLastError());
    if (Process)
    {
        ok(IsWow64Process(Process, &Queried), "real handle query: %lu\n", GetLastError());
        ok(Queried == Wow64, "pseudo/real handle disagreement\n");
        CloseHandle(Process);
    }
    /* Windows 10 22H2 accepts a NULL handle in 32 and 64-bit processes: TRUE, and "not a WoW64 process" */
    Queried = 0x55;
    ok(IsWow64Process(NULL, &Queried), "NULL handle rejected: %lu\n", GetLastError());
    ok(Queried == FALSE, "NULL handle reads as WoW64: %d\n", Queried);
    Queried = 0x55;
    ok(IsWow64Process(INVALID_HANDLE_VALUE, &Queried), "pseudo handle rejected: %lu\n", GetLastError());
    ok(Queried == Wow64, "pseudo handle disagrees: %d\n", Queried);
    CheckGuestMachines();
    CheckEnvironment(Wow64);
    CheckSharedDirectories(Wow64);
    GetSystemInfo(&Info);
    GetNativeSystemInfo(&Native);
    ok(Info.dwPageSize == Native.dwPageSize && Info.dwNumberOfProcessors == Native.dwNumberOfProcessors,
       "basic system information differs\n");
    if (!Wow64)
    {
        ok(!memcmp(&Info, &Native, sizeof(Info)), "native process system information differs\n");
        CheckNativeFilesystem();
        return;
    }
    ok(Info.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL, "guest architecture %u\n", Info.wProcessorArchitecture);
    ok(Native.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64, "native architecture %u\n", Native.wProcessorArchitecture);
    ok(Native.dwProcessorType == PROCESSOR_AMD_X8664, "native processor type %lu\n", Native.dwProcessorType);

    if (!Wow64DisableWow64FsRedirection(&Old))
    {
        ok(FALSE, "disable redirection: %lu\n", GetLastError());
        return;
    }
    ok(Old == NULL, "initial redirection token %p\n", Old);
    ok(Wow64DisableWow64FsRedirection(&Nested), "nested disable failed\n");
    ok(Nested != NULL, "nested token lost disabled state\n");
    ok(Wow64RevertWow64FsRedirection(Nested), "nested revert failed\n");
    GetWindowsDirectoryW(System, _countof(System));
    wcscpy(Guest, System);
    wcscpy(Alias, System);
    wcscat(System, L"\\System32");
    Directory = CreateFileW(System, FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                            NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
    ok(Directory != INVALID_HANDLE_VALUE, "open native directory: %lu\n", GetLastError());
    wcscat(System, L"\\wow64-view-test.dat");
    wcscat(Guest, L"\\SysWOW64\\wow64-view-test.dat");
    wcscat(Alias, L"\\Sysnative\\wow64-view-test.dat");
    if (PutFile(System, '6') && PutFile(Guest, '3'))
    {
        CheckFile(System, '6');
        if (Directory != INVALID_HANDLE_VALUE) CheckRelative(Directory, '6');
        ok(Wow64RevertWow64FsRedirection(Old), "revert failed\n");
        CheckFile(System, '3');
        if (Directory != INVALID_HANDLE_VALUE) CheckRelative(Directory, '3');
        CheckFile(Guest, '3');
        CheckFile(Alias, '6');
        ok(!Wow64DisableWow64FsRedirection(NULL), "NULL token pointer accepted\n");
        CheckFile(System, '3'); /* A failed disable must preserve state. */
        ok(DeleteFileW(System), "redirected delete: %lu\n", GetLastError());
        ok(GetFileAttributesW(Guest) == INVALID_FILE_ATTRIBUTES, "redirected delete left guest file\n");
        CheckFile(Alias, '6');
        ok(Wow64DisableWow64FsRedirection(&Old), "second disable failed\n");
        CheckFile(System, '6');
        ok(DeleteFileW(System), "native delete: %lu\n", GetLastError());

    }
    ok(Wow64RevertWow64FsRedirection(Old), "final revert failed\n");
    if (Directory != INVALID_HANDLE_VALUE) CloseHandle(Directory);
}

/* Installation values must agree with both architecture environments. */
START_TEST(Wow64ProgramFiles)
{
    SYSTEM_INFO Native;
    BOOL Wow64 = FALSE;
    HKEY Key;
    WCHAR Expected[MAX_PATH], Actual[MAX_PATH];
    static const PCWSTR Values[] = {L"ProgramFilesDir", L"CommonFilesDir"};
    static const PCWSTR Variables[2][2] = {
        {L"ProgramFiles(x86)", L"CommonProgramFiles(x86)"},
        {L"ProgramW6432", L"CommonProgramW6432"}
    };
    DWORD View, i, Length, Type;
    LONG Error;
    GetNativeSystemInfo(&Native);
    IsWow64Process(GetCurrentProcess(), &Wow64);
    if (Native.wProcessorArchitecture != PROCESSOR_ARCHITECTURE_AMD64)
    {
        skip("Two Program Files views require a 64-bit installation\n");
        return;
    }
    for (View = 0; View < 2; ++View)
    {
        Error = RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion",
            0, KEY_READ | (View ? KEY_WOW64_64KEY : KEY_WOW64_32KEY), &Key);
        ok(Error == ERROR_SUCCESS, "Program Files view %lu: %ld\n", View, Error);
        if (Error) continue;
        for (i = 0; i < _countof(Values); ++i)
        {
            Expected[0] = Actual[0] = 0;
            Length = GetEnvironmentVariableW(Variables[View][i], Expected, _countof(Expected));
            ok(Length != 0 && Length < _countof(Expected), "missing %S\n", Variables[View][i]);
            Type = 0; Length = sizeof(Actual);
            Error = RegQueryValueExW(Key, Values[i], NULL, &Type, (BYTE *)Actual, &Length);
            ok(Error == ERROR_SUCCESS && Type == REG_SZ && Length <= sizeof(Actual),
               "Program Files value %S view %lu: %ld type %lu length %lu\n", Values[i], View, Error, Type, Length);
            if (!Error && Length <= sizeof(Actual))
            {
                Actual[_countof(Actual) - 1] = 0;
                ok(!wcscmp(Expected, Actual), "%S view %lu: registry %S environment %S\n", Values[i], View, Actual, Expected);
                ok(GetFileAttributesW(Actual) != INVALID_FILE_ATTRIBUTES &&
                   (GetFileAttributesW(Actual) & FILE_ATTRIBUTE_DIRECTORY),
                   "Program Files directory %S missing\n", Actual);
            }
        }
        RegCloseKey(Key);
    }
}

START_TEST(Wow64EnvironmentBlock)
{
    typedef BOOL (WINAPI *CREATE_BLOCK)(PVOID *, HANDLE, BOOL);
    typedef BOOL (WINAPI *DESTROY_BLOCK)(PVOID);
    static const PCWSTR Names[] = {L"ProgramFiles", L"CommonProgramFiles",
        L"ProgramFiles(x86)", L"CommonProgramFiles(x86)", L"ProgramW6432", L"CommonProgramW6432"};
    WCHAR Expected[MAX_PATH], Actual[MAX_PATH];
    UNICODE_STRING Name, Value;
    HMODULE Module;
    CREATE_BLOCK CreateBlock;
    DESTROY_BLOCK DestroyBlock;
    PVOID Environment = NULL;
    SYSTEM_INFO Native;
    BOOL Wow64 = FALSE;
    ULONG i, Length;
    NTSTATUS Status;
    GetNativeSystemInfo(&Native);
    IsWow64Process(GetCurrentProcess(), &Wow64);
    if (Wow64 || Native.wProcessorArchitecture != PROCESSOR_ARCHITECTURE_AMD64)
    {
        skip("Native amd64 userenv fixture; guest userenv requires the GUI runtime\n");
        return;
    }
    Module = LoadLibraryW(L"userenv.dll");
    ok(Module != NULL, "load userenv: %lu\n", GetLastError());
    if (!Module) return;
    CreateBlock = (CREATE_BLOCK)GetProcAddress(Module, "CreateEnvironmentBlock");
    DestroyBlock = (DESTROY_BLOCK)GetProcAddress(Module, "DestroyEnvironmentBlock");
    ok(CreateBlock && DestroyBlock, "environment exports missing\n");
    if (CreateBlock && DestroyBlock)
    {
        ok(CreateBlock(&Environment, NULL, FALSE), "create non-inherited environment: %lu\n", GetLastError());
        if (Environment)
        {
            for (i = 0; i < _countof(Names); ++i)
            {
                Length = GetEnvironmentVariableW(Names[i], Expected, _countof(Expected));
                ok(Length && Length < _countof(Expected), "process %S missing\n", Names[i]);
                RtlInitUnicodeString(&Name, Names[i]);
                RtlInitEmptyUnicodeString(&Value, Actual, sizeof(Actual) - sizeof(WCHAR));
                Status = RtlQueryEnvironmentVariable_U(Environment, &Name, &Value);
                ok(Status == STATUS_SUCCESS, "block %S: %lx\n", Names[i], Status);
                if (NT_SUCCESS(Status))
                {
                    Actual[Value.Length / sizeof(WCHAR)] = 0;
                    ok(!wcscmp(Expected, Actual), "block %S: %S expected %S\n", Names[i], Actual, Expected);
                }
            }
            ok(DestroyBlock(Environment), "destroy environment block\n");
        }
    }
    FreeLibrary(Module);
}

/* Run "cmd.exe /c set" in a child that inherits the environment and return what it prints. */
static BOOL RunSet(PCWSTR Application, PSTR Output, DWORD Size)
{
    SECURITY_ATTRIBUTES Security = {sizeof(Security), NULL, TRUE};
    STARTUPINFOW Startup = {sizeof(Startup)};
    PROCESS_INFORMATION Info;
    WCHAR CommandLine[MAX_PATH + 32];
    HANDLE Read, Write;
    DWORD Total = 0, Bytes;

    if (!CreatePipe(&Read, &Write, &Security, 0)) return FALSE;
    SetHandleInformation(Read, HANDLE_FLAG_INHERIT, 0);
    Startup.dwFlags = STARTF_USESTDHANDLES;
    Startup.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    Startup.hStdOutput = Write;
    Startup.hStdError = Write;
    _snwprintf(CommandLine, _countof(CommandLine), L"\"%ls\" /c set", Application);
    if (!CreateProcessW(Application, CommandLine, NULL, NULL, TRUE, 0, NULL, NULL, &Startup, &Info))
    {
        skip("cannot start %S: %lu\n", Application, GetLastError());
        CloseHandle(Read);
        CloseHandle(Write);
        return FALSE;
    }
    CloseHandle(Write);
    while (Total < Size - 1 && ReadFile(Read, Output + Total, Size - 1 - Total, &Bytes, NULL) && Bytes)
        Total += Bytes;
    Output[Total] = 0;
    WaitForSingleObject(Info.hProcess, 60000);
    CloseHandle(Info.hProcess);
    CloseHandle(Info.hThread);
    CloseHandle(Read);
    return Total != 0;
}

static BOOL FindVariable(PCSTR Output, PCSTR Name, PSTR Value, DWORD Size)
{
    SIZE_T Length = strlen(Name);
    PCSTR Line = Output, End;

    Value[0] = 0;

    while (*Line)
    {
        End = strpbrk(Line, "\r\n");
        if (!_strnicmp(Line, Name, Length) && Line[Length] == '=')
        {
            SIZE_T Count = (End ? End : Line + strlen(Line)) - (Line + Length + 1);
            if (Count >= Size) Count = Size - 1;
            memcpy(Value, Line + Length + 1, Count);
            Value[Count] = 0;
            return TRUE;
        }
        if (!End) break;
        Line = End + strspn(End, "\r\n");
    }
    return FALSE;
}

static VOID GetOwn(PCSTR Name, PSTR Value, DWORD Size)
{
    Value[0] = 0;
    GetEnvironmentVariableA(Name, Value, Size);
}

/* A process starts a child of the other bitness: the child gets the environment of its own kind, and not what
 * its parent sees. A 64-bit child of a 32-bit process takes %CommonProgramFiles% for its own common files
 * folder (Office Click-to-Run). */
START_TEST(Wow64ChildEnvironment)
{
    static CHAR Output[65536];
    CHAR Value[MAX_PATH], Own[MAX_PATH];
    WCHAR Path[MAX_PATH];
    SYSTEM_INFO Native;
    BOOL Wow64 = FALSE;
    UINT Length;

    GetNativeSystemInfo(&Native);
    IsWow64Process(GetCurrentProcess(), &Wow64);
    if (Native.wProcessorArchitecture != PROCESSOR_ARCHITECTURE_AMD64)
    {
        skip("Two environments need a 64-bit installation\n");
        return;
    }
    Length = GetWindowsDirectoryW(Path, _countof(Path));
    ok(Length != 0 && Length + 20 < _countof(Path), "GetWindowsDirectory: %lu\n", GetLastError());
    if (!Length || Length + 20 >= _countof(Path)) return;
    wcscat(Path, Wow64 ? L"\\Sysnative\\cmd.exe" : L"\\System32\\cmd.exe");

    /* the 64-bit child */
    if (RunSet(Path, Output, sizeof(Output)))
    {
        ok(FindVariable(Output, "PROCESSOR_ARCHITECTURE", Value, sizeof(Value)) && !_stricmp(Value, "AMD64"),
           "64-bit child: PROCESSOR_ARCHITECTURE %s\n", Value);
        if (FindVariable(Output, "PROCESSOR_ARCHITEW6432", Value, sizeof(Value)))
            trace("64-bit child: PROCESSOR_ARCHITEW6432 = %s\n", Value);
        else
            trace("64-bit child: PROCESSOR_ARCHITEW6432 is not set\n");
        GetOwn("ProgramW6432", Own, sizeof(Own));
        ok(Own[0], "ProgramW6432 is missing in the parent\n");
        ok(FindVariable(Output, "ProgramFiles", Value, sizeof(Value)) && !_stricmp(Value, Own),
           "64-bit child: ProgramFiles %s, expected %s\n", Value, Own);
        ok(FindVariable(Output, "ProgramW6432", Value, sizeof(Value)) && !_stricmp(Value, Own),
           "64-bit child: ProgramW6432 %s, expected %s\n", Value, Own);
        GetOwn("CommonProgramW6432", Own, sizeof(Own));
        ok(Own[0], "CommonProgramW6432 is missing in the parent\n");
        ok(FindVariable(Output, "CommonProgramFiles", Value, sizeof(Value)) && !_stricmp(Value, Own),
           "64-bit child: CommonProgramFiles %s, expected %s\n", Value, Own);
        ok(FindVariable(Output, "CommonProgramW6432", Value, sizeof(Value)) && !_stricmp(Value, Own),
           "64-bit child: CommonProgramW6432 %s, expected %s\n", Value, Own);
        ok(FindVariable(Output, "ProgramFiles(x86)", Value, sizeof(Value)) &&
           strstr(Value, "(x86)"), "64-bit child: ProgramFiles(x86) %s\n", Value);
    }

    if (!Wow64) return;

    /* the 32-bit child: the guest's view */
    GetWindowsDirectoryW(Path, _countof(Path));
    wcscat(Path, L"\\SysWOW64\\cmd.exe");
    if (RunSet(Path, Output, sizeof(Output)))
    {
        ok(FindVariable(Output, "PROCESSOR_ARCHITECTURE", Value, sizeof(Value)) && !_stricmp(Value, "x86"),
           "32-bit child: PROCESSOR_ARCHITECTURE %s\n", Value);
        ok(FindVariable(Output, "PROCESSOR_ARCHITEW6432", Value, sizeof(Value)) && !_stricmp(Value, "AMD64"),
           "32-bit child: PROCESSOR_ARCHITEW6432 %s\n", Value);
        GetOwn("ProgramFiles", Own, sizeof(Own));
        ok(FindVariable(Output, "ProgramFiles", Value, sizeof(Value)) && !_stricmp(Value, Own),
           "32-bit child: ProgramFiles %s, expected %s\n", Value, Own);
        GetOwn("CommonProgramFiles", Own, sizeof(Own));
        ok(FindVariable(Output, "CommonProgramFiles", Value, sizeof(Value)) && !_stricmp(Value, Own),
           "32-bit child: CommonProgramFiles %s, expected %s\n", Value, Own);
    }
}
