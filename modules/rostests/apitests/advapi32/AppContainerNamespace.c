/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     What a lowbox (AppContainer) token needs of the object namespace to start a process
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * The AppContainer pass of the access check grants a lowbox token only what an ACE for its package, its
 * capabilities, ALL APPLICATION PACKAGES (S-1-15-2-1) or ALL RESTRICTED APPLICATION PACKAGES (S-1-15-2-2)
 * grants it. Every process in an AppContainer opens \KnownDlls, its sections and the link KnownDllPath while it
 * starts, connects to the API port of the server (\Windows\ApiPort), and to the interactive window station
 * and its Default desktop: without such an ACE on them the process cannot start (Edge's renderers did not).
 * The entries are those of Windows Server 2022 (measured): \KnownDlls 0x20003 for both SIDs, its sections 0x2000f and
 * its link 0x20001 (inherited from the directory); the interactive window station 0x20327 and the generic read
 * and execute rights inherited by what is made in it; the Default desktop 0xf00ff. The \NLS sections have no entry
 * for either SID there: a process in an AppContainer does not open them.
 * Part 1: the descriptors. Part 2: the opens with a lowbox token. Part 3: the storage key of an AppContainer
 * profile can be written by its own package. Part 4: a process started with a lowbox token runs and returns its
 * exit code (this is the port, the loader, the known DLLs and the window station together).
 */

#include "precomp.h"
#include <winuser.h>
#include <ndk/obfuncs.h>
#include <ndk/mmfuncs.h>

typedef NTSTATUS (NTAPI *PFN_CreateLowBox)(PHANDLE, HANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PSID, ULONG,
                                           PSID_AND_ATTRIBUTES, ULONG, HANDLE *);
typedef HRESULT (WINAPI *PFN_CreateProfile)(PCWSTR, PCWSTR, PCWSTR, PSID_AND_ATTRIBUTES, DWORD, PSID *);
typedef HRESULT (WINAPI *PFN_DeleteProfile)(PCWSTR);

static struct { UCHAR Revision, Count, Authority[6]; ULONG Sub[8]; } AcPackage =
    { 1, 8, { 0, 0, 0, 0, 0, 15 }, { 2, 1, 2, 3, 4, 5, 6, 7 } };
static struct { UCHAR Revision, Count, Authority[6]; ULONG Sub[2]; } AllPackages =
    { 1, 2, { 0, 0, 0, 0, 0, 15 }, { 2, 1 } };
static struct { UCHAR Revision, Count, Authority[6]; ULONG Sub[2]; } AllRestrictedPackages =
    { 1, 2, { 0, 0, 0, 0, 0, 15 }, { 2, 2 } };

#define DIRECTORY_QUERY_TRAVERSE 0x3
#define SECTION_QUERY_READ_EXEC  (0x1 | 0x4 | 0x8)
#define SYMLINK_QUERY            0x1

#define PACKAGE_WINSTA_ACCESS    0x20327  /* READ_CONTROL, ENUMDESKTOPS, READATTRIBUTES, ACCESSCLIPBOARD, ACCESSGLOBALATOMS, ENUMERATE, READSCREEN */
#define PACKAGE_DESKTOP_ACCESS   0xf00ff  /* DELETE, READ_CONTROL, WRITE_DAC, WRITE_OWNER and every desktop right but SWITCHDESKTOP */

typedef NTSTATUS (NTAPI *PFN_Open)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);

static NTSTATUS OpenNamed(PFN_Open Open, PCWSTR Name, ACCESS_MASK Access, PHANDLE Handle)
{
    UNICODE_STRING String;
    OBJECT_ATTRIBUTES Attributes;

    RtlInitUnicodeString(&String, Name);
    InitializeObjectAttributes(&Attributes, &String, OBJ_CASE_INSENSITIVE, NULL, NULL);
    return Open(Handle, Access, &Attributes);
}

/*
 * Whether the DACL has allow ACEs for the SID that are not inherit-only (InheritOnly FALSE) or only inherit-only
 * ones (TRUE) and that grant at least these rights together (generic rights mapped when a mapping is given)
 */
static BOOLEAN SidGets(PACL Dacl, PSID Sid, ACCESS_MASK Wanted, PGENERIC_MAPPING Mapping, BOOLEAN InheritOnly)
{
    ULONG i;
    ACCESS_MASK Got = 0;

    for (i = 0; i < Dacl->AceCount; i++)
    {
        PACCESS_ALLOWED_ACE Ace;
        ACCESS_MASK Mask;

        if (!NT_SUCCESS(RtlGetAce(Dacl, i, (PVOID *)&Ace)))
            break;
        if (Ace->Header.AceType != ACCESS_ALLOWED_ACE_TYPE)
            continue;
        if (!!(Ace->Header.AceFlags & INHERIT_ONLY_ACE) != !!InheritOnly)
            continue;
        if (!EqualSid((PSID)&Ace->SidStart, Sid))
            continue;
        Mask = Ace->Mask;
        if (Mapping)
            RtlMapGenericMask(&Mask, Mapping);
        Got |= Mask;
    }
    return (Got & Wanted) == Wanted;
}

/* whether the SID has no allow ACE at all in the DACL */
static BOOLEAN SidHasNone(PACL Dacl, PSID Sid)
{
    ULONG i;

    for (i = 0; i < Dacl->AceCount; i++)
    {
        PACCESS_ALLOWED_ACE Ace;

        if (!NT_SUCCESS(RtlGetAce(Dacl, i, (PVOID *)&Ace)))
            break;
        if (Ace->Header.AceType == ACCESS_ALLOWED_ACE_TYPE && EqualSid((PSID)&Ace->SidStart, Sid))
            return FALSE;
    }
    return TRUE;
}

/* the DACL of a kernel object handle (self-relative descriptor in Buffer); NULL when there is none */
static PACL DaclOfHandle(HANDLE Handle, PUCHAR Buffer, ULONG Size)
{
    ULONG Length;
    PACL Dacl;
    BOOLEAN Present, Defaulted;

    if (!NT_SUCCESS(NtQuerySecurityObject(Handle, DACL_SECURITY_INFORMATION, (PSECURITY_DESCRIPTOR)Buffer, Size, &Length)))
        return NULL;
    if (!NT_SUCCESS(RtlGetDaclSecurityDescriptor((PSECURITY_DESCRIPTOR)Buffer, &Present, &Dacl, &Defaulted)) || !Present)
        return NULL;
    return Dacl;
}

/* the DACL of a window station or a desktop */
static PACL DaclOfUserObject(HANDLE Handle, PUCHAR Buffer, ULONG Size)
{
    DWORD Length;
    SECURITY_INFORMATION Info = DACL_SECURITY_INFORMATION;
    PACL Dacl;
    BOOLEAN Present, Defaulted;

    if (!GetUserObjectSecurity(Handle, &Info, (PSECURITY_DESCRIPTOR)Buffer, Size, &Length))
        return NULL;
    if (!NT_SUCCESS(RtlGetDaclSecurityDescriptor((PSECURITY_DESCRIPTOR)Buffer, &Present, &Dacl, &Defaulted)) || !Present)
        return NULL;
    return Dacl;
}

static void TestKnownDllsDescriptors(void)
{
    static GENERIC_MAPPING DirMap = { STANDARD_RIGHTS_READ | 1, STANDARD_RIGHTS_WRITE | 0xC, STANDARD_RIGHTS_EXECUTE | 3, 0xF000F };
    static GENERIC_MAPPING LinkMap = { STANDARD_RIGHTS_READ | 1, STANDARD_RIGHTS_WRITE, STANDARD_RIGHTS_EXECUTE | 1, 0xF0001 };
    static GENERIC_MAPPING SectionMap = { STANDARD_RIGHTS_READ | 5, STANDARD_RIGHTS_WRITE | 6, STANDARD_RIGHTS_EXECUTE | 8, 0xF001F };
    static const struct { PCWSTR Name; PFN_Open Open; PGENERIC_MAPPING Map; ACCESS_MASK Wanted; PCSTR What; } Cases[] =
    {
        { L"\\KnownDlls", NtOpenDirectoryObject, &DirMap, DIRECTORY_QUERY_TRAVERSE, "\\KnownDlls (query, traverse)" },
        { L"\\KnownDlls\\KnownDllPath", NtOpenSymbolicLinkObject, &LinkMap, SYMLINK_QUERY, "KnownDllPath (query)" },
        { L"\\KnownDlls\\kernel32.dll", NtOpenSection, &SectionMap, SECTION_QUERY_READ_EXEC, "kernel32.dll (query, read, execute)" },
    };
    UCHAR Buffer[4096];
    ULONG i;

    for (i = 0; i < RTL_NUMBER_OF(Cases); i++)
    {
        HANDLE Handle;
        NTSTATUS Status = OpenNamed(Cases[i].Open, Cases[i].Name, READ_CONTROL, &Handle);
        PACL Dacl;

        ok(Status == STATUS_SUCCESS, "open %ls: %lx\n", Cases[i].Name, Status);
        if (!NT_SUCCESS(Status))
            continue;
        Dacl = DaclOfHandle(Handle, Buffer, sizeof(Buffer));
        ok(Dacl != NULL, "%ls: no DACL\n", Cases[i].Name);
        if (Dacl)
        {
            ok(SidGets(Dacl, (PSID)&AllPackages, Cases[i].Wanted, Cases[i].Map, FALSE),
               "%s: no entry of ALL APPLICATION PACKAGES\n", Cases[i].What);
            ok(SidGets(Dacl, (PSID)&AllRestrictedPackages, Cases[i].Wanted, Cases[i].Map, FALSE),
               "%s: no entry of ALL RESTRICTED APPLICATION PACKAGES\n", Cases[i].What);
        }
        NtClose(Handle);
    }
}

/* the full name of a code page section that exists in \NLS (the first one the directory lists) */
static BOOLEAN FindNlsSection(PWSTR Name, ULONG Chars)
{
    UNICODE_STRING Directory = RTL_CONSTANT_STRING(L"\\NLS");
    OBJECT_ATTRIBUTES Attributes;
    UCHAR Buffer[512];
    POBJECT_DIRECTORY_INFORMATION Info = (POBJECT_DIRECTORY_INFORMATION)Buffer;
    ULONG Context = 0, Length;
    HANDLE Handle;
    BOOLEAN Found = FALSE, First = TRUE;

    InitializeObjectAttributes(&Attributes, &Directory, OBJ_CASE_INSENSITIVE, NULL, NULL);
    if (!NT_SUCCESS(NtOpenDirectoryObject(&Handle, DIRECTORY_QUERY, &Attributes)))
        return FALSE;
    while (NT_SUCCESS(NtQueryDirectoryObject(Handle, Buffer, sizeof(Buffer), TRUE, First, &Context, &Length)))
    {
        First = FALSE;
        if (Info->Name.Length / sizeof(WCHAR) > 10 && !_wcsnicmp(Info->Name.Buffer, L"NlsSection", 10) &&
            Info->Name.Length / sizeof(WCHAR) + 6 < Chars)
        {
            StringCchPrintfW(Name, Chars, L"\\NLS\\%.*ls", Info->Name.Length / sizeof(WCHAR), Info->Name.Buffer);
            Found = TRUE;
            break;
        }
    }
    NtClose(Handle);
    return Found;
}

/* Windows Server 2022 has no entry for either SID on the code page sections of \NLS (only the system and the administrators) */
static void TestNlsDescriptor(void)
{
    UCHAR Buffer[4096];
    HANDLE Handle;
    WCHAR Name[100];
    NTSTATUS Status;
    PACL Dacl;

    if (!FindNlsSection(Name, RTL_NUMBER_OF(Name)))
    {
        skip("no section in \\NLS\n");
        return;
    }
    Status = OpenNamed(NtOpenSection, Name, READ_CONTROL, &Handle);
    ok(Status == STATUS_SUCCESS, "open %ls: %lx\n", Name, Status);
    if (!NT_SUCCESS(Status))
        return;
    Dacl = DaclOfHandle(Handle, Buffer, sizeof(Buffer));
    ok(Dacl != NULL, "%ls: no DACL\n", Name);
    if (Dacl)
    {
        ok(SidHasNone(Dacl, (PSID)&AllPackages), "%ls: an entry of ALL APPLICATION PACKAGES (Windows has none)\n", Name);
        ok(SidHasNone(Dacl, (PSID)&AllRestrictedPackages), "%ls: an entry of ALL RESTRICTED APPLICATION PACKAGES (Windows has none)\n", Name);
    }
    NtClose(Handle);
}

static void TestInteractiveDescriptors(void)
{
    UCHAR Buffer[4096];
    HWINSTA Station, Previous;
    HDESK Desktop;
    PACL Dacl;

    Station = OpenWindowStationW(L"WinSta0", FALSE, READ_CONTROL);
    if (!Station)
    {
        skip("no interactive window station: %lu\n", GetLastError());
        return;
    }
    Dacl = DaclOfUserObject(Station, Buffer, sizeof(Buffer));
    ok(Dacl != NULL, "WinSta0: no DACL\n");
    if (Dacl)
    {
        ok(SidGets(Dacl, (PSID)&AllPackages, PACKAGE_WINSTA_ACCESS, NULL, FALSE), "WinSta0: no entry of ALL APPLICATION PACKAGES for 0x20327\n");
        ok(SidGets(Dacl, (PSID)&AllRestrictedPackages, PACKAGE_WINSTA_ACCESS, NULL, FALSE), "WinSta0: no entry of ALL RESTRICTED APPLICATION PACKAGES for 0x20327\n");
        ok(SidGets(Dacl, (PSID)&AllPackages, GENERIC_READ | GENERIC_EXECUTE, NULL, TRUE), "WinSta0: no inheritable generic read and execute for ALL APPLICATION PACKAGES\n");
        ok(SidGets(Dacl, (PSID)&AllRestrictedPackages, GENERIC_READ | GENERIC_EXECUTE, NULL, TRUE), "WinSta0: no inheritable generic read and execute for ALL RESTRICTED APPLICATION PACKAGES\n");
    }

    Previous = GetProcessWindowStation();
    if (SetProcessWindowStation(Station))
    {
        Desktop = OpenDesktopW(L"Default", 0, FALSE, READ_CONTROL);
        ok(Desktop != NULL, "open the Default desktop: %lu\n", GetLastError());
        if (Desktop)
        {
            Dacl = DaclOfUserObject(Desktop, Buffer, sizeof(Buffer));
            ok(Dacl != NULL, "Default desktop: no DACL\n");
            if (Dacl)
            {
                ok(SidGets(Dacl, (PSID)&AllPackages, PACKAGE_DESKTOP_ACCESS, NULL, FALSE), "Default desktop: no entry of ALL APPLICATION PACKAGES for 0xf00ff\n");
                ok(SidGets(Dacl, (PSID)&AllRestrictedPackages, PACKAGE_DESKTOP_ACCESS, NULL, FALSE), "Default desktop: no entry of ALL RESTRICTED APPLICATION PACKAGES for 0xf00ff\n");
                ok(!SidGets(Dacl, (PSID)&AllPackages, DESKTOP_SWITCHDESKTOP, NULL, FALSE), "Default desktop: ALL APPLICATION PACKAGES may switch desktops\n");
            }
            CloseDesktop(Desktop);
        }
        SetProcessWindowStation(Previous);
    }
    CloseWindowStation(Station);
}

static void TestOpens(HANDLE Lowbox)
{
    HANDLE Handle;
    NTSTATUS Status;
    HWINSTA Station, Previous;
    HDESK Desktop;
    WCHAR NlsName[100] = L"";
    DWORD Error;

    /* the name is found before the token changes: a lowbox token cannot open the directory's entries by itself */
    FindNlsSection(NlsName, RTL_NUMBER_OF(NlsName));
    ok(SetThreadToken(NULL, Lowbox), "SetThreadToken: %lu\n", GetLastError());
    Status = OpenNamed(NtOpenDirectoryObject, L"\\KnownDlls", DIRECTORY_QUERY_TRAVERSE, &Handle);
    ok(Status == STATUS_SUCCESS, "lowbox: open \\KnownDlls: %lx\n", Status);
    if (NT_SUCCESS(Status))
        NtClose(Handle);
    Status = OpenNamed(NtOpenSymbolicLinkObject, L"\\KnownDlls\\KnownDllPath", SYMLINK_QUERY, &Handle);
    ok(Status == STATUS_SUCCESS, "lowbox: open KnownDllPath: %lx\n", Status);
    if (NT_SUCCESS(Status))
        NtClose(Handle);
    Status = OpenNamed(NtOpenSection, L"\\KnownDlls\\kernel32.dll", SECTION_QUERY_READ_EXEC, &Handle);
    ok(Status == STATUS_SUCCESS, "lowbox: open \\KnownDlls\\kernel32.dll: %lx\n", Status);
    if (NT_SUCCESS(Status))
        NtClose(Handle);

    /* Windows: the code page sections are not open to a lowbox token */
    if (NlsName[0])
    {
        Status = OpenNamed(NtOpenSection, NlsName, SECTION_MAP_READ, &Handle);
        ok(Status == STATUS_ACCESS_DENIED, "lowbox: open %ls: %lx\n", NlsName, Status);
        if (NT_SUCCESS(Status))
            NtClose(Handle);
    }

    /* the interactive window station and its Default desktop, with what Windows grants the package SIDs */
    Station = OpenWindowStationW(L"WinSta0", FALSE, PACKAGE_WINSTA_ACCESS & ~READ_CONTROL);
    Error = GetLastError();
    ok(Station != NULL, "lowbox: open WinSta0 for 0x%x: %lu\n", PACKAGE_WINSTA_ACCESS & ~READ_CONTROL, Error);
    if (Station)
    {
        CloseWindowStation(Station);
        Station = OpenWindowStationW(L"WinSta0", FALSE, WINSTA_CREATEDESKTOP);
        ok(Station == NULL, "lowbox: WinSta0 opened for WINSTA_CREATEDESKTOP\n");
        if (Station)
            CloseWindowStation(Station);

        Station = OpenWindowStationW(L"WinSta0", FALSE, WINSTA_ENUMDESKTOPS | WINSTA_ENUMERATE);
        Previous = GetProcessWindowStation();
        if (Station && SetProcessWindowStation(Station))
        {
            Desktop = OpenDesktopW(L"Default", 0, FALSE, DESKTOP_READOBJECTS | DESKTOP_CREATEWINDOW | DESKTOP_WRITEOBJECTS);
            ok(Desktop != NULL, "lowbox: open the Default desktop: %lu\n", GetLastError());
            if (Desktop)
                CloseDesktop(Desktop);
            Desktop = OpenDesktopW(L"Default", 0, FALSE, DESKTOP_SWITCHDESKTOP);
            ok(Desktop == NULL, "lowbox: the Default desktop opened for DESKTOP_SWITCHDESKTOP\n");
            if (Desktop)
                CloseDesktop(Desktop);
            SetProcessWindowStation(Previous);
        }
        if (Station)
            CloseWindowStation(Station);
    }

    /* a process in an AppContainer makes the pipes of its own IPC (Edge's renderers: \pipe\LOCAL\mojo.*): decided by its integrity level */
    {
        HANDLE Pipe = CreateNamedPipeW(L"\\\\.\\pipe\\LOCAL\\AppContainerNamespaceTest", PIPE_ACCESS_DUPLEX,
                                       PIPE_TYPE_BYTE | PIPE_WAIT, 1, 512, 512, 0, NULL);
        ok(Pipe != INVALID_HANDLE_VALUE, "lowbox: CreateNamedPipe: %lu\n", GetLastError());
        if (Pipe != INVALID_HANDLE_VALUE)
            CloseHandle(Pipe);
    }
    RevertToSelf();
}

/*
 * A package's own storage key under HKCU\...\AppContainer\Storage: the package SID has an entry with all access
 * (Windows: the AppContainer writes it through that entry). Registry key security is enforced and a lowbox
 * token is Low: the entry of the package SID must be what lets the write through.
 */
static void TestStorageKey(PFN_CreateLowBox pNtCreateLowBoxToken, HANDLE Plain)
{
    static const WCHAR Prefix[] = L"Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\CurrentVersion\\AppContainer\\Storage\\";
    HMODULE Userenv = LoadLibraryW(L"userenv.dll");
    PFN_CreateProfile pCreate = Userenv ? (PFN_CreateProfile)GetProcAddress(Userenv, "CreateAppContainerProfile") : NULL;
    PFN_DeleteProfile pDelete = Userenv ? (PFN_DeleteProfile)GetProcAddress(Userenv, "DeleteAppContainerProfile") : NULL;
    WCHAR Name[64], Path[300];
    PSID Package = NULL;
    HANDLE Lowbox = NULL;
    HKEY Key;
    HRESULT Hr;
    LONG Error;
    NTSTATUS Status;
    DWORD Value = 1;

    if (!pCreate || !pDelete)
    {
        skip("no AppContainer profiles\n");
        return;
    }
    StringCbPrintfW(Name, sizeof(Name), L"AcNsTest.%lu", GetCurrentProcessId());
    pDelete(Name);
    Hr = pCreate(Name, Name, Name, NULL, 0, &Package);
    if (FAILED(Hr))
    {
        skip("CreateAppContainerProfile: %lx\n", Hr);
        return;
    }

    Status = pNtCreateLowBoxToken(&Lowbox, Plain, TOKEN_ALL_ACCESS, NULL, Package, 0, NULL, 0, NULL);
    ok(Status == STATUS_SUCCESS, "NtCreateLowBoxToken for the profile: %lx\n", Status);
    if (NT_SUCCESS(Status))
    {
        StringCbPrintfW(Path, sizeof(Path), L"%ls%ls", Prefix, Name);
        ok(SetThreadToken(NULL, Lowbox), "SetThreadToken: %lu\n", GetLastError());
        Error = RegOpenKeyExW(HKEY_CURRENT_USER, Path, 0, KEY_SET_VALUE | KEY_QUERY_VALUE, &Key);
        ok(Error == ERROR_SUCCESS, "the package opens its own storage key for writing: %ld\n", Error);
        if (Error == ERROR_SUCCESS)
        {
            Error = RegSetValueExW(Key, L"AcNsTest", 0, REG_DWORD, (PBYTE)&Value, sizeof(Value));
            ok(Error == ERROR_SUCCESS, "the package writes a value of its own storage key: %ld\n", Error);
            RegDeleteValueW(Key, L"AcNsTest");
            RegCloseKey(Key);
        }
        /* and no other package's key, nor the user's HKCU\Software */
        Error = RegOpenKeyExW(HKEY_CURRENT_USER, L"Software", 0, KEY_SET_VALUE, &Key);
        ok(Error == ERROR_ACCESS_DENIED, "the package opens HKCU\\Software for writing: %ld\n", Error);
        if (Error == ERROR_SUCCESS)
            RegCloseKey(Key);
        RevertToSelf();
        CloseHandle(Lowbox);
    }
    pDelete(Name);
    FreeSid(Package);
}

static void TestProcess(HANDLE Lowbox)
{
    HANDLE Primary = NULL;
    STARTUPINFOW Startup = { sizeof(Startup) };
    PROCESS_INFORMATION Info;
    WCHAR Command[] = L"cmd.exe /c exit 7";
    DWORD Code = 0, Wait;

    if (!DuplicateTokenEx(Lowbox, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenPrimary, &Primary))
    {
        skip("no primary lowbox token: %lu\n", GetLastError());
        return;
    }
    if (!CreateProcessAsUserW(Primary, NULL, Command, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &Startup, &Info))
    {
        DWORD Error = GetLastError();
        if (Error == ERROR_PRIVILEGE_NOT_HELD)
            skip("CreateProcessAsUser needs a privilege this account does not hold\n");
        else
            ok(0, "CreateProcessAsUser with the lowbox token: %lu\n", Error);
        CloseHandle(Primary);
        return;
    }
    Wait = WaitForSingleObject(Info.hProcess, 60000);
    ok(Wait == WAIT_OBJECT_0, "the process in the AppContainer did not end: %lu\n", Wait);
    if (Wait == WAIT_OBJECT_0)
    {
        GetExitCodeProcess(Info.hProcess, &Code);
        ok(Code == 7, "the process in the AppContainer ended with %lx, expected 7\n", Code);
    }
    else
    {
        TerminateProcess(Info.hProcess, 1);
    }
    CloseHandle(Info.hThread);
    CloseHandle(Info.hProcess);
    CloseHandle(Primary);
}

START_TEST(AppContainerNamespace)
{
    PFN_CreateLowBox pNtCreateLowBoxToken =
        (PFN_CreateLowBox)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtCreateLowBoxToken");
    HANDLE Process, Plain, Lowbox = NULL;
    NTSTATUS Status;

    TestKnownDllsDescriptors();
    TestNlsDescriptor();
    TestInteractiveDescriptors();

    if (!pNtCreateLowBoxToken)
    {
        skip("NtCreateLowBoxToken is not available\n");
        return;
    }
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY, &Process) ||
        !DuplicateTokenEx(Process, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenImpersonation, &Plain))
    {
        skip("no impersonation token: %lu\n", GetLastError());
        return;
    }
    Status = pNtCreateLowBoxToken(&Lowbox, Plain, TOKEN_ALL_ACCESS, NULL, (PSID)&AcPackage, 0, NULL, 0, NULL);
    ok(Status == STATUS_SUCCESS, "NtCreateLowBoxToken returned %lx\n", Status);
    if (NT_SUCCESS(Status))
    {
        TestOpens(Lowbox);
        TestProcess(Lowbox);
        CloseHandle(Lowbox);
    }
    TestStorageKey(pNtCreateLowBoxToken, Plain);
    CloseHandle(Plain);
    CloseHandle(Process);
}
