/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Tests that a descriptor set on an object keeps only the rights of the object's type in allow and deny ACEs
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"
#include <sddl.h>

/*
 * Measured on Windows Server 2022 (x64 and x86 under WoW64, the same): NtSetSecurityObject, SetKernelObjectSecurity,
 * RegSetKeySecurity, SetFileSecurity, SetServiceObjectSecurity and SetPrivateObjectSecurity store the DACL's allow and
 * deny ACEs (one ACE, one bit or a combination of bits, SY) with the mask reduced to the rights of the object type: the
 * type's GenericAll. ACCESS_SYSTEM_SECURITY and MAXIMUM_ALLOWED never stay; an ACE whose mask is left empty stays.
 * Inherit-only ACEs keep their masks.
 */

typedef enum { OEvent, OMutant, OSemaphore, OSection, OToken, OProcess, OThread, OKey, OFile, ODir, OService, OPrivate, OCount } OBJ_KIND;

static const struct { PCSTR Name; ULONG GenericAll; } Types[OCount] =
{
    {"event", 0x001F0003}, {"mutant", 0x001F0001}, {"semaphore", 0x001F0003}, {"section", 0x000F001F},
    {"token", 0x000F01FF}, {"process", 0x001FFFFF}, {"thread", 0x001FFFFF}, {"key", 0x000F003F},
    {"file", 0x001F01FF}, {"dir", 0x001F01FF}, {"service", 0x000F01FF}, {"private", 0x001F00FF},
};

static GENERIC_MAPPING PrivateMapping = {0x20001, 0x20002, 0x20004, 0x1F00FF};

static HANDLE Handles[OCount];
static HKEY Key;
static SC_HANDLE ServiceManager, Service;
static WCHAR FilePath[MAX_PATH], DirPath[MAX_PATH];
static PSECURITY_DESCRIPTOR Private;
static HANDLE PrivateToken;
static const WCHAR ServiceName[] = L"SetSecTypeMask";
static PROCESS_INFORMATION Child;

static BOOL SetDacl(OBJ_KIND Kind, PSECURITY_DESCRIPTOR Sd)
{
    switch (Kind)
    {
        case OKey: return RegSetKeySecurity(Key, DACL_SECURITY_INFORMATION, Sd) == ERROR_SUCCESS;
        case OFile: return SetFileSecurityW(FilePath, DACL_SECURITY_INFORMATION, Sd);
        case ODir: return SetFileSecurityW(DirPath, DACL_SECURITY_INFORMATION, Sd);
        case OService: return SetServiceObjectSecurity(Service, DACL_SECURITY_INFORMATION, Sd);
        case OPrivate: return SetPrivateObjectSecurity(DACL_SECURITY_INFORMATION, Sd, &Private, &PrivateMapping, PrivateToken);
        default: return SetKernelObjectSecurity(Handles[Kind], DACL_SECURITY_INFORMATION, Sd);
    }
}

static BOOL GetDacl(OBJ_KIND Kind, PVOID Buffer, DWORD Size)
{
    DWORD Needed = Size;

    switch (Kind)
    {
        case OKey: return RegGetKeySecurity(Key, DACL_SECURITY_INFORMATION, Buffer, &Needed) == ERROR_SUCCESS;
        case OFile: return GetFileSecurityW(FilePath, DACL_SECURITY_INFORMATION, Buffer, Size, &Needed);
        case ODir: return GetFileSecurityW(DirPath, DACL_SECURITY_INFORMATION, Buffer, Size, &Needed);
        case OService: return QueryServiceObjectSecurity(Service, DACL_SECURITY_INFORMATION, Buffer, Size, &Needed);
        case OPrivate: return GetPrivateObjectSecurity(Private, DACL_SECURITY_INFORMATION, Buffer, Size, &Needed);
        default: return GetKernelObjectSecurity(Handles[Kind], DACL_SECURITY_INFORMATION, Buffer, Size, &Needed);
    }
}

static VOID Sweep(OBJ_KIND Kind)
{
    static const ULONG Combos[] = {0x001F01FF, 0x00FFFFFF, 0x01FFFFFF, 0x0FFFFFFF, 0x0000FFFF, 0x00FF0000, 0x02000000, 0x01000000};
    ULONG Bit, Mask, Deny;

    for (Deny = 0; Deny < 2; Deny++)
    {
        for (Bit = 0; Bit < 32 + RTL_NUMBER_OF(Combos); Bit++)
        {
            BYTE Buffer[1024];
            WCHAR Sddl[96];
            PSECURITY_DESCRIPTOR Sd = NULL;
            PACL Dacl = NULL;
            BOOL Present = FALSE, Defaulted;
            ACCESS_ALLOWED_ACE *Ace;
            ULONG Expected;

            Mask = Bit < 32 ? (1UL << Bit) : Combos[Bit - 32];
            /* the generic bits are mapped, not dropped: the rows of SetSecurityGenericMap */
            if (Mask & 0xF0000000)
                continue;
            StringCchPrintfW(Sddl, RTL_NUMBER_OF(Sddl), L"D:(%lc;;0x%lx;;;SY)", Deny ? L'D' : L'A', Mask);
            if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(Sddl, SDDL_REVISION_1, &Sd, NULL))
            {
                ok(0, "%s: SDDL %ls: %lu\n", Types[Kind].Name, Sddl, GetLastError());
                continue;
            }
            ok(SetDacl(Kind, Sd), "%s %ls: set failed %lu\n", Types[Kind].Name, Sddl, GetLastError());
            LocalFree(Sd);
            ok(GetDacl(Kind, Buffer, sizeof(Buffer)), "%s %ls: get failed %lu\n", Types[Kind].Name, Sddl, GetLastError());
            if (!GetSecurityDescriptorDacl(Buffer, &Present, &Dacl, &Defaulted) || !Present || !Dacl)
            {
                ok(0, "%s %ls: no DACL\n", Types[Kind].Name, Sddl);
                continue;
            }
            ok(Dacl->AceCount == 1, "%s %ls: %u ACEs\n", Types[Kind].Name, Sddl, Dacl->AceCount);
            if (Dacl->AceCount != 1 || !GetAce(Dacl, 0, (PVOID *)&Ace))
                continue;
            Expected = Mask & Types[Kind].GenericAll;
            ok(Ace->Header.AceType == (Deny ? ACCESS_DENIED_ACE_TYPE : ACCESS_ALLOWED_ACE_TYPE) && Ace->Mask == Expected,
               "%s %ls: stored (%u;%02x;0x%08lx), expected mask 0x%08lx\n", Types[Kind].Name, Sddl,
               Ace->Header.AceType, Ace->Header.AceFlags, Ace->Mask, Expected);
        }
    }
}

/* An inherit-only ACE keeps what it was given (it is reduced when it is inherited) */
static VOID InheritOnlyRow(OBJ_KIND Kind)
{
    BYTE Buffer[1024];
    PSECURITY_DESCRIPTOR Sd = NULL;
    PACL Dacl = NULL;
    BOOL Present = FALSE, Defaulted;
    ACCESS_ALLOWED_ACE *Ace;

    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:(A;OICIIO;0x1F01FF;;;SY)(A;;0x1;;;WD)", SDDL_REVISION_1, &Sd, NULL))
        return;
    ok(SetDacl(Kind, Sd), "%s inherit-only: set failed %lu\n", Types[Kind].Name, GetLastError());
    LocalFree(Sd);
    ok(GetDacl(Kind, Buffer, sizeof(Buffer)), "%s inherit-only: get failed %lu\n", Types[Kind].Name, GetLastError());
    if (!GetSecurityDescriptorDacl(Buffer, &Present, &Dacl, &Defaulted) || !Present || !Dacl || Dacl->AceCount != 2)
    {
        ok(0, "%s inherit-only: DACL\n", Types[Kind].Name);
        return;
    }
    GetAce(Dacl, 0, (PVOID *)&Ace);
    ok(Ace->Mask == 0x1F01FF, "%s inherit-only: stored mask 0x%08lx\n", Types[Kind].Name, Ace->Mask);
}

START_TEST(SetSecurityTypeMask)
{
    WCHAR Name[64], Temp[MAX_PATH], Self[MAX_PATH], Command[MAX_PATH + 32];
    HANDLE Token = NULL;
    STARTUPINFOW Startup = {sizeof(Startup)};
    PSECURITY_DESCRIPTOR Creator = NULL;
    DWORD Disposition;
    char **Argv;
    int Argc = winetest_get_mainargs(&Argv);
    OBJ_KIND Kind;

    if (Argc >= 3 && !strcmp(Argv[2], "idle"))
    {
        Sleep(60000);
        return;
    }

    ZeroMemory(Handles, sizeof(Handles));
    StringCchPrintfW(Name, RTL_NUMBER_OF(Name), L"Local\\SetSecTypeMask%lu", GetCurrentProcessId());
    Handles[OEvent] = CreateEventW(NULL, TRUE, FALSE, Name);
    Handles[OMutant] = CreateMutexW(NULL, FALSE, L"Local\\SetSecTypeMaskMutex");
    Handles[OSemaphore] = CreateSemaphoreW(NULL, 0, 1, L"Local\\SetSecTypeMaskSemaphore");
    Handles[OSection] = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, 4096, L"Local\\SetSecTypeMaskSection");
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY, &Token))
    {
        DuplicateTokenEx(Token, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenPrimary, &Handles[OToken]);
        CloseHandle(Token);
    }
    GetModuleFileNameW(NULL, Self, RTL_NUMBER_OF(Self));
    StringCchPrintfW(Command, RTL_NUMBER_OF(Command), L"\"%ls\" SetSecurityTypeMask idle", Self);
    if (CreateProcessW(Self, Command, NULL, NULL, FALSE, 0, NULL, NULL, &Startup, &Child))
    {
        Handles[OProcess] = Child.hProcess;
        Handles[OThread] = Child.hThread;
    }
    if (RegCreateKeyExW(HKEY_CURRENT_USER, L"Software\\SetSecurityTypeMaskTest", 0, NULL, REG_OPTION_VOLATILE,
                        KEY_ALL_ACCESS, NULL, &Key, &Disposition) != ERROR_SUCCESS)
        Key = NULL;
    GetTempPathW(RTL_NUMBER_OF(Temp), Temp);
    StringCchPrintfW(FilePath, RTL_NUMBER_OF(FilePath), L"%lsSetSecTypeMask%lu.tmp", Temp, GetCurrentProcessId());
    StringCchPrintfW(DirPath, RTL_NUMBER_OF(DirPath), L"%lsSetSecTypeMask%lu.dir", Temp, GetCurrentProcessId());
    {
        HANDLE File = CreateFileW(FilePath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
        if (File != INVALID_HANDLE_VALUE) CloseHandle(File);
        else FilePath[0] = 0;
        if (!CreateDirectoryW(DirPath, NULL)) DirPath[0] = 0;
    }
    ServiceManager = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (ServiceManager)
        Service = CreateServiceW(ServiceManager, ServiceName, ServiceName, SERVICE_ALL_ACCESS | READ_CONTROL | WRITE_DAC, SERVICE_WIN32_OWN_PROCESS,
                                 SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE, L"C:\\Windows\\System32\\none.exe", NULL, NULL, NULL, NULL, NULL);
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &PrivateToken) &&
        ConvertStringSecurityDescriptorToSecurityDescriptorW(L"O:SYG:SYD:(A;;GA;;;WD)", SDDL_REVISION_1, &Creator, NULL))
    {
        if (!CreatePrivateObjectSecurity(NULL, Creator, &Private, FALSE, PrivateToken, &PrivateMapping))
            Private = NULL;
        LocalFree(Creator);
    }

    for (Kind = 0; Kind < OCount; Kind++)
    {
        BOOL Have = FALSE;

        switch (Kind)
        {
            case OKey: Have = Key != NULL; break;
            case OFile: Have = FilePath[0] != 0; break;
            case ODir: Have = DirPath[0] != 0; break;
            case OService: Have = Service != NULL; break;
            case OPrivate: Have = Private != NULL; break;
            default: Have = Handles[Kind] != NULL; break;
        }
        if (!Have)
        {
            skip("%s: the object could not be made (%lu)\n", Types[Kind].Name, GetLastError());
            continue;
        }
        if (Kind == OFile || Kind == ODir)
        {
            PSECURITY_DESCRIPTOR Sd = NULL;
            BOOL Done = FALSE;

            if (ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:(A;;FA;;;WD)", SDDL_REVISION_1, &Sd, NULL))
            {
                Done = SetFileSecurityW(Kind == OFile ? FilePath : DirPath, DACL_SECURITY_INFORMATION, Sd);
                LocalFree(Sd);
            }
            if (!Done)
            {
                skip("%s: the volume keeps no security descriptors (FAT)\n", Types[Kind].Name);
                continue;
            }
        }
        Sweep(Kind);
        InheritOnlyRow(Kind);
    }

    /* Everyone all access again where a set took it away, then clean up */
    if (Key)
    {
        PSECURITY_DESCRIPTOR Sd = NULL;
        if (ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:(A;;KA;;;WD)", SDDL_REVISION_1, &Sd, NULL))
        {
            RegSetKeySecurity(Key, DACL_SECURITY_INFORMATION, Sd);
            LocalFree(Sd);
        }
        RegCloseKey(Key);
        RegDeleteKeyW(HKEY_CURRENT_USER, L"Software\\SetSecurityTypeMaskTest");
    }
    {
        PSECURITY_DESCRIPTOR Sd = NULL;
        if (ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:(A;;FA;;;WD)", SDDL_REVISION_1, &Sd, NULL))
        {
            if (FilePath[0]) SetFileSecurityW(FilePath, DACL_SECURITY_INFORMATION, Sd);
            if (DirPath[0]) SetFileSecurityW(DirPath, DACL_SECURITY_INFORMATION, Sd);
            LocalFree(Sd);
        }
    }
    if (FilePath[0]) DeleteFileW(FilePath);
    if (DirPath[0]) RemoveDirectoryW(DirPath);
    if (Service) { DeleteService(Service); CloseServiceHandle(Service); }
    if (ServiceManager) CloseServiceHandle(ServiceManager);
    if (Private) DestroyPrivateObjectSecurity(&Private);
    if (PrivateToken) CloseHandle(PrivateToken);
    if (Child.hProcess) TerminateProcess(Child.hProcess, 0);
    for (Kind = 0; Kind < OCount; Kind++)
        if (Handles[Kind] && Kind != OProcess && Kind != OThread)
            CloseHandle(Handles[Kind]);
    if (Child.hProcess)
    {
        CloseHandle(Child.hProcess);
        CloseHandle(Child.hThread);
    }
}
