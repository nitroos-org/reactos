/*
 * PROJECT:     ReactOS api tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     The one-time Program Files repair is not redirected by a directory swapped for a junction
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * The repair (SecureSystemDirectories, as winlogon runs it as SYSTEM, once while its log does not exist) walks
 * Program Files and gives every object that still has the volume root's Authenticated Users entry its folder's
 * inheritance. It used to name every object by its path below the folder it had listed: a directory replaced by a
 * junction between the listing and the set made "<dir>\<swapped>\<child>" name a child of the junction's target,
 * and the repair changed that object's DACL, outside Program Files.
 *
 * The test points the Program Files values to a scratch tree (restored afterwards) whose objects have the old
 * DACL, and runs the repair many times while a second thread keeps replacing one directory of it by a junction to
 * a directory outside (its files have the same names and the same old DACL) and putting it back. Nothing outside may
 * change, and the scratch tree must still be repaired. Run it as SYSTEM (as winlogon runs the repair) or as an
 * administrator; it changes the Program Files values and the repair log for its duration.
 */

#include <apitest.h>
#include <windows.h>
#include <sddl.h>
#include <winioctl.h>
#include <strsafe.h>
#include <userenv.h>
#include <lm.h>

static void PublicResetSwap(void);

#define TOP         L"C:\\hbkrepair"
#define PF          TOP L"\\pf"
#define DIR1        PF L"\\d"
#define SUB         DIR1 L"\\sub"
#define SUBREAL     DIR1 L"\\sub.real"
#define OUTSIDE     L"C:\\hbkoutside"
#define OUTSUB      OUTSIDE L"\\sub"
#define FILES       24
#define CV_KEY      L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion"

static const PCWSTR LegacyDir = L"D:(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1301bf;;;AU)";
static const PCWSTR LegacyFile = L"D:(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1301bf;;;AU)";

static volatile LONG s_Stop, s_Pause, s_Paused, s_Swaps;

static BOOL SetSddl(PCWSTR Path, PCWSTR Sddl)
{
    PSECURITY_DESCRIPTOR Sd;
    BOOL Ok;

    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(Sddl, SDDL_REVISION_1, &Sd, NULL))
        return FALSE;
    /* SetFileSecurity sets the object alone (no propagation below it) */
    Ok = SetFileSecurityW(Path, DACL_SECURITY_INFORMATION, Sd);
    LocalFree(Sd);
    return Ok;
}

static PWSTR GetSddl(PCWSTR Path)
{
    BYTE Buffer[4096];
    DWORD Needed;
    PWSTR Text = NULL;

    if (GetFileSecurityW(Path, DACL_SECURITY_INFORMATION, (PSECURITY_DESCRIPTOR)Buffer, sizeof(Buffer), &Needed))
        ConvertSecurityDescriptorToStringSecurityDescriptorW((PSECURITY_DESCRIPTOR)Buffer, SDDL_REVISION_1,
                                                             DACL_SECURITY_INFORMATION, &Text, NULL);
    return Text;
}

static BOOL MakeJunction(PCWSTR Link, PCWSTR Target)
{
    struct
    {
        ULONG ReparseTag;
        USHORT ReparseDataLength, Reserved, SubstituteNameOffset, SubstituteNameLength, PrintNameOffset, PrintNameLength;
        WCHAR PathBuffer[2 * MAX_PATH + 8];
    } Data;
    USHORT cb = (USHORT)(wcslen(Target) * sizeof(WCHAR));
    DWORD Size = 16 + (cb + 8) + cb + 4, Ret;
    HANDLE h;
    BOOL Ok;

    ZeroMemory(&Data, sizeof(Data));
    Data.ReparseTag = IO_REPARSE_TAG_MOUNT_POINT;
    Data.ReparseDataLength = (USHORT)(Size - 8);
    Data.SubstituteNameLength = cb + 8;
    Data.PrintNameOffset = cb + 8 + 2;
    Data.PrintNameLength = cb;
    wcscpy(Data.PathBuffer, L"\\??\\");
    wcscat(Data.PathBuffer, Target);
    wcscpy(&Data.PathBuffer[Data.PrintNameOffset / sizeof(WCHAR)], Target);
    if (!CreateDirectoryW(Link, NULL))
        return FALSE;
    h = CreateFileW(Link, GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    if (h == INVALID_HANDLE_VALUE)
    {
        RemoveDirectoryW(Link);
        return FALSE;
    }
    Ok = DeviceIoControl(h, FSCTL_SET_REPARSE_POINT, &Data, Size, NULL, 0, &Ret, NULL);
    CloseHandle(h);
    if (!Ok)
        RemoveDirectoryW(Link);
    return Ok;
}

/* Replaces SUB by a junction to OUTSUB and puts it back, again and again; leaves SUB real while paused */
static DWORD WINAPI Swapper(PVOID Unused)
{
    while (!s_Stop)
    {
        ULONG Spin;

        if (s_Pause)
        {
            InterlockedExchange(&s_Paused, 1);
            Sleep(1);
            continue;
        }
        InterlockedExchange(&s_Paused, 0);
        if (!MoveFileW(SUB, SUBREAL))
        {
            Sleep(0);
            continue;
        }
        if (MakeJunction(SUB, OUTSUB))
        {
            InterlockedIncrement(&s_Swaps);
            for (Spin = 0; Spin < 20000; Spin++)
                YieldProcessor();
            while (!RemoveDirectoryW(SUB) && !s_Stop)
                Sleep(0);
        }
        while (!MoveFileW(SUBREAL, SUB) && !s_Stop)
            Sleep(0);
    }
    InterlockedExchange(&s_Paused, 1);
    return 0;
}

static void PauseSwapper(BOOL Pause)
{
    InterlockedExchange(&s_Pause, Pause);
    if (Pause)
    {
        InterlockedExchange(&s_Paused, 0);
        while (!s_Paused)
            Sleep(1);
    }
}

static void MakeTree(void)
{
    WCHAR Path[MAX_PATH];
    HANDLE h;
    ULONG i;

    CreateDirectoryW(TOP, NULL);
    CreateDirectoryW(PF, NULL);
    CreateDirectoryW(DIR1, NULL);
    CreateDirectoryW(SUB, NULL);
    CreateDirectoryW(OUTSIDE, NULL);
    CreateDirectoryW(OUTSUB, NULL);
    for (i = 0; i < FILES; i++)
    {
        StringCchPrintfW(Path, ARRAYSIZE(Path), SUB L"\\f%02lu", i);
        h = CreateFileW(Path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
        if (h != INVALID_HANDLE_VALUE)
            CloseHandle(h);
        StringCchPrintfW(Path, ARRAYSIZE(Path), OUTSUB L"\\f%02lu", i);
        h = CreateFileW(Path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
        if (h != INVALID_HANDLE_VALUE)
            CloseHandle(h);
        ok(SetSddl(Path, LegacyFile), "outside %ls: DACL not set (%lu)\n", Path, GetLastError());
    }
    /* Program Files itself is protected (the repair then leaves the folder alone and walks what is in it); outside
       is protected too, so its files keep their DACL unless something sets it */
    ok(SetSddl(PF, L"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)"), "pf DACL (%lu)\n", GetLastError());
    ok(SetSddl(OUTSUB, L"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"), "outside DACL (%lu)\n", GetLastError());
}

/* The old DACL again on the scratch tree, as an install from before left it */
static ULONG MakeLegacy(void)
{
    WCHAR Path[MAX_PATH];
    ULONG i, Set = 0;

    Set += SetSddl(DIR1, LegacyDir);
    Set += SetSddl(SUB, LegacyDir);
    for (i = 0; i < FILES; i++)
    {
        StringCchPrintfW(Path, ARRAYSIZE(Path), SUB L"\\f%02lu", i);
        Set += SetSddl(Path, LegacyFile);
    }
    return Set;
}

/* Files of the scratch tree that no longer have the old Authenticated Users entry (repaired) */
static ULONG CountRepaired(void)
{
    WCHAR Path[MAX_PATH];
    ULONG i, n = 0;
    PWSTR Sddl;

    for (i = 0; i < FILES; i++)
    {
        StringCchPrintfW(Path, ARRAYSIZE(Path), SUB L"\\f%02lu", i);
        Sddl = GetSddl(Path);
        if (Sddl && !wcsstr(Sddl, L"(A;;0x1301bf;;;AU)"))
            n++;
        if (Sddl)
            LocalFree(Sddl);
    }
    return n;
}

static BOOL ReadValue(HKEY Key, PCWSTR Name, PWSTR Buffer, DWORD cb)
{
    DWORD Type;
    return RegQueryValueExW(Key, Name, NULL, &Type, (PBYTE)Buffer, &cb) == ERROR_SUCCESS;
}

static void EnablePrivilege(PCWSTR Name)
{
    TOKEN_PRIVILEGES Tp;
    HANDLE hToken;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
        return;
    Tp.PrivilegeCount = 1;
    Tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (LookupPrivilegeValueW(NULL, Name, &Tp.Privileges[0].Luid))
        AdjustTokenPrivileges(hToken, FALSE, &Tp, 0, NULL, NULL);
    CloseHandle(hToken);
}

START_TEST(ProgramFilesRepairSwap)
{
    BOOL (WINAPI *pSecureSystemDirectories)(VOID);
    WCHAR OldPf[MAX_PATH], OldPf86[MAX_PATH], Log[MAX_PATH], Saved[MAX_PATH], Path[MAX_PATH], User[64];
    PWSTR Before[FILES], After;
    BOOL HadPf, HadPf86, HadLog;
    ULONG Round, Rounds = 40, Changed = 0, RoundsRepaired = 0, i;
    DWORD cch = ARRAYSIZE(User);
    HANDLE Thread;
    HKEY Key;

    if (!is_reactos())
    {
        skip("SecureSystemDirectories is ours\n");
        return;
    }
    pSecureSystemDirectories = (PVOID)GetProcAddress(GetModuleHandleW(L"userenv.dll"), MAKEINTRESOURCEA(300));
    if (!pSecureSystemDirectories)
    {
        skip("No SecureSystemDirectories\n");
        return;
    }
    GetUserNameW(User, &cch);
    trace("running as %ls\n", User);
    EnablePrivilege(L"SeRestorePrivilege");
    EnablePrivilege(L"SeBackupPrivilege");

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, CV_KEY, 0, KEY_QUERY_VALUE | KEY_SET_VALUE | KEY_WOW64_64KEY, &Key) != ERROR_SUCCESS)
    {
        skip("CurrentVersion not opened\n");
        return;
    }
    HadPf = ReadValue(Key, L"ProgramFilesDir", OldPf, sizeof(OldPf));
    HadPf86 = ReadValue(Key, L"ProgramFilesDir (x86)", OldPf86, sizeof(OldPf86));
    ExpandEnvironmentStringsW(L"%SystemRoot%\\System32\\LogFiles\\FolderAcl\\program-files-repair.txt", Log, ARRAYSIZE(Log));
    StringCchPrintfW(Saved, ARRAYSIZE(Saved), L"%s.hbksave", Log);
    HadLog = MoveFileExW(Log, Saved, MOVEFILE_REPLACE_EXISTING);

    MakeTree();
    for (i = 0; i < FILES; i++)
    {
        StringCchPrintfW(Path, ARRAYSIZE(Path), OUTSUB L"\\f%02lu", i);
        Before[i] = GetSddl(Path);
    }
    RegSetValueExW(Key, L"ProgramFilesDir", 0, REG_SZ, (PBYTE)PF, sizeof(PF));
    RegSetValueExW(Key, L"ProgramFilesDir (x86)", 0, REG_SZ, (PBYTE)PF, sizeof(PF));

    s_Stop = 0;
    s_Pause = 1;
    s_Paused = 0;
    Thread = CreateThread(NULL, 0, Swapper, NULL, 0, NULL);
    ok(Thread != NULL, "CreateThread failed (%lu)\n", GetLastError());

    /* The race needs a swap during a repair: a fast repair can finish before the swapper thread gets to run (it
     * sleeps in 1 ms steps, which is one timer tick), so the repair starts only when the swapper has left its pause,
     * and the rounds go on (up to 2000) until the directory has been swapped at least once */
    for (Round = 0; Thread && (Round < Rounds || (s_Swaps == 0 && Round < 2000)); Round++)
    {
        ULONG Wait;

        PauseSwapper(TRUE);
        ok(MakeLegacy() == FILES + 2, "round %lu: the old DACL was not put back on every object\n", Round);
        DeleteFileW(Log);
        PauseSwapper(FALSE);
        for (Wait = 0; s_Paused && Wait < 1000; Wait++)
            Sleep(1);
        pSecureSystemDirectories();
        PauseSwapper(TRUE);
        if (CountRepaired() != 0)
            RoundsRepaired++;
    }

    if (Thread)
    {
        InterlockedExchange(&s_Stop, 1);
        WaitForSingleObject(Thread, INFINITE);
        CloseHandle(Thread);
    }

    /* Put back what the test changed */
    if (HadPf)
        RegSetValueExW(Key, L"ProgramFilesDir", 0, REG_SZ, (PBYTE)OldPf, (DWORD)(wcslen(OldPf) + 1) * sizeof(WCHAR));
    else
        RegDeleteValueW(Key, L"ProgramFilesDir");
    if (HadPf86)
        RegSetValueExW(Key, L"ProgramFilesDir (x86)", 0, REG_SZ, (PBYTE)OldPf86, (DWORD)(wcslen(OldPf86) + 1) * sizeof(WCHAR));
    else
        RegDeleteValueW(Key, L"ProgramFilesDir (x86)");
    RegCloseKey(Key);
    if (HadLog)
        MoveFileExW(Saved, Log, MOVEFILE_REPLACE_EXISTING);

    for (i = 0; i < FILES; i++)
    {
        StringCchPrintfW(Path, ARRAYSIZE(Path), OUTSUB L"\\f%02lu", i);
        After = GetSddl(Path);
        if (!Before[i] || !After || wcscmp(Before[i], After))
        {
            if (Changed++ < 5)
                ok(0, "%ls (outside the tree) changed: %ls -> %ls\n", Path, Before[i] ? Before[i] : L"?", After ? After : L"?");
        }
        if (After)
            LocalFree(After);
        if (Before[i])
            LocalFree(Before[i]);
    }
    trace("%lu rounds, %ld swaps, scratch tree repaired in %lu rounds, %lu objects outside changed\n",
          Round, s_Swaps, RoundsRepaired, Changed);
    ok(Changed == 0, "%lu objects outside the tree were changed by the repair\n", Changed);
    ok(RoundsRepaired > 0, "the scratch tree was never repaired: the repair did not run\n");
    ok(s_Swaps > 0, "the directory was never swapped\n");

    PublicResetSwap();
}

/*
 * The same for the reset of a profile directory at a profile load (UpgradeProfileSecurity: the Public profile, when its
 * DACL is not protected, gets the DACL of Windows and everything below it its inheritance alone). The Public value of
 * ProfileList points to the scratch tree (restored afterwards), a test user's profile is loaded and unloaded each
 * round while the swapper runs.
 */
static void PublicResetSwap(void)
{
    static const WCHAR ProfileList[] = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList";
    WCHAR OldPublic[MAX_PATH], Path[MAX_PATH], Password[] = L"Hbk-Swap-2026!x", UserName[] = L"hbkswap";
    PWSTR Before[FILES], After;
    USER_INFO_1 Info = {0};
    PROFILEINFOW Profile;
    HANDLE Thread, Token = NULL;
    BOOL HadPublic;
    DWORD Type, cb = sizeof(OldPublic);
    ULONG Round, Rounds = 20, Changed = 0, RoundsRepaired = 0, Loads = 0, i;
    HKEY Key;

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, ProfileList, 0, KEY_QUERY_VALUE | KEY_SET_VALUE | KEY_WOW64_64KEY, &Key) != ERROR_SUCCESS)
    {
        skip("ProfileList not opened\n");
        return;
    }
    HadPublic = RegQueryValueExW(Key, L"Public", NULL, &Type, (PBYTE)OldPublic, &cb) == ERROR_SUCCESS;
    if (!HadPublic)
        Type = REG_EXPAND_SZ;

    Info.usri1_name = UserName;
    Info.usri1_password = Password;
    Info.usri1_priv = USER_PRIV_USER;
    Info.usri1_flags = UF_SCRIPT;
    NetUserAdd(NULL, 1, (PBYTE)&Info, NULL);
    if (!LogonUserW(UserName, L".", Password, LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, &Token))
    {
        skip("LogonUserW failed (%lu)\n", GetLastError());
        RegCloseKey(Key);
        return;
    }

    for (i = 0; i < FILES; i++)
    {
        StringCchPrintfW(Path, ARRAYSIZE(Path), OUTSUB L"\\f%02lu", i);
        Before[i] = GetSddl(Path);
    }
    RegSetValueExW(Key, L"Public", 0, REG_SZ, (PBYTE)PF, sizeof(PF));

    s_Stop = 0;
    s_Pause = 1;
    s_Paused = 0;
    s_Swaps = 0;
    Thread = CreateThread(NULL, 0, Swapper, NULL, 0, NULL);
    ok(Thread != NULL, "CreateThread failed (%lu)\n", GetLastError());

    for (Round = 0; Thread && Round < Rounds; Round++)
    {
        PauseSwapper(TRUE);
        MakeLegacy();
        /* a Public folder of an older install: not protected */
        SetSddl(PF, LegacyDir);
        PauseSwapper(FALSE);
        ZeroMemory(&Profile, sizeof(Profile));
        Profile.dwSize = sizeof(Profile);
        Profile.dwFlags = PI_NOUI;
        Profile.lpUserName = UserName;
        if (LoadUserProfileW(Token, &Profile))
        {
            Loads++;
            UnloadUserProfile(Token, Profile.hProfile);
        }
        PauseSwapper(TRUE);
        if (CountRepaired() != 0)
            RoundsRepaired++;
    }

    if (Thread)
    {
        InterlockedExchange(&s_Stop, 1);
        WaitForSingleObject(Thread, INFINITE);
        CloseHandle(Thread);
    }
    if (HadPublic)
        RegSetValueExW(Key, L"Public", 0, Type, (PBYTE)OldPublic, (DWORD)(wcslen(OldPublic) + 1) * sizeof(WCHAR));
    else
        RegDeleteValueW(Key, L"Public");
    RegCloseKey(Key);
    CloseHandle(Token);

    for (i = 0; i < FILES; i++)
    {
        StringCchPrintfW(Path, ARRAYSIZE(Path), OUTSUB L"\\f%02lu", i);
        After = GetSddl(Path);
        if (!Before[i] || !After || wcscmp(Before[i], After))
        {
            if (Changed++ < 5)
                ok(0, "Public reset: %ls (outside the tree) changed: %ls -> %ls\n", Path, Before[i] ? Before[i] : L"?",
                   After ? After : L"?");
        }
        if (After)
            LocalFree(After);
        if (Before[i])
            LocalFree(Before[i]);
    }
    trace("Public reset: %lu rounds, %lu profile loads, %ld swaps, scratch tree reset in %lu rounds, %lu objects outside changed\n",
          Rounds, Loads, s_Swaps, RoundsRepaired, Changed);
    ok(Changed == 0, "Public reset: %lu objects outside the tree were changed\n", Changed);
    ok(RoundsRepaired > 0, "Public reset: the scratch tree was never reset: the reset did not run\n");
}
