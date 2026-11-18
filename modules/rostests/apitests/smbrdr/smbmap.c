/*
 * PROJECT:     NitroOS
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     smbmap: maps a drive letter of the caller's logon session to an SMB share
 *              through the mini-redirector, the way a network provider will (test tool:
 *              there is no network provider and no 'net use' for SMB yet)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

/*
 * smbmap X: \\server\share    tree connect, then X: -> \Device\LanmanRedirector\;X:<logon id>\server\share
 * smbmap /d X:                remove the drive letter
 * smbmap /q X:                print QueryDosDevice and GetDriveType of X:
 * The drive letter is defined with DefineDosDevice (raw target), so it lives in the device map
 * of the caller's logon session, as on Windows (measured: \Device\LanmanRedirector\;Q:<16 hex
 * digit logon id>\server\share). The tree connect is an NtCreateFile of that name with
 * FILE_CREATE_TREE_CONNECTION; it proves the share is reachable before the letter appears.
 * Exit code: 0, or the Win32 error.
 */

#include <stdio.h>
#include <wchar.h>

#define WIN32_NO_STATUS
#include <windows.h>
#include <ndk/iofuncs.h>
#include <ndk/obfuncs.h>
#include <ndk/rtlfuncs.h>
#include <ntstatus.h>

static int usage(void)
{
    printf("usage: smbmap X: \\\\server\\share | smbmap /d X: | smbmap /q X:\n");
    return ERROR_INVALID_PARAMETER;
}

static int query(const WCHAR *drive)
{
    WCHAR target[1024], root[4];
    DWORD n = QueryDosDeviceW(drive, target, ARRAYSIZE(target));

    _snwprintf(root, ARRAYSIZE(root), L"%c:\\", drive[0]);
    root[ARRAYSIZE(root) - 1] = 0;
    if (n == 0)
        printf("QueryDosDevice(%ls) failed %lu\n", drive, GetLastError());
    else
        printf("QueryDosDevice(%ls) = %ls\n", drive, target);
    printf("GetDriveType(%ls) = %u\n", root, GetDriveTypeW(root));
    return n ? 0 : (int)GetLastError();
}

int wmain(int argc, WCHAR **argv)
{
    WCHAR drive[3], target[1024], ntname[1024];
    TOKEN_STATISTICS stats;
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES oa;
    IO_STATUS_BLOCK iosb;
    HANDLE token, h;
    NTSTATUS st;
    DWORD len;
    const WCHAR *unc;

    if (argc == 3 && (!_wcsicmp(argv[1], L"/d") || !_wcsicmp(argv[1], L"/q")))
    {
        if (wcslen(argv[2]) != 2 || argv[2][1] != L':')
            return usage();
        drive[0] = towupper(argv[2][0]);
        drive[1] = L':';
        drive[2] = 0;
        if (!_wcsicmp(argv[1], L"/q"))
            return query(drive);
        if (!QueryDosDeviceW(drive, target, ARRAYSIZE(target)))
        {
            printf("smbmap: %ls is not defined (%lu)\n", drive, GetLastError());
            return (int)GetLastError();
        }
        if (!DefineDosDeviceW(DDD_RAW_TARGET_PATH | DDD_REMOVE_DEFINITION | DDD_EXACT_MATCH_ON_REMOVE | DDD_NO_BROADCAST_SYSTEM,
                              drive, target))
        {
            printf("smbmap: remove %ls failed %lu\n", drive, GetLastError());
            return (int)GetLastError();
        }
        printf("smbmap: %ls removed\n", drive);
        return 0;
    }

    if (argc != 3 || wcslen(argv[1]) != 2 || argv[1][1] != L':' ||
        argv[2][0] != L'\\' || argv[2][1] != L'\\' || wcslen(argv[2]) > 512)
        return usage();
    drive[0] = towupper(argv[1][0]);
    drive[1] = L':';
    drive[2] = 0;
    unc = argv[2] + 1;  /* \server\share */

    /* The logon session of the caller: its device map gets the letter */
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token) ||
        !GetTokenInformation(token, TokenStatistics, &stats, sizeof(stats), &len))
    {
        printf("smbmap: token query failed %lu\n", GetLastError());
        return (int)GetLastError();
    }
    CloseHandle(token);

    _snwprintf(target, ARRAYSIZE(target) - 1, L"\\Device\\LanmanRedirector\\;%ls%08lx%08lx%ls", drive,
               (ULONG)stats.AuthenticationId.HighPart, stats.AuthenticationId.LowPart, unc);
    target[ARRAYSIZE(target) - 1] = 0;

    /* Tree connect: the share must answer before the letter exists */
    wcscpy(ntname, target);
    RtlInitUnicodeString(&name, ntname);
    InitializeObjectAttributes(&oa, &name, OBJ_CASE_INSENSITIVE, NULL, NULL);
    st = NtCreateFile(&h, SYNCHRONIZE, &oa, &iosb, NULL, FILE_ATTRIBUTE_NORMAL,
                      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_OPEN_IF,
                      FILE_CREATE_TREE_CONNECTION | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
    if (!NT_SUCCESS(st))
    {
        printf("smbmap: tree connect %ls failed 0x%08lx (win32 %lu)\n", target, st, RtlNtStatusToDosError(st));
        return (int)RtlNtStatusToDosError(st);
    }
    NtClose(h);

    if (!DefineDosDeviceW(DDD_RAW_TARGET_PATH | DDD_NO_BROADCAST_SYSTEM, drive, target))
    {
        printf("smbmap: DefineDosDevice %ls failed %lu\n", drive, GetLastError());
        return (int)GetLastError();
    }
    printf("smbmap: %ls -> %ls\n", drive, target);
    return query(drive);
}
