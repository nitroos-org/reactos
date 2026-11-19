/*
 * PROJECT:     ReactOS net command
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     NET USE
 * COPYRIGHT:   Copyright Pierre Schweitzer (the first version)
 *              Copyright 2026 Tomas Srnka
 */

/*
 * NET USE                                           list the connections
 * NET USE [devicename | *] [\\computer\share[\path] [password | *]]
 *         [/USER:[domain\]user | /USER:user@domain] [/SAVECRED]
 *         [[/DELETE] | [/PERSISTENT:{YES | NO}]]
 * NET USE {devicename | *} [password | *] /HOME      (not supported: no home directory)
 * NET USE [/PERSISTENT:{YES | NO}]                   the default for new connections
 *
 * Everything goes through mpr (WNetUseConnection, WNetCancelConnection2, WNetOpenEnum), so the
 * network providers do the work. A password typed at the "*" prompt is read without echo and
 * wiped after use; nothing here stores one.
 */

#include "net.h"
#include <winreg.h>

extern HMODULE hModuleNetMsg;

#define MSG_REMEMBERED          3676
#define MSG_NOT_REMEMBERED      3677
#define MSG_NO_ENTRIES          3683
#define MSG_OPEN_FILES          3691
#define MSG_DRIVE_CONNECTED     3919
#define MSG_STATUS_OK           4343
#define MSG_TYPE_PASSWORD       4357
#define MSG_DELETED             4650
#define MSG_HEADER              4714
#define MSG_DISCONNECTED        4718
#define MSG_UNAVAILABLE         4728
#define MSG_FORCE_CLOSE         5289
#define MSG_SUCCESS             3500

static const WCHAR PersistentKey[] = L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Network\\Persistent Connections";

/* The user's default for new connections (Windows: "yes" unless set to "no") */
static
BOOL
GetRememberDefault(VOID)
{
    WCHAR Value[8];
    DWORD Size = sizeof(Value), Type;
    HKEY Key;
    BOOL Remember = TRUE;

    if (RegOpenKeyExW(HKEY_CURRENT_USER, PersistentKey, 0, KEY_READ, &Key) == ERROR_SUCCESS)
    {
        if (RegQueryValueExW(Key, L"SaveConnections", NULL, &Type, (LPBYTE)Value, &Size) == ERROR_SUCCESS &&
            Type == REG_SZ && _wcsnicmp(Value, L"no", 2) == 0)
        {
            Remember = FALSE;
        }
        RegCloseKey(Key);
    }
    return Remember;
}

static
DWORD
SetRememberDefault(BOOL Remember)
{
    LPCWSTR Value = Remember ? L"yes" : L"no";
    HKEY Key;
    DWORD Error;

    Error = RegCreateKeyExW(HKEY_CURRENT_USER, PersistentKey, 0, NULL, 0, KEY_SET_VALUE, NULL, &Key, NULL);
    if (Error != ERROR_SUCCESS)
        return Error;
    Error = RegSetValueExW(Key, L"SaveConnections", 0, REG_SZ, (const BYTE *)Value,
                           (DWORD)(wcslen(Value) + 1) * sizeof(WCHAR));
    RegCloseKey(Key);
    return Error;
}

/* A line from standard input; without echo for passwords. The caller wipes the buffer. */
static
VOID
ReadLine(LPWSTR Line, DWORD Chars, BOOL Echo)
{
    HANDLE Input = GetStdHandle(STD_INPUT_HANDLE);
    CHAR Buffer[512];
    DWORD Mode = 0, Read = 0, i;
    BOOL Console = GetConsoleMode(Input, &Mode);

    ZeroMemory(Line, Chars * sizeof(WCHAR));
    if (Console)
        SetConsoleMode(Input, ENABLE_LINE_INPUT | ENABLE_PROCESSED_INPUT | (Echo ? ENABLE_ECHO_INPUT : 0));
    if (!ReadFile(Input, Buffer, min(sizeof(Buffer) - 1, Chars - 1), &Read, NULL))
        Read = 0;
    if (Console)
        SetConsoleMode(Input, Mode);
    for (i = 0; i < Read; i++)
    {
        if (Buffer[i] == '\r' || Buffer[i] == '\n')
            break;
    }
    MultiByteToWideChar(GetConsoleCP(), 0, Buffer, i, Line, Chars - 1);
    SecureZeroMemory(Buffer, sizeof(Buffer));
    if (!Echo && Console)
        ConPuts(StdOut, L"\n");
}

static
BOOL
IsDeviceName(LPCWSTR Name)
{
    return Name[0] && iswalpha(Name[0]) && Name[1] == L':' && !Name[2];
}

static
BOOL
IsRemoteName(LPCWSTR Name)
{
    return Name[0] == L'\\' && Name[1] == L'\\' && Name[2] && Name[2] != L'\\';
}

static
VOID
PrintRow(DWORD StatusMessage, LPCWSTR Local, LPCWSTR Remote, LPCWSTR Provider)
{
    PWSTR Status = NULL;
    SIZE_T n;

    if (StatusMessage)
        FormatMessageW(FORMAT_MESSAGE_FROM_HMODULE | FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_IGNORE_INSERTS,
                       hModuleNetMsg, StatusMessage, LANG_USER_DEFAULT, (LPWSTR)&Status, 0, NULL);
    ConPrintf(StdOut, L"%-13s%-10s", Status ? Status : L"", Local ? Local : L"");
    n = wcslen(Remote);
    if (n > 25)
        ConPrintf(StdOut, L"%s\n%-48s%s\n", Remote, L"", Provider ? Provider : L"");
    else
        ConPrintf(StdOut, L"%-26s%s\n", Remote, Provider ? Provider : L"");
    if (Status)
        LocalFree(Status);
}

/* NET USE (all) or NET USE X: / \\server\share (one): connected and remembered connections */
static
INT
ListConnections(LPCWSTR Only)
{
    LPNETRESOURCEW Buffer;
    DWORD Size = 0x4000, Count, Error, i, Shown = 0, Phase;
    WCHAR Seen[26] = { 0 };
    HANDLE Enum;

    Buffer = HeapAlloc(GetProcessHeap(), 0, Size);
    if (Buffer == NULL)
        return 1;

    if (Only == NULL)
    {
        PrintMessageString(GetRememberDefault() ? MSG_REMEMBERED : MSG_NOT_REMEMBERED);
        ConPuts(StdOut, L"\n\n");
    }

    /* Phase 0: connected; phase 1: remembered drives that are not connected */
    for (Phase = 0; Phase < 2; Phase++)
    {
        Error = WNetOpenEnumW(Phase == 0 ? RESOURCE_CONNECTED : RESOURCE_REMEMBERED, RESOURCETYPE_ANY, 0, NULL, &Enum);
        if (Error != WN_SUCCESS)
            continue;
        for (;;)
        {
            Count = (DWORD)-1;
            Size = 0x4000;
            Error = WNetEnumResourceW(Enum, &Count, Buffer, &Size);
            if (Error != WN_SUCCESS)
                break;
            for (i = 0; i < Count; i++)
            {
                LPNETRESOURCEW r = &Buffer[i];
                LPCWSTR Local = (r->lpLocalName && r->lpLocalName[0]) ? r->lpLocalName : NULL;
                DWORD Status = MSG_STATUS_OK;

                if (r->lpRemoteName == NULL)
                    continue;
                if (Only && !(Local && !_wcsicmp(Local, Only)) && _wcsicmp(r->lpRemoteName, Only))
                    continue;
                if (Local && iswalpha(Local[0]))
                {
                    WCHAR l = towupper(Local[0]) - L'A';

                    if (l < 26)
                    {
                        if (Seen[l])
                            continue;
                        Seen[l] = 1;
                    }
                }
                if (Phase == 1)
                    Status = MSG_UNAVAILABLE;
                if (Shown++ == 0)
                {
                    ConPuts(StdOut, L"\n");
                    PrintMessageString(MSG_HEADER);
                    ConPuts(StdOut, L"\n\n");
                    ConPuts(StdOut, L"-------------------------------------------------------------------------------\n");
                }
                PrintRow(Status, Local, r->lpRemoteName, r->lpProvider);
            }
        }
        WNetCloseEnum(Enum);
    }
    HeapFree(GetProcessHeap(), 0, Buffer);

    if (Shown == 0)
    {
        if (Only != NULL)
        {
            PrintErrorMessage(ERROR_NOT_CONNECTED);
            return 2;
        }
        PrintMessageString(MSG_NO_ENTRIES);
        ConPuts(StdOut, L"\n");
        return 0;
    }
    PrintMessageString(MSG_SUCCESS);
    ConPuts(StdOut, L"\n");
    return 0;
}

static
INT
DeleteConnection(LPCWSTR Name)
{
    DWORD Error;
    WCHAR Answer[8];

    Error = WNetCancelConnection2W(Name, CONNECT_UPDATE_PROFILE, FALSE);
    if (Error == ERROR_OPEN_FILES)
    {
        /* Windows asks before it closes them */
        PrintMessageStringV(MSG_OPEN_FILES, Name);
        ConPuts(StdOut, L"\n\n");
        PrintMessageStringV(MSG_FORCE_CLOSE, L"(Y/N) [N]");
        ReadLine(Answer, ARRAYSIZE(Answer), TRUE);
        if (towupper(Answer[0]) != L'Y')
        {
            PrintErrorMessage(ERROR_CANCELLED);
            return 2;
        }
        Error = WNetCancelConnection2W(Name, CONNECT_UPDATE_PROFILE, TRUE);
    }
    if (Error != NO_ERROR)
    {
        PrintErrorMessage(Error);
        return 2;
    }
    PrintMessageStringV(MSG_DELETED, Name);
    ConPuts(StdOut, L"\n\n");
    return 0;
}

INT
cmdUse(
    INT argc,
    WCHAR **argv)
{
    LPCWSTR Device = NULL, Remote = NULL, User = NULL;
    LPWSTR Password = NULL;
    WCHAR Typed[PWLEN + 1], Access[MAX_PATH];
    BOOL Delete = FALSE, PasswordPrompt = FALSE, HaveRemember = FALSE, Remember = FALSE;
    DWORD Error, Flags, Size = ARRAYSIZE(Access), Result = 0;
    NETRESOURCEW Resource;
    INT i, Positional = 0, Ret;

    for (i = 2; i < argc; i++)
    {
        LPCWSTR a = argv[i];

        if (a[0] == L'/')
        {
            if (_wcsicmp(a, L"/help") == 0 || _wcsicmp(a, L"/?") == 0)
            {
                PrintCommandHelp(MSG_USE_SYNTAX, MSG_USE_HELP);
                return 0;
            }
            else if (_wcsicmp(a, L"/delete") == 0 || _wcsicmp(a, L"/d") == 0)
                Delete = TRUE;
            else if (_wcsnicmp(a, L"/user:", 6) == 0 || _wcsnicmp(a, L"/u:", 3) == 0)
                User = wcschr(a, L':') + 1;
            else if (_wcsnicmp(a, L"/persistent:", 12) == 0 || _wcsnicmp(a, L"/p:", 3) == 0)
            {
                LPCWSTR v = wcschr(a, L':') + 1;

                if (_wcsicmp(v, L"yes") == 0 || _wcsicmp(v, L"y") == 0)
                    Remember = TRUE;
                else if (_wcsicmp(v, L"no") == 0 || _wcsicmp(v, L"n") == 0)
                    Remember = FALSE;
                else
                    return PrintCommandSyntax(MSG_USE_SYNTAX, 3952, L"/PERSISTENT");
                HaveRemember = TRUE;
            }
            else if (_wcsicmp(a, L"/savecred") == 0)
            {
                /* Accepted as Windows accepts it (measured: the connection is made as without it);
                 * nothing is stored: there is no credential manager to store into */
            }
            else
            {
                return PrintUnknownOption(MSG_USE_SYNTAX, a);
            }
            continue;
        }

        switch (Positional++)
        {
            case 0:
                if (IsRemoteName(a))
                {
                    Remote = a;
                    Positional++;
                }
                else if (IsDeviceName(a) || (a[0] == L'*' && !a[1]))
                    Device = a;
                else
                    return PrintCommandSyntax(MSG_USE_SYNTAX, 3952, a);
                break;
            case 1:
                if (!IsRemoteName(a))
                {
                    if (Device != NULL && !Delete)
                    {
                        /* "NET USE X: password /HOME" */
                        PrintErrorMessage(ERROR_NOT_SUPPORTED);
                        return 2;
                    }
                    return PrintCommandSyntax(MSG_USE_SYNTAX, 3952, a);
                }
                Remote = a;
                break;
            case 2:
                if (a[0] == L'*' && !a[1])
                    PasswordPrompt = TRUE;
                else
                    Password = (LPWSTR)a;
                break;
            default:
                return PrintCommandSyntax(MSG_USE_SYNTAX, 3952, a);
        }
    }

    /* NET USE [/PERSISTENT:...] */
    if (Device == NULL && Remote == NULL && !Delete)
    {
        if (User != NULL)
            return PrintCommandSyntax(MSG_USE_SYNTAX, 3952, L"/USER");
        if (HaveRemember)
        {
            Error = SetRememberDefault(Remember);
            return PrintCommandStatus(Error);
        }
        return ListConnections(NULL);
    }

    if (Delete)
    {
        if (Device != NULL && Device[0] == L'*')
        {
            /* All of them (Windows asks first) */
            HANDLE Enum;
            LPNETRESOURCEW Buffer = HeapAlloc(GetProcessHeap(), 0, 0x4000);
            DWORD Count = (DWORD)-1, BufSize = 0x4000, j;

            if (Buffer == NULL)
                return 1;
            Ret = 0;
            if (WNetOpenEnumW(RESOURCE_CONNECTED, RESOURCETYPE_ANY, 0, NULL, &Enum) == WN_SUCCESS)
            {
                while (WNetEnumResourceW(Enum, &Count, Buffer, &BufSize) == WN_SUCCESS)
                {
                    for (j = 0; j < Count; j++)
                    {
                        LPCWSTR Name = (Buffer[j].lpLocalName && Buffer[j].lpLocalName[0]) ?
                                       Buffer[j].lpLocalName : Buffer[j].lpRemoteName;

                        if (Name && DeleteConnection(Name) != 0)
                            Ret = 2;
                    }
                    Count = (DWORD)-1;
                    BufSize = 0x4000;
                }
                WNetCloseEnum(Enum);
            }
            HeapFree(GetProcessHeap(), 0, Buffer);
            return Ret;
        }
        return DeleteConnection(Device != NULL ? Device : Remote);
    }

    /* NET USE X: or NET USE \\server\share: show that one */
    if (Remote == NULL)
        return ListConnections(Device);

    if (PasswordPrompt)
    {
        PrintMessageStringV(MSG_TYPE_PASSWORD, Remote);
        ReadLine(Typed, ARRAYSIZE(Typed), FALSE);
        Password = Typed;
    }

    ZeroMemory(&Resource, sizeof(Resource));
    Resource.dwType = RESOURCETYPE_DISK;
    Resource.lpRemoteName = (LPWSTR)Remote;
    Resource.lpLocalName = (Device != NULL && Device[0] != L'*') ? (LPWSTR)Device : NULL;

    if (!HaveRemember)
        Remember = GetRememberDefault();
    Flags = 0;
    if (Device != NULL && Device[0] == L'*')
        Flags |= CONNECT_REDIRECT;
    if (Remember && Device != NULL)
        Flags |= CONNECT_UPDATE_PROFILE;

    Error = WNetUseConnectionW(NULL, &Resource, Password, User, Flags,
                               (Flags & CONNECT_REDIRECT) ? Access : NULL,
                               (Flags & CONNECT_REDIRECT) ? &Size : NULL, &Result);
    if (PasswordPrompt)
        SecureZeroMemory(Typed, sizeof(Typed));
    else if (Password != NULL)
        SecureZeroMemory(Password, wcslen(Password) * sizeof(WCHAR));

    if (Error != NO_ERROR)
    {
        PrintErrorMessage(Error);
        return 2;
    }
    if ((Flags & CONNECT_REDIRECT) && (Result & CONNECT_LOCALDRIVE))
    {
        PrintMessageStringV(MSG_DRIVE_CONNECTED, Access, Remote);
        ConPuts(StdOut, L"\n\n");
    }
    PrintMessageString(MSG_SUCCESS);
    ConPuts(StdOut, L"\n\n");
    return 0;
}
