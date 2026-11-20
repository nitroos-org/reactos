/*
 *  ReactOS kernel
 *  Copyright (C) 2004 ReactOS Team
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
/*
 * COPYRIGHT:       See COPYING in the top level directory
 * PROJECT:         ReactOS system libraries
 * FILE:            dll/win32/userenv/environment.c
 * PURPOSE:         User environment functions
 * PROGRAMMER:      Eric Kohl
 */

#include "precomp.h"

#define NDEBUG
#include <debug.h>

static
BOOL
SetUserEnvironmentVariable(PWSTR* Environment,
                           LPCWSTR lpName,
                           LPCWSTR lpValue,
                           BOOL bExpand)
{
    NTSTATUS Status;
    UNICODE_STRING Name;
    UNICODE_STRING SrcValue, DstValue;
    ULONG Length;
    PVOID Buffer = NULL;
    WCHAR ShortName[MAX_PATH];

    if (bExpand)
    {
        RtlInitUnicodeString(&SrcValue, lpValue);

        Length = 2 * MAX_PATH * sizeof(WCHAR);

        DstValue.Length = 0;
        DstValue.MaximumLength = Length;
        DstValue.Buffer = Buffer = LocalAlloc(LPTR, Length);
        if (DstValue.Buffer == NULL)
        {
            DPRINT1("LocalAlloc() failed\n");
            return FALSE;
        }

        Status = RtlExpandEnvironmentStrings_U(*Environment,
                                               &SrcValue,
                                               &DstValue,
                                               &Length);
        if (!NT_SUCCESS(Status))
        {
            DPRINT1("RtlExpandEnvironmentStrings_U() failed (Status %lx)\n", Status);
            DPRINT1("Length %lu\n", Length);

            if (Buffer)
                LocalFree(Buffer);

            return FALSE;
        }
    }
    else
    {
        RtlInitUnicodeString(&DstValue, lpValue);
    }

    if (!_wcsicmp(lpName, L"TEMP") || !_wcsicmp(lpName, L"TMP"))
    {
        if (GetShortPathNameW(DstValue.Buffer, ShortName, ARRAYSIZE(ShortName)))
        {
            RtlInitUnicodeString(&DstValue, ShortName);
        }
        else
        {
            DPRINT("GetShortPathNameW() failed for %S (Error %lu)\n", DstValue.Buffer, GetLastError());
        }
    }

    RtlInitUnicodeString(&Name, lpName);

    DPRINT("Value: %wZ\n", &DstValue);

    Status = RtlSetEnvironmentVariable(Environment,
                                       &Name,
                                       &DstValue);

    if (Buffer)
        LocalFree(Buffer);

    if (!NT_SUCCESS(Status))
    {
        DPRINT1("RtlSetEnvironmentVariable() failed (Status %lx)\n", Status);
        return FALSE;
    }

    return TRUE;
}


static
BOOL
AppendUserEnvironmentVariable(PWSTR* Environment,
                              LPWSTR lpName,
                              LPWSTR lpValue)
{
    NTSTATUS Status;
    UNICODE_STRING Name, Value;

    RtlInitUnicodeString(&Name, lpName);

    Value.Length = 0;
    Value.MaximumLength = 1024 * sizeof(WCHAR);
    Value.Buffer = LocalAlloc(LPTR, Value.MaximumLength);
    if (Value.Buffer == NULL)
        return FALSE;

    Value.Buffer[0] = UNICODE_NULL;

    Status = RtlQueryEnvironmentVariable_U(*Environment,
                                           &Name,
                                           &Value);
    if (NT_SUCCESS(Status))
        RtlAppendUnicodeToString(&Value, L";");

    RtlAppendUnicodeToString(&Value, lpValue);

    Status = RtlSetEnvironmentVariable(Environment,
                                       &Name,
                                       &Value);
    LocalFree(Value.Buffer);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("RtlSetEnvironmentVariable() failed (Status %lx)\n", Status);
        return FALSE;
    }

    return TRUE;
}


static
HKEY
GetCurrentUserKey(HANDLE hToken)
{
    LONG Error;
    UNICODE_STRING SidString;
    HKEY hKey;

    if (!GetUserSidStringFromToken(hToken, &SidString))
    {
        DPRINT1("GetUserSidFromToken() failed\n");
        return NULL;
    }

    Error = RegOpenKeyExW(HKEY_USERS,
                          SidString.Buffer,
                          0,
                          MAXIMUM_ALLOWED,
                          &hKey);
    if (Error != ERROR_SUCCESS)
    {
        DPRINT1("RegOpenKeyExW() failed (Error %ld)\n", Error);
        RtlFreeUnicodeString(&SidString);
        SetLastError((DWORD)Error);
        return NULL;
    }

    RtlFreeUnicodeString(&SidString);

    return hKey;
}


static
BOOL
GetUserAndDomainName(IN HANDLE hToken,
                     OUT LPWSTR *UserName,
                     OUT LPWSTR *DomainName)
{
    BOOL bRet = TRUE;
    PSID Sid = NULL;
    LPWSTR lpUserName = NULL;
    LPWSTR lpDomainName = NULL;
    DWORD cbUserName = 0;
    DWORD cbDomainName = 0;
    SID_NAME_USE SidNameUse;

    Sid = GetUserSid(hToken);
    if (Sid == NULL)
    {
        DPRINT1("GetUserSid() failed\n");
        return FALSE;
    }

    if (!LookupAccountSidW(NULL,
                           Sid,
                           NULL,
                           &cbUserName,
                           NULL,
                           &cbDomainName,
                           &SidNameUse))
    {
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
        {
            bRet = FALSE;
            goto done;
        }
    }

    lpUserName = LocalAlloc(LPTR, cbUserName * sizeof(WCHAR));
    if (lpUserName == NULL)
    {
        bRet = FALSE;
        goto done;
    }

    lpDomainName = LocalAlloc(LPTR, cbDomainName * sizeof(WCHAR));
    if (lpDomainName == NULL)
    {
        bRet = FALSE;
        goto done;
    }

    if (!LookupAccountSidW(NULL,
                           Sid,
                           lpUserName,
                           &cbUserName,
                           lpDomainName,
                           &cbDomainName,
                           &SidNameUse))
    {
        bRet = FALSE;
        goto done;
    }

    *UserName = lpUserName;
    *DomainName = lpDomainName;

done:
    if (bRet == FALSE)
    {
        if (lpUserName != NULL)
            LocalFree(lpUserName);

        if (lpDomainName != NULL)
            LocalFree(lpDomainName);
    }

    LocalFree(Sid);

    return bRet;
}


static
BOOL
SetUserEnvironment(PWSTR* Environment,
                   HKEY hKey,
                   LPWSTR lpSubKeyName)
{
    LONG Error;
    HKEY hEnvKey;
    DWORD dwValues;
    DWORD dwMaxValueNameLength;
    DWORD dwMaxValueDataLength;
    DWORD dwValueNameLength;
    DWORD dwValueDataLength;
    DWORD dwType;
    DWORD i;
    LPWSTR lpValueName;
    LPWSTR lpValueData;

    Error = RegOpenKeyExW(hKey,
                          lpSubKeyName,
                          0,
                          KEY_QUERY_VALUE,
                          &hEnvKey);
    if (Error != ERROR_SUCCESS)
    {
        DPRINT1("RegOpenKeyExW() failed (Error %ld)\n", Error);
        SetLastError((DWORD)Error);
        return FALSE;
    }

    Error = RegQueryInfoKey(hEnvKey,
                            NULL,
                            NULL,
                            NULL,
                            NULL,
                            NULL,
                            NULL,
                            &dwValues,
                            &dwMaxValueNameLength,
                            &dwMaxValueDataLength,
                            NULL,
                            NULL);
    if (Error != ERROR_SUCCESS)
    {
        DPRINT1("RegQueryInforKey() failed (Error %ld)\n", Error);
        RegCloseKey(hEnvKey);
        SetLastError((DWORD)Error);
        return FALSE;
    }

    if (dwValues == 0)
    {
        RegCloseKey(hEnvKey);
        return TRUE;
    }

    /* Allocate buffers */
    dwMaxValueNameLength++;
    lpValueName = LocalAlloc(LPTR, dwMaxValueNameLength * sizeof(WCHAR));
    if (lpValueName == NULL)
    {
        RegCloseKey(hEnvKey);
        return FALSE;
    }

    lpValueData = LocalAlloc(LPTR, dwMaxValueDataLength);
    if (lpValueData == NULL)
    {
        LocalFree(lpValueName);
        RegCloseKey(hEnvKey);
        return FALSE;
    }

    /* Enumerate values */
    for (i = 0; i < dwValues; i++)
    {
        dwValueNameLength = dwMaxValueNameLength;
        dwValueDataLength = dwMaxValueDataLength;

        Error = RegEnumValueW(hEnvKey,
                              i,
                              lpValueName,
                              &dwValueNameLength,
                              NULL,
                              &dwType,
                              (LPBYTE)lpValueData,
                              &dwValueDataLength);
        if (Error == ERROR_SUCCESS)
        {
            if (!_wcsicmp(lpValueName, L"PATH"))
            {
                /* Append 'Path' environment variable */
                AppendUserEnvironmentVariable(Environment,
                                              lpValueName,
                                              lpValueData);
            }
            else
            {
                /* Set environment variable */
                SetUserEnvironmentVariable(Environment,
                                           lpValueName,
                                           lpValueData,
                                           (dwType == REG_EXPAND_SZ));
            }
        }
        else
        {
            LocalFree(lpValueData);
            LocalFree(lpValueName);
            RegCloseKey(hEnvKey);

            return FALSE;
        }
    }

    LocalFree(lpValueData);
    LocalFree(lpValueName);
    RegCloseKey(hEnvKey);

    return TRUE;
}


static
BOOL
SetSystemEnvironment(PWSTR* Environment)
{
    LONG Error;
    HKEY hEnvKey;
    DWORD dwValues;
    DWORD dwMaxValueNameLength;
    DWORD dwMaxValueDataLength;
    DWORD dwValueNameLength;
    DWORD dwValueDataLength;
    DWORD dwType;
    DWORD i;
    LPWSTR lpValueName;
    LPWSTR lpValueData;

    Error = RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                          L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment",
                          0,
                          KEY_QUERY_VALUE,
                          &hEnvKey);
    if (Error != ERROR_SUCCESS)
    {
        DPRINT1("RegOpenKeyExW() failed (Error %ld)\n", Error);
        return FALSE;
    }

    Error = RegQueryInfoKey(hEnvKey,
                            NULL,
                            NULL,
                            NULL,
                            NULL,
                            NULL,
                            NULL,
                            &dwValues,
                            &dwMaxValueNameLength,
                            &dwMaxValueDataLength,
                            NULL,
                            NULL);
    if (Error != ERROR_SUCCESS)
    {
        DPRINT1("RegQueryInforKey() failed (Error %ld)\n", Error);
        RegCloseKey(hEnvKey);
        return FALSE;
    }

    if (dwValues == 0)
    {
        RegCloseKey(hEnvKey);
        return TRUE;
    }

    /* Allocate buffers */
    dwMaxValueNameLength++;
    lpValueName = LocalAlloc(LPTR, dwMaxValueNameLength * sizeof(WCHAR));
    if (lpValueName == NULL)
    {
        RegCloseKey(hEnvKey);
        return FALSE;
    }

    lpValueData = LocalAlloc(LPTR, dwMaxValueDataLength);
    if (lpValueData == NULL)
    {
        LocalFree(lpValueName);
        RegCloseKey(hEnvKey);
        return FALSE;
    }

    /* Enumerate values */
    for (i = 0; i < dwValues; i++)
    {
        dwValueNameLength = dwMaxValueNameLength;
        dwValueDataLength = dwMaxValueDataLength;

        Error = RegEnumValueW(hEnvKey,
                              i,
                              lpValueName,
                              &dwValueNameLength,
                              NULL,
                              &dwType,
                              (LPBYTE)lpValueData,
                              &dwValueDataLength);
        if (Error == ERROR_SUCCESS)
        {
            /* Set environment variable */
            SetUserEnvironmentVariable(Environment,
                                       lpValueName,
                                       lpValueData,
                                       (dwType == REG_EXPAND_SZ));
        }
        else
        {
            LocalFree(lpValueData);
            LocalFree(lpValueName);
            RegCloseKey(hEnvKey);

            return FALSE;
        }
    }

    LocalFree(lpValueData);
    LocalFree(lpValueName);
    RegCloseKey(hEnvKey);

    return TRUE;
}


/* TRUE when the token's user is LocalSystem */
static
BOOL
IsLocalSystemToken(HANDLE hToken)
{
    PSID Sid = GetUserSid(hToken);
    BOOL Result;

    if (Sid == NULL)
        return FALSE;
    Result = IsWellKnownSid(Sid, WinLocalSystemSid);
    LocalFree(Sid);
    return Result;
}


/* A LocalAlloc'ed copy of a variable of an environment block, NULL if it has none */
static
PWSTR
CopyVariable(PWSTR Environment, PCWSTR lpName)
{
    UNICODE_STRING Name, Value;
    NTSTATUS Status;
    PWSTR Copy;

    RtlInitUnicodeString(&Name, lpName);
    Value.Length = 0;
    Value.MaximumLength = 0;
    Value.Buffer = NULL;
    Status = RtlQueryEnvironmentVariable_U(Environment, &Name, &Value);
    if (Status != STATUS_BUFFER_TOO_SMALL || Value.Length == 0)
        return NULL;

    Copy = LocalAlloc(LPTR, Value.Length + sizeof(WCHAR));
    if (Copy == NULL)
        return NULL;
    Value.MaximumLength = Value.Length + sizeof(WCHAR);
    Value.Buffer = Copy;
    if (!NT_SUCCESS(RtlQueryEnvironmentVariable_U(Environment, &Name, &Value)))
    {
        LocalFree(Copy);
        return NULL;
    }
    return Copy;
}


/*
 * 'APPDATA' and 'LOCALAPPDATA': the user's AppData and Local AppData shell folders, expanded
 * against the block (they name %USERPROFILE%), else the folders under the profile directory.
 * Windows sets them for every user it finds a profile for, also for LocalSystem, whose hive has
 * no Volatile Environment (measured on Windows Server 2022).
 */
static
VOID
SetAppDataVariables(PWSTR* Environment,
                    HKEY hKeyUser,
                    PCWSTR ProfileDirectory)
{
    static const struct
    {
        PCWSTR Variable;
        PCWSTR ShellFolder;
        PCWSTR Default;
    } Folders[] =
    {
        {L"APPDATA", L"AppData", L"AppData\\Roaming"},
        {L"LOCALAPPDATA", L"Local AppData", L"AppData\\Local"},
    };
    WCHAR Value[MAX_PATH];
    DWORD i, Size, Type;
    LONG Error;

    for (i = 0; i < ARRAYSIZE(Folders); i++)
    {
        Error = ERROR_FILE_NOT_FOUND;
        if (hKeyUser != NULL)
        {
            Size = sizeof(Value) - sizeof(WCHAR);
            Error = RegGetValueW(hKeyUser,
                                 L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders",
                                 Folders[i].ShellFolder,
                                 RRF_RT_REG_SZ | RRF_RT_REG_EXPAND_SZ | RRF_NOEXPAND,
                                 &Type,
                                 Value,
                                 &Size);
        }

        if (Error == ERROR_SUCCESS && Value[0] != UNICODE_NULL)
        {
            SetUserEnvironmentVariable(Environment, Folders[i].Variable, Value, Type == REG_EXPAND_SZ);
        }
        else if (SUCCEEDED(StringCchPrintfW(Value, ARRAYSIZE(Value), L"%s\\%s",
                                            ProfileDirectory, Folders[i].Default)))
        {
            SetUserEnvironmentVariable(Environment, Folders[i].Variable, Value, FALSE);
        }
    }
}


BOOL
WINAPI
CreateEnvironmentBlock(OUT LPVOID *lpEnvironment,
                       IN HANDLE hToken,
                       IN BOOL bInherit)
{
    NTSTATUS Status;
    LONG lError;
    PWSTR* Environment = (PWSTR*)lpEnvironment;
    DWORD Length;
    DWORD dwType;
    HKEY hKey;
    HKEY hKeyUser;
    LPWSTR lpUserName = NULL;
    LPWSTR lpDomainName = NULL;
    WCHAR Buffer[MAX_PATH];
    WCHAR PublicDirectory[MAX_PATH];
    WCHAR szValue[1024];
    BOOL Wow64 = FALSE, HasWow64 = FALSE;
    BOOL ProfileFound;

    DPRINT("CreateEnvironmentBlock() called\n");

    if (lpEnvironment == NULL)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    Status = RtlCreateEnvironment((BOOLEAN)bInherit, Environment);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("RtlCreateEnvironment() failed (Status %lx)\n", Status);
        SetLastError(RtlNtStatusToDosError(Status));
        return FALSE;
    }

    IsWow64Process(GetCurrentProcess(), &Wow64);
    HasWow64 = Wow64;
#if defined(_M_AMD64) && defined(BUILD_WOW64_ENABLED)
    HasWow64 = TRUE;
#endif

    /* Set 'SystemRoot' variable */
    Length = ARRAYSIZE(Buffer);
    if (GetEnvironmentVariableW(L"SystemRoot", Buffer, Length))
    {
        SetUserEnvironmentVariable(Environment,
                                   L"SystemRoot",
                                   Buffer,
                                   FALSE);
    }

    /* Set 'SystemDrive' variable */
    if (GetEnvironmentVariableW(L"SystemDrive", Buffer, Length))
    {
        SetUserEnvironmentVariable(Environment,
                                   L"SystemDrive",
                                   Buffer,
                                   FALSE);
    }

    /* Set variables from Session Manager */
    if (!SetSystemEnvironment(Environment))
    {
        RtlDestroyEnvironment(*Environment);
        return FALSE;
    }

    if (Wow64)
    {
        SetUserEnvironmentVariable(Environment, L"PROCESSOR_ARCHITECTURE", L"x86", FALSE);
        SetUserEnvironmentVariable(Environment, L"PROCESSOR_ARCHITEW6432", L"AMD64", FALSE);
    }

    /* Set 'COMPUTERNAME' variable */
    Length = ARRAYSIZE(Buffer);
    if (GetComputerNameW(Buffer, &Length))
    {
        SetUserEnvironmentVariable(Environment,
                                   L"COMPUTERNAME",
                                   Buffer,
                                   FALSE);
    }

    /* Set 'ALLUSERSPROFILE' variable */
    Length = ARRAYSIZE(Buffer);
    if (GetAllUsersProfileDirectoryW(Buffer, &Length))
    {
        SetUserEnvironmentVariable(Environment,
                                   L"ALLUSERSPROFILE",
                                   Buffer,
                                   FALSE);
        SetUserEnvironmentVariable(Environment,
                            L"ProgramData",
                            Buffer,
                            FALSE);
    }

    /* Set 'USERPROFILE' variable to the default users profile */
    Length = ARRAYSIZE(Buffer);
    if (GetDefaultUserProfileDirectoryW(Buffer, &Length))
    {
        SetUserEnvironmentVariable(Environment,
                                   L"USERPROFILE",
                                   Buffer,
                                   TRUE);
    }

    lError = RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                           L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion",
                           0,
                           KEY_READ | (Wow64 ? KEY_WOW64_64KEY : 0),
                           &hKey);
    if (lError == ERROR_SUCCESS)
    {
        Length = sizeof(szValue);
        lError = RegQueryValueExW(hKey,
                                  Wow64 ? L"ProgramFilesDir (x86)" : L"ProgramFilesDir",
                                  NULL,
                                  &dwType,
                                  (LPBYTE)szValue,
                                  &Length);
        if (lError == ERROR_SUCCESS)
        {
            SetUserEnvironmentVariable(Environment,
                                       L"ProgramFiles",
                                       szValue,
                                       FALSE);
        }

        Length = sizeof(szValue);
        lError = RegQueryValueExW(hKey,
                                  Wow64 ? L"CommonFilesDir (x86)" : L"CommonFilesDir",
                                  NULL,
                                  &dwType,
                                  (LPBYTE)szValue,
                                  &Length);
        if (lError == ERROR_SUCCESS)
        {
            SetUserEnvironmentVariable(Environment,
                                       L"CommonProgramFiles",
                                       szValue,
                                       FALSE);
        }

        if (HasWow64)
        {
            static const struct { PCWSTR Value, Variable; } Paths[] = {
                {L"ProgramFilesDir", L"ProgramW6432"},
                {L"CommonFilesDir", L"CommonProgramW6432"},
                {L"ProgramFilesDir (x86)", L"ProgramFiles(x86)"},
                {L"CommonFilesDir (x86)", L"CommonProgramFiles(x86)"}
            };
            DWORD i;
            for (i = 0; i < ARRAYSIZE(Paths); ++i)
            {
                Length = sizeof(szValue);
                lError = RegQueryValueExW(hKey, Paths[i].Value, NULL, &dwType, (LPBYTE)szValue, &Length);
                if (lError == ERROR_SUCCESS && dwType == REG_SZ && Length >= sizeof(WCHAR) &&
                    Length <= sizeof(szValue) && !(Length % sizeof(WCHAR)) &&
                    szValue[Length / sizeof(WCHAR) - 1] == UNICODE_NULL)
                    SetUserEnvironmentVariable(Environment, Paths[i].Variable, szValue, FALSE);
            }
        }

        RegCloseKey(hKey);
    }

    /* Set 'PUBLIC' variable to the public user directory */
    lError = RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList",
                        0,
                        KEY_READ,
                        &hKey);
    if (lError == ERROR_SUCCESS)
    {
        Length = sizeof(szValue);
        lError = RegQueryValueExW(hKey,
                                  L"Public",
                                  NULL,
                                  &dwType,
                                  (LPBYTE)szValue,
                                  &Length);
        if (lError == ERROR_SUCCESS)
        {
            if (!ExpandEnvironmentStringsW(szValue,
                                            PublicDirectory,
                                            ARRAYSIZE(PublicDirectory)))
            {
                DPRINT1("Error: %lu\n", GetLastError());
                RegCloseKey(hKey);
                RtlDestroyEnvironment(*Environment);
                *Environment = NULL;
                return FALSE;
            }

            SetUserEnvironmentVariable(Environment, L"PUBLIC", PublicDirectory, FALSE);
        }
        RegCloseKey(hKey);
    }

    /*
     * If no user token is specified, the system environment variables are set
     * and we stop here, otherwise continue setting the user-specific variables.
     */
    if (hToken == NULL)
        return TRUE;

    /*
     * The hive of the user is loaded only while the user has a profile loaded. As on Windows, a token whose
     * profile is not loaded still gets the environment: the system variables, USERNAME and USERDOMAIN, and
     * the default user profile as USERPROFILE. (sshd of OpenSSH for Windows asks for it before any profile
     * is loaded.)
     */
    hKeyUser = GetCurrentUserKey(hToken);
    if (hKeyUser == NULL)
        DPRINT1("GetCurrentUserKey() failed (error %lu), the user's profile is not loaded\n", GetLastError());

    /* Set 'USERPROFILE' variable */
    Length = ARRAYSIZE(Buffer);
    ProfileFound = GetUserProfileDirectoryW(hToken, Buffer, &Length);
    if (ProfileFound ||
        (hKeyUser == NULL && (Length = ARRAYSIZE(Buffer), GetDefaultUserProfileDirectoryW(Buffer, &Length))))
    {
        DWORD MinLen = 2;

        SetUserEnvironmentVariable(Environment,
                                   L"USERPROFILE",
                                   Buffer,
                                   FALSE);

        /* 'APPDATA' and 'LOCALAPPDATA' of the user's own profile */
        if (ProfileFound)
            SetAppDataVariables(Environment, hKeyUser, Buffer);

        // FIXME: Strangely enough the following two environment variables
        // are not set by userenv.dll in Windows... See r68284 / CORE-9875
        // FIXME2: This is done by msgina.dll !!

        /* At least <drive letter>:<path> */
        if (Length > MinLen)
        {
            /* Set 'HOMEDRIVE' variable */
            StringCchCopyNW(szValue, ARRAYSIZE(Buffer), Buffer, MinLen);
            SetUserEnvironmentVariable(Environment,
                                       L"HOMEDRIVE",
                                       szValue,
                                       FALSE);

            /* Set 'HOMEPATH' variable */
            StringCchCopyNW(szValue, ARRAYSIZE(Buffer), Buffer + MinLen, Length - MinLen);
            SetUserEnvironmentVariable(Environment,
                                       L"HOMEPATH",
                                       szValue,
                                       FALSE);
        }
    }
    else
    {
        DPRINT1("GetUserProfileDirectoryW failed with error %lu\n", GetLastError());
    }

    if (GetUserAndDomainName(hToken,
                             &lpUserName,
                             &lpDomainName))
    {
        /* Set 'USERNAME' variable */
        SetUserEnvironmentVariable(Environment,
                                   L"USERNAME",
                                   lpUserName,
                                   FALSE);

        /* Set 'USERDOMAIN' variable */
        SetUserEnvironmentVariable(Environment,
                                   L"USERDOMAIN",
                                   lpDomainName,
                                   FALSE);

        if (lpUserName != NULL)
            LocalFree(lpUserName);

        if (lpDomainName != NULL)
            LocalFree(lpDomainName);
    }

    if (hKeyUser != NULL)
    {
        /* LocalSystem keeps the system TEMP and TMP: on Windows its environment has %SystemRoot%\TEMP
         * although its hive's Environment key names %USERPROFILE%\AppData\Local\Temp (measured on
         * Windows Server 2022 for a LocalSystem service, a LocalSystem task and CreateEnvironmentBlock
         * with the LocalSystem token) */
        BOOL KeepTemp = IsLocalSystemToken(hToken);
        PWSTR SystemTemp = KeepTemp ? CopyVariable(*Environment, L"TEMP") : NULL;
        PWSTR SystemTmp = KeepTemp ? CopyVariable(*Environment, L"TMP") : NULL;

        /* Set user environment variables */
        SetUserEnvironment(Environment,
                           hKeyUser,
                           L"Environment");

        if (SystemTemp)
        {
            SetUserEnvironmentVariable(Environment, L"TEMP", SystemTemp, FALSE);
            LocalFree(SystemTemp);
        }
        if (SystemTmp)
        {
            SetUserEnvironmentVariable(Environment, L"TMP", SystemTmp, FALSE);
            LocalFree(SystemTmp);
        }

        /* Set user volatile environment variables */
        SetUserEnvironment(Environment,
                           hKeyUser,
                           L"Volatile Environment");

        RegCloseKey(hKeyUser);
    }

    return TRUE;
}


BOOL
WINAPI
DestroyEnvironmentBlock(IN LPVOID lpEnvironment)
{
    DPRINT("DestroyEnvironmentBlock() called\n");

    if (lpEnvironment == NULL)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    RtlDestroyEnvironment(lpEnvironment);

    return TRUE;
}


BOOL
WINAPI
ExpandEnvironmentStringsForUserW(IN HANDLE hToken,
                                 IN LPCWSTR lpSrc,
                                 OUT LPWSTR lpDest,
                                 IN DWORD dwSize)
{
    BOOL Ret = FALSE;
    PVOID lpEnvironment;

    if (lpSrc == NULL || lpDest == NULL || dwSize == 0)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    if (CreateEnvironmentBlock(&lpEnvironment,
                               hToken,
                               FALSE))
    {
        UNICODE_STRING SrcU, DestU;
        NTSTATUS Status;

        /* Initialize the strings */
        RtlInitUnicodeString(&SrcU, lpSrc);
        DestU.Length = 0;
        DestU.MaximumLength = dwSize * sizeof(WCHAR);
        DestU.Buffer = lpDest;

        /* Expand the strings */
        Status = RtlExpandEnvironmentStrings_U((PWSTR)lpEnvironment,
                                               &SrcU,
                                               &DestU,
                                               NULL);

        DestroyEnvironmentBlock(lpEnvironment);

        if (NT_SUCCESS(Status))
        {
            Ret = TRUE;
        }
        else
        {
            SetLastError(RtlNtStatusToDosError(Status));
        }
    }

    return Ret;
}


BOOL
WINAPI
ExpandEnvironmentStringsForUserA(IN HANDLE hToken,
                                 IN LPCSTR lpSrc,
                                 OUT LPSTR lpDest,
                                 IN DWORD dwSize)
{
    BOOL Ret = FALSE;
    DWORD dwSrcLen;
    LPWSTR lpSrcW = NULL, lpDestW = NULL;

    if (lpSrc == NULL || lpDest == NULL || dwSize == 0)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    dwSrcLen = strlen(lpSrc);
    lpSrcW = (LPWSTR)GlobalAlloc(GMEM_FIXED,
                                 (dwSrcLen + 1) * sizeof(WCHAR));
    if (lpSrcW == NULL ||
        MultiByteToWideChar(CP_ACP,
                            0,
                            lpSrc,
                            -1,
                            lpSrcW,
                            dwSrcLen + 1) == 0)
    {
        goto Cleanup;
    }

    lpDestW = (LPWSTR)GlobalAlloc(GMEM_FIXED,
                                  dwSize * sizeof(WCHAR));
    if (lpDestW == NULL)
        goto Cleanup;

    Ret = ExpandEnvironmentStringsForUserW(hToken,
                                           lpSrcW,
                                           lpDestW,
                                           dwSize);
    if (Ret)
    {
        if (WideCharToMultiByte(CP_ACP,
                                0,
                                lpDestW,
                                -1,
                                lpDest,
                                dwSize,
                                NULL,
                                NULL) == 0)
        {
            Ret = FALSE;
        }
    }

Cleanup:
    if (lpSrcW != NULL)
        GlobalFree((HGLOBAL)lpSrcW);

    if (lpDestW != NULL)
        GlobalFree((HGLOBAL)lpDestW);

    return Ret;
}

/* EOF */
