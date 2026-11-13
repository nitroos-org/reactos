/*
 * PROJECT:     ReactOS system libraries
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     AppContainer SID registration (the moniker of an AppContainer SID), exported by kernelbase as on
 *              Windows 8 and later
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Windows keeps the moniker (the AppContainer name) and the display name of every registered AppContainer SID in
 * the user's registry, under HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\
 * AppContainer\Mappings\<SID>. Chrome registers the SIDs of its sandbox profiles here itself instead of calling
 * userenv!CreateAppContainerProfile, and checks that the functions exist.
 *
 * The registration is bookkeeping only. CreateAppContainerToken makes an AppContainer (lowbox) token with
 * NtCreateLowBoxToken; nothing here grants or checks access.
 */

#include <stdarg.h>
#include <string.h>
#define WIN32_NO_STATUS
#include <windef.h>
#include <winbase.h>
#include <winreg.h>
#include <winerror.h>
#include <sddl.h>
#include <winternl.h>

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#endif

#define APPCONTAINER_MAPPINGS \
    L"Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\CurrentVersion\\AppContainer\\Mappings"
#define APPCONTAINER_MONIKER_MAX 64
#define APPCONTAINER_DISPLAY_NAME_MAX 512
/* The mappings path, a backslash and the SID string (at most 184 characters for 15 sub-authorities) */
#define MAPPING_PATH_MAX (ARRAYSIZE(APPCONTAINER_MAPPINGS) + 1 + 192)

/* S-1-15-2 followed by seven sub-authorities: the SID of an AppContainer (not of a child or a capability) */
static
BOOL
IsAppContainerSid(
    _In_opt_ PSID Sid)
{
    static const SID_IDENTIFIER_AUTHORITY AppPackageAuthority = { SECURITY_APP_PACKAGE_AUTHORITY };
    PSID_IDENTIFIER_AUTHORITY Authority;

    if (!Sid || !IsValidSid(Sid))
        return FALSE;
    Authority = GetSidIdentifierAuthority(Sid);
    return !memcmp(Authority, &AppPackageAuthority, sizeof(AppPackageAuthority)) &&
           *GetSidSubAuthorityCount(Sid) == SECURITY_APP_PACKAGE_RID_COUNT &&
           *GetSidSubAuthority(Sid, 0) == SECURITY_APP_PACKAGE_BASE_RID;
}

static
BOOL
IsValidName(
    _In_opt_ PCWSTR Name,
    _In_ SIZE_T Max,
    _In_ BOOL AllowEmpty)
{
    SIZE_T Length;

    if (!Name)
        return FALSE;
    for (Length = 0; Length <= Max && Name[Length]; Length++)
        ;
    return Length <= Max && (AllowEmpty || Length > 0);
}

/* The registry path of the mapping key of an AppContainer SID, relative to HKEY_CURRENT_USER */
static
LONG
GetMappingPath(
    _In_ PSID Sid,
    _Out_writes_(Size) PWSTR Path,
    _In_ SIZE_T Size)
{
    LPWSTR SidString;
    SIZE_T Length;

    if (!ConvertSidToStringSidW(Sid, &SidString))
        return GetLastError();
    Length = wcslen(APPCONTAINER_MAPPINGS) + 1 + wcslen(SidString);
    if (Length >= Size)
    {
        LocalFree(SidString);
        return ERROR_INVALID_SID;
    }
    wcscpy(Path, APPCONTAINER_MAPPINGS L"\\");
    wcscat(Path, SidString);
    LocalFree(SidString);
    return ERROR_SUCCESS;
}

/* Delete a mapping key with whatever it contains */
static
LONG
DeleteMappingKey(
    _In_ PCWSTR Path)
{
    LONG Error = RegDeleteTreeW(HKEY_CURRENT_USER, Path);

    if (Error != ERROR_SUCCESS)
        return Error;
    /* RegDeleteTree deletes the key itself too on Windows; make sure of it */
    Error = RegDeleteKeyW(HKEY_CURRENT_USER, Path);
    return Error == ERROR_FILE_NOT_FOUND ? ERROR_SUCCESS : Error;
}

static
LONG
SetStringValue(
    _In_ HKEY Key,
    _In_ PCWSTR Name,
    _In_ PCWSTR Value)
{
    return RegSetValueExW(Key, Name, 0, REG_SZ, (const BYTE *)Value, (DWORD)((wcslen(Value) + 1) * sizeof(WCHAR)));
}

/*
 * @implemented
 *
 * Registers the moniker and the display name of an AppContainer SID. Fails with
 * HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS) when the SID is registered already.
 */
HRESULT
WINAPI
AppContainerRegisterSid(
    _In_ PSID Sid,
    _In_ PCWSTR Moniker,
    _In_ PCWSTR DisplayName)
{
    WCHAR Path[MAPPING_PATH_MAX];
    DWORD Disposition;
    LONG Error;
    HKEY Key;

    if (!IsAppContainerSid(Sid) ||
        !IsValidName(Moniker, APPCONTAINER_MONIKER_MAX, FALSE) ||
        !IsValidName(DisplayName, APPCONTAINER_DISPLAY_NAME_MAX, TRUE))
    {
        return E_INVALIDARG;
    }

    Error = GetMappingPath(Sid, Path, ARRAYSIZE(Path));
    if (Error == ERROR_SUCCESS)
        Error = RegCreateKeyExW(HKEY_CURRENT_USER, Path, 0, NULL, 0, KEY_SET_VALUE, NULL, &Key, &Disposition);
    if (Error != ERROR_SUCCESS)
        return HRESULT_FROM_WIN32(Error);
    if (Disposition == REG_OPENED_EXISTING_KEY)
    {
        RegCloseKey(Key);
        return HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS);
    }

    Error = SetStringValue(Key, L"Moniker", Moniker);
    if (Error == ERROR_SUCCESS)
        Error = SetStringValue(Key, L"DisplayName", DisplayName);
    RegCloseKey(Key);
    if (Error != ERROR_SUCCESS)
    {
        /* Do not leave a half-written registration behind: it would read as registered */
        DeleteMappingKey(Path);
        return HRESULT_FROM_WIN32(Error);
    }
    return S_OK;
}

/*
 * @implemented
 */
HRESULT
WINAPI
AppContainerUnregisterSid(
    _In_ PSID Sid)
{
    WCHAR Path[MAPPING_PATH_MAX];
    LONG Error;

    if (!IsAppContainerSid(Sid))
        return E_INVALIDARG;

    /* The values and any subkeys (Windows keeps the children of the AppContainer there), then the key itself */
    Error = GetMappingPath(Sid, Path, ARRAYSIZE(Path));
    if (Error == ERROR_SUCCESS)
        Error = DeleteMappingKey(Path);
    return Error == ERROR_SUCCESS ? S_OK : HRESULT_FROM_WIN32(Error);
}

/*
 * @implemented
 *
 * Returns the moniker a SID was registered with. The caller frees it with AppContainerFreeMemory.
 */
HRESULT
WINAPI
AppContainerLookupMoniker(
    _In_ PSID Sid,
    _Outptr_ PWSTR *Moniker)
{
    WCHAR Path[MAPPING_PATH_MAX];
    DWORD Type, Size;
    PWSTR Buffer;
    LONG Error;
    HKEY Key;

    if (!Moniker)
        return E_INVALIDARG;
    *Moniker = NULL;
    if (!IsAppContainerSid(Sid))
        return E_INVALIDARG;

    Error = GetMappingPath(Sid, Path, ARRAYSIZE(Path));
    if (Error == ERROR_SUCCESS)
        Error = RegOpenKeyExW(HKEY_CURRENT_USER, Path, 0, KEY_QUERY_VALUE, &Key);
    if (Error != ERROR_SUCCESS)
        return HRESULT_FROM_WIN32(Error);

    Size = 0;
    Error = RegQueryValueExW(Key, L"Moniker", NULL, &Type, NULL, &Size);
    if (Error == ERROR_SUCCESS && (Type != REG_SZ || Size > (APPCONTAINER_MONIKER_MAX + 1) * sizeof(WCHAR)))
        Error = ERROR_INVALID_DATA;
    if (Error != ERROR_SUCCESS)
    {
        RegCloseKey(Key);
        return HRESULT_FROM_WIN32(Error);
    }

    /* Room for a terminator the value may lack */
    Buffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, Size + sizeof(WCHAR));
    if (!Buffer)
    {
        RegCloseKey(Key);
        return E_OUTOFMEMORY;
    }
    Error = RegQueryValueExW(Key, L"Moniker", NULL, &Type, (BYTE *)Buffer, &Size);
    RegCloseKey(Key);
    if (Error == ERROR_SUCCESS && (Type != REG_SZ || !Buffer[0]))
        Error = ERROR_INVALID_DATA;
    if (Error != ERROR_SUCCESS)
    {
        HeapFree(GetProcessHeap(), 0, Buffer);
        return HRESULT_FROM_WIN32(Error);
    }

    *Moniker = Buffer;
    return S_OK;
}

/*
 * @implemented
 *
 * Frees memory that the AppContainer functions returned.
 */
BOOLEAN
WINAPI
AppContainerFreeMemory(
    _In_opt_ PVOID Memory)
{
    if (!Memory)
        return TRUE;
    return HeapFree(GetProcessHeap(), 0, Memory) != FALSE;
}

/* SECURITY_CAPABILITIES (winnt.h of Windows 8 and later; not in this tree's headers) */
typedef struct _BASEP_SECURITY_CAPABILITIES
{
    PSID AppContainerSid;
    PSID_AND_ATTRIBUTES Capabilities;
    DWORD CapabilityCount;
    DWORD Reserved;
} BASEP_SECURITY_CAPABILITIES, *PBASEP_SECURITY_CAPABILITIES;

#ifdef KERNELBASE_NT6_NTDLL
/*
 * @implemented
 *
 * Makes an AppContainer token: a copy of TokenHandle (of the process token when it is NULL) that belongs to the
 * AppContainer SID of SecurityCapabilities and holds its capabilities (Chromium's sandbox builds its renderer
 * tokens with it). The kernel checks the SIDs.
 *
 * Windows also creates the AppContainer's named object directory (\Sessions\<n>\AppContainerNamedObjects\<SID>)
 * and its links and hands them to the token; that is not done here: AppContainer processes keep using the session's
 * named objects, and no access is checked against the AppContainer (as before AppContainer tokens existed).
 * The error codes for bad arguments are not measured on Windows.
 */
BOOL
WINAPI
CreateAppContainerToken(
    _In_opt_ HANDLE TokenHandle,
    _In_ PBASEP_SECURITY_CAPABILITIES SecurityCapabilities,
    _Out_ PHANDLE OutToken)
{
    HANDLE Token = TokenHandle, OwnToken = NULL, NewToken = NULL;
    NTSTATUS Status;

    if (!SecurityCapabilities || !OutToken)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    if (!Token)
    {
        Status = NtOpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY, &OwnToken);
        if (!NT_SUCCESS(Status))
        {
            SetLastError(RtlNtStatusToDosError(Status));
            return FALSE;
        }
        Token = OwnToken;
    }

    Status = NtCreateLowBoxToken(&NewToken,
                                 Token,
                                 TOKEN_ALL_ACCESS,
                                 NULL,
                                 SecurityCapabilities->AppContainerSid,
                                 SecurityCapabilities->CapabilityCount,
                                 SecurityCapabilities->Capabilities,
                                 0,
                                 NULL);
    if (OwnToken)
        NtClose(OwnToken);
    if (!NT_SUCCESS(Status))
    {
        SetLastError(RtlNtStatusToDosError(Status));
        return FALSE;
    }

    *OutToken = NewToken;
    return TRUE;
}
#endif /* KERNELBASE_NT6_NTDLL */
