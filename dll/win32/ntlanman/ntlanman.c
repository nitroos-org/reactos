/*
 * PROJECT:     NitroOS
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     "Microsoft Windows Network" network provider (NPxxx) over the SMB redirector
 * COPYRIGHT:   Copyright Dmitry Chapyshev (dmitry@reactos.org) (the original stubs)
 *              Copyright 2026 Tomas Srnka
 */

/*
 * The network provider of the SMB client: the multiple provider router (mpr.dll) calls it
 * for net use, WNetAddConnection2/3, Map Network Drive and friends. Contract with the
 * redirector: sdk/include/reactos/drivers/smbrdr/smbconn.h.
 *
 * A connection is a tree connect to \Device\LanmanRedirector, made in the caller's own
 * security context (its logon session owns it); a drive letter is a raw-target DOS device in
 * the caller's logon session's device map:
 *   X: -> \Device\LanmanRedirector\;X:<logon id>\server\share[\path]
 * (the shape Windows uses). Explicit credentials go to the redirector once, in the EA of that
 * tree connect, and this buffer is wiped right after. Nothing here stores a password.
 * Persistent connections (HKCU\Network) are written and restored by mpr.
 */

#define WIN32_NO_STATUS
#include <windef.h>
#include <winbase.h>
#include <winreg.h>
#include <winnetwk.h>
#include <npapi.h>
#include <winioctl.h>
#include <lmcons.h>
#define NTOS_MODE_USER
#include <ndk/iofuncs.h>
#include <ndk/obfuncs.h>
#include <ndk/rtlfuncs.h>
#undef WIN32_NO_STATUS
#include <ntstatus.h>
#include <drivers/smbrdr/smbconn.h>

#include <wine/debug.h>

WINE_DEFAULT_DEBUG_CHANNEL(ntlanman);

#define PROVIDER_NAME L"Microsoft Windows Network"
#define SESSION_CREDENTIAL_CONFLICT 1219    /* ERROR_SESSION_CREDENTIAL_CONFLICT */
#define NOT_CONNECTED 2250                  /* ERROR_NOT_CONNECTED */
#define OPEN_FILES 2401                     /* ERROR_OPEN_FILES */

/* Longest DOS device target of a drive letter of ours (characters with the NUL): every function
 * that reads a drive's target back (cancel, NPGetConnection, NPGetUser, NPGetUniversalName) has
 * room for it, and NPAddConnection3 makes no longer one (a drive it could not cancel) */
#define NP_MAX_TARGET 1024

/* Helpers *******************************************************************/

/*
 * Win32 codes of a connect, as measured on Windows Server 2022 as the client of a Samba server
 * (WNetAddConnection2 and net use, evidence of ticket SMB-07): a refused logon (wrong password,
 * unknown user) is ERROR_INVALID_PASSWORD (86), an unknown share and an unreachable server are
 * ERROR_BAD_NETPATH (53). A UNC open of an unknown share stays ERROR_BAD_NET_NAME (67): that is
 * the redirector's status, not changed here.
 */
static
DWORD
StatusToError(NTSTATUS Status)
{
    switch (Status)
    {
        case STATUS_SUCCESS: return WN_SUCCESS;
        case STATUS_OBJECT_NAME_NOT_FOUND:
        case STATUS_OBJECT_PATH_NOT_FOUND:
        case STATUS_REDIRECTOR_NOT_STARTED:
        case STATUS_NO_SUCH_DEVICE:
            return WN_NO_NETWORK;
        case STATUS_BAD_NETWORK_PATH:
        case STATUS_HOST_UNREACHABLE:
        case STATUS_NETWORK_UNREACHABLE:
        case STATUS_CONNECTION_REFUSED:
        case STATUS_IO_TIMEOUT:
            return ERROR_BAD_NETPATH;
        case STATUS_BAD_NETWORK_NAME: return ERROR_BAD_NETPATH;
        case STATUS_LOGON_FAILURE:
        case STATUS_WRONG_PASSWORD:
        case STATUS_NO_SUCH_USER:
            return ERROR_INVALID_PASSWORD;
        case STATUS_NETWORK_CREDENTIAL_CONFLICT: return SESSION_CREDENTIAL_CONFLICT;
        case STATUS_FILES_OPEN: return OPEN_FILES;
        case STATUS_NOT_FOUND: return NOT_CONNECTED;
        default: return RtlNtStatusToDosError(Status);
    }
}

/* The redirector device, or NULL with *Error = WN_NO_NETWORK (the SMB client is not loaded) */
static
HANDLE
OpenRedirector(DWORD *Error)
{
    UNICODE_STRING Name = RTL_CONSTANT_STRING(SMBCONN_DEVICE_NAME);
    OBJECT_ATTRIBUTES Attributes;
    IO_STATUS_BLOCK Iosb;
    HANDLE Handle;
    NTSTATUS Status;

    InitializeObjectAttributes(&Attributes, &Name, OBJ_CASE_INSENSITIVE, NULL, NULL);
    Status = NtCreateFile(&Handle, SYNCHRONIZE, &Attributes, &Iosb, NULL, 0, FILE_SHARE_READ | FILE_SHARE_WRITE,
                          FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
    if (!NT_SUCCESS(Status))
    {
        *Error = WN_NO_NETWORK;
        return NULL;
    }
    *Error = WN_SUCCESS;
    return Handle;
}

/* The connections of the caller's logon session; HeapFree the result */
static
PSMBCONN_ENUM_OUTPUT
GetUses(DWORD *Error)
{
    PSMBCONN_ENUM_OUTPUT Out = NULL;
    ULONG Size = 4096;
    IO_STATUS_BLOCK Iosb;
    NTSTATUS Status;
    HANDLE Device;
    int Tries;

    Device = OpenRedirector(Error);
    if (Device == NULL)
        return NULL;
    for (Tries = 0; Tries < 4; Tries++)
    {
        Out = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, Size);
        if (Out == NULL)
        {
            *Error = WN_OUT_OF_MEMORY;
            break;
        }
        Status = NtDeviceIoControlFile(Device, NULL, NULL, NULL, &Iosb, IOCTL_SMBCONN_ENUM, NULL, 0, Out, Size);
        if (NT_SUCCESS(Status) && Status != STATUS_BUFFER_OVERFLOW)
        {
            *Error = WN_SUCCESS;
            NtClose(Device);
            return Out;
        }
        if (Status != STATUS_BUFFER_OVERFLOW)
        {
            *Error = StatusToError(Status);
            break;
        }
        Size = Out->Needed + 1024;
        HeapFree(GetProcessHeap(), 0, Out);
        Out = NULL;
    }
    if (Out != NULL)
        HeapFree(GetProcessHeap(), 0, Out);
    if (*Error == WN_SUCCESS)
        *Error = WN_OUT_OF_MEMORY;
    NtClose(Device);
    return NULL;
}

static
NTSTATUS
DeleteUse(ULONGLONG Id, BOOL Force)
{
    SMBCONN_DELETE_INPUT In;
    IO_STATUS_BLOCK Iosb;
    NTSTATUS Status;
    HANDLE Device;
    DWORD Error;

    Device = OpenRedirector(&Error);
    if (Device == NULL)
        return STATUS_REDIRECTOR_NOT_STARTED;
    ZeroMemory(&In, sizeof(In));
    In.Id = Id;
    In.Flags = Force ? SMBCONN_DELETE_FORCE : 0;
    Status = NtDeviceIoControlFile(Device, NULL, NULL, NULL, &Iosb, IOCTL_SMBCONN_DELETE, &In, sizeof(In), NULL, 0);
    NtClose(Device);
    return Status;
}

static
BOOL
EntryRemoteIs(PSMBCONN_ENUM_OUTPUT Uses, PSMBCONN_ENTRY e, LPCWSTR Remote, SIZE_T RemoteChars)
{
    return e->RemoteLength == RemoteChars * sizeof(WCHAR) &&
           _wcsnicmp((PCWSTR)((PUCHAR)Uses + e->RemoteOffset), Remote, RemoteChars) == 0;
}

/* Is the connection to the server (the "\\server" of Remote, as the caller wrote it) */
static
BOOL
EntryServerIs(PSMBCONN_ENUM_OUTPUT Uses, PSMBCONN_ENTRY e, LPCWSTR Remote)
{
    PCWSTR Theirs = (PCWSTR)((PUCHAR)Uses + e->RemoteOffset);
    SIZE_T TheirChars = e->RemoteLength / sizeof(WCHAR), n = 2, m = 2;

    while (Remote[n] != 0 && Remote[n] != L'\\')
        n++;
    while (m < TheirChars && Theirs[m] != L'\\')
        m++;
    return n == m && _wcsnicmp(Theirs, Remote, n) == 0;
}

/* The password (and the rest) of an EA buffer never outlives the call that used it */
static
VOID
WipeEa(PVOID Ea, ULONG Bytes)
{
    if (Ea != NULL)
    {
        SecureZeroMemory(Ea, Bytes);
        HeapFree(GetProcessHeap(), 0, Ea);
    }
}

/*
 * Do the credentials of Ea (user, domain, password) fit the identity the caller's logon session
 * uses for the server of Remote? A second explicit use of a name that is connected never reaches
 * the driver (rdbss reuses the connection), so the driver is asked with a create of a \;#: name
 * (smbconn.h) that the engine answers by comparing and the driver never keeps.
 */
static
NTSTATUS
ProbeCredentials(LPCWSTR Remote, SIZE_T RemoteChars, const LUID *LogonId, PVOID Ea, ULONG EaLength)
{
    static const WCHAR Device[] = SMBCONN_REDIRECTOR_PREFIX;
    UNICODE_STRING NtName;
    OBJECT_ATTRIBUTES Attributes;
    IO_STATUS_BLOCK Iosb;
    HANDLE Handle;
    PWSTR Name;
    SIZE_T Chars = wcslen(Device) + 24 + RemoteChars + 1;
    NTSTATUS Status;

    Name = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, Chars * sizeof(WCHAR));
    if (Name == NULL)
        return STATUS_INSUFFICIENT_RESOURCES;
    _snwprintf(Name, Chars - 1, L"%s\\;#:%08lx%08lx%.*s", Device, (ULONG)LogonId->HighPart, LogonId->LowPart,
               (int)(RemoteChars - 1), Remote + 1);
    RtlInitUnicodeString(&NtName, Name);
    InitializeObjectAttributes(&Attributes, &NtName, OBJ_CASE_INSENSITIVE, NULL, NULL);
    Status = NtCreateFile(&Handle, SYNCHRONIZE, &Attributes, &Iosb, NULL, FILE_ATTRIBUTE_NORMAL,
                          FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN_IF,
                          FILE_CREATE_TREE_CONNECTION | FILE_SYNCHRONOUS_IO_NONALERT, Ea, EaLength);
    if (NT_SUCCESS(Status))
        NtClose(Handle);
    HeapFree(GetProcessHeap(), 0, Name);
    return Status;
}

/* "\\server\share[\path]" without trailing separators; FALSE when it is not one */
static
BOOL
CheckRemoteName(LPCWSTR Remote, SIZE_T *Chars)
{
    SIZE_T n, i;

    if (Remote == NULL)
        return FALSE;
    n = wcslen(Remote);
    while (n > 2 && Remote[n - 1] == L'\\')
        n--;
    if (n < 5 || Remote[0] != L'\\' || Remote[1] != L'\\' || Remote[2] == L'\\')
        return FALSE;
    for (i = 2; i < n && Remote[i] != L'\\'; i++)
        ;
    if (i >= n - 1 || Remote[i + 1] == L'\\' || i - 2 > 256)
        return FALSE;
    if (n > 32000)
        return FALSE;
    *Chars = n;
    return TRUE;
}

/* "X:" (any case); the upper-case letter, 0 if it is not a drive name */
static
WCHAR
DriveLetterOf(LPCWSTR Local)
{
    if (Local == NULL || !Local[0] || Local[1] != L':' || Local[2])
        return 0;
    if (Local[0] >= L'a' && Local[0] <= L'z')
        return (WCHAR)(Local[0] - L'a' + L'A');
    if (Local[0] >= L'A' && Local[0] <= L'Z')
        return Local[0];
    return 0;
}

static
BOOL
CallerLogonId(LUID *LogonId)
{
    TOKEN_STATISTICS Stats;
    HANDLE Token;
    DWORD Size;
    BOOL Ok;

    if (!OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &Token) &&
        !OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &Token))
        return FALSE;
    Ok = GetTokenInformation(Token, TokenStatistics, &Stats, sizeof(Stats), &Size);
    CloseHandle(Token);
    if (Ok)
        *LogonId = Stats.AuthenticationId;
    return Ok;
}

/* "\\server\share..." of a drive letter of ours, from its DOS device target; WN_NOT_CONNECTED if
 * the letter is not one of the redirector's. Target (optional) gets the raw target. */
static
DWORD
DriveRemote(WCHAR Letter, LPWSTR Remote, DWORD RemoteChars, DWORD *Needed, LPWSTR Target, DWORD TargetChars)
{
    static const WCHAR Prefix[] = SMBCONN_REDIRECTOR_PREFIX L"\\;";
    WCHAR Drive[3] = { Letter, L':', 0 };
    WCHAR Buffer[NP_MAX_TARGET];
    PWCHAR p;
    SIZE_T n;

    if (!QueryDosDeviceW(Drive, Buffer, ARRAYSIZE(Buffer)))
        return GetLastError() == ERROR_FILE_NOT_FOUND ? WN_NOT_CONNECTED : WN_BAD_LOCALNAME;
    n = wcslen(Prefix);
    if (_wcsnicmp(Buffer, Prefix, n) != 0 || towupper(Buffer[n]) != Letter || Buffer[n + 1] != L':')
        return WN_NOT_CONNECTED;
    p = wcschr(Buffer + n, L'\\');
    if (p == NULL)
        return WN_NOT_CONNECTED;
    if (Target != NULL)
    {
        if (wcslen(Buffer) >= TargetChars)
            return WN_MORE_DATA;
        wcscpy(Target, Buffer);
    }
    /* "\server\share" -> "\\server\share" */
    *Needed = (DWORD)wcslen(p) + 2;
    if (Remote == NULL || RemoteChars < *Needed)
        return WN_MORE_DATA;
    Remote[0] = L'\\';
    wcscpy(Remote + 1, p);
    return WN_SUCCESS;
}

/* One EA entry; returns the next free offset. Entries are ULONG-aligned and NextEntryOffset is the
 * aligned size of the entry exactly, as IoCheckEaBufferValidity requires */
static
ULONG
PutEa(PUCHAR Buffer, ULONG Offset, PFILE_FULL_EA_INFORMATION *Previous, PCSTR Name, LPCWSTR Value, SIZE_T ValueChars)
{
    PFILE_FULL_EA_INFORMATION Ea = (PFILE_FULL_EA_INFORMATION)(Buffer + Offset);
    ULONG NameLength = (ULONG)strlen(Name);
    ULONG Size;

    if (*Previous != NULL)
        (*Previous)->NextEntryOffset = Offset - (ULONG)((PUCHAR)*Previous - Buffer);
    Ea->NextEntryOffset = 0;
    Ea->Flags = 0;
    Ea->EaNameLength = (UCHAR)NameLength;
    Ea->EaValueLength = (USHORT)(ValueChars * sizeof(WCHAR));
    memcpy(Ea->EaName, Name, NameLength + 1);
    if (ValueChars != 0)
        memcpy(Ea->EaName + NameLength + 1, Value, ValueChars * sizeof(WCHAR));
    *Previous = Ea;
    Size = FIELD_OFFSET(FILE_FULL_EA_INFORMATION, EaName) + NameLength + 1 + (ULONG)(ValueChars * sizeof(WCHAR));
    return Offset + ((Size + 3) & ~3UL);
}

/* The user name of the caller's own logon ("DOMAIN\user") */
static
BOOL
GetOwnUser(LPWSTR Out, DWORD Chars)
{
    WCHAR User[UNLEN + 1], Domain[DNLEN + 1 + 256];
    DWORD UserChars = ARRAYSIZE(User), DomainChars = ARRAYSIZE(Domain);
    UCHAR Buffer[sizeof(TOKEN_USER) + SECURITY_MAX_SID_SIZE];
    SID_NAME_USE Use;
    HANDLE Token;
    DWORD Size;
    BOOL Ok;

    if (!OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &Token) &&
        !OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &Token))
        return FALSE;
    Ok = GetTokenInformation(Token, TokenUser, Buffer, sizeof(Buffer), &Size);
    CloseHandle(Token);
    if (!Ok || !LookupAccountSidW(NULL, ((PTOKEN_USER)Buffer)->User.Sid, User, &UserChars, Domain, &DomainChars, &Use))
        return FALSE;
    if (wcslen(Domain) + wcslen(User) + 2 > Chars)
        return FALSE;
    _snwprintf(Out, Chars, L"%s\\%s", Domain, User);
    Out[Chars - 1] = 0;
    return TRUE;
}

/* Capabilities **************************************************************/

DWORD
APIENTRY
NPGetCaps(DWORD nIndex)
{
    switch (nIndex)
    {
        case WNNC_SPEC_VERSION:
            return WNNC_SPEC_VERSION51;
        case WNNC_NET_TYPE:
            return WNNC_NET_LANMAN;
        case WNNC_DRIVER_VERSION:
            return 1;
        case WNNC_USER:
            return WNNC_USR_GETUSER;
        case WNNC_CONNECTION:
            return WNNC_CON_ADDCONNECTION | WNNC_CON_CANCELCONNECTION | WNNC_CON_GETCONNECTIONS |
                   WNNC_CON_ADDCONNECTION3;
        case WNNC_DIALOG:
            return WNNC_DLG_FORMATNETWORKNAME | WNNC_DLG_GETRESOURCEPARENT | WNNC_DLG_GETRESOURCEINFORMATION;
        case WNNC_ENUMERATION:
            /* Connected resources only: browsing servers needs srvsvc over named pipes */
            return WNNC_ENUM_LOCAL;
        case WNNC_START:
            return 1;
        default:
            return 0;
    }
}

/* Connections ***************************************************************/

DWORD
APIENTRY
NPAddConnection3(HWND hwndOwner,
                 LPNETRESOURCEW lpNetResource,
                 LPWSTR lpPassword,
                 LPWSTR lpUserName,
                 DWORD dwFlags)
{
    static const WCHAR Device[] = SMBCONN_REDIRECTOR_PREFIX;
    UNICODE_STRING NtName;
    OBJECT_ATTRIBUTES Attributes;
    IO_STATUS_BLOCK Iosb;
    PSMBCONN_ENUM_OUTPUT Uses;
    PFILE_FULL_EA_INFORMATION Previous = NULL;
    LPCWSTR Remote, User = NULL, Domain = NULL, Slash;
    SIZE_T RemoteChars, UserChars = 0, DomainChars = 0, PasswordChars = 0;
    WCHAR Letter, Own[UNLEN + DNLEN + 260];
    PUCHAR Ea = NULL;
    ULONG EaLength = 0, EaAlloc;
    BOOL Explicit = FALSE;
    PWSTR Name = NULL;
    HANDLE Handle;
    LUID LogonId;
    DWORD Error, i;
    NTSTATUS Status;

    UNREFERENCED_PARAMETER(hwndOwner);
    UNREFERENCED_PARAMETER(dwFlags);

    if (lpNetResource == NULL)
        return WN_BAD_POINTER;
    if (lpNetResource->dwType & RESOURCETYPE_PRINT)
        return WN_BAD_DEV_TYPE;
    Remote = lpNetResource->lpRemoteName;
    if (!CheckRemoteName(Remote, &RemoteChars))
        return WN_BAD_NETNAME;
    Letter = 0;
    if (lpNetResource->lpLocalName != NULL && lpNetResource->lpLocalName[0])
    {
        WCHAR Target[8];

        Letter = DriveLetterOf(lpNetResource->lpLocalName);
        if (Letter == 0)
            return WN_BAD_LOCALNAME;
        if (QueryDosDeviceW(lpNetResource->lpLocalName, Target, ARRAYSIZE(Target)) ||
            GetLastError() != ERROR_FILE_NOT_FOUND)
            return WN_ALREADY_CONNECTED;
    }
    if (!CallerLogonId(&LogonId))
        return GetLastError();

    /* Which identity: a user name names one; a password alone or nothing is the caller's own
     * (WNetAddConnection2: a NULL password is the default one of the user; a NULL user is the
     * caller). The caller's own name with no password is the caller too. */
    if (lpUserName != NULL && lpUserName[0])
    {
        Slash = wcschr(lpUserName, L'\\');
        if (Slash != NULL)
        {
            Domain = lpUserName;
            DomainChars = Slash - lpUserName;
            User = Slash + 1;
        }
        else
        {
            User = lpUserName;
        }
        UserChars = wcslen(User);
        if (UserChars == 0 || UserChars > SMBCONN_MAX_USER_CHARS || DomainChars > SMBCONN_MAX_DOMAIN_CHARS)
            return WN_BAD_USER;
        Explicit = TRUE;
        if (lpPassword == NULL && GetOwnUser(Own, ARRAYSIZE(Own)))
        {
            PWCHAR OwnUser = wcschr(Own, L'\\') + 1;

            if (_wcsicmp(OwnUser, User) == 0 &&
                (Domain == NULL || (DomainChars == (SIZE_T)(OwnUser - Own - 1) && !_wcsnicmp(Own, Domain, DomainChars))))
                Explicit = FALSE;
        }
    }
    if (Explicit && lpPassword != NULL)
    {
        PasswordChars = wcslen(lpPassword);
        if (PasswordChars > SMBCONN_MAX_PASSWORD_CHARS)
            return WN_BAD_PASSWORD;
    }

    /* The explicit credentials, as the EA buffer of the tree connect (and of the credential check) */
    if (Explicit)
    {
        EaAlloc = 3 * (FIELD_OFFSET(FILE_FULL_EA_INFORMATION, EaName) + 32 + 8) +
                  (ULONG)((UserChars + DomainChars + PasswordChars) * sizeof(WCHAR));
        Ea = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, EaAlloc);
        if (Ea == NULL)
            return WN_OUT_OF_MEMORY;
        EaLength = PutEa(Ea, 0, &Previous, SMBCONN_EA_USERNAME, User, UserChars);
        EaLength = PutEa(Ea, EaLength, &Previous, SMBCONN_EA_DOMAIN, Domain, DomainChars);
        EaLength = PutEa(Ea, EaLength, &Previous, SMBCONN_EA_PASSWORD, lpPassword, PasswordChars);
    }

    Uses = GetUses(&Error);
    if (Uses == NULL)
    {
        WipeEa(Ea, EaAlloc);
        return Error;
    }
    if (Explicit)
    {
        /* Explicit credentials become the identity for the server, and connections that plain UNC
         * opens made do not hold one (Windows Server 2022, measured): they are ended and made
         * again with it when used. One that has files open cannot be ended; it stays. */
        for (i = 0; i < Uses->Count; i++)
        {
            PSMBCONN_ENTRY e = &Uses->Entries[i];

            if (!(e->Flags & SMBCONN_FLAG_TREE_CONNECTED) && EntryServerIs(Uses, e, Remote))
                DeleteUse(e->Id, FALSE);
        }
        HeapFree(GetProcessHeap(), 0, Uses);
        Uses = GetUses(&Error);
        if (Uses == NULL)
        {
            WipeEa(Ea, EaAlloc);
            return Error;
        }
    }

    /* A connection to the same name may exist: rdbss would use it whatever the credentials of this
     * call, so they are compared first. The user name here; the password by the engine
     * (ProbeCredentials), which is the only one that has the other one. A drive of the caller to the
     * same share counts too: when rdbss finds a connection of that name of another logon session
     * first, it takes any connection of the caller's logon session to the share instead, the
     * drive's included, and the tree connect of a name without a drive then never reaches the driver. */
    if (Letter == 0 && Explicit)
    {
        WCHAR Want[DNLEN + UNLEN + 260];
        BOOL Conflict = FALSE, Held = FALSE, HeldByDrive = FALSE;

        _snwprintf(Want, ARRAYSIZE(Want), L"%.*s%s%.*s", (int)DomainChars, Domain ? Domain : L"",
                   DomainChars ? L"\\" : L"", (int)UserChars, User);
        Want[ARRAYSIZE(Want) - 1] = 0;
        for (i = 0; i < Uses->Count && !Conflict; i++)
        {
            PSMBCONN_ENTRY e = &Uses->Entries[i];

            if (!EntryRemoteIs(Uses, e, Remote, RemoteChars))
                continue;
            if (!(e->Flags & SMBCONN_FLAG_TREE_CONNECTED) || !(e->Flags & SMBCONN_FLAG_EXPLICIT) ||
                e->UserLength != wcslen(Want) * sizeof(WCHAR) ||
                _wcsnicmp((PCWSTR)((PUCHAR)Uses + e->UserOffset), Want, wcslen(Want)) != 0)
                Conflict = TRUE;    /* another identity, or a connection in use that could not be ended */
            else if (e->Local == 0)
                Held = TRUE;
            else
                HeldByDrive = TRUE;
        }
        HeapFree(GetProcessHeap(), 0, Uses);
        if (Conflict)
        {
            WipeEa(Ea, EaAlloc);
            return SESSION_CREDENTIAL_CONFLICT;
        }
        if ((Held || HeldByDrive) && lpPassword == NULL)
        {
            /* The user again with no password given: the connection that is there (Windows Server 2022:
             * net use \\server\share /user:u with a connection of u is a success) */
            WipeEa(Ea, EaAlloc);
            return WN_SUCCESS;
        }
        if (Held)
        {
            /* The same user already uses the name: the connection stays, if the password is the same */
            Status = ProbeCredentials(Remote, RemoteChars, &LogonId, Ea, EaLength);
            WipeEa(Ea, EaAlloc);
            return (Status == SMBCONN_STATUS_PROBE_OK || NT_SUCCESS(Status)) ? WN_SUCCESS : StatusToError(Status);
        }
        if (HeldByDrive)
        {
            /* Only a drive of the same user: the password first, then the use without a drive */
            Status = ProbeCredentials(Remote, RemoteChars, &LogonId, Ea, EaLength);
            if (Status != SMBCONN_STATUS_PROBE_OK && !NT_SUCCESS(Status))
            {
                WipeEa(Ea, EaAlloc);
                return StatusToError(Status);
            }
        }
    }
    else
    {
        HeapFree(GetProcessHeap(), 0, Uses);
    }

    /* \Device\LanmanRedirector\;X:<logon id>\server\share  or  \Device\LanmanRedirector\server\share */
    i = (DWORD)(wcslen(Device) + 24 + RemoteChars + 1);
    Name = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, i * sizeof(WCHAR));
    if (Name == NULL)
    {
        WipeEa(Ea, EaAlloc);
        return WN_OUT_OF_MEMORY;
    }
    if (Letter != 0)
        _snwprintf(Name, i - 1, L"%s\\;%c:%08lx%08lx%.*s", Device, Letter, (ULONG)LogonId.HighPart, LogonId.LowPart,
                   (int)(RemoteChars - 1), Remote + 1);
    else
        _snwprintf(Name, i - 1, L"%s%.*s", Device, (int)(RemoteChars - 1), Remote + 1);
    if (Letter != 0 && wcslen(Name) >= NP_MAX_TARGET)
    {
        /* A drive whose target could not be read back could not be cancelled either */
        HeapFree(GetProcessHeap(), 0, Name);
        WipeEa(Ea, EaAlloc);
        return ERROR_BAD_NETPATH;
    }
    RtlInitUnicodeString(&NtName, Name);

    InitializeObjectAttributes(&Attributes, &NtName, OBJ_CASE_INSENSITIVE, NULL, NULL);
    Status = NtCreateFile(&Handle, SYNCHRONIZE, &Attributes, &Iosb, NULL, FILE_ATTRIBUTE_NORMAL,
                          FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN_IF,
                          FILE_CREATE_TREE_CONNECTION | FILE_SYNCHRONOUS_IO_NONALERT, Ea, EaLength);
    WipeEa(Ea, EaAlloc);
    if (!NT_SUCCESS(Status))
    {
        TRACE("tree connect %wZ: %lx\n", &NtName, Status);
        HeapFree(GetProcessHeap(), 0, Name);
        return StatusToError(Status);
    }
    /* The connection stays after this handle (the redirector keeps it until NPCancelConnection) */
    NtClose(Handle);

    Error = WN_SUCCESS;
    if (Letter != 0)
    {
        WCHAR Drive[3] = { Letter, L':', 0 };

        if (!DefineDosDeviceW(DDD_RAW_TARGET_PATH, Drive, Name))
        {
            Error = GetLastError();
            /* Take the connection back */
            Uses = GetUses(&i);
            if (Uses != NULL)
            {
                for (i = 0; i < Uses->Count; i++)
                {
                    if (Uses->Entries[i].Local == Letter)
                        DeleteUse(Uses->Entries[i].Id, TRUE);
                }
                HeapFree(GetProcessHeap(), 0, Uses);
            }
        }
    }
    HeapFree(GetProcessHeap(), 0, Name);
    return Error;
}

DWORD
APIENTRY
NPAddConnection(LPNETRESOURCEW lpNetResource,
                LPWSTR lpPassword,
                LPWSTR lpUserName)
{
    return NPAddConnection3(NULL, lpNetResource, lpPassword, lpUserName, 0);
}

DWORD
APIENTRY
NPCancelConnection(LPWSTR lpName,
                   BOOL fForce)
{
    PSMBCONN_ENUM_OUTPUT Uses;
    WCHAR Letter, Target[NP_MAX_TARGET], Remote[4];
    SIZE_T RemoteChars;
    DWORD Error, Needed, i, Found = 0;
    NTSTATUS Status;

    if (lpName == NULL)
        return WN_BAD_POINTER;

    Letter = DriveLetterOf(lpName);
    if (Letter != 0)
    {
        WCHAR Drive[3] = { Letter, L':', 0 };

        Error = DriveRemote(Letter, Remote, 0, &Needed, Target, ARRAYSIZE(Target));
        if (Error != WN_SUCCESS && Error != WN_MORE_DATA)
            return Error == WN_NOT_CONNECTED ? NOT_CONNECTED : Error;
        Uses = GetUses(&Error);
        if (Uses != NULL)
        {
            for (i = 0; i < Uses->Count; i++)
            {
                if (Uses->Entries[i].Local != Letter)
                    continue;
                Status = DeleteUse(Uses->Entries[i].Id, fForce);
                if (Status == STATUS_FILES_OPEN)
                {
                    HeapFree(GetProcessHeap(), 0, Uses);
                    return OPEN_FILES;
                }
            }
            HeapFree(GetProcessHeap(), 0, Uses);
        }
        /* The letter goes even when the redirector has forgotten the connection (an engine restart) */
        if (!DefineDosDeviceW(DDD_REMOVE_DEFINITION | DDD_RAW_TARGET_PATH | DDD_EXACT_MATCH_ON_REMOVE, Drive, Target))
            return GetLastError();
        return WN_SUCCESS;
    }

    if (!CheckRemoteName(lpName, &RemoteChars))
        return WN_BAD_NETNAME;
    Uses = GetUses(&Error);
    if (Uses == NULL)
        return Error == WN_NO_NETWORK ? NOT_CONNECTED : Error;
    for (i = 0; i < Uses->Count; i++)
    {
        PSMBCONN_ENTRY e = &Uses->Entries[i];

        /* "net use \\server\share /delete": the connection made without a device (as listed) */
        if (e->Local != 0 || !(e->Flags & SMBCONN_FLAG_TREE_CONNECTED) || !EntryRemoteIs(Uses, e, lpName, RemoteChars))
            continue;
        Status = DeleteUse(e->Id, fForce);
        if (Status == STATUS_FILES_OPEN)
        {
            HeapFree(GetProcessHeap(), 0, Uses);
            return OPEN_FILES;
        }
        if (NT_SUCCESS(Status))
            Found++;
    }
    HeapFree(GetProcessHeap(), 0, Uses);
    return Found ? WN_SUCCESS : NOT_CONNECTED;
}

DWORD
APIENTRY
NPGetConnection(LPWSTR lpLocalName,
                LPWSTR lpRemoteName,
                LPDWORD lpBufferSize)
{
    WCHAR Letter = DriveLetterOf(lpLocalName);
    DWORD Needed = 0, Error;

    if (lpBufferSize == NULL)
        return WN_BAD_POINTER;
    if (Letter == 0)
        return WN_BAD_LOCALNAME;
    Error = DriveRemote(Letter, lpRemoteName, *lpBufferSize, &Needed, NULL, 0);
    if (Error == WN_MORE_DATA)
        *lpBufferSize = Needed;
    return Error;
}

/* Enumeration of connected resources ****************************************/

typedef struct _NP_ENUM
{
    PSMBCONN_ENUM_OUTPUT Uses;
    DWORD Next;
    DWORD Type;
} NP_ENUM, *PNP_ENUM;

/* What net use and WNetOpenEnum(RESOURCE_CONNECTED) list: connections made by a tree connect */
static
BOOL
Listed(PSMBCONN_ENTRY e)
{
    return (e->Flags & SMBCONN_FLAG_TREE_CONNECTED) != 0;
}

DWORD
APIENTRY
NPOpenEnum(DWORD dwScope,
           DWORD dwType,
           DWORD dwUsage,
           LPNETRESOURCEW lpNetResource,
           LPHANDLE lphEnum)
{
    PNP_ENUM Enum;
    DWORD Error;

    UNREFERENCED_PARAMETER(dwUsage);
    UNREFERENCED_PARAMETER(lpNetResource);

    if (lphEnum == NULL)
        return WN_BAD_POINTER;
    if (dwScope != RESOURCE_CONNECTED)
        return WN_NOT_SUPPORTED;
    Enum = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*Enum));
    if (Enum == NULL)
        return WN_OUT_OF_MEMORY;
    Enum->Type = dwType;
    Enum->Uses = GetUses(&Error);
    if (Enum->Uses == NULL && Error != WN_NO_NETWORK)
    {
        HeapFree(GetProcessHeap(), 0, Enum);
        return Error;
    }
    *lphEnum = Enum;
    return WN_SUCCESS;
}

DWORD
APIENTRY
NPEnumResource(HANDLE hEnum,
               LPDWORD lpcCount,
               LPVOID lpBuffer,
               LPDWORD lpBufferSize)
{
    PNP_ENUM Enum = hEnum;
    LPNETRESOURCEW Out = lpBuffer;
    PUCHAR End;
    DWORD Count = 0, Want;
    static const WCHAR Provider[] = PROVIDER_NAME;

    if (Enum == NULL || lpcCount == NULL || lpBufferSize == NULL)
        return WN_BAD_POINTER;
    Want = *lpcCount;
    End = (PUCHAR)lpBuffer + *lpBufferSize;

    while (Enum->Uses != NULL && Enum->Next < Enum->Uses->Count && Count < Want &&
           (Enum->Type == RESOURCETYPE_ANY || (Enum->Type & RESOURCETYPE_DISK)))
    {
        PSMBCONN_ENTRY e = &Enum->Uses->Entries[Enum->Next];
        DWORD Strings, Need;
        PWCHAR s;

        if (!Listed(e))
        {
            Enum->Next++;
            continue;
        }
        Strings = (e->Local ? 3 : 0) * sizeof(WCHAR) + e->RemoteLength + sizeof(WCHAR) + sizeof(Provider);
        Need = sizeof(NETRESOURCEW) + Strings;
        if ((PUCHAR)(Out + 1) + Strings > End || (PUCHAR)(Out + 1) > End - Strings)
        {
            if (Count == 0)
            {
                *lpBufferSize = Need;
                return WN_MORE_DATA;
            }
            break;
        }
        /* Strings from the end of the buffer down */
        End -= Strings;
        s = (PWCHAR)End;
        ZeroMemory(Out, sizeof(*Out));
        Out->dwScope = RESOURCE_CONNECTED;
        Out->dwType = RESOURCETYPE_DISK;
        Out->dwDisplayType = RESOURCEDISPLAYTYPE_SHARE;
        Out->dwUsage = RESOURCEUSAGE_CONNECTABLE;
        if (e->Local)
        {
            Out->lpLocalName = s;
            s[0] = e->Local; s[1] = L':'; s[2] = 0;
            s += 3;
        }
        Out->lpRemoteName = s;
        memcpy(s, (PUCHAR)Enum->Uses + e->RemoteOffset, e->RemoteLength);
        s += e->RemoteLength / sizeof(WCHAR);
        *s++ = 0;
        Out->lpProvider = s;
        memcpy(s, Provider, sizeof(Provider));
        Out++;
        Count++;
        Enum->Next++;
    }
    *lpcCount = Count;
    return Count ? WN_SUCCESS : WN_NO_MORE_ENTRIES;
}

DWORD
APIENTRY
NPCloseEnum(HANDLE hEnum)
{
    PNP_ENUM Enum = hEnum;

    if (Enum == NULL)
        return WN_BAD_HANDLE;
    if (Enum->Uses != NULL)
        HeapFree(GetProcessHeap(), 0, Enum->Uses);
    HeapFree(GetProcessHeap(), 0, Enum);
    return WN_SUCCESS;
}

/* Names *********************************************************************/

DWORD
APIENTRY
NPGetUser(LPWSTR lpName,
          LPWSTR lpUserName,
          LPDWORD lpBufferSize)
{
    WCHAR Own[UNLEN + DNLEN + 260], Remote[NP_MAX_TARGET];
    PSMBCONN_ENUM_OUTPUT Uses;
    LPCWSTR Which = NULL;
    SIZE_T Chars = 0, RemoteChars;
    DWORD Error, Needed, i;
    WCHAR Letter;
    BOOL Found = FALSE;

    if (lpBufferSize == NULL)
        return WN_BAD_POINTER;

    if (lpName != NULL && lpName[0])
    {
        Letter = DriveLetterOf(lpName);
        if (Letter != 0)
        {
            Error = DriveRemote(Letter, Remote, ARRAYSIZE(Remote), &Needed, NULL, 0);
            if (Error != WN_SUCCESS)
                return Error;
        }
        else if (!CheckRemoteName(lpName, &RemoteChars))
        {
            return WN_BAD_NETNAME;
        }
        Uses = GetUses(&Error);
        if (Uses == NULL)
            return WN_NOT_CONNECTED;
        for (i = 0; i < Uses->Count && !Found; i++)
        {
            PSMBCONN_ENTRY e = &Uses->Entries[i];

            if ((Letter != 0 && e->Local == Letter) ||
                (Letter == 0 && e->Local == 0 && EntryRemoteIs(Uses, e, lpName, RemoteChars)))
            {
                Found = TRUE;
                if (e->UserLength != 0 && e->UserLength < sizeof(Own))
                {
                    memcpy(Own, (PUCHAR)Uses + e->UserOffset, e->UserLength);
                    Own[e->UserLength / sizeof(WCHAR)] = 0;
                    Which = Own;
                }
            }
        }
        HeapFree(GetProcessHeap(), 0, Uses);
        if (!Found)
            return WN_NOT_CONNECTED;
    }
    if (Which == NULL)
    {
        if (!GetOwnUser(Own, ARRAYSIZE(Own)))
            return GetLastError();
        Which = Own;
    }
    Chars = wcslen(Which) + 1;
    if (lpUserName == NULL || *lpBufferSize < Chars)
    {
        *lpBufferSize = (DWORD)Chars;
        return WN_MORE_DATA;
    }
    wcscpy(lpUserName, Which);
    return WN_SUCCESS;
}

DWORD
APIENTRY
NPGetUniversalName(LPCWSTR lpLocalPath,
                   DWORD dwInfoLevel,
                   LPVOID lpBuffer,
                   LPDWORD lpBufferSize)
{
    WCHAR Remote[NP_MAX_TARGET];
    LPCWSTR Rest;
    DWORD Needed, Error, Size, RemoteChars, RestChars;
    WCHAR Letter;

    if (lpLocalPath == NULL || lpBufferSize == NULL)
        return WN_BAD_POINTER;
    if (dwInfoLevel != UNIVERSAL_NAME_INFO_LEVEL && dwInfoLevel != REMOTE_NAME_INFO_LEVEL)
        return WN_BAD_LEVEL;
    if (!lpLocalPath[0] || lpLocalPath[1] != L':')
        return WN_BAD_LOCALNAME;
    Letter = (WCHAR)towupper(lpLocalPath[0]);
    if (Letter < L'A' || Letter > L'Z')
        return WN_BAD_LOCALNAME;
    Error = DriveRemote(Letter, Remote, ARRAYSIZE(Remote), &Needed, NULL, 0);
    if (Error != WN_SUCCESS)
        return Error;
    Rest = lpLocalPath + 2;
    RemoteChars = (DWORD)wcslen(Remote);
    RestChars = (DWORD)wcslen(Rest);

    if (dwInfoLevel == UNIVERSAL_NAME_INFO_LEVEL)
    {
        LPUNIVERSAL_NAME_INFOW Info = lpBuffer;

        Size = sizeof(*Info) + (RemoteChars + RestChars + 1) * sizeof(WCHAR);
        if (lpBuffer == NULL || *lpBufferSize < Size)
        {
            *lpBufferSize = Size;
            return WN_MORE_DATA;
        }
        Info->lpUniversalName = (LPWSTR)(Info + 1);
        wcscpy(Info->lpUniversalName, Remote);
        wcscat(Info->lpUniversalName, Rest);
    }
    else
    {
        LPREMOTE_NAME_INFOW Info = lpBuffer;
        PWCHAR s;

        Size = sizeof(*Info) + (RemoteChars + RestChars + 1 + RemoteChars + 1 + RestChars + 1) * sizeof(WCHAR);
        if (lpBuffer == NULL || *lpBufferSize < Size)
        {
            *lpBufferSize = Size;
            return WN_MORE_DATA;
        }
        s = (PWCHAR)(Info + 1);
        Info->lpUniversalName = s;
        wcscpy(s, Remote);
        wcscat(s, Rest);
        s += RemoteChars + RestChars + 1;
        Info->lpConnectionName = s;
        wcscpy(s, Remote);
        s += RemoteChars + 1;
        Info->lpRemainingPath = s;
        wcscpy(s, Rest);
    }
    return WN_SUCCESS;
}

/* "\\server\share\path" -> resource "\\server\share", system part "\path" (names only: the
 * server is not asked) */
DWORD
APIENTRY
NPGetResourceInformation(LPNETRESOURCEW lpNetResource,
                         LPVOID lpBuffer,
                         LPDWORD lpcbBuffer,
                         LPWSTR *lplpSystem)
{
    static const WCHAR Provider[] = PROVIDER_NAME;
    LPNETRESOURCEW Out = lpBuffer;
    LPCWSTR Remote, p;
    SIZE_T Chars, Share, System;
    DWORD Size;
    PWCHAR s;

    if (lpNetResource == NULL || lpcbBuffer == NULL || lplpSystem == NULL)
        return WN_BAD_POINTER;
    Remote = lpNetResource->lpRemoteName;
    if (!CheckRemoteName(Remote, &Chars))
        return WN_BAD_NETNAME;
    p = wcschr(Remote + 2, L'\\');
    p = wcschr(p + 1, L'\\');
    Share = (p != NULL && (SIZE_T)(p - Remote) < Chars) ? (SIZE_T)(p - Remote) : Chars;
    System = Chars - Share;
    Size = sizeof(NETRESOURCEW) + (DWORD)((Share + 1 + System + 1) * sizeof(WCHAR)) + sizeof(Provider);
    if (lpBuffer == NULL || *lpcbBuffer < Size)
    {
        *lpcbBuffer = Size;
        return WN_MORE_DATA;
    }
    ZeroMemory(Out, sizeof(*Out));
    Out->dwScope = RESOURCE_GLOBALNET;
    Out->dwType = RESOURCETYPE_DISK;
    Out->dwDisplayType = RESOURCEDISPLAYTYPE_SHARE;
    Out->dwUsage = RESOURCEUSAGE_CONNECTABLE;
    s = (PWCHAR)(Out + 1);
    Out->lpRemoteName = s;
    memcpy(s, Remote, Share * sizeof(WCHAR));
    s[Share] = 0;
    s += Share + 1;
    Out->lpProvider = s;
    memcpy(s, Provider, sizeof(Provider));
    s += ARRAYSIZE(Provider);
    if (System != 0)
    {
        memcpy(s, Remote + Share, System * sizeof(WCHAR));
        s[System] = 0;
        *lplpSystem = s;
    }
    else
    {
        *lplpSystem = NULL;
    }
    return WN_SUCCESS;
}

/* "\\server\share[\path]" -> "\\server"; "\\server" has no parent here (WN_BAD_NETNAME) */
DWORD
APIENTRY
NPGetResourceParent(LPNETRESOURCEW lpNetResource,
                    LPVOID lpBuffer,
                    LPDWORD lpcbBuffer)
{
    static const WCHAR Provider[] = PROVIDER_NAME;
    LPNETRESOURCEW Out = lpBuffer;
    LPCWSTR Remote, p;
    SIZE_T Chars, Server;
    DWORD Size;
    PWCHAR s;

    if (lpNetResource == NULL || lpcbBuffer == NULL)
        return WN_BAD_POINTER;
    Remote = lpNetResource->lpRemoteName;
    if (!CheckRemoteName(Remote, &Chars))
        return WN_BAD_NETNAME;
    p = wcschr(Remote + 2, L'\\');
    Server = p - Remote;
    Size = sizeof(NETRESOURCEW) + (DWORD)((Server + 1) * sizeof(WCHAR)) + sizeof(Provider);
    if (lpBuffer == NULL || *lpcbBuffer < Size)
    {
        *lpcbBuffer = Size;
        return WN_MORE_DATA;
    }
    ZeroMemory(Out, sizeof(*Out));
    Out->dwScope = RESOURCE_GLOBALNET;
    Out->dwType = RESOURCETYPE_ANY;
    Out->dwDisplayType = RESOURCEDISPLAYTYPE_SERVER;
    Out->dwUsage = RESOURCEUSAGE_CONTAINER;
    s = (PWCHAR)(Out + 1);
    Out->lpRemoteName = s;
    memcpy(s, Remote, Server * sizeof(WCHAR));
    s[Server] = 0;
    s += Server + 1;
    Out->lpProvider = s;
    memcpy(s, Provider, sizeof(Provider));
    return WN_SUCCESS;
}

DWORD
APIENTRY
NPFormatNetworkName(LPWSTR lpRemoteName,
                    LPWSTR lpFormattedName,
                    LPDWORD lpnLength,
                    DWORD dwFlags,
                    DWORD dwAveCharPerLine)
{
    SIZE_T Chars;

    UNREFERENCED_PARAMETER(dwFlags);
    UNREFERENCED_PARAMETER(dwAveCharPerLine);

    if (lpRemoteName == NULL || lpnLength == NULL)
        return WN_BAD_POINTER;
    Chars = wcslen(lpRemoteName) + 1;
    if (lpFormattedName == NULL || *lpnLength < Chars)
    {
        *lpnLength = (DWORD)Chars;
        return WN_MORE_DATA;
    }
    wcscpy(lpFormattedName, lpRemoteName);
    return WN_SUCCESS;
}

/* Not provided: Explorer's property pages and directory notifications of the provider */
DWORD
APIENTRY
NPPropertyDialog(HWND hwndParent,
                 DWORD iButtonDlg,
                 DWORD nPropSel,
                 LPWSTR lpFileName,
                 DWORD nType)
{
    return WN_NOT_SUPPORTED;
}

DWORD
APIENTRY
NPGetDirectoryType(LPWSTR lpName,
                   LPINT lpType,
                   BOOL bFlushCache)
{
    return WN_NOT_SUPPORTED;
}

DWORD
APIENTRY
NPDirectoryNotify(HWND hwnd,
                  LPWSTR lpDir,
                  DWORD dwOper)
{
    return WN_NOT_SUPPORTED;
}

DWORD
APIENTRY
NPGetPropertyText(DWORD iButton,
                  DWORD nPropSel,
                  LPWSTR lpName,
                  LPWSTR lpButtonName,
                  DWORD nButtonNameLen,
                  DWORD nType)
{
    return WN_NOT_SUPPORTED;
}

BOOL
WINAPI
DllMain(IN HINSTANCE hinstDLL,
        IN DWORD dwReason,
        IN LPVOID lpvReserved)
{
    if (dwReason == DLL_PROCESS_ATTACH)
        DisableThreadLibraryCalls(hinstDLL);
    return TRUE;
}
