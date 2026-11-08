/*
 * PROJECT:     ReactOS Device Installer
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Installs the driver of a new device for the Plug and Play
 *              service, in the service's own (SYSTEM) context, as DrvInst.exe
 *              does on Windows. No user interface: when no driver is found,
 *              the service hands the device to the wizard in the user's session.
 *              It also installs the driver an administrator picked (wizard,
 *              Update Driver, UpdateDriverForPlugAndPlayDevices): the service
 *              passes the INF path it checked, and the install runs here.
 */

#define WIN32_NO_STATUS
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <windef.h>
#include <winbase.h>
#include <winreg.h>
#include <winuser.h>
#include <sddl.h>
#include <setupapi.h>
#include <cfgmgr32.h>
#include <dll/newdevp.h>

/* The pipe protocol is the one umpnpmgr uses for newdev!ClientSideInstallW */
#define MAX_EVENT_NAME_BYTES    (128 * sizeof(WCHAR))
#define MAX_DEVICE_ID_BYTES     PNP_INSTALL_MAX_DEVICE_ID_BYTES
#define MAX_INF_PATH_BYTES      (MAX_PATH * sizeof(WCHAR))
#define MAX_REQUESTER_BYTES     (256 * sizeof(WCHAR))

static HANDLE hLog = INVALID_HANDLE_VALUE;

/* A device ID is not trusted input: control characters (CR, LF, ...) in it could
   inject fake sections into setupapi.dev.log */
static BOOL
HasControlChars(_In_ PCWSTR String)
{
    for (; *String != UNICODE_NULL; String++)
    {
        if (*String < L' ' || *String == 0x7f)
            return TRUE;
    }
    return FALSE;
}

/* Does this process run as SYSTEM? An install of an administrator's driver does only there:
   run by anyone else, drvinst.exe must not stage or install anything */
static BOOL
IsSystemProcess(VOID)
{
    SID_IDENTIFIER_AUTHORITY NtAuthority = {SECURITY_NT_AUTHORITY};
    /* The kernel probes the output buffer for ULONG alignment: a plain BYTE array on the stack
       is not aligned, and a Debug build's stack layout made GetTokenInformation fail */
    union { TOKEN_USER User; BYTE Bytes[sizeof(TOKEN_USER) + SECURITY_MAX_SID_SIZE]; } Buffer;
    PSID SystemSid;
    HANDLE hToken;
    DWORD Size;
    BOOL Result = FALSE;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
        return FALSE;
    if (GetTokenInformation(hToken, TokenUser, &Buffer, sizeof(Buffer), &Size) &&
        AllocateAndInitializeSid(&NtAuthority, 1, SECURITY_LOCAL_SYSTEM_RID, 0, 0, 0, 0, 0, 0, 0, &SystemSid))
    {
        Result = EqualSid(Buffer.User.User.Sid, SystemSid);
        FreeSid(SystemSid);
    }
    CloseHandle(hToken);
    return Result;
}

static VOID
LogPrint(_In_ PCSTR Format, ...)
{
    CHAR Buffer[1024] = {0};
    DWORD Written;
    va_list Args;
    int Length, i;

    if (hLog == INVALID_HANDLE_VALUE)
        return;

    va_start(Args, Format);
    Length = _vsnprintf(Buffer, sizeof(Buffer) - 3, Format, Args);
    va_end(Args);
    /* Negative: truncated, or an encoding failure. Write only the part that was
       filled in: the buffer started zeroed, so that is the part before the first NUL */
    if (Length < 0)
        Length = (int)strnlen(Buffer, sizeof(Buffer) - 3);

    /* Only printable ASCII reaches the log, whatever the arguments held */
    for (i = 0; i < Length; i++)
    {
        if ((UCHAR)Buffer[i] < ' ' || (UCHAR)Buffer[i] > 0x7e)
            Buffer[i] = '?';
    }
    Buffer[Length++] = '\r';
    Buffer[Length++] = '\n';
    WriteFile(hLog, Buffer, Length, &Written, NULL);
}

/* %SystemRoot%\inf\setupapi.dev.log, in the section format Windows uses */
static VOID
OpenDeviceLog(VOID)
{
    WCHAR Path[MAX_PATH];
    UINT Length;
    OSVERSIONINFOEXW Version;
    SYSTEM_INFO SystemInfo;
    PCSTR Architecture;

    Length = GetSystemWindowsDirectoryW(Path, _countof(Path));
    if (Length == 0 || Length + 22 >= _countof(Path))
        return;
    wcscat(Path, L"\\inf\\setupapi.dev.log");

    hLog = CreateFileW(Path, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE,
                       NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hLog == INVALID_HANDLE_VALUE || GetLastError() == ERROR_ALREADY_EXISTS)
        return;

    /* New log: write the header */
    ZeroMemory(&Version, sizeof(Version));
    Version.dwOSVersionInfoSize = sizeof(Version);
    GetVersionExW((POSVERSIONINFOW)&Version);
    GetNativeSystemInfo(&SystemInfo);
    switch (SystemInfo.wProcessorArchitecture)
    {
        case PROCESSOR_ARCHITECTURE_AMD64: Architecture = "amd64"; break;
        case PROCESSOR_ARCHITECTURE_INTEL: Architecture = "x86"; break;
        case PROCESSOR_ARCHITECTURE_ARM:   Architecture = "arm"; break;
        default:                           Architecture = "unknown"; break;
    }
    LogPrint("[Device Install Log]");
    LogPrint("     OS Version = %lu.%lu.%lu", Version.dwMajorVersion, Version.dwMinorVersion, Version.dwBuildNumber);
    LogPrint("     Service Pack = %u.%u", Version.wServicePackMajor, Version.wServicePackMinor);
    LogPrint("     Suite = 0x%04x", Version.wSuiteMask);
    LogPrint("     ProductType = %u", Version.wProductType);
    LogPrint("     Architecture = %s", Architecture);
    LogPrint("");
    LogPrint("[BeginLog]");
}

static VOID
LogTime(_Out_writes_(Size) PSTR Buffer, _In_ SIZE_T Size, _In_ BOOL WithDate)
{
    SYSTEMTIME Time;

    GetLocalTime(&Time);
    if (WithDate)
        _snprintf(Buffer, Size, "%04u/%02u/%02u %02u:%02u:%02u.%03u",
                  Time.wYear, Time.wMonth, Time.wDay,
                  Time.wHour, Time.wMinute, Time.wSecond, Time.wMilliseconds);
    else
        _snprintf(Buffer, Size, "%02u:%02u:%02u.%03u",
                  Time.wHour, Time.wMinute, Time.wSecond, Time.wMilliseconds);
    Buffer[Size - 1] = ANSI_NULL;
}

/* The account the install runs as: this is what makes the registry writes service-side */
static VOID
LogAccount(VOID)
{
    HANDLE hToken;
    union { TOKEN_USER User; BYTE Bytes[256]; } Buffer; /* ULONG aligned: the kernel probes it */
    PTOKEN_USER User = &Buffer.User;
    DWORD Size;
    WCHAR Name[64], Domain[64];
    DWORD NameLength = _countof(Name), DomainLength = _countof(Domain);
    SID_NAME_USE Use;
    LPWSTR SidString = NULL;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
        return;
    if (GetTokenInformation(hToken, TokenUser, &Buffer, sizeof(Buffer), &Size))
    {
        if (!LookupAccountSidW(NULL, User->User.Sid, Name, &NameLength, Domain, &DomainLength, &Use))
        {
            wcscpy(Name, L"?");
            Domain[0] = UNICODE_NULL;
        }
        ConvertSidToStringSidW(User->User.Sid, &SidString);
        LogPrint("     ndv: Install process %lu runs as %ls%ls%ls (%ls)",
                 GetCurrentProcessId(), Domain, Domain[0] ? L"\\" : L"", Name,
                 SidString ? SidString : L"?");
        if (SidString)
            LocalFree(SidString);
    }
    CloseHandle(hToken);
}

/* Header of the device install log section, by who asked for the install */
static PCSTR
SectionTitle(_In_ DWORD UiMode, _In_ DWORD Origin)
{
    if (UiMode != NEWDEV_UI_INSTALL_INF)
        return "Hardware initiated";
    switch (Origin)
    {
        case PNP_INSTALL_ORIGIN_WIZARD:       return "Wizard selected driver";
        case PNP_INSTALL_ORIGIN_UPDATEDRIVER: return "UpdateDriverForPlugAndPlayDevices";
        default:                              return "DevInstall selected driver";
    }
}

/* Is the INF in %SystemRoot%\inf already? Then there is nothing to stage */
static BOOL
IsSystemInf(_In_ PCWSTR InfPath)
{
    WCHAR InfDir[MAX_PATH];
    PCWSTR FileName;
    UINT Length;

    Length = GetSystemWindowsDirectoryW(InfDir, _countof(InfDir));
    if (Length == 0 || Length + 5 >= _countof(InfDir))
        return FALSE;
    wcscat(InfDir, L"\\inf\\");
    FileName = wcsrchr(InfPath, L'\\');
    if (!FileName)
        return FALSE;
    FileName++;
    return ((SIZE_T)(FileName - InfPath) == wcslen(InfDir) &&
            _wcsnicmp(InfPath, InfDir, FileName - InfPath) == 0);
}

/* Stages the driver package (the INF) into %SystemRoot%\inf as oemN.inf, as SYSTEM */
static BOOL
StageDriverPackage(_In_ PCWSTR InfPath)
{
    WCHAR OemInf[MAX_PATH];
    DWORD Error;

    if (IsSystemInf(InfPath))
    {
        LogPrint("     sto: %ls is a system INF, nothing to stage", InfPath);
        return TRUE;
    }

    OemInf[0] = UNICODE_NULL;
    if (SetupCopyOEMInfW(InfPath, NULL, SPOST_NONE, SP_COPY_NOOVERWRITE, OemInf, _countof(OemInf), NULL, NULL))
    {
        LogPrint("     sto: Driver package %ls staged as %ls", InfPath, OemInf);
        return TRUE;
    }

    Error = GetLastError();
    if (Error == ERROR_FILE_EXISTS)
    {
        LogPrint("     sto: Driver package %ls is staged already as %ls", InfPath, OemInf);
        return TRUE;
    }

    LogPrint("     sto: Cannot stage %ls, error 0x%08lx", InfPath, Error);
    SetLastError(Error);
    return FALSE;
}

static BOOL
ReadPipe(_In_ HANDLE hPipe, _Out_writes_bytes_(Size) PVOID Buffer, _In_ DWORD Size)
{
    DWORD Read;
    return ReadFile(hPipe, Buffer, Size, &Read, NULL) && Read == Size;
}

/* Reads a counted, NUL-terminated wide string of at most MaxBytes bytes */
static PWSTR
ReadPipeString(_In_ HANDLE hPipe, _In_ DWORD MaxBytes)
{
    DWORD Bytes;
    PWSTR String;

    if (!ReadPipe(hPipe, &Bytes, sizeof(Bytes)))
        return NULL;
    if (Bytes < sizeof(WCHAR) || Bytes > MaxBytes || (Bytes % sizeof(WCHAR)) != 0)
        return NULL;
    String = HeapAlloc(GetProcessHeap(), 0, Bytes + sizeof(WCHAR));
    if (!String)
        return NULL;
    if (!ReadPipe(hPipe, String, Bytes))
    {
        HeapFree(GetProcessHeap(), 0, String);
        return NULL;
    }
    String[Bytes / sizeof(WCHAR)] = UNICODE_NULL;
    return String;
}

int WINAPI
wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPWSTR lpCmdLine, int nShowCmd)
{
    HANDLE hPipe, hEvent;
    PWSTR EventName = NULL, DeviceInstance = NULL, InfPath = NULL, Requester = NULL;
    BOOL Installed = FALSE, NeedRestart = FALSE;
    DWORD UiMode, Origin = 0, Error = ERROR_SUCCESS;
    CHAR Time[32];
    PWSTR Text;

    UNREFERENCED_PARAMETER(hInstance);
    UNREFERENCED_PARAMETER(hPrevInstance);
    UNREFERENCED_PARAMETER(nShowCmd);

    /* Only the Plug and Play service's pipes */
    if (_wcsnicmp(lpCmdLine, L"\\\\.\\pipe\\PNP_Device_Install_Pipe_", 33) != 0)
        return ERROR_INVALID_PARAMETER;

    /* Identification only: a pipe server that is not the service cannot impersonate us */
    hPipe = CreateFileW(lpCmdLine, GENERIC_READ, 0, NULL, OPEN_EXISTING,
                        FILE_ATTRIBUTE_NORMAL | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, NULL);
    if (hPipe == INVALID_HANDLE_VALUE)
        return GetLastError();

    EventName = ReadPipeString(hPipe, MAX_EVENT_NAME_BYTES);
    if (!EventName || !ReadPipe(hPipe, &UiMode, sizeof(UiMode)))
    {
        Error = ERROR_INVALID_DATA;
        goto Quit;
    }
    DeviceInstance = ReadPipeString(hPipe, MAX_DEVICE_ID_BYTES);
    if (!DeviceInstance || HasControlChars(DeviceInstance))
    {
        Error = ERROR_INVALID_DATA;
        goto Quit;
    }

    /* An install an administrator asked for: the INF, who asked for it, and from where */
    if (UiMode == NEWDEV_UI_INSTALL_INF)
    {
        /* Before anything is read, logged or staged */
        if (!IsSystemProcess())
        {
            Error = ERROR_ACCESS_DENIED;
            goto Quit;
        }
        InfPath = ReadPipeString(hPipe, MAX_INF_PATH_BYTES);
        if (!InfPath || HasControlChars(InfPath) || !ReadPipe(hPipe, &Origin, sizeof(Origin)))
        {
            Error = ERROR_INVALID_DATA;
            goto Quit;
        }
        Requester = ReadPipeString(hPipe, MAX_REQUESTER_BYTES);
        if (!Requester)
        {
            Error = ERROR_INVALID_DATA;
            goto Quit;
        }
        /* The account name goes into the log: no control characters (no fake log lines) */
        for (Text = Requester; *Text != UNICODE_NULL; Text++)
        {
            if (*Text < L' ' || *Text == 0x7f)
                *Text = L'?';
        }
    }

    OpenDeviceLog();
    LogPrint("");
    LogPrint(">>>  [Device Install (%s) - %ls]", SectionTitle(UiMode, Origin), DeviceInstance);
    LogTime(Time, sizeof(Time), TRUE);
    LogPrint(">>>  Section start %s", Time);
    LogPrint("      cmd: %ls", GetCommandLineW());
    LogAccount();
    LogTime(Time, sizeof(Time), FALSE);
    if (InfPath)
    {
        LogPrint("     ndv: Requested by %ls", Requester);
        LogPrint("     ndv: INF: %ls", InfPath);
    }
    LogPrint("     ndv: {Install Device: %ls} %s", DeviceInstance, Time);

    SetLastError(ERROR_SUCCESS);
    if (InfPath)
    {
        /* The driver the administrator picked: stage its package, then install it, without UI */
        Installed = StageDriverPackage(InfPath) &&
                    DevInstallFromInfW(DeviceInstance, InfPath, 0);
    }
    else
    {
        /* Driver search in the system INF directory and install, without UI */
        Installed = DevInstallW(NULL, NULL, DeviceInstance, SW_HIDE);
    }
    if (!Installed)
    {
        Error = GetLastError();
        if (Error == ERROR_SUCCESS)
            Error = ERROR_NO_DRIVER_SELECTED;
    }
    else
    {
        /* DevInstallW without UI reports a needed restart this way */
        NeedRestart = (GetLastError() == ERROR_SUCCESS_REBOOT_REQUIRED);
    }

    LogTime(Time, sizeof(Time), FALSE);
    LogPrint("     ndv: {Install Device - exit(0x%08lx)} %s", Installed ? 0 : Error, Time);
    if (NeedRestart)
        LogPrint("     ndv: The device needs a restart to finish the install.");
    if (!Installed && UiMode == NEWDEV_UI_WIZARD)
        LogPrint("     ndv: No driver installed here; the wizard runs in the user's session.");

    if (Installed)
    {
        hEvent = OpenEventW(EVENT_MODIFY_STATE, FALSE, EventName);
        if (hEvent)
        {
            SetEvent(hEvent);
            CloseHandle(hEvent);
        }
        else
        {
            /* The device is installed: that stays a success. The service also takes
               the exit code as the result, so the user gets no redundant wizard. */
            LogPrint("     ndv: Cannot open the install event, error %lu; the install itself succeeded.", GetLastError());
        }
    }

    LogTime(Time, sizeof(Time), TRUE);
    LogPrint("<<<  Section end %s", Time);
    if (Installed)
        LogPrint("<<<  [Exit status: SUCCESS]");
    else
        LogPrint("<<<  [Exit status: FAILURE(0x%08lx)]", Error);

Quit:
    if (hLog != INVALID_HANDLE_VALUE)
        CloseHandle(hLog);
    CloseHandle(hPipe);
    if (EventName)
        HeapFree(GetProcessHeap(), 0, EventName);
    if (DeviceInstance)
        HeapFree(GetProcessHeap(), 0, DeviceInstance);
    if (InfPath)
        HeapFree(GetProcessHeap(), 0, InfPath);
    if (Requester)
        HeapFree(GetProcessHeap(), 0, Requester);
    /* The Plug and Play service shows the restart page in the user's session */
    if (Installed)
        return NeedRestart ? ERROR_SUCCESS_REBOOT_REQUIRED : ERROR_SUCCESS;
    return Error;
}
