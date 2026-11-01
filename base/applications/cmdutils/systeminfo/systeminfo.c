/*
 * PROJECT:     ReactOS Command-Line Utilities
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     systeminfo.exe: displays operating system and hardware configuration
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * The field set, field order and the TABLE / LIST / CSV layouts follow the documented
 * behaviour of the Windows tool (English output). The values come from this system:
 * the registry, NtQuerySystemInformation, SMBIOS, iphlpapi, netapi32 and WMI.
 */

#define COBJMACROS
#define WIN32_NO_STATUS

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <wchar.h>

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <lm.h>
#include <shlwapi.h>
#include <ndk/rtlfuncs.h>
#include <ndk/exfuncs.h>
#include <initguid.h>
#include <objbase.h>
#include <wbemcli.h>
#include <intrin.h>

#include <udmihelp.h>
#include <conutils.h>

/* Field list (the order is the Windows order) ********************************/

enum
{
    F_HOST_NAME, F_OS_NAME, F_OS_VERSION, F_OS_MANUFACTURER, F_OS_CONFIGURATION,
    F_OS_BUILD_TYPE, F_REG_OWNER, F_REG_ORG, F_PRODUCT_ID, F_INSTALL_DATE,
    F_BOOT_TIME, F_SYS_MANUFACTURER, F_SYS_MODEL, F_SYS_TYPE, F_PROCESSORS,
    F_BIOS_VERSION, F_WIN_DIR, F_SYS_DIR, F_BOOT_DEVICE, F_SYS_LOCALE,
    F_INPUT_LOCALE, F_TIME_ZONE, F_TOTAL_PHYS, F_AVAIL_PHYS, F_VM_MAX,
    F_VM_AVAIL, F_VM_INUSE, F_PAGEFILE, F_DOMAIN, F_LOGON_SERVER,
    F_HOTFIX, F_NIC, F_HYPERV,
    F_COUNT
};

static const struct
{
    PCWSTR Name;
    UINT TableWidth;
} g_FieldInfo[F_COUNT] =
{
    { L"Host Name", 30 },
    { L"OS Name", 30 },
    { L"OS Version", 30 },
    { L"OS Manufacturer", 40 },
    { L"OS Configuration", 40 },
    { L"OS Build Type", 20 },
    { L"Registered Owner", 50 },
    { L"Registered Organization", 50 },
    { L"Product ID", 30 },
    { L"Original Install Date", 25 },
    { L"System Boot Time", 30 },
    { L"System Manufacturer", 30 },
    { L"System Model", 20 },
    { L"System Type", 25 },
    { L"Processor(s)", 45 },
    { L"BIOS Version", 30 },
    { L"Windows Directory", 20 },
    { L"System Directory", 20 },
    { L"Boot Device", 35 },
    { L"System Locale", 35 },
    { L"Input Locale", 35 },
    { L"Time Zone", 50 },
    { L"Total Physical Memory", 25 },
    { L"Available Physical Memory", 25 },
    { L"Virtual Memory: Max Size", 25 },
    { L"Virtual Memory: Available", 25 },
    { L"Virtual Memory: In Use", 25 },
    { L"Page File Location(s)", 30 },
    { L"Domain", 20 },
    { L"Logon Server", 20 },
    { L"Hotfix(s)", 20 },
    { L"Network Card(s)", 100 },
    { L"Hyper-V Requirements", 100 },
};

#define LIST_VALUE_COLUMN 27

/* Growing string; the lines of a multi-line value are separated by L'\n' */
typedef struct _SB
{
    PWSTR Str;
    SIZE_T Len, Cap;
} SB;

static SB g_Fields[F_COUNT];

static VOID
SbAppend(SB *Sb, PCWSTR Text)
{
    SIZE_T n = wcslen(Text);

    if (Sb->Len + n + 1 > Sb->Cap)
    {
        SIZE_T NewCap = max(256, (Sb->Len + n + 1) * 2);
        PWSTR p = realloc(Sb->Str, NewCap * sizeof(WCHAR));
        if (!p)
            return;
        Sb->Str = p;
        Sb->Cap = NewCap;
    }
    memcpy(Sb->Str + Sb->Len, Text, (n + 1) * sizeof(WCHAR));
    Sb->Len += n;
}

static VOID
SbAppendF(SB *Sb, PCWSTR Format, ...)
{
    WCHAR Buf[1024];
    va_list Args;

    va_start(Args, Format);
    _vsnwprintf(Buf, _countof(Buf) - 1, Format, Args);
    va_end(Args);
    Buf[_countof(Buf) - 1] = UNICODE_NULL;
    SbAppend(Sb, Buf);
}

/* Start a new line of a multi-line value */
static VOID
SbLine(SB *Sb, PCWSTR Text)
{
    if (Sb->Len)
        SbAppend(Sb, L"\n");
    SbAppend(Sb, Text);
}

static VOID
SbLineF(SB *Sb, PCWSTR Format, ...)
{
    WCHAR Buf[1024];
    va_list Args;

    va_start(Args, Format);
    _vsnwprintf(Buf, _countof(Buf) - 1, Format, Args);
    va_end(Args);
    Buf[_countof(Buf) - 1] = UNICODE_NULL;
    SbLine(Sb, Buf);
}

/* A value that is empty or could not be obtained is shown as N/A */
static VOID
SbNA(SB *Sb)
{
    if (!Sb->Len)
        SbAppend(Sb, L"N/A");
}

/* Registry helpers ***********************************************************/

static BOOL
RegGetString(HKEY Root, PCWSTR SubKey, PCWSTR Name, PWSTR Buf, DWORD cchBuf)
{
    HKEY hKey;
    DWORD Type, Size = (cchBuf - 1) * sizeof(WCHAR);
    BOOL Ok = FALSE;

    Buf[0] = UNICODE_NULL;
    if (RegOpenKeyExW(Root, SubKey, 0, KEY_QUERY_VALUE, &hKey) != ERROR_SUCCESS)
        return FALSE;
    if (RegQueryValueExW(hKey, Name, NULL, &Type, (PBYTE)Buf, &Size) == ERROR_SUCCESS &&
        (Type == REG_SZ || Type == REG_MULTI_SZ || Type == REG_EXPAND_SZ))
    {
        Buf[Size / sizeof(WCHAR)] = UNICODE_NULL;
        Ok = Buf[0] != UNICODE_NULL;
    }
    RegCloseKey(hKey);
    return Ok;
}

static BOOL
RegGetDword(HKEY Root, PCWSTR SubKey, PCWSTR Name, PDWORD pValue)
{
    HKEY hKey;
    DWORD Type, Size = sizeof(*pValue);
    BOOL Ok;

    if (RegOpenKeyExW(Root, SubKey, 0, KEY_QUERY_VALUE, &hKey) != ERROR_SUCCESS)
        return FALSE;
    Ok = RegQueryValueExW(hKey, Name, NULL, &Type, (PBYTE)pValue, &Size) == ERROR_SUCCESS &&
         Type == REG_DWORD;
    RegCloseKey(hKey);
    return Ok;
}

#define CURRENT_VERSION_KEY L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"

/* Formatting helpers *********************************************************/

/* "<short date>, <time>" in the user locale, like "10/28/2026, 1:14:38 AM" */
static VOID
FormatLocalTime(SB *Sb, const SYSTEMTIME *St)
{
    WCHAR Date[64], Time[64];

    if (GetDateFormatW(LOCALE_USER_DEFAULT, DATE_SHORTDATE, St, NULL, Date, _countof(Date)) &&
        GetTimeFormatW(LOCALE_USER_DEFAULT, 0, St, NULL, Time, _countof(Time)))
    {
        SbAppendF(Sb, L"%s, %s", Date, Time);
    }
}

static VOID
FormatFileTimeLocal(SB *Sb, const FILETIME *Utc)
{
    FILETIME Local;
    SYSTEMTIME St;

    if (FileTimeToLocalFileTime(Utc, &Local) && FileTimeToSystemTime(&Local, &St))
        FormatLocalTime(Sb, &St);
}

/* "8,187 MB" */
static VOID
FormatMegabytes(SB *Sb, ULONGLONG Bytes)
{
    WCHAR Num[32], Sep[8] = L",", Out[64];
    NUMBERFMTW Fmt = { 0 };

    GetLocaleInfoW(LOCALE_USER_DEFAULT, LOCALE_STHOUSAND, Sep, _countof(Sep));
    _swprintf(Num, L"%I64u", Bytes / (1024 * 1024));
    Fmt.Grouping = 3;
    Fmt.lpDecimalSep = L".";
    Fmt.lpThousandSep = Sep;
    if (GetNumberFormatW(LOCALE_USER_DEFAULT, 0, Num, &Fmt, Out, _countof(Out)))
        SbAppendF(Sb, L"%s MB", Out);
    else
        SbAppendF(Sb, L"%s MB", Num);
}

/* SMBIOS dates are mm/dd/yyyy; the tool shows them without the leading zeros */
static VOID
FormatBiosDate(PWSTR Date)
{
    UINT m, d, y;
    WCHAR Out[32];

    if (swscanf(Date, L"%u/%u/%u", &m, &d, &y) == 3 && wcslen(Date) == 10)
    {
        _swprintf(Out, L"%u/%u/%u", m, d, y);
        wcscpy(Date, Out);
    }
}

/* WMI ************************************************************************/

/* Runs a WQL query and appends the (string converted) property of every row to Out,
 * one line each. Returns the number of rows, 0 when the class or WMI is unavailable. */
static UINT
WmiQueryProperty(PCWSTR Query, PCWSTR Property, SB *Out)
{
    IWbemLocator *Locator = NULL;
    IWbemServices *Services = NULL;
    IEnumWbemClassObject *Result = NULL;
    IWbemClassObject *Obj;
    BSTR bPath = NULL, bWql = NULL, bQuery = NULL;
    ULONG Count;
    UINT Rows = 0;
    HRESULT hr;

    hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (FAILED(hr) && hr != RPC_E_CHANGED_MODE)
        return 0;

    hr = CoCreateInstance(&CLSID_WbemLocator, NULL, CLSCTX_INPROC_SERVER,
                          &IID_IWbemLocator, (void **)&Locator);
    if (hr != S_OK)
        goto done;
    bPath = SysAllocString(L"ROOT\\CIMV2");
    bWql = SysAllocString(L"WQL");
    bQuery = SysAllocString(Query);
    if (!bPath || !bWql || !bQuery)
        goto done;
    if (IWbemLocator_ConnectServer(Locator, bPath, NULL, NULL, NULL, 0, NULL, NULL, &Services) != S_OK)
        goto done;
    if (IWbemServices_ExecQuery(Services, bWql, bQuery,
                                WBEM_FLAG_RETURN_IMMEDIATELY | WBEM_FLAG_FORWARD_ONLY,
                                NULL, &Result) != S_OK)
        goto done;

    for (;;)
    {
        VARIANT V;

        Obj = NULL;
        Count = 0;
        if (IEnumWbemClassObject_Next(Result, 10000, 1, &Obj, &Count) != S_OK || !Count)
            break;
        VariantInit(&V);
        if (IWbemClassObject_Get(Obj, Property, 0, &V, NULL, NULL) == S_OK &&
            VariantChangeType(&V, &V, 0, VT_BSTR) == S_OK && V_BSTR(&V) && V_BSTR(&V)[0])
        {
            SbLine(Out, V_BSTR(&V));
            Rows++;
        }
        VariantClear(&V);
        IWbemClassObject_Release(Obj);
    }

done:
    if (Result) IEnumWbemClassObject_Release(Result);
    if (Services) IWbemServices_Release(Services);
    if (Locator) IWbemLocator_Release(Locator);
    if (bPath) SysFreeString(bPath);
    if (bWql) SysFreeString(bWql);
    if (bQuery) SysFreeString(bQuery);
    if (hr == S_OK || hr == S_FALSE)
        CoUninitialize();
    return Rows;
}

/* Field collectors ***********************************************************/

static RTL_OSVERSIONINFOEXW g_Ver;
static NETSETUP_JOIN_STATUS g_JoinStatus = NetSetupUnknownStatus;
static WCHAR g_ComputerName[MAX_COMPUTERNAME_LENGTH + 1];
static WCHAR g_SystemDrive[3];

static VOID
GetHostAndOs(VOID)
{
    WCHAR Buf[512], WinDir[MAX_PATH];
    DWORD Size = _countof(g_ComputerName), Date;
    SB *Sb;
    PWSTR Name;
    SYSTEM_INFO Si;
    WCHAR Mfr[256];
    SB Tmp = { 0 };

    GetComputerNameW(g_ComputerName, &Size);
    SbAppend(&g_Fields[F_HOST_NAME], g_ComputerName);
    SbNA(&g_Fields[F_HOST_NAME]);

    g_Ver.dwOSVersionInfoSize = sizeof(g_Ver);
    RtlGetVersion((PRTL_OSVERSIONINFOW)&g_Ver);

    /* OS Name: the product name this system reports; the tool prefixes the vendor name
     * the same way for any Windows-branded product name */
    Sb = &g_Fields[F_OS_NAME];
    if (RegGetString(HKEY_LOCAL_MACHINE, CURRENT_VERSION_KEY, L"ProductName", Buf, _countof(Buf)))
    {
        if (!_wcsnicmp(Buf, L"Windows", 7))
            SbAppendF(Sb, L"Microsoft %s", Buf);
        else
            SbAppend(Sb, Buf);
    }
    SbNA(Sb);

    Sb = &g_Fields[F_OS_VERSION];
    SbAppendF(Sb, L"%lu.%lu.%lu %s Build %lu", g_Ver.dwMajorVersion, g_Ver.dwMinorVersion,
              g_Ver.dwBuildNumber, g_Ver.szCSDVersion[0] ? g_Ver.szCSDVersion : L"N/A",
              g_Ver.dwBuildNumber);

    /* OS Manufacturer: what WMI reports for this system, like the Windows tool */
    WmiQueryProperty(L"SELECT Manufacturer FROM Win32_OperatingSystem", L"Manufacturer", &Tmp);
    if (Tmp.Str)
    {
        wcsncpy(Mfr, Tmp.Str, _countof(Mfr) - 1);
        Mfr[_countof(Mfr) - 1] = UNICODE_NULL;
        if ((Name = wcschr(Mfr, L'\n')))
            *Name = UNICODE_NULL;
        SbAppend(&g_Fields[F_OS_MANUFACTURER], Mfr);
        free(Tmp.Str);
    }
    SbNA(&g_Fields[F_OS_MANUFACTURER]);

    /* OS Configuration: domain membership and product type */
    {
        PWSTR JoinName = NULL;

        if (NetGetJoinInformation(NULL, &JoinName, &g_JoinStatus) == NERR_Success)
            NetApiBufferFree(JoinName);
        else
            g_JoinStatus = NetSetupUnknownStatus;
    }
    Sb = &g_Fields[F_OS_CONFIGURATION];
    if (g_JoinStatus == NetSetupDomainName)
        SbAppend(Sb, g_Ver.wProductType == VER_NT_WORKSTATION ? L"Member Workstation" : L"Member Server");
    else
        SbAppend(Sb, g_Ver.wProductType == VER_NT_WORKSTATION ? L"Standalone Workstation" : L"Standalone Server");

    /* OS Build Type */
    GetSystemInfo(&Si);
    Sb = &g_Fields[F_OS_BUILD_TYPE];
    if (RegGetString(HKEY_LOCAL_MACHINE, CURRENT_VERSION_KEY, L"CurrentType", Buf, _countof(Buf)))
        SbAppend(Sb, Buf);
    else
#if DBG
        SbAppendF(Sb, L"%s Checked", Si.dwNumberOfProcessors > 1 ? L"Multiprocessor" : L"Uniprocessor");
#else
        SbAppendF(Sb, L"%s Free", Si.dwNumberOfProcessors > 1 ? L"Multiprocessor" : L"Uniprocessor");
#endif

    Sb = &g_Fields[F_REG_OWNER];
    if (RegGetString(HKEY_LOCAL_MACHINE, CURRENT_VERSION_KEY, L"RegisteredOwner", Buf, _countof(Buf)))
        SbAppend(Sb, Buf);
    SbNA(Sb);

    Sb = &g_Fields[F_REG_ORG];
    if (RegGetString(HKEY_LOCAL_MACHINE, CURRENT_VERSION_KEY, L"RegisteredOrganization", Buf, _countof(Buf)))
        SbAppend(Sb, Buf);
    SbNA(Sb);

    Sb = &g_Fields[F_PRODUCT_ID];
    if (RegGetString(HKEY_LOCAL_MACHINE, CURRENT_VERSION_KEY, L"ProductId", Buf, _countof(Buf)))
        SbAppend(Sb, Buf);
    SbNA(Sb);

    /* Original Install Date: the InstallDate registry value (seconds since 1970); when
     * setup did not record one, the creation time of the Windows directory */
    Sb = &g_Fields[F_INSTALL_DATE];
    if (RegGetDword(HKEY_LOCAL_MACHINE, CURRENT_VERSION_KEY, L"InstallDate", &Date) && Date)
    {
        FILETIME Ft;
        ULARGE_INTEGER Li;

        Li.QuadPart = ((ULONGLONG)Date + 11644473600ULL) * 10000000ULL;
        Ft.dwLowDateTime = Li.LowPart;
        Ft.dwHighDateTime = Li.HighPart;
        FormatFileTimeLocal(Sb, &Ft);
    }
    else if (GetWindowsDirectoryW(WinDir, _countof(WinDir)))
    {
        WIN32_FILE_ATTRIBUTE_DATA Fad;

        if (GetFileAttributesExW(WinDir, GetFileExInfoStandard, &Fad))
            FormatFileTimeLocal(Sb, &Fad.ftCreationTime);
    }
    SbNA(Sb);

    /* System Boot Time */
    Sb = &g_Fields[F_BOOT_TIME];
    {
        SYSTEM_TIMEOFDAY_INFORMATION Tod;

        if (NT_SUCCESS(NtQuerySystemInformation(SystemTimeOfDayInformation, &Tod, sizeof(Tod), NULL)))
        {
            FILETIME Ft;

            Ft.dwLowDateTime = Tod.BootTime.LowPart;
            Ft.dwHighDateTime = Tod.BootTime.HighPart;
            FormatFileTimeLocal(Sb, &Ft);
        }
    }
    SbNA(Sb);
}

static VOID
GetHardware(VOID)
{
    WCHAR Buf[512], Tmp[256];
    PCHAR DmiStrings[ID_STRINGS_MAX] = { 0 };
    PVOID Smbios;
    SYSTEM_INFO Si;
    SB *Sb;
    UINT i;

    Smbios = LoadSMBiosData(DmiStrings);

    Sb = &g_Fields[F_SYS_MANUFACTURER];
    if (Smbios && GetSMBiosStringW(DmiStrings[SYS_VENDOR], Buf, _countof(Buf), TRUE))
        SbAppend(Sb, Buf);
    SbNA(Sb);

    Sb = &g_Fields[F_SYS_MODEL];
    if (Smbios && GetSMBiosStringW(DmiStrings[SYS_PRODUCT], Buf, _countof(Buf), TRUE))
        SbAppend(Sb, Buf);
    SbNA(Sb);

    /* System Type: the native architecture, also for a 32-bit process on 64-bit */
    GetNativeSystemInfo(&Si);
    Sb = &g_Fields[F_SYS_TYPE];
    switch (Si.wProcessorArchitecture)
    {
        case PROCESSOR_ARCHITECTURE_INTEL: SbAppend(Sb, L"x86-based PC"); break;
        case PROCESSOR_ARCHITECTURE_AMD64: SbAppend(Sb, L"x64-based PC"); break;
        case PROCESSOR_ARCHITECTURE_IA64: SbAppend(Sb, L"Itanium-based PC"); break;
        case PROCESSOR_ARCHITECTURE_ARM: SbAppend(Sb, L"ARM-based PC"); break;
        case 12: SbAppend(Sb, L"ARM64-based PC"); break;
        default: SbAppend(Sb, L"Unknown"); break;
    }

    /* Processor(s): one line per package, taken from the first logical processor of it */
    {
        BOOL (WINAPI *pGetLpi)(PSYSTEM_LOGICAL_PROCESSOR_INFORMATION, PDWORD);
        PSYSTEM_LOGICAL_PROCESSOR_INFORMATION Lpi = NULL;
        DWORD Len = 0;
        UINT Cpus[64], nCpus = 0;

        pGetLpi = (PVOID)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "GetLogicalProcessorInformation");
        if (pGetLpi && !pGetLpi(NULL, &Len) && GetLastError() == ERROR_INSUFFICIENT_BUFFER &&
            (Lpi = malloc(Len)) && pGetLpi(Lpi, &Len))
        {
            for (i = 0; i < Len / sizeof(*Lpi) && nCpus < _countof(Cpus); i++)
            {
                if (Lpi[i].Relationship == RelationProcessorPackage && Lpi[i].ProcessorMask)
                {
                    UINT Bit = 0;
                    while (!((Lpi[i].ProcessorMask >> Bit) & 1))
                        Bit++;
                    Cpus[nCpus++] = Bit;
                }
            }
        }
        free(Lpi);
        if (!nCpus)
        {
            /* no topology information: one entry per logical processor */
            GetSystemInfo(&Si);
            for (i = 0; i < Si.dwNumberOfProcessors && nCpus < _countof(Cpus); i++)
                Cpus[nCpus++] = i;
        }

        Sb = &g_Fields[F_PROCESSORS];
        SbLineF(Sb, L"%u Processor(s) Installed.", nCpus);
        for (i = 0; i < nCpus; i++)
        {
            WCHAR Key[128], Id[256] = L"", Vendor[64] = L"";
            DWORD Mhz = 0;

            _swprintf(Key, L"HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\%u", Cpus[i]);
            RegGetString(HKEY_LOCAL_MACHINE, Key, L"Identifier", Id, _countof(Id));
            RegGetString(HKEY_LOCAL_MACHINE, Key, L"VendorIdentifier", Vendor, _countof(Vendor));
            RegGetDword(HKEY_LOCAL_MACHINE, Key, L"~MHz", &Mhz);
            SbLineF(Sb, L"[%02u]: %s %s ~%lu Mhz", i + 1, Id, Vendor, Mhz);
        }
    }

    /* BIOS Version: vendor, version, release date */
    Sb = &g_Fields[F_BIOS_VERSION];
    if (Smbios && GetSMBiosStringW(DmiStrings[BIOS_VENDOR], Buf, _countof(Buf), TRUE))
    {
        if (GetSMBiosStringW(DmiStrings[BIOS_VERSION], Tmp, _countof(Tmp), TRUE))
        {
            wcscat(Buf, L" ");
            wcsncat(Buf, Tmp, _countof(Buf) - wcslen(Buf) - 1);
        }
        if (GetSMBiosStringW(DmiStrings[BIOS_DATE], Tmp, _countof(Tmp), TRUE))
        {
            FormatBiosDate(Tmp);
            wcsncat(Buf, L", ", _countof(Buf) - wcslen(Buf) - 1);
            wcsncat(Buf, Tmp, _countof(Buf) - wcslen(Buf) - 1);
        }
        SbAppend(Sb, Buf);
    }
    else if (RegGetString(HKEY_LOCAL_MACHINE, L"HARDWARE\\DESCRIPTION\\System", L"SystemBiosVersion", Buf, _countof(Buf)))
    {
        SbAppend(Sb, Buf);
        if (RegGetString(HKEY_LOCAL_MACHINE, L"HARDWARE\\DESCRIPTION\\System", L"SystemBiosDate", Tmp, _countof(Tmp)))
            SbAppendF(Sb, L", %s", Tmp);
    }
    SbNA(Sb);

    if (Smbios)
        FreeSMBiosData(Smbios);
}

static VOID
GetLocaleField(SB *Sb, LCID Lcid)
{
    WCHAR Name[LOCALE_NAME_MAX_LENGTH], Lang[80], Country[80];
    int (WINAPI *pLCIDToLocaleName)(LCID, LPWSTR, int, DWORD);

    pLCIDToLocaleName = (PVOID)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LCIDToLocaleName");
    if (!pLCIDToLocaleName || !pLCIDToLocaleName(Lcid, Name, _countof(Name), 0))
    {
        /* old style name from the ISO language and country codes */
        WCHAR Iso[16], Ctry[16];

        if (!GetLocaleInfoW(Lcid, LOCALE_SISO639LANGNAME, Iso, _countof(Iso)) ||
            !GetLocaleInfoW(Lcid, LOCALE_SISO3166CTRYNAME, Ctry, _countof(Ctry)))
            return;
        _swprintf(Name, L"%s-%s", Iso, Ctry);
    }
    _wcslwr(Name);

    if (!GetLocaleInfoW(Lcid, LOCALE_SENGLANGUAGE, Lang, _countof(Lang)) ||
        !GetLocaleInfoW(Lcid, LOCALE_SENGCOUNTRY, Country, _countof(Country)))
        return;
    SbAppendF(Sb, L"%s;%s (%s)", Name, Lang, Country);
}

static VOID
GetSystemEnvironment(VOID)
{
    WCHAR Buf[MAX_PATH + 64];
    SB *Sb;

    Sb = &g_Fields[F_WIN_DIR];
    if (GetWindowsDirectoryW(Buf, _countof(Buf)))
    {
        SbAppend(Sb, Buf);
        g_SystemDrive[0] = Buf[0];
        g_SystemDrive[1] = L':';
    }
    SbNA(Sb);

    Sb = &g_Fields[F_SYS_DIR];
    if (GetSystemDirectoryW(Buf, _countof(Buf)))
        SbAppend(Sb, Buf);
    SbNA(Sb);

    /* Boot Device: the system partition recorded by setup, else the device of the system drive */
    Sb = &g_Fields[F_BOOT_DEVICE];
    if (RegGetString(HKEY_LOCAL_MACHINE, L"SYSTEM\\Setup", L"SystemPartition", Buf, _countof(Buf)))
        SbAppend(Sb, Buf);
    else if (g_SystemDrive[0] && QueryDosDeviceW(g_SystemDrive, Buf, _countof(Buf)))
        SbAppend(Sb, Buf);
    SbNA(Sb);

    Sb = &g_Fields[F_SYS_LOCALE];
    GetLocaleField(Sb, GetSystemDefaultLCID());
    SbNA(Sb);

    /* Input Locale: the first preloaded keyboard layout; its low word is the language */
    Sb = &g_Fields[F_INPUT_LOCALE];
    {
        LCID Lcid = GetUserDefaultLCID();

        if (RegGetString(HKEY_CURRENT_USER, L"Keyboard Layout\\Preload", L"1", Buf, _countof(Buf)) ||
            RegGetString(HKEY_USERS, L".DEFAULT\\Keyboard Layout\\Preload", L"1", Buf, _countof(Buf)))
        {
            ULONG Layout = wcstoul(Buf, NULL, 16);
            if (LOWORD(Layout))
                Lcid = MAKELCID(LOWORD(Layout), SORT_DEFAULT);
        }
        GetLocaleField(Sb, Lcid);
    }
    SbNA(Sb);

    /* Time Zone: the display name of the active zone */
    Sb = &g_Fields[F_TIME_ZONE];
    {
        WCHAR KeyName[128], Path[256];

        if (RegGetString(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\TimeZoneInformation",
                         L"TimeZoneKeyName", KeyName, _countof(KeyName)))
        {
            _swprintf(Path, CURRENT_VERSION_KEY L"\\Time Zones\\%s", KeyName);
            if (RegGetString(HKEY_LOCAL_MACHINE, Path, L"Display", Buf, _countof(Buf)))
            {
                if (Buf[0] == L'@')
                    SHLoadIndirectString(Buf, Buf, _countof(Buf), NULL);
                SbAppend(Sb, Buf);
            }
        }
    }
    SbNA(Sb);

    /* Memory */
    {
        MEMORYSTATUSEX Ms = { sizeof(Ms) };

        if (GlobalMemoryStatusEx(&Ms))
        {
            FormatMegabytes(&g_Fields[F_TOTAL_PHYS], Ms.ullTotalPhys);
            FormatMegabytes(&g_Fields[F_AVAIL_PHYS], Ms.ullAvailPhys);
            FormatMegabytes(&g_Fields[F_VM_MAX], Ms.ullTotalPageFile);
            FormatMegabytes(&g_Fields[F_VM_AVAIL], Ms.ullAvailPageFile);
            FormatMegabytes(&g_Fields[F_VM_INUSE], Ms.ullTotalPageFile - Ms.ullAvailPageFile);
        }
    }
    SbNA(&g_Fields[F_TOTAL_PHYS]);
    SbNA(&g_Fields[F_AVAIL_PHYS]);
    SbNA(&g_Fields[F_VM_MAX]);
    SbNA(&g_Fields[F_VM_AVAIL]);
    SbNA(&g_Fields[F_VM_INUSE]);

    /* Page File Location(s): the configured paging files that exist */
    Sb = &g_Fields[F_PAGEFILE];
    {
        HKEY hKey;
        PWSTR Data = NULL;
        DWORD Type, Size = 0;

        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                          L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management",
                          0, KEY_QUERY_VALUE, &hKey) == ERROR_SUCCESS)
        {
            if (RegQueryValueExW(hKey, L"PagingFiles", NULL, &Type, NULL, &Size) == ERROR_SUCCESS &&
                Type == REG_MULTI_SZ && (Data = calloc(1, Size + 2 * sizeof(WCHAR))) &&
                RegQueryValueExW(hKey, L"PagingFiles", NULL, &Type, (PBYTE)Data, &Size) == ERROR_SUCCESS)
            {
                PWSTR p;

                for (p = Data; *p; p += wcslen(p) + 1)
                {
                    WCHAR Path[MAX_PATH];
                    PWSTR Sp;
                    UINT Skip;

                    wcsncpy(Path, p, _countof(Path) - 1);
                    Path[_countof(Path) - 1] = UNICODE_NULL;
                    /* "path min max": drop the two trailing size tokens */
                    for (Skip = 0; Skip < 2 && (Sp = wcsrchr(Path, L' ')); Skip++)
                    {
                        PWSTR t;
                        for (t = Sp + 1; *t >= L'0' && *t <= L'9'; t++) ;
                        if (*t || Sp[1] == UNICODE_NULL)
                            break;
                        *Sp = UNICODE_NULL;
                    }
                    if (Path[0] == L'?' && g_SystemDrive[0])
                        Path[0] = g_SystemDrive[0];
                    if (GetFileAttributesW(Path) != INVALID_FILE_ATTRIBUTES)
                    {
                        if (Sb->Len)
                            SbAppend(Sb, L", ");
                        SbAppend(Sb, Path);
                    }
                }
            }
            free(Data);
            RegCloseKey(hKey);
        }
    }
    SbNA(Sb);

    /* Domain and Logon Server */
    Sb = &g_Fields[F_DOMAIN];
    {
        PWSTR JoinName = NULL;
        NETSETUP_JOIN_STATUS Status;
        WCHAR Dns[256];
        DWORD Size = _countof(Dns);

        if (NetGetJoinInformation(NULL, &JoinName, &Status) == NERR_Success)
        {
            if (Status == NetSetupDomainName && GetComputerNameExW(ComputerNameDnsDomain, Dns, &Size) && Dns[0])
                SbAppend(Sb, Dns);
            else if (Status == NetSetupWorkgroupName || Status == NetSetupDomainName)
                SbAppend(Sb, JoinName);
            NetApiBufferFree(JoinName);
        }
    }
    SbNA(Sb);

    Sb = &g_Fields[F_LOGON_SERVER];
    if (GetEnvironmentVariableW(L"LOGONSERVER", Buf, _countof(Buf)) && Buf[0])
        SbAppend(Sb, Buf);
    else if (g_JoinStatus != NetSetupDomainName && g_ComputerName[0])
        SbAppendF(Sb, L"\\\\%s", g_ComputerName);
    SbNA(Sb);
}

static VOID
GetHotfixes(VOID)
{
    SB List = { 0 };
    SB *Sb = &g_Fields[F_HOTFIX];
    UINT n, i;
    PWSTR p, Line;

    n = WmiQueryProperty(L"SELECT HotFixID FROM Win32_QuickFixEngineering", L"HotFixID", &List);
    if (!n)
    {
        SbAppend(Sb, L"N/A");
        free(List.Str);
        return;
    }
    SbLineF(Sb, L"%u Hotfix(s) Installed.", n);
    i = 0;
    for (Line = List.Str; Line; Line = p)
    {
        p = wcschr(Line, L'\n');
        if (p)
            *p++ = UNICODE_NULL;
        SbLineF(Sb, L"[%02u]: %s", ++i, Line);
    }
    free(List.Str);
}

static VOID
AppendAddress(SB *Sb, PSOCKADDR Sa, UINT Index)
{
    WCHAR Text[64];

    if (Sa->sa_family == AF_INET)
        RtlIpv4AddressToStringW(&((PSOCKADDR_IN)Sa)->sin_addr, Text);
    else if (Sa->sa_family == AF_INET6)
        RtlIpv6AddressToStringW(&((PSOCKADDR_IN6)Sa)->sin6_addr, Text);
    else
        return;
    SbLineF(Sb, L"      [%02u]: %s", Index, Text);
}

static VOID
GetNetwork(VOID)
{
    SB *Sb = &g_Fields[F_NIC];
    PIP_ADAPTER_ADDRESSES Buf = NULL, A;
    PIP_ADAPTER_INFO InfoBuf = NULL;
    ULONG Size = 16384, Rc, InfoSize = 0;
    UINT Count = 0, i, n;

    for (i = 0; i < 3; i++)
    {
        free(Buf);
        Buf = malloc(Size);
        if (!Buf)
            break;
        Rc = GetAdaptersAddresses(AF_UNSPEC,
                                  GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER,
                                  NULL, Buf, &Size);
        if (Rc != ERROR_BUFFER_OVERFLOW)
            break;
    }
    if (!Buf || Rc != ERROR_SUCCESS)
    {
        free(Buf);
        SbAppend(Sb, L"N/A");
        return;
    }

    for (A = Buf; A; A = A->Next)
        if (A->IfType != IF_TYPE_SOFTWARE_LOOPBACK && A->IfType != IF_TYPE_TUNNEL)
            Count++;
    if (!Count)
    {
        free(Buf);
        SbAppend(Sb, L"N/A");
        return;
    }

    /* the DHCP server addresses are only in the older adapter table */
    if (GetAdaptersInfo(NULL, &InfoSize) == ERROR_BUFFER_OVERFLOW && (InfoBuf = malloc(InfoSize)) &&
        GetAdaptersInfo(InfoBuf, &InfoSize) != ERROR_SUCCESS)
    {
        free(InfoBuf);
        InfoBuf = NULL;
    }

    SbLineF(Sb, L"%u NIC(s) Installed.", Count);
    i = 0;
    for (A = Buf; A; A = A->Next)
    {
        PIP_ADAPTER_UNICAST_ADDRESS U;
        UINT Pass;

        if (A->IfType == IF_TYPE_SOFTWARE_LOOPBACK || A->IfType == IF_TYPE_TUNNEL)
            continue;
        SbLineF(Sb, L"[%02u]: %s", ++i, A->Description);
        SbLineF(Sb, L"      Connection Name: %s", A->FriendlyName);
        if (A->OperStatus == IfOperStatusDown || A->OperStatus == IfOperStatusNotPresent)
        {
            SbLine(Sb, L"      Status:          Media disconnected");
            continue;
        }
        if (A->Flags & IP_ADAPTER_DHCP_ENABLED)
        {
            PIP_ADAPTER_INFO Info;

            SbLine(Sb, L"      DHCP Enabled:    Yes");
            for (Info = InfoBuf; Info; Info = Info->Next)
            {
                if (A->AdapterName && !_stricmp(A->AdapterName, Info->AdapterName) &&
                    Info->DhcpEnabled && Info->DhcpServer.IpAddress.String[0] &&
                    strcmp(Info->DhcpServer.IpAddress.String, "0.0.0.0"))
                {
                    SbLineF(Sb, L"      DHCP Server:     %S", Info->DhcpServer.IpAddress.String);
                    break;
                }
            }
        }
        else
        {
            SbLine(Sb, L"      DHCP Enabled:    No");
        }
        SbLine(Sb, L"      IP address(es)");
        n = 0;
        /* IPv4 addresses first, then IPv6 */
        for (Pass = 0; Pass < 2; Pass++)
        {
            for (U = A->FirstUnicastAddress; U; U = U->Next)
            {
                USHORT Family = U->Address.lpSockaddr->sa_family;

                if ((Pass == 0 && Family == AF_INET) || (Pass == 1 && Family == AF_INET6))
                    AppendAddress(Sb, U->Address.lpSockaddr, ++n);
            }
        }
    }
    free(InfoBuf);
    free(Buf);
}

static VOID
GetHyperV(VOID)
{
    SB *Sb = &g_Fields[F_HYPERV];
    int Regs[4];
    BOOL Hypervisor, Vmx, Intel;

    __cpuid(Regs, 1);
    Hypervisor = (Regs[2] >> 31) & 1;
    if (Hypervisor)
    {
        SbAppend(Sb, L"A hypervisor has been detected. Features required for Hyper-V will not be displayed.");
        return;
    }

    /* VMX (Intel) or SVM (AMD) */
    Intel = (Regs[2] >> 5) & 1;
    Vmx = Intel;
    if (!Vmx)
    {
        __cpuid(Regs, 0x80000000);
        if ((unsigned)Regs[0] >= 0x80000001)
        {
            __cpuid(Regs, 0x80000001);
            Vmx = (Regs[2] >> 2) & 1;
        }
    }
    SbLineF(Sb, L"VM Monitor Mode Extensions: %s", Vmx ? L"Yes" : L"No");
    SbLineF(Sb, L"Virtualization Enabled In Firmware: %s", IsProcessorFeaturePresent(21) ? L"Yes" : L"No");
    SbLineF(Sb, L"Second Level Address Translation: %s", IsProcessorFeaturePresent(20) ? L"Yes" : L"No");
    SbLineF(Sb, L"Data Execution Prevention Available: %s", IsProcessorFeaturePresent(12) ? L"Yes" : L"No");
}

static VOID
CollectAll(VOID)
{
    GetHostAndOs();
    GetHardware();
    GetSystemEnvironment();
    GetHotfixes();
    GetNetwork();
    GetHyperV();
}

/* Output *********************************************************************/

#define NL L"\r\n"

static VOID
PrintList(VOID)
{
    UINT i;

    ConPuts(StdOut, NL);
    for (i = 0; i < F_COUNT; i++)
    {
        WCHAR Label[64], Pad[LIST_VALUE_COLUMN + 1];
        PWSTR Copy = _wcsdup(g_Fields[i].Str ? g_Fields[i].Str : L""), Line, Next;
        BOOL First = TRUE;

        /* "Name:" and the padding up to the value column */
        _swprintf(Label, L"%s:", g_FieldInfo[i].Name);
        _swprintf(Pad, L"%-*s", LIST_VALUE_COLUMN, Label);
        for (Line = Copy; Line; Line = Next)
        {
            Next = wcschr(Line, L'\n');
            if (Next)
                *Next++ = UNICODE_NULL;
            if (First)
                ConPuts(StdOut, Pad);
            else
                ConPrintf(StdOut, L"%*s", LIST_VALUE_COLUMN, L"");
            ConPuts(StdOut, Line);
            ConPuts(StdOut, NL);
            First = FALSE;
        }
        free(Copy);
    }
}

static VOID
CsvCell(SB *Cell, PCWSTR Text, PCWSTR LineSep)
{
    PCWSTR p;

    SbAppend(Cell, L"\"");
    for (p = Text; *p; p++)
    {
        WCHAR One[2] = { *p, 0 };

        if (*p == L'\n')
            SbAppend(Cell, LineSep);
        else if (*p == L'"')
            SbAppend(Cell, L"\"\"");
        else
            SbAppend(Cell, One);
    }
    SbAppend(Cell, L"\"");
}

static VOID
PrintCsv(BOOL NoHeader)
{
    UINT i;

    if (!NoHeader)
    {
        for (i = 0; i < F_COUNT; i++)
        {
            SB Cell = { 0 };

            CsvCell(&Cell, g_FieldInfo[i].Name, L",");
            if (i)
                ConPuts(StdOut, L",");
            ConPuts(StdOut, Cell.Str);
            free(Cell.Str);
        }
        ConPuts(StdOut, NL);
    }
    for (i = 0; i < F_COUNT; i++)
    {
        SB Cell = { 0 };

        CsvCell(&Cell, g_Fields[i].Str, L",");
        if (i)
            ConPuts(StdOut, L",");
        ConPuts(StdOut, Cell.Str);
        free(Cell.Str);
    }
    ConPuts(StdOut, NL);
}

/* One table cell: the lines joined with ", ", cut to the column width and padded */
static VOID
TableCell(PCWSTR Text, UINT Width, BOOL Last)
{
    PWSTR Buf = calloc(Width + 1, sizeof(WCHAR));
    UINT n = 0;
    PCWSTR p;

    if (!Buf)
        return;
    for (p = Text; *p && n < Width; p++)
    {
        if (*p == L'\n')
        {
            if (n < Width) Buf[n++] = L',';
            if (n < Width) Buf[n++] = L' ';
        }
        else
        {
            Buf[n++] = *p;
        }
    }
    while (n < Width)
        Buf[n++] = L' ';
    Buf[Width] = UNICODE_NULL;
    ConPuts(StdOut, Buf);
    if (!Last)
        ConPuts(StdOut, L" ");
    free(Buf);
}

static VOID
PrintTable(BOOL NoHeader)
{
    UINT i, w;

    ConPuts(StdOut, NL);
    if (!NoHeader)
    {
        for (i = 0; i < F_COUNT; i++)
            TableCell(g_FieldInfo[i].Name, g_FieldInfo[i].TableWidth, i == F_COUNT - 1);
        ConPuts(StdOut, NL);
        for (i = 0; i < F_COUNT; i++)
        {
            WCHAR Bar[128];

            for (w = 0; w < g_FieldInfo[i].TableWidth; w++)
                Bar[w] = L'=';
            Bar[w] = UNICODE_NULL;
            ConPuts(StdOut, Bar);
            if (i != F_COUNT - 1)
                ConPuts(StdOut, L" ");
        }
        ConPuts(StdOut, NL);
    }
    for (i = 0; i < F_COUNT; i++)
        TableCell(g_Fields[i].Str, g_FieldInfo[i].TableWidth, i == F_COUNT - 1);
    ConPuts(StdOut, NL);
}

/* Command line ***************************************************************/

static const WCHAR g_Usage[] =
    NL
    L"SYSTEMINFO [/S system [/U username [/P [password]]]] [/FO format] [/NH]" NL
    NL
    L"Description:" NL
    L"    This tool displays operating system configuration information for" NL
    L"    a local or remote machine, including service pack levels." NL
    NL
    L"Parameter List:" NL
    L"    /S      system           Specifies the remote system to connect to." NL
    NL
    L"    /U      [domain\\]user    Specifies the user context under which" NL
    L"                             the command should execute." NL
    NL
    L"    /P      [password]       Specifies the password for the given" NL
    L"                             user context. Prompts for input if omitted." NL
    NL
    L"    /FO     format           Specifies the format in which the output" NL
    L"                             is to be displayed." NL
    L"                             Valid values: \"TABLE\", \"LIST\", \"CSV\"." NL
    NL
    L"    /NH                      Specifies that the \"Column Header\" should" NL
    L"                             not be displayed in the output." NL
    L"                             Valid only for \"TABLE\" and \"CSV\" formats." NL
    NL
    L"    /?                       Displays this help message." NL
    NL
    L"Examples:" NL
    L"    SYSTEMINFO" NL
    L"    SYSTEMINFO /?" NL
    L"    SYSTEMINFO /S system" NL
    L"    SYSTEMINFO /S system /U user" NL
    L"    SYSTEMINFO /S system /U domain\\user /P password /FO TABLE" NL
    L"    SYSTEMINFO /S system /FO LIST" NL
    L"    SYSTEMINFO /S system /FO CSV /NH" NL;

static INT
SyntaxError(PCWSTR Format, ...)
{
    va_list Args;
    WCHAR Buf[512];

    va_start(Args, Format);
    _vsnwprintf(Buf, _countof(Buf) - 1, Format, Args);
    va_end(Args);
    Buf[_countof(Buf) - 1] = UNICODE_NULL;
    ConPrintf(StdErr, L"ERROR: %s" NL L"Type \"SYSTEMINFO /?\" for usage." NL, Buf);
    return 1;
}

typedef enum { FmtList, FmtTable, FmtCsv } FORMAT;

static BOOL
IsLocalSystem(PCWSTR Name)
{
    WCHAR Dns[256];
    DWORD Size = _countof(Dns);

    if (!_wcsicmp(Name, L".") || !_wcsicmp(Name, L"localhost") || !_wcsicmp(Name, L"127.0.0.1") ||
        !_wcsicmp(Name, L"::1") || !_wcsicmp(Name, L"\\\\localhost"))
        return TRUE;
    if (g_ComputerName[0] && (!_wcsicmp(Name, g_ComputerName) ||
        (Name[0] == L'\\' && Name[1] == L'\\' && !_wcsicmp(Name + 2, g_ComputerName))))
        return TRUE;
    if (GetComputerNameExW(ComputerNameDnsFullyQualified, Dns, &Size) && !_wcsicmp(Name, Dns))
        return TRUE;
    return FALSE;
}

/* The Windows tool reports a failed remote connection as an RPC error; the message text
 * ends in a CR LF of its own and the tool adds a line end after it. */
static INT
RemoteUnavailable(DWORD Error, BOOL Reached)
{
    WCHAR Msg[256] = L"";
    SIZE_T n;

    if (Reached)
    {
        ConPrintf(StdErr, L"ERROR: Remote system information is not supported by this system." NL);
        return 1;
    }
    FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, Error,
                   MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), Msg, _countof(Msg), NULL);
    n = wcslen(Msg);
    while (n && (Msg[n - 1] == L'\r' || Msg[n - 1] == L'\n'))
        Msg[--n] = UNICODE_NULL;
    ConPrintf(StdErr, L"ERROR: %s\r" NL, Msg);
    return 1;
}

/* Remote systems cannot be queried: resolve the name and probe the RPC endpoint mapper port
 * so that an unreachable host gets the same error as on Windows. */
static INT
QueryRemote(PCWSTR System)
{
    WSADATA Wsa;
    ADDRINFOW Hints = { 0 }, *Res = NULL;
    BOOL Reached = FALSE;
    PCWSTR Host = System;

    while (*Host == L'\\')
        Host++;
    WSAStartup(MAKEWORD(2, 2), &Wsa);
    Hints.ai_socktype = SOCK_STREAM;
    if (GetAddrInfoW(Host, L"135", &Hints, &Res) == 0 && Res)
    {
        SOCKET s = socket(Res->ai_family, Res->ai_socktype, Res->ai_protocol);

        if (s != INVALID_SOCKET)
        {
            u_long NonBlock = 1;
            fd_set Wr, Ex;
            struct timeval Tv = { 5, 0 };

            ioctlsocket(s, FIONBIO, &NonBlock);
            connect(s, Res->ai_addr, (int)Res->ai_addrlen);
            FD_ZERO(&Wr);
            FD_ZERO(&Ex);
            FD_SET(s, &Wr);
            FD_SET(s, &Ex);
            if (select(0, NULL, &Wr, &Ex, &Tv) > 0 && FD_ISSET(s, &Wr))
                Reached = TRUE;
            closesocket(s);
        }
        FreeAddrInfoW(Res);
    }
    WSACleanup();
    return RemoteUnavailable(RPC_S_SERVER_UNAVAILABLE, Reached);
}

int wmain(int argc, wchar_t *argv[])
{
    FORMAT Format = FmtList;
    BOOL NoHeader = FALSE, HaveFo = FALSE, HaveNh = FALSE, HaveS = FALSE, HaveU = FALSE, HaveP = FALSE;
    PCWSTR System = NULL;
    int i;

    ConInitStdStreams();

    for (i = 1; i < argc; i++)
    {
        PCWSTR a = argv[i];

        if (a[0] != L'/' && a[0] != L'-')
            return SyntaxError(L"Invalid argument/option - '%s'.", a);
        if (!wcscmp(a + 1, L"?"))
        {
            ConPuts(StdOut, g_Usage);
            return 0;
        }
        if (!_wcsicmp(a + 1, L"FO"))
        {
            if (HaveFo)
                return SyntaxError(L"Invalid syntax. '/FO' option is not allowed more than '1' time(s).");
            if (i + 1 >= argc)
                return SyntaxError(L"Invalid syntax. Value expected for '/FO'.");
            HaveFo = TRUE;
            a = argv[++i];
            if (!_wcsicmp(a, L"TABLE"))
                Format = FmtTable;
            else if (!_wcsicmp(a, L"LIST"))
                Format = FmtList;
            else if (!_wcsicmp(a, L"CSV"))
                Format = FmtCsv;
            else
                return SyntaxError(L"Invalid syntax. '%s' value is not allowed for '/FO' option.", a);
        }
        else if (!_wcsicmp(a + 1, L"NH"))
        {
            if (HaveNh)
                return SyntaxError(L"Invalid syntax. '/NH' option is not allowed more than '1' time(s).");
            HaveNh = NoHeader = TRUE;
        }
        else if (!_wcsicmp(a + 1, L"S"))
        {
            if (HaveS)
                return SyntaxError(L"Invalid syntax. '/S' option is not allowed more than '1' time(s).");
            if (i + 1 >= argc)
                return SyntaxError(L"Invalid syntax. Value expected for '/S'.");
            HaveS = TRUE;
            System = argv[++i];
        }
        else if (!_wcsicmp(a + 1, L"U"))
        {
            if (HaveU)
                return SyntaxError(L"Invalid syntax. '/U' option is not allowed more than '1' time(s).");
            if (i + 1 >= argc)
                return SyntaxError(L"Invalid syntax. Value expected for '/U'.");
            HaveU = TRUE;
            i++;
        }
        else if (!_wcsicmp(a + 1, L"P"))
        {
            if (HaveP)
                return SyntaxError(L"Invalid syntax. '/P' option is not allowed more than '1' time(s).");
            HaveP = TRUE;
            /* the password is optional; it is only used for a remote system */
            if (i + 1 < argc && argv[i + 1][0] != L'/' && argv[i + 1][0] != L'-')
                i++;
        }
        else
        {
            return SyntaxError(L"Invalid argument/option - '%s'.", a);
        }
    }

    if (HaveU && !HaveS)
        return SyntaxError(L"Invalid syntax. /U can be specified only when /S is specified.");
    if (HaveP && !HaveU)
        return SyntaxError(L"Invalid syntax. /P can be specified only when /U is specified.");
    if (HaveNh && Format == FmtList)
        return SyntaxError(L"Invalid syntax. /NH option is allowed only for \"TABLE\" and \"CSV\" formats.");

    if (HaveS)
    {
        DWORD Size = _countof(g_ComputerName);

        GetComputerNameW(g_ComputerName, &Size);
        if (!IsLocalSystem(System))
            return QueryRemote(System);
    }

    CollectAll();

    switch (Format)
    {
        case FmtTable: PrintTable(NoHeader); break;
        case FmtCsv: PrintCsv(NoHeader); break;
        default: PrintList(); break;
    }
    return 0;
}
