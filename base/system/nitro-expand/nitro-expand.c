/*
 * PROJECT:     NitroOS
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Grows the system partition and its volume to fill the disk after the
 *              disk was enlarged (VM and cloud images that are resized after install).
 *
 *   nitro-expand [/n] [X:]   Plan (and with no /n carry out) the growth of volume X:
 *                            (default: the system drive). /n prints the plan only.
 *   nitro-expand /service    The first-boot service: does the work once when the
 *                            marker HKLM\SOFTWARE\Nitro\Setup\ExpandStorage is 1,
 *                            deletes the marker, logs to %SystemRoot%\nitro-expand.log
 *                            and the Application event log.
 *
 * The partition and file system are grown by diskpart's EXTEND (it knows NTFS,
 * FAT and the FAT size limits); this tool decides whether to, on which volume,
 * prepares a GPT disk (the backup header sits at the old end of the disk and
 * has to move to the new one first) and checks the result. Only a partition
 * that is the last on its disk, with free space behind it, is grown.
 *
 * Windows has no such step; diskpart EXTEND and Disk Management are its manual
 * path, so this is off for normal installs (no marker, no change).
 * COPYRIGHT:   Copyright 2026 Tomas Srnka (tomas.srnka@e2b.dev)
 */

#include <stdarg.h>
#include <stdio.h>
#include <wchar.h>
#define WIN32_NO_STATUS
#include <windef.h>
#include <winbase.h>
#include <winnls.h>
#include <winreg.h>
#include <winsvc.h>
#include <winioctl.h>
#include <ntddstor.h>

#define SWP(buf, ...) _snwprintf(buf, ARRAYSIZE(buf) - 1, __VA_ARGS__)
#define MARKER_KEY      L"SOFTWARE\\Nitro\\Setup"
#define MARKER_VALUE    L"ExpandStorage"
#define ONE_MIB         (1024ULL * 1024ULL)
/* Below this, free space behind the partition is alignment slack, not an enlarged disk */
#define MIN_GROW_BYTES  (8ULL * ONE_MIB)
#define GPT_ENTRY_BYTES 128ULL

static BOOL g_Preview;
static BOOL g_ToLog;                /* service mode: no console */
static SERVICE_STATUS_HANDLE g_hStatus;
static SERVICE_STATUS g_Status;

typedef struct _PLAN
{
    WCHAR Drive[3];
    ULONG DiskNumber, PartitionNumber, SectorSize;
    WCHAR FileSystem[32];
    BOOL Gpt;
    ULONGLONG DiskBytes, PartStart, PartLength, LimitEnd, GrowBytes;
    ULONGLONG VolumeBytes;
} PLAN;

/* LOGGING ********************************************************************/

static
VOID
Say(const WCHAR *Format, ...)
{
    WCHAR Line[1024];
    CHAR Oem[2048];
    SYSTEMTIME St;
    va_list Args;
    HANDLE hOut, hLog;
    DWORD Written;
    int Len;
    WCHAR Path[MAX_PATH];

    va_start(Args, Format);
    _vsnwprintf(Line, ARRAYSIZE(Line) - 2, Format, Args);
    va_end(Args);
    Line[ARRAYSIZE(Line) - 3] = UNICODE_NULL;
    wcscat(Line, L"\r\n");

    if (!g_ToLog)
    {
        hOut = GetStdHandle(STD_OUTPUT_HANDLE);
        Len = WideCharToMultiByte(CP_OEMCP, 0, Line, -1, Oem, sizeof(Oem), NULL, NULL);
        if (Len > 1 && hOut != INVALID_HANDLE_VALUE)
            WriteFile(hOut, Oem, Len - 1, &Written, NULL);
    }

    if (!g_Preview)
    {
        /* The record of what was done: %SystemRoot%\nitro-expand.log, UTC */
        if (GetWindowsDirectoryW(Path, ARRAYSIZE(Path) - 24))
        {
            wcscat(Path, L"\\nitro-expand.log");
            hLog = CreateFileW(Path, FILE_APPEND_DATA, FILE_SHARE_READ, NULL,
                               OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
            if (hLog != INVALID_HANDLE_VALUE)
            {
                GetSystemTime(&St);
                Len = _snprintf(Oem, sizeof(Oem) - 1, "%04u-%02u-%02uT%02u:%02u:%02uZ ",
                                St.wYear, St.wMonth, St.wDay, St.wHour, St.wMinute, St.wSecond);
                WriteFile(hLog, Oem, Len, &Written, NULL);
                Len = WideCharToMultiByte(CP_OEMCP, 0, Line, -1, Oem, sizeof(Oem), NULL, NULL);
                if (Len > 1)
                    WriteFile(hLog, Oem, Len - 1, &Written, NULL);
                CloseHandle(hLog);
            }
        }
    }
}

static
VOID
ReportEvent_(WORD Type, const WCHAR *Text)
{
    HANDLE hSource = RegisterEventSourceW(NULL, L"NitroExpand");
    if (hSource)
    {
        ReportEventW(hSource, Type, 0, 0, NULL, 1, 0, &Text, NULL);
        DeregisterEventSource(hSource);
    }
}

/* DISK ***********************************************************************/

static
HANDLE
OpenDevice(const WCHAR *Path, DWORD Access)
{
    return CreateFileW(Path, Access, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                       OPEN_EXISTING, 0, NULL);
}

/* The drive layout of a disk in a heap buffer (the caller frees it). */
static
PDRIVE_LAYOUT_INFORMATION_EX
GetLayout(HANDLE hDisk)
{
    DWORD Size = 4096, Returned;
    PDRIVE_LAYOUT_INFORMATION_EX Layout;

    for (;;)
    {
        Layout = HeapAlloc(GetProcessHeap(), 0, Size);
        if (!Layout)
            return NULL;
        if (DeviceIoControl(hDisk, IOCTL_DISK_GET_DRIVE_LAYOUT_EX, NULL, 0, Layout, Size, &Returned, NULL))
            return Layout;
        HeapFree(GetProcessHeap(), 0, Layout);
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER && GetLastError() != ERROR_MORE_DATA)
            return NULL;
        Size *= 2;
        if (Size > 1024 * 1024)
            return NULL;
    }
}

static
BOOL
IsMbrContainer(const PARTITION_INFORMATION_EX *Part)
{
    return Part->PartitionStyle == PARTITION_STYLE_MBR &&
           (Part->Mbr.PartitionType == PARTITION_EXTENDED ||
            Part->Mbr.PartitionType == PARTITION_XINT13_EXTENDED ||
            Part->Mbr.PartitionType == 0x85);
}

/*
 * Works out what to do for the volume: fills Plan, returns 0 when there is a
 * growth to do, 1 when there is nothing to do (Why says why), -1 on an error
 * or a layout that is not touched.
 */
static
int
MakePlan(PLAN *Plan, const WCHAR *Why, const WCHAR **pWhy)
{
    WCHAR Path[64], Root[8];
    HANDLE hVolume, hDisk;
    STORAGE_DEVICE_NUMBER Number;
    DISK_GEOMETRY_EX *Geometry;
    BYTE GeomBuffer[512];
    PDRIVE_LAYOUT_INFORMATION_EX Layout;
    DWORD Returned, i;
    const PARTITION_INFORMATION_EX *Part = NULL;
    ULONGLONG PartEnd, LastUsable;
    ULARGE_INTEGER FreeToCaller, Total, TotalFree;

    UNREFERENCED_PARAMETER(Why);

    SWP(Path, L"\\\\.\\%s", Plan->Drive);
    hVolume = OpenDevice(Path, 0);
    if (hVolume == INVALID_HANDLE_VALUE)
    {
        *pWhy = L"cannot open the volume";
        return -1;
    }
    if (!DeviceIoControl(hVolume, IOCTL_STORAGE_GET_DEVICE_NUMBER, NULL, 0, &Number, sizeof(Number), &Returned, NULL))
    {
        CloseHandle(hVolume);
        *pWhy = L"the volume is not on a disk (no device number)";
        return -1;
    }
    CloseHandle(hVolume);
    Plan->DiskNumber = Number.DeviceNumber;
    Plan->PartitionNumber = Number.PartitionNumber;

    SWP(Root, L"%s\\", Plan->Drive);
    Plan->FileSystem[0] = UNICODE_NULL;
    if (!GetVolumeInformationW(Root, NULL, 0, NULL, NULL, NULL, Plan->FileSystem, ARRAYSIZE(Plan->FileSystem)))
    {
        *pWhy = L"cannot read the file system type";
        return -1;
    }
    if (_wcsicmp(Plan->FileSystem, L"NTFS") && _wcsicmp(Plan->FileSystem, L"FAT") &&
        _wcsicmp(Plan->FileSystem, L"FAT32"))
    {
        *pWhy = L"the file system cannot be extended";
        return 1;
    }
    Plan->VolumeBytes = GetDiskFreeSpaceExW(Root, &FreeToCaller, &Total, &TotalFree) ? Total.QuadPart : 0;

    SWP(Path, L"\\\\.\\PhysicalDrive%lu", Plan->DiskNumber);
    hDisk = OpenDevice(Path, GENERIC_READ | GENERIC_WRITE);
    if (hDisk == INVALID_HANDLE_VALUE)
    {
        *pWhy = L"cannot open the disk";
        return -1;
    }

    /* A disk that was resized: the size the stack knows must be current */
    DeviceIoControl(hDisk, IOCTL_DISK_UPDATE_PROPERTIES, NULL, 0, NULL, 0, &Returned, NULL);

    Geometry = (DISK_GEOMETRY_EX *)GeomBuffer;
    if (!DeviceIoControl(hDisk, IOCTL_DISK_GET_DRIVE_GEOMETRY_EX, NULL, 0, GeomBuffer, sizeof(GeomBuffer), &Returned, NULL))
    {
        CloseHandle(hDisk);
        *pWhy = L"cannot read the disk size";
        return -1;
    }
    Plan->DiskBytes = Geometry->DiskSize.QuadPart;
    Plan->SectorSize = Geometry->Geometry.BytesPerSector ? Geometry->Geometry.BytesPerSector : 512;

    Layout = GetLayout(hDisk);
    CloseHandle(hDisk);
    if (!Layout)
    {
        *pWhy = L"cannot read the partition layout";
        return -1;
    }

    for (i = 0; i < Layout->PartitionCount; i++)
    {
        if (!IsMbrContainer(&Layout->PartitionEntry[i]) &&
            Layout->PartitionEntry[i].PartitionNumber == Plan->PartitionNumber &&
            Layout->PartitionEntry[i].PartitionLength.QuadPart != 0)
        {
            Part = &Layout->PartitionEntry[i];
            break;
        }
    }
    if (!Part)
    {
        HeapFree(GetProcessHeap(), 0, Layout);
        *pWhy = L"the partition is not in the disk layout";
        return -1;
    }
    Plan->PartStart = Part->StartingOffset.QuadPart;
    Plan->PartLength = Part->PartitionLength.QuadPart;
    PartEnd = Plan->PartStart + Plan->PartLength;
    Plan->Gpt = (Layout->PartitionStyle == PARTITION_STYLE_GPT);

    /* The last partition on the disk: nothing but free space behind it */
    for (i = 0; i < Layout->PartitionCount; i++)
    {
        const PARTITION_INFORMATION_EX *Other = &Layout->PartitionEntry[i];

        if (Other == Part || Other->PartitionLength.QuadPart == 0 || IsMbrContainer(Other))
            continue;
        if (Other->StartingOffset.QuadPart + Other->PartitionLength.QuadPart > PartEnd)
        {
            HeapFree(GetProcessHeap(), 0, Layout);
            *pWhy = L"another partition lies behind it";
            return 1;
        }
    }

    if (Plan->Gpt)
    {
        /* Backup entry array and header sit at the very end of the disk */
        ULONGLONG Entries = Layout->Gpt.MaxPartitionCount ? Layout->Gpt.MaxPartitionCount : 128;
        ULONGLONG ArraySectors = (Entries * GPT_ENTRY_BYTES + Plan->SectorSize - 1) / Plan->SectorSize;
        ULONGLONG TotalSectors = Plan->DiskBytes / Plan->SectorSize;

        LastUsable = (TotalSectors - 1 - ArraySectors - 1) * Plan->SectorSize + Plan->SectorSize;
    }
    else
    {
        /* MBR: partitions hold a 32-bit sector count */
        LastUsable = min(Plan->DiskBytes, (ULONGLONG)Plan->SectorSize << 32);
    }
    HeapFree(GetProcessHeap(), 0, Layout);

    Plan->LimitEnd = LastUsable;
    if (LastUsable <= PartEnd)
    {
        Plan->GrowBytes = 0;
        *pWhy = L"no free space behind the partition";
        return 1;
    }
    Plan->GrowBytes = ((LastUsable - PartEnd) / ONE_MIB) * ONE_MIB;
    if (Plan->GrowBytes < MIN_GROW_BYTES)
    {
        Plan->GrowBytes = 0;
        *pWhy = L"less than 8 MiB free behind the partition (the disk was not enlarged)";
        return 1;
    }
    return 0;
}

static
VOID
PrintPlan(const PLAN *Plan)
{
    Say(L"volume %s: disk %lu partition %lu, %s, %s", Plan->Drive, Plan->DiskNumber,
        Plan->PartitionNumber, Plan->FileSystem, Plan->Gpt ? L"GPT" : L"MBR");
    Say(L"  disk %I64u bytes, sector %lu, partition at %I64u + %I64u bytes", Plan->DiskBytes,
        Plan->SectorSize, Plan->PartStart, Plan->PartLength);
    Say(L"  grow by %I64u bytes (%I64u MiB) to %I64u bytes", Plan->GrowBytes, Plan->GrowBytes / ONE_MIB,
        Plan->PartLength + Plan->GrowBytes);
    if (!_wcsnicmp(Plan->FileSystem, L"FAT", 3))
    {
        Say(L"  note: a FAT volume grows in place only while its FAT tables can describe the new space;");
        Say(L"        otherwise diskpart refuses on the system volume and nothing is changed");
    }
}

/*
 * GPT: the backup header is still at the old end of a disk that was
 * enlarged, and the usable area stops there. Writing the layout back as it
 * is makes the stack write both headers for the current disk size.
 */
static
BOOL
RefreshGptHeaders(const PLAN *Plan)
{
    WCHAR Path[64];
    HANDLE hDisk;
    PDRIVE_LAYOUT_INFORMATION_EX Layout;
    DWORD Returned, Size;
    BOOL Ok;

    SWP(Path, L"\\\\.\\PhysicalDrive%lu", Plan->DiskNumber);
    hDisk = OpenDevice(Path, GENERIC_READ | GENERIC_WRITE);
    if (hDisk == INVALID_HANDLE_VALUE)
        return FALSE;
    Layout = GetLayout(hDisk);
    if (!Layout)
    {
        CloseHandle(hDisk);
        return FALSE;
    }
    Size = FIELD_OFFSET(DRIVE_LAYOUT_INFORMATION_EX, PartitionEntry) +
           Layout->PartitionCount * sizeof(PARTITION_INFORMATION_EX);
    Ok = DeviceIoControl(hDisk, IOCTL_DISK_SET_DRIVE_LAYOUT_EX, Layout, Size, NULL, 0, &Returned, NULL);
    if (!Ok)
        Say(L"  rewriting the GPT headers failed (error %lu)", GetLastError());
    else
        DeviceIoControl(hDisk, IOCTL_DISK_UPDATE_PROPERTIES, NULL, 0, NULL, 0, &Returned, NULL);
    HeapFree(GetProcessHeap(), 0, Layout);
    CloseHandle(hDisk);
    return Ok;
}

/* Runs diskpart on a one-use script; its output goes into the log. */
static
DWORD
RunDiskpart(const PLAN *Plan)
{
    WCHAR Dir[MAX_PATH], Script[MAX_PATH], Output[MAX_PATH], Cmd[2 * MAX_PATH];
    HANDLE hScript, hOut;
    SECURITY_ATTRIBUTES Sa = { sizeof(Sa), NULL, TRUE };
    STARTUPINFOW Si;
    PROCESS_INFORMATION Pi;
    CHAR Text[128], Buf[1024];
    DWORD Written, Read, ExitCode = (DWORD)-1;

    GetWindowsDirectoryW(Dir, ARRAYSIZE(Dir) - 40);
    SWP(Script, L"%s\\nitro-expand.dp", Dir);
    SWP(Output, L"%s\\nitro-expand.dpout", Dir);

    hScript = CreateFileW(Script, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hScript == INVALID_HANDLE_VALUE)
        return ExitCode;
    _snprintf(Text, sizeof(Text), "select volume %c\r\nextend\r\nexit\r\n", (CHAR)Plan->Drive[0]);
    WriteFile(hScript, Text, (DWORD)strlen(Text), &Written, NULL);
    CloseHandle(hScript);

    hOut = CreateFileW(Output, GENERIC_WRITE, FILE_SHARE_READ, &Sa, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hOut == INVALID_HANDLE_VALUE)
    {
        DeleteFileW(Script);
        return ExitCode;
    }

    ZeroMemory(&Si, sizeof(Si));
    Si.cb = sizeof(Si);
    Si.dwFlags = STARTF_USESTDHANDLES;
    Si.hStdOutput = hOut;
    Si.hStdError = hOut;
    Si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    SWP(Cmd, L"\"%s\\system32\\diskpart.exe\" /s \"%s\"", Dir, Script);
    if (CreateProcessW(NULL, Cmd, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &Si, &Pi))
    {
        WaitForSingleObject(Pi.hProcess, 10 * 60 * 1000);
        GetExitCodeProcess(Pi.hProcess, &ExitCode);
        CloseHandle(Pi.hThread);
        CloseHandle(Pi.hProcess);
    }
    else
    {
        Say(L"  cannot start diskpart (error %lu)", GetLastError());
    }
    CloseHandle(hOut);

    /* Its words, line by line, into the log */
    hOut = CreateFileW(Output, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hOut != INVALID_HANDLE_VALUE)
    {
        if (ReadFile(hOut, Buf, sizeof(Buf) - 1, &Read, NULL) && Read)
        {
            WCHAR Wide[1024];
            DWORD n, o = 0;

            Buf[Read] = 0;
            /* NULs of UTF-16 output out */
            for (n = 0; n < Read; n++)
                if (Buf[n]) Buf[o++] = Buf[n];
            Buf[o] = 0;
            MultiByteToWideChar(CP_OEMCP, 0, Buf, -1, Wide, ARRAYSIZE(Wide));
            Say(L"  diskpart said: %s", Wide);
        }
        CloseHandle(hOut);
    }
    DeleteFileW(Script);
    DeleteFileW(Output);
    return ExitCode;
}

/*
 * Plan, and unless preview carry out. Returns the process exit code:
 * 0 done or nothing to do, 1 failed.
 */
static
int
DoExpand(const WCHAR *Drive)
{
    PLAN Plan, After;
    const WCHAR *Why = L"";
    int Verdict;
    WCHAR Line[256];

    ZeroMemory(&Plan, sizeof(Plan));
    if (Drive)
    {
        Plan.Drive[0] = Drive[0];
    }
    else
    {
        WCHAR Dir[MAX_PATH];
        GetWindowsDirectoryW(Dir, ARRAYSIZE(Dir));
        Plan.Drive[0] = Dir[0];
    }
    Plan.Drive[1] = L':';

    Verdict = MakePlan(&Plan, L"", &Why);
    if (Verdict < 0)
    {
        Say(L"nitro-expand: %s: %s (error %lu)", Plan.Drive, Why, GetLastError());
        return 1;
    }
    if (Verdict > 0)
    {
        Say(L"nitro-expand: %s: nothing to do, %s", Plan.Drive, Why);
        return 0;
    }

    PrintPlan(&Plan);
    if (g_Preview)
    {
        Say(L"preview only, nothing was changed");
        return 0;
    }

    if (Plan.Gpt && !RefreshGptHeaders(&Plan))
    {
        Say(L"nitro-expand: %s: cannot update the GPT headers for the new disk size, not growing", Plan.Drive);
        return 1;
    }

    Say(L"growing %s ...", Plan.Drive);
    RunDiskpart(&Plan);

    /* Believe the disk, not the exit code */
    ZeroMemory(&After, sizeof(After));
    After.Drive[0] = Plan.Drive[0];
    After.Drive[1] = L':';
    MakePlan(&After, L"", &Why);
    if (After.PartLength > Plan.PartLength)
    {
        Say(L"partition grew from %I64u to %I64u bytes; volume %I64u -> %I64u bytes",
            Plan.PartLength, After.PartLength, Plan.VolumeBytes, After.VolumeBytes);
        if (After.VolumeBytes <= Plan.VolumeBytes)
        {
            Say(L"warning: the file system did not grow (diskpart EXTEND FILESYSTEM finishes it)");
            SWP(Line, L"%s: partition grown to %I64u bytes, the file system was not extended",
                     Plan.Drive, After.PartLength);
            ReportEvent_(EVENTLOG_WARNING_TYPE, Line);
            return 1;
        }
        SWP(Line, L"%s grown from %I64u to %I64u bytes (partition %lu of disk %lu, %s, %s)", Plan.Drive,
                 Plan.VolumeBytes, After.VolumeBytes, Plan.PartitionNumber, Plan.DiskNumber,
                 Plan.Gpt ? L"GPT" : L"MBR", Plan.FileSystem);
        ReportEvent_(EVENTLOG_INFORMATION_TYPE, Line);
        return 0;
    }

    Say(L"nitro-expand: %s: the partition did not grow", Plan.Drive);
    SWP(Line, L"%s could not be grown (see %%SystemRoot%%\\nitro-expand.log)", Plan.Drive);
    ReportEvent_(EVENTLOG_ERROR_TYPE, Line);
    return 1;
}

/* FIRST BOOT *****************************************************************/

static
BOOL
MarkerPresent(VOID)
{
    HKEY hKey;
    DWORD Value = 0, Size = sizeof(Value), Type;
    BOOL Present = FALSE;

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, MARKER_KEY, 0, KEY_READ, &hKey) == ERROR_SUCCESS)
    {
        if (RegQueryValueExW(hKey, MARKER_VALUE, NULL, &Type, (LPBYTE)&Value, &Size) == ERROR_SUCCESS &&
            Type == REG_DWORD && Value == 1)
            Present = TRUE;
        RegCloseKey(hKey);
    }
    return Present;
}

static
VOID
DeleteMarker(VOID)
{
    HKEY hKey;

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, MARKER_KEY, 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS)
    {
        RegDeleteValueW(hKey, MARKER_VALUE);
        RegCloseKey(hKey);
    }
}

static
VOID
WINAPI
ServiceHandler(DWORD Control)
{
    UNREFERENCED_PARAMETER(Control);
    SetServiceStatus(g_hStatus, &g_Status);
}

static
VOID
WINAPI
ServiceMain(DWORD argc, LPWSTR *argv)
{
    UNREFERENCED_PARAMETER(argc);
    UNREFERENCED_PARAMETER(argv);

    g_Status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_Status.dwCurrentState = SERVICE_START_PENDING;
    g_Status.dwWaitHint = 10 * 60 * 1000;
    g_hStatus = RegisterServiceCtrlHandlerW(L"NitroExpand", ServiceHandler);
    if (!g_hStatus)
        return;
    SetServiceStatus(g_hStatus, &g_Status);

    /* Running while it works, so that a start request does not report a service that quit */
    g_Status.dwCurrentState = SERVICE_RUNNING;
    g_Status.dwWaitHint = 0;
    SetServiceStatus(g_hStatus, &g_Status);

    if (MarkerPresent())
    {
        /* Once: the marker goes first, so that a crash cannot repeat a half-done growth */
        DeleteMarker();
        Say(L"first boot: ExpandStorage marker found, expanding the system volume");
        DoExpand(NULL);
    }

    g_Status.dwCurrentState = SERVICE_STOPPED;
    g_Status.dwWaitHint = 0;
    SetServiceStatus(g_hStatus, &g_Status);
}

int
wmain(int argc, WCHAR **argv)
{
    const WCHAR *Drive = NULL;
    int i;
    SERVICE_TABLE_ENTRYW Table[] = { { L"NitroExpand", ServiceMain }, { NULL, NULL } };

    for (i = 1; i < argc; i++)
    {
        if (!_wcsicmp(argv[i], L"/service"))
        {
            g_ToLog = TRUE;
            return StartServiceCtrlDispatcherW(Table) ? 0 : 1;
        }
        else if (!_wcsicmp(argv[i], L"/n") || !_wcsicmp(argv[i], L"-n"))
        {
            g_Preview = TRUE;
        }
        else if (wcslen(argv[i]) == 2 && argv[i][1] == L':')
        {
            Drive = argv[i];
        }
        else
        {
            Say(L"usage: nitro-expand [/n] [X:]");
            Say(L"  Grows the system partition (or the volume X:) and its file system into free");
            Say(L"  space behind it, e.g. after a VM disk was enlarged. /n shows the plan only.");
            return 2;
        }
    }
    return DoExpand(Drive);
}
