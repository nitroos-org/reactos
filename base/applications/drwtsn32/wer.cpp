/*
 * PROJECT:     Dr. Watson crash reporter
 * LICENSE:     GPL-2.0+ (https://spdx.org/licenses/GPL-2.0+)
 * PURPOSE:     Report an unhandled exception without a debugger (event log, LocalDumps)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"
#include <shlobj.h>
#include <shlwapi.h>
#include <strsafe.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <dbghelp.h>
#include <algorithm>

/*
 * kernel32's UnhandledExceptionFilter starts "drwtsn32 -u -p PID -t TID -x PTR"
 * (see WerReportMain for the other options) and waits for it. PTR is the
 * address of the EXCEPTION_POINTERS in the crashed process. The settings
 * follow the documented LocalDumps key.
 */

#define LOCALDUMPS_KEY L"SOFTWARE\\Microsoft\\Windows\\Windows Error Reporting\\LocalDumps"

#define DEFAULT_DUMP_COUNT 10
#define MINI_DUMP_FLAGS (MiniDumpWithDataSegs | MiniDumpWithUnloadedModules | MiniDumpWithProcessThreadData)
#define FULL_DUMP_FLAGS (MiniDumpWithFullMemory | MiniDumpWithHandleData | MiniDumpWithUnloadedModules | \
                         MiniDumpWithFullMemoryInfo | MiniDumpWithThreadInfo)

struct LocalDumpSettings
{
    bool HaveFolder;
    std::wstring Folder;
    DWORD Count;
    DWORD Type;
    DWORD CustomFlags;

    LocalDumpSettings()
        : HaveFolder(false), Count(DEFAULT_DUMP_COUNT), Type(1), CustomFlags(MINI_DUMP_FLAGS)
    {
    }
};

static void ReadDword(HKEY hKey, LPCWSTR Name, DWORD& Value)
{
    DWORD Type, Data, Size = sizeof(Data);
    if (RegQueryValueExW(hKey, Name, NULL, &Type, (LPBYTE)&Data, &Size) == ERROR_SUCCESS &&
        Type == REG_DWORD && Size == sizeof(Data))
    {
        Value = Data;
    }
}

static void ReadSettingsFromKey(HKEY hKey, LocalDumpSettings& Settings)
{
    WCHAR Buffer[MAX_PATH];
    DWORD Type, Size = sizeof(Buffer) - sizeof(WCHAR);

    if (RegQueryValueExW(hKey, L"DumpFolder", NULL, &Type, (LPBYTE)Buffer, &Size) == ERROR_SUCCESS &&
        (Type == REG_EXPAND_SZ || Type == REG_SZ))
    {
        Buffer[Size / sizeof(WCHAR)] = UNICODE_NULL;
        if (Buffer[0])
        {
            Settings.HaveFolder = true;
            Settings.Folder = Buffer;
        }
    }
    ReadDword(hKey, L"DumpCount", Settings.Count);
    ReadDword(hKey, L"DumpType", Settings.Type);
    ReadDword(hKey, L"CustomDumpFlags", Settings.CustomFlags);
}

/* The global values apply first; a subkey named after the program overrides them */
static bool ReadLocalDumpSettings(const std::wstring& ProcessName, LocalDumpSettings& Settings)
{
    HKEY hKey, hAppKey;

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, LOCALDUMPS_KEY, 0, KEY_READ | WER_REG_VIEW, &hKey) != ERROR_SUCCESS)
        return false;

    ReadSettingsFromKey(hKey, Settings);
    if (!ProcessName.empty() &&
        RegOpenKeyExW(hKey, ProcessName.c_str(), 0, KEY_READ | WER_REG_VIEW, &hAppKey) == ERROR_SUCCESS)
    {
        ReadSettingsFromKey(hAppKey, Settings);
        RegCloseKey(hAppKey);
    }
    RegCloseKey(hKey);
    return true;
}

/* The folder is expanded in the environment of the crashed program, which this process inherited */
static std::wstring GetDumpFolder(const LocalDumpSettings& Settings)
{
    WCHAR LocalAppData[MAX_PATH], Buffer[MAX_PATH];

    if (FAILED(SHGetFolderPathW(NULL, CSIDL_LOCAL_APPDATA | CSIDL_FLAG_CREATE, NULL, SHGFP_TYPE_CURRENT, LocalAppData)))
        LocalAppData[0] = UNICODE_NULL;

    if (!Settings.HaveFolder)
    {
        if (!LocalAppData[0])
            return std::wstring();
        return std::wstring(LocalAppData) + L"\\CrashDumps";
    }

    /* The documented default uses %LOCALAPPDATA%, which this system does not always define */
    if (LocalAppData[0] && !GetEnvironmentVariableW(L"LOCALAPPDATA", Buffer, _countof(Buffer)))
        SetEnvironmentVariableW(L"LOCALAPPDATA", LocalAppData);

    DWORD Length = ExpandEnvironmentStringsW(Settings.Folder.c_str(), Buffer, _countof(Buffer));
    if (!Length || Length > _countof(Buffer))
        return std::wstring();
    return std::wstring(Buffer);
}

struct DumpFile
{
    std::wstring Name;
    FILETIME LastWrite;
};

static bool OlderFirst(const DumpFile& Left, const DumpFile& Right)
{
    return CompareFileTime(&Left.LastWrite, &Right.LastWrite) < 0;
}

/* A dump this reporter wrote: <program>.<pid>.dmp */
static bool IsReporterDumpName(const std::wstring& Name)
{
    std::wstring::size_type Extension = Name.size() - 4;
    std::wstring::size_type Dot = Name.rfind(L'.', Extension - 1);

    if (Dot == std::wstring::npos || Dot == 0 || Dot + 1 >= Extension)
        return false;
    return Name.find_first_not_of(L"0123456789", Dot + 1) == Extension;
}

/* Like Windows, every .dmp file in the folder counts; the oldest go first */
static void MakeRoomForDump(const std::wstring& Folder, DWORD MaxCount)
{
    std::vector<DumpFile> Files;
    WIN32_FIND_DATAW FindData;
    HANDLE hFind = FindFirstFileW((Folder + L"\\*.dmp").c_str(), &FindData);

    if (hFind == INVALID_HANDLE_VALUE)
        return;
    do
    {
        if (!(FindData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
        {
            DumpFile File;
            File.Name = FindData.cFileName;
            File.LastWrite = FindData.ftLastWriteTime;
            Files.push_back(File);
        }
    } while (FindNextFileW(hFind, &FindData));
    FindClose(hFind);

    std::sort(Files.begin(), Files.end(), OlderFirst);
    size_t Remaining = Files.size();
    for (size_t n = 0; n < Files.size() && Remaining >= MaxCount; ++n)
    {
        std::wstring Path = Folder + L"\\" + Files[n].Name;
        if (!DeleteFileW(Path.c_str()))
            continue;
        --Remaining;

        /* Only our own text report goes with it */
        if (IsReporterDumpName(Files[n].Name))
        {
            Path.replace(Path.size() - 4, 4, L".txt");
            DeleteFileW(Path.c_str());
        }
    }
}

static DWORD GetDumpFlags(const LocalDumpSettings& Settings)
{
    switch (Settings.Type)
    {
        case 0:
            return Settings.CustomFlags;
        case 2:
            return FULL_DUMP_FLAGS;
        default:
            return MINI_DUMP_FLAGS;
    }
}

static bool ReadRemote(HANDLE hProcess, const void* Address, void* Buffer, SIZE_T Size)
{
    SIZE_T Read = 0;
    return ReadProcessMemory(hProcess, Address, Buffer, Size, &Read) && Read == Size;
}

static std::wstring FileNamePart(const std::wstring& Path)
{
    std::wstring::size_type pos = Path.find_last_of(L"\\/");
    return (pos != std::wstring::npos) ? Path.substr(pos + 1) : Path;
}

/* Open the crashed process and read its exception; fill DumpData as the debug events do in debugger mode */
static bool OpenCrashedProcess(DumpData& data, DWORD pid, DWORD tid, ULONG_PTR RemotePointers, EXCEPTION_POINTERS& Pointers)
{
    WCHAR Path[MAX_PATH * 2];
    DWORD len;

    data.ProcessID = pid;
    data.ThreadID = tid;
    data.ProcessHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_DUP_HANDLE | SYNCHRONIZE,
                                     FALSE, pid);
    if (!data.ProcessHandle)
        return false;

    /* The loader data of a damaged process may be unreadable; the kernel still knows the image */
    len = GetModuleFileNameExW(data.ProcessHandle, NULL, Path, _countof(Path));
    if (len)
    {
        data.ProcessPath.assign(Path, len);
    }
    else
    {
        len = GetProcessImageFileNameW(data.ProcessHandle, Path, _countof(Path));
        data.ProcessPath = len ? std::wstring(Path, len) : std::wstring(L"unknown");
    }
    data.ProcessName = FileNamePart(data.ProcessPath);
    if (data.ProcessName.empty())
        data.ProcessName = L"unknown";

    if (!ReadRemote(data.ProcessHandle, (PVOID)RemotePointers, &Pointers, sizeof(Pointers)) ||
        !ReadRemote(data.ProcessHandle, Pointers.ExceptionRecord, &data.ExceptionInfo.ExceptionRecord,
                    sizeof(data.ExceptionInfo.ExceptionRecord)))
    {
        return false;
    }
    data.ExceptionInfo.dwFirstChance = 0;
    return true;
}

static void CollectThreads(DumpData& data, const EXCEPTION_POINTERS& Pointers)
{
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnap != INVALID_HANDLE_VALUE)
    {
        THREADENTRY32 te;
        te.dwSize = sizeof(te);
        if (Thread32First(hSnap, &te))
        {
            do
            {
                if (te.th32OwnerProcessID != data.ProcessID)
                    continue;
                HANDLE hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION,
                                            FALSE, te.th32ThreadID);
                if (hThread)
                    data.Threads[te.th32ThreadID] = ThreadData(hThread);
            } while (Thread32Next(hSnap, &te));
        }
        CloseHandle(hSnap);
    }

    /* The crashed thread is waiting in UnhandledExceptionFilter: report the context of the fault */
    ThreadMap::iterator crash = data.Threads.find(data.ThreadID);
    if (crash != data.Threads.end() &&
        ReadRemote(data.ProcessHandle, Pointers.ContextRecord, &crash->second.Context, sizeof(CONTEXT)))
    {
        crash->second.HaveContext = true;
    }
}

/* With the other threads held, so no module goes away meanwhile; the main module is printed separately */
static void CollectModules(DumpData& data)
{
    HMODULE Modules[1024];
    DWORD Needed = 0;
    if (EnumProcessModules(data.ProcessHandle, Modules, sizeof(Modules), &Needed))
    {
        DWORD Count = std::min<DWORD>(Needed / sizeof(HMODULE), _countof(Modules));
        for (DWORD n = 1; n < Count; ++n)
            data.Modules.push_back(ModuleData(Modules[n]));
    }
}

/* Threads this reporter suspended; resumed on every way out, also from a fault */
static std::vector<HANDLE> SuspendedThreads;

/* Hold every other thread while the dump and the report are written; the crashed thread only waits */
static void SuspendOtherThreads(DumpData& data)
{
    for (ThreadMap::iterator it = data.Threads.begin(); it != data.Threads.end(); ++it)
    {
        if (it->first != data.ThreadID && SuspendThread(it->second.Handle) != (DWORD)-1)
            SuspendedThreads.push_back(it->second.Handle);
    }
}

static void ResumeOtherThreads()
{
    for (size_t n = 0; n < SuspendedThreads.size(); ++n)
        ResumeThread(SuspendedThreads[n]);
    SuspendedThreads.clear();
}

static bool WriteDump(LPCWSTR Path, DumpData& data, ULONG_PTR RemotePointers, DWORD Flags)
{
    HANDLE hFile = CreateFileW(Path, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
        return false;

    MINIDUMP_EXCEPTION_INFORMATION ExceptionParam;
    ExceptionParam.ThreadId = data.ThreadID;
    ExceptionParam.ExceptionPointers = (PEXCEPTION_POINTERS)RemotePointers;
    ExceptionParam.ClientPointers = TRUE;

    BOOL Success = MiniDumpWriteDump(data.ProcessHandle, data.ProcessID, hFile, (MINIDUMP_TYPE)Flags,
                                     &ExceptionParam, NULL, NULL);
    CloseHandle(hFile);
    if (!Success)
        DeleteFileW(Path);
    return Success != FALSE;
}

/* A fault in the reporter itself must not start another reporter, nor leave threads held */
static LONG WINAPI ReporterFaultFilter(PEXCEPTION_POINTERS)
{
    ResumeOtherThreads();
    return EXCEPTION_EXECUTE_HANDLER;
}

/* LocalDumps: the dump and the text report; the paths of what was written are returned */
static int WriteLocalDumps(DumpData& data, ULONG_PTR RemotePointers, const EXCEPTION_POINTERS& Pointers,
                           std::wstring& WrittenDump, std::wstring& WrittenReport)
{
    LocalDumpSettings Settings;
    if (!ReadLocalDumpSettings(data.ProcessName, Settings) || Settings.Count == 0)
        return 0;

    std::wstring Folder = GetDumpFolder(Settings);
    if (Folder.empty())
        return 3;
    int res = SHCreateDirectoryExW(NULL, Folder.c_str(), NULL);
    if (res != ERROR_SUCCESS && res != ERROR_ALREADY_EXISTS && res != ERROR_FILE_EXISTS)
        return 3;

    /* Check the full names before anything is deleted */
    WCHAR DumpPath[MAX_PATH], ReportPath[MAX_PATH];
    if (FAILED(StringCchPrintfW(DumpPath, _countof(DumpPath), L"%s\\%s.%lu.dmp",
                                Folder.c_str(), data.ProcessName.c_str(), data.ProcessID)) ||
        FAILED(StringCchPrintfW(ReportPath, _countof(ReportPath), L"%s\\%s.%lu.txt",
                                Folder.c_str(), data.ProcessName.c_str(), data.ProcessID)))
    {
        return 3;
    }

    MakeRoomForDump(Folder, Settings.Count);

    CollectThreads(data, Pointers);

    /* Recording a suspension must not allocate */
    SuspendedThreads.reserve(data.Threads.size());

    bool DumpWritten = false, ReportWritten = false;
    try
    {
        SuspendOtherThreads(data);
        CollectModules(data);

        DumpWritten = WriteDump(DumpPath, data, RemotePointers, GetDumpFlags(Settings));

        FILE* output = _wfopen(ReportPath, L"wb");
        if (output)
        {
            PrintBugreport(output, data);
            fclose(output);
            ReportWritten = true;
        }
    }
    catch (...)
    {
    }
    ResumeOtherThreads();

    if (DumpWritten)
        WrittenDump = DumpPath;
    if (ReportWritten)
        WrittenReport = ReportPath;
    return (DumpWritten && ReportWritten) ? 0 : 4;
}

/*
 * Tell the crashed process that the report is written; it then waits for the
 * dialog without a time limit. Only a handle that is an event can be set.
 */
static bool SignalReported(HANDLE hProcess, ULONG_PTR RemoteEvent)
{
    HANDLE hEvent;
    BOOL Set;

    if (!RemoteEvent ||
        !DuplicateHandle(hProcess, (HANDLE)RemoteEvent, GetCurrentProcess(), &hEvent, EVENT_MODIFY_STATE, FALSE, 0))
    {
        return false;
    }
    Set = SetEvent(hEvent);
    CloseHandle(hEvent);
    return Set != FALSE;
}

/*
 * Options after -u: -p PID -t TID -x POINTERS (required); -ui asks the user
 * after the report, -d offers to debug, -r EVENT is a handle in the crashed
 * process to set once the report is written. With -ui the exit code is
 * CRASH_REPORTER_CLOSE or CRASH_REPORTER_DEBUG; any other code makes kernel32
 * show the classic hard error box instead.
 */
int WerReportMain(int argc, WCHAR** argv)
{
    DWORD pid = 0, tid = 0;
    ULONG_PTR RemotePointers = 0, RemoteEvent = 0;
    bool ShowUi = false, OfferDebug = false;
    DumpData data;

    SetUnhandledExceptionFilter(ReporterFaultFilter);
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);

    for (int n = 0; n < argc; ++n)
    {
        if (!wcscmp(argv[n], L"-ui"))
            ShowUi = true;
        else if (!wcscmp(argv[n], L"-d"))
            OfferDebug = true;
        else if (n + 1 >= argc)
            break;
        else if (!wcscmp(argv[n], L"-p"))
            pid = wcstoul(argv[++n], NULL, 10);
        else if (!wcscmp(argv[n], L"-t"))
            tid = wcstoul(argv[++n], NULL, 10);
        else if (!wcscmp(argv[n], L"-x"))
            RemotePointers = (ULONG_PTR)_wcstoui64(argv[++n], NULL, 16);
        else if (!wcscmp(argv[n], L"-r"))
            RemoteEvent = (ULONG_PTR)_wcstoui64(argv[++n], NULL, 16);
    }
    if (!pid || !tid || !RemotePointers)
        return 1;

    EXCEPTION_POINTERS Pointers;
    if (!OpenCrashedProcess(data, pid, tid, RemotePointers, Pointers))
        return 2;

    /* Windows logs every reported crash, with or without local dumps */
    ProblemSignature Signature;
    GetProblemSignature(data, Signature);
    WriteApplicationErrorEvent(data, Signature);

    std::wstring DumpPath, ReportPath;
    int Result = WriteLocalDumps(data, RemotePointers, Pointers, DumpPath, ReportPath);

    if (!ShowUi)
        return Result;

    /* Without the signal kernel32 keeps its time limit, which could end the program during the dialog */
    if (!SignalReported(data.ProcessHandle, RemoteEvent))
        return 6;

    return ShowCrashDialog(data, Signature, DumpPath.c_str(), ReportPath.c_str(), OfferDebug);
}
