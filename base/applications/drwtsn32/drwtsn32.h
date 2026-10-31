/*
 * PROJECT:     Dr. Watson crash reporter
 * LICENSE:     GPL-2.0+ (https://spdx.org/licenses/GPL-2.0+)
 * PURPOSE:     Project header
 * COPYRIGHT:   Copyright 2017 Mark Jansen (mark.jansen@reactos.org)
 */

#pragma once


struct ModuleData
{
    std::string ModuleName;
    void *BaseAddress;
    DWORD Size;
    bool Unloaded;


    ModuleData(void* addr);
    void Update(HANDLE hProcess);
};

struct ThreadData
{
    HANDLE Handle;
    CONTEXT Context;
    bool HaveContext;

    ThreadData(HANDLE handle = NULL);

    void Update();
};

typedef std::vector<ModuleData> ModuleList;
typedef std::map<DWORD, ThreadData> ThreadMap;

class DumpData
{
public:
    std::wstring ProcessPath;
    std::wstring ProcessName;
    DWORD ProcessID;
    DWORD ThreadID;
    HANDLE ProcessHandle;
    ModuleList Modules;
    ThreadMap Threads;
    EXCEPTION_DEBUG_INFO ExceptionInfo;
    HANDLE Event;
    bool FirstBPHit;

    DumpData();
};

#define NEWLINE "\r\n"

/* main.cpp */
void xfprintf(FILE* stream, const char *fmt, ...);
void PrintBugreport(FILE* output, DumpData& data);

/* The problem signature of a crash, as Windows shows it */
struct ProblemSignature
{
    WCHAR AppVersion[32];
    WCHAR AppTimeStamp[16];
    std::wstring ModuleName;
    std::wstring ModulePath;
    WCHAR ModuleVersion[32];
    WCHAR ModuleTimeStamp[16];
    WCHAR Code[16];
    WCHAR Offset[24];
};

/* Exit codes of "drwtsn32 -u -ui" for kernel32's UnhandledExceptionFilter */
#define CRASH_REPORTER_CLOSE    0x00C105ED
#define CRASH_REPORTER_DEBUG    0x00DEB06D

/* wer.cpp */
int WerReportMain(int argc, WCHAR** argv);

/* eventlog.cpp */
void GetProblemSignature(DumpData& data, ProblemSignature& Signature);
void WriteApplicationErrorEvent(DumpData& data, const ProblemSignature& Signature);

/* crashdlg.cpp */
bool CanShowUi();
int ShowCrashDialog(DumpData& data, const ProblemSignature& Signature, LPCWSTR DumpPath, LPCWSTR ReportPath,
                    bool OfferDebug);

/* drwtsn32.cpp */
bool UpdateFromEvent(DEBUG_EVENT& evt, DumpData& data);

/* sysinfo.cpp */
void PrintSystemInfo(FILE* output, DumpData& data);

/* stacktrace.cpp */
void BeginStackBacktrace(DumpData& data);
void PrintStackBacktrace(FILE* output, DumpData& data, ThreadData& thread);
void EndStackBacktrace(DumpData& data);

