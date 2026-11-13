/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     TLS of a DLL that is loaded after the process started
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"
#include <ndk/pstypes.h>
#include <ndk/psfuncs.h>
#include <stdio.h>
#include <pseh/pseh2.h>

typedef ULONG (WINAPI *FN_TlsDynGetValue)(VOID);
typedef VOID (WINAPI *FN_TlsDynSetValue)(ULONG);
typedef PCSTR (WINAPI *FN_TlsDynGetEvents)(VOID);
typedef VOID (WINAPI *FN_TlsDynSetLog)(char *, LONG *);
typedef ULONG (WINAPI *FN_TlsDynGetIndex)(VOID);
typedef PVOID (WINAPI *FN_TlsDynGetTemplate)(VOID);
typedef VOID (WINAPI *FN_TlsDynWatchFls)(DWORD);
typedef VOID (WINAPI *FN_TlsDynDumpAtProcessDetach)(HANDLE);
typedef PVOID (WINAPI *FN_TlsDynGetFlsAtDetach)(VOID);
typedef VOID (WINAPI *FN_TlsDynSetFlsAtDetach)(DWORD, PVOID);
typedef BOOL (WINAPI *FN_TlsDynGetFlsSetResult)(BOOL *);

#define TEMPLATE_VALUE 0x5EEDF00D
#define AFTER_UNLOAD_CODE 0x1234

static FN_TlsDynGetValue pTlsDynGetValue;
static FN_TlsDynSetValue pTlsDynSetValue;

/* A thread started before the first load that lives until the end, doing what it is told */
enum { CMD_GET, CMD_SET, CMD_EXIT };
static HANDLE CommandEvent, DoneEvent;
static LONG Command;
static ULONG CommandValue;

static DWORD WINAPI Worker(LPVOID Parameter)
{
    for (;;)
    {
        SetEvent(DoneEvent);
        WaitForSingleObject(CommandEvent, INFINITE);
        if (Command == CMD_EXIT)
            return 0;
        if (Command == CMD_GET)
            CommandValue = pTlsDynGetValue();
        else
            pTlsDynSetValue(CommandValue);
    }
}

static BOOL RunCommand(LONG Cmd, ULONG *Value)
{
    Command = Cmd;
    CommandValue = *Value;
    SetEvent(CommandEvent);
    if (WaitForSingleObject(DoneEvent, 10000) != WAIT_OBJECT_0)
        return FALSE;
    *Value = CommandValue;
    return TRUE;
}

static ULONG WorkerGet(VOID)
{
    ULONG Value = 0xDEAD;
    ok(RunCommand(CMD_GET, &Value), "The worker did not answer\n");
    return Value;
}

static VOID WorkerSet(ULONG Value)
{
    ok(RunCommand(CMD_SET, &Value), "The worker did not answer\n");
}

static DWORD WINAPI NewThread(LPVOID Parameter)
{
    return Parameter ? AFTER_UNLOAD_CODE : pTlsDynGetValue();
}

static DWORD RunThread(LPVOID Parameter)
{
    HANDLE hThread;
    DWORD Code = 0xDEAD;

    hThread = CreateThread(NULL, 0, NewThread, Parameter, 0, NULL);
    ok(hThread != NULL, "CreateThread failed: %lu\n", GetLastError());
    if (!hThread)
        return Code;
    ok(WaitForSingleObject(hThread, 10000) == WAIT_OBJECT_0, "The thread did not finish\n");
    ok(GetExitCodeThread(hThread, &Code), "GetExitCodeThread failed: %lu\n", GetLastError());
    CloseHandle(hThread);
    return Code;
}

static HMODULE LoadTlsDll(VOID)
{
    HMODULE hDll;

    hDll = LoadLibraryW(L"kernel32_tlsdyn.dll");
    ok(hDll != NULL, "kernel32_tlsdyn.dll did not load: %lu\n", GetLastError());
    if (!hDll)
        return NULL;
    pTlsDynGetValue = (FN_TlsDynGetValue)GetProcAddress(hDll, "TlsDynGetValue");
    pTlsDynSetValue = (FN_TlsDynSetValue)GetProcAddress(hDll, "TlsDynSetValue");
    ok(pTlsDynGetValue && pTlsDynSetValue, "Exports missing\n");
    if (!pTlsDynGetValue || !pTlsDynSetValue)
    {
        FreeLibrary(hDll);
        return NULL;
    }
    return hDll;
}

/* Child process: the template becomes unreadable after the load, then a thread starts */
#define THREAD_HAD_BLOCK 1
#define THREAD_HAD_NO_BLOCK 2

static ULONG ChildTlsIndex;

static DWORD WINAPI CheckBlockThread(LPVOID Parameter)
{
    PVOID *TlsVector = (PVOID *)NtCurrentTeb()->ThreadLocalStoragePointer;
    return (TlsVector && TlsVector[ChildTlsIndex]) ? THREAD_HAD_BLOCK : THREAD_HAD_NO_BLOCK;
}

static VOID ProtectedTemplateChild(VOID)
{
    FN_TlsDynGetIndex pGetIndex;
    FN_TlsDynGetTemplate pGetTemplate;
    HANDLE hThread;
    HMODULE hDll;
    DWORD Old, Code = 0xDEAD;

    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
    hDll = LoadLibraryW(L"kernel32_tlsdyn.dll");
    if (!hDll)
        ExitProcess(0xD1);
    pGetIndex = (FN_TlsDynGetIndex)GetProcAddress(hDll, "TlsDynGetIndex");
    pGetTemplate = (FN_TlsDynGetTemplate)GetProcAddress(hDll, "TlsDynGetTemplate");
    if (!pGetIndex || !pGetTemplate)
        ExitProcess(0xD2);
    ChildTlsIndex = pGetIndex();
    if (!VirtualProtect(pGetTemplate(), 1, PAGE_NOACCESS, &Old))
        ExitProcess(0xD3);
    hThread = CreateThread(NULL, 0, CheckBlockThread, NULL, 0, NULL);
    if (!hThread)
        ExitProcess(0xD4);
    if (WaitForSingleObject(hThread, 10000) != WAIT_OBJECT_0)
        ExitProcess(0xD5);
    if (!GetExitCodeThread(hThread, &Code))
        ExitProcess(0xD6);
    ExitProcess(Code);
}

static VOID TestProtectedTemplate(PCSTR Self)
{
    STARTUPINFOA StartupInfo = { sizeof(StartupInfo) };
    PROCESS_INFORMATION ProcessInfo;
    char CommandLine[MAX_PATH + 32];
    DWORD Code = 0;

    StringCchPrintfA(CommandLine, ARRAYSIZE(CommandLine), "\"%s\" DynamicTls protected", Self);
    if (!CreateProcessA(NULL, CommandLine, NULL, NULL, FALSE, 0, NULL, NULL, &StartupInfo, &ProcessInfo))
    {
        skip("CreateProcess failed: %lu\n", GetLastError());
        return;
    }
    if (WaitForSingleObject(ProcessInfo.hProcess, 30000) != WAIT_OBJECT_0)
    {
        ok(0, "The child did not exit\n");
        TerminateProcess(ProcessInfo.hProcess, 0xDEAD);
        WaitForSingleObject(ProcessInfo.hProcess, 10000);
    }
    ok(GetExitCodeProcess(ProcessInfo.hProcess, &Code), "GetExitCodeProcess failed: %lu\n", GetLastError());
    trace("Unreadable template, new thread: child exit code 0x%lx\n", Code);
    ok(Code < 0xD1 || Code > 0xD6, "The child failed to set up or to wait: 0x%lx\n", Code);
    /*
     * The thread must not run without its block: on ReactOS it ends before it
     * runs, with its status; on Windows the template fault ends the process.
     */
    ok(Code == (is_reactos() ? 0xC0000017 /* STATUS_NO_MEMORY */ : 0xC0000005 /* STATUS_ACCESS_VIOLATION */),
       "Child exit code 0x%lx\n", Code);
    CloseHandle(ProcessInfo.hProcess);
    CloseHandle(ProcessInfo.hThread);
}

/*
 * Child process: code that keeps the TLS vector pointer of its thread in a
 * register across a call (compilers do: Oracle's server does it around a
 * callout that loads a DLL with TLS) reads the vector it had before the call.
 * The loading thread's vector is replaced when a second module with TLS grows
 * the vectors; the old one must stay readable and unchanged.
 */
#define OLDVEC_INTACT 0x10
#define OLDVEC_CHANGED 0x11
#define OLDVEC_UNREADABLE 0x12
#define OLDVEC_NOT_REPLACED 0x13

static VOID OldVectorChild(PCSTR CopyPath)
{
    FN_TlsDynGetIndex pGetIndex;
    PVOID *OldVector, Saved[8], *Churn[64];
    HMODULE hFirst, hSecond;
    ULONG Index, Count, i;
    BOOL Same = TRUE, Faulted = FALSE;

    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
    hFirst = LoadLibraryW(L"kernel32_tlsdyn.dll");
    if (!hFirst)
        ExitProcess(0xD1);
    pGetIndex = (FN_TlsDynGetIndex)GetProcAddress(hFirst, "TlsDynGetIndex");
    if (!pGetIndex)
        ExitProcess(0xD2);
    Index = pGetIndex();
    OldVector = (PVOID *)NtCurrentTeb()->ThreadLocalStoragePointer;
    if (!OldVector || Index >= ARRAYSIZE(Saved))
        ExitProcess(0xD3);
    Count = Index + 1;
    for (i = 0; i < Count; i++)
        Saved[i] = OldVector[i];

    /* The same DLL under another name is another module: it takes the next index, every vector grows */
    hSecond = LoadLibraryA(CopyPath);
    if (!hSecond)
        ExitProcess(0xD4);
    if ((PVOID *)NtCurrentTeb()->ThreadLocalStoragePointer == OldVector)
        ExitProcess(OLDVEC_NOT_REPLACED);

    /* Heap blocks of the vector's size: memory that was given back is handed out again and overwritten */
    for (i = 0; i < ARRAYSIZE(Churn); i++)
    {
        Churn[i] = HeapAlloc(GetProcessHeap(), 0, (Count + 1) * sizeof(PVOID));
        if (Churn[i])
            memset(Churn[i], 0xCC, (Count + 1) * sizeof(PVOID));
    }

    _SEH2_TRY
    {
        for (i = 0; i < Count; i++)
        {
            if (OldVector[i] != Saved[i])
                Same = FALSE;
        }
        /* The block of the first DLL, reached through the old vector, is still the thread's block */
        if (Same && OldVector[Index] != ((PVOID *)NtCurrentTeb()->ThreadLocalStoragePointer)[Index])
            Same = FALSE;
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        Faulted = TRUE;
    }
    _SEH2_END;

    ExitProcess(Faulted ? OLDVEC_UNREADABLE : (Same ? OLDVEC_INTACT : OLDVEC_CHANGED));
}

static VOID TestOldVectorOfLoadingThread(PCSTR Self, PCWSTR DllPath)
{
    STARTUPINFOA StartupInfo = { sizeof(StartupInfo) };
    PROCESS_INFORMATION ProcessInfo;
    WCHAR TempDir[MAX_PATH], CopyPathW[MAX_PATH];
    char CopyPath[MAX_PATH], CommandLine[2 * MAX_PATH + 32];
    DWORD Code = 0xDEAD;

    GetTempPathW(ARRAYSIZE(TempDir), TempDir);
    StringCchPrintfW(CopyPathW, ARRAYSIZE(CopyPathW), L"%stlsdyn_oldvec_%lu.dll", TempDir, GetCurrentProcessId());
    if (!CopyFileW(DllPath, CopyPathW, FALSE))
    {
        skip("CopyFile failed: %lu\n", GetLastError());
        return;
    }
    WideCharToMultiByte(CP_ACP, 0, CopyPathW, -1, CopyPath, ARRAYSIZE(CopyPath), NULL, NULL);
    StringCchPrintfA(CommandLine, ARRAYSIZE(CommandLine), "\"%s\" DynamicTls oldvector \"%s\"", Self, CopyPath);
    if (!CreateProcessA(NULL, CommandLine, NULL, NULL, FALSE, 0, NULL, NULL, &StartupInfo, &ProcessInfo))
    {
        skip("CreateProcess failed: %lu\n", GetLastError());
        DeleteFileW(CopyPathW);
        return;
    }
    if (WaitForSingleObject(ProcessInfo.hProcess, 30000) != WAIT_OBJECT_0)
    {
        ok(0, "The child did not exit\n");
        TerminateProcess(ProcessInfo.hProcess, 0xDEAD);
        WaitForSingleObject(ProcessInfo.hProcess, 10000);
    }
    ok(GetExitCodeProcess(ProcessInfo.hProcess, &Code), "GetExitCodeProcess failed: %lu\n", GetLastError());
    /* Windows 10 22H2 does not replace the loading thread's vector here (measured: 0x13); only a loader that
       replaces it must keep the old one readable */
    if (Code == OLDVEC_NOT_REPLACED)
        skip("The loader kept the TLS vector of the loading thread: nothing to check\n");
    else
        ok(Code == OLDVEC_INTACT, "Old TLS vector of the loading thread after a second load: child exit code 0x%lx "
           "(0x11 changed, 0x12 unreadable)\n", Code);
    CloseHandle(ProcessInfo.hProcess);
    CloseHandle(ProcessInfo.hThread);
    DeleteFileW(CopyPathW);
}

/* Copies of the DLL whose TLS directory, or image size, wraps around the address space on i386 */
static VOID TestBadImage(PCWSTR DllPath, BOOL BadSize)
{
    WCHAR TempDir[MAX_PATH], Path[MAX_PATH];
    PIMAGE_DOS_HEADER DosHeader;
    PIMAGE_NT_HEADERS32 Nt32;
    PIMAGE_NT_HEADERS64 Nt64;
    PUCHAR Data = NULL;
    DWORD Size, Written;
    HANDLE hFile;
    HMODULE hDll;
    BOOL Ret;

    hFile = CreateFileW(DllPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    ok(hFile != INVALID_HANDLE_VALUE, "Cannot open %S: %lu\n", DllPath, GetLastError());
    if (hFile == INVALID_HANDLE_VALUE)
        return;
    Size = GetFileSize(hFile, NULL);
    Data = HeapAlloc(GetProcessHeap(), 0, Size);
    Ret = Data && ReadFile(hFile, Data, Size, &Written, NULL) && Written == Size;
    CloseHandle(hFile);
    ok(Ret, "Cannot read %S\n", DllPath);
    if (!Ret)
        goto Exit;

    DosHeader = (PIMAGE_DOS_HEADER)Data;
    Nt32 = (PIMAGE_NT_HEADERS32)(Data + DosHeader->e_lfanew);
    Nt64 = (PIMAGE_NT_HEADERS64)Nt32;
    if (Nt32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
    {
        /* Base plus RVA (or plus size) is 0 at the preferred base */
        ULONG Wrap = 0 - Nt32->OptionalHeader.ImageBase;
        if (BadSize)
            Nt32->OptionalHeader.SizeOfImage = Wrap;
        else
            Nt32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress = Wrap;
    }
    else
    {
        if (BadSize)
            Nt64->OptionalHeader.SizeOfImage = 0xF0000000;
        else
            Nt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress = 0xFFFFF000;
    }

    GetTempPathW(ARRAYSIZE(TempDir), TempDir);
    StringCchPrintfW(Path, ARRAYSIZE(Path), L"%stlsdyn_bad%u.dll", TempDir, BadSize);
    hFile = CreateFileW(Path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    ok(hFile != INVALID_HANDLE_VALUE, "Cannot create %S: %lu\n", Path, GetLastError());
    if (hFile == INVALID_HANDLE_VALUE)
        goto Exit;
    Ret = WriteFile(hFile, Data, Size, &Written, NULL);
    CloseHandle(hFile);
    ok(Ret, "Cannot write %S\n", Path);

    SetLastError(0xdeadbeef);
    hDll = LoadLibraryW(Path);
    trace("%s: LoadLibrary %p, error %lu\n", BadSize ? "Wrapping image size" : "Wrapping TLS directory", hDll, GetLastError());
    if (hDll)
    {
        /* A module that loads must have working TLS */
        FN_TlsDynGetValue pGetValue = (FN_TlsDynGetValue)GetProcAddress(hDll, "TlsDynGetValue");
        if (!BadSize)
            ok(!is_reactos(), "A TLS directory outside the image was accepted\n");
        else if (pGetValue)
            ok(pGetValue() == TEMPLATE_VALUE, "TLS of a module with a wrapping image size: 0x%lx\n", pGetValue());
        FreeLibrary(hDll);
    }
    else if (is_reactos() && !BadSize)
    {
        ok(GetLastError() == ERROR_BAD_EXE_FORMAT, "Error %lu\n", GetLastError());
    }
    DeleteFileW(Path);

Exit:
    HeapFree(GetProcessHeap(), 0, Data);
}

/*
 * FLS callbacks of an exiting thread run while the thread still has its TLS:
 * the C++ runtime destroys its thread_local objects from an FLS callback.
 */
#define FLS_DATA ((PVOID)(ULONG_PTR)0xF15DA7A)
#define FLS_SLOT_COUNT 70
#define FLS_IMPLICIT_VALUE 0xC0DE
#define FLS_EXPLICIT_VALUE ((PVOID)(ULONG_PTR)0xE4B11C17)

static char FlsLog[64];
static LONG FlsLogCount;
static DWORD FlsSlot[FLS_SLOT_COUNT];
static DWORD FlsIndex;
static ULONG FlsImplicit;
static BOOL FlsImplicitFaulted;
static PVOID FlsExplicit, FlsDataSeen, FlsOwnValue, FlsAtDetach;
static LONG FlsCalls;

static VOID FlsAddEvent(char Kind, DWORD Value)
{
    LONG i = InterlockedExchangeAdd(&FlsLogCount, 2);
    if (i + 1 < (LONG)sizeof(FlsLog) - 1)
    {
        FlsLog[i] = Kind;
        FlsLog[i + 1] = (char)('0' + Value);
    }
}

static VOID NTAPI FlsCheckCallback(PVOID Data)
{
    FlsAddEvent('F', 0);
    InterlockedIncrement(&FlsCalls);
    FlsDataSeen = Data;
    FlsOwnValue = FlsGetValue(FlsIndex);
    _SEH2_TRY
    {
        FlsImplicit = pTlsDynGetValue();
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        FlsImplicitFaulted = TRUE;
    }
    _SEH2_END;
    FlsExplicit = TlsGetValue(FlsSlot[FLS_SLOT_COUNT - 1]);
}

static DWORD WINAPI FlsCheckThread(LPVOID Parameter)
{
    pTlsDynSetValue(FLS_IMPLICIT_VALUE);
    TlsSetValue(FlsSlot[FLS_SLOT_COUNT - 1], FLS_EXPLICIT_VALUE);
    FlsSetValue(FlsIndex, FLS_DATA);
    return 0;
}

static VOID TestFlsAtThreadExit(VOID)
{
    FN_TlsDynSetLog pSetLog;
    FN_TlsDynWatchFls pWatchFls;
    FN_TlsDynGetFlsAtDetach pGetFlsAtDetach;
    HMODULE hDll;
    HANDLE hThread;
    ULONG i, Allocated = 0;
    DWORD Wait;

    hDll = LoadTlsDll();
    if (!hDll)
        return;
    pSetLog = (FN_TlsDynSetLog)GetProcAddress(hDll, "TlsDynSetLog");
    pWatchFls = (FN_TlsDynWatchFls)GetProcAddress(hDll, "TlsDynWatchFls");
    pGetFlsAtDetach = (FN_TlsDynGetFlsAtDetach)GetProcAddress(hDll, "TlsDynGetFlsAtDetach");
    if (!pSetLog || !pWatchFls || !pGetFlsAtDetach)
    {
        ok(0, "Exports missing\n");
        goto Done;
    }

    /* The last slot is above the 64 that live in the TEB */
    for (i = 0; i < FLS_SLOT_COUNT; i++)
    {
        FlsSlot[i] = TlsAlloc();
        if (FlsSlot[i] == TLS_OUT_OF_INDEXES)
            break;
        Allocated++;
    }
    ok(Allocated == FLS_SLOT_COUNT, "Only %lu TLS slots were allocated\n", Allocated);
    FlsIndex = FlsAlloc(FlsCheckCallback);
    ok(FlsIndex != FLS_OUT_OF_INDEXES, "FlsAlloc failed: %lu\n", GetLastError());
    if (Allocated != FLS_SLOT_COUNT || FlsIndex == FLS_OUT_OF_INDEXES)
        goto Free;
    ok(FlsSlot[FLS_SLOT_COUNT - 1] >= TLS_MINIMUM_AVAILABLE, "The slot %lu is in the TEB\n", FlsSlot[FLS_SLOT_COUNT - 1]);

    FlsLogCount = 0;
    ZeroMemory(FlsLog, sizeof(FlsLog));
    pSetLog(FlsLog, &FlsLogCount);
    pWatchFls(FlsIndex);
    FlsCalls = 0;
    FlsImplicitFaulted = FALSE;
    FlsImplicit = 0;
    FlsExplicit = FlsDataSeen = FlsOwnValue = (PVOID)(ULONG_PTR)1;

    hThread = CreateThread(NULL, 0, FlsCheckThread, NULL, 0, NULL);
    ok(hThread != NULL, "CreateThread failed: %lu\n", GetLastError());
    if (hThread)
    {
        Wait = WaitForSingleObject(hThread, 10000);
        ok(Wait == WAIT_OBJECT_0, "The thread did not finish: %lu\n", Wait);
        CloseHandle(hThread);
    }

    FlsAtDetach = pGetFlsAtDetach();
    trace("FLS callback at thread exit: log '%s', calls %ld, implicit 0x%lx faulted %d, explicit %p, data %p, own value %p, at detach %p\n",
          FlsLog, FlsCalls, FlsImplicit, FlsImplicitFaulted, FlsExplicit, FlsDataSeen, FlsOwnValue, FlsAtDetach);
    ok(FlsCalls == 1, "FLS callback ran %ld times\n", FlsCalls);
    ok(FlsDataSeen == FLS_DATA, "FLS data %p\n", FlsDataSeen);
    ok(!FlsImplicitFaulted, "The FLS callback could not read the thread's implicit TLS\n");
    ok(FlsImplicit == FLS_IMPLICIT_VALUE, "Implicit TLS in the FLS callback: 0x%lx\n", FlsImplicit);
    ok(FlsExplicit == FLS_EXPLICIT_VALUE, "Explicit TLS slot above 64 in the FLS callback: %p\n", FlsExplicit);
    ok(FlsOwnValue == FLS_DATA, "FlsGetValue in the FLS callback: %p\n", FlsOwnValue);
    /* The callback comes before the DLL thread notifications: T3 is the TLS callback, M3 DllMain */
    ok(!strcmp(FlsLog, "T2M2F0T3M3"), "Events at thread exit: '%s'\n", FlsLog);
    /* The value is gone once its callback ran: DllMain finds the slot empty */
    ok(FlsAtDetach == NULL, "FlsGetValue in DLL_THREAD_DETACH: %p\n", FlsAtDetach);

Free:
    for (i = 0; i < Allocated; i++)
        TlsFree(FlsSlot[i]);
    if (FlsIndex != FLS_OUT_OF_INDEXES)
        FlsFree(FlsIndex);
Done:
    FreeLibrary(hDll);
}

/*
 * A DLL_THREAD_DETACH that calls FlsSetValue on a thread without FLS data
 * links a new block into the PEB list; the thread exit must take it out
 * again before freeing it, or a later FlsFree walks freed memory.
 */
#define DETACH_FLS_DATA ((PVOID)(ULONG_PTR)0xDE7AC4ED)

static LONG DetachFlsCalls;

static VOID NTAPI DetachFlsCallback(PVOID Data)
{
    InterlockedIncrement(&DetachFlsCalls);
}

static BOOL NoFlsAtStart;

static DWORD WINAPI NoFlsThread(LPVOID Parameter)
{
    NoFlsAtStart = (NtCurrentTeb()->FlsData == NULL);
    return 0;
}

/* The FLS blocks linked in the PEB, -1 when the list does not lead back to its head */
static LONG CountFlsBlocks(VOID)
{
    PLIST_ENTRY Head = &NtCurrentPeb()->FlsListHead, Entry;
    LONG Count = 0;

    _SEH2_TRY
    {
        for (Entry = Head->Flink; Entry && Entry != Head; Entry = Entry->Flink)
        {
            if (++Count > 1024)
                break;
        }
        if (!Entry && Count)
            Count = -1;
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        Count = -1;
    }
    _SEH2_END;
    return Count > 1024 ? -1 : Count;
}

static VOID TestFlsSetAtThreadDetach(VOID)
{
    FN_TlsDynSetFlsAtDetach pSetFlsAtDetach;
    FN_TlsDynGetFlsSetResult pGetFlsSetResult;
    HMODULE hDll;
    HANDLE hThread;
    DWORD Index, Wait;
    LONG Before, After;
    BOOL SetResult, HadNoData = FALSE;

    hDll = LoadTlsDll();
    if (!hDll)
        return;
    pSetFlsAtDetach = (FN_TlsDynSetFlsAtDetach)GetProcAddress(hDll, "TlsDynSetFlsAtDetach");
    pGetFlsSetResult = (FN_TlsDynGetFlsSetResult)GetProcAddress(hDll, "TlsDynGetFlsSetResult");
    Index = FlsAlloc(DetachFlsCallback);
    ok(pSetFlsAtDetach && pGetFlsSetResult, "Exports missing\n");
    ok(Index != FLS_OUT_OF_INDEXES, "FlsAlloc failed: %lu\n", GetLastError());
    if (!pSetFlsAtDetach || !pGetFlsSetResult || Index == FLS_OUT_OF_INDEXES)
        goto Done;

    Before = CountFlsBlocks();
    ok(Before >= 0, "The FLS list is broken before the test: %ld\n", Before);
    DetachFlsCalls = 0;
    NoFlsAtStart = FALSE;
    pSetFlsAtDetach(Index, DETACH_FLS_DATA);
    hThread = CreateThread(NULL, 0, NoFlsThread, NULL, 0, NULL);
    ok(hThread != NULL, "CreateThread failed: %lu\n", GetLastError());
    if (hThread)
    {
        Wait = WaitForSingleObject(hThread, 10000);
        ok(Wait == WAIT_OBJECT_0, "The thread did not finish: %lu\n", Wait);
        CloseHandle(hThread);
    }
    SetResult = pGetFlsSetResult(&HadNoData);
    pSetFlsAtDetach(FLS_OUT_OF_INDEXES, NULL);

    After = CountFlsBlocks();
    trace("FLS set at thread detach: no FLS at start %d, at detach %d, set %d, blocks %ld -> %ld, callback calls %ld\n",
          NoFlsAtStart, HadNoData, SetResult, Before, After, DetachFlsCalls);
    if (!NoFlsAtStart)
    {
        skip("The thread had FLS data when it started\n");
    }
    else
    {
        /* The detach made the thread's first FLS block */
        ok(HadNoData, "The thread had FLS data at its DLL_THREAD_DETACH\n");
        ok(SetResult, "FlsSetValue failed in DLL_THREAD_DETACH\n");
    }
    /* The exited thread's block is gone from the list */
    ok(After == Before, "FLS blocks linked: %ld before the thread, %ld after it exited\n", Before, After);

    /* FlsFree clears the index in every linked block: not with a freed one in the list */
    if (After == Before)
        FlsFree(Index);
Done:
    FreeLibrary(hDll);
}

/*
 * FLS callbacks at process exit: the exiting thread's callbacks run, with its
 * TLS intact, before the DLL process notifications. The child prints the
 * events it logged at its own process detach.
 */
#define EXIT_DATA ((PVOID)(ULONG_PTR)0xE817DA7A)

static char ChildLog[64];
static LONG ChildLogCount;
static DWORD ChildSlot, ChildFlsIndex;
static BOOL ChildRaise;
static FN_TlsDynGetValue pChildGetValue;
static FN_TlsDynSetValue pChildSetValue;

static VOID ChildEvent(char Kind, DWORD Value)
{
    LONG i = InterlockedExchangeAdd(&ChildLogCount, 2);
    if (i + 1 < (LONG)sizeof(ChildLog) - 1)
    {
        ChildLog[i] = Kind;
        ChildLog[i + 1] = (char)('0' + Value);
    }
}

static VOID NTAPI ChildFlsCallback(PVOID Data)
{
    ULONG Value = 0;
    BOOL Faulted = FALSE;

    ChildEvent('F', Data == EXIT_DATA);
    _SEH2_TRY
    {
        Value = pChildGetValue();
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        Faulted = TRUE;
    }
    _SEH2_END;
    ChildEvent('I', !Faulted && Value == FLS_IMPLICIT_VALUE);
    ChildEvent('E', TlsGetValue(ChildSlot) == FLS_EXPLICIT_VALUE);
    if (ChildRaise)
        RaiseException(0xE0001234, 0, 0, NULL);
}

static VOID ChildPrepareThread(VOID)
{
    pChildSetValue(FLS_IMPLICIT_VALUE);
    TlsSetValue(ChildSlot, FLS_EXPLICIT_VALUE);
    FlsSetValue(ChildFlsIndex, EXIT_DATA);
}

static DWORD WINAPI ChildExitingThread(LPVOID Parameter)
{
    ChildPrepareThread();
    ExitProcess(5);
    return 0;
}

static DWORD WINAPI ChildEndingThread(LPVOID Parameter)
{
    ChildPrepareThread();
    return 0;
}

/* Mode: "main" (ExitProcess from the main thread), "other" (from another thread), "last" (ExitThread of the last thread) */
static VOID FlsExitChild(PCSTR Mode)
{
    FN_TlsDynSetLog pSetLog;
    FN_TlsDynDumpAtProcessDetach pDump;
    HMODULE hDll;
    ULONG i;

    hDll = LoadLibraryW(L"kernel32_tlsdyn.dll");
    if (!hDll)
        ExitProcess(0xD1);
    pSetLog = (FN_TlsDynSetLog)GetProcAddress(hDll, "TlsDynSetLog");
    pDump = (FN_TlsDynDumpAtProcessDetach)GetProcAddress(hDll, "TlsDynDumpAtProcessDetach");
    pChildGetValue = (FN_TlsDynGetValue)GetProcAddress(hDll, "TlsDynGetValue");
    pChildSetValue = (FN_TlsDynSetValue)GetProcAddress(hDll, "TlsDynSetValue");
    if (!pSetLog || !pDump || !pChildGetValue || !pChildSetValue)
        ExitProcess(0xD2);
    for (i = 0; i < FLS_SLOT_COUNT; i++)
        ChildSlot = TlsAlloc();
    ChildFlsIndex = FlsAlloc(ChildFlsCallback);
    pSetLog(ChildLog, &ChildLogCount);
    pDump(GetStdHandle(STD_OUTPUT_HANDLE));

    SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS);
    if (!strcmp(Mode, "raise-process"))
        ChildRaise = TRUE;
    if (!strcmp(Mode, "raise-thread"))
    {
        /* The callback of a thread that ends raises an exception; does the process live on? */
        HANDLE hThread;
        ChildRaise = TRUE;
        hThread = CreateThread(NULL, 0, ChildEndingThread, NULL, 0, NULL);
        WaitForSingleObject(hThread, 10000);
        ChildEvent('A', 1);
        ChildRaise = FALSE;
        ExitProcess(7);
    }
    if (!strcmp(Mode, "other"))
    {
        HANDLE hThread = CreateThread(NULL, 0, ChildExitingThread, NULL, 0, NULL);
        /* The main thread has a callback too; it must not run */
        FlsSetValue(ChildFlsIndex, (PVOID)(ULONG_PTR)1);
        WaitForSingleObject(hThread, 10000);
        ExitProcess(0xD3);
    }
    ChildPrepareThread();
    if (!strcmp(Mode, "last"))
        ExitThread(6);
    ExitProcess(3);
}

static VOID RunFlsExitChild(PCSTR Self, PCSTR Mode, PCSTR Expected, PCSTR Alternative, DWORD ExpectedCode)
{
    SECURITY_ATTRIBUTES Sa = { sizeof(Sa), NULL, TRUE };
    STARTUPINFOA StartupInfo = { sizeof(StartupInfo) };
    PROCESS_INFORMATION ProcessInfo;
    char CommandLine[MAX_PATH + 32], Output[128] = "";
    HANDLE hRead, hWrite;
    DWORD Read = 0, Code = 0xDEAD;

    if (!CreatePipe(&hRead, &hWrite, &Sa, 0))
    {
        skip("CreatePipe failed: %lu\n", GetLastError());
        return;
    }
    SetHandleInformation(hRead, HANDLE_FLAG_INHERIT, 0);
    StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    StartupInfo.hStdOutput = hWrite;
    StartupInfo.hStdError = hWrite;
    StartupInfo.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    StringCchPrintfA(CommandLine, ARRAYSIZE(CommandLine), "\"%s\" DynamicTls flsexit %s", Self, Mode);
    if (!CreateProcessA(NULL, CommandLine, NULL, NULL, TRUE, 0, NULL, NULL, &StartupInfo, &ProcessInfo))
    {
        skip("CreateProcess failed: %lu\n", GetLastError());
        CloseHandle(hRead);
        CloseHandle(hWrite);
        return;
    }
    CloseHandle(hWrite);
    if (WaitForSingleObject(ProcessInfo.hProcess, 30000) != WAIT_OBJECT_0)
    {
        ok(0, "The %s child did not exit\n", Mode);
        TerminateProcess(ProcessInfo.hProcess, 0xDEAD);
        WaitForSingleObject(ProcessInfo.hProcess, 10000);
    }
    ReadFile(hRead, Output, sizeof(Output) - 1, &Read, NULL);
    Output[Read] = 0;
    GetExitCodeProcess(ProcessInfo.hProcess, &Code);
    trace("FLS at process exit, %s: exit code %lu, events '%s'\n", Mode, Code, Output);
    ok(!strcmp(Output, Expected) || (Alternative && !strcmp(Output, Alternative)),
       "%s: events '%s', expected '%s'\n", Mode, Output, Expected);
    ok(Code == ExpectedCode, "%s: exit code 0x%lx, expected 0x%lx\n", Mode, Code, ExpectedCode);
    CloseHandle(hRead);
    CloseHandle(ProcessInfo.hProcess);
    CloseHandle(ProcessInfo.hThread);
}

/* Committed private bytes by walking the address space: what a process is charged for, VAD by VAD */
static SIZE_T CountPrivateCommitted(SIZE_T *Regions)
{
    MEMORY_BASIC_INFORMATION Info;
    PUCHAR Address = NULL;
    SIZE_T Total = 0;

    *Regions = 0;
    while (VirtualQuery(Address, &Info, sizeof(Info)) == sizeof(Info))
    {
        if (Info.State != MEM_FREE)
            (*Regions)++;
        if (Info.State == MEM_COMMIT && Info.Type == MEM_PRIVATE)
            Total += Info.RegionSize;
        Address = (PUCHAR)Info.BaseAddress + Info.RegionSize;
        if (Address <= (PUCHAR)Info.BaseAddress)
            break;
    }
    return Total;
}

static SIZE_T GetPrivateUsage(VOID)
{
    VM_COUNTERS_EX Counters;
    NTSTATUS Status;

    Status = NtQueryInformationProcess(GetCurrentProcess(), ProcessVmCounters, &Counters, sizeof(Counters), NULL);
    ok(NT_SUCCESS(Status), "NtQueryInformationProcess failed: 0x%08lx\n", Status);
    return NT_SUCCESS(Status) ? Counters.PrivateUsage : 0;
}

#define CYCLES_WARMUP 200
#define CYCLES_MEASURED 10000

/*
 * Loading and unloading a DLL with TLS over and over leaves the process' private memory where it was.
 * The loader copies the DLL's base name for its data table entry; the copy must go with the entry.
 */
static VOID TestLoadCycles(VOID)
{
    SIZE_T Private0, Private1, Walk0, Walk1, Regions0, Regions1;
    HMODULE hDll;
    ULONG i;

    for (i = 0; i < CYCLES_WARMUP; i++)
    {
        hDll = LoadLibraryW(L"kernel32_tlsdyn.dll");
        if (!hDll || !FreeLibrary(hDll))
        {
            ok(0, "Cycle %lu: load/free failed: %lu\n", i, GetLastError());
            return;
        }
    }

    Private0 = GetPrivateUsage();
    Walk0 = CountPrivateCommitted(&Regions0);
    for (i = 0; i < CYCLES_MEASURED; i++)
    {
        hDll = LoadLibraryW(L"kernel32_tlsdyn.dll");
        if (!hDll || !FreeLibrary(hDll))
        {
            ok(0, "Cycle %lu: load/free failed: %lu\n", i, GetLastError());
            return;
        }
    }
    Private1 = GetPrivateUsage();
    Walk1 = CountPrivateCommitted(&Regions1);

    trace("PrivateUsage %Iu -> %Iu (%+Id), committed private walk %Iu -> %Iu (%+Id), regions %Iu -> %Iu\n",
          Private0, Private1, (SSIZE_T)(Private1 - Private0), Walk0, Walk1, (SSIZE_T)(Walk1 - Walk0), Regions0, Regions1);
    ok(Private1 - Private0 < 0x10000, "PrivateUsage grew by %Iu bytes over %u cycles\n", Private1 - Private0, CYCLES_MEASURED);
    ok(Walk1 - Walk0 < 0x10000, "Committed private memory grew by %Iu bytes over %u cycles\n", Walk1 - Walk0, CYCLES_MEASURED);
    ok(Regions1 <= Regions0 + 4, "Address space regions: %Iu, %Iu after the cycles\n", Regions0, Regions1);
}

START_TEST(DynamicTls)
{
    FN_TlsDynGetEvents pTlsDynGetEvents;
    FN_TlsDynSetLog pTlsDynSetLog;
    static char HostLog[64];
    static LONG HostCount;
    HANDLE hWorker;
    HMODULE hDll;
    ULONG Value;
    PCSTR Events;
    size_t Length;
    WCHAR DllPath[MAX_PATH], *Slash;
    char **argv;
    int argc;

    argc = winetest_get_mainargs(&argv);
    if (argc >= 3 && !strcmp(argv[2], "protected"))
    {
        ProtectedTemplateChild();
        return;
    }
    if (argc >= 4 && !strcmp(argv[2], "oldvector"))
    {
        OldVectorChild(argv[3]);
        return;
    }
    if (argc >= 4 && !strcmp(argv[2], "flsexit"))
    {
        FlsExitChild(argv[3]);
        return;
    }

    CommandEvent = CreateEventW(NULL, FALSE, FALSE, NULL);
    DoneEvent = CreateEventW(NULL, FALSE, FALSE, NULL);
    ok(CommandEvent && DoneEvent, "CreateEventW failed: %lu\n", GetLastError());
    if (!CommandEvent || !DoneEvent)
        return;

    /* A thread that has initialized (its TLS too) before the load */
    hWorker = CreateThread(NULL, 0, Worker, NULL, 0, NULL);
    ok(hWorker != NULL, "CreateThread failed: %lu\n", GetLastError());
    if (!hWorker)
        return;
    ok(WaitForSingleObject(DoneEvent, 10000) == WAIT_OBJECT_0, "The worker did not start\n");

    hDll = LoadTlsDll();
    if (!hDll)
        goto Cleanup;

    /* TLS callbacks run for the process attach, before DllMain */
    pTlsDynGetEvents = (FN_TlsDynGetEvents)GetProcAddress(hDll, "TlsDynGetEvents");
    pTlsDynSetLog = (FN_TlsDynSetLog)GetProcAddress(hDll, "TlsDynSetLog");
    ok(pTlsDynGetEvents && pTlsDynSetLog, "Exports missing\n");
    Events = pTlsDynGetEvents ? pTlsDynGetEvents() : "";
    ok(!strncmp(Events, "T1M1", 4), "Events at load: '%s'\n", Events);

    /* The loading thread sees the template */
    Value = pTlsDynGetValue();
    ok(Value == TEMPLATE_VALUE, "Loading thread: 0x%lx\n", Value);
    pTlsDynSetValue(0xAAAA);
    ok(pTlsDynGetValue() == 0xAAAA, "Loading thread after set: 0x%lx\n", pTlsDynGetValue());

    /* The thread that existed before the load has its own copy of the template */
    ok(WorkerGet() == TEMPLATE_VALUE, "Thread started before the load\n");
    WorkerSet(0x0D0D);
    ok(WorkerGet() == 0x0D0D, "Thread started before the load, after its set\n");
    ok(pTlsDynGetValue() == 0xAAAA, "The other thread's set changed this thread's copy: 0x%lx\n", pTlsDynGetValue());

    /* A thread started after the load gets the template too */
    Value = RunThread(NULL);
    ok(Value == TEMPLATE_VALUE, "Thread started after the load: 0x%lx\n", Value);

    /* The unload runs the TLS callbacks, then DllMain, for the process detach */
    if (pTlsDynSetLog)
        pTlsDynSetLog(HostLog, &HostCount);
    ok(FreeLibrary(hDll), "FreeLibrary failed: %lu\n", GetLastError());
    ok(GetModuleHandleW(L"kernel32_tlsdyn.dll") == NULL, "The DLL is still loaded\n");
    Length = strlen(HostLog);
    ok(Length >= 4 && !strcmp(HostLog + Length - 4, "T0M0"), "Events at unload: '%s'\n", HostLog);

    /* A thread started after the unload does not get the gone DLL's TLS */
    Value = RunThread((LPVOID)1);
    ok(Value == AFTER_UNLOAD_CODE, "Thread started after the unload: 0x%lx\n", Value);

    /* A second load starts from the template again, in the old thread and the loading one */
    hDll = LoadTlsDll();
    if (!hDll)
        goto Cleanup;
    ok(pTlsDynGetValue() == TEMPLATE_VALUE, "Loading thread after a reload: 0x%lx\n", pTlsDynGetValue());
    ok(WorkerGet() == TEMPLATE_VALUE, "Thread started before the first load, after a reload\n");
    WorkerSet(0x0E0E);
    ok(WorkerGet() == 0x0E0E, "Thread started before the first load, after a reload and a set\n");
    ok(pTlsDynGetValue() == TEMPLATE_VALUE, "The other thread's set changed this thread's copy: 0x%lx\n", pTlsDynGetValue());
    ok(FreeLibrary(hDll), "FreeLibrary failed: %lu\n", GetLastError());

    TestLoadCycles();
    TestFlsAtThreadExit();
    TestFlsSetAtThreadDetach();
    /* F1I1E1: the callback ran with the thread's data and TLS, before the process detach T0M0. Windows 10 detaches the last thread first. */
    RunFlsExitChild(argv[0], "main", "F1I1E1T0M0", NULL, 3);
    RunFlsExitChild(argv[0], "other", "T2M2F1I1E1T0M0", NULL, 5);
    RunFlsExitChild(argv[0], "last", "F1I1E1T0M0", "F1I1E1T3M3T0M0", 6);
    /* An exception that a callback raises ends the process, at exit and in a thread that ends; nothing reaches the pipe */
    RunFlsExitChild(argv[0], "raise-process", "", NULL, 0xE0001234);
    RunFlsExitChild(argv[0], "raise-thread", "", NULL, 0xE0001234);

    /* Failures */
    TestProtectedTemplate(argv[0]);
    GetModuleFileNameW(NULL, DllPath, ARRAYSIZE(DllPath));
    Slash = wcsrchr(DllPath, L'\\');
    if (Slash)
    {
        StringCchCopyW(Slash + 1, ARRAYSIZE(DllPath) - (Slash + 1 - DllPath), L"kernel32_tlsdyn.dll");
        TestOldVectorOfLoadingThread(argv[0], DllPath);
        TestBadImage(DllPath, FALSE);
        TestBadImage(DllPath, TRUE);
    }

Cleanup:
    Command = CMD_EXIT;
    SetEvent(CommandEvent);
    ok(WaitForSingleObject(hWorker, 10000) == WAIT_OBJECT_0, "The worker did not exit\n");
    CloseHandle(hWorker);
    CloseHandle(CommandEvent);
    CloseHandle(DoneEvent);
}
