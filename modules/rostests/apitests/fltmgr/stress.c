/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0+ (https://spdx.org/licenses/GPL-2.0+)
 * PURPOSE:     File system load with filters in the stack (load, bootcheck, stress)
 *
 *   load       loads two sample filters and leaves them loaded, for the programs that run after it
 *   bootcheck  the first time: sets the sample filter up to start with the system. After the next boot:
 *              checks that it is loaded, got its instances and sees operations.
 *   stress     file operations with data checks from several threads for FLTMGR_STRESS_SECONDS (60),
 *              while filters come and go
 */

#include "precomp.h"
#include <fltuser.h>

#define BOOT_NAME L"FltSampleBoot"

START_TEST(load)
{
    SAMPLE A = { { 0 } }, B = { { 0 } };

    EnsureTestDirectory();
    if (!StartFilterManager() ||
        !LoadSample(&A, L"FltSampleA", L"380000.5", 0xFFFF) ||
        !LoadSample(&B, L"FltSampleB", L"380000.25", 0xFFFF))
    {
        skip("Can't load the sample filters\n");
        return;
    }
    ok(TRUE, "loaded\n");
    /* Deliberately not unloaded */
    CloseHandle(A.Control);
    CloseHandle(B.Control);
}

static
BOOL
ServiceExists(PCWSTR Name)
{
    SC_HANDLE Manager = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS), Service;
    BOOL Ret = FALSE;

    if (Manager)
    {
        Service = OpenServiceW(Manager, Name, SERVICE_QUERY_STATUS);
        if (Service)
        {
            Ret = TRUE;
            CloseServiceHandle(Service);
        }
        CloseServiceHandle(Manager);
    }
    return Ret;
}

START_TEST(bootcheck)
{
    SC_HANDLE Manager, Service;
    SAMPLE Boot = { { 0 } };
    FLTSAMPLE_STATS S;
    WCHAR Device[64], Path[MAX_PATH];
    HANDLE File;

    EnsureTestDirectory();

    if (!ServiceExists(BOOT_NAME))
    {
        /* The first boot: the sample as a filter which starts with the system, after the filter manager */
        if (!LoadSample(&Boot, BOOT_NAME, L"370000", 0xFFFF))
        {
            skip("Can't set the sample filter up\n");
            return;
        }
        CloseHandle(Boot.Control);
        FilterUnload(BOOT_NAME);

        Manager = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
        ok(Manager != NULL, "OpenSCManager failed\n");
        if (Manager)
        {
            Service = OpenServiceW(Manager, BOOT_NAME, SERVICE_ALL_ACCESS);
            ok(ChangeServiceConfigW(Service, SERVICE_NO_CHANGE, SERVICE_AUTO_START, SERVICE_NO_CHANGE,
                                    NULL, NULL, NULL, L"fltmgr\0", NULL, NULL, NULL), "ChangeServiceConfig failed: %lu\n", GetLastError());
            CloseServiceHandle(Service);

            Service = OpenServiceW(Manager, L"fltmgr", SERVICE_ALL_ACCESS);
            ok(ChangeServiceConfigW(Service, SERVICE_NO_CHANGE, SERVICE_AUTO_START, SERVICE_NO_CHANGE,
                                    NULL, NULL, NULL, NULL, NULL, NULL, NULL), "ChangeServiceConfig(fltmgr) failed: %lu\n", GetLastError());
            CloseServiceHandle(Service);
            CloseServiceHandle(Manager);
        }
        trace("BOOTCHECK: installed\n");
        return;
    }

    /* The next boot: it is there without anybody having loaded it */
    StringCbPrintfW(Device, sizeof(Device), L"\\\\.\\%ls", BOOT_NAME);
    Boot.Control = CreateFileW(Device, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    ok(Boot.Control != INVALID_HANDLE_VALUE, "The sample filter isn't loaded after the boot: %lu\n", GetLastError());
    if (Boot.Control == INVALID_HANDLE_VALUE)
        return;

    ok(SampleStats(&Boot, &S), "No statistics\n");
    ok(S.LiveInstances >= 1 && S.InstanceSetups >= 1, "%lu instances after the boot\n", S.LiveInstances);
    ok(S.VolumeCount >= 1, "%lu volumes\n", S.VolumeCount);

    GetTestDirectory(Path, RTL_NUMBER_OF(Path));
    StringCbCatW(Path, sizeof(Path), L"\\boot.txt");
    File = CreateFileW(Path, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    ok(File != INVALID_HANDLE_VALUE, "Create failed: %lu\n", GetLastError());
    if (File != INVALID_HANDLE_VALUE)
        CloseHandle(File);
    SampleStats(&Boot, &S);
    ok(S.Pre[IRP_MJ_CREATE] >= 1 && S.Post[IRP_MJ_CREATE] >= 1, "The filter saw %lu creates\n", S.Pre[IRP_MJ_CREATE]);
    trace("BOOTCHECK: %lu instances, %lu creates\n", S.LiveInstances, S.Pre[IRP_MJ_CREATE]);
    DeleteFileW(Path);
    CloseHandle(Boot.Control);
}

typedef struct _STRESS
{
    volatile LONG Stop;
    volatile LONG Operations;
    volatile LONG Errors;
    volatile LONG Cycles;
    WCHAR FirstError[160];

} STRESS;

typedef struct _WORKER
{
    STRESS *Stress;
    ULONG Id;

} WORKER;

static
void
Fail(STRESS *Stress, PCWSTR What, ULONG Error)
{
    if (InterlockedIncrement(&Stress->Errors) == 1)
        StringCbPrintfW(Stress->FirstError, sizeof(Stress->FirstError), L"%ls: %lu", What, Error);
}

static
void
Pattern(PUCHAR Buffer, ULONG Length, ULONG Seed)
{
    ULONG i, State = Seed * 2654435761u + 12345;

    for (i = 0; i < Length; i++)
    {
        State = State * 1103515245u + 12345;
        Buffer[i] = (UCHAR)(State >> 16);
    }
}

static
DWORD
WINAPI
Worker(PVOID Parameter)
{
    WORKER *Self = Parameter;
    STRESS *Stress = Self->Stress;
    WCHAR Directory[MAX_PATH], Path[MAX_PATH], Moved[MAX_PATH], Name[64];
    PUCHAR Write, Read;
    ULONG Counter = 0;
    PCWSTR Extensions[] = { L"txt", L"half", L"safe", L"sync", L"pend" };

    Write = HeapAlloc(GetProcessHeap(), 0, 65536);
    Read = HeapAlloc(GetProcessHeap(), 0, 65536);
    GetTestDirectory(Directory, RTL_NUMBER_OF(Directory));
    StringCbPrintfW(Directory + lstrlenW(Directory), sizeof(Directory) - lstrlenW(Directory) * sizeof(WCHAR), L"\\w%lu", Self->Id);
    CreateDirectoryW(Directory, NULL);

    while (!Stress->Stop)
    {
        ULONG Size = 1 + (Counter * 7919 + Self->Id * 104729) % 65535;
        PCWSTR Extension = Extensions[Counter % 5];
        HANDLE File;
        DWORD Done, Offset;
        WIN32_FIND_DATAW Find;
        HANDLE Search;
        ULONG Found = 0;

        /* The ".half" files are written in halves by the filter: they get no data check */
        BOOL Checked = wcscmp(Extension, L"half") != 0;

        StringCbPrintfW(Name, sizeof(Name), L"f%lu.%ls", Counter, Extension);
        StringCbPrintfW(Path, sizeof(Path), L"%ls\\%ls", Directory, Name);
        StringCbPrintfW(Moved, sizeof(Moved), L"%ls\\m%lu.%ls", Directory, Counter, Extension);
        Pattern(Write, Size, Counter + Self->Id * 1000003);

        File = CreateFileW(Path, GENERIC_READ | GENERIC_WRITE | DELETE, 0, NULL, CREATE_ALWAYS, 0, NULL);
        if (File == INVALID_HANDLE_VALUE)
        {
            Fail(Stress, L"create", GetLastError());
            break;
        }

        if (!WriteFile(File, Write, Size, &Done, NULL) || Done == 0 || (Checked && Done != Size))
            Fail(Stress, L"write", GetLastError());
        if (Counter % 4 == 0)
            FlushFileBuffers(File);

        if (Checked)
        {
            ZeroMemory(Read, Size);
            Offset = SetFilePointer(File, 0, NULL, FILE_BEGIN);
            if (Offset != 0 || !ReadFile(File, Read, Size, &Done, NULL) || Done != Size || memcmp(Read, Write, Size))
                Fail(Stress, L"read back", GetLastError());
        }

        if (Size > 100 && Checked)
        {
            SetFilePointer(File, Size / 2, NULL, FILE_BEGIN);
            if (!SetEndOfFile(File))
                Fail(Stress, L"truncate", GetLastError());
            SetFilePointer(File, 0, NULL, FILE_BEGIN);
            if (!ReadFile(File, Read, Size, &Done, NULL) || Done != Size / 2 || memcmp(Read, Write, Size / 2))
                Fail(Stress, L"read after truncate", GetLastError());
        }
        CloseHandle(File);

        if (!MoveFileW(Path, Moved))
            Fail(Stress, L"rename", GetLastError());

        StringCbPrintfW(Path, sizeof(Path), L"%ls\\*", Directory);
        Search = FindFirstFileW(Path, &Find);
        if (Search != INVALID_HANDLE_VALUE)
        {
            do { Found++; } while (FindNextFileW(Search, &Find));
            FindClose(Search);
        }
        if (Found < 3)
            Fail(Stress, L"directory listing", Found);

        if (!DeleteFileW(Moved))
            Fail(Stress, L"delete", GetLastError());

        Counter++;
        InterlockedIncrement(&Stress->Operations);
    }

    HeapFree(GetProcessHeap(), 0, Write);
    HeapFree(GetProcessHeap(), 0, Read);
    return 0;
}

static
DWORD
WINAPI
Churn(PVOID Parameter)
{
    STRESS *Stress = Parameter;
    SAMPLE B = { { 0 } };
    HANDLE Port;
    HRESULT hr;

    /* A filter loaded and unloaded in turn, with a client on its port, while the files are in use */
    while (!Stress->Stop)
    {
        if (!LoadSample(&B, L"FltSampleChurn", L"350000", 0xFFFF))
        {
            Fail(Stress, L"load", GetLastError());
            break;
        }
        {
            ULONG Delay = 5;

            SampleIoctl(&B, FLTSAMPLE_IOCTL_SET_PEND_DELAY, &Delay, sizeof(Delay), NULL, 0);
        }
        hr = FilterConnectCommunicationPort(L"\\FltSampleChurnPort", 0, NULL, 0, NULL, &Port);
        if (SUCCEEDED(hr))
            CloseHandle(Port);
        Sleep(3000);
        if (!UnloadSample(&B, FALSE))
        {
            Fail(Stress, L"unload", 0);
            break;
        }
        InterlockedIncrement(&Stress->Cycles);
        Sleep(1000);
    }
    return 0;
}

START_TEST(stress)
{
    STRESS Stress = { 0 };
    SAMPLE A = { { 0 } };
    HANDLE Thread[5];
    WCHAR Text[16];
    ULONG Seconds = 60, i;
    DWORD Start;
    FLTSAMPLE_STATS S;

    if (GetEnvironmentVariableW(L"FLTMGR_STRESS_SECONDS", Text, RTL_NUMBER_OF(Text)))
        Seconds = _wtoi(Text);

    EnsureTestDirectory();
    if (!StartFilterManager() || !LoadSample(&A, L"FltSampleA", L"380000.5", 0xFFFF))
    {
        skip("Can't load the sample filter\n");
        return;
    }

    {
        ULONG Delay = 5;

        SampleIoctl(&A, FLTSAMPLE_IOCTL_SET_PEND_DELAY, &Delay, sizeof(Delay), NULL, 0);
    }

    for (i = 0; i < 4; i++)
    {
        WORKER *Worker_ = HeapAlloc(GetProcessHeap(), 0, sizeof(*Worker_));

        Worker_->Stress = &Stress;
        Worker_->Id = i;
        Thread[i] = CreateThread(NULL, 0, Worker, Worker_, 0, NULL);
    }
    Thread[4] = CreateThread(NULL, 0, Churn, &Stress, 0, NULL);

    Start = GetTickCount();
    while (GetTickCount() - Start < Seconds * 1000)
    {
        Sleep(1000);
        if (Stress.Errors)
            break;
    }

    InterlockedExchange(&Stress.Stop, 1);
    WaitForMultipleObjects(RTL_NUMBER_OF(Thread), Thread, TRUE, 120000);

    SampleStats(&A, &S);
    ok(Stress.Errors == 0, "%ld errors, the first: %ls\n", Stress.Errors, Stress.FirstError);
    ok(Stress.Operations > 0, "No operations\n");
    ok(S.Pre[IRP_MJ_WRITE] > 0 && S.Post[IRP_MJ_WRITE] == S.Pre[IRP_MJ_WRITE], "Writes: %lu pre, %lu post\n", S.Pre[IRP_MJ_WRITE], S.Post[IRP_MJ_WRITE]);
    trace("STRESS: %lu seconds, %ld rounds, %ld filter load/unload cycles, %lu creates %lu writes %lu reads seen by the filter\n",
          Seconds, Stress.Operations, Stress.Cycles, S.Pre[IRP_MJ_CREATE], S.Pre[IRP_MJ_WRITE], S.Pre[IRP_MJ_READ]);

    UnloadSample(&A, TRUE);
    ok(A.LastLive == 0, "%lu instances left\n", A.LastLive);
    ok(A.LastCtxAlloc == A.LastCtxCleaned, "%lu contexts allocated, %lu freed\n", A.LastCtxAlloc, A.LastCtxCleaned);
}
