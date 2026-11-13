/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0+ (https://spdx.org/licenses/GPL-2.0+)
 * PURPOSE:     Tests of the pre and post operation callbacks and their results
 */

#include "precomp.h"

#define PEND_MS 300

static
HANDLE
OpenTest(PCWSTR Name, DWORD Disposition, DWORD Flags)
{
    WCHAR Path[MAX_PATH];

    MakeTestFile(Name, Path, RTL_NUMBER_OF(Path));
    return CreateFileW(Path, GENERIC_READ | GENERIC_WRITE | DELETE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                       NULL, Disposition, Flags, NULL);
}

static
void
Remove(PCWSTR Name)
{
    WCHAR Path[MAX_PATH];

    MakeTestFile(Name, Path, RTL_NUMBER_OF(Path));
    SetFileAttributesW(Path, FILE_ATTRIBUTE_NORMAL);
    DeleteFileW(Path);
}

/* The close of a file comes a bit after the CloseHandle */
static
void
WaitForClose(PSAMPLE Sample, ULONG ExpectedOpen)
{
    FLTSAMPLE_STATS Stats;
    ULONG i;

    for (i = 0; i < 50; i++)
    {
        SampleStats(Sample, &Stats);
        if (Stats.OpenFiles <= ExpectedOpen)
            return;
        Sleep(20);
    }
}

static
void
test_Counts(PSAMPLE A)
{
    FLTSAMPLE_STATS S;
    WCHAR Path[MAX_PATH], Directory[MAX_PATH];
    WIN32_FIND_DATAW Find;
    HANDLE File, Search;
    char Buffer[100];
    DWORD Done;
    ULONG BaseOpen;

    SampleStats(A, &S);
    BaseOpen = S.OpenFiles;
    SampleIoctl(A, FLTSAMPLE_IOCTL_RESET, NULL, 0, NULL, 0);

    /* One file through the operations of a file */
    File = OpenTest(L"counts.txt", CREATE_ALWAYS, 0);
    ok(File != INVALID_HANDLE_VALUE, "Create failed: %lu\n", GetLastError());
    SampleStats(A, &S);
    ok(S.Pre[IRP_MJ_CREATE] >= 1 && S.Post[IRP_MJ_CREATE] >= 1, "Create: %lu pre, %lu post\n", S.Pre[IRP_MJ_CREATE], S.Post[IRP_MJ_CREATE]);
    ok(S.OpenFiles == BaseOpen + 1, "%lu open files\n", S.OpenFiles);

    FillMemory(Buffer, sizeof(Buffer), 'a');
    ok(WriteFile(File, Buffer, sizeof(Buffer), &Done, NULL) && Done == sizeof(Buffer), "Write failed: %lu\n", GetLastError());
    ok(FlushFileBuffers(File), "Flush failed: %lu\n", GetLastError());
    SampleStats(A, &S);
    ok(S.Pre[IRP_MJ_WRITE] >= 1 && S.Post[IRP_MJ_WRITE] == S.Pre[IRP_MJ_WRITE], "Write: %lu pre, %lu post\n", S.Pre[IRP_MJ_WRITE], S.Post[IRP_MJ_WRITE]);
    ok(S.LastWritePre <= S.LastWritePost, "Write pre %I64d, post %I64d\n", S.LastWritePre, S.LastWritePost);

    ok(SetFilePointer(File, 0, NULL, FILE_BEGIN) == 0, "Seek failed\n");
    ZeroMemory(Buffer, sizeof(Buffer));
    ok(ReadFile(File, Buffer, sizeof(Buffer), &Done, NULL) && Done == sizeof(Buffer), "Read failed: %lu\n", GetLastError());
    ok(Buffer[0] == 'a' && Buffer[99] == 'a', "Data read back is wrong\n");
    SampleStats(A, &S);
    ok(S.Pre[IRP_MJ_READ] >= 1 && S.Post[IRP_MJ_READ] == S.Pre[IRP_MJ_READ], "Read: %lu pre, %lu post\n", S.Pre[IRP_MJ_READ], S.Post[IRP_MJ_READ]);

    /* Set information, query information */
    ok(SetFilePointer(File, 40, NULL, FILE_BEGIN) == 40 && SetEndOfFile(File), "SetEndOfFile failed: %lu\n", GetLastError());
    ok(GetFileSize(File, NULL) == 40, "File size %lu\n", GetFileSize(File, NULL));
    SampleStats(A, &S);
    ok(S.Pre[IRP_MJ_SET_INFORMATION] >= 1 && S.Post[IRP_MJ_SET_INFORMATION] == S.Pre[IRP_MJ_SET_INFORMATION],
       "Set information: %lu pre, %lu post\n", S.Pre[IRP_MJ_SET_INFORMATION], S.Post[IRP_MJ_SET_INFORMATION]);
    ok(S.Pre[IRP_MJ_QUERY_INFORMATION] >= 1, "No query information\n");

    ok(CloseHandle(File), "Close failed\n");
    WaitForClose(A, BaseOpen);
    SampleStats(A, &S);
    ok(S.Pre[IRP_MJ_CLEANUP] >= 1 && S.Post[IRP_MJ_CLEANUP] == S.Pre[IRP_MJ_CLEANUP], "Cleanup: %lu pre, %lu post\n", S.Pre[IRP_MJ_CLEANUP], S.Post[IRP_MJ_CLEANUP]);
    ok(S.Pre[IRP_MJ_CLOSE] >= 1, "No close\n");
    ok(S.OpenFiles == BaseOpen, "%lu open files, %lu before\n", S.OpenFiles, BaseOpen);

    /* A directory listing */
    GetTestDirectory(Directory, RTL_NUMBER_OF(Directory));
    StringCbPrintfW(Path, sizeof(Path), L"%ls\\*", Directory);
    SampleIoctl(A, FLTSAMPLE_IOCTL_RESET, NULL, 0, NULL, 0);
    Search = FindFirstFileW(Path, &Find);
    ok(Search != INVALID_HANDLE_VALUE, "FindFirstFile failed: %lu\n", GetLastError());
    if (Search != INVALID_HANDLE_VALUE)
    {
        while (FindNextFileW(Search, &Find))
            ;
        FindClose(Search);
    }
    SampleStats(A, &S);
    ok(S.Pre[IRP_MJ_DIRECTORY_CONTROL] >= 1 && S.Post[IRP_MJ_DIRECTORY_CONTROL] == S.Pre[IRP_MJ_DIRECTORY_CONTROL],
       "Directory control: %lu pre, %lu post\n", S.Pre[IRP_MJ_DIRECTORY_CONTROL], S.Post[IRP_MJ_DIRECTORY_CONTROL]);

    /* Reading a missing file is a failure the post-operation hears about */
    SampleIoctl(A, FLTSAMPLE_IOCTL_RESET, NULL, 0, NULL, 0);
    File = OpenTest(L"missing.txt", OPEN_EXISTING, 0);
    ok(File == INVALID_HANDLE_VALUE && GetLastError() == ERROR_FILE_NOT_FOUND, "Open of a missing file: %p, %lu\n", File, GetLastError());
    SampleStats(A, &S);
    ok(S.PostErrors >= 1, "No failure seen in the post-operation\n");
    ok(S.OpenFiles == BaseOpen, "%lu open files after a failed create\n", S.OpenFiles);

    Remove(L"counts.txt");
}

static
void
test_Vetoes(PSAMPLE A)
{
    FLTSAMPLE_STATS S;
    HANDLE File;
    DWORD Done, Error;
    char Buffer[100];
    NTSTATUS Status;
    IO_STATUS_BLOCK Iosb;
    FILE_DISPOSITION_INFORMATION Disposition = { TRUE };

    FillMemory(Buffer, sizeof(Buffer), 'v');
    SampleIoctl(A, FLTSAMPLE_IOCTL_RESET, NULL, 0, NULL, 0);

    /* The create is completed by the pre-operation: no file system is involved, the caller gets the status */
    File = OpenTest(L"refused.blk", CREATE_ALWAYS, 0);
    Error = GetLastError();
    ok(File == INVALID_HANDLE_VALUE && Error == ERROR_ACCESS_DENIED, "Create of .blk: %p, %lu\n", File, Error);
    SampleStats(A, &S);
    ok(S.Vetoed == 1, "%lu vetoes\n", S.Vetoed);
    ok(S.Post[IRP_MJ_CREATE] == 0, "The filter which completed the create got its post-operation (%lu), last create %ls\n", S.Post[IRP_MJ_CREATE], S.LastCreate);

    /* The file is made, the write is refused */
    File = OpenTest(L"readonly.nowr", CREATE_ALWAYS, 0);
    ok(File != INVALID_HANDLE_VALUE, "Create failed: %lu\n", GetLastError());
    ok(!WriteFile(File, Buffer, sizeof(Buffer), &Done, NULL) && GetLastError() == ERROR_ACCESS_DENIED,
       "Write to .nowr: %lu\n", GetLastError());
    ok(GetFileSize(File, NULL) == 0, "File size %lu\n", GetFileSize(File, NULL));
    CloseHandle(File);
    Remove(L"readonly.nowr");

    /* A file which can't be deleted: neither on close nor by disposition */
    File = OpenTest(L"keep.nodel", CREATE_ALWAYS, 0);
    ok(File != INVALID_HANDLE_VALUE, "Create failed: %lu\n", GetLastError());
    Status = NtSetInformationFile(File, &Iosb, &Disposition, sizeof(Disposition), FileDispositionInformation);
    ok(Status == STATUS_ACCESS_DENIED, "Disposition status 0x%lx\n", Status);
    CloseHandle(File);
    File = OpenTest(L"keep.nodel", OPEN_EXISTING, FILE_FLAG_DELETE_ON_CLOSE);
    ok(File == INVALID_HANDLE_VALUE && GetLastError() == ERROR_ACCESS_DENIED, "Delete on close of .nodel: %p, %lu\n", File, GetLastError());
    SampleIoctl(A, FLTSAMPLE_IOCTL_RESET, NULL, 0, NULL, 0);
}

static
void
test_Modify(PSAMPLE A)
{
    FLTSAMPLE_STATS S;
    HANDLE File;
    DWORD Done;
    char Buffer[100];

    FillMemory(Buffer, sizeof(Buffer), 'h');
    SampleIoctl(A, FLTSAMPLE_IOCTL_RESET, NULL, 0, NULL, 0);

    /* A pre-operation changes the length of the write: the caller sees half of it written */
    File = OpenTest(L"short.half", CREATE_ALWAYS, 0);
    ok(File != INVALID_HANDLE_VALUE, "Create failed: %lu\n", GetLastError());
    Done = 0;
    ok(WriteFile(File, Buffer, sizeof(Buffer), &Done, NULL), "Write failed: %lu\n", GetLastError());
    ok(Done == sizeof(Buffer) / 2, "%lu bytes written\n", Done);
    ok(GetFileSize(File, NULL) == sizeof(Buffer) / 2, "File size %lu\n", GetFileSize(File, NULL));
    CloseHandle(File);
    SampleStats(A, &S);
    ok(S.Halved == 1, "%lu writes changed\n", S.Halved);
    Remove(L"short.half");
}

static
void
test_Pend(PSAMPLE A)
{
    FLTSAMPLE_STATS S;
    HANDLE File;
    DWORD Done, Start, Elapsed;
    ULONG Delay = PEND_MS;
    char Buffer[100];

    FillMemory(Buffer, sizeof(Buffer), 'p');
    SampleIoctl(A, FLTSAMPLE_IOCTL_SET_PEND_DELAY, &Delay, sizeof(Delay), NULL, 0);
    SampleIoctl(A, FLTSAMPLE_IOCTL_RESET, NULL, 0, NULL, 0);

    /* The write waits in the pre-operation until another thread lets it go, and then completes */
    File = OpenTest(L"later.pend", CREATE_ALWAYS, 0);
    ok(File != INVALID_HANDLE_VALUE, "Create failed: %lu\n", GetLastError());
    Start = GetTickCount();
    Done = 0;
    {
        IO_STATUS_BLOCK Iosb = { { 0x77777777 }, 0x55555555 };
        NTSTATUS St = NtWriteFile(File, NULL, NULL, NULL, &Iosb, Buffer, sizeof(Buffer), NULL, NULL);
        ok(NT_SUCCESS(St), "NtWriteFile: 0x%lx, iosb 0x%lx %Iu\n", St, Iosb.Status, Iosb.Information);
        Done = (DWORD)Iosb.Information;
    }
    Elapsed = GetTickCount() - Start;
    ok(Done == sizeof(Buffer), "%lu bytes written\n", Done);
    ok(Elapsed >= PEND_MS - 50, "The write took %lu ms\n", Elapsed);
    ok(GetFileSize(File, NULL) == sizeof(Buffer), "File size %lu\n", GetFileSize(File, NULL));
    CloseHandle(File);
    SampleStats(A, &S);
    ok(S.Pended == 1 && S.PendCompleted == 1, "%lu pended, %lu completed\n", S.Pended, S.PendCompleted);
    ok(S.Post[IRP_MJ_WRITE] == S.Pre[IRP_MJ_WRITE], "Write: %lu pre, %lu post\n", S.Pre[IRP_MJ_WRITE], S.Post[IRP_MJ_WRITE]);
    Remove(L"later.pend");
}

static
void
test_Synchronize(PSAMPLE A)
{
    FLTSAMPLE_STATS S;
    HANDLE File;
    DWORD Done;
    char Buffer[100];
    ULONG i;

    FillMemory(Buffer, sizeof(Buffer), 's');
    File = OpenTest(L"same.sync", CREATE_ALWAYS, 0);
    ok(File != INVALID_HANDLE_VALUE, "Create failed: %lu\n", GetLastError());
    ok(WriteFile(File, Buffer, sizeof(Buffer), &Done, NULL), "Write failed: %lu\n", GetLastError());
    SampleIoctl(A, FLTSAMPLE_IOCTL_RESET, NULL, 0, NULL, 0);

    /* FLT_PREOP_SYNCHRONIZE: the post-operation comes in the thread of the pre-operation, below DISPATCH_LEVEL */
    for (i = 0; i < 10; i++)
    {
        SetFilePointer(File, 0, NULL, FILE_BEGIN);
        ok(ReadFile(File, Buffer, sizeof(Buffer), &Done, NULL) && Done == sizeof(Buffer), "Read failed: %lu\n", GetLastError());
    }
    SampleStats(A, &S);
    ok(S.Synchronized >= 10, "%lu synchronized reads\n", S.Synchronized);
    ok(S.SyncSameThread == S.Synchronized, "%lu synchronized reads, %lu in the same thread\n", S.Synchronized, S.SyncSameThread);
    ok(S.SyncPostNotPassive == 0, "%lu post-operations at DISPATCH_LEVEL\n", S.SyncPostNotPassive);
    CloseHandle(File);
    Remove(L"same.sync");
}

static
void
test_Safe(PSAMPLE A)
{
    FLTSAMPLE_STATS S;
    HANDLE File;
    DWORD Done;
    char Buffer[100];
    ULONG i;

    FillMemory(Buffer, sizeof(Buffer), 'f');
    File = OpenTest(L"safe.safe", CREATE_ALWAYS, 0);
    ok(File != INVALID_HANDLE_VALUE, "Create failed: %lu\n", GetLastError());
    ok(WriteFile(File, Buffer, sizeof(Buffer), &Done, NULL), "Write failed: %lu\n", GetLastError());
    SampleIoctl(A, FLTSAMPLE_IOCTL_RESET, NULL, 0, NULL, 0);

    for (i = 0; i < 10; i++)
    {
        SetFilePointer(File, 0, NULL, FILE_BEGIN);
        ok(ReadFile(File, Buffer, sizeof(Buffer), &Done, NULL) && Done == sizeof(Buffer), "Read failed: %lu\n", GetLastError());
    }
    SampleStats(A, &S);
    ok(S.SafePosts >= 10, "%lu reads went through FltDoCompletionProcessingWhenSafe\n", S.SafePosts);
    ok(S.SafeWorkerPassive == S.SafePosts, "%lu safe post-operations, %lu below DISPATCH_LEVEL\n", S.SafePosts, S.SafeWorkerPassive);
    CloseHandle(File);
    Remove(L"safe.safe");
}

static
void
test_Stack(PSAMPLE Upper, PSAMPLE Lower)
{
    FLTSAMPLE_STATS Su, Sl;
    ULONG Off = 0;
    HANDLE File;
    DWORD Error;

    /* The upper filter refuses a create: the lower one doesn't see it */
    SampleIoctl(Upper, FLTSAMPLE_IOCTL_RESET, NULL, 0, NULL, 0);
    SampleIoctl(Lower, FLTSAMPLE_IOCTL_RESET, NULL, 0, NULL, 0);
    File = OpenTest(L"stack.blk", CREATE_ALWAYS, 0);
    Error = GetLastError();
    ok(File == INVALID_HANDLE_VALUE && Error == ERROR_ACCESS_DENIED, "Create: %p, %lu\n", File, Error);
    SampleStats(Upper, &Su);
    SampleStats(Lower, &Sl);
    ok(Su.Vetoed == 1 && Su.Pre[IRP_MJ_CREATE] >= 1, "Upper: %lu vetoes, %lu creates\n", Su.Vetoed, Su.Pre[IRP_MJ_CREATE]);
    ok(Sl.Pre[IRP_MJ_CREATE] == 0, "Lower: %lu creates seen after the upper one refused: %ls\n", Sl.Pre[IRP_MJ_CREATE], Sl.LastCreate);

    /* The lower filter refuses it: the upper one saw it, and hears about the result */
    ok(SampleIoctl(Upper, FLTSAMPLE_IOCTL_SET_VETO, &Off, sizeof(Off), NULL, 0), "No veto setting\n");
    SampleIoctl(Upper, FLTSAMPLE_IOCTL_RESET, NULL, 0, NULL, 0);
    SampleIoctl(Lower, FLTSAMPLE_IOCTL_RESET, NULL, 0, NULL, 0);
    File = OpenTest(L"stack.blk", CREATE_ALWAYS, 0);
    Error = GetLastError();
    ok(File == INVALID_HANDLE_VALUE && Error == ERROR_ACCESS_DENIED, "Create: %p, %lu\n", File, Error);
    SampleStats(Upper, &Su);
    SampleStats(Lower, &Sl);
    ok(Su.Vetoed == 0 && Sl.Vetoed == 1, "Vetoes: %lu upper, %lu lower\n", Su.Vetoed, Sl.Vetoed);
    ok(Su.Pre[IRP_MJ_CREATE] >= 1 && Su.Post[IRP_MJ_CREATE] == Su.Pre[IRP_MJ_CREATE],
       "Upper: %lu pre, %lu post\n", Su.Pre[IRP_MJ_CREATE], Su.Post[IRP_MJ_CREATE]);
    ok(Su.PostErrors == Su.Post[IRP_MJ_CREATE], "Upper: %lu failures seen in %lu post-operations\n", Su.PostErrors, Su.Post[IRP_MJ_CREATE]);
    ok(Sl.Post[IRP_MJ_CREATE] == 0, "Lower: post-operation of the create it completed (%lu)\n", Sl.Post[IRP_MJ_CREATE]);
}

START_TEST(operation)
{
    SAMPLE A = { { 0 } }, B = { { 0 } };

    EnsureTestDirectory();
    if (!StartFilterManager() ||
        !LoadSample(&A, L"FltSampleA", L"380000.5", 0xFFFF))
    {
        skip("Can't load the sample filter\n");
        return;
    }

    test_Counts(&A);
    test_Vetoes(&A);
    test_Modify(&A);
    test_Pend(&A);
    test_Synchronize(&A);
    test_Safe(&A);

    if (LoadSample(&B, L"FltSampleB", L"380000.25", 0xFFFF))
    {
        test_Stack(&A, &B);
        UnloadSample(&B, TRUE);
    }
    else
    {
        skip("Can't load the second sample filter\n");
    }

    UnloadSample(&A, TRUE);
}
