/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0+ (https://spdx.org/licenses/GPL-2.0+)
 * PURPOSE:     Tests of the contexts of the filter manager: instance, volume, stream and stream handle
 */

#include "precomp.h"

static
HANDLE
OpenCtxFile(PCWSTR Name, DWORD Disposition)
{
    WCHAR Path[MAX_PATH];

    MakeTestFile(Name, Path, RTL_NUMBER_OF(Path));
    return CreateFileW(Path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                       NULL, Disposition, 0, NULL);
}

/* The close of a file comes a bit after the CloseHandle: wait for the statistics to say what we expect */
static
BOOL
WaitForCleaned(PSAMPLE A, ULONG Index, ULONG Expected, PFLTSAMPLE_STATS S)
{
    ULONG i;

    for (i = 0; i < 1000; i++)
    {
        SampleStats(A, S);
        if (S->CleanedByType[Index] == Expected)
            return TRUE;
        Sleep(20);
    }
    return FALSE;
}

static
void
test_FileContexts(PSAMPLE A)
{
    FLTSAMPLE_STATS S;
    WCHAR Path[MAX_PATH];
    HANDLE File1, File2;
    DWORD Done;
    char Buffer[64];
    ULONG BaseHandle, BaseStream;

    MakeTestFile(L"ctx.txt", Path, RTL_NUMBER_OF(Path));
    DeleteFileW(Path);
    SampleStats(A, &S);
    BaseHandle = S.CleanedByType[3];
    BaseStream = S.CleanedByType[2];
    SampleIoctl(A, FLTSAMPLE_IOCTL_RESET, NULL, 0, NULL, 0);

    /* The first open of a stream makes the stream context, every open its own handle context */
    File1 = OpenCtxFile(L"ctx.txt", CREATE_ALWAYS);
    ok(File1 != INVALID_HANDLE_VALUE, "Create failed: %lu\n", GetLastError());
    SampleStats(A, &S);
    ok(S.Contexts[FLTSAMPLE_CTX_STREAM_NEW] == 1, "%lu stream contexts made\n", S.Contexts[FLTSAMPLE_CTX_STREAM_NEW]);
    ok(S.Contexts[FLTSAMPLE_CTX_HANDLE_NEW] == 1, "%lu handle contexts made\n", S.Contexts[FLTSAMPLE_CTX_HANDLE_NEW]);

    FillMemory(Buffer, sizeof(Buffer), 'c');
    ok(WriteFile(File1, Buffer, sizeof(Buffer), &Done, NULL), "Write failed: %lu\n", GetLastError());
    SetFilePointer(File1, 0, NULL, FILE_BEGIN);
    ok(ReadFile(File1, Buffer, sizeof(Buffer), &Done, NULL), "Read failed: %lu\n", GetLastError());
    SampleStats(A, &S);
    ok(S.Contexts[FLTSAMPLE_CTX_HANDLE_HITS] >= 2, "%lu handle contexts found by the operations\n", S.Contexts[FLTSAMPLE_CTX_HANDLE_HITS]);
    ok(S.Contexts[FLTSAMPLE_CTX_STREAM_HITS] >= 2, "%lu stream contexts found by the operations\n", S.Contexts[FLTSAMPLE_CTX_STREAM_HITS]);
    ok(S.Contexts[FLTSAMPLE_CTX_INSTANCE_HITS] >= 2, "%lu instance contexts found\n", S.Contexts[FLTSAMPLE_CTX_INSTANCE_HITS]);
    ok(S.Contexts[FLTSAMPLE_CTX_VOLUME_HITS] >= 1, "%lu volume contexts found\n", S.Contexts[FLTSAMPLE_CTX_VOLUME_HITS]);
    ok(S.ContextMismatch == 0, "%lu contexts with the wrong content\n", S.ContextMismatch);

    /* The second open of the stream finds the context of the first */
    File2 = OpenCtxFile(L"ctx.txt", OPEN_EXISTING);
    ok(File2 != INVALID_HANDLE_VALUE, "Open failed: %lu\n", GetLastError());
    SampleStats(A, &S);
    ok(S.Contexts[FLTSAMPLE_CTX_STREAM_NEW] == 1, "%lu stream contexts made for two opens\n", S.Contexts[FLTSAMPLE_CTX_STREAM_NEW]);
    ok(S.Contexts[FLTSAMPLE_CTX_HANDLE_NEW] == 2, "%lu handle contexts made for two opens\n", S.Contexts[FLTSAMPLE_CTX_HANDLE_NEW]);

    /* A handle context goes with its handle, the stream context with the last one. (The context
     * which the sample made for the second open and found to be one too many was freed already.) */
    SampleStats(A, &S);
    BaseHandle = S.CleanedByType[3];
    BaseStream = S.CleanedByType[2];
    FlushFileBuffers(File1);
    FlushFileBuffers(File2);
    /* (The cache manager keeps the file object of the first open until the stream is uncached, so that one goes second) */
    CloseHandle(File2);
    ok(WaitForCleaned(A, 3, BaseHandle + 1, &S), "%lu handle contexts freed after the first close\n", S.CleanedByType[3] - BaseHandle);
    ok(S.CleanedByType[2] == BaseStream, "The stream context was freed with one open left\n");
    CloseHandle(File1);

    /* One open only: both contexts go with it */
    DeleteFileW(Path);
    SampleStats(A, &S);
    BaseHandle = S.CleanedByType[3];
    BaseStream = S.CleanedByType[2];
    File1 = OpenCtxFile(L"ctx2.txt", CREATE_ALWAYS);
    ok(File1 != INVALID_HANDLE_VALUE, "Create failed: %lu\n", GetLastError());
    ok(WriteFile(File1, Buffer, sizeof(Buffer), &Done, NULL), "Write failed: %lu\n", GetLastError());
    FlushFileBuffers(File1);
    CloseHandle(File1);
    /* The file system holds the file object for its cache for a while, how long isn't up to us */
    if (WaitForCleaned(A, 3, BaseHandle + 1, &S))
    {
        ok(WaitForCleaned(A, 2, BaseStream + 1, &S), "%lu stream contexts freed after the close\n", S.CleanedByType[2] - BaseStream);
    }
    else
    {
        skip("The file system hasn't closed the file after 20 seconds\n");
    }
    MakeTestFile(L"ctx2.txt", Path, RTL_NUMBER_OF(Path));
    ok(S.ContextMismatch == 0, "%lu contexts with the wrong content\n", S.ContextMismatch);
    DeleteFileW(Path);
}

static
void
test_Behaviour(PSAMPLE A)
{
    FLTSAMPLE_STATS S;
    ULONG R[16] = { 0 };

    /* The functions of the contexts, on an instance context */
    ok(SampleIoctl(A, FLTSAMPLE_IOCTL_CONTEXT_SELFTEST, NULL, 0, R, sizeof(R)), "No self test\n");
    ok(R[0] == STATUS_FLT_INVALID_CONTEXT_REGISTRATION, "Allocation of a wrong size: 0x%lx\n", R[0]);
    ok(R[13] == STATUS_FLT_CONTEXT_ALLOCATION_NOT_FOUND, "Allocation of a type nobody registered: 0x%lx\n", R[13]);
    ok(R[1] == STATUS_SUCCESS && R[2] == STATUS_SUCCESS, "Allocate and set: 0x%lx, 0x%lx\n", R[1], R[2]);
    ok(R[3] == STATUS_FLT_CONTEXT_ALREADY_DEFINED, "Set to keep: 0x%lx\n", R[3]);
    ok(R[4] == 1, "Set to keep didn't return the context in place\n");
    ok(R[5] == STATUS_SUCCESS, "Set to replace: 0x%lx\n", R[5]);
    ok(R[6] == 1, "Set to replace didn't return the old context\n");
    ok(R[7] == 1, "The old context was freed before it was released\n");
    ok(R[8] == 1, "The old context wasn't freed with its last reference\n");
    ok(R[9] == 1, "The context found isn't the one set\n");
    ok(R[10] == STATUS_SUCCESS, "Delete: 0x%lx\n", R[10]);
    ok(R[11] == 1, "The context was freed while a reference was left\n");
    ok(R[12] == 1, "The context wasn't freed with its last reference\n");
    ok(R[14] == STATUS_NOT_FOUND, "Get after the delete: 0x%lx\n", R[14]);

    SampleStats(A, &S);
    ok(S.ContextMismatch == 0, "%lu contexts with the wrong content\n", S.ContextMismatch);
}

static
void
test_Teardown(void)
{
    SAMPLE B = { { 0 } };
    FLTSAMPLE_STATS S;
    ATTACH_RESULT Result;
    HANDLE File;
    ULONG Live;

    if (!LoadSample(&B, L"FltSampleB", L"380000.25", 0xFFFF))
    {
        skip("Can't load the sample filter\n");
        return;
    }

    /* Contexts of a file which stays open are freed when the instance goes */
    File = OpenCtxFile(L"open.txt", CREATE_ALWAYS);
    ok(File != INVALID_HANDLE_VALUE, "Create failed: %lu\n", GetLastError());
    SampleStats(&B, &S);
    Live = S.LiveInstances;
    ok(S.Contexts[FLTSAMPLE_CTX_HANDLE_NEW] >= 1 && S.Contexts[FLTSAMPLE_CTX_STREAM_NEW] >= 1, "No contexts made\n");

    ZeroMemory(&Result, sizeof(Result));
    ok(SampleIoctl(&B, FLTSAMPLE_IOCTL_DETACH_ALL, NULL, 0, &Result, sizeof(Result)), "No detach\n");
    ok(Result.Done == Live, "Detached %lu of %lu\n", Result.Done, Live);
    SampleStats(&B, &S);
    ok(S.CleanedByType[0] >= Live, "%lu instance contexts freed for %lu instances\n", S.CleanedByType[0], Live);
    ok(S.CleanedByType[2] >= 1 && S.CleanedByType[3] >= 1, "Stream contexts %lu, handle contexts %lu freed by the detach\n", S.CleanedByType[2], S.CleanedByType[3]);
    ok(S.Contexts[FLTSAMPLE_CTX_ALLOCATED] - S.Contexts[FLTSAMPLE_CTX_CLEANED] <= 1,
       "%lu contexts allocated, %lu freed\n", S.Contexts[FLTSAMPLE_CTX_ALLOCATED], S.Contexts[FLTSAMPLE_CTX_CLEANED]);
    CloseHandle(File);

    /* Nothing is left behind when the filter goes either: the volume context is the last to go */
    UnloadSample(&B, TRUE);
    ok(B.LastCtxAlloc != 0xDEADBEEF && B.LastCtxAlloc == B.LastCtxCleaned, "%lu contexts allocated, %lu freed\n", B.LastCtxAlloc, B.LastCtxCleaned);
    WCHAR Path[MAX_PATH];
    MakeTestFile(L"open.txt", Path, RTL_NUMBER_OF(Path));
    DeleteFileW(Path);
}

static
void
test_UnloadWithOpenFiles(void)
{
    SAMPLE A = { { 0 } };
    HANDLE File[8];
    ULONG i;
    WCHAR Name[32], Path[MAX_PATH];

    if (!LoadSample(&A, L"FltSampleA", L"380000.5", 0xFFFF))
    {
        skip("Can't load the sample filter\n");
        return;
    }

    for (i = 0; i < RTL_NUMBER_OF(File); i++)
    {
        StringCbPrintfW(Name, sizeof(Name), L"many%lu.txt", i);
        File[i] = OpenCtxFile(Name, CREATE_ALWAYS);
        ok(File[i] != INVALID_HANDLE_VALUE, "Create %lu failed: %lu\n", i, GetLastError());
    }

    UnloadSample(&A, TRUE);
    ok(A.LastCtxAlloc != 0xDEADBEEF && A.LastCtxAlloc == A.LastCtxCleaned, "%lu contexts allocated, %lu freed\n", A.LastCtxAlloc, A.LastCtxCleaned);

    /* The files go on being files */
    for (i = 0; i < RTL_NUMBER_OF(File); i++)
    {
        DWORD Done;

        ok(WriteFile(File[i], "x", 1, &Done, NULL) && Done == 1, "Write to file %lu after the unload failed: %lu\n", i, GetLastError());
        CloseHandle(File[i]);
        StringCbPrintfW(Name, sizeof(Name), L"many%lu.txt", i);
        MakeTestFile(Name, Path, RTL_NUMBER_OF(Path));
        DeleteFileW(Path);
    }
}

START_TEST(context)
{
    SAMPLE A = { { 0 } };

    EnsureTestDirectory();
    if (!StartFilterManager() ||
        !LoadSample(&A, L"FltSampleA", L"380000.5", 0xFFFF))
    {
        skip("Can't load the sample filter\n");
        return;
    }

    test_FileContexts(&A);
    test_Behaviour(&A);
    UnloadSample(&A, TRUE);

    test_Teardown();
    test_UnloadWithOpenFiles();
}
