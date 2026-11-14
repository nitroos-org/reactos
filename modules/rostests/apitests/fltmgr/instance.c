/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0+ (https://spdx.org/licenses/GPL-2.0+)
 * PURPOSE:     Tests of altitudes, instances and their setup and teardown
 */

#include "precomp.h"
#include <fltuser.h>

static
void
TouchFile(PCWSTR Name)
{
    WCHAR Path[MAX_PATH];
    HANDLE File;

    MakeTestFile(Name, Path, RTL_NUMBER_OF(Path));
    File = CreateFileW(Path, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_ALWAYS, 0, NULL);
    ok(File != INVALID_HANDLE_VALUE, "Can't create %ls: %lu\n", Path, GetLastError());
    if (File != INVALID_HANDLE_VALUE)
        CloseHandle(File);
}

static
void
test_Altitudes(void)
{
    SAMPLE A = { { 0 } }, B = { { 0 } }, C = { { 0 } };
    FLTSAMPLE_STATS Sa, Sb, Sc;
    BOOL Strict = FALSE, OrderOk;
    ULONG Fs = CurrentFileSystem();
    ULONG i, Try;

    /* Altitudes are decimal numbers: 9999 is below 380000.25, and 380000.5 is above it, as strings it'd be all different */
    if (!LoadSample(&A, L"FltSampleA", L"380000.5", 0xFFFF) ||
        !LoadSample(&B, L"FltSampleB", L"380000.25", 0xFFFF) ||
        !LoadSample(&C, L"FltSampleC", L"9999", 0xFFFF))
    {
        skip("Can't load the sample filters\n");
        goto Cleanup;
    }

    ok(SampleStats(&A, &Sa) && SampleStats(&B, &Sb) && SampleStats(&C, &Sc), "No statistics\n");
    ok(Sa.InstanceSetups >= 1, "A: %lu instance setups\n", Sa.InstanceSetups);
    ok(Sa.LiveInstances == Sa.InstanceSetups, "A: %lu live instances for %lu setups\n", Sa.LiveInstances, Sa.InstanceSetups);
    ok(Sa.VolumeCount >= Sa.LiveInstances, "A: %lu volumes, %lu instances\n", Sa.VolumeCount, Sa.LiveInstances);
    ok(Sb.InstanceSetups == Sa.InstanceSetups, "B: %lu instance setups, A had %lu\n", Sb.InstanceSetups, Sa.InstanceSetups);
    ok(Sc.InstanceSetups == Sa.InstanceSetups, "C: %lu instance setups, A had %lu\n", Sc.InstanceSetups, Sa.InstanceSetups);
    if (Fs)
        ok(Sa.SetupsByFsType[Fs] >= 1, "A: no setup for the file system of the system volume (type %lu)\n", Fs);

    /* The operations go through the instances from the highest altitude down, and the post-operations back up */
    for (i = 0; i < 5; i++)
    {
        for (Try = 0; Try < 3; Try++)
        {
            TouchFile(L"order.txt");
            SampleStats(&A, &Sa);
            SampleStats(&B, &Sb);
            SampleStats(&C, &Sc);
            OrderOk = Sa.LastCreatePre <= Sb.LastCreatePre && Sb.LastCreatePre <= Sc.LastCreatePre &&
                      Sc.LastCreatePost <= Sb.LastCreatePost && Sb.LastCreatePost <= Sa.LastCreatePost;
            if (OrderOk)
                break;
        }
        ok(OrderOk, "Order of the callbacks: pre %I64d %I64d %I64d, post %I64d %I64d %I64d\n",
           Sa.LastCreatePre, Sb.LastCreatePre, Sc.LastCreatePre,
           Sa.LastCreatePost, Sb.LastCreatePost, Sc.LastCreatePost);
        if (Sa.LastCreatePre < Sc.LastCreatePre)
            Strict = TRUE;
    }
    ok(Strict, "The pre-operations never ran in different moments\n");

Cleanup:
    if (C.ServiceCreated) UnloadSample(&C, FALSE);
    if (B.ServiceCreated) UnloadSample(&B, FALSE);
    if (A.ServiceCreated) UnloadSample(&A, FALSE);
}

static
void
test_Collision(void)
{
    SAMPLE A = { { 0 } }, E = { { 0 } };
    FLTSAMPLE_STATS Se;

    /* The same altitude, written another way: a volume has room for one of them only */
    if (!LoadSample(&A, L"FltSampleA", L"380000.5", 0xFFFF))
    {
        skip("Can't load the sample filter\n");
        goto Cleanup;
    }

    if (!LoadSample(&E, L"FltSampleE", L"0380000.50", 0xFFFF))
    {
        skip("Can't load the second sample filter\n");
        goto Cleanup;
    }

    ok(SampleStats(&E, &Se), "No statistics\n");
    ok(Se.LiveInstances == 0, "%lu instances of the filter with a taken altitude\n", Se.LiveInstances);
    ok(Se.InstanceSetups == 0, "The filter with a taken altitude was asked to set up %lu instances\n", Se.InstanceSetups);

Cleanup:
    if (E.ServiceCreated) UnloadSample(&E, FALSE);
    if (A.ServiceCreated) UnloadSample(&A, FALSE);
}

static
void
test_Setup(void)
{
    SAMPLE D = { { 0 } };
    FLTSAMPLE_STATS Sd;
    ATTACH_RESULT Result;

    /* A filter which doesn't want any volume gets none */
    if (!LoadSample(&D, L"FltSampleD", L"190000", 0))
    {
        skip("Can't load the sample filter\n");
        goto Cleanup;
    }

    ok(SampleStats(&D, &Sd), "No statistics\n");
    ok(Sd.InstanceSetups == 0 && Sd.LiveInstances == 0, "%lu setups, %lu instances\n", Sd.InstanceSetups, Sd.LiveInstances);
    ok(Sd.VolumeCount >= 1, "%lu volumes known to the filter manager\n", Sd.VolumeCount);

    ZeroMemory(&Result, sizeof(Result));
    ok(SampleIoctl(&D, FLTSAMPLE_IOCTL_ATTACH_ALL, NULL, 0, &Result, sizeof(Result)), "No attach\n");
    ok(Result.Done == 0 && Result.Failed == Sd.VolumeCount, "Attached %lu, refused %lu of %lu volumes\n",
       Result.Done, Result.Failed, Sd.VolumeCount);
    ok(Result.LastStatus == STATUS_FLT_DO_NOT_ATTACH, "Last status 0x%lx\n", Result.LastStatus);

Cleanup:
    if (D.ServiceCreated) UnloadSample(&D, FALSE);
}

static
void
test_ManualAttach(void)
{
    SAMPLE B = { { 0 } };
    FLTSAMPLE_STATS Sb, Sb2;
    ATTACH_RESULT Result;
    ULONG Refuse = 1, Allow = 0;
    ULONG Count;

    if (!LoadSample(&B, L"FltSampleB", L"380000.25", 0xFFFF))
    {
        skip("Can't load the sample filter\n");
        goto Cleanup;
    }

    SampleStats(&B, &Sb);
    Count = Sb.LiveInstances;
    ok(Count >= 1, "No instance\n");

    /* The instance is there already: the same filter can't take the same altitude twice */
    ZeroMemory(&Result, sizeof(Result));
    ok(SampleIoctl(&B, FLTSAMPLE_IOCTL_ATTACH_ALL, NULL, 0, &Result, sizeof(Result)), "No attach\n");
    ok(Result.Done == 0 && Result.Failed == Sb.VolumeCount, "Attached %lu, refused %lu\n", Result.Done, Result.Failed);
    ok(Result.LastStatus == STATUS_FLT_INSTANCE_ALTITUDE_COLLISION ||
       Result.LastStatus == STATUS_FLT_INSTANCE_NAME_COLLISION, "Last status 0x%lx\n", Result.LastStatus);

    /* The filter has a say in a manual detach */
    ok(SampleIoctl(&B, FLTSAMPLE_IOCTL_REFUSE_DETACH, &Refuse, sizeof(Refuse), NULL, 0), "No refuse\n");
    ZeroMemory(&Result, sizeof(Result));
    ok(SampleIoctl(&B, FLTSAMPLE_IOCTL_DETACH_ALL, NULL, 0, &Result, sizeof(Result)), "No detach\n");
    ok(Result.Done == 0 && Result.Failed == Sb.VolumeCount, "Detached %lu, refused %lu\n", Result.Done, Result.Failed);
    ok(Result.LastStatus == STATUS_FLT_DO_NOT_DETACH, "Last status 0x%lx\n", Result.LastStatus);
    SampleStats(&B, &Sb2);
    ok(Sb2.LiveInstances == Count, "%lu instances after the refused detach, had %lu\n", Sb2.LiveInstances, Count);
    ok(Sb2.QueryTeardowns >= Count, "%lu query teardown calls\n", Sb2.QueryTeardowns);

    /* Detached, the filter doesn't see the operations of the volume anymore */
    ok(SampleIoctl(&B, FLTSAMPLE_IOCTL_REFUSE_DETACH, &Allow, sizeof(Allow), NULL, 0), "No refuse\n");
    ZeroMemory(&Result, sizeof(Result));
    ok(SampleIoctl(&B, FLTSAMPLE_IOCTL_DETACH_ALL, NULL, 0, &Result, sizeof(Result)), "No detach\n");
    ok(Result.Done == Sb.VolumeCount, "Detached %lu\n", Result.Done);
    SampleStats(&B, &Sb2);
    ok(Sb2.LiveInstances == 0, "%lu instances after the detach\n", Sb2.LiveInstances);
    ok(Sb2.InstanceTeardownStarts == Sb2.InstanceSetups && Sb2.InstanceTeardownCompletes == Sb2.InstanceSetups,
       "%lu teardown starts, %lu completes, %lu setups\n", Sb2.InstanceTeardownStarts, Sb2.InstanceTeardownCompletes, Sb2.InstanceSetups);
    ok(Sb2.LastTeardownReason == FLTFL_INSTANCE_TEARDOWN_MANUAL, "Teardown reason 0x%lx\n", Sb2.LastTeardownReason);

    SampleIoctl(&B, FLTSAMPLE_IOCTL_RESET, NULL, 0, NULL, 0);
    TouchFile(L"nofilter.txt");
    SampleStats(&B, &Sb2);
    ok(Sb2.Pre[IRP_MJ_CREATE] == 0, "%lu creates seen without an instance\n", Sb2.Pre[IRP_MJ_CREATE]);

    /* And attached again by hand */
    ZeroMemory(&Result, sizeof(Result));
    ok(SampleIoctl(&B, FLTSAMPLE_IOCTL_ATTACH_ALL, NULL, 0, &Result, sizeof(Result)), "No attach\n");
    ok(Result.Done == Sb.VolumeCount, "Attached %lu\n", Result.Done);
    SampleStats(&B, &Sb2);
    ok(Sb2.LiveInstances == Count, "%lu instances\n", Sb2.LiveInstances);
    ok(Sb2.ManualSetups == Count, "%lu manual setups\n", Sb2.ManualSetups);
    TouchFile(L"nofilter.txt");
    SampleStats(&B, &Sb2);
    ok(Sb2.Pre[IRP_MJ_CREATE] >= 1, "No create seen after the attach\n");

Cleanup:
    if (B.ServiceCreated) UnloadSample(&B, FALSE);
}

static
void
test_Unload(void)
{
    SAMPLE A = { { 0 } }, B = { { 0 } };
    FLTSAMPLE_STATS Sa;
    ULONG Refuse = 1, Allow = 0, i;
    HRESULT hr;

    if (!LoadSample(&A, L"FltSampleA", L"380000.5", 0xFFFF) ||
        !LoadSample(&B, L"FltSampleB", L"380000.25", 0xFFFF))
    {
        skip("Can't load the sample filters\n");
        goto Cleanup;
    }

    /* A filter can say it doesn't want to go */
    ok(SampleIoctl(&A, FLTSAMPLE_IOCTL_REFUSE_UNLOAD, &Refuse, sizeof(Refuse), NULL, 0), "No refuse\n");
    hr = FilterUnload(A.Name);
    ok(FAILED(hr), "Unload of a filter which refuses returned 0x%lx\n", (ULONG)hr);
    ok(SampleStats(&A, &Sa) && Sa.LiveInstances >= 1, "The filter which refused the unload lost its instances\n");
    ok(SampleIoctl(&A, FLTSAMPLE_IOCTL_REFUSE_UNLOAD, &Allow, sizeof(Allow), NULL, 0), "No refuse\n");

    hr = FilterUnload(L"NoSuchFilter");
    ok(FAILED(hr), "Unload of a filter which isn't there returned 0x%lx\n", (ULONG)hr);

    /* Unloading takes the instances down with it, and the others go on working */
    UnloadSample(&B, TRUE);
    ok(B.LastLive == 0, "B left %lu instances\n", B.LastLive);
    ok(B.LastSetups != 0xDEADBEEF && B.LastSetups >= 1, "B had %lu setups\n", B.LastSetups);
    ok(B.LastTeardownStarts == B.LastSetups && B.LastTeardownCompletes == B.LastSetups,
       "B: %lu setups, %lu teardown starts, %lu completes\n", B.LastSetups, B.LastTeardownStarts, B.LastTeardownCompletes);
    TouchFile(L"afterunload.txt");
    SampleStats(&A, &Sa);
    ok(Sa.LiveInstances >= 1, "A lost its instances\n");

    /* Again and again */
    for (i = 0; i < 4; i++)
    {
        ok(LoadSample(&B, L"FltSampleB", L"380000.25", 0xFFFF), "Load %lu failed\n", i);
        TouchFile(L"cycle.txt");
        UnloadSample(&B, TRUE);
        ok(B.LastLive == 0 && B.LastSetups == B.LastTeardownCompletes, "Cycle %lu: %lu setups, %lu live, %lu completes\n",
           i, B.LastSetups, B.LastLive, B.LastTeardownCompletes);
    }

    UnloadSample(&A, TRUE);
    ok(A.LastLive == 0, "A left %lu instances\n", A.LastLive);
    TouchFile(L"nofilters.txt");
    return;

Cleanup:
    if (B.ServiceCreated) UnloadSample(&B, FALSE);
    if (A.ServiceCreated) UnloadSample(&A, FALSE);
}

typedef struct _LOAD_STRESS
{
    volatile LONG Stop;
    volatile LONG Operations;
    volatile LONG Failures;
    volatile LONG FirstStep;
    volatile LONG FirstError;

} LOAD_STRESS;

static
void
Fail(LOAD_STRESS *Stress, LONG Step)
{
    if (InterlockedIncrement(&Stress->Failures) == 1)
    {
        Stress->FirstError = GetLastError();
        Stress->FirstStep = Step;
    }
}

static
DWORD
WINAPI
IoThread(PVOID Parameter)
{
    LOAD_STRESS *Stress = Parameter;
    WCHAR Path[MAX_PATH];
    char Buffer[4096];
    ULONG Counter = 0;

    FillMemory(Buffer, sizeof(Buffer), 'x');
    while (!Stress->Stop)
    {
        PCWSTR Names[] = { L"stress1.txt", L"stress2.pend", L"stress3.half", L"stress4.safe" };
        HANDLE File;
        DWORD Done;

        WCHAR Name[64];

        /* Each thread has its own files */
        StringCbPrintfW(Name, sizeof(Name), L"t%lu_%ls", GetCurrentThreadId(), Names[Counter++ % 4]);
        MakeTestFile(Name, Path, RTL_NUMBER_OF(Path));
        File = CreateFileW(Path, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_ALWAYS, 0, NULL);
        if (File == INVALID_HANDLE_VALUE)
        {
            Fail(Stress, 1);
            continue;
        }

        if (!WriteFile(File, Buffer, sizeof(Buffer), &Done, NULL) || Done == 0)
            Fail(Stress, 2);
        else if (SetFilePointer(File, 0, NULL, FILE_BEGIN) != 0)
            Fail(Stress, 3);
        else if (!ReadFile(File, Buffer, sizeof(Buffer), &Done, NULL) || Done == 0)
            Fail(Stress, 4);
        CloseHandle(File);
        InterlockedIncrement(&Stress->Operations);
    }
    return 0;
}

static
void
test_UnloadWhileBusy(void)
{
    SAMPLE A = { { 0 } }, B = { { 0 } };
    LOAD_STRESS Stress = { 0 };
    HANDLE Thread[2];
    ULONG Delay = 20, i;
    LONG Before;

    if (!LoadSample(&A, L"FltSampleA", L"380000.5", 0xFFFF))
    {
        skip("Can't load the sample filter\n");
        return;
    }
    SampleIoctl(&A, FLTSAMPLE_IOCTL_SET_PEND_DELAY, &Delay, sizeof(Delay), NULL, 0);

    Thread[0] = CreateThread(NULL, 0, IoThread, &Stress, 0, NULL);
    Thread[1] = CreateThread(NULL, 0, IoThread, &Stress, 0, NULL);

    /* The filters come and go while the file system is in use, with operations pended in them */
    for (i = 0; i < 6; i++)
    {
        Sleep(100);
        if (!LoadSample(&B, L"FltSampleB", L"380000.25", 0xFFFF))
        {
            skip("Can't load the second sample filter\n");
            break;
        }
        SampleIoctl(&B, FLTSAMPLE_IOCTL_SET_PEND_DELAY, &Delay, sizeof(Delay), NULL, 0);
        Before = Stress.Operations;
        Sleep(150);
        ok(Stress.Operations > Before, "Cycle %lu: no progress with the filters loaded\n", i);
        UnloadSample(&B, TRUE);
        ok(B.LastLive == 0 && B.LastSetups == B.LastTeardownCompletes, "Cycle %lu: %lu setups, %lu live, %lu completes\n",
           i, B.LastSetups, B.LastLive, B.LastTeardownCompletes);
    }

    InterlockedExchange(&Stress.Stop, 1);
    WaitForSingleObject(Thread[0], INFINITE);
    WaitForSingleObject(Thread[1], INFINITE);
    CloseHandle(Thread[0]);
    CloseHandle(Thread[1]);

    ok(Stress.Failures == 0, "%ld of %ld operations failed, the first in step %ld with error %ld\n",
       Stress.Failures, Stress.Operations, Stress.FirstStep, Stress.FirstError);
    ok(Stress.Operations > 20, "Only %ld operations\n", Stress.Operations);
    UnloadSample(&A, TRUE);
    ok(A.LastLive == 0, "A left %lu instances\n", A.LastLive);
}

START_TEST(instance)
{
    WCHAR Directory[MAX_PATH];

    if (!StartFilterManager())
    {
        skip("The filter manager isn't there\n");
        return;
    }

    GetTestDirectory(Directory, RTL_NUMBER_OF(Directory));
    EnsureTestDirectory();

    test_Altitudes();
    test_Collision();
    test_Setup();
    test_ManualAttach();
    test_Unload();
    test_UnloadWhileBusy();
}
