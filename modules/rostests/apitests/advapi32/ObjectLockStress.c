/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Handle churn with access checks on many named objects of one type while other threads set their security
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * The object manager's per-type object locks (4 slots by object address) are taken when a handle is created or
 * closed and when a security descriptor is referenced or replaced. Worker threads open, duplicate and close handles
 * of many named events, object directories and registry keys (each open runs an access check against the
 * descriptor), while two threads replace the descriptors of the same objects, for OBJLOCK_SECONDS seconds
 * (default 3). The test fails when no thread makes progress for 30 seconds. Kernel hangs and deadlocks show up
 * as that.
 */

#include "precomp.h"
#include <aclapi.h>
#include <ndk/obfuncs.h>
#include <ndk/exfuncs.h>

#define OBJECTS         48
#define WORKERS         8
#define SETTERS         2
#define HANG_SECONDS    30

typedef struct
{
    WCHAR Dir[64];
    HANDLE Event[OBJECTS];
    HANDLE Directory[OBJECTS];
    HKEY Key[OBJECTS];
    WCHAR EventName[OBJECTS][40];
    WCHAR DirectoryName[OBJECTS][80];
    WCHAR KeyName[OBJECTS][80];
} SET;

static SET Set;
static volatile LONG Stop;
static volatile LONG Progress;
static volatile LONG Errors;
static PACL Dacls[2];
static PSID Everyone;

static ULONG Rand(ULONG *Seed)
{
    *Seed = *Seed * 1103515245 + 12345;
    return (*Seed >> 8) & 0xffffff;
}

static DWORD WINAPI Worker(PVOID Param)
{
    ULONG Seed = (ULONG)(ULONG_PTR)Param * 7919 + GetCurrentThreadId();
    HANDLE Handle, Copy;
    HKEY Key;

    while (!Stop)
    {
        ULONG i = Rand(&Seed) % OBJECTS;

        switch (Rand(&Seed) % 6)
        {
        case 0:
            Handle = OpenEventW(SYNCHRONIZE | EVENT_MODIFY_STATE, FALSE, Set.EventName[i]);
            if (Handle)
            {
                if (DuplicateHandle(GetCurrentProcess(), Handle, GetCurrentProcess(), &Copy, SYNCHRONIZE, FALSE, 0))
                    CloseHandle(Copy);
                CloseHandle(Handle);
            }
            break;
        case 1:
            Handle = OpenEventW(READ_CONTROL, FALSE, Set.EventName[i]);
            if (Handle) CloseHandle(Handle);
            break;
        case 2:
        {
            UNICODE_STRING Name;
            OBJECT_ATTRIBUTES Oa;

            RtlInitUnicodeString(&Name, Set.DirectoryName[i]);
            InitializeObjectAttributes(&Oa, &Name, 0, NULL, NULL);
            if (NT_SUCCESS(NtOpenDirectoryObject(&Handle, DIRECTORY_QUERY | DIRECTORY_TRAVERSE, &Oa)))
            {
                if (DuplicateHandle(GetCurrentProcess(), Handle, GetCurrentProcess(), &Copy, 0, FALSE, DUPLICATE_SAME_ACCESS))
                    CloseHandle(Copy);
                CloseHandle(Handle);
            }
            break;
        }
        case 3:
            if (RegOpenKeyExW(HKEY_CURRENT_USER, Set.KeyName[i], 0, KEY_READ, &Key) == ERROR_SUCCESS)
            {
                if (DuplicateHandle(GetCurrentProcess(), Key, GetCurrentProcess(), &Copy, 0, FALSE, DUPLICATE_SAME_ACCESS))
                    CloseHandle(Copy);
                RegCloseKey(Key);
            }
            break;
        case 4:
            /* An open through a handle that is closed right away, from another object of the same type */
            Handle = CreateEventW(NULL, TRUE, FALSE, NULL);
            if (Handle) CloseHandle(Handle);
            break;
        default:
            if (DuplicateHandle(GetCurrentProcess(), Set.Event[i], GetCurrentProcess(), &Copy, 0, FALSE, DUPLICATE_SAME_ACCESS))
                CloseHandle(Copy);
            break;
        }
        InterlockedIncrement(&Progress);
    }
    return 0;
}

static DWORD WINAPI Setter(PVOID Param)
{
    ULONG Seed = (ULONG)(ULONG_PTR)Param * 104729 + GetCurrentThreadId();
    SECURITY_DESCRIPTOR Sd;

    InitializeSecurityDescriptor(&Sd, SECURITY_DESCRIPTOR_REVISION);
    while (!Stop)
    {
        ULONG i = Rand(&Seed) % OBJECTS;
        PACL Acl = (Rand(&Seed) & 1) ? Dacls[0] : Dacls[1];

        SetSecurityDescriptorDacl(&Sd, TRUE, Acl, FALSE);
        if (!SetKernelObjectSecurity(Set.Event[i], DACL_SECURITY_INFORMATION, &Sd)) InterlockedIncrement(&Errors);
        if (!SetKernelObjectSecurity(Set.Directory[i], DACL_SECURITY_INFORMATION, &Sd)) InterlockedIncrement(&Errors);
        if (RegSetKeySecurity(Set.Key[i], DACL_SECURITY_INFORMATION, &Sd) != ERROR_SUCCESS) InterlockedIncrement(&Errors);
        InterlockedIncrement(&Progress);
    }
    return 0;
}

START_TEST(ObjectLockStress)
{
    SID_IDENTIFIER_AUTHORITY World = { SECURITY_WORLD_SID_AUTHORITY };
    WCHAR Env[16], RootName[64];
    DWORD Seconds = 3, Start, Last, Now;
    HANDLE Threads[WORKERS + SETTERS];
    LONG Seen = 0;
    ULONG i;
    DWORD Pid = GetCurrentProcessId();
    DWORD Size;
    HKEY Root;

    Size = GetEnvironmentVariableW(L"OBJLOCK_SECONDS", Env, 16);
    if (Size > 0 && Size < 16) Seconds = _wtoi(Env);

    ok(AllocateAndInitializeSid(&World, 1, SECURITY_WORLD_RID, 0, 0, 0, 0, 0, 0, 0, &Everyone), "SID\n");
    for (i = 0; i < 2; i++)
    {
        Dacls[i] = HeapAlloc(GetProcessHeap(), 0, 256);
        InitializeAcl(Dacls[i], 256, ACL_REVISION);
        AddAccessAllowedAce(Dacls[i], ACL_REVISION, i ? GENERIC_READ | SYNCHRONIZE | EVENT_MODIFY_STATE : GENERIC_ALL, Everyone);
    }

    StringCchPrintfW(Set.Dir, ARRAYSIZE(Set.Dir), L"\\BaseNamedObjects\\ols%lu", Pid);
    StringCchPrintfW(RootName, ARRAYSIZE(RootName), L"Software\\OLS%lu", Pid);
    ok_int(RegCreateKeyExW(HKEY_CURRENT_USER, RootName, 0, NULL, 0, KEY_ALL_ACCESS, NULL, &Root, NULL), ERROR_SUCCESS);
    for (i = 0; i < OBJECTS; i++)
    {
        UNICODE_STRING Name;
        OBJECT_ATTRIBUTES Oa;

        StringCchPrintfW(Set.EventName[i], ARRAYSIZE(Set.EventName[i]), L"ols%lu_%lu", Pid, i);
        Set.Event[i] = CreateEventW(NULL, TRUE, FALSE, Set.EventName[i]);
        StringCchPrintfW(Set.DirectoryName[i], ARRAYSIZE(Set.DirectoryName[i]), L"\\BaseNamedObjects\\ols%lu_d%lu", Pid, i);
        RtlInitUnicodeString(&Name, Set.DirectoryName[i]);
        InitializeObjectAttributes(&Oa, &Name, 0, NULL, NULL);
        ok_ntstatus(NtCreateDirectoryObject(&Set.Directory[i], DIRECTORY_ALL_ACCESS, &Oa), STATUS_SUCCESS);
        StringCchPrintfW(Set.KeyName[i], ARRAYSIZE(Set.KeyName[i]), L"Software\\OLS%lu\\k%lu", Pid, i);
        ok_int(RegCreateKeyExW(HKEY_CURRENT_USER, Set.KeyName[i], 0, NULL, 0, KEY_ALL_ACCESS, NULL, &Set.Key[i], NULL), ERROR_SUCCESS);
        if (!Set.Event[i] || !Set.Directory[i] || !Set.Key[i]) return;
    }

    for (i = 0; i < WORKERS + SETTERS; i++)
        Threads[i] = CreateThread(NULL, 0, i < WORKERS ? Worker : Setter, (PVOID)(ULONG_PTR)(i + 1), 0, NULL);

    Start = Last = GetTickCount();
    while ((Now = GetTickCount()) - Start < Seconds * 1000)
    {
        LONG Current;

        Sleep(500);
        Current = Progress;
        if (Current != Seen)
        {
            Seen = Current;
            Last = Now;
        }
        else if (Now - Last > HANG_SECONDS * 1000)
        {
            ok(0, "No progress for %d seconds: the object locks are deadlocked\n", HANG_SECONDS);
            ExitProcess(2);
        }
    }
    InterlockedExchange(&Stop, 1);
    for (i = 0; i < WORKERS + SETTERS; i++)
    {
        ok(WaitForSingleObject(Threads[i], HANG_SECONDS * 1000) == WAIT_OBJECT_0, "thread %lu did not finish\n", i);
        CloseHandle(Threads[i]);
    }
    trace("%ld rounds in %lu s, %ld security errors\n", Progress, Seconds, Errors);
    ok(Progress > 0, "no progress\n");
    ok(Errors == 0, "%ld security calls failed\n", Errors);

    for (i = 0; i < OBJECTS; i++)
    {
        CloseHandle(Set.Event[i]);
        CloseHandle(Set.Directory[i]);
        RegCloseKey(Set.Key[i]);
        RegDeleteKeyW(HKEY_CURRENT_USER, Set.KeyName[i]);
    }
    RegCloseKey(Root);
    RegDeleteKeyW(HKEY_CURRENT_USER, RootName);
    FreeSid(Everyone);
}
