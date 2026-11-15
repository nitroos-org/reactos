/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     A process or thread that is still being created must not be reachable by its
 *              id: a handle opened to it before its creator has inserted it into the object
 *              manager made the creator's ObInsertObject fail ("attempting to insert
 *              existing object", a break into the debugger / bugcheck 0x1E).
 *              The test creates processes and threads while other threads open every id
 *              near the newest one; the system must survive and every open must either
 *              fail or give a handle that works.
 */

#include "precomp.h"

#define MAX_TICKS       8000
#define OPENERS         3
#define CREATORS        2
#define ID_SLACK        256
#define RECENT          4
#define NEAR_IDS            8     /* ids tried on each side of a recent id, in steps of 4 */

static volatile LONG g_Done;
static volatile LONG g_MaxId;        /* highest process or thread id seen so far */
static volatile LONG g_Recent[RECENT];  /* the ids of the newest children: a new id is usually one of these */
static volatile LONG g_RecentNext;
static volatile LONG g_Opened;
static volatile LONG g_BadHandles;   /* opens that gave a handle that does not work */

static VOID NoteId(ULONG Id)
{
    LONG Old;

    g_Recent[(ULONG)InterlockedIncrement(&g_RecentNext) % RECENT] = (LONG)Id;
    do
    {
        Old = g_MaxId;
        if ((LONG)Id <= Old)
            return;
    } while (InterlockedCompareExchange(&g_MaxId, (LONG)Id, Old) != Old);
}

static DWORD WINAPI OpenerThread(PVOID Context)
{
    BOOLEAN Threads = (BOOLEAN)(ULONG_PTR)Context;
    OBJECT_ATTRIBUTES Attributes;
    CLIENT_ID Cid;
    HANDLE Handle;
    NTSTATUS Status;
    ULONG_PTR Id, Max;
    ULONG Sweeps = 0, Step;

    InitializeObjectAttributes(&Attributes, NULL, 0, NULL, NULL);

    while (!g_Done)
    {
        /* Most sweeps look only near the newest ids, every 64th one looks at all of them */
        Sweeps++;
        SwitchToThread();
        Max = (ULONG_PTR)g_MaxId + ID_SLACK;
        for (Step = 0; !g_Done; Step++)
        {
            if (Sweeps % 64 == 0)
            {
                Id = 4 + 4 * (ULONG_PTR)Step;
                if (Id > Max)
                    break;
            }
            else
            {
                LONG Base;

                if (Step >= RECENT * (2 * NEAR_IDS + 1))
                    break;
                Base = g_Recent[Step / (2 * NEAR_IDS + 1)];
                Id = (ULONG_PTR)(Base + 4 * ((LONG)(Step % (2 * NEAR_IDS + 1)) - NEAR_IDS));
                if (Base == 0 || (LONG)Id < 4)
                    continue;
            }

            Handle = NULL;
            if (Threads)
            {
                Cid.UniqueProcess = (HANDLE)(ULONG_PTR)GetCurrentProcessId();
                Cid.UniqueThread = (HANDLE)Id;
                Status = NtOpenThread(&Handle, THREAD_QUERY_LIMITED_INFORMATION, &Attributes, &Cid);
            }
            else
            {
                Cid.UniqueProcess = (HANDLE)Id;
                Cid.UniqueThread = NULL;
                Status = NtOpenProcess(&Handle, PROCESS_QUERY_LIMITED_INFORMATION, &Attributes, &Cid);
            }

            if (NT_SUCCESS(Status))
            {
                InterlockedIncrement(&g_Opened);
                if (Threads)
                {
                    THREAD_BASIC_INFORMATION Basic;
                    Status = NtQueryInformationThread(Handle, ThreadBasicInformation,
                                                      &Basic, sizeof(Basic), NULL);
                }
                else
                {
                    PROCESS_BASIC_INFORMATION Basic;
                    Status = NtQueryInformationProcess(Handle, ProcessBasicInformation,
                                                       &Basic, sizeof(Basic), NULL);
                }
                if (!NT_SUCCESS(Status))
                    InterlockedIncrement(&g_BadHandles);
                NtClose(Handle);
            }
        }
    }
    return 0;
}

static DWORD WINAPI ExitThreadProc(PVOID Context)
{
    return 0;
}

static WCHAR g_Cmd[2][MAX_PATH + 32];   /* the 64-bit (or native) cmd.exe, and the 32-bit one if there is one */
static ULONG g_CmdCount;
static volatile LONG g_Created;
static volatile LONG g_Failed;

static DWORD WINAPI ProcessCreator(PVOID Context)
{
    ULONG n = 0;

    while (!g_Done)
    {
        STARTUPINFOW Startup = { sizeof(Startup) };
        PROCESS_INFORMATION Info;
        WCHAR Cmd[MAX_PATH + 32];

        StringCchCopyW(Cmd, RTL_NUMBER_OF(Cmd), g_Cmd[n++ % g_CmdCount]);
        if (CreateProcessW(NULL, Cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &Startup, &Info))
        {
            NoteId(Info.dwProcessId);
            WaitForSingleObject(Info.hProcess, 10000);
            CloseHandle(Info.hThread);
            CloseHandle(Info.hProcess);
            InterlockedIncrement(&g_Created);
        }
        else
            InterlockedIncrement(&g_Failed);
    }
    return 0;
}

static DWORD WINAPI ThreadCreator(PVOID Context)
{
    while (!g_Done)
    {
        DWORD Tid;
        HANDLE Thread = CreateThread(NULL, 0, ExitThreadProc, NULL, 0, &Tid);
        if (Thread)
        {
            NoteId(Tid);
            WaitForSingleObject(Thread, INFINITE);
            CloseHandle(Thread);
            InterlockedIncrement(&g_Created);
        }
        else
            InterlockedIncrement(&g_Failed);
    }
    return 0;
}

static VOID RunPhase(BOOLEAN Threads, PCSTR Name)
{
    HANDLE Openers[OPENERS];
    HANDLE Creators[CREATORS];
    ULONG i;

    g_Done = 0;
    g_Opened = 0;
    g_BadHandles = 0;
    g_Created = 0;
    g_Failed = 0;
    g_MaxId = GetCurrentProcessId();

    for (i = 0; i < OPENERS; i++)
    {
        Openers[i] = CreateThread(NULL, 0, OpenerThread, (PVOID)(ULONG_PTR)Threads, 0, NULL);
        ok(Openers[i] != NULL, "%s: CreateThread for the opener failed\n", Name);
    }
    for (i = 0; i < CREATORS; i++)
    {
        Creators[i] = CreateThread(NULL, 0, Threads ? ThreadCreator : ProcessCreator, NULL, 0, NULL);
        ok(Creators[i] != NULL, "%s: CreateThread for the creator failed\n", Name);
    }

    Sleep(MAX_TICKS);

    g_Done = 1;
    for (i = 0; i < OPENERS; i++)
    {
        if (Openers[i])
        {
            WaitForSingleObject(Openers[i], 30000);
            CloseHandle(Openers[i]);
        }
    }
    for (i = 0; i < CREATORS; i++)
    {
        if (Creators[i])
        {
            WaitForSingleObject(Creators[i], 30000);
            CloseHandle(Creators[i]);
        }
    }

    ok(g_Created > 0, "%s: nothing was created\n", Name);
    ok(g_Failed == 0, "%s: %ld creations failed (of %ld)\n", Name, g_Failed, g_Created + g_Failed);
    ok(g_BadHandles == 0, "%s: %ld opened handles could not be queried\n", Name, g_BadHandles);
    trace("%s: %ld created, %ld opens succeeded\n", Name, g_Created, g_Opened);
}

START_TEST(NtOpenCreateRace)
{
    WCHAR Dir[MAX_PATH];
    UINT Len = GetSystemDirectoryW(Dir, MAX_PATH);

    StringCchPrintfW(g_Cmd[0], RTL_NUMBER_OF(g_Cmd[0]), L"%s\\cmd.exe /c exit 0", Dir);
    g_CmdCount = 1;

    /* On a 64-bit system with WoW64 the 32-bit cmd.exe is a second kind of child */
    if (Len && GetEnvironmentVariableW(L"SystemRoot", Dir, MAX_PATH))
    {
        WCHAR Path[MAX_PATH + 32];

        StringCchPrintfW(Path, RTL_NUMBER_OF(Path), L"%s\\SysWOW64\\cmd.exe", Dir);
        if (GetFileAttributesW(Path) != INVALID_FILE_ATTRIBUTES)
        {
            StringCchPrintfW(g_Cmd[1], RTL_NUMBER_OF(g_Cmd[1]), L"%s /c exit 0", Path);
            g_CmdCount = 2;
        }
    }

    RunPhase(FALSE, "process");
    RunPhase(TRUE, "thread");
}
