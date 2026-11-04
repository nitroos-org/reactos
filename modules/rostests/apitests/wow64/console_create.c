/*
 * PROJECT:     NitroOS
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     console_create
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

/* Concurrent console creation must survive another console's destruction. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>

#define TOTAL 48
#define ACTIVE 4
static unsigned Checks, Failures;
#define CHECK(x) do { ++Checks; if (!(x)) { ++Failures; printf("FAIL line %u: %s error=%lu\n", __LINE__, #x, GetLastError()); } } while (0)

int main(int argc, char **argv)
{
    char Application[MAX_PATH], Command[MAX_PATH + 32];
    STARTUPINFOA Startup = {sizeof(Startup)};
    PROCESS_INFORMATION Process;
    HANDLE Children[ACTIVE];
    DWORD Code, Wait, Bytes, Mode, Begin = GetTickCount();
    unsigned Started = 0, Finished = 0, Count = 0, i;
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc > 1)
    {
        if (!GetConsoleMode(GetStdHandle(STD_OUTPUT_HANDLE), &Mode) ||
            !WriteConsoleA(GetStdHandle(STD_OUTPUT_HANDLE), "console", 7, &Bytes, NULL) || Bytes != 7)
            return 2;
        Sleep(25);
        return 37;
    }
    CHECK(GetModuleFileNameA(NULL, Application, MAX_PATH));
    while (Finished < TOTAL && GetTickCount() - Begin < 60000)
    {
        while (Count < ACTIVE && Started < TOTAL)
        {
            _snprintf(Command, sizeof(Command), "\"%s\" child", Application);
            if (!CreateProcessA(Application, Command, NULL, NULL, FALSE, CREATE_NEW_CONSOLE,
                                NULL, NULL, &Startup, &Process))
            {
                CHECK(FALSE);
                goto Cleanup;
            }
            Children[Count++] = Process.hProcess;
            CloseHandle(Process.hThread);
            ++Started;
        }
        Wait = WaitForMultipleObjects(Count, Children, FALSE, 10000);
        CHECK(Wait >= WAIT_OBJECT_0 && Wait < WAIT_OBJECT_0 + Count);
        if (Wait < WAIT_OBJECT_0 || Wait >= WAIT_OBJECT_0 + Count) break;
        i = Wait - WAIT_OBJECT_0;
        CHECK(GetExitCodeProcess(Children[i], &Code) && Code == 37);
        CloseHandle(Children[i]);
        Children[i] = Children[--Count];
        ++Finished;
    }
Cleanup:
    for (i = 0; i < Count; ++i)
    {
        TerminateProcess(Children[i], 99);
        CloseHandle(Children[i]);
    }
    CHECK(Started == TOTAL && Finished == TOTAL);
    printf("CONSOLE CREATE started=%u finished=%u checks=%u failures=%u\n", Started, Finished, Checks, Failures);
    return Failures ? 1 : 0;
}
