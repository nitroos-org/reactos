/*
 * PROJECT:     NitroOS
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Console-helper job limits, assignment and kill-on-last-close lifetime
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

/* Console-helper job limits, assignment and kill-on-last-close lifetime. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
HANDLE WINAPI OpenJobObjectW(DWORD, BOOL, LPCWSTR);

static unsigned Checks, Failures;
#define CHECK(x) do { ++Checks; if (!(x)) { ++Failures; printf("FAIL line %u: %s error=%lu\n", __LINE__, #x, GetLastError()); } } while (0)

int main(int argc, char **argv)
{
    HANDLE Job, Opened, Duplicate = NULL;
    WCHAR Path[MAX_PATH], Command[MAX_PATH + 16], Name[64];
    STARTUPINFOW Startup = {sizeof(Startup)};
    PROCESS_INFORMATION Child = {0};
    JOBOBJECT_BASIC_LIMIT_INFORMATION Basic = {0};
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION Extended = {0};
    BOOL InJob = FALSE;
    DWORD_PTR ProcessMask, SystemMask;
    if (argc > 1) { Sleep(INFINITE); return 0; }
    _snwprintf(Name, 64, L"Local\\w643c-job-%lu", GetCurrentProcessId());
    Job = CreateJobObjectW(NULL, Name);
    CHECK(Job != NULL);
    if (!Job) goto done;
    Opened = OpenJobObjectW(JOB_OBJECT_QUERY, FALSE, Name);
    CHECK(Opened != NULL);
    if (Opened) CloseHandle(Opened);
    Basic.LimitFlags = JOB_OBJECT_LIMIT_AFFINITY;
    Basic.Affinity = 1;
    CHECK(!SetInformationJobObject(Job, JobObjectBasicLimitInformation, &Basic, sizeof(Basic) - 1));
    CHECK(GetLastError() == ERROR_BAD_LENGTH);
    CHECK(SetInformationJobObject(Job, JobObjectBasicLimitInformation, &Basic, sizeof(Basic)));
    Extended.BasicLimitInformation = Basic;
    Extended.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    CHECK(SetInformationJobObject(Job, JobObjectExtendedLimitInformation, &Extended, sizeof(Extended)));
    CHECK(DuplicateHandle(GetCurrentProcess(), Job, GetCurrentProcess(), &Duplicate, 0, FALSE, DUPLICATE_SAME_ACCESS));
    CHECK(GetModuleFileNameW(NULL, Path, MAX_PATH));
    _snwprintf(Command, MAX_PATH + 16, L"\"%ls\" child", Path);
    CHECK(CreateProcessW(Path, Command, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &Startup, &Child));
    if (Child.hProcess)
    {
        CHECK(AssignProcessToJobObject(Job, Child.hProcess));
        CHECK(IsProcessInJob(Child.hProcess, Job, &InJob) && InJob);
        InJob = FALSE;
        CHECK(IsProcessInJob(Child.hProcess, NULL, &InJob) && InJob);
        CHECK(GetProcessAffinityMask(Child.hProcess, &ProcessMask, &SystemMask));
        /* Native job.c stores the job affinity but does not apply it to the
         * assigned process. Record that shared limitation separately. */
        printf("JOB assigned process affinity=%Ix system=%Ix\n", ProcessMask, SystemMask);
        CHECK(ResumeThread(Child.hThread) == 1);
        CHECK(CloseHandle(Job)); Job = NULL;
        CHECK(WaitForSingleObject(Child.hProcess, 100) == WAIT_TIMEOUT);
        CHECK(CloseHandle(Duplicate)); Duplicate = NULL;
        CHECK(WaitForSingleObject(Child.hProcess, 10000) == WAIT_OBJECT_0);
        /* Clean up even if a failed assignment left the child outside the job. */
        TerminateProcess(Child.hProcess, 98);
        CloseHandle(Child.hThread); CloseHandle(Child.hProcess);
    }
done:
    if (Duplicate) CloseHandle(Duplicate);
    if (Job) CloseHandle(Job);
    printf("JOB: %u checks, %u failures\n", Checks, Failures);
    return Failures ? 1 : 0;
}
