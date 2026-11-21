/*
 * PROJECT:     ReactOS API Tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     diskpart.exe writes what it reports: "delete partition" on a GPT disk and "set id" / "active" /
 *              "inactive" on an MBR disk change the partition table on the disk. Every check reads the disk again
 *              with a new diskpart process.
 *              Needs a scratch disk: the number of a blank disk in the environment variable DISKPART_SCRATCH_DISK.
 *              It is converted and cleaned; without the variable, or when the disk has a partition, the test is skipped.
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include <apitest.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define OUT_SIZE 16384

static char DiskNumber[16];

/* Runs "diskpart /s" with the script text; the output goes to Out. Returns FALSE when diskpart could not run. */
static BOOL RunScript(const char *Text, char *Out, size_t OutSize)
{
    char Dir[MAX_PATH], Script[MAX_PATH], Tmp[MAX_PATH], Sys[MAX_PATH], Cmd[3 * MAX_PATH];
    SECURITY_ATTRIBUTES Sa = { sizeof(Sa), NULL, TRUE };
    STARTUPINFOA Si = { sizeof(Si) };
    PROCESS_INFORMATION Pi;
    HANDLE h;
    DWORD Got = 0;

    GetTempPathA(sizeof(Dir), Dir);
    GetTempFileNameA(Dir, "dpw", 0, Script);
    h = CreateFileA(Script, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE)
        return FALSE;
    WriteFile(h, Text, (DWORD)strlen(Text), &Got, NULL);
    CloseHandle(h);

    GetTempFileNameA(Dir, "dpo", 0, Tmp);
    h = CreateFileA(Tmp, GENERIC_WRITE, FILE_SHARE_READ, &Sa, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE)
        return FALSE;
    GetSystemDirectoryA(Sys, sizeof(Sys));
    sprintf(Cmd, "\"%s\\diskpart.exe\" /s \"%s\"", Sys, Script);
    Si.dwFlags = STARTF_USESTDHANDLES;
    Si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    Si.hStdOutput = h;
    Si.hStdError = h;
    if (!CreateProcessA(NULL, Cmd, NULL, NULL, TRUE, 0, NULL, NULL, &Si, &Pi))
    {
        ok(0, "cannot start %s: %lu\n", Cmd, GetLastError());
        CloseHandle(h);
        DeleteFileA(Tmp);
        DeleteFileA(Script);
        return FALSE;
    }
    if (WaitForSingleObject(Pi.hProcess, 120000) != WAIT_OBJECT_0)
    {
        TerminateProcess(Pi.hProcess, 99);
        ok(0, "diskpart /s did not end\n");
    }
    CloseHandle(Pi.hProcess);
    CloseHandle(Pi.hThread);
    CloseHandle(h);

    h = CreateFileA(Tmp, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    Got = 0;
    if (h != INVALID_HANDLE_VALUE)
    {
        ReadFile(h, Out, (DWORD)(OutSize - 1), &Got, NULL);
        CloseHandle(h);
    }
    Out[Got] = 0;
    DeleteFileA(Tmp);
    DeleteFileA(Script);
    return TRUE;
}

/* Runs the commands on the scratch disk (after "select disk N") */
static BOOL RunOnDisk(const char *Commands, char *Out, size_t OutSize)
{
    char Text[2048];

    sprintf(Text, "select disk %s\r\n%s", DiskNumber, Commands);
    return RunScript(Text, Out, OutSize);
}

/* The number of rows of "list partition" */
static int CountPartitions(const char *Out)
{
    const char *Line = Out;
    int Count = 0, Number;

    while (Line && *Line)
    {
        const char *Row = Line;

        while (*Row == ' ' || *Row == '*')
            Row++;
        if (sscanf(Row, "Partition %d", &Number) == 1)
            Count++;
        Line = strchr(Line, '\n');
        if (Line)
            Line++;
    }
    return Count;
}

static int ListCount(void)
{
    static char Out[OUT_SIZE];

    if (!RunOnDisk("list partition\r\n", Out, sizeof(Out)))
        return -1;
    return CountPartitions(Out);
}

/* The value of a line of "detail partition" ("Type          : 07"): points into Out, NULL when there is none */
static const char *DetailValue(char *Out, const char *Key)
{
    char *p = strstr(Out, Key);

    if (!p)
        return NULL;
    p = strchr(p, ':');
    if (!p)
        return NULL;
    p++;
    while (*p == ' ')
        p++;
    return p;
}

static void TestGptDelete(void)
{
    static char Out[OUT_SIZE];

    ok(RunOnDisk("convert gpt\r\n", Out, sizeof(Out)), "no convert\n");
    ok(RunOnDisk("create partition primary size=16\r\ncreate partition primary size=16\r\n"
                 "create partition primary size=16\r\n", Out, sizeof(Out)), "no create\n");
    ok(ListCount() == 3, "three partitions expected after creating them: %d\n", ListCount());

    ok(RunOnDisk("select partition 2\r\ndelete partition override\r\n", Out, sizeof(Out)), "no delete\n");
    ok(strstr(Out, "successfully deleted") != NULL, "delete does not report success:\n%s\n", Out);
    ok(ListCount() == 2, "two partitions expected after the delete, a new diskpart sees %d\n", ListCount());

    ok(RunOnDisk("select partition 1\r\ndelete partition override\r\n", Out, sizeof(Out)), "no delete\n");
    ok(ListCount() == 1, "one partition expected after the second delete, a new diskpart sees %d\n", ListCount());

    ok(RunOnDisk("clean\r\n", Out, sizeof(Out)), "no clean\n");
    ok(ListCount() == 0, "no partition expected after clean: %d\n", ListCount());
}

static void TestMbrChanges(void)
{
    static char Out[OUT_SIZE];
    const char *Value;

    ok(RunOnDisk("convert mbr\r\n", Out, sizeof(Out)), "no convert\n");
    ok(RunOnDisk("create partition primary size=16 noerr\r\ncreate partition primary size=16\r\n", Out, sizeof(Out)),
       "no create\n");
    ok(ListCount() == 2, "two partitions expected after creating them: %d\n", ListCount());

    /* set id: the new type is in the table, the offset and the length are the same */
    ok(RunOnDisk("select partition 2\r\nset id=83\r\n", Out, sizeof(Out)), "no set id\n");
    ok(RunOnDisk("select partition 2\r\ndetail partition\r\n", Out, sizeof(Out)), "no detail\n");
    Value = DetailValue(Out, "Type");
    ok(Value && !_strnicmp(Value, "83", 2), "type 83 expected after set id: %.20s\n", Value ? Value : "(none)");

    ok(RunOnDisk("select partition 2\r\nset id=07\r\n", Out, sizeof(Out)), "no set id\n");
    ok(strstr(Out, "changed successfully") != NULL, "set id does not report success:\n%s\n", Out);
    ok(RunOnDisk("select partition 2\r\ndetail partition\r\n", Out, sizeof(Out)), "no detail\n");
    Value = DetailValue(Out, "Type");
    ok(Value && !_strnicmp(Value, "07", 2), "type 07 expected after set id: %.20s\n", Value ? Value : "(none)");
    ok(ListCount() == 2, "two partitions expected: %d\n", ListCount());

    /* the other partition keeps its type */
    ok(RunOnDisk("select partition 1\r\ndetail partition\r\n", Out, sizeof(Out)), "no detail\n");
    Value = DetailValue(Out, "Type");
    ok(Value && _strnicmp(Value, "07", 2) != 0, "partition 1 has changed its type too: %.20s\n", Value ? Value : "(none)");

    /* active / inactive: the boot flag */
    ok(RunOnDisk("select partition 1\r\nactive\r\n", Out, sizeof(Out)), "no active\n");
    ok(RunOnDisk("select partition 1\r\ndetail partition\r\n", Out, sizeof(Out)), "no detail\n");
    Value = DetailValue(Out, "Active");
    ok(Value && !_strnicmp(Value, "Yes", 3), "partition 1 is active: %.20s\n", Value ? Value : "(none)");

    ok(RunOnDisk("select partition 1\r\ninactive\r\n", Out, sizeof(Out)), "no inactive\n");
    ok(RunOnDisk("select partition 1\r\ndetail partition\r\n", Out, sizeof(Out)), "no detail\n");
    Value = DetailValue(Out, "Active");
    ok(Value && !_strnicmp(Value, "No", 2), "partition 1 is not active: %.20s\n", Value ? Value : "(none)");

    ok(RunOnDisk("clean\r\n", Out, sizeof(Out)), "no clean\n");
    ok(ListCount() == 0, "no partition expected after clean: %d\n", ListCount());
}

START_TEST(diskpart_write)
{
    static char Out[OUT_SIZE];
    const char *Disk = getenv("DISKPART_SCRATCH_DISK");

    if (!Disk || !*Disk || strlen(Disk) >= sizeof(DiskNumber) || strspn(Disk, "0123456789") != strlen(Disk))
    {
        skip("DISKPART_SCRATCH_DISK (the number of a blank scratch disk) is not set\n");
        return;
    }
    strcpy(DiskNumber, Disk);

    /* Never touch a disk that has a partition */
    if (!RunOnDisk("list partition\r\n", Out, sizeof(Out)) || strstr(Out, "no partitions") == NULL)
    {
        skip("disk %s is not blank:\n%s\n", DiskNumber, Out);
        return;
    }

    TestGptDelete();
    TestMbrChanges();
}
