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
/* the exit code of the last diskpart /s: the error level of the first command that failed (0x80070057 = -2147024809) */
static DWORD g_ExitCode;

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
    g_ExitCode = 0;
    GetExitCodeProcess(Pi.hProcess, &g_ExitCode);
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

/*
 * Options that the Windows DiskPart takes (measured on Windows Server 2022): "noerr" on assign, remove, delete partition,
 * set id, uniqueid disk and format lets a failing command go on with the next one of the script, and "create partition
 * extended" takes offset= (KB) like the other partition types.
 */
static void TestOptions(void)
{
    static char Out[OUT_SIZE];
    const char *Value;

    ok(RunOnDisk("convert mbr\r\n", Out, sizeof(Out)), "no convert\n");

    /* a failing command with noerr: the next command of the script runs */
    ok(RunOnDisk("assign noerr\r\nlist partition\r\n", Out, sizeof(Out)), "no assign\n");
    ok(strstr(Out, "no partitions") != NULL, "assign noerr stops the script:\n%s\n", Out);
    ok(strstr(Out, "not supported") == NULL, "assign noerr is refused:\n%s\n", Out);

    ok(RunOnDisk("remove noerr\r\nlist partition\r\n", Out, sizeof(Out)), "no remove\n");
    ok(strstr(Out, "no partitions") != NULL, "remove noerr stops the script:\n%s\n", Out);

    ok(RunOnDisk("delete partition noerr\r\nlist partition\r\n", Out, sizeof(Out)), "no delete\n");
    ok(strstr(Out, "no partitions") != NULL, "delete partition noerr stops the script:\n%s\n", Out);

    ok(RunOnDisk("uniqueid disk id=zz noerr\r\nlist partition\r\n", Out, sizeof(Out)), "no uniqueid\n");
    ok(strstr(Out, "no partitions") != NULL, "uniqueid disk noerr stops the script:\n%s\n", Out);

    ok(RunOnDisk("create partition primary size=16\r\nselect partition 1\r\nset id=zz noerr\r\nlist partition\r\n",
                 Out, sizeof(Out)), "no set id\n");
    ok(ListCount() == 1, "one partition expected after set id noerr: %d\n", ListCount());
    ok(strstr(Out, "Partition 1") != NULL, "set id noerr stops the script:\n%s\n", Out);

    /* an id that is not 1 or 2 hex digits, or is 0, is a format error and changes nothing */
    /* each one stops the script of its own (0x80070057), so each is a script of its own */
    ok(RunOnDisk("select partition 1\r\nset id=0\r\n", Out, sizeof(Out)), "no set id\n");
    ok(RunOnDisk("select partition 1\r\nset id=g1\r\n", Out, sizeof(Out)), "no set id\n");
    ok(RunOnDisk("select partition 1\r\nset id=100\r\n", Out, sizeof(Out)), "no set id\n");
    ok(RunOnDisk("select partition 1\r\ndetail partition\r\n", Out, sizeof(Out)), "no detail\n");
    Value = DetailValue(Out, "Type");
    ok(Value && _strnicmp(Value, "00", 2) != 0, "an invalid id has changed the type: %.20s\n", Value ? Value : "(none)");
    ok(RunOnDisk("select partition 1\r\nset id=7\r\ndetail partition\r\n", Out, sizeof(Out)), "no set id\n");
    Value = DetailValue(Out, "Type");
    ok(Value && !_strnicmp(Value, "07", 2), "type 07 expected after set id=7: %.20s\n", Value ? Value : "(none)");

    ok(RunOnDisk("clean\r\nconvert mbr\r\n", Out, sizeof(Out)), "no clean\n");

    /* create partition extended offset=: exactly there */
    ok(RunOnDisk("create partition extended size=64 offset=64000\r\nlist partition\r\n", Out, sizeof(Out)),
       "no create extended\n");
    ok(strstr(Out, "succeeded in creating") != NULL, "create partition extended offset= fails:\n%s\n", Out);
    ok(strstr(Out, "Extended") != NULL, "no extended partition:\n%s\n", Out);
    ok(strstr(Out, "not supported") == NULL, "offset= on extended is refused:\n%s\n", Out);

    ok(RunOnDisk("clean\r\n", Out, sizeof(Out)), "no clean\n");
    ok(ListCount() == 0, "no partition expected after clean: %d\n", ListCount());
}


#define LEVEL_BADARGS ((DWORD)0x80070057)
#define LEVEL_NOSPACE ((DWORD)0x8004240F)
#define LEVEL_BADTYPE ((DWORD)0x80042565)

/* The text of the row of "list partition" for the partition: its size and offset as listed ("6000 KB  3000 KB") */
static int HasRow(const char *Out, const char *SizeText, const char *OffsetText)
{
    char Pattern[64];
    const char *p;

    sprintf(Pattern, "%s  %s", SizeText, OffsetText);
    p = strstr(Out, Pattern);
    return p != NULL;
}

/*
 * What the Windows DiskPart does with align= and offset= (Windows Server 2022, rows of kbatch8): the start is rounded UP and the size
 * DOWN to the alignment (size=8 align=3000: 3000 KB, 6000 KB), an offset= is rounded DOWN at the start and offset + size UP at the
 * end (offset=40000 size=8 align=4096: 36 MB, 12 MB; offset=1100 size=8 with the 64 KB default: 1088 KB, 8256 KB), and the error
 * level of a command of a script that fails: 0x80070057 for invalid arguments (noerr does not hide it), 0x8004240F for no room that
 * an align= or offset= asks for, and with noerr the next command runs after a failure that Windows lets pass.
 */
static void TestAlignAndLevels(void)
{
    static char Out[OUT_SIZE];

    ok(RunOnDisk("clean\r\nconvert mbr\r\n", Out, sizeof(Out)), "no clean\n");

    ok(RunOnDisk("create partition primary size=8 align=3000\r\nlist partition\r\n", Out, sizeof(Out)), "no create\n");
    ok(g_ExitCode == 0, "align=3000: level 0x%08lx\n", g_ExitCode);
    ok(HasRow(Out, "6000 KB", "3000 KB"), "size=8 align=3000 is not 6000 KB at 3000 KB:\n%s\n", Out);

    ok(RunOnDisk("clean\r\nconvert mbr\r\ncreate partition primary size=8 align=4096\r\nlist partition\r\n", Out, sizeof(Out)), "no create\n");
    ok(HasRow(Out, "8192 KB", "4096 KB"), "size=8 align=4096 is not 8192 KB at 4096 KB:\n%s\n", Out);

    ok(RunOnDisk("clean\r\nconvert mbr\r\ncreate partition primary size=8 offset=40000 align=4096\r\nlist partition\r\n", Out, sizeof(Out)),
       "no create\n");
    ok(HasRow(Out, "  12 MB", "  36 MB"), "offset=40000 size=8 align=4096 is not 12 MB at 36 MB:\n%s\n", Out);

    ok(RunOnDisk("clean\r\nconvert mbr\r\ncreate partition primary size=8 offset=1100\r\nlist partition\r\n", Out, sizeof(Out)), "no create\n");
    ok(HasRow(Out, "8256 KB", "1088 KB"), "offset=1100 size=8 is not 8256 KB at 1088 KB:\n%s\n", Out);

    /* align=0 is no align=; abc and -5 are not valid arguments; no room for an align that does not fit is not enough usable space */
    ok(RunOnDisk("clean\r\nconvert mbr\r\ncreate partition primary size=8 align=0\r\n", Out, sizeof(Out)), "no create\n");
    ok(g_ExitCode == 0, "align=0: level 0x%08lx\n%s\n", g_ExitCode, Out);
    ok(RunOnDisk("clean\r\nconvert mbr\r\ncreate partition primary size=8 align=abc\r\n", Out, sizeof(Out)), "no create\n");
    ok(g_ExitCode == LEVEL_BADARGS, "align=abc: level 0x%08lx\n", g_ExitCode);
    ok(RunOnDisk("clean\r\nconvert mbr\r\ncreate partition primary size=8 align=-5\r\n", Out, sizeof(Out)), "no create\n");
    ok(g_ExitCode == LEVEL_BADARGS, "align=-5: level 0x%08lx\n", g_ExitCode);
    ok(RunOnDisk("clean\r\nconvert mbr\r\ncreate partition primary size=8 align=100000000\r\n", Out, sizeof(Out)), "no create\n");
    ok(g_ExitCode == LEVEL_NOSPACE, "an align that leaves no room: level 0x%08lx\n", g_ExitCode);

    /* invalid arguments are not hidden by noerr: the script stops, the next command does not run */
    ok(RunOnDisk("clean\r\nconvert mbr\r\ncreate partition primary size=abc noerr\r\ncreate partition primary size=8\r\n", Out, sizeof(Out)),
       "no create\n");
    ok(g_ExitCode == LEVEL_BADARGS, "size=abc noerr: level 0x%08lx\n", g_ExitCode);
    ok(strstr(Out, "succeeded in creating") == NULL, "size=abc noerr did not stop the script:\n%s\n", Out);
    ok(RunOnDisk("clean\r\nconvert mbr\r\ncreate partition primary size=8 noerr noerr\r\n", Out, sizeof(Out)), "no create\n");
    ok(g_ExitCode == LEVEL_BADARGS, "noerr noerr: level 0x%08lx\n", g_ExitCode);

    /* no room for the size: 0x80070057, which noerr hides (the next command runs) */
    ok(RunOnDisk("clean\r\nconvert mbr\r\ncreate partition primary size=99999\r\n", Out, sizeof(Out)), "no create\n");
    ok(g_ExitCode == LEVEL_BADARGS, "size=99999: level 0x%08lx\n", g_ExitCode);
    ok(RunOnDisk("clean\r\nconvert mbr\r\ncreate partition primary size=99999 noerr\r\ncreate partition primary size=8\r\n", Out, sizeof(Out)),
       "no create\n");
    ok(g_ExitCode == 0 && strstr(Out, "succeeded in creating") != NULL, "size=99999 noerr: level 0x%08lx\n%s\n", g_ExitCode, Out);

    /* set id=42 is a Virtual Disk Service error, an id that is not hex is a format error; noerr hides both */
    ok(RunOnDisk("select partition 1\r\nset id=42\r\n", Out, sizeof(Out)), "no set id\n");
    ok(g_ExitCode == LEVEL_BADTYPE, "set id=42: level 0x%08lx\n", g_ExitCode);
    ok(RunOnDisk("select partition 1\r\nset id=42 noerr\r\nlist partition\r\n", Out, sizeof(Out)), "no set id\n");
    ok(g_ExitCode == 0 && strstr(Out, "Partition 1") != NULL, "set id=42 noerr: level 0x%08lx\n", g_ExitCode);
    ok(RunOnDisk("select partition 1\r\nset id=zz\r\n", Out, sizeof(Out)), "no set id\n");
    ok(g_ExitCode == LEVEL_BADARGS, "set id=zz: level 0x%08lx\n", g_ExitCode);
    ok(RunOnDisk("select partition 1\r\nset id=07 override\r\ndetail partition\r\n", Out, sizeof(Out)), "no set id\n");
    ok(g_ExitCode == 0 && strstr(Out, "not supported") == NULL, "set id=07 override: level 0x%08lx\n%s\n", g_ExitCode, Out);

    /* nothing selected: 0x80070057; noerr hides it for delete partition, uniqueid and assign, not for set id */
    ok(RunOnDisk("select partition 1\r\ndelete partition override\r\n", Out, sizeof(Out)), "no delete\n");
    ok(RunOnDisk("delete partition\r\n", Out, sizeof(Out)), "no delete\n");
    ok(g_ExitCode == LEVEL_BADARGS, "delete partition with none selected: level 0x%08lx\n", g_ExitCode);
    ok(RunOnDisk("delete partition noerr\r\nlist partition\r\n", Out, sizeof(Out)), "no delete\n");
    ok(g_ExitCode == 0, "delete partition noerr with none selected: level 0x%08lx\n", g_ExitCode);
    ok(RunOnDisk("set id=07 noerr\r\n", Out, sizeof(Out)), "no set id\n");
    ok(g_ExitCode == LEVEL_BADARGS, "set id noerr with none selected: level 0x%08lx\n", g_ExitCode);
    ok(RunOnDisk("uniqueid disk id=zz\r\n", Out, sizeof(Out)), "no uniqueid\n");
    ok(g_ExitCode == LEVEL_BADARGS, "uniqueid disk id=zz: level 0x%08lx\n", g_ExitCode);
    ok(RunOnDisk("uniqueid disk id=zz noerr\r\nlist partition\r\n", Out, sizeof(Out)), "no uniqueid\n");
    ok(g_ExitCode == 0, "uniqueid disk id=zz noerr: level 0x%08lx\n", g_ExitCode);
    ok(RunOnDisk("assign letter=1\r\n", Out, sizeof(Out)), "no assign\n");
    ok(g_ExitCode == LEVEL_BADARGS, "assign with no volume: level 0x%08lx\n", g_ExitCode);
    ok(RunOnDisk("format fs=fat32 quick revision=1\r\n", Out, sizeof(Out)), "no format\n");
    ok(g_ExitCode == LEVEL_BADARGS, "format with no volume: level 0x%08lx\n", g_ExitCode);
    ok(RunOnDisk("format fs=fat32 quick noerr\r\n", Out, sizeof(Out)), "no format\n");
    ok(g_ExitCode == LEVEL_BADARGS, "format noerr with no volume: noerr hides nothing here, level 0x%08lx\n", g_ExitCode);
    ok(RunOnDisk("extend disk=1 size=8\r\n", Out, sizeof(Out)), "no extend\n");
    ok(g_ExitCode == LEVEL_BADARGS, "extend disk=: level 0x%08lx\n", g_ExitCode);

    /* list partition cuts the offset off: 64000 KB is 62 MB */
    ok(RunOnDisk("clean\r\nconvert mbr\r\ncreate partition primary size=8 offset=64000\r\nlist partition\r\n", Out, sizeof(Out)), "no create\n");
    ok(strstr(Out, "62 MB") != NULL && strstr(Out, "63 MB") == NULL, "the offset 64000 KB is not listed as 62 MB:\n%s\n", Out);

    ok(RunOnDisk("clean\r\n", Out, sizeof(Out)), "no clean\n");
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
    TestOptions();
    TestAlignAndLevels();
}
