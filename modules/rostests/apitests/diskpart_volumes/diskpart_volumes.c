/*
 * PROJECT:     ReactOS API Tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     diskpart.exe "list volume": the order and the numbers of the volumes do not change
 *              between runs on the same disks, and the order is the one of Windows Server 2022 (one disk and one
 *              CD-ROM drive: the CD-ROM volume is volume 0): CD-ROM volumes, partition volumes, removable volumes
 *              (read-only command only)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include <apitest.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>

#define RUNS 5
#define MAX_ROWS 64

static BOOL RunListVolume(const char *Script, char *Out, size_t OutSize)
{
    char Dir[MAX_PATH], Tmp[MAX_PATH], Sys[MAX_PATH], Cmd[3 * MAX_PATH];
    SECURITY_ATTRIBUTES Sa = { sizeof(Sa), NULL, TRUE };
    STARTUPINFOA Si = { sizeof(Si) };
    PROCESS_INFORMATION Pi;
    HANDLE h;
    DWORD Got = 0;

    GetTempPathA(sizeof(Dir), Dir);
    GetTempFileNameA(Dir, "dpv", 0, Tmp);
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
        return FALSE;
    }
    if (WaitForSingleObject(Pi.hProcess, 60000) != WAIT_OBJECT_0)
    {
        TerminateProcess(Pi.hProcess, 99);
        ok(0, "diskpart /s did not end\n");
    }
    CloseHandle(Pi.hProcess);
    CloseHandle(Pi.hThread);
    CloseHandle(h);

    h = CreateFileA(Tmp, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE)
        return FALSE;
    ReadFile(h, Out, (DWORD)(OutSize - 1), &Got, NULL);
    Out[Got] = 0;
    CloseHandle(h);
    DeleteFileA(Tmp);
    return Got != 0;
}

static int TypeRank(const char *Type)
{
    if (!strncmp(Type, "DVD", 3) || !strncmp(Type, "CD-ROM", 6))
        return 0;
    if (!strncmp(Type, "Partition", 9))
        return 1;
    if (!strncmp(Type, "Removable", 9))
        return 2;
    return 3;
}

START_TEST(diskpart_volumes)
{
    static char Out[RUNS][16384];
    char Dir[MAX_PATH], Script[MAX_PATH];
    HANDLE h;
    DWORD Got;
    int Run;
    char *Line, *Next, *Head;
    int Col, LtrCol, Number, Expected = 0, LastRank = -1, Rows = 0;

    GetTempPathA(sizeof(Dir), Dir);
    GetTempFileNameA(Dir, "dpl", 0, Script);
    h = CreateFileA(Script, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    ok(h != INVALID_HANDLE_VALUE, "cannot create %s\n", Script);
    WriteFile(h, "list volume\r\n", 13, &Got, NULL);
    CloseHandle(h);

    for (Run = 0; Run < RUNS; Run++)
    {
        ok(RunListVolume(Script, Out[Run], sizeof(Out[Run])), "run %d: no output\n", Run);
        ok(strstr(Out[Run], "Volume ###") != NULL, "run %d: no volume list\n", Run);
    }

    /* the same disks, the same list, in the same order, with the same numbers */
    for (Run = 1; Run < RUNS; Run++)
        ok(!strcmp(Out[0], Out[Run]), "run %d lists the volumes differently from run 0:\n%s\n---\n%s\n",
           Run, Out[0], Out[Run]);

    /* the numbers are 0, 1, 2, ... and the types come in the documented order */
    trace("%s\n", Out[0]);
    Head = strstr(Out[0], "Volume ###");
    if (Head == NULL)
        return;
    /* the column of "Type" counted from the start of the header line, as in the rows */
    while (Head > Out[0] && Head[-1] != '\n')
        Head--;
    Col = (int)(strstr(Head, "Type") - Head);
    LtrCol = (int)(strstr(Head, "Ltr") - Head) + 1;
    for (Line = strchr(Head, '\n'); Line != NULL; Line = Next)
    {
        Line++;
        Next = strchr(Line, '\n');
        if (Next)
            *Next = 0;
        if (sscanf(Line, " * Volume %d", &Number) == 1 || sscanf(Line, " Volume %d", &Number) == 1)
        {
            const char *Type = Line + Col;
            int Rank;

            if ((int)strlen(Line) > Col + 2)
            {
                Rank = TypeRank(Type);
                if (LtrCol > 0 && isalpha((unsigned char)Line[LtrCol]))
                {
                    char Root[4] = { Line[LtrCol], ':', '\\', 0 };

                    /* a CD-ROM drive is listed as DVD whether or not its medium is recognised */
                    ok((GetDriveTypeA(Root) == DRIVE_CDROM) == (Rank == 0),
                       "volume %d (%s) is typed %.10s but GetDriveType says %lu\n", Number, Root, Type,
                       GetDriveTypeA(Root));
                }
                ok(Number == Expected, "volume number %d where %d is expected: %s\n", Number, Expected, Line);
                ok(Rank >= LastRank, "volume %d (%.10s) listed after a type that must come later\n", Number, Type);
                LastRank = Rank;
            }
            Expected++;
            Rows++;
        }
        if (!Next)
            break;
    }
    trace("%d volumes\n", Rows);
    DeleteFileA(Script);
}
