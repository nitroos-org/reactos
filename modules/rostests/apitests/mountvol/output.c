/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     mountvol.exe: structure of its listing, /L, /D, mount point round trip, error paths and exit codes.
 *              The structure (header line, one block per volume: "    \\?\Volume{...}\", then one line per
 *              mount point or a "*** ... ***" line, then an empty line; usage and errors on stdout, exit code 0
 *              for the listing and the usage, 1 for a failed call) was measured on Windows Server 2022. The test
 *              parses the output and compares it with what FindFirstVolume and GetVolumePathNamesForVolumeName
 *              say, so it needs no fixed machine.
 */

#include <apitest.h>
#include <stdio.h>
#include <string.h>
#include <winioctl.h>
#include <mountmgr.h>

#define HEADER "Possible values for VolumeName along with current mount points are:"

static
BOOL
RunMountvol(const char *Args, char **Output, DWORD *ExitCode)
{
    SECURITY_ATTRIBUTES Sa = { sizeof(Sa), NULL, TRUE };
    STARTUPINFOA Si = { sizeof(Si) };
    PROCESS_INFORMATION Pi;
    HANDLE Read, Write, Nul;
    char Cmd[1024];
    char *Buf;
    DWORD Size = 0, Cap = 262144, Got;

    if (!CreatePipe(&Read, &Write, &Sa, 0))
        return FALSE;
    SetHandleInformation(Read, HANDLE_FLAG_INHERIT, 0);
    Nul = CreateFileA("NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, &Sa, OPEN_EXISTING, 0, NULL);
    Si.dwFlags = STARTF_USESTDHANDLES;
    Si.hStdInput = Nul;
    Si.hStdOutput = Write;
    Si.hStdError = Write;
    sprintf(Cmd, "mountvol.exe %s", Args);
    if (!CreateProcessA(NULL, Cmd, NULL, NULL, TRUE, 0, NULL, NULL, &Si, &Pi))
    {
        CloseHandle(Read);
        CloseHandle(Write);
        CloseHandle(Nul);
        return FALSE;
    }
    CloseHandle(Write);
    CloseHandle(Nul);

    Buf = HeapAlloc(GetProcessHeap(), 0, Cap);
    while (Size < Cap - 1 && ReadFile(Read, Buf + Size, Cap - 1 - Size, &Got, NULL) && Got != 0)
        Size += Got;
    Buf[Size] = 0;
    WaitForSingleObject(Pi.hProcess, 60000);
    GetExitCodeProcess(Pi.hProcess, ExitCode);
    CloseHandle(Pi.hProcess);
    CloseHandle(Pi.hThread);
    CloseHandle(Read);
    *Output = Buf;
    return TRUE;
}

/* the one-line system message of an error, with the CRLF the command prints */
static
void
SystemMessage(DWORD Error, char *Out, DWORD Size)
{
    DWORD Len = FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, Error, 0, Out, Size, NULL);

    if (Len == 0)
        Out[0] = 0;
}

static
BOOL
Contains(const char *List, const char *Needle)
{
    return strstr(List, Needle) != NULL;
}

/* Parse the listing: every volume of the system appears once, with the mount points of
 * GetVolumePathNamesForVolumeNameA, or with one of the "***" lines when it has none. */
static
void
Test_Listing(void)
{
    char *Output = NULL, *Line, *Next, *Body;
    DWORD ExitCode = 0xDEAD;
    char Volume[MAX_PATH];
    char Names[64][MAX_PATH];
    HANDLE Find;
    int Listed = 0, Expected = 0;

    if (!RunMountvol("", &Output, &ExitCode))
    {
        skip("mountvol.exe cannot be started\n");
        return;
    }
    ok(ExitCode == 0, "exit code %lu\n", ExitCode);
    Body = strstr(Output, HEADER "\r\n\r\n");
    ok(Body != NULL, "the listing header is missing:\n%s\n", Output);
    if (!Body)
    {
        HeapFree(GetProcessHeap(), 0, Output);
        return;
    }
    Body += strlen(HEADER "\r\n\r\n");

    /* the usage comes first and does not start with a space */
    ok(Output[0] != ' ' && Output[0] != 0, "the usage text is missing\n");
    ok(Contains(Output, "MOUNTVOL [drive:]path VolumeName\r\n"), "no syntax line\n");
    ok(Contains(Output, "MOUNTVOL /R\r\nMOUNTVOL /N\r\nMOUNTVOL /E\r\n"), "no /R /N /E syntax lines\n");

    /* blocks: "    \\?\Volume{...}\" CRLF, mount point lines (8 spaces) CRLF, CRLF */
    for (Line = Body; *Line; Line = Next)
    {
        char Name[MAX_PATH];
        char Paths[4096];
        DWORD Length = 0, Count = 0, Seen = 0;
        const char *P;

        Next = strstr(Line, "\r\n");
        ok(Next != NULL, "unterminated line\n");
        if (!Next)
            break;
        *Next = 0;
        Next += 2;
        ok(strncmp(Line, "    \\\\?\\Volume{", 14) == 0, "volume line expected, got [%s]\n", Line);
        if (strncmp(Line, "    \\\\?\\Volume{", 14) != 0)
            break;
        strcpy(Name, Line + 4);
        if (Listed < 64)
            strcpy(Names[Listed], Name);
        Listed++;

        ZeroMemory(Paths, sizeof(Paths));
        if (GetVolumePathNamesForVolumeNameA(Name, Paths, sizeof(Paths) - 1, &Length))
        {
            for (P = Paths; *P; P += strlen(P) + 1)
                Count++;
        }

        /* the lines of this block */
        for (;;)
        {
            char *End = strstr(Next, "\r\n");

            ok(End != NULL, "block of %s is not terminated\n", Name);
            if (!End)
                goto Done;
            *End = 0;
            if (Next[0] == 0)
            {
                Next = End + 2;
                break;
            }
            ok(strncmp(Next, "        ", 8) == 0, "mount point line expected, got [%s]\n", Next);
            if (strcmp(Next + 8, "*** NO MOUNT POINTS ***") == 0 ||
                strcmp(Next + 8, "*** NOT MOUNTABLE UNTIL A VOLUME MOUNT POINT IS CREATED ***") == 0)
            {
                ok(Count == 0, "%s: \"%s\" but the volume has %lu paths\n", Name, Next + 8, Count);
            }
            else
            {
                BOOL Found = FALSE;

                for (P = Paths; *P; P += strlen(P) + 1)
                    if (_stricmp(P, Next + 8) == 0)
                        Found = TRUE;
                ok(Found, "%s: mount point [%s] is not one of the volume's paths\n", Name, Next + 8);
                Seen++;
            }
            Next = End + 2;
        }
        if (Count != 0)
            ok(Seen == Count, "%s: %lu mount points listed, the volume has %lu\n", Name, Seen, Count);
    }
Done:
    /* every volume FindFirstVolume knows is in the listing */
    Find = FindFirstVolumeA(Volume, sizeof(Volume));
    if (Find != INVALID_HANDLE_VALUE)
    {
        do
        {
            int n;
            BOOL InList = FALSE;

            for (n = 0; n < Listed && n < 64; n++)
                if (_stricmp(Names[n], Volume) == 0)
                    InList = TRUE;
            Expected++;
            ok(InList, "volume %s is not listed\n", Volume);
        } while (FindNextVolumeA(Find, Volume, sizeof(Volume)));
        FindVolumeClose(Find);
    }
    ok(Listed == Expected, "%d volumes listed, %d volumes exist\n", Listed, Expected);
    HeapFree(GetProcessHeap(), 0, Output);
}

/* mountvol X: /L prints "    " + the volume name for every drive letter */
static
void
Test_ListLetters(void)
{
    DWORD Drives = GetLogicalDrives();
    char Letter;
    int Tested = 0;

    for (Letter = 'A'; Letter <= 'Z'; Letter++)
    {
        char Root[4] = { Letter, ':', '\\', 0 };
        char Name[MAX_PATH], Args[32], Expected[MAX_PATH + 16];
        char *Output = NULL;
        DWORD ExitCode = 0xDEAD;

        if (!(Drives & (1UL << (Letter - 'A'))))
            continue;
        if (!GetVolumeNameForVolumeMountPointA(Root, Name, sizeof(Name)))
            continue;

        sprintf(Args, "%c: /L", Letter);
        if (!RunMountvol(Args, &Output, &ExitCode))
        {
            skip("mountvol.exe cannot be started\n");
            return;
        }
        sprintf(Expected, "    %s\r\n", Name);
        ok(strcmp(Output, Expected) == 0, "%s: [%s], expected [%s]\n", Args, Output, Expected);
        ok(ExitCode == 0, "%s: exit code %lu\n", Args, ExitCode);
        HeapFree(GetProcessHeap(), 0, Output);

        /* the switch is not case sensitive and the backslash is optional */
        sprintf(Args, "%c:\\ /l", Letter);
        RunMountvol(Args, &Output, &ExitCode);
        ok(strcmp(Output, Expected) == 0, "%s: [%s], expected [%s]\n", Args, Output, Expected);
        HeapFree(GetProcessHeap(), 0, Output);
        if (++Tested == 3)
            break;
    }
    ok(Tested != 0, "no drive letter names a volume\n");
}

static
void
Test_Errors(void)
{
    static const struct
    {
        const char *Args;
        DWORD Error;
        int ExitCode;
    } Cases[] =
    {
        { "Q: /L", ERROR_FILE_NOT_FOUND, 1 },
        { "Q:\\ /L", ERROR_FILE_NOT_FOUND, 1 },
        { "Q: /D", ERROR_FILE_NOT_FOUND, 1 },
        { "Q: /P", ERROR_FILE_NOT_FOUND, 1 },
        { "Q:\\no\\such\\folder /L", ERROR_PATH_NOT_FOUND, 1 },
        { "/N /E", ERROR_INVALID_PARAMETER, 1 },
        { "/R /N", ERROR_INVALID_PARAMETER, 1 },
    };
    static const char *Usage[] = { "/?", "/L", "/D", "/P", "/X", "1 2 3 4", "C:\\ /L extra", "C:\\ /L /D" };
    size_t i;

    if (GetDriveTypeA("Q:\\") != DRIVE_NO_ROOT_DIR)
    {
        skip("Q: exists, the cases name it as a missing drive\n");
        return;
    }

    for (i = 0; i < RTL_NUMBER_OF(Cases); i++)
    {
        char Expected[512];
        char *Output = NULL;
        DWORD ExitCode = 0xDEAD;

        /* "Q:\no\such\folder" is not tested by Windows with a distinct code: path not found or file not found */
        SystemMessage(Cases[i].Error, Expected, sizeof(Expected));
        if (!RunMountvol(Cases[i].Args, &Output, &ExitCode))
        {
            skip("mountvol.exe cannot be started\n");
            return;
        }
        if (Cases[i].Error == ERROR_PATH_NOT_FOUND)
        {
            char Alt[512];

            SystemMessage(ERROR_FILE_NOT_FOUND, Alt, sizeof(Alt));
            ok(strcmp(Output, Expected) == 0 || strcmp(Output, Alt) == 0, "mountvol %s: [%s]\n", Cases[i].Args, Output);
        }
        else
        {
            ok(strcmp(Output, Expected) == 0, "mountvol %s: [%s], expected [%s]\n", Cases[i].Args, Output, Expected);
        }
        ok(ExitCode == (DWORD)Cases[i].ExitCode, "mountvol %s: exit code %lu\n", Cases[i].Args, ExitCode);
        HeapFree(GetProcessHeap(), 0, Output);
    }

    /* anything that is not a call of the syntax prints the usage and the listing, exit code 0 */
    for (i = 0; i < RTL_NUMBER_OF(Usage); i++)
    {
        char *Output = NULL;
        DWORD ExitCode = 0xDEAD;

        if (!RunMountvol(Usage[i], &Output, &ExitCode))
            return;
        ok(Contains(Output, "MOUNTVOL /R\r\n") && Contains(Output, HEADER "\r\n\r\n"),
           "mountvol %s: no usage and listing: [%s]\n", Usage[i], Output);
        ok(ExitCode == 0, "mountvol %s: exit code %lu\n", Usage[i], ExitCode);
        HeapFree(GetProcessHeap(), 0, Output);
    }
}

/* Put a volume on a folder, read it back, take it away */
static
void
Test_RoundTrip(void)
{
    char Temp[MAX_PATH], Dir[MAX_PATH], Target[MAX_PATH], Args[2 * MAX_PATH + 8], Expected[MAX_PATH + 16];
    char HostRoot[4], Volume[MAX_PATH], HostVolume[MAX_PATH], Message[512];
    char *Output = NULL;
    DWORD ExitCode = 0xDEAD, Flags = 0;
    HANDLE Find;
    BOOL Found = FALSE;

    if (!GetTempPathA(sizeof(Temp), Temp))
        return;
    HostRoot[0] = Temp[0]; HostRoot[1] = ':'; HostRoot[2] = '\\'; HostRoot[3] = 0;
    GetVolumeInformationA(HostRoot, NULL, 0, NULL, NULL, &Flags, NULL, 0);
    if (!(Flags & FILE_SUPPORTS_REPARSE_POINTS))
    {
        skip("%s does not support reparse points\n", HostRoot);
        return;
    }
    if (!GetVolumeNameForVolumeMountPointA(HostRoot, HostVolume, sizeof(HostVolume)))
        return;

    /* a volume other than the one that holds the folder */
    Find = FindFirstVolumeA(Volume, sizeof(Volume));
    if (Find != INVALID_HANDLE_VALUE)
    {
        do
        {
            if (_stricmp(Volume, HostVolume) != 0 && GetDriveTypeA(Volume) == DRIVE_FIXED)
            {
                strcpy(Target, Volume);
                Found = TRUE;
                break;
            }
        } while (FindNextVolumeA(Find, Volume, sizeof(Volume)));
        FindVolumeClose(Find);
    }
    if (!Found)
    {
        skip("there is no second fixed volume to mount\n");
        return;
    }

    sprintf(Dir, "%smountvol_apitest_%lu", Temp, GetCurrentProcessId());
    if (!CreateDirectoryA(Dir, NULL))
    {
        skip("cannot create %s: %lu\n", Dir, GetLastError());
        return;
    }

    sprintf(Args, "%s %s", Dir, Target);
    RunMountvol(Args, &Output, &ExitCode);
    ok(ExitCode == 0 && Output[0] == 0, "mount: exit code %lu, output [%s]\n", ExitCode, Output);
    HeapFree(GetProcessHeap(), 0, Output);

    sprintf(Args, "%s /L", Dir);
    sprintf(Expected, "    %s\r\n", Target);
    RunMountvol(Args, &Output, &ExitCode);
    ok(strcmp(Output, Expected) == 0 && ExitCode == 0, "/L: [%s] exit code %lu\n", Output, ExitCode);
    HeapFree(GetProcessHeap(), 0, Output);

    /* a folder that is a mount point is not empty */
    sprintf(Args, "%s %s", Dir, Target);
    RunMountvol(Args, &Output, &ExitCode);
    SystemMessage(ERROR_DIR_NOT_EMPTY, Message, sizeof(Message));
    ok(strcmp(Output, Message) == 0 && ExitCode == 1, "mount twice: [%s] exit code %lu\n", Output, ExitCode);
    HeapFree(GetProcessHeap(), 0, Output);

    sprintf(Args, "%s /D", Dir);
    RunMountvol(Args, &Output, &ExitCode);
    ok(ExitCode == 0 && Output[0] == 0, "/D: exit code %lu, output [%s]\n", ExitCode, Output);
    HeapFree(GetProcessHeap(), 0, Output);

    sprintf(Args, "%s /D", Dir);
    RunMountvol(Args, &Output, &ExitCode);
    SystemMessage(ERROR_NOT_A_REPARSE_POINT, Message, sizeof(Message));
    ok(strcmp(Output, Message) == 0 && ExitCode == 1, "/D twice: [%s] exit code %lu\n", Output, ExitCode);
    HeapFree(GetProcessHeap(), 0, Output);

    /* the volume name without its closing backslash is accepted */
    sprintf(Args, "%s %s", Dir, Target);
    Args[strlen(Args) - 1] = 0;
    RunMountvol(Args, &Output, &ExitCode);
    ok(ExitCode == 0 && Output[0] == 0, "mount without backslash: exit code %lu, output [%s]\n", ExitCode, Output);
    HeapFree(GetProcessHeap(), 0, Output);
    sprintf(Args, "%s /D", Dir);
    RunMountvol(Args, &Output, &ExitCode);
    HeapFree(GetProcessHeap(), 0, Output);

    RemoveDirectoryA(Dir);
}

static
BOOL
QueryAutoMount(DWORD *State)
{
    HANDLE Manager = CreateFileA("\\\\.\\MountPointManager", 0, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                 NULL, OPEN_EXISTING, 0, NULL);
    DWORD Returned = 0;
    MOUNTMGR_QUERY_AUTO_MOUNT Query;
    BOOL Ok;

    if (Manager == INVALID_HANDLE_VALUE)
        return FALSE;
    Ok = DeviceIoControl(Manager, IOCTL_MOUNTMGR_QUERY_AUTO_MOUNT, NULL, 0, &Query, sizeof(Query), &Returned, NULL);
    CloseHandle(Manager);
    if (Ok)
        *State = Query.CurrentState;
    return Ok;
}

/* /N and /E change the mount manager's state; the state found is put back */
static
void
Test_AutoMount(void)
{
    DWORD Original, State;
    char *Output = NULL;
    DWORD ExitCode = 0xDEAD;

    if (!QueryAutoMount(&Original))
    {
        skip("the mount manager state cannot be read: %lu\n", GetLastError());
        return;
    }

    RunMountvol("/N", &Output, &ExitCode);
    ok(ExitCode == 0 && Output[0] == 0, "/N: exit code %lu, output [%s]\n", ExitCode, Output);
    HeapFree(GetProcessHeap(), 0, Output);
    ok(QueryAutoMount(&State) && State == 0, "automount is not disabled after /N\n");

    RunMountvol("/n", &Output, &ExitCode);
    ok(ExitCode == 0 && Output[0] == 0, "/n twice: exit code %lu, output [%s]\n", ExitCode, Output);
    HeapFree(GetProcessHeap(), 0, Output);

    RunMountvol("/E", &Output, &ExitCode);
    ok(ExitCode == 0 && Output[0] == 0, "/E: exit code %lu, output [%s]\n", ExitCode, Output);
    HeapFree(GetProcessHeap(), 0, Output);
    ok(QueryAutoMount(&State) && State == 1, "automount is not enabled after /E\n");

    if (!Original)
    {
        RunMountvol("/N", &Output, &ExitCode);
        HeapFree(GetProcessHeap(), 0, Output);
    }
}

START_TEST(output)
{
    Test_Listing();
    Test_ListLetters();
    Test_Errors();
    Test_RoundTrip();
    Test_AutoMount();
}
