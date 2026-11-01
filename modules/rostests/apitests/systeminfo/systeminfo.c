/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Tests for systeminfo.exe: field names and order of the TABLE, LIST and CSV outputs
 *              (as measured on the Windows 10 22H2 reference system), plausibility of the values,
 *              option errors
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include <apitest.h>
#include <winnls.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>

#define FIELD_COUNT 33
#define LIST_COLUMN 27

static const struct
{
    const char *Name;
    int TableWidth;
} s_Fields[FIELD_COUNT] =
{
    { "Host Name", 30 }, { "OS Name", 30 }, { "OS Version", 30 }, { "OS Manufacturer", 40 },
    { "OS Configuration", 40 }, { "OS Build Type", 20 }, { "Registered Owner", 50 },
    { "Registered Organization", 50 }, { "Product ID", 30 }, { "Original Install Date", 25 },
    { "System Boot Time", 30 }, { "System Manufacturer", 30 }, { "System Model", 20 },
    { "System Type", 25 }, { "Processor(s)", 45 }, { "BIOS Version", 30 },
    { "Windows Directory", 20 }, { "System Directory", 20 }, { "Boot Device", 35 },
    { "System Locale", 35 }, { "Input Locale", 35 }, { "Time Zone", 50 },
    { "Total Physical Memory", 25 }, { "Available Physical Memory", 25 },
    { "Virtual Memory: Max Size", 25 }, { "Virtual Memory: Available", 25 },
    { "Virtual Memory: In Use", 25 }, { "Page File Location(s)", 30 }, { "Domain", 20 },
    { "Logon Server", 20 }, { "Hotfix(s)", 20 }, { "Network Card(s)", 100 },
    { "Hyper-V Requirements", 100 },
};

enum { I_HOST, I_OSNAME, I_OSVER, I_OSMFR, I_OSCFG, I_BUILDTYPE, I_OWNER, I_ORG, I_PID, I_INSTALL,
       I_BOOT, I_SYSMFR, I_MODEL, I_TYPE, I_PROCS, I_BIOS, I_WINDIR, I_SYSDIR, I_BOOTDEV,
       I_SYSLOC, I_INLOC, I_TZ, I_TOTPHYS, I_AVPHYS, I_VMMAX, I_VMAV, I_VMUSE, I_PAGEFILE,
       I_DOMAIN, I_LOGON, I_HOTFIX, I_NIC, I_HYPERV };

typedef struct
{
    char *Out;
    char *Err;
    DWORD ExitCode;
} RUN;

static void ReadPipe(HANDLE h, char **pBuf)
{
    size_t Len = 0, Cap = 4096;
    char *Buf = malloc(Cap);
    DWORD Got;

    for (;;)
    {
        if (Len + 2048 > Cap)
        {
            Cap *= 2;
            Buf = realloc(Buf, Cap);
        }
        if (!ReadFile(h, Buf + Len, 2048, &Got, NULL) || !Got)
            break;
        Len += Got;
    }
    Buf[Len] = 0;
    *pBuf = Buf;
}

static BOOL RunSysteminfo(const char *Args, RUN *Run)
{
    SECURITY_ATTRIBUTES Sa = { sizeof(Sa), NULL, TRUE };
    HANDLE OutR, OutW, ErrR, ErrW;
    STARTUPINFOA Si = { sizeof(Si) };
    PROCESS_INFORMATION Pi;
    char Cmd[MAX_PATH + 128];
    char Sys[MAX_PATH];

    memset(Run, 0, sizeof(*Run));
    GetSystemDirectoryA(Sys, sizeof(Sys));
    sprintf(Cmd, "\"%s\\systeminfo.exe\" %s", Sys, Args);
    if (!CreatePipe(&OutR, &OutW, &Sa, 0) || !CreatePipe(&ErrR, &ErrW, &Sa, 0))
        return FALSE;
    SetHandleInformation(OutR, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(ErrR, HANDLE_FLAG_INHERIT, 0);
    Si.dwFlags = STARTF_USESTDHANDLES;
    Si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    Si.hStdOutput = OutW;
    Si.hStdError = ErrW;
    if (!CreateProcessA(NULL, Cmd, NULL, NULL, TRUE, 0, NULL, NULL, &Si, &Pi))
    {
        ok(0, "cannot start %s: %lu\n", Cmd, GetLastError());
        return FALSE;
    }
    CloseHandle(OutW);
    CloseHandle(ErrW);
    ReadPipe(OutR, &Run->Out);
    ReadPipe(ErrR, &Run->Err);
    WaitForSingleObject(Pi.hProcess, 60000);
    GetExitCodeProcess(Pi.hProcess, &Run->ExitCode);
    CloseHandle(Pi.hProcess);
    CloseHandle(Pi.hThread);
    CloseHandle(OutR);
    CloseHandle(ErrR);
    return TRUE;
}

static void FreeRun(RUN *Run)
{
    free(Run->Out);
    free(Run->Err);
}

/* Parse one CSV record starting at p; the cells are decoded in place. Returns the cell count. */
static int ParseCsvLine(char *p, char **Cells, int Max)
{
    int n = 0;

    while (*p && *p != '\r' && *p != '\n' && n < Max)
    {
        char *w;

        if (*p != '"')
            return -1;
        p++;
        Cells[n++] = w = p;
        for (;;)
        {
            if (!*p)
                return -1;
            if (*p == '"')
            {
                if (p[1] == '"')
                {
                    *w++ = '"';
                    p += 2;
                    continue;
                }
                break;
            }
            *w++ = *p++;
        }
        p++;
        if (*p == ',')
            p++;
        *w = 0;
    }
    return n;
}

static BOOL MatchesDate(const char *s)
{
    /* M/D/YYYY, h:mm:ss AM */
    int m, d, y, h, mi, se;
    char ap[3];

    return sscanf(s, "%d/%d/%d, %d:%d:%d %2s", &m, &d, &y, &h, &mi, &se, ap) == 7 &&
           m >= 1 && m <= 12 && d >= 1 && d <= 31 && y >= 2000 && h >= 1 && h <= 12 &&
           mi < 60 && se < 60 && (!strcmp(ap, "AM") || !strcmp(ap, "PM"));
}

static BOOL MatchesMegabytes(const char *s, unsigned long *pValue)
{
    unsigned long v = 0;
    const char *p = s;

    if (!isdigit((unsigned char)*p))
        return FALSE;
    for (; isdigit((unsigned char)*p) || *p == ','; p++)
        if (*p != ',')
            v = v * 10 + (*p - '0');
    *pValue = v;
    return !strcmp(p, " MB");
}

static void CheckValues(char **V)
{
    char Buf[MAX_PATH], Host[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD Size = sizeof(Host);
    unsigned long Total = 0, Avail, Max, VAvail, Used, Maj, Min, Build, Build2;
    char Sp[64];
    int i;
    BOOL EnUs = (GetUserDefaultLangID() & 0xFF) == LANG_ENGLISH;

    for (i = 0; i < FIELD_COUNT; i++)
        ok(V[i][0] != 0, "%s is empty\n", s_Fields[i].Name);

    GetComputerNameA(Host, &Size);
    ok(!_stricmp(V[I_HOST], Host), "Host Name '%s', expected '%s'\n", V[I_HOST], Host);

    ok(!strncmp(V[I_OSNAME], "Microsoft Windows", 17) || strcmp(V[I_OSNAME], "N/A"),
       "OS Name '%s'\n", V[I_OSNAME]);
    ok(sscanf(V[I_OSVER], "%lu.%lu.%lu %63[^B]Build %lu", &Maj, &Min, &Build, Sp, &Build2) == 5 &&
       Maj >= 5 && Build == Build2, "OS Version '%s'\n", V[I_OSVER]);
    ok(!strcmp(V[I_OSCFG], "Standalone Workstation") || !strcmp(V[I_OSCFG], "Standalone Server") ||
       !strcmp(V[I_OSCFG], "Member Workstation") || !strcmp(V[I_OSCFG], "Member Server"),
       "OS Configuration '%s'\n", V[I_OSCFG]);
    ok(!strncmp(V[I_BUILDTYPE], "Multiprocessor ", 15) || !strncmp(V[I_BUILDTYPE], "Uniprocessor ", 13),
       "OS Build Type '%s'\n", V[I_BUILDTYPE]);

    if (EnUs)
    {
        ok(MatchesDate(V[I_INSTALL]), "Original Install Date '%s'\n", V[I_INSTALL]);
        ok(MatchesDate(V[I_BOOT]), "System Boot Time '%s'\n", V[I_BOOT]);
    }

    ok(!strcmp(V[I_TYPE], "x86-based PC") || !strcmp(V[I_TYPE], "x64-based PC") ||
       !strcmp(V[I_TYPE], "ARM64-based PC"), "System Type '%s'\n", V[I_TYPE]);
    ok(sscanf(V[I_PROCS], "%lu Processor(s) Installed.", &Total) == 1 && Total >= 1 &&
       strstr(V[I_PROCS], "[01]: ") != NULL, "Processor(s) '%s'\n", V[I_PROCS]);

    GetWindowsDirectoryA(Buf, sizeof(Buf));
    ok(!_stricmp(V[I_WINDIR], Buf), "Windows Directory '%s', expected '%s'\n", V[I_WINDIR], Buf);
    GetSystemDirectoryA(Buf, sizeof(Buf));
    ok(!_stricmp(V[I_SYSDIR], Buf), "System Directory '%s', expected '%s'\n", V[I_SYSDIR], Buf);
    ok(!strncmp(V[I_BOOTDEV], "\\Device\\", 8), "Boot Device '%s'\n", V[I_BOOTDEV]);

    if (EnUs)
    {
        ok(strstr(V[I_SYSLOC], "en-") == V[I_SYSLOC] && strchr(V[I_SYSLOC], ';'), "System Locale '%s'\n", V[I_SYSLOC]);
        ok(strchr(V[I_INLOC], ';') != NULL, "Input Locale '%s'\n", V[I_INLOC]);
    }

    ok(MatchesMegabytes(V[I_TOTPHYS], &Total) && Total > 0, "Total Physical Memory '%s'\n", V[I_TOTPHYS]);
    ok(MatchesMegabytes(V[I_AVPHYS], &Avail) && Avail <= Total, "Available Physical Memory '%s'\n", V[I_AVPHYS]);
    ok(MatchesMegabytes(V[I_VMMAX], &Max) && Max > 0, "Virtual Memory: Max Size '%s'\n", V[I_VMMAX]);
    ok(MatchesMegabytes(V[I_VMAV], &VAvail) && VAvail <= Max, "Virtual Memory: Available '%s'\n", V[I_VMAV]);
    ok(MatchesMegabytes(V[I_VMUSE], &Used), "Virtual Memory: In Use '%s'\n", V[I_VMUSE]);
    ok(Used + VAvail + 1 >= Max && Used + VAvail <= Max + 1, "In Use %lu + Available %lu != Max %lu\n", Used, VAvail, Max);

    ok(!strcmp(V[I_PAGEFILE], "N/A") || V[I_PAGEFILE][1] == ':', "Page File Location(s) '%s'\n", V[I_PAGEFILE]);
    ok(!strcmp(V[I_HOTFIX], "N/A") || strstr(V[I_HOTFIX], " Hotfix(s) Installed.") != NULL,
       "Hotfix(s) '%s'\n", V[I_HOTFIX]);
    ok(!strcmp(V[I_NIC], "N/A") || strstr(V[I_NIC], " NIC(s) Installed.") != NULL, "Network Card(s) '%s'\n", V[I_NIC]);
    ok(!strncmp(V[I_HYPERV], "A hypervisor has been detected.", 31) ||
       !strncmp(V[I_HYPERV], "VM Monitor Mode Extensions: ", 28), "Hyper-V Requirements '%s'\n", V[I_HYPERV]);
}

static void TestCsv(void)
{
    RUN Run;
    char *Cells[FIELD_COUNT + 1];
    char *Line1;
    int i, n;

    if (!RunSysteminfo("/FO CSV", &Run))
        return;
    ok(Run.ExitCode == 0, "/FO CSV exit code %lu\n", Run.ExitCode);
    ok(Run.Err[0] == 0, "/FO CSV wrote to stderr: %s\n", Run.Err);

    /* header record, CR LF, data record, CR LF */
    Line1 = strstr(Run.Out, "\r\n");
    ok(Line1 != NULL, "no CR LF in the CSV output\n");
    if (!Line1)
    {
        FreeRun(&Run);
        return;
    }
    *Line1 = 0;
    Line1 += 2;
    n = ParseCsvLine(Run.Out, Cells, FIELD_COUNT + 1);
    ok(n == FIELD_COUNT, "CSV header has %d fields, expected %d\n", n, FIELD_COUNT);
    for (i = 0; i < n && i < FIELD_COUNT; i++)
        ok(!strcmp(Cells[i], s_Fields[i].Name), "CSV header field %d is '%s', expected '%s'\n",
           i, Cells[i], s_Fields[i].Name);

    n = ParseCsvLine(Line1, Cells, FIELD_COUNT + 1);
    ok(n == FIELD_COUNT, "CSV data has %d fields, expected %d\n", n, FIELD_COUNT);
    if (n == FIELD_COUNT)
        CheckValues(Cells);
    FreeRun(&Run);

    /* /NH: the data record only */
    if (!RunSysteminfo("/FO CSV /NH", &Run))
        return;
    ok(Run.ExitCode == 0, "/FO CSV /NH exit code %lu\n", Run.ExitCode);
    n = ParseCsvLine(Run.Out, Cells, FIELD_COUNT + 1);
    ok(n == FIELD_COUNT, "CSV /NH has %d fields\n", n);
    if (n > 0)
        ok(strcmp(Cells[0], "Host Name") != 0, "CSV /NH still has the header\n");
    FreeRun(&Run);
}

static void TestList(void)
{
    RUN Run;
    char *p, *Next;
    int Field = -1;
    BOOL First = TRUE;

    if (!RunSysteminfo("/FO LIST", &Run))
        return;
    ok(Run.ExitCode == 0, "/FO LIST exit code %lu\n", Run.ExitCode);
    for (p = Run.Out; *p; p = Next)
    {
        char *eol = strstr(p, "\r\n");
        size_t Len;

        if (!eol)
        {
            ok(0, "line without CR LF: '%s'\n", p);
            break;
        }
        *eol = 0;
        Next = eol + 2;
        if (First)
        {
            ok(*p == 0, "the LIST output must start with an empty line: '%s'\n", p);
            First = FALSE;
            continue;
        }
        if (*p == ' ')
        {
            ok(Field >= 0 && strspn(p, " ") >= LIST_COLUMN, "continuation line not indented: '%s'\n", p);
            continue;
        }
        Field++;
        ok(Field < FIELD_COUNT, "too many fields in the LIST output: '%s'\n", p);
        if (Field >= FIELD_COUNT)
            break;
        Len = strlen(s_Fields[Field].Name);
        ok(!strncmp(p, s_Fields[Field].Name, Len) && p[Len] == ':', "LIST field %d is '%s', expected '%s:'\n",
           Field, p, s_Fields[Field].Name);
        ok(strlen(p) > LIST_COLUMN && p[LIST_COLUMN - 1] == ' ' && p[LIST_COLUMN] != ' ',
           "LIST value of '%s' not at column %d: '%s'\n", s_Fields[Field].Name, LIST_COLUMN, p);
    }
    ok(Field == FIELD_COUNT - 1, "LIST has %d fields, expected %d\n", Field + 1, FIELD_COUNT);
    FreeRun(&Run);
}

static void TestTable(void)
{
    RUN Run;
    char *Lines[8];
    char *p = NULL;
    int n = 0, i, Total = FIELD_COUNT - 1, Pos = 0;

    for (i = 0; i < FIELD_COUNT; i++)
        Total += s_Fields[i].TableWidth;

    if (!RunSysteminfo("/FO TABLE", &Run))
        return;
    ok(Run.ExitCode == 0, "/FO TABLE exit code %lu\n", Run.ExitCode);
    for (p = Run.Out; *p && n < 8; )
    {
        char *eol = strstr(p, "\r\n");

        if (!eol)
            break;
        *eol = 0;
        Lines[n++] = p;
        p = eol + 2;
    }
    ok(n == 4, "TABLE has %d lines, expected 4\n", n);
    if (n == 4)
    {
        ok(Lines[0][0] == 0, "TABLE does not start with an empty line\n");
        ok((int)strlen(Lines[1]) == Total, "TABLE header is %d wide, expected %d\n", (int)strlen(Lines[1]), Total);
        ok((int)strlen(Lines[2]) == Total, "TABLE ruler is %d wide, expected %d\n", (int)strlen(Lines[2]), Total);
        ok((int)strlen(Lines[3]) == Total, "TABLE data is %d wide, expected %d\n", (int)strlen(Lines[3]), Total);
        for (i = 0; i < FIELD_COUNT && (int)strlen(Lines[1]) == Total; i++)
        {
            size_t Len = strlen(s_Fields[i].Name);

            ok(!strncmp(Lines[1] + Pos, s_Fields[i].Name, Len), "TABLE column %d header is not '%s'\n", i, s_Fields[i].Name);
            Pos += s_Fields[i].TableWidth + 1;
        }
        ok(strspn(Lines[2], "= ") == strlen(Lines[2]), "TABLE ruler: '%s'\n", Lines[2]);
    }
    FreeRun(&Run);

    if (!RunSysteminfo("/FO TABLE /NH", &Run))
        return;
    ok(Run.ExitCode == 0, "/FO TABLE /NH exit code %lu\n", Run.ExitCode);
    ok(strncmp(Run.Out, "\r\n", 2) == 0, "TABLE /NH does not start with an empty line\n");
    p = strstr(Run.Out + 2, "\r\n");
    ok(p != NULL && (int)(p - Run.Out - 2) == Total && p[2] == 0, "TABLE /NH is not one data row\n");
    FreeRun(&Run);
}

static void TestError(const char *Args, const char *Expect)
{
    RUN Run;

    if (!RunSysteminfo(Args, &Run))
        return;
    ok(Run.ExitCode == 1, "'%s' exit code %lu\n", Args, Run.ExitCode);
    ok(Run.Out[0] == 0, "'%s' wrote to stdout\n", Args);
    ok(strstr(Run.Err, Expect) != NULL, "'%s' stderr '%s', expected '%s'\n", Args, Run.Err, Expect);
    FreeRun(&Run);
}

START_TEST(systeminfo)
{
    RUN Run;

    TestCsv();
    TestList();
    TestTable();

    TestError("/FO LIST /NH", "ERROR: Invalid syntax. /NH option is allowed only for \"TABLE\" and \"CSV\" formats.\r\n"
                              "Type \"SYSTEMINFO /?\" for usage.\r\n");
    TestError("/NH", "/NH option is allowed only for");
    TestError("/FO XML", "ERROR: Invalid syntax. 'XML' value is not allowed for '/FO' option.\r\n");
    TestError("/FO", "ERROR: Invalid syntax. Value expected for '/FO'.\r\n");
    TestError("/FO CSV /FO LIST", "'/FO' option is not allowed more than '1' time(s).");
    TestError("/X", "ERROR: Invalid argument/option - '/X'.\r\n");
    TestError("/U bob", "/U can be specified only when /S is specified.");
    TestError("/P pw", "/P can be specified only when /U is specified.");
    TestError("/S", "ERROR: Invalid syntax. Value expected for '/S'.\r\n");

    /* the documentation address 192.0.2.1 is not routable: the RPC error of the Windows tool */
    TestError("/S 192.0.2.1", "ERROR: The RPC server is unavailable.\r\r\n");

    if (RunSysteminfo("/?", &Run))
    {
        ok(Run.ExitCode == 0, "/? exit code %lu\n", Run.ExitCode);
        ok(strstr(Run.Out, "SYSTEMINFO [/S system [/U username [/P [password]]]] [/FO format] [/NH]") != NULL,
           "/? usage line missing\n");
        FreeRun(&Run);
    }
}
