/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Test for typeperf.exe: the layout of its output against typeperf.exe of Windows 10 22H2
 *
 * Counter values, time stamps, the computer name and the spinner steps differ from run to run
 * and are masked; everything else (quoting, separators, line ends, messages, exit codes) is
 * compared with the capture of the Windows 10 22H2 reference. The banner line of -? is the one
 * intentional difference: it names NitroOS and the version of the tree.
 */

#include "precomp.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <reactos/buildno.h>

#define PAD "Exiting, please wait...                         \r\n"
#define DONE PAD "The command completed successfully.\r\n\r\r"
#define SYNTAX "\r\nThe syntax of the command is incorrect.\r\n"
#define MISSING \
    "Missing parameter: <counter [counter ...]>\r\n" \
    "Missing parameter: -cf <filename>\r\n" \
    "Missing parameter: -q [object]\r\n" \
    "Missing parameter: -qx [object]\r\n"

static const char s_Usage[] =
    "\r\n"
    "NitroOS TypePerf.exe (" KERNEL_VERSION_STR ")\r\n"
    "\r\n"
    "Typeperf writes performance data to the command window or to a log file. To\r\n"
    "stop Typeperf, press CTRL+C.\r\n"
    "\r\n"
    "Usage:\r\n"
    "typeperf { <counter [counter ...]> \r\n"
    "                                | -cf <filename> \r\n"
    "                                | -q [object] \r\n"
    "                                | -qx [object] \r\n"
    "                                } [options]\r\n"
    "\r\n"
    "Parameters:\r\n"
    "  <counter [counter ...]>       Performance counters to monitor.\r\n"
    "\nOptions:\r\n"
    "  -?                            Displays context sensitive help.\r\n"
    "  -f <CSV|TSV|BIN|SQL>          Output file format. Default is CSV.\r\n"
    "  -cf <filename>                File containing performance counters to\r\n"
    "                                monitor, one per line.\r\n"
    "  -si <[[hh:]mm:]ss>            Time between samples. Default is 1 second.\r\n"
    "  -o <filename>                 Path of output file or SQL database. Default\r\n"
    "                                is STDOUT.\r\n"
    "  -q [object]                   List installed counters (no instances). To\r\n"
    "                                list counters for one object, include the\r\n"
    "                                object name, such as Processor.\r\n"
    "  -qx [object]                  List installed counters with instances. To\r\n"
    "                                list counters for one object, include the\r\n"
    "                                object name, such as Processor.\r\n"
    "  -sc <samples>                 Number of samples to collect. Default is to\r\n"
    "                                sample until CTRL+C.\r\n"
    "  -config <filename>            Settings file containing command options.\r\n"
    "  -s <computer_name>            Server to monitor if no server is specified\r\n"
    "                                in the counter path.\r\n"
    "  -y                            Answer yes to all questions without prompting.\r\n"
    "\r\n"
    "Note:\r\n"
    "  Counter is the full name of a performance counter in\r\n"
    "  \"\\\\<Computer>\\<Object>(<Instance>)\\<Counter>\" format,\r\n"
    "  such as \"\\\\Server1\\Processor(0)\\% User Time\".\r\n"
    "\r\n"
    "Examples:\r\n"
    "  typeperf \"\\Processor(_Total)\\% Processor Time\"\r\n"
    "  typeperf -cf counters.txt -si 5 -sc 50 -f TSV -o domain2.tsv\r\n"
    "  typeperf -qx PhysicalDisk -o counters.txt\r\n";

static char s_Computer[MAX_COMPUTERNAME_LENGTH + 4];

/* Runs "typeperf.exe <args>" with stdin from NUL; returns the exit code, the output in *out. */
static DWORD RunTypeperf(const char *args, char *out, size_t cbOut)
{
    SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, TRUE };
    char cmd[1024], tmp[MAX_PATH], tmpDir[MAX_PATH];
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    HANDLE hOut, hIn;
    DWORD rc = 0xDEADBEEF, got = 0;

    out[0] = 0;
    GetTempPathA(sizeof(tmpDir), tmpDir);
    GetTempFileNameA(tmpDir, "tpf", 0, tmp);
    hOut = CreateFileA(tmp, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, &sa,
                       CREATE_ALWAYS, FILE_ATTRIBUTE_TEMPORARY, NULL);
    hIn = CreateFileA("NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, &sa, OPEN_EXISTING, 0, NULL);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = si.hStdError = hOut;
    si.hStdInput = hIn;
    sprintf(cmd, "typeperf.exe %s", args);
    if (!CreateProcessA(NULL, cmd, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi))
    {
        skip("cannot start typeperf.exe (%lu)\n", GetLastError());
    }
    else
    {
        if (WaitForSingleObject(pi.hProcess, 60000) != WAIT_OBJECT_0)
            TerminateProcess(pi.hProcess, 0xDEAD);
        GetExitCodeProcess(pi.hProcess, &rc);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    }
    SetFilePointer(hOut, 0, NULL, FILE_BEGIN);
    ReadFile(hOut, out, (DWORD)cbOut - 1, &got, NULL);
    out[got] = 0;
    CloseHandle(hOut);
    CloseHandle(hIn);
    DeleteFileA(tmp);
    return rc;
}

static BOOL IsDigits(const char *p, int n)
{
    while (n--)
        if (*p < '0' || *p++ > '9')
            return FALSE;
    return TRUE;
}

/* "MM/dd/yyyy HH:mm:ss.fff" at p? */
static BOOL IsStamp(const char *p)
{
    return IsDigits(p, 2) && p[2] == '/' && IsDigits(p + 3, 2) && p[5] == '/' && IsDigits(p + 6, 4) &&
           p[10] == ' ' && IsDigits(p + 11, 2) && p[13] == ':' && IsDigits(p + 14, 2) && p[16] == ':' &&
           IsDigits(p + 17, 2) && p[19] == '.' && IsDigits(p + 20, 3);
}

/* Masks the data of a log: the computer name, quoted time stamps, quoted values, spinner steps. */
static void Mask(const char *in, char *out)
{
    size_t clen = strlen(s_Computer);

    while (*in)
    {
        if (in[0] == '\\' && in[1] == '\\' && !_strnicmp(in + 2, s_Computer, clen) && in[2 + clen] == '\\')
        {
            strcpy(out, "\\\\HOST");
            out += 6;
            in += 2 + clen;
        }
        else if (in[0] == '"' && IsStamp(in + 1) && in[24] == '"')
        {
            strcpy(out, "\"<TS>\"");
            out += 6;
            in += 25;
        }
        else if (in[0] == '"' && (in[1] == '-' || (in[1] >= '0' && in[1] <= '9')))
        {
            const char *q = in + 1;
            while (*q == '-' || *q == '.' || *q == '+' || *q == 'e' || *q == 'E' || (*q >= '0' && *q <= '9'))
                q++;
            if (*q == '"')
            {
                strcpy(out, "\"<V>\"");
                out += 5;
                in = q + 1;
            }
            else
                *out++ = *in++;
        }
        else if (in[0] == '"' && in[1] == ' ' && in[2] == '"')
        {
            strcpy(out, "\"<V>\"");
            out += 5;
            in += 3;
        }
        else if (in[0] == '\r' && in[1] == '[' && in[3] == ']' && strchr("|/-\\", in[2]))
            in += 4;                            /* a spinner step */
        else if (in[0] == '"' && !strncmp(in, "\"(PDH-", 6) && (in[6] == 'C' || in[6] == 'T') && in[7] == 'S' &&
                 in[8] == 'V' && !strncmp(in + 9, " 4.0) (", 7))
        {
            /* "(PDH-CSV 4.0) (<time zone name>)(<bias>)" of a log file */
            const char *q = in + 16;
            while (*q && *q != ')')
                q++;
            if (q[0] == ')' && q[1] == '(')
            {
                q += 2;
                while (*q == '-' || (*q >= '0' && *q <= '9'))
                    q++;
                if (q[0] == ')' && q[1] == '"')
                {
                    memcpy(out, in, 14);        /* "(PDH-CSV 4.0) */
                    out += 14;
                    strcpy(out, " (<TZ>)\"");
                    out += 8;
                    in = q + 2;
                    continue;
                }
            }
            *out++ = *in++;
        }
        else
            *out++ = *in++;
    }
    *out = 0;
}

static void CheckRun(int line, const char *args, const char *expected, DWORD expectedRc)
{
    static char out[65536], masked[65536];
    DWORD rc = RunTypeperf(args, out, sizeof(out));

    Mask(out, masked);
    ok(!strcmp(masked, expected), "line %d: typeperf %s: got\n%s\nexpected\n%s\n", line, args, masked, expected);
    ok(rc == expectedRc, "line %d: typeperf %s: exit code 0x%08lX, expected 0x%08lX\n", line, args, rc,
       expectedRc);
}

#define CHECK(args, expected, rc) CheckRun(__LINE__, args, expected, rc)

static void WriteTemp(const char *path, const char *text)
{
    HANDLE h = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    DWORD n;
    WriteFile(h, text, (DWORD)strlen(text), &n, NULL);
    CloseHandle(h);
}

static void ReadTemp(const char *path, char *out, size_t cb)
{
    HANDLE h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    DWORD n = 0;

    out[0] = 0;
    if (h != INVALID_HANDLE_VALUE)
    {
        ReadFile(h, out, (DWORD)cb - 1, &n, NULL);
        CloseHandle(h);
    }
    out[n] = 0;
}

START_TEST(typeperf)
{
    static char out[65536], masked[65536];
    char dir[MAX_PATH], file[MAX_PATH + 64], args[2 * MAX_PATH + 256];
    DWORD size = MAX_COMPUTERNAME_LENGTH + 1, rc;
    const char *p;

    GetComputerNameA(s_Computer, &size);

    CHECK("-?", s_Usage, 0);

    /* messages and syntax errors */
    CHECK("", MISSING SYNTAX, 11);
    CHECK("-sc 1", MISSING SYNTAX, 11);
    CHECK("-bogus", "Unknown parameter \"-bogus\"\r\n" MISSING SYNTAX, 11);
    CHECK("\"\\Memory\\Available MBytes\" -o", "Invalid syntax: -o <filename>\r\n" SYNTAX, 11);
    CHECK("\"\\Memory\\Available MBytes\" -f XYZ", PAD "\"XYZ\" is not a valid format.\r\n\r\r", 0xF0000001);
    CHECK("\"\\Nonexistent\\Counter\" -sc 1", "\r\n" PAD "Error: No valid counters.\r\n\r\r", 0xF0000002);
    CHECK("-q NoSuchObject", PAD "\r\nError:\r\nThe specified object was not found on the computer.\r\n\r\n\r\r",
          0xC0000BB8);
    CHECK("-qx NoSuchObject", PAD "\r\nError:\r\nThe specified object was not found on the computer.\r\n\r\n\r\r",
          0xC0000BB8);

    /* console output: all fields quoted, 6 decimals */
    CHECK("\"\\Processor(_Total)\\% Processor Time\" -sc 2",
          "\r\n\"(PDH-CSV 4.0)\",\"\\\\HOST\\Processor(_Total)\\% Processor Time\"\r\n"
          "\"<TS>\",\"<V>\"\r\n\"<TS>\",\"<V>\"\r\n" DONE, 0);
    CHECK("\"\\Memory\\Available MBytes\" \"\\Paging File(_Total)\\% Usage\" -sc 2 -si 1",
          "\r\n\"(PDH-CSV 4.0)\",\"\\\\HOST\\Memory\\Available MBytes\",\"\\\\HOST\\Paging File(_Total)\\% Usage\"\r\n"
          "\"<TS>\",\"<V>\",\"<V>\"\r\n\"<TS>\",\"<V>\",\"<V>\"\r\n" DONE, 0);
    /* an invalid counter is skipped, not-a-number sample counts are one sample, an interval of 0 is accepted */
    CHECK("\"\\Memory\\Available MBytes\" \"\\Nonexistent\\Counter\" -sc abc -si 0",
          "\r\n\"(PDH-CSV 4.0)\",\"\\\\HOST\\Memory\\Available MBytes\"\r\n\"<TS>\",\"<V>\"\r\n" DONE, 0);
    {
        char expect[512];
        sprintf(expect, "\r\n\"(PDH-CSV 4.0)\",\"\\\\HOST\\Memory\\Available MBytes\"\r\n\"<TS>\",\"<V>\"\r\n" DONE);
        sprintf(args, "\"\\\\%s\\Memory\\Available MBytes\" -sc 1", s_Computer);
        CHECK(args, expect, 0);
    }

    /* wildcards expand to every instance, _Total last */
    rc = RunTypeperf("\"\\Processor(*)\\% Processor Time\" -sc 1", out, sizeof(out));
    Mask(out, masked);
    p = strstr(masked, "\\\\HOST\\Processor(_Total)\\% Processor Time\"\r\n\"<TS>\"");
    ok(p != NULL, "Processor(*): _Total is not the last column:\n%s\n", masked);
    ok(rc == 0, "Processor(*): exit code %lu\n", rc);

    /* counter lists */
    GetTempPathA(sizeof(dir), dir);
    sprintf(file, "%stypeperf-test-list.txt", dir);
    WriteTemp(file, "\\Memory\\Available MBytes\r\n\r\n\\Paging File(_Total)\\% Usage\r\n");
    sprintf(args, "-cf \"%s\" -sc 1", file);
    CHECK(args,
          "\r\n\"(PDH-CSV 4.0)\",\"\\\\HOST\\Memory\\Available MBytes\",\"\\\\HOST\\Paging File(_Total)\\% Usage\"\r\n"
          "\"<TS>\",\"<V>\",\"<V>\"\r\n" DONE, 0);
    DeleteFileA(file);
    sprintf(args, "-cf \"%s\" -sc 1", file);
    CHECK(args, "\r\n" PAD "Error: No valid counters.\r\n\r\r", 0xF0000002);

    /* counter listing */
    CHECK("-q \"Paging File\"", "\\Paging File(*)\\% Usage\r\n\\Paging File(*)\\% Usage Peak\r\n" DONE, 0);
    /* The counters of an object come in the order of Windows. pdh serves only part of the Windows 10 list
     * of the Memory object (36 counters), so the output must be an ordered selection of it. */
    {
        static const char *const memory[] =
        {
            "Page Faults/sec", "Available Bytes", "Committed Bytes", "Commit Limit", "Write Copies/sec",
            "Transition Faults/sec", "Cache Faults/sec", "Demand Zero Faults/sec", "Pages/sec",
            "Pages Input/sec", "Page Reads/sec", "Pages Output/sec", "Pool Paged Bytes", "Pool Nonpaged Bytes",
            "Page Writes/sec", "Pool Paged Allocs", "Pool Nonpaged Allocs", "Free System Page Table Entries",
            "Cache Bytes", "Cache Bytes Peak", "Pool Paged Resident Bytes", "System Code Total Bytes",
            "System Code Resident Bytes", "System Driver Total Bytes", "System Driver Resident Bytes",
            "System Cache Resident Bytes", "% Committed Bytes In Use", "Available KBytes", "Available MBytes",
            "Transition Pages RePurposed/sec", "Free & Zero Page List Bytes", "Modified Page List Bytes",
            "Standby Cache Reserve Bytes", "Standby Cache Normal Priority Bytes", "Standby Cache Core Bytes",
            "Long-Term Average Standby Cache Lifetime (s)"
        };
        const char *line = out, *eol;
        size_t pos = 0, n = 0;

        rc = RunTypeperf("-q Memory", out, sizeof(out));
        ok(rc == 0, "-q Memory: exit code %lu\n", rc);
        while (!strncmp(line, "\\Memory\\", 8) && (eol = strstr(line, "\r\n")) != NULL)
        {
            size_t len = eol - (line + 8);
            while (pos < ARRAYSIZE(memory) && (strlen(memory[pos]) != len || strncmp(memory[pos], line + 8, len)))
                pos++;
            ok(pos < ARRAYSIZE(memory), "-q Memory: unknown or misplaced counter %.*s\n", (int)len, line + 8);
            pos++;
            n++;
            line = eol + 2;
        }
        ok(n > 0, "-q Memory lists counters\n");
        ok(!strcmp(line, DONE), "-q Memory: ends with the completion message: %s\n", line);
    }

    /* -qx lists counter by counter, every instance of a counter in turn */
    rc = RunTypeperf("-qx \"Paging File\"", out, sizeof(out));
    ok(rc == 0, "-qx: exit code %lu\n", rc);
    {
        const char *u = strstr(out, ")\\% Usage\r\n");
        const char *t1 = strstr(out, "\\Paging File(_Total)\\% Usage\r\n");
        const char *pk = strstr(out, ")\\% Usage Peak\r\n");
        const char *t2 = strstr(out, "\\Paging File(_Total)\\% Usage Peak\r\n");
        const char *end = strstr(out, DONE);

        ok(!strncmp(out, "\\Paging File(", 13), "-qx starts with a counter: %.40s\n", out);
        ok(u && t1 && pk && t2 && u < t1 && t1 < pk && pk < t2, "-qx: order of the counters\n%s\n", out);
        ok(end && !end[sizeof(DONE) - 1], "-qx: ends with the completion message\n%s\n", out);
    }

    /* log files: CSV and TSV keep the value, the header names the time zone, the console shows a spinner */
    sprintf(file, "%stypeperf-test.csv", dir);
    sprintf(args, "\"\\Memory\\Available MBytes\" \"\\Paging File(_Total)\\%% Usage\" -sc 2 -o \"%s\" -y", file);
    CHECK(args, "\r\n" DONE, 0);
    ReadTemp(file, out, sizeof(out));
    Mask(out, masked);
    ok(!strcmp(masked, "\"(PDH-CSV 4.0) (<TZ>)\",\"\\\\HOST\\Memory\\Available MBytes\",\"\\\\HOST\\Paging File(_Total)\\% Usage\"\r\n"
                       "\"<TS>\",\"<V>\",\"<V>\"\r\n\"<TS>\",\"<V>\",\"<V>\"\r\n"), "CSV file:\n%s\n", masked);
    DeleteFileA(file);

    sprintf(file, "%stypeperf-test.tsv", dir);
    sprintf(args, "\"\\Memory\\Available MBytes\" \"\\Paging File(_Total)\\%% Usage\" -sc 1 -f TSV -o \"%s\" -y", file);
    CHECK(args, "\r\n" DONE, 0);
    ReadTemp(file, out, sizeof(out));
    Mask(out, masked);
    ok(!strcmp(masked, "\"(PDH-TSV 4.0) (<TZ>)\"\t\"\\\\HOST\\Memory\\Available MBytes\"\t\"\\\\HOST\\Paging File(_Total)\\% Usage\"\r\n"
                       "\"<TS>\"\t\"<V>\"\t\"<V>\"\r\n"), "TSV file:\n%s\n", masked);

    /* a log file that cannot be created */
    sprintf(args, "\"\\Memory\\Available MBytes\" -sc 1 -o \"%stypeperf-no-such-dir\\x.csv\" -y", dir);
    CHECK(args, "\r\n" PAD "\r\nError:\r\nUnable to create the specified log file.\r\n\r\n\r\r", 0xC0000BC9);
}
