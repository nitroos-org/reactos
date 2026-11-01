/*
 * PROJECT:     ReactOS net.exe Tests
 * LICENSE:     GPL-2.0+ (https://spdx.org/licenses/GPL-2.0+)
 * PURPOSE:     Tests the exit codes and the error text of net.exe for commands that fail, and for a few that succeed
 * COPYRIGHT:   Copyright 2026 Tomas Srnka (tomas.srnka@e2b.dev)
 *
 * Every case asks for something that does not exist (a user, a group, a service, a share, a message number made up
 * for this test) or gives a wrong option, so no case changes the system. The expected values were measured on
 * Windows 10 22H2 (English): a failed command ends with 2 and writes its message and the NET HELPMSG hint to standard
 * error, a wrong option or verb ends with 1 and writes the syntax to standard error, and a command that works
 * writes "The command completed successfully." to standard output.
 */

#include <apitest.h>

#define WIN32_NO_STATUS
#include <windef.h>
#include <winbase.h>
#include <stdio.h>
#include <string.h>

#define CHILD_TIMEOUT 60000
#define OUT_SIZE 65536
#define ANY_CODE (-2)

typedef struct
{
    LONG code;
    char out[OUT_SIZE];
    char err[OUT_SIZE];
} NET_RESULT;

static BOOL ReadAll(const char *path, char *buf, DWORD size)
{
    DWORD cb = 0;
    HANDLE h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

    buf[0] = 0;
    if (h == INVALID_HANDLE_VALUE)
        return FALSE;
    ReadFile(h, buf, size - 1, &cb, NULL);
    CloseHandle(h);
    buf[cb] = 0;
    return TRUE;
}

/* Runs net.exe with the arguments; standard output and standard error go to separate files, standard input is NUL */
static void RunNet(const char *args, NET_RESULT *res)
{
    char cmd[512], dir[MAX_PATH], pathOut[MAX_PATH], pathErr[MAX_PATH];
    SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, TRUE };
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    HANDLE hNul, hOut, hErr;
    DWORD code, t0 = GetTickCount();

    res->code = -1;
    res->out[0] = res->err[0] = 0;

    GetTempPathA(sizeof(dir), dir);
    sprintf(pathOut, "%snetexit_%lu_o.txt", dir, GetCurrentProcessId());
    sprintf(pathErr, "%snetexit_%lu_e.txt", dir, GetCurrentProcessId());

    hNul = CreateFileA("NUL", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, &sa, OPEN_EXISTING, 0, NULL);
    hOut = CreateFileA(pathOut, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, &sa, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    hErr = CreateFileA(pathErr, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, &sa, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hNul != INVALID_HANDLE_VALUE && hOut != INVALID_HANDLE_VALUE && hErr != INVALID_HANDLE_VALUE)
    {
        si.dwFlags = STARTF_USESTDHANDLES;
        si.hStdInput = hNul;
        si.hStdOutput = hOut;
        si.hStdError = hErr;
        sprintf(cmd, "net.exe %s", args);
        if (CreateProcessA(NULL, cmd, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi))
        {
            while (WaitForSingleObject(pi.hProcess, 100) == WAIT_TIMEOUT && GetTickCount() - t0 < CHILD_TIMEOUT)
                ;
            if (GetExitCodeProcess(pi.hProcess, &code) && code != 259 /* STILL_ACTIVE */)
                res->code = (LONG)code;
            else
                TerminateProcess(pi.hProcess, 99);
            WaitForSingleObject(pi.hProcess, 5000);
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
        }
    }
    if (hNul != INVALID_HANDLE_VALUE) CloseHandle(hNul);
    if (hOut != INVALID_HANDLE_VALUE) CloseHandle(hOut);
    if (hErr != INVALID_HANDLE_VALUE) CloseHandle(hErr);
    ReadAll(pathOut, res->out, sizeof(res->out));
    ReadAll(pathErr, res->err, sizeof(res->err));
    DeleteFileA(pathOut);
    DeleteFileA(pathErr);
}

/* One expected result. A NULL text is not checked; "" is the empty stream. */
static void Check(const char *args, LONG code, const char *out, const char *err1, const char *err2)
{
    static NET_RESULT res;

    RunNet(args, &res);
    if (code != ANY_CODE)
        ok(res.code == code, "net %s: exit code %ld, expected %ld\n", args, res.code, code);
    if (out != NULL)
    {
        if (out[0] == 0)
            ok(res.out[0] == 0, "net %s: standard output is not empty: '%.200s'\n", args, res.out);
        else
            ok(strstr(res.out, out) != NULL, "net %s: no '%s' on standard output: '%.200s'\n", args, out, res.out);
    }
    if (err1 != NULL)
        ok(strstr(res.err, err1) != NULL, "net %s: no '%s' on standard error: '%.300s'\n", args, err1, res.err);
    if (err2 != NULL)
        ok(strstr(res.err, err2) != NULL, "net %s: no '%s' on standard error: '%.300s'\n", args, err2, res.err);
}

START_TEST(NetExit)
{
    char args[256];
    DWORD id = GetTickCount() % 100000;

    /* A missing user: the NERR message and its hint, exit code 2, nothing on standard output */
    sprintf(args, "user nosuchuser_%lu", id);
    Check(args, 2, "", "The user name could not be found.", "NET HELPMSG 2221.");
    sprintf(args, "user nosuchuser_%lu /delete", id);
    Check(args, 2, "", "The user name could not be found.", "NET HELPMSG 2221.");

    /* A missing local group is a system error (no such local group, 1376), which has no hint */
    sprintf(args, "localgroup nosuchgroup_%lu", id);
    Check(args, 2, "", "System error 1376 has occurred.", "The specified local group does not exist.");
    sprintf(args, "localgroup nosuchgroup_%lu /delete", id);
    Check(args, 2, "", "System error 1376 has occurred.", "The specified local group does not exist.");

    /* Global groups need a domain controller */
    Check("group", 2, "", "This command can be used only on a Windows Domain Controller.", "NET HELPMSG 3515.");

    /* A service that does not exist */
    sprintf(args, "start \"nosuchsvc_%lu\"", id);
    Check(args, 2, "", "The service name is invalid.", "NET HELPMSG 2185.");
    sprintf(args, "stop \"nosuchsvc_%lu\"", id);
    Check(args, 2, "", "The service name is invalid.", "NET HELPMSG 2185.");

    /* NET HELPMSG: a known number prints on standard output and works, an unknown one is an error */
    Check("helpmsg 2221", 0, "The user name could not be found.", NULL, NULL);
    Check("helpmsg 99999", 2, "", "99999 is not a valid Windows network message number.", "NET HELPMSG 3871.");
    Check("helpmsg", 1, "", "The syntax of this command is:", "NET HELPMSG");

    /* A verb that does not exist, and options that do not exist: the syntax goes to standard error, exit code 1 */
    Check("bogusverb", 1, "", "The syntax of this command is:", "ACCOUNTS | COMPUTER");
    Check("", 1, "", "The syntax of this command is:", "ACCOUNTS | COMPUTER");
    Check("user /bogusopt", 1, "", "The option /BOGUSOPT is unknown.", "NET HELPMSG 3506.");
    Check("localgroup /bogusopt", 1, "", "The option /BOGUSOPT is unknown.", "NET HELPMSG 3506.");

    /* A share that does not exist: a system error, exit code 2 */
    sprintf(args, "use \\\\127.0.0.1\\nosuchshare_%lu", id);
    Check(args, 2, "", "System error ", " has occurred.");

    /* Commands that work: exit code 0 and the success line on standard output */
    Check("localgroup", 0, "Administrators", NULL, NULL);
    Check("localgroup", 0, "The command completed successfully.", NULL, NULL);
    Check("start", 0, "The command completed successfully.", NULL, NULL);
    /* net user ends with 1 and "completed with one or more errors" on the reference machine, for an account it cannot read */
    Check("user", ANY_CODE, "Administrator", NULL, NULL);
    Check("localgroup Administrators", 0, "Alias name", NULL, NULL);
    Check("localgroup Administrators", 0, "The command completed successfully.", NULL, NULL);
}
