/*
 * PROJECT:     ReactOS tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Records the end-session messages a GUI process receives during
 *              a restart/shutdown/logoff and checks the Windows sequence:
 *              WM_QUERYENDSESSION, then WM_ENDSESSION(TRUE), to every
 *              top-level window (visible, hidden, on another thread), and the
 *              process is not terminated while a window is still handling
 *              WM_ENDSESSION within the default timeouts.
 *
 * Usage:   endsession /run [log [delay_ms]]   create the windows, log, pump messages
 *          endsession /verify [log [delay_ms]]  check the log of a previous /run
 * The log is flushed after every line, so it survives the process being killed.
 */

#include <windows.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#define DEFAULT_LOG "C:\\harness\\out\\endsession.log"

static HANDLE g_Log = INVALID_HANDLE_VALUE;
static DWORD g_Delay = 0;
static CRITICAL_SECTION g_Cs;

static void Log(const char *fmt, ...)
{
    char buf[512];
    int n;
    DWORD wr;
    va_list ap;

    n = sprintf(buf, "%lu ", GetTickCount());
    va_start(ap, fmt);
    n += vsprintf(buf + n, fmt, ap);
    va_end(ap);
    buf[n++] = '\r';
    buf[n++] = '\n';
    EnterCriticalSection(&g_Cs);
    if (g_Log != INVALID_HANDLE_VALUE)
    {
        WriteFile(g_Log, buf, n, &wr, NULL);
        FlushFileBuffers(g_Log);
    }
    LeaveCriticalSection(&g_Cs);
}

static LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    char cls[64];

    switch (msg)
    {
        case WM_QUERYENDSESSION:
            GetClassNameA(hWnd, cls, sizeof(cls));
            Log("QES %s lParam=%08lx", cls, (unsigned long)lParam);
            return TRUE;
        case WM_ENDSESSION:
            GetClassNameA(hWnd, cls, sizeof(cls));
            Log("ES %s wParam=%d lParam=%08lx", cls, wParam ? 1 : 0, (unsigned long)lParam);
            if (wParam && g_Delay && !strcmp(cls, "ES_Main"))
            {
                Sleep(g_Delay);
                Log("ES-DONE %s", cls);
            }
            return 0;
    }
    return DefWindowProcA(hWnd, msg, wParam, lParam);
}

static DWORD WINAPI Thread2(LPVOID p)
{
    MSG m;
    HWND w = CreateWindowA("ES_Thread2", "ES thread2", WS_OVERLAPPEDWINDOW | WS_VISIBLE,
                           300, 100, 200, 100, NULL, NULL, GetModuleHandleA(NULL), NULL);
    Log("WINDOW ES_Thread2 %p", w);
    while (GetMessageA(&m, NULL, 0, 0) > 0)
    {
        TranslateMessage(&m);
        DispatchMessageA(&m);
    }
    return 0;
}

static int Run(const char *logname)
{
    WNDCLASSA wc;
    HINSTANCE hi = GetModuleHandleA(NULL);
    HWND hMain, hHidden;
    MSG m;
    const char *names[] = { "ES_Main", "ES_Hidden", "ES_Thread2" };
    int i;

    g_Log = CreateFileA(logname, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (g_Log == INVALID_HANDLE_VALUE)
        return 2;
    Log("START delay=%lu", g_Delay);

    memset(&wc, 0, sizeof(wc));
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hi;
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    for (i = 0; i < 3; i++)
    {
        wc.lpszClassName = names[i];
        RegisterClassA(&wc);
    }
    hMain = CreateWindowA("ES_Main", "ES main", WS_OVERLAPPEDWINDOW | WS_VISIBLE,
                          50, 50, 200, 100, NULL, NULL, hi, NULL);
    hHidden = CreateWindowA("ES_Hidden", "ES hidden", WS_OVERLAPPEDWINDOW,
                            0, 0, 10, 10, NULL, NULL, hi, NULL);
    Log("WINDOW ES_Main %p ES_Hidden %p", hMain, hHidden);
    CreateThread(NULL, 0, Thread2, NULL, 0, NULL);
    Log("READY");
    while (GetMessageA(&m, NULL, 0, 0) > 0)
    {
        TranslateMessage(&m);
        DispatchMessageA(&m);
    }
    Log("QUIT");
    return 0;
}

struct seen { int qes, es, es1; DWORD tqes, tes; };

static FILE *g_Out;
static void vp(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt); vprintf(fmt, ap); va_end(ap);
    if (g_Out) { va_start(ap, fmt); vfprintf(g_Out, fmt, ap); va_end(ap); fflush(g_Out); }
}

static int Verify(const char *logname)
{
    FILE *f = fopen(logname, "r");
    char vname[MAX_PATH];
    char line[512], cls[64];
    struct seen s[3];
    const char *names[] = { "ES_Main", "ES_Hidden", "ES_Thread2" };
    int i, bad = 0, done = 0, started = 0, ready = 0, quit = 0;
    DWORD t, tlastES = 0, tdone = 0, t0 = 0;
    int w;

    memset(s, 0, sizeof(s));
    sprintf(vname, "%s.verdict", logname);
    g_Out = fopen(vname, "w");
    if (!f) { vp("FAIL: cannot open %s\n", logname); return 2; }
    while (fgets(line, sizeof(line), f))
    {
        unsigned long lp; int wp;
        if (sscanf(line, "%lu %*s", &t) != 1) continue;
        if (!t0) t0 = t;
        if (strstr(line, " START")) started = 1;
        if (strstr(line, " READY")) ready = 1;
        if (strstr(line, " QUIT")) quit = 1;
        if (strstr(line, " ES-DONE")) { done = 1; tdone = t; }
        if (sscanf(line, "%*u QES %63s lParam=%lx", cls, &lp) == 2)
        {
            for (i = 0; i < 3; i++) if (!strcmp(cls, names[i]) && !s[i].qes) { s[i].qes = 1; s[i].tqes = t; }
        }
        else if (sscanf(line, "%*u ES %63s wParam=%d lParam=%lx", cls, &wp, &lp) == 3)
        {
            for (i = 0; i < 3; i++) if (!strcmp(cls, names[i]))
            {
                if (!s[i].qes) { vp("FAIL: %s got ES before QES\n", cls); bad++; }
                s[i].es = 1; if (wp) s[i].es1 = 1; s[i].tes = t; tlastES = t;
            }
        }
        (void)w;
    }
    fclose(f);
    vp("log %s: started=%d ready=%d\n", logname, started, ready);
    if (!started || !ready) { vp("FAIL: app never became ready\n"); return 1; }
    for (i = 0; i < 3; i++)
    {
        vp("%-11s QES=%d ES=%d ES(TRUE)=%d  tQES=+%lums tES=+%lums\n", names[i], s[i].qes, s[i].es, s[i].es1,
               s[i].qes ? s[i].tqes - t0 : 0, s[i].es ? s[i].tes - t0 : 0);
        if (!s[i].qes) { vp("FAIL: %s did not get WM_QUERYENDSESSION\n", names[i]); bad++; }
        if (!s[i].es1) { vp("FAIL: %s did not get WM_ENDSESSION(TRUE)\n", names[i]); bad++; }
    }
    if (g_Delay)
    {
        vp("ES handler delay %lums: ES-DONE seen=%d (+%lums after last ES)\n", g_Delay, done, done ? tdone - tlastES : 0);
        if (!done) { vp("FAIL: process was killed inside WM_ENDSESSION before the handler finished\n"); bad++; }
    }
    (void)quit;
    vp(bad ? "RESULT: FAIL (%d)\n" : "RESULT: PASS\n", bad);
    return bad ? 1 : 0;
}

static int RealMain(int argc, char **argv)
{
    const char *log = argc > 2 ? argv[2] : DEFAULT_LOG;

    InitializeCriticalSection(&g_Cs);
    if (argc > 3) g_Delay = strtoul(argv[3], NULL, 10);
    if (argc >= 2 && !strcmp(argv[1], "/run")) return Run(log);
    if (argc >= 2 && !strcmp(argv[1], "/verify")) return Verify(log);
    printf("usage: endsession /run|/verify [log [delay_ms]]\n");
    return 64;
}

int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPSTR cmd, int show)
{
    return RealMain(__argc, __argv);
}
