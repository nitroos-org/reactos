/*
 * PROJECT:     NitroOS compatibility log tool
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     The report: verdict, system header, details
 */

#include "nitrodiag.h"

/* ---- WBUF ---- */

static BOOL WbGrow(WBUF *b, size_t need)
{
    size_t ncap;
    WCHAR *n;
    if (b->len + need + 1 <= b->cap)
        return TRUE;
    ncap = b->cap ? b->cap : 4096;
    while (ncap < b->len + need + 1)
        ncap *= 2;
    if (b->p)
        n = HeapReAlloc(GetProcessHeap(), 0, b->p, ncap * sizeof(WCHAR));
    else
        n = HeapAlloc(GetProcessHeap(), 0, ncap * sizeof(WCHAR));
    if (!n)
        return FALSE;
    b->p = n;
    b->cap = ncap;
    return TRUE;
}

void WbAppend(WBUF *b, const WCHAR *s)
{
    size_t n = wcslen(s);
    if (!WbGrow(b, n))
        return;
    memcpy(b->p + b->len, s, (n + 1) * sizeof(WCHAR));
    b->len += n;
}

void WbPrintf(WBUF *b, const WCHAR *fmt, ...)
{
    WCHAR tmp[2048];
    va_list ap;
    va_start(ap, fmt);
    StringCchVPrintfW(tmp, _countof(tmp), fmt, ap);
    va_end(ap);
    WbAppend(b, tmp);
}

void WbFree(WBUF *b)
{
    if (b->p)
        HeapFree(GetProcessHeap(), 0, b->p);
    ZeroMemory(b, sizeof(*b));
}

/* ---- names ---- */

const WCHAR *StatusName(DWORD code)
{
    switch (code)
    {
        case ND_STATUS_ORDINAL_NOT_FOUND:     return L"ordinal not found";
        case ND_STATUS_ENTRYPOINT_NOT_FOUND:  return L"entry point not found";
        case ND_STATUS_INVALID_IMAGE_FORMAT:  return L"bad image format";
        case ND_STATUS_DLL_INIT_FAILED:       return L"DLL initialization failed";
        case ND_STATUS_APP_INIT_FAILURE:      return L"application initialization failure";
        case ND_STATUS_ILLEGAL_DLL_RELOC:     return L"illegal DLL relocation";
        case ND_STATUS_MACHINE_MISMATCH:      return L"image machine type mismatch";
        case 0xC0000135:                      return L"DLL not found";
        case 0xC0000022:                      return L"access denied";
        case 0xC0000034:                      return L"file not found";
        case 0xC0000017:                      return L"not enough memory";
        case 0xC000012F:                      return L"bad image";
        case 0xC0150002:                      return L"side-by-side configuration is incorrect";
        case 0xC0150004:                      return L"side-by-side: assembly not found";
        case 0xC0150001:                      return L"side-by-side: activation context failed";
        case 0xC0000409:                      return L"fast fail (stack buffer overrun or abort)";
        case 0xC0000374:                      return L"heap corruption";
        case 0xC000013A:                      return L"stopped with Ctrl+C";
        default:                              return L"error";
    }
}

const WCHAR *ExceptionName(DWORD code)
{
    switch (code)
    {
        case EXCEPTION_ACCESS_VIOLATION:      return L"access violation";
        case EXCEPTION_ARRAY_BOUNDS_EXCEEDED: return L"array bounds exceeded";
        case EXCEPTION_BREAKPOINT:            return L"breakpoint";
        case EXCEPTION_DATATYPE_MISALIGNMENT: return L"misaligned data access";
        case EXCEPTION_FLT_DIVIDE_BY_ZERO:    return L"floating-point divide by zero";
        case EXCEPTION_FLT_INVALID_OPERATION: return L"floating-point invalid operation";
        case EXCEPTION_FLT_OVERFLOW:          return L"floating-point overflow";
        case EXCEPTION_ILLEGAL_INSTRUCTION:   return L"illegal instruction";
        case EXCEPTION_IN_PAGE_ERROR:         return L"in-page error";
        case EXCEPTION_INT_DIVIDE_BY_ZERO:    return L"integer divide by zero";
        case EXCEPTION_INT_OVERFLOW:          return L"integer overflow";
        case EXCEPTION_PRIV_INSTRUCTION:      return L"privileged instruction";
        case EXCEPTION_STACK_OVERFLOW:        return L"stack overflow";
        case EXCEPTION_GUARD_PAGE:            return L"guard page";
        case EXCEPTION_INVALID_HANDLE:        return L"invalid handle";
        case 0xC0000017:                      return L"no memory";
        case 0xC0000409:                      return L"fast fail (stack buffer overrun or abort)";
        case 0xC0000374:                      return L"heap corruption";
        case ND_EXCEPTION_CPP:                return L"unhandled C++ exception";
        case 0x20474343:                      return L"C++ exception (GCC runtime)";
        case ND_EXCEPTION_WINE_STUB:          return L"call to a function that is not implemented";
        case 0x40010005:                      return L"Ctrl+C";
        default:                              return L"exception";
    }
}

static const WCHAR *BaseName(const WCHAR *p)
{
    const WCHAR *s = wcsrchr(p, L'\\');
    return s ? s + 1 : p;
}

/* ---- file version ---- */

void FileVersionOf(const WCHAR *path, WCHAR *out, size_t cch)
{
    DWORD h = 0, sz;
    void *data;
    VS_FIXEDFILEINFO *ffi = NULL;
    UINT n = 0;

    out[0] = 0;
    sz = GetFileVersionInfoSizeW(path, &h);
    if (!sz)
        return;
    data = HeapAlloc(GetProcessHeap(), 0, sz);
    if (!data)
        return;
    if (GetFileVersionInfoW(path, 0, sz, data) && VerQueryValueW(data, L"\\", (LPVOID *)&ffi, &n) && ffi && n >= sizeof(*ffi))
        StringCchPrintfW(out, cch, L"%u.%u.%u.%u", HIWORD(ffi->dwFileVersionMS), LOWORD(ffi->dwFileVersionMS),
                         HIWORD(ffi->dwFileVersionLS), LOWORD(ffi->dwFileVersionLS));
    HeapFree(GetProcessHeap(), 0, data);
}

/* ---- system header ---- */

static BOOL RegStr(HKEY root, const WCHAR *key, const WCHAR *val, WCHAR *out, DWORD cch)
{
    HKEY k;
    DWORD type = 0, cb = cch * sizeof(WCHAR);
    BOOL ok = FALSE;
    out[0] = 0;
    if (RegOpenKeyExW(root, key, 0, KEY_QUERY_VALUE, &k) == ERROR_SUCCESS)
    {
        if (RegQueryValueExW(k, val, NULL, &type, (LPBYTE)out, &cb) == ERROR_SUCCESS && (type == REG_SZ || type == REG_EXPAND_SZ))
        {
            out[cch - 1] = 0;
            ok = TRUE;
        }
        RegCloseKey(k);
    }
    return ok;
}

static BOOL RegDword(HKEY root, const WCHAR *key, const WCHAR *val, DWORD *out)
{
    HKEY k;
    DWORD type = 0, cb = sizeof(DWORD);
    BOOL ok = FALSE;
    if (RegOpenKeyExW(root, key, 0, KEY_QUERY_VALUE, &k) == ERROR_SUCCESS)
    {
        ok = RegQueryValueExW(k, val, NULL, &type, (LPBYTE)out, &cb) == ERROR_SUCCESS && type == REG_DWORD;
        RegCloseKey(k);
    }
    return ok;
}

static void FeatureLine(WBUF *out, const WCHAR *label, const WCHAR *file)
{
    WCHAR sysdir[MAX_PATH], p[MAX_PATH], ver[40];
    GetSystemDirectoryW(sysdir, _countof(sysdir));
    StringCchPrintfW(p, _countof(p), L"%s\\%s", sysdir, file);
    if (GetFileAttributesW(p) != INVALID_FILE_ATTRIBUTES)
    {
        FileVersionOf(p, ver, _countof(ver));
        WbPrintf(out, L"    %s: %s present (%s)\r\n", label, file, ver[0] ? ver : L"no version");
    }
    else
        WbPrintf(out, L"    %s: %s not present\r\n", label, file);
}

void WriteSystemHeader(WBUF *out)
{
    typedef LONG (WINAPI *PFN_RGV)(OSVERSIONINFOW *);
    OSVERSIONINFOW vi;
    SYSTEM_INFO si;
    MEMORYSTATUSEX ms;
    WCHAR buf[300], loc[LOCALE_NAME_MAX_LENGTH];
    DWORD dw, i;
    HKEY k;
    BOOL w64 = FALSE;
    DEVMODEW dm;
    DISPLAY_DEVICEW dd;
    PFN_RGV pRtlGetVersion = (PFN_RGV)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlGetVersion");
    BOOL (WINAPI *pIsW64)(HANDLE, PBOOL) = (BOOL (WINAPI *)(HANDLE, PBOOL))GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "IsWow64Process");
    static const struct { int pf; const WCHAR *name; } feats[] =
    {
        { 10, L"SSE2" }, { 13, L"SSE3" }, { 36, L"SSSE3" }, { 37, L"SSE4.1" }, { 38, L"SSE4.2" },
        { 39, L"AVX" }, { 40, L"AVX2" }, { 41, L"AVX512F" }, { 12, L"NX" }, { 17, L"AES/PCLMUL" },
    };

    WbPrintf(out, L"  Product:        %S\r\n", BRAND_VERSION_FULL_STR);
    WbPrintf(out, L"  Build id:       %S  (commit %S)\r\n", KERNEL_VERSION_BUILD_STR, KERNEL_VERSION_COMMIT_HASH);
    ZeroMemory(&vi, sizeof(vi));
    vi.dwOSVersionInfoSize = sizeof(vi);
    if (pRtlGetVersion && pRtlGetVersion(&vi) == 0)
        WbPrintf(out, L"  System reports: %lu.%lu build %lu %s\r\n", vi.dwMajorVersion, vi.dwMinorVersion, vi.dwBuildNumber, vi.szCSDVersion);
    if (RegStr(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", L"BuildLab", buf, _countof(buf)) && buf[0])
        WbPrintf(out, L"  Build lab:      %s\r\n", buf);

    GetNativeSystemInfo(&si);
    if (pIsW64)
        pIsW64(GetCurrentProcess(), &w64);
    WbPrintf(out, L"  Architecture:   %s (this tool is %s%s)\r\n",
             si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 ? L"amd64" :
             (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL ? L"i386" : L"other"),
#ifdef _M_AMD64
             L"64-bit",
#else
             L"32-bit",
#endif
             w64 ? L", running under WoW64" : L"");

    ZeroMemory(&ms, sizeof(ms));
    ms.dwLength = sizeof(ms);
    if (GlobalMemoryStatusEx(&ms))
        WbPrintf(out, L"  Memory:         %I64u MB total, %I64u MB free; commit limit %I64u MB\r\n",
                 ms.ullTotalPhys >> 20, ms.ullAvailPhys >> 20, ms.ullTotalPageFile >> 20);

    RegStr(HKEY_LOCAL_MACHINE, L"HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0", L"ProcessorNameString", buf, _countof(buf));
    for (dw = (DWORD)wcslen(buf); dw && buf[dw - 1] == L' '; dw--)
        buf[dw - 1] = 0;
    WbPrintf(out, L"  CPU:            %s, %lu logical processor(s)\r\n", buf[0] ? buf : L"(name not available)", si.dwNumberOfProcessors);
    WbAppend(out, L"  CPU features:  ");
    for (i = 0; i < _countof(feats); i++)
        if (IsProcessorFeaturePresent(feats[i].pf))
            WbPrintf(out, L" %s", feats[i].name);
    WbAppend(out, L"\r\n");

    ZeroMemory(&dm, sizeof(dm));
    dm.dmSize = sizeof(dm);
    if (EnumDisplaySettingsW(NULL, ENUM_CURRENT_SETTINGS, &dm))
        WbPrintf(out, L"  Display:        %lux%lu, %lu bit, %lu Hz\r\n", dm.dmPelsWidth, dm.dmPelsHeight, dm.dmBitsPerPel, dm.dmDisplayFrequency);
    ZeroMemory(&dd, sizeof(dd));
    dd.cb = sizeof(dd);
    if (EnumDisplayDevicesW(NULL, 0, &dd, 0))
        WbPrintf(out, L"  Display driver: %s (%s)\r\n", dd.DeviceString, dd.DeviceID);

    WbAppend(out, L"  Graphics packs:\r\n");
    FeatureLine(out, L"OpenGL (Gallium)", L"libgallium_wgl.dll");
    FeatureLine(out, L"Vulkan (lavapipe)", L"vulkan_lvp.dll");
    FeatureLine(out, L"Direct3D 9/11 translation", L"wined3d.dll");

    WbAppend(out, L"  Features (Optional Features state):");
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\ReactOS\\Nitro\\OptionalFeatures", 0, KEY_READ, &k) == ERROR_SUCCESS)
    {
        BOOL any = FALSE;
        for (i = 0;; i++)
        {
            WCHAR name[128], state[32];
            HKEY sub;
            dw = _countof(name);
            if (RegEnumKeyExW(k, i, name, &dw, NULL, NULL, NULL, NULL) != ERROR_SUCCESS)
                break;
            if (RegOpenKeyExW(k, name, 0, KEY_QUERY_VALUE, &sub) == ERROR_SUCCESS)
            {
                if (RegStr(k, name, L"State", state, _countof(state)))
                {
                    WbPrintf(out, L"%s %s=%s", any ? L"," : L"", name, state);
                    any = TRUE;
                }
                RegCloseKey(sub);
            }
        }
        if (!any)
            WbAppend(out, L" none turned on");
        RegCloseKey(k);
    }
    else
        WbAppend(out, L" none recorded");
    WbAppend(out, L"\r\n");

    {
        DWORD mode = 0, src = 0, cfg = 0;
        if (RegDword(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\RegAcl\\AuditStats", L"Mode", &mode))
        {
            RegDword(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\RegAcl\\AuditStats", L"ModeSource", &src);
            RegDword(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\RegAcl\\AuditStats", L"ConfiguredMode", &cfg);
            WbPrintf(out, L"  Registry ACL:   mode %lu (configured %lu, source %lu; 0 = legacy, 1 = audit, 2 = enforce)\r\n", mode, cfg, src);
        }
        else
            WbAppend(out, L"  Registry ACL:   mode not published\r\n");
    }

    GetUserDefaultLocaleName(loc, _countof(loc));
    WbPrintf(out, L"  Locale:         user %s, UI language 0x%04x, ANSI code page %u, OEM code page %u\r\n", loc,
             GetUserDefaultUILanguage(), GetACP(), GetOEMCP());
}

/* ---- environment allow-list ---- */

static void WriteEnv(WBUF *out)
{
    WCHAR *env = GetEnvironmentStringsW(), *p;
    if (!env)
        return;
    for (p = env; *p; p += wcslen(p) + 1)
    {
        const WCHAR *eq = wcschr(p, L'=');
        size_t n;
        if (!eq || eq == p)
            continue;
        n = eq - p;
        if ((n == 4 && !_wcsnicmp(p, L"PATH", 4)) || (n == 7 && !_wcsnicmp(p, L"PATHEXT", 7)) ||
            (n == 4 && !_wcsnicmp(p, L"TEMP", 4)) || (n == 3 && !_wcsnicmp(p, L"TMP", 3)) ||
            (n >= 10 && !_wcsnicmp(p, L"PROCESSOR_", 10)) || (n == 20 && !_wcsnicmp(p, L"NUMBER_OF_PROCESSORS", 20)) ||
            (n == 2 && !_wcsnicmp(p, L"OS", 2)))
            WbPrintf(out, L"  %s\r\n", p);
    }
    FreeEnvironmentStringsW(env);
}

/* ---- the verdict ---- */

static ND_PROC *RootProc(void)
{
    int i;
    for (i = 0; i < g_nProcs; i++)
        if (g_Procs[i].IsRoot)
            return &g_Procs[i];
    return g_nProcs ? &g_Procs[0] : NULL;
}

static const WCHAR *ProcName(DWORD pid)
{
    int i;
    for (i = 0; i < g_nProcs; i++)
        if (g_Procs[i].Pid == pid)
            return BaseName(g_Procs[i].Image);
    return L"?";
}

static void ErrText(DWORD err, WCHAR *out, size_t cch)
{
    DWORD n = FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, err, 0, out, (DWORD)cch, NULL);
    while (n && (out[n - 1] == L'\r' || out[n - 1] == L'\n' || out[n - 1] == L' '))
        out[--n] = 0;
    if (!n)
        StringCchPrintfW(out, cch, L"error %lu", err);
}

/* the import problem that explains a loader error, if the import check found it */
static const WCHAR *ImporterOfMissingDll(const WCHAR *dllPathOrName, WCHAR *importer, size_t cch)
{
    const WCHAR *want = BaseName(dllPathOrName);
    WCHAR pat[300];
    WCHAR *hit;
    StringCchPrintfW(pat, _countof(pat), L" needs %s: not found", want);
    hit = g_Res.ImportReport.p ? wcsstr(g_Res.ImportReport.p, pat) : NULL;
    if (hit)
    {
        WCHAR *s = hit;
        size_t n = 0;
        while (s > g_Res.ImportReport.p && s[-1] != L' ')
            s--;
        while (s + n < hit && n + 1 < cch)
        {
            importer[n] = s[n];
            n++;
        }
        importer[n] = 0;
        return importer;
    }
    return NULL;
}

static void LoaderErrLine(ND_LDRERR *e, BOOL isRoot, WCHAR *line, size_t cch)
{
    WCHAR who[120], imp[MAX_PATH];
    const WCHAR *prefix = isRoot ? L"did not start: " : L"a child process did not start: ";
    who[0] = 0;
    if (!isRoot)
        StringCchPrintfW(who, _countof(who), L"%s: ", ProcName(e->Pid));

    switch (e->Status)
    {
        case 0xC0000135:
        {
            const WCHAR *by = ImporterOfMissingDll(e->Name, imp, _countof(imp));
            if (by)
                StringCchPrintfW(line, cch, L"%s%smissing DLL %s needed by %s", prefix, who, BaseName(e->Name), by);
            else
                StringCchPrintfW(line, cch, L"%s%smissing DLL %s (needed while the program was loading)", prefix, who, BaseName(e->Name));
            break;
        }
        case ND_STATUS_ENTRYPOINT_NOT_FOUND:
        {
            /* the import check names the DLL that should have the function */
            WCHAR pat[300], dll[120] = L"";
            WCHAR *hit;
            StringCchPrintfW(pat, _countof(pat), L" needs %s in ", e->Name);
            hit = g_Res.ImportReport.p ? wcsstr(g_Res.ImportReport.p, pat) : NULL;
            if (hit)
            {
                size_t n = 0;
                hit += wcslen(pat);
                while (hit[n] && hit[n] != L' ' && n + 1 < _countof(dll))
                {
                    dll[n] = hit[n];
                    n++;
                }
                dll[n] = 0;
            }
            if (dll[0])
                StringCchPrintfW(line, cch, L"%s%smissing function %s in %s needed by %s", prefix, who, e->Name, dll, BaseName(e->Module));
            else
                StringCchPrintfW(line, cch, L"%s%smissing function %s needed by %s", prefix, who, e->Name, BaseName(e->Module));
            break;
        }
        case ND_STATUS_ORDINAL_NOT_FOUND:
            StringCchPrintfW(line, cch, L"%s%smissing function #%lu needed by %s", prefix, who, e->Ordinal, BaseName(e->Module));
            break;
        case ND_STATUS_INVALID_IMAGE_FORMAT:
            StringCchPrintfW(line, cch, L"%s%sbad image: %s is not a valid program or DLL here (wrong 32/64-bit type, or damaged)", prefix, who, e->Name);
            break;
        case ND_STATUS_MACHINE_MISMATCH:
            StringCchPrintfW(line, cch, L"%s%sbad image: %s was built for another processor type", prefix, who, e->Name);
            break;
        case ND_STATUS_APP_INIT_FAILURE:
            if (g_Res.BadImage[0])
            {
                StringCchPrintfW(line, cch, L"%s%sbad image: %s", prefix, who, g_Res.BadImage);
                break;
            }
            /* fall through */
        default:
            StringCchPrintfW(line, cch, L"%s%sthe system reports %s (0x%08lx) %s %s", prefix, who, StatusName(e->Status), e->Status, e->Name, e->Module);
            break;
    }
}

static int BuildVerdict(WCHAR lines[][600], int maxLines)
{
    int n = 0, i;
    ND_PROC *root = RootProc();
    WCHAR duration[64];
    DWORD ms = 0;
    BOOL mainSet = FALSE;

    if (root && root->Exited)
        ms = root->EndTick - root->StartTick;
    else
        ms = ElapsedMs();
    StringCchPrintfW(duration, _countof(duration), L"%lu.%01lu s", ms / 1000, (ms % 1000) / 100);

    /* 1: the main sentence */
    lines[n][0] = 0;
    if (g_Res.CreateFailed)
    {
        WCHAR t[200];
        ErrText(g_Res.CreateError, t, _countof(t));
        if (g_Res.Attached)
            StringCchPrintfW(lines[n], 600, L"VERDICT: could not attach to process %lu: %s (error %lu)", g_Opt.AttachPid, t, g_Res.CreateError);
        else if (g_Res.CreateError == ERROR_BAD_EXE_FORMAT)
            StringCchPrintfW(lines[n], 600, L"VERDICT: did not start: this is not a program that runs on this system (error 193: %s)", t);
        else
            StringCchPrintfW(lines[n], 600, L"VERDICT: did not start: Windows could not start the program: %s (error %lu)", t, g_Res.CreateError);
        mainSet = TRUE;
    }
    /* a loader failure of the main program, then any crash of it */
    for (i = 0; !mainSet && i < g_Res.nLdrErr; i++)
    {
        ND_LDRERR *e = &g_Res.LdrErr[i];
        if (root && e->Pid == root->Pid)
        {
            WCHAR t[560];
            LoaderErrLine(e, TRUE, t, _countof(t));
            StringCchPrintfW(lines[n], 600, L"VERDICT: %s", t);
            mainSet = TRUE;
        }
    }
    for (i = 0; !mainSet && i < g_Res.nCrash; i++)
    {
        ND_CRASH *c = &g_Res.Crash[i];
        if (root && c->Pid == root->Pid)
        {
            if (c->Code == ND_EXCEPTION_WINE_STUB && g_Res.nStubs)
                StringCchPrintfW(lines[n], 600, L"VERDICT: crashed after calling a function NitroOS does not implement yet: %S!%S (%lu times), at %s",
                                 g_Res.Stubs[0].Dll[0] ? g_Res.Stubs[0].Dll : "?", g_Res.Stubs[0].Func, g_Res.Stubs[0].Count, c->Where);
            else if (c->Code == EXCEPTION_ACCESS_VIOLATION && c->NumInfo >= 2)
                StringCchPrintfW(lines[n], 600, L"VERDICT: crashed: access violation (%s 0x%I64x) in %s",
                                 c->Info0 == 0 ? L"reading" : (c->Info0 == 1 ? L"writing" : L"executing"), c->Info1, c->Where);
            else
                StringCchPrintfW(lines[n], 600, L"VERDICT: crashed: %s (0x%08lx) in %s", ExceptionName(c->Code), c->Code, c->Where);
            mainSet = TRUE;
        }
    }
    if (!mainSet && g_Res.nStubs)
    {
        StringCchPrintfW(lines[n], 600, L"VERDICT: called a function NitroOS does not implement yet: %S!%S (%lu times); the program %s",
                         g_Res.Stubs[0].Dll[0] ? g_Res.Stubs[0].Dll : "?", g_Res.Stubs[0].Func, g_Res.Stubs[0].Count,
                         root && root->Exited ? L"then ended with an exit code (see PROGRAM)" : L"was still running");
        mainSet = TRUE;
    }
    for (i = 0; !mainSet && i < g_Res.nLdrErr; i++)
    {
        WCHAR t[560];
        LoaderErrLine(&g_Res.LdrErr[i], FALSE, t, _countof(t));
        StringCchPrintfW(lines[n], 600, L"VERDICT: the main program started, but %s", t);
        mainSet = TRUE;
    }
    for (i = 0; !mainSet && i < g_Res.nCrash; i++)
    {
        ND_CRASH *c = &g_Res.Crash[i];
        StringCchPrintfW(lines[n], 600, L"VERDICT: a child process (%s) crashed: %s (0x%08lx) in %s", ProcName(c->Pid),
                         ExceptionName(c->Code), c->Code, c->Where);
        mainSet = TRUE;
    }
    if (!mainSet && root && root->Exited)
    {
        DWORD c = root->ExitCode;
        if ((c & 0xC0000000) == 0xC0000000)
        {
            if (c == 0xC0000135 || c == ND_STATUS_ENTRYPOINT_NOT_FOUND || c == ND_STATUS_ORDINAL_NOT_FOUND || c == ND_STATUS_INVALID_IMAGE_FORMAT ||
                c == ND_STATUS_DLL_INIT_FAILED || (c & 0xFFFF0000) == 0xC0150000)
                StringCchPrintfW(lines[n], 600, L"VERDICT: did not start: the loader stopped it with %s (0x%08lx) after %s", StatusName(c), c, duration);
            else
                StringCchPrintfW(lines[n], 600, L"VERDICT: ended abnormally: exit code 0x%08lx (%s) after %s", c, ExceptionName(c) , duration);
        }
        else if (c == 3 && g_Res.CppThrown)
            StringCchPrintfW(lines[n], 600, L"VERDICT: exited with code 3 after %s: a C++ exception was thrown and nothing caught it (the C++ runtime then called abort)", duration);
        else if (c == 3)
            StringCchPrintfW(lines[n], 600, L"VERDICT: exited with code 3 after %s (3 is the code the C runtime's abort() uses; it can also be the program's own choice)", duration);
        else
            StringCchPrintfW(lines[n], 600, L"VERDICT: exited normally with code %lu after %s", c, duration);
        mainSet = TRUE;
    }
    if (!mainSet && g_Res.StillRunning)
    {
        StringCchPrintfW(lines[n], 600, L"VERDICT: still running after %lu s%s (it did not crash, but it had not finished)",
                         (ElapsedMs() + 500) / 1000, g_Res.StoppedByUser ? L", report requested by you" : L"");
        mainSet = TRUE;
    }
    if (!mainSet)
        StringCchPrintfW(lines[n], 600, L"VERDICT: no result (the program did not report an exit)");
    n++;

    /* 2..: what else was seen */
    if (g_Res.StillRunning && g_Res.nLdrErr && n < maxLines)
        StringCchPrintfW(lines[n++], 600, L"The program was waiting at a system error box (the loader asked Windows to show it) when the report was made, after %lu s.", (ElapsedMs() + 500) / 1000);
    else if (g_Res.StillRunning && n < maxLines && !wcsstr(lines[0], L"still running"))
        StringCchPrintfW(lines[n++], 600, L"Still running after %lu s when the report was made: stacks of every thread are in the SNAPSHOT section.", (ElapsedMs() + 500) / 1000);
    if (g_Res.nStubs && n < maxLines && !wcsstr(lines[0], L"not implement yet"))
    {
        int k;
        WCHAR *p = lines[n];
        size_t room = 600;
        StringCchPrintfW(p, room, L"Called a function NitroOS does not implement yet: ");
        for (k = 0; k < g_Res.nStubs && k < 3; k++)
        {
            WCHAR one[220];
            StringCchPrintfW(one, _countof(one), L"%s%S!%S (%lu times)", k ? L"; " : L"", g_Res.Stubs[k].Dll[0] ? g_Res.Stubs[k].Dll : "?",
                             g_Res.Stubs[k].Func, g_Res.Stubs[k].Count);
            StringCchCatW(p, room, one);
        }
        if (g_Res.nStubs > 3)
            StringCchCatW(p, room, L"; more in the timeline");
        n++;
    }
    if (g_Res.nImpProblems && n < maxLines)
    {
        StringCchPrintfW(lines[n++], 600, L"Import check: %d problem(s) found in the program's imports (see IMPORT CHECK): the first one: %s",
                         g_Res.nImpProblems, g_Res.FirstImpProblem);
    }
    if (g_Res.nLdrErr && n < maxLines && !wcsstr(lines[0], L"did not start"))
    {
        WCHAR t[560];
        LoaderErrLine(&g_Res.LdrErr[0], FALSE, t, _countof(t));
        StringCchPrintfW(lines[n++], 600, L"Loader: %s", t);
    }
    if (g_Res.DebuggerQuery && n < maxLines)
        StringCchPrintfW(lines[n++], 600, L"The program asked whether a debugger is attached (IsDebuggerPresent, %lu time(s)): this tool is one, so it will have been told yes.", g_Res.DebuggerQueryCount);
    if (g_Res.nProcsStarted > 1 && n < maxLines)
        StringCchPrintfW(lines[n++], 600, L"%lu processes were started in total (child processes are followed).", g_Res.nProcsStarted);
    if (g_Res.LastDebugText[0] && n < maxLines)
        StringCchPrintfW(lines[n++], 600, L"Last debug text from the program: %.150s", g_Res.LastDebugText);
    return n;
}

void BuildReport(WBUF *out)
{
    WCHAR (*lines)[600] = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 10 * 600 * sizeof(WCHAR));
    WCHAR name[260], cwd[MAX_PATH], user[128];
    SYSTEMTIME st;
    DWORD n, i, un = _countof(user);
    int nl;
    int k;
    ND_PROC *root = RootProc();

    if (!lines)
        return;
    nl = BuildVerdict(lines, 8);
    GetSystemTime(&st);

    /* the first ten lines: the verdict, then the privacy note and the author */
    for (k = 0; k < nl; k++)
        WbPrintf(out, L"%s\r\n", lines[k]);
    GetUserNameW(user, &un);
    WbPrintf(out, L"PRIVACY: this report contains file paths, the user name (%s), the command line as you typed it and the module list. Nothing was uploaded: you decide whether to send it.\r\n", user);
    WbPrintf(out, L"Made by nitrodiag on %S, %04u-%02u-%02u %02u:%02u:%02u UTC.\r\n", BRAND_VERSION_FULL_STR,
             st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    WbAppend(out, L"\r\n");
    (void)name; (void)n; (void)i;

    WbAppend(out, L"==== PROGRAM ====\r\n");
    if (g_Res.Attached)
        WbPrintf(out, L"  attached to process id %lu\r\n", g_Opt.AttachPid);
    else
        WbPrintf(out, L"  command line:   %s\r\n", g_Opt.CmdLine ? g_Opt.CmdLine : L"");
    if (root)
        WbPrintf(out, L"  program:        %s (%s)\r\n", root->Image, root->Wow64 ? L"32-bit on a 64-bit system" :
#ifdef _M_AMD64
                 L"64-bit"
#else
                 L"32-bit"
#endif
                 );
    GetCurrentDirectoryW(_countof(cwd), cwd);
    WbPrintf(out, L"  working folder: %s\r\n", g_Opt.WorkDir[0] ? g_Opt.WorkDir : cwd);
    WbPrintf(out, L"  started:        %04u-%02u-%02u %02u:%02u:%02u UTC (the clock of this computer)\r\n", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    if (root && root->Exited)
        WbPrintf(out, L"  exit code:      0x%08lx (%ld) after %lu ms\r\n", root->ExitCode, (LONG)root->ExitCode, root->EndTick - root->StartTick);
    WbPrintf(out, L"  processes:      %lu started, %lu hard error(s) reported by the loader, %lu first-chance exception(s)\r\n",
             g_Res.nProcsStarted, g_Res.nHardErrors, g_Res.nFirstChance);
    WbPrintf(out, L"  debug text:     %lu line(s) from the program; %lu loader trace line(s) seen\r\n", g_Res.nDebugStrings, g_Res.nSnapLines);
    if (g_Res.Extras.p)
        WbAppend(out, g_Res.Extras.p);

    WbAppend(out, L"\r\n==== SYSTEM ====\r\n");
    WriteSystemHeader(out);
    WbAppend(out, L"  Environment (only these names are included):\r\n");
    WriteEnv(out);

    WbAppend(out, L"\r\n==== TIMELINE ====\r\n");
    if (g_Res.Timeline.p)
        WbAppend(out, g_Res.Timeline.p);

    if (g_Res.nCrash)
    {
        WbAppend(out, L"\r\n==== CRASH DETAILS ====\r\n");
        for (k = 0; k < g_Res.nCrash; k++)
        {
            ND_CRASH *c = &g_Res.Crash[k];
            WbPrintf(out, L"Process %lu (%s), thread %lu: %s (0x%08lx) at %s\r\n", c->Pid, ProcName(c->Pid), c->Tid,
                     ExceptionName(c->Code), c->Code, c->Where);
            if (c->Detail.p)
                WbAppend(out, c->Detail.p);
        }
    }

    {
        BOOL head = FALSE;
        for (k = 0; k < g_Res.nShapes; k++)
        {
            if (g_Res.Shapes[k].Count <= 3)
                continue;
            if (!head)
            {
                WbAppend(out, L"\r\n==== DEBUG TEXT PRINTED MANY TIMES (only the first three of each kind are in the timeline) ====\r\n");
                head = TRUE;
            }
            WbPrintf(out, L"  %lu x  %.100s\r\n", g_Res.Shapes[k].Count, g_Res.Shapes[k].Sample);
        }
    }

    if (g_Res.nStubs)
    {
        WbAppend(out, L"\r\n==== FUNCTIONS NOT IMPLEMENTED YET (called by the program) ====\r\n");
        for (k = 0; k < g_Res.nStubs; k++)
            WbPrintf(out, L"  %S!%S  %lu time(s)\r\n", g_Res.Stubs[k].Dll[0] ? g_Res.Stubs[k].Dll : "?", g_Res.Stubs[k].Func, g_Res.Stubs[k].Count);
    }

    if (g_Res.ImportReport.p)
    {
        WbAppend(out, L"\r\n==== IMPORT CHECK ====\r\n");
        WbAppend(out, g_Res.ImportReport.p);
    }
    if (g_Res.Snapshot.p)
    {
        WbAppend(out, L"\r\n==== SNAPSHOT (processes still running) ====\r\n");
        WbAppend(out, g_Res.Snapshot.p);
    }

    WbAppend(out, L"\r\n==== WHAT THIS REPORT CONTAINS ====\r\n");
    WbAppend(out, L"  The command line, the working folder, the module list with file paths and versions, debug text the program printed (repeated lines are counted),\r\n");
    WbAppend(out, L"  exceptions with module+offset and a stack trace, a few environment names (PATH, PATHEXT, TEMP, PROCESSOR_*, NUMBER_OF_PROCESSORS, OS),\r\n");
    WbAppend(out, L"  hardware and system settings, and the user name. A minidump (crash-*.dmp) is in the zip only when the program crashed; it holds the stacks\r\n");
    WbAppend(out, L"  and module list of the crashed process, not its whole memory. No file contents, no screenshots (unless you used /screenshot). Nothing is uploaded.\r\n");
    HeapFree(GetProcessHeap(), 0, lines);
}
