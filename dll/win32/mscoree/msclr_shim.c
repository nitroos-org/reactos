/*
 * mscoree.dll -> real Microsoft CLR (mscoreei.dll) handoff shim.
 *
 * When a genuine Microsoft .NET Framework v4.0.30319 is installed, hand the
 * CLR hosting entry points off to the installed mscoreei.dll instead of taking
 * the built-in Wine/Mono path.  This mirrors what the real system32\mscoree.dll
 * does on Windows: it is only a thin shim that forwards to the version-specific
 * mscoreei.dll in the framework directory, which in turn loads clr.dll.
 *
 * mscoreei.dll refuses to initialise unless mscoree.dll is already loaded: its
 * DllMain calls GetModuleHandleW(L"mscoree.dll") and returns FALSE when that is
 * NULL (see T116 - this is by design, not a loader bug).  Because this code only
 * ever loads mscoreei from inside mscoree's own exports, that precondition is
 * always satisfied here.
 *
 * Copyright 2026 Tomas Srnka
 */

#include <stdarg.h>

#define COBJMACROS
#include "windef.h"
#include "winbase.h"
#include "winuser.h"
#include "winnls.h"
#include "winreg.h"
#include "ole2.h"
#include "ocidl.h"
#include "cor.h"
#include "mscoree.h"
#include "corhdr.h"
#include "cordebug.h"
#include "metahost.h"
#include "fusion.h"
#include "wine/list.h"
#include "mscoree_private.h"

#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(mscoree);

static HMODULE real_mscoreei;
static BOOL real_mscoreei_done;

static CRITICAL_SECTION msclr_cs;
static CRITICAL_SECTION_DEBUG msclr_cs_debug =
{
    0, 0, &msclr_cs,
    { &msclr_cs_debug.ProcessLocksList,
      &msclr_cs_debug.ProcessLocksList },
      0, 0, { (DWORD_PTR)(__FILE__ ": msclr_cs") }
};
static CRITICAL_SECTION msclr_cs = { &msclr_cs_debug, -1, 0, 0, 0, 0 };

static BOOL find_real_mscoreei_path(WCHAR *path)
{
    static const WCHAR netfx_key[] =
        {'S','O','F','T','W','A','R','E','\\','M','i','c','r','o','s','o','f','t',
         '\\','.','N','E','T','F','r','a','m','e','w','o','r','k',0};
    static const WCHAR install_root[] =
        {'I','n','s','t','a','l','l','R','o','o','t',0};
    static const WCHAR v4_subpath[] =
        {'v','4','.','0','.','3','0','3','1','9','\\',
         'm','s','c','o','r','e','e','i','.','d','l','l',0};
    static const WCHAR msnet_sub[] =
        {'\\','M','i','c','r','o','s','o','f','t','.','N','E','T','\\',
         'F','r','a','m','e','w','o','r','k','\\',0};
    HKEY key;
    DWORD type, size;
    WCHAR root[MAX_PATH];
    UINT len;

    /* 1. HKLM\SOFTWARE\Microsoft\.NETFramework : InstallRoot */
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, netfx_key, 0, KEY_QUERY_VALUE, &key) == ERROR_SUCCESS)
    {
        size = sizeof(root);
        if (RegQueryValueExW(key, install_root, NULL, &type, (BYTE *)root, &size) == ERROR_SUCCESS &&
            (type == REG_SZ || type == REG_EXPAND_SZ) && root[0])
        {
            RegCloseKey(key);
            len = lstrlenW(root);
            if (len + lstrlenW(v4_subpath) + 2 < MAX_PATH)
            {
                lstrcpyW(path, root);
                if (path[len - 1] != '\\')
                {
                    path[len] = '\\';
                    path[len + 1] = 0;
                }
                lstrcatW(path, v4_subpath);
                if (GetFileAttributesW(path) != INVALID_FILE_ATTRIBUTES)
                    return TRUE;
            }
        }
        else
            RegCloseKey(key);
    }

    /* 2. %SystemRoot%\Microsoft.NET\Framework\v4.0.30319\mscoreei.dll */
    len = GetWindowsDirectoryW(root, MAX_PATH);
    if (len && len + lstrlenW(msnet_sub) + lstrlenW(v4_subpath) < MAX_PATH)
    {
        lstrcpyW(path, root);
        lstrcatW(path, msnet_sub);
        lstrcatW(path, v4_subpath);
        if (GetFileAttributesW(path) != INVALID_FILE_ATTRIBUTES)
            return TRUE;
    }

    return FALSE;
}

/* Returns a handle to the installed Microsoft mscoreei.dll, or NULL when no
 * real CLR is present (in which case callers fall back to the Mono path).
 * The result is cached for the life of the process. */
HMODULE mscoree_get_real_mscoreei(void)
{
    static const WCHAR disable_env[] =
        {'M','S','C','O','R','E','E','_','N','O','_','M','S','C','L','R',0};
    WCHAR path[MAX_PATH], tmp[4];

    if (real_mscoreei_done)
        return real_mscoreei;

    EnterCriticalSection(&msclr_cs);
    if (!real_mscoreei_done)
    {
        if (!GetEnvironmentVariableW(disable_env, tmp, ARRAY_SIZE(tmp)) &&
            find_real_mscoreei_path(path))
        {
            /* LOAD_WITH_ALTERED_SEARCH_PATH so clr.dll and the other siblings in
             * the framework directory resolve from there. */
            real_mscoreei = LoadLibraryExW(path, NULL, LOAD_WITH_ALTERED_SEARCH_PATH);
            if (real_mscoreei)
                TRACE("handed CLR hosting off to real mscoreei %s (%p)\n",
                      debugstr_w(path), real_mscoreei);
            else
                WARN("found real mscoreei %s but LoadLibrary failed (%lu)\n",
                     debugstr_w(path), GetLastError());
        }
        real_mscoreei_done = TRUE;
    }
    LeaveCriticalSection(&msclr_cs);

    return real_mscoreei;
}

/* Convenience: resolve an export from the real mscoreei, or NULL.  Returns
 * void* (as the Mono loader does) so callers can cast straight to the matching
 * function-pointer type without tripping -Wcast-function-type. */
void *mscoree_real_export(const char *name)
{
    HMODULE mod = mscoree_get_real_mscoreei();
    return mod ? (void *)GetProcAddress(mod, name) : NULL;
}

/* Ordinal 24 (no name).  Microsoft clr.dll calls
 * GetProcAddress(GetModuleHandle("mscoree.dll"), MAKEINTRESOURCE(24)) during
 * EEStartup and invokes the result as HRESULT (WINAPI *)(void *, void **);
 * it treats a success HRESULT as "the out-interface is valid" and calls
 * through it.  Microsoft's own mscoree.dll implements this ordinal as a pure
 * forwarder: it resolves ordinal 24 from the runtime's mscoreei.dll and calls
 * it with the same two arguments, returning CLR_E_SHIM_RUNTIMEEXPORT when that
 * is not possible.  Do the same.  Without an installed Microsoft runtime there
 * is no caller for this ordinal (Mono never uses it). */
HRESULT WINAPI MSCOREE_Ordinal24(void *arg1, void **arg2)
{
    typedef HRESULT (WINAPI *ord24_fn)(void *, void **);
    ord24_fn fn = (ord24_fn)mscoree_real_export((const char *)MAKEINTRESOURCEA(24));

    TRACE("(%p, %p) -> real %p\n", arg1, arg2, fn);
    if (!fn)
        return CLR_E_SHIM_RUNTIMEEXPORT;
    return fn(arg1, arg2);
}

/* Native vtable-fixup slots of mixed-mode (C++/CLI, IJW) assemblies.  The
 * CLR calls these mscoree exports (ordinals 31 and 37) when it patches the
 * vtable fixups of such an assembly it loaded through LoadLibrary.  Microsoft's
 * mscoree.dll (4.0.31106) implements them as plain slot accessors:
 *   Get: return *ppVTEntry          (ret 8)
 *   Set: *ppVTEntry = pTarget       (ret 0xC)
 * Leaving them as stubs raised EXCEPTION_WINE_STUB inside the CLR, which
 * surfaced as System.Runtime.InteropServices.SEHException (E_FAIL) in managed
 * code that loads an IJW assembly, e.g. KROS ALFA plus startup. */
BYTE * WINAPI GetTargetForVTableEntry(HINSTANCE hinst, BYTE **ppVTEntry)
{
    TRACE("(%p, %p)\n", hinst, ppVTEntry);
    return *ppVTEntry;
}

void WINAPI SetTargetForVTableEntry(HINSTANCE hinst, BYTE **ppVTEntry, BYTE *pTarget)
{
    TRACE("(%p, %p, %p)\n", hinst, ppVTEntry, pTarget);
    *ppVTEntry = pTarget;
}

/* Exports that Microsoft clr.dll delay-imports from mscoree.dll by name and
 * that Microsoft's mscoree implements by forwarding to mscoreei.dll. */
HANDLE WINAPI GetProcessExecutableHeap(void)
{
    typedef HANDLE (WINAPI *fn_t)(void);
    fn_t fn = (fn_t)mscoree_real_export("GetProcessExecutableHeap");

    TRACE("() -> real %p\n", fn);
    if (!fn)
    {
        FIXME("no Microsoft runtime installed\n");
        return NULL;
    }
    return fn();
}

HRESULT WINAPI CorBindToRuntimeEx(LPWSTR, LPWSTR, DWORD, REFCLSID, REFIID, LPVOID *);

HRESULT WINAPI CorBindToRuntime(LPCWSTR version, LPCWSTR flavor, REFCLSID rclsid,
                                REFIID riid, LPVOID *ppv)
{
    typedef HRESULT (WINAPI *fn_t)(LPCWSTR, LPCWSTR, REFCLSID, REFIID, LPVOID *);
    fn_t fn = (fn_t)mscoree_real_export("CorBindToRuntime");

    TRACE("(%s, %s, %s, %s, %p) -> real %p\n", debugstr_w(version), debugstr_w(flavor),
          debugstr_guid(rclsid), debugstr_guid(riid), ppv, fn);
    if (fn)
        return fn(version, flavor, rclsid, riid, ppv);
    /* Same semantics as CorBindToRuntimeEx with no startup flags. */
    return CorBindToRuntimeEx((LPWSTR)version, (LPWSTR)flavor, 0, rclsid, riid, ppv);
}
