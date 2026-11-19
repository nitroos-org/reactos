/*
 * PROJECT:     NitroOS compatibility log tool
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Import-table check: which DLL or function a program (or one of its DLLs) needs is not there
 */

#include "nitrodiag.h"

#define MAX_CHECKED     300

typedef struct _PEIMG
{
    HANDLE hFile, hMap;
    BYTE  *base;
    DWORD  size;
    BOOL   is64;
    WORD   machine;
    DWORD  nSections;
    IMAGE_SECTION_HEADER *sec;
    IMAGE_DATA_DIRECTORY dirs[16];
} PEIMG;

static BOOL PeMap(const WCHAR *path, PEIMG *pe)
{
    IMAGE_DOS_HEADER *dos;
    IMAGE_NT_HEADERS32 *nt32;
    DWORD hi = 0, i;
    DWORD nrva;

    ZeroMemory(pe, sizeof(*pe));
    pe->hFile = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
                            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (pe->hFile == INVALID_HANDLE_VALUE)
        return FALSE;
    pe->size = GetFileSize(pe->hFile, &hi);
    if (hi || pe->size < 0x200)
        goto fail;
    pe->hMap = CreateFileMappingW(pe->hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!pe->hMap)
        goto fail;
    pe->base = MapViewOfFile(pe->hMap, FILE_MAP_READ, 0, 0, 0);
    if (!pe->base)
        goto fail;
    dos = (IMAGE_DOS_HEADER *)pe->base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0 || (DWORD)dos->e_lfanew + sizeof(IMAGE_NT_HEADERS32) > pe->size)
        goto fail;
    nt32 = (IMAGE_NT_HEADERS32 *)(pe->base + dos->e_lfanew);
    if (nt32->Signature != IMAGE_NT_SIGNATURE)
        goto fail;
    pe->machine = nt32->FileHeader.Machine;
    pe->is64 = (nt32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC);
    pe->nSections = nt32->FileHeader.NumberOfSections;
    if (pe->is64)
    {
        IMAGE_NT_HEADERS64 *nt64 = (IMAGE_NT_HEADERS64 *)nt32;
        nrva = nt64->OptionalHeader.NumberOfRvaAndSizes;
        for (i = 0; i < 16 && i < nrva; i++)
            pe->dirs[i] = nt64->OptionalHeader.DataDirectory[i];
        pe->sec = (IMAGE_SECTION_HEADER *)((BYTE *)&nt64->OptionalHeader + nt64->FileHeader.SizeOfOptionalHeader);
    }
    else
    {
        nrva = nt32->OptionalHeader.NumberOfRvaAndSizes;
        for (i = 0; i < 16 && i < nrva; i++)
            pe->dirs[i] = nt32->OptionalHeader.DataDirectory[i];
        pe->sec = (IMAGE_SECTION_HEADER *)((BYTE *)&nt32->OptionalHeader + nt32->FileHeader.SizeOfOptionalHeader);
    }
    if ((BYTE *)(pe->sec + pe->nSections) > pe->base + pe->size)
        goto fail;
    return TRUE;
fail:
    if (pe->base)
        UnmapViewOfFile(pe->base);
    if (pe->hMap)
        CloseHandle(pe->hMap);
    CloseHandle(pe->hFile);
    ZeroMemory(pe, sizeof(*pe));
    return FALSE;
}

static void PeUnmap(PEIMG *pe)
{
    if (pe->base)
        UnmapViewOfFile(pe->base);
    if (pe->hMap)
        CloseHandle(pe->hMap);
    if (pe->hFile && pe->hFile != INVALID_HANDLE_VALUE)
        CloseHandle(pe->hFile);
    ZeroMemory(pe, sizeof(*pe));
}

static void *PeRva(PEIMG *pe, DWORD rva, DWORD need)
{
    DWORD i;
    for (i = 0; i < pe->nSections; i++)
    {
        DWORD va = pe->sec[i].VirtualAddress;
        DWORD span = pe->sec[i].Misc.VirtualSize > pe->sec[i].SizeOfRawData ? pe->sec[i].Misc.VirtualSize : pe->sec[i].SizeOfRawData;
        if (rva >= va && rva < va + span)
        {
            DWORD off = rva - va + pe->sec[i].PointerToRawData;
            if (off + need > pe->size || rva - va >= pe->sec[i].SizeOfRawData)
                return NULL;
            return pe->base + off;
        }
    }
    /* headers */
    if (rva + need <= pe->size && rva < 0x200)
        return pe->base + rva;
    return NULL;
}

static const char *PeStr(PEIMG *pe, DWORD rva)
{
    const char *s = PeRva(pe, rva, 1);
    DWORD n = 0;
    if (!s)
        return NULL;
    /* make sure it ends inside the file */
    while (s + n < (const char *)pe->base + pe->size && s[n] && n < 600)
        n++;
    if (s[n])
        return NULL;
    return s;
}

BOOL PeMachine(const WCHAR *path, WORD *Machine)
{
    PEIMG pe;
    if (!PeMap(path, &pe))
        return FALSE;
    *Machine = pe.machine;
    PeUnmap(&pe);
    return TRUE;
}

/* 1 = found, 0 = not exported, 2 = forwarded (text in fwd) */
static int ExportLookup(PEIMG *pe, const char *name, DWORD ordinal, BOOL byOrd, DWORD *rvaOut, char *fwd, size_t cchFwd)
{
    IMAGE_EXPORT_DIRECTORY *ed;
    DWORD dirRva = pe->dirs[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    DWORD dirSize = pe->dirs[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    DWORD *funcs, *names;
    WORD *ords;
    DWORD idx = (DWORD)-1, i, frva;

    if (!dirRva)
        return 0;
    ed = PeRva(pe, dirRva, sizeof(*ed));
    if (!ed)
        return 0;
    funcs = PeRva(pe, ed->AddressOfFunctions, ed->NumberOfFunctions * 4);
    if (!funcs)
        return 0;
    if (byOrd)
    {
        if (ordinal < ed->Base || ordinal - ed->Base >= ed->NumberOfFunctions)
            return 0;
        idx = ordinal - ed->Base;
    }
    else
    {
        names = PeRva(pe, ed->AddressOfNames, ed->NumberOfNames * 4);
        ords = PeRva(pe, ed->AddressOfNameOrdinals, ed->NumberOfNames * 2);
        if (!names || !ords)
            return 0;
        for (i = 0; i < ed->NumberOfNames; i++)
        {
            const char *n = PeStr(pe, names[i]);
            if (n && !strcmp(n, name))
            {
                idx = ords[i];
                break;
            }
        }
        if (idx == (DWORD)-1 || idx >= ed->NumberOfFunctions)
            return 0;
    }
    frva = funcs[idx];
    if (!frva)
        return 0;
    if (frva >= dirRva && frva < dirRva + dirSize)
    {
        const char *f = PeStr(pe, frva);
        if (f && fwd)
            StringCchCopyA(fwd, cchFwd, f);
        return 2;
    }
    if (rvaOut)
        *rvaOut = frva;
    return 1;
}

BOOL PeFindExportRva(const WCHAR *path, const char *name, DWORD *rva)
{
    PEIMG pe;
    BOOL ok = FALSE;
    DWORD r = 0;
    if (!PeMap(path, &pe))
        return FALSE;
    if (ExportLookup(&pe, name, 0, FALSE, &r, NULL, 0) == 1)
    {
        *rva = r;
        ok = TRUE;
    }
    PeUnmap(&pe);
    return ok;
}

/* ---- finding a DLL the way the program would ---- */

typedef struct _SEARCH
{
    WCHAR AppDir[MAX_PATH];
    BOOL  Is32;
} SEARCH;

static BOOL IsApiSet(const WCHAR *name)
{
    return !_wcsnicmp(name, L"api-ms-", 7) || !_wcsnicmp(name, L"ext-ms-", 7);
}

static BOOL FileThere(const WCHAR *p)
{
    DWORD a = GetFileAttributesW(p);
    return a != INVALID_FILE_ATTRIBUTES && !(a & FILE_ATTRIBUTE_DIRECTORY);
}

static BOOL FindDll(const SEARCH *s, const WCHAR *name, WCHAR *out)
{
    WCHAR dir[MAX_PATH], pathEnv[8192];
    WCHAR *tok, *ctx = NULL;

    StringCchPrintfW(out, MAX_PATH, L"%s\\%s", s->AppDir, name);
    if (FileThere(out))
        return TRUE;
    dir[0] = 0;
#ifdef _M_AMD64
    if (s->Is32)
        GetSystemWow64DirectoryW(dir, _countof(dir));
    else
#endif
        GetSystemDirectoryW(dir, _countof(dir));
    StringCchPrintfW(out, MAX_PATH, L"%s\\%s", dir, name);
    if (FileThere(out))
        return TRUE;
    GetWindowsDirectoryW(dir, _countof(dir));
    StringCchPrintfW(out, MAX_PATH, L"%s\\%s", dir, name);
    if (FileThere(out))
        return TRUE;
    GetCurrentDirectoryW(_countof(dir), dir);
    StringCchPrintfW(out, MAX_PATH, L"%s\\%s", dir, name);
    if (FileThere(out))
        return TRUE;
    if (GetEnvironmentVariableW(L"PATH", pathEnv, _countof(pathEnv)))
    {
        for (tok = wcstok_s(pathEnv, L";", &ctx); tok; tok = wcstok_s(NULL, L";", &ctx))
        {
            if (!*tok)
                continue;
            StringCchPrintfW(out, MAX_PATH, L"%s\\%s", tok, name);
            if (FileThere(out))
                return TRUE;
        }
    }
    out[0] = 0;
    return FALSE;
}

/* does DLL path export the function? follows forwarders up to 4 levels */
static int CheckExport(const SEARCH *s, const WCHAR *dllPath, const char *name, DWORD ord, BOOL byOrd, int depth, char *why, size_t cchWhy)
{
    PEIMG pe;
    char fwd[300];
    int r;

    if (!PeMap(dllPath, &pe))
        return 1;       /* cannot read it: do not claim anything */
    r = ExportLookup(&pe, name, ord, byOrd, NULL, fwd, sizeof(fwd));
    PeUnmap(&pe);
    if (r == 2 && depth < 4)
    {
        char dllA[260], *dot = strchr(fwd, '.');
        WCHAR dllW[MAX_PATH], fp[MAX_PATH];
        if (!dot)
            return 1;
        StringCchCopyNA(dllA, sizeof(dllA), fwd, dot - fwd);
        StringCchPrintfW(dllW, _countof(dllW), L"%S.dll", dllA);
        if (IsApiSet(dllW))
            return 1;
        if (!FindDll(s, dllW, fp))
        {
            StringCchPrintfA(why, cchWhy, "forwarded to %s, which is missing", fwd);
            return 0;
        }
        if (dot[1] == '#')
            return CheckExport(s, fp, NULL, (DWORD)atoi(dot + 2), TRUE, depth + 1, why, cchWhy);
        return CheckExport(s, fp, dot + 1, 0, FALSE, depth + 1, why, cchWhy);
    }
    return r ? 1 : 0;
}

/* ---- the walk ---- */

typedef struct _QENT
{
    WCHAR Path[MAX_PATH];
    WCHAR From[MAX_PATH];
} QENT;

static void RecordProblem(const WCHAR *kind, const WCHAR *importer, const WCHAR *what)
{
    if (!g_Res.BadImage[0] && wcsstr(kind, L"-bit DLL in a"))
        StringCchPrintfW(g_Res.BadImage, _countof(g_Res.BadImage), L"%s needs %s, but that is a %s", importer, what, kind);
    if (!g_Res.nImpProblems++)
        StringCchPrintfW(g_Res.FirstImpProblem, _countof(g_Res.FirstImpProblem), L"%s: %s needs %s", kind, importer, what);
}

void ImportsCheck(const WCHAR *exe, BOOL is32target, WBUF *out, int *nProblems)
{
    QENT *q = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, MAX_CHECKED * sizeof(QENT));
    int head = 0, tail = 0, i;
    SEARCH s;
    WCHAR *slash;
    int checked = 0;

    *nProblems = 0;
    if (!q)
        return;
    StringCchCopyW(s.AppDir, _countof(s.AppDir), exe);
    slash = wcsrchr(s.AppDir, L'\\');
    if (slash)
        *slash = 0;
    else
        GetCurrentDirectoryW(_countof(s.AppDir), s.AppDir);
    s.Is32 = is32target;

    StringCchCopyW(q[tail++].Path, MAX_PATH, exe);
    while (head < tail)
    {
        PEIMG pe;
        QENT *cur = &q[head++];
        DWORD impRva;
        IMAGE_IMPORT_DESCRIPTOR *id;
        const WCHAR *curName = wcsrchr(cur->Path, L'\\');
        curName = curName ? curName + 1 : cur->Path;

        if (!PeMap(cur->Path, &pe))
            continue;
        checked++;
        impRva = pe.dirs[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        id = impRva ? PeRva(&pe, impRva, sizeof(*id)) : NULL;
        for (; id && id->Name; id++)
        {
            const char *dllA = PeStr(&pe, id->Name);
            WCHAR dllW[MAX_PATH], full[MAX_PATH];
            BOOL found;
            DWORD thunkRva;

            if (!dllA)
                break;
            MultiByteToWideChar(CP_ACP, 0, dllA, -1, dllW, _countof(dllW));
            if (IsApiSet(dllW))
                continue;       /* the loader resolves API set names itself */
            found = FindDll(&s, dllW, full);
            if (!found)
            {
                WbPrintf(out, L"MISSING DLL   %s needs %s: not found in the program folder, the system folder, the Windows folder or PATH\r\n",
                         curName, dllW);
                RecordProblem(L"missing DLL", curName, dllW);
                (*nProblems)++;
                continue;
            }
            {
                WORD mach = 0;
                if (PeMachine(full, &mach))
                {
                    BOOL dll32 = (mach == IMAGE_FILE_MACHINE_I386);
                    if (dll32 != is32target)
                    {
                        WbPrintf(out, L"BAD IMAGE     %s needs %s: found %s, but it is a %s DLL and the program is %s\r\n",
                                 curName, dllW, full, dll32 ? L"32-bit" : L"64-bit", is32target ? L"32-bit" : L"64-bit");
                        RecordProblem(dll32 ? L"32-bit DLL in a 64-bit program" : L"64-bit DLL in a 32-bit program", curName, dllW);
                        (*nProblems)++;
                        continue;
                    }
                }
            }

            /* functions */
            thunkRva = id->OriginalFirstThunk ? id->OriginalFirstThunk : id->FirstThunk;
            if (thunkRva)
            {
                DWORD step = pe.is64 ? 8 : 4;
                DWORD idx;
                for (idx = 0; idx < 20000; idx++)
                {
                    BYTE *t = PeRva(&pe, thunkRva + idx * step, step);
                    ULONG64 v;
                    BOOL byOrd;
                    char why[200];
                    int r;
                    if (!t)
                        break;
                    v = pe.is64 ? *(ULONG64 *)t : *(DWORD *)t;
                    if (!v)
                        break;
                    byOrd = pe.is64 ? (v >> 63) != 0 : (v & 0x80000000) != 0;
                    why[0] = 0;
                    if (byOrd)
                    {
                        r = CheckExport(&s, full, NULL, (DWORD)(v & 0xFFFF), TRUE, 0, why, sizeof(why));
                        if (!r)
                        {
                            WbPrintf(out, L"MISSING FUNC  %s needs ordinal %lu in %s (%s): not exported\r\n", curName,
                                     (DWORD)(v & 0xFFFF), dllW, full);
                            RecordProblem(L"missing ordinal", curName, dllW);
                            (*nProblems)++;
                        }
                    }
                    else
                    {
                        const char *fn = PeStr(&pe, (DWORD)(v & 0x7FFFFFFF) + 2);
                        if (!fn)
                            break;
                        r = CheckExport(&s, full, fn, 0, FALSE, 0, why, sizeof(why));
                        if (!r)
                        {
                            WCHAR ver[40];
                            FileVersionOf(full, ver, _countof(ver));
                            WbPrintf(out, L"MISSING FUNC  %s needs %S in %s (%s, version %s): %s\r\n", curName, fn, dllW, full,
                                     ver[0] ? ver : L"-", L"not exported");
                            if (why[0])
                                WbPrintf(out, L"              %S\r\n", why);
                            {
                                WCHAR t2[260];
                                StringCchPrintfW(t2, _countof(t2), L"%S in %s", fn, dllW);
                                RecordProblem(L"missing function", curName, t2);
                            }
                            (*nProblems)++;
                        }
                    }
                }
            }

            /* queue the DLL itself (once) */
            for (i = 0; i < tail; i++)
                if (!_wcsicmp(q[i].Path, full))
                    break;
            if (i == tail && tail < MAX_CHECKED)
            {
                StringCchCopyW(q[tail].Path, MAX_PATH, full);
                StringCchCopyW(q[tail].From, MAX_PATH, curName);
                tail++;
            }
        }
        PeUnmap(&pe);
    }
    WbPrintf(out, L"checked the imports of %d module(s) (this tool resolves them itself from the files on disk; API set names are left to the loader)\r\n", checked);
    HeapFree(GetProcessHeap(), 0, q);
}
