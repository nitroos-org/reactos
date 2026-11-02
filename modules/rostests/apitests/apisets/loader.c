/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     API set names through the loader: minor versions and application manifests
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include <apitest.h>
#include <windef.h>
#include <winbase.h>
#include <winnls.h>
#include <winuser.h>
#include <stdio.h>
#include <string.h>
#include <strsafe.h>

#define IDR_LOCALDLL 101

/* A child process loads these names; bit n of its exit code is set when name n loads. */
static const WCHAR *g_ChildNames[] =
{
    L"api-ms-win-core-synch-l1-1-0.dll",
    L"api-ms-win-core-synch-l1-2-0.dll",
    L"api-ms-win-core-libraryloader-l1-2-0.dll",
    L"api-ms-win-crt-runtime-l1-1-0.dll",
    L"api-ms-win-core-libraryloader-l1-2-1.dll",
    L"api-ms-win-core-processthreads-l1-1-3.dll",
};

#define CHILD_RAN       0x01000000
#define CHILD_MARK_MASK 0xFF000000
#define CHILD_COUNT(x)  (((x) >> 16) & 0xFF)
#define CHILD_BITS(x)   ((x) & 0xFFFF)

#define GUID_VISTA L"{e2011457-1546-43c5-a5fe-008deee3d3f0}"
#define GUID_WIN7  L"{35138b9a-5d96-4fbd-8e2d-a2440225f93a}"
#define GUID_WIN8  L"{4a2f28e3-53b9-4441-ba9c-d69d4a4a6e38}"
#define GUID_WIN81 L"{1f676c76-80e1-4239-95bb-83d0f6d0da78}"
#define GUID_WIN10 L"{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}"

typedef struct _MANIFEST_VARIANT
{
    const WCHAR *Name;
    BOOL HasManifest;
    DWORD GuidCount;
    const WCHAR *Guids[5];
} MANIFEST_VARIANT;

static const MANIFEST_VARIANT g_Variants[] =
{
    { L"none", FALSE, 0, { NULL } },
    { L"nocompat", TRUE, 0, { NULL } },
    { L"vista", TRUE, 1, { GUID_VISTA } },
    { L"win7", TRUE, 1, { GUID_WIN7 } },
    { L"win10", TRUE, 1, { GUID_WIN10 } },
    { L"vista-to-10", TRUE, 5, { GUID_VISTA, GUID_WIN7, GUID_WIN8, GUID_WIN81, GUID_WIN10 } },
    { L"7-to-10", TRUE, 4, { GUID_WIN7, GUID_WIN8, GUID_WIN81, GUID_WIN10 } },
};

static BOOL
LoadName(const WCHAR *Name, WCHAR *Host, DWORD HostChars, DWORD *Error)
{
    HMODULE Module;

    SetLastError(0xdeadbeef);
    Module = LoadLibraryW(Name);
    *Error = GetLastError();
    if (Host)
        Host[0] = UNICODE_NULL;
    if (!Module)
        return FALSE;
    if (Host && !GetModuleFileNameW(Module, Host, HostChars))
        Host[0] = UNICODE_NULL;
    FreeLibrary(Module);
    return TRUE;
}

static DWORD
LoadChildNames(void)
{
    DWORD n, Error, Bits = 0;

    for (n = 0; n < _countof(g_ChildNames); ++n)
    {
        if (LoadName(g_ChildNames[n], NULL, 0, &Error))
            Bits |= 1 << n;
    }
    return Bits;
}

static DWORD
QueryCompatCount(DWORD Flags)
{
    DWORD Buffer[512] = { 0 };
    SIZE_T Needed = 0;

    /* Without an activation context the call can succeed and write nothing */
    if (!QueryActCtxW(Flags, NULL, NULL, CompatibilityInformationInActivationContext, Buffer, sizeof(Buffer), &Needed) ||
        Needed < sizeof(DWORD))
    {
        return 0;
    }
    return Buffer[0];
}

/* Number of compatibility elements in the process activation context: shows that the manifest was applied. ReactOS
   does not find the process context through the active one when no context is active, so both ways are tried. */
static DWORD
CompatElementCount(void)
{
    return max(QueryCompatCount(0), QueryCompatCount(QUERY_ACTCTX_FLAG_USE_ACTIVE_ACTCTX));
}

static void
RunChild(int argc, char **argv)
{
    WCHAR Name[MAX_PATH], Host[MAX_PATH];
    DWORD Count, Error;
    int n;

    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOOPENFILEERRORBOX);
    Count = CompatElementCount();
    if (argc == 0)
        ExitProcess(CHILD_RAN | (min(Count, 0xFF) << 16) | LoadChildNames());

    /* Names on the command line: print what each one loads (used to measure Windows). */
    printf("compat elements %lu (null handle %lu, active %lu), version %lu.%lu\n", Count, QueryCompatCount(0),
           QueryCompatCount(QUERY_ACTCTX_FLAG_USE_ACTIVE_ACTCTX), GetVersion() & 0xFF, (GetVersion() >> 8) & 0xFF);
    for (n = 0; n < argc; ++n)
    {
        if (!MultiByteToWideChar(CP_ACP, 0, argv[n], -1, Name, _countof(Name)))
            printf("%s\tSKIPPED\n", argv[n]);
        else if (LoadName(Name, Host, _countof(Host), &Error))
            printf("%s\tOK\t%ls\n", argv[n], Host);
        else
            printf("%s\tFAIL\t%lu\n", argv[n], Error);
    }
    fflush(stdout);
    ExitProcess(0);
}

static BOOL
WriteManifest(const WCHAR *Path, const MANIFEST_VARIANT *Variant)
{
    char Text[2048];
    DWORD n, Written;
    HANDLE File;
    BOOL Ret;

    strcpy(Text, "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\r\n"
                 "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\">\r\n"
                 "<assemblyIdentity type=\"win32\" name=\"ReactOS.Apitest.ApisetLoader\" version=\"1.0.0.0\"/>\r\n");
    if (Variant->GuidCount)
    {
        strcat(Text, "<compatibility xmlns=\"urn:schemas-microsoft-com:compatibility.v1\"><application>\r\n");
        for (n = 0; n < Variant->GuidCount; ++n)
            sprintf(Text + strlen(Text), "<supportedOS Id=\"%ls\"/>\r\n", Variant->Guids[n]);
        strcat(Text, "</application></compatibility>\r\n");
    }
    strcat(Text, "</assembly>\r\n");

    File = CreateFileW(Path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (File == INVALID_HANDLE_VALUE)
        return FALSE;
    Ret = WriteFile(File, Text, (DWORD)strlen(Text), &Written, NULL) && Written == strlen(Text);
    CloseHandle(File);
    return Ret;
}

static DWORD
StartChild(const WCHAR *Exe, const WCHAR *Mode)
{
    WCHAR CommandLine[MAX_PATH + 32];
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    DWORD Code = 0;

    if (FAILED(StringCchPrintfW(CommandLine, _countof(CommandLine), L"\"%ls\" loader %ls", Exe, Mode)))
        return 0;
    if (!CreateProcessW(Exe, CommandLine, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi))
    {
        ok(0, "CreateProcessW(%ls) failed with %lu\n", Exe, GetLastError());
        return 0;
    }
    if (WaitForSingleObject(pi.hProcess, 60000) != WAIT_OBJECT_0)
    {
        ok(0, "child %ls did not end\n", Exe);
        TerminateProcess(pi.hProcess, 1);
        WaitForSingleObject(pi.hProcess, 10000);
    }
    GetExitCodeProcess(pi.hProcess, &Code);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return Code;
}

/* A directory of its own for the child processes of this test, and the path of this executable */
static BOOL
MakeTestDir(const WCHAR *Tag, WCHAR *Self, WCHAR *Dir)
{
    WCHAR Temp[MAX_PATH];
    DWORD Length;

    Length = GetModuleFileNameW(NULL, Self, MAX_PATH);
    if (!Length || Length >= MAX_PATH)
    {
        skip("GetModuleFileNameW gave %lu, error %lu\n", Length, GetLastError());
        return FALSE;
    }
    Length = GetTempPathW(_countof(Temp), Temp);
    if (!Length || Length >= _countof(Temp) ||
        FAILED(StringCchPrintfW(Dir, MAX_PATH - 40, L"%lsapisetldr-%ls-%lu", Temp, Tag, GetCurrentProcessId())))
    {
        skip("no usable temporary directory (%lu)\n", Length);
        return FALSE;
    }
    if (!CreateDirectoryW(Dir, NULL) && GetLastError() != ERROR_ALREADY_EXISTS)
    {
        skip("CreateDirectoryW(%ls) failed with %lu\n", Dir, GetLastError());
        return FALSE;
    }
    return TRUE;
}

/*
 * The supportedOS entries of an application manifest do not change which API set names load: a child process with
 * each manifest below loads the same names as one without a manifest.
 */
static void
test_manifests(void)
{
    WCHAR Self[MAX_PATH], Dir[MAX_PATH], Exe[MAX_PATH], Manifest[MAX_PATH];
    DWORD n, Code, Reference = 0;

    /* MakeTestDir leaves 40 characters for the file names below */
    if (!MakeTestDir(L"manifest", Self, Dir))
        return;

    trace("without a manifest, in process: 0x%lx\n", LoadChildNames());

    for (n = 0; n < _countof(g_Variants); ++n)
    {
        const MANIFEST_VARIANT *Variant = &g_Variants[n];

        winetest_push_context("%ls", Variant->Name);
        StringCchPrintfW(Exe, _countof(Exe), L"%ls\\apl-%ls.exe", Dir, Variant->Name);
        StringCchPrintfW(Manifest, _countof(Manifest), L"%ls.manifest", Exe);
        ok(CopyFileW(Self, Exe, FALSE), "CopyFileW failed with %lu\n", GetLastError());
        if (Variant->HasManifest)
            ok(WriteManifest(Manifest, Variant), "manifest not written: %lu\n", GetLastError());

        Code = StartChild(Exe, L"child");
        trace("child exit code 0x%lx\n", Code);
        ok((Code & CHILD_MARK_MASK) == CHILD_RAN, "child did not run to the end: 0x%lx\n", Code);
        if ((Code & CHILD_MARK_MASK) == CHILD_RAN)
        {
            ok(CHILD_COUNT(Code) == Variant->GuidCount, "manifest not applied: %lu compatibility elements, expected %lu\n",
               CHILD_COUNT(Code), Variant->GuidCount);
            /* The first variant has no manifest: the others must load what it loads */
            if (n == 0)
                Reference = CHILD_BITS(Code);
            ok(CHILD_BITS(Code) == Reference, "loaded 0x%lx, without a manifest 0x%lx\n", CHILD_BITS(Code), Reference);
        }

        DeleteFileW(Manifest);
        DeleteFileW(Exe);
        winetest_pop_context();
    }
    RemoveDirectoryW(Dir);
}

/* Contract names a child process loads with a DLL of the same name next to it */
static const WCHAR *g_LocalNames[] =
{
    L"api-ms-win-core-synch-l1-1-0.dll",    /* a Windows 7 contract */
    L"api-ms-win-crt-runtime-l1-1-0.dll",   /* a contract Windows 7 does not have */
};

#define LOCAL_LOADED(n) (1 << (2 * (n)))
#define LOCAL_FROM_APP(n) (1 << (2 * (n) + 1))

/* Windows 7 loads a copy next to the executable for a name that is not one of its own contracts; Windows 10 and
   ReactOS never load such a copy for a name the schema resolves */
static BOOL
LoadsAppLocalContracts(void)
{
    return !is_reactos() && GetNTVersion() == 0x0601;
}

/* The module is the test fixture (localdll), recognised by its marker export: neither the path form nor the location
   of the directory (it can be under the Windows directory, %SystemRoot%\\TEMP) decides */
static BOOL
IsAppLocalCopy(HMODULE Module)
{
    return GetProcAddress(Module, "ApisetLoaderTestMarker") != NULL;
}

static void
RunLocalChild(void)
{
    DWORD n, Bits = 0;

    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOOPENFILEERRORBOX);
    for (n = 0; n < _countof(g_LocalNames); ++n)
    {
        HMODULE Module = LoadLibraryW(g_LocalNames[n]);

        if (!Module)
            continue;
        Bits |= LOCAL_LOADED(n);
        if (IsAppLocalCopy(Module))
            Bits |= LOCAL_FROM_APP(n);
        FreeLibrary(Module);
    }
    ExitProcess(CHILD_RAN | Bits);
}

static BOOL ExtractLocalDll(const WCHAR *Path, BOOL Exclusive);

#define LATE_FIRST_LOAD  0x1
#define LATE_SAME_MODULE 0x2
#define LATE_SAME_HANDLE 0x4

/* Load a contract that Windows 7 does not have, then put a copy next to the executable: the name keeps its module */
static void
RunLateChild(void)
{
    WCHAR Copy[MAX_PATH];
    HMODULE First, Second;
    DWORD Bits = 0;
    WCHAR *Slash;

    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOOPENFILEERRORBOX);
    if (!GetModuleFileNameW(NULL, Copy, _countof(Copy)) || !(Slash = wcsrchr(Copy, L'\\')) ||
        FAILED(StringCchCopyW(Slash + 1, _countof(Copy) - (Slash + 1 - Copy), g_LocalNames[1])))
    {
        ExitProcess(0);
    }
    First = LoadLibraryW(g_LocalNames[1]);
    if (First)
    {
        Bits |= LATE_FIRST_LOAD;
        /* Only a copy this child created is deleted again */
        if (ExtractLocalDll(Copy, TRUE))
        {
            Second = LoadLibraryW(g_LocalNames[1]);
            if (Second == First)
                Bits |= LATE_SAME_MODULE;
            if (GetModuleHandleW(g_LocalNames[1]) == First)
                Bits |= LATE_SAME_HANDLE;
            if (Second)
                FreeLibrary(Second);
            DeleteFileW(Copy);
        }
        FreeLibrary(First);
    }
    ExitProcess(CHILD_RAN | Bits);
}

/* Exclusive: create the file only if it does not exist, so that a run never overwrites a file it did not create.
   A file this call created is removed again when it cannot be written completely. */
static BOOL
ExtractLocalDll(const WCHAR *Path, BOOL Exclusive)
{
    HRSRC Resource = FindResourceW(NULL, MAKEINTRESOURCEW(IDR_LOCALDLL), (LPCWSTR)RT_RCDATA);
    HGLOBAL Data;
    DWORD Size, Written;
    HANDLE File;
    BOOL Created, Ret;

    if (!Resource || !(Data = LoadResource(NULL, Resource)) || !(Size = SizeofResource(NULL, Resource)))
        return FALSE;
    File = CreateFileW(Path, GENERIC_WRITE, 0, NULL, Exclusive ? CREATE_NEW : CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (File == INVALID_HANDLE_VALUE)
        return FALSE;
    Created = Exclusive || GetLastError() != ERROR_ALREADY_EXISTS;
    Ret = WriteFile(File, LockResource(Data), Size, &Written, NULL) && Written == Size;
    CloseHandle(File);
    if (!Ret && Created)
        DeleteFileW(Path);
    return Ret;
}

/*
 * A DLL in the application directory with the name of a contract: Windows 10 ignores it for every contract. Windows 7
 * ignores it for its own contracts and loads it for any other name, which is not a contract there. ReactOS resolves
 * every name of its table as Windows 10 does, whatever is next to the executable (applications that deploy the
 * Universal CRT next to themselves run with the system ucrtbase, as on Windows 10).
 */
static void
test_app_local(void)
{
    WCHAR Self[MAX_PATH], Dir[MAX_PATH], Exe[MAX_PATH], Dll[_countof(g_LocalNames)][MAX_PATH];
    DWORD n, Code, Expected;

    if (!is_reactos() && GetNTVersion() != 0x0601 && GetNTVersion() < 0x0A00)
    {
        skip("no measurement for Windows 0x%lx\n", GetNTVersion());
        return;
    }
    if (!MakeTestDir(L"local", Self, Dir))
        return;

    StringCchPrintfW(Exe, _countof(Exe), L"%ls\\apl-local.exe", Dir);
    ok(CopyFileW(Self, Exe, FALSE), "CopyFileW failed with %lu\n", GetLastError());
    for (n = 0; n < _countof(g_LocalNames); ++n)
    {
        StringCchPrintfW(Dll[n], _countof(Dll[n]), L"%ls\\%ls", Dir, g_LocalNames[n]);
        ok(ExtractLocalDll(Dll[n], FALSE), "%ls not written: %lu\n", Dll[n], GetLastError());
    }

    /* Both names load; only on Windows 7 does the second come from the application directory */
    Expected = CHILD_RAN | LOCAL_LOADED(0) | LOCAL_LOADED(1);
    if (LoadsAppLocalContracts())
        Expected |= LOCAL_FROM_APP(1);

    Code = StartChild(Exe, L"local");
    ok(Code == Expected, "child exit code 0x%lx, expected 0x%lx\n", Code, Expected);

    /* A directory with the name of a contract is not a copy */
    ok(DeleteFileW(Dll[1]), "DeleteFileW failed with %lu\n", GetLastError());
    ok(CreateDirectoryW(Dll[1], NULL), "CreateDirectoryW failed with %lu\n", GetLastError());
    if (!LoadsAppLocalContracts())
    {
        Code = StartChild(Exe, L"local");
        ok(Code == (CHILD_RAN | LOCAL_LOADED(0) | LOCAL_LOADED(1)), "directory: child exit code 0x%lx\n", Code);
    }
    RemoveDirectoryW(Dll[1]);

    /* A copy that appears after the first load does not change the module of the name */
    if (!LoadsAppLocalContracts())
    {
        Code = StartChild(Exe, L"late");
        ok(Code == (CHILD_RAN | LATE_FIRST_LOAD | LATE_SAME_MODULE | LATE_SAME_HANDLE), "late copy: child exit code 0x%lx\n",
           Code);
    }

    DeleteFileW(Dll[0]);
    DeleteFileW(Exe);
    RemoveDirectoryW(Dir);
}

/* What a child that loads g_LocalNames finds when the second name has a copy next to it */
static DWORD
ExpectedWithLocalCopy(void)
{
    DWORD Expected = CHILD_RAN | LOCAL_LOADED(0) | LOCAL_LOADED(1);

    if (LoadsAppLocalContracts())
        Expected |= LOCAL_FROM_APP(1);
    return Expected;
}

/*
 * The executable is started through the volume name of the root of the system drive (\\?\Volume{...}\), with a copy of
 * a contract next to it: the root of a volume is its directory.
 */
static void
test_app_local_volume_root(void)
{
    WCHAR Self[MAX_PATH], Windows[MAX_PATH], Volume[64], Exe[MAX_PATH], VolumeExe[MAX_PATH], Dll[MAX_PATH];
    DWORD Code, Expected;

    if (!is_reactos() && GetNTVersion() != 0x0601 && GetNTVersion() < 0x0A00)
    {
        skip("no measurement for Windows 0x%lx\n", GetNTVersion());
        return;
    }
    if (!GetModuleFileNameW(NULL, Self, _countof(Self)) || GetWindowsDirectoryW(Windows, _countof(Windows)) < 3)
    {
        skip("no module or Windows directory\n");
        return;
    }
    Windows[3] = UNICODE_NULL;
    if (!GetVolumeNameForVolumeMountPointW(Windows, Volume, _countof(Volume)))
    {
        skip("GetVolumeNameForVolumeMountPointW(%ls) failed with %lu\n", Windows, GetLastError());
        return;
    }
    StringCchPrintfW(Exe, _countof(Exe), L"%lsapisetldr-%lu.exe", Windows, GetCurrentProcessId());
    StringCchPrintfW(VolumeExe, _countof(VolumeExe), L"%lsapisetldr-%lu.exe", Volume, GetCurrentProcessId());
    StringCchPrintfW(Dll, _countof(Dll), L"%ls%ls", Windows, g_LocalNames[1]);
    /* Both files are created only if they do not exist, and only what this run created is deleted */
    if (!CopyFileW(Self, Exe, TRUE))
    {
        skip("CopyFileW(%ls) failed with %lu\n", Exe, GetLastError());
        return;
    }
    if (!ExtractLocalDll(Dll, TRUE))
    {
        skip("%ls not created (%lu): another file has that name\n", Dll, GetLastError());
        DeleteFileW(Exe);
        return;
    }

    Expected = ExpectedWithLocalCopy();
    Code = StartChild(VolumeExe, L"local");
    ok(Code == Expected, "%ls: child exit code 0x%lx, expected 0x%lx\n", VolumeExe, Code, Expected);

    DeleteFileW(Dll);
    DeleteFileW(Exe);
}

/* DACL of Path: Everyone is denied DenyMask (if not 0) and allowed everything else */
static BOOL
SetDenied(const WCHAR *Path, ACCESS_MASK DenyMask)
{
    SID_IDENTIFIER_AUTHORITY World = { SECURITY_WORLD_SID_AUTHORITY };
    SECURITY_DESCRIPTOR Descriptor;
    DWORD AclBuffer[64];
    PACL Acl = (PACL)AclBuffer;
    PSID Everyone = NULL;
    BOOL Ret;

    if (!AllocateAndInitializeSid(&World, 1, SECURITY_WORLD_RID, 0, 0, 0, 0, 0, 0, 0, &Everyone))
        return FALSE;
    Ret = InitializeAcl(Acl, sizeof(AclBuffer), ACL_REVISION) &&
          (!DenyMask || AddAccessDeniedAce(Acl, ACL_REVISION, DenyMask, Everyone)) &&
          AddAccessAllowedAce(Acl, ACL_REVISION, FILE_ALL_ACCESS, Everyone) &&
          InitializeSecurityDescriptor(&Descriptor, SECURITY_DESCRIPTOR_REVISION) &&
          SetSecurityDescriptorDacl(&Descriptor, TRUE, Acl, FALSE) &&
          SetFileSecurityW(Path, DACL_SECURITY_INFORMATION, &Descriptor);
    FreeSid(Everyone);
    return Ret;
}

/*
 * The directory of the executable cannot be listed, but its files can be opened: the copy of a contract next to the
 * executable is still found where Windows 7 finds it, and still ignored where Windows 10 ignores it.
 */
static void
test_app_local_unlisted(void)
{
    WCHAR Self[MAX_PATH], Dir[MAX_PATH], Exe[MAX_PATH], Dll[MAX_PATH], Pattern[MAX_PATH];
    WIN32_FIND_DATAW FindData;
    HANDLE Find;
    DWORD Code, Expected;

    if (!is_reactos() && GetNTVersion() != 0x0601 && GetNTVersion() < 0x0A00)
    {
        skip("no measurement for Windows 0x%lx\n", GetNTVersion());
        return;
    }
    if (!MakeTestDir(L"unlisted", Self, Dir))
        return;
    StringCchPrintfW(Exe, _countof(Exe), L"%ls\\apl-unlisted.exe", Dir);
    StringCchPrintfW(Dll, _countof(Dll), L"%ls\\%ls", Dir, g_LocalNames[1]);
    StringCchPrintfW(Pattern, _countof(Pattern), L"%ls\\*", Dir);
    ok(CopyFileW(Self, Exe, FALSE), "CopyFileW failed with %lu\n", GetLastError());
    ok(ExtractLocalDll(Dll, FALSE), "%ls not written: %lu\n", Dll, GetLastError());

    ok(SetDenied(Dir, FILE_LIST_DIRECTORY), "SetFileSecurityW failed with %lu\n", GetLastError());
    Find = FindFirstFileW(Pattern, &FindData);
    if (Find != INVALID_HANDLE_VALUE)
    {
        FindClose(Find);
        skip("the file system of %ls does not deny listing\n", Dir);
    }
    else
    {
        ok(GetLastError() == ERROR_ACCESS_DENIED, "FindFirstFileW failed with %lu\n", GetLastError());
        Expected = ExpectedWithLocalCopy();
        Code = StartChild(Exe, L"local");
        ok(Code == Expected, "child exit code 0x%lx, expected 0x%lx\n", Code, Expected);
    }

    ok(SetDenied(Dir, 0), "SetFileSecurityW failed with %lu\n", GetLastError());
    DeleteFileW(Dll);
    DeleteFileW(Exe);
    RemoveDirectoryW(Dir);
}

#define RETRY_FIRST_LOADED  0x1
#define RETRY_FIRST_LOCAL   0x2
#define RETRY_SECOND_LOADED 0x4
#define RETRY_SECOND_LOCAL  0x8
#define RETRY_REFUSED       0x10

/* The parent marks a fixture it created exclusively with this file next to it; the token comes on the command line */
static BOOL
MakeFixtureMarkerPath(const WCHAR *Exe, const char *Token, WCHAR *Path, SIZE_T Count)
{
    const WCHAR *Slash = wcsrchr(Exe, L'\\');
    WCHAR WideToken[33];
    SIZE_T n;

    if (!Slash || !Token || !*Token || strlen(Token) >= _countof(WideToken))
        return FALSE;
    for (n = 0; Token[n]; ++n)
    {
        if ((Token[n] < '0' || Token[n] > '9') && Token[n] != '-')
            return FALSE;
        WideToken[n] = Token[n];
    }
    WideToken[n] = UNICODE_NULL;
    return SUCCEEDED(StringCchPrintfW(Path, Count, L"%.*lsapl-%ls.fixture", (int)(Slash + 1 - Exe), Exe, WideToken));
}

/*
 * The copy next to this executable cannot be checked: load the contract, make the copy readable (or delete it), load
 * it again. The first answer must not be kept: with a readable copy the second load uses it (a kept "host" answer
 * fails this), with the copy gone it uses the host (a kept "copy" answer fails this). Freed heap blocks filled with copies of a "system host" entry for the name come
 * first, so that a decision list the loader allocates and searches without initialising it is likely to read one.
 */
static void
RunRetryChild(BOOL MakeAbsent, const char *Token)
{
    WCHAR Copy[MAX_PATH], Marker[MAX_PATH];
    PVOID Blocks[64];
    HMODULE Module;
    DWORD n, Attributes, Bits = 0;
    WCHAR *Slash;

    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOOPENFILEERRORBOX);
    if (!GetModuleFileNameW(NULL, Copy, _countof(Copy)))
        ExitProcess(0);

    /* This child changes and deletes the copy: only one the parent created and marked for this run */
    Attributes = MakeFixtureMarkerPath(Copy, Token, Marker, _countof(Marker)) ? GetFileAttributesW(Marker)
                                                                              : INVALID_FILE_ATTRIBUTES;
    if (Attributes == INVALID_FILE_ATTRIBUTES || (Attributes & FILE_ATTRIBUTE_DIRECTORY))
        ExitProcess(CHILD_RAN | RETRY_REFUSED);

    if (!(Slash = wcsrchr(Copy, L'\\')) ||
        FAILED(StringCchCopyW(Slash + 1, _countof(Copy) - (Slash + 1 - Copy), g_LocalNames[1])))
    {
        ExitProcess(0);
    }

    for (n = 0; n < _countof(Blocks); ++n)
    {
        SIZE_T Size = 1024 + 16 * (n % 16), Used;
        Blocks[n] = HeapAlloc(GetProcessHeap(), 0, Size);
        for (Used = 0; Blocks[n] && Used + sizeof(L"S") + wcslen(g_LocalNames[1]) * sizeof(WCHAR) <= Size;)
        {
            WCHAR *Entry = (WCHAR *)((PUCHAR)Blocks[n] + Used);
            Entry[0] = L'S';
            wcscpy(Entry + 1, g_LocalNames[1]);
            Used += sizeof(L"S") + wcslen(g_LocalNames[1]) * sizeof(WCHAR);
        }
    }
    for (n = 0; n < _countof(Blocks); ++n)
    {
        if (Blocks[n])
            HeapFree(GetProcessHeap(), 0, Blocks[n]);
    }

    Module = LoadLibraryW(g_LocalNames[1]);
    if (Module)
    {
        Bits |= RETRY_FIRST_LOADED;
        if (IsAppLocalCopy(Module))
            Bits |= RETRY_FIRST_LOCAL;
        FreeLibrary(Module);
    }
    if (!SetDenied(Copy, 0) || (MakeAbsent && !DeleteFileW(Copy)))
        ExitProcess(0);
    Module = LoadLibraryW(g_LocalNames[1]);
    if (Module)
    {
        Bits |= RETRY_SECOND_LOADED;
        if (IsAppLocalCopy(Module))
            Bits |= RETRY_SECOND_LOCAL;
        FreeLibrary(Module);
    }
    ExitProcess(CHILD_RAN | Bits);
}

/*
 * As above, and the attributes of the copy cannot be read either. Windows 7 then leaves the name to the DLL search;
 * Windows 10 and ReactOS load the system host whatever the state of the copy.
 */
static void
test_app_local_unreadable(void)
{
    WCHAR Self[MAX_PATH], Dir[MAX_PATH], Exe[MAX_PATH], Dll[MAX_PATH], Marker[MAX_PATH], Token[32], Mode[64];
    HANDLE File;
    DWORD Code;

    if (!is_reactos() && GetNTVersion() != 0x0601 && GetNTVersion() < 0x0A00)
    {
        skip("no measurement for Windows 0x%lx\n", GetNTVersion());
        return;
    }
    if (!MakeTestDir(L"unreadable", Self, Dir))
        return;
    StringCchPrintfW(Exe, _countof(Exe), L"%ls\\apl-unreadable.exe", Dir);
    StringCchPrintfW(Dll, _countof(Dll), L"%ls\\%ls", Dir, g_LocalNames[1]);
    ok(CopyFileW(Self, Exe, FALSE), "CopyFileW failed with %lu\n", GetLastError());
    if (!ExtractLocalDll(Dll, TRUE))
    {
        skip("%ls not created: %lu\n", Dll, GetLastError());
        DeleteFileW(Exe);
        RemoveDirectoryW(Dir);
        return;
    }

    /* The retry children change and delete the copy only when this marker of the run is next to it */
    StringCchPrintfW(Token, _countof(Token), L"%lu-%lu", GetCurrentProcessId(), GetTickCount());
    StringCchPrintfW(Marker, _countof(Marker), L"%ls\\apl-%ls.fixture", Dir, Token);
    File = CreateFileW(Marker, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    ok(File != INVALID_HANDLE_VALUE, "%ls not created: %lu\n", Marker, GetLastError());
    if (File != INVALID_HANDLE_VALUE)
        CloseHandle(File);

    ok(SetDenied(Dll, FILE_READ_ATTRIBUTES), "SetFileSecurityW failed with %lu\n", GetLastError());
    ok(SetDenied(Dir, FILE_LIST_DIRECTORY), "SetFileSecurityW failed with %lu\n", GetLastError());
    if (GetFileAttributesW(Dll) != INVALID_FILE_ATTRIBUTES)
    {
        skip("the file system of %ls does not deny reading attributes\n", Dir);
    }
    else
    {
        ok(GetLastError() == ERROR_ACCESS_DENIED, "GetFileAttributesW failed with %lu\n", GetLastError());
        Code = StartChild(Exe, L"local");
        trace("unreadable copy: child exit code 0x%lx\n", Code);
        ok((Code & CHILD_MARK_MASK) == CHILD_RAN, "child did not run to the end: 0x%lx\n", Code);
        if (LoadsAppLocalContracts())
            ok(!(Code & LOCAL_LOADED(1)) || (Code & LOCAL_FROM_APP(1)), "the system host was used: 0x%lx\n", Code);
        else
            ok((Code & (LOCAL_LOADED(1) | LOCAL_FROM_APP(1))) == LOCAL_LOADED(1), "child exit code 0x%lx\n", Code);

        /* Without the marker of this run, or with another token, a retry child touches nothing */
        Code = StartChild(Exe, L"retry-absent");
        ok(Code == (CHILD_RAN | RETRY_REFUSED), "retry-absent without a token: child exit code 0x%lx\n", Code);
        Code = StartChild(Exe, L"retry-absent 1-1");
        ok(Code == (CHILD_RAN | RETRY_REFUSED), "retry-absent with another token: child exit code 0x%lx\n", Code);
        ok(GetFileAttributesW(Dll) == INVALID_FILE_ATTRIBUTES && GetLastError() == ERROR_ACCESS_DENIED,
           "the copy changed: %lu\n", GetLastError());

        /* The undecided name is asked again once the copy can be read (the child makes it readable) */
        StringCchPrintfW(Mode, _countof(Mode), L"retry %ls", Token);
        Code = StartChild(Exe, Mode);
        if (LoadsAppLocalContracts())
            ok(Code == (CHILD_RAN | RETRY_SECOND_LOADED | RETRY_SECOND_LOCAL), "retry: child exit code 0x%lx\n", Code);
        else
            ok(Code == (CHILD_RAN | RETRY_FIRST_LOADED | RETRY_SECOND_LOADED), "retry: child exit code 0x%lx\n", Code);

        /* Again with the copy unreadable; this time the child deletes it before the second load */
        ok(SetDenied(Dll, FILE_READ_ATTRIBUTES), "SetFileSecurityW failed with %lu\n", GetLastError());
        StringCchPrintfW(Mode, _countof(Mode), L"retry-absent %ls", Token);
        Code = StartChild(Exe, Mode);
        if (LoadsAppLocalContracts())
            ok(Code == CHILD_RAN, "retry-absent: child exit code 0x%lx\n", Code);
        else
            ok(Code == (CHILD_RAN | RETRY_FIRST_LOADED | RETRY_SECOND_LOADED), "retry-absent: child exit code 0x%lx\n",
               Code);
    }

    ok(SetDenied(Dir, 0), "SetFileSecurityW failed with %lu\n", GetLastError());
    SetDenied(Dll, 0); /* the retry-absent child may have deleted it */
    DeleteFileW(Dll);
    DeleteFileW(Marker);
    DeleteFileW(Exe);
    RemoveDirectoryW(Dir);
}

static void
check_family(const WCHAR *Reference, const WCHAR *Name)
{
    WCHAR RefHost[MAX_PATH], Host[MAX_PATH];
    DWORD Error;

    winetest_push_context("%ls", Name);
    if (!LoadName(Reference, RefHost, _countof(RefHost), &Error))
    {
        ok(0, "%ls does not load: %lu\n", Reference, Error);
    }
    else
    {
        ok(LoadName(Name, Host, _countof(Host), &Error), "does not load: %lu\n", Error);
        ok(!_wcsicmp(Host, RefHost), "host %ls, %ls has %ls\n", Host, Reference, RefHost);
    }
    winetest_pop_context();
}

static void
check_absent(const WCHAR *Name)
{
    DWORD Error;

    ok(!LoadName(Name, NULL, 0, &Error), "%ls loads\n", Name);
    ok(Error == ERROR_MOD_NOT_FOUND, "%ls: error %lu\n", Name, Error);
}

/*
 * Windows 10 resolves every minor version of a contract to the host of the contract: the part after the last hyphen
 * does not matter, whatever it is. Windows 7 resolves only the exact name. ReactOS resolves like Windows 10.
 */
static void
test_minor_versions(void)
{
    if (is_reactos() || GetNTVersion() >= 0x0A00)
    {
        check_family(L"api-ms-win-core-libraryloader-l1-2-0.dll", L"api-ms-win-core-libraryloader-l1-2-1.dll");
        check_family(L"api-ms-win-core-libraryloader-l1-2-0.dll", L"api-ms-win-core-libraryloader-l1-2-12.dll");
        check_family(L"api-ms-win-core-file-l1-2-0.dll", L"api-ms-win-core-file-l1-2-2.dll");
        check_family(L"api-ms-win-core-processthreads-l1-1-0.dll", L"api-ms-win-core-processthreads-l1-1-3.dll");
        check_family(L"api-ms-win-core-synch-l1-2-0.dll", L"API-MS-Win-Core-Synch-L1-2-9.DLL");
        check_family(L"api-ms-win-core-synch-l1-2-0.dll", L"api-ms-win-core-synch-l1-2-99");
        check_family(L"api-ms-win-core-synch-l1-2-0.dll", L"api-ms-win-core-synch-l1-2-x.dll");
        check_family(L"api-ms-win-core-synch-l1-2-0.dll", L"api-ms-win-core-synch-l1-2-.dll");
        check_family(L"api-ms-win-crt-runtime-l1-1-0.dll", L"api-ms-win-crt-runtime-l1-1-9.dll");
        check_absent(L"api-ms-win-core-synch-l1-9-0.dll");
        check_absent(L"api-ms-win-core-synch-l1-2.dll");
        check_absent(L"api-ms-win-core-synch-l1-2-0-0.dll");
        check_absent(L"api-ms-win-core-synch-l1.dll");
        check_absent(L"api-ms-win-core-nosuchcontract-l1-1-0.dll");
    }
    else if (GetNTVersion() == 0x0601)
    {
        check_family(L"api-ms-win-core-processthreads-l1-1-0.dll", L"API-MS-Win-Core-ProcessThreads-L1-1-0.DLL");
        check_absent(L"api-ms-win-core-processthreads-l1-1-1.dll");
        check_absent(L"api-ms-win-core-synch-l1-1-9.dll");
    }
    else
    {
        skip("no measurement for Windows 0x%lx\n", GetNTVersion());
    }
}

START_TEST(loader)
{
    char **argv;
    int argc = winetest_get_mainargs(&argv);

    if (argc >= 3 && !strcmp(argv[2], "child"))
        RunChild(argc - 3, argv + 3);
    if (argc >= 3 && !strcmp(argv[2], "local"))
        RunLocalChild();
    if (argc >= 3 && !strcmp(argv[2], "late"))
        RunLateChild();
    if (argc >= 3 && !strcmp(argv[2], "retry"))
        RunRetryChild(FALSE, argc >= 4 ? argv[3] : NULL);
    if (argc >= 3 && !strcmp(argv[2], "retry-absent"))
        RunRetryChild(TRUE, argc >= 4 ? argv[3] : NULL);

    test_minor_versions();
    test_manifests();
    test_app_local();
    test_app_local_volume_root();
    test_app_local_unlisted();
    test_app_local_unreadable();
}
