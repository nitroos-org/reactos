/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     MIT
 * PURPOSE:     Optional WoW64 setup failures must not abort native setup
 */
#include <apitest.h>
#include "../../../../dll/win32/syssetup/precomp.h"

HINSTANCE hDllInstance;
static ULONG OptionalCalls, FailAt, Directories;
static BOOL Optional, FailNative;

static BOOL FailOperation(VOID)
{
    if (!Optional) return FALSE;
    if (++OptionalCalls != FailAt) return FALSE;
    SetLastError(ERROR_ACCESS_DENIED);
    return TRUE;
}

static INT WINAPI MockLoadString(HINSTANCE Instance, UINT Id, PWSTR Buffer, INT Count)
{
    if (FailNative && Id == IDS_PROGRAMFILES) return 0;
    wcscpy(Buffer, Id == IDS_PROGRAMFILES ? L"C:\\Program Files" : L"Common Files");
    return wcslen(Buffer);
}

static DWORD WINAPI MockExpand(PCWSTR Input, PWSTR Output, DWORD Size)
{
    wcscpy(Output, Input);
    return wcslen(Output) + 1;
}

static LSTATUS WINAPI MockOpen(HKEY Root, PCWSTR Name, DWORD Options, REGSAM Access, PHKEY Key)
{
    if (FailOperation()) return ERROR_ACCESS_DENIED;
    *Key = (HKEY)1;
    return ERROR_SUCCESS;
}

#ifdef _M_AMD64
static LSTATUS WINAPI MockCreate(HKEY Root, PCWSTR Name, DWORD Reserved, PWSTR Class,
    DWORD Options, REGSAM Access, LPSECURITY_ATTRIBUTES Security, PHKEY Key, PDWORD Disposition)
{
    return MockOpen(Root, Name, Options, Access, Key);
}
#endif

static LSTATUS WINAPI MockSet(HKEY Key, PCWSTR Name, DWORD Reserved, DWORD Type,
    const BYTE *Data, DWORD Size)
{
    return FailOperation() ? ERROR_ACCESS_DENIED : ERROR_SUCCESS;
}

static LSTATUS WINAPI MockClose(HKEY Key)
{
    return ERROR_SUCCESS;
}

static BOOL WINAPI MockDirectory(PCWSTR Name, LPSECURITY_ATTRIBUTES Security)
{
    if (Optional) return !FailOperation();
    if (++Directories == 2) Optional = TRUE;
    return TRUE;
}

/* Execute the production functions with deterministic registry/filesystem
 * failures. No registry values or directories in the test machine are changed. */
#define LoadStringW MockLoadString
#define ExpandEnvironmentStringsW MockExpand
#define RegOpenKeyExW MockOpen
#define RegCreateKeyExW MockCreate
#define RegSetValueExW MockSet
#define RegCloseKey MockClose
#define CreateDirectoryW MockDirectory
#include "../../../../dll/win32/syssetup/programfiles.c"

/* open + 6 values, create + 6 values, 2 directories */
#define OPTIONAL_OPERATIONS 16

START_TEST(ProgramFiles)
{
    ULONG i;
    FailNative = TRUE;
    ok(!InitializeProgramFilesDir(), "Native Program Files failure must remain fatal\n");
    FailNative = FALSE;
    for (i = 0; i <= OPTIONAL_OPERATIONS; ++i)
    {
        Optional = FALSE;
        OptionalCalls = Directories = 0;
        FailAt = i;
        ok(InitializeProgramFilesDir(), "Optional operation %lu aborted native setup\n", i);
#ifdef _M_AMD64
        ok_eq_ulong(OptionalCalls, i ? i : OPTIONAL_OPERATIONS);
#else
        ok_eq_ulong(OptionalCalls, 0);
#endif
        ok_eq_ulong(Directories, 2);
    }
}
