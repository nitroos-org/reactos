/*
 * PROJECT:     ReactOS Win32 Base API
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Windows Error Reporting process flags
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "k32_vista.h"

#define NDEBUG
#include <debug.h>

/* There is no error reporting service to consult them, they are only kept for WerGetFlags */
static DWORD BaseWerFlags;

/*
 * @implemented
 */
HRESULT
WINAPI
WerSetFlags(
    _In_ DWORD dwFlags)
{
    InterlockedExchange((PLONG)&BaseWerFlags, (LONG)dwFlags);
    return S_OK;
}

/*
 * @implemented
 */
HRESULT
WINAPI
WerGetFlags(
    _In_ HANDLE hProcess,
    _Out_ PDWORD pdwFlags)
{
    PROCESS_BASIC_INFORMATION ProcessInfo;
    NTSTATUS Status;

    if (!pdwFlags)
        return E_INVALIDARG;

    if (hProcess != NtCurrentProcess())
    {
        Status = NtQueryInformationProcess(hProcess,
                                           ProcessBasicInformation,
                                           &ProcessInfo,
                                           sizeof(ProcessInfo),
                                           NULL);
        if (!NT_SUCCESS(Status))
            return HRESULT_FROM_NT(Status);

        if (ProcessInfo.UniqueProcessId != (ULONG_PTR)NtCurrentTeb()->ClientId.UniqueProcess)
        {
            DPRINT1("FIXME: WerGetFlags for another process is not supported\n");
            return E_NOTIMPL;
        }
    }

    *pdwFlags = BaseWerFlags;
    return S_OK;
}

/*
 * @implemented
 *
 * A runtime exception module is a DLL the error reporting service loads, out of process, when this
 * process crashes, so that it can claim the crash (the CLR registers mscordacwks.dll). Windows keeps
 * up to WER_MAX_REGISTERED_RUNTIME_EXCEPTION_MODULES registrations per process, keyed by the module
 * path (compared case-sensitively) and the context; registering the same pair again succeeds
 * without taking another slot. The crash reporter here (drwtsn32) does not load such modules yet, but the
 * registration contract is kept: the CLR refuses to start when it cannot register.
 */
#define BASE_WER_MAX_RUNTIME_MODULES 16

typedef struct _BASE_WER_RUNTIME_MODULE
{
    PWSTR Path;
    PVOID Context;
} BASE_WER_RUNTIME_MODULE;

static BASE_WER_RUNTIME_MODULE BaseWerRuntimeModules[BASE_WER_MAX_RUNTIME_MODULES];
static RTL_SRWLOCK BaseWerRuntimeModulesLock = RTL_SRWLOCK_INIT;

HRESULT
WINAPI
WerRegisterRuntimeExceptionModule(
    _In_ PCWSTR pwszOutOfProcessCallbackDll,
    _In_opt_ PVOID pContext)
{
    SIZE_T Size;
    PWSTR Copy;
    ULONG i, Free = BASE_WER_MAX_RUNTIME_MODULES;

    if (!pwszOutOfProcessCallbackDll || !*pwszOutOfProcessCallbackDll)
        return E_INVALIDARG;

    Size = (wcslen(pwszOutOfProcessCallbackDll) + 1) * sizeof(WCHAR);
    Copy = RtlAllocateHeap(RtlGetProcessHeap(), 0, Size);
    if (!Copy)
        return E_OUTOFMEMORY;
    RtlCopyMemory(Copy, pwszOutOfProcessCallbackDll, Size);

    RtlAcquireSRWLockExclusive(&BaseWerRuntimeModulesLock);
    for (i = 0; i < BASE_WER_MAX_RUNTIME_MODULES; i++)
    {
        if (!BaseWerRuntimeModules[i].Path)
        {
            if (Free == BASE_WER_MAX_RUNTIME_MODULES)
                Free = i;
        }
        else if (BaseWerRuntimeModules[i].Context == pContext &&
                 !wcscmp(BaseWerRuntimeModules[i].Path, pwszOutOfProcessCallbackDll))
        {
            /* Already registered */
            RtlReleaseSRWLockExclusive(&BaseWerRuntimeModulesLock);
            RtlFreeHeap(RtlGetProcessHeap(), 0, Copy);
            return S_OK;
        }
    }
    if (Free < BASE_WER_MAX_RUNTIME_MODULES)
    {
        BaseWerRuntimeModules[Free].Path = Copy;
        BaseWerRuntimeModules[Free].Context = pContext;
        Copy = NULL;
    }
    RtlReleaseSRWLockExclusive(&BaseWerRuntimeModulesLock);

    if (Copy)
    {
        RtlFreeHeap(RtlGetProcessHeap(), 0, Copy);
        return HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER);
    }

    DPRINT("WerRegisterRuntimeExceptionModule(%S, %p): registered in slot %lu\n",
           pwszOutOfProcessCallbackDll, pContext, Free);
    return S_OK;
}

/*
 * @implemented
 */
HRESULT
WINAPI
WerUnregisterRuntimeExceptionModule(
    _In_ PCWSTR pwszOutOfProcessCallbackDll,
    _In_opt_ PVOID pContext)
{
    PWSTR Path = NULL;
    ULONG i;

    if (!pwszOutOfProcessCallbackDll || !*pwszOutOfProcessCallbackDll)
        return E_INVALIDARG;

    RtlAcquireSRWLockExclusive(&BaseWerRuntimeModulesLock);
    for (i = 0; i < BASE_WER_MAX_RUNTIME_MODULES; i++)
    {
        if (BaseWerRuntimeModules[i].Path &&
            BaseWerRuntimeModules[i].Context == pContext &&
            !wcscmp(BaseWerRuntimeModules[i].Path, pwszOutOfProcessCallbackDll))
        {
            Path = BaseWerRuntimeModules[i].Path;
            BaseWerRuntimeModules[i].Path = NULL;
            BaseWerRuntimeModules[i].Context = NULL;
            break;
        }
    }
    RtlReleaseSRWLockExclusive(&BaseWerRuntimeModulesLock);

    if (!Path)
        return HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND);
    RtlFreeHeap(RtlGetProcessHeap(), 0, Path);
    return S_OK;
}

/*
 * @implemented
 *
 * Registered files and memory blocks are what the error reporting service attaches to a crash report.
 * There is no such service here, so they are only recorded, but the registration contract is kept
 * (all checked on Windows 10 22H2): files and memory blocks share one table of 512 entries and a full
 * table returns HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER); a memory block is 1 to 0x10000 bytes
 * and is keyed by its address (registering it again updates the size and succeeds); the address is not
 * validated. A file is keyed by its path (compared case-sensitively on registration, so registering
 * the same path again succeeds without a slot; unregistering ignores the case), the type is
 * WerRegFileTypeUserDocument or WerRegFileTypeOther, the flags are WER_FILE_DELETE_WHEN_DONE and
 * WER_FILE_ANONYMOUS_DATA, a path of MAX_PATH or more characters is HRESULT_FROM_WIN32(ERROR_FILENAME_EXCED_RANGE),
 * and the file does not have to exist. WPF registers memory blocks while it starts.
 */
#define BASE_WER_MAX_REGISTERED_ENTRIES 512
#define BASE_WER_MAX_MEM_BLOCK_SIZE     0x10000
#define BASE_WER_FILE_DELETE_WHEN_DONE  1
#define BASE_WER_FILE_ANONYMOUS_DATA    2

typedef struct _BASE_WER_ENTRY
{
    PWSTR Path;     /* NULL for a memory block */
    PVOID Block;
    DWORD Size;     /* memory block size, or the file flags */
    DWORD Type;     /* file type */
} BASE_WER_ENTRY;

static BASE_WER_ENTRY BaseWerEntries[BASE_WER_MAX_REGISTERED_ENTRIES];
static BOOLEAN BaseWerEntryUsed[BASE_WER_MAX_REGISTERED_ENTRIES];
static RTL_SRWLOCK BaseWerEntriesLock = RTL_SRWLOCK_INIT;

HRESULT
WINAPI
WerRegisterMemoryBlock(
    _In_ PVOID pvAddress,
    _In_ DWORD dwSize)
{
    ULONG i, Free = BASE_WER_MAX_REGISTERED_ENTRIES;
    HRESULT hr = S_OK;

    if (!pvAddress || !dwSize || dwSize > BASE_WER_MAX_MEM_BLOCK_SIZE)
        return E_INVALIDARG;

    RtlAcquireSRWLockExclusive(&BaseWerEntriesLock);
    for (i = 0; i < BASE_WER_MAX_REGISTERED_ENTRIES; i++)
    {
        if (!BaseWerEntryUsed[i])
        {
            if (Free == BASE_WER_MAX_REGISTERED_ENTRIES)
                Free = i;
        }
        else if (!BaseWerEntries[i].Path && BaseWerEntries[i].Block == pvAddress)
        {
            /* Already registered: only the size changes */
            BaseWerEntries[i].Size = dwSize;
            RtlReleaseSRWLockExclusive(&BaseWerEntriesLock);
            return S_OK;
        }
    }
    if (Free < BASE_WER_MAX_REGISTERED_ENTRIES)
    {
        BaseWerEntries[Free].Path = NULL;
        BaseWerEntries[Free].Block = pvAddress;
        BaseWerEntries[Free].Size = dwSize;
        BaseWerEntries[Free].Type = 0;
        BaseWerEntryUsed[Free] = TRUE;
    }
    else
    {
        hr = HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER);
    }
    RtlReleaseSRWLockExclusive(&BaseWerEntriesLock);
    return hr;
}

/*
 * @implemented
 */
HRESULT
WINAPI
WerUnregisterMemoryBlock(
    _In_ PVOID pvAddress)
{
    ULONG i;
    HRESULT hr = HRESULT_FROM_WIN32(ERROR_NOT_FOUND);

    if (!pvAddress)
        return E_INVALIDARG;

    RtlAcquireSRWLockExclusive(&BaseWerEntriesLock);
    for (i = 0; i < BASE_WER_MAX_REGISTERED_ENTRIES; i++)
    {
        if (BaseWerEntryUsed[i] && !BaseWerEntries[i].Path && BaseWerEntries[i].Block == pvAddress)
        {
            BaseWerEntryUsed[i] = FALSE;
            BaseWerEntries[i].Block = NULL;
            hr = S_OK;
            break;
        }
    }
    RtlReleaseSRWLockExclusive(&BaseWerEntriesLock);
    return hr;
}

/*
 * @implemented
 */
HRESULT
WINAPI
WerRegisterFile(
    _In_ PCWSTR pwzFile,
    _In_ INT regFileType,
    _In_ DWORD dwFlags)
{
    SIZE_T Length, Size;
    PWSTR Copy;
    ULONG i, Free = BASE_WER_MAX_REGISTERED_ENTRIES;
    HRESULT hr = S_OK;

    if (!pwzFile || (regFileType != 1 && regFileType != 2) ||
        (dwFlags & ~(BASE_WER_FILE_DELETE_WHEN_DONE | BASE_WER_FILE_ANONYMOUS_DATA)))
        return E_INVALIDARG;

    Length = wcslen(pwzFile);
    if (Length >= MAX_PATH)
        return HRESULT_FROM_WIN32(ERROR_FILENAME_EXCED_RANGE);

    Size = (Length + 1) * sizeof(WCHAR);
    Copy = RtlAllocateHeap(RtlGetProcessHeap(), 0, Size);
    if (!Copy)
        return E_OUTOFMEMORY;
    RtlCopyMemory(Copy, pwzFile, Size);

    RtlAcquireSRWLockExclusive(&BaseWerEntriesLock);
    for (i = 0; i < BASE_WER_MAX_REGISTERED_ENTRIES; i++)
    {
        if (!BaseWerEntryUsed[i])
        {
            if (Free == BASE_WER_MAX_REGISTERED_ENTRIES)
                Free = i;
        }
        else if (BaseWerEntries[i].Path && !wcscmp(BaseWerEntries[i].Path, pwzFile))
        {
            BaseWerEntries[i].Type = regFileType;
            BaseWerEntries[i].Size = dwFlags;
            RtlReleaseSRWLockExclusive(&BaseWerEntriesLock);
            RtlFreeHeap(RtlGetProcessHeap(), 0, Copy);
            return S_OK;
        }
    }
    if (Free < BASE_WER_MAX_REGISTERED_ENTRIES)
    {
        BaseWerEntries[Free].Path = Copy;
        BaseWerEntries[Free].Block = NULL;
        BaseWerEntries[Free].Type = regFileType;
        BaseWerEntries[Free].Size = dwFlags;
        BaseWerEntryUsed[Free] = TRUE;
        Copy = NULL;
    }
    else
    {
        hr = HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER);
    }
    RtlReleaseSRWLockExclusive(&BaseWerEntriesLock);
    if (Copy)
        RtlFreeHeap(RtlGetProcessHeap(), 0, Copy);
    return hr;
}

/*
 * @implemented
 */
HRESULT
WINAPI
WerUnregisterFile(
    _In_ PCWSTR pwzFilePath)
{
    PWSTR Path = NULL;
    ULONG i;

    if (!pwzFilePath)
        return E_INVALIDARG;

    RtlAcquireSRWLockExclusive(&BaseWerEntriesLock);
    for (i = 0; i < BASE_WER_MAX_REGISTERED_ENTRIES; i++)
    {
        if (BaseWerEntryUsed[i] && BaseWerEntries[i].Path && !_wcsicmp(BaseWerEntries[i].Path, pwzFilePath))
        {
            Path = BaseWerEntries[i].Path;
            BaseWerEntries[i].Path = NULL;
            BaseWerEntryUsed[i] = FALSE;
            break;
        }
    }
    RtlReleaseSRWLockExclusive(&BaseWerEntriesLock);

    if (!Path)
        return HRESULT_FROM_WIN32(ERROR_NOT_FOUND);
    RtlFreeHeap(RtlGetProcessHeap(), 0, Path);
    return S_OK;
}

/*
 * @implemented
 *
 * Custom metadata only goes into a report, and there is no error reporting service to send one to:
 * a well-formed pair is accepted and dropped.
 */
HRESULT
WINAPI
WerRegisterCustomMetadata(
    _In_ PCWSTR pwzKey,
    _In_ PCWSTR pwzValue)
{
    if (!pwzKey || !pwzValue || !*pwzKey)
        return E_INVALIDARG;

    return S_OK;
}
