/*
 * PROJECT:     ReactOS API Tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Test for NtFlushBuffersFileEx and ZwFlushBuffersFileEx (Windows 8 and later)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka (tomas.srnka@e2b.dev)
 *
 * Every expected value was measured on Windows 10 22H2 (19045), x64 and x86 under WOW64, on an NTFS volume:
 * - the flags are not checked, any value is accepted on a file;
 * - the parameter block is reserved: a pointer or a size that is not zero is STATUS_INVALID_PARAMETER, checked
 *   before the I/O status block and before the handle (an event handle gives INVALID_PARAMETER too);
 * - a NULL I/O status block is STATUS_ACCESS_VIOLATION as a status, before the handle is looked at;
 * - the access check is the one of NtFlushBuffersFile: FILE_WRITE_DATA or FILE_APPEND_DATA.
 */

#include "precomp.h"

#define PATTERN 0x55

typedef NTSTATUS (NTAPI *PFN_FLUSH_EX)(HANDLE, ULONG, PVOID, ULONG, PIO_STATUS_BLOCK);

static PFN_FLUSH_EX pNtFlushBuffersFileEx;

static
NTSTATUS
FlushEx(HANDLE Handle, ULONG Flags, PVOID Parameters, ULONG Size, IO_STATUS_BLOCK *Io)
{
    RtlFillMemory(Io, sizeof(*Io), PATTERN);
    return pNtFlushBuffersFileEx(Handle, Flags, Parameters, Size, Io);
}

#define ok_untouched(Io) \
    do { \
        ULONG_PTR Pattern_; \
        RtlFillMemory(&Pattern_, sizeof(Pattern_), PATTERN); \
        ok_eq_hex((ULONG)(Io).Status, PATTERN * 0x01010101); \
        ok_eq_ulongptr((Io).Information, Pattern_); \
    } while (0)

static
void
TestFlags(HANDLE File)
{
    static const ULONG Flags[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 0x10, 0x100, 0x80000000, 0xFFFFFFFF };
    IO_STATUS_BLOCK Io;
    NTSTATUS Status;
    ULONG i;

    for (i = 0; i < RTL_NUMBER_OF(Flags); i++)
    {
        Status = FlushEx(File, Flags[i], NULL, 0, &Io);
        ok(Status == STATUS_SUCCESS, "flags 0x%lx: status 0x%lx\n", Flags[i], Status);
        ok_hex(Io.Status, STATUS_SUCCESS);
        ok_eq_ulongptr(Io.Information, 0);
    }
}

static
void
TestParameters(HANDLE File)
{
    IO_STATUS_BLOCK Io;
    NTSTATUS Status;
    CHAR Block[16] = { 0 };
    HANDLE Event = CreateEventW(NULL, TRUE, FALSE, NULL);

    Status = FlushEx(File, 0, Block, 0, &Io);
    ok_hex(Status, STATUS_INVALID_PARAMETER);
    ok_untouched(Io);

    Status = FlushEx(File, 0, NULL, 4, &Io);
    ok_hex(Status, STATUS_INVALID_PARAMETER);
    ok_untouched(Io);

    Status = FlushEx(File, 1, Block, sizeof(Block), &Io);
    ok_hex(Status, STATUS_INVALID_PARAMETER);
    ok_untouched(Io);

    /* before the handle is looked at, and before the block */
    Status = FlushEx(Event, 0, NULL, 4, &Io);
    ok_hex(Status, STATUS_INVALID_PARAMETER);
    ok_untouched(Io);
    Status = FlushEx((HANDLE)(ULONG_PTR)0xdeadbeef, 0, Block, 0, &Io);
    ok_hex(Status, STATUS_INVALID_PARAMETER);
    ok_untouched(Io);
    Status = FlushEx(NULL, 0, NULL, 4, &Io);
    ok_hex(Status, STATUS_INVALID_PARAMETER);
    Status = pNtFlushBuffersFileEx(File, 0, NULL, 4, NULL);
    ok_hex(Status, STATUS_INVALID_PARAMETER);

    CloseHandle(Event);
}

static
void
TestIoStatusBlock(HANDLE File)
{
    NTSTATUS Status;

    /* a status, not an exception, and before the handle */
    Status = pNtFlushBuffersFileEx(File, 0, NULL, 0, NULL);
    ok_hex(Status, STATUS_ACCESS_VIOLATION);
    Status = pNtFlushBuffersFileEx((HANDLE)(ULONG_PTR)0xdeadbeef, 0, NULL, 0, NULL);
    ok_hex(Status, STATUS_ACCESS_VIOLATION);
}

static
void
TestAccess(PCWSTR Path)
{
    static const struct
    {
        PCSTR Name;
        DWORD Access;
        NTSTATUS Expected;
    } Cases[] =
    {
        { "GENERIC_READ", GENERIC_READ, STATUS_ACCESS_DENIED },
        { "GENERIC_WRITE", GENERIC_WRITE, STATUS_SUCCESS },
        { "FILE_WRITE_DATA", FILE_WRITE_DATA, STATUS_SUCCESS },
        { "FILE_APPEND_DATA", FILE_APPEND_DATA, STATUS_SUCCESS },
        { "FILE_WRITE_ATTRIBUTES", FILE_WRITE_ATTRIBUTES, STATUS_ACCESS_DENIED },
        { "FILE_READ_DATA | SYNCHRONIZE", FILE_READ_DATA | SYNCHRONIZE, STATUS_ACCESS_DENIED },
        { "READ_CONTROL", READ_CONTROL, STATUS_ACCESS_DENIED },
        { "FILE_WRITE_EA", FILE_WRITE_EA, STATUS_ACCESS_DENIED },
    };
    IO_STATUS_BLOCK Io;
    NTSTATUS Status;
    HANDLE File;
    ULONG i;

    for (i = 0; i < RTL_NUMBER_OF(Cases); i++)
    {
        File = CreateFileW(Path, Cases[i].Access, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           NULL, OPEN_EXISTING, 0, NULL);
        ok(File != INVALID_HANDLE_VALUE, "%s: open failed, error %lu\n", Cases[i].Name, GetLastError());
        if (File == INVALID_HANDLE_VALUE)
            continue;

        Status = FlushEx(File, 0, NULL, 0, &Io);
        ok(Status == Cases[i].Expected, "%s: status 0x%lx, expected 0x%lx\n", Cases[i].Name, Status, Cases[i].Expected);
        if (Cases[i].Expected == STATUS_SUCCESS)
        {
            ok_hex(Io.Status, STATUS_SUCCESS);
            ok_eq_ulongptr(Io.Information, 0);
        }
        else
        {
            /* refused before the block is written */
            ok_untouched(Io);
        }

        /* the flags do not change the outcome */
        Status = FlushEx(File, 4, NULL, 0, &Io);
        ok(Status == Cases[i].Expected, "%s, flags 4: status 0x%lx, expected 0x%lx\n", Cases[i].Name, Status, Cases[i].Expected);
        CloseHandle(File);
    }
}

static
void
TestHandles(void)
{
    IO_STATUS_BLOCK Io;
    NTSTATUS Status;
    HANDLE Event = CreateEventW(NULL, TRUE, FALSE, NULL);

    /* the handle type is checked, the flags are not looked at first */
    Status = FlushEx(Event, 0, NULL, 0, &Io);
    ok_hex(Status, STATUS_OBJECT_TYPE_MISMATCH);
    ok_untouched(Io);
    Status = FlushEx(Event, 0x80000000, NULL, 0, &Io);
    ok_hex(Status, STATUS_OBJECT_TYPE_MISMATCH);
    CloseHandle(Event);

    Status = FlushEx(NtCurrentProcess(), 0, NULL, 0, &Io);
    ok_hex(Status, STATUS_OBJECT_TYPE_MISMATCH);

    Status = FlushEx(NULL, 0, NULL, 0, &Io);
    ok_hex(Status, STATUS_INVALID_HANDLE);
    ok_untouched(Io);
    Status = FlushEx((HANDLE)(ULONG_PTR)0xdeadbeef, 0, NULL, 0, &Io);
    ok_hex(Status, STATUS_INVALID_HANDLE);
    Status = FlushEx((HANDLE)(ULONG_PTR)0xdeadbeef, 0x80000000, NULL, 0, &Io);
    ok_hex(Status, STATUS_INVALID_HANDLE);
    ok_untouched(Io);
}

static
void
TestDirectory(PCWSTR Dir)
{
    IO_STATUS_BLOCK Io;
    NTSTATUS Status;
    HANDLE Handle;

    Handle = CreateFileW(Dir, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                         NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
    ok(Handle != INVALID_HANDLE_VALUE, "open of the directory failed, error %lu\n", GetLastError());
    if (Handle != INVALID_HANDLE_VALUE)
    {
        Status = FlushEx(Handle, 0, NULL, 0, &Io);
        ok_hex(Status, STATUS_SUCCESS);
        ok_hex(Io.Status, STATUS_SUCCESS);

        /* the other flags */
        Status = FlushEx(Handle, 2, NULL, 0, &Io);
        ok_hex(Status, STATUS_SUCCESS);
        Status = FlushEx(Handle, 4, NULL, 0, &Io);
        ok_hex(Status, STATUS_SUCCESS);
        Status = FlushEx(Handle, 0x80000000, NULL, 0, &Io);
        ok_hex(Status, STATUS_SUCCESS);

        /* NTFS refuses FLUSH_FLAGS_FILE_DATA_ONLY (1) on a directory, whatever else is set; the flags only reach
         * a file system through its own interface, which the file systems here do not have */
        todo_if(is_reactos())
            ok_hex(FlushEx(Handle, 1, NULL, 0, &Io), STATUS_INVALID_PARAMETER);
        todo_if(is_reactos())
            ok_hex(FlushEx(Handle, 7, NULL, 0, &Io), STATUS_INVALID_PARAMETER);
        CloseHandle(Handle);
    }

    Handle = CreateFileW(Dir, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                         NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
    if (Handle != INVALID_HANDLE_VALUE)
    {
        Status = FlushEx(Handle, 0, NULL, 0, &Io);
        ok_hex(Status, STATUS_ACCESS_DENIED);
        ok_untouched(Io);
        CloseHandle(Handle);
    }
}

static
void
TestPipe(void)
{
    IO_STATUS_BLOCK Io;
    NTSTATUS Status;
    HANDLE Read, Write;

    if (!CreatePipe(&Read, &Write, NULL, 0))
    {
        skip("CreatePipe failed, error %lu\n", GetLastError());
        return;
    }
    Status = FlushEx(Write, 0, NULL, 0, &Io);
    ok_hex(Status, STATUS_SUCCESS);
    ok_hex(Io.Status, STATUS_SUCCESS);
    Status = FlushEx(Read, 0, NULL, 0, &Io);
    ok_hex(Status, STATUS_ACCESS_DENIED);
    ok_untouched(Io);
    CloseHandle(Read);
    CloseHandle(Write);
}

START_TEST(NtFlushBuffersFileEx)
{
    HMODULE Ntdll = GetModuleHandleW(L"ntdll.dll");
    PVOID pZw;
    WCHAR Dir[MAX_PATH], Path[MAX_PATH];
    HANDLE File;
    DWORD Written;
    ULONG Length;

    pNtFlushBuffersFileEx = (PFN_FLUSH_EX)GetProcAddress(Ntdll, "NtFlushBuffersFileEx");
    if (!pNtFlushBuffersFileEx)
    {
        skip("NtFlushBuffersFileEx is not available\n");
        return;
    }

    /* Zw and Nt are the same function in user mode */
    pZw = GetProcAddress(Ntdll, "ZwFlushBuffersFileEx");
    ok(pZw == (PVOID)pNtFlushBuffersFileEx, "ZwFlushBuffersFileEx %p, NtFlushBuffersFileEx %p\n", pZw, pNtFlushBuffersFileEx);

    Length = GetTempPathW(RTL_NUMBER_OF(Dir), Dir);
    ok(Length != 0, "GetTempPath failed\n");
    StringCbPrintfW(Path, sizeof(Path), L"%lsflushex_%lu.tmp", Dir, GetCurrentProcessId());

    File = CreateFileW(Path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                       NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_DELETE_ON_CLOSE, NULL);
    ok(File != INVALID_HANDLE_VALUE, "create failed, error %lu\n", GetLastError());
    if (File == INVALID_HANDLE_VALUE)
        return;
    ok(WriteFile(File, "abc", 3, &Written, NULL) && Written == 3, "write failed, error %lu\n", GetLastError());

    TestFlags(File);
    TestParameters(File);
    TestIoStatusBlock(File);
    TestAccess(Path);
    TestHandles();
    TestDirectory(Dir);
    TestPipe();

    /* an overlapped handle completes the request before the call returns */
    {
        IO_STATUS_BLOCK Io;
        NTSTATUS Status;
        HANDLE Async = CreateFileW(Path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                   NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL);
        ok(Async != INVALID_HANDLE_VALUE, "open overlapped failed, error %lu\n", GetLastError());
        if (Async != INVALID_HANDLE_VALUE)
        {
            Status = FlushEx(Async, 0, NULL, 0, &Io);
            ok_hex(Status, STATUS_SUCCESS);
            ok_hex(Io.Status, STATUS_SUCCESS);
            ok_eq_ulongptr(Io.Information, 0);
            Status = FlushEx(Async, 4, NULL, 0, &Io);
            ok_hex(Status, STATUS_SUCCESS);
            CloseHandle(Async);
        }
    }

    CloseHandle(File);
}
