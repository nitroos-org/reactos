/*
 * PROJECT:     ReactOS API Tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Test for NtFlushVirtualMemory (FlushViewOfFile)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka (tomas.srnka@e2b.dev)
 */

#include "precomp.h"

#define PATTERN 0x55
#define FILE_SIZE 0x3000

START_TEST(NtFlushVirtualMemory)
{
    WCHAR Path[MAX_PATH];
    IO_STATUS_BLOCK Io;
    NTSTATUS Status;
    HANDLE File, Mapping, Reader;
    PBYTE View;
    PVOID Base;
    SIZE_T Size;
    DWORD Count;
    BYTE Byte;
    ULONG Length;

    Length = GetTempPathW(RTL_NUMBER_OF(Path), Path);
    StringCbPrintfW(Path + Length, sizeof(Path) - Length * sizeof(WCHAR), L"wow64pf_flushvm_%lu.tmp", GetCurrentProcessId());
    File = CreateFileW(Path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, CREATE_ALWAYS,
                       FILE_ATTRIBUTE_NORMAL, NULL);
    ok(File != INVALID_HANDLE_VALUE, "CreateFile failed, error %lu\n", GetLastError());
    if (File == INVALID_HANDLE_VALUE)
        return;
    SetFilePointer(File, FILE_SIZE, NULL, FILE_BEGIN);
    SetEndOfFile(File);
    Mapping = CreateFileMappingW(File, NULL, PAGE_READWRITE, 0, FILE_SIZE, NULL);
    View = Mapping ? MapViewOfFile(Mapping, FILE_MAP_WRITE, 0, 0, 0) : NULL;
    ok(View != NULL, "mapping failed, error %lu\n", GetLastError());
    if (!View)
    {
        CloseHandle(File);
        DeleteFileW(Path);
        return;
    }
    View[0x1100] = 0x42;

    /* A range inside the second page: rounded out to whole pages */
    Base = View + 0x1100;
    Size = 0x10;
    RtlFillMemory(&Io, sizeof(Io), PATTERN);
    Status = NtFlushVirtualMemory(NtCurrentProcess(), &Base, &Size, &Io);
    ok_hex(Status, STATUS_SUCCESS);
    ok(Base == View + 0x1000, "base %p, view %p\n", Base, View);
    /* The rounded size, and the length in the block (Windows 10 22H2) */
    ok(Size == 0x1000, "size %Ix\n", Size);
    ok_hex(Io.Status, STATUS_SUCCESS);
    ok(Io.Information == 0x1000, "information %Ix\n", Io.Information);

    /* The data is on its way to the file: another handle reads it */
    Reader = CreateFileW(Path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    ok(Reader != INVALID_HANDLE_VALUE, "reader failed, error %lu\n", GetLastError());
    Byte = 0;
    SetFilePointer(Reader, 0x1100, NULL, FILE_BEGIN);
    ok(ReadFile(Reader, &Byte, 1, &Count, NULL) && Count == 1, "read failed, error %lu\n", GetLastError());
    ok_eq_hex(Byte, 0x42);
    CloseHandle(Reader);
    ok(FlushViewOfFile(View, 0), "FlushViewOfFile failed, error %lu\n", GetLastError());

    /* Size 0: to the end of the view */
    Base = View;
    Size = 0;
    Status = NtFlushVirtualMemory(NtCurrentProcess(), &Base, &Size, &Io);
    ok_hex(Status, STATUS_SUCCESS);
    ok(Base == View, "base %p, view %p\n", Base, View);
    ok(Size == FILE_SIZE, "size %Ix\n", Size);

    /* Size 0 from inside the view: to its end */
    Base = View + 0x1000;
    Size = 0;
    Status = NtFlushVirtualMemory(NtCurrentProcess(), &Base, &Size, &Io);
    ok_hex(Status, STATUS_SUCCESS);
    ok(Size == FILE_SIZE - 0x1000, "size %Ix\n", Size);

    /* Past the end of the view: not mapped, the size is left as given */
    Base = View + 0x800;
    Size = FILE_SIZE;
    Status = NtFlushVirtualMemory(NtCurrentProcess(), &Base, &Size, &Io);
    ok_hex(Status, STATUS_NOT_MAPPED_VIEW);
    ok(Base == View, "base %p, view %p\n", Base, View);
    ok(Size == FILE_SIZE, "size %Ix\n", Size);

    /* Private memory is no view; an image view and a pagefile-backed view have no file data to write */
    {
        PVOID Private = VirtualAlloc(NULL, 0x10000, MEM_COMMIT, PAGE_READWRITE);
        HANDLE PagefileSection = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, 0x10000, NULL);
        PBYTE PagefileView = PagefileSection ? MapViewOfFile(PagefileSection, FILE_MAP_WRITE, 0, 0, 0) : NULL;

        ok(Private && PagefileView, "allocation failed, error %lu\n", GetLastError());
        if (Private)
        {
            Base = Private;
            Size = 0x1000;
            ok_hex(NtFlushVirtualMemory(NtCurrentProcess(), &Base, &Size, &Io), STATUS_NOT_MAPPED_VIEW);
            ok(!FlushViewOfFile(Private, 0x1000), "FlushViewOfFile of private memory succeeded\n");
            VirtualFree(Private, 0, MEM_RELEASE);
            /* A free address */
            Base = Private;
            Size = 0x1000;
            ok_hex(NtFlushVirtualMemory(NtCurrentProcess(), &Base, &Size, &Io), STATUS_NOT_MAPPED_VIEW);
        }
        if (PagefileView)
        {
            PagefileView[0] = 1;
            Base = PagefileView;
            Size = 0x1000;
            ok_hex(NtFlushVirtualMemory(NtCurrentProcess(), &Base, &Size, &Io), STATUS_NOT_MAPPED_DATA);
            ok(FlushViewOfFile(PagefileView, 0x1000), "FlushViewOfFile failed, error %lu\n", GetLastError());
            UnmapViewOfFile(PagefileView);
        }
        if (PagefileSection)
            CloseHandle(PagefileSection);
        Base = GetModuleHandleW(NULL);
        Size = 0x1000;
        ok_hex(NtFlushVirtualMemory(NtCurrentProcess(), &Base, &Size, &Io), STATUS_NOT_MAPPED_DATA);
    }

    Base = View;
    Size = 0;
    Status = NtFlushVirtualMemory((HANDLE)(ULONG_PTR)0x12344, &Base, &Size, &Io);
    ok_hex(Status, STATUS_INVALID_HANDLE);

    UnmapViewOfFile(View);
    CloseHandle(Mapping);
    CloseHandle(File);
    DeleteFileW(Path);
}
