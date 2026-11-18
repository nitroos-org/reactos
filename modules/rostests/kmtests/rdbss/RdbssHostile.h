/*
 * PROJECT:     ReactOS kernel-mode tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     RDBSS tests: hostile caller operations, shared by the RdbssHostile
 *              kmtest and its second process (rdbsshostile.exe)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka
 *
 * Every operation targets a small set of files that all threads and both
 * processes share, so that opens collapse onto the same FCB and SRV_OPENs:
 * asynchronous I/O cancelled or orphaned by a handle close, mapped views
 * with truncation attempts, byte-range locks (overflowing ranges, waiting
 * locks cancelled, locks left to the cleanup), size changes, information
 * queries, relative opens with odd names, threads terminated in the middle
 * of I/O, user buffers decommitted during a cached read and uncommitted
 * during a cached write. No result is compared with a model: the mini-
 * redirector may be injecting faults. What is checked is that every
 * operation ends (a watchdog reports any that takes over 60 s), that no
 * kernel address comes back as a file ID, and, by the caller, that nothing
 * leaks once the driver is gone.
 */

#ifndef _RDBSSHOSTILE_H_
#define _RDBSSHOSTILE_H_

#include <stdio.h>

#define HOSTILE_FILES       4
#define HOSTILE_MAXSIZE     (1024 * 1024)
#define HOSTILE_OPS         16

typedef struct _HOSTILE
{
    PCWSTR Root;                /* \\looprdr\share\hostile */
    ULONG Index;
    ULONG Seed;
    DWORD EndTick;
    volatile LONG Op;           /* in progress, -1 between operations */
    volatile DWORD OpStart;
    ULONG Ops;
    ULONG Errors;               /* failed operations (expected with faults) */
    ULONG Problems;             /* real problems: kernel pointer as file ID, ... */
    HANDLE LoopDevice;          /* for buffering breaks (kmtest process only) */
    PUCHAR Buffer;              /* 256 KB */
    ULONG OpsMask;              /* operations allowed (bit n = op n) */
} HOSTILE;

/* CancelIoEx is a version-gated export: look it up, fall back to CancelIo
 * (the I/O is always the calling thread's here) */
static
VOID
HostileCancel(
    _In_ HANDLE File,
    _In_ OVERLAPPED *Ov)
{
    typedef BOOL (WINAPI *PFN_CANCELIOEX)(HANDLE, LPOVERLAPPED);
    static PFN_CANCELIOEX pCancelIoEx;
    static BOOLEAN Looked;

    if (!Looked)
    {
        pCancelIoEx = (PFN_CANCELIOEX)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "CancelIoEx");
        Looked = TRUE;
    }
    if (pCancelIoEx != NULL)
        pCancelIoEx(File, Ov);
    else
        CancelIo(File);
}

static
ULONG
HostileRand(
    _Inout_ PULONG Seed)
{
    *Seed = *Seed * 1103515245 + 12345;
    return *Seed >> 8;
}

static
VOID
HostilePath(
    _In_ HOSTILE *H,
    _In_ ULONG File,
    _Out_writes_(MAX_PATH) PWSTR Path)
{
    _snwprintf(Path, MAX_PATH, L"%s\\s%lu.bin", H->Root, File);
    Path[MAX_PATH - 1] = 0;
}

static
HANDLE
HostileOpen(
    _In_ HOSTILE *H,
    _In_ ULONG File,
    _In_ DWORD Flags)
{
    WCHAR Path[MAX_PATH];

    HostilePath(H, File, Path);
    return CreateFileW(Path, GENERIC_READ | GENERIC_WRITE | DELETE,
                       FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_ALWAYS, Flags, NULL);
}

/* Waits for an overlapped operation that may have been cancelled or whose
 * handle may be gone: it must end, whatever its status */
static
VOID
HostileWaitOverlapped(
    _In_ HOSTILE *H,
    _In_ OVERLAPPED *Ov,
    _In_ PCSTR What,
    _In_ ULONG How)
{
    DWORD Start = GetTickCount(), Wait;
    CHAR Msg[192];

    if (WaitForSingleObject(Ov->hEvent, 60000) == WAIT_OBJECT_0)
    {
        return;
    }
    /* Over 60 s is a problem whatever happens next; how long it takes in the
     * end (or that it never ends) tells what kind */
    ++H->Problems;
    sprintf(Msg, "RdbssHostile: %s (%lu): an overlapped operation is not done after 60 s\n", What, How);
    OutputDebugStringA(Msg);
    Wait = WaitForSingleObject(Ov->hEvent, 900000);
    sprintf(Msg, "RdbssHostile: %s (%lu): %s after %lu ms, status %lx\n", What, How,
            Wait == WAIT_OBJECT_0 ? "done" : "never completed", GetTickCount() - Start, (ULONG)Ov->Internal);
    OutputDebugStringA(Msg);
    if (Wait != WAIT_OBJECT_0)
    {
        /* The OVERLAPPED stays referenced by the IRP: leak it, never reuse */
        Ov->hEvent = NULL;
    }
}

typedef struct _HOSTILE_VICTIM
{
    HOSTILE *H;
    ULONG File;
    ULONG Seed;
    HANDLE Started;     /* set once the thread is in its I/O loop (out of
                           its start-up, which holds the loader lock) */
    HANDLE Handle;      /* its file: thread termination does not close it */
} HOSTILE_VICTIM;

/* A thread that is terminated at a random point of its I/O */
static
DWORD
WINAPI
HostileVictim(
    _In_ PVOID Parameter)
{
    HOSTILE_VICTIM *V = Parameter;
    HANDLE File;
    UCHAR Buffer[8192];
    DWORD Done;
    ULONG i;
    OVERLAPPED Ov;

    File = HostileOpen(V->H, V->File, 0);
    V->Handle = File;
    SetEvent(V->Started);
    if (File == INVALID_HANDLE_VALUE)
        return 0;
    for (i = 0; i < 1000; ++i)
    {
        LARGE_INTEGER Offset;

        Offset.QuadPart = HostileRand(&V->Seed) % HOSTILE_MAXSIZE;
        SetFilePointerEx(File, Offset, NULL, FILE_BEGIN);
        if (i & 1)
            ReadFile(File, Buffer, sizeof(Buffer), &Done, NULL);
        else
            WriteFile(File, Buffer, sizeof(Buffer), &Done, NULL);
        /* A lock that may have to wait for another owner */
        RtlZeroMemory(&Ov, sizeof(Ov));
        Ov.Offset = (DWORD)(HostileRand(&V->Seed) % 65536);
        LockFileEx(File, LOCKFILE_EXCLUSIVE_LOCK, 0, 4096, 0, &Ov);
    }
    V->Handle = INVALID_HANDLE_VALUE;
    CloseHandle(File);
    return 0;
}

/* Reads into a buffer whose second page another thread keeps decommitting */
typedef struct _HOSTILE_DECOMMIT
{
    PUCHAR Region;
    volatile LONG Stop;
} HOSTILE_DECOMMIT;

static
DWORD
WINAPI
HostileDecommitter(
    _In_ PVOID Parameter)
{
    HOSTILE_DECOMMIT *D = Parameter;

    while (!D->Stop)
    {
        VirtualFree(D->Region + 4096, 60 * 1024, MEM_DECOMMIT);
        VirtualAlloc(D->Region + 4096, 60 * 1024, MEM_COMMIT, PAGE_READWRITE);
    }
    return 0;
}

static
VOID
HostileOneOp(
    _In_ HOSTILE *H,
    _In_ ULONG Op)
{
    ULONG File = HostileRand(&H->Seed) % HOSTILE_FILES;
    HANDLE F;
    DWORD Done;

    switch (Op)
    {
        case 0:     /* overlapped I/O, cancelled, or orphaned by a close */
        case 1:
        {
            OVERLAPPED Ov;
            BOOL Started, Write = (HostileRand(&H->Seed) & 1);
            ULONG How = HostileRand(&H->Seed) % 3, Length = 1 + HostileRand(&H->Seed) % (256 * 1024);

            F = HostileOpen(H, File, FILE_FLAG_OVERLAPPED | ((HostileRand(&H->Seed) % 4 == 0) ? FILE_FLAG_NO_BUFFERING : 0));
            if (F == INVALID_HANDLE_VALUE) { ++H->Errors; break; }
            RtlZeroMemory(&Ov, sizeof(Ov));
            Ov.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
            Ov.Offset = (HostileRand(&H->Seed) % HOSTILE_MAXSIZE) & ~511;
            if (HostileRand(&H->Seed) & 1)
                Length = (Length + 511) & ~511;
            Started = Write ? WriteFile(F, H->Buffer, Length, NULL, &Ov) : ReadFile(F, H->Buffer, Length, NULL, &Ov);
            if (!Started && GetLastError() != ERROR_IO_PENDING) { ++H->Errors; CloseHandle(Ov.hEvent); CloseHandle(F); break; }
            if (How == 0)
                HostileCancel(F, &Ov);
            else if (How == 1)
            {
                CloseHandle(F);
                F = NULL;
            }
            HostileWaitOverlapped(H, &Ov, Write ? "overlapped write, how" : "overlapped read, how", How);
            if (F != NULL)
                CloseHandle(F);
            if (Ov.hEvent != NULL)
                CloseHandle(Ov.hEvent);
            break;
        }

        case 2:     /* synchronous cached I/O */
        {
            LARGE_INTEGER Offset;
            ULONG Length = 1 + HostileRand(&H->Seed) % (256 * 1024);

            F = HostileOpen(H, File, (HostileRand(&H->Seed) % 3 == 0) ? FILE_FLAG_WRITE_THROUGH : 0);
            if (F == INVALID_HANDLE_VALUE) { ++H->Errors; break; }
            Offset.QuadPart = HostileRand(&H->Seed) % HOSTILE_MAXSIZE;
            SetFilePointerEx(F, Offset, NULL, FILE_BEGIN);
            if (!((HostileRand(&H->Seed) & 1) ? WriteFile(F, H->Buffer, Length, &Done, NULL)
                                               : ReadFile(F, H->Buffer, Length, &Done, NULL)))
                ++H->Errors;
            CloseHandle(F);
            break;
        }

        case 3:     /* mapped view, truncation attempts under it */
        case 4:
        {
            HANDLE Section;
            PUCHAR View;
            LARGE_INTEGER Size;

            F = HostileOpen(H, File, 0);
            if (F == INVALID_HANDLE_VALUE) { ++H->Errors; break; }
            if (!GetFileSizeEx(F, &Size) || Size.QuadPart == 0)
            {
                Size.QuadPart = 65536;
                SetFilePointerEx(F, Size, NULL, FILE_BEGIN);
                SetEndOfFile(F);
            }
            Section = CreateFileMappingW(F, NULL, PAGE_READWRITE, 0, 0, NULL);
            if (Section == NULL) { ++H->Errors; CloseHandle(F); break; }
            View = MapViewOfFile(Section, FILE_MAP_WRITE, 0, 0, 0);
            if (View != NULL)
            {
                LARGE_INTEGER Small;
                SIZE_T i, Limit = (SIZE_T)min(Size.QuadPart, 512 * 1024);

                _SEH2_TRY
                {
                    for (i = 0; i < Limit; i += 4096)
                    {
                        View[i] ^= (UCHAR)HostileRand(&H->Seed);
                    }
                }
                _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
                {
                    /* The size moved between the query and the mapping */
                    ++H->Errors;
                }
                _SEH2_END;

                /* Must be refused while the view exists (STATUS_USER_MAPPED_FILE) */
                Small.QuadPart = HostileRand(&H->Seed) % 4096;
                SetFilePointerEx(F, Small, NULL, FILE_BEGIN);
                if (SetEndOfFile(F) && Small.QuadPart < Size.QuadPart)
                {
                    ++H->Problems;
                    OutputDebugStringA("RdbssHostile: truncated under a mapped view\n");
                }
                if (Op == 4)
                    FlushViewOfFile(View, 0);
                UnmapViewOfFile(View);
            }
            CloseHandle(Section);
            CloseHandle(F);
            break;
        }

        case 5:     /* sizes: end of file and allocation, sane and absurd */
        {
            IO_STATUS_BLOCK Iosb;
            FILE_END_OF_FILE_INFORMATION Eof;
            FILE_ALLOCATION_INFORMATION Alloc;
            ULONG Kind = HostileRand(&H->Seed) % 4;

            F = HostileOpen(H, File, 0);
            if (F == INVALID_HANDLE_VALUE) { ++H->Errors; break; }
            Eof.EndOfFile.QuadPart = (Kind == 0) ? (1LL << 62) : (Kind == 1) ? -1LL : (LONGLONG)(HostileRand(&H->Seed) % HOSTILE_MAXSIZE);
            NtSetInformationFile(F, &Iosb, &Eof, sizeof(Eof), FileEndOfFileInformation);
            Alloc.AllocationSize.QuadPart = (Kind == 0) ? 0x7FFFFFFFFFFFFFFFLL : (LONGLONG)(HostileRand(&H->Seed) % HOSTILE_MAXSIZE);
            NtSetInformationFile(F, &Iosb, &Alloc, sizeof(Alloc), FileAllocationInformation);
            CloseHandle(F);
            break;
        }

        case 6:     /* locks: overflowing ranges, waiting locks cancelled, locks left to cleanup */
        {
            OVERLAPPED Ov;
            ULONG Kind = HostileRand(&H->Seed) % 4;

            F = HostileOpen(H, File, FILE_FLAG_OVERLAPPED);
            if (F == INVALID_HANDLE_VALUE) { ++H->Errors; break; }
            RtlZeroMemory(&Ov, sizeof(Ov));
            Ov.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
            if (Kind == 0)
            {
                /* Offset + length past 2^64 */
                Ov.Offset = 0xFFFFF000;
                Ov.OffsetHigh = 0xFFFFFFFF;
                if (LockFileEx(F, LOCKFILE_FAIL_IMMEDIATELY, 0, 0x10000, 0, &Ov) || GetLastError() == ERROR_IO_PENDING)
                {
                    HostileWaitOverlapped(H, &Ov, "lock past 2^64", 0);
                }
            }
            else
            {
                DWORD Flags = (Kind == 1) ? LOCKFILE_FAIL_IMMEDIATELY : 0;

                Ov.Offset = HostileRand(&H->Seed) % 65536;
                if (HostileRand(&H->Seed) & 1)
                    Flags |= LOCKFILE_EXCLUSIVE_LOCK;
                if (!LockFileEx(F, Flags, 0, 1 + HostileRand(&H->Seed) % 8192, 0, &Ov) && GetLastError() == ERROR_IO_PENDING)
                {
                    /* Waiting behind another owner: give up after a moment */
                    if (WaitForSingleObject(Ov.hEvent, HostileRand(&H->Seed) % 30) == WAIT_TIMEOUT)
                    {
                        if (HostileRand(&H->Seed) & 1)
                            HostileCancel(F, &Ov);
                        else
                        {
                            CloseHandle(F);
                            F = NULL;
                        }
                    }
                    HostileWaitOverlapped(H, &Ov, F == NULL ? "waiting lock, handle closed, kind" : "waiting lock, kind", Kind);
                }
                else if (Kind == 3)
                {
                    UnlockFileEx(F, 0, 8192, 0, &Ov);
                }
                /* Kind 2: the lock stays for the cleanup to drop */
            }
            if (F != NULL)
                CloseHandle(F);
            if (Ov.hEvent != NULL)
                CloseHandle(Ov.hEvent);
            break;
        }

        case 7:     /* queries: the file ID must never be a kernel address */
        {
            IO_STATUS_BLOCK Iosb;
            FILE_INTERNAL_INFORMATION Internal;
            PUCHAR All = H->Buffer;

            F = HostileOpen(H, File, 0);
            if (F == INVALID_HANDLE_VALUE) { ++H->Errors; break; }
            if (NT_SUCCESS(NtQueryInformationFile(F, &Iosb, &Internal, sizeof(Internal), FileInternalInformation)))
            {
                if (sizeof(PVOID) == 8 && (ULONGLONG)Internal.IndexNumber.QuadPart >= 0xFFFF800000000000ULL)
                {
                    ++H->Problems;
                    OutputDebugStringA("RdbssHostile: FileInternalInformation returned a kernel address\n");
                }
            }
            NtQueryInformationFile(F, &Iosb, All, 1024 + HostileRand(&H->Seed) % 2048, FileAllInformation);
            NtQueryInformationFile(F, &Iosb, All, HostileRand(&H->Seed) % 64, FileNameInformation);
            NtQueryInformationFile(F, &Iosb, All, 4096, FileStandardInformation);
            CloseHandle(F);
            break;
        }

        case 8:     /* directory enumeration with small buffers */
        {
            WIN32_FIND_DATAW Data;
            WCHAR Pattern[MAX_PATH];
            HANDLE Find;

            _snwprintf(Pattern, MAX_PATH, L"%s\\*", H->Root);
            Pattern[MAX_PATH - 1] = 0;
            Find = FindFirstFileW(Pattern, &Data);
            if (Find == INVALID_HANDLE_VALUE) { ++H->Errors; break; }
            while (FindNextFileW(Find, &Data))
                ;
            FindClose(Find);
            break;
        }

        case 9:     /* relative opens with odd names */
        {
            static WCHAR Long[4096];
            UNICODE_STRING Name;
            OBJECT_ATTRIBUTES Attributes;
            IO_STATUS_BLOCK Iosb;
            HANDLE Dir, Child;
            ULONG i, Kind = HostileRand(&H->Seed) % 5;

            Dir = CreateFileW(H->Root, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
                              OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
            if (Dir == INVALID_HANDLE_VALUE) { ++H->Errors; break; }
            if (Long[0] == 0)
            {
                for (i = 0; i < RTL_NUMBER_OF(Long) - 1; ++i)
                    Long[i] = L'a' + (WCHAR)(i % 26);
            }
            switch (Kind)
            {
                case 0: RtlInitUnicodeString(&Name, L"s0.bin"); break;
                case 1: RtlInitUnicodeString(&Name, L""); break;
                case 2: RtlInitUnicodeString(&Name, L"\\s1.bin"); break;
                case 3: Name.Buffer = Long; Name.Length = Name.MaximumLength = (USHORT)(sizeof(Long) - sizeof(WCHAR)); break;
                default: Name.Buffer = Long; Name.Length = Name.MaximumLength = 0xFFFE; break;   /* past the end: refused by the I/O manager */
            }
            if (Kind == 4)
            {
                /* A name that would push the canonical name past 64 KB:
                 * build it in a heap buffer */
                PWSTR Huge = HeapAlloc(GetProcessHeap(), 0, 0xFFFE);

                if (Huge != NULL)
                {
                    for (i = 0; i < 0xFFFE / sizeof(WCHAR); ++i)
                        Huge[i] = L'b';
                    Name.Buffer = Huge;
                    InitializeObjectAttributes(&Attributes, &Name, OBJ_CASE_INSENSITIVE, Dir, NULL);
                    if (NT_SUCCESS(NtCreateFile(&Child, GENERIC_READ | SYNCHRONIZE, &Attributes, &Iosb, NULL, 0,
                                                FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0)))
                    {
                        ++H->Problems;
                        CloseHandle(Child);
                    }
                    HeapFree(GetProcessHeap(), 0, Huge);
                }
            }
            else
            {
                InitializeObjectAttributes(&Attributes, &Name, OBJ_CASE_INSENSITIVE, Dir, NULL);
                if (NT_SUCCESS(NtCreateFile(&Child, GENERIC_READ | SYNCHRONIZE, &Attributes, &Iosb, NULL, 0,
                                            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_OPEN,
                                            FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0)))
                    CloseHandle(Child);
            }
            CloseHandle(Dir);
            break;
        }

        case 10:    /* a thread terminated in the middle of its I/O */
        {
            HOSTILE_VICTIM V;
            HANDLE Thread;

            V.H = H;
            V.File = File;
            V.Seed = HostileRand(&H->Seed);
            V.Handle = INVALID_HANDLE_VALUE;
            V.Started = CreateEventW(NULL, TRUE, FALSE, NULL);
            Thread = CreateThread(NULL, 0, HostileVictim, &V, 0, NULL);
            if (Thread == NULL) { ++H->Errors; CloseHandle(V.Started); break; }
            /* Terminate it inside its I/O, never during its start-up */
            if (WaitForSingleObject(V.Started, 30000) == WAIT_OBJECT_0)
            {
                Sleep(HostileRand(&H->Seed) % 25);
                TerminateThread(Thread, 0);
            }
            CloseHandle(V.Started);
            if (WaitForSingleObject(Thread, 60000) != WAIT_OBJECT_0)
            {
                ++H->Problems;
                OutputDebugStringA("RdbssHostile: a terminated thread did not go away\n");
            }
            else if (V.Handle != INVALID_HANDLE_VALUE && V.Handle != NULL)
            {
                /* Its handle outlives it: the process would keep the file
                 * open until it exits */
                CloseHandle(V.Handle);
            }
            CloseHandle(Thread);
            break;
        }

        case 11:    /* cached read into a buffer being decommitted */
        {
            HOSTILE_DECOMMIT D;
            HANDLE Thread;
            ULONG i;

            D.Region = VirtualAlloc(NULL, 64 * 1024, MEM_COMMIT, PAGE_READWRITE);
            if (D.Region == NULL) { ++H->Errors; break; }
            D.Stop = 0;
            F = HostileOpen(H, File, 0);
            if (F == INVALID_HANDLE_VALUE) { ++H->Errors; VirtualFree(D.Region, 0, MEM_RELEASE); break; }
            Thread = CreateThread(NULL, 0, HostileDecommitter, &D, 0, NULL);
            for (i = 0; i < 50; ++i)
            {
                SetFilePointer(F, 0, NULL, FILE_BEGIN);
                ReadFile(F, D.Region, 64 * 1024, &Done, NULL);
            }
            D.Stop = 1;
            if (Thread != NULL)
            {
                WaitForSingleObject(Thread, INFINITE);
                CloseHandle(Thread);
            }
            CloseHandle(F);
            VirtualFree(D.Region, 0, MEM_RELEASE);
            break;
        }

        case 12:    /* cached write from a buffer with an uncommitted page */
        {
            PUCHAR Region;

            Region = VirtualAlloc(NULL, 64 * 1024, MEM_RESERVE, PAGE_READWRITE);
            if (Region == NULL || !VirtualAlloc(Region, 4096, MEM_COMMIT, PAGE_READWRITE)) { ++H->Errors; break; }
            F = HostileOpen(H, File, 0);
            if (F != INVALID_HANDLE_VALUE)
            {
                SetFilePointer(F, HostileRand(&H->Seed) % 65536, NULL, FILE_BEGIN);
                if (WriteFile(F, Region, 64 * 1024, &Done, NULL))
                {
                    /* Only the committed page could have been written */
                    if (Done > 4096)
                        ++H->Problems;
                }
                CloseHandle(F);
            }
            VirtualFree(Region, 0, MEM_RELEASE);
            break;
        }

        case 13:    /* buffering state break on a handle (kmtest process only) */
        {
#ifdef IOCTL_LOOPRDR_BREAK
            LOOPRDR_BREAK Break;
            DWORD Returned;

            if (H->LoopDevice == NULL)
                break;
            F = HostileOpen(H, File, 0);
            if (F == INVALID_HANDLE_VALUE) { ++H->Errors; break; }
            WriteFile(F, H->Buffer, 4096, &Done, NULL);
            Break.FileHandle = (ULONG_PTR)F;
            Break.NewBufferingState = 0;
            Break.Flags = (HostileRand(&H->Seed) & 1) ? LOOPRDR_BREAK_FOR_SRVOPEN : 0;
            DeviceIoControl(H->LoopDevice, IOCTL_LOOPRDR_BREAK, &Break, sizeof(Break), NULL, 0, &Returned, NULL);
            if (HostileRand(&H->Seed) & 1)
                CloseHandle(F);     /* closes while the break may still be queued */
            else
            {
                ReadFile(F, H->Buffer, 4096, &Done, NULL);
                CloseHandle(F);
            }
#endif
            break;
        }

        case 14:    /* flush, delete on close, rename */
        {
            IO_STATUS_BLOCK Iosb;

            F = HostileOpen(H, File, 0);
            if (F == INVALID_HANDLE_VALUE) { ++H->Errors; break; }
            switch (HostileRand(&H->Seed) % 3)
            {
                case 0:
                    FlushFileBuffers(F);
                    break;
                case 1:
                {
                    FILE_DISPOSITION_INFORMATION Disposition;

                    Disposition.DeleteFile = TRUE;
                    NtSetInformationFile(F, &Iosb, &Disposition, sizeof(Disposition), FileDispositionInformation);
                    break;
                }
                default:
                {
                    struct { FILE_RENAME_INFORMATION Info; WCHAR More[32]; } Rename;

                    RtlZeroMemory(&Rename, sizeof(Rename));
                    Rename.Info.ReplaceIfExists = TRUE;
                    _snwprintf(Rename.Info.FileName, 32, L"s%lu.bin", (ULONG)(HostileRand(&H->Seed) % HOSTILE_FILES));
                    Rename.Info.FileNameLength = (ULONG)wcslen(Rename.Info.FileName) * sizeof(WCHAR);
                    NtSetInformationFile(F, &Iosb, &Rename, sizeof(Rename), FileRenameInformation);
                    break;
                }
            }
            CloseHandle(F);
            break;
        }

        default:    /* plain open/close storm */
            F = HostileOpen(H, File, 0);
            if (F != INVALID_HANDLE_VALUE)
                CloseHandle(F);
            else
                ++H->Errors;
            break;
    }
}

static
DWORD
WINAPI
HostileThread(
    _In_ PVOID Parameter)
{
    HOSTILE *H = Parameter;

    while ((LONG)(GetTickCount() - H->EndTick) < 0)
    {
        ULONG Op = HostileRand(&H->Seed) % HOSTILE_OPS;

        if (!(H->OpsMask & (1UL << Op)))
            Op = HOSTILE_OPS - 1;   /* plain open/close */
        H->OpStart = GetTickCount();
        H->Op = Op;
        HostileOneOp(H, Op);
        H->Op = -1;
        ++H->Ops;
    }
    return 0;
}

/* Runs Count hostile threads for Seconds; returns problems found (and the
 * totals through the out parameters). Reports operations stuck for 60 s */
static
ULONG
HostileRun(
    _In_ PCWSTR Root,
    _In_ ULONG Count,
    _In_ ULONG Seconds,
    _In_ ULONG Seed,
    _In_opt_ HANDLE LoopDevice,
    _In_ ULONG OpsMask,
    _Out_ PULONG Ops,
    _Out_ PULONG Errors)
{
    HOSTILE H[16];
    HANDLE Threads[16];
    ULONG i, Problems = 0;
    DWORD Start = GetTickCount();

    *Ops = *Errors = 0;
    if (Count > 16)
        Count = 16;
    for (i = 0; i < Count; ++i)
    {
        RtlZeroMemory(&H[i], sizeof(H[i]));
        H[i].Root = Root;
        H[i].Index = i;
        H[i].Seed = Seed + i * 7919;
        H[i].EndTick = Start + Seconds * 1000;
        H[i].Op = -1;
        H[i].OpStart = Start;
        H[i].LoopDevice = LoopDevice;
        H[i].OpsMask = OpsMask;
        H[i].Buffer = VirtualAlloc(NULL, 256 * 1024, MEM_COMMIT, PAGE_READWRITE);
        Threads[i] = CreateThread(NULL, 0, HostileThread, &H[i], 0, NULL);
    }
    while (WaitForMultipleObjects(Count, Threads, TRUE, 15000) == WAIT_TIMEOUT)
    {
        static ULONG Dumps;
        DWORD Longest = 0;

        for (i = 0; i < Count; ++i)
        {
            LONG Op = H[i].Op;

            if (Op >= 0 && GetTickCount() - H[i].OpStart > 60000)
            {
                CHAR Msg[128];

                _snprintf(Msg, sizeof(Msg), "RdbssHostile: thread %lu stuck in op %ld for %lu ms\n",
                          i, Op, GetTickCount() - H[i].OpStart);
                Msg[sizeof(Msg) - 1] = 0;
                OutputDebugStringA(Msg);
                Longest = max(Longest, GetTickCount() - H[i].OpStart);
            }
        }
#ifdef IOCTL_LOOPRDR_DUMP
        /* The kernel side of a hang, once early and once late */
        if (LoopDevice != NULL && ((Longest > 60000 && Dumps == 0) || (Longest > 300000 && Dumps == 1)))
        {
            DWORD Returned;
            WCHAR Env[8];
            /* RDBSS_HOSTILE_BREAK=1: stop in the kernel debugger in the
             * thread that holds the contended FCB (its stack is the
             * debugger's backtrace) */
            ULONG Break = (GetEnvironmentVariableW(L"RDBSS_HOSTILE_BREAK", Env, RTL_NUMBER_OF(Env)) && Env[0] == L'1');

            ++Dumps;
            DeviceIoControl(LoopDevice, IOCTL_LOOPRDR_DUMP, &Break, sizeof(Break), NULL, 0, &Returned, NULL);
        }
#endif
    }
    for (i = 0; i < Count; ++i)
    {
        *Ops += H[i].Ops;
        *Errors += H[i].Errors;
        Problems += H[i].Problems;
        CloseHandle(Threads[i]);
        VirtualFree(H[i].Buffer, 0, MEM_RELEASE);
    }
    return Problems;
}

#endif /* _RDBSSHOSTILE_H_ */
