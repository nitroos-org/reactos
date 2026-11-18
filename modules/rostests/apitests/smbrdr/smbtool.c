/*
 * PROJECT:     NitroOS
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     smbtool: helpers for the SMB redirector tests (test data, checksums, pool tags)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

/*
 * smbtool gen FILE BYTES [SEED]   write BYTES of seeded pseudo-random data, print its SHA-256
 * smbtool sum FILE                print size and SHA-256 of FILE
 * smbtool pool TAG...             print allocations, frees and bytes of the pool tags (4 chars each)
 * smbtool drive X:                GetDriveType, QueryDosDevice, volume information, the NT name of the root
 * Output lines: "GEN bytes=N sha256=H", "SUM bytes=N sha256=H", "POOL tag=T ...", "DRIVE ..."; exit code
 * is the Win32 error of a failure.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define WIN32_NO_STATUS
#include <windows.h>
#include <bcrypt.h>
#include <ndk/exfuncs.h>
#include <ndk/iofuncs.h>
#include <ndk/obfuncs.h>
#include <ndk/rtlfuncs.h>
#include <ntstatus.h>

#define CHUNK (1024 * 1024)

static int hash_file(HANDLE f, BOOL gen, ULONGLONG bytes, ULONG seed)
{
    BCRYPT_ALG_HANDLE alg;
    BCRYPT_HASH_HANDLE h;
    UCHAR digest[32], *buf = malloc(CHUNK);
    ULONGLONG done = 0;
    ULONG x = seed * 2654435761u + 12345, i;
    DWORD n;

    if (!buf || !BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, NULL, 0)) ||
        !BCRYPT_SUCCESS(BCryptCreateHash(alg, &h, NULL, 0, NULL, 0, 0)))
        return ERROR_NOT_ENOUGH_MEMORY;

    for (;;)
    {
        if (gen)
        {
            n = (DWORD)min(bytes - done, CHUNK);
            if (n == 0)
                break;
            for (i = 0; i < n; i++)
            {
                x ^= x << 13; x ^= x >> 17; x ^= x << 5;
                buf[i] = (UCHAR)x;
            }
            if (!WriteFile(f, buf, n, &n, NULL))
                return (int)GetLastError();
        }
        else
        {
            if (!ReadFile(f, buf, CHUNK, &n, NULL))
                return (int)GetLastError();
            if (n == 0)
                break;
        }
        BCryptHashData(h, buf, n, 0);
        done += n;
    }
    BCryptFinishHash(h, digest, sizeof(digest), 0);
    printf("%s bytes=%I64u sha256=", gen ? "GEN" : "SUM", done);
    for (i = 0; i < 32; i++)
        printf("%02x", digest[i]);
    printf("\n");
    BCryptDestroyHash(h);
    BCryptCloseAlgorithmProvider(alg, 0);
    free(buf);
    return 0;
}

static int pool(int argc, WCHAR **argv)
{
    ULONG size = 1 << 20, i, j;
    PSYSTEM_POOLTAG_INFORMATION info;
    NTSTATUS st;

    for (;;)
    {
        info = malloc(size);
        if (!info)
            return ERROR_NOT_ENOUGH_MEMORY;
        st = NtQuerySystemInformation(SystemPoolTagInformation, info, size, &size);
        if (st != STATUS_INFO_LENGTH_MISMATCH)
            break;
        free(info);
        size += 65536;
    }
    if (!NT_SUCCESS(st))
    {
        printf("POOL query failed 0x%08lx\n", st);
        return (int)RtlNtStatusToDosError(st);
    }
    for (j = 2; j < (ULONG)argc; j++)
    {
        char want[5] = { 0 };
        BOOL found = FALSE;

        WideCharToMultiByte(CP_ACP, 0, argv[j], -1, want, sizeof(want), NULL, NULL);
        for (i = 0; i < info->Count; i++)
        {
            PSYSTEM_POOLTAG t = &info->TagInfo[i];

            if (!memcmp(t->Tag, want, 4))
            {
                printf("POOL tag=%.4s paged_allocs=%lu paged_frees=%lu paged_bytes=%Iu nonpaged_allocs=%lu nonpaged_frees=%lu nonpaged_bytes=%Iu\n",
                       want, t->PagedAllocs, t->PagedFrees, t->PagedUsed, t->NonPagedAllocs, t->NonPagedFrees, t->NonPagedUsed);
                found = TRUE;
            }
        }
        if (!found)
            printf("POOL tag=%.4s none\n", want);
    }
    free(info);
    return 0;
}

static int drive(const WCHAR *d)
{
    WCHAR root[8], target[1024], label[MAX_PATH + 1], fs[MAX_PATH + 1], nt[1024];
    DWORD serial = 0, maxc = 0, flags = 0;
    UCHAR buf[2048];
    IO_STATUS_BLOCK iosb;
    FILE_FS_DEVICE_INFORMATION dev;
    POBJECT_NAME_INFORMATION name = (void *)buf;
    HANDLE h;
    ULONG len;

    _snwprintf(root, ARRAYSIZE(root), L"%c:\\", d[0]);
    root[ARRAYSIZE(root) - 1] = 0;
    printf("DRIVE type=%u\n", GetDriveTypeW(root));
    _snwprintf(nt, ARRAYSIZE(nt), L"%c:", d[0]);
    nt[ARRAYSIZE(nt) - 1] = 0;
    if (QueryDosDeviceW(nt, target, ARRAYSIZE(target)))
        printf("DRIVE dosdevice=%ls\n", target);
    else
        printf("DRIVE dosdevice failed %lu\n", GetLastError());
    if (GetVolumeInformationW(root, label, ARRAYSIZE(label), &serial, &maxc, &flags, fs, ARRAYSIZE(fs)))
        printf("DRIVE label=%ls fs=%ls flags=0x%lx maxcomponent=%lu\n", label, fs, flags, maxc);
    else
        printf("DRIVE volumeinformation failed %lu\n", GetLastError());

    h = CreateFileW(root, FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
                    OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
    if (h == INVALID_HANDLE_VALUE)
    {
        printf("DRIVE open root failed %lu\n", GetLastError());
        return (int)GetLastError();
    }
    if (NT_SUCCESS(NtQueryVolumeInformationFile(h, &iosb, &dev, sizeof(dev), FileFsDeviceInformation)))
        printf("DRIVE devicetype=0x%lx characteristics=0x%lx\n", dev.DeviceType, dev.Characteristics);
    if (NT_SUCCESS(NtQueryObject(h, ObjectNameInformation, buf, sizeof(buf) - 2, &len)))
        printf("DRIVE ntname=%.*ls\n", name->Name.Length / 2, name->Name.Buffer);
    CloseHandle(h);
    return 0;
}

/* An object name: symbolic link target, or the device type of what it opens */
static int obj(const WCHAR *path)
{
    UNICODE_STRING name, target;
    OBJECT_ATTRIBUTES oa;
    IO_STATUS_BLOCK iosb;
    FILE_FS_DEVICE_INFORMATION dev;
    WCHAR buf[512];
    HANDLE h;
    NTSTATUS st;

    RtlInitUnicodeString(&name, path);
    InitializeObjectAttributes(&oa, &name, OBJ_CASE_INSENSITIVE, NULL, NULL);
    st = NtOpenSymbolicLinkObject(&h, SYMBOLIC_LINK_QUERY, &oa);
    if (NT_SUCCESS(st))
    {
        target.Buffer = buf;
        target.Length = 0;
        target.MaximumLength = sizeof(buf) - sizeof(WCHAR);
        st = NtQuerySymbolicLinkObject(h, &target, NULL);
        NtClose(h);
        if (NT_SUCCESS(st))
            printf("OBJ %ls link=%.*ls\n", path, target.Length / 2, target.Buffer);
    }
    else
        printf("OBJ %ls notalink=0x%08lx\n", path, st);

    st = NtOpenFile(&h, FILE_READ_ATTRIBUTES | SYNCHRONIZE, &oa, &iosb, FILE_SHARE_READ | FILE_SHARE_WRITE,
                    FILE_SYNCHRONOUS_IO_NONALERT);
    if (!NT_SUCCESS(st))
    {
        printf("OBJ %ls open=0x%08lx\n", path, st);
        return 0;
    }
    if (NT_SUCCESS(NtQueryVolumeInformationFile(h, &iosb, &dev, sizeof(dev), FileFsDeviceInformation)))
        printf("OBJ %ls devicetype=0x%lx characteristics=0x%lx\n", path, dev.DeviceType, dev.Characteristics);
    NtClose(h);
    return 0;
}

int wmain(int argc, WCHAR **argv)
{
    HANDLE f;
    int rc;

    if (argc >= 4 && !wcscmp(argv[1], L"gen"))
    {
        f = CreateFileW(argv[2], GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (f == INVALID_HANDLE_VALUE)
            return (int)GetLastError();
        rc = hash_file(f, TRUE, _wcstoui64(argv[3], NULL, 10), argc > 4 ? (ULONG)_wtoi(argv[4]) : 1);
        CloseHandle(f);
        return rc;
    }
    if (argc == 3 && !wcscmp(argv[1], L"sum"))
    {
        f = CreateFileW(argv[2], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
        if (f == INVALID_HANDLE_VALUE)
        {
            printf("SUM open failed %lu\n", GetLastError());
            return (int)GetLastError();
        }
        rc = hash_file(f, FALSE, 0, 0);
        CloseHandle(f);
        return rc;
    }
    if (argc == 4 && !wcscmp(argv[1], L"cp"))
    {
        /* Buffered copy (CopyFile reads big files unbuffered) */
        HANDLE in = CreateFileW(argv[2], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
        HANDLE out;
        UCHAR *buf = malloc(CHUNK);
        DWORD n, w;
        ULONGLONG total = 0;

        if (in == INVALID_HANDLE_VALUE || !buf)
        {
            printf("CP open source failed %lu\n", GetLastError());
            return (int)GetLastError();
        }
        out = CreateFileW(argv[3], GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (out == INVALID_HANDLE_VALUE)
        {
            printf("CP open destination failed %lu\n", GetLastError());
            return (int)GetLastError();
        }
        rc = 0;
        while (ReadFile(in, buf, CHUNK, &n, NULL) && n)
        {
            if (!WriteFile(out, buf, n, &w, NULL) || w != n)
            {
                rc = (int)GetLastError();
                break;
            }
            total += n;
        }
        if (!rc && GetLastError() != ERROR_SUCCESS && GetLastError() != ERROR_HANDLE_EOF)
            rc = 0;
        CloseHandle(in);
        CloseHandle(out);
        free(buf);
        printf("CP bytes=%I64u rc=%d\n", total, rc);
        return rc;
    }
    if (argc >= 3 && !wcscmp(argv[1], L"pool"))
        return pool(argc, argv);
    if (argc == 3 && !wcscmp(argv[1], L"drive"))
        return drive(argv[2]);
    if (argc == 2 && !wcscmp(argv[1], L"uptime"))
        return (int)(GetTickCount() / 1000);    /* seconds since boot, as the exit code (for cmd loops) */
    if (argc >= 3 && !wcscmp(argv[1], L"obj"))
    {
        for (rc = 2; rc < argc; rc++)
            obj(argv[rc]);
        return 0;
    }
    printf("usage: smbtool gen FILE BYTES [SEED] | sum FILE | pool TAG... | drive X:\n");
    return ERROR_INVALID_PARAMETER;
}
