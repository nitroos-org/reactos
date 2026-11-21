/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     FileNormalizedNameInformation (class 48) reaches every file system: it answers without
 *              harm, a short buffer is not written beyond, a success gives the path of the file
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * "ntdll_apitest NtQueryInformationFileNormalizedName <path>..." also runs on the files and directories
 * named (a CD-ROM, an UDF, ext2 or btrfs volume of the system under test). Without a path the Windows
 * directory and a file in it are used.
 */

#include "precomp.h"

#define PATTERN 0x55
#define CLASS_NORMALIZED_NAME 48
#define BUFFER_SIZE 1024

static
VOID
CheckPath(
    PCWSTR Path)
{
    static UCHAR Buffer[BUFFER_SIZE + 16];
    UNICODE_STRING NtPath;
    OBJECT_ATTRIBUTES Attributes;
    IO_STATUS_BLOCK Iosb;
    HANDLE Handle;
    NTSTATUS Status;
    ULONG Length, Tail;
    PFILE_NAME_INFORMATION Name = (PFILE_NAME_INFORMATION)Buffer;

    if (!RtlDosPathNameToNtPathName_U(Path, &NtPath, NULL, NULL))
    {
        skip("%ls: no NT path\n", Path);
        return;
    }
    InitializeObjectAttributes(&Attributes, &NtPath, OBJ_CASE_INSENSITIVE, NULL, NULL);
    Status = NtOpenFile(&Handle, FILE_READ_ATTRIBUTES | SYNCHRONIZE, &Attributes, &Iosb,
                        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_SYNCHRONOUS_IO_NONALERT);
    RtlFreeUnicodeString(&NtPath);
    if (!NT_SUCCESS(Status))
    {
        skip("%ls: cannot be opened: 0x%lx\n", Path, Status);
        return;
    }

    /* every buffer length from 0 up: nothing is written beyond the length, whatever the answer is */
    for (Length = 0; Length <= 40; Length++)
    {
        RtlFillMemory(Buffer, sizeof(Buffer), PATTERN);
        RtlFillMemory(&Iosb, sizeof(Iosb), PATTERN);
        Status = NtQueryInformationFile(Handle, &Iosb, Buffer, Length, CLASS_NORMALIZED_NAME);
        for (Tail = Length; Tail < sizeof(Buffer); Tail++)
        {
            if (Buffer[Tail] != PATTERN)
                break;
        }
        ok(Tail == sizeof(Buffer), "%ls: length %lu: status 0x%lx wrote beyond the buffer at %lu\n",
           Path, Length, Status, Tail);
        if (Tail != sizeof(Buffer))
            break;
    }

    /* a buffer that is large enough */
    RtlFillMemory(Buffer, sizeof(Buffer), PATTERN);
    RtlFillMemory(&Iosb, sizeof(Iosb), PATTERN);
    Status = NtQueryInformationFile(Handle, &Iosb, Buffer, BUFFER_SIZE, CLASS_NORMALIZED_NAME);
    for (Tail = BUFFER_SIZE; Tail < sizeof(Buffer); Tail++)
    {
        if (Buffer[Tail] != PATTERN)
            break;
    }
    ok(Tail == sizeof(Buffer), "%ls: status 0x%lx wrote beyond the buffer\n", Path, Status);
    if (NT_SUCCESS(Status))
    {
        ok(Name->FileNameLength % sizeof(WCHAR) == 0 &&
           FIELD_OFFSET(FILE_NAME_INFORMATION, FileName) + Name->FileNameLength <= BUFFER_SIZE,
           "%ls: name length %lu\n", Path, Name->FileNameLength);
        ok(Iosb.Information == FIELD_OFFSET(FILE_NAME_INFORMATION, FileName) + Name->FileNameLength,
           "%ls: Information %Iu, name length %lu\n", Path, Iosb.Information, Name->FileNameLength);
        ok(Name->FileNameLength == 0 || Name->FileName[0] == L'\\', "%ls: the name does not start at the root\n", Path);
    }
    else
    {
        /* a file system that does not know the class says so */
        ok(Status == STATUS_INVALID_PARAMETER || Status == STATUS_INVALID_INFO_CLASS ||
           Status == STATUS_NOT_IMPLEMENTED || Status == STATUS_NOT_SUPPORTED ||
           Status == STATUS_INVALID_DEVICE_REQUEST,
           "%ls: unexpected status 0x%lx\n", Path, Status);
        trace("%ls: class 48 answers 0x%lx\n", Path, Status);
    }
    NtClose(Handle);
}

START_TEST(NtQueryInformationFileNormalizedName)
{
    WCHAR Dir[MAX_PATH], File[MAX_PATH];
    char **Argv;
    int Argc = winetest_get_mainargs(&Argv), i;

    if (Argc > 2)
    {
        for (i = 2; i < Argc; i++)
        {
            WCHAR Path[MAX_PATH];

            RtlMultiByteToUnicodeN(Path, sizeof(Path) - sizeof(WCHAR), NULL, Argv[i], (ULONG)strlen(Argv[i]) + 1);
            Path[ARRAYSIZE(Path) - 1] = UNICODE_NULL;
            CheckPath(Path);
        }
        return;
    }

    wcscpy(Dir, SharedUserData->NtSystemRoot);
    CheckPath(Dir);
    wcscpy(File, Dir);
    wcscat(File, L"\\system32\\ntdll.dll");
    CheckPath(File);
}
