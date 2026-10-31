/*
 * PROJECT:     ReactOS NT User Mode Library
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     RtlUTF8ToUnicodeN as the ntdll of Windows 7 and later answers it
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include <ntdll.h>

#define NDEBUG
#include <debug.h>

/*
 * The decoder follows Wine's ntdll (dlls/ntdll/locale_private.h), Copyright 2000 Alexandre Julliard and others,
 * LGPL-2.1+: it takes the bytes of a sequence one by one, so that a sequence that stops early costs one
 * replacement character and the next character is read from where the sequence stopped. This is what the
 * tests of Wine's rtlstr measure on Windows 10 for every kind of invalid input.
 */
static
ULONG
DecodeUtf8Char(
    _In_ UCHAR Lead,
    _Inout_ const CHAR **Source,
    _In_ const CHAR *SourceEnd)
{
    /* the number of bytes that follow, by lead byte value from 0x80 on */
    static const CHAR Utf8Length[128] =
    {
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, /* 0x80-0x8f */
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, /* 0x90-0x9f */
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, /* 0xa0-0xaf */
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, /* 0xb0-0xbf */
        0,0,1,1,1,1,1,1,1,1,1,1,1,1,1,1, /* 0xc0-0xcf */
        1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1, /* 0xd0-0xdf */
        2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2, /* 0xe0-0xef */
        3,3,3,3,3,0,0,0,0,0,0,0,0,0,0,0  /* 0xf0-0xff */
    };
    static const UCHAR Utf8Mask[4] = { 0x7f, 0x1f, 0x0f, 0x07 };

    ULONG Length = Utf8Length[Lead - 0x80];
    ULONG Result = Lead & Utf8Mask[Length];
    const CHAR *End = *Source + Length;

    /* a sequence that the end of the string cuts short takes the continuation bytes that are there, and no others (measured) */
    if (End > SourceEnd)
    {
        while (*Source < SourceEnd && ((UCHAR)**Source ^ 0x80) < 0x40)
            (*Source)++;
        return ~0;
    }

    switch (Length)
    {
        case 3:
            if ((Lead = End[-3] ^ 0x80) >= 0x40) break;
            Result = (Result << 6) | Lead;
            (*Source)++;
            if (Result < 0x10) break;
            /* fall through */
        case 2:
            if ((Lead = End[-2] ^ 0x80) >= 0x40) break;
            Result = (Result << 6) | Lead;
            if (Result >= 0x110000 >> 6) break;
            (*Source)++;
            if (Result < 0x20) break;
            if (Result >= 0xd800 >> 6 && Result <= 0xdfff >> 6) break;
            /* fall through */
        case 1:
            if ((Lead = End[-1] ^ 0x80) >= 0x40) break;
            Result = (Result << 6) | Lead;
            (*Source)++;
            if (Result < 0x80) break;
            return Result;
    }
    return ~0;
}

static
NTSTATUS
Utf8ToWideSize(
    _In_ const CHAR *Source,
    _In_ ULONG SourceLength,
    _Out_ PULONG Length)
{
    NTSTATUS Status = STATUS_SUCCESS;
    const CHAR *SourceEnd = Source + SourceLength;
    ULONG Result, Count;

    for (Count = 0; Source < SourceEnd; Count++)
    {
        UCHAR Lead = (UCHAR)*Source++;

        if (Lead < 0x80)
            continue;
        if ((Result = DecodeUtf8Char(Lead, &Source, SourceEnd)) > 0x10ffff)
            Status = STATUS_SOME_NOT_MAPPED;
        else if (Result > 0xffff)
            Count++;
    }

    *Length = Count;
    return Status;
}

static
NTSTATUS
Utf8ToWide(
    _Out_writes_(DestinationLength) WCHAR *Destination,
    _In_ ULONG DestinationLength,
    _Out_ PULONG Length,
    _In_ const CHAR *Source,
    _In_ ULONG SourceLength)
{
    NTSTATUS Status = STATUS_SUCCESS;
    const CHAR *SourceEnd = Source + SourceLength;
    WCHAR *DestinationEnd = Destination + DestinationLength;
    ULONG Result;

    while (Destination < DestinationEnd && Source < SourceEnd)
    {
        UCHAR Lead = (UCHAR)*Source++;

        if (Lead < 0x80)
        {
            *Destination++ = Lead;
            continue;
        }

        if ((Result = DecodeUtf8Char(Lead, &Source, SourceEnd)) <= 0xffff)
        {
            *Destination++ = (WCHAR)Result;
        }
        else if (Result <= 0x10ffff)
        {
            /* a surrogate pair */
            Result -= 0x10000;
            *Destination++ = 0xd800 | (Result >> 10);
            if (Destination == DestinationEnd)
            {
                Status = STATUS_BUFFER_TOO_SMALL;
                break;
            }
            *Destination++ = 0xdc00 | (Result & 0x3ff);
        }
        else
        {
            *Destination++ = 0xfffd;
            Status = STATUS_SOME_NOT_MAPPED;
        }
    }

    if (Source < SourceEnd)
        Status = STATUS_BUFFER_TOO_SMALL;

    *Length = DestinationLength - (ULONG)(DestinationEnd - Destination);
    return Status;
}

/******************************************************************************
 * RtlUTF8ToUnicodeN [NTDLL.@]
 *
 * The ntdll export of Windows 7 and later. The function of the same name in the shared runtime library (the
 * ntdll_vista export, the kernel and the callers inside ntdll) keeps its older answers for invalid input.
 */
NTSTATUS NTAPI RtlpUTF8ToUnicodeNWindows(WCHAR *uni_dest, ULONG uni_bytes_max,
                                 ULONG *uni_bytes_written,
                                 const CHAR *utf8_src, ULONG utf8_bytes)
{
    NTSTATUS Status;
    ULONG Count;

    if (!utf8_src)
        return STATUS_INVALID_PARAMETER_4;
    if (!uni_bytes_written)
        return STATUS_INVALID_PARAMETER;

    if (!uni_dest)
        Status = Utf8ToWideSize(utf8_src, utf8_bytes, &Count);
    else
        Status = Utf8ToWide(uni_dest, uni_bytes_max / sizeof(WCHAR), &Count, utf8_src, utf8_bytes);

    *uni_bytes_written = Count * sizeof(WCHAR);
    return Status;
}

NTSTATUS NTAPI RtlUnicodeToUTF8N(CHAR *utf8_dest, ULONG utf8_bytes_max, ULONG *utf8_bytes_written,
                                 const WCHAR *uni_src, ULONG uni_bytes);

/******************************************************************************
 * UTF-8 strings: the STRING structure holding UTF-8, converted to and from UNICODE_STRING
 *
 * The answers (statuses, what is left in the structures after a failure) are measured on Windows 10 22H2.
 */

/*
 * The result is the Windows 10 behaviour for a UNICODE_STRING that holds at most 0xFFFF bytes: the converted
 * string and its terminator have to fit.
 */
NTSTATUS
NTAPI
RtlUTF8StringToUnicodeString(
    _Inout_ PUNICODE_STRING DestinationString,
    _In_ PSTRING SourceString,
    _In_ BOOLEAN AllocateDestinationString)
{
    NTSTATUS Status;
    ULONG Needed;
    PWCHAR Buffer;

    Status = RtlpUTF8ToUnicodeNWindows(NULL, 0, &Needed, SourceString->Buffer, SourceString->Length);
    if (!NT_SUCCESS(Status) && Status != STATUS_SOME_NOT_MAPPED)
        return Status;

    if (Needed + sizeof(WCHAR) > MAXUSHORT)
        return STATUS_INVALID_PARAMETER_2;

    if (AllocateDestinationString)
    {
        Buffer = RtlAllocateHeap(RtlGetProcessHeap(), 0, Needed + sizeof(WCHAR));
        if (!Buffer)
            return STATUS_NO_MEMORY;
        DestinationString->Buffer = Buffer;
        DestinationString->MaximumLength = (USHORT)(Needed + sizeof(WCHAR));
    }
    else
    {
        if (DestinationString->MaximumLength < Needed + sizeof(WCHAR))
        {
            DestinationString->Length = (USHORT)Needed;
            return STATUS_BUFFER_OVERFLOW;
        }
        Buffer = DestinationString->Buffer;
    }

    RtlpUTF8ToUnicodeNWindows(Buffer, Needed, &Needed, SourceString->Buffer, SourceString->Length);
    Buffer[Needed / sizeof(WCHAR)] = UNICODE_NULL;
    DestinationString->Length = (USHORT)Needed;
    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
RtlUnicodeStringToUTF8String(
    _Inout_ PSTRING DestinationString,
    _In_ PCUNICODE_STRING SourceString,
    _In_ BOOLEAN AllocateDestinationString)
{
    NTSTATUS Status;
    ULONG Needed, Written;
    PCHAR Buffer;

    Status = RtlUnicodeToUTF8N(NULL, 0, &Needed, SourceString->Buffer, SourceString->Length);
    if (!NT_SUCCESS(Status))
        return Status;

    if (Needed + sizeof(CHAR) > MAXUSHORT)
        return STATUS_INVALID_PARAMETER_2;

    if (AllocateDestinationString)
    {
        Buffer = RtlAllocateHeap(RtlGetProcessHeap(), 0, Needed + sizeof(CHAR));
        if (!Buffer)
            return STATUS_NO_MEMORY;
        DestinationString->Buffer = Buffer;
        DestinationString->MaximumLength = (USHORT)(Needed + sizeof(CHAR));
    }
    else
    {
        if (DestinationString->MaximumLength == 0)
        {
            DestinationString->Length = (USHORT)Needed;
            return STATUS_BUFFER_OVERFLOW;
        }
        Buffer = DestinationString->Buffer;
    }

    /* A buffer that is too small takes the part of the string that fits and is not terminated */
    Status = RtlUnicodeToUTF8N(Buffer,
                               DestinationString->MaximumLength - sizeof(CHAR),
                               &Written,
                               SourceString->Buffer,
                               SourceString->Length);
    DestinationString->Length = (USHORT)Written;
    if (!NT_SUCCESS(Status))
        return Status;

    Buffer[Written] = ANSI_NULL;
    return STATUS_SUCCESS;
}

VOID
NTAPI
RtlFreeUTF8String(
    _Inout_ PSTRING UTF8String)
{
    if (UTF8String->Buffer)
    {
        RtlFreeHeap(RtlGetProcessHeap(), 0, UTF8String->Buffer);
        UTF8String->Buffer = NULL;
        UTF8String->Length = 0;
        UTF8String->MaximumLength = 0;
    }
}
