/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Tests for RtlCrc64 of ntdll
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Every expected value was measured on Windows 10 22H2 (19045), x64 and x86 (WOW64): the function is the
 * CRC-64/NVME (reflected, polynomial 0xAD93D23594C93659, register started as the complement of the initial CRC,
 * result complemented), so that "123456789" gives 0xAE8B14860A799888 and an empty buffer returns the initial CRC.
 */

#include "precomp.h"

typedef ULONGLONG (NTAPI *PFN_Crc64)(const void *, SIZE_T, ULONGLONG);

static void Check(PFN_Crc64 Crc64, const void *Buffer, SIZE_T Size, ULONGLONG Initial, ULONGLONG Expected, const char *What)
{
    ULONGLONG Got = Crc64(Buffer, Size, Initial);

    ok(Got == Expected, "%s: initial %016I64x: expected %016I64x, got %016I64x\n", What, Initial, Expected, Got);
}

START_TEST(RtlCrc64)
{
    PFN_Crc64 Crc64 = (PFN_Crc64)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlCrc64");
    UCHAR Buffer[1024], Unaligned[16], Byte;
    ULONGLONG Crc;
    ULONG i;

    if (!Crc64)
    {
        ok(!is_reactos(), "RtlCrc64 is not exported by ntdll.dll\n");
        skip("RtlCrc64 is not exported\n");
        return;
    }

    /* an empty buffer is the initial value */
    Check(Crc64, "", 0, 0, 0, "empty");
    Check(Crc64, "", 0, 1, 1, "empty");
    Check(Crc64, "", 0, 0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL, "empty");
    Check(Crc64, "", 0, 0x123456789ABCDEF0ULL, 0x123456789ABCDEF0ULL, "empty");

    /* the check string, from several initial values */
    Check(Crc64, "123456789", 9, 0, 0xAE8B14860A799888ULL, "123456789");
    Check(Crc64, "123456789", 9, 1, 0xAA799969593EE0E4ULL, "123456789");
    Check(Crc64, "123456789", 9, 0xFFFFFFFFFFFFFFFFULL, 0x87FF3F9B2B57C87BULL, "123456789");
    Check(Crc64, "123456789", 9, 0x123456789ABCDEF0ULL, 0xF91ED82CEA6E1267ULL, "123456789");
    Check(Crc64, "123456789", 9, 0x8000000000000000ULL, 0x0B50FFCBBE289581ULL, "123456789");
    Check(Crc64, "123456789", 9, 0x00000000FFFFFFFFULL, 0xBFCE6371B8CB7BA6ULL, "123456789");

    /* single bytes (the table of the algorithm), from 0 and from all ones */
    Byte = 0x00; Check(Crc64, &Byte, 1, 0, 0xD5DA5047EFEC8728ULL, "byte 00");
    Byte = 0x01; Check(Crc64, &Byte, 1, 0, 0xAAB4A08FDFD90E51ULL, "byte 01");
    Byte = 0x7F; Check(Crc64, &Byte, 1, 0, 0x656C9329AC4BC9B5ULL, "byte 7f");
    Byte = 0x80; Check(Crc64, &Byte, 1, 0, 0x4FB6C36E43A74E9DULL, "byte 80");
    Byte = 0xFF; Check(Crc64, &Byte, 1, 0, 0xFF00000000000000ULL, "byte ff");
    Byte = 0x00; Check(Crc64, &Byte, 1, ~0ULL, 0xFFFFFFFFFFFFFFFFULL, "byte 00");
    Byte = 0x01; Check(Crc64, &Byte, 1, ~0ULL, 0x80910F37CFCA7686ULL, "byte 01");
    Byte = 0x7F; Check(Crc64, &Byte, 1, ~0ULL, 0x4F493C91BC58B162ULL, "byte 7f");
    Byte = 0x80; Check(Crc64, &Byte, 1, ~0ULL, 0x65936CD653B4364AULL, "byte 80");
    Byte = 0xFF; Check(Crc64, &Byte, 1, ~0ULL, 0xD525AFB8101378D7ULL, "byte ff");

    /* zero bytes from 0 move the CRC, from all ones they do not */
    RtlFillMemory(Buffer, 4, 0);
    Check(Crc64, Buffer, 2, 0, 0x82D298D4D16B4AD8ULL, "2 zeroes");
    Check(Crc64, Buffer, 3, 0, 0x4692D8C40DB2994CULL, "3 zeroes");
    Check(Crc64, Buffer, 4, 0, 0x6DB811E5A1DA5024ULL, "4 zeroes");
    for (i = 1; i <= 4; i++)
        Check(Crc64, Buffer, i, ~0ULL, 0xFFFFFFFFFFFFFFFFULL, "zeroes from all ones");

    /* a long buffer (byte i is i * 7 + 3), also in two parts: the result continues a CRC */
    for (i = 0; i < 1024; i++)
        Buffer[i] = (UCHAR)(i * 7 + 3);
    Check(Crc64, Buffer, 1024, 0, 0x94401118876A3109ULL, "1024 bytes");
    Check(Crc64, Buffer, 1024, ~0ULL, 0x02A45C57E370877CULL, "1024 bytes");
    Check(Crc64, Buffer, 1023, 0, 0xED7C463A5D27BEA3ULL, "1023 bytes");
    Crc = Crc64(Buffer, 100, 0);
    Check(Crc64, Buffer + 100, 924, Crc, 0x94401118876A3109ULL, "in two parts");

    /* the alignment of the buffer does not matter */
    for (i = 0; i < 4; i++)
    {
        RtlCopyMemory(Unaligned + i, "123456789", 9);
        Check(Crc64, Unaligned + i, 9, 0, 0xAE8B14860A799888ULL, "unaligned");
    }
}
