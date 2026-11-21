/*
 * PROJECT:         ReactOS kernel-mode tests
 * LICENSE:         LGPLv2+ - See COPYING.LIB in the top level directory
 * PURPOSE:         Kernel-Mode Test Suite for the unicode prefix table
 */

#include <kmt_test.h>

/* A counted string whose last character is the last byte of a page: reading
 * one WCHAR beyond it faults */
static
PWCHAR
AllocateAtPageEnd(
    _In_ PCWSTR Text,
    _Out_ PUNICODE_STRING String)
{
    SIZE_T Length = wcslen(Text) * sizeof(WCHAR);
    PWCHAR Buffer = KmtAllocateGuarded(Length);

    if (Buffer)
    {
        RtlCopyMemory(Buffer, Text, Length);
        String->Buffer = Buffer;
        String->Length = (USHORT)Length;
        String->MaximumLength = (USHORT)Length;
    }
    return Buffer;
}

START_TEST(RtlUnicodePrefix)
{
    UNICODE_PREFIX_TABLE Table;
    UNICODE_PREFIX_TABLE_ENTRY Entry1, Entry2, Entry3;
    UNICODE_STRING Prefix1, Prefix2, Prefix3, Name;
    PWCHAR Buffer1, Buffer2, Buffer3, NameBuffer;
    PUNICODE_PREFIX_TABLE_ENTRY Found;
    BOOLEAN Inserted;

    Buffer1 = AllocateAtPageEnd(L"\\Device", &Prefix1);
    Buffer2 = AllocateAtPageEnd(L"\\Device\\Mup", &Prefix2);
    Buffer3 = AllocateAtPageEnd(L"\\Dev", &Prefix3);
    if (!skip(Buffer1 && Buffer2 && Buffer3, "No memory\n"))
    {
        RtlInitializeUnicodePrefix(&Table);

        /* Each insert compares the new prefix with the ones in the table, all
         * of them ending at a page end */
        Inserted = RtlInsertUnicodePrefix(&Table, &Prefix1, &Entry1);
        ok_bool_true(Inserted, "RtlInsertUnicodePrefix returned");
        Inserted = RtlInsertUnicodePrefix(&Table, &Prefix2, &Entry2);
        ok_bool_true(Inserted, "RtlInsertUnicodePrefix returned");
        Inserted = RtlInsertUnicodePrefix(&Table, &Prefix3, &Entry3);
        ok_bool_true(Inserted, "RtlInsertUnicodePrefix returned");

        /* The same prefix twice is refused */
        Inserted = RtlInsertUnicodePrefix(&Table, &Prefix2, &Entry2);
        ok_bool_false(Inserted, "RtlInsertUnicodePrefix of a duplicate returned");

        /* Names that end at a page end, shorter than, equal to and longer
         * than the prefixes */
        NameBuffer = AllocateAtPageEnd(L"\\Device\\Mup\\server\\share", &Name);
        if (!skip(NameBuffer != NULL, "No memory\n"))
        {
            Found = RtlFindUnicodePrefix(&Table, &Name, 0);
            ok(Found == &Entry2, "Found %p, expected %p\n", Found, &Entry2);
            Found = RtlFindUnicodePrefix(&Table, &Name, 1);
            ok(Found == &Entry2, "Found %p, expected %p\n", Found, &Entry2);
            KmtFreeGuarded(NameBuffer);
        }

        NameBuffer = AllocateAtPageEnd(L"\\Device\\Mup", &Name);
        if (!skip(NameBuffer != NULL, "No memory\n"))
        {
            Found = RtlFindUnicodePrefix(&Table, &Name, 0);
            ok(Found == &Entry2, "Found %p, expected %p\n", Found, &Entry2);
            Found = RtlFindUnicodePrefix(&Table, &Name, 1);
            ok(Found == &Entry2, "Found %p, expected %p\n", Found, &Entry2);
            KmtFreeGuarded(NameBuffer);
        }

        NameBuffer = AllocateAtPageEnd(L"\\DEVICE\\mup", &Name);
        if (!skip(NameBuffer != NULL, "No memory\n"))
        {
            /* The index is where the case insensitive comparison starts: 0 is all of it,
             * the length of the name none of it */
            Found = RtlFindUnicodePrefix(&Table, &Name, 0);
            ok(Found == &Entry2, "Found %p, expected %p\n", Found, &Entry2);
            Found = RtlFindUnicodePrefix(&Table, &Name, 1);
            ok(Found == &Entry2, "Found %p, expected %p\n", Found, &Entry2);
            Found = RtlFindUnicodePrefix(&Table, &Name, Name.Length / sizeof(WCHAR));
            ok(Found == NULL, "Found %p, expected NULL\n", Found);
            KmtFreeGuarded(NameBuffer);
        }

        NameBuffer = AllocateAtPageEnd(L"\\Device", &Name);
        if (!skip(NameBuffer != NULL, "No memory\n"))
        {
            Found = RtlFindUnicodePrefix(&Table, &Name, 0);
            ok(Found == &Entry1, "Found %p, expected %p\n", Found, &Entry1);
            KmtFreeGuarded(NameBuffer);
        }

        NameBuffer = AllocateAtPageEnd(L"\\Dev", &Name);
        if (!skip(NameBuffer != NULL, "No memory\n"))
        {
            Found = RtlFindUnicodePrefix(&Table, &Name, 0);
            ok(Found == &Entry3, "Found %p, expected %p\n", Found, &Entry3);
            KmtFreeGuarded(NameBuffer);
        }

        NameBuffer = AllocateAtPageEnd(L"\\Devic", &Name);
        if (!skip(NameBuffer != NULL, "No memory\n"))
        {
            Found = RtlFindUnicodePrefix(&Table, &Name, 0);
            ok(Found == NULL, "Found %p, expected NULL\n", Found);
            KmtFreeGuarded(NameBuffer);
        }

        RtlRemoveUnicodePrefix(&Table, &Entry3);
        RtlRemoveUnicodePrefix(&Table, &Entry2);
        RtlRemoveUnicodePrefix(&Table, &Entry1);
    }

    if (Buffer1)
        KmtFreeGuarded(Buffer1);
    if (Buffer2)
        KmtFreeGuarded(Buffer2);
    if (Buffer3)
        KmtFreeGuarded(Buffer3);
}
