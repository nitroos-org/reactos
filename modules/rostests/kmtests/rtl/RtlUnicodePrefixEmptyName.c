/*
 * PROJECT:         ReactOS kernel-mode tests
 * LICENSE:         LGPLv2+ - See COPYING.LIB in the top level directory
 * PURPOSE:         Kernel-Mode Test Suite for the unicode prefix table with an empty name
 */

#include <kmt_test.h>

/* A counted string of length 0 whose buffer is the guard page: a read through it faults */
static
VOID
EmptyAtGuardPage(
    _In_ PVOID Block,
    _In_ SIZE_T BlockSize,
    _Out_ PUNICODE_STRING String)
{
    String->Buffer = (PWCHAR)((PUCHAR)Block + BlockSize);
    String->Length = 0;
    String->MaximumLength = 0;
}

START_TEST(RtlUnicodePrefixEmptyName)
{
    UNICODE_PREFIX_TABLE Table;
    UNICODE_PREFIX_TABLE_ENTRY Entry, EmptyEntry;
    UNICODE_STRING Prefix, Empty;
    PUNICODE_PREFIX_TABLE_ENTRY Found = NULL;
    PVOID Block;
    BOOLEAN Inserted;
    static const WCHAR PrefixText[] = L"\\Device";

    Block = KmtAllocateGuarded(sizeof(PrefixText));
    if (skip(Block != NULL, "No memory\n"))
        return;

    RtlCopyMemory(Block, PrefixText, sizeof(PrefixText));
    Prefix.Buffer = Block;
    Prefix.Length = sizeof(PrefixText) - sizeof(WCHAR);
    Prefix.MaximumLength = sizeof(PrefixText);
    EmptyAtGuardPage(Block, sizeof(PrefixText), &Empty);

    RtlInitializeUnicodePrefix(&Table);
    Inserted = RtlInsertUnicodePrefix(&Table, &Prefix, &Entry);
    ok_bool_true(Inserted, "RtlInsertUnicodePrefix returned");

    /* The number of names of an empty name is not computed from the memory behind it */
    KmtStartSeh()
        Found = RtlFindUnicodePrefix(&Table, &Empty, FALSE);
    KmtEndSeh(STATUS_SUCCESS)
    ok(Found == NULL, "Found %p for an empty name\n", Found);

    KmtStartSeh()
        Found = RtlFindUnicodePrefix(&Table, &Empty, TRUE);
    KmtEndSeh(STATUS_SUCCESS)
    ok(Found == NULL, "Found %p for an empty name, case insensitive\n", Found);

    /* An empty prefix can be inserted (and is then the first name) without reading beyond it */
    KmtStartSeh()
        Inserted = RtlInsertUnicodePrefix(&Table, &Empty, &EmptyEntry);
    KmtEndSeh(STATUS_SUCCESS)
    ok_bool_true(Inserted, "RtlInsertUnicodePrefix of an empty prefix returned");
    ok_eq_int(EmptyEntry.NameLength, 1);

    /* The table still works */
    Found = RtlFindUnicodePrefix(&Table, &Prefix, FALSE);
    ok(Found == &Entry, "Found %p, expected %p\n", Found, &Entry);

    KmtFreeGuarded(Block);
}
