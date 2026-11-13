/*
 * PROJECT:     ReactOS api tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Test many open keys that have the same name under different parents
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"

/*
 * The kernel keeps one name block for every key name in use, shared by all
 * open keys with that name, whatever their parent or hive. This test holds
 * more than 65536 keys of one name open at the same time (each under its
 * own parent, so every one is a different key), then deletes and closes
 * them all. A name block reference count that wraps at 16 bits frees the
 * block while keys still use it, and the closes after that work on freed
 * memory (kernel crash or pool corruption). Every operation must succeed.
 */

#define TEST_ROOT L"Software\\ReactOS RegSharedKeyName"
#define CHILD_NAME L"RegSharedKeyNameChild"
#define GROUPS 260
#define PARENTS_PER_GROUP 256
#define CHILDREN (GROUPS * PARENTS_PER_GROUP)

C_ASSERT(CHILDREN > 0x10000);

static
LONG
CreateVolatileKey(
    _In_ HKEY Parent,
    _In_ PCWSTR Name,
    _Out_ PHKEY Key)
{
    return RegCreateKeyExW(Parent, Name, 0, NULL, REG_OPTION_VOLATILE,
                           KEY_ALL_ACCESS, NULL, Key, NULL);
}

/* Delete the test tree (whatever exists of it); returns the number of failed deletes of existing keys */
static
ULONG
DeleteTestTree(VOID)
{
    HKEY Root;
    WCHAR Name[64];
    ULONG g, p, Failures = 0;
    LONG Error;

    if (RegOpenKeyExW(HKEY_CURRENT_USER, TEST_ROOT, 0, KEY_ALL_ACCESS, &Root) != ERROR_SUCCESS)
        return 0;

    RegDeleteKeyW(Root, CHILD_NAME);
    for (g = 0; g < GROUPS; g++)
    {
        for (p = 0; p < PARENTS_PER_GROUP; p++)
        {
            StringCchPrintfW(Name, _countof(Name), L"G%03lu\\P%03lu\\%ls", g, p, CHILD_NAME);
            Error = RegDeleteKeyW(Root, Name);
            if ((Error != ERROR_SUCCESS) && (Error != ERROR_FILE_NOT_FOUND)) Failures++;
            StringCchPrintfW(Name, _countof(Name), L"G%03lu\\P%03lu", g, p);
            Error = RegDeleteKeyW(Root, Name);
            if ((Error != ERROR_SUCCESS) && (Error != ERROR_FILE_NOT_FOUND)) Failures++;
        }
        StringCchPrintfW(Name, _countof(Name), L"G%03lu", g);
        Error = RegDeleteKeyW(Root, Name);
        if ((Error != ERROR_SUCCESS) && (Error != ERROR_FILE_NOT_FOUND)) Failures++;
    }
    RegCloseKey(Root);
    Error = RegDeleteKeyW(HKEY_CURRENT_USER, TEST_ROOT);
    if (Error != ERROR_SUCCESS) Failures++;
    return Failures;
}

START_TEST(RegSharedKeyName)
{
    HKEY Root, Group, Parent, Extra;
    HKEY *Children;
    WCHAR Name[32];
    ULONG g, p, Created = 0, Deleted = 0, Closed = 0;
    LONG Error, FirstError = ERROR_SUCCESS;
    DWORD SubKeys;

    /* Start from nothing (left over by an interrupted run) */
    DeleteTestTree();

    Error = CreateVolatileKey(HKEY_CURRENT_USER, TEST_ROOT, &Root);
    ok(Error == ERROR_SUCCESS, "Creating the test root failed: %ld\n", Error);
    if (Error != ERROR_SUCCESS)
        return;

    Children = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, CHILDREN * sizeof(HKEY));
    ok(Children != NULL, "Out of memory\n");
    if (!Children)
    {
        RegCloseKey(Root);
        RegDeleteKeyW(HKEY_CURRENT_USER, TEST_ROOT);
        return;
    }

    /*
     * Root\Gnnn\Pnnn\CHILD_NAME, children held open. Two levels of parents
     * keep every parent below the per-key reference limit: the only count
     * that goes past 65536 is the one of the shared name.
     */
    for (g = 0; g < GROUPS; g++)
    {
        StringCchPrintfW(Name, _countof(Name), L"G%03lu", g);
        Error = CreateVolatileKey(Root, Name, &Group);
        if (Error != ERROR_SUCCESS)
        {
            if (FirstError == ERROR_SUCCESS) FirstError = Error;
            break;
        }

        for (p = 0; p < PARENTS_PER_GROUP; p++)
        {
            StringCchPrintfW(Name, _countof(Name), L"P%03lu", p);
            Error = CreateVolatileKey(Group, Name, &Parent);
            if (Error != ERROR_SUCCESS)
            {
                if (FirstError == ERROR_SUCCESS) FirstError = Error;
                break;
            }

            Error = CreateVolatileKey(Parent, CHILD_NAME, &Children[Created]);
            RegCloseKey(Parent);
            if (Error != ERROR_SUCCESS)
            {
                if (FirstError == ERROR_SUCCESS) FirstError = Error;
                break;
            }
            Created++;
        }

        RegCloseKey(Group);
        if (p != PARENTS_PER_GROUP)
            break;
    }

    ok(Created == CHILDREN, "Created %lu of %lu keys of one name, first error %ld\n",
       Created, (ULONG)CHILDREN, FirstError);

    /* One more key of that name while all the others are open */
    Error = CreateVolatileKey(Root, CHILD_NAME, &Extra);
    ok(Error == ERROR_SUCCESS, "Creating one more key of the name failed: %ld\n", Error);
    if (Error == ERROR_SUCCESS)
    {
        Error = RegQueryInfoKeyW(Extra, NULL, NULL, NULL, &SubKeys, NULL, NULL,
                                 NULL, NULL, NULL, NULL, NULL);
        ok(Error == ERROR_SUCCESS, "RegQueryInfoKeyW failed: %ld\n", Error);
        RegCloseKey(Extra);
        Error = RegDeleteKeyW(Root, CHILD_NAME);
        ok(Error == ERROR_SUCCESS, "Deleting the extra key failed: %ld\n", Error);
    }

    /* Delete every child through its parent while it is still open, then close it */
    FirstError = ERROR_SUCCESS;
    for (g = 0; g * PARENTS_PER_GROUP < Created; g++)
    {
        for (p = 0; (p < PARENTS_PER_GROUP) && (g * PARENTS_PER_GROUP + p < Created); p++)
        {
            StringCchPrintfW(Name, _countof(Name), L"G%03lu\\P%03lu", g, p);
            Error = RegOpenKeyExW(Root, Name, 0, KEY_ALL_ACCESS, &Parent);
            if (Error == ERROR_SUCCESS)
            {
                Error = RegDeleteKeyW(Parent, CHILD_NAME);
                RegCloseKey(Parent);
            }
            if (Error == ERROR_SUCCESS)
                Deleted++;
            else if (FirstError == ERROR_SUCCESS)
                FirstError = Error;

            if (RegCloseKey(Children[g * PARENTS_PER_GROUP + p]) == ERROR_SUCCESS)
                Closed++;
        }
    }
    ok(Deleted == Created, "Deleted %lu of %lu keys, first error %ld\n", Deleted, Created, FirstError);
    ok(Closed == Created, "Closed %lu of %lu keys\n", Closed, Created);

    /* The kernel drops its last references to closed keys a few seconds later */
    Sleep(15000);

    /* The name must still work: create, open and delete a key with it */
    Error = CreateVolatileKey(Root, CHILD_NAME, &Extra);
    ok(Error == ERROR_SUCCESS, "Creating the name after the closes failed: %ld\n", Error);
    if (Error == ERROR_SUCCESS)
    {
        RegCloseKey(Extra);
        Error = RegOpenKeyExW(Root, CHILD_NAME, 0, KEY_READ, &Extra);
        ok(Error == ERROR_SUCCESS, "Opening the name after the closes failed: %ld\n", Error);
        if (Error == ERROR_SUCCESS)
            RegCloseKey(Extra);
        Error = RegDeleteKeyW(Root, CHILD_NAME);
        ok(Error == ERROR_SUCCESS, "Deleting the name after the closes failed: %ld\n", Error);
    }

    HeapFree(GetProcessHeap(), 0, Children);
    RegCloseKey(Root);
    g = DeleteTestTree();
    ok(g == 0, "Deleting the test tree failed for %lu keys\n", g);
}
