/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     LsaRemoveAccountRights: an account that is not there, the last right, all rights, rights not held
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Every row is a measurement on Windows Server 2022 (build 20348), with a scratch SID that no account has.
 * Removing a right of an account that is not there faulted in lsass; removing a privilege that is not the last
 * one of the account moved the entries by a wrong count; an account without a right stayed in the database.
 */

#include "precomp.h"
#include <ntsecapi.h>
#include <sddl.h>

static LSA_HANDLE Policy;

static void Init(LSA_UNICODE_STRING *String, PCWSTR Text)
{
    String->Buffer = (PWSTR)Text;
    String->Length = (USHORT)(wcslen(Text) * sizeof(WCHAR));
    String->MaximumLength = String->Length + sizeof(WCHAR);
}

static NTSTATUS Add(PSID Sid, PCWSTR *Names, ULONG Count)
{
    LSA_UNICODE_STRING Strings[4];
    ULONG i;

    for (i = 0; i < Count; i++)
        Init(&Strings[i], Names[i]);
    return LsaAddAccountRights(Policy, Sid, Strings, Count);
}

static NTSTATUS Remove(PSID Sid, BOOLEAN All, PCWSTR *Names, ULONG Count)
{
    LSA_UNICODE_STRING Strings[4];
    ULONG i;

    for (i = 0; i < Count; i++)
        Init(&Strings[i], Names[i]);
    return LsaRemoveAccountRights(Policy, Sid, All, Count ? Strings : NULL, Count);
}

/* the rights of the account, as the names in order, or the status when it has none */
static NTSTATUS Rights(PSID Sid, WCHAR *Text, ULONG Size)
{
    PLSA_UNICODE_STRING List = NULL;
    ULONG Count = 0, i;
    NTSTATUS Status = LsaEnumerateAccountRights(Policy, Sid, &List, &Count);

    Text[0] = 0;
    if (NT_SUCCESS(Status))
    {
        for (i = 0; i < Count; i++)
        {
            if (i)
                wcscat(Text, L" ");
            wcsncat(Text, List[i].Buffer, List[i].Length / sizeof(WCHAR));
        }
    }
    if (List)
        LsaFreeMemory(List);
    return Status;
}

#define CHECK_REMOVE(Sid, All, Names, Count, Expected) \
    do { NTSTATUS s_ = Remove(Sid, All, Names, Count); \
         ok(s_ == (Expected), "line %d: remove: 0x%08lx, expected 0x%08lx\n", __LINE__, (ULONG)s_, (ULONG)(Expected)); } while (0)

#define CHECK_RIGHTS(Sid, Status_, Expected) \
    do { WCHAR t_[256]; NTSTATUS s_ = Rights(Sid, t_, 256); \
         ok(s_ == (Status_), "line %d: enumerate: 0x%08lx, expected 0x%08lx\n", __LINE__, (ULONG)s_, (ULONG)(Status_)); \
         if (NT_SUCCESS(s_)) ok(!wcscmp(t_, Expected), "line %d: rights '%ls', expected '%ls'\n", __LINE__, t_, Expected); } while (0)

START_TEST(LsaRemoveAccountRights)
{
    LSA_OBJECT_ATTRIBUTES Attributes = { sizeof(Attributes) };
    PSID Sid = NULL;
    NTSTATUS Status;
    PCWSTR Batch[] = { L"SeBatchLogonRight" };
    PCWSTR Both[] = { L"SeBatchLogonRight", L"SeDenyBatchLogonRight" };
    PCWSTR Priv1[] = { L"SeShutdownPrivilege" };
    PCWSTR Priv3[] = { L"SeShutdownPrivilege", L"SeBackupPrivilege", L"SeRestorePrivilege" };
    PCWSTR Bad[] = { L"SeNoSuchRight" };

    Status = LsaOpenPolicy(NULL, &Attributes, POLICY_ALL_ACCESS, &Policy);
    if (!NT_SUCCESS(Status))
    {
        skip("LsaOpenPolicy: 0x%08lx\n", (ULONG)Status);
        return;
    }
    ConvertStringSidToSidW(L"S-1-5-21-1111111111-2222222222-3333333333-4242", &Sid);

    /* an account that is not there */
    CHECK_RIGHTS(Sid, STATUS_OBJECT_NAME_NOT_FOUND, L"");
    CHECK_REMOVE(Sid, FALSE, Batch, 1, STATUS_OBJECT_NAME_NOT_FOUND);
    CHECK_REMOVE(Sid, TRUE, NULL, 0, STATUS_OBJECT_NAME_NOT_FOUND);

    /* the last right takes the account with it */
    ok(Add(Sid, Batch, 1) == STATUS_SUCCESS, "add\n");
    CHECK_RIGHTS(Sid, STATUS_SUCCESS, L"SeBatchLogonRight");
    CHECK_REMOVE(Sid, FALSE, Batch, 1, STATUS_SUCCESS);
    CHECK_RIGHTS(Sid, STATUS_OBJECT_NAME_NOT_FOUND, L"");
    CHECK_REMOVE(Sid, FALSE, Batch, 1, STATUS_OBJECT_NAME_NOT_FOUND);

    /* a right the account does not hold changes nothing; a name that is no right is an error */
    ok(Add(Sid, Both, 2) == STATUS_SUCCESS, "add\n");
    CHECK_REMOVE(Sid, FALSE, Priv1, 1, STATUS_SUCCESS);
    CHECK_RIGHTS(Sid, STATUS_SUCCESS, L"SeBatchLogonRight SeDenyBatchLogonRight");
    CHECK_REMOVE(Sid, FALSE, Bad, 1, STATUS_NO_SUCH_PRIVILEGE);
    CHECK_RIGHTS(Sid, STATUS_SUCCESS, L"SeBatchLogonRight SeDenyBatchLogonRight");

    /* all rights: the list is not looked at */
    CHECK_REMOVE(Sid, TRUE, Batch, 1, STATUS_SUCCESS);
    CHECK_RIGHTS(Sid, STATUS_OBJECT_NAME_NOT_FOUND, L"");
    ok(Add(Sid, Both, 2) == STATUS_SUCCESS, "add\n");
    CHECK_REMOVE(Sid, TRUE, NULL, 0, STATUS_SUCCESS);
    CHECK_RIGHTS(Sid, STATUS_OBJECT_NAME_NOT_FOUND, L"");

    /* privileges and rights together; one after the other */
    ok(Add(Sid, Priv1, 1) == STATUS_SUCCESS, "add\n");
    ok(Add(Sid, Batch, 1) == STATUS_SUCCESS, "add\n");
    CHECK_RIGHTS(Sid, STATUS_SUCCESS, L"SeShutdownPrivilege SeBatchLogonRight");
    CHECK_REMOVE(Sid, FALSE, Priv1, 1, STATUS_SUCCESS);
    CHECK_RIGHTS(Sid, STATUS_SUCCESS, L"SeBatchLogonRight");
    CHECK_REMOVE(Sid, FALSE, Batch, 1, STATUS_SUCCESS);
    CHECK_RIGHTS(Sid, STATUS_OBJECT_NAME_NOT_FOUND, L"");

    /* a privilege that is not the last one of three */
    ok(Add(Sid, Priv3, 3) == STATUS_SUCCESS, "add\n");
    CHECK_REMOVE(Sid, FALSE, Priv1, 1, STATUS_SUCCESS);
    {
        WCHAR Text[256];
        NTSTATUS Left = Rights(Sid, Text, 256);

        ok(Left == STATUS_SUCCESS, "enumerate: 0x%08lx\n", (ULONG)Left);
        ok(wcsstr(Text, L"SeBackupPrivilege") && wcsstr(Text, L"SeRestorePrivilege") && !wcsstr(Text, L"SeShutdownPrivilege"),
           "rights '%ls'\n", Text);
    }
    CHECK_REMOVE(Sid, TRUE, NULL, 0, STATUS_SUCCESS);
    CHECK_RIGHTS(Sid, STATUS_OBJECT_NAME_NOT_FOUND, L"");

    LocalFree(Sid);
    LsaClose(Policy);
}
