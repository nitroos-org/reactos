/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     LsaQueryInformationPolicy returns the structure and its strings and SID as one heap block
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"
#include <ndk/rtlfuncs.h>
#include <ndk/umtypes.h>
#include <ntsecapi.h>

#define QUERY_ITERATIONS    10000
#define WARMUP_ITERATIONS   200

typedef struct _HEAP_TOTALS
{
    SIZE_T Blocks;
    SIZE_T Bytes;
} HEAP_TOTALS;

/* Busy blocks and bytes in the process heap */
static void SnapshotHeap(HEAP_TOTALS *Totals)
{
    HANDLE Heap = GetProcessHeap();
    PROCESS_HEAP_ENTRY Entry;

    Totals->Blocks = 0;
    Totals->Bytes = 0;
    HeapLock(Heap);
    Entry.lpData = NULL;
    while (HeapWalk(Heap, &Entry))
    {
        if ((Entry.wFlags & PROCESS_HEAP_ENTRY_BUSY) && !(Entry.wFlags & PROCESS_HEAP_REGION))
        {
            Totals->Blocks++;
            Totals->Bytes += Entry.cbData;
        }
    }
    HeapUnlock(Heap);
}

static BOOL InBlock(PVOID Block, SIZE_T BlockSize, PVOID Pointer, SIZE_T Length)
{
    PUCHAR Start = Block, P = Pointer;

    return P >= Start && Length <= BlockSize && (SIZE_T)(P - Start) <= BlockSize - Length;
}

static void CheckString(PVOID Block, SIZE_T Size, PLSA_UNICODE_STRING String, PCSTR What, PCSTR Member)
{
    if (String->Buffer != NULL)
        ok(InBlock(Block, Size, String->Buffer, String->MaximumLength),
           "%s: %s buffer %p is outside the %Iu byte block at %p\n", What, Member, String->Buffer, Size, Block);
}

static void CheckSid(PVOID Block, SIZE_T Size, PSID Sid, PCSTR What)
{
    if (Sid != NULL)
        ok(InBlock(Block, Size, Sid, RtlLengthSid(Sid)),
           "%s: SID %p is outside the %Iu byte block at %p\n", What, Sid, Size, Block);
}

static const struct
{
    POLICY_INFORMATION_CLASS Class;
    PCSTR Name;
} Classes[] =
{
    { PolicyAccountDomainInformation, "PolicyAccountDomainInformation" },
    { PolicyPrimaryDomainInformation, "PolicyPrimaryDomainInformation" },
    { PolicyDnsDomainInformation, "PolicyDnsDomainInformation" },
    { PolicyAuditEventsInformation, "PolicyAuditEventsInformation" },
};

/* Returns FALSE when the class is not available */
static BOOL QueryOnce(LSA_HANDLE Policy, ULONG Index, BOOL Check)
{
    PVOID Info = NULL;
    NTSTATUS Status;
    SIZE_T Size;
    PCSTR What = Classes[Index].Name;

    Status = LsaQueryInformationPolicy(Policy, Classes[Index].Class, &Info);
    if (Status != STATUS_SUCCESS)
        return FALSE;

    if (Check)
    {
        ok(HeapValidate(GetProcessHeap(), 0, Info), "%s: %p is not a heap block\n", What, Info);
        Size = HeapSize(GetProcessHeap(), 0, Info);
        ok(Size != (SIZE_T)-1, "%s: HeapSize failed\n", What);

        switch (Classes[Index].Class)
        {
            case PolicyAccountDomainInformation:
            {
                PPOLICY_ACCOUNT_DOMAIN_INFO Account = Info;
                CheckString(Info, Size, &Account->DomainName, What, "name");
                CheckSid(Info, Size, Account->DomainSid, What);
                ok(Account->DomainSid != NULL, "%s: no SID\n", What);
                break;
            }
            case PolicyPrimaryDomainInformation:
            {
                PPOLICY_PRIMARY_DOMAIN_INFO Primary = Info;
                CheckString(Info, Size, &Primary->Name, What, "name");
                CheckSid(Info, Size, Primary->Sid, What);
                break;
            }
            case PolicyDnsDomainInformation:
            {
                PPOLICY_DNS_DOMAIN_INFO Dns = Info;
                CheckString(Info, Size, &Dns->Name, What, "name");
                CheckString(Info, Size, &Dns->DnsDomainName, What, "DNS name");
                CheckString(Info, Size, &Dns->DnsForestName, What, "forest name");
                CheckSid(Info, Size, Dns->Sid, What);
                break;
            }
            case PolicyAuditEventsInformation:
            {
                PPOLICY_AUDIT_EVENTS_INFO Audit = Info;
                if (Audit->EventAuditingOptions != NULL)
                    ok(InBlock(Info, Size, Audit->EventAuditingOptions,
                               Audit->MaximumAuditEventCount * sizeof(*Audit->EventAuditingOptions)),
                       "%s: options %p are outside the %Iu byte block at %p\n",
                       What, Audit->EventAuditingOptions, Size, Info);
                break;
            }
            default:
                break;
        }
    }

    Status = LsaFreeMemory(Info);
    ok(Status == STATUS_SUCCESS, "%s: LsaFreeMemory(%p) returned 0x%lx\n", What, Info, Status);
    return TRUE;
}

START_TEST(LsaPolicyInfoLeak)
{
    LSA_OBJECT_ATTRIBUTES Attributes = {sizeof(Attributes)};
    LSA_HANDLE Policy;
    NTSTATUS Status;
    HEAP_TOTALS Before, After;
    ULONG i, Class;

    Status = LsaOpenPolicy(NULL, &Attributes, POLICY_VIEW_LOCAL_INFORMATION | POLICY_VIEW_AUDIT_INFORMATION, &Policy);
    if (Status != STATUS_SUCCESS)
    {
        skip("LsaOpenPolicy failed: 0x%lx\n", Status);
        return;
    }

    for (Class = 0; Class < ARRAYSIZE(Classes); Class++)
    {
        if (!QueryOnce(Policy, Class, TRUE))
        {
            skip("%s is not available\n", Classes[Class].Name);
            continue;
        }

        for (i = 0; i < WARMUP_ITERATIONS; i++)
            QueryOnce(Policy, Class, FALSE);

        SnapshotHeap(&Before);
        for (i = 0; i < QUERY_ITERATIONS; i++)
            QueryOnce(Policy, Class, FALSE);
        SnapshotHeap(&After);

        trace("%s: process heap busy before: %Iu blocks, %Iu bytes; after %d queries: %Iu blocks, %Iu bytes\n",
              Classes[Class].Name, Before.Blocks, Before.Bytes, QUERY_ITERATIONS, After.Blocks, After.Bytes);
        /* A leak costs at least one block per query; allow slack for the RPC runtime's own caches */
        ok(After.Blocks < Before.Blocks + 100, "%s: heap blocks grew from %Iu to %Iu\n",
           Classes[Class].Name, Before.Blocks, After.Blocks);
        ok(After.Bytes < Before.Bytes + 32 * 1024, "%s: heap bytes grew from %Iu to %Iu\n",
           Classes[Class].Name, Before.Bytes, After.Bytes);
    }

    LsaClose(Policy);
}
