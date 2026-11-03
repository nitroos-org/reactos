/* NtQuerySystemInformation(SystemHandleInformation, SystemExtendedHandleInformation) from a
 * 32-bit process. Under WoW64 the 64-bit tables are narrowed to the 32-bit layouts (class 16:
 * 4 + 16 * n bytes; class 64: 8 + 28 * n bytes, the Object pointer is the low 32 bits of the
 * kernel address). Windows 10 22H2 measured for class 64: a buffer shorter than the header and
 * one entry is refused with that length and nothing stored; a longer one that is still too short
 * receives the header with the full count and the entries that fit, then
 * STATUS_INFO_LENGTH_MISMATCH with the length of the whole table. The layout checks use the
 * types of the build, so the test also runs natively. Restart Manager and the process
 * explorers depend on it. SPDX-License-Identifier: LGPL-2.1-or-later */
#include "precomp.h"

#define SENTINEL 0x5a
#define EX_HEADER FIELD_OFFSET(SYSTEM_HANDLE_INFORMATION_EX, Handles)
#define EX_ENTRY sizeof(SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX)
#define OLD_HEADER FIELD_OFFSET(SYSTEM_HANDLE_INFORMATION, Handles)
#define OLD_ENTRY sizeof(SYSTEM_HANDLE_TABLE_ENTRY_INFO)

/* Query a class into a heap buffer that has slack after the table, retrying while the table grows */
static PUCHAR QueryTable(ULONG Class, ULONG *Length, ULONG *Size, NTSTATUS *Status)
{
    PUCHAR Buffer;
    ULONG Retries;

    *Size = 0x10000;
    for (Retries = 0; Retries < 16; Retries++)
    {
        Buffer = HeapAlloc(GetProcessHeap(), 0, *Size);
        if (!Buffer) return NULL;
        memset(Buffer, SENTINEL, *Size);
        *Length = 0xdeadbeef;
        *Status = NtQuerySystemInformation(Class, Buffer, *Size, Length);
        if (*Status != STATUS_INFO_LENGTH_MISMATCH) return Buffer;
        HeapFree(GetProcessHeap(), 0, Buffer);
        *Size = max(*Size * 2, *Length + 0x10000);
    }
    return NULL;
}

START_TEST(Wow64HandleInformation)
{
    SYSTEM_HANDLE_INFORMATION_EX *Ex;
    SYSTEM_HANDLE_INFORMATION *Old;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX *EntryEx = NULL;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO *EntryOld = NULL;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Saved;
    PUCHAR Buffer, Small;
    ULONG Length, Size, i;
    NTSTATUS Status;
    HANDLE Event;
    BOOL Wow64 = FALSE;

    IsWow64Process(GetCurrentProcess(), &Wow64);
    if (Wow64)
    {
        ok(EX_HEADER == 8 && EX_ENTRY == 28, "header %lu, entry %lu\n", (ULONG)EX_HEADER, (ULONG)EX_ENTRY);
        ok(OLD_HEADER == 4 && OLD_ENTRY == 16, "header %lu, entry %lu\n", (ULONG)OLD_HEADER, (ULONG)OLD_ENTRY);
    }

    Event = CreateEventW(NULL, TRUE, FALSE, NULL);
    ok(Event != NULL, "CreateEvent failed: %lu\n", GetLastError());

    /* A buffer shorter than the header and one entry: the length is that minimum, nothing is stored.
     * (Native ReactOS only needs the header.) */
    Small = HeapAlloc(GetProcessHeap(), 0, EX_HEADER + EX_ENTRY);
    memset(Small, SENTINEL, EX_HEADER + EX_ENTRY);
    Length = 0xdeadbeef;
    Status = NtQuerySystemInformation(SystemExtendedHandleInformation, Small, EX_HEADER - 1, &Length);
    ok_ntstatus(Status, STATUS_INFO_LENGTH_MISMATCH);
    if (Wow64)
    {
        ok_long(Length, EX_HEADER + EX_ENTRY);
        Length = 0xdeadbeef;
        Status = NtQuerySystemInformation(SystemExtendedHandleInformation, Small, EX_HEADER + EX_ENTRY - 1, &Length);
        ok_ntstatus(Status, STATUS_INFO_LENGTH_MISMATCH);
        ok_long(Length, EX_HEADER + EX_ENTRY);
        Status = NtQuerySystemInformation(SystemExtendedHandleInformation, NULL, 0, &Length);
        ok_ntstatus(Status, STATUS_INFO_LENGTH_MISMATCH);
        ok_long(Length, EX_HEADER + EX_ENTRY);
    }
    for (i = 0; i < EX_HEADER + EX_ENTRY; i++)
        if (Small[i] != SENTINEL) break;
    ok(i == EX_HEADER + EX_ENTRY, "A buffer that is too short was written at %lu\n", i);

    /* Room for exactly one entry: under WoW64 the header holds the full count, the first entry is
     * stored, and the status and length describe the whole table (native ReactOS reports what it filled) */
    Ex = (SYSTEM_HANDLE_INFORMATION_EX *)Small;
    Length = 0xdeadbeef;
    Status = NtQuerySystemInformation(SystemExtendedHandleInformation, Small, EX_HEADER + EX_ENTRY, &Length);
    ok_ntstatus(Status, STATUS_INFO_LENGTH_MISMATCH);
    if (Wow64)
    {
        ok(Ex->NumberOfHandles > 1, "NumberOfHandles %lu\n", (ULONG)Ex->NumberOfHandles);
        ok_long(Length, EX_HEADER + Ex->NumberOfHandles * EX_ENTRY);
    }
    ok(Ex->Handles[0].UniqueProcessId < 0x100000, "First entry process %lu\n", (ULONG)Ex->Handles[0].UniqueProcessId);
    ok(Ex->Handles[0].GrantedAccess != 0, "First entry access %lx\n", Ex->Handles[0].GrantedAccess);
    HeapFree(GetProcessHeap(), 0, Small);

    /* The whole table */
    Buffer = QueryTable(SystemExtendedHandleInformation, &Length, &Size, &Status);
    ok(Buffer != NULL, "No table\n");
    if (!Buffer) goto old;
    ok_ntstatus(Status, STATUS_SUCCESS);
    Ex = (SYSTEM_HANDLE_INFORMATION_EX *)Buffer;
    ok(Ex->NumberOfHandles > 0 && Ex->NumberOfHandles < Size / EX_ENTRY, "NumberOfHandles %lu\n", (ULONG)Ex->NumberOfHandles);
    ok(Length == EX_HEADER + Ex->NumberOfHandles * EX_ENTRY, "Length %lu, %lu handles\n", Length, (ULONG)Ex->NumberOfHandles);
    ok(Length <= Size, "Length %lu, size %lu\n", Length, Size);
    i = Size;
    if (Length <= Size)
        for (i = Length; i < Size; i++)
            if (Buffer[i] != SENTINEL) break;
    ok(i == Size, "Stored past the returned length, at %lu of %lu\n", i, Length);
    for (i = 0; i < Ex->NumberOfHandles && i < (Size - EX_HEADER) / EX_ENTRY; i++)
    {
        SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX *Entry = &Ex->Handles[i];
        if (Entry->UniqueProcessId == GetCurrentProcessId() && Entry->HandleValue == (ULONG_PTR)Event)
            EntryEx = Entry;
        ok(Entry->Reserved == 0, "Entry %lu reserved %lx\n", i, Entry->Reserved);
        if (Entry->Reserved) break;
    }
    ok(EntryEx != NULL, "The event is not in the table\n");
    if (EntryEx)
    {
        Saved = *EntryEx;
        EntryEx = &Saved;
        ok(EntryEx->Object != NULL, "No object\n");
        ok(EntryEx->GrantedAccess == EVENT_ALL_ACCESS || (EntryEx->GrantedAccess & SYNCHRONIZE),
           "Access %lx\n", EntryEx->GrantedAccess);
        if (Wow64)
            ok(((ULONG_PTR)EntryEx->Object >> 16) != 0, "Object %p\n", EntryEx->Object);
    }

    HeapFree(GetProcessHeap(), 0, Buffer);

old:
    /* Class 16 describes the same handle the same way */
    Buffer = QueryTable(SystemHandleInformation, &Length, &Size, &Status);
    ok(Buffer != NULL, "No table\n");
    if (!Buffer) goto done;
    ok_ntstatus(Status, STATUS_SUCCESS);
    Old = (SYSTEM_HANDLE_INFORMATION *)Buffer;
    ok(Old->NumberOfHandles > 0, "NumberOfHandles %lu\n", Old->NumberOfHandles);
    ok(Length == OLD_HEADER + Old->NumberOfHandles * OLD_ENTRY, "Length %lu, %lu handles\n", Length, Old->NumberOfHandles);
    for (i = 0; i < Old->NumberOfHandles && i < (Size - OLD_HEADER) / OLD_ENTRY; i++)
        if (Old->Handles[i].UniqueProcessId == GetCurrentProcessId() &&
            Old->Handles[i].HandleValue == (USHORT)(ULONG_PTR)Event)
            EntryOld = &Old->Handles[i];
    ok(EntryOld != NULL, "The event is not in the table\n");
    if (EntryOld && EntryEx)
    {
        ok(EntryOld->Object == EntryEx->Object, "Objects %p and %p\n", EntryOld->Object, EntryEx->Object);
        ok(EntryOld->GrantedAccess == EntryEx->GrantedAccess, "Access %lx and %lx\n",
           EntryOld->GrantedAccess, EntryEx->GrantedAccess);
    }
    HeapFree(GetProcessHeap(), 0, Buffer);

    /* Too short for the header: the length is the header (and one entry under WoW64) */
    Length = 0xdeadbeef;
    Status = NtQuerySystemInformation(SystemHandleInformation, NULL, 0, &Length);
    ok_ntstatus(Status, STATUS_INFO_LENGTH_MISMATCH);

done:
    /* Invalid buffers and return length. The length is checked first. */
    {
        ULONG Valid = EX_HEADER + EX_ENTRY;
        PVOID Bad = (PVOID)(ULONG_PTR)0x10;
        ULONG Dummy;

        Status = NtQuerySystemInformation(SystemExtendedHandleInformation, Bad, Valid, &Dummy);
        ok(Status == STATUS_ACCESS_VIOLATION || Status == STATUS_INVALID_USER_BUFFER, "Bad buffer: %lx\n", Status);
        Small = HeapAlloc(GetProcessHeap(), 0, 0x10000);
        Status = NtQuerySystemInformation(SystemExtendedHandleInformation, Small, 0x10000, (PULONG)Bad);
        ok(Status == STATUS_ACCESS_VIOLATION, "Bad return length: %lx\n", Status);
        HeapFree(GetProcessHeap(), 0, Small);
        if (Wow64)
        {
            /* A buffer that runs into the kernel half is refused whole */
            Status = NtQuerySystemInformation(SystemExtendedHandleInformation, (PVOID)0x7ffff000, 0x10000, &Dummy);
            ok(Status == STATUS_ACCESS_VIOLATION || Status == STATUS_INVALID_USER_BUFFER, "Buffer past the range: %lx\n", Status);
        }
    }
    if (Event) CloseHandle(Event);
}
