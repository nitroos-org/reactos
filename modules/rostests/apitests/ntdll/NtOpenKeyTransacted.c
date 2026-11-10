/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Tests for NtOpenKeyTransacted, NtOpenKeyTransactedEx and NtCreateKeyTransacted of ntdll
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Measured on Windows 10 22H2 (19045), x64 and 32-bit under WOW64 (arguments only; no transaction is ever created):
 *  - The three functions are exported by ntdll as real system calls.
 *  - The transaction handle is looked at first, before the output pointer, the access mask and the attributes: a NULL
 *    handle, a handle value that is not open and a closed handle are STATUS_INVALID_HANDLE; a handle to an object of
 *    another type (event, the process and thread pseudo handles) is STATUS_OBJECT_TYPE_MISMATCH. This holds with a
 *    NULL output pointer, a NULL attributes pointer, an attributes block without a name, access 0 and options
 *    0x80000000. Nothing is returned in the output handle, and the disposition of the create call is not written.
 *  - A 32-bit caller under WOW64 differs only where the attributes are bad and the transaction handle exists: a NULL
 *    attributes pointer, an attributes block with no name or an output pointer that cannot be written (8; a NULL
 *    pointer is not checked) is STATUS_ACCESS_VIOLATION (the 64-bit call gives STATUS_OBJECT_TYPE_MISMATCH).
 */

#include "precomp.h"

typedef NTSTATUS (NTAPI *PFN_OPEN)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE);
typedef NTSTATUS (NTAPI *PFN_OPENEX)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG, HANDLE);
typedef NTSTATUS (NTAPI *PFN_CREATE)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG, PUNICODE_STRING, ULONG, HANDLE, PULONG);
typedef BOOL (WINAPI *PFN_ISWOW64)(HANDLE, PBOOL);

START_TEST(NtOpenKeyTransacted)
{
    HMODULE Ntdll = GetModuleHandleA("ntdll.dll");
    PFN_OPEN pOpen = (PFN_OPEN)GetProcAddress(Ntdll, "NtOpenKeyTransacted");
    PFN_OPENEX pOpenEx = (PFN_OPENEX)GetProcAddress(Ntdll, "NtOpenKeyTransactedEx");
    PFN_CREATE pCreate = (PFN_CREATE)GetProcAddress(Ntdll, "NtCreateKeyTransacted");
    PFN_ISWOW64 pIsWow64 = (PFN_ISWOW64)GetProcAddress(GetModuleHandleA("kernel32.dll"), "IsWow64Process");
    UNICODE_STRING Name, CreateName;
    OBJECT_ATTRIBUTES Oa, OaNoName, CreateOa;
    HANDLE Event, Closed, Key;
    BOOL Wow64 = FALSE;
    NTSTATUS Status;
    ULONG Disposition;
    struct { HANDLE Handle; NTSTATUS Expected; const char *Desc; } Cases[6];
    ULONG i;

    ok(pOpen != NULL, "NtOpenKeyTransacted is not exported\n");
    ok(pOpenEx != NULL, "NtOpenKeyTransactedEx is not exported\n");
    ok(pCreate != NULL, "NtCreateKeyTransacted is not exported\n");
    if (!pOpen || !pOpenEx || !pCreate)
    {
        skip("exports missing\n");
        return;
    }
    if (pIsWow64)
        pIsWow64(GetCurrentProcess(), &Wow64);

    RtlInitUnicodeString(&Name, L"\\Registry\\Machine\\SOFTWARE");
    InitializeObjectAttributes(&Oa, &Name, OBJ_CASE_INSENSITIVE, NULL, NULL);
    InitializeObjectAttributes(&OaNoName, NULL, OBJ_CASE_INSENSITIVE, NULL, NULL);
    RtlInitUnicodeString(&CreateName, L"\\Registry\\User\\.Default\\TransactedProbe");
    InitializeObjectAttributes(&CreateOa, &CreateName, OBJ_CASE_INSENSITIVE, NULL, NULL);

    Event = CreateEventW(NULL, TRUE, FALSE, NULL);
    Closed = CreateEventW(NULL, TRUE, FALSE, NULL);
    ok(Event && Closed, "CreateEvent failed\n");
    CloseHandle(Closed);

    Cases[0].Handle = NULL;                    Cases[0].Expected = STATUS_INVALID_HANDLE;       Cases[0].Desc = "NULL";
    Cases[1].Handle = (HANDLE)(ULONG_PTR)0x7777; Cases[1].Expected = STATUS_INVALID_HANDLE;     Cases[1].Desc = "0x7777";
    Cases[2].Handle = Closed;                  Cases[2].Expected = STATUS_INVALID_HANDLE;       Cases[2].Desc = "closed";
    Cases[3].Handle = Event;                   Cases[3].Expected = STATUS_OBJECT_TYPE_MISMATCH; Cases[3].Desc = "event";
    Cases[4].Handle = NtCurrentProcess();      Cases[4].Expected = STATUS_OBJECT_TYPE_MISMATCH; Cases[4].Desc = "process";
    Cases[5].Handle = NtCurrentThread();       Cases[5].Expected = STATUS_OBJECT_TYPE_MISMATCH; Cases[5].Desc = "thread";

    for (i = 0; i < RTL_NUMBER_OF(Cases); i++)
    {
        Key = NULL;
        Status = pOpen(&Key, KEY_READ, &Oa, Cases[i].Handle);
        ok_ntstatus(Status, Cases[i].Expected);
        ok(Key == NULL, "OpenKeyTransacted (%s): handle returned\n", Cases[i].Desc);

        Key = NULL;
        Status = pOpenEx(&Key, KEY_READ, &Oa, 0, Cases[i].Handle);
        ok_ntstatus(Status, Cases[i].Expected);
        ok(Key == NULL, "OpenKeyTransactedEx (%s): handle returned\n", Cases[i].Desc);

        Key = NULL;
        Status = pOpenEx(&Key, KEY_READ, &Oa, 0x80000000, Cases[i].Handle);
        ok_ntstatus(Status, Cases[i].Expected);

        Key = NULL;
        Status = pOpen(&Key, 0, &Oa, Cases[i].Handle);
        ok_ntstatus(Status, Cases[i].Expected);

        Key = NULL;
        Disposition = 0xDEAD;
        Status = pCreate(&Key, KEY_READ | KEY_WRITE, &CreateOa, 0, NULL, 0, Cases[i].Handle, &Disposition);
        ok_ntstatus(Status, Cases[i].Expected);
        ok(Key == NULL, "CreateKeyTransacted (%s): handle returned\n", Cases[i].Desc);
        ok(Disposition == 0xDEAD, "CreateKeyTransacted (%s): disposition written\n", Cases[i].Desc);
    }

    /* an invalid transaction handle wins over every other bad argument */
    Status = pOpen(NULL, KEY_READ, &Oa, NULL);
    ok_ntstatus(Status, STATUS_INVALID_HANDLE);
    Status = pOpen(&Key, KEY_READ, NULL, NULL);
    ok_ntstatus(Status, STATUS_INVALID_HANDLE);
    Status = pOpen(&Key, KEY_READ, &OaNoName, NULL);
    ok_ntstatus(Status, STATUS_INVALID_HANDLE);
    Status = pOpen((PHANDLE)(ULONG_PTR)8, KEY_READ, &Oa, NULL);
    ok_ntstatus(Status, STATUS_INVALID_HANDLE);
    Status = pOpenEx(NULL, KEY_READ, NULL, 0, (HANDLE)(ULONG_PTR)0x7777);
    ok_ntstatus(Status, STATUS_INVALID_HANDLE);
    Status = pCreate(NULL, KEY_READ, NULL, 0, NULL, 0, NULL, NULL);
    ok_ntstatus(Status, STATUS_INVALID_HANDLE);

    /* a handle that exists but is no transaction: bad attributes */
    if (!Wow64)
    {
        Status = pOpen(NULL, KEY_READ, &Oa, Event);
        ok_ntstatus(Status, STATUS_OBJECT_TYPE_MISMATCH);
        Status = pOpen(&Key, KEY_READ, NULL, Event);
        ok_ntstatus(Status, STATUS_OBJECT_TYPE_MISMATCH);
        Status = pOpen(&Key, KEY_READ, &OaNoName, Event);
        ok_ntstatus(Status, STATUS_OBJECT_TYPE_MISMATCH);
        Status = pOpen((PHANDLE)(ULONG_PTR)8, KEY_READ, &Oa, Event);
        ok_ntstatus(Status, STATUS_OBJECT_TYPE_MISMATCH);
        Status = pOpenEx(&Key, KEY_READ, NULL, 0, Event);
        ok_ntstatus(Status, STATUS_OBJECT_TYPE_MISMATCH);
        Status = pCreate(&Key, KEY_READ, NULL, 0, NULL, 0, Event, NULL);
        ok_ntstatus(Status, STATUS_OBJECT_TYPE_MISMATCH);
    }
    else
    {
        Status = pOpen(NULL, KEY_READ, &Oa, Event);
        ok_ntstatus(Status, STATUS_OBJECT_TYPE_MISMATCH);
        Status = pOpen(&Key, KEY_READ, NULL, Event);
        ok_ntstatus(Status, STATUS_ACCESS_VIOLATION);
        Status = pOpen(&Key, KEY_READ, &OaNoName, Event);
        ok_ntstatus(Status, STATUS_ACCESS_VIOLATION);
        Status = pOpen((PHANDLE)(ULONG_PTR)8, KEY_READ, &Oa, Event);
        ok_ntstatus(Status, STATUS_ACCESS_VIOLATION);
        Status = pOpenEx(&Key, KEY_READ, NULL, 0, Event);
        ok_ntstatus(Status, STATUS_ACCESS_VIOLATION);
        Status = pCreate(&Key, KEY_READ, NULL, 0, NULL, 0, Event, NULL);
        ok_ntstatus(Status, STATUS_ACCESS_VIOLATION);
    }

    CloseHandle(Event);
}
