/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     The registry services that take a name from the caller (NtUnloadKey2, NtCreateKey's class)
 *              must read the caller's buffers once, safely: a name or class buffer that is invalid,
 *              unmapped, freed after the call is made, or made inaccessible by another thread while the
 *              service runs, gives an error status and never takes the system down.
 */

#include "precomp.h"

#define REG_CREATED_NEW_KEY 1
#define STRESS_MS       4000
#define SCRATCH_KEY     L"\\Registry\\Machine\\SOFTWARE\\NtUnloadKeyBufferTest"
/* An existing key that is not the root of a hive: NtUnloadKey2 refuses it, and nothing is created */
#define EXISTING_KEY    L"\\Registry\\Machine\\SYSTEM\\Select"

static NTSTATUS (NTAPI *pNtUnloadKey2)(POBJECT_ATTRIBUTES, ULONG);

/* Every part runs unless UKB_ONLY names one of rows-unload, rows-class, stress-unload, stress-class: a kernel that
 * fails a part can then be told from one that fails another */
static BOOLEAN Selected(PCSTR Part)
{
    CHAR Only[32];

    if (!GetEnvironmentVariableA("UKB_ONLY", Only, sizeof(Only)))
        return TRUE;
    return !strcmp(Only, Part);
}

/* A page of memory that holds a counted string at its end, so that what follows it is not accessible */
typedef struct _PAGE_NAME
{
    PUCHAR Page;
    PWCHAR Buffer;
    USHORT Length;
} PAGE_NAME;

static BOOLEAN MakePageName(PAGE_NAME *Name, PCWSTR Text)
{
    SIZE_T Bytes = wcslen(Text) * sizeof(WCHAR);

    Name->Page = VirtualAlloc(NULL, 2 * 4096, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!Name->Page)
        return FALSE;
    /* The second page is the guard: the string ends where the first one does */
    VirtualProtect(Name->Page + 4096, 4096, PAGE_NOACCESS, &(DWORD){0});
    Name->Length = (USHORT)Bytes;
    Name->Buffer = (PWCHAR)(Name->Page + 4096 - Bytes);
    RtlCopyMemory(Name->Buffer, Text, Bytes);
    return TRUE;
}

/* An address in the user range that is not mapped: it was, and is freed */
static PWCHAR Unmapped(void)
{
    PVOID Page = VirtualAlloc(NULL, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

    if (Page)
        VirtualFree(Page, 0, MEM_RELEASE);
    return Page;
}

static NTSTATUS UnloadWith(PUNICODE_STRING Name, PVOID NameLocation)
{
    OBJECT_ATTRIBUTES Attributes;

    InitializeObjectAttributes(&Attributes, NameLocation ? NameLocation : Name, OBJ_CASE_INSENSITIVE, NULL, NULL);
    return pNtUnloadKey2(&Attributes, 0);
}

static void TestUnloadKey2Rows(void)
{
    PAGE_NAME Name;
    UNICODE_STRING String;
    OBJECT_ATTRIBUTES Attributes;
    PUNICODE_STRING Freed;
    NTSTATUS Status;
    PVOID Page;

    if (!MakePageName(&Name, EXISTING_KEY))
    {
        skip("no memory\n");
        return;
    }
    String.Length = String.MaximumLength = Name.Length;
    String.Buffer = Name.Buffer;

    /* A good name: the key exists and is not a hive root */
    Status = UnloadWith(&String, NULL);
    ok_ntstatus(Status, STATUS_INVALID_PARAMETER);

    /* No attributes at all: no name, nothing to unload */
    Status = pNtUnloadKey2(NULL, 0);
    ok(Status == STATUS_INVALID_PARAMETER || Status == STATUS_ACCESS_VIOLATION, "NULL gave 0x%08lx\n", Status);

    /* An unmapped attributes block, and one at the end of the address space */
    Status = pNtUnloadKey2((POBJECT_ATTRIBUTES)Unmapped(), 0);
    ok_ntstatus(Status, STATUS_ACCESS_VIOLATION);
    Status = pNtUnloadKey2((POBJECT_ATTRIBUTES)(ULONG_PTR)~(ULONG_PTR)7, 0);
    ok_ntstatus(Status, STATUS_ACCESS_VIOLATION);

    /* A kernel address as the name string, and as its buffer */
    InitializeObjectAttributes(&Attributes, (PUNICODE_STRING)(ULONG_PTR)(sizeof(PVOID) == 8 ? 0xFFFFF78000000000ULL : 0x80001000UL),
                               OBJ_CASE_INSENSITIVE, NULL, NULL);
    Status = pNtUnloadKey2(&Attributes, 0);
    ok_ntstatus(Status, STATUS_ACCESS_VIOLATION);
    String.Buffer = (PWCHAR)(ULONG_PTR)(sizeof(PVOID) == 8 ? 0xFFFFF78000000000ULL : 0x80001000UL);
    Status = UnloadWith(&String, NULL);
    ok_ntstatus(Status, STATUS_ACCESS_VIOLATION);

    /* A string whose length reaches into the inaccessible page */
    String.Buffer = Name.Buffer;
    String.Length = String.MaximumLength = Name.Length + 8;
    Status = UnloadWith(&String, NULL);
    ok_ntstatus(Status, STATUS_ACCESS_VIOLATION);

    /* A name buffer that is not mapped (never was) */
    String.Length = String.MaximumLength = Name.Length;
    String.Buffer = Unmapped();
    Status = UnloadWith(&String, NULL);
    ok_ntstatus(Status, STATUS_ACCESS_VIOLATION);

    /* A name buffer that has been freed before the call */
    Page = VirtualAlloc(NULL, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    ok(Page != NULL, "VirtualAlloc failed\n");
    if (Page)
    {
        RtlCopyMemory(Page, EXISTING_KEY, Name.Length);
        String.Buffer = Page;
        VirtualFree(Page, 0, MEM_RELEASE);
        Status = UnloadWith(&String, NULL);
        ok_ntstatus(Status, STATUS_ACCESS_VIOLATION);
    }

    /* The UNICODE_STRING itself freed before the call */
    Freed = VirtualAlloc(NULL, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    ok(Freed != NULL, "VirtualAlloc failed\n");
    if (Freed)
    {
        Freed->Length = Freed->MaximumLength = Name.Length;
        Freed->Buffer = Name.Buffer;
        VirtualFree(Freed, 0, MEM_RELEASE);
        Status = UnloadWith(NULL, Freed);
        ok_ntstatus(Status, STATUS_ACCESS_VIOLATION);
    }

    /* The service is still good after all of that */
    String.Buffer = Name.Buffer;
    String.Length = String.MaximumLength = Name.Length;
    Status = UnloadWith(&String, NULL);
    ok_ntstatus(Status, STATUS_INVALID_PARAMETER);

    VirtualFree(Name.Page, 0, MEM_RELEASE);
}

static void TestCreateKeyClassRows(void)
{
    UNICODE_STRING KeyName, Class;
    OBJECT_ATTRIBUTES Attributes;
    HANDLE Key;
    ULONG Disposition, Length;
    UCHAR Info[512];
    PKEY_NODE_INFORMATION Node = (PKEY_NODE_INFORMATION)Info;
    NTSTATUS Status;
    PVOID Page;
    static const WCHAR ClassText[] = L"ClassOfTheKey";

    RtlInitUnicodeString(&KeyName, SCRATCH_KEY);
    InitializeObjectAttributes(&Attributes, &KeyName, OBJ_CASE_INSENSITIVE, NULL, NULL);

    /* A class in unmapped memory: an error, and no key is made */
    Class.Length = Class.MaximumLength = 16;
    Class.Buffer = Unmapped();
    Key = NULL;
    Status = NtCreateKey(&Key, KEY_ALL_ACCESS, &Attributes, 0, &Class, REG_OPTION_VOLATILE, &Disposition);
    ok_ntstatus(Status, STATUS_ACCESS_VIOLATION);
    Status = NtOpenKey(&Key, KEY_READ, &Attributes);
    ok_ntstatus(Status, STATUS_OBJECT_NAME_NOT_FOUND);

    /* A class that was freed before the call */
    Page = VirtualAlloc(NULL, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (Page)
    {
        RtlCopyMemory(Page, ClassText, sizeof(ClassText));
        Class.Length = Class.MaximumLength = sizeof(ClassText) - sizeof(WCHAR);
        Class.Buffer = Page;
        VirtualFree(Page, 0, MEM_RELEASE);
        Status = NtCreateKey(&Key, KEY_ALL_ACCESS, &Attributes, 0, &Class, REG_OPTION_VOLATILE, &Disposition);
        ok_ntstatus(Status, STATUS_ACCESS_VIOLATION);
        Status = NtOpenKey(&Key, KEY_READ, &Attributes);
        ok_ntstatus(Status, STATUS_OBJECT_NAME_NOT_FOUND);
    }

    /* A good class is kept as it is */
    RtlInitUnicodeString(&Class, ClassText);
    Key = NULL;
    Status = NtCreateKey(&Key, KEY_ALL_ACCESS, &Attributes, 0, &Class, REG_OPTION_VOLATILE, &Disposition);
    ok_ntstatus(Status, STATUS_SUCCESS);
    if (NT_SUCCESS(Status))
    {
        ok_int(Disposition, REG_CREATED_NEW_KEY);
        Status = NtQueryKey(Key, KeyNodeInformation, Info, sizeof(Info), &Length);
        ok_ntstatus(Status, STATUS_SUCCESS);
        if (NT_SUCCESS(Status))
        {
            ok_int(Node->ClassLength, Class.Length);
            ok(Node->ClassOffset != 0xFFFFFFFF &&
               RtlEqualMemory(Info + Node->ClassOffset, ClassText, Class.Length),
               "class not kept\n");
        }
        NtDeleteKey(Key);
        NtClose(Key);
    }
}

static volatile LONG g_Stop;
static volatile LONG g_Toggles;
static PUCHAR g_TogglePage;

/* Makes the page that holds the caller's buffer inaccessible and accessible again, while the main thread calls */
static DWORD WINAPI ToggleThread(PVOID Context)
{
    DWORD Old;

    while (!g_Stop)
    {
        VirtualProtect(g_TogglePage, 4096, PAGE_NOACCESS, &Old);
        VirtualProtect(g_TogglePage, 4096, PAGE_READWRITE, &Old);
        InterlockedIncrement(&g_Toggles);
    }
    return 0;
}

static BOOLEAN KnownStatus(NTSTATUS Status, NTSTATUS Wanted)
{
    return Status == STATUS_ACCESS_VIOLATION || Status == Wanted;
}

static void TestStress(void)
{
    HANDLE Thread;
    ULONG Start, Calls = 0, Faults = 0, Others = 0;
    PUCHAR Page;
    PWCHAR Buffer;
    UNICODE_STRING String, Class, KeyName;
    OBJECT_ATTRIBUTES Attributes, KeyAttributes;
    NTSTATUS Status;
    HANDLE Key;
    SIZE_T Bytes = wcslen(EXISTING_KEY) * sizeof(WCHAR);
    static const WCHAR ClassText[] = L"ClassOfTheKey";

    Page = VirtualAlloc(NULL, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!Page)
    {
        skip("no memory\n");
        return;
    }
    g_TogglePage = Page;
    /* The name and the class sit in the page the other thread toggles */
    Buffer = (PWCHAR)Page;
    RtlCopyMemory(Buffer, EXISTING_KEY, Bytes);
    RtlCopyMemory(Page + 2048, ClassText, sizeof(ClassText));
    String.Length = String.MaximumLength = (USHORT)Bytes;
    String.Buffer = Buffer;
    Class.Length = Class.MaximumLength = sizeof(ClassText) - sizeof(WCHAR);
    Class.Buffer = (PWCHAR)(Page + 2048);
    InitializeObjectAttributes(&Attributes, &String, OBJ_CASE_INSENSITIVE, NULL, NULL);
    RtlInitUnicodeString(&KeyName, SCRATCH_KEY);
    InitializeObjectAttributes(&KeyAttributes, &KeyName, OBJ_CASE_INSENSITIVE, NULL, NULL);

    g_Stop = 0;
    g_Toggles = 0;
    Thread = CreateThread(NULL, 0, ToggleThread, NULL, 0, NULL);
    if (!Thread)
    {
        skip("no thread\n");
        VirtualFree(Page, 0, MEM_RELEASE);
        return;
    }

    Start = GetTickCount();
    while (GetTickCount() - Start < STRESS_MS)
    {
        if (Selected("stress-unload"))
        {
            Status = pNtUnloadKey2(&Attributes, 0);
            Calls++;
            if (Status == STATUS_ACCESS_VIOLATION)
                Faults++;
            else if (Status != STATUS_INVALID_PARAMETER)
                Others++;
        }

        if (!Selected("stress-class"))
            continue;

        /* The class: either the key is made with it, or the call fails and no key is left */
        Key = NULL;
        Status = NtCreateKey(&Key, KEY_ALL_ACCESS, &KeyAttributes, 0, &Class, REG_OPTION_VOLATILE, NULL);
        Calls++;
        if (NT_SUCCESS(Status))
        {
            NtDeleteKey(Key);
            NtClose(Key);
        }
        else if (!KnownStatus(Status, STATUS_SUCCESS))
        {
            Others++;
        }
        else
        {
            Faults++;
        }
    }

    InterlockedExchange(&g_Stop, 1);
    WaitForSingleObject(Thread, INFINITE);
    CloseHandle(Thread);
    VirtualFree(Page, 0, MEM_RELEASE);

    ok(Others == 0, "%lu calls gave an unexpected status\n", Others);
    ok(g_Toggles > 0, "the toggling thread never ran\n");
    trace("stress: %lu calls, %lu faulted, %ld page toggles\n", Calls, Faults, g_Toggles);

    Status = NtOpenKey(&Key, KEY_READ, &KeyAttributes);
    ok_ntstatus(Status, STATUS_OBJECT_NAME_NOT_FOUND);
    if (NT_SUCCESS(Status))
        NtClose(Key);
}

START_TEST(NtUnloadKeyBuffer)
{
    BOOLEAN Old;
    NTSTATUS Status;

    pNtUnloadKey2 = (PVOID)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtUnloadKey2");
    if (!pNtUnloadKey2)
    {
        skip("NtUnloadKey2 is not exported\n");
        return;
    }

    Status = RtlAdjustPrivilege(SE_RESTORE_PRIVILEGE, TRUE, FALSE, &Old);
    if (!NT_SUCCESS(Status))
    {
        skip("no restore privilege (0x%08lx)\n", Status);
        return;
    }

    if (Selected("rows-unload"))
        TestUnloadKey2Rows();
    if (Selected("rows-class"))
        TestCreateKeyClassRows();
    if (Selected("stress-unload") || Selected("stress-class"))
        TestStress();

    RtlAdjustPrivilege(SE_RESTORE_PRIVILEGE, Old, FALSE, &Old);
}
