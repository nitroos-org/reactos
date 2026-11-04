/*
 * The handle output of a failed open or create service under WoW64. Windows' WoW64 layer stores
 * NULL in the 32-bit caller's handle variable whenever the native call fails, also for services
 * whose native 64-bit form leaves the variable alone (Windows 10 22H2 measured for every call
 * below). 32-bit code that closes an unchecked handle after a failed open relies on that: with
 * the old value left in place it closes whatever the variable held, possibly a live handle.
 * A failure found before the native call (an unreadable object name) and an unwritable handle
 * variable leave the variable unchanged.
 * A native caller (64-bit, or 32-bit on a 32-bit system) gets the native services' own rules, which
 * differ per service. Windows 10 22H2 writes NULL for the services in NativeChecks and, measured for
 * 64-bit callers only (so only a 64-bit build checks them), leaves the variable alone for the others.
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
#include "precomp.h"

#define SENTINEL ((HANDLE)(ULONG_PTR)0xdeadbeef)
#define MISSING_OBJECT L"\\BaseNamedObjects\\WoW64NullHandleNoSuchObject"
#define MISSING_DIR    L"\\WoW64NullHandleNoSuchDirectory"

static OBJECT_ATTRIBUTES Attributes;
static UNICODE_STRING Name;

static POBJECT_ATTRIBUTES Named(PCWSTR Path)
{
    RtlInitUnicodeString(&Name, Path);
    InitializeObjectAttributes(&Attributes, &Name, OBJ_CASE_INSENSITIVE, NULL, NULL);
    return &Attributes;
}

static void CheckFailed(int Line, const char *Service, NTSTATUS Status, HANDLE Handle)
{
    ok_(__FILE__, Line)(!NT_SUCCESS(Status), "%s: status 0x%lx, expected a failure\n", Service, Status);
    if (NT_SUCCESS(Status))
    {
        if (Handle && Handle != SENTINEL) NtClose(Handle);
        return;
    }
    ok_(__FILE__, Line)(Handle == NULL, "%s: status 0x%lx, handle %p, expected NULL\n", Service, Status, Handle);
}
#define CHECK_FAILED(Service) CheckFailed(__LINE__, Service, Status, Handle)

#ifdef _WIN64
static void CheckUnchanged(int Line, const char *Service, NTSTATUS Status, HANDLE Handle)
{
    ok_(__FILE__, Line)(!NT_SUCCESS(Status), "%s: status 0x%lx, expected a failure\n", Service, Status);
    if (NT_SUCCESS(Status))
    {
        if (Handle && Handle != SENTINEL) NtClose(Handle);
        return;
    }
    ok_(__FILE__, Line)(Handle == SENTINEL, "%s: status 0x%lx, handle %p, expected it unchanged\n", Service, Status, Handle);
}
#define CHECK_UNCHANGED(Service) CheckUnchanged(__LINE__, Service, Status, Handle)
#endif

static void NativeChecks(void)
{
    HANDLE Handle, *ReadOnly;
    NTSTATUS Status;
    CLIENT_ID ClientId;
    CONTEXT Context;
    INITIAL_TEB InitialTeb;
    ULONG Old;
#ifdef _WIN64
    IO_STATUS_BLOCK Io;
    LARGE_INTEGER Value;
#endif

    /* The successful calls still return a handle */
    Handle = SENTINEL;
    Status = NtOpenDirectoryObject(&Handle, DIRECTORY_QUERY, Named(L"\\BaseNamedObjects"));
    ok_ntstatus(Status, STATUS_SUCCESS);
    ok(Handle != NULL && Handle != SENTINEL, "NtOpenDirectoryObject: handle %p\n", Handle);
    if (NT_SUCCESS(Status)) NtClose(Handle);
    Handle = SENTINEL;
    Status = NtCreateKeyedEvent(&Handle, EVENT_ALL_ACCESS, NULL, 0);
    ok_ntstatus(Status, STATUS_SUCCESS);
    ok(Handle != NULL && Handle != SENTINEL, "NtCreateKeyedEvent: handle %p\n", Handle);
    if (NT_SUCCESS(Status)) NtClose(Handle);
    Handle = SENTINEL;
    Status = NtCreateJobObject(&Handle, JOB_OBJECT_ALL_ACCESS, NULL);
    ok_ntstatus(Status, STATUS_SUCCESS);
    ok(Handle != NULL && Handle != SENTINEL, "NtCreateJobObject: handle %p\n", Handle);
    if (NT_SUCCESS(Status)) NtClose(Handle);

    /* Registry */
    Handle = SENTINEL;
    Status = NtOpenKey(&Handle, KEY_READ, Named(L"\\Registry\\Machine\\Software\\WoW64NullHandleNoSuchKey"));
    CHECK_FAILED("NtOpenKey");
    Handle = SENTINEL;
    Status = NtOpenKeyEx(&Handle, KEY_READ, Named(L"\\Registry\\Machine\\Software\\WoW64NullHandleNoSuchKey"), 0);
    CHECK_FAILED("NtOpenKeyEx");
    Handle = SENTINEL;
    Status = NtCreateKey(&Handle, KEY_ALL_ACCESS, Named(L"\\Registry\\User\\WoW64NullHandleNoSuchSid\\Sub"), 0, NULL, 0, NULL);
    CHECK_FAILED("NtCreateKey");

    /* Object directories, symbolic links, sections, keyed events and jobs */
    Handle = SENTINEL;
    Status = NtOpenDirectoryObject(&Handle, DIRECTORY_ALL_ACCESS, Named(MISSING_DIR));
    ok_ntstatus(Status, STATUS_OBJECT_NAME_NOT_FOUND);
    CHECK_FAILED("NtOpenDirectoryObject");
    Handle = SENTINEL;
    Status = NtCreateDirectoryObject(&Handle, DIRECTORY_ALL_ACCESS, Named(MISSING_DIR L"\\Directory"));
    CHECK_FAILED("NtCreateDirectoryObject");
    Handle = SENTINEL;
    Status = NtOpenSymbolicLinkObject(&Handle, SYMBOLIC_LINK_ALL_ACCESS, Named(MISSING_DIR));
    CHECK_FAILED("NtOpenSymbolicLinkObject");
    Handle = SENTINEL;
    Status = NtOpenSection(&Handle, SECTION_ALL_ACCESS, Named(MISSING_OBJECT));
    CHECK_FAILED("NtOpenSection");
    Handle = SENTINEL;
    Status = NtCreateKeyedEvent(&Handle, EVENT_ALL_ACCESS, Named(MISSING_DIR L"\\KeyedEvent"), 0);
    ok_ntstatus(Status, STATUS_OBJECT_PATH_NOT_FOUND);
    CHECK_FAILED("NtCreateKeyedEvent");
    Handle = SENTINEL;
    Status = NtCreateJobObject(&Handle, JOB_OBJECT_ALL_ACCESS, Named(MISSING_DIR L"\\Job"));
    ok_ntstatus(Status, STATUS_OBJECT_PATH_NOT_FOUND);
    CHECK_FAILED("NtCreateJobObject");

    /* Duplication of an invalid handle */
    Handle = SENTINEL;
    Status = NtDuplicateObject(NtCurrentProcess(), (HANDLE)(ULONG_PTR)0x1230, NtCurrentProcess(), &Handle,
                               0, 0, DUPLICATE_SAME_ACCESS);
    CHECK_FAILED("NtDuplicateObject");

    /* A thread in an invalid process, with an empty context and initial TEB. Windows 10 gives
     * STATUS_INVALID_PARAMETER; which of the two it checks first is unknown, so not implemented */
    RtlZeroMemory(&ClientId, sizeof(ClientId));
    RtlZeroMemory(&Context, sizeof(Context));
    RtlZeroMemory(&InitialTeb, sizeof(InitialTeb));
    Handle = SENTINEL;
    Status = NtCreateThread(&Handle, THREAD_ALL_ACCESS, NULL, (HANDLE)(ULONG_PTR)0x1230, &ClientId, &Context, &InitialTeb, TRUE);
    todo_if(is_reactos()) ok_ntstatus(Status, STATUS_INVALID_PARAMETER);
    CHECK_FAILED("NtCreateThread");

    /* An unwritable handle variable fails the call and is not written */
    Status = NtOpenDirectoryObject(NULL, DIRECTORY_ALL_ACCESS, Named(MISSING_DIR));
    ok_ntstatus(Status, STATUS_ACCESS_VIOLATION);
    Status = NtCreateJobObject(NULL, JOB_OBJECT_ALL_ACCESS, Named(MISSING_DIR L"\\Job"));
    ok_ntstatus(Status, STATUS_ACCESS_VIOLATION);
    ReadOnly = VirtualAlloc(NULL, PAGE_SIZE, MEM_COMMIT, PAGE_READWRITE);
    ok(ReadOnly != NULL, "VirtualAlloc failed %lu\n", GetLastError());
    if (!ReadOnly) return;
    *ReadOnly = SENTINEL;
    ok(VirtualProtect(ReadOnly, PAGE_SIZE, PAGE_READONLY, &Old), "VirtualProtect failed %lu\n", GetLastError());
    Status = NtOpenDirectoryObject(ReadOnly, DIRECTORY_ALL_ACCESS, Named(MISSING_DIR));
    ok_ntstatus(Status, STATUS_ACCESS_VIOLATION);
    ok(*ReadOnly == SENTINEL, "Handle %p\n", *ReadOnly);
    Status = NtCreateJobObject(ReadOnly, JOB_OBJECT_ALL_ACCESS, Named(MISSING_DIR L"\\Job"));
    ok_ntstatus(Status, STATUS_ACCESS_VIOLATION);
    ok(*ReadOnly == SENTINEL, "Handle %p\n", *ReadOnly);
    Status = NtCreateThread(ReadOnly, THREAD_ALL_ACCESS, NULL, (HANDLE)(ULONG_PTR)0x1230, &ClientId, &Context, &InitialTeb, TRUE);
    ok_ntstatus(Status, STATUS_ACCESS_VIOLATION);
    ok(*ReadOnly == SENTINEL, "Handle %p\n", *ReadOnly);
    VirtualFree(ReadOnly, 0, MEM_RELEASE);

#ifdef _WIN64
    /* These native services leave the variable alone */
    Handle = SENTINEL;
    Status = NtOpenFile(&Handle, FILE_GENERIC_READ, Named(L"\\??\\C:\\WoW64NullHandleNoSuchDir\\x.txt"), &Io,
                        FILE_SHARE_READ, FILE_SYNCHRONOUS_IO_NONALERT);
    CHECK_UNCHANGED("NtOpenFile");
    Handle = SENTINEL;
    Status = NtOpenEvent(&Handle, EVENT_ALL_ACCESS, Named(MISSING_OBJECT));
    CHECK_UNCHANGED("NtOpenEvent");
    Handle = SENTINEL;
    Status = NtCreateEvent(&Handle, EVENT_ALL_ACCESS, Named(MISSING_DIR L"\\Event"), NotificationEvent, FALSE);
    CHECK_UNCHANGED("NtCreateEvent");
    Handle = SENTINEL;
    Status = NtCreateSemaphore(&Handle, SEMAPHORE_ALL_ACCESS, NULL, 2, 1);
    CHECK_UNCHANGED("NtCreateSemaphore(count)");
    Handle = SENTINEL;
    Status = NtOpenTimer(&Handle, TIMER_ALL_ACCESS, Named(MISSING_OBJECT));
    CHECK_UNCHANGED("NtOpenTimer");
    Handle = SENTINEL;
    Status = NtOpenJobObject(&Handle, JOB_OBJECT_ALL_ACCESS, Named(MISSING_OBJECT));
    CHECK_UNCHANGED("NtOpenJobObject");
    Handle = SENTINEL;
    Value.QuadPart = PAGE_SIZE;
    Status = NtCreateSection(&Handle, SECTION_ALL_ACCESS, Named(MISSING_DIR L"\\Section"), &Value, PAGE_READWRITE, SEC_COMMIT, NULL);
    CHECK_UNCHANGED("NtCreateSection");
#endif
}

START_TEST(Wow64FailedOpenHandle)
{
    HANDLE Handle, *ReadOnly;
    NTSTATUS Status;
    IO_STATUS_BLOCK Io;
    LARGE_INTEGER Value;
    CLIENT_ID ClientId;
    UNICODE_STRING Target;
    CONTEXT Context;
    INITIAL_TEB InitialTeb;
    ULONG Old;
    BOOL Wow64 = FALSE;

    IsWow64Process(GetCurrentProcess(), &Wow64);
    if (!Wow64)
    {
        /* The native services differ per service; the contract below is the WoW64 layer's */
        NativeChecks();
        return;
    }

    /* A successful open still returns the handle */
    Handle = SENTINEL;
    Status = NtOpenKey(&Handle, KEY_READ, Named(L"\\Registry\\Machine\\Software"));
    ok_ntstatus(Status, STATUS_SUCCESS);
    ok(Handle != NULL && Handle != SENTINEL, "Handle %p\n", Handle);
    if (NT_SUCCESS(Status)) NtClose(Handle);

    /* Registry */
    Handle = SENTINEL;
    Status = NtOpenKey(&Handle, KEY_READ, Named(L"\\Registry\\Machine\\Software\\WoW64NullHandleNoSuchKey"));
    CHECK_FAILED("NtOpenKey");
    Handle = SENTINEL;
    Status = NtOpenKeyEx(&Handle, KEY_READ, Named(L"\\Registry\\Machine\\Software\\WoW64NullHandleNoSuchKey"), 0);
    CHECK_FAILED("NtOpenKeyEx");
    /* A missing parent; nothing is created */
    Handle = SENTINEL;
    Status = NtCreateKey(&Handle, KEY_ALL_ACCESS, Named(L"\\Registry\\User\\WoW64NullHandleNoSuchSid\\Sub"), 0, NULL, 0, NULL);
    CHECK_FAILED("NtCreateKey");

    /* Files */
    Handle = SENTINEL;
    Status = NtOpenFile(&Handle, FILE_GENERIC_READ, Named(L"\\??\\C:\\WoW64NullHandleNoSuchDir\\x.txt"), &Io,
                        FILE_SHARE_READ, FILE_SYNCHRONOUS_IO_NONALERT);
    CHECK_FAILED("NtOpenFile");
    Handle = SENTINEL;
    Status = NtCreateFile(&Handle, FILE_GENERIC_READ, Named(L"\\??\\C:\\WoW64NullHandleNoSuchDir\\x.txt"), &Io, NULL, 0,
                          FILE_SHARE_READ, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
    CHECK_FAILED("NtCreateFile");

    /* Named objects: a missing object to open, a missing directory to create in */
    Handle = SENTINEL;
    Status = NtOpenEvent(&Handle, EVENT_ALL_ACCESS, Named(MISSING_OBJECT));
    CHECK_FAILED("NtOpenEvent");
    Handle = SENTINEL;
    Status = NtCreateEvent(&Handle, EVENT_ALL_ACCESS, Named(MISSING_DIR L"\\Event"), NotificationEvent, FALSE);
    CHECK_FAILED("NtCreateEvent");
    Handle = SENTINEL;
    Status = NtOpenMutant(&Handle, MUTANT_ALL_ACCESS, Named(MISSING_OBJECT));
    CHECK_FAILED("NtOpenMutant");
    Handle = SENTINEL;
    Status = NtCreateMutant(&Handle, MUTANT_ALL_ACCESS, Named(MISSING_DIR L"\\Mutant"), FALSE);
    CHECK_FAILED("NtCreateMutant");
    Handle = SENTINEL;
    Status = NtOpenSemaphore(&Handle, SEMAPHORE_ALL_ACCESS, Named(MISSING_OBJECT));
    CHECK_FAILED("NtOpenSemaphore");
    Handle = SENTINEL;
    Status = NtCreateSemaphore(&Handle, SEMAPHORE_ALL_ACCESS, Named(MISSING_DIR L"\\Semaphore"), 0, 1);
    CHECK_FAILED("NtCreateSemaphore");
    /* A parameter the native service rejects */
    Handle = SENTINEL;
    Status = NtCreateSemaphore(&Handle, SEMAPHORE_ALL_ACCESS, NULL, 2, 1);
    CHECK_FAILED("NtCreateSemaphore(count)");
    Handle = SENTINEL;
    Status = NtOpenSection(&Handle, SECTION_ALL_ACCESS, Named(MISSING_OBJECT));
    CHECK_FAILED("NtOpenSection");
    Handle = SENTINEL;
    Value.QuadPart = PAGE_SIZE;
    Status = NtCreateSection(&Handle, SECTION_ALL_ACCESS, Named(MISSING_DIR L"\\Section"), &Value, PAGE_READWRITE, SEC_COMMIT, NULL);
    CHECK_FAILED("NtCreateSection");
    Handle = SENTINEL;
    Status = NtOpenDirectoryObject(&Handle, DIRECTORY_ALL_ACCESS, Named(MISSING_DIR));
    CHECK_FAILED("NtOpenDirectoryObject");
    Handle = SENTINEL;
    Status = NtCreateDirectoryObject(&Handle, DIRECTORY_ALL_ACCESS, Named(MISSING_DIR L"\\Directory"));
    CHECK_FAILED("NtCreateDirectoryObject");
    Handle = SENTINEL;
    Status = NtOpenSymbolicLinkObject(&Handle, SYMBOLIC_LINK_ALL_ACCESS, Named(MISSING_DIR));
    CHECK_FAILED("NtOpenSymbolicLinkObject");
    Handle = SENTINEL;
    RtlInitUnicodeString(&Target, L"\\Device");
    Status = NtCreateSymbolicLinkObject(&Handle, SYMBOLIC_LINK_ALL_ACCESS, Named(MISSING_DIR L"\\Link"), &Target);
    CHECK_FAILED("NtCreateSymbolicLinkObject");
    Handle = SENTINEL;
    Status = NtOpenTimer(&Handle, TIMER_ALL_ACCESS, Named(MISSING_OBJECT));
    CHECK_FAILED("NtOpenTimer");
    Handle = SENTINEL;
    Status = NtCreateTimer(&Handle, TIMER_ALL_ACCESS, Named(MISSING_DIR L"\\Timer"), NotificationTimer);
    CHECK_FAILED("NtCreateTimer");
    Handle = SENTINEL;
    Status = NtOpenIoCompletion(&Handle, IO_COMPLETION_ALL_ACCESS, Named(MISSING_OBJECT));
    CHECK_FAILED("NtOpenIoCompletion");
    Handle = SENTINEL;
    Status = NtCreateIoCompletion(&Handle, IO_COMPLETION_ALL_ACCESS, Named(MISSING_DIR L"\\Completion"), 0);
    CHECK_FAILED("NtCreateIoCompletion");
    Handle = SENTINEL;
    Status = NtCreateKeyedEvent(&Handle, EVENT_ALL_ACCESS, Named(MISSING_DIR L"\\KeyedEvent"), 0);
    CHECK_FAILED("NtCreateKeyedEvent");
    Handle = SENTINEL;
    Status = NtOpenJobObject(&Handle, JOB_OBJECT_ALL_ACCESS, Named(MISSING_OBJECT));
    CHECK_FAILED("NtOpenJobObject");
    Handle = SENTINEL;
    Status = NtCreateJobObject(&Handle, JOB_OBJECT_ALL_ACCESS, Named(MISSING_DIR L"\\Job"));
    CHECK_FAILED("NtCreateJobObject");

    /* Processes and threads by a client ID that does not exist */
    InitializeObjectAttributes(&Attributes, NULL, 0, NULL, NULL);
    ClientId.UniqueProcess = (HANDLE)(ULONG_PTR)0x7ffffff0;
    ClientId.UniqueThread = NULL;
    Handle = SENTINEL;
    Status = NtOpenProcess(&Handle, PROCESS_QUERY_INFORMATION, &Attributes, &ClientId);
    CHECK_FAILED("NtOpenProcess");
    ClientId.UniqueProcess = NULL;
    ClientId.UniqueThread = (HANDLE)(ULONG_PTR)0x7ffffff0;
    Handle = SENTINEL;
    Status = NtOpenThread(&Handle, THREAD_QUERY_INFORMATION, &Attributes, &ClientId);
    CHECK_FAILED("NtOpenThread");

    /* Tokens: an invalid source handle, or a thread without a token */
    Handle = SENTINEL;
    Status = NtOpenProcessToken((HANDLE)(ULONG_PTR)0x1230, TOKEN_QUERY, &Handle);
    CHECK_FAILED("NtOpenProcessToken");
    Handle = SENTINEL;
    Status = NtOpenProcessTokenEx((HANDLE)(ULONG_PTR)0x1230, TOKEN_QUERY, 0, &Handle);
    CHECK_FAILED("NtOpenProcessTokenEx");
    Handle = SENTINEL;
    Status = NtOpenThreadToken(NtCurrentThread(), TOKEN_QUERY, FALSE, &Handle);
    CHECK_FAILED("NtOpenThreadToken");
    Handle = SENTINEL;
    Status = NtOpenThreadTokenEx(NtCurrentThread(), TOKEN_QUERY, FALSE, 0, &Handle);
    CHECK_FAILED("NtOpenThreadTokenEx");
    Handle = SENTINEL;
    Status = NtDuplicateToken((HANDLE)(ULONG_PTR)0x1230, TOKEN_ALL_ACCESS, NULL, FALSE, TokenPrimary, &Handle);
    CHECK_FAILED("NtDuplicateToken");
    Handle = SENTINEL;
    Status = NtFilterToken((HANDLE)(ULONG_PTR)0x1230, 0, NULL, NULL, NULL, &Handle);
    CHECK_FAILED("NtFilterToken");

    /* Duplication of an invalid handle */
    Handle = SENTINEL;
    Status = NtDuplicateObject(NtCurrentProcess(), (HANDLE)(ULONG_PTR)0x1230, NtCurrentProcess(), &Handle,
                               0, 0, DUPLICATE_SAME_ACCESS);
    CHECK_FAILED("NtDuplicateObject");

    /* A thread in an invalid process */
    RtlZeroMemory(&Context, sizeof(Context));
    RtlZeroMemory(&InitialTeb, sizeof(InitialTeb));
    Handle = SENTINEL;
    Status = NtCreateThread(&Handle, THREAD_ALL_ACCESS, NULL, (HANDLE)(ULONG_PTR)0x1230, &ClientId, &Context, &InitialTeb, TRUE);
    CHECK_FAILED("NtCreateThread");

    /* A failure before the native call (the object name cannot be read) leaves the variable */
    InitializeObjectAttributes(&Attributes, (PUNICODE_STRING)(ULONG_PTR)0x10, OBJ_CASE_INSENSITIVE, NULL, NULL);
    Handle = SENTINEL;
    Status = NtOpenEvent(&Handle, EVENT_ALL_ACCESS, &Attributes);
    ok_ntstatus(Status, STATUS_ACCESS_VIOLATION);
    ok(Handle == SENTINEL, "Handle %p\n", Handle);

    /* An unwritable handle variable fails the call and is not written */
    Status = NtOpenEvent(NULL, EVENT_ALL_ACCESS, Named(MISSING_OBJECT));
    ok_ntstatus(Status, STATUS_ACCESS_VIOLATION);
    ReadOnly = VirtualAlloc(NULL, PAGE_SIZE, MEM_COMMIT, PAGE_READWRITE);
    ok(ReadOnly != NULL, "VirtualAlloc failed %lu\n", GetLastError());
    if (!ReadOnly) return;
    *ReadOnly = SENTINEL;
    ok(VirtualProtect(ReadOnly, PAGE_SIZE, PAGE_READONLY, &Old), "VirtualProtect failed %lu\n", GetLastError());
    Status = NtOpenKey(ReadOnly, KEY_READ, Named(L"\\Registry\\Machine\\Software\\WoW64NullHandleNoSuchKey"));
    ok_ntstatus(Status, STATUS_ACCESS_VIOLATION);
    ok(*ReadOnly == SENTINEL, "Handle %p\n", *ReadOnly);
    Status = NtOpenEvent(ReadOnly, EVENT_ALL_ACCESS, Named(MISSING_OBJECT));
    ok_ntstatus(Status, STATUS_ACCESS_VIOLATION);
    ok(*ReadOnly == SENTINEL, "Handle %p\n", *ReadOnly);
    VirtualFree(ReadOnly, 0, MEM_RELEASE);
}
