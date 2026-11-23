/*
 * PROJECT:     ReactOS Kernel
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Test for NtDuplicateObject
 * COPYRIGHT:   Copyright 2019 Thomas Faber (thomas.faber@reactos.org)
 *              Copyright 2026 Tomas Srnka (tomas.srnka@e2b.dev)
 */

#include "precomp.h"

#define OBJ_PROTECT_CLOSE 0x01

/*
 * Widening-duplicate contract (T127b + SEC-dup-ro-section-widen).
 *
 * DuplicateHandle/NtDuplicateObject asking for MORE access than the source
 * handle holds re-evaluates the object's security descriptor and grants the
 * extra rights iff the SD grants them -- exactly as Windows (validated on
 * Win10 and Server 2008 R2). This is the Windows-correct behaviour that the
 * earlier blanket user-mode deny (T100) got wrong:
 *
 *   - Default-SD object (no caller SD): the widen SUCCEEDS. A reduced handle
 *     on an object the caller owns can be re-widened, because the (default or
 *     absent) SD grants it. Denying this broke 24 legitimate cases.
 *
 *   - NULL-DACL object (SD present, DACL present flag set but DACL pointer
 *     NULL): a NULL DACL grants EVERYONE full access -- so the widen SUCCEEDS.
 *     This is Windows-normal, and is the shape most "deny-all" microtests
 *     accidentally build (SetDacl with a NULL ACL pointer).
 *
 *   - Restrictive-SD / deny-all-DACL object (caller supplied a DACL that does
 *     NOT grant the wider right): the widen is DENIED, because SeAccessCheck
 *     re-evaluates the SD and the DACL refuses it. This is what blocks a
 *     read-only shared-memory section from being re-duplicated writable
 *     (Chromium/Electron read-only SHM validation).
 */

static PSID
GetCurrentUserSid(PBYTE Buffer, ULONG BufferSize)
{
    NTSTATUS Status;
    HANDLE Token = NULL;
    ULONG RetLen = 0;
    PTOKEN_USER UserInfo;

    Status = NtOpenProcessToken(NtCurrentProcess(), TOKEN_QUERY, &Token);
    if (!NT_SUCCESS(Status))
    {
        trace("NtOpenProcessToken failed 0x%lx\n", Status);
        return NULL;
    }

    Status = NtQueryInformationToken(Token, TokenUser, Buffer, BufferSize, &RetLen);
    NtClose(Token);
    if (!NT_SUCCESS(Status))
    {
        trace("NtQueryInformationToken(TokenUser) failed 0x%lx\n", Status);
        return NULL;
    }

    UserInfo = (PTOKEN_USER)Buffer;
    return UserInfo->User.Sid;
}

/* Create an anonymous (unnamed) section with an optional explicit SD. */
static NTSTATUS
CreateTestSection(PHANDLE SectionHandle, PSECURITY_DESCRIPTOR Sd)
{
    OBJECT_ATTRIBUTES ObjectAttributes;
    LARGE_INTEGER MaxSize;

    MaxSize.QuadPart = 0x1000;
    InitializeObjectAttributes(&ObjectAttributes, NULL, 0, NULL, Sd);

    return NtCreateSection(SectionHandle,
                           SECTION_ALL_ACCESS,
                           &ObjectAttributes,
                           &MaxSize,
                           PAGE_READWRITE,
                           SEC_COMMIT,
                           NULL);
}

static void
TestDefaultSdWidening(void)
{
    NTSTATUS Status;
    HANDLE hSection = NULL, hReadOnly = NULL, hWidened = NULL;
    OBJECT_BASIC_INFORMATION obi;

    /* Anonymous section, no caller SD -> default/absent security. */
    Status = CreateTestSection(&hSection, NULL);
    ok_hex(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status))
        return;

    /* Reduce to a read-only handle. */
    Status = NtDuplicateObject(NtCurrentProcess(), hSection, NtCurrentProcess(),
                               &hReadOnly, SECTION_MAP_READ, 0, 0);
    ok_hex(Status, STATUS_SUCCESS);

    /* Widen the read-only handle back to write: default SD -> SUCCEEDS. */
    hWidened = NULL;
    Status = NtDuplicateObject(NtCurrentProcess(), hReadOnly, NtCurrentProcess(),
                               &hWidened, SECTION_MAP_WRITE, 0, 0);
    trace("DEFAULT-SD widen RO->WRITE: Status=0x%lx handle=%p\n", Status, hWidened);
    ok_hex(Status, STATUS_SUCCESS);
    if (NT_SUCCESS(Status))
    {
        RtlZeroMemory(&obi, sizeof(obi));
        Status = NtQueryObject(hWidened, ObjectBasicInformation, &obi, sizeof(obi), NULL);
        ok_hex(Status, STATUS_SUCCESS);
        ok((obi.GrantedAccess & SECTION_MAP_WRITE) != 0,
           "default-SD widen did not grant SECTION_MAP_WRITE, got 0x%lx\n",
           obi.GrantedAccess);
        NtClose(hWidened);
    }

    NtClose(hReadOnly);
    NtClose(hSection);
}

/*
 * NULL-DACL section: DACL present flag TRUE, DACL pointer NULL. A NULL DACL
 * grants everyone all access, so the write-widen SUCCEEDS -- Windows-normal.
 * This is the "deny-all DACL" that a microtest builds by accident.
 */
static void
TestNullDaclWidening(void)
{
    NTSTATUS Status;
    HANDLE hSection = NULL, hReadOnly = NULL, hWidened = NULL;
    BYTE SidBuffer[256];
    PSID UserSid;
    SECURITY_DESCRIPTOR Sd;
    OBJECT_BASIC_INFORMATION obi;

    UserSid = GetCurrentUserSid(SidBuffer, sizeof(SidBuffer));
    if (UserSid == NULL) { skip("no SID\n"); return; }

    Status = RtlCreateSecurityDescriptor(&Sd, SECURITY_DESCRIPTOR_REVISION);
    ok_hex(Status, STATUS_SUCCESS);
    /* DaclPresent=TRUE, Dacl=NULL -> a NULL DACL (grants everyone). */
    Status = RtlSetDaclSecurityDescriptor(&Sd, TRUE, NULL, FALSE);
    ok_hex(Status, STATUS_SUCCESS);
    Status = RtlSetOwnerSecurityDescriptor(&Sd, UserSid, FALSE);
    ok_hex(Status, STATUS_SUCCESS);

    Status = CreateTestSection(&hSection, &Sd);
    ok_hex(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status)) return;

    Status = NtDuplicateObject(NtCurrentProcess(), hSection, NtCurrentProcess(),
                               &hReadOnly, SECTION_MAP_READ, 0, 0);
    ok_hex(Status, STATUS_SUCCESS);

    hWidened = NULL;
    Status = NtDuplicateObject(NtCurrentProcess(), hReadOnly, NtCurrentProcess(),
                               &hWidened, SECTION_MAP_WRITE, 0, 0);
    trace("NULL-DACL widen RO->WRITE: Status=0x%lx handle=%p\n", Status, hWidened);
    ok_hex(Status, STATUS_SUCCESS);
    if (NT_SUCCESS(Status))
    {
        RtlZeroMemory(&obi, sizeof(obi));
        NtQueryObject(hWidened, ObjectBasicInformation, &obi, sizeof(obi), NULL);
        trace("NULL-DACL widened GrantedAccess=0x%lx\n", obi.GrantedAccess);
        NtClose(hWidened);
    }

    NtClose(hReadOnly);
    NtClose(hSection);
}

static void
TestRestrictiveSdWidening(void)
{
    NTSTATUS Status;
    HANDLE hSection = NULL, hReadOnly = NULL, hWidened = NULL;
    BYTE SidBuffer[256];
    BYTE DaclBuffer[256];
    PSID UserSid;
    PACL Dacl = (PACL)DaclBuffer;
    SECURITY_DESCRIPTOR Sd;

    UserSid = GetCurrentUserSid(SidBuffer, sizeof(SidBuffer));
    if (UserSid == NULL)
    {
        skip("Could not obtain current user SID\n");
        return;
    }

    /* DACL that grants the caller READ only -- deliberately no SECTION_MAP_WRITE. */
    Status = RtlCreateAcl(Dacl, sizeof(DaclBuffer), ACL_REVISION);
    ok_hex(Status, STATUS_SUCCESS);
    Status = RtlAddAccessAllowedAce(Dacl, ACL_REVISION,
                                    SECTION_MAP_READ | READ_CONTROL, UserSid);
    ok_hex(Status, STATUS_SUCCESS);

    Status = RtlCreateSecurityDescriptor(&Sd, SECURITY_DESCRIPTOR_REVISION);
    ok_hex(Status, STATUS_SUCCESS);
    Status = RtlSetDaclSecurityDescriptor(&Sd, TRUE, Dacl, FALSE);
    ok_hex(Status, STATUS_SUCCESS);
    Status = RtlSetOwnerSecurityDescriptor(&Sd, UserSid, FALSE);
    ok_hex(Status, STATUS_SUCCESS);

    /* Create is not access-checked: the creator still gets SECTION_ALL_ACCESS. */
    Status = CreateTestSection(&hSection, &Sd);
    ok_hex(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status))
        return;

    /* Reduce to a read-only handle (the DACL grants read, so this is fine). */
    Status = NtDuplicateObject(NtCurrentProcess(), hSection, NtCurrentProcess(),
                               &hReadOnly, SECTION_MAP_READ, 0, 0);
    ok_hex(Status, STATUS_SUCCESS);

    /*
     * Widen the read-only handle to write. The section carries a restrictive
     * SD that does not grant SECTION_MAP_WRITE, so the re-evaluation must DENY.
     * This is the Chromium read-only-SHM validation shape.
     */
    hWidened = NULL;
    Status = NtDuplicateObject(NtCurrentProcess(), hReadOnly, NtCurrentProcess(),
                               &hWidened, SECTION_MAP_WRITE, 0, 0);
    trace("RESTRICTIVE-SD (read-only DACL) widen RO->WRITE: Status=0x%lx handle=%p\n",
          Status, hWidened);
    ok_hex(Status, STATUS_ACCESS_DENIED);
    ok(hWidened == NULL, "restrictive-SD widen unexpectedly granted handle %p\n", hWidened);
    if (NT_SUCCESS(Status))
        NtClose(hWidened);

    /* A same-or-lesser (read) re-duplicate is still allowed by the DACL. */
    hWidened = NULL;
    Status = NtDuplicateObject(NtCurrentProcess(), hReadOnly, NtCurrentProcess(),
                               &hWidened, SECTION_MAP_READ, 0, 0);
    ok_hex(Status, STATUS_SUCCESS);
    if (NT_SUCCESS(Status))
        NtClose(hWidened);

    NtClose(hReadOnly);
    NtClose(hSection);
}

/*
 * Genuine deny-all DACL: DACL present with ZERO ACEs. SeAccessCheck grants
 * nothing from such a DACL (the owner gets only implicit READ_CONTROL/WRITE_DAC,
 * never SECTION_MAP_WRITE), so the write-widen MUST be denied. This is the
 * literal "deny-all DACL" the SEC-dup-ro-section-widen ticket described.
 */
static void
TestDenyAllDaclWidening(void)
{
    NTSTATUS Status;
    HANDLE hSection = NULL, hReadOnly = NULL, hWidened = NULL;
    BYTE SidBuffer[256];
    BYTE DaclBuffer[256];
    PSID UserSid;
    PACL Dacl = (PACL)DaclBuffer;
    SECURITY_DESCRIPTOR Sd;

    UserSid = GetCurrentUserSid(SidBuffer, sizeof(SidBuffer));
    if (UserSid == NULL) { skip("no SID\n"); return; }

    /* Empty DACL: present, revision set, but NO ACEs -> denies everyone. */
    Status = RtlCreateAcl(Dacl, sizeof(DaclBuffer), ACL_REVISION);
    ok_hex(Status, STATUS_SUCCESS);

    Status = RtlCreateSecurityDescriptor(&Sd, SECURITY_DESCRIPTOR_REVISION);
    ok_hex(Status, STATUS_SUCCESS);
    Status = RtlSetDaclSecurityDescriptor(&Sd, TRUE, Dacl, FALSE);
    ok_hex(Status, STATUS_SUCCESS);
    Status = RtlSetOwnerSecurityDescriptor(&Sd, UserSid, FALSE);
    ok_hex(Status, STATUS_SUCCESS);

    Status = CreateTestSection(&hSection, &Sd);
    ok_hex(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status)) return;

    /* RO reduce is not a widen -> always allowed. */
    Status = NtDuplicateObject(NtCurrentProcess(), hSection, NtCurrentProcess(),
                               &hReadOnly, SECTION_MAP_READ, 0, 0);
    ok_hex(Status, STATUS_SUCCESS);

    /* Write-widen must be DENIED by the empty DACL. */
    hWidened = NULL;
    Status = NtDuplicateObject(NtCurrentProcess(), hReadOnly, NtCurrentProcess(),
                               &hWidened, SECTION_MAP_WRITE, 0, 0);
    trace("DENY-ALL-DACL (empty DACL) widen RO->WRITE: Status=0x%lx handle=%p\n",
          Status, hWidened);
    ok_hex(Status, STATUS_ACCESS_DENIED);
    ok(hWidened == NULL, "deny-all-DACL widen unexpectedly granted handle %p\n", hWidened);
    if (NT_SUCCESS(Status))
        NtClose(hWidened);

    NtClose(hReadOnly);
    NtClose(hSection);
}

/*
 * A target process handle that cannot be used (measured on Windows Server 2022, DuplicateHandle): ERROR_INVALID_HANDLE for a
 * handle that is none and for a handle that is no process, ERROR_ACCESS_DENIED for a process handle without
 * PROCESS_DUP_HANDLE; with DUPLICATE_CLOSE_SOURCE the source handle is closed all the same and the error is returned,
 * with a NULL target process handle the call succeeds and closes the source.
 */
static HANDLE
MakeEvent(void)
{
    HANDLE Event = NULL;
    NTSTATUS Status = NtCreateEvent(&Event, EVENT_ALL_ACCESS, NULL, NotificationEvent, FALSE);

    ok_hex(Status, STATUS_SUCCESS);
    return Event;
}

static BOOLEAN
IsOpen(HANDLE Handle)
{
    OBJECT_HANDLE_FLAG_INFORMATION Flags;

    return NT_SUCCESS(NtQueryObject(Handle, ObjectHandleFlagInformation, &Flags, sizeof(Flags), NULL));
}

static void
TestTargetProcessStatus(void)
{
    static const struct
    {
        const char *Name;
        int Kind;           /* 0 invalid value, 1 process without PROCESS_DUP_HANDLE, 2 an event, 3 NULL */
        NTSTATUS Expected;
    } Rows[] =
    {
        { "invalid handle", 0, STATUS_INVALID_HANDLE },
        { "process without PROCESS_DUP_HANDLE", 1, STATUS_ACCESS_DENIED },
        { "event", 2, STATUS_OBJECT_TYPE_MISMATCH },
        { "NULL", 3, STATUS_SUCCESS },
    };
    HANDLE LimitedProcess = NULL, Event2 = MakeEvent();
    CLIENT_ID Cid;
    OBJECT_ATTRIBUTES Oa;
    NTSTATUS Status;
    ULONG Row, Close;

    InitializeObjectAttributes(&Oa, NULL, 0, NULL, NULL);
    Cid.UniqueProcess = (HANDLE)(ULONG_PTR)GetCurrentProcessId();
    Cid.UniqueThread = NULL;
    Status = NtOpenProcess(&LimitedProcess, PROCESS_QUERY_LIMITED_INFORMATION, &Oa, &Cid);
    ok_hex(Status, STATUS_SUCCESS);

    for (Row = 0; Row < RTL_NUMBER_OF(Rows); Row++)
    {
        for (Close = 0; Close < 2; Close++)
        {
            HANDLE Source = MakeEvent(), Target, Out = (HANDLE)(ULONG_PTR)0x77;
            BOOLEAN Open;

            switch (Rows[Row].Kind)
            {
                case 0: Target = (HANDLE)(ULONG_PTR)0x1234; break;
                case 1: Target = LimitedProcess; break;
                case 2: Target = Event2; break;
                default: Target = NULL; break;
            }

            Status = NtDuplicateObject(NtCurrentProcess(), Source, Target, &Out, 0, 0,
                                       Close ? DUPLICATE_CLOSE_SOURCE : 0);
            Open = IsOpen(Source);
            if (Rows[Row].Kind == 3 && !Close)
            {
                /* No target at all and nothing to close: not a request */
                ok_hex(Status, STATUS_INVALID_PARAMETER);
            }
            else
            {
                ok(Status == Rows[Row].Expected, "%s, close source %lu: status 0x%08lx, expected 0x%08lx\n",
                   Rows[Row].Name, Close, Status, Rows[Row].Expected);
            }
            ok(Out == NULL, "%s, close source %lu: the target handle is %p\n", Rows[Row].Name, Close, Out);
            ok(Open == !Close, "%s, close source %lu: the source handle is %s\n", Rows[Row].Name, Close,
               Open ? "open" : "closed");
            if (Open)
                NtClose(Source);
        }
    }

    /* The same through kernel32: the errors Windows gives */
    {
        HANDLE Source = MakeEvent(), Out = (HANDLE)(ULONG_PTR)0x77;
        BOOL Ret;

        SetLastError(0xdeadbeef);
        Ret = DuplicateHandle(GetCurrentProcess(), Source, (HANDLE)(ULONG_PTR)0x1234, &Out, 0, FALSE, DUPLICATE_CLOSE_SOURCE);
        ok(!Ret && GetLastError() == ERROR_INVALID_HANDLE, "invalid target: ret %d, error %lu\n", Ret, GetLastError());
        ok(!IsOpen(Source), "invalid target: the source handle is still open\n");

        Source = MakeEvent();
        SetLastError(0xdeadbeef);
        Ret = DuplicateHandle(GetCurrentProcess(), Source, LimitedProcess, &Out, 0, FALSE, DUPLICATE_CLOSE_SOURCE);
        ok(!Ret && GetLastError() == ERROR_ACCESS_DENIED, "limited process target: ret %d, error %lu\n", Ret, GetLastError());
        ok(!IsOpen(Source), "limited process target: the source handle is still open\n");
    }

    NtClose(LimitedProcess);
    NtClose(Event2);
}

START_TEST(NtDuplicateObject)
{
    NTSTATUS Status;
    HANDLE Handle;

    Handle = NULL;
    Status = NtDuplicateObject(NtCurrentProcess(),
                               NtCurrentProcess(),
                               NtCurrentProcess(),
                               &Handle,
                               GENERIC_ALL,
                               OBJ_PROTECT_CLOSE,
                               0);
    ok_hex(Status, STATUS_SUCCESS);
    ok(Handle != NULL && Handle != NtCurrentProcess(),
        "Handle = %p\n", Handle);
    Status = NtClose(Handle);
    ok_hex(Status, STATUS_HANDLE_NOT_CLOSABLE);

    /* Default-SD object: a widening duplicate SUCCEEDS (Windows-normal). */
    TestDefaultSdWidening();

    /* NULL-DACL object: a widening duplicate SUCCEEDS (NULL DACL grants all). */
    TestNullDaclWidening();

    /* Restrictive-SD object (read-only DACL): a widening duplicate is DENIED. */
    TestRestrictiveSdWidening();

    /* Deny-all DACL (empty DACL): a widening duplicate is DENIED. */
    TestDenyAllDaclWidening();

    /* A target process handle that cannot be used */
    TestTargetProcessStatus();
}
