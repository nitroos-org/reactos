/* ReactOS WoW64 filesystem namespace. SPDX-License-Identifier: GPL-2.0-or-later */
#include "wow64p.h"

static UNICODE_STRING DosRoot, ObjectRoot;
static WCHAR DosRootBuffer[MAX_PATH + 4];
static PVOID ObjectRootBuffer;
/* \Windows on the system volume, when it is a junction to the system directory (setup makes
 * one on NTFS installs): C:\Windows\System32 is the same directory as C:\ReactOS\System32
 * and is redirected the same way. */
static UNICODE_STRING DosAlias, ObjectAlias;
static WCHAR DosAliasBuffer[MAX_PATH + 4], ObjectAliasBuffer[MAX_PATH + 4];

static NTSTATUS ObjectName(HANDLE Handle, PVOID *Buffer)
{
    ULONG Capacity = 1024, Length;
    NTSTATUS Status;
    for (;;)
    {
        *Buffer = RtlAllocateHeap(RtlGetProcessHeap(), 0, Capacity);
        if (!*Buffer) return STATUS_NO_MEMORY;
        Length = 0;
        Status = NtQueryObject(Handle, ObjectNameInformation, *Buffer, Capacity, &Length);
        if (NT_SUCCESS(Status)) return Status;
        RtlFreeHeap(RtlGetProcessHeap(), 0, *Buffer);
        *Buffer = NULL;
        if (Status != STATUS_INFO_LENGTH_MISMATCH && Status != STATUS_BUFFER_TOO_SMALL &&
            Status != STATUS_BUFFER_OVERFLOW) return Status;
        if (Capacity >= 0x20000) return STATUS_NAME_TOO_LONG;
        /* Filesystem name queries may first report only their fixed header. */
        Capacity = max(Length, Capacity * 2);
        if (Capacity > 0x20000) return STATUS_NAME_TOO_LONG;
    }
}

/* Enables the \Windows aliases only if \Windows resolves to the system directory itself:
 * a different directory of that name (another Windows on this volume) is not ours to redirect. */
static VOID InitializeWindowsAlias(VOID)
{
    static const WCHAR Windows[] = L"\\Windows";
    OBJECT_ATTRIBUTES Attributes;
    IO_STATUS_BLOCK Io;
    UNICODE_STRING Alias, Resolved, ObjectTail, SystemTail;
    PVOID Buffer = NULL;
    HANDLE Directory;
    PCWSTR Root = SharedUserData->NtSystemRoot;
    ULONG Tail, RootChars = ObjectRoot.Length / sizeof(WCHAR);
    WCHAR Drive[3] = {SharedUserData->NtSystemRoot[0], L':', UNICODE_NULL};
    BOOLEAN Same;

    if (Root[0] == UNICODE_NULL || Root[1] != L':' || Root[2] != L'\\') return;
    Tail = (ULONG)wcslen(Root) - 2;
    if (RootChars <= Tail) return;
    ObjectTail.Buffer = ObjectRoot.Buffer + RootChars - Tail;
    ObjectTail.Length = ObjectTail.MaximumLength = (USHORT)(Tail * sizeof(WCHAR));
    RtlInitUnicodeString(&SystemTail, Root + 2);
    if (!RtlEqualUnicodeString(&ObjectTail, &SystemTail, TRUE)) return;
    RootChars -= Tail;
    if (RootChars + RTL_NUMBER_OF(Windows) > RTL_NUMBER_OF(ObjectAliasBuffer)) return;

    RtlInitEmptyUnicodeString(&Alias, DosAliasBuffer, sizeof(DosAliasBuffer));
    RtlAppendUnicodeToString(&Alias, L"\\??\\");
    RtlAppendUnicodeToString(&Alias, Drive);
    RtlAppendUnicodeToString(&Alias, Windows);
    InitializeObjectAttributes(&Attributes, &Alias, OBJ_CASE_INSENSITIVE, NULL, NULL);
    if (!NT_SUCCESS(NtOpenFile(&Directory, FILE_READ_ATTRIBUTES | SYNCHRONIZE, &Attributes, &Io,
                               FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                               FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT)))
        return;
    Same = NT_SUCCESS(ObjectName(Directory, &Buffer));
    NtClose(Directory);
    if (!Same) return;
    Resolved = ((OBJECT_NAME_INFORMATION *)Buffer)->Name;
    Same = RtlEqualUnicodeString(&Resolved, &ObjectRoot, TRUE);
    RtlFreeHeap(RtlGetProcessHeap(), 0, Buffer);
    if (!Same) return;

    DosAlias = Alias;
    RtlInitEmptyUnicodeString(&ObjectAlias, ObjectAliasBuffer, sizeof(ObjectAliasBuffer));
    ObjectAlias.Length = (USHORT)(RootChars * sizeof(WCHAR));
    RtlCopyMemory(ObjectAliasBuffer, ObjectRoot.Buffer, ObjectAlias.Length);
    RtlAppendUnicodeToString(&ObjectAlias, Windows);
}

NTSTATUS Wow64InitializeRedirection(VOID)
{
    OBJECT_ATTRIBUTES Attributes;
    IO_STATUS_BLOCK Io;
    HANDLE Directory;
    NTSTATUS Status;
    RtlInitEmptyUnicodeString(&DosRoot, DosRootBuffer, sizeof(DosRootBuffer));
    RtlAppendUnicodeToString(&DosRoot, L"\\??\\");
    RtlAppendUnicodeToString(&DosRoot, SharedUserData->NtSystemRoot);
    InitializeObjectAttributes(&Attributes, &DosRoot, OBJ_CASE_INSENSITIVE, NULL, NULL);
    Status = NtOpenFile(&Directory, FILE_READ_ATTRIBUTES | SYNCHRONIZE, &Attributes, &Io,
                        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT);
    if (!NT_SUCCESS(Status)) return Status;
    Status = ObjectName(Directory, &ObjectRootBuffer);
    NtClose(Directory);
    if (NT_SUCCESS(Status)) ObjectRoot = ((OBJECT_NAME_INFORMATION *)ObjectRootBuffer)->Name;
    if (NT_SUCCESS(Status)) InitializeWindowsAlias();
    return Status;
}

static BOOLEAN Prefix(const UNICODE_STRING *Path, const UNICODE_STRING *Root)
{
    return RtlPrefixUnicodeString(Root, Path, TRUE) &&
           (Path->Length == Root->Length || Path->Buffer[Root->Length / sizeof(WCHAR)] == L'\\');
}

static BOOLEAN Component(const UNICODE_STRING *Path, PCWSTR Text)
{
    UNICODE_STRING Name;
    RtlInitUnicodeString(&Name, Text);
    return Prefix(Path, &Name);
}

NTSTATUS Wow64RedirectFile(OBJECT_ATTRIBUTES *Attributes, UNICODE_STRING *Name, PVOID *Buffer)
{
    static const UNICODE_STRING SystemRoot = RTL_CONSTANT_STRING(L"\\SystemRoot");
    static const UNICODE_STRING PipeRoot = RTL_CONSTANT_STRING(L"\\Device\\NamedPipe");
    static const PCWSTR Shared[] = {L"catroot", L"catroot2", L"driverstore", L"drivers\\etc", L"logfiles", L"spool"};
    WOW64_CPU_STATE *Cpu = NtCurrentTeb()->TlsSlots[WOW64_TLS_CPU];
    UNICODE_STRING Path, Tail, RootName;
    ULONG RootLength, Offset, Remove, Insert, Length, i;
    PCWSTR Replacement;
    NTSTATUS Status;
    PVOID RootBuffer = NULL;
    PWSTR Captured;
    BOOLEAN PipeRelative;

    if (!Attributes->ObjectName) return STATUS_SUCCESS;
    Path = *Attributes->ObjectName;
    if (Path.Length & 1) return STATUS_OBJECT_NAME_INVALID;
    if (!Path.Length) return STATUS_SUCCESS;

    if (Attributes->RootDirectory)
    {
        /* Capture root-relative names before substituting directories. The
         * actual object name also covers drive aliases and device paths. */
        Status = ObjectName(Attributes->RootDirectory, &RootBuffer);
        if (!NT_SUCCESS(Status)) return Status;
        RootName = ((OBJECT_NAME_INFORMATION *)RootBuffer)->Name;
        if (Path.Buffer[0] != L'\\' && Prefix(&RootName, &PipeRoot))
        {
            struct { ULONG Length; WCHAR Name[4]; } FileName;
            IO_STATUS_BLOCK Io;
            /* NPFS includes structure padding in the object-name query's
             * returned byte count. Use FileNameLength to recognize its root;
             * bytes following that counted name are not part of the path. */
            Status = NtQueryInformationFile(Attributes->RootDirectory, &Io,
                                            &FileName, sizeof(FileName), FileNameInformation);
            if (NT_SUCCESS(Status) && FileName.Length == sizeof(WCHAR) &&
                FileName.Name[0] == L'\\')
                RootName = PipeRoot;
        }
        if (RootName.Length && RootName.Buffer[RootName.Length / sizeof(WCHAR) - 1] == L'\\')
            RootName.Length -= sizeof(WCHAR);
        PipeRelative = Path.Buffer[0] != L'\\' && RtlEqualUnicodeString(&RootName, &PipeRoot, TRUE);
        Length = RootName.Length + sizeof(WCHAR) + Path.Length;
        if (Length > MAXUSHORT - sizeof(WCHAR))
        {
            RtlFreeHeap(RtlGetProcessHeap(), 0, RootBuffer);
            return STATUS_NAME_TOO_LONG;
        }
        Captured = RtlAllocateHeap(RtlGetProcessHeap(), 0, Length + sizeof(WCHAR));
        if (!Captured)
        {
            RtlFreeHeap(RtlGetProcessHeap(), 0, RootBuffer);
            return STATUS_NO_MEMORY;
        }
        /* Ownership is published before any guest input is read. */
        *Buffer = Captured;
        RtlCopyMemory(Captured, RootName.Buffer, RootName.Length);
        Captured[RootName.Length / sizeof(WCHAR)] = L'\\';
        RtlFreeHeap(RtlGetProcessHeap(), 0, RootBuffer);
        RtlCopyMemory((PUCHAR)Captured + RootName.Length + sizeof(WCHAR), Path.Buffer, Path.Length);
        Path.Buffer = Captured;
        Path.Length = Length;
        Path.MaximumLength = Length + sizeof(WCHAR);
        Captured[Length / sizeof(WCHAR)] = UNICODE_NULL;
        if (PipeRelative)
        {
            /* NPFS's legacy relative-open path mistakes its root CCB for a
             * DCB. The pipe root has a stable device name; issue the equivalent
             * absolute open from the guest without changing native NPFS. */
            *Name = Path;
            Attributes->ObjectName = Name;
            Attributes->RootDirectory = NULL;
            return STATUS_SUCCESS;
        }
    }

    if (Prefix(&Path, &DosRoot)) RootLength = DosRoot.Length;
    else if (Prefix(&Path, &ObjectRoot)) RootLength = ObjectRoot.Length;
    else if (Prefix(&Path, &SystemRoot)) RootLength = SystemRoot.Length;
    else if (DosAlias.Length && Prefix(&Path, &DosAlias)) RootLength = DosAlias.Length;
    else if (ObjectAlias.Length && Prefix(&Path, &ObjectAlias)) RootLength = ObjectAlias.Length;
    else return STATUS_SUCCESS;
    if (Path.Length <= RootLength) return STATUS_SUCCESS;
    Offset = RootLength + sizeof(WCHAR);
    Tail.Buffer = (PWSTR)((PUCHAR)Path.Buffer + Offset);
    Tail.Length = Tail.MaximumLength = Path.Length - Offset;
    if (Component(&Tail, L"Sysnative"))
    {
        Remove = 9 * sizeof(WCHAR);
        Replacement = L"System32";
    }
    else if (Component(&Tail, L"System32") && !Cpu->FsRedirectionDisabled)
    {
        Remove = 8 * sizeof(WCHAR);
        if (Tail.Length > Remove)
        {
            UNICODE_STRING Child = Tail;
            Child.Buffer += 9;
            Child.Length -= 9 * sizeof(WCHAR);
            for (i = 0; i < RTL_NUMBER_OF(Shared); ++i)
                if (Component(&Child, Shared[i])) return STATUS_SUCCESS;
        }
        Replacement = L"SysWOW64";
    }
    else return STATUS_SUCCESS;

    Insert = 8 * sizeof(WCHAR);
    Length = Path.Length - Remove + Insert;
    if (Length > MAXUSHORT - sizeof(WCHAR)) return STATUS_NAME_TOO_LONG;
    Captured = RtlAllocateHeap(RtlGetProcessHeap(), 0, Length + sizeof(WCHAR));
    if (!Captured) return STATUS_NO_MEMORY;
    /* Path may still refer to guest memory. Retain both allocations through
     * the copy so an exception cannot leak the replacement. */
    _SEH2_TRY
    {
        RtlCopyMemory(Captured, Path.Buffer, Offset);
        RtlCopyMemory((PUCHAR)Captured + Offset, Replacement, Insert);
        RtlCopyMemory((PUCHAR)Captured + Offset + Insert, (PUCHAR)Path.Buffer + Offset + Remove,
                      Path.Length - Offset - Remove);
        Captured[Length / sizeof(WCHAR)] = UNICODE_NULL;
        Status = STATUS_SUCCESS;
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        Status = _SEH2_GetExceptionCode();
    }
    _SEH2_END;
    if (!NT_SUCCESS(Status))
    {
        RtlFreeHeap(RtlGetProcessHeap(), 0, Captured);
        return Status;
    }
    if (*Buffer) RtlFreeHeap(RtlGetProcessHeap(), 0, *Buffer);
    *Buffer = Captured;
    Name->Buffer = Captured;
    Name->Length = Length;
    Name->MaximumLength = Length + sizeof(WCHAR);
    Attributes->ObjectName = Name;
    Attributes->RootDirectory = NULL;
    return STATUS_SUCCESS;
}
