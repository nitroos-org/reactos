/*
 * PROJECT:     ReactOS WoW64
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Guest LPC to the LSA authentication port (LsaRegisterLogonProcess, LsaLogonUser)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * LPC messages carry the pointers and structure layouts of the sender, and lsass is a native
 * process. A guest connects only to \LsaAuthenticationPort, and each request for which a
 * translation exists is rebuilt in the native layout (the guest's pointers widen, so lsass reads
 * the caller's memory from them as before), and its reply is converted back. Any other port,
 * or an LSA request without a translation, is refused.
 */

#include "wow64p.h"
#include <ntsecapi.h>
#include <lsass/lsass.h>
#include <ntlmros.h>

/* The guest's PORT_MESSAGE: CLIENT_ID and the view size are 32 bits wide */
typedef struct
{
    USHORT DataLength, TotalLength, Type, DataInfoOffset;
    ULONG ProcessId, ThreadId, MessageId, ClientViewSize;
} WOW64_PORT_MESSAGE;
C_ASSERT(sizeof(WOW64_PORT_MESSAGE) == 24);

/* The guest's LSA_API_MSG body, which follows the header (from lsass.h compiled for i386) */
typedef struct
{
    WOW64_STRING OriginName;
    ULONG LogonType;
    ULONG AuthenticationPackage;
    ULONG AuthenticationInformation;
    ULONG AuthenticationInformationLength;
    ULONG LocalGroups;
    ULONG LocalGroupsCount;
    TOKEN_SOURCE SourceContext;
} WOW64_LSA_LOGON_REQUEST;
C_ASSERT(sizeof(WOW64_LSA_LOGON_REQUEST) == 48);

typedef struct
{
    ULONG ProfileBuffer;
    ULONG ProfileBufferLength;
    LUID LogonId;
    ULONG Token;
    ULONG Reserved1;
    ULONG Quotas[5]; /* QUOTA_LIMITS without the time limit: pool, working set and pagefile limits */
    ULONG Reserved2;
    LONGLONG TimeLimit;
    LONG SubStatus;
} WOW64_LSA_LOGON_REPLY;
C_ASSERT(FIELD_OFFSET(WOW64_LSA_LOGON_REPLY, Quotas) == 24);
C_ASSERT(FIELD_OFFSET(WOW64_LSA_LOGON_REPLY, TimeLimit) == 48);
C_ASSERT(FIELD_OFFSET(WOW64_LSA_LOGON_REPLY, SubStatus) == 56);

typedef struct
{
    ULONG ApiNumber;
    LONG Status;
    union
    {
        WOW64_LSA_LOGON_REQUEST LogonRequest;
        WOW64_LSA_LOGON_REPLY LogonReply;
        struct { ULONG PackageNameLength; CHAR PackageName[LSASS_MAX_PACKAGE_NAME_LENGTH + 1]; } LookupRequest;
        struct { ULONG Package; } LookupReply;
        struct { ULONG AuthenticationPackage, ProtocolSubmitBuffer, SubmitBufferLength; } CallRequest;
        struct { ULONG ProtocolReturnBuffer, ReturnBufferLength; LONG ProtocolStatus; } CallReply;
        struct { LUID LogonId; } SessionRequest;
        struct { ULONG SessionDataBuffer; } SessionReply;
        struct { ULONG Dummy; } EnumRequest;
        struct { ULONG LogonSessionCount, LogonSessionBuffer; } EnumReply;
        struct { ULONG InformationClass, NotificationEventHandle; BOOLEAN Register; } PolicyRequest;
    };
} WOW64_LSA_BODY;
C_ASSERT(FIELD_OFFSET(WOW64_LSA_BODY, LogonRequest) == 8);

/* SECURITY_LOGON_SESSION_DATA for i386: the string buffers and the SID hold offsets from the start of the block */
typedef struct
{
    ULONG Size;
    LUID LogonId;
    WOW64_STRING UserName, LogonDomain, AuthenticationPackage;
    ULONG LogonType, Session, Sid;
    LONGLONG LogonTime;
    WOW64_STRING LogonServer, DnsDomainName, Upn;
} WOW64_SESSION_DATA;
C_ASSERT(FIELD_OFFSET(WOW64_SESSION_DATA, LogonTime) == 48);
C_ASSERT(sizeof(WOW64_SESSION_DATA) == 80);

/* MSV1_0_CHANGEPASSWORD_REQUEST for i386 */
typedef struct
{
    ULONG MessageType;
    WOW64_STRING DomainName, AccountName, OldPassword, NewPassword;
    BOOLEAN Impersonating;
} WOW64_MSV1_0_CHANGEPASSWORD_REQUEST;
C_ASSERT(sizeof(WOW64_MSV1_0_CHANGEPASSWORD_REQUEST) == 40);

/* MSV1_0_INTERACTIVE_LOGON and MSV1_0_INTERACTIVE_PROFILE for i386 */
typedef struct
{
    ULONG MessageType;
    WOW64_STRING LogonDomainName, UserName, Password;
} WOW64_MSV1_0_INTERACTIVE_LOGON;
C_ASSERT(sizeof(WOW64_MSV1_0_INTERACTIVE_LOGON) == 28);

/* MSV1_0_LM20_LOGON (a network logon: the response to a challenge) for i386 */
typedef struct
{
    ULONG MessageType;
    WOW64_STRING LogonDomainName, UserName, Workstation;
    UCHAR ChallengeToClient[MSV1_0_CHALLENGE_LENGTH];
    WOW64_STRING CaseSensitiveChallengeResponse, CaseInsensitiveChallengeResponse;
    ULONG ParameterControl;
} WOW64_MSV1_0_LM20_LOGON;
C_ASSERT(sizeof(WOW64_MSV1_0_LM20_LOGON) == 56);

/* MSV1_0_S4U_LOGON for i386: the strings hold addresses in the guest, or offsets from the start of the buffer */
typedef struct
{
    ULONG MessageType;
    ULONG Flags;
    WOW64_STRING UserPrincipalName, DomainName;
} WOW64_MSV1_0_S4U_LOGON;
C_ASSERT(sizeof(WOW64_MSV1_0_S4U_LOGON) == 24);

/* MSV1_0_LM20_LOGON_PROFILE for i386 (the profile of an S4U logon): the times are 8-byte aligned */
typedef struct
{
    ULONG MessageType;
    LONGLONG KickOffTime, LogoffTime;
    ULONG UserFlags;
    UCHAR UserSessionKey[MSV1_0_USER_SESSION_KEY_LENGTH];
    WOW64_STRING LogonDomainName;
    UCHAR LanmanSessionKey[MSV1_0_LANMAN_SESSION_KEY_LENGTH];
    WOW64_STRING LogonServer, UserParameters;
} WOW64_MSV1_0_LM20_LOGON_PROFILE;
C_ASSERT(FIELD_OFFSET(WOW64_MSV1_0_LM20_LOGON_PROFILE, KickOffTime) == 8);
C_ASSERT(FIELD_OFFSET(WOW64_MSV1_0_LM20_LOGON_PROFILE, UserFlags) == 24);
C_ASSERT(FIELD_OFFSET(WOW64_MSV1_0_LM20_LOGON_PROFILE, LogonDomainName) == 44);
C_ASSERT(FIELD_OFFSET(WOW64_MSV1_0_LM20_LOGON_PROFILE, LogonServer) == 60);
C_ASSERT(sizeof(WOW64_MSV1_0_LM20_LOGON_PROFILE) == 80);

typedef struct
{
    ULONG MessageType;
    USHORT LogonCount, BadPasswordCount;
    LONGLONG LogonTime, LogoffTime, KickOffTime, PasswordLastSet, PasswordCanChange, PasswordMustChange;
    WOW64_STRING LogonScript, HomeDirectory, FullName, ProfilePath, HomeDirectoryDrive, LogonServer;
    ULONG UserFlags;
} WOW64_MSV1_0_INTERACTIVE_PROFILE;
C_ASSERT(FIELD_OFFSET(WOW64_MSV1_0_INTERACTIVE_PROFILE, LogonScript) == 56);
C_ASSERT(sizeof(WOW64_MSV1_0_INTERACTIVE_PROFILE) == 112);

#define LSA_PORT_NAME L"\\LsaAuthenticationPort"
#define MAX_LSA_PORTS 16
static volatile LONG LsaPorts[MAX_LSA_PORTS]; /* the guest's handles to the LSA port, 0 for a free slot */

static VOID Forget(ULONG Handle)
{
    ULONG i;
    for (i = 0; Handle && i < MAX_LSA_PORTS; ++i)
    {
        /* A plain read first: most calls to Wow64LpcForget concern a handle that is no port */
        if ((ULONG)LsaPorts[i] == Handle)
            InterlockedCompareExchange(&LsaPorts[i], 0, (LONG)Handle);
    }
}

/* The slot of a handle that was closed or moved without passing through Wow64LpcForget would
 * make a later object with the same handle value look like the LSA port, so a hit must still
 * be a port */
static BOOLEAN IsLsaPort(ULONG Handle)
{
    UCHAR Buffer[sizeof(OBJECT_TYPE_INFORMATION) + 64 * sizeof(WCHAR)];
    POBJECT_TYPE_INFORMATION Type = (POBJECT_TYPE_INFORMATION)Buffer;
    UNICODE_STRING Port, AlpcPort;
    ULONG i;
    BOOLEAN Found = FALSE;

    for (i = 0; Handle && !Found && i < MAX_LSA_PORTS; ++i)
        Found = (ULONG)LsaPorts[i] == Handle;
    if (!Found) return FALSE;
    RtlInitUnicodeString(&Port, L"Port");
    RtlInitUnicodeString(&AlpcPort, L"ALPC Port");
    if (NT_SUCCESS(NtQueryObject(HANDLE32(Handle), ObjectTypeInformation, Buffer, sizeof(Buffer), NULL)) &&
        (RtlEqualUnicodeString(&Type->TypeName, &Port, TRUE) || RtlEqualUnicodeString(&Type->TypeName, &AlpcPort, TRUE)))
        return TRUE;
    Forget(Handle);
    return FALSE;
}

VOID Wow64LpcForget(ULONG Handle)
{
    Forget(Handle);
}

static BOOLEAN Remember(ULONG Handle)
{
    ULONG i;
    for (i = 0; i < MAX_LSA_PORTS; ++i)
        if (!InterlockedCompareExchange(&LsaPorts[i], (LONG)Handle, 0)) return TRUE;
    return FALSE;
}

static BOOLEAN InGuest(ULONG Address, ULONG64 Size)
{
    return (ULONG64)Address + Size <= (ULONG64)Wow64HighestUserAddress + 1;
}

/* NtConnectPort(PHANDLE, PUNICODE_STRING, PSECURITY_QUALITY_OF_SERVICE, PPORT_VIEW, PREMOTE_PORT_VIEW,
 * PULONG MaxMessageLength, PVOID ConnectionInformation, PULONG ConnectionInformationLength).
 * The quality of service and the connection information (LSA_CONNECTION_INFO) hold no pointers. */
NTSTATUS Wow64LpcConnect(ULONG Number, const ULONG *a, HANDLE *Handle, BOOLEAN *Reported)
{
    UNICODE_STRING Name, Lsa;
    WCHAR NameBuffer[sizeof(LSA_PORT_NAME) / sizeof(WCHAR)];
    WOW64_STRING Guest;
    NTSTATUS Status;

    if (!a[1] || !InGuest(a[1], sizeof(WOW64_STRING)))
        return STATUS_ACCESS_VIOLATION;
    Guest = *(volatile WOW64_STRING *)PTR32(a[1]);
    if (Guest.Length > Guest.MaximumLength || !InGuest(Guest.Buffer, Guest.Length))
        return STATUS_ACCESS_VIOLATION;
    RtlInitUnicodeString(&Lsa, LSA_PORT_NAME);
    /* Only the LSA port is allowed. Compare a native copy of the name and connect with that
     * same copy, so the name that passed the check is the one the kernel opens. */
    if (Guest.Length != Lsa.Length)
        return Wow64Unsupported(Number, WOW64_UNSUPPORTED_SERVICE, 0, Reported);
    RtlCopyMemory(NameBuffer, PTR32(Guest.Buffer), Guest.Length);
    Name.Length = Guest.Length;
    Name.MaximumLength = sizeof(NameBuffer);
    Name.Buffer = NameBuffer;
    if (!RtlEqualUnicodeString(&Name, &Lsa, TRUE))
        return Wow64Unsupported(Number, WOW64_UNSUPPORTED_SERVICE, 0, Reported);
    /* The views carry native pointers and sizes; the LSA port uses neither */
    if (a[3] || a[4])
        return Wow64Unsupported(Number, WOW64_UNSUPPORTED_SERVICE, 1, Reported);

    Status = NtConnectPort(Handle, &Name, PTR32(a[2]), NULL, NULL, PTR32(a[5]), PTR32(a[6]), PTR32(a[7]));
    if (NT_SUCCESS(Status) && !Remember(HandleToUlong(*Handle)))
    {
        NtClose(*Handle);
        *Handle = NULL;
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    return Status;
}

/* The guest's MSV1_0_INTERACTIVE_LOGON (the copy made by LogonSubmitFrom32) in the native layout, in one
 * heap block with its strings. The block holds the password, so it is wiped before it is freed. */
static NTSTATUS InteractiveLogonFrom32(const WOW64_MSV1_0_INTERACTIVE_LOGON *Captured, PVOID *Native, ULONG *NativeLength)
{
    const WOW64_MSV1_0_INTERACTIVE_LOGON Logon = *Captured;
    const WOW64_STRING *From[3];
    ULONG Bytes[3];
    UNICODE_STRING *To[3];
    PMSV1_0_INTERACTIVE_LOGON Blob;
    PUCHAR Next;
    ULONG Size = sizeof(MSV1_0_INTERACTIVE_LOGON), i;
    NTSTATUS Status = STATUS_SUCCESS;

    From[0] = &Logon.LogonDomainName;
    From[1] = &Logon.UserName;
    From[2] = &Logon.Password;
    for (i = 0; i < 3; ++i)
    {
        /* As msv1_0 reads it, the password's length keeps the seed of its encoding in the high byte
         * (RtlRunEncodeUnicodeString) and the data is the low byte's worth of bytes; the seed is
         * passed on as it is. Domain and user name are plain. */
        Bytes[i] = i == 2 ? (From[i]->Length & 0xff) : From[i]->Length;
        if (Bytes[i] > From[i]->MaximumLength || (Bytes[i] && (!From[i]->Buffer || !InGuest(From[i]->Buffer, Bytes[i]))))
            return STATUS_INVALID_PARAMETER;
        Size += From[i]->MaximumLength;
    }
    Blob = RtlAllocateHeap(RtlGetProcessHeap(), HEAP_ZERO_MEMORY, Size);
    if (!Blob) return STATUS_NO_MEMORY;
    Blob->MessageType = MsV1_0InteractiveLogon;
    To[0] = &Blob->LogonDomainName;
    To[1] = &Blob->UserName;
    To[2] = &Blob->Password;
    Next = (PUCHAR)(Blob + 1);
    _SEH2_TRY
    {
        for (i = 0; i < 3; ++i)
        {
            To[i]->Length = From[i]->Length;
            To[i]->MaximumLength = From[i]->MaximumLength;
            /* As advapi32 builds it, a missing string keeps a NULL buffer */
            To[i]->Buffer = From[i]->Buffer ? (PWSTR)Next : NULL;
            if (Bytes[i]) RtlCopyMemory(Next, PTR32(From[i]->Buffer), Bytes[i]);
            Next += From[i]->MaximumLength;
        }
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        Status = _SEH2_GetExceptionCode();
    }
    _SEH2_END;
    if (!NT_SUCCESS(Status))
    {
        RtlSecureZeroMemory(Blob, Size);
        RtlFreeHeap(RtlGetProcessHeap(), 0, Blob);
        return Status;
    }
    *Native = Blob;
    *NativeLength = Size;
    return STATUS_SUCCESS;
}

/* The guest's MSV1_0_LM20_LOGON in the native layout, in one heap block with its five strings: the names as
 * UTF-16 text and the two responses as bytes. As msv1_0 reads it, the length of a string is all that counts
 * (it makes its own Maximum from it). */
static NTSTATUS Lm20LogonFrom32(const WOW64_MSV1_0_LM20_LOGON *Captured, PVOID *Native, ULONG *NativeLength)
{
    const WOW64_MSV1_0_LM20_LOGON Logon = *Captured;
    const WOW64_STRING *From[5];
    UNICODE_STRING *ToW[3];
    STRING *ToA[2];
    PMSV1_0_LM20_LOGON Blob;
    PUCHAR Next;
    ULONG Size = sizeof(MSV1_0_LM20_LOGON), i;
    NTSTATUS Status = STATUS_SUCCESS;

    From[0] = &Logon.LogonDomainName;
    From[1] = &Logon.UserName;
    From[2] = &Logon.Workstation;
    From[3] = &Logon.CaseSensitiveChallengeResponse;
    From[4] = &Logon.CaseInsensitiveChallengeResponse;
    for (i = 0; i < 5; ++i)
    {
        if (From[i]->Length && (!From[i]->Buffer || !InGuest(From[i]->Buffer, From[i]->Length)))
            return STATUS_INVALID_PARAMETER;
        if (From[i]->Length > MAXLONG - Size)
            return STATUS_INVALID_PARAMETER;
        Size += ALIGN_UP_BY(From[i]->Length, sizeof(WCHAR));
    }
    Blob = RtlAllocateHeap(RtlGetProcessHeap(), HEAP_ZERO_MEMORY, Size);
    if (!Blob) return STATUS_NO_MEMORY;
    Blob->MessageType = Logon.MessageType;
    RtlCopyMemory(Blob->ChallengeToClient, Logon.ChallengeToClient, sizeof(Blob->ChallengeToClient));
    Blob->ParameterControl = Logon.ParameterControl;
    ToW[0] = &Blob->LogonDomainName;
    ToW[1] = &Blob->UserName;
    ToW[2] = &Blob->Workstation;
    ToA[0] = &Blob->CaseSensitiveChallengeResponse;
    ToA[1] = &Blob->CaseInsensitiveChallengeResponse;
    Next = (PUCHAR)(Blob + 1);
    _SEH2_TRY
    {
        for (i = 0; i < 5; ++i)
        {
            USHORT Length = From[i]->Length;
            PUCHAR Buffer = Length ? Next : NULL;

            if (i < 3)
            {
                ToW[i]->Length = Length;
                ToW[i]->MaximumLength = Length;
                ToW[i]->Buffer = (PWSTR)Buffer;
            }
            else
            {
                ToA[i - 3]->Length = Length;
                ToA[i - 3]->MaximumLength = Length;
                ToA[i - 3]->Buffer = (PCHAR)Buffer;
            }
            if (Length) RtlCopyMemory(Next, PTR32(From[i]->Buffer), Length);
            Next += ALIGN_UP_BY(Length, sizeof(WCHAR));
        }
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        Status = _SEH2_GetExceptionCode();
    }
    _SEH2_END;
    if (!NT_SUCCESS(Status))
    {
        RtlFreeHeap(RtlGetProcessHeap(), 0, Blob);
        return Status;
    }
    *Native = Blob;
    *NativeLength = Size;
    return STATUS_SUCCESS;
}

/* The guest's MSV1_0_S4U_LOGON in the native layout, in one heap block that holds the two strings after
 * the structure. A string is an address inside the guest's buffer, or an offset from its start, which
 * is how msv1_0 tells them apart; the same rule picks where the characters are read from, once. A
 * string that does not lie inside the buffer is passed on with a Buffer outside the block, so msv1_0
 * rejects it in its own order of checks. */
static NTSTATUS S4ULogonFrom32(ULONG Guest, ULONG Length, ULONG Captured, const WOW64_MSV1_0_S4U_LOGON *Submit,
                               PVOID *Native, ULONG *NativeLength)
{
    const WOW64_MSV1_0_S4U_LOGON Logon = *Submit;
    const WOW64_STRING *From[2];
    UNICODE_STRING *To[2];
    ULONG Offset[2];
    BOOLEAN Inside[2];
    PMSV1_0_S4U_LOGON Blob;
    PUCHAR Next;
    ULONG Size = sizeof(MSV1_0_S4U_LOGON), i;
    NTSTATUS Status = STATUS_SUCCESS;

    if (Captured < sizeof(Logon))
        return STATUS_INVALID_PARAMETER;
    From[0] = &Logon.UserPrincipalName;
    From[1] = &Logon.DomainName;
    for (i = 0; i < 2; ++i)
    {
        ULONG64 Address = From[i]->Buffer;

        /* As in msv1_0: an address in the buffer is turned into an offset */
        Offset[i] = From[i]->Buffer;
        if (Address >= Guest && Address - Guest <= Length)
            Offset[i] = (ULONG)(Address - Guest);
        Inside[i] = Offset[i] <= Length && From[i]->Length <= Length - Offset[i];
        if (Inside[i]) Size += From[i]->Length;
    }
    Blob = RtlAllocateHeap(RtlGetProcessHeap(), HEAP_ZERO_MEMORY, Size);
    if (!Blob) return STATUS_NO_MEMORY;
    Blob->MessageType = MsV1_0S4ULogon;
    Blob->Flags = Logon.Flags;
    To[0] = &Blob->UserPrincipalName;
    To[1] = &Blob->DomainName;
    Next = (PUCHAR)(Blob + 1);
    _SEH2_TRY
    {
        for (i = 0; i < 2; ++i)
        {
            To[i]->Length = From[i]->Length;
            To[i]->MaximumLength = From[i]->MaximumLength;
            if (!From[i]->Buffer)
                continue; /* a missing string keeps a NULL buffer */
            if (!Inside[i])
            {
                To[i]->Buffer = (PWSTR)~(ULONG_PTR)0;
                continue;
            }
            To[i]->Buffer = (PWSTR)Next;
            if (From[i]->Length) RtlCopyMemory(Next, PTR32(Guest + Offset[i]), From[i]->Length);
            Next += From[i]->Length;
        }
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        Status = _SEH2_GetExceptionCode();
    }
    _SEH2_END;
    if (!NT_SUCCESS(Status))
    {
        RtlFreeHeap(RtlGetProcessHeap(), 0, Blob);
        return Status;
    }
    *Native = Blob;
    *NativeLength = Size;
    return STATUS_SUCCESS;
}

/* The submit buffer of LsaLogonUser for MSV1_0, which holds the guest's layout of the message the
 * first ULONG names. Its start is read once, as far as the buffer goes, and every later decision is
 * made from that copy. */
static NTSTATUS LogonSubmitFrom32(ULONG Number, ULONG Guest, ULONG Length, PVOID *Native, ULONG *NativeLength)
{
    union
    {
        ULONG MessageType;
        WOW64_MSV1_0_INTERACTIVE_LOGON Interactive;
        WOW64_MSV1_0_S4U_LOGON S4U;
        WOW64_MSV1_0_LM20_LOGON Lm20;
    } Submit;
    ULONG Captured;
    NTSTATUS Status = STATUS_SUCCESS;

    if (!Guest || Length < sizeof(ULONG) || !InGuest(Guest, Length))
        return STATUS_INVALID_PARAMETER;
    Captured = min(Length, sizeof(Submit));
    RtlZeroMemory(&Submit, sizeof(Submit));
    _SEH2_TRY
    {
        RtlCopyMemory(&Submit, PTR32(Guest), Captured);
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        Status = _SEH2_GetExceptionCode();
    }
    _SEH2_END;
    if (!NT_SUCCESS(Status)) return Status;

    if (Submit.MessageType == MsV1_0S4ULogon)
        return S4ULogonFrom32(Guest, Length, Captured, &Submit.S4U, Native, NativeLength);
    if (Submit.MessageType == MsV1_0Lm20Logon || Submit.MessageType == MsV1_0NetworkLogon)
    {
        if (Length < sizeof(Submit.Lm20))
            return STATUS_INVALID_PARAMETER;
        return Lm20LogonFrom32(&Submit.Lm20, Native, NativeLength);
    }
    if (Length < sizeof(Submit.Interactive))
        return STATUS_INVALID_PARAMETER;
    if (Submit.MessageType != MsV1_0InteractiveLogon)
    {
        if (Wow64FirstReport(Number, WOW64_UNSUPPORTED_CLASS, Submit.MessageType))
            DbgPrint("WoW64: unsupported LsaLogonUser logon submit type %lu, pid %lx\n", Submit.MessageType,
                     HandleToUlong(NtCurrentTeb()->ClientId.UniqueProcess));
        return STATUS_NOT_SUPPORTED;
    }
    return InteractiveLogonFrom32(&Submit.Interactive, Native, NativeLength);
}

/* The guest's TOKEN_GROUPS in the native layout; the SIDs stay in guest memory, where lsass reads them */
static NTSTATUS GroupsFrom32(ULONG Guest, ULONG Count, PTOKEN_GROUPS *Native)
{
    const ULONG *Source = PTR32(Guest);
    PTOKEN_GROUPS Groups;
    ULONG i;
    NTSTATUS Status = STATUS_SUCCESS;

    *Native = NULL;
    if (!Count) return STATUS_SUCCESS;
    if (!Guest || Count > WOW64_MAX_ARRAY_COUNT || !InGuest(Guest, sizeof(ULONG) + (ULONG64)Count * 2 * sizeof(ULONG)))
        return STATUS_INVALID_PARAMETER;
    Groups = RtlAllocateHeap(RtlGetProcessHeap(), HEAP_ZERO_MEMORY,
                             FIELD_OFFSET(TOKEN_GROUPS, Groups) + (SIZE_T)Count * sizeof(SID_AND_ATTRIBUTES));
    if (!Groups) return STATUS_NO_MEMORY;
    Groups->GroupCount = Count;
    _SEH2_TRY
    {
        for (i = 0; i < Count; ++i)
        {
            Groups->Groups[i].Sid = PTR32(Source[1 + 2 * i]);
            Groups->Groups[i].Attributes = Source[2 + 2 * i];
        }
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        Status = _SEH2_GetExceptionCode();
    }
    _SEH2_END;
    if (!NT_SUCCESS(Status))
    {
        RtlFreeHeap(RtlGetProcessHeap(), 0, Groups);
        return Status;
    }
    *Native = Groups;
    return STATUS_SUCCESS;
}

/* The MSV1_0_LM20_LOGON_PROFILE of an S4U logon as the guest's layout, in a new block below the
 * guest's limit with the strings after the structure (the caller frees the native one) */
static NTSTATUS Lm20ProfileTo32(PVOID Native, ULONG *Guest, ULONG *GuestLength)
{
    PMSV1_0_LM20_LOGON_PROFILE From = Native;
    WOW64_MSV1_0_LM20_LOGON_PROFILE *To;
    const UNICODE_STRING *Source[3];
    WOW64_STRING *Target[3];
    ULONG Bytes[3];
    SIZE_T Size = sizeof(*To);
    PUCHAR Next;
    PVOID Block = NULL;
    NTSTATUS Status;
    ULONG i;

    Source[0] = &From->LogonDomainName;
    Source[1] = &From->LogonServer;
    Source[2] = &From->UserParameters;
    for (i = 0; i < 3; ++i)
    {
        /* lsass wrote the profile, but the copy never reads past a string's own buffer */
        Bytes[i] = Source[i]->Buffer ? min(Source[i]->Length, Source[i]->MaximumLength) : 0;
        if (Source[i]->Buffer) Size += ALIGN_UP_BY(Source[i]->MaximumLength, sizeof(ULONG));
    }
    Status = Wow64Allocate(Size, &Block);
    if (!NT_SUCCESS(Status)) return Status;
    To = Block;
    To->MessageType = From->MessageType;
    To->KickOffTime = From->KickOffTime.QuadPart;
    To->LogoffTime = From->LogoffTime.QuadPart;
    To->UserFlags = From->UserFlags;
    RtlCopyMemory(To->UserSessionKey, From->UserSessionKey, sizeof(To->UserSessionKey));
    RtlCopyMemory(To->LanmanSessionKey, From->LanmanSessionKey, sizeof(To->LanmanSessionKey));
    Target[0] = &To->LogonDomainName;
    Target[1] = &To->LogonServer;
    Target[2] = &To->UserParameters;
    Next = (PUCHAR)(To + 1);
    for (i = 0; i < 3; ++i)
    {
        Target[i]->Length = (USHORT)Bytes[i];
        Target[i]->MaximumLength = Source[i]->MaximumLength;
        if (Source[i]->Buffer)
        {
            Target[i]->Buffer = PtrToUlong(Next);
            RtlCopyMemory(Next, Source[i]->Buffer, Bytes[i]);
            Next += ALIGN_UP_BY(Source[i]->MaximumLength, sizeof(ULONG));
        }
    }
    *Guest = PtrToUlong(Block);
    *GuestLength = (ULONG)Size;
    return STATUS_SUCCESS;
}

/* The native profile lsass left in this process, as a guest MSV1_0_INTERACTIVE_PROFILE in a new
 * block below the guest's limit. The native block is freed; the guest frees the new one with
 * LsaFreeReturnBuffer as for any profile. Other profile types are dropped. */
static NTSTATUS ProfileTo32(PVOID Native, ULONG *Guest, ULONG *GuestLength)
{
    PMSV1_0_INTERACTIVE_PROFILE From = Native;
    WOW64_MSV1_0_INTERACTIVE_PROFILE *To;
    const UNICODE_STRING *Source[6];
    WOW64_STRING *Target[6];
    SIZE_T Size = sizeof(*To), Zero = 0;
    PUCHAR Next;
    PVOID Block = NULL;
    NTSTATUS Status = STATUS_SUCCESS;
    ULONG i;

    *Guest = 0;
    *GuestLength = 0;
    if (From->MessageType == MsV1_0Lm20LogonProfile)
    {
        Status = Lm20ProfileTo32(Native, Guest, GuestLength);
        goto Free;
    }
    if (From->MessageType != MsV1_0InteractiveProfile)
        goto Free;
    Source[0] = &From->LogonScript;
    Source[1] = &From->HomeDirectory;
    Source[2] = &From->FullName;
    Source[3] = &From->ProfilePath;
    Source[4] = &From->HomeDirectoryDrive;
    Source[5] = &From->LogonServer;
    for (i = 0; i < 6; ++i)
        Size += ALIGN_UP_BY(Source[i]->MaximumLength, sizeof(ULONG));
    Status = Wow64Allocate(Size, &Block);
    if (!NT_SUCCESS(Status)) goto Free;
    To = Block;
    To->MessageType = From->MessageType;
    To->LogonCount = From->LogonCount;
    To->BadPasswordCount = From->BadPasswordCount;
    To->LogonTime = From->LogonTime.QuadPart;
    To->LogoffTime = From->LogoffTime.QuadPart;
    To->KickOffTime = From->KickOffTime.QuadPart;
    To->PasswordLastSet = From->PasswordLastSet.QuadPart;
    To->PasswordCanChange = From->PasswordCanChange.QuadPart;
    To->PasswordMustChange = From->PasswordMustChange.QuadPart;
    To->UserFlags = From->UserFlags;
    Target[0] = &To->LogonScript;
    Target[1] = &To->HomeDirectory;
    Target[2] = &To->FullName;
    Target[3] = &To->ProfilePath;
    Target[4] = &To->HomeDirectoryDrive;
    Target[5] = &To->LogonServer;
    Next = (PUCHAR)(To + 1);
    for (i = 0; i < 6; ++i)
    {
        /* lsass wrote the profile, but the copy never reads past a string's own buffer */
        Target[i]->Length = min(Source[i]->Length, Source[i]->MaximumLength);
        Target[i]->MaximumLength = Source[i]->MaximumLength;
        if (Source[i]->Buffer)
        {
            Target[i]->Buffer = PtrToUlong(Next);
            RtlCopyMemory(Next, Source[i]->Buffer, Target[i]->Length);
            Next += ALIGN_UP_BY(Source[i]->MaximumLength, sizeof(ULONG));
        }
    }
    *Guest = PtrToUlong(Block);
    *GuestLength = (ULONG)Size;
Free:
    NtFreeVirtualMemory(NtCurrentProcess(), &Native, &Zero, MEM_RELEASE);
    return Status;
}

static ULONG Saturate(SIZE_T Value)
{
    return Value > MAXULONG ? MAXULONG : (ULONG)Value;
}

static NTSTATUS RequestLogonUser(ULONG Number, HANDLE Port, UCHAR *Message, ULONG DataLength, ULONG TotalLength,
                                 LSA_API_MSG *Native)
{
    WOW64_LSA_BODY *Body = (WOW64_LSA_BODY *)(Message + sizeof(WOW64_PORT_MESSAGE));
    WOW64_LSA_LOGON_REQUEST Request;
    WOW64_LSA_LOGON_REPLY Reply;
    PVOID AuthInfo = NULL;
    PTOKEN_GROUPS Groups = NULL;
    ULONG AuthInfoLength = 0;
    NTSTATUS Status, Result, Written = STATUS_SUCCESS;

    if (DataLength < FIELD_OFFSET(WOW64_LSA_BODY, LogonRequest) + sizeof(Request) ||
        TotalLength < sizeof(WOW64_PORT_MESSAGE) + FIELD_OFFSET(WOW64_LSA_BODY, LogonReply) + sizeof(Reply))
        return STATUS_INVALID_PARAMETER; /* checked before the logon, the reply must fit in the message */
    RtlCopyMemory(&Request, &Body->LogonRequest, sizeof(Request));

    if (Request.AuthenticationInformationLength)
    {
        Status = LogonSubmitFrom32(Number, Request.AuthenticationInformation,
                                   Request.AuthenticationInformationLength, &AuthInfo, &AuthInfoLength);
        if (!NT_SUCCESS(Status)) return Status;
    }
    Status = GroupsFrom32(Request.LocalGroups, Request.LocalGroupsCount, &Groups);
    if (!NT_SUCCESS(Status)) goto Done;
    if (Request.OriginName.Length > Request.OriginName.MaximumLength ||
        (Request.OriginName.Length && !InGuest(Request.OriginName.Buffer, Request.OriginName.Length)))
    {
        Status = STATUS_INVALID_PARAMETER;
        goto Done;
    }

    RtlZeroMemory(Native, sizeof(*Native));
    Native->ApiNumber = LSASS_REQUEST_LOGON_USER;
    Native->h.u1.s1.DataLength = LSA_PORT_DATA_SIZE(Native->LogonUser);
    Native->h.u1.s1.TotalLength = LSA_PORT_MESSAGE_SIZE;
    Native->LogonUser.Request.OriginName.Length = Request.OriginName.Length;
    Native->LogonUser.Request.OriginName.MaximumLength = Request.OriginName.MaximumLength;
    Native->LogonUser.Request.OriginName.Buffer = PTR32(Request.OriginName.Buffer);
    Native->LogonUser.Request.LogonType = Request.LogonType;
    Native->LogonUser.Request.AuthenticationPackage = Request.AuthenticationPackage;
    Native->LogonUser.Request.AuthenticationInformation = AuthInfo;
    Native->LogonUser.Request.AuthenticationInformationLength = AuthInfoLength;
    Native->LogonUser.Request.LocalGroups = Groups;
    Native->LogonUser.Request.LocalGroupsCount = Request.LocalGroupsCount;
    Native->LogonUser.Request.SourceContext = Request.SourceContext;

    Status = NtRequestWaitReplyPort(Port, &Native->h, &Native->h);
    if (!NT_SUCCESS(Status)) goto Done;

    RtlZeroMemory(&Reply, sizeof(Reply));
    Reply.SubStatus = Native->LogonUser.Reply.SubStatus;
    Result = Native->Status;
    if (NT_SUCCESS(Result) && Native->LogonUser.Reply.ProfileBuffer)
        Result = ProfileTo32(Native->LogonUser.Reply.ProfileBuffer, &Reply.ProfileBuffer, &Reply.ProfileBufferLength);
    if (NT_SUCCESS(Result))
    {
        Reply.LogonId = Native->LogonUser.Reply.LogonId;
        Reply.Token = HandleToUlong(Native->LogonUser.Reply.Token);
        Reply.Quotas[0] = Saturate(Native->LogonUser.Reply.Quotas.PagedPoolLimit);
        Reply.Quotas[1] = Saturate(Native->LogonUser.Reply.Quotas.NonPagedPoolLimit);
        Reply.Quotas[2] = Saturate(Native->LogonUser.Reply.Quotas.MinimumWorkingSetSize);
        Reply.Quotas[3] = Saturate(Native->LogonUser.Reply.Quotas.MaximumWorkingSetSize);
        Reply.Quotas[4] = Saturate(Native->LogonUser.Reply.Quotas.PagefileLimit);
        Reply.TimeLimit = Native->LogonUser.Reply.Quotas.TimeLimit.QuadPart;
    }
    else if (NT_SUCCESS(Native->Status) && Native->LogonUser.Reply.Token)
    {
        /* The logon succeeded but its reply could not be converted: the guest never sees the token */
        NtClose(Native->LogonUser.Reply.Token);
    }
    _SEH2_TRY
    {
        Body->Status = Result;
        RtlCopyMemory(&Body->LogonReply, &Reply, sizeof(Reply));
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        Written = _SEH2_GetExceptionCode();
    }
    _SEH2_END;
    if (!NT_SUCCESS(Written))
    {
        /* The guest cannot receive the reply: it must not be left holding nothing but a token and a profile */
        if (NT_SUCCESS(Result))
        {
            SIZE_T Zero = 0;
            PVOID Profile = UlongToPtr(Reply.ProfileBuffer);
            if (Reply.Token) NtClose(HANDLE32(Reply.Token));
            if (Profile) NtFreeVirtualMemory(NtCurrentProcess(), &Profile, &Zero, MEM_RELEASE);
        }
        Status = Written;
    }
    else
        Status = STATUS_SUCCESS;

Done:
    if (Groups) RtlFreeHeap(RtlGetProcessHeap(), 0, Groups);
    if (AuthInfo)
    {
        RtlSecureZeroMemory(AuthInfo, AuthInfoLength);
        RtlFreeHeap(RtlGetProcessHeap(), 0, AuthInfo);
    }
    return Status;
}

/* The Size bytes at Base, lsass's allocation in this process, lie within one committed region */
static BOOLEAN NativeBlockHolds(PVOID Base, ULONG64 Size)
{
    MEMORY_BASIC_INFORMATION Info;

    if (!NT_SUCCESS(NtQueryVirtualMemory(NtCurrentProcess(), Base, MemoryBasicInformation, &Info, sizeof(Info), NULL)) ||
        Info.State != MEM_COMMIT)
        return FALSE;
    return (ULONG64)(ULONG_PTR)Base + Size <= (ULONG64)(ULONG_PTR)Info.BaseAddress + Info.RegionSize;
}

static VOID FreeBlock(PVOID Block)
{
    SIZE_T Zero = 0;
    if (Block) NtFreeVirtualMemory(NtCurrentProcess(), &Block, &Zero, MEM_RELEASE);
}

/* Fills a request for an API without pointers */
static VOID InitNative(LSA_API_MSG *Native, ULONG Api, ULONG DataLength)
{
    RtlZeroMemory(Native, sizeof(*Native));
    Native->ApiNumber = Api;
    Native->h.u1.s1.DataLength = DataLength;
    Native->h.u1.s1.TotalLength = LSA_PORT_MESSAGE_SIZE;
}

/* LsaEnumerateLogonSessions: the LUID array lsass allocated in this process is copied below the guest's
 * limit, as for the profile of a logon */
static NTSTATUS RequestEnumSessions(HANDLE Port, WOW64_LSA_BODY *Body, LSA_API_MSG *Native)
{
    NTSTATUS Status, Result, Written = STATUS_SUCCESS;
    ULONG Count = 0, Guest = 0;

    InitNative(Native, LSASS_REQUEST_ENUM_LOGON_SESSIONS, LSA_PORT_DATA_SIZE(Native->EnumLogonSessions));
    Status = NtRequestWaitReplyPort(Port, &Native->h, &Native->h);
    if (!NT_SUCCESS(Status)) return Status;

    Result = Native->Status;
    if (NT_SUCCESS(Result))
    {
        PVOID Block = Native->EnumLogonSessions.Reply.LogonSessionBuffer;
        Count = Native->EnumLogonSessions.Reply.LogonSessionCount;
        if (!Block || Count > WOW64_MAX_ARRAY_COUNT || !NativeBlockHolds(Block, (ULONG64)Count * sizeof(LUID)))
            Result = STATUS_INVALID_PARAMETER;
        else
        {
            PVOID Copy;
            Result = Wow64Allocate((SIZE_T)Count * sizeof(LUID), &Copy);
            if (NT_SUCCESS(Result))
            {
                RtlCopyMemory(Copy, Block, (SIZE_T)Count * sizeof(LUID));
                Guest = PtrToUlong(Copy);
            }
        }
        FreeBlock(Block);
    }
    _SEH2_TRY
    {
        Body->Status = Result;
        Body->EnumReply.LogonSessionCount = NT_SUCCESS(Result) ? Count : 0;
        Body->EnumReply.LogonSessionBuffer = Guest;
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        Written = _SEH2_GetExceptionCode();
    }
    _SEH2_END;
    if (!NT_SUCCESS(Written))
    {
        FreeBlock(UlongToPtr(Guest));
        return Written;
    }
    return STATUS_SUCCESS;
}

/* The session data lsass built in this process, as a guest SECURITY_LOGON_SESSION_DATA with its strings and
 * SID in a new block below the guest's limit; offsets stay offsets from the start of the block */
static NTSTATUS SessionDataTo32(PVOID Native, ULONG *Guest)
{
    PSECURITY_LOGON_SESSION_DATA From = Native;
    const UNICODE_STRING *Source[6];
    WOW64_STRING *Target[6];
    WOW64_SESSION_DATA *To;
    ULONG Size = sizeof(*To), SidOffset = 0, SidLength = 0, Offset, i;
    NTSTATUS Status = STATUS_SUCCESS;
    PVOID Block = NULL;

    *Guest = 0;
    _SEH2_TRY
    {
        if (!NativeBlockHolds(Native, sizeof(*From)))
            Status = STATUS_INVALID_PARAMETER;
        Source[0] = &From->UserName;
        Source[1] = &From->LogonDomain;
        Source[2] = &From->AuthenticationPackage;
        Source[3] = &From->LogonServer;
        Source[4] = &From->DnsDomainName;
        Source[5] = &From->Upn;
        for (i = 0; NT_SUCCESS(Status) && i < 6; ++i)
        {
            if (Source[i]->Length > Source[i]->MaximumLength) { Status = STATUS_INVALID_PARAMETER; break; }
            if (!Source[i]->MaximumLength) continue;
            Offset = (ULONG)(ULONG_PTR)Source[i]->Buffer;
            if ((ULONG_PTR)Source[i]->Buffer > MAXULONG || Offset < sizeof(*From) ||
                !NativeBlockHolds(Native, (ULONG64)Offset + Source[i]->MaximumLength))
            {
                Status = STATUS_INVALID_PARAMETER;
                break;
            }
            Size += ALIGN_UP_BY(Source[i]->MaximumLength, sizeof(ULONG));
        }
        if (NT_SUCCESS(Status) && From->Sid)
        {
            SidOffset = (ULONG)(ULONG_PTR)From->Sid;
            if ((ULONG_PTR)From->Sid > MAXULONG || SidOffset < sizeof(*From) ||
                !NativeBlockHolds(Native, (ULONG64)SidOffset + FIELD_OFFSET(SID, SubAuthority)))
                Status = STATUS_INVALID_PARAMETER;
            else
            {
                SidLength = RtlLengthRequiredSid(((PISID)((PUCHAR)Native + SidOffset))->SubAuthorityCount);
                if (!NativeBlockHolds(Native, (ULONG64)SidOffset + SidLength)) Status = STATUS_INVALID_PARAMETER;
                Size += ALIGN_UP_BY(SidLength, sizeof(ULONG));
            }
        }
        if (NT_SUCCESS(Status)) Status = Wow64Allocate(Size, &Block);
        if (NT_SUCCESS(Status))
        {
            PUCHAR Next;
            To = Block;
            To->Size = sizeof(*To);
            To->LogonId = From->LogonId;
            To->LogonType = From->LogonType;
            To->Session = From->Session;
            To->LogonTime = From->LogonTime.QuadPart;
            Target[0] = &To->UserName;
            Target[1] = &To->LogonDomain;
            Target[2] = &To->AuthenticationPackage;
            Target[3] = &To->LogonServer;
            Target[4] = &To->DnsDomainName;
            Target[5] = &To->Upn;
            Next = (PUCHAR)(To + 1);
            for (i = 0; i < 6; ++i)
            {
                Target[i]->Length = Source[i]->Length;
                Target[i]->MaximumLength = Source[i]->MaximumLength;
                if (!Source[i]->MaximumLength) continue;
                RtlCopyMemory(Next, (PUCHAR)Native + (ULONG)(ULONG_PTR)Source[i]->Buffer, Source[i]->MaximumLength);
                Target[i]->Buffer = (ULONG)(Next - (PUCHAR)To);
                Next += ALIGN_UP_BY(Source[i]->MaximumLength, sizeof(ULONG));
            }
            if (From->Sid)
            {
                RtlCopyMemory(Next, (PUCHAR)Native + SidOffset, SidLength);
                To->Sid = (ULONG)(Next - (PUCHAR)To);
            }
            *Guest = PtrToUlong(Block);
        }
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        Status = _SEH2_GetExceptionCode();
    }
    _SEH2_END;
    if (!NT_SUCCESS(Status))
    {
        FreeBlock(Block);
        *Guest = 0;
    }
    return Status;
}

static NTSTATUS RequestSessionData(HANDLE Port, WOW64_LSA_BODY *Body, LSA_API_MSG *Native)
{
    NTSTATUS Status, Result, Written = STATUS_SUCCESS;
    ULONG Guest = 0;

    InitNative(Native, LSASS_REQUEST_GET_LOGON_SESSION_DATA, LSA_PORT_DATA_SIZE(Native->GetLogonSessionData));
    Native->GetLogonSessionData.Request.LogonId = Body->SessionRequest.LogonId;
    Status = NtRequestWaitReplyPort(Port, &Native->h, &Native->h);
    if (!NT_SUCCESS(Status)) return Status;

    Result = Native->Status;
    if (NT_SUCCESS(Result))
    {
        PVOID Block = Native->GetLogonSessionData.Reply.SessionDataBuffer;
        Result = Block ? SessionDataTo32(Block, &Guest) : STATUS_INVALID_PARAMETER;
        FreeBlock(Block);
    }
    _SEH2_TRY
    {
        Body->Status = Result;
        Body->SessionReply.SessionDataBuffer = Guest;
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        Written = _SEH2_GetExceptionCode();
    }
    _SEH2_END;
    if (!NT_SUCCESS(Written))
    {
        FreeBlock(UlongToPtr(Guest));
        return Written;
    }
    return STATUS_SUCCESS;
}

/* LsaRegisterPolicyChangeNotification and LsaUnregisterPolicyChangeNotification: an information class and
 * an event handle, which lsass duplicates out of this process by its value */
static NTSTATUS RequestPolicyNotify(HANDLE Port, WOW64_LSA_BODY *Body, LSA_API_MSG *Native)
{
    NTSTATUS Status;

    InitNative(Native, LSASS_REQUEST_POLICY_CHANGE_NOTIFY, LSA_PORT_DATA_SIZE(Native->PolicyChangeNotify));
    Native->PolicyChangeNotify.Request.InformationClass = Body->PolicyRequest.InformationClass;
    Native->PolicyChangeNotify.Request.NotificationEventHandle = HANDLE32(Body->PolicyRequest.NotificationEventHandle);
    Native->PolicyChangeNotify.Request.Register = Body->PolicyRequest.Register;
    Status = NtRequestWaitReplyPort(Port, &Native->h, &Native->h);
    if (NT_SUCCESS(Status))
        Body->Status = Native->Status;
    return Status;
}

/* The id of the MSV1_0 package, the only one LsaCallAuthenticationPackage is translated for */
static NTSTATUS Msv1_0PackageId(HANDLE Port, ULONG *Id)
{
    LSA_API_MSG Message;
    NTSTATUS Status;

    InitNative(&Message, LSASS_REQUEST_LOOKUP_AUTHENTICATION_PACKAGE, LSA_PORT_DATA_SIZE(Message.LookupAuthenticationPackage));
    Message.LookupAuthenticationPackage.Request.PackageNameLength = sizeof(MSV1_0_PACKAGE_NAME) - 1;
    RtlCopyMemory(Message.LookupAuthenticationPackage.Request.PackageName, MSV1_0_PACKAGE_NAME, sizeof(MSV1_0_PACKAGE_NAME));
    Status = NtRequestWaitReplyPort(Port, &Message.h, &Message.h);
    if (NT_SUCCESS(Status)) Status = Message.Status;
    if (NT_SUCCESS(Status)) *Id = Message.LookupAuthenticationPackage.Reply.Package;
    return Status;
}

/* The guest's MSV1_0_CHANGEPASSWORD_REQUEST in the native layout, in one heap block with its strings (both
 * passwords: wiped before it is freed) */
static NTSTATUS ChangePasswordFrom32(ULONG Guest, ULONG Length, PVOID *Native, ULONG *NativeLength)
{
    WOW64_MSV1_0_CHANGEPASSWORD_REQUEST Request;
    const WOW64_STRING *From[4];
    UNICODE_STRING *To[4];
    PMSV1_0_CHANGEPASSWORD_REQUEST Blob;
    PUCHAR Next;
    ULONG Size = sizeof(MSV1_0_CHANGEPASSWORD_REQUEST), i;
    NTSTATUS Status = STATUS_SUCCESS;

    if (Length < sizeof(Request) || !InGuest(Guest, Length))
        return STATUS_INVALID_PARAMETER;
    _SEH2_TRY
    {
        RtlCopyMemory(&Request, PTR32(Guest), sizeof(Request));
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        Status = _SEH2_GetExceptionCode();
    }
    _SEH2_END;
    if (!NT_SUCCESS(Status)) return Status;
    From[0] = &Request.DomainName;
    From[1] = &Request.AccountName;
    From[2] = &Request.OldPassword;
    From[3] = &Request.NewPassword;
    for (i = 0; i < 4; ++i)
    {
        if (From[i]->Length > From[i]->MaximumLength || (From[i]->Length & 1) ||
            (From[i]->Length && (!From[i]->Buffer || !InGuest(From[i]->Buffer, From[i]->Length))))
            return STATUS_INVALID_PARAMETER;
        Size += From[i]->Length + sizeof(WCHAR);
    }
    Blob = RtlAllocateHeap(RtlGetProcessHeap(), HEAP_ZERO_MEMORY, Size);
    if (!Blob) return STATUS_NO_MEMORY;
    Blob->MessageType = MsV1_0ChangePassword;
    Blob->Impersonating = Request.Impersonating;
    To[0] = &Blob->DomainName;
    To[1] = &Blob->AccountName;
    To[2] = &Blob->OldPassword;
    To[3] = &Blob->NewPassword;
    Next = (PUCHAR)(Blob + 1);
    _SEH2_TRY
    {
        for (i = 0; i < 4; ++i)
        {
            To[i]->Length = From[i]->Length;
            To[i]->MaximumLength = From[i]->Length + sizeof(WCHAR);
            To[i]->Buffer = (PWSTR)Next;
            if (From[i]->Length) RtlCopyMemory(Next, PTR32(From[i]->Buffer), From[i]->Length);
            Next += From[i]->Length + sizeof(WCHAR);
        }
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        Status = _SEH2_GetExceptionCode();
    }
    _SEH2_END;
    if (!NT_SUCCESS(Status))
    {
        RtlSecureZeroMemory(Blob, Size);
        RtlFreeHeap(RtlGetProcessHeap(), 0, Blob);
        return Status;
    }
    *Native = Blob;
    *NativeLength = Size;
    return STATUS_SUCCESS;
}

/* LsaCallAuthenticationPackage for the MSV1_0 message types that 32-bit callers use: MsV1_0ChangePassword
 * (NetUserChangePassword), which has no reply buffer. The others, and the other packages, are refused. */
/* MsV1_0RosNtlmV2Response (ReactOS private, see ntlmros.h): the request and the answer are flat, without pointers.
 * lsass allocates the answer in this process, maybe above the guest's limit: it is copied into a block below it
 * and the native one is released. */
static NTSTATUS RequestRosNtlmV2(HANDLE Port, WOW64_LSA_BODY *Body, LSA_API_MSG *Native, ULONG Package, ULONG Buffer,
                                 ULONG Length)
{
    PVOID Submit;
    PVOID Return = NULL;
    ULONG ReturnLength = 0, GuestReturn = 0;
    NTSTATUS Status = STATUS_SUCCESS, Written = STATUS_SUCCESS, Result;

    if (Length > 0x4100)
        return STATUS_INVALID_PARAMETER;
    Submit = RtlAllocateHeap(RtlGetProcessHeap(), 0, Length);
    if (!Submit) return STATUS_NO_MEMORY;
    _SEH2_TRY
    {
        RtlCopyMemory(Submit, PTR32(Buffer), Length);
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        Status = _SEH2_GetExceptionCode();
    }
    _SEH2_END;
    if (!NT_SUCCESS(Status))
    {
        RtlFreeHeap(RtlGetProcessHeap(), 0, Submit);
        return Status;
    }

    InitNative(Native, LSASS_REQUEST_CALL_AUTHENTICATION_PACKAGE, LSA_PORT_DATA_SIZE(Native->CallAuthenticationPackage));
    Native->CallAuthenticationPackage.Request.AuthenticationPackage = Package;
    Native->CallAuthenticationPackage.Request.ProtocolSubmitBuffer = Submit;
    Native->CallAuthenticationPackage.Request.SubmitBufferLength = Length;
    Status = NtRequestWaitReplyPort(Port, &Native->h, &Native->h);
    RtlFreeHeap(RtlGetProcessHeap(), 0, Submit);
    if (!NT_SUCCESS(Status)) return Status;

    Result = Native->Status;
    Return = Native->CallAuthenticationPackage.Reply.ProtocolReturnBuffer;
    ReturnLength = Native->CallAuthenticationPackage.Reply.ReturnBufferLength;
    if (NT_SUCCESS(Result) && Return)
    {
        PVOID Block = NULL;

        /* The answer holds proofs: wiped when it is released */
        if (NT_SUCCESS(Wow64Allocate(ReturnLength, &Block)))
        {
            RtlCopyMemory(Block, Return, ReturnLength);
            GuestReturn = PtrToUlong(Block);
        }
        else
        {
            ReturnLength = 0;
            Result = STATUS_NO_MEMORY;
        }
        RtlSecureZeroMemory(Return, Native->CallAuthenticationPackage.Reply.ReturnBufferLength);
        FreeBlock(Return);
    }
    _SEH2_TRY
    {
        Body->Status = Result;
        Body->CallReply.ProtocolReturnBuffer = GuestReturn;
        Body->CallReply.ReturnBufferLength = GuestReturn ? ReturnLength : 0;
        Body->CallReply.ProtocolStatus = Native->CallAuthenticationPackage.Reply.ProtocolStatus;
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        Written = _SEH2_GetExceptionCode();
    }
    _SEH2_END;
    if (!NT_SUCCESS(Written) && GuestReturn)
    {
        SIZE_T Zero = 0;
        PVOID Block = UlongToPtr(GuestReturn);

        NtFreeVirtualMemory(NtCurrentProcess(), &Block, &Zero, MEM_RELEASE);
    }
    return NT_SUCCESS(Written) ? STATUS_SUCCESS : Written;
}

static NTSTATUS RequestCallPackage(ULONG Number, HANDLE Port, WOW64_LSA_BODY *Body, LSA_API_MSG *Native,
                                   BOOLEAN *Reported)
{
    ULONG Package, Length, Buffer, MessageType = 0, Msv1_0 = 0, NativeLength = 0;
    PVOID Submit = NULL;
    NTSTATUS Status = STATUS_SUCCESS, Written = STATUS_SUCCESS, Result;

    Package = Body->CallRequest.AuthenticationPackage;
    Buffer = Body->CallRequest.ProtocolSubmitBuffer;
    Length = Body->CallRequest.SubmitBufferLength;
    if (Length < sizeof(ULONG) || !InGuest(Buffer, Length))
        return STATUS_INVALID_PARAMETER;
    _SEH2_TRY
    {
        MessageType = *(ULONG *)PTR32(Buffer);
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        Status = _SEH2_GetExceptionCode();
    }
    _SEH2_END;
    if (!NT_SUCCESS(Status)) return Status;
    Status = Msv1_0PackageId(Port, &Msv1_0);
    if (!NT_SUCCESS(Status)) return Status;
    if (Package == Msv1_0 && MessageType == MsV1_0RosNtlmV2Response)
        return RequestRosNtlmV2(Port, Body, Native, Package, Buffer, Length);
    if (Package != Msv1_0 || MessageType != MsV1_0ChangePassword)
    {
        /* Reported with the message type, or 0xffffffff for another package */
        return Wow64Unsupported(Number, WOW64_UNSUPPORTED_CLASS, Package != Msv1_0 ? 0xffffffff : MessageType,
                                Reported);
    }
    Status = ChangePasswordFrom32(Buffer, Length, &Submit, &NativeLength);
    if (!NT_SUCCESS(Status)) return Status;

    InitNative(Native, LSASS_REQUEST_CALL_AUTHENTICATION_PACKAGE, LSA_PORT_DATA_SIZE(Native->CallAuthenticationPackage));
    Native->CallAuthenticationPackage.Request.AuthenticationPackage = Package;
    Native->CallAuthenticationPackage.Request.ProtocolSubmitBuffer = Submit;
    Native->CallAuthenticationPackage.Request.SubmitBufferLength = NativeLength;
    Status = NtRequestWaitReplyPort(Port, &Native->h, &Native->h);
    RtlSecureZeroMemory(Submit, NativeLength);
    RtlFreeHeap(RtlGetProcessHeap(), 0, Submit);
    if (!NT_SUCCESS(Status)) return Status;

    Result = Native->Status;
    /* MSV1_0 returns nothing for a password change; whatever came back is released, not converted */
    if (NT_SUCCESS(Result) && Native->CallAuthenticationPackage.Reply.ProtocolReturnBuffer)
        FreeBlock(Native->CallAuthenticationPackage.Reply.ProtocolReturnBuffer);
    _SEH2_TRY
    {
        Body->Status = Result;
        Body->CallReply.ProtocolReturnBuffer = 0;
        Body->CallReply.ReturnBufferLength = 0;
        Body->CallReply.ProtocolStatus = Native->CallAuthenticationPackage.Reply.ProtocolStatus;
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        Written = _SEH2_GetExceptionCode();
    }
    _SEH2_END;
    return NT_SUCCESS(Written) ? STATUS_SUCCESS : Written;
}

/* NtRequestWaitReplyPort(PortHandle, PPORT_MESSAGE LpcRequest, PPORT_MESSAGE LpcReply): the request
 * and the reply of an LSA call share one message, as lsalib sends it. */
#define NEEDED(Member) (sizeof(WOW64_PORT_MESSAGE) + FIELD_OFFSET(WOW64_LSA_BODY, Member) + sizeof(((WOW64_LSA_BODY *)0)->Member))

NTSTATUS Wow64LpcRequest(ULONG Number, ULONG Handle, ULONG Request, ULONG Reply, BOOLEAN *Reported)
{
    WOW64_PORT_MESSAGE Header;
    WOW64_LSA_BODY *Body;
    LSA_API_MSG Native;
    ULONG DataLength, Api;
    NTSTATUS Status;

    if (!IsLsaPort(Handle) || Request != Reply)
        return Wow64Unsupported(Number, WOW64_UNSUPPORTED_SERVICE, 2, Reported);
    if (!InGuest(Request, sizeof(Header) + FIELD_OFFSET(WOW64_LSA_BODY, LogonRequest)))
        return STATUS_ACCESS_VIOLATION;
    RtlCopyMemory(&Header, PTR32(Request), sizeof(Header));
    DataLength = Header.DataLength;
    if (Header.TotalLength < sizeof(Header) + DataLength || !InGuest(Request, (ULONG64)Header.TotalLength) ||
        DataLength < FIELD_OFFSET(WOW64_LSA_BODY, LogonRequest))
        return STATUS_INVALID_PARAMETER;
    Body = (WOW64_LSA_BODY *)((PUCHAR)PTR32(Request) + sizeof(Header));
    Api = Body->ApiNumber;

    switch (Api)
    {
    case LSASS_REQUEST_LOGON_USER:
        Status = RequestLogonUser(Number, HANDLE32(Handle), PTR32(Request), DataLength, Header.TotalLength, &Native);
        break;
    case LSASS_REQUEST_LOOKUP_AUTHENTICATION_PACKAGE:
        if (DataLength < FIELD_OFFSET(WOW64_LSA_BODY, LookupRequest) + sizeof(Body->LookupRequest))
            return STATUS_INVALID_PARAMETER;
        RtlZeroMemory(&Native, sizeof(Native));
        Native.ApiNumber = Api;
        Native.h.u1.s1.DataLength = LSA_PORT_DATA_SIZE(Native.LookupAuthenticationPackage);
        Native.h.u1.s1.TotalLength = LSA_PORT_MESSAGE_SIZE;
        Native.LookupAuthenticationPackage.Request.PackageNameLength = Body->LookupRequest.PackageNameLength;
        RtlCopyMemory(Native.LookupAuthenticationPackage.Request.PackageName, Body->LookupRequest.PackageName,
                      sizeof(Native.LookupAuthenticationPackage.Request.PackageName));
        Status = NtRequestWaitReplyPort(HANDLE32(Handle), &Native.h, &Native.h);
        if (NT_SUCCESS(Status))
        {
            Body->Status = Native.Status;
            Body->LookupReply.Package = Native.LookupAuthenticationPackage.Reply.Package;
        }
        break;
    case LSASS_REQUEST_DEREGISTER_LOGON_PROCESS:
        RtlZeroMemory(&Native, sizeof(Native));
        Native.ApiNumber = Api;
        Native.h.u1.s1.DataLength = LSA_PORT_DATA_SIZE(Native.DeregisterLogonProcess);
        Native.h.u1.s1.TotalLength = LSA_PORT_MESSAGE_SIZE;
        Status = NtRequestWaitReplyPort(HANDLE32(Handle), &Native.h, &Native.h);
        if (NT_SUCCESS(Status))
            Body->Status = Native.Status;
        break;
    case LSASS_REQUEST_CALL_AUTHENTICATION_PACKAGE:
        if (Header.TotalLength < NEEDED(CallReply)) return STATUS_INVALID_PARAMETER;
        Status = RequestCallPackage(Number, HANDLE32(Handle), Body, &Native, Reported);
        if (!NT_SUCCESS(Status)) return Status;
        break;
    case LSASS_REQUEST_ENUM_LOGON_SESSIONS:
        if (Header.TotalLength < NEEDED(EnumReply)) return STATUS_INVALID_PARAMETER;
        Status = RequestEnumSessions(HANDLE32(Handle), Body, &Native);
        break;
    case LSASS_REQUEST_GET_LOGON_SESSION_DATA:
        if (Header.TotalLength < NEEDED(SessionRequest)) return STATUS_INVALID_PARAMETER;
        Status = RequestSessionData(HANDLE32(Handle), Body, &Native);
        break;
    case LSASS_REQUEST_POLICY_CHANGE_NOTIFY:
        if (Header.TotalLength < NEEDED(PolicyRequest)) return STATUS_INVALID_PARAMETER;
        Status = RequestPolicyNotify(HANDLE32(Handle), Body, &Native);
        break;
    default:
        /* Not an LSA request this layer knows */
        return Wow64Unsupported(Number, WOW64_UNSUPPORTED_CLASS, Api, Reported);
    }

    if (NT_SUCCESS(Status))
    {
        WOW64_PORT_MESSAGE *Out = PTR32(Request);
        Out->Type = Native.h.u2.s2.Type;
        Out->ProcessId = HandleToUlong(Native.h.ClientId.UniqueProcess);
        Out->ThreadId = HandleToUlong(Native.h.ClientId.UniqueThread);
        Out->MessageId = Native.h.MessageId;
    }
    return Status;
}
