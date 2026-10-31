/*
 * PROJECT:     ReactOS NT User Mode Library
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Small Rtl functions that ntdll exports on Windows 8 and later
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Behaviour, including the answers to inputs a caller should not pass, measured on Windows 10 22H2 (x64 and x86).
 */

#include <ntdll.h>

#define NDEBUG
#include <debug.h>

/* MISC *********************************************************************/

BOOLEAN
NTAPI
RtlIsZeroMemory(
    _In_reads_bytes_(Length) PVOID Buffer,
    _In_ SIZE_T Length)
{
    const UCHAR *Bytes = Buffer;

    while (Length != 0)
    {
        if (*Bytes++ != 0)
            return FALSE;
        Length--;
    }

    return TRUE;
}

#ifdef _M_IX86
/* x86 ntdll exports the function; on 64-bit builds it is in the runtime library and not exported by name */
VOID
NTAPI
RtlpFillMemoryUlonglong32(
    _Out_writes_bytes_all_(Length) PVOID Destination,
    _In_ SIZE_T Length,
    _In_ ULONGLONG Fill)
{
    PULONG Dest = Destination;
    SIZE_T Count = Length / sizeof(ULONG);
    BOOLEAN High = FALSE;

    /* Ulong by ulong, the low half first: a length that is no multiple of eight ends in the low half */
    while (Count > 0)
    {
        *Dest++ = High ? (ULONG)(Fill >> 32) : (ULONG)Fill;
        High = !High;
        Count--;
    }
}
#endif

/* The CRC-32C (Castagnoli) of the buffer, continuing the CRC in InitialCrc (0 to start) */
ULONG
NTAPI
RtlCrc32(
    _In_reads_bytes_(Size) const VOID *Buffer,
    _In_ SIZE_T Size,
    _In_ ULONG InitialCrc)
{
    static ULONG Table[256];
    static LONG TableReady;
    const UCHAR *Bytes = Buffer;
    ULONG Crc = ~InitialCrc;

    if (!TableReady)
    {
        ULONG i, j;

        for (i = 0; i < 256; i++)
        {
            ULONG Value = i;

            for (j = 0; j < 8; j++)
                Value = (Value & 1) ? ((Value >> 1) ^ 0x82F63B78) : (Value >> 1);
            Table[i] = Value;
        }
        InterlockedExchange(&TableReady, 1);
    }

    while (Size != 0)
    {
        Crc = Table[(Crc ^ *Bytes++) & 0xFF] ^ (Crc >> 8);
        Size--;
    }

    return ~Crc;
}

BOOLEAN
NTAPI
RtlIsCurrentProcess(
    _In_ HANDLE ProcessHandle)
{
    PROCESS_BASIC_INFORMATION BasicInfo;

    if (ProcessHandle == NtCurrentProcess())
        return TRUE;

    if (!NT_SUCCESS(NtQueryInformationProcess(ProcessHandle,
                                              ProcessBasicInformation,
                                              &BasicInfo,
                                              sizeof(BasicInfo),
                                              NULL)))
    {
        return FALSE;
    }

    return BasicInfo.UniqueProcessId == (ULONG_PTR)NtCurrentTeb()->ClientId.UniqueProcess;
}

BOOLEAN
NTAPI
RtlIsCurrentThread(
    _In_ HANDLE ThreadHandle)
{
    THREAD_BASIC_INFORMATION BasicInfo;

    if (ThreadHandle == NtCurrentThread())
        return TRUE;

    if (!NT_SUCCESS(NtQueryInformationThread(ThreadHandle,
                                             ThreadBasicInformation,
                                             &BasicInfo,
                                             sizeof(BasicInfo),
                                             NULL)))
    {
        return FALSE;
    }

    return BasicInfo.ClientId.UniqueThread == NtCurrentTeb()->ClientId.UniqueThread;
}

/* SHARED USER DATA *********************************************************/

PWSTR
NTAPI
RtlGetNtSystemRoot(VOID)
{
    return SharedUserData->NtSystemRoot;
}

ULONG
NTAPI
RtlGetSuiteMask(VOID)
{
    return SharedUserData->SuiteMask;
}

ULONG
NTAPI
RtlGetActiveConsoleId(VOID)
{
    return SharedUserData->ActiveConsoleId;
}

/*
 * The version is major.minor.build.revision as four words, the revision being the UBR value of the CurrentVersion
 * key (0 where there is none); family 3 is the desktop family, form 0 is unknown.
 */
VOID
NTAPI
RtlGetDeviceFamilyInfoEnum(
    _Out_opt_ PULONGLONG UapInfo,
    _Out_opt_ PULONG DeviceFamily,
    _Out_opt_ PULONG DeviceForm)
{
    if (UapInfo)
    {
        RTL_OSVERSIONINFOW VersionInfo = { sizeof(VersionInfo) };
        ULONG Revision = 0;
        RTL_QUERY_REGISTRY_TABLE QueryTable[2] = { { 0 } };

        RtlGetVersion(&VersionInfo);

        QueryTable[0].Flags = RTL_QUERY_REGISTRY_DIRECT;
        QueryTable[0].Name = L"UBR";
        QueryTable[0].EntryContext = &Revision;
        if (!NT_SUCCESS(RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE,
                                               L"\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion",
                                               QueryTable,
                                               NULL,
                                               NULL)))
        {
            Revision = 0;
        }

        *UapInfo = ((ULONGLONG)(VersionInfo.dwMajorVersion & 0xFFFF) << 48) |
                   ((ULONGLONG)(VersionInfo.dwMinorVersion & 0xFFFF) << 32) |
                   ((ULONGLONG)(VersionInfo.dwBuildNumber & 0xFFFF) << 16) |
                   (Revision & 0xFFFF);
    }

    if (DeviceFamily)
        *DeviceFamily = 3;

    if (DeviceForm)
        *DeviceForm = 0;
}

/* STRINGS ******************************************************************/

BOOLEAN
NTAPI
RtlDoesNameContainWildCards(
    _In_ PCUNICODE_STRING Expression)
{
    PWCHAR Char = Expression->Buffer;
    PWCHAR End = Char + Expression->Length / sizeof(WCHAR);

    for (; Char < End; Char++)
    {
        if (*Char == L'*' || *Char == L'?' || *Char == L'<' || *Char == L'>' || *Char == L'"')
            return TRUE;
    }

    return FALSE;
}

/* The GUID in lower case, as {xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}: 38 characters */
NTSTATUS
NTAPI
RtlStringFromGUIDEx(
    _In_ const GUID *Guid,
    _Inout_ PUNICODE_STRING GuidString,
    _In_ BOOLEAN AllocateGuidString)
{
    static const WCHAR Digits[] = L"0123456789abcdef";
    static const UCHAR Groups[] = { 4, 2, 2, 2, 6 };
    const UCHAR *Bytes[16];
    const UCHAR Order[16] = { 3, 2, 1, 0, 5, 4, 7, 6, 8, 9, 10, 11, 12, 13, 14, 15 };
    ULONG i, Group, Pos = 0;
    PWCHAR Buffer;

    if (AllocateGuidString)
    {
        Buffer = RtlAllocateHeap(RtlGetProcessHeap(), 0, 78);
        if (!Buffer)
            return STATUS_NO_MEMORY;
        GuidString->Buffer = Buffer;
        GuidString->MaximumLength = 78;
    }
    else
    {
        if (GuidString->MaximumLength < 78)
            return STATUS_BUFFER_TOO_SMALL;
        Buffer = GuidString->Buffer;
    }

    for (i = 0; i < 16; i++)
        Bytes[i] = (const UCHAR *)Guid + Order[i];

    Buffer[Pos++] = L'{';
    i = 0;
    for (Group = 0; Group < RTL_NUMBER_OF(Groups); Group++)
    {
        ULONG n;

        if (Group != 0)
            Buffer[Pos++] = L'-';
        for (n = 0; n < Groups[Group]; n++, i++)
        {
            Buffer[Pos++] = Digits[*Bytes[i] >> 4];
            Buffer[Pos++] = Digits[*Bytes[i] & 0xF];
        }
    }
    Buffer[Pos++] = L'}';
    Buffer[Pos] = UNICODE_NULL;

    GuidString->Length = 76;
    return STATUS_SUCCESS;
}

/* ETHERNET ADDRESSES *******************************************************/

typedef struct _DL_EUI48_ADDRESS
{
    UCHAR Byte[6];
} DL_EUI48_ADDRESS;

static
LONG
HexDigitValue(
    _In_ ULONG Char)
{
    if (Char >= '0' && Char <= '9') return Char - '0';
    if (Char >= 'a' && Char <= 'f') return Char - 'a' + 10;
    if (Char >= 'A' && Char <= 'F') return Char - 'A' + 10;
    return -1;
}

PSTR
NTAPI
RtlEthernetAddressToStringA(
    _In_ const DL_EUI48_ADDRESS *Address,
    _Out_writes_(18) PSTR S)
{
    static const CHAR Digits[] = "0123456789ABCDEF";
    ULONG i;

    for (i = 0; i < 6; i++)
    {
        if (i != 0)
            *S++ = '-';
        *S++ = Digits[Address->Byte[i] >> 4];
        *S++ = Digits[Address->Byte[i] & 0xF];
    }
    *S = ANSI_NULL;
    return S;
}

PWSTR
NTAPI
RtlEthernetAddressToStringW(
    _In_ const DL_EUI48_ADDRESS *Address,
    _Out_writes_(18) PWSTR S)
{
    static const WCHAR Digits[] = L"0123456789ABCDEF";
    ULONG i;

    for (i = 0; i < 6; i++)
    {
        if (i != 0)
            *S++ = L'-';
        *S++ = Digits[Address->Byte[i] >> 4];
        *S++ = Digits[Address->Byte[i] & 0xF];
    }
    *S = UNICODE_NULL;
    return S;
}

/* Six pairs of hex digits, each pair after the first led by '-' or ':' (the two may be mixed) */
#define ETHERNET_STRING_TO_ADDRESS(CharType)                                    \
    DL_EUI48_ADDRESS Result;                                                    \
    const CharType *Pos = S;                                                    \
    ULONG i;                                                                    \
                                                                                \
    for (i = 0; i < 6; i++)                                                     \
    {                                                                           \
        LONG High, Low;                                                         \
                                                                                \
        if (i != 0)                                                             \
        {                                                                       \
            if (*Pos != '-' && *Pos != ':')                                     \
                goto Fail;                                                      \
            Pos++;                                                              \
        }                                                                       \
        High = HexDigitValue(Pos[0]);                                           \
        if (High < 0)                                                           \
            goto Fail;                                                          \
        Low = HexDigitValue(Pos[1]);                                            \
        if (Low < 0)                                                            \
        {                                                                       \
            Pos++;                                                              \
            goto Fail;                                                          \
        }                                                                       \
        Result.Byte[i] = (UCHAR)((High << 4) | Low);                            \
        Pos += 2;                                                               \
    }                                                                           \
    *Address = Result;                                                          \
    *Terminator = Pos;                                                          \
    return STATUS_SUCCESS;                                                      \
Fail:                                                                           \
    *Terminator = Pos;                                                          \
    return STATUS_INVALID_PARAMETER;

NTSTATUS
NTAPI
RtlEthernetStringToAddressA(
    _In_ PCSTR S,
    _Out_ PCSTR *Terminator,
    _Out_ DL_EUI48_ADDRESS *Address)
{
    ETHERNET_STRING_TO_ADDRESS(CHAR)
}

NTSTATUS
NTAPI
RtlEthernetStringToAddressW(
    _In_ PCWSTR S,
    _Out_ PCWSTR *Terminator,
    _Out_ DL_EUI48_ADDRESS *Address)
{
    ETHERNET_STRING_TO_ADDRESS(WCHAR)
}
