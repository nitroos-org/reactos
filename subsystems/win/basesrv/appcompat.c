/*
 * COPYRIGHT:       See COPYING in the top level directory
 * PROJECT:         ReactOS Base API Server DLL
 * FILE:            subsystems/win/basesrv/appcompat.c
 * PURPOSE:         Initialization
 * PROGRAMMERS:     Timo Kreuzer (timo.kreuzer@reactos.org)
 */

/* INCLUDES *******************************************************************/

#include "basesrv.h"
#include "api.h"

#include <ndk/iofuncs.h>

#ifndef REG_BINARY
#define REG_BINARY 3
#endif

#define NDEBUG
#include <debug.h>

/* GLOBALS ********************************************************************/

typedef struct _BASE_APP_COMPAT_EXTRA1
{
    WCHAR String1[32];
    ULONG tdwFlags;
    ULONG SizeOfStruct;
    ULONG tdwMagic;
    ULONG ttrExe;
    ULONG dword50;
    ULONG dword54;
    ULONG dword58;
    PVOID ttrLayer;
    CHAR String2[28];
    ULONG dword7C;
    ULONG dword80;
    ULONG field_84;
    CHAR String3[256];
} BASE_APP_COMPAT_EXTRA1, *PBASE_APP_COMPAT_EXTRA1;

typedef struct _BASE_APP_COMPAT_DATA
{
    UNICODE_STRING FileName;
    HANDLE ProcessHandle;
    ULONG Flags;
    USHORT Code;
    USHORT Unknown_012;
    PVOID Environment;
    ULONG EnvironmentSize;
    PBASE_APP_COMPAT_EXTRA1 AppCompExtra1;
    ULONG AppCompExtra1Size;
    PVOID AppCompExtra2;
    ULONG AppCompExtra2Size;
    BOOL CheckRunAppResult;
    ULONG Flags2;
} BASE_APP_COMPAT_DATA, *PBASE_APP_COMPAT_DATA;

/* PUBLIC SERVER APIS *********************************************************/

CSR_API(BaseSrvCheckApplicationCompatibility)
{
    PBASE_APP_COMPAT_DATA AppCompatData = (PBASE_APP_COMPAT_DATA)&ApiMessage->Data;
    DPRINT1("BASESRV: BaseSrvCheckApplicationCompatibility(%wZ)\n",
           AppCompatData->FileName);

    AppCompatData->CheckRunAppResult = FALSE;

    return STATUS_SUCCESS;
}

/*
 * The kernel application compatibility cache (ntoskrnl/ps/apphelp.c) says "no shim database entry" for an
 * image it knows by name, size and last write time. The kernel takes an insert from a caller with
 * SeTcbPrivilege only, so the client library (kernel32 BasepShimCacheUpdate) asks this server, which has it.
 */

static const UNICODE_STRING AppCompatCacheKeyName =
    RTL_CONSTANT_STRING(L"\\Registry\\MACHINE\\System\\CurrentControlSet\\Control\\Session Manager\\AppCompatCache");
static const UNICODE_STRING AppCompatDbStampName = RTL_CONSTANT_STRING(L"DbStamp");
static const UNICODE_STRING SysMainSdbName = RTL_CONSTANT_STRING(L"\\SystemRoot\\AppPatch\\sysmain.sdb");

typedef struct _APPCOMPAT_DB_STAMP
{
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER EndOfFile;
} APPCOMPAT_DB_STAMP;

/* The shim database a cache entry was checked against is the system database plus the installed ones;
 * installing or removing one flushes the cache (apphelp). A system database replaced while the system
 * was down is noticed here: the cache the kernel loaded from the registry is flushed when the system
 * database is not the one the cache was built with. */
VOID
BaseSrvValidateAppcompatCache(VOID)
{
    OBJECT_ATTRIBUTES ObjectAttributes;
    IO_STATUS_BLOCK IoStatusBlock;
    FILE_BASIC_INFORMATION Basic;
    FILE_STANDARD_INFORMATION Standard;
    APPCOMPAT_DB_STAMP Current = {{{0}}}, Saved;
    UCHAR Buffer[sizeof(KEY_VALUE_PARTIAL_INFORMATION) + sizeof(Saved)];
    PKEY_VALUE_PARTIAL_INFORMATION Info = (PVOID)Buffer;
    HANDLE FileHandle, KeyHandle;
    ULONG Length;
    NTSTATUS Status;

    InitializeObjectAttributes(&ObjectAttributes, (PUNICODE_STRING)&SysMainSdbName, OBJ_CASE_INSENSITIVE, NULL, NULL);
    Status = NtOpenFile(&FileHandle, FILE_READ_ATTRIBUTES | SYNCHRONIZE, &ObjectAttributes, &IoStatusBlock,
                        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_SYNCHRONOUS_IO_NONALERT);
    if (NT_SUCCESS(Status))
    {
        if (NT_SUCCESS(NtQueryInformationFile(FileHandle, &IoStatusBlock, &Basic, sizeof(Basic), FileBasicInformation)) &&
            NT_SUCCESS(NtQueryInformationFile(FileHandle, &IoStatusBlock, &Standard, sizeof(Standard), FileStandardInformation)))
        {
            Current.LastWriteTime = Basic.LastWriteTime;
            Current.EndOfFile = Standard.EndOfFile;
        }
        NtClose(FileHandle);
    }

    InitializeObjectAttributes(&ObjectAttributes, (PUNICODE_STRING)&AppCompatCacheKeyName, OBJ_CASE_INSENSITIVE, NULL, NULL);
    Status = NtCreateKey(&KeyHandle, KEY_QUERY_VALUE | KEY_SET_VALUE, &ObjectAttributes, 0, NULL,
                         REG_OPTION_NON_VOLATILE, NULL);
    if (!NT_SUCCESS(Status)) return;

    Status = NtQueryValueKey(KeyHandle, (PUNICODE_STRING)&AppCompatDbStampName, KeyValuePartialInformation,
                             Info, sizeof(Buffer), &Length);
    if (!NT_SUCCESS(Status) || Info->Type != REG_BINARY || Info->DataLength != sizeof(Saved) ||
        (RtlCopyMemory(&Saved, Info->Data, sizeof(Saved)), !RtlEqualMemory(&Saved, &Current, sizeof(Saved))))
    {
        DPRINT("BASESRV: the system shim database changed, flushing the appcompat cache\n");
        NtApphelpCacheControl(ApphelpCacheServiceFlush, NULL);
        NtSetValueKey(KeyHandle, (PUNICODE_STRING)&AppCompatDbStampName, 0, REG_BINARY, &Current, sizeof(Current));
    }
    NtClose(KeyHandle);
}

/* Is Handle a file on a local disk volume, and is it the same file as the NT path? (both opened for attributes only) */
static
NTSTATUS
BaseSrvCheckImageIdentity(IN HANDLE Handle, IN PUNICODE_STRING NtName)
{
    OBJECT_ATTRIBUTES ObjectAttributes;
    IO_STATUS_BLOCK IoStatusBlock;
    FILE_FS_DEVICE_INFORMATION Device;
    FILE_INTERNAL_INFORMATION Index1, Index2;
    FILE_FS_VOLUME_INFORMATION Volume1, Volume2;
    HANDLE ByName;
    NTSTATUS Status;

    Status = NtQueryVolumeInformationFile(Handle, &IoStatusBlock, &Device, sizeof(Device), FileFsDeviceInformation);
    if (!NT_SUCCESS(Status)) return Status;
    /* Only images on a local disk are cached: nothing else reports the file's identity reliably */
    if (Device.DeviceType != FILE_DEVICE_DISK && Device.DeviceType != FILE_DEVICE_DISK_FILE_SYSTEM)
        return STATUS_NOT_SUPPORTED;
    if (Device.Characteristics & (FILE_REMOTE_DEVICE | FILE_REMOVABLE_MEDIA))
        return STATUS_NOT_SUPPORTED;

    InitializeObjectAttributes(&ObjectAttributes, NtName, OBJ_CASE_INSENSITIVE, NULL, NULL);
    Status = NtOpenFile(&ByName, FILE_READ_ATTRIBUTES | SYNCHRONIZE, &ObjectAttributes, &IoStatusBlock,
                        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT);
    if (!NT_SUCCESS(Status)) return Status;

    RtlZeroMemory(&Index1, sizeof(Index1));
    RtlZeroMemory(&Index2, sizeof(Index2));
    Status = NtQueryInformationFile(Handle, &IoStatusBlock, &Index1, sizeof(Index1), FileInternalInformation);
    if (NT_SUCCESS(Status))
        Status = NtQueryInformationFile(ByName, &IoStatusBlock, &Index2, sizeof(Index2), FileInternalInformation);
    if (NT_SUCCESS(Status))
        Status = NtQueryVolumeInformationFile(Handle, &IoStatusBlock, &Volume1, sizeof(Volume1), FileFsVolumeInformation);
    if (NT_SUCCESS(Status) || Status == STATUS_BUFFER_OVERFLOW)
        Status = NtQueryVolumeInformationFile(ByName, &IoStatusBlock, &Volume2, sizeof(Volume2), FileFsVolumeInformation);
    if (Status == STATUS_BUFFER_OVERFLOW) Status = STATUS_SUCCESS; /* the label does not fit, the rest does */
    NtClose(ByName);
    if (!NT_SUCCESS(Status)) return Status;

    if (!Index1.IndexNumber.QuadPart ||
        Index1.IndexNumber.QuadPart != Index2.IndexNumber.QuadPart ||
        Volume1.VolumeSerialNumber != Volume2.VolumeSerialNumber ||
        Volume1.VolumeCreationTime.QuadPart != Volume2.VolumeCreationTime.QuadPart)
        return STATUS_NOT_SAME_DEVICE;
    return STATUS_SUCCESS;
}

CSR_API(BaseSrvUpdateAppcompatCache)
{
    PBASE_APPCOMPAT_CACHE_UPDATE Request = &((PBASE_API_MESSAGE)ApiMessage)->Data.AppcompatCacheUpdate;
    PCSR_THREAD CsrThread = CsrGetClientThread();
    APPHELP_CACHE_SERVICE_LOOKUP Update;
    UNICODE_STRING Name;
    HANDLE Handle;
    ULONG Length = Request->ImageNameLength;
    NTSTATUS Status;

    if (!CsrThread) return STATUS_INVALID_PARAMETER;
    if (!Length || (Length & 1) || Length > 0x7FFE ||
        !CsrValidateMessageBuffer(ApiMessage, (PVOID*)&Request->ImageName, Length, sizeof(BYTE)))
        return STATUS_INVALID_PARAMETER;

    /* The handle is the client's own, with the access the client has to the image */
    Status = NtDuplicateObject(CsrThread->Process->ProcessHandle, Request->ImageHandle, NtCurrentProcess(),
                               &Handle, FILE_READ_ATTRIBUTES, 0, 0);
    if (!NT_SUCCESS(Status)) return Status;

    Name.Length = (USHORT)Length;
    Name.MaximumLength = (USHORT)(Length + sizeof(WCHAR));
    Name.Buffer = RtlAllocateHeap(RtlGetProcessHeap(), 0, Name.MaximumLength);
    if (!Name.Buffer)
    {
        NtClose(Handle);
        return STATUS_NO_MEMORY;
    }
    RtlCopyMemory(Name.Buffer, Request->ImageName, Length);
    Name.Buffer[Length / sizeof(WCHAR)] = UNICODE_NULL;

    /* The name is an NT path as CreateProcess has it (\??\C:\dir\image.exe, a local drive letter only). It and the handle must name
     * the same file: a client cannot enter an image it did not check under another name. */
    if (Length < 7 * sizeof(WCHAR) || _wcsnicmp(Name.Buffer, L"\\??\\", 4) ||
        !((Name.Buffer[4] >= L'A' && Name.Buffer[4] <= L'Z') || (Name.Buffer[4] >= L'a' && Name.Buffer[4] <= L'z')) ||
        Name.Buffer[5] != L':' || Name.Buffer[6] != L'\\')
        Status = STATUS_OBJECT_PATH_SYNTAX_BAD;
    else
        Status = BaseSrvCheckImageIdentity(Handle, &Name);
    if (NT_SUCCESS(Status))
    {
        Update.ImageName = Name;
        Update.ImageHandle = Handle;
        Status = NtApphelpCacheControl(ApphelpCacheServiceUpdate, &Update);
    }
    RtlFreeHeap(RtlGetProcessHeap(), 0, Name.Buffer);
    NtClose(Handle);
    return Status;
}

/* EOF */
