/*
 * PROJECT:     NitroOS
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Local Security Authority server: values of secret objects encrypted at rest
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

/*
 * The current and old values of every secret object (LsaStorePrivateData, LsaSetSecret) are stored in the
 * SECURITY hive as records encrypted with AES-256-GCM under one random key per installation. The key is not in
 * the registry: it is in the file \SystemRoot\System32\config\LsaKey, whose descriptor grants SYSTEM alone, so a
 * user who can read the registry (registry descriptors are not enforced by default yet), or someone who has a
 * copy of the SECURITY hive file only, reads ciphertext. Someone with the whole disk has both: without a TPM or
 * a boot-time secret nothing on the disk can protect the key. On a volume without file security (FAT) every user
 * can read the key file.
 *
 * Record: header || ciphertext || tag. The associated data is the header, the upper-cased name of the secret
 * (from its registry key) and the name of the attribute, so a record moved to another secret or swapped between
 * the current and the old value does not decrypt. Anything that is not a valid record under the loaded key fails
 * closed for that secret (STATUS_INTERNAL_DB_CORRUPTION); a value is never returned as stored plaintext once the
 * store has been converted.
 *
 * Conversion of plaintext values stored by earlier versions runs once, before the RPC server starts, and
 * survives a power cut at any point (LsapProtectValue). The policy attribute PolSecPr says that it has run to
 * completion; from then on values are never classified again.
 *
 * The key is made when it is first needed (the first secret written, or the conversion), written to
 * LsaKey.new, flushed and renamed, and only then used. In memory it is kept encrypted with RtlEncryptMemory and
 * decrypted only for the duration of one encryption or decryption.
 */

#include "lsasrv.h"
#include <ndk/iofuncs.h>
#include <symcrypt.h>

SYMCRYPT_ENVIRONMENT_DEFS(WindowsUsermodeWin8_1nLater);

/* advapi32: RtlGenRandom, RtlEncryptMemory, RtlDecryptMemory */
BOOLEAN WINAPI SystemFunction036(PVOID Buffer, ULONG Length);
NTSTATUS WINAPI SystemFunction040(PVOID Memory, ULONG MemorySize, ULONG OptionFlags);
NTSTATUS WINAPI SystemFunction041(PVOID Memory, ULONG MemorySize, ULONG OptionFlags);

void *__cdecl _aligned_malloc(size_t Size, size_t Alignment);
void __cdecl _aligned_free(void *Block);

#define LSAP_KEY_SIZE           32
#define LSAP_KEY_ID_SIZE        16
#define LSAP_NONCE_SIZE         12
#define LSAP_TAG_SIZE           16
#define LSAP_RECORD_VERSION     1
#define LSAP_ALGORITHM_AES_GCM  1
#define LSAP_STORE_PROTECTED    1   /* value of the policy attribute PolSecPr */
#define LSAP_MAX_PLAIN_LENGTH   0x7FFF0000

#include <pshpack1.h>
typedef struct _LSAP_SECRET_RECORD
{
    UCHAR Magic[8];
    USHORT Version;
    USHORT Algorithm;
    ULONG PlainLength;
    UCHAR KeyId[LSAP_KEY_ID_SIZE];
    UCHAR Nonce[LSAP_NONCE_SIZE];
    ULONG Reserved;
    /* ciphertext (PlainLength bytes), tag (LSAP_TAG_SIZE bytes) */
} LSAP_SECRET_RECORD, *PLSAP_SECRET_RECORD;

typedef struct _LSAP_KEY_FILE
{
    UCHAR Magic[8];
    ULONG Version;
    ULONG Algorithm;
    UCHAR KeyId[LSAP_KEY_ID_SIZE];
    UCHAR Key[LSAP_KEY_SIZE];
    UCHAR Check[SYMCRYPT_SHA256_RESULT_SIZE];   /* SHA-256 of the fields before it: detects a damaged file */
} LSAP_KEY_FILE, *PLSAP_KEY_FILE;
#include <poppack.h>

C_ASSERT(sizeof(LSAP_SECRET_RECORD) == 48);
C_ASSERT(sizeof(LSAP_KEY_FILE) == 96);

#define LSAP_RECORD_OVERHEAD    (sizeof(LSAP_SECRET_RECORD) + LSAP_TAG_SIZE)

/* Every second byte is non-zero, so no UTF-16 text made of ASCII characters starts with it */
static const UCHAR LsapRecordMagic[8] = {0x4C, 0xA7, 0x53, 0xE5, 0x43, 0xB1, 0x52, 0x9D};
static const UCHAR LsapKeyFileMagic[8] = {'L', 'S', 'A', 'K', 'E', 'Y', '0', '1'};

static const WCHAR LsapKeyFileName[] = L"\\SystemRoot\\System32\\config\\LsaKey";
static const WCHAR LsapKeyFileNewName[] = L"\\SystemRoot\\System32\\config\\LsaKey.new";
static WCHAR LsapPendingValueName[] = L"Pending";
static WCHAR LsapDefaultValueName[] = L"";

static RTL_CRITICAL_SECTION LsapKeyLock;
static BOOLEAN LsapKeyLockReady = FALSE;
static BOOLEAN LsapKeyLooked = FALSE;       /* the key file has been read (or found missing) */
static NTSTATUS LsapKeyState = STATUS_OBJECT_NAME_NOT_FOUND;   /* success: a key is loaded */
static UCHAR LsapKeyId[LSAP_KEY_ID_SIZE];
static UCHAR LsapKeyHidden[LSAP_KEY_SIZE];  /* RtlEncryptMemory(SAME_PROCESS) of the key */


/* SymCrypt callbacks *********************************************************/

void * SYMCRYPT_CALL SymCryptCallbackAlloc(SIZE_T Size)
{
    return _aligned_malloc(Size, SYMCRYPT_ASYM_ALIGN_VALUE);
}

void SYMCRYPT_CALL SymCryptCallbackFree(void *Block)
{
    _aligned_free(Block);
}

SYMCRYPT_ERROR SYMCRYPT_CALL SymCryptCallbackRandom(BYTE *Buffer, SIZE_T Size)
{
    return SystemFunction036(Buffer, (ULONG)Size) ? SYMCRYPT_NO_ERROR : SYMCRYPT_EXTERNAL_FAILURE;
}


/* Helpers ********************************************************************/

static PVOID
LsapAllocWiped(SIZE_T Size)
{
    return RtlAllocateHeap(RtlGetProcessHeap(), HEAP_ZERO_MEMORY, Size ? Size : 1);
}

static VOID
LsapFreeWiped(PVOID Buffer, SIZE_T Size)
{
    if (Buffer == NULL)
        return;
    RtlSecureZeroMemory(Buffer, Size);
    RtlFreeHeap(RtlGetProcessHeap(), 0, Buffer);
}

VOID
LsapFreeSecretValue(PVOID Value, ULONG Length)
{
    LsapFreeWiped(Value, Length);
}

/* Wipes the bytes of a value a client sent (the stub's copy, freed after the call without being wiped) */
VOID
LsapWipeCipherValue(PLSAPR_CR_CIPHER_VALUE Value)
{
    if (Value == NULL || Value->Buffer == NULL)
        return;
    RtlSecureZeroMemory(Value->Buffer, min(Value->Length, Value->MaximumLength));
}

/* A value of a key, read into a buffer of its own (the query buffer is wiped) */
static NTSTATUS
LsapReadRawValue(HANDLE KeyHandle,
                 LPWSTR ValueName,
                 PULONG Type,
                 PUCHAR *Data,
                 PULONG DataLength)
{
    PKEY_VALUE_PARTIAL_INFORMATION Info = NULL;
    UNICODE_STRING Name;
    ULONG InfoLength = FIELD_OFFSET(KEY_VALUE_PARTIAL_INFORMATION, Data) + 256;
    ULONG Needed;
    NTSTATUS Status;

    *Data = NULL;
    *DataLength = 0;
    RtlInitUnicodeString(&Name, ValueName);

    for (;;)
    {
        Info = LsapAllocWiped(InfoLength);
        if (Info == NULL)
            return STATUS_INSUFFICIENT_RESOURCES;

        Needed = 0;
        Status = NtQueryValueKey(KeyHandle, &Name, KeyValuePartialInformation, Info, InfoLength, &Needed);
        if (Status != STATUS_BUFFER_OVERFLOW && Status != STATUS_BUFFER_TOO_SMALL)
            break;

        LsapFreeWiped(Info, InfoLength);
        Info = NULL;
        if (Needed <= InfoLength)
            return STATUS_INTERNAL_ERROR;
        InfoLength = Needed;
    }

    if (NT_SUCCESS(Status))
    {
        *Data = LsapAllocWiped(Info->DataLength);
        if (*Data == NULL)
        {
            Status = STATUS_INSUFFICIENT_RESOURCES;
        }
        else
        {
            RtlCopyMemory(*Data, Info->Data, Info->DataLength);
            *DataLength = Info->DataLength;
            if (Type != NULL)
                *Type = Info->Type;
        }
    }

    LsapFreeWiped(Info, InfoLength);
    return Status;
}

/* The upper-cased name of a registry key (the name of a secret: part of its records' associated data) */
static NTSTATUS
LsapGetUpcasedKeyName(HANDLE KeyHandle,
                      PUNICODE_STRING UpcasedName)
{
    PKEY_BASIC_INFORMATION Info;
    ULONG InfoLength = sizeof(KEY_BASIC_INFORMATION) + 256 * sizeof(WCHAR);
    ULONG Needed = 0;
    UNICODE_STRING Name;
    NTSTATUS Status;

    Info = LsapAllocWiped(InfoLength);
    if (Info == NULL)
        return STATUS_INSUFFICIENT_RESOURCES;

    Status = NtQueryKey(KeyHandle, KeyBasicInformation, Info, InfoLength, &Needed);
    if ((Status == STATUS_BUFFER_OVERFLOW || Status == STATUS_BUFFER_TOO_SMALL) && Needed > InfoLength)
    {
        LsapFreeWiped(Info, InfoLength);
        InfoLength = Needed;
        Info = LsapAllocWiped(InfoLength);
        if (Info == NULL)
            return STATUS_INSUFFICIENT_RESOURCES;
        Status = NtQueryKey(KeyHandle, KeyBasicInformation, Info, InfoLength, &Needed);
    }

    if (NT_SUCCESS(Status))
    {
        if (Info->NameLength > MAXUSHORT - sizeof(WCHAR))
        {
            Status = STATUS_NAME_TOO_LONG;
        }
        else
        {
            Name.Buffer = Info->Name;
            Name.Length = (USHORT)Info->NameLength;
            Name.MaximumLength = Name.Length;
            Status = RtlUpcaseUnicodeString(UpcasedName, &Name, TRUE);
        }
    }

    LsapFreeWiped(Info, InfoLength);
    return Status;
}

static NTSTATUS
LsapUpcaseName(LPCWSTR Name, PUNICODE_STRING UpcasedName)
{
    UNICODE_STRING String;

    RtlInitUnicodeString(&String, Name);
    return RtlUpcaseUnicodeString(UpcasedName, &String, TRUE);
}


/* The key file ***************************************************************/

static NTSTATUS
LsapKeyFileSd(PSECURITY_DESCRIPTOR Sd, PACL Dacl, ULONG DaclSize)
{
    NTSTATUS Status;

    Status = RtlCreateSecurityDescriptor(Sd, SECURITY_DESCRIPTOR_REVISION);
    if (NT_SUCCESS(Status))
        Status = RtlCreateAcl(Dacl, DaclSize, ACL_REVISION);
    if (NT_SUCCESS(Status))
        Status = RtlAddAccessAllowedAce(Dacl, ACL_REVISION, FILE_ALL_ACCESS, LsapLocalSystemSid);
    if (NT_SUCCESS(Status))
        Status = RtlSetDaclSecurityDescriptor(Sd, TRUE, Dacl, FALSE);
    if (NT_SUCCESS(Status))
        Status = RtlSetOwnerSecurityDescriptor(Sd, LsapLocalSystemSid, FALSE);
    if (NT_SUCCESS(Status))
        Status = RtlSetControlSecurityDescriptor(Sd, SE_DACL_PROTECTED, SE_DACL_PROTECTED);
    return Status;
}

static VOID
LsapKeyFileChecksum(PLSAP_KEY_FILE File, PUCHAR Check)
{
    SymCryptSha256((PCBYTE)File, FIELD_OFFSET(LSAP_KEY_FILE, Check), Check);
}

/*
 * The file system keeps the key file's descriptor (SYSTEM alone), else other users can read the key: said once
 * per start. Asked of the file itself: a volume's FILE_PERSISTENT_ACLS flag is not reliable (ntfsng enforces
 * descriptors without reporting it).
 */
static VOID
LsapCheckKeyFileSecurity(HANDLE FileHandle)
{
    ULONG_PTR Buffer[128];
    PSECURITY_DESCRIPTOR Sd = (PSECURITY_DESCRIPTOR)Buffer;
    PACCESS_ALLOWED_ACE Ace;
    PACL Dacl = NULL;
    BOOLEAN Present = FALSE, Defaulted = FALSE, Sound = FALSE;
    ULONG Needed = 0;
    NTSTATUS Status;

    Status = NtQuerySecurityObject(FileHandle, DACL_SECURITY_INFORMATION, Sd, sizeof(Buffer), &Needed);
    if (NT_SUCCESS(Status))
        Status = RtlGetDaclSecurityDescriptor(Sd, &Present, &Dacl, &Defaulted);
    if (NT_SUCCESS(Status) && Present && Dacl != NULL && Dacl->AceCount == 1 &&
        NT_SUCCESS(RtlGetAce(Dacl, 0, (PVOID *)&Ace)) &&
        Ace->Header.AceType == ACCESS_ALLOWED_ACE_TYPE &&
        RtlEqualSid((PSID)&Ace->SidStart, LsapLocalSystemSid))
    {
        Sound = TRUE;
    }

    if (!Sound)
        ERR("The LSA secret key file does not have its SYSTEM-only descriptor (Status 0x%08lx): "
            "on this file system other users may read the key\n", Status);
}

/* Reads and checks a key file: success (the key in File), not found, or STATUS_INTERNAL_DB_CORRUPTION */
static NTSTATUS
LsapReadKeyFile(LPCWSTR Path, PLSAP_KEY_FILE File)
{
    OBJECT_ATTRIBUTES ObjectAttributes;
    UNICODE_STRING Name;
    IO_STATUS_BLOCK Iosb;
    FILE_STANDARD_INFORMATION Standard;
    UCHAR Check[SYMCRYPT_SHA256_RESULT_SIZE];
    HANDLE FileHandle;
    NTSTATUS Status;

    RtlInitUnicodeString(&Name, Path);
    InitializeObjectAttributes(&ObjectAttributes, &Name, OBJ_CASE_INSENSITIVE, NULL, NULL);

    Status = NtOpenFile(&FileHandle,
                        FILE_GENERIC_READ,
                        &ObjectAttributes,
                        &Iosb,
                        FILE_SHARE_READ,
                        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT);
    if (Status == STATUS_OBJECT_NAME_NOT_FOUND || Status == STATUS_OBJECT_PATH_NOT_FOUND)
        return STATUS_OBJECT_NAME_NOT_FOUND;
    if (!NT_SUCCESS(Status))
    {
        ERR("The LSA secret key file cannot be opened (Status 0x%08lx)\n", Status);
        return STATUS_INTERNAL_DB_CORRUPTION;
    }

    Status = NtQueryInformationFile(FileHandle, &Iosb, &Standard, sizeof(Standard), FileStandardInformation);
    if (NT_SUCCESS(Status) && Standard.EndOfFile.QuadPart != sizeof(LSAP_KEY_FILE))
        Status = STATUS_INTERNAL_DB_CORRUPTION;
    if (NT_SUCCESS(Status))
        Status = NtReadFile(FileHandle, NULL, NULL, NULL, &Iosb, File, sizeof(*File), NULL, NULL);
    if (NT_SUCCESS(Status) && Iosb.Information != sizeof(*File))
        Status = STATUS_INTERNAL_DB_CORRUPTION;

    if (NT_SUCCESS(Status))
        LsapCheckKeyFileSecurity(FileHandle);

    NtClose(FileHandle);

    if (NT_SUCCESS(Status))
    {
        LsapKeyFileChecksum(File, Check);
        if (RtlCompareMemory(File->Magic, LsapKeyFileMagic, sizeof(File->Magic)) != sizeof(File->Magic) ||
            File->Version != LSAP_RECORD_VERSION ||
            File->Algorithm != LSAP_ALGORITHM_AES_GCM ||
            RtlCompareMemory(File->Check, Check, sizeof(Check)) != sizeof(Check))
        {
            Status = STATUS_INTERNAL_DB_CORRUPTION;
        }
    }

    if (!NT_SUCCESS(Status))
    {
        RtlSecureZeroMemory(File, sizeof(*File));
        return STATUS_INTERNAL_DB_CORRUPTION;
    }

    return STATUS_SUCCESS;
}

static VOID
LsapDeleteFileByName(LPCWSTR Path)
{
    OBJECT_ATTRIBUTES ObjectAttributes;
    UNICODE_STRING Name;

    RtlInitUnicodeString(&Name, Path);
    InitializeObjectAttributes(&ObjectAttributes, &Name, OBJ_CASE_INSENSITIVE, NULL, NULL);
    NtDeleteFile(&ObjectAttributes);
}

/*
 * Best effort: the directory entry of the key file reaches the disk before any record made with the key does
 * (a file system that cannot flush a directory leaves it to its own metadata writes; a key whose rename was lost
 * is found again as LsaKey.new by LsapLookForKey)
 */
static VOID
LsapFlushKeyDirectory(VOID)
{
    OBJECT_ATTRIBUTES ObjectAttributes;
    UNICODE_STRING Name = RTL_CONSTANT_STRING(L"\\SystemRoot\\System32\\config");
    IO_STATUS_BLOCK Iosb;
    HANDLE Directory;

    InitializeObjectAttributes(&ObjectAttributes, &Name, OBJ_CASE_INSENSITIVE, NULL, NULL);
    if (NT_SUCCESS(NtOpenFile(&Directory, FILE_ADD_FILE | SYNCHRONIZE, &ObjectAttributes, &Iosb,
                              FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                              FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT)))
    {
        NtFlushBuffersFile(Directory, &Iosb);
        NtClose(Directory);
    }
}

/* Renames LsaKey.new to LsaKey (never over an existing LsaKey) and flushes it */
static NTSTATUS
LsapCommitKeyFile(HANDLE NewFileHandle)
{
    /* The I/O manager checks the alignment of the information: no byte array */
    union
    {
        FILE_RENAME_INFORMATION Info;
        UCHAR Bytes[sizeof(FILE_RENAME_INFORMATION) + sizeof(LsapKeyFileName)];
    } Buffer;
    PFILE_RENAME_INFORMATION Rename = &Buffer.Info;
    IO_STATUS_BLOCK Iosb;
    NTSTATUS Status;

    RtlZeroMemory(&Buffer, sizeof(Buffer));
    Rename->ReplaceIfExists = FALSE;
    Rename->RootDirectory = NULL;
    Rename->FileNameLength = sizeof(LsapKeyFileName) - sizeof(WCHAR);
    RtlCopyMemory(Rename->FileName, LsapKeyFileName, Rename->FileNameLength);

    Status = NtSetInformationFile(NewFileHandle, &Iosb, Rename, sizeof(Buffer), FileRenameInformation);
    if (NT_SUCCESS(Status))
    {
        NtFlushBuffersFile(NewFileHandle, &Iosb);
        LsapFlushKeyDirectory();
    }
    return Status;
}

static VOID
LsapLoadKey(PLSAP_KEY_FILE File)
{
    RtlCopyMemory(LsapKeyId, File->KeyId, sizeof(LsapKeyId));
    RtlCopyMemory(LsapKeyHidden, File->Key, sizeof(LsapKeyHidden));
    if (!NT_SUCCESS(SystemFunction040(LsapKeyHidden, sizeof(LsapKeyHidden), 0)))
    {
        RtlSecureZeroMemory(LsapKeyHidden, sizeof(LsapKeyHidden));
        ERR("The LSA secret key cannot be protected in memory\n");
        LsapKeyState = STATUS_INTERNAL_ERROR;
        return;
    }
    LsapKeyState = STATUS_SUCCESS;
}

/* Under LsapKeyLock: the key file is read once; a valid LsaKey.new left by a cut before its rename is finished */
static VOID
LsapLookForKey(VOID)
{
    LSAP_KEY_FILE File;
    OBJECT_ATTRIBUTES ObjectAttributes;
    UNICODE_STRING Name;
    IO_STATUS_BLOCK Iosb;
    HANDLE FileHandle;
    NTSTATUS Status;

    LsapKeyLooked = TRUE;

    Status = LsapReadKeyFile(LsapKeyFileName, &File);
    if (NT_SUCCESS(Status))
    {
        LsapDeleteFileByName(LsapKeyFileNewName);
        LsapLoadKey(&File);
        RtlSecureZeroMemory(&File, sizeof(File));
        return;
    }

    if (Status != STATUS_OBJECT_NAME_NOT_FOUND)
    {
        /* Never overwritten: an administrator removes it, then the next write makes a new key */
        ERR("The LSA secret key file is damaged: stored secrets cannot be read or written\n");
        LsapKeyState = STATUS_INTERNAL_DB_CORRUPTION;
        return;
    }

    Status = LsapReadKeyFile(LsapKeyFileNewName, &File);
    if (NT_SUCCESS(Status))
    {
        RtlInitUnicodeString(&Name, LsapKeyFileNewName);
        InitializeObjectAttributes(&ObjectAttributes, &Name, OBJ_CASE_INSENSITIVE, NULL, NULL);
        Status = NtOpenFile(&FileHandle, DELETE | SYNCHRONIZE, &ObjectAttributes, &Iosb, 0,
                            FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT);
        if (NT_SUCCESS(Status))
        {
            Status = LsapCommitKeyFile(FileHandle);
            NtClose(FileHandle);
        }
        if (NT_SUCCESS(Status))
        {
            WARN("The LSA secret key file was completed after an interrupted creation\n");
            LsapLoadKey(&File);
            RtlSecureZeroMemory(&File, sizeof(File));
            return;
        }
        RtlSecureZeroMemory(&File, sizeof(File));
    }

    LsapDeleteFileByName(LsapKeyFileNewName);
    LsapKeyState = STATUS_OBJECT_NAME_NOT_FOUND;
}

/* Under LsapKeyLock: a new key, durable on disk before it is used */
static NTSTATUS
LsapCreateKey(VOID)
{
    SECURITY_DESCRIPTOR SdBuffer;
    ULONG_PTR DaclBuffer[16];
    LSAP_KEY_FILE File;
    OBJECT_ATTRIBUTES ObjectAttributes;
    UNICODE_STRING Name;
    IO_STATUS_BLOCK Iosb;
    FILE_DISPOSITION_INFORMATION Disposition;
    HANDLE FileHandle = NULL;
    NTSTATUS Status;

    Status = LsapKeyFileSd(&SdBuffer, (PACL)DaclBuffer, sizeof(DaclBuffer));
    if (!NT_SUCCESS(Status))
        return Status;

    RtlZeroMemory(&File, sizeof(File));
    RtlCopyMemory(File.Magic, LsapKeyFileMagic, sizeof(File.Magic));
    File.Version = LSAP_RECORD_VERSION;
    File.Algorithm = LSAP_ALGORITHM_AES_GCM;
    if (!SystemFunction036(File.KeyId, sizeof(File.KeyId)) ||
        !SystemFunction036(File.Key, sizeof(File.Key)))
    {
        RtlSecureZeroMemory(&File, sizeof(File));
        ERR("No random data for the LSA secret key: the secret is not stored\n");
        return STATUS_INTERNAL_ERROR;
    }
    LsapKeyFileChecksum(&File, File.Check);

    LsapDeleteFileByName(LsapKeyFileNewName);

    RtlInitUnicodeString(&Name, LsapKeyFileNewName);
    InitializeObjectAttributes(&ObjectAttributes, &Name, OBJ_CASE_INSENSITIVE, NULL, &SdBuffer);
    Status = NtCreateFile(&FileHandle,
                          FILE_GENERIC_WRITE | DELETE,
                          &ObjectAttributes,
                          &Iosb,
                          NULL,
                          FILE_ATTRIBUTE_NORMAL,
                          0,
                          FILE_CREATE,
                          FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | FILE_WRITE_THROUGH,
                          NULL,
                          0);
    if (!NT_SUCCESS(Status))
    {
        RtlSecureZeroMemory(&File, sizeof(File));
        ERR("The LSA secret key file cannot be created (Status 0x%08lx)\n", Status);
        return Status;
    }

    Status = NtWriteFile(FileHandle, NULL, NULL, NULL, &Iosb, &File, sizeof(File), NULL, NULL);
    if (NT_SUCCESS(Status) && Iosb.Information != sizeof(File))
        Status = STATUS_DISK_FULL;
    if (NT_SUCCESS(Status))
        Status = NtFlushBuffersFile(FileHandle, &Iosb);
    if (NT_SUCCESS(Status))
        Status = LsapCommitKeyFile(FileHandle);

    if (!NT_SUCCESS(Status))
    {
        ERR("The LSA secret key file cannot be written (Status 0x%08lx)\n", Status);
        Disposition.DeleteFile = TRUE;
        NtSetInformationFile(FileHandle, &Iosb, &Disposition, sizeof(Disposition), FileDispositionInformation);
        NtClose(FileHandle);
        RtlSecureZeroMemory(&File, sizeof(File));
        return Status;
    }

    LsapCheckKeyFileSecurity(FileHandle);
    NtClose(FileHandle);

    LsapLoadKey(&File);
    RtlSecureZeroMemory(&File, sizeof(File));
    return LsapKeyState;
}

/*
 * The expanded key for one operation (aligned heap, the caller wipes and frees it with LsapPutKey).
 * Create: make the key if there is none (a write); a read without a key fails closed.
 */
static NTSTATUS
LsapGetKey(BOOLEAN Create,
           PUCHAR KeyId,
           PSYMCRYPT_GCM_EXPANDED_KEY *ExpandedKey)
{
    UCHAR Key[LSAP_KEY_SIZE];
    PSYMCRYPT_GCM_EXPANDED_KEY Expanded;
    NTSTATUS Status;

    *ExpandedKey = NULL;

    /* LsapInitSecretProtection did not run (the database could not be opened at the start) */
    if (!LsapKeyLockReady)
        return STATUS_INTERNAL_ERROR;

    Expanded = _aligned_malloc(sizeof(*Expanded), SYMCRYPT_ASYM_ALIGN_VALUE);
    if (Expanded == NULL)
        return STATUS_INSUFFICIENT_RESOURCES;

    RtlEnterCriticalSection(&LsapKeyLock);

    if (!LsapKeyLooked)
        LsapLookForKey();

    if (LsapKeyState == STATUS_OBJECT_NAME_NOT_FOUND && Create)
        LsapCreateKey();

    Status = LsapKeyState;
    if (Status == STATUS_OBJECT_NAME_NOT_FOUND)
        Status = Create ? STATUS_INTERNAL_ERROR : STATUS_INTERNAL_DB_CORRUPTION;

    if (NT_SUCCESS(Status))
    {
        RtlCopyMemory(Key, LsapKeyHidden, sizeof(Key));
        Status = SystemFunction041(Key, sizeof(Key), 0);
        if (NT_SUCCESS(Status))
        {
            if (SymCryptGcmExpandKey(Expanded, SymCryptAesBlockCipher, Key, sizeof(Key)) != SYMCRYPT_NO_ERROR)
                Status = STATUS_INTERNAL_ERROR;
        }
        else
        {
            Status = STATUS_INTERNAL_ERROR;
        }
        SymCryptWipeKnownSize(Key, sizeof(Key));
        RtlCopyMemory(KeyId, LsapKeyId, LSAP_KEY_ID_SIZE);
    }

    RtlLeaveCriticalSection(&LsapKeyLock);

    if (!NT_SUCCESS(Status))
    {
        SymCryptWipe(Expanded, sizeof(*Expanded));
        _aligned_free(Expanded);
        return Status;
    }

    *ExpandedKey = Expanded;
    return STATUS_SUCCESS;
}

static VOID
LsapPutKey(PSYMCRYPT_GCM_EXPANDED_KEY Expanded)
{
    if (Expanded == NULL)
        return;
    SymCryptWipe(Expanded, sizeof(*Expanded));
    _aligned_free(Expanded);
}


/* Records *********************************************************************/

/* Associated data: the header, then the length and bytes of the upper-cased secret name and of the attribute name */
static PUCHAR
LsapBuildAad(PLSAP_SECRET_RECORD Header,
             PCUNICODE_STRING UpcasedSecretName,
             PCUNICODE_STRING UpcasedAttributeName,
             PSIZE_T AadLength)
{
    SIZE_T Length = sizeof(*Header) + sizeof(ULONG) + UpcasedSecretName->Length + sizeof(ULONG) + UpcasedAttributeName->Length;
    PUCHAR Aad, p;
    ULONG n;

    Aad = LsapAllocWiped(Length);
    if (Aad == NULL)
        return NULL;

    p = Aad;
    RtlCopyMemory(p, Header, sizeof(*Header));
    p += sizeof(*Header);
    n = UpcasedSecretName->Length;
    RtlCopyMemory(p, &n, sizeof(n));
    p += sizeof(n);
    RtlCopyMemory(p, UpcasedSecretName->Buffer, n);
    p += n;
    n = UpcasedAttributeName->Length;
    RtlCopyMemory(p, &n, sizeof(n));
    p += sizeof(n);
    RtlCopyMemory(p, UpcasedAttributeName->Buffer, n);

    *AadLength = Length;
    return Aad;
}

/* Has the shape of a record (magic and a consistent length); says nothing about its authenticity */
static BOOLEAN
LsapIsRecordShaped(PUCHAR Data, ULONG Length)
{
    PLSAP_SECRET_RECORD Header = (PLSAP_SECRET_RECORD)Data;

    if (Data == NULL || Length < LSAP_RECORD_OVERHEAD)
        return FALSE;
    if (RtlCompareMemory(Header->Magic, LsapRecordMagic, sizeof(Header->Magic)) != sizeof(Header->Magic))
        return FALSE;
    return Header->PlainLength <= LSAP_MAX_PLAIN_LENGTH &&
           Length == LSAP_RECORD_OVERHEAD + Header->PlainLength;
}

static NTSTATUS
LsapEncryptRecord(PCUNICODE_STRING UpcasedSecretName,
                  PCUNICODE_STRING UpcasedAttributeName,
                  PVOID Plain,
                  ULONG PlainLength,
                  PUCHAR *Record,
                  PULONG RecordLength)
{
    PSYMCRYPT_GCM_EXPANDED_KEY Expanded = NULL;
    PLSAP_SECRET_RECORD Header;
    PUCHAR Buffer, Aad;
    SIZE_T AadLength;
    ULONG Length;
    NTSTATUS Status;

    *Record = NULL;
    *RecordLength = 0;

    if (PlainLength > LSAP_MAX_PLAIN_LENGTH || (Plain == NULL && PlainLength != 0))
        return STATUS_INVALID_PARAMETER;

    Length = LSAP_RECORD_OVERHEAD + PlainLength;
    Buffer = LsapAllocWiped(Length);
    if (Buffer == NULL)
        return STATUS_INSUFFICIENT_RESOURCES;

    Header = (PLSAP_SECRET_RECORD)Buffer;
    Status = LsapGetKey(TRUE, Header->KeyId, &Expanded);
    if (!NT_SUCCESS(Status))
    {
        LsapFreeWiped(Buffer, Length);
        return Status;
    }

    RtlCopyMemory(Header->Magic, LsapRecordMagic, sizeof(Header->Magic));
    Header->Version = LSAP_RECORD_VERSION;
    Header->Algorithm = LSAP_ALGORITHM_AES_GCM;
    Header->PlainLength = PlainLength;
    Header->Reserved = 0;
    if (!SystemFunction036(Header->Nonce, sizeof(Header->Nonce)))
    {
        LsapPutKey(Expanded);
        LsapFreeWiped(Buffer, Length);
        return STATUS_INTERNAL_ERROR;
    }

    Aad = LsapBuildAad(Header, UpcasedSecretName, UpcasedAttributeName, &AadLength);
    if (Aad == NULL)
    {
        LsapPutKey(Expanded);
        LsapFreeWiped(Buffer, Length);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    SymCryptGcmEncrypt(Expanded,
                       Header->Nonce, sizeof(Header->Nonce),
                       Aad, AadLength,
                       Plain, Buffer + sizeof(*Header), PlainLength,
                       Buffer + sizeof(*Header) + PlainLength, LSAP_TAG_SIZE);

    LsapPutKey(Expanded);
    LsapFreeWiped(Aad, AadLength);

    *Record = Buffer;
    *RecordLength = Length;
    return STATUS_SUCCESS;
}

/* The plaintext of a record (heap, LsapFreeSecretValue), or STATUS_INTERNAL_DB_CORRUPTION */
static NTSTATUS
LsapDecryptRecord(PCUNICODE_STRING UpcasedSecretName,
                  PCUNICODE_STRING UpcasedAttributeName,
                  PUCHAR Record,
                  ULONG RecordLength,
                  PVOID *Plain,
                  PULONG PlainLength)
{
    PSYMCRYPT_GCM_EXPANDED_KEY Expanded = NULL;
    PLSAP_SECRET_RECORD Header = (PLSAP_SECRET_RECORD)Record;
    UCHAR KeyId[LSAP_KEY_ID_SIZE];
    PUCHAR Buffer, Aad;
    SIZE_T AadLength;
    SYMCRYPT_ERROR Error;
    NTSTATUS Status;

    *Plain = NULL;
    *PlainLength = 0;

    if (!LsapIsRecordShaped(Record, RecordLength) ||
        Header->Version != LSAP_RECORD_VERSION ||
        Header->Algorithm != LSAP_ALGORITHM_AES_GCM)
    {
        return STATUS_INTERNAL_DB_CORRUPTION;
    }

    Status = LsapGetKey(FALSE, KeyId, &Expanded);
    if (!NT_SUCCESS(Status))
        return STATUS_INTERNAL_DB_CORRUPTION;

    if (RtlCompareMemory(KeyId, Header->KeyId, sizeof(KeyId)) != sizeof(KeyId))
    {
        LsapPutKey(Expanded);
        return STATUS_INTERNAL_DB_CORRUPTION;
    }

    Buffer = LsapAllocWiped(Header->PlainLength);
    Aad = LsapBuildAad(Header, UpcasedSecretName, UpcasedAttributeName, &AadLength);
    if (Buffer == NULL || Aad == NULL)
    {
        LsapPutKey(Expanded);
        LsapFreeWiped(Buffer, Header->PlainLength);
        LsapFreeWiped(Aad, Aad ? AadLength : 0);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    Error = SymCryptGcmDecrypt(Expanded,
                               Header->Nonce, sizeof(Header->Nonce),
                               Aad, AadLength,
                               Record + sizeof(*Header), Buffer, Header->PlainLength,
                               Record + sizeof(*Header) + Header->PlainLength, LSAP_TAG_SIZE);

    LsapPutKey(Expanded);
    LsapFreeWiped(Aad, AadLength);

    if (Error != SYMCRYPT_NO_ERROR)
    {
        LsapFreeWiped(Buffer, Header->PlainLength);
        return STATUS_INTERNAL_DB_CORRUPTION;
    }

    *Plain = Buffer;
    *PlainLength = Header->PlainLength;
    return STATUS_SUCCESS;
}

static BOOLEAN
LsapRecordAuthenticates(PCUNICODE_STRING UpcasedSecretName,
                        PCUNICODE_STRING UpcasedAttributeName,
                        PUCHAR Record,
                        ULONG RecordLength)
{
    PVOID Plain;
    ULONG PlainLength;

    if (!NT_SUCCESS(LsapDecryptRecord(UpcasedSecretName, UpcasedAttributeName, Record, RecordLength,
                                      &Plain, &PlainLength)))
        return FALSE;
    LsapFreeSecretValue(Plain, PlainLength);
    return TRUE;
}


/* Secret values (lsarpc.c) ****************************************************/

/* Stores Data as the encrypted value of the attribute (CurrentValue or OldValue) of a secret object */
NTSTATUS
LsapSetSecretValue(PLSA_DB_OBJECT SecretObject,
                   LPWSTR AttributeName,
                   PVOID Data,
                   ULONG DataLength)
{
    UNICODE_STRING SecretName = {0, 0, NULL};
    UNICODE_STRING Attribute = {0, 0, NULL};
    PUCHAR Record = NULL;
    ULONG RecordLength = 0;
    NTSTATUS Status;

    Status = LsapGetUpcasedKeyName(SecretObject->KeyHandle, &SecretName);
    if (NT_SUCCESS(Status))
        Status = LsapUpcaseName(AttributeName, &Attribute);
    if (NT_SUCCESS(Status))
        Status = LsapEncryptRecord(&SecretName, &Attribute, Data, DataLength, &Record, &RecordLength);
    if (NT_SUCCESS(Status))
        Status = LsapSetObjectAttribute(SecretObject, AttributeName, Record, RecordLength);
    else
        ERR("The value of a secret cannot be encrypted (Status 0x%08lx)\n", Status);

    LsapFreeWiped(Record, RecordLength);
    RtlFreeUnicodeString(&Attribute);
    RtlFreeUnicodeString(&SecretName);
    return Status;
}

/*
 * The decrypted value of the attribute of a secret object, in a heap buffer the caller frees with
 * LsapFreeSecretValue. A missing attribute gives the status the stored value's query gave before (unchanged);
 * a value that is not a valid record under the loaded key gives STATUS_INTERNAL_DB_CORRUPTION.
 */
NTSTATUS
LsapGetSecretValue(PLSA_DB_OBJECT SecretObject,
                   LPWSTR AttributeName,
                   PVOID *Data,
                   PULONG DataLength)
{
    UNICODE_STRING SecretName = {0, 0, NULL};
    UNICODE_STRING Attribute = {0, 0, NULL};
    PUCHAR Record = NULL;
    ULONG RecordLength = 0;
    NTSTATUS Status;

    *Data = NULL;
    *DataLength = 0;

    /* The size, then the value: the queries of the stored value as before */
    Status = LsapGetObjectAttribute(SecretObject, AttributeName, NULL, &RecordLength);
    if (!NT_SUCCESS(Status))
        return Status;

    Record = LsapAllocWiped(RecordLength);
    if (Record == NULL)
        return STATUS_INSUFFICIENT_RESOURCES;

    Status = LsapGetObjectAttribute(SecretObject, AttributeName, Record, &RecordLength);
    if (NT_SUCCESS(Status))
        Status = LsapGetUpcasedKeyName(SecretObject->KeyHandle, &SecretName);
    if (NT_SUCCESS(Status))
        Status = LsapUpcaseName(AttributeName, &Attribute);
    if (NT_SUCCESS(Status))
    {
        Status = LsapDecryptRecord(&SecretName, &Attribute, Record, RecordLength, Data, DataLength);
        if (!NT_SUCCESS(Status))
            ERR("The %S of secret %wZ cannot be decrypted: refused (Status 0x%08lx)\n",
                AttributeName, &SecretName, Status);
    }

    LsapFreeWiped(Record, RecordLength);
    RtlFreeUnicodeString(&Attribute);
    RtlFreeUnicodeString(&SecretName);
    return Status;
}


/* Conversion of stored plaintext **********************************************/

static NTSTATUS
LsapWriteValueFlushed(HANDLE KeyHandle, LPWSTR ValueName, ULONG Type, PVOID Data, ULONG Length)
{
    NTSTATUS Status;

    Status = LsapRegSetValue(KeyHandle, ValueName, Type, Data, Length);
    if (NT_SUCCESS(Status))
        Status = NtFlushKey(KeyHandle);
    return Status;
}

static NTSTATUS
LsapDeleteValueFlushed(HANDLE KeyHandle, LPWSTR ValueName)
{
    NTSTATUS Status;

    Status = LsapRegDeleteValue(KeyHandle, ValueName);
    if (NT_SUCCESS(Status) || Status == STATUS_OBJECT_NAME_NOT_FOUND)
        Status = NtFlushKey(KeyHandle);
    return Status;
}

/*
 * Replaces the stored value of an attribute key by Record, with the record in "Pending" first: steps 2-4 below
 * leave either the old value or a valid record reachable after a cut at any point, and a later start finishes
 * them. The old value is overwritten in place with zeros of the same length first (the configuration manager
 * re-uses a data cell for data that fits), so its plaintext does not stay in a freed cell of the hive.
 */
static NTSTATUS
LsapReplaceWithRecord(HANDLE AttributeKey,
                      PUCHAR OldValue,
                      ULONG OldLength,
                      ULONG OldType,
                      PUCHAR Record,
                      ULONG RecordLength,
                      BOOLEAN PendingWritten)
{
    PUCHAR Zeros;
    NTSTATUS Status = STATUS_SUCCESS;

    /* 1. the record, where a cut cannot lose it */
    if (!PendingWritten)
    {
        Status = LsapWriteValueFlushed(AttributeKey, LsapPendingValueName, REG_NONE, Record, RecordLength);
        if (!NT_SUCCESS(Status))
            return Status;
    }

    /* 2. the old value overwritten in place */
    if (OldValue != NULL && OldLength != 0)
    {
        Zeros = LsapAllocWiped(OldLength);
        if (Zeros == NULL)
            return STATUS_INSUFFICIENT_RESOURCES;
        Status = LsapWriteValueFlushed(AttributeKey, LsapDefaultValueName, OldType, Zeros, OldLength);
        LsapFreeWiped(Zeros, OldLength);
        if (!NT_SUCCESS(Status))
            return Status;
    }

    /* 3. the record as the value */
    Status = LsapWriteValueFlushed(AttributeKey, LsapDefaultValueName, REG_NONE, Record, RecordLength);
    if (!NT_SUCCESS(Status))
        return Status;

    /* 4. no second copy */
    return LsapDeleteValueFlushed(AttributeKey, LsapPendingValueName);
}

/* One attribute (CurrentValue or OldValue) of one secret; FALSE: it could not be converted (retried next start) */
static BOOLEAN
LsapProtectValue(HANDLE SecretKey,
                 PCUNICODE_STRING UpcasedSecretName,
                 LPWSTR AttributeName,
                 PULONG Converted,
                 PULONG Refused)
{
    UNICODE_STRING Attribute = {0, 0, NULL};
    HANDLE AttributeKey = NULL;
    PUCHAR Value = NULL, Pending = NULL, Record = NULL;
    ULONG ValueLength = 0, PendingLength = 0, RecordLength = 0, ValueType = REG_NONE;
    BOOLEAN HaveValue, Done = FALSE;
    NTSTATUS Status;

    Status = LsapRegOpenKey(SecretKey, AttributeName, KEY_QUERY_VALUE | KEY_SET_VALUE, &AttributeKey);
    if (!NT_SUCCESS(Status))
        return (Status == STATUS_OBJECT_NAME_NOT_FOUND);    /* no such attribute: nothing to protect */

    Status = LsapUpcaseName(AttributeName, &Attribute);
    if (!NT_SUCCESS(Status))
        goto done;

    Status = LsapReadRawValue(AttributeKey, LsapDefaultValueName, &ValueType, &Value, &ValueLength);
    if (!NT_SUCCESS(Status) && Status != STATUS_OBJECT_NAME_NOT_FOUND)
        goto done;
    HaveValue = NT_SUCCESS(Status);

    /* A conversion cut short: its record, if it is valid, is the value */
    Status = LsapReadRawValue(AttributeKey, LsapPendingValueName, NULL, &Pending, &PendingLength);
    if (NT_SUCCESS(Status))
    {
        if (LsapRecordAuthenticates(UpcasedSecretName, &Attribute, Pending, PendingLength))
        {
            if (HaveValue && LsapRecordAuthenticates(UpcasedSecretName, &Attribute, Value, ValueLength))
                Status = LsapDeleteValueFlushed(AttributeKey, LsapPendingValueName);
            else
                Status = LsapReplaceWithRecord(AttributeKey,
                                               (HaveValue && !LsapIsRecordShaped(Value, ValueLength)) ? Value : NULL,
                                               ValueLength, ValueType, Pending, PendingLength, TRUE);
            if (NT_SUCCESS(Status))
                (*Converted)++;
            Done = NT_SUCCESS(Status);
            goto done;
        }

        /*
         * A registry value is written whole, so a Pending record that does not decrypt was not cut short: the key
         * it was made with is gone (or the hive was changed). The value may already be zeroed (step 2): never take
         * it for plaintext. Both stay as they are; the secret fails closed and this is tried again at every start.
         */
        ERR("The %S of secret %wZ has a conversion record that cannot be decrypted: left as it is\n",
            AttributeName, UpcasedSecretName);
        (*Refused)++;
        Status = STATUS_INTERNAL_DB_CORRUPTION;
        goto done;
    }
    else if (Status != STATUS_OBJECT_NAME_NOT_FOUND)
    {
        goto done;
    }

    if (!HaveValue)
    {
        Done = TRUE;
        goto done;
    }

    if (LsapIsRecordShaped(Value, ValueLength))
    {
        /* Converted before, or damaged: never taken for plaintext */
        if (!LsapRecordAuthenticates(UpcasedSecretName, &Attribute, Value, ValueLength))
        {
            ERR("The %S of secret %wZ is not a valid record: it stays unreadable\n", AttributeName, UpcasedSecretName);
            (*Refused)++;
        }
        Done = TRUE;
        goto done;
    }

    /* Plaintext stored by an earlier version */
    Status = LsapEncryptRecord(UpcasedSecretName, &Attribute, Value, ValueLength, &Record, &RecordLength);
    if (NT_SUCCESS(Status))
        Status = LsapReplaceWithRecord(AttributeKey, Value, ValueLength, ValueType, Record, RecordLength, FALSE);
    if (NT_SUCCESS(Status))
        (*Converted)++;
    Done = NT_SUCCESS(Status);

done:
    if (!Done)
        ERR("The %S of secret %wZ cannot be protected now (Status 0x%08lx): retried at the next start\n",
            AttributeName, UpcasedSecretName, Status);

    LsapFreeWiped(Record, RecordLength);
    LsapFreeWiped(Pending, PendingLength);
    LsapFreeWiped(Value, ValueLength);
    RtlFreeUnicodeString(&Attribute);
    if (AttributeKey != NULL)
        NtClose(AttributeKey);
    return Done;
}

static NTSTATUS
LsapSetStoreProtected(PLSA_DB_OBJECT PolicyObject)
{
    ULONG Value = LSAP_STORE_PROTECTED;
    NTSTATUS Status;

    Status = LsapSetObjectAttribute(PolicyObject, L"PolSecPr", &Value, sizeof(Value));
    if (NT_SUCCESS(Status))
        Status = NtFlushKey(PolicyObject->KeyHandle);
    return Status;
}

static VOID
LsapProtectStoredSecrets(PLSA_DB_OBJECT PolicyObject)
{
    UNICODE_STRING SecretName = {0, 0, NULL};
    PKEY_BASIC_INFORMATION Info = NULL;
    ULONG InfoLength = sizeof(KEY_BASIC_INFORMATION) + 512 * sizeof(WCHAR);
    ULONG Needed, Index, Secrets = 0, Converted = 0, Refused = 0;
    HANDLE SecretsKey = NULL, SecretKey;
    UNICODE_STRING Name;
    OBJECT_ATTRIBUTES ObjectAttributes;
    BOOLEAN AllDone = TRUE;
    NTSTATUS Status;

    Status = LsapRegOpenKey(PolicyObject->KeyHandle, L"Secrets", KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE, &SecretsKey);
    if (!NT_SUCCESS(Status) && Status != STATUS_OBJECT_NAME_NOT_FOUND)
    {
        ERR("The stored secrets cannot be listed (Status 0x%08lx): their protection is retried at the next start\n", Status);
        return;
    }

    if (NT_SUCCESS(Status))
    {
        Info = LsapAllocWiped(InfoLength);
        if (Info == NULL)
        {
            NtClose(SecretsKey);
            return;
        }

        for (Index = 0; ; Index++)
        {
            Needed = 0;
            Status = NtEnumerateKey(SecretsKey, Index, KeyBasicInformation, Info, InfoLength, &Needed);
            if (Status == STATUS_NO_MORE_ENTRIES)
                break;
            if (!NT_SUCCESS(Status) || Info->NameLength > MAXUSHORT - sizeof(WCHAR))
            {
                AllDone = FALSE;
                break;
            }

            if (Secrets == 0)
                ERR("LSA: protecting the stored secret values\n");
            Secrets++;

            Name.Buffer = Info->Name;
            Name.Length = (USHORT)Info->NameLength;
            Name.MaximumLength = Name.Length;

            InitializeObjectAttributes(&ObjectAttributes, &Name, OBJ_CASE_INSENSITIVE, SecretsKey, NULL);
            Status = NtOpenKey(&SecretKey, KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE, &ObjectAttributes);
            if (!NT_SUCCESS(Status))
            {
                AllDone = FALSE;
                continue;
            }

            Status = RtlUpcaseUnicodeString(&SecretName, &Name, TRUE);
            if (NT_SUCCESS(Status))
            {
                if (!LsapProtectValue(SecretKey, &SecretName, L"CurrentValue", &Converted, &Refused))
                    AllDone = FALSE;
                if (!LsapProtectValue(SecretKey, &SecretName, L"OldValue", &Converted, &Refused))
                    AllDone = FALSE;
                RtlFreeUnicodeString(&SecretName);
            }
            else
            {
                AllDone = FALSE;
            }

            NtClose(SecretKey);
        }

        LsapFreeWiped(Info, InfoLength);
        NtClose(SecretsKey);
    }

    if (Secrets != 0)
        ERR("LSA: %lu secrets, %lu values protected now, %lu unreadable, %s\n",
            Secrets, Converted, Refused, AllDone ? "done" : "not complete: retried at the next start");

    if (AllDone)
    {
        Status = LsapSetStoreProtected(PolicyObject);
        if (!NT_SUCCESS(Status))
            ERR("The protection of the stored secrets cannot be recorded (Status 0x%08lx)\n", Status);
    }
}

/*
 * At the start of lsass, before the RPC server: NewDatabase marks a database made now as converted; otherwise
 * plaintext values left by an earlier version are converted (once: until PolSecPr records it).
 */
VOID
LsapInitSecretProtection(BOOLEAN NewDatabase)
{
    PLSA_DB_OBJECT PolicyObject = NULL;
    ULONG Value = 0, Size = sizeof(Value);
    NTSTATUS Status;

    if (!LsapKeyLockReady)
    {
        RtlInitializeCriticalSection(&LsapKeyLock);
        LsapKeyLockReady = TRUE;
        SymCryptInit();
    }

    Status = LsapOpenDbObject(NULL, NULL, L"Policy", LsaDbPolicyObject, 0, TRUE, &PolicyObject);
    if (!NT_SUCCESS(Status))
    {
        ERR("The policy object cannot be opened (Status 0x%08lx)\n", Status);
        return;
    }

    if (NewDatabase)
    {
        Status = LsapSetStoreProtected(PolicyObject);
        if (!NT_SUCCESS(Status))
            ERR("The protection of the stored secrets cannot be recorded (Status 0x%08lx)\n", Status);
    }
    else
    {
        Status = LsapGetObjectAttribute(PolicyObject, L"PolSecPr", &Value, &Size);
        if (!NT_SUCCESS(Status) || Size != sizeof(Value) || Value != LSAP_STORE_PROTECTED)
            LsapProtectStoredSecrets(PolicyObject);
    }

    LsapCloseDbObject(PolicyObject);
}

/* EOF */
