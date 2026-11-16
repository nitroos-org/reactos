/*
 * PROJECT:         ReactOS CNG kernel mode library
 * LICENSE:         GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:         Minimal cng.sys: SHA-1 hashing through the BCrypt kernel API
 * COPYRIGHT:       Copyright 2026 Tomas Srnka
 *
 * Drivers such as WinFsp import the BCrypt functions from cng.sys, and use them
 * for SHA-1 only. Everything else is refused with STATUS_NOT_SUPPORTED.
 * BCryptGenRandom is forwarded to ksecdd.sys (the system random number generator).
 */

/* INCLUDES *******************************************************************/

#include <ntddk.h>
#include <sha1.h>

#define TAG_CNG 'gnCB'

#define CNG_PROVIDER_MAGIC 'PgnC'
#define CNG_HASH_MAGIC     'HgnC'

#define SHA1_DIGEST_LENGTH 20

typedef struct _CNG_PROVIDER
{
    ULONG Magic;
} CNG_PROVIDER, *PCNG_PROVIDER;

typedef struct _CNG_HASH
{
    ULONG Magic;
    SHA_CTX Context;
} CNG_HASH, *PCNG_HASH;

/* FUNCTIONS ******************************************************************/

NTSTATUS
NTAPI
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);
    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
BCryptOpenAlgorithmProvider(
    _Out_ PVOID *Algorithm,
    _In_ PCWSTR AlgorithmId,
    _In_opt_ PCWSTR Implementation,
    _In_ ULONG Flags)
{
    PCNG_PROVIDER Provider;

    UNREFERENCED_PARAMETER(Implementation);

    *Algorithm = NULL;
    if (AlgorithmId == NULL || _wcsicmp(AlgorithmId, L"SHA1") != 0)
        return STATUS_NOT_SUPPORTED;
    if (Flags != 0)
        return STATUS_NOT_SUPPORTED; /* no HMAC, no reuse */

    Provider = ExAllocatePoolWithTag(PagedPool, sizeof(*Provider), TAG_CNG);
    if (Provider == NULL)
        return STATUS_NO_MEMORY;

    Provider->Magic = CNG_PROVIDER_MAGIC;
    *Algorithm = Provider;
    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
BCryptCloseAlgorithmProvider(
    _Inout_ PVOID Algorithm,
    _In_ ULONG Flags)
{
    PCNG_PROVIDER Provider = Algorithm;

    UNREFERENCED_PARAMETER(Flags);

    if (Provider == NULL || Provider->Magic != CNG_PROVIDER_MAGIC)
        return STATUS_INVALID_HANDLE;

    Provider->Magic = 0;
    ExFreePoolWithTag(Provider, TAG_CNG);
    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
BCryptCreateHash(
    _Inout_ PVOID Algorithm,
    _Out_ PVOID *Hash,
    _Out_writes_bytes_all_opt_(HashObjectLength) PUCHAR HashObject,
    _In_ ULONG HashObjectLength,
    _In_reads_bytes_opt_(SecretLength) PUCHAR Secret,
    _In_ ULONG SecretLength,
    _In_ ULONG Flags)
{
    PCNG_PROVIDER Provider = Algorithm;
    PCNG_HASH HashState;

    UNREFERENCED_PARAMETER(HashObject);
    UNREFERENCED_PARAMETER(HashObjectLength);

    *Hash = NULL;
    if (Provider == NULL || Provider->Magic != CNG_PROVIDER_MAGIC)
        return STATUS_INVALID_HANDLE;
    if (Secret != NULL || SecretLength != 0 || Flags != 0)
        return STATUS_NOT_SUPPORTED;

    HashState = ExAllocatePoolWithTag(PagedPool, sizeof(*HashState), TAG_CNG);
    if (HashState == NULL)
        return STATUS_NO_MEMORY;

    HashState->Magic = CNG_HASH_MAGIC;
    A_SHAInit(&HashState->Context);
    *Hash = HashState;
    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
BCryptHashData(
    _Inout_ PVOID Hash,
    _In_reads_bytes_(InputLength) PUCHAR Input,
    _In_ ULONG InputLength,
    _In_ ULONG Flags)
{
    PCNG_HASH HashState = Hash;

    if (HashState == NULL || HashState->Magic != CNG_HASH_MAGIC)
        return STATUS_INVALID_HANDLE;
    if (Flags != 0)
        return STATUS_INVALID_PARAMETER;

    A_SHAUpdate(&HashState->Context, Input, InputLength);
    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
BCryptFinishHash(
    _Inout_ PVOID Hash,
    _Out_writes_bytes_all_(OutputLength) PUCHAR Output,
    _In_ ULONG OutputLength,
    _In_ ULONG Flags)
{
    PCNG_HASH HashState = Hash;
    ULONG Digest[SHA1_DIGEST_LENGTH / sizeof(ULONG)];

    if (HashState == NULL || HashState->Magic != CNG_HASH_MAGIC)
        return STATUS_INVALID_HANDLE;
    if (Flags != 0 || OutputLength != SHA1_DIGEST_LENGTH)
        return STATUS_INVALID_PARAMETER;

    A_SHAFinal(&HashState->Context, Digest);
    RtlCopyMemory(Output, Digest, SHA1_DIGEST_LENGTH);
    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
BCryptDestroyHash(
    _Inout_ PVOID Hash)
{
    PCNG_HASH HashState = Hash;

    if (HashState == NULL || HashState->Magic != CNG_HASH_MAGIC)
        return STATUS_INVALID_HANDLE;

    HashState->Magic = 0;
    ExFreePoolWithTag(HashState, TAG_CNG);
    return STATUS_SUCCESS;
}

/* EOF */
