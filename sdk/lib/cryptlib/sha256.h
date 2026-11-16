/*
 * PROJECT:     ReactOS Crypto Library
 * LICENSE:     MIT (https://spdx.org/licenses/MIT)
 * PURPOSE:     SHA-256 (FIPS 180-4)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka
 */

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <ntdef.h>

#define SHA256_DIGEST_SIZE 32
#define SHA256_BLOCK_SIZE  64

typedef struct _CRYPTLIB_SHA256_CTX
{
    ULONG State[8];
    ULONGLONG Length;   /* bytes hashed so far */
    ULONG Used;         /* bytes in Buffer */
    UCHAR Buffer[SHA256_BLOCK_SIZE];
} CRYPTLIB_SHA256_CTX, *PCRYPTLIB_SHA256_CTX;

VOID NTAPI
Sha256Init(_Out_ PCRYPTLIB_SHA256_CTX Context);

VOID NTAPI
Sha256Update(_Inout_ PCRYPTLIB_SHA256_CTX Context, _In_reads_bytes_(Length) const VOID *Data, _In_ SIZE_T Length);

/* Writes the digest and wipes the context */
VOID NTAPI
Sha256Final(_Inout_ PCRYPTLIB_SHA256_CTX Context, _Out_writes_bytes_(SHA256_DIGEST_SIZE) UCHAR *Digest);

#ifdef __cplusplus
}
#endif
