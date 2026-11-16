/*
 * PROJECT:     ReactOS Crypto Library
 * LICENSE:     MIT (https://spdx.org/licenses/MIT)
 * PURPOSE:     ChaCha20 block function and keystream (RFC 8439)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka
 */

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <ntdef.h>

#define CHACHA20_KEY_SIZE   32
#define CHACHA20_NONCE_SIZE 12
#define CHACHA20_BLOCK_SIZE 64

/* One 64-byte block for (Key, Counter, Nonce): RFC 8439 section 2.3 */
VOID NTAPI
ChaCha20Block(
    _In_reads_bytes_(CHACHA20_KEY_SIZE) const UCHAR *Key,
    _In_ ULONG Counter,
    _In_reads_bytes_(CHACHA20_NONCE_SIZE) const UCHAR *Nonce,
    _Out_writes_bytes_(CHACHA20_BLOCK_SIZE) UCHAR *Output);

/* The keystream from block Counter on (RFC 8439 section 2.4 without the XOR), Length bytes. The caller keeps one
   (Key, Nonce) below 2^32 blocks (256 GB), counted from Counter */
VOID NTAPI
ChaCha20KeyStream(
    _In_reads_bytes_(CHACHA20_KEY_SIZE) const UCHAR *Key,
    _In_ ULONG Counter,
    _In_reads_bytes_(CHACHA20_NONCE_SIZE) const UCHAR *Nonce,
    _Out_writes_bytes_(Length) UCHAR *Output,
    _In_ SIZE_T Length);

#ifdef __cplusplus
}
#endif
