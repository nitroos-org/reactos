/*
 * PROJECT:     NitroOS
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     libsmb2 porting hooks on bcrypt: random bytes (arc4random_buf), SHA-512 and HMAC-SHA256 (nitro/sha.h)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

/*
 * Random bytes. libsmb2 takes every random value it needs from
 * smb2_random_bytes() (lib/init.c), which calls arc4random_buf() when
 * HAVE_ARC4RANDOM_BUF is set (nitro/config.h). The call sites, all in the
 * client path we build:
 *   lib/init.c   smb2_init_context(): client_challenge (8 bytes, only read by
 *                the built-in NTLMSSP, which is not built), salt (32 bytes,
 *                SMB 3.1.1 preauth integrity salt in NEGOTIATE), client_guid
 *                (16 bytes, NEGOTIATE ClientGuid)
 *   lib/smb3-seal.c smb3_encrypt_pdu(): the AES-CCM/GCM nonce of every
 *                encrypted message (11 or 12 bytes)
 * (lib/ntlmssp.c, server challenge, is not built.) libsmb2's random()
 * fallback is compiled out, so srandom() only seeds an unused generator.
 *
 * A failure of the system generator is not survivable for this library (a
 * repeated CCM nonce breaks the encryption), so it ends the process.
 */

#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS
#include <ntstatus.h>
#include <bcrypt.h>
#include <stdint.h>
#include <string.h>

#include "config.h"
#include "sha.h"

void arc4random_buf(void *buf, size_t len)
{
    UCHAR *p = buf;

    while (len > 0)
    {
        ULONG chunk = len > 0x10000 ? 0x10000 : (ULONG)len;

        if (!BCRYPT_SUCCESS(BCryptGenRandom(NULL, p, chunk, BCRYPT_USE_SYSTEM_PREFERRED_RNG)))
        {
            TerminateProcess(GetCurrentProcess(), (UINT)STATUS_INTERNAL_ERROR);
        }
        p += chunk;
        len -= chunk;
    }
}

/* Algorithm providers are opened once per process and never closed. */
static INIT_ONCE ProvidersOnce = INIT_ONCE_STATIC_INIT;
static BCRYPT_ALG_HANDLE Sha512Alg;
static BCRYPT_ALG_HANDLE HmacSha256Alg;

static BOOL CALLBACK OpenProviders(PINIT_ONCE once, PVOID param, PVOID *context)
{
    (void)once; (void)param; (void)context;
    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&Sha512Alg, BCRYPT_SHA512_ALGORITHM, NULL, 0)))
        Sha512Alg = NULL;
    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&HmacSha256Alg, BCRYPT_SHA256_ALGORITHM, NULL,
                                                    BCRYPT_ALG_HANDLE_HMAC_FLAG)))
        HmacSha256Alg = NULL;
    return TRUE;
}

static void Begin(USHAContext *ctx, BCRYPT_ALG_HANDLE alg, int which, const unsigned char *key, ULONG key_len)
{
    BCRYPT_HASH_HANDLE h = NULL;

    ctx->hash = NULL;
    ctx->which = which;
    ctx->failed = 1;
    if (alg == NULL)
        return;
    if (!BCRYPT_SUCCESS(BCryptCreateHash(alg, &h, NULL, 0, (PUCHAR)key, key_len, 0)))
        return;
    ctx->hash = h;
    ctx->failed = 0;
}

static void Feed(USHAContext *ctx, const unsigned char *bytes, ULONG len)
{
    if (ctx->failed || len == 0)
        return;
    if (!BCRYPT_SUCCESS(BCryptHashData(ctx->hash, (PUCHAR)bytes, len, 0)))
        ctx->failed = 1;
}

static int Finish(USHAContext *ctx, uint8_t *digest)
{
    ULONG size = ctx->which == SHA512 ? 64 : 32;
    int ok = !ctx->failed &&
             BCRYPT_SUCCESS(BCryptFinishHash(ctx->hash, digest, size, 0));

    if (ctx->hash)
        BCryptDestroyHash(ctx->hash);
    ctx->hash = NULL;
    if (!ok)
    {
        /* Never a predictable digest: a signature compared against it
         * cannot match, a key derived from it is unknown to everyone. */
        arc4random_buf(digest, size);
        ctx->failed = 1;
        return shaStateError;
    }
    return shaSuccess;
}

int USHAReset(USHAContext *ctx, SHAversion which)
{
    InitOnceExecuteOnce(&ProvidersOnce, OpenProviders, NULL, NULL);
    if (which != SHA512)
    {
        ctx->hash = NULL;
        ctx->which = SHA512;
        ctx->failed = 1;
        return shaBadParam;
    }
    Begin(ctx, Sha512Alg, SHA512, NULL, 0);
    return ctx->failed ? shaStateError : shaSuccess;
}

int USHAInput(USHAContext *ctx, const uint8_t *bytes, unsigned int bytecount)
{
    Feed(ctx, bytes, bytecount);
    return ctx->failed ? shaStateError : shaSuccess;
}

int USHAResult(USHAContext *ctx, uint8_t *digest)
{
    return Finish(ctx, digest);
}

int hmacReset(HMACContext *ctx, SHAversion which, const unsigned char *key, int key_len)
{
    InitOnceExecuteOnce(&ProvidersOnce, OpenProviders, NULL, NULL);
    if (which != SHA256 || key_len < 0)
    {
        ctx->hash = NULL;
        ctx->which = SHA256;
        ctx->failed = 1;
        return shaBadParam;
    }
    Begin(ctx, HmacSha256Alg, SHA256, key, (ULONG)key_len);
    return ctx->failed ? shaStateError : shaSuccess;
}

int hmacInput(HMACContext *ctx, const unsigned char *text, int text_len)
{
    if (text_len < 0)
    {
        ctx->failed = 1;
        return shaBadParam;
    }
    Feed(ctx, text, (ULONG)text_len);
    return ctx->failed ? shaStateError : shaSuccess;
}

int hmacResult(HMACContext *ctx, uint8_t *digest)
{
    return Finish(ctx, digest);
}
