/*
 * PROJECT:     NitroOS
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     The SHA/HMAC interface libsmb2 calls (USHA* and hmac*), implemented with bcrypt in nitro/crypto.c.
 *              Replaces upstream lib/sha.h and its RFC 4634 code, which carry no licence notice.
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#ifndef NITRO_LIBSMB2_SHA_H
#define NITRO_LIBSMB2_SHA_H

#include <stdint.h>

/* Only the names libsmb2 uses: SHA-512 for the SMB 3.1.1 pre-authentication
 * hash, HMAC-SHA256 for SMB 2.x signing and the SP800-108 key derivation. */
typedef enum SHAversion
{
    SHA1, SHA224, SHA256, SHA384, SHA512
} SHAversion;

enum
{
    shaSuccess = 0,
    shaNull,
    shaInputTooLong,
    shaStateError,
    shaBadParam
};

enum
{
    USHAMaxHashSize = 64
};

/* One bcrypt hash object; failed = 1 after any bcrypt error. A failed
 * context yields an unpredictable digest (random bytes), never a constant
 * one, so a signature check against it fails closed. */
typedef struct USHAContext
{
    void *hash;
    int which;
    int failed;
} USHAContext;

typedef USHAContext HMACContext;

int USHAReset(USHAContext *ctx, SHAversion which);
int USHAInput(USHAContext *ctx, const uint8_t *bytes, unsigned int bytecount);
int USHAResult(USHAContext *ctx, uint8_t *digest);

int hmacReset(HMACContext *ctx, SHAversion which, const unsigned char *key, int key_len);
int hmacInput(HMACContext *ctx, const unsigned char *text, int text_len);
int hmacResult(HMACContext *ctx, uint8_t *digest);

#endif /* NITRO_LIBSMB2_SHA_H */
