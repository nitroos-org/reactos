/*
 * PROJECT:     NitroOS
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     AES-128-CCM (SMB 3.x encryption) and AES-128-CMAC (SMB 3.x signing) for libsmb2 through bcrypt
 *              (built when NITRO_SMB2_BCRYPT_AES is set, see CMakeLists.txt)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

/*
 * aes128ccm_encrypt()/aes128ccm_decrypt() replace upstream lib/aes128ccm.c
 * (same interface, lib/aes128ccm.h): in-place, 16-byte key, 11-byte nonce,
 * the 32 bytes of the transform header from Nonce on as associated data,
 * the 16-byte tag in m. nitro_smb2_aes_cmac() is called from
 * lib/smb2-signing.c (one marked local change) over the message pieces,
 * without copying them into one buffer.
 * bcrypt (SymCrypt) uses the CPU's AES instructions where libsmb2's own CCM
 * code runs AES one byte at a time.
 */

#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS
#include <ntstatus.h>
#include <bcrypt.h>
#include <stdint.h>
#include <string.h>

#include "config.h"
#include "compat.h"
#include "smb2.h"
#include "libsmb2.h"
#include "aes128ccm.h"
#include "nitro-aes.h"

static INIT_ONCE AesOnce = INIT_ONCE_STATIC_INIT;
static BCRYPT_ALG_HANDLE CcmAlg;
static BCRYPT_ALG_HANDLE CmacAlg;

static BOOL CALLBACK OpenAes(PINIT_ONCE once, PVOID param, PVOID *context)
{
    (void)once; (void)param; (void)context;
    if (BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&CcmAlg, BCRYPT_AES_ALGORITHM, NULL, 0)))
    {
        if (!BCRYPT_SUCCESS(BCryptSetProperty(CcmAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_CCM,
                                              sizeof(BCRYPT_CHAIN_MODE_CCM), 0)))
        {
            BCryptCloseAlgorithmProvider(CcmAlg, 0);
            CcmAlg = NULL;
        }
    }
    else
        CcmAlg = NULL;
    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&CmacAlg, BCRYPT_AES_CMAC_ALGORITHM, NULL, 0)))
        CmacAlg = NULL;
    return TRUE;
}

static int ccm(int enc, unsigned char *key, unsigned char *nonce, size_t nlen, unsigned char *aad, size_t alen,
               unsigned char *p, size_t plen, unsigned char *m, size_t mlen)
{
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
    BCRYPT_KEY_HANDLE k = NULL;
    ULONG done = 0;
    NTSTATUS status;

    InitOnceExecuteOnce(&AesOnce, OpenAes, NULL, NULL);
    if (CcmAlg == NULL || plen > 0xFFFFFFFFu || alen > 0xFFFFFFFFu)
        return -1;
    if (!BCRYPT_SUCCESS(BCryptGenerateSymmetricKey(CcmAlg, &k, NULL, 0, key, 16, 0)))
        return -1;
    memset(&info, 0, sizeof(info));
    info.cbSize = sizeof(info);
    info.dwInfoVersion = 1;    /* BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO_VERSION */
    info.pbNonce = nonce;
    info.cbNonce = (ULONG)nlen;
    info.pbAuthData = aad;
    info.cbAuthData = (ULONG)alen;
    info.pbTag = m;
    info.cbTag = (ULONG)mlen;
    if (enc)
        status = BCryptEncrypt(k, p, (ULONG)plen, &info, NULL, 0, p, (ULONG)plen, &done, 0);
    else
        status = BCryptDecrypt(k, p, (ULONG)plen, &info, NULL, 0, p, (ULONG)plen, &done, 0);
    BCryptDestroyKey(k);
    if (!BCRYPT_SUCCESS(status) || done != plen)
    {
        if (!enc)
            SecureZeroMemory(p, plen);     /* never hand out unauthenticated plaintext */
        return -1;
    }
    return 0;
}

int aes128ccm_encrypt(unsigned char *key, unsigned char *nonce, size_t nlen, unsigned char *aad, size_t alen,
                      unsigned char *p, size_t plen, unsigned char *m, size_t mlen)
{
    return ccm(1, key, nonce, nlen, aad, alen, p, plen, m, mlen);
}

int aes128ccm_decrypt(unsigned char *key, unsigned char *nonce, size_t nlen, unsigned char *aad, size_t alen,
                      unsigned char *p, size_t plen, unsigned char *m, size_t mlen)
{
    return ccm(0, key, nonce, nlen, aad, alen, p, plen, m, mlen);
}

int nitro_smb2_aes_cmac(const uint8_t key[16], const struct smb2_iovec *iov, size_t niov, uint8_t mac[16])
{
    BCRYPT_HASH_HANDLE h = NULL;
    size_t i;
    int ok;

    InitOnceExecuteOnce(&AesOnce, OpenAes, NULL, NULL);
    if (CmacAlg == NULL ||
        !BCRYPT_SUCCESS(BCryptCreateHash(CmacAlg, &h, NULL, 0, (PUCHAR)key, 16, 0)))
        return -1;
    ok = 1;
    for (i = 0; ok && i < niov; i++)
    {
        if (iov[i].len > 0xFFFFFFFFu)
            ok = 0;
        else if (iov[i].len)
            ok = BCRYPT_SUCCESS(BCryptHashData(h, iov[i].buf, (ULONG)iov[i].len, 0));
    }
    ok = ok && BCRYPT_SUCCESS(BCryptFinishHash(h, mac, 16, 0));
    BCryptDestroyHash(h);
    return ok ? 0 : -1;
}
