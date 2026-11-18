/*
 * PROJECT:     NitroOS
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     AES-CMAC through bcrypt for lib/smb2-signing.c (NITRO_SMB2_BCRYPT_AES)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#ifndef NITRO_LIBSMB2_AES_H
#define NITRO_LIBSMB2_AES_H

#include <stddef.h>
#include <stdint.h>

struct smb2_iovec;

/* AES-128-CMAC (RFC 4493) of the concatenated pieces; 0, or -1 if bcrypt failed */
int nitro_smb2_aes_cmac(const uint8_t key[16], const struct smb2_iovec *iov, size_t niov, uint8_t mac[16]);

#endif /* NITRO_LIBSMB2_AES_H */
