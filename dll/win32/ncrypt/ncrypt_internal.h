/*
 * Copyright (c) 2021 Santino Mazza
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

#include <bcrypt.h>

enum algid
{
    /* symmetric */
    AES,
    /* asymmetric */
    RSA,
    DSA,
    ECDSA,
    ECDSA_P256,
    ECDSA_P384,
    ECDSA_P521,
    ECDH,
    ECDH_P256,
    ECDH_P384,
    ECDH_P521,
};

struct key
{
    enum algid algid;
    BCRYPT_KEY_HANDLE bcrypt_key;
    const struct key_alg *alg;  /* algorithm of the key material (a named curve for generic ECC keys) */
    DWORD bits;
    BOOL finalized;
};

struct storage_provider
{
#ifdef __REACTOS__
    BYTE unused; /* mutes error C2016: C requires that a struct or union have at least one member */
#endif
};

enum object_type
{
    KEY,
    STORAGE_PROVIDER,
    SECRET,
};

struct object_property
{
    WCHAR *key;
    DWORD value_size;
    void *value;
};

#define NCRYPT_OBJECT_MAGIC 0x4e43524f /* 'NCRO' */

struct object
{
    DWORD magic;
    enum object_type type;
    LONG refs;
    DWORD num_properties;
    struct object_property *properties;
    union
    {
        struct key key;
        struct storage_provider storage_provider;
        BCRYPT_SECRET_HANDLE secret;
    };
};
