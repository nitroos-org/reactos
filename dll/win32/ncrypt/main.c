/*
 * New cryptographic library (ncrypt.dll)
 *
 * Copyright 2016 Alex Henrie
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

#include <stdarg.h>
#include <stdlib.h>

#include "ntstatus.h"
#ifdef __REACTOS__
#define WIN32_NO_STATUS
#endif
#include "windef.h"
#include "winbase.h"
#include "ncrypt.h"
#include "wincrypt.h"
#include "bcrypt.h"
#include "ncrypt_internal.h"
#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(ncrypt);

#ifndef NCRYPT_MAX_PROPERTY_NAME
#define NCRYPT_MAX_PROPERTY_NAME 64
#endif

/* The key storage provider only keeps ephemeral keys: there is no persisted key store. Key
 * material lives in bcrypt; this layer adds the NCrypt object model (properties, provider,
 * finalization) and the PKCS #8 key blob. */

struct key_alg
{
    const WCHAR *name;          /* NCrypt algorithm name */
    const WCHAR *group;         /* algorithm group */
    enum algid algid;
    BCRYPT_ALG_HANDLE bcrypt;   /* NULL for the generic ECC algorithms, whose curve is a property */
    DWORD bits;                 /* fixed key length of a named curve */
    DWORD public_magic, private_magic;
};

static const struct key_alg key_algs[] =
{
    { BCRYPT_RSA_ALGORITHM, NCRYPT_RSA_ALGORITHM_GROUP, RSA, BCRYPT_RSA_ALG_HANDLE, 0 },
    { BCRYPT_ECDSA_P256_ALGORITHM, NCRYPT_ECDSA_ALGORITHM_GROUP, ECDSA_P256, BCRYPT_ECDSA_P256_ALG_HANDLE, 256,
      BCRYPT_ECDSA_PUBLIC_P256_MAGIC, BCRYPT_ECDSA_PRIVATE_P256_MAGIC },
    { BCRYPT_ECDSA_P384_ALGORITHM, NCRYPT_ECDSA_ALGORITHM_GROUP, ECDSA_P384, BCRYPT_ECDSA_P384_ALG_HANDLE, 384,
      BCRYPT_ECDSA_PUBLIC_P384_MAGIC, BCRYPT_ECDSA_PRIVATE_P384_MAGIC },
    { BCRYPT_ECDSA_P521_ALGORITHM, NCRYPT_ECDSA_ALGORITHM_GROUP, ECDSA_P521, BCRYPT_ECDSA_P521_ALG_HANDLE, 521,
      BCRYPT_ECDSA_PUBLIC_P521_MAGIC, BCRYPT_ECDSA_PRIVATE_P521_MAGIC },
    { BCRYPT_ECDH_P256_ALGORITHM, NCRYPT_ECDH_ALGORITHM_GROUP, ECDH_P256, BCRYPT_ECDH_P256_ALG_HANDLE, 256,
      BCRYPT_ECDH_PUBLIC_P256_MAGIC, BCRYPT_ECDH_PRIVATE_P256_MAGIC },
    { BCRYPT_ECDH_P384_ALGORITHM, NCRYPT_ECDH_ALGORITHM_GROUP, ECDH_P384, BCRYPT_ECDH_P384_ALG_HANDLE, 384,
      BCRYPT_ECDH_PUBLIC_P384_MAGIC, BCRYPT_ECDH_PRIVATE_P384_MAGIC },
    { BCRYPT_ECDH_P521_ALGORITHM, NCRYPT_ECDH_ALGORITHM_GROUP, ECDH_P521, BCRYPT_ECDH_P521_ALG_HANDLE, 521,
      BCRYPT_ECDH_PUBLIC_P521_MAGIC, BCRYPT_ECDH_PRIVATE_P521_MAGIC },
    { BCRYPT_ECDSA_ALGORITHM, NCRYPT_ECDSA_ALGORITHM_GROUP, ECDSA, NULL, 0,
      BCRYPT_ECDSA_PUBLIC_GENERIC_MAGIC, BCRYPT_ECDSA_PRIVATE_GENERIC_MAGIC },
    { BCRYPT_ECDH_ALGORITHM, NCRYPT_ECDH_ALGORITHM_GROUP, ECDH, NULL, 0,
      BCRYPT_ECDH_PUBLIC_GENERIC_MAGIC, BCRYPT_ECDH_PRIVATE_GENERIC_MAGIC },
};

static const struct key_alg *find_alg_by_name(const WCHAR *name)
{
    unsigned int i;
    for (i = 0; i < ARRAYSIZE(key_algs); i++)
        if (!lstrcmpiW(key_algs[i].name, name)) return &key_algs[i];
    return NULL;
}

static BOOL is_ecc(enum algid algid)
{
    return algid >= ECDSA && algid <= ECDH_P521;
}

static BOOL is_ecdh(enum algid algid)
{
    return algid >= ECDH && algid <= ECDH_P521;
}

/* the named curve algorithm of a group (ECDSA or ECDH) for a curve name, NULL if not supported */
static const struct key_alg *find_named_curve(enum algid group, const WCHAR *curve)
{
    static const struct { const WCHAR *name; DWORD bits; } curves[] =
    {
        { L"nistP256", 256 }, { BCRYPT_ECC_CURVE_SECP256R1, 256 },
        { L"nistP384", 384 }, { BCRYPT_ECC_CURVE_SECP384R1, 384 },
        { L"nistP521", 521 }, { BCRYPT_ECC_CURVE_SECP521R1, 521 },
    };
    unsigned int i, j;

    for (i = 0; i < ARRAYSIZE(curves); i++)
    {
        if (lstrcmpiW(curves[i].name, curve)) continue;
        for (j = 0; j < ARRAYSIZE(key_algs); j++)
            if (key_algs[j].bcrypt && key_algs[j].bits == curves[i].bits && is_ecc(key_algs[j].algid) &&
                is_ecdh(key_algs[j].algid) == is_ecdh(group))
                return &key_algs[j];
    }
    return NULL;
}

static const struct key_alg *find_named_curve_by_bits(enum algid group, DWORD bits)
{
    unsigned int j;
    for (j = 0; j < ARRAYSIZE(key_algs); j++)
        if (key_algs[j].bcrypt && key_algs[j].bits == bits && is_ecc(key_algs[j].algid) &&
            is_ecdh(key_algs[j].algid) == is_ecdh(group))
            return &key_algs[j];
    return NULL;
}

static SECURITY_STATUS map_ntstatus(NTSTATUS status)
{
    switch (status)
    {
    case STATUS_INVALID_HANDLE:    return NTE_INVALID_HANDLE;
    case STATUS_INVALID_SIGNATURE: return NTE_BAD_SIGNATURE;
    case STATUS_SUCCESS:           return ERROR_SUCCESS;
    case STATUS_INVALID_PARAMETER: return NTE_INVALID_PARAMETER;
    case STATUS_INVALID_BUFFER_SIZE: return NTE_INVALID_PARAMETER;
    case STATUS_NO_MEMORY:         return NTE_NO_MEMORY;
    case STATUS_NOT_SUPPORTED:     return NTE_NOT_SUPPORTED;
    case STATUS_NOT_IMPLEMENTED:   return NTE_NOT_SUPPORTED;
    case STATUS_NOT_FOUND:         return NTE_NOT_FOUND;
    case NTE_BAD_DATA:             return NTE_BAD_DATA;
    case STATUS_BUFFER_TOO_SMALL:  return NTE_BUFFER_TOO_SMALL;
    default:
        FIXME("unhandled status %#lx\n", status);
        return NTE_INTERNAL_ERROR;
    }
}

static struct object *allocate_object(enum object_type type)
{
    struct object *ret;
    if (!(ret = calloc(1, sizeof(*ret)))) return NULL;
    ret->magic = NCRYPT_OBJECT_MAGIC;
    ret->type = type;
    ret->refs = 1;
    return ret;
}

static struct object *get_object(NCRYPT_HANDLE handle)
{
    struct object *object = (struct object *)handle;

    if (!object || IsBadReadPtr(object, sizeof(*object)) || object->magic != NCRYPT_OBJECT_MAGIC) return NULL;
    return object;
}

static struct object *get_key_object(NCRYPT_HANDLE handle)
{
    struct object *object = get_object(handle);
    return object && object->type == KEY ? object : NULL;
}

static struct object *get_provider_object(NCRYPT_HANDLE handle)
{
    struct object *object = get_object(handle);
    return object && object->type == STORAGE_PROVIDER ? object : NULL;
}

static struct object *get_secret_object(NCRYPT_HANDLE handle)
{
    struct object *object = get_object(handle);
    return object && object->type == SECRET ? object : NULL;
}

static void provider_addref(NCRYPT_PROV_HANDLE handle)
{
    struct object *object = (struct object *)handle;
    InterlockedIncrement(&object->refs);
}

static struct object_property *get_object_property(struct object *object, const WCHAR *name)
{
    unsigned int i;
    for (i = 0; i < object->num_properties; i++)
    {
        struct object_property *property = &object->properties[i];
        if (property->key && !lstrcmpW(property->key, name)) return property;
    }
    return NULL;
}

struct object_property *add_object_property(struct object *object, const WCHAR *name)
{
    struct object_property *property;

    if (!object->num_properties)
    {
        if (!(object->properties = malloc(sizeof(*property))))
        {
            ERR("Error allocating memory.\n");
            return NULL;
        }
        property = &object->properties[object->num_properties++];
    }
    else
    {
        struct object_property *tmp;
        if (!(tmp = realloc(object->properties, sizeof(*property) * (object->num_properties + 1))))
        {
            ERR("Error allocating memory.\n");
            return NULL;
        }
        object->properties = tmp;
        property = &object->properties[object->num_properties++];
    }

    memset(property, 0, sizeof(*property));
    if (!(property->key = wcsdup(name)))
    {
        ERR("Error allocating memory.\n");
        return NULL;
    }

    return property;
}

static SECURITY_STATUS set_object_property(struct object *object, const WCHAR *name, const BYTE *value, DWORD value_size)
{
    struct object_property *property = get_object_property(object, name);
    void *tmp;

    if (!property && !(property = add_object_property(object, name))) return NTE_NO_MEMORY;

    if (!(tmp = realloc(property->value, value_size ? value_size : 1)))
    {
        ERR("Error allocating memory.\n");
        return NTE_NO_MEMORY;
    }

    property->value = tmp;
    property->value_size = value_size;
    if (value_size) memcpy(property->value, value, value_size);

    return ERROR_SUCCESS;
}

static void set_dword_property(struct object *object, const WCHAR *name, DWORD value)
{
    set_object_property(object, name, (const BYTE *)&value, sizeof(value));
}

static void set_string_property(struct object *object, const WCHAR *name, const WCHAR *value)
{
    set_object_property(object, name, (const BYTE *)value, (lstrlenW(value) + 1) * sizeof(WCHAR));
}

/* Properties an application sets with NCRYPT_PERSIST_ONLY_FLAG are kept apart from the provider's. */
static const WCHAR *custom_property_name(const WCHAR *name, WCHAR *buf, DWORD len)
{
    if (lstrlenW(name) + 2 > len) return NULL;
    buf[0] = 1;
    lstrcpyW(buf + 1, name);
    return buf;
}

static void set_key_length_properties(struct object *object, DWORD bits)
{
    struct key *key = &object->key;

    key->bits = bits;
    set_dword_property(object, NCRYPT_LENGTH_PROPERTY, bits);
    set_dword_property(object, BCRYPT_PUBLIC_KEY_LENGTH, bits);
    if (key->algid == RSA)
    {
        set_dword_property(object, NCRYPT_BLOCK_LENGTH_PROPERTY, bits / 8);
        set_dword_property(object, BCRYPT_SIGNATURE_LENGTH, bits / 8);
    }
    else if (is_ecc(key->algid))
    {
        NCRYPT_SUPPORTED_LENGTHS lengths = {bits, bits, 0, bits};

        set_object_property(object, NCRYPT_LENGTHS_PROPERTY, (BYTE *)&lengths, sizeof(lengths));
        if (!is_ecdh(key->algid)) set_dword_property(object, BCRYPT_SIGNATURE_LENGTH, 2 * ((bits + 7) / 8));
    }
}

static struct object *create_key_object(const struct key_alg *alg, NCRYPT_PROV_HANDLE provider)
{
    struct object *object;

    if (!(object = allocate_object(KEY))) return NULL;

    object->key.algid = alg->algid;
    object->key.alg = alg;
    set_string_property(object, NCRYPT_ALGORITHM_PROPERTY, alg->name);
    set_string_property(object, NCRYPT_ALGORITHM_GROUP_PROPERTY, alg->group);
    if (alg->algid == RSA)
    {
        NCRYPT_SUPPORTED_LENGTHS supported_lengths = {512, 16384, 8, 1024};

        set_object_property(object, NCRYPT_LENGTHS_PROPERTY, (BYTE *)&supported_lengths, sizeof(supported_lengths));
        set_key_length_properties(object, 1024);
    }
    else if (alg->bits)
        set_key_length_properties(object, alg->bits);

    set_dword_property(object, NCRYPT_EXPORT_POLICY_PROPERTY, 0);
    set_dword_property(object, NCRYPT_KEY_USAGE_PROPERTY, NCRYPT_ALLOW_ALL_USAGES);
    set_dword_property(object, NCRYPT_KEY_TYPE_PROPERTY, 0);
    provider_addref(provider);
    set_object_property(object, NCRYPT_PROVIDER_HANDLE_PROPERTY, (BYTE *)&provider, sizeof(provider));
    return object;
}

static void free_object(struct object *object)
{
    unsigned int i;

    for (i = 0; i < object->num_properties; i++)
    {
        if (object->properties[i].key && !wcscmp(object->properties[i].key, NCRYPT_PROVIDER_HANDLE_PROPERTY))
            NCryptFreeObject(*(NCRYPT_HANDLE *)object->properties[i].value);

        free(object->properties[i].key);
        free(object->properties[i].value);
    }
    free(object->properties);
    *(volatile DWORD *)&object->magic = 0; /* not a dead store: stale handles must stop validating */
    free(object);
}

static void free_key_object(struct object *object)
{
    if (object->key.bcrypt_key) BCryptDestroyKey(object->key.bcrypt_key);
    free_object(object);
}

SECURITY_STATUS WINAPI NCryptCreatePersistedKey(NCRYPT_PROV_HANDLE provider, NCRYPT_KEY_HANDLE *key,
                                                const WCHAR *algid, const WCHAR *name, DWORD keyspec, DWORD flags)
{
    const struct key_alg *alg;
    struct object *object;

    TRACE("(%#Ix, %p, %s, %s, %#lx, %#lx)\n", provider, key, wine_dbgstr_w(algid),
          wine_dbgstr_w(name), keyspec, flags);

    if (!get_provider_object(provider)) return NTE_INVALID_HANDLE;
    if (!algid) return HRESULT_FROM_WIN32(RPC_X_NULL_REF_POINTER);
    if (name) FIXME("Persistent keys are not supported\n");

    if (!(alg = find_alg_by_name(algid)))
    {
        FIXME("Algorithm not handled %s\n", wine_dbgstr_w(algid));
        return NTE_NOT_SUPPORTED;
    }
    if (!(object = create_key_object(alg, provider)))
    {
        ERR("Error allocating memory\n");
        return NTE_NO_MEMORY;
    }
    if (flags & NCRYPT_MACHINE_KEY_FLAG) set_dword_property(object, NCRYPT_KEY_TYPE_PROPERTY, NCRYPT_MACHINE_KEY_FLAG);

    *key = (NCRYPT_KEY_HANDLE)object;
    return ERROR_SUCCESS;
}

SECURITY_STATUS WINAPI NCryptDecrypt(NCRYPT_KEY_HANDLE key, BYTE *input, DWORD insize, void *padding,
                                     BYTE *output, DWORD outsize, DWORD *result, DWORD flags)
{
    struct object *key_object = get_key_object(key);

    TRACE("(%#Ix, %p, %lu, %p, %p, %lu, %p, %#lx)\n", key, input, insize, padding,
          output, outsize, result, flags);

    if (!key_object) return NTE_INVALID_HANDLE;
    if (flags & ~(NCRYPT_NO_PADDING_FLAG | NCRYPT_PAD_OAEP_FLAG | NCRYPT_PAD_PKCS1_FLAG | NCRYPT_SILENT_FLAG))
    {
        FIXME("Flags %lx not supported\n", flags);
        return NTE_BAD_FLAGS;
    }
    if (!key_object->key.finalized) return NTE_INVALID_HANDLE;
    if (key_object->key.algid != RSA) return NTE_NOT_SUPPORTED;

    return map_ntstatus(BCryptDecrypt(key_object->key.bcrypt_key, input, insize, padding,
                                      NULL, 0, output, outsize, result, flags & ~NCRYPT_SILENT_FLAG));
}

SECURITY_STATUS WINAPI NCryptDeleteKey(NCRYPT_KEY_HANDLE key, DWORD flags)
{
    struct object *object = get_key_object(key);

    TRACE("(%#Ix, %#lx)\n", key, flags);

    if (!object) return NTE_INVALID_HANDLE;
    /* nothing is persisted: deleting the key frees its handle */
    free_key_object(object);
    return ERROR_SUCCESS;
}

SECURITY_STATUS WINAPI NCryptEncrypt(NCRYPT_KEY_HANDLE key, BYTE *input, DWORD insize, void *padding,
                                     BYTE *output, DWORD outsize, DWORD *result, DWORD flags)
{
    struct object *key_object = get_key_object(key);

    TRACE("(%#Ix, %p, %lu, %p, %p, %lu, %p, %#lx)\n", key, input, insize, padding,
          output, outsize, result, flags);

    if (!key_object) return NTE_INVALID_HANDLE;
    if (flags & ~(NCRYPT_NO_PADDING_FLAG | NCRYPT_PAD_OAEP_FLAG
                | NCRYPT_PAD_PKCS1_FLAG | NCRYPT_SILENT_FLAG))
    {
        FIXME("Flags %lx not supported\n", flags);
        return NTE_BAD_FLAGS;
    }

    if (flags & NCRYPT_NO_PADDING_FLAG)
    {
        FIXME("No padding not supported\n");
        return NTE_NOT_SUPPORTED;
    }

    if (!key_object->key.finalized) return NTE_BAD_KEY_STATE;
    if (key_object->key.algid != RSA) return NTE_NOT_SUPPORTED;

    return map_ntstatus(BCryptEncrypt(key_object->key.bcrypt_key, input, insize, padding,
                                      NULL, 0, output, outsize, result, flags & ~NCRYPT_SILENT_FLAG));
}

SECURITY_STATUS WINAPI NCryptEnumAlgorithms(NCRYPT_PROV_HANDLE provider, DWORD alg_ops,
                                            DWORD *alg_count, NCryptAlgorithmName **alg_list, DWORD flags)
{
    FIXME("(%#Ix, %#lx, %p, %p, %#lx): stub\n", provider, alg_ops, alg_count, alg_list, flags);
    return NTE_NOT_SUPPORTED;
}

SECURITY_STATUS WINAPI NCryptEnumKeys(NCRYPT_PROV_HANDLE provider, const WCHAR *scope,
                                      NCryptKeyName **key_name, PVOID *enum_state, DWORD flags)
{
    TRACE("(%#Ix, %p, %p, %p, %#lx)\n", provider, scope, key_name, enum_state, flags);

    if (!get_provider_object(provider)) return NTE_INVALID_HANDLE;
    /* there is no persisted key store */
    return NTE_NO_MORE_ITEMS;
}

static SECURITY_STATUS generate_key(struct object *object)
{
    struct key *key = &object->key;
    const struct key_alg *alg = key->alg;
    struct object_property *prop;
    DWORD bits;
    NTSTATUS status;

    if (alg->algid == RSA)
    {
        if (!(prop = get_object_property(object, NCRYPT_LENGTH_PROPERTY)) || prop->value_size != sizeof(DWORD))
            return NTE_INVALID_HANDLE;
        bits = *(DWORD *)prop->value;
    }
    else if (!alg->bits)
    {
        /* generic ECC algorithm: the curve comes from the ECCCurveName property */
        if (!(prop = get_object_property(object, BCRYPT_ECC_CURVE_NAME)) || prop->value_size < sizeof(WCHAR) ||
            ((WCHAR *)prop->value)[prop->value_size / sizeof(WCHAR) - 1])
            return NTE_INVALID_PARAMETER;
        if (!(alg = find_named_curve(alg->algid, prop->value)))
        {
            FIXME("curve %s not supported\n", wine_dbgstr_w(prop->value));
            return NTE_NOT_SUPPORTED;
        }
        key->alg = alg;
        bits = alg->bits;
    }
    else bits = alg->bits;

    status = BCryptGenerateKeyPair(alg->bcrypt, &key->bcrypt_key, bits, 0);
    if (status == STATUS_SUCCESS && (status = BCryptFinalizeKeyPair(key->bcrypt_key, 0)))
    {
        BCryptDestroyKey(key->bcrypt_key);
        key->bcrypt_key = NULL;
    }
    if (status != STATUS_SUCCESS)
    {
        ERR("Error generating key pair %#lx\n", status);
        return map_ntstatus(status);
    }
    set_key_length_properties(object, bits);
    return ERROR_SUCCESS;
}

SECURITY_STATUS WINAPI NCryptFinalizeKey(NCRYPT_KEY_HANDLE handle, DWORD flags)
{
    struct object *object = get_key_object(handle);
    SECURITY_STATUS ret;

    TRACE("(%#Ix, %#lx)\n", handle, flags);

    if (!object || object->key.finalized) return NTE_INVALID_HANDLE;

    /* a key imported with NCRYPT_DO_NOT_FINALIZE_FLAG already has its key material */
    if (!object->key.bcrypt_key && (ret = generate_key(object))) return ret;
    object->key.finalized = TRUE;
    return ERROR_SUCCESS;
}

SECURITY_STATUS WINAPI NCryptFreeBuffer(PVOID buf)
{
    TRACE("(%p)\n", buf);
    free(buf);
    return ERROR_SUCCESS;
}

SECURITY_STATUS WINAPI NCryptFreeObject(NCRYPT_HANDLE handle)
{
    struct object *object = get_object(handle);

    TRACE("(%#Ix)\n", handle);

    if (!object)
    {
        WARN("invalid handle %#Ix\n", handle);
        return NTE_INVALID_HANDLE;
    }

    switch (object->type)
    {
    case KEY:
        free_key_object(object);
        break;

    case STORAGE_PROVIDER:
        if (InterlockedDecrement(&object->refs))
            return ERROR_SUCCESS;
        free_object(object);
        break;

    case SECRET:
        BCryptDestroySecret(object->secret);
        free_object(object);
        break;

    default:
        WARN("invalid handle %#Ix\n", handle);
        return NTE_INVALID_HANDLE;
    }
    return ERROR_SUCCESS;
}

/* status of a property the object does not have */
static SECURITY_STATUS missing_property(struct object *object, const WCHAR *name, DWORD flags)
{
    static const WCHAR *not_found[] =
    {
        NCRYPT_UI_POLICY_PROPERTY, NCRYPT_WINDOW_HANDLE_PROPERTY, NCRYPT_USE_CONTEXT_PROPERTY,
        NCRYPT_LAST_MODIFIED_PROPERTY, NCRYPT_CERTIFICATE_PROPERTY,
    };
    unsigned int i;

    if (flags & NCRYPT_PERSIST_ONLY_FLAG) return NTE_NOT_FOUND;
    if (!wcscmp(name, NCRYPT_SECURITY_DESCR_PROPERTY) && object->type == KEY) return NTE_BAD_FLAGS;
    if (!wcscmp(name, BCRYPT_ECC_CURVE_NAME) && object->type == KEY && is_ecc(object->key.algid))
        return NTE_NOT_FOUND;
    for (i = 0; i < ARRAYSIZE(not_found); i++)
        if (!wcscmp(name, not_found[i])) return NTE_NOT_FOUND;
    return NTE_NOT_SUPPORTED;
}

SECURITY_STATUS WINAPI NCryptGetProperty(NCRYPT_HANDLE handle, const WCHAR *name, BYTE *output,
                                         DWORD outsize, DWORD *result, DWORD flags)
{
    struct object *object = get_object(handle);
    const struct object_property *property;
    WCHAR custom[NCRYPT_MAX_PROPERTY_NAME + 2];
    const WCHAR *key = name;

    TRACE("(%#Ix, %s, %p, %lu, %p, %#lx)\n", handle, wine_dbgstr_w(name), output, outsize, result, flags);
    if (flags & ~(NCRYPT_PERSIST_ONLY_FLAG | NCRYPT_SILENT_FLAG)) FIXME("flags %#lx not supported\n", flags);

    /* a secret has no properties: it is not a handle for this function */
    if (!object || object->type == SECRET) return NTE_INVALID_HANDLE;
    if (!name) return NTE_INVALID_PARAMETER;
    if ((flags & NCRYPT_PERSIST_ONLY_FLAG) && !(key = custom_property_name(name, custom, ARRAYSIZE(custom))))
        return NTE_INVALID_PARAMETER;
    if (!(property = get_object_property(object, key))) return missing_property(object, name, flags);

    *result = property->value_size;
    if (!output) return ERROR_SUCCESS;
    if (outsize < property->value_size) return NTE_BUFFER_TOO_SMALL;

    memcpy(output, property->value, property->value_size);
    if (!wcscmp(key, NCRYPT_PROVIDER_HANDLE_PROPERTY))
        provider_addref(*(NCRYPT_PROV_HANDLE*)property->value);
    return ERROR_SUCCESS;
}

/*
 * Minimal DER reader and writer for the PKCS #8 private key blob (RFC 5208), with RSAPrivateKey
 * (RFC 8017) and ECPrivateKey (RFC 5915) inside.
 */
struct der
{
    const BYTE *data;
    DWORD len;
};

static BOOL der_get(struct der *in, BYTE tag, struct der *out)
{
    DWORD len, hdr = 2, i, n;

    if (in->len < 2 || in->data[0] != tag) return FALSE;
    len = in->data[1];
    if (len & 0x80)
    {
        n = len & 0x7f;
        if (!n || n > 3 || in->len < 2 + n) return FALSE;
        for (i = 0, len = 0; i < n; i++) len = (len << 8) | in->data[2 + i];
        hdr += n;
    }
    if (len > in->len - hdr) return FALSE;
    out->data = in->data + hdr;
    out->len = len;
    in->data += hdr + len;
    in->len -= hdr + len;
    return TRUE;
}

/* unsigned big-endian value of an INTEGER */
static BOOL der_get_uint(struct der *in, struct der *out)
{
    if (!der_get(in, 0x02, out) || !out->len || (out->data[0] & 0x80)) return FALSE;
    while (out->len > 1 && !out->data[0]) { out->data++; out->len--; }
    return TRUE;
}

static BOOL der_equal(const struct der *d, const BYTE *value, DWORD len)
{
    return d->len == len && !memcmp(d->data, value, len);
}

struct dbuf
{
    BYTE *data;
    DWORD len, size;
    BOOL failed;
};

static void dbuf_add(struct dbuf *b, const void *data, DWORD len)
{
    if (b->failed) return;
    if (b->len + len > b->size)
    {
        /* the buffer holds private key material: the old one is wiped, not left behind by realloc */
        DWORD size = max(b->size * 2, b->len + len + 64);
        BYTE *tmp = malloc(size);
        if (!tmp) { b->failed = TRUE; return; }
        if (b->data)
        {
            memcpy(tmp, b->data, b->len);
            SecureZeroMemory(b->data, b->len);
            free(b->data);
        }
        b->data = tmp;
        b->size = size;
    }
    if (len) memcpy(b->data + b->len, data, len);
    b->len += len;
}

static void dbuf_add_header(struct dbuf *b, BYTE tag, DWORD len)
{
    BYTE hdr[5];
    DWORD n = 0;

    hdr[n++] = tag;
    if (len < 0x80) hdr[n++] = len;
    else if (len < 0x100) { hdr[n++] = 0x81; hdr[n++] = len; }
    else if (len < 0x10000) { hdr[n++] = 0x82; hdr[n++] = len >> 8; hdr[n++] = len; }
    else { hdr[n++] = 0x83; hdr[n++] = len >> 16; hdr[n++] = len >> 8; hdr[n++] = len; }
    dbuf_add(b, hdr, n);
}

/* appends content as a TLV and frees it */
static void dbuf_add_tlv(struct dbuf *b, BYTE tag, struct dbuf *content)
{
    if (content->failed) b->failed = TRUE;
    dbuf_add_header(b, tag, content->len);
    dbuf_add(b, content->data, content->len);
    if (content->data) SecureZeroMemory(content->data, content->len);
    free(content->data);
    memset(content, 0, sizeof(*content));
}

static void dbuf_add_uint(struct dbuf *b, const BYTE *value, DWORD len)
{
    BOOL pad;

    while (len > 1 && !value[0]) { value++; len--; }
    pad = !len || (value[0] & 0x80);
    dbuf_add_header(b, 0x02, len + pad);
    if (pad) dbuf_add(b, "", 1);
    dbuf_add(b, value, len);
}

static const BYTE oid_rsa[] = {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01};
static const BYTE oid_ec_public_key[] = {0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01};
static const struct { BYTE oid[8]; DWORD len; DWORD bits; } curve_oids[] =
{
    { {0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07}, 8, 256 },
    { {0x2b, 0x81, 0x04, 0x00, 0x22}, 5, 384 },
    { {0x2b, 0x81, 0x04, 0x00, 0x23}, 5, 521 },
};

static SECURITY_STATUS import_key_blob(struct object *object, const WCHAR *type, const BYTE *data, DWORD size);

/* copies a big-endian value right-aligned into a field of len bytes */
static BOOL put_be(BYTE *dst, DWORD len, const struct der *value)
{
    if (value->len > len) return FALSE;
    memset(dst, 0, len - value->len);
    memcpy(dst + len - value->len, value->data, value->len);
    return TRUE;
}

static DWORD bit_length(const struct der *value)
{
    DWORD bits = value->len * 8;
    BYTE top = value->len ? value->data[0] : 0;

    if (!value->len) return 0;
    while (bits && !(top & 0x80)) { top <<= 1; bits--; }
    return bits;
}

static SECURITY_STATUS import_pkcs8(NCRYPT_PROV_HANDLE provider, enum algid ecc_group, const BYTE *data, DWORD size,
                                    struct object **ret)
{
    struct der in = {data, size}, info, alg, oid, params, key, priv, n, e, p, q, version, info_version;
    const struct key_alg *key_alg = NULL;
    SECURITY_STATUS status = NTE_BAD_DATA;
    struct object *object;
    BYTE *blob = NULL;
    DWORD blob_size = 0;
    const WCHAR *blob_type;
    unsigned int i;

    if (!der_get(&in, 0x30, &info) || !der_get_uint(&info, &info_version) || !der_get(&info, 0x30, &alg) ||
        !der_get(&alg, 0x06, &oid) || !der_get(&info, 0x04, &key))
        return CRYPT_E_BAD_ENCODE;

    if (der_equal(&oid, oid_rsa, sizeof(oid_rsa)))
    {
        BCRYPT_RSAKEY_BLOB *hdr;
        struct der rsa;

        if (!der_get(&key, 0x30, &rsa) || !der_get_uint(&rsa, &version) || !der_get_uint(&rsa, &n) ||
            !der_get_uint(&rsa, &e) || !der_get_uint(&rsa, &priv) || !der_get_uint(&rsa, &p) ||
            !der_get_uint(&rsa, &q))
            return CRYPT_E_BAD_ENCODE;
        blob_size = sizeof(*hdr) + e.len + n.len + p.len + q.len;
        if (!(blob = malloc(blob_size))) return NTE_NO_MEMORY;
        hdr = (BCRYPT_RSAKEY_BLOB *)blob;
        hdr->Magic = BCRYPT_RSAPRIVATE_MAGIC;
        hdr->BitLength = bit_length(&n);
        hdr->cbPublicExp = e.len;
        hdr->cbModulus = n.len;
        hdr->cbPrime1 = p.len;
        hdr->cbPrime2 = q.len;
        memcpy(blob + sizeof(*hdr), e.data, e.len);
        memcpy(blob + sizeof(*hdr) + e.len, n.data, n.len);
        memcpy(blob + sizeof(*hdr) + e.len + n.len, p.data, p.len);
        memcpy(blob + sizeof(*hdr) + e.len + n.len + p.len, q.data, q.len);
        key_alg = &key_algs[0];
        blob_type = BCRYPT_RSAPRIVATE_BLOB;
    }
    else if (der_equal(&oid, oid_ec_public_key, sizeof(oid_ec_public_key)))
    {
        BCRYPT_ECCKEY_BLOB *hdr;
        struct der ec, curve = {NULL, 0}, pub = {NULL, 0}, tagged;
        DWORD bits = 0, cb;

        /* unlike for RSA keys, a PrivateKeyInfo version other than 0 is rejected */
        if (info_version.len != 1 || info_version.data[0]) return CRYPT_E_BAD_ENCODE;
        if (der_get(&alg, 0x06, &params)) curve = params;
        if (!der_get(&key, 0x30, &ec) || !der_get_uint(&ec, &version) || !der_get(&ec, 0x04, &priv))
            return CRYPT_E_BAD_ENCODE;
        if (der_get(&ec, 0xa0, &tagged) && !curve.len && !der_get(&tagged, 0x06, &curve)) return CRYPT_E_BAD_ENCODE;
        if (der_get(&ec, 0xa1, &tagged) && !der_get(&tagged, 0x03, &pub)) return CRYPT_E_BAD_ENCODE;
        for (i = 0; i < ARRAYSIZE(curve_oids); i++)
            if (der_equal(&curve, curve_oids[i].oid, curve_oids[i].len)) bits = curve_oids[i].bits;
        if (!bits)
        {
            FIXME("curve not supported\n");
            return NTE_NOT_SUPPORTED;
        }
        key_alg = find_named_curve_by_bits(ecc_group, bits);
        cb = (bits + 7) / 8;
        /* the public key is an uncompressed point: unused-bits byte, 0x04, X, Y */
        if (pub.data && (pub.len != 2 + 2 * cb || pub.data[0] || pub.data[1] != 4)) return CRYPT_E_BAD_ENCODE;
        blob_size = sizeof(*hdr) + 3 * cb;
        if (!(blob = malloc(blob_size))) return NTE_NO_MEMORY;
        hdr = (BCRYPT_ECCKEY_BLOB *)blob;
        hdr->dwMagic = key_alg->private_magic;
        hdr->cbKey = cb;
        /* the optional public key is left out: an all-zero point makes bcrypt derive it from the private key */
        if (pub.data) memcpy(blob + sizeof(*hdr), pub.data + 2, 2 * cb);
        else memset(blob + sizeof(*hdr), 0, 2 * cb);
        if (!put_be(blob + sizeof(*hdr) + 2 * cb, cb, &priv))
        {
            SecureZeroMemory(blob, blob_size);
            free(blob);
            return CRYPT_E_BAD_ENCODE;
        }
        blob_type = BCRYPT_ECCPRIVATE_BLOB;
    }
    else
    {
        FIXME("unsupported PKCS #8 key algorithm\n");
        return NTE_NOT_SUPPORTED;
    }

    if (!(object = create_key_object(key_alg, provider)))
        status = NTE_NO_MEMORY;
    else if ((status = import_key_blob(object, blob_type, blob, blob_size)))
        free_key_object(object);
    else
        *ret = object;
    SecureZeroMemory(blob, blob_size);
    free(blob);
    return status;
}

static SECURITY_STATUS export_pkcs8(struct object *object, BYTE *output, DWORD output_len, DWORD *ret_len)
{
    struct key *key = &object->key;
    struct dbuf inner = {0}, alg = {0}, info = {0}, out = {0}, tmp = {0};
    SECURITY_STATUS status;
    BYTE *blob;
    ULONG size;
    unsigned int i;

    if (key->algid == RSA)
    {
        const BCRYPT_RSAKEY_BLOB *hdr;
        const BYTE *p;
        static const BYTE zero = 0;

        if ((status = map_ntstatus(BCryptExportKey(key->bcrypt_key, NULL, BCRYPT_RSAFULLPRIVATE_BLOB, NULL, 0, &size, 0))))
            return status;
        if (!(blob = malloc(size))) return NTE_NO_MEMORY;
        if ((status = map_ntstatus(BCryptExportKey(key->bcrypt_key, NULL, BCRYPT_RSAFULLPRIVATE_BLOB, blob, size, &size, 0))))
        {
            SecureZeroMemory(blob, size);
            free(blob);
            return status;
        }
        hdr = (const BCRYPT_RSAKEY_BLOB *)blob;
        p = blob + sizeof(*hdr);
        /* RSAPrivateKey: version, n, e, d, p, q, dp, dq, qinv; the blob holds e, n, p, q, dp, dq, qinv, d */
        dbuf_add_uint(&inner, &zero, 1);
        dbuf_add_uint(&inner, p + hdr->cbPublicExp, hdr->cbModulus);
        dbuf_add_uint(&inner, p, hdr->cbPublicExp);
        dbuf_add_uint(&inner, p + hdr->cbPublicExp + hdr->cbModulus + 3 * hdr->cbPrime1 + 2 * hdr->cbPrime2, hdr->cbModulus);
        dbuf_add_uint(&inner, p + hdr->cbPublicExp + hdr->cbModulus, hdr->cbPrime1);
        dbuf_add_uint(&inner, p + hdr->cbPublicExp + hdr->cbModulus + hdr->cbPrime1, hdr->cbPrime2);
        dbuf_add_uint(&inner, p + hdr->cbPublicExp + hdr->cbModulus + hdr->cbPrime1 + hdr->cbPrime2, hdr->cbPrime1);
        dbuf_add_uint(&inner, p + hdr->cbPublicExp + hdr->cbModulus + 2 * hdr->cbPrime1 + hdr->cbPrime2, hdr->cbPrime2);
        dbuf_add_uint(&inner, p + hdr->cbPublicExp + hdr->cbModulus + 2 * hdr->cbPrime1 + 2 * hdr->cbPrime2, hdr->cbPrime1);
        dbuf_add_tlv(&tmp, 0x30, &inner);
        inner = tmp;
        memset(&tmp, 0, sizeof(tmp));

        dbuf_add_header(&alg, 0x06, sizeof(oid_rsa));
        dbuf_add(&alg, oid_rsa, sizeof(oid_rsa));
        dbuf_add(&alg, "\x05\x00", 2);
    }
    else if (is_ecc(key->algid))
    {
        const BCRYPT_ECCKEY_BLOB *hdr;
        const BYTE *p;
        static const BYTE one = 1;
        int curve = -1;

        for (i = 0; i < ARRAYSIZE(curve_oids); i++)
            if (curve_oids[i].bits == key->bits) curve = i;
        if (curve < 0) return NTE_NOT_SUPPORTED;
        if ((status = map_ntstatus(BCryptExportKey(key->bcrypt_key, NULL, BCRYPT_ECCPRIVATE_BLOB, NULL, 0, &size, 0))))
            return status;
        if (!(blob = malloc(size))) return NTE_NO_MEMORY;
        if ((status = map_ntstatus(BCryptExportKey(key->bcrypt_key, NULL, BCRYPT_ECCPRIVATE_BLOB, blob, size, &size, 0))))
        {
            SecureZeroMemory(blob, size);
            free(blob);
            return status;
        }
        hdr = (const BCRYPT_ECCKEY_BLOB *)blob;
        p = blob + sizeof(*hdr);
        /* ECPrivateKey: version 1, privateKey, [0] curve, [1] public key; the blob holds X, Y, d */
        dbuf_add_uint(&inner, &one, 1);
        dbuf_add_header(&inner, 0x04, hdr->cbKey);
        dbuf_add(&inner, p + 2 * hdr->cbKey, hdr->cbKey);
        dbuf_add_header(&tmp, 0x06, curve_oids[curve].len);
        dbuf_add(&tmp, curve_oids[curve].oid, curve_oids[curve].len);
        dbuf_add_tlv(&inner, 0xa0, &tmp);
        dbuf_add_header(&tmp, 0x03, 2 + 2 * hdr->cbKey);
        dbuf_add(&tmp, "\x00\x04", 2);
        dbuf_add(&tmp, p, 2 * hdr->cbKey);
        dbuf_add_tlv(&inner, 0xa1, &tmp);
        dbuf_add_tlv(&tmp, 0x30, &inner);
        inner = tmp;
        memset(&tmp, 0, sizeof(tmp));

        dbuf_add_header(&alg, 0x06, sizeof(oid_ec_public_key));
        dbuf_add(&alg, oid_ec_public_key, sizeof(oid_ec_public_key));
        dbuf_add_header(&alg, 0x06, curve_oids[curve].len);
        dbuf_add(&alg, curve_oids[curve].oid, curve_oids[curve].len);
    }
    else return NTE_NOT_SUPPORTED;

    SecureZeroMemory(blob, size);
    free(blob);

    /* PrivateKeyInfo: version 0, algorithm, privateKey */
    dbuf_add(&info, "\x02\x01\x00", 3);
    dbuf_add_tlv(&info, 0x30, &alg);
    dbuf_add_tlv(&info, 0x04, &inner);
    dbuf_add_tlv(&out, 0x30, &info);

    if (out.failed) status = NTE_NO_MEMORY;
    else
    {
        *ret_len = out.len;
        if (!output) status = ERROR_SUCCESS;
        else if (output_len < out.len) status = HRESULT_FROM_WIN32(ERROR_MORE_DATA);
        else
        {
            memcpy(output, out.data, out.len);
            status = ERROR_SUCCESS;
        }
    }
    if (out.data) SecureZeroMemory(out.data, out.len);
    free(out.data);
    return status;
}

/* imports the key material of a key blob into a key object */
static SECURITY_STATUS import_key_blob(struct object *object, const WCHAR *type, const BYTE *data, DWORD size)
{
    NTSTATUS status;
    DWORD bits;

    status = BCryptImportKeyPair(object->key.alg->bcrypt, NULL, type, &object->key.bcrypt_key, (UCHAR *)data, size, 0);
    if (status != STATUS_SUCCESS)
    {
        WARN("Error importing key pair %#lx\n", status);
        object->key.bcrypt_key = NULL;
        return map_ntstatus(status);
    }
    if (object->key.algid == RSA)
    {
        const BCRYPT_RSAKEY_BLOB *hdr = (const BCRYPT_RSAKEY_BLOB *)data;

        /* the BitLength of the blob is only taken as the length if the modulus has the room for exactly
         * that many bits: it is not trusted otherwise */
        bits = hdr->cbModulus * 8;
        if (hdr->BitLength <= bits && hdr->BitLength > bits - 8) bits = hdr->BitLength;
    }
    else bits = object->key.alg->bits;
    set_key_length_properties(object, bits);
    return ERROR_SUCCESS;
}

static const WCHAR *get_curve_name_param(const NCryptBufferDesc *params)
{
    const WCHAR *curve = NULL;
    ULONG i;

    for (i = 0; i < params->cBuffers; i++)
    {
        const NCryptBuffer *buf = &params->pBuffers[i];

        if (buf->BufferType != NCRYPTBUFFER_ECC_CURVE_NAME) return NULL;
        if (!buf->pvBuffer || buf->cbBuffer < sizeof(WCHAR) ||
            ((const WCHAR *)buf->pvBuffer)[buf->cbBuffer / sizeof(WCHAR) - 1])
            return NULL;
        curve = buf->pvBuffer;
    }
    return curve;
}

SECURITY_STATUS WINAPI NCryptImportKey(NCRYPT_PROV_HANDLE provider, NCRYPT_KEY_HANDLE decrypt_key,
                                       const WCHAR *type, NCryptBufferDesc *params, NCRYPT_KEY_HANDLE *handle,
                                       BYTE *data, DWORD datasize, DWORD flags)
{
    const struct key_alg *alg = NULL, *named = NULL;
    const WCHAR *curve = NULL, *blob_type = type;
    struct object *object = NULL;
    SECURITY_STATUS status;
    BYTE *copy = NULL;
    DWORD magic;
    unsigned int i;

    TRACE("(%#Ix, %#Ix, %s, %p, %p, %p, %lu, %#lx)\n", provider, decrypt_key, wine_dbgstr_w(type),
          params, handle, data, datasize, flags);

    if (!get_provider_object(provider)) return NTE_INVALID_HANDLE;
    if (decrypt_key)
    {
        FIXME("Key blob decryption not implemented\n");
        return NTE_NOT_SUPPORTED;
    }
    if (flags & ~(NCRYPT_SILENT_FLAG | NCRYPT_DO_NOT_FINALIZE_FLAG))
    {
        WARN("Invalid flags %#lx\n", flags);
        return NTE_BAD_FLAGS;
    }
    if (!type || !data) return NTE_INVALID_PARAMETER;
    if (params && params->cBuffers && !(curve = get_curve_name_param(params)))
    {
        FIXME("Parameter information not implemented\n");
        return NTE_NOT_SUPPORTED;
    }

    if (!wcscmp(type, NCRYPT_PKCS8_PRIVATE_KEY_BLOB))
    {
        status = import_pkcs8(provider, ECDSA, data, datasize, &object);
        if (status) return status;
    }
    else
    {
        if (datasize < sizeof(DWORD)) return NTE_BAD_DATA;
        magic = *(DWORD *)data;
        switch (magic)
        {
        case BCRYPT_RSAFULLPRIVATE_MAGIC:
        case BCRYPT_RSAPRIVATE_MAGIC:
        case BCRYPT_RSAPUBLIC_MAGIC:
            alg = &key_algs[0];
            if (!wcscmp(type, BCRYPT_PUBLIC_KEY_BLOB) || !wcscmp(type, BCRYPT_PRIVATE_KEY_BLOB))
                blob_type = magic == BCRYPT_RSAPUBLIC_MAGIC ? BCRYPT_RSAPUBLIC_BLOB :
                            magic == BCRYPT_RSAPRIVATE_MAGIC ? BCRYPT_RSAPRIVATE_BLOB : BCRYPT_RSAFULLPRIVATE_BLOB;
            break;
        default:
            for (i = 0; i < ARRAYSIZE(key_algs); i++)
                if (key_algs[i].public_magic == magic || key_algs[i].private_magic == magic) alg = &key_algs[i];
            if (!alg)
            {
                FIXME("Unhandled key magic %#lx\n", magic);
                return NTE_INVALID_PARAMETER;
            }
            if (datasize < sizeof(BCRYPT_ECCKEY_BLOB)) return NTE_BAD_DATA;
            named = alg;
            if (!alg->bcrypt)
            {
                /* generic blob: the curve is a parameter */
                if (!curve || !(named = find_named_curve(alg->algid, curve)))
                {
                    FIXME("curve %s not supported\n", wine_dbgstr_w(curve));
                    return NTE_INVALID_PARAMETER;
                }
                if (!(copy = malloc(datasize))) return NTE_NO_MEMORY;
                memcpy(copy, data, datasize);
                ((BCRYPT_ECCKEY_BLOB *)copy)->dwMagic = magic == alg->private_magic ? named->private_magic :
                                                                                      named->public_magic;
            }
            blob_type = magic == alg->private_magic ? BCRYPT_ECCPRIVATE_BLOB : BCRYPT_ECCPUBLIC_BLOB;
            break;
        }

        if (!(object = create_key_object(alg, provider)))
        {
            free(copy);
            return NTE_NO_MEMORY;
        }
        if (named && named != alg)
        {
            object->key.alg = named;
            set_string_property(object, BCRYPT_ECC_CURVE_NAME, curve);
        }
        status = import_key_blob(object, blob_type, copy ? copy : data, datasize);
        if (copy)
        {
            SecureZeroMemory(copy, datasize);
            free(copy);
        }
        if (status)
        {
            free_key_object(object);
            return status;
        }
    }

    object->key.finalized = !(flags & NCRYPT_DO_NOT_FINALIZE_FLAG);
    *handle = (NCRYPT_KEY_HANDLE)object;
    return ERROR_SUCCESS;
}

static DWORD get_export_policy(struct object *object)
{
    const struct object_property *property = get_object_property(object, NCRYPT_EXPORT_POLICY_PROPERTY);

    return property && property->value_size == sizeof(DWORD) ? *(const DWORD *)property->value : 0;
}

SECURITY_STATUS WINAPI NCryptExportKey(NCRYPT_KEY_HANDLE key, NCRYPT_KEY_HANDLE encrypt_key, const WCHAR *type,
                                       NCryptBufferDesc *params, BYTE *output, DWORD output_len, DWORD *ret_len,
                                       DWORD flags)
{
    struct object *object = get_key_object(key);

    TRACE("(%#Ix, %#Ix, %s, %p, %p, %lu, %p, %#lx)\n", key, encrypt_key, wine_dbgstr_w(type), params, output,
          output_len, ret_len, flags);

    if (!object) return NTE_INVALID_HANDLE;
    if (encrypt_key)
    {
        FIXME("Key blob encryption not implemented\n");
        return NTE_NOT_SUPPORTED;
    }
    if (params)
    {
        FIXME("Parameter information not implemented\n");
        return NTE_NOT_SUPPORTED;
    }
    if (flags & NCRYPT_SILENT_FLAG)
    {
        FIXME("Silent flag not implemented\n");
    }
    if (!type || !ret_len) return NTE_INVALID_PARAMETER;
    if (!object->key.finalized) return NTE_BAD_KEY_STATE;

    if (!wcscmp(type, BCRYPT_PUBLIC_KEY_BLOB))
        type = object->key.algid == RSA ? BCRYPT_RSAPUBLIC_BLOB : BCRYPT_ECCPUBLIC_BLOB;
    else if (!wcscmp(type, BCRYPT_PRIVATE_KEY_BLOB))
        type = object->key.algid == RSA ? BCRYPT_RSAPRIVATE_BLOB : BCRYPT_ECCPRIVATE_BLOB;

    /* a blob of another kind of key */
    if (object->key.algid == RSA ? (!wcscmp(type, BCRYPT_ECCPUBLIC_BLOB) || !wcscmp(type, BCRYPT_ECCPRIVATE_BLOB)) :
        (!wcscmp(type, BCRYPT_RSAPUBLIC_BLOB) || !wcscmp(type, BCRYPT_RSAPRIVATE_BLOB) ||
         !wcscmp(type, BCRYPT_RSAFULLPRIVATE_BLOB)))
        return NTE_BAD_TYPE;

    /* the private key is only handed out in plaintext if the export policy allows it */
    if ((!wcscmp(type, NCRYPT_PKCS8_PRIVATE_KEY_BLOB) || !wcscmp(type, BCRYPT_RSAPRIVATE_BLOB) ||
         !wcscmp(type, BCRYPT_RSAFULLPRIVATE_BLOB) || !wcscmp(type, BCRYPT_ECCPRIVATE_BLOB)) &&
        !(get_export_policy(object) & NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG))
        return NTE_NOT_SUPPORTED;

    if (!wcscmp(type, NCRYPT_PKCS8_PRIVATE_KEY_BLOB)) return export_pkcs8(object, output, output_len, ret_len);
    return map_ntstatus(BCryptExportKey(object->key.bcrypt_key, NULL, type, output, output_len, ret_len, 0));
}

SECURITY_STATUS WINAPI NCryptIsAlgSupported(NCRYPT_PROV_HANDLE provider, const WCHAR *algid, DWORD flags)
{
    static const ULONG supported = BCRYPT_CIPHER_OPERATION |\
                                   BCRYPT_ASYMMETRIC_ENCRYPTION_OPERATION |\
                                   BCRYPT_SIGNATURE_OPERATION |\
                                   BCRYPT_SECRET_AGREEMENT_OPERATION;
    BCRYPT_ALGORITHM_IDENTIFIER *list;
    ULONG i, count;
    NTSTATUS status;

    TRACE("(%#Ix, %s, %#lx)\n", provider, wine_dbgstr_w(algid), flags);

    if (!provider) return NTE_INVALID_HANDLE;
    if (!algid) return HRESULT_FROM_WIN32(RPC_X_NULL_REF_POINTER);
    if (flags == NCRYPT_SILENT_FLAG)
    {
        FIXME("Silent flag not implemented\n");
    }
    else if (flags)
    {
        WARN("Invalid flags %#lx\n", flags);
        return NTE_BAD_FLAGS;
    }
    if (!lstrcmpiW(BCRYPT_RSA_SIGN_ALGORITHM, algid)) return NTE_NOT_SUPPORTED;

    status = BCryptEnumAlgorithms(supported, &count, &list, 0);
    if (status != STATUS_SUCCESS)
    {
        ERR("Error retrieving algorithm list %#lx\n", status);
        return map_ntstatus(status);
    }

    status = STATUS_NOT_SUPPORTED;
    for (i = 0; i < count; i++)
    {
        if (!lstrcmpiW(list[i].pszName, algid))
        {
            status = STATUS_SUCCESS;
            break;
        }
    }

    BCryptFreeBuffer(list);
    return map_ntstatus(status);
}

BOOL WINAPI NCryptIsKeyHandle(NCRYPT_KEY_HANDLE hKey)
{
    TRACE("(%#Ix)\n", hKey);
    return get_key_object(hKey) != NULL;
}

SECURITY_STATUS WINAPI NCryptOpenKey(NCRYPT_PROV_HANDLE provider, NCRYPT_KEY_HANDLE *key,
                                     const WCHAR *name, DWORD keyspec, DWORD flags)
{
    TRACE("(%#Ix, %p, %s, %#lx, %#lx)\n", provider, key, wine_dbgstr_w(name), keyspec, flags);

    if (!get_provider_object(provider)) return NTE_INVALID_HANDLE;
    if (!key || !name) return NTE_INVALID_PARAMETER;
    /* there is no persisted key store, so no key of that name */
    FIXME("persisted key %s not found\n", wine_dbgstr_w(name));
    return NTE_BAD_KEYSET;
}

SECURITY_STATUS WINAPI NCryptOpenStorageProvider(NCRYPT_PROV_HANDLE *provider, const WCHAR *name, DWORD flags)
{
    struct object *object;

    TRACE("(%p, %s, %#lx)\n", provider, wine_dbgstr_w(name), flags);

    if (!(object = allocate_object(STORAGE_PROVIDER)))
    {
        ERR("Error allocating memory.\n");
        return NTE_NO_MEMORY;
    }
    set_string_property(object, NCRYPT_NAME_PROPERTY, name ? name : MS_KEY_STORAGE_PROVIDER);
    set_dword_property(object, NCRYPT_IMPL_TYPE_PROPERTY, NCRYPT_IMPL_SOFTWARE_FLAG);
    set_dword_property(object, NCRYPT_VERSION_PROPERTY, 0x10000);
    set_dword_property(object, NCRYPT_MAX_NAME_LENGTH_PROPERTY, MAX_PATH);
    set_dword_property(object, NCRYPT_SECURITY_DESCR_SUPPORT_PROPERTY, 1);
    *provider = (NCRYPT_PROV_HANDLE)object;
    return ERROR_SUCCESS;
}

SECURITY_STATUS WINAPI NCryptSetProperty(NCRYPT_HANDLE handle, const WCHAR *name, BYTE *input, DWORD insize, DWORD flags)
{
    static const WCHAR *settable[] =
    {
        NCRYPT_LENGTH_PROPERTY, NCRYPT_EXPORT_POLICY_PROPERTY, NCRYPT_KEY_USAGE_PROPERTY,
        NCRYPT_UI_POLICY_PROPERTY, NCRYPT_WINDOW_HANDLE_PROPERTY, NCRYPT_USE_CONTEXT_PROPERTY,
        NCRYPT_SECURITY_DESCR_PROPERTY, BCRYPT_ECC_CURVE_NAME, L"ECCParameters", BCRYPT_DH_PARAMETERS,
        BCRYPT_CHAINING_MODE, NCRYPT_PIN_PROPERTY, NCRYPT_PIN_PROMPT_PROPERTY, NCRYPT_SECURE_PIN_PROPERTY,
    };
    struct object *object = get_object(handle);
    WCHAR custom[NCRYPT_MAX_PROPERTY_NAME + 2];
    unsigned int i;

    TRACE("(%#Ix, %s, %p, %lu, %#lx)\n", handle, wine_dbgstr_w(name), input, insize, flags);
    if (flags & ~(NCRYPT_PERSIST_ONLY_FLAG | NCRYPT_PERSIST_FLAG | NCRYPT_SILENT_FLAG))
        FIXME("flags %#lx not supported\n", flags);

    if (!object || object->type == SECRET) return NTE_INVALID_HANDLE;
    if (!name || (insize && !input)) return NTE_INVALID_PARAMETER;
    if (flags & NCRYPT_PERSIST_ONLY_FLAG)
    {
        if (!custom_property_name(name, custom, ARRAYSIZE(custom))) return NTE_INVALID_PARAMETER;
        return set_object_property(object, custom, input, insize);
    }
    for (i = 0; i < ARRAYSIZE(settable); i++)
    {
        if (wcscmp(name, settable[i])) continue;
        if (!wcscmp(name, NCRYPT_EXPORT_POLICY_PROPERTY) && object->type == KEY)
        {
            DWORD policy;

            /* the policy can be changed after the key is finalized: it is read when the key is exported */
            if (insize != sizeof(policy)) return NTE_BAD_DATA;
            memcpy(&policy, input, sizeof(policy));
            if (policy & ~(NCRYPT_ALLOW_EXPORT_FLAG | NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG |
                           NCRYPT_ALLOW_ARCHIVING_FLAG | NCRYPT_ALLOW_PLAINTEXT_ARCHIVING_FLAG))
                return NTE_NOT_SUPPORTED;
            /* archiving implies the matching export right */
            if (policy & NCRYPT_ALLOW_ARCHIVING_FLAG) policy |= NCRYPT_ALLOW_EXPORT_FLAG;
            if (policy & NCRYPT_ALLOW_PLAINTEXT_ARCHIVING_FLAG) policy |= NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG;
            return set_object_property(object, name, (const BYTE *)&policy, sizeof(policy));
        }
        return set_object_property(object, name, input, insize);
    }
    return NTE_NOT_SUPPORTED;
}

SECURITY_STATUS WINAPI NCryptSignHash(NCRYPT_KEY_HANDLE handle, void *padding, BYTE *value, DWORD value_len,
                                      BYTE *sig, DWORD sig_len, DWORD *ret_len, DWORD flags)
{
    struct object *object = get_key_object(handle);

    TRACE("(%#Ix, %p, %p, %lu, %p, %lu, %#lx)\n", handle, padding, value, value_len, sig, sig_len, flags);
    if (flags & NCRYPT_SILENT_FLAG) FIXME("Silent flag not implemented\n");

    if (!object) return NTE_INVALID_HANDLE;
    if (!object->key.finalized) return NTE_BAD_KEY_STATE;
    if (object->key.algid != RSA && (object->key.algid < ECDSA || object->key.algid > ECDSA_P521))
        return NTE_NOT_SUPPORTED;

    return map_ntstatus(BCryptSignHash(object->key.bcrypt_key, padding, value, value_len, sig, sig_len,
                                       ret_len, flags & ~NCRYPT_SILENT_FLAG));
}

SECURITY_STATUS WINAPI NCryptVerifySignature(NCRYPT_KEY_HANDLE handle, void *padding, BYTE *hash, DWORD hash_size,
                                             BYTE *signature, DWORD signature_size, DWORD flags)
{
    struct object *key_object = get_key_object(handle);

    TRACE("(%#Ix, %p, %p, %lu, %p, %lu, %#lx)\n", handle, padding, hash, hash_size, signature,
          signature_size, flags);

    if (!hash_size || !signature_size) return NTE_INVALID_PARAMETER;
    if (!hash || !signature) return HRESULT_FROM_WIN32(RPC_X_NULL_REF_POINTER);
    if (!key_object) return NTE_INVALID_HANDLE;

    if (key_object->key.algid < RSA)
    {
        FIXME("Symmetric keys not supported.\n");
        return NTE_NOT_SUPPORTED;
    }
    if (!key_object->key.finalized) return NTE_BAD_KEY_STATE;

    return map_ntstatus(BCryptVerifySignature(key_object->key.bcrypt_key, padding, hash, hash_size, signature,
                                              signature_size, flags & ~NCRYPT_SILENT_FLAG));
}

/* a key with its private part: a public key (imported from a public blob) cannot be an agreement's own key */
static BOOL key_has_private_part(const struct key *key)
{
    ULONG size = 0;

    if (!is_ecc(key->algid)) return FALSE;
    return !BCryptExportKey(key->bcrypt_key, NULL, BCRYPT_ECCPRIVATE_BLOB, NULL, 0, &size, 0);
}

SECURITY_STATUS WINAPI NCryptSecretAgreement(NCRYPT_KEY_HANDLE privkey_handle, NCRYPT_KEY_HANDLE pubkey_handle,
                                             NCRYPT_SECRET_HANDLE *secret_handle, DWORD flags)
{
    struct object *privkey = get_key_object(privkey_handle);
    struct object *pubkey = get_key_object(pubkey_handle);
    struct object *secret;
    NTSTATUS status;

    TRACE("(%#Ix, %#Ix, %p, %#lx)\n", privkey_handle, pubkey_handle, secret_handle, flags);

    if (!privkey || !pubkey) return NTE_INVALID_HANDLE;
    if (flags) return NTE_BAD_FLAGS;
    if (!secret_handle) return NTE_INVALID_PARAMETER;
    if (!privkey->key.finalized || !pubkey->key.finalized) return NTE_BAD_KEY_STATE;
    /* an agreement is made with elliptic curve Diffie-Hellman keys: the algorithm of the own key is checked
       first, then the other key (a key of another algorithm or of another curve is an invalid parameter) */
    if (!is_ecdh(privkey->key.algid)) return NTE_BAD_ALGID;
    if (!is_ecdh(pubkey->key.algid) || privkey->key.bits != pubkey->key.bits) return NTE_INVALID_PARAMETER;
    if (!key_has_private_part(&privkey->key)) return NTE_NO_KEY;

    if (!(secret = allocate_object(SECRET))) return NTE_NO_MEMORY;
    if ((status = BCryptSecretAgreement(privkey->key.bcrypt_key, pubkey->key.bcrypt_key, &secret->secret, 0)))
    {
        free_object(secret);
        return map_ntstatus(status);
    }
    *secret_handle = (NCRYPT_SECRET_HANDLE)secret;
    return ERROR_SUCCESS;
}

SECURITY_STATUS WINAPI NCryptDeriveKey(NCRYPT_SECRET_HANDLE secret_handle, const WCHAR *kdf,
                                       NCryptBufferDesc *params, BYTE *output, DWORD output_len,
                                       DWORD *ret_len, ULONG flags)
{
    struct object *secret = get_secret_object(secret_handle);
    NTSTATUS status;

    TRACE("(%#Ix, %s, %p, %p, %lu, %p, %#lx)\n", secret_handle, wine_dbgstr_w(kdf), params, output, output_len,
          ret_len, flags);

    if (!secret) return NTE_INVALID_HANDLE;
    /* a missing pointer is the RPC error of a null reference (the Microsoft provider is in the key isolation
       service) */
    if (!kdf || !ret_len) return HRESULT_FROM_WIN32(RPC_X_NULL_REF_POINTER);

    /* NCryptBufferDesc and BCryptBufferDesc are one structure */
    status = BCryptDeriveKey(secret->secret, kdf, (BCryptBufferDesc *)params, output, output_len, ret_len, flags);
    if (status) *ret_len = 0;
    return map_ntstatus(status);
}

SECURITY_STATUS WINAPI NCryptTranslateHandle(NCRYPT_PROV_HANDLE *provider, NCRYPT_KEY_HANDLE *key,
                                             HCRYPTPROV legacy_provider, HCRYPTKEY legacy_key,
                                             DWORD legacy_keyspec, DWORD flags)
{
    DWORD size = 0;

    TRACE("(%p, %p, %#Ix, %#Ix, %lu, %#lx)\n", provider, key, legacy_provider, legacy_key, legacy_keyspec, flags);

    if (flags) return NTE_BAD_FLAGS;
    if (!key || !legacy_provider) return NTE_INVALID_PARAMETER;

    /* a legacy provider handle is validated by asking it for its name */
    if (!CryptGetProvParam(legacy_provider, PP_NAME, NULL, &size, 0) && GetLastError() != ERROR_MORE_DATA)
        return NTE_INVALID_PARAMETER;

    /* Windows makes a key of the Microsoft key storage provider for the key of a persisted legacy container
       (NTE_BAD_TYPE for a provider with no container). The key storage provider here only has ephemeral
       keys, the keys of a legacy container are not reachable: this is not supported */
    return NTE_NOT_SUPPORTED;
}

SECURITY_STATUS WINAPI NCryptCreateClaim(NCRYPT_KEY_HANDLE subject_key, NCRYPT_KEY_HANDLE authority_key,
                                         DWORD claim_type, NCryptBufferDesc *params, BYTE *claim,
                                         DWORD claim_len, DWORD *ret_len, DWORD flags)
{
    TRACE("(%#Ix, %#Ix, %#lx, %p, %p, %lu, %p, %#lx)\n", subject_key, authority_key, claim_type, params, claim,
          claim_len, ret_len, flags);

    if (!ret_len) return HRESULT_FROM_WIN32(RPC_X_NULL_REF_POINTER);
    if (!get_key_object(subject_key)) return NTE_INVALID_HANDLE;
    if (authority_key && !get_key_object(authority_key)) return NTE_INVALID_HANDLE;

    /* a claim is made by a key of a platform (TPM) provider, a software key cannot make one */
    *ret_len = 0;
    return NTE_NOT_SUPPORTED;
}
