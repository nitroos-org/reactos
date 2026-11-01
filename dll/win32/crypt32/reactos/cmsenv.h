/*
 * PROJECT:     ReactOS crypt32
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     CMS EnvelopedData (RFC 5652 section 6) reader, writer and content cipher for msg.c
 * COPYRIGHT:   Copyright 2026 Tomas Srnka
 */

#ifndef _CRYPT32_CMSENV_H
#define _CRYPT32_CMSENV_H

/* CRYPT_RSAES_OAEP_PARAMETERS, which the PSDK of this tree does not have yet */
typedef struct _CMS_RSAES_OAEP_PARAMETERS
{
    CRYPT_ALGORITHM_IDENTIFIER HashAlgorithm;
    struct { LPSTR pszObjId; CRYPT_ALGORITHM_IDENTIFIER HashAlgorithm; } MaskGenAlgorithm;
    struct { LPSTR pszObjId; CRYPT_DATA_BLOB EncodingParameters; } PSourceAlgorithm;
} CMS_RSAES_OAEP_PARAMETERS;

/* one RecipientInfo of a decoded message */
struct cms_recip
{
    DWORD choice;               /* CMSG_KEY_TRANS_RECIPIENT, _KEY_AGREE_, _MAIL_LIST_, or 0 for pwri/ori/unknown */
    DWORD version;              /* key transport only from here on */
    CERT_ID id;                 /* issuer and key id point into the message, the serial is serial_le */
    BYTE *serial_le;            /* owned: the serial number in the little endian form of CERT_INFO */
    BYTE *synth_issuer;         /* owned: issuer name made up for subject key identifier recipients */
    char *alg_oid;              /* owned */
    CRYPT_DATA_BLOB alg_params; /* points into the message, empty for NULL */
    CRYPT_DATA_BLOB enc_key;    /* points into the message */
    CRYPT_DATA_BLOB legacy_issuer, legacy_serial; /* what CMSG_RECIPIENT_INFO_PARAM reports */
};

struct cms_env
{
    BYTE *raw;                  /* private copy of the message, everything below points into it */
    DWORD raw_len;
    DWORD version;
    DWORD n_recip;
    struct cms_recip *recip;
    DWORD n_ktri;               /* key transport recipients: what the legacy parameters count */
    DWORD *ktri_index;          /* position in recip of each key transport recipient */
    DWORD n_cert, n_crl;
    CRYPT_DATA_BLOB *certs, *crls;
    char *content_type;         /* owned */
    char *alg_oid;              /* owned */
    CRYPT_DATA_BLOB alg_params;
    BOOL has_content;
    CRYPT_DATA_BLOB content;    /* the encrypted content */
    BYTE *content_buf;          /* owned: the content of a BER message put together from its segments */
    BOOL has_attrs;
    CRYPT_DATA_BLOB attrs;      /* the complete [1] unprotectedAttrs element */
};

/* The largest content, in bytes, the CMS code buffers or encrypts at once: keeps every size sum and block
 * padding inside a DWORD (and a 32 bit size_t). Above it the call fails with ERROR_OUTOFMEMORY, as a
 * failed allocation of that size does. */
#define CMS_MAX_CONTENT 0x7fffff00

/* ncrypt.dll from the system directory only, never from the default DLL search order */
HMODULE CMSEnv_LoadNcrypt(void);

BOOL CMSEnv_Decode(const BYTE *pb, DWORD cb, struct cms_env **out);
void CMSEnv_Free(struct cms_env *env);

/* GetParam support: the buffers follow CryptMsgGetParam's size negotiation */
BYTE *CMSEnv_WrapContent(const BYTE *content, DWORD len, DWORD *out_len);
BOOL CMSEnv_CopyAlgorithm(const struct cms_env *env, void *pv, DWORD *pcb);
BOOL CMSEnv_CopyCmsRecipient(const struct cms_recip *r, void *pv, DWORD *pcb);

/* Decryption. key is a CryptoAPI provider, or an NCrypt key handle when keyspec is CERT_NCRYPT_KEY_SPEC.
 * ktri may point to the application's copy of the recipient (CMSG_CTRL_KEY_TRANS_DECRYPT), or be NULL. */
BOOL CMSEnv_Decrypt(const struct cms_env *env, const struct cms_recip *recip,
                    const CMSG_KEY_TRANS_RECIPIENT_INFO *ktri, ULONG_PTR key, DWORD keyspec,
                    const BYTE *content, DWORD content_len, BYTE **out, DWORD *out_len);

/* Encoding */
struct cms_enc_recip
{
    DWORD id_choice;            /* CERT_ID_ISSUER_SERIAL_NUMBER or CERT_ID_KEY_IDENTIFIER */
    CRYPT_DATA_BLOB issuer, serial_le, key_id;
    const char *key_alg;        /* NULL: rsaEncryption */
    CRYPT_DATA_BLOB key_alg_params;
    const CMS_RSAES_OAEP_PARAMETERS *oaep;
    CRYPT_BIT_BLOB public_key;  /* RSAPublicKey */
};

struct cms_enc;
BOOL CMSEnv_CheckContentAlg(const char *oid);
struct cms_enc *CMSEnv_EncNew(const char *content_type, const char *content_alg, const CRYPT_DATA_BLOB *alg_params,
                              const void *aux, DWORD n_recip, const struct cms_enc_recip *recip,
                              DWORD n_cert, const CERT_BLOB *certs, DWORD n_crl, const CRL_BLOB *crls,
                              DWORD n_attr, const CRYPT_ATTRIBUTE *attrs);
BOOL CMSEnv_EncContent(struct cms_enc *enc, const BYTE *data, DWORD len);
BOOL CMSEnv_EncGetBare(const struct cms_enc *enc, void *pv, DWORD *pcb);
void CMSEnv_EncFree(struct cms_enc *enc);

/* Streamed output, which Windows does as follows: the header (everything up to the opening of the encrypted
 * content) comes with the first update, the encrypted content and the closing bytes with the final update
 * (definite length: the ciphertext, then the unprotected attributes, if any; indefinite length: the OCTET
 * STRING header, the ciphertext, two end-of-contents, the attributes, three end-of-contents). */
typedef BOOL (*cms_emit_fn)(void *ctx, const BYTE *pb, DWORD cb, BOOL final);
BOOL CMSEnv_EncStreamStart(struct cms_enc *enc, BOOL indefinite, DWORD cb_content, cms_emit_fn emit, void *ctx);
BOOL CMSEnv_EncStreamFinish(struct cms_enc *enc, BOOL indefinite, const BYTE *data, DWORD len,
                            cms_emit_fn emit, void *ctx);

#endif
