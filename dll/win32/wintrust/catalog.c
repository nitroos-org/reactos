/*
 * WinTrust catalog files (CryptCAT*) and catalog definition files (CDF)
 *
 * Copyright 2008 Juan Lang
 * Copyright 2026 reactos-nitro contributors
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
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>
#include "windef.h"
#include "winbase.h"
#include "wintrust.h"
#include "mscat.h"
#include "mssip.h"
#include "winnls.h"
#include "winternl.h"

#include "wine/debug.h"

#include "wintrust_priv.h"

WINE_DEFAULT_DEBUG_CHANNEL(wintrust);

#define CRYPTCAT_MAGIC 0x43415443 /* 'CATC' */
#define CDF_MAGIC      0x43414344 /* 'CACD' */

#define CAT_MEMBERINFO2_OBJID "1.3.6.1.4.1.311.12.2.3"
#define CAT_LIST_MEMBER_V1    "1.3.6.1.4.1.311.12.1.2"
#define CAT_LIST_MEMBER_V2    "1.3.6.1.4.1.311.12.1.3"

static const GUID subject_pe = {0xc689aab8, 0x8e78, 0x11d0, {0x8c, 0x47, 0x00, 0xc0, 0x4f, 0xc2, 0x95, 0xee}};
static const GUID subject_flat = {0xde351a42, 0x8e59, 0x11d0, {0x8c, 0x47, 0x00, 0xc0, 0x4f, 0xc2, 0x95, 0xee}};

/* DER encoded object identifier contents */
static const BYTE oid_signed_data[] = {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02};
static const BYTE oid_ctl[] = {0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x0a, 0x01};
static const BYTE oid_cat_list[] = {0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x0c, 0x01, 0x01};
static const BYTE oid_cat_member_v1[] = {0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x0c, 0x01, 0x02};
static const BYTE oid_cat_member_v2[] = {0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x0c, 0x01, 0x03};
static const BYTE oid_namevalue[] = {0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x0c, 0x02, 0x01};
static const BYTE oid_memberinfo[] = {0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x0c, 0x02, 0x02};
static const BYTE oid_memberinfo2[] = {0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x0c, 0x02, 0x03};
static const BYTE oid_indirect[] = {0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x01, 0x04};

/* SpcPeImageData without resources, and the empty file link of other subjects */
static const BYTE pe_image_value[] = {0x30, 0x0a, 0x03, 0x02, 0x05, 0xa0, 0xa0, 0x04, 0xa2, 0x02, 0x80, 0x00};
static const BYTE flat_value[] = {0xa2, 0x02, 0x80, 0x00};

struct catattr
{
    CRYPTCATATTRIBUTE attr; /* must be first */
};

struct catmember
{
    CRYPTCATMEMBER member; /* must be first */
    struct catattr **attrs;
    DWORD attr_count, attr_cap;
    BYTE *id;               /* subject identifier */
    DWORD id_len;
    BYTE compat_id[20];     /* SHA-1 entry added to version 2 catalogs */
    BOOL has_compat;
    BOOL has_indirect;      /* the indirect data was stored in the catalog */
};

struct cryptcat
{
    DWORD magic;
    HCRYPTMSG msg;
    DWORD encoding;
    WCHAR *filename;
    DWORD open_flags;
    DWORD version;
    CRYPTCATSTORE store;
    struct catattr **attrs;
    DWORD attr_count, attr_cap;
    struct catmember **members;
    DWORD member_count, member_cap;
};

static BOOL is_valid_cat(HANDLE h)
{
    struct cryptcat *cc = h;

    if (!h || h == INVALID_HANDLE_VALUE) return FALSE;
    return cc->magic == CRYPTCAT_MAGIC;
}

static WCHAR *strdupW_(const WCHAR *s)
{
    WCHAR *ret;
    SIZE_T len = lstrlenW(s) + 1;

    if ((ret = malloc(len * sizeof(WCHAR)))) memcpy(ret, s, len * sizeof(WCHAR));
    return ret;
}

static BOOL grow_array(void **array, DWORD *cap, DWORD count, size_t elem)
{
    void *p;
    DWORD new_cap;

    if (count < *cap) return TRUE;
    new_cap = *cap ? *cap * 2 : 8;
    if (!(p = realloc(*array, new_cap * elem))) return FALSE;
    *array = p;
    *cap = new_cap;
    return TRUE;
}

/* ---------------------------------------------------------------- DER */

struct der_buf
{
    BYTE *data;
    DWORD len, cap;
    BOOL failed;
};

static void der_reserve(struct der_buf *b, DWORD add)
{
    BYTE *p;
    DWORD cap;

    if (b->failed) return;
    if (b->len + add <= b->cap) return;
    cap = max(b->cap * 2, b->len + add + 64);
    if (!(p = realloc(b->data, cap))) { b->failed = TRUE; return; }
    b->data = p;
    b->cap = cap;
}

static void der_append(struct der_buf *b, const void *data, DWORD len)
{
    der_reserve(b, len);
    if (b->failed) return;
    if (len) memcpy(b->data + b->len, data, len);
    b->len += len;
}

static void der_append_tlv(struct der_buf *b, BYTE tag, const void *data, DWORD len)
{
    BYTE hdr[6];
    DWORD n = 0;

    hdr[n++] = tag;
    if (len < 0x80) hdr[n++] = len;
    else if (len < 0x100) { hdr[n++] = 0x81; hdr[n++] = len; }
    else if (len < 0x10000) { hdr[n++] = 0x82; hdr[n++] = len >> 8; hdr[n++] = len; }
    else { hdr[n++] = 0x83; hdr[n++] = len >> 16; hdr[n++] = len >> 8; hdr[n++] = len; }
    der_append(b, hdr, n);
    der_append(b, data, len);
}

/* appends the content of "inner" wrapped in a tag and frees inner */
static void der_wrap(struct der_buf *b, BYTE tag, struct der_buf *inner)
{
    if (inner->failed) b->failed = TRUE;
    else der_append_tlv(b, tag, inner->data, inner->len);
    free(inner->data);
    memset(inner, 0, sizeof(*inner));
}

static void der_integer(struct der_buf *b, DWORD value)
{
    BYTE tmp[5];
    DWORD n = 0, i;

    for (i = 0; i < 4; i++) tmp[1 + i] = value >> (24 - 8 * i);
    tmp[0] = 0;
    /* minimal positive encoding */
    i = 0;
    while (i < 4 && !tmp[i] && !(tmp[i + 1] & 0x80)) i++;
    n = 5 - i;
    der_append_tlv(b, 0x02, tmp + i, n);
}

static void der_bmpstring(struct der_buf *b, const WCHAR *s)
{
    struct der_buf inner = {0};
    DWORD i, len = lstrlenW(s);

    der_reserve(&inner, len * 2);
    for (i = 0; i < len && !inner.failed; i++)
    {
        BYTE c[2] = {s[i] >> 8, s[i] & 0xff};
        der_append(&inner, c, 2);
    }
    der_wrap(b, 0x1e, &inner);
}

static void der_utctime(struct der_buf *b)
{
    SYSTEMTIME st;
    char buf[16];

    GetSystemTime(&st);
    sprintf(buf, "%02u%02u%02u%02u%02u%02uZ", st.wYear % 100, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    der_append_tlv(b, 0x17, buf, 13);
}

static void der_attribute(struct der_buf *b, const BYTE *oid, DWORD oid_len, const BYTE *value, DWORD value_len)
{
    struct der_buf seq = {0}, set = {0};

    der_append_tlv(&seq, 0x06, oid, oid_len);
    der_append(&set, value, value_len);
    der_wrap(&seq, 0x31, &set);
    der_wrap(b, 0x30, &seq);
}

static void der_oid_string(struct der_buf *b, const char *oid)
{
    BYTE content[32];
    DWORD n = 0, parts[16], np = 0, v = 0, i;

    for (;; oid++)
    {
        if (*oid == '.' || !*oid)
        {
            if (np < ARRAY_SIZE(parts)) parts[np++] = v;
            v = 0;
            if (!*oid) break;
        }
        else v = v * 10 + (*oid - '0');
    }
    if (np < 2) { b->failed = TRUE; return; }
    content[n++] = parts[0] * 40 + parts[1];
    for (i = 2; i < np; i++)
    {
        BYTE tmp[5];
        int k = 0;

        v = parts[i];
        do { tmp[k++] = v & 0x7f; v >>= 7; } while (v);
        while (k > 0 && n < sizeof(content))
        {
            k--;
            content[n++] = tmp[k] | (k ? 0x80 : 0);
        }
    }
    der_append_tlv(b, 0x06, content, n);
}

/* SpcIndirectDataContent */
static BYTE *encode_indirect_data(const SIP_INDIRECT_DATA *d, DWORD *len)
{
    struct der_buf seq = {0}, data = {0}, digest_info = {0}, alg = {0}, out = {0};

    if (!d->Data.pszObjId || !d->DigestAlgorithm.pszObjId) return NULL;
    der_oid_string(&data, d->Data.pszObjId);
    der_append(&data, d->Data.Value.pbData, d->Data.Value.cbData);
    der_wrap(&seq, 0x30, &data);

    der_oid_string(&alg, d->DigestAlgorithm.pszObjId);
    der_append(&alg, d->DigestAlgorithm.Parameters.pbData, d->DigestAlgorithm.Parameters.cbData);
    der_wrap(&digest_info, 0x30, &alg);
    der_append_tlv(&digest_info, 0x04, d->Digest.pbData, d->Digest.cbData);
    der_wrap(&seq, 0x30, &digest_info);
    der_wrap(&out, 0x30, &seq);
    if (out.failed) { free(out.data); return NULL; }
    *len = out.len;
    return out.data;
}

static BYTE *encode_namevalue(const CRYPTCATATTRIBUTE *attr, DWORD *len)
{
    struct der_buf seq = {0}, out = {0};

    der_bmpstring(&seq, attr->pwszReferenceTag);
    der_integer(&seq, attr->dwAttrTypeAndAction);
    der_append_tlv(&seq, 0x04, attr->pbValue, attr->cbValue);
    der_wrap(&out, 0x30, &seq);
    if (out.failed) { free(out.data); return NULL; }
    *len = out.len;
    return out.data;
}

static BYTE *encode_memberinfo(const GUID *guid, DWORD version, DWORD *len)
{
    struct der_buf seq = {0}, out = {0};
    WCHAR str[40];

    swprintf(str, ARRAY_SIZE(str), L"{%08lX-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
             guid->Data1, guid->Data2, guid->Data3, guid->Data4[0], guid->Data4[1], guid->Data4[2],
             guid->Data4[3], guid->Data4[4], guid->Data4[5], guid->Data4[6], guid->Data4[7]);
    der_bmpstring(&seq, str);
    der_integer(&seq, version);
    der_wrap(&out, 0x30, &seq);
    if (out.failed) { free(out.data); return NULL; }
    *len = out.len;
    return out.data;
}

static int cmp_blob(const void *a, const void *b)
{
    const struct der_buf *x = a, *y = b;
    DWORD n = min(x->len, y->len);
    int r = memcmp(x->data, y->data, n);

    if (r) return r;
    return (x->len > y->len) - (x->len < y->len);
}

/* ---------------------------------------------------------------- reading */

static struct catattr *alloc_attr(const WCHAR *name, DWORD flags, const BYTE *value, DWORD size)
{
    struct catattr *a;

    if (!(a = calloc(1, sizeof(*a)))) return NULL;
    a->attr.cbStruct = sizeof(a->attr);
    a->attr.pwszReferenceTag = strdupW_(name);
    a->attr.dwAttrTypeAndAction = flags;
    a->attr.cbValue = size;
    a->attr.pbValue = malloc(size ? size : 1);
    if (!a->attr.pwszReferenceTag || !a->attr.pbValue)
    {
        free(a->attr.pwszReferenceTag);
        free(a->attr.pbValue);
        free(a);
        return NULL;
    }
    if (size) memcpy(a->attr.pbValue, value, size);
    return a;
}

static void free_attr(struct catattr *a)
{
    if (!a) return;
    free(a->attr.pwszReferenceTag);
    free(a->attr.pbValue);
    free(a);
}

static void free_member(struct catmember *m)
{
    DWORD i;

    if (!m) return;
    for (i = 0; i < m->attr_count; i++) free_attr(m->attrs[i]);
    free(m->attrs);
    free(m->id);
    free(m->member.pwszReferenceTag);
    free(m->member.pwszFileName);
    free(m->member.pIndirectData);
    free(m->member.sEncodedIndirectData.pbData);
    free(m->member.sEncodedMemberInfo.pbData);
    free(m);
}

static BOOL cat_add_attr(struct catattr ***list, DWORD *cap, DWORD *count, struct catattr *a)
{
    if (!grow_array((void **)list, cap, *count, sizeof(**list))) return FALSE;
    (*list)[(*count)++] = a;
    return TRUE;
}

static CTL_INFO *decode_inner_content(HANDLE hmsg, DWORD encoding)
{
    DWORD size;
    LPSTR oid = NULL;
    BYTE *buffer = NULL;
    CTL_INFO *inner = NULL;

    if (!CryptMsgGetParam(hmsg, CMSG_INNER_CONTENT_TYPE_PARAM, 0, NULL, &size)) return NULL;
    if (!(oid = malloc(size)))
    {
        SetLastError(ERROR_OUTOFMEMORY);
        return NULL;
    }
    if (!CryptMsgGetParam(hmsg, CMSG_INNER_CONTENT_TYPE_PARAM, 0, oid, &size)) goto out;
    if (!CryptMsgGetParam(hmsg, CMSG_CONTENT_PARAM, 0, NULL, &size)) goto out;
    if (!(buffer = malloc(size)))
    {
        SetLastError(ERROR_OUTOFMEMORY);
        goto out;
    }
    if (!CryptMsgGetParam(hmsg, CMSG_CONTENT_PARAM, 0, buffer, &size)) goto out;
    if (!CryptDecodeObject(encoding, oid, buffer, size, 0, NULL, &size)) goto out;
    if (!(inner = malloc(size)))
    {
        SetLastError(ERROR_OUTOFMEMORY);
        goto out;
    }
    if (!CryptDecodeObject(encoding, oid, buffer, size, 0, inner, &size))
    {
        free(inner);
        inner = NULL;
    }

out:
    free(oid);
    free(buffer);
    return inner;
}

static BYTE *copy_bytes(const BYTE *src, DWORD len)
{
    BYTE *p = malloc(len ? len : 1);

    if (p && len) memcpy(p, src, len);
    return p;
}

static void *decode_object(DWORD encoding, const char *oid, const BYTE *data, DWORD len)
{
    DWORD size;
    void *buf;

    if (!CryptDecodeObject(encoding, oid, data, len, 0, NULL, &size)) return NULL;
    if (!(buf = malloc(size))) return NULL;
    if (!CryptDecodeObject(encoding, oid, data, len, 0, buf, &size))
    {
        free(buf);
        return NULL;
    }
    return buf;
}

static WCHAR *hex_tag(const BYTE *data, DWORD len)
{
    WCHAR *tag = malloc((len * 2 + 1) * sizeof(WCHAR));
    DWORD i;

    if (!tag) return NULL;
    for (i = 0; i < len; i++)
    {
        BYTE hi = data[i] >> 4, lo = data[i] & 0xf;
        tag[i * 2] = hi < 10 ? '0' + hi : 'A' + hi - 10;
        tag[i * 2 + 1] = lo < 10 ? '0' + lo : 'A' + lo - 10;
    }
    tag[len * 2] = 0;
    return tag;
}

/* indirect data of an entry that carries only the subject identifier (the SHA-1 entries of version 2 catalogs) */
static SIP_INDIRECT_DATA *synthesize_indirect_data(const BYTE *id, DWORD len)
{
    static const char sha1_oid[] = szOID_OIWSEC_sha1;
    static const char sha256_oid[] = "2.16.840.1.101.3.4.2.1";
    static const char cab_oid[] = SPC_CAB_DATA_OBJID;
    const char *alg = len == 20 ? sha1_oid : sha256_oid;
    SIP_INDIRECT_DATA *data;
    char *p;

    if (!(data = calloc(1, sizeof(*data) + sizeof(sha256_oid) + sizeof(cab_oid) + len))) return NULL;
    p = (char *)(data + 1);
    memcpy(p, cab_oid, sizeof(cab_oid));
    data->Data.pszObjId = p;
    p += sizeof(cab_oid);
    memcpy(p, alg, strlen(alg) + 1);
    data->DigestAlgorithm.pszObjId = p;
    p += sizeof(sha256_oid);
    memcpy(p, id, len);
    data->Digest.pbData = (BYTE *)p;
    data->Digest.cbData = len;
    return data;
}

static BOOL cat_load_entry(struct cryptcat *cc, const CTL_ENTRY *entry)
{
    struct catmember *m;
    DWORD i;

    if (!(m = calloc(1, sizeof(*m)))) return FALSE;
    m->member.cbStruct = sizeof(m->member);
    m->member.gSubjectType = subject_flat;
    m->member.dwCertVersion = 0x200;
    m->id_len = entry->SubjectIdentifier.cbData;
    m->id = copy_bytes(entry->SubjectIdentifier.pbData, m->id_len);
    if (!m->id) goto error;

    /* version 1 catalogs store the reference tag, version 2 the digest */
    if (cc->version != CRYPTCAT_VERSION_2 && m->id_len >= 2 && !(m->id_len & 1) &&
        !((WCHAR *)m->id)[m->id_len / 2 - 1])
        m->member.pwszReferenceTag = strdupW_((WCHAR *)m->id);
    else
        m->member.pwszReferenceTag = hex_tag(m->id, m->id_len);
    if (!m->member.pwszReferenceTag) goto error;

    for (i = 0; i < entry->cAttribute; i++)
    {
        CRYPT_ATTRIBUTE *attr = entry->rgAttribute + i;

        if (attr->cValue != 1)
        {
            ERR("Can't handle attr->cValue of %lu\n", attr->cValue);
            continue;
        }

        if (!strcmp(attr->pszObjId, CAT_NAMEVALUE_OBJID))
        {
            CAT_NAMEVALUE *nv = decode_object(cc->encoding, CAT_NAMEVALUE_OBJID, attr->rgValue->pbData,
                                              attr->rgValue->cbData);
            struct catattr *a;

            if (!nv) continue;
            a = alloc_attr(nv->pwszTag, nv->fdwFlags, nv->Value.pbData, nv->Value.cbData);
            free(nv);
            if (!a) goto error;
            if (!cat_add_attr(&m->attrs, &m->attr_cap, &m->attr_count, a)) { free_attr(a); goto error; }
        }
        else if (!strcmp(attr->pszObjId, CAT_MEMBERINFO_OBJID))
        {
            CAT_MEMBERINFO *mi = decode_object(cc->encoding, CAT_MEMBERINFO_OBJID, attr->rgValue->pbData,
                                               attr->rgValue->cbData);
            UNICODE_STRING guid;

            m->member.sEncodedMemberInfo.cbData = attr->rgValue->cbData;
            m->member.sEncodedMemberInfo.pbData = copy_bytes(attr->rgValue->pbData, attr->rgValue->cbData);
            if (!mi) continue;
            m->member.dwCertVersion = mi->dwCertVersion;
            RtlInitUnicodeString(&guid, mi->pwszSubjGuid);
            RtlGUIDFromString(&guid, &m->member.gSubjectType);
            free(mi);
        }
        else if (!strcmp(attr->pszObjId, CAT_MEMBERINFO2_OBJID))
        {
            m->member.sEncodedMemberInfo.cbData = attr->rgValue->cbData;
            m->member.sEncodedMemberInfo.pbData = copy_bytes(attr->rgValue->pbData, attr->rgValue->cbData);
            if (attr->rgValue->cbData && attr->rgValue->pbData[0] == 0x80)
                m->member.gSubjectType = subject_pe;
        }
        else if (!strcmp(attr->pszObjId, SPC_INDIRECT_DATA_OBJID))
        {
            /* SPC_INDIRECT_DATA_CONTENT is equal to SIP_INDIRECT_DATA */
            m->member.sEncodedIndirectData.cbData = attr->rgValue->cbData;
            m->member.sEncodedIndirectData.pbData = copy_bytes(attr->rgValue->pbData, attr->rgValue->cbData);
            m->member.pIndirectData = decode_object(cc->encoding, SPC_INDIRECT_DATA_OBJID,
                                                    attr->rgValue->pbData, attr->rgValue->cbData);
            if (m->member.pIndirectData && m->member.pIndirectData->Data.pszObjId &&
                !strcmp(m->member.pIndirectData->Data.pszObjId, SPC_PE_IMAGE_DATA_OBJID))
                m->member.gSubjectType = subject_pe;
        }
        else
            FIXME("unhandled object id \"%s\"\n", attr->pszObjId);
    }

    if (m->member.pIndirectData) m->has_indirect = TRUE;
    else if (!(m->member.pIndirectData = synthesize_indirect_data(m->id, m->id_len))) goto error;

    if (!grow_array((void **)&cc->members, &cc->member_cap, cc->member_count, sizeof(*cc->members))) goto error;
    cc->members[cc->member_count++] = m;
    return TRUE;

error:
    free_member(m);
    SetLastError(ERROR_OUTOFMEMORY);
    return FALSE;
}

static BOOL cat_load(struct cryptcat *cc)
{
    CTL_INFO *ctl;
    DWORD i;

    if (!(ctl = decode_inner_content(cc->msg, cc->encoding))) return FALSE;

    if (ctl->SubjectAlgorithm.pszObjId && !strcmp(ctl->SubjectAlgorithm.pszObjId, CAT_LIST_MEMBER_V2))
        cc->version = CRYPTCAT_VERSION_2;
    else
        cc->version = CRYPTCAT_VERSION_1;

    /* the attributes of a catalog without members are not reported */
    if (ctl->cCTLEntry)
    {
        for (i = 0; i < ctl->cExtension; i++)
        {
            CERT_EXTENSION *ext = ctl->rgExtension + i;
            CAT_NAMEVALUE *nv;
            struct catattr *a;

            if (!ext->pszObjId || strcmp(ext->pszObjId, CAT_NAMEVALUE_OBJID)) continue;
            if (!(nv = decode_object(cc->encoding, CAT_NAMEVALUE_OBJID, ext->Value.pbData, ext->Value.cbData)))
                continue;
            a = alloc_attr(nv->pwszTag, nv->fdwFlags, nv->Value.pbData, nv->Value.cbData);
            free(nv);
            if (!a || !cat_add_attr(&cc->attrs, &cc->attr_cap, &cc->attr_count, a))
            {
                free_attr(a);
                free(ctl);
                SetLastError(ERROR_OUTOFMEMORY);
                return FALSE;
            }
        }
    }

    /* list the members backwards, like native */
    for (i = ctl->cCTLEntry; i > 0; i--)
    {
        if (!cat_load_entry(cc, ctl->rgCTLEntry + i - 1))
        {
            free(ctl);
            return FALSE;
        }
    }
    free(ctl);
    return TRUE;
}

/***********************************************************************
 *      CryptCATOpen  (WINTRUST.@)
 */
HANDLE WINAPI CryptCATOpen(WCHAR *filename, DWORD flags, HCRYPTPROV hProv,
                           DWORD dwPublicVersion, DWORD dwEncodingType)
{
    HANDLE file, hmsg;
    BYTE *buffer = NULL;
    DWORD size, open_mode = OPEN_ALWAYS;
    struct cryptcat *cc;
    BOOL valid;

    TRACE("filename %s, flags %#lx, provider %#Ix, version %#lx, type %#lx\n",
          debugstr_w(filename), flags, hProv, dwPublicVersion, dwEncodingType);

    if (!filename)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return INVALID_HANDLE_VALUE;
    }

    if (!dwEncodingType)  dwEncodingType  = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;

    if (flags == CRYPTCAT_OPEN_EXISTING)
        open_mode = OPEN_EXISTING;
    if (flags & CRYPTCAT_OPEN_CREATENEW)
        open_mode = CREATE_ALWAYS;

    file = CreateFileW(filename, GENERIC_READ, FILE_SHARE_READ, NULL, open_mode, 0, NULL);
    if (file == INVALID_HANDLE_VALUE) return INVALID_HANDLE_VALUE;

    size = GetFileSize(file, NULL);
    if (!(buffer = malloc(size ? size : 1)))
    {
        CloseHandle(file);
        SetLastError(ERROR_OUTOFMEMORY);
        return INVALID_HANDLE_VALUE;
    }
    if (!(hmsg = CryptMsgOpenToDecode(dwEncodingType, 0, 0, hProv, NULL, NULL)))
    {
        CloseHandle(file);
        free(buffer);
        return INVALID_HANDLE_VALUE;
    }
    if (!size) valid = FALSE;
    else if (!ReadFile(file, buffer, size, &size, NULL))
    {
        CloseHandle(file);
        free(buffer);
        CryptMsgClose(hmsg);
        return INVALID_HANDLE_VALUE;
    }
    else valid = CryptMsgUpdate(hmsg, buffer, size, TRUE);
    free(buffer);
    CloseHandle(file);

    if (!(cc = calloc(1, sizeof(*cc))))
    {
        CryptMsgClose(hmsg);
        SetLastError(ERROR_OUTOFMEMORY);
        return INVALID_HANDLE_VALUE;
    }

    cc->msg = hmsg;
    cc->encoding = dwEncodingType;
    cc->open_flags = flags;
    cc->filename = strdupW_(filename);
    cc->version = dwPublicVersion == CRYPTCAT_VERSION_2 ? CRYPTCAT_VERSION_2 : CRYPTCAT_VERSION_1;
    if (!cc->filename)
    {
        CryptMsgClose(hmsg);
        free(cc);
        SetLastError(ERROR_OUTOFMEMORY);
        return INVALID_HANDLE_VALUE;
    }

    if (valid && !cat_load(cc))
    {
        DWORD err = GetLastError();
        DWORD i;

        for (i = 0; i < cc->attr_count; i++) free_attr(cc->attrs[i]);
        for (i = 0; i < cc->member_count; i++) free_member(cc->members[i]);
        free(cc->attrs);
        free(cc->members);
        free(cc->filename);
        CryptMsgClose(hmsg);
        free(cc);
        SetLastError(err);
        return INVALID_HANDLE_VALUE;
    }

    cc->store.cbStruct = sizeof(cc->store);
    cc->store.dwPublicVersion = cc->version;
    cc->store.pwszP7File = cc->filename;
    cc->store.hProv = hProv;
    cc->store.dwEncodingType = cc->encoding;
    cc->store.fdwStoreFlags = flags;
    cc->store.hCryptMsg = cc->msg;
    cc->magic = CRYPTCAT_MAGIC;
    SetLastError(ERROR_SUCCESS);
    return cc;
}

/***********************************************************************
 *      CryptCATClose  (WINTRUST.@)
 */
BOOL WINAPI CryptCATClose(HANDLE hCatalog)
{
    struct cryptcat *cc = hCatalog;
    DWORD i;

    TRACE("(%p)\n", hCatalog);

    if (!is_valid_cat(hCatalog))
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    for (i = 0; i < cc->attr_count; i++) free_attr(cc->attrs[i]);
    for (i = 0; i < cc->member_count; i++) free_member(cc->members[i]);
    free(cc->attrs);
    free(cc->members);
    free(cc->filename);
    CryptMsgClose(cc->msg);

    /* Ensure compiler doesn't optimize out the assignment with 0. */
    SecureZeroMemory(&cc->magic, sizeof(cc->magic));
    free(cc);
    return TRUE;
}

/***********************************************************************
 *      CryptCATStoreFromHandle  (WINTRUST.@)
 */
CRYPTCATSTORE * WINAPI CryptCATStoreFromHandle(HANDLE hCatalog)
{
    struct cryptcat *cc = hCatalog;

    TRACE("(%p)\n", hCatalog);

    if (!is_valid_cat(hCatalog))
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return NULL;
    }
    cc->store.dwPublicVersion = cc->version;
    return &cc->store;
}

static struct catattr *find_attr(struct catattr **list, DWORD count, const WCHAR *tag)
{
    DWORD i;

    for (i = 0; i < count; i++)
        if (!lstrcmpiW(list[i]->attr.pwszReferenceTag, tag)) return list[i];
    return NULL;
}

static struct catmember *member_from_ptr(struct cryptcat *cc, const CRYPTCATMEMBER *p)
{
    DWORD i;

    for (i = 0; i < cc->member_count; i++)
        if (&cc->members[i]->member == p) return cc->members[i];
    return NULL;
}

/***********************************************************************
 *      CryptCATGetAttrInfo  (WINTRUST.@)
 */
CRYPTCATATTRIBUTE * WINAPI CryptCATGetAttrInfo(HANDLE hCatalog, CRYPTCATMEMBER *member, LPWSTR tag)
{
    struct cryptcat *cc = hCatalog;
    struct catmember *m;
    struct catattr *a;

    TRACE("%p, %p, %s\n", hCatalog, member, debugstr_w(tag));

    if (!is_valid_cat(hCatalog) || !member || !tag || !(m = member_from_ptr(cc, member)))
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return NULL;
    }
    if (!(a = find_attr(m->attrs, m->attr_count, tag)))
    {
        SetLastError(CRYPT_E_NOT_FOUND);
        return NULL;
    }
    SetLastError(ERROR_SUCCESS);
    return &a->attr;
}

/***********************************************************************
 *      CryptCATGetCatAttrInfo  (WINTRUST.@)
 */
CRYPTCATATTRIBUTE * WINAPI CryptCATGetCatAttrInfo(HANDLE hCatalog, LPWSTR tag)
{
    struct cryptcat *cc = hCatalog;
    struct catattr *a;

    TRACE("%p, %s\n", hCatalog, debugstr_w(tag));

    if (!is_valid_cat(hCatalog) || !tag)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return NULL;
    }
    if (!(a = find_attr(cc->attrs, cc->attr_count, tag)))
    {
        SetLastError(CRYPT_E_NOT_FOUND);
        return NULL;
    }
    SetLastError(ERROR_SUCCESS);
    return &a->attr;
}

/***********************************************************************
 *      CryptCATGetMemberInfo  (WINTRUST.@)
 */
CRYPTCATMEMBER * WINAPI CryptCATGetMemberInfo(HANDLE hCatalog, LPWSTR tag)
{
    struct cryptcat *cc = hCatalog;
    DWORD i;

    TRACE("%p, %s\n", hCatalog, debugstr_w(tag));

    if (!is_valid_cat(hCatalog) || !tag)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return NULL;
    }
    for (i = 0; i < cc->member_count; i++)
    {
        if (!lstrcmpiW(cc->members[i]->member.pwszReferenceTag, tag))
        {
            SetLastError(ERROR_SUCCESS);
            return &cc->members[i]->member;
        }
    }
    /* native leaves the last error alone */
    return NULL;
}

/***********************************************************************
 *      CryptCATEnumerateAttr  (WINTRUST.@)
 */
CRYPTCATATTRIBUTE * WINAPI CryptCATEnumerateAttr(HANDLE hCatalog, CRYPTCATMEMBER *member, CRYPTCATATTRIBUTE *prev)
{
    struct cryptcat *cc = hCatalog;
    struct catmember *m;
    DWORD i = 0;

    TRACE("%p, %p, %p\n", hCatalog, member, prev);

    if (!is_valid_cat(hCatalog) || !member || !(m = member_from_ptr(cc, member)))
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return NULL;
    }
    if (prev)
    {
        while (i < m->attr_count && &m->attrs[i]->attr != prev) i++;
        if (i == m->attr_count)
        {
            SetLastError(ERROR_INVALID_PARAMETER);
            return NULL;
        }
        i++;
    }
    if (i >= m->attr_count)
    {
        SetLastError(CRYPT_E_NOT_FOUND);
        return NULL;
    }
    SetLastError(ERROR_SUCCESS);
    return &m->attrs[i]->attr;
}

/***********************************************************************
 *      CryptCATEnumerateCatAttr  (WINTRUST.@)
 */
CRYPTCATATTRIBUTE * WINAPI CryptCATEnumerateCatAttr(HANDLE hCatalog, CRYPTCATATTRIBUTE *prev)
{
    struct cryptcat *cc = hCatalog;
    DWORD i = 0;

    TRACE("%p, %p\n", hCatalog, prev);

    if (!is_valid_cat(hCatalog))
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return NULL;
    }
    if (prev)
    {
        while (i < cc->attr_count && &cc->attrs[i]->attr != prev) i++;
        if (i == cc->attr_count)
        {
            SetLastError(ERROR_INVALID_PARAMETER);
            return NULL;
        }
        i++;
    }
    if (i >= cc->attr_count)
    {
        SetLastError(CRYPT_E_NOT_FOUND);
        return NULL;
    }
    SetLastError(ERROR_SUCCESS);
    return &cc->attrs[i]->attr;
}

/***********************************************************************
 *      CryptCATEnumerateMember  (WINTRUST.@)
 */
CRYPTCATMEMBER * WINAPI CryptCATEnumerateMember(HANDLE hCatalog, CRYPTCATMEMBER *prev)
{
    struct cryptcat *cc = hCatalog;
    DWORD i = 0;

    TRACE("%p, %p\n", hCatalog, prev);

    if (!is_valid_cat(hCatalog))
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return NULL;
    }
    if (prev)
    {
        while (i < cc->member_count && &cc->members[i]->member != prev) i++;
        if (i == cc->member_count)
        {
            SetLastError(ERROR_INVALID_PARAMETER);
            return NULL;
        }
        i++;
    }
    if (i >= cc->member_count)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return NULL;
    }
    SetLastError(ERROR_SUCCESS);
    return &cc->members[i]->member;
}

/* ---------------------------------------------------------------- writing */

/***********************************************************************
 *      CryptCATPutCatAttrInfo  (WINTRUST.@)
 */
CRYPTCATATTRIBUTE * WINAPI CryptCATPutCatAttrInfo(HANDLE catalog,
        WCHAR *name, DWORD flags, DWORD size, BYTE *data)
{
    struct cryptcat *cc = catalog;
    struct catattr *a;

    TRACE("catalog %p, name %s, flags %#lx, size %lu, data %p\n", catalog, debugstr_w(name), flags, size, data);

    if (!is_valid_cat(catalog) || !name || (size && !data))
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return NULL;
    }
    if (!(a = alloc_attr(name, flags, data, size)) ||
        !cat_add_attr(&cc->attrs, &cc->attr_cap, &cc->attr_count, a))
    {
        free_attr(a);
        SetLastError(ERROR_OUTOFMEMORY);
        return NULL;
    }
    SetLastError(ERROR_SUCCESS);
    return &a->attr;
}

/***********************************************************************
 *      CryptCATPutAttrInfo  (WINTRUST.@)
 */
CRYPTCATATTRIBUTE * WINAPI CryptCATPutAttrInfo(HANDLE catalog, CRYPTCATMEMBER *member,
        WCHAR *name, DWORD flags, DWORD size, BYTE *data)
{
    struct cryptcat *cc = catalog;
    struct catmember *m;
    struct catattr *a;

    TRACE("catalog %p, member %p, name %s, flags %#lx, size %lu, data %p\n",
          catalog, member, debugstr_w(name), flags, size, data);

    if (!is_valid_cat(catalog) || !member || !name || (size && !data) || !(m = member_from_ptr(cc, member)))
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return NULL;
    }
    if (!(a = alloc_attr(name, flags, data, size)) ||
        !cat_add_attr(&m->attrs, &m->attr_cap, &m->attr_count, a))
    {
        free_attr(a);
        SetLastError(ERROR_OUTOFMEMORY);
        return NULL;
    }
    SetLastError(ERROR_SUCCESS);
    return &a->attr;
}

/***********************************************************************
 *      CryptCATPutMemberInfo  (WINTRUST.@)
 */
CRYPTCATMEMBER * WINAPI CryptCATPutMemberInfo(HANDLE catalog, WCHAR *filename,
        WCHAR *member, GUID *subject, DWORD version, DWORD size, BYTE *data)
{
    struct cryptcat *cc = catalog;
    struct catmember *m;

    TRACE("catalog %p, filename %s, member %s, subject %s, version %lu, size %lu, data %p\n",
          catalog, debugstr_w(filename), debugstr_w(member), debugstr_guid(subject), version, size, data);

    if (!is_valid_cat(catalog) || !member || !subject || size < sizeof(SIP_INDIRECT_DATA) || !data)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return NULL;
    }
    if (!(m = calloc(1, sizeof(*m)))) goto nomem;

    m->member.cbStruct = sizeof(m->member);
    m->member.gSubjectType = *subject;
    m->member.dwCertVersion = version;
    m->has_indirect = TRUE;
    m->member.sEncodedIndirectData.pbData = encode_indirect_data((const SIP_INDIRECT_DATA *)data,
                                                                 &m->member.sEncodedIndirectData.cbData);
    if (!m->member.sEncodedIndirectData.pbData)
    {
        free_member(m);
        SetLastError(ERROR_INVALID_PARAMETER);
        return NULL;
    }
    m->member.pwszReferenceTag = strdupW_(member);
    if (filename) m->member.pwszFileName = strdupW_(filename);
    m->member.pIndirectData = decode_object(cc->encoding, SPC_INDIRECT_DATA_OBJID,
                                            m->member.sEncodedIndirectData.pbData,
                                            m->member.sEncodedIndirectData.cbData);
    if (!m->member.pwszReferenceTag || (filename && !m->member.pwszFileName)) goto nomem;
    if (!m->member.pIndirectData)
    {
        free_member(m);
        return NULL;
    }

    if (cc->version == CRYPTCAT_VERSION_2)
    {
        m->id_len = m->member.pIndirectData->Digest.cbData;
        m->id = copy_bytes(m->member.pIndirectData->Digest.pbData, m->id_len);
        if (!m->id) goto nomem;

        /* version 2 catalogs also list the SHA-1 hash of the file */
        if (filename && m->id_len != 20)
        {
            HANDLE file = CreateFileW(filename, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                                      OPEN_EXISTING, 0, NULL);
            if (file != INVALID_HANDLE_VALUE)
            {
                DWORD len = sizeof(m->compat_id);
                m->has_compat = WINTRUST_CalcFileDigest(file, CALG_SHA1, &len, m->compat_id, NULL) && len == 20;
                CloseHandle(file);
            }
        }
    }
    else
    {
        m->id_len = (lstrlenW(member) + 1) * sizeof(WCHAR);
        m->id = malloc(m->id_len);
        if (!m->id) goto nomem;
        memcpy(m->id, member, m->id_len);
    }

    if (!grow_array((void **)&cc->members, &cc->member_cap, cc->member_count, sizeof(*cc->members))) goto nomem;
    cc->members[cc->member_count++] = m;
    SetLastError(ERROR_SUCCESS);
    return &m->member;

nomem:
    free_member(m);
    SetLastError(ERROR_OUTOFMEMORY);
    return NULL;
}

struct entry_blob
{
    BYTE *id;           /* subject identifier */
    DWORD id_len;
    struct der_buf der; /* complete TrustedSubject */
};

static int cmp_entries(const void *a, const void *b)
{
    const struct entry_blob *x = a, *y = b;
    DWORD n = min(x->id_len, y->id_len);
    int r = memcmp(x->id, y->id, n);

    if (r) return r;
    return (x->id_len > y->id_len) - (x->id_len < y->id_len);
}

static void encode_entry(struct cryptcat *cc, struct catmember *m, BOOL compat, struct entry_blob *out)
{
    struct der_buf seq = {0}, attrs = {0}, set = {0};
    struct der_buf *blobs;
    DWORD i, count, n = 0;
    BYTE *enc;
    DWORD enc_len;
    const BYTE *id = compat ? m->compat_id : m->id;
    DWORD id_len = compat ? sizeof(m->compat_id) : m->id_len;

    out->id = copy_bytes(id, id_len);
    out->id_len = id_len;
    memset(&out->der, 0, sizeof(out->der));

    blobs = calloc(m->attr_count + 3, sizeof(*blobs));
    if (!blobs || !out->id) { out->der.failed = TRUE; free(blobs); return; }

    if (cc->version == CRYPTCAT_VERSION_2)
    {
        BYTE choice[2] = {0x80, 0x00};

        if (!IsEqualGUID(&m->member.gSubjectType, &subject_pe)) choice[0] = 0x82;
        der_attribute(&blobs[n], oid_memberinfo2, sizeof(oid_memberinfo2), choice, 2);
        n++;
    }
    for (i = 0; i < m->attr_count; i++)
    {
        if (!(enc = encode_namevalue(&m->attrs[i]->attr, &enc_len))) { out->der.failed = TRUE; break; }
        der_attribute(&blobs[n++], oid_namevalue, sizeof(oid_namevalue), enc, enc_len);
        free(enc);
    }
    if (!compat && m->member.sEncodedIndirectData.cbData)
    {
        der_attribute(&blobs[n++], oid_indirect, sizeof(oid_indirect), m->member.sEncodedIndirectData.pbData,
                      m->member.sEncodedIndirectData.cbData);
    }
    if (cc->version != CRYPTCAT_VERSION_2)
    {
        if (!(enc = encode_memberinfo(&m->member.gSubjectType, m->member.dwCertVersion, &enc_len)))
            out->der.failed = TRUE;
        else
        {
            der_attribute(&blobs[n++], oid_memberinfo, sizeof(oid_memberinfo), enc, enc_len);
            free(enc);
        }
    }
    count = n;

    /* SET OF is sorted by encoding */
    qsort(blobs, count, sizeof(*blobs), cmp_blob);
    for (i = 0; i < count; i++)
    {
        der_append(&attrs, blobs[i].data, blobs[i].len);
        free(blobs[i].data);
    }
    free(blobs);

    der_append_tlv(&seq, 0x04, id, id_len);
    der_wrap(&set, 0x31, &attrs);
    der_append(&seq, set.data, set.len);
    free(set.data);
    if (attrs.failed || seq.failed) out->der.failed = TRUE;
    der_wrap(&out->der, 0x30, &seq);
}

static BYTE *build_catalog(struct cryptcat *cc, DWORD *out_len)
{
    struct der_buf ctl = {0}, subjects = {0}, exts = {0}, out = {0};
    struct entry_blob *entries = NULL;
    DWORD i, n = 0;
    BYTE list_id[16];
    BYTE *result = NULL;

    if (!(entries = calloc(cc->member_count * 2 + 1, sizeof(*entries)))) return NULL;
    for (i = 0; i < cc->member_count; i++)
    {
        struct catmember *m = cc->members[i];

        encode_entry(cc, m, FALSE, &entries[n++]);
        if (m->has_compat) encode_entry(cc, m, TRUE, &entries[n++]);
    }
    qsort(entries, n, sizeof(*entries), cmp_entries);

    for (i = 0; i < n; i++)
    {
        der_append(&subjects, entries[i].der.data, entries[i].der.len);
        if (entries[i].der.failed) subjects.failed = TRUE;
        free(entries[i].der.data);
        free(entries[i].id);
    }
    free(entries);

    {
        HCRYPTPROV prov;

        memset(list_id, 0, sizeof(list_id));
        if (CryptAcquireContextW(&prov, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
        {
            /* a catalog with a list identifier that is not random is not written */
            if (!CryptGenRandom(prov, sizeof(list_id), list_id)) out.failed = TRUE;
            CryptReleaseContext(prov, 0);
        }
        else out.failed = TRUE;
    }

    /* subject usage */
    {
        struct der_buf usage = {0}, alg = {0};

        der_append_tlv(&usage, 0x06, oid_cat_list, sizeof(oid_cat_list));
        der_wrap(&ctl, 0x30, &usage);
        der_append_tlv(&ctl, 0x04, list_id, sizeof(list_id));
        der_utctime(&ctl);
        der_append_tlv(&alg, 0x06, cc->version == CRYPTCAT_VERSION_2 ? oid_cat_member_v2 : oid_cat_member_v1,
                       sizeof(oid_cat_member_v2));
        der_append_tlv(&alg, 0x05, NULL, 0);
        der_wrap(&ctl, 0x30, &alg);
    }
    der_wrap(&ctl, 0x30, &subjects);

    /* catalog attributes are extensions, in reverse order */
    for (i = cc->attr_count; i > 0; i--)
    {
        struct der_buf ext = {0};
        DWORD len;
        BYTE *enc = encode_namevalue(&cc->attrs[i - 1]->attr, &len);

        if (!enc) { exts.failed = TRUE; break; }
        der_append_tlv(&ext, 0x06, oid_namevalue, sizeof(oid_namevalue));
        der_append_tlv(&ext, 0x04, enc, len);
        free(enc);
        der_wrap(&exts, 0x30, &ext);
    }
    if (cc->attr_count)
    {
        struct der_buf wrapped = {0};

        der_wrap(&wrapped, 0x30, &exts);
        der_wrap(&ctl, 0xa0, &wrapped);
    }
    else free(exts.data);

    /* ctl now holds the fields of the CTL; wrap it up */
    {
        struct der_buf ctl_seq = {0}, content = {0}, inner = {0}, signed_data = {0}, explicit_ctl = {0};

        der_wrap(&ctl_seq, 0x30, &ctl);
        der_append_tlv(&inner, 0x06, oid_ctl, sizeof(oid_ctl));
        der_wrap(&explicit_ctl, 0xa0, &ctl_seq);
        der_append(&inner, explicit_ctl.data, explicit_ctl.len);
        free(explicit_ctl.data);

        der_integer(&content, 1);
        der_append_tlv(&content, 0x31, NULL, 0);
        der_wrap(&content, 0x30, &inner);
        der_append_tlv(&content, 0x31, NULL, 0);
        der_wrap(&signed_data, 0x30, &content);

        der_append_tlv(&out, 0x06, oid_signed_data, sizeof(oid_signed_data));
        {
            struct der_buf ex = {0};

            der_wrap(&ex, 0xa0, &signed_data);
            der_append(&out, ex.data, ex.len);
            free(ex.data);
        }
        {
            struct der_buf top = {0};

            der_wrap(&top, 0x30, &out);
            out = top;
        }
    }

    if (!out.failed)
    {
        result = out.data;
        *out_len = out.len;
    }
    else free(out.data);
    return result;
}

/***********************************************************************
 *      CryptCATPersistStore  (WINTRUST.@)
 */
BOOL WINAPI CryptCATPersistStore(HANDLE catalog)
{
    struct cryptcat *cc = catalog;
    BYTE *data;
    DWORD len, written;
    HANDLE file;
    BOOL ret;

    TRACE("catalog %p\n", catalog);

    if (!is_valid_cat(catalog))
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    if (!(data = build_catalog(cc, &len)))
    {
        if (GetLastError() == ERROR_SUCCESS) SetLastError(ERROR_OUTOFMEMORY);
        return FALSE;
    }
    file = CreateFileW(cc->filename, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE)
    {
        free(data);
        return FALSE;
    }
    ret = WriteFile(file, data, len, &written, NULL) && written == len;
    if (!ret && GetLastError() == ERROR_SUCCESS) SetLastError(ERROR_WRITE_FAULT);
    free(data);
    if (!CloseHandle(file)) ret = FALSE;
    if (ret) SetLastError(ERROR_SUCCESS);
    return ret;
}

/* ---------------------------------------------------------------- CDF */

struct cdf_attr
{
    WCHAR *key;
    DWORD flags;
    WCHAR *name;
    WCHAR *value;
    BOOL bad;
};

struct cdf_member
{
    WCHAR *tag;
    WCHAR *path;
    struct cdf_attr *attrs;
    DWORD attr_count, attr_cap;
    DWORD attr_next;
    struct catmember *put;
};

struct hash_info
{
    ALG_ID alg;
    const char *oid;
};

static const struct hash_info hash_md5 = {CALG_MD5, "1.2.840.113549.2.5"};
static const struct hash_info hash_sha1 = {CALG_SHA1, "1.3.14.3.2.26"};
static const struct hash_info hash_sha256 = {CALG_SHA_256, "2.16.840.1.101.3.4.2.1"};
static const struct hash_info hash_sha384 = {CALG_SHA_384, "2.16.840.1.101.3.4.2.2"};
static const struct hash_info hash_sha512 = {CALG_SHA_512, "2.16.840.1.101.3.4.2.3"};

struct cdf
{
    CRYPTCATCDF pub; /* must be first */
    DWORD magic;
    HANDLE cat;
    const struct hash_info *hash;
    struct cdf_attr *attrs;
    DWORD attr_count, attr_cap;
    DWORD attr_next;
    struct cdf_member *members;
    DWORD member_count, member_cap;
    DWORD member_next;
    WCHAR *dir;
};

static void free_cdf_attrs(struct cdf_attr *attrs, DWORD count)
{
    DWORD i;

    for (i = 0; i < count; i++)
    {
        free(attrs[i].key);
        free(attrs[i].name);
        free(attrs[i].value);
    }
    free(attrs);
}

static void free_cdf(struct cdf *cdf)
{
    DWORD i;

    free_cdf_attrs(cdf->attrs, cdf->attr_count);
    for (i = 0; i < cdf->member_count; i++)
    {
        free(cdf->members[i].tag);
        free(cdf->members[i].path);
        free_cdf_attrs(cdf->members[i].attrs, cdf->members[i].attr_count);
    }
    free(cdf->members);
    free(cdf->pub.pwszResultDir);
    free(cdf->dir);
    free(cdf);
}

static WCHAR *trim_span(WCHAR *start, WCHAR *end)
{
    while (start < end && (*start == ' ' || *start == '\t')) start++;
    while (end > start && (end[-1] == ' ' || end[-1] == '\t')) end--;
    *end = 0;
    return start;
}

static WCHAR *cdf_decode_text(const BYTE *data, DWORD size)
{
    WCHAR *text;
    int len;

    if (size >= 2 && data[0] == 0xff && data[1] == 0xfe)
    {
        len = (size - 2) / sizeof(WCHAR);
        if (!(text = malloc((len + 1) * sizeof(WCHAR)))) return NULL;
        memcpy(text, data + 2, len * sizeof(WCHAR));
        text[len] = 0;
        return text;
    }
    if (size >= 3 && data[0] == 0xef && data[1] == 0xbb && data[2] == 0xbf)
    {
        data += 3;
        size -= 3;
    }
    len = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, (const char *)data, size, NULL, 0);
    if (len || !size)
    {
        if (!(text = malloc((len + 1) * sizeof(WCHAR)))) return NULL;
        if (len) MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, (const char *)data, size, text, len);
        text[len] = 0;
        return text;
    }
    len = MultiByteToWideChar(CP_ACP, 0, (const char *)data, size, NULL, 0);
    if (!(text = malloc((len + 1) * sizeof(WCHAR)))) return NULL;
    MultiByteToWideChar(CP_ACP, 0, (const char *)data, size, text, len);
    text[len] = 0;
    return text;
}

static BOOL cdf_parse_attr(const WCHAR *value, struct cdf_attr *attr)
{
    const WCHAR *p1, *p2;
    WCHAR *end;

    memset(attr, 0, sizeof(*attr));
    if (!(p1 = wcschr(value, ':')) || !(p2 = wcschr(p1 + 1, ':')))
    {
        attr->bad = TRUE;
        return TRUE;
    }
    attr->flags = wcstoul(value, &end, 0);
    if (!(attr->name = malloc((p2 - p1) * sizeof(WCHAR)))) return FALSE;
    memcpy(attr->name, p1 + 1, (p2 - p1 - 1) * sizeof(WCHAR));
    attr->name[p2 - p1 - 1] = 0;
    if (!(attr->value = strdupW_(p2 + 1))) return FALSE;
    return TRUE;
}

static BOOL cdf_add_attr(struct cdf_attr **list, DWORD *cap, DWORD *count, const WCHAR *key, const WCHAR *value)
{
    struct cdf_attr attr;
    DWORD i;

    /* the first attribute with a given key wins */
    for (i = 0; i < *count; i++)
        if (!wcsicmp((*list)[i].key, key)) return TRUE;

    if (!cdf_parse_attr(value, &attr)) return FALSE;
    attr.key = strdupW_(key);
    if (!attr.key || !grow_array((void **)list, cap, *count, sizeof(**list)))
    {
        free(attr.key);
        free(attr.name);
        free(attr.value);
        return FALSE;
    }
    (*list)[(*count)++] = attr;
    return TRUE;
}

static BOOL starts_with_nocase(const WCHAR *s, const WCHAR *prefix, SIZE_T len)
{
    return !wcsnicmp(s, prefix, len);
}

/* find the member that owns a "<tag>ATTR<n>" key */
static struct cdf_member *cdf_find_attr_owner(struct cdf *cdf, const WCHAR *key)
{
    DWORD i;
    struct cdf_member *best = NULL;
    SIZE_T best_len = 0;

    for (i = 0; i < cdf->member_count; i++)
    {
        SIZE_T len = lstrlenW(cdf->members[i].tag);
        const WCHAR *rest;

        if (len <= best_len || !starts_with_nocase(key, cdf->members[i].tag, len)) continue;
        rest = key + len;
        if (wcsnicmp(rest, L"ATTR", 4) || !rest[4]) continue;
        for (rest += 4; *rest; rest++) if (*rest < '0' || *rest > '9') break;
        if (*rest) continue;
        best = &cdf->members[i];
        best_len = len;
    }
    return best;
}

static const struct hash_info *hash_from_name(const WCHAR *name)
{
    if (!wcsnicmp(name, L"SHA256", 6)) return &hash_sha256;
    if (!wcsnicmp(name, L"SHA384", 6)) return &hash_sha384;
    if (!wcsnicmp(name, L"SHA512", 6)) return &hash_sha512;
    if (!wcsnicmp(name, L"MD5", 3)) return &hash_md5;
    return &hash_sha1;
}

static BOOL cdf_parse(struct cdf *cdf, WCHAR *text, BOOL *have_header, WCHAR **name, DWORD *version,
                      DWORD *encoding, WCHAR **result_dir)
{
    WCHAR *p = text, *line_end;
    int section = 0; /* 1 header, 2 files, -1 other */

    *have_header = FALSE;
    *name = NULL;
    *version = CRYPTCAT_VERSION_1;
    *encoding = 0;
    *result_dir = NULL;

    while (*p)
    {
        WCHAR *start = p, *key, *eq, *value;

        while (*p && *p != '\r' && *p != '\n') p++;
        line_end = p;
        if (*p == '\r' && p[1] == '\n') p += 2;
        else if (*p) p++;

        key = trim_span(start, line_end);
        if (!*key || *key == ';') continue;
        if (*key == '[')
        {
            WCHAR *close = wcschr(key, ']');

            if (close) *close = 0;
            if (!wcsicmp(key + 1, L"CatalogHeader")) { section = 1; *have_header = TRUE; }
            else if (!wcsicmp(key + 1, L"CatalogFiles")) section = 2;
            else section = -1;
            continue;
        }
        eq = wcschr(key, '=');
        if (!eq) continue;
        value = trim_span(eq + 1, eq + 1 + lstrlenW(eq + 1));
        trim_span(key, eq);

        if (section == 1)
        {
            if (!wcsicmp(key, L"Name")) { free(*name); *name = strdupW_(value); }
            else if (!wcsicmp(key, L"ResultDir")) { free(*result_dir); *result_dir = strdupW_(value); }
            else if (!wcsicmp(key, L"PublicVersion"))
            {
                DWORD v = wcstoul(value, NULL, 0);
                if (v == 2 || v == 0x200) *version = CRYPTCAT_VERSION_2;
                else *version = CRYPTCAT_VERSION_1;
            }
            else if (!wcsicmp(key, L"CatalogVersion"))
            {
                DWORD v = wcstoul(value, NULL, 0);
                if (v == 2 || v == 0x200) *version = CRYPTCAT_VERSION_2;
                else if (v == 1 || v == 0x100) *version = CRYPTCAT_VERSION_1;
            }
            else if (!wcsicmp(key, L"EncodingType"))
            {
                if (*value) *encoding = wcstoul(value, NULL, 0);
            }
            else if (!wcsicmp(key, L"HashAlgorithms"))
                cdf->hash = hash_from_name(value);
            else if (!wcsnicmp(key, L"CATATTR", 7) && key[7])
            {
                if (!cdf_add_attr(&cdf->attrs, &cdf->attr_cap, &cdf->attr_count, key, value)) return FALSE;
            }
        }
        else if (section == 2)
        {
            struct cdf_member *owner = cdf_find_attr_owner(cdf, key);

            if (owner)
            {
                if (!cdf_add_attr(&owner->attrs, &owner->attr_cap, &owner->attr_count, key, value)) return FALSE;
                continue;
            }
            {
                DWORD i;
                BOOL dup = FALSE;

                for (i = 0; i < cdf->member_count; i++)
                    if (!lstrcmpW(cdf->members[i].tag, key)) { dup = TRUE; break; }
                if (dup) continue;
            }
            if (!grow_array((void **)&cdf->members, &cdf->member_cap, cdf->member_count, sizeof(*cdf->members)))
                return FALSE;
            {
                struct cdf_member *member = &cdf->members[cdf->member_count++];

                memset(member, 0, sizeof(*member));
                member->tag = strdupW_(key);
                member->path = strdupW_(value);
                if (!member->tag || !member->path) return FALSE;
            }
        }
    }
    return TRUE;
}

/***********************************************************************
 *      CryptCATCDFOpen  (WINTRUST.@)
 */
CRYPTCATCDF * WINAPI CryptCATCDFOpen(LPWSTR pwszFilePath, PFN_CDF_PARSE_ERROR_CALLBACK pfnParseError)
{
    HANDLE file;
    DWORD size, read_size, version, encoding;
    BYTE *raw;
    WCHAR *text, *name, *result_dir, *path = NULL;
    BOOL have_header;
    struct cdf *cdf;

    TRACE("(%s %p)\n", debugstr_w(pwszFilePath), pfnParseError);

    if (!pwszFilePath)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return NULL;
    }

    file = CreateFileW(pwszFilePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (file == INVALID_HANDLE_VALUE) return NULL;
    size = GetFileSize(file, NULL);
    if (size == INVALID_FILE_SIZE || !(raw = malloc(size ? size : 1)))
    {
        CloseHandle(file);
        SetLastError(ERROR_OUTOFMEMORY);
        return NULL;
    }
    if (!ReadFile(file, raw, size, &read_size, NULL))
    {
        DWORD err = GetLastError();
        free(raw);
        CloseHandle(file);
        SetLastError(err);
        return NULL;
    }
    CloseHandle(file);
    text = cdf_decode_text(raw, read_size);
    free(raw);
    if (!text)
    {
        SetLastError(ERROR_OUTOFMEMORY);
        return NULL;
    }

    if (!(cdf = calloc(1, sizeof(*cdf))))
    {
        free(text);
        SetLastError(ERROR_OUTOFMEMORY);
        return NULL;
    }
    cdf->hash = &hash_sha1;

    if (!cdf_parse(cdf, text, &have_header, &name, &version, &encoding, &result_dir))
    {
        free(text);
        free(name);
        free(result_dir);
        free_cdf(cdf);
        SetLastError(ERROR_OUTOFMEMORY);
        return NULL;
    }
    free(text);

    if (!have_header)
    {
        if (pfnParseError) pfnParseError(CRYPTCAT_E_AREA_HEADER, CRYPTCAT_E_CDF_TAGNOTFOUND, NULL);
        free(name);
        free(result_dir);
        free_cdf(cdf);
        SetLastError(ERROR_SUCCESS);
        return NULL;
    }
    if (!name || !*name)
    {
        free(name);
        free(result_dir);
        free_cdf(cdf);
        SetLastError(ERROR_SHARING_VIOLATION);
        return NULL;
    }

    /* the catalog goes into the result directory unless the name is a full path */
    if (result_dir && *result_dir && !(name[0] && name[1] == ':') && !(name[0] == '\\' && name[1] == '\\'))
    {
        SIZE_T dir_len = lstrlenW(result_dir), name_len = lstrlenW(name);
        BOOL slash = result_dir[dir_len - 1] != '\\' && result_dir[dir_len - 1] != '/';

        if ((path = malloc((dir_len + name_len + 2) * sizeof(WCHAR))))
        {
            lstrcpyW(path, result_dir);
            if (slash) lstrcatW(path, L"\\");
            lstrcatW(path, name);
        }
    }
    else path = strdupW_(name);
    cdf->pub.pwszResultDir = result_dir;
    if (!path)
    {
        free(name);
        free_cdf(cdf);
        SetLastError(ERROR_OUTOFMEMORY);
        return NULL;
    }

    cdf->cat = CryptCATOpen(path, CRYPTCAT_OPEN_CREATENEW, 0, version, encoding);
    free(path);
    free(name);
    if (cdf->cat == INVALID_HANDLE_VALUE)
    {
        DWORD err = GetLastError();

        free_cdf(cdf);
        SetLastError(err);
        return NULL;
    }

    cdf->pub.cbStruct = sizeof(cdf->pub);
    cdf->pub.hCATStore = cdf->cat;
    cdf->magic = CDF_MAGIC;
    SetLastError(ERROR_SUCCESS);
    return &cdf->pub;
}

static BOOL is_valid_cdf(CRYPTCATCDF *pub)
{
    struct cdf *cdf = (struct cdf *)pub;

    return pub && cdf->magic == CDF_MAGIC;
}

/***********************************************************************
 *      CryptCATCDFClose  (WINTRUST.@)
 */
BOOL WINAPI CryptCATCDFClose(CRYPTCATCDF *pCDF)
{
    struct cdf *cdf = (struct cdf *)pCDF;
    BOOL ret;
    DWORD err;

    TRACE("(%p)\n", pCDF);

    if (!is_valid_cdf(pCDF))
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    ret = CryptCATPersistStore(cdf->cat);
    err = GetLastError();
    CryptCATClose(cdf->cat);
    cdf->magic = 0;
    free_cdf(cdf);
    SetLastError(ret ? ERROR_SUCCESS : err);
    return ret;
}

static WCHAR *ascii_value_to_bytes(const WCHAR *value, DWORD *size)
{
    /* the value of an attribute is stored as a null terminated Unicode string */
    WCHAR *ret = strdupW_(value);

    if (ret) *size = (lstrlenW(ret) + 1) * sizeof(WCHAR);
    return ret;
}

/***********************************************************************
 *      CryptCATCDFEnumCatAttributes  (WINTRUST.@)
 */
CRYPTCATATTRIBUTE * WINAPI CryptCATCDFEnumCatAttributes(CRYPTCATCDF *pCDF, CRYPTCATATTRIBUTE *pPrevAttr,
                                                        PFN_CDF_PARSE_ERROR_CALLBACK pfnParseError)
{
    struct cdf *cdf = (struct cdf *)pCDF;

    TRACE("(%p %p %p)\n", pCDF, pPrevAttr, pfnParseError);

    if (!is_valid_cdf(pCDF))
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return NULL;
    }
    if (!pPrevAttr) cdf->attr_next = 0;

    while (cdf->attr_next < cdf->attr_count)
    {
        struct cdf_attr *a = &cdf->attrs[cdf->attr_next++];
        CRYPTCATATTRIBUTE *ret;
        WCHAR *value;
        DWORD size;

        if (a->bad)
        {
            if (pfnParseError) pfnParseError(CRYPTCAT_E_AREA_ATTRIBUTE, CRYPTCAT_E_CDF_ATTR_TOOFEWVALUES, NULL);
            continue;
        }
        if (!(value = ascii_value_to_bytes(a->value, &size)))
        {
            SetLastError(ERROR_OUTOFMEMORY);
            return NULL;
        }
        ret = CryptCATPutCatAttrInfo(cdf->cat, a->name, a->flags, size, (BYTE *)value);
        free(value);
        if (ret) SetLastError(ERROR_SUCCESS);
        return ret;
    }
    SetLastError(ERROR_SUCCESS);
    return NULL;
}

static BOOL cdf_put_member(struct cdf *cdf, struct cdf_member *m, PFN_CDF_PARSE_ERROR_CALLBACK cb)
{
    HANDLE file;
    BYTE digest[64];
    DWORD digest_len = sizeof(digest);
    BOOL pe = FALSE;
    GUID subject;
    WCHAR *ref_tag;
    SIP_INDIRECT_DATA indirect = {{0}};
    const BYTE *value;
    DWORD value_len;
    CRYPTCATMEMBER *member;

    file = CreateFileW(m->path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (file == INVALID_HANDLE_VALUE)
    {
        if (cb) cb(CRYPTCAT_E_AREA_MEMBER, CRYPTCAT_E_CDF_MEMBER_FILENOTFOUND, m->tag);
        return FALSE;
    }
    if (!WINTRUST_CalcFileDigest(file, cdf->hash->alg, &digest_len, digest, &pe))
    {
        CloseHandle(file);
        if (cb) cb(CRYPTCAT_E_AREA_MEMBER, CRYPTCAT_E_CDF_MEMBER_FILENOTFOUND, m->tag);
        return FALSE;
    }
    CloseHandle(file);

    subject = pe ? subject_pe : subject_flat;
    value = pe ? pe_image_value : flat_value;
    value_len = pe ? sizeof(pe_image_value) : sizeof(flat_value);

    {
        static BYTE null_params[] = {0x05, 0x00};

        indirect.Data.pszObjId = (char *)(pe ? SPC_PE_IMAGE_DATA_OBJID : SPC_CAB_DATA_OBJID);
        indirect.Data.Value.cbData = value_len;
        indirect.Data.Value.pbData = (BYTE *)value;
        indirect.DigestAlgorithm.pszObjId = (char *)cdf->hash->oid;
        indirect.DigestAlgorithm.Parameters.cbData = sizeof(null_params);
        indirect.DigestAlgorithm.Parameters.pbData = null_params;
        indirect.Digest.cbData = digest_len;
        indirect.Digest.pbData = digest;
    }

    if (!wcsnicmp(m->tag, L"<HASH>", 6)) ref_tag = hex_tag(digest, digest_len);
    else ref_tag = strdupW_(m->tag);
    if (!ref_tag)
    {
        SetLastError(ERROR_OUTOFMEMORY);
        return FALSE;
    }

    member = CryptCATPutMemberInfo(cdf->cat, m->path, ref_tag, &subject, 0x200, sizeof(indirect), (BYTE *)&indirect);
    free(ref_tag);
    if (!member) return FALSE;
    m->put = (struct catmember *)member;
    return TRUE;
}

/***********************************************************************
 *      CryptCATCDFEnumMembersByCDFTagEx  (WINTRUST.@)
 */
LPWSTR WINAPI CryptCATCDFEnumMembersByCDFTagEx(CRYPTCATCDF *pCDF, LPWSTR pwszPrevCDFTag,
                                               PFN_CDF_PARSE_ERROR_CALLBACK pfnParseError,
                                               CRYPTCATMEMBER **ppMember, BOOL fContinueOnError,
                                               LPVOID pvReserved)
{
    struct cdf *cdf = (struct cdf *)pCDF;

    TRACE("(%p %s %p %p %d %p)\n", pCDF, debugstr_w(pwszPrevCDFTag), pfnParseError, ppMember,
          fContinueOnError, pvReserved);

    if (!is_valid_cdf(pCDF) || !ppMember)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return NULL;
    }
    if (!pwszPrevCDFTag) cdf->member_next = 0;

    while (cdf->member_next < cdf->member_count)
    {
        struct cdf_member *m = &cdf->members[cdf->member_next++];

        if (cdf_put_member(cdf, m, pfnParseError))
        {
            *ppMember = &m->put->member;
            SetLastError(ERROR_SUCCESS);
            return m->tag;
        }
        if (!fContinueOnError)
        {
            *ppMember = NULL;
            return NULL;
        }
    }
    *ppMember = NULL;
    SetLastError(ERROR_SUCCESS);
    return NULL;
}

/***********************************************************************
 *      CryptCATCDFEnumAttributesWithCDFTag  (WINTRUST.@)
 */
CRYPTCATATTRIBUTE * WINAPI CryptCATCDFEnumAttributesWithCDFTag(CRYPTCATCDF *pCDF, LPWSTR pwszMemberTag,
                                                               CRYPTCATMEMBER *pMember,
                                                               CRYPTCATATTRIBUTE *pPrevAttr,
                                                               PFN_CDF_PARSE_ERROR_CALLBACK pfnParseError)
{
    struct cdf *cdf = (struct cdf *)pCDF;
    struct cdf_member *m = NULL;
    DWORD i;

    TRACE("(%p %s %p %p %p)\n", pCDF, debugstr_w(pwszMemberTag), pMember, pPrevAttr, pfnParseError);

    if (!is_valid_cdf(pCDF) || !pwszMemberTag || !pMember)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return NULL;
    }
    for (i = 0; i < cdf->member_count; i++)
    {
        if (!lstrcmpW(cdf->members[i].tag, pwszMemberTag)) { m = &cdf->members[i]; break; }
    }
    if (!m)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return NULL;
    }
    if (!pPrevAttr) m->attr_next = 0;

    while (m->attr_next < m->attr_count)
    {
        struct cdf_attr *a = &m->attrs[m->attr_next++];
        CRYPTCATATTRIBUTE *ret;
        WCHAR *value;
        DWORD size;

        if (a->bad)
        {
            if (pfnParseError) pfnParseError(CRYPTCAT_E_AREA_ATTRIBUTE, CRYPTCAT_E_CDF_ATTR_TOOFEWVALUES, NULL);
            continue;
        }
        if (!(value = ascii_value_to_bytes(a->value, &size)))
        {
            SetLastError(ERROR_OUTOFMEMORY);
            return NULL;
        }
        ret = CryptCATPutAttrInfo(cdf->cat, pMember, a->name, a->flags, size, (BYTE *)value);
        free(value);
        if (ret) SetLastError(ERROR_SUCCESS);
        return ret;
    }
    SetLastError(ERROR_SUCCESS);
    return NULL;
}
