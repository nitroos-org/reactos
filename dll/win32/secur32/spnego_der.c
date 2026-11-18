/*
 * PROJECT:     ReactOS secur32
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     SPNEGO (RFC 4178, [MS-SPNG]) token codec: a bounded DER reader and writer
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Written from RFC 4178 (the ASN.1 module of section 4), RFC 2743 3.1 (the framing of the first token),
 * X.690 (DER) and [MS-SPNG] 2.2 (NegTokenInit2). Rules of this decoder, for the reviewer:
 *  - It reads only the two token shapes, field by field, with a fixed nesting (at most 5 levels): it never recurses and
 *    never follows a length it did not check. Deeply nested input is just an unexpected tag at the first level.
 *  - Lengths: definite form only (the indefinite form 0x80 is refused), at most 4 length bytes, and every content
 *    length is compared with what is left of the enclosing element (remaining = end - position, never a sum).
 *  - Tags: one-byte tags only (the high-tag-number form is refused); the fields of a SEQUENCE in ascending context
 *    tag order, each at most once; an element that must contain exactly one value may not carry trailing bytes.
 *  - The outer element may be followed by other data: the caller gets its length and decides (the Negotiate package
 *    follows what Windows was measured to do per leg).
 */

#include <string.h>
#include "spnego_der.h"

const spnego_byte spnego_oid_spnego[6] = { 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02 };
const spnego_byte spnego_oid_ntlm[10] = { 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a };

#define TAG_OID             0x06
#define TAG_OCTET_STRING    0x04
#define TAG_BIT_STRING      0x03
#define TAG_ENUMERATED      0x0a
#define TAG_SEQUENCE        0x30
#define TAG_APPLICATION_0   0x60
#define TAG_CONTEXT(n)      (0xa0 + (n))

int spnego_oid_is(const spnego_span *oid, const spnego_byte *want, spnego_u32 want_len)
{
    return oid->len == want_len && !memcmp(oid->data, want, want_len);
}

/* The header of the element at buf[*pos], within buf[0..end). On success *pos points behind the element.
 * short_ok: report SPNEGO_SHORT (instead of SPNEGO_BAD) when the element runs past end (outer elements only). */
static spnego_result read_element(const spnego_byte *buf, spnego_u32 end, spnego_u32 *pos, spnego_byte *tag,
                                  spnego_span *content, int short_ok)
{
    spnego_u32 p = *pos, remaining, n, clen, i, hdr;
    spnego_byte l0;

    if (p >= end) return short_ok ? SPNEGO_SHORT : SPNEGO_BAD;
    remaining = end - p;
    if (remaining < 2) return short_ok ? SPNEGO_SHORT : SPNEGO_BAD;
    *tag = buf[p];
    if ((*tag & 0x1f) == 0x1f) return SPNEGO_BAD;          /* high-tag-number form: never used by SPNEGO */
    l0 = buf[p + 1];
    if (l0 < 0x80)
    {
        clen = l0;
        hdr = 2;
    }
    else
    {
        n = l0 & 0x7f;
        if (n == 0 || n > 4) return SPNEGO_BAD;            /* indefinite form, or a length beyond 32 bits */
        if (remaining - 2 < n) return short_ok ? SPNEGO_SHORT : SPNEGO_BAD;
        clen = 0;
        for (i = 0; i < n; i++) clen = (clen << 8) | buf[p + 2 + i];
        hdr = 2 + n;
    }
    if (clen > SPNEGO_MAX_TOKEN) return SPNEGO_BAD;
    if (clen > remaining - hdr) return short_ok ? SPNEGO_SHORT : SPNEGO_BAD;
    content->data = buf + p + hdr;
    content->len = clen;
    *pos = p + hdr + clen;
    return SPNEGO_OK;
}

/* the content of an element that must hold exactly one element with the tag want */
static spnego_result read_single(const spnego_span *outer, spnego_byte want, spnego_span *inner, spnego_span *whole)
{
    spnego_u32 pos = 0;
    spnego_byte tag;

    if (read_element(outer->data, outer->len, &pos, &tag, inner, 0) != SPNEGO_OK) return SPNEGO_BAD;
    if (tag != want || pos != outer->len) return SPNEGO_BAD;
    if (whole)
    {
        whole->data = outer->data;
        whole->len = outer->len;
    }
    return SPNEGO_OK;
}

spnego_result spnego_outer_length(const spnego_byte *tok, spnego_u32 len, spnego_u32 *total)
{
    spnego_u32 n, clen, i, hdr;

    if (len < 2) return SPNEGO_SHORT;
    if ((tok[0] & 0x1f) == 0x1f) return SPNEGO_BAD;
    if (tok[1] < 0x80)
    {
        clen = tok[1];
        hdr = 2;
    }
    else
    {
        n = tok[1] & 0x7f;
        if (n == 0 || n > 4) return SPNEGO_BAD;
        if (len - 2 < n) return SPNEGO_SHORT;
        clen = 0;
        for (i = 0; i < n; i++) clen = (clen << 8) | tok[2 + i];
        hdr = 2 + n;
    }
    if (clen > SPNEGO_MAX_TOKEN - hdr) return SPNEGO_BAD;
    *total = hdr + clen;
    return SPNEGO_OK;
}

static spnego_result read_oid(const spnego_span *s, spnego_u32 *pos, spnego_span *oid);

spnego_result spnego_gss_mech(const spnego_byte *tok, spnego_u32 len, spnego_span *oid)
{
    spnego_span app;
    spnego_u32 pos = 0, p = 0;
    spnego_byte tag;

    if (read_element(tok, len, &pos, &tag, &app, 0) != SPNEGO_OK || tag != TAG_APPLICATION_0) return SPNEGO_BAD;
    if (read_oid(&app, &p, oid) != SPNEGO_OK) return SPNEGO_BAD;
    /* a complete OID: its last sub-identifier byte has no continuation bit */
    if (oid->data[oid->len - 1] & 0x80) return SPNEGO_BAD;
    return SPNEGO_OK;
}

static spnego_result read_oid(const spnego_span *s, spnego_u32 *pos, spnego_span *oid)
{
    spnego_byte tag;

    if (read_element(s->data, s->len, pos, &tag, oid, 0) != SPNEGO_OK) return SPNEGO_BAD;
    if (tag != TAG_OID || oid->len == 0 || oid->len > SPNEGO_MAX_OID) return SPNEGO_BAD;
    return SPNEGO_OK;
}

spnego_result spnego_decode_init(const spnego_byte *tok, spnego_u32 len, spnego_init *out, spnego_u32 *consumed)
{
    spnego_span app, choice, seq, field, inner, oid;
    spnego_u32 pos = 0, p, end;
    spnego_byte tag;
    int last = -1;
    spnego_result r;

    memset(out, 0, sizeof(*out));
    if (len > SPNEGO_MAX_TOKEN) return SPNEGO_BAD;

    /* [APPLICATION 0] IMPLICIT SEQUENCE { thisMech, innerContextToken } */
    r = read_element(tok, len, &pos, &tag, &app, 1);
    if (r != SPNEGO_OK) return r;
    if (tag != TAG_APPLICATION_0) return SPNEGO_BAD;
    *consumed = pos;

    p = 0;
    if (read_oid(&app, &p, &oid) != SPNEGO_OK) return SPNEGO_BAD;
    if (!spnego_oid_is(&oid, spnego_oid_spnego, sizeof(spnego_oid_spnego))) return SPNEGO_BAD;
    /* NegotiationToken: the [0] choice (negTokenInit), and nothing behind it */
    if (read_element(app.data, app.len, &p, &tag, &choice, 0) != SPNEGO_OK) return SPNEGO_BAD;
    if (tag != TAG_CONTEXT(0) || p != app.len) return SPNEGO_BAD;
    if (read_single(&choice, TAG_SEQUENCE, &seq, NULL) != SPNEGO_OK) return SPNEGO_BAD;

    /* NegTokenInit / NegTokenInit2: [0] mechTypes, [1] reqFlags, [2] mechToken,
     * [3] mechListMIC (NegTokenInit) or negHints (NegTokenInit2), [4] mechListMIC (NegTokenInit2) */
    p = 0;
    end = seq.len;
    while (p < end)
    {
        int n;

        if (read_element(seq.data, end, &p, &tag, &field, 0) != SPNEGO_OK) return SPNEGO_BAD;
        if (tag < TAG_CONTEXT(0) || tag > TAG_CONTEXT(4)) return SPNEGO_BAD;
        n = tag - TAG_CONTEXT(0);
        if (n <= last) return SPNEGO_BAD;
        last = n;
        switch (n)
        {
        case 0:
        {
            spnego_u32 q = 0;

            if (read_single(&field, TAG_SEQUENCE, &inner, &out->mech_list) != SPNEGO_OK) return SPNEGO_BAD;
            while (q < inner.len)
            {
                if (out->mech_count == SPNEGO_MAX_MECHS) return SPNEGO_BAD;
                if (read_oid(&inner, &q, &out->mechs[out->mech_count]) != SPNEGO_OK) return SPNEGO_BAD;
                out->mech_count++;
            }
            if (out->mech_count == 0) return SPNEGO_BAD;
            break;
        }
        case 1:
            if (read_single(&field, TAG_BIT_STRING, &inner, NULL) != SPNEGO_OK) return SPNEGO_BAD;
            out->has_req_flags = 1;
            break;
        case 2:
            if (read_single(&field, TAG_OCTET_STRING, &out->mech_token, NULL) != SPNEGO_OK) return SPNEGO_BAD;
            out->has_mech_token = 1;
            break;
        case 3:
            if (read_single(&field, TAG_OCTET_STRING, &out->mic, NULL) == SPNEGO_OK)
                out->has_mic = 1;
            else if (read_single(&field, TAG_SEQUENCE, &inner, NULL) == SPNEGO_OK)
                out->has_neg_hints = 1;
            else
                return SPNEGO_BAD;
            break;
        case 4:
            if (out->has_mic) return SPNEGO_BAD;
            if (read_single(&field, TAG_OCTET_STRING, &out->mic, NULL) != SPNEGO_OK) return SPNEGO_BAD;
            out->has_mic = 1;
            break;
        }
    }
    if (!out->mech_count) return SPNEGO_BAD;
    return SPNEGO_OK;
}

spnego_result spnego_decode_resp(const spnego_byte *tok, spnego_u32 len, spnego_resp *out, spnego_u32 *consumed)
{
    spnego_span choice, seq, field, inner;
    spnego_u32 pos = 0, p;
    spnego_byte tag;
    int last = -1;
    spnego_result r;

    memset(out, 0, sizeof(*out));
    out->neg_state = SPNEGO_NEGSTATE_ABSENT;
    if (len > SPNEGO_MAX_TOKEN) return SPNEGO_BAD;

    /* [1] NegTokenResp ::= SEQUENCE { [0] negState, [1] supportedMech, [2] responseToken, [3] mechListMIC } */
    r = read_element(tok, len, &pos, &tag, &choice, 1);
    if (r != SPNEGO_OK) return r;
    if (tag != TAG_CONTEXT(1)) return SPNEGO_BAD;
    *consumed = pos;
    if (read_single(&choice, TAG_SEQUENCE, &seq, NULL) != SPNEGO_OK) return SPNEGO_BAD;

    p = 0;
    while (p < seq.len)
    {
        int n;

        if (read_element(seq.data, seq.len, &p, &tag, &field, 0) != SPNEGO_OK) return SPNEGO_BAD;
        if (tag < TAG_CONTEXT(0) || tag > TAG_CONTEXT(3)) return SPNEGO_BAD;
        n = tag - TAG_CONTEXT(0);
        if (n <= last) return SPNEGO_BAD;
        last = n;
        switch (n)
        {
        case 0:
            /* ENUMERATED in one content byte; values outside RFC 4178's four are passed on as they are (Windows
             * continues on them, measured), the caller treats them as "not completed, not rejected" */
            if (read_single(&field, TAG_ENUMERATED, &inner, NULL) != SPNEGO_OK) return SPNEGO_BAD;
            if (inner.len != 1) return SPNEGO_BAD;
            out->neg_state = inner.data[0];
            break;
        case 1:
            if (read_single(&field, TAG_OID, &out->supported_mech, NULL) != SPNEGO_OK) return SPNEGO_BAD;
            if (out->supported_mech.len == 0 || out->supported_mech.len > SPNEGO_MAX_OID) return SPNEGO_BAD;
            out->has_supported_mech = 1;
            break;
        case 2:
            if (read_single(&field, TAG_OCTET_STRING, &out->response_token, NULL) != SPNEGO_OK) return SPNEGO_BAD;
            out->has_response_token = 1;
            break;
        case 3:
            if (read_single(&field, TAG_OCTET_STRING, &out->mic, NULL) != SPNEGO_OK) return SPNEGO_BAD;
            out->has_mic = 1;
            break;
        }
    }
    return SPNEGO_OK;
}

/* ---------------------------------------------------------------------------------------------------------------- */
/* Encoder. Sizes are computed bottom-up first; every input is bounded by SPNEGO_MAX_TOKEN, so no sum overflows. */

static spnego_u32 hdr_len(spnego_u32 n)
{
    if (n < 0x80) return 2;
    if (n < 0x100) return 3;
    if (n < 0x10000) return 4;
    return 5;
}

static spnego_u32 elem_len(spnego_u32 n)
{
    return hdr_len(n) + n;
}

static spnego_byte *put_hdr(spnego_byte *p, spnego_byte tag, spnego_u32 n)
{
    *p++ = tag;
    if (n < 0x80) *p++ = (spnego_byte)n;
    else if (n < 0x100) { *p++ = 0x81; *p++ = (spnego_byte)n; }
    else if (n < 0x10000) { *p++ = 0x82; *p++ = (spnego_byte)(n >> 8); *p++ = (spnego_byte)n; }
    else { *p++ = 0x83; *p++ = (spnego_byte)(n >> 16); *p++ = (spnego_byte)(n >> 8); *p++ = (spnego_byte)n; }
    return p;
}

static spnego_byte *put_elem(spnego_byte *p, spnego_byte tag, const spnego_byte *data, spnego_u32 n)
{
    p = put_hdr(p, tag, n);
    if (n) memcpy(p, data, n);
    return p + n;
}

spnego_u32 spnego_encode_init(spnego_byte *out, spnego_u32 out_max, const spnego_byte *const *mech_oids,
                              const spnego_u32 *mech_oid_lens, spnego_u32 mech_count,
                              const spnego_byte *mech_token, spnego_u32 mech_token_len)
{
    spnego_u32 i, oids = 0, mt, a0, a2 = 0, seq, neg, app, total;
    spnego_byte *p;

    if (!mech_count || mech_count > SPNEGO_MAX_MECHS) return 0;
    if (mech_token && mech_token_len > SPNEGO_MAX_TOKEN) return 0;
    for (i = 0; i < mech_count; i++)
    {
        if (!mech_oid_lens[i] || mech_oid_lens[i] > SPNEGO_MAX_OID) return 0;
        oids += elem_len(mech_oid_lens[i]);
    }
    mt = elem_len(oids);                                    /* SEQUENCE OF MechType */
    a0 = elem_len(mt);                                      /* [0] mechTypes */
    if (mech_token) a2 = elem_len(elem_len(mech_token_len)); /* [2] OCTET STRING */
    seq = elem_len(a0 + a2);                                /* NegTokenInit SEQUENCE */
    neg = elem_len(seq);                                    /* [0] negTokenInit */
    app = elem_len(sizeof(spnego_oid_spnego)) + neg;        /* thisMech + innerContextToken */
    total = elem_len(app);
    if (total > SPNEGO_MAX_TOKEN) return 0;
    if (!out) return total;
    if (total > out_max) return 0;

    p = put_hdr(out, TAG_APPLICATION_0, app);
    p = put_elem(p, TAG_OID, spnego_oid_spnego, sizeof(spnego_oid_spnego));
    p = put_hdr(p, TAG_CONTEXT(0), seq);
    p = put_hdr(p, TAG_SEQUENCE, a0 + a2);
    p = put_hdr(p, TAG_CONTEXT(0), mt);
    p = put_hdr(p, TAG_SEQUENCE, oids);
    for (i = 0; i < mech_count; i++) p = put_elem(p, TAG_OID, mech_oids[i], mech_oid_lens[i]);
    if (mech_token)
    {
        p = put_hdr(p, TAG_CONTEXT(2), elem_len(mech_token_len));
        p = put_elem(p, TAG_OCTET_STRING, mech_token, mech_token_len);
    }
    return (spnego_u32)(p - out);
}

spnego_u32 spnego_encode_resp(spnego_byte *out, spnego_u32 out_max, int neg_state,
                              const spnego_byte *supported_mech, spnego_u32 supported_mech_len,
                              const spnego_byte *response_token, spnego_u32 response_token_len,
                              const spnego_byte *mic, spnego_u32 mic_len)
{
    spnego_u32 a0 = 0, a1 = 0, a2 = 0, a3 = 0, seq, total;
    spnego_byte *p, state;

    if (neg_state != SPNEGO_NEGSTATE_ABSENT && (neg_state < 0 || neg_state > 0x7f)) return 0;
    if (supported_mech && (!supported_mech_len || supported_mech_len > SPNEGO_MAX_OID)) return 0;
    if (response_token && response_token_len > SPNEGO_MAX_TOKEN) return 0;
    if (mic && mic_len > SPNEGO_MAX_TOKEN) return 0;
    if (neg_state != SPNEGO_NEGSTATE_ABSENT) a0 = elem_len(elem_len(1));
    if (supported_mech) a1 = elem_len(elem_len(supported_mech_len));
    if (response_token) a2 = elem_len(elem_len(response_token_len));
    if (mic) a3 = elem_len(elem_len(mic_len));
    seq = elem_len(a0 + a1 + a2 + a3);
    total = elem_len(seq);
    if (total > SPNEGO_MAX_TOKEN) return 0;
    if (!out) return total;
    if (total > out_max) return 0;

    p = put_hdr(out, TAG_CONTEXT(1), seq);
    p = put_hdr(p, TAG_SEQUENCE, a0 + a1 + a2 + a3);
    if (neg_state != SPNEGO_NEGSTATE_ABSENT)
    {
        state = (spnego_byte)neg_state;
        p = put_hdr(p, TAG_CONTEXT(0), elem_len(1));
        p = put_elem(p, TAG_ENUMERATED, &state, 1);
    }
    if (supported_mech)
    {
        p = put_hdr(p, TAG_CONTEXT(1), elem_len(supported_mech_len));
        p = put_elem(p, TAG_OID, supported_mech, supported_mech_len);
    }
    if (response_token)
    {
        p = put_hdr(p, TAG_CONTEXT(2), elem_len(response_token_len));
        p = put_elem(p, TAG_OCTET_STRING, response_token, response_token_len);
    }
    if (mic)
    {
        p = put_hdr(p, TAG_CONTEXT(3), elem_len(mic_len));
        p = put_elem(p, TAG_OCTET_STRING, mic, mic_len);
    }
    return (spnego_u32)(p - out);
}
