/*
 * PROJECT:     ReactOS secur32
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     SPNEGO (RFC 4178, [MS-SPNG]) token codec: a bounded DER reader and writer for NegTokenInit,
 *              NegTokenInit2 and NegTokenResp. No Windows types and no allocation: it builds on Linux too (fuzzing).
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#ifndef SPNEGO_DER_H
#define SPNEGO_DER_H

#include <stddef.h>

typedef unsigned char spnego_byte;
typedef unsigned int spnego_u32;

/* Every token is attacker controlled. The decoder walks the fixed structure of the two token types and never
 * recurses on its input; every length is checked against what is left of its parent before it is used. */
#define SPNEGO_MAX_TOKEN    48256   /* the cbMaxToken of the Negotiate package (measured on Windows) */
#define SPNEGO_MAX_MECHS    32      /* mechanism OIDs kept from a mechTypes list (more is refused) */
#define SPNEGO_MAX_OID      64      /* bytes of one OID's content */

typedef struct
{
    const spnego_byte *data;
    spnego_u32 len;
} spnego_span;

typedef enum
{
    SPNEGO_OK = 0,
    SPNEGO_BAD,         /* not a token of the expected shape */
    SPNEGO_SHORT        /* the outer element is longer than the data: more may follow (reassembly) */
} spnego_result;

/* negState values (RFC 4178 4.2.2) */
#define SPNEGO_ACCEPT_COMPLETED     0
#define SPNEGO_ACCEPT_INCOMPLETE    1
#define SPNEGO_REJECT               2
#define SPNEGO_REQUEST_MIC          3
#define SPNEGO_NEGSTATE_ABSENT      (-1)

typedef struct
{
    spnego_span mech_list;          /* the whole MechTypeList element (tag, length, content): the mechListMIC covers it */
    spnego_span mechs[SPNEGO_MAX_MECHS]; /* the content of each OID */
    spnego_u32 mech_count;
    int has_req_flags;
    int has_mech_token;
    spnego_span mech_token;         /* content of the OCTET STRING */
    int has_mic;                    /* [3] of NegTokenInit or [4] of NegTokenInit2 */
    spnego_span mic;
    int has_neg_hints;              /* NegTokenInit2 [3] (not interpreted) */
} spnego_init;

typedef struct
{
    int neg_state;                  /* SPNEGO_NEGSTATE_ABSENT or 0-255 */
    int has_supported_mech;
    spnego_span supported_mech;     /* content of the OID */
    int has_response_token;
    spnego_span response_token;
    int has_mic;
    spnego_span mic;
} spnego_resp;

/* OIDs (content bytes, no tag) */
extern const spnego_byte spnego_oid_spnego[6];   /* 1.3.6.1.5.5.2 */
extern const spnego_byte spnego_oid_ntlm[10];    /* 1.3.6.1.4.1.311.2.2.10 */

int spnego_oid_is(const spnego_span *oid, const spnego_byte *want, spnego_u32 want_len);

/* The total length (header + content) of the outer element of a token, for reassembly. SPNEGO_SHORT: the header
 * itself is incomplete; SPNEGO_BAD: not a definite-length element or larger than SPNEGO_MAX_TOKEN. */
spnego_result spnego_outer_length(const spnego_byte *tok, spnego_u32 len, spnego_u32 *total);

/* The mechanism OID of an InitialContextToken ([APPLICATION 0] { thisMech, ... }), whatever the mechanism. */
spnego_result spnego_gss_mech(const spnego_byte *tok, spnego_u32 len, spnego_span *oid);

/* InitialContextToken with a NegTokenInit/NegTokenInit2 ([APPLICATION 0] { thisMech, [0] NegTokenInit }).
 * *consumed = length of the outer element; data behind it is the caller's business. */
spnego_result spnego_decode_init(const spnego_byte *tok, spnego_u32 len, spnego_init *out, spnego_u32 *consumed);

/* NegTokenResp ([1] NegTokenResp, without the GSS framing, as every reply carries it). */
spnego_result spnego_decode_resp(const spnego_byte *tok, spnego_u32 len, spnego_resp *out, spnego_u32 *consumed);

/* Encoders: return the length written, or 0 when out_max is too small or an input is too long. With out == NULL
 * they return the length that would be written. */
spnego_u32 spnego_encode_init(spnego_byte *out, spnego_u32 out_max, const spnego_byte *const *mech_oids,
                              const spnego_u32 *mech_oid_lens, spnego_u32 mech_count,
                              const spnego_byte *mech_token, spnego_u32 mech_token_len);
spnego_u32 spnego_encode_resp(spnego_byte *out, spnego_u32 out_max, int neg_state,
                              const spnego_byte *supported_mech, spnego_u32 supported_mech_len,
                              const spnego_byte *response_token, spnego_u32 response_token_len,
                              const spnego_byte *mic, spnego_u32 mic_len);

#endif /* SPNEGO_DER_H */
