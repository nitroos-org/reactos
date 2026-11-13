/*
 * PROJECT:     Authentication Package DLL
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     NTLMv2 challenge response check of a network logon
 *
 * The algorithm is the one the NTLM protocol documents publicly (MS-NLMP, "NTLM v2 Authentication"):
 *   ResponseKeyNT = HMAC_MD5(NTOWF, UNICODE(Uppercase(UserName) + DomainName))
 *   NTProofStr    = HMAC_MD5(ResponseKeyNT, ServerChallenge + ClientBlob)
 *   SessionBaseKey = HMAC_MD5(ResponseKeyNT, NTProofStr)
 */

#include "../precomp.h"

#include "ntlmv2.h"

#include "wine/debug.h"
WINE_DEFAULT_DEBUG_CHANNEL(ntlm);

typedef struct
{
    unsigned int i[2];
    unsigned int buf[4];
    unsigned char in[64];
    unsigned char digest[16];
} NTLM_MD5_CTX;

void WINAPI MD5Init(NTLM_MD5_CTX *ctx);
void WINAPI MD5Update(NTLM_MD5_CTX *ctx, const unsigned char *buf, unsigned int len);
void WINAPI MD5Final(NTLM_MD5_CTX *ctx);

typedef struct
{
    NTLM_MD5_CTX ctx;
    unsigned char opad[64];
} NTLM_HMAC_CTX;

static
void
HmacInit(
    _Out_ NTLM_HMAC_CTX *h,
    _In_ const UCHAR *Key,
    _In_ ULONG KeyLength)
{
    UCHAR ipad[64];
    UCHAR kbuf[16];
    ULONG i;

    if (KeyLength > 64)
    {
        NTLM_MD5_CTX k;

        MD5Init(&k);
        MD5Update(&k, Key, KeyLength);
        MD5Final(&k);
        RtlCopyMemory(kbuf, k.digest, 16);
        Key = kbuf;
        KeyLength = 16;
    }

    RtlZeroMemory(ipad, sizeof(ipad));
    RtlZeroMemory(h->opad, sizeof(h->opad));
    RtlCopyMemory(ipad, Key, KeyLength);
    RtlCopyMemory(h->opad, Key, KeyLength);
    for (i = 0; i < 64; i++)
    {
        ipad[i] ^= 0x36;
        h->opad[i] ^= 0x5c;
    }

    MD5Init(&h->ctx);
    MD5Update(&h->ctx, ipad, 64);
}

static
void
HmacUpdate(
    _Inout_ NTLM_HMAC_CTX *h,
    _In_ const UCHAR *Data,
    _In_ ULONG Length)
{
    MD5Update(&h->ctx, Data, Length);
}

static
void
HmacFinal(
    _Inout_ NTLM_HMAC_CTX *h,
    _Out_writes_bytes_(16) UCHAR *Digest)
{
    UCHAR inner[16];
    NTLM_MD5_CTX outer;

    MD5Final(&h->ctx);
    RtlCopyMemory(inner, h->ctx.digest, 16);

    MD5Init(&outer);
    MD5Update(&outer, h->opad, 64);
    MD5Update(&outer, inner, 16);
    MD5Final(&outer);
    RtlCopyMemory(Digest, outer.digest, 16);
}

/* ResponseKeyNT = HMAC_MD5(NTOWF, UNICODE(Uppercase(UserName) + DomainName)) */
static
NTSTATUS
MsvpNtlmv2ResponseKey(
    _In_ PUNICODE_STRING UserName,
    _In_ PUNICODE_STRING DomainName,
    _In_ const UCHAR *NtOwfPassword,
    _Out_writes_bytes_(16) UCHAR *ResponseKey)
{
    UNICODE_STRING UpperUser;
    NTLM_HMAC_CTX h;
    NTSTATUS Status;

    Status = RtlUpcaseUnicodeString(&UpperUser, UserName, TRUE);
    if (!NT_SUCCESS(Status))
        return Status;

    HmacInit(&h, NtOwfPassword, 16);
    HmacUpdate(&h, (const UCHAR *)UpperUser.Buffer, UpperUser.Length);
    HmacUpdate(&h, (const UCHAR *)DomainName->Buffer, DomainName->Length);
    HmacFinal(&h, ResponseKey);
    RtlFreeUnicodeString(&UpperUser);
    return STATUS_SUCCESS;
}

NTSTATUS
MsvpComputeNtlmv2Response(
    _In_ const UCHAR *NtOwfPassword,
    _In_ PUNICODE_STRING UserName,
    _In_ PUNICODE_STRING DomainName,
    _In_ const UCHAR *ServerChallenge,
    _In_ const UCHAR *ClientChallenge,
    _In_reads_bytes_(BlobLength) const UCHAR *Blob,
    _In_ ULONG BlobLength,
    _Out_writes_bytes_(16) UCHAR *NtProof,
    _Out_writes_bytes_(16) UCHAR *LmProof,
    _Out_writes_bytes_(16) UCHAR *SessionBaseKey)
{
    NTLM_HMAC_CTX h;
    UCHAR ResponseKey[16];
    NTSTATUS Status;

    Status = MsvpNtlmv2ResponseKey(UserName, DomainName, NtOwfPassword, ResponseKey);
    if (!NT_SUCCESS(Status))
        return Status;

    HmacInit(&h, ResponseKey, 16);
    HmacUpdate(&h, ServerChallenge, 8);
    HmacUpdate(&h, Blob, BlobLength);
    HmacFinal(&h, NtProof);

    HmacInit(&h, ResponseKey, 16);
    HmacUpdate(&h, ServerChallenge, 8);
    HmacUpdate(&h, ClientChallenge, 8);
    HmacFinal(&h, LmProof);

    HmacInit(&h, ResponseKey, 16);
    HmacUpdate(&h, NtProof, 16);
    HmacFinal(&h, SessionBaseKey);

    RtlSecureZeroMemory(ResponseKey, sizeof(ResponseKey));
    return STATUS_SUCCESS;
}

/* The minimum of the client blob: the fixed 28 bytes and a target info that is at least its terminator */
#define NTLMV2_MIN_RESPONSE_LENGTH (16 + 28 + 4)

NTSTATUS
MsvpCheckNtlmv2Response(
    _In_ const UCHAR *ServerChallenge,
    _In_ PUNICODE_STRING UserName,
    _In_ PUNICODE_STRING DomainName,
    _In_ const UCHAR *NtOwfPassword,
    _In_reads_bytes_(NtResponseLength) const UCHAR *NtResponse,
    _In_ ULONG NtResponseLength,
    _Out_writes_bytes_(16) UCHAR *SessionBaseKey)
{
    NTLM_HMAC_CTX h;
    UCHAR ResponseKey[16];
    UCHAR Proof[16];
    ULONG i, Diff;
    NTSTATUS Status;

    if (NtResponseLength < NTLMV2_MIN_RESPONSE_LENGTH)
        return STATUS_WRONG_PASSWORD;

    /* The version bytes of the blob */
    if (NtResponse[16] != 1 || NtResponse[17] != 1)
        return STATUS_WRONG_PASSWORD;

    Status = MsvpNtlmv2ResponseKey(UserName, DomainName, NtOwfPassword, ResponseKey);
    if (!NT_SUCCESS(Status))
        return Status;

    HmacInit(&h, ResponseKey, 16);
    HmacUpdate(&h, ServerChallenge, 8);
    HmacUpdate(&h, NtResponse + 16, NtResponseLength - 16);
    HmacFinal(&h, Proof);

    /* Compare without stopping at the first difference */
    Diff = 0;
    for (i = 0; i < 16; i++)
        Diff |= (ULONG)(Proof[i] ^ NtResponse[i]);
    if (Diff != 0)
    {
        RtlSecureZeroMemory(ResponseKey, sizeof(ResponseKey));
        return STATUS_WRONG_PASSWORD;
    }

    HmacInit(&h, ResponseKey, 16);
    HmacUpdate(&h, Proof, 16);
    HmacFinal(&h, SessionBaseKey);

    RtlSecureZeroMemory(ResponseKey, sizeof(ResponseKey));
    return STATUS_SUCCESS;
}
