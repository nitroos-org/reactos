/*
 * PROJECT:     Authentication Package DLL
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     NTLMv2 challenge response check of a network logon (header)
 */

#pragma once

/* Checks the NTLMv2 response of a network logon against the NT OWF of the account's password and returns the
 * session base key (16 bytes). STATUS_WRONG_PASSWORD when the response does not match. */
NTSTATUS
MsvpCheckNtlmv2Response(
    _In_ const UCHAR *ServerChallenge,
    _In_ PUNICODE_STRING UserName,
    _In_ PUNICODE_STRING DomainName,
    _In_ const UCHAR *NtOwfPassword,
    _In_reads_bytes_(NtResponseLength) const UCHAR *NtResponse,
    _In_ ULONG NtResponseLength,
    _Out_writes_bytes_(16) UCHAR *SessionBaseKey);

/* The NTLMv2 proofs for a challenge: NtProof, the proof of the LM response and the session base key. The caller makes
 * the blob (the bytes of the response after the proof). */
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
    _Out_writes_bytes_(16) UCHAR *SessionBaseKey);
