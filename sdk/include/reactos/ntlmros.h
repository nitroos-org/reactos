/*
 * PROJECT:     ReactOS LSA
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     ReactOS private messages of the MSV1_0 authentication package: the NTLM client of secur32 asks the
 *              package for the NTLMv2 response of the logon session of the caller (the credentials of the
 *              logged on user), as the NTLM package does inside the LSA on Windows. The package keeps the NT hash
 *              of the password of a logon and never hands it out: only the proofs that a challenge needs.
 */

#pragma once

/* MessageType of LsaCallAuthenticationPackage for the MSV1_0 package */
#define MsV1_0RosNtlmV2Response 0x4d530001

/* The request: the challenge of the server, the client challenge, the blob of the NTLMv2 response
 * (the bytes after the 16 byte proof) that follows this structure */
typedef struct _MSV1_0_ROS_NTLMV2_REQUEST
{
    ULONG MessageType;
    UCHAR ServerChallenge[8];
    UCHAR ClientChallenge[8];
    ULONG BlobLength;
    /* UCHAR Blob[BlobLength] */
} MSV1_0_ROS_NTLMV2_REQUEST, *PMSV1_0_ROS_NTLMV2_REQUEST;

/* The answer (in memory of the caller, to release with LsaFreeReturnBuffer): the proofs and the names of the
 * logon, which follow as UTF-16 text (not terminated) */
typedef struct _MSV1_0_ROS_NTLMV2_RESPONSE
{
    ULONG MessageType;
    UCHAR NtProof[16];          /* HMAC_MD5(ResponseKeyNT, ServerChallenge + Blob) */
    UCHAR LmProof[16];          /* HMAC_MD5(ResponseKeyNT, ServerChallenge + ClientChallenge) */
    UCHAR SessionBaseKey[16];   /* HMAC_MD5(ResponseKeyNT, NtProof) */
    ULONG UserNameLength;       /* in bytes */
    ULONG DomainNameLength;     /* in bytes */
    /* WCHAR UserName[UserNameLength / 2]; WCHAR DomainName[DomainNameLength / 2]; */
} MSV1_0_ROS_NTLMV2_RESPONSE, *PMSV1_0_ROS_NTLMV2_RESPONSE;
