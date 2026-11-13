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

/*
 * The local call of a same-machine NTLM exchange. The NTLM server of secur32 asks the package for a context when the
 * NEGOTIATE message names this machine, and sends its id in the CHALLENGE (NTLMSSP_NEGOTIATE_LOCAL_CALL). The NTLM
 * client binds its own logon to the context: the package judges the client by its token (thread, else process), not
 * by anything in a message. The server gets the token of the client only for a context that it issued itself and
 * that a client on this machine bound; a remote peer cannot bind one (it cannot reach this package), so an empty
 * AUTHENTICATE never stands for a logon. The answers are flat (no pointers), the same for 32-bit and 64-bit callers.
 */
#define MsV1_0RosNtlmLocalIssue     0x4d530002
#define MsV1_0RosNtlmLocalBind      0x4d530003
#define MsV1_0RosNtlmLocalAccept    0x4d530004
#define MsV1_0RosNtlmLocalDelete    0x4d530005

/* MsV1_0RosNtlmLocalIssue: the server asks for a context for its CHALLENGE */
typedef struct _MSV1_0_ROS_NTLM_LOCAL_ISSUE
{
    ULONG MessageType;
    UCHAR ServerChallenge[8];
} MSV1_0_ROS_NTLM_LOCAL_ISSUE, *PMSV1_0_ROS_NTLM_LOCAL_ISSUE;

/* the answer to MsV1_0RosNtlmLocalIssue; the request of MsV1_0RosNtlmLocalDelete */
typedef struct _MSV1_0_ROS_NTLM_LOCAL_CONTEXT
{
    ULONG MessageType;
    ULONG Reserved;
    ULONG64 ContextId;          /* never 0; the 8 bytes of the context field of the CHALLENGE */
} MSV1_0_ROS_NTLM_LOCAL_CONTEXT, *PMSV1_0_ROS_NTLM_LOCAL_CONTEXT;

/* MsV1_0RosNtlmLocalBind: the client, for the context and the challenge of the CHALLENGE it got */
typedef struct _MSV1_0_ROS_NTLM_LOCAL_BIND
{
    ULONG MessageType;
    ULONG ImpersonationLevel;   /* SECURITY_IMPERSONATION_LEVEL the client allows the server */
    ULONG64 ContextId;
    UCHAR ServerChallenge[8];
} MSV1_0_ROS_NTLM_LOCAL_BIND, *PMSV1_0_ROS_NTLM_LOCAL_BIND;

/* MsV1_0RosNtlmLocalAccept: the server, for the context it issued */
typedef struct _MSV1_0_ROS_NTLM_LOCAL_ACCEPT
{
    ULONG MessageType;
    ULONG Reserved;
    ULONG64 ContextId;
} MSV1_0_ROS_NTLM_LOCAL_ACCEPT, *PMSV1_0_ROS_NTLM_LOCAL_ACCEPT;

/* The answer to MsV1_0RosNtlmLocalBind (TokenHandle 0) and to MsV1_0RosNtlmLocalAccept: the session key both sides
 * share and, for the server, the token of the client (an impersonation token, a handle in the server's process) */
typedef struct _MSV1_0_ROS_NTLM_LOCAL_RESPONSE
{
    ULONG MessageType;
    ULONG Reserved;
    ULONG64 TokenHandle;
    UCHAR SessionKey[16];
} MSV1_0_ROS_NTLM_LOCAL_RESPONSE, *PMSV1_0_ROS_NTLM_LOCAL_RESPONSE;

/* The same layout for 32-bit and 64-bit callers (WoW64 passes these through unchanged) */
C_ASSERT(sizeof(MSV1_0_ROS_NTLM_LOCAL_ISSUE) == 12);
C_ASSERT(sizeof(MSV1_0_ROS_NTLM_LOCAL_CONTEXT) == 16);
C_ASSERT(sizeof(MSV1_0_ROS_NTLM_LOCAL_BIND) == 24);
C_ASSERT(sizeof(MSV1_0_ROS_NTLM_LOCAL_ACCEPT) == 16);
C_ASSERT(sizeof(MSV1_0_ROS_NTLM_LOCAL_RESPONSE) == 32);
