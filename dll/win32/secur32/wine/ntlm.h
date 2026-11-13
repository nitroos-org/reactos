
#ifndef __WINE_NTLM_H__
#define __WINE_NTLM_H__


void SECUR32_initNTLMSP(void) DECLSPEC_HIDDEN;

typedef enum _helper_mode {
    NTLM_SERVER,
    NTLM_CLIENT,
    NUM_HELPER_MODES
} HelperMode;

typedef struct tag_arc4_info {
    unsigned char x, y;
    unsigned char state[256];
} arc4_info;

/* the identity of the credentials of an outbound use */
typedef struct _NtlmCredentials
{
    ULONG use;              /* SECPKG_CRED_INBOUND, _OUTBOUND or _BOTH */
    BOOL has_identity;      /* explicit user, domain and password; otherwise the caller's own */
    WCHAR *username;
    WCHAR *domain;
    BYTE nt_hash[16];       /* NT hash of the password */
} NtlmCredentials, *PNtlmCredentials;

/* a security context of one side of an exchange (the name is from the helper process based version) */
typedef struct _NegoHelper {
    HelperMode mode;
    int state;                  /* 0: the exchange is not complete, 1: complete */
    ULONG req_flags;            /* the request flags of the context */
    ULONG offered_flags;        /* the NTLMSSP flags this side put in its message */
    ULONG neg_flags;            /* the negotiated NTLMSSP flags */
    BYTE *session_key;          /* the (exported) session key, 16 bytes */
    BYTE *negotiate_msg;        /* the messages that the MIC covers */
    ULONG negotiate_len;
    BYTE *challenge_msg;
    ULONG challenge_len;
    BYTE server_challenge[8];
    PNtlmCredentials cred;      /* client: copy of the credentials */
    WCHAR *user_name;           /* server: the client as it authenticated */
    WCHAR *domain_name;
    HANDLE token;               /* server: the impersonation token of the client */
    struct {
        struct {
            ULONG seq_num;
            arc4_info *a4i;
        } ntlm;
        struct {
            BYTE *send_sign_key;
            BYTE *send_seal_key;
            BYTE *recv_sign_key;
            BYTE *recv_seal_key;
            ULONG send_seq_no;
            ULONG recv_seq_no;
            arc4_info *send_a4i;
            arc4_info *recv_a4i;
        } ntlm2;
    } crypt;
} NegoHelper, *PNegoHelper;

typedef enum _sign_direction {
    NTLM_SEND,
    NTLM_RECV
} SignDirection;

SECURITY_STATUS SECUR32_CreateNTLM1SessionKey(PBYTE password, int len, PBYTE session_key) DECLSPEC_HIDDEN;
SECURITY_STATUS SECUR32_CreateNTLM2SubKeys(PNegoHelper helper) DECLSPEC_HIDDEN;

/* NTLMSSP flags indicating the negotiated features */
#define NTLMSSP_NEGOTIATE_UNICODE                   0x00000001
#define NTLMSSP_NEGOTIATE_OEM                       0x00000002
#define NTLMSSP_REQUEST_TARGET                      0x00000004
#define NTLMSSP_NEGOTIATE_SIGN                      0x00000010
#define NTLMSSP_NEGOTIATE_SEAL                      0x00000020
#define NTLMSSP_NEGOTIATE_DATAGRAM_STYLE            0x00000040
#define NTLMSSP_NEGOTIATE_LM_SESSION_KEY            0x00000080
#define NTLMSSP_NEGOTIATE_NTLM                      0x00000200
#define NTLMSSP_NEGOTIATE_DOMAIN_SUPPLIED           0x00001000
#define NTLMSSP_NEGOTIATE_WORKSTATION_SUPPLIED      0x00002000
#define NTLMSSP_NEGOTIATE_LOCAL_CALL                0x00004000
#define NTLMSSP_NEGOTIATE_ALWAYS_SIGN               0x00008000
#define NTLMSSP_NEGOTIATE_TARGET_TYPE_DOMAIN        0x00010000
#define NTLMSSP_NEGOTIATE_TARGET_TYPE_SERVER        0x00020000
#define NTLMSSP_NEGOTIATE_NTLM2                     0x00080000
#define NTLMSSP_NEGOTIATE_TARGET_INFO               0x00800000
#define NTLMSSP_NEGOTIATE_128                       0x20000000
#define NTLMSSP_NEGOTIATE_KEY_EXCHANGE              0x40000000
#define NTLMSSP_NEGOTIATE_56                        0x80000000

SECURITY_STATUS SEC_ENTRY ntlm_AcquireCredentialsHandleW(SEC_WCHAR *, SEC_WCHAR *,
    ULONG, PLUID, PVOID, SEC_GET_KEY_FN, PVOID, PCredHandle, PTimeStamp) DECLSPEC_HIDDEN;
SECURITY_STATUS SEC_ENTRY ntlm_InitializeSecurityContextW(PCredHandle, PCtxtHandle,
    SEC_WCHAR *, ULONG fContextReq, ULONG, ULONG, PSecBufferDesc, ULONG, PCtxtHandle,
    PSecBufferDesc, ULONG *, PTimeStamp) DECLSPEC_HIDDEN;
SECURITY_STATUS SEC_ENTRY ntlm_AcceptSecurityContext(PCredHandle, PCtxtHandle, PSecBufferDesc,
    ULONG, ULONG, PCtxtHandle, PSecBufferDesc, ULONG *, PTimeStamp) DECLSPEC_HIDDEN;
SECURITY_STATUS SEC_ENTRY ntlm_QueryContextAttributesA(PCtxtHandle, ULONG, void *) DECLSPEC_HIDDEN;
SECURITY_STATUS SEC_ENTRY ntlm_QueryContextAttributesW(PCtxtHandle, ULONG, void *) DECLSPEC_HIDDEN;
SECURITY_STATUS SEC_ENTRY ntlm_EncryptMessage(PCtxtHandle, ULONG, PSecBufferDesc, ULONG) DECLSPEC_HIDDEN;
SECURITY_STATUS SEC_ENTRY ntlm_DecryptMessage(PCtxtHandle, PSecBufferDesc, ULONG, PULONG) DECLSPEC_HIDDEN;
SECURITY_STATUS SEC_ENTRY ntlm_FreeCredentialsHandle(PCredHandle) DECLSPEC_HIDDEN;
SECURITY_STATUS SEC_ENTRY ntlm_DeleteSecurityContext(PCtxtHandle) DECLSPEC_HIDDEN;
SECURITY_STATUS SEC_ENTRY ntlm_MakeSignature(PCtxtHandle, ULONG, PSecBufferDesc, ULONG) DECLSPEC_HIDDEN;
SECURITY_STATUS SEC_ENTRY ntlm_VerifySignature(PCtxtHandle, PSecBufferDesc, ULONG, PULONG) DECLSPEC_HIDDEN;

SecPkgInfoW *ntlm_copy_package_infoW(void) DECLSPEC_HIDDEN;
SecPkgInfoA *ntlm_copy_package_infoA(void) DECLSPEC_HIDDEN;
extern SecPkgInfoW *ntlm_package_infoW DECLSPEC_HIDDEN;
extern SecPkgInfoA *ntlm_package_infoA DECLSPEC_HIDDEN;

#endif /* __WINE_NTLM_H__ */
