/*
 * PROJECT:     NitroOS
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     The built-in NTLMSSP engine of libsmb2 is not built on NitroOS (the client authenticates through
 *              SSPI, nitro/sspi.c). The server side of lib/libsmb2.c still refers to it: these stand-ins make
 *              every server session setup fail. The DLL does not export the server API.
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "config.h"
#include <stdint.h>
#include <stddef.h>
#include <time.h>

#include "compat.h"
#include "smb2.h"
#include "libsmb2.h"
#include "ntlmssp.h"

struct auth_data *
ntlmssp_init_context(const char *user, const char *password, const char *domain,
                     const char *workstation, const char *client_challenge)
{
    (void)user; (void)password; (void)domain; (void)workstation; (void)client_challenge;
    return NULL;
}

void
ntlmssp_destroy_context(struct auth_data *auth)
{
    (void)auth;
}

void
ntlmssp_set_spnego_wrapping(struct auth_data *auth, int wrap)
{
    (void)auth; (void)wrap;
}

int
ntlmssp_set_spnego_mech_types(struct auth_data *auth, const uint8_t *mech_types,
                              int len, int counter_proposed)
{
    (void)auth; (void)mech_types; (void)len; (void)counter_proposed;
    return -1;
}

int
ntlmssp_get_spnego_wrapping(struct auth_data *auth)
{
    (void)auth;
    return 0;
}

int
ntlmssp_get_message_type(struct smb2_context *smb2, uint8_t *ntlmssp_buffer, int len,
                         int suppress_errors, uint32_t *message_type,
                         uint8_t **ntlmssp_ptr, int *ntlmssp_len, int *is_wrapped)
{
    (void)smb2; (void)ntlmssp_buffer; (void)len; (void)suppress_errors;
    (void)message_type; (void)ntlmssp_ptr; (void)ntlmssp_len; (void)is_wrapped;
    return -1;
}

int
ntlmssp_generate_blob(struct smb2_server *server, struct smb2_context *smb2, time_t t,
                      struct auth_data *auth_data, unsigned char *input_buf, int input_len,
                      unsigned char **output_buf, uint16_t *output_len)
{
    (void)server; (void)smb2; (void)t; (void)auth_data; (void)input_buf; (void)input_len;
    (void)output_buf; (void)output_len;
    return -1;
}

int
ntlmssp_authenticate_blob(struct smb2_server *server, struct smb2_context *smb2,
                          struct auth_data *auth_data, unsigned char *input_buf, int input_len)
{
    (void)server; (void)smb2; (void)auth_data; (void)input_buf; (void)input_len;
    return -1;
}

int
ntlmssp_get_authenticated(struct auth_data *auth)
{
    (void)auth;
    return 0;
}

int
ntlmssp_get_session_key(struct auth_data *auth, uint8_t **key, uint8_t *key_size)
{
    (void)auth; (void)key; (void)key_size;
    return -1;
}
