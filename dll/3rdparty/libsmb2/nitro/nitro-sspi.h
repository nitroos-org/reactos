/*
 * PROJECT:     NitroOS
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     The SSPI authentication backend of libsmb2 (internal interface; called from lib/libsmb2.c, lib/init.c)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#ifndef NITRO_LIBSMB2_SSPI_H
#define NITRO_LIBSMB2_SSPI_H

#include <stdint.h>

struct smb2_context;

/* TCP connected (lib/libsmb2.c connect_cb): for the error mapping. */
void smb2_sspi_transport_connected(struct smb2_context *smb2);

/* After NEGOTIATE (negotiate_cb): credentials (if not set yet) and a new
 * security context; hint = the NEGOTIATE response's security buffer.
 * Returns the per-session-setup state (c_data->auth_data) or NULL. */
void *smb2_sspi_negotiate_reply(struct smb2_context *smb2, const char *server,
                                const uint8_t *hint, int hint_len);

/* Next token to send (send_session_setup_request); in = the server's token
 * of the MORE_PROCESSING_REQUIRED response (NULL for the first leg). The
 * output stays owned by auth. Returns 0 or -1 (error set on smb2). */
int smb2_sspi_session_request(struct smb2_context *smb2, void *auth,
                              const uint8_t *in, int in_len,
                              uint8_t **out, uint16_t *out_len);

/* SESSION_SETUP succeeded (session_setup_cb): refuses guest/anonymous
 * sessions, completes the exchange with the server's last token, sets
 * smb2->session_key. Returns 0 or -1 (error set on smb2). */
int smb2_sspi_session_complete(struct smb2_context *smb2, void *auth,
                               uint16_t session_flags,
                               const uint8_t *in, int in_len);

void smb2_sspi_free_auth_data(void *auth);

/* smb2_destroy_context(): credentials released, secrets wiped. */
void smb2_sspi_destroy(struct smb2_context *smb2);

#endif /* NITRO_LIBSMB2_SSPI_H */
