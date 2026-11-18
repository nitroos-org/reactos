/*
 * PROJECT:     NitroOS
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     libsmb2 build configuration for NitroOS (the file its sources include as "config.h")
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#ifndef NITRO_LIBSMB2_CONFIG_H
#define NITRO_LIBSMB2_CONFIG_H

#include <stddef.h>

#define HAVE_STDINT_H 1
#define HAVE_STDLIB_H 1
#define HAVE_STRING_H 1
#define HAVE_STDIO_H 1
#define HAVE_INTTYPES_H 1
#define HAVE_SYS_TYPES_H 1
#define HAVE_SYS_STAT_H 1
#define HAVE_TIME_H 1
#define HAVE_FCNTL_H 1
#define HAVE_SOCKADDR_STORAGE 1
#define HAVE_STRUCT_ADDRINFO 1
#define HAVE_LINGER 1

#define _U_ __attribute__((unused))

/* Set on the command line (CMakeLists.txt), because some upstream files do
 * not include this one: NEED_GETLOGIN_R, NEED_GETPID, NEED_RANDOM,
 * NEED_SRANDOM (what libsmb2's own CMake sets for Windows), HAVE_SSPI
 * (authentication through nitro/sspi.c; it also changes struct
 * smb2_context, so every file must see it) and HAVE_ARC4RANDOM_BUF
 * (smb2_random_bytes() takes its bytes from arc4random_buf(), which
 * nitro/crypto.c implements with BCryptGenRandom; libsmb2's rand()-based
 * fallback is never compiled). */
void arc4random_buf(void *buf, size_t len);

#endif /* NITRO_LIBSMB2_CONFIG_H */
