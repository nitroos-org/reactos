/*
 * PROJECT:     NitroOS SMB redirector
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Private contract between the network provider (ntlanman.dll, wkssvc)
 *              and the SMB mini-redirector (mrxsmb.sys): connection credentials,
 *              connection list, connection deletion
 * COPYRIGHT:   Copyright 2026 Tomas Srnka
 */

/*
 * Making a connection. The provider opens, in the caller's own security context,
 *   \Device\LanmanRedirector\;X:<logon id, 16 hex digits>\server\share[\path]   (drive X:)
 *   \Device\LanmanRedirector\server\share[\path]                                (no device)
 * with FILE_CREATE_TREE_CONNECTION. Explicit credentials travel in the EA buffer of
 * that create (ZwCreateFile EaBuffer, FILE_FULL_EA_INFORMATION entries), never through
 * the registry or a file: SMBCONN_EA_USERNAME, SMBCONN_EA_DOMAIN and SMBCONN_EA_PASSWORD,
 * values UTF-16LE without a terminating NUL. A connection with SMBCONN_EA_USERNAME is
 * an explicit-credential connection (an absent SMBCONN_EA_PASSWORD = empty password).
 * The driver reads them only for tree-connect opens that create a new virtual net
 * root, passes them to the engine once and wipes its copies (the IRP's EA buffer
 * included). The caller wipes its own buffer after the create.
 * The logon id in a drive-letter name must be the caller's: the driver refuses
 * other values (STATUS_ACCESS_DENIED).
 *
 * Checking credentials against an existing connection. A second explicit tree connect to a name
 * that is already connected reaches no driver code (rdbss reuses the connection), so the password
 * of the second one would never be compared with the first one's. The provider asks instead with
 *   \Device\LanmanRedirector\;#:<logon id, 16 hex digits>\server\share[\path]
 * and the credentials in the EA buffer, as above (a name that is no drive, nothing is kept): the
 * engine compares them with the identity the caller's logon session uses for the server. The
 * answer is STATUS_NETWORK_CREDENTIAL_CONFLICT when they differ, SMBCONN_STATUS_PROBE_OK
 * (an error severity, so that rdbss keeps nothing of the create) when they fit, or the status of
 * a failed connect. Without credentials, or in a create that is no tree connect, it is
 * STATUS_INVALID_PARAMETER.
 *
 * The tree-connect handle keeps the connection after it is closed (rdbss's extra
 * reference); IOCTL_SMBCONN_DELETE ends it. Both list and delete act only on the
 * connections of the caller's logon session (the driver takes the logon id from the
 * caller's token, impersonation included, never from the input).
 *
 * The IOCTLs go to the redirector device \Device\NitroSmbRedirector opened without a
 * file name (SMBCONN_DEVICE_NAME), METHOD_BUFFERED.
 */

#ifndef _NITRO_SMBCONN_H_
#define _NITRO_SMBCONN_H_

#define SMBCONN_DEVICE_NAME              L"\\Device\\NitroSmbRedirector"
#define SMBCONN_REDIRECTOR_PREFIX        L"\\Device\\LanmanRedirector"

/* Customer-defined NTSTATUS (bit 29 set): the credentials of a \;#: check fit */
#define SMBCONN_STATUS_PROBE_OK          ((NTSTATUS)0xE0534D01)

#define SMBCONN_EA_USERNAME              "NitroSmbAccount"
#define SMBCONN_EA_DOMAIN                "NitroSmbDomain"
#define SMBCONN_EA_PASSWORD              "NitroSmbPassword"

/* Limits (characters) of what the driver accepts in the EA (Windows: UNLEN 256, DNLEN 15 + DNS names, PWLEN 256) */
#define SMBCONN_MAX_USER_CHARS           256
#define SMBCONN_MAX_DOMAIN_CHARS         256
#define SMBCONN_MAX_PASSWORD_CHARS       256

#define SMBCONN_CTL_CODE(f) CTL_CODE(FILE_DEVICE_NETWORK_FILE_SYSTEM, 0xB00 | (f), METHOD_BUFFERED, FILE_ANY_ACCESS)

/* out: SMBCONN_ENUM_OUTPUT (+ strings); STATUS_BUFFER_OVERFLOW with Needed set when too small */
#define IOCTL_SMBCONN_ENUM               SMBCONN_CTL_CODE(1)
/* in: SMBCONN_DELETE_INPUT */
#define IOCTL_SMBCONN_DELETE             SMBCONN_CTL_CODE(2)

/* SMBCONN_ENTRY.Flags */
#define SMBCONN_FLAG_TREE_CONNECTED      0x00000001  /* made by a tree connect (net use), not by a UNC open */
#define SMBCONN_FLAG_EXPLICIT            0x00000002  /* explicit credentials (or those of another connection to the server) */
#define SMBCONN_FLAG_CONNECTED           0x00000004  /* the engine has a session for it now */

typedef struct _SMBCONN_ENTRY
{
    ULONGLONG Id;               /* for IOCTL_SMBCONN_DELETE */
    ULONG Flags;
    WCHAR Local;                /* drive letter, 0 = none */
    USHORT Reserved;
    ULONG RemoteOffset;         /* "\\server\share[\path]", from the start of the output, bytes */
    ULONG RemoteLength;
    ULONG UserOffset;           /* "DOMAIN\user" or "user"; empty = the caller's own (single sign-on) */
    ULONG UserLength;
} SMBCONN_ENTRY, *PSMBCONN_ENTRY;

typedef struct _SMBCONN_ENUM_OUTPUT
{
    ULONG Count;
    ULONG Needed;               /* bytes needed for the whole list */
    SMBCONN_ENTRY Entries[1];
} SMBCONN_ENUM_OUTPUT, *PSMBCONN_ENUM_OUTPUT;

#define SMBCONN_DELETE_FORCE             0x00000001  /* close open files (WNetCancelConnection2 fForce) */

typedef struct _SMBCONN_DELETE_INPUT
{
    ULONGLONG Id;
    ULONG Flags;
    ULONG Reserved;
} SMBCONN_DELETE_INPUT, *PSMBCONN_DELETE_INPUT;

/*
 * Machine switch of the client (administrators only: the Services key):
 * HKLM\SYSTEM\CurrentControlSet\Services\smbengine\Parameters, ClientEnabled (REG_DWORD).
 * 0 or absent = the SMB client stays off (nothing loads it); 1 = the Workstation service
 * loads mrxsmb at its start and starts the engine service when the redirector first needs it.
 */
#define SMBCONN_SWITCH_KEY               L"SYSTEM\\CurrentControlSet\\Services\\smbengine\\Parameters"
#define SMBCONN_SWITCH_VALUE             L"ClientEnabled"

#endif /* _NITRO_SMBCONN_H_ */
