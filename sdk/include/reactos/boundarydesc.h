/*
 * PROJECT:     ReactOS headers
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     The layout of a boundary descriptor between kernel32 and the private namespace system calls
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * The layout is ours (the one Windows passes to NtCreatePrivateNamespace is not documented): one block, no pointers
 * (so a WoW64 caller passes it as it is), a header and then entries, each a multiple of 4 bytes long. kernel32's
 * CreateBoundaryDescriptor hands out the block itself as the descriptor; AddSIDToBoundaryDescriptor and
 * AddIntegrityLabelToBoundaryDescriptor grow it (they take a pointer to the handle for that).
 */

#pragma once

#define BOUNDARY_DESCRIPTOR_VERSION     0x4E424431  /* 'NBD1' */
#define BOUNDARY_DESCRIPTOR_MAX_SIZE    0x2000      /* the header and every entry */

#define BOUNDARY_ENTRY_NAME             1           /* the name, WCHARs without a terminating null; exactly one */
#define BOUNDARY_ENTRY_SID              2           /* a SID the creator must hold */
#define BOUNDARY_ENTRY_INTEGRITY_LABEL  3           /* a SID whose last sub-authority is the level; at most one */

typedef struct _BOUNDARY_DESCRIPTOR_HEADER
{
    ULONG Version;      /* BOUNDARY_DESCRIPTOR_VERSION */
    ULONG TotalSize;    /* the header and every entry */
    ULONG Flags;        /* as given to CreateBoundaryDescriptor */
    ULONG EntryCount;
} BOUNDARY_DESCRIPTOR_HEADER, *PBOUNDARY_DESCRIPTOR_HEADER;

typedef struct _BOUNDARY_DESCRIPTOR_ENTRY
{
    ULONG Type;         /* BOUNDARY_ENTRY_* */
    ULONG Size;         /* this header and the data, rounded up to a multiple of 4 */
    ULONG DataSize;     /* the bytes of the data (WCHARs of the name, the SID) */
    /* the data follows */
} BOUNDARY_DESCRIPTOR_ENTRY, *PBOUNDARY_DESCRIPTOR_ENTRY;
