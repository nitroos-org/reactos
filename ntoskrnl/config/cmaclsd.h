/*
 * PROJECT:     NitroOS
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Configuration Manager - the verdict on a stored key descriptor of a per-user hive
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#pragma once

/*
 * Why a stored descriptor in a per-user hive was not set by the hive's own
 * account or the system (the reasons a check after the transition to
 * enforcement replaces it). The first bits are the machine transition's
 * (cmacl.c CMP_ACL_PLANTED_*) with the same meaning.
 */
#define CMP_ACL_UH_OWNER        0x0001  /* no owner, or an owner outside the trusted set */
#define CMP_ACL_UH_WRITE        0x0002  /* a write right for an untrusted SID; a NULL or missing DACL */
#define CMP_ACL_UH_ACETYPE      0x0008  /* an allow ACE of a type the kernel never stores on a key, or malformed */
#define CMP_ACL_UH_READ         0x0080  /* a read right for a SID outside the read-trusted set */
#define CMP_ACL_UH_DENY         0x0100  /* a deny ACE for the account itself, SYSTEM, Administrators or a group every logon holds */
#define CMP_ACL_UH_LABEL        0x0200  /* a mandatory label above Medium */

/* Where the key is (Place): rules that depend on it */
#define CMP_ACL_UH_PLACE_ROOT           0x1     /* the hive's root key */
#define CMP_ACL_UH_PLACE_APPCONTAINER   0x2     /* below ...\AppContainer\Storage or ...\AppContainer\Mappings */

ULONG
NTAPI
CmpAclUserHiveSdVerdict(
    _In_ PSECURITY_DESCRIPTOR Sd,
    _In_ PSID OwnSid,
    _In_ ULONG Place,
    _In_ PGENERIC_MAPPING Mapping,
    _Out_opt_ PSID *Owner);
