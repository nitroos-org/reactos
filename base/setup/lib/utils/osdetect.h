/*
 * PROJECT:     ReactOS Setup Library
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     NT 5.x family (MS Windows <= 2003, and ReactOS)
 *              operating systems detection code.
 * COPYRIGHT:   Copyright 2017-2024 Hermès Bélusca-Maïto <hermes.belusca-maito@reactos.org>
 */

#pragma once

/* Language-independent Vendor strings */
#define VENDOR_REACTOS      L"ReactOS"
#define VENDOR_MICROSOFT    L"Microsoft"

typedef struct _NTOS_INSTALLATION
{
    LIST_ENTRY ListEntry;
// BOOLEAN IsDefault;   // TRUE / FALSE whether this installation is marked as "default" in its corresponding loader configuration file.
    USHORT Machine;                 // Target architecture of the NTOS installation
    UNICODE_STRING SystemArcPath;   // Normalized ARC path ("ArcSystemRoot")
    UNICODE_STRING SystemNtPath;    // Corresponding NT path ("NtSystemRoot")
    PCWSTR PathComponent;           // Pointer inside SystemNtPath.Buffer
    ULONG DiskNumber;
    ULONG PartitionNumber;
    PVOLENTRY Volume; // PVOLINFO
    WCHAR InstallationName[MAX_PATH];
    WCHAR VendorName[MAX_PATH];
    // CHAR Data[ANYSIZE_ARRAY];
} NTOS_INSTALLATION, *PNTOS_INSTALLATION;

/*
 * Boot entries written without GUID keys name their partition by its position only. ResolveKeylessPaths
 * decides which partition each distinct path of such entries belongs to (see osdetect.c); the answer is
 * Found: an index into Parts, or -1 when it could not be told. Holds(Context, Tail) tells whether the
 * partition holds an installation at the path Tail (starting with a backslash).
 */
#define MAX_KEYLESS_PATHS   8

typedef struct _KEYLESS_PART
{
    BOOLEAN Usable;     // could hold an installation (a GPT partition with a volume that was there before)
    BOOLEAN Claimed;    // an entry with GUID keys names it already
    PVOID Context;
} KEYLESS_PART, *PKEYLESS_PART;

typedef struct _KEYLESS_PATH
{
    PCWSTR Tail;        // the path after "partition(N)"
    LONG Stored;        // the partition at the stored position (index into Parts), or -1
    LONG Found;         // out
} KEYLESS_PATH, *PKEYLESS_PATH;

typedef BOOLEAN (NTAPI *PKEYLESS_HOLDS_ROUTINE)(_In_ PVOID Context, _In_ PCWSTR Tail);

VOID
NTAPI
ResolveKeylessPaths(
    _In_ ULONG PathCount,
    _Inout_updates_(PathCount) PKEYLESS_PATH Paths,
    _In_ ULONG PartCount,
    _Inout_updates_(PartCount) PKEYLESS_PART Parts,
    _In_ PKEYLESS_HOLDS_ROUTINE Holds);

// EnumerateNTOSInstallations
PGENERIC_LIST
NTAPI
CreateNTOSInstallationsList(
    _In_ PPARTLIST PartList);

PCWSTR
NTAPI
FindSubStrI(
    _In_ PCWSTR str,
    _In_ PCWSTR strSearch);

/* EOF */
