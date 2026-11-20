/*
 * PROJECT:     ReactOS Setup Library
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Optional components: the component list (components.inf on the
 *              installation medium), the selection (profile + per-component
 *              switches of the answer file), the file filter of the copy queue
 *              and the record of the selection on the installed system.
 */

#pragma once

#define COMPONENT_MAX           32
#define COMPONENT_ID_MAX        32

/* Profiles are presets of the per-component switches */
#define COMPONENT_PROFILE_STANDARD  0
#define COMPONENT_PROFILE_MINIMAL   1
#define COMPONENT_PROFILE_CORE      2
#define COMPONENT_PROFILE_COUNT     3

/* Explicit answer of the answer file for one component */
typedef signed char COMPONENT_CHOICE;
#define COMPONENT_UNSET     (-1)
#define COMPONENT_NO        0
#define COMPONENT_YES       1

#define COMPONENT_REG_GLOB_MAX  128    /* registry patterns of the left-out components */

/*
 * What the resolver needs to know about a component (pure data: unit-tested).
 * Bit i of a mask is the component with index i.
 */
typedef struct _COMPONENT_DESC
{
    WCHAR Id[COMPONENT_ID_MAX];
    BOOLEAN Applicable;     /* exists for this architecture */
    ULONG Profiles;         /* bit p: ON in profile p */
    ULONG Depends;          /* needs these (indexes) */
    ULONG Conflicts;        /* cannot be installed together with these */
} COMPONENT_DESC, *PCOMPONENT_DESC;

typedef struct _COMPONENTS_STATE
{
    HINF Inf;                           /* components.inf, kept open: the strings below point into it */
    ULONG Count;
    COMPONENT_DESC Desc[COMPONENT_MAX];
    ULONG Profile;
    ULONG Selected;                     /* bit i: component i is installed */
    COMPONENT_CHOICE Explicit[COMPONENT_MAX];      /* COMPONENT_UNSET / NO / YES from the answer file */
    BOOLEAN Resolved;
    BOOLEAN Record;                     /* write the record on the installed system (the answer file had a
                                           [Components] section, or something is left out) */
    BOOLEAN AnyOff;
    ULONG RegSkipped;                   /* registry lines of the hive inf files that were not added (left-out components) */
    ULONG OmitRegCount;                 /* the registry patterns of the components that are left out */
    PCWSTR OmitReg[COMPONENT_REG_GLOB_MAX];
    ULONG SkippedFiles;
    ULONG TotalFiles;
} COMPONENTS_STATE, *PCOMPONENTS_STATE;


/* Pure functions (unit-tested) ****************************************************/

/* Case-insensitive wildcard match: '*' = any run of characters (also '\'), '?' = one character */
BOOLEAN
NTAPI
ComponentGlobMatch(
    _In_ PCWSTR Pattern,
    _In_ PCWSTR Path);

/* "standard", "minimal", "core" (any case) */
BOOLEAN
NTAPI
ComponentParseProfile(
    _In_ PCWSTR Name,
    _Out_ PULONG Profile);

PCWSTR
NTAPI
ComponentProfileName(
    _In_ ULONG Profile);

/* One "id = yes|no" line of the answer file */
typedef enum _COMPONENT_ANSWER
{
    COMPONENT_ANSWER_OK,
    COMPONENT_ANSWER_UNKNOWN,   /* no such id */
    COMPONENT_ANSWER_NOT_HERE,  /* the id exists, not for this architecture */
    COMPONENT_ANSWER_BAD        /* the value is not yes/no */
} COMPONENT_ANSWER;

COMPONENT_ANSWER
NTAPI
ComponentSetAnswer(
    _In_ ULONG Count,
    _In_reads_(Count) const COMPONENT_DESC *Desc,
    _Inout_updates_(Count) COMPONENT_CHOICE *Explicit,
    _In_ PCWSTR Key,
    _In_ PCWSTR Value);

/*
 * Compute the set of installed components from the profile and the explicit answers.
 * Rules (documented in the user page): an explicit "no" always wins; a component
 * whose dependency is off because of the profile only gets the dependency turned on;
 * a component whose dependency is explicitly off (or does not exist for this
 * architecture) is left out; of two conflicting components the later one in the list
 * is left out, unless only the earlier one was asked for by the profile.
 * Every correction is logged (SetupLogFormat).
 */
ULONG
NTAPI
ComponentsResolve(
    _In_ ULONG Count,
    _In_reads_(Count) const COMPONENT_DESC *Desc,
    _In_ ULONG Profile,
    _In_reads_(Count) const COMPONENT_CHOICE *Explicit);

/* index of Id in Desc (case-insensitive), -1 if none */
LONG
NTAPI
ComponentFindIndex(
    _In_ ULONG Count,
    _In_reads_(Count) const COMPONENT_DESC *Desc,
    _In_ PCWSTR Id);


/* Loading and use by setup *********************************************************/

/* Open components.inf in SourcePath and read the list; NULL if there is none */
PCOMPONENTS_STATE
NTAPI
ComponentsLoad(
    _In_ PCWSTR SourcePath,
    _In_ LCID LocaleId);

/*
 * Read [Components] of the answer file (Profile and per-component yes/no), resolve,
 * log. Unknown ids and bad values are logged and ignored.
 */
VOID
NTAPI
ComponentsApplyAnswerFile(
    _In_ PCOMPONENTS_STATE State,
    _In_ HINF AnswerInf);

/* Is the file (path relative to the installation directory, "dir\name") of a component that is left out? */
BOOLEAN
NTAPI
ComponentsIsFileOmitted(
    _In_ PCOMPONENTS_STATE State,
    _In_ PCWSTR RelativePath);

/* Features (featmgr ids) of [Features] Install= that a left-out component keeps from working; NULL if none */
PCWSTR
NTAPI
ComponentsFeatureBlockedBy(
    _In_ PCOMPONENTS_STATE State,
    _In_ PCWSTR FeatureId);

/* Is the directory (relative to the installation directory) only there for files of components that are left out?
 * (A file of the directory would match a pattern of a left-out component.) Such a directory is not created. */
BOOLEAN
NTAPI
ComponentsIsDirectoryOmitted(
    _In_ PCOMPONENTS_STATE State,
    _In_ PCWSTR RelativeDir);

/* A line of a hive inf file (Root "HKLM", Key, optional value name): does a left-out component own it? Matched
 * against "Root\Key" (the whole key) and "Root\Key|Value" (one value) with the Registry= patterns of components.inf */
BOOLEAN
NTAPI
ComponentsIsRegistryOmitted(
    _In_ PCOMPONENTS_STATE State,
    _In_ PCWSTR Root,
    _In_ PCWSTR Key,
    _In_opt_ PCWSTR Value);

/* An update or repair of an installed system: read what the installation recorded
 * (<installation directory>\Panther\components.txt) and apply the same selection to the files of the medium.
 * Returns NULL (nothing recorded: install everything as always). */
PCOMPONENTS_STATE
NTAPI
ComponentsLoadRecorded(
    _In_ PCWSTR SourcePath,
    _In_ LCID LocaleId,
    _In_ PCWSTR InstallationDirectory);

/* After the hives are built: apply the registry lines of the left-out components and of the profile,
 * and record the selection under HKLM\SOFTWARE\ReactOS\Nitro\Components */
BOOLEAN
NTAPI
ComponentsApplyRegistry(
    _In_ PCOMPONENTS_STATE State);

/* After the files are copied: <installation directory>\Panther\components.txt */
NTSTATUS
NTAPI
ComponentsWriteManifest(
    _In_ PCOMPONENTS_STATE State,
    _In_ PCWSTR DestinationPath,
    _In_ PCWSTR SourcePath);
