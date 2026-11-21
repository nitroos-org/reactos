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
#define COMPONENT_GLOB_MAX      256

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
    WCHAR MediumId[24];                 /* identity of the installation medium (ReadMediumId), recorded for adding components later */
    ULONG RegSkipped;                   /* registry lines of the hive inf files that were not added (left-out components) */
    ULONG OmitRegCount;                 /* the registry patterns of the components that are left out */
    PCWSTR OmitReg[COMPONENT_REG_GLOB_MAX];
    ULONG SkippedFiles;
    ULONG TotalFiles;

    /* Sizes (the interactive page): every file of the medium that belongs to at least one component, with
     * the mask of the components it belongs to and its size; read from the cabinet inf by ComponentsMeasure */
    BOOLEAN SizesKnown;
    ULONG FileCount;
    ULONG FileCapacity;
    PULONG FileMask;
    PULONGLONG FileBytes;
    ULONGLONG OwnBytes[COMPONENT_MAX];  /* bytes of all files that belong to component i */
    ULONG GlobCount;                    /* the file patterns of every component, for ComponentsAddFile */
    PCWSTR Glob[COMPONENT_GLOB_MAX];
    UCHAR GlobOwner[COMPONENT_GLOB_MAX];
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


/* The interactive choice (text mode setup page) ***********************************/

/* Result of ComponentsToggle */
#define COMPONENT_TOGGLE_OK             0
#define COMPONENT_TOGGLE_NOT_HERE       1   /* the component does not exist in this edition */
#define COMPONENT_TOGGLE_NEEDS_MISSING  2   /* it needs a component that does not exist in this edition */

/*
 * Turn one component on or off in a selection (a mask) the way the person at the keyboard does: turning a
 * component on turns on what it needs, turning one off turns off everything that needs it (and, when something
 * is turned on that conflicts with a selected component, that one goes). AlsoOn / AlsoOff report which other
 * components changed, so that the page can say so. The result is a selection that ComponentsResolve leaves as it is.
 * On failure the selection is unchanged.
 */
ULONG
NTAPI
ComponentsToggle(
    _In_ ULONG Count,
    _In_reads_(Count) const COMPONENT_DESC *Desc,
    _In_ ULONG Selected,
    _In_ ULONG Index,
    _In_ BOOLEAN On,
    _Out_ PULONG NewSelected,
    _Out_ PULONG AlsoOn,
    _Out_ PULONG AlsoOff);

/* Mask of the components that exist in this edition */
ULONG
NTAPI
ComponentsApplicableMask(
    _In_ ULONG Count,
    _In_reads_(Count) const COMPONENT_DESC *Desc);

/* Record a file of the medium (path relative to the installation directory, size in bytes): which components it
 * belongs to is decided by their patterns (State->Glob). Files that belong to no component are not kept. */
VOID
NTAPI
ComponentsAddFile(
    _Inout_ PCOMPONENTS_STATE State,
    _In_ PCWSTR RelativePath,
    _In_ ULONGLONG Bytes);

/* Bytes that are not installed when only the components in Selected are: the files of every component that exists
 * in this edition and is not in Selected (a file shared by two components counts once). */
ULONGLONG
NTAPI
ComponentsBytesLeftOut(
    _In_ PCOMPONENTS_STATE State,
    _In_ ULONG Selected);

/* The profile and the selection chosen on the page: becomes the selection of the installation (the same state as an
 * answer file leaves: resolved, logged, file filter built). Returns TRUE if anything is left out or the profile is
 * not "standard", that is, if the record is written; FALSE means: install everything, as without the page. */
BOOLEAN
NTAPI
ComponentsSetChoice(
    _Inout_ PCOMPONENTS_STATE State,
    _In_ ULONG Profile,
    _In_ ULONG Selected);

/* Selection of a profile alone (the preset, resolved) */
ULONG
NTAPI
ComponentsProfileSelection(
    _In_ PCOMPONENTS_STATE State,
    _In_ ULONG Profile);

/* [Strings]-expanded text of key (Description, Compat) of component Index, or of the profile (ProfileText) */
PCWSTR
NTAPI
ComponentsGetText(
    _In_ PCOMPONENTS_STATE State,
    _In_ ULONG Index,
    _In_ PCWSTR Key,
    _Out_writes_(Size) PWSTR Buffer,
    _In_ ULONG Size);

PCWSTR
NTAPI
ComponentsGetProfileText(
    _In_ PCOMPONENTS_STATE State,
    _In_ ULONG Profile,
    _In_ ULONG Field,   /* 1 = name, 2 = description */
    _Out_writes_(Size) PWSTR Buffer,
    _In_ ULONG Size);

PCWSTR
NTAPI
ComponentsGetName(
    _In_ PCOMPONENTS_STATE State,
    _In_ ULONG Index,
    _Out_writes_(Size) PWSTR Buffer,
    _In_ ULONG Size);

/* Release the state (an interactive choice that left everything on installs as without the page) */
VOID
NTAPI
ComponentsFree(
    _In_opt_ PCOMPONENTS_STATE State);
