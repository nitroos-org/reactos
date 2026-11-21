/*
 * PROJECT:     ReactOS Setup Library
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Optional components: the component list (components.inf on the
 *              installation medium), the selection (profile + per-component
 *              switches of the answer file), the file filter of the copy queue
 *              and the record of the selection on the installed system.
 *
 *              Nothing here runs unless the answer file has a [Components]
 *              section: a default installation never opens components.inf.
 */

/* INCLUDES *****************************************************************/

#include "precomp.h"
#include "filesup.h"
#include "infsupp.h"
#include "registry.h"

#include "setuplib.h"
#include "components.h"

#define NDEBUG
#include <debug.h>

/* GLOBALS ******************************************************************/

/* Lines of the answer file's [Components] that are logged one by one when they cannot be used */
#define COMPONENT_LOG_PROBLEMS  12

static PCWSTR ProfileNames[COMPONENT_PROFILE_COUNT] = { L"standard", L"minimal", L"core" };

/* The patterns of the components that are left out, built once after the resolution */
static PCWSTR OmitGlobs[COMPONENT_GLOB_MAX];
static ULONG OmitGlobCount = 0;

#define COMPONENTS_REG_KEY  L"SOFTWARE\\ReactOS\\Nitro\\Components"

/* PURE FUNCTIONS ***********************************************************/

BOOLEAN
NTAPI
ComponentGlobMatch(
    _In_ PCWSTR Pattern,
    _In_ PCWSTR Path)
{
    PCWSTR StarPattern = NULL, StarPath = NULL;

    while (*Path)
    {
        if (*Pattern == L'*')
        {
            StarPattern = ++Pattern;
            StarPath = Path;
        }
        else if (*Pattern == L'?' ||
                 (*Pattern && RtlUpcaseUnicodeChar(*Pattern) == RtlUpcaseUnicodeChar(*Path)))
        {
            ++Pattern;
            ++Path;
        }
        else if (StarPattern)
        {
            /* Let the last '*' take one more character */
            Pattern = StarPattern;
            Path = ++StarPath;
        }
        else
        {
            return FALSE;
        }
    }
    while (*Pattern == L'*')
        ++Pattern;
    return (*Pattern == UNICODE_NULL);
}

BOOLEAN
NTAPI
ComponentParseProfile(
    _In_ PCWSTR Name,
    _Out_ PULONG Profile)
{
    ULONG i;
    SIZE_T Length;

    while (*Name == L' ' || *Name == L'\t')
        ++Name;
    Length = wcslen(Name);
    while (Length && (Name[Length - 1] == L' ' || Name[Length - 1] == L'\t'))
        --Length;
    for (i = 0; i < COMPONENT_PROFILE_COUNT; ++i)
    {
        if (Length == wcslen(ProfileNames[i]) && !_wcsnicmp(Name, ProfileNames[i], Length))
        {
            *Profile = i;
            return TRUE;
        }
    }
    /* "core-like" is the name the study used for the same profile */
    if (Length == 9 && !_wcsnicmp(Name, L"core-like", 9))
    {
        *Profile = COMPONENT_PROFILE_CORE;
        return TRUE;
    }
    return FALSE;
}

PCWSTR
NTAPI
ComponentProfileName(
    _In_ ULONG Profile)
{
    return (Profile < COMPONENT_PROFILE_COUNT) ? ProfileNames[Profile] : ProfileNames[0];
}

LONG
NTAPI
ComponentFindIndex(
    _In_ ULONG Count,
    _In_reads_(Count) const COMPONENT_DESC *Desc,
    _In_ PCWSTR Id)
{
    ULONG i;

    for (i = 0; i < Count; ++i)
    {
        if (!_wcsicmp(Desc[i].Id, Id))
            return (LONG)i;
    }
    return -1;
}

COMPONENT_ANSWER
NTAPI
ComponentSetAnswer(
    _In_ ULONG Count,
    _In_reads_(Count) const COMPONENT_DESC *Desc,
    _Inout_updates_(Count) COMPONENT_CHOICE *Explicit,
    _In_ PCWSTR Key,
    _In_ PCWSTR Value)
{
    LONG Id, Flag;

    Id = ComponentFindIndex(Count, Desc, Key);
    if (Id < 0)
        return COMPONENT_ANSWER_UNKNOWN;
    if (!Desc[Id].Applicable)
        return COMPONENT_ANSWER_NOT_HERE;
    if (!UnattendParseBool(Value, &Flag))
        return COMPONENT_ANSWER_BAD;
    Explicit[Id] = (COMPONENT_CHOICE)(Flag ? COMPONENT_YES : COMPONENT_NO);
    return COMPONENT_ANSWER_OK;
}

ULONG
NTAPI
ComponentsResolve(
    _In_ ULONG Count,
    _In_reads_(Count) const COMPONENT_DESC *Desc,
    _In_ ULONG Profile,
    _In_reads_(Count) const COMPONENT_CHOICE *Explicit)
{
    ULONG Selected = 0, Dropped = 0, Pass, i, k;
    BOOLEAN Changed;

    if (Count > COMPONENT_MAX)
        Count = COMPONENT_MAX;
    if (Profile >= COMPONENT_PROFILE_COUNT)
        Profile = COMPONENT_PROFILE_STANDARD;

    /* 1. The profile, then the explicit answers on top */
    for (i = 0; i < Count; ++i)
    {
        if (!Desc[i].Applicable)
            continue;
        if (Explicit[i] == COMPONENT_YES)
            Selected |= (1UL << i);
        else if (Explicit[i] == COMPONENT_UNSET && (Desc[i].Profiles & (1UL << Profile)))
            Selected |= (1UL << i);
    }

    /* 2. Dependencies and conflicts, until nothing changes (a correction can cause another) */
    for (Pass = 0; Pass < 2 * Count + 2; ++Pass)
    {
        Changed = FALSE;

        for (i = 0; i < Count; ++i)
        {
            if (!(Selected & (1UL << i)))
                continue;
            for (k = 0; k < Count; ++k)
            {
                if (!(Desc[i].Depends & (1UL << k)) || (Selected & (1UL << k)))
                    continue;

                if (Desc[k].Applicable && Explicit[k] != COMPONENT_NO && !(Dropped & (1UL << k)))
                {
                    /* Off only because of the profile: the dependency comes with it */
                    Selected |= (1UL << k);
                    SetupLogFormat("component %S needs %S: %S is installed too", Desc[i].Id, Desc[k].Id, Desc[k].Id);
                }
                else
                {
                    /* The dependency was refused (or cannot exist): the dependent goes */
                    Selected &= ~(1UL << i);
                    Dropped |= (1UL << i);
                    SetupLogFormat("component %S needs %S which is left out: %S is left out too",
                                   Desc[i].Id, Desc[k].Id, Desc[i].Id);
                }
                Changed = TRUE;
                break;
            }
        }

        for (i = 0; i < Count; ++i)
        {
            for (k = i + 1; k < Count; ++k)
            {
                ULONG Victim;

                if (!(Selected & (1UL << i)) || !(Selected & (1UL << k)))
                    continue;
                if (!((Desc[i].Conflicts & (1UL << k)) || (Desc[k].Conflicts & (1UL << i))))
                    continue;

                /* The later one in the list is left out, unless only the earlier one was asked for */
                Victim = k;
                if (Explicit[i] == COMPONENT_YES && Explicit[k] != COMPONENT_YES)
                    Victim = k;
                else if (Explicit[k] == COMPONENT_YES && Explicit[i] != COMPONENT_YES)
                    Victim = i;
                Selected &= ~(1UL << Victim);
                Dropped |= (1UL << Victim);
                SetupLogFormat("components %S and %S cannot be installed together: %S is left out",
                               Desc[i].Id, Desc[k].Id, Desc[Victim].Id);
                Changed = TRUE;
            }
        }

        if (!Changed)
            break;
    }

    return Selected;
}

ULONG
NTAPI
ComponentsApplicableMask(
    _In_ ULONG Count,
    _In_reads_(Count) const COMPONENT_DESC *Desc)
{
    ULONG Mask = 0, i;

    if (Count > COMPONENT_MAX)
        Count = COMPONENT_MAX;
    for (i = 0; i < Count; ++i)
    {
        if (Desc[i].Applicable)
            Mask |= (1UL << i);
    }
    return Mask;
}

/* Everything that (transitively) needs a component that is not selected goes; returns what went */
static ULONG
DropOrphans(
    _In_ ULONG Count,
    _In_reads_(Count) const COMPONENT_DESC *Desc,
    _Inout_ PULONG Selected)
{
    ULONG Dropped = 0, i;
    BOOLEAN Changed;

    do
    {
        Changed = FALSE;
        for (i = 0; i < Count; ++i)
        {
            if ((*Selected & (1UL << i)) && (Desc[i].Depends & ~*Selected))
            {
                *Selected &= ~(1UL << i);
                Dropped |= (1UL << i);
                Changed = TRUE;
            }
        }
    } while (Changed);
    return Dropped;
}

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
    _Out_ PULONG AlsoOff)
{
    ULONG Sel = Selected, Applicable, NewlyOn, On2 = 0, Off2 = 0, i, k;
    BOOLEAN Changed;

    *NewSelected = Selected;
    *AlsoOn = 0;
    *AlsoOff = 0;
    if (Count > COMPONENT_MAX)
        Count = COMPONENT_MAX;
    if (Index >= Count || !Desc[Index].Applicable)
        return COMPONENT_TOGGLE_NOT_HERE;
    Applicable = ComponentsApplicableMask(Count, Desc);

    if (!On)
    {
        Sel &= ~(1UL << Index);
        Off2 = DropOrphans(Count, Desc, &Sel);
        *NewSelected = Sel;
        *AlsoOff = Off2;
        return COMPONENT_TOGGLE_OK;
    }

    /* On: what it needs comes with it, to the end of the chain */
    Sel |= (1UL << Index);
    NewlyOn = (1UL << Index);
    do
    {
        Changed = FALSE;
        for (i = 0; i < Count; ++i)
        {
            if (!(NewlyOn & (1UL << i)))
                continue;
            for (k = 0; k < Count; ++k)
            {
                if (!(Desc[i].Depends & (1UL << k)) || (Sel & (1UL << k)))
                    continue;
                if (!(Applicable & (1UL << k)))
                    return COMPONENT_TOGGLE_NEEDS_MISSING;
                Sel |= (1UL << k);
                NewlyOn |= (1UL << k);
                On2 |= (1UL << k);
                Changed = TRUE;
            }
        }
    } while (Changed);

    /* a component that was selected before and conflicts with one that is turned on goes (and what needs it) */
    for (i = 0; i < Count; ++i)
    {
        if (!(NewlyOn & (1UL << i)))
            continue;
        for (k = 0; k < Count; ++k)
        {
            if ((Selected & (1UL << k)) && !(NewlyOn & (1UL << k)) &&
                ((Desc[i].Conflicts & (1UL << k)) || (Desc[k].Conflicts & (1UL << i))))
            {
                Sel &= ~(1UL << k);
                Off2 |= (1UL << k);
            }
        }
    }
    Off2 |= DropOrphans(Count, Desc, &Sel);
    /* the request itself cannot stand (what it needs conflicts with another thing it needs): refuse it */
    if (!(Sel & (1UL << Index)))
        return COMPONENT_TOGGLE_NEEDS_MISSING;
    On2 &= Sel;

    *NewSelected = Sel;
    *AlsoOn = On2;
    *AlsoOff = Off2;
    return COMPONENT_TOGGLE_OK;
}

VOID
NTAPI
ComponentsAddFile(
    _Inout_ PCOMPONENTS_STATE State,
    _In_ PCWSTR RelativePath,
    _In_ ULONGLONG Bytes)
{
    ULONG Mask = 0, i;

    for (i = 0; i < State->GlobCount; ++i)
    {
        if (ComponentGlobMatch(State->Glob[i], RelativePath))
            Mask |= (1UL << State->GlobOwner[i]);
    }
    if (!Mask)
        return;

    if (State->FileCount >= State->FileCapacity)
    {
        ULONG NewCapacity = State->FileCapacity ? State->FileCapacity * 2 : 512;
        PULONG NewMask = RtlAllocateHeap(RtlGetProcessHeap(), 0, NewCapacity * sizeof(ULONG));
        PULONGLONG NewBytes = RtlAllocateHeap(RtlGetProcessHeap(), 0, NewCapacity * sizeof(ULONGLONG));

        if (!NewMask || !NewBytes)
        {
            if (NewMask) RtlFreeHeap(RtlGetProcessHeap(), 0, NewMask);
            if (NewBytes) RtlFreeHeap(RtlGetProcessHeap(), 0, NewBytes);
            return;
        }
        if (State->FileCount)
        {
            RtlCopyMemory(NewMask, State->FileMask, State->FileCount * sizeof(ULONG));
            RtlCopyMemory(NewBytes, State->FileBytes, State->FileCount * sizeof(ULONGLONG));
        }
        if (State->FileMask) RtlFreeHeap(RtlGetProcessHeap(), 0, State->FileMask);
        if (State->FileBytes) RtlFreeHeap(RtlGetProcessHeap(), 0, State->FileBytes);
        State->FileMask = NewMask;
        State->FileBytes = NewBytes;
        State->FileCapacity = NewCapacity;
    }
    State->FileMask[State->FileCount] = Mask;
    State->FileBytes[State->FileCount] = Bytes;
    State->FileCount++;

    for (i = 0; i < COMPONENT_MAX; ++i)
    {
        if (Mask & (1UL << i))
            State->OwnBytes[i] += Bytes;
    }
}

ULONGLONG
NTAPI
ComponentsBytesLeftOut(
    _In_ PCOMPONENTS_STATE State,
    _In_ ULONG Selected)
{
    ULONGLONG Total = 0;
    ULONG Off = ComponentsApplicableMask(State->Count, State->Desc) & ~Selected;
    ULONG i;

    for (i = 0; i < State->FileCount; ++i)
    {
        if (State->FileMask[i] & Off)
            Total += State->FileBytes[i];
    }
    return Total;
}


/* INF LOADING **************************************************************/

/* The value of field Index (1 = first value) of Key in Section; NULL if absent or empty */
static PCWSTR
GetKeyField(
    _In_ HINF Inf,
    _In_ PCWSTR Section,
    _In_ PCWSTR Key,
    _In_ ULONG Index)
{
    INFCONTEXT Context;
    PCWSTR Value;

    if (!SpInfFindFirstLine(Inf, Section, Key, &Context))
        return NULL;
    if (!INF_GetDataField(&Context, Index, &Value) || !*Value)
        return NULL;
    return Value;
}

/* A comma separated list of ids into a mask of component indexes */
static ULONG
ReadIdMask(
    _In_ PCOMPONENTS_STATE State,
    _In_ PCWSTR Section,
    _In_ PCWSTR Key)
{
    ULONG Mask = 0, Index;
    PCWSTR Value;

    for (Index = 1; (Value = GetKeyField(State->Inf, Section, Key, Index)) != NULL; ++Index)
    {
        LONG Id = ComponentFindIndex(State->Count, State->Desc, Value);
        if (Id >= 0)
            Mask |= (1UL << Id);
        else
            DPRINT1("components.inf: [%S] %S names the unknown component '%S'\n", Section, Key, Value);
    }
    return Mask;
}

/*
 * A short identity of the installation medium: size, number of files and set id from the header of its first
 * cabinet (reactos.cab). Two builds of the system do not have the same one. It is recorded with the selection
 * so that a component added later is taken from the medium it belongs to (an empty string: not readable).
 */
static VOID
ReadMediumId(
    _In_ PCWSTR SourcePath,
    _Out_writes_(Size) PWSTR Id,
    _In_ ULONG Size)
{
    WCHAR Path[MAX_PATH];
    UNICODE_STRING FileName;
    OBJECT_ATTRIBUTES ObjectAttributes;
    IO_STATUS_BLOCK IoStatusBlock;
    HANDLE FileHandle;
    UCHAR Header[36];
    NTSTATUS Status;

    Id[0] = UNICODE_NULL;
    if (!NT_SUCCESS(CombinePaths(Path, ARRAYSIZE(Path), 2, SourcePath, L"reactos.cab")))
        return;
    RtlInitUnicodeString(&FileName, Path);
    InitializeObjectAttributes(&ObjectAttributes, &FileName, OBJ_CASE_INSENSITIVE, NULL, NULL);
    Status = NtCreateFile(&FileHandle, FILE_READ_DATA | SYNCHRONIZE, &ObjectAttributes, &IoStatusBlock,
                          NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN,
                          FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
    if (!NT_SUCCESS(Status))
        return;
    Status = NtReadFile(FileHandle, NULL, NULL, NULL, &IoStatusBlock, Header, sizeof(Header), NULL, NULL);
    NtClose(FileHandle);
    if (!NT_SUCCESS(Status) || IoStatusBlock.Information < sizeof(Header) || RtlCompareMemory(Header, "MSCF", 4) != 4)
        return;
    /* CFHEADER: cbCabinet at 8, cFiles at 28, setID at 32 (little endian) */
    RtlStringCchPrintfW(Id, Size, L"%08lx-%04x-%04x",
                        *(UNALIGNED ULONG *)&Header[8], *(UNALIGNED USHORT *)&Header[28], *(UNALIGNED USHORT *)&Header[32]);
}

PCOMPONENTS_STATE
NTAPI
ComponentsLoad(
    _In_ PCWSTR SourcePath,
    _In_ LCID LocaleId)
{
    PCOMPONENTS_STATE State;
    WCHAR Path[MAX_PATH];
    INFCONTEXT Context;
    UINT ErrorLine;
    PCWSTR Value;
    ULONG i, Index;
    BOOLEAN Ok;

    if (!NT_SUCCESS(CombinePaths(Path, ARRAYSIZE(Path), 2, SourcePath, L"components.inf")))
        return NULL;
    if (!DoesFileExist(NULL, Path))
        return NULL;

    State = RtlAllocateHeap(RtlGetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*State));
    if (!State)
        return NULL;

    State->Inf = SpInfOpenInfFile(Path, NULL, INF_STYLE_WIN4, LocaleId, &ErrorLine);
    if (State->Inf == INVALID_HANDLE_VALUE)
    {
        DPRINT1("components.inf: cannot open '%S' (line %u)\n", Path, ErrorLine);
        RtlFreeHeap(RtlGetProcessHeap(), 0, State);
        return NULL;
    }
    ReadMediumId(SourcePath, State->MediumId, ARRAYSIZE(State->MediumId));

    /* The ids first: Depends and Conflicts refer to them */
    Ok = SpInfFindFirstLine(State->Inf, L"Components", NULL, &Context);
    for (; Ok && State->Count < COMPONENT_MAX; Ok = SpInfFindNextLine(&Context, &Context))
    {
        if (!INF_GetDataField(&Context, 0, &Value) || !*Value || wcslen(Value) >= COMPONENT_ID_MAX)
            continue;
        RtlStringCchCopyW(State->Desc[State->Count].Id, COMPONENT_ID_MAX, Value);
        State->Count++;
    }
    if (Ok)
    {
        /* The masks hold COMPONENT_MAX components: the rest of the list cannot be used. Say so (a medium that lists
         * more components than this Setup can handle would otherwise install them all without a word) */
        ULONG More = 0;

        for (; Ok; Ok = SpInfFindNextLine(&Context, &Context))
            ++More;
        SetupLogFormat("components.inf lists more than %lu components: the last %lu are ignored (always installed)",
                       (ULONG)COMPONENT_MAX, More);
    }

    /* A file without a component list (empty, or not a components.inf) is as good as none: nothing is left out,
     * nothing is recorded */
    if (!State->Count)
    {
        DPRINT1("components.inf: '%S' lists no component\n", Path);
        SpInfCloseInfFile(State->Inf);
        RtlFreeHeap(RtlGetProcessHeap(), 0, State);
        return NULL;
    }

    for (i = 0; i < State->Count; ++i)
    {
        PCOMPONENT_DESC Desc = &State->Desc[i];

        Value = GetKeyField(State->Inf, Desc->Id, L"Arch", 1);
        Desc->Applicable = (!Value || !_wcsicmp(Value, L"any") || !_wcsicmp(Value, INF_ARCH) ||
                            (!_wcsicmp(Value, L"i386") && !_wcsicmp(INF_ARCH, L"x86")));

        for (Index = 1; (Value = GetKeyField(State->Inf, Desc->Id, L"Profiles", Index)) != NULL; ++Index)
        {
            ULONG Profile;
            if (ComponentParseProfile(Value, &Profile))
                Desc->Profiles |= (1UL << Profile);
        }
        Desc->Depends = ReadIdMask(State, Desc->Id, L"Depends");
        Desc->Conflicts = ReadIdMask(State, Desc->Id, L"Conflicts");

        /* The file patterns of every component, for the sizes (ComponentsAddFile) */
        if (Desc->Applicable)
        {
            for (Index = 1; (Value = GetKeyField(State->Inf, Desc->Id, L"Files", Index)) != NULL; ++Index)
            {
                if (State->GlobCount < COMPONENT_GLOB_MAX)
                {
                    State->Glob[State->GlobCount] = Value;
                    State->GlobOwner[State->GlobCount] = (UCHAR)i;
                    State->GlobCount++;
                }
            }
        }
    }

    return State;
}

VOID
NTAPI
ComponentsFree(
    _In_opt_ PCOMPONENTS_STATE State)
{
    if (!State)
        return;
    if (State->FileMask)
        RtlFreeHeap(RtlGetProcessHeap(), 0, State->FileMask);
    if (State->FileBytes)
        RtlFreeHeap(RtlGetProcessHeap(), 0, State->FileBytes);
    if (State->Inf && State->Inf != INVALID_HANDLE_VALUE)
        SpInfCloseInfFile(State->Inf);
    RtlFreeHeap(RtlGetProcessHeap(), 0, State);
}

/* The display name of component i, with the [Strings] tokens expanded (what the field functions return is raw) */
static PCWSTR
GetDisplayName(
    _In_ PCOMPONENTS_STATE State,
    _In_ ULONG i,
    _Out_writes_(Size) PWSTR Buffer,
    _In_ ULONG Size)
{
    INFCONTEXT Context;

    Buffer[0] = UNICODE_NULL;
    if (SpInfFindFirstLine(State->Inf, L"Components", State->Desc[i].Id, &Context))
        (void)SpInfGetStringField(&Context, 1, Buffer, Size, NULL);
    return Buffer;
}

/* The state whose registry patterns RegistryLineFilter applies (NULL: nothing is filtered) */
static PCOMPONENTS_STATE RegFilterState = NULL;

static BOOLEAN
NTAPI
RegistryLineFilter(
    _In_ PCWSTR Root,
    _In_ PCWSTR Key,
    _In_opt_ PCWSTR Value)
{
    if (RegFilterState && ComponentsIsRegistryOmitted(RegFilterState, Root, Key, Value))
    {
        RegFilterState->RegSkipped++;
        return TRUE;
    }
    return FALSE;
}

/* Collect the file patterns of the components that are left out */
static VOID
BuildOmitGlobs(
    _In_ PCOMPONENTS_STATE State)
{
    ULONG i, Index;
    PCWSTR Value;

    OmitGlobCount = 0;
    State->OmitRegCount = 0;
    RegistrySetLineFilter(RegistryLineFilter);
    for (i = 0; i < State->Count; ++i)
    {
        if (!State->Desc[i].Applicable || (State->Selected & (1UL << i)))
            continue;
        for (Index = 1; (Value = GetKeyField(State->Inf, State->Desc[i].Id, L"Files", Index)) != NULL; ++Index)
        {
            if (OmitGlobCount < COMPONENT_GLOB_MAX)
                OmitGlobs[OmitGlobCount++] = Value;
            else
                DPRINT1("components.inf: too many file patterns\n");
        }
        /* the registry lines that name programs of this component: the hive inf files are read as always, but
         * these lines are not added (there is nothing to delete later) */
        for (Index = 1; (Value = GetKeyField(State->Inf, State->Desc[i].Id, L"Registry", Index)) != NULL; ++Index)
        {
            if (State->OmitRegCount < COMPONENT_REG_GLOB_MAX)
                State->OmitReg[State->OmitRegCount++] = Value;
            else
                SetupLogFormat("components.inf: too many registry patterns (%u)", COMPONENT_REG_GLOB_MAX);
        }
    }
    RegFilterState = State->OmitRegCount ? State : NULL;
}

static VOID
CommitSelection(
    _Inout_ PCOMPONENTS_STATE State);

VOID
NTAPI
ComponentsApplyAnswerFile(
    _In_ PCOMPONENTS_STATE State,
    _In_ HINF AnswerInf)
{
    INFCONTEXT Context;
    PCWSTR Key, Value;
    BOOLEAN Ok;
    ULONG Problems = 0;

    RtlFillMemory(State->Explicit, sizeof(State->Explicit), (UCHAR)COMPONENT_UNSET);
    State->Profile = COMPONENT_PROFILE_STANDARD;
    State->Record = TRUE;

    Ok = SpInfFindFirstLine(AnswerInf, L"Components", NULL, &Context);
    for (; Ok; Ok = SpInfFindNextLine(&Context, &Context))
    {
        if (!INF_GetDataField(&Context, 0, &Key) || !*Key)
            continue;
        if (!INF_GetDataField(&Context, 1, &Value))
            Value = L"";

        if (!_wcsicmp(Key, L"Profile"))
        {
            if (!ComponentParseProfile(Value, &State->Profile))
            {
                State->Profile = COMPONENT_PROFILE_STANDARD;
                if (Problems++ < COMPONENT_LOG_PROBLEMS)
                    SetupLogLine("bad value for Profile in [Components] (standard, minimal or core expected): using standard");
            }
            continue;
        }

        /* The setup log is a small buffer that drops what does not fit: a long list of bad lines must not push out
         * the summary below, so only the first few problems are logged one by one */
        switch (ComponentSetAnswer(State->Count, State->Desc, State->Explicit, Key, Value))
        {
            case COMPONENT_ANSWER_UNKNOWN:
                if (Problems++ < COMPONENT_LOG_PROBLEMS)
                    SetupLogFormat("unknown component id \"%S\" in [Components]: ignored", Key);
                break;
            case COMPONENT_ANSWER_NOT_HERE:
                if (Problems++ < COMPONENT_LOG_PROBLEMS)
                    SetupLogFormat("component \"%S\" does not exist in this edition: ignored", Key);
                break;
            case COMPONENT_ANSWER_BAD:
                if (Problems++ < COMPONENT_LOG_PROBLEMS)
                    SetupLogFormat("bad value for component %S (yes or no expected): ignored", Key);
                break;
            default:
                break;
        }
    }
    if (Problems > COMPONENT_LOG_PROBLEMS)
        SetupLogFormat("[Components]: %lu more lines were ignored (not logged one by one)", Problems - COMPONENT_LOG_PROBLEMS);

    State->Selected = ComponentsResolve(State->Count, State->Desc, State->Profile, State->Explicit);
    CommitSelection(State);
}

/* The selection in State->Selected is final: log it and build the file filter */
static VOID
CommitSelection(
    _Inout_ PCOMPONENTS_STATE State)
{
    WCHAR Names[400];
    ULONG i;

    State->Resolved = TRUE;
    State->AnyOff = FALSE;

    /* The summary */
    Names[0] = UNICODE_NULL;
    for (i = 0; i < State->Count; ++i)
    {
        if (State->Desc[i].Applicable && (State->Selected & (1UL << i)))
        {
            if (Names[0]) RtlStringCchCatW(Names, ARRAYSIZE(Names), L", ");
            RtlStringCchCatW(Names, ARRAYSIZE(Names), State->Desc[i].Id);
        }
    }
    SetupLogFormat("components: profile %S, installed: %S", ComponentProfileName(State->Profile), Names[0] ? Names : L"(none)");
    Names[0] = UNICODE_NULL;
    for (i = 0; i < State->Count; ++i)
    {
        if (State->Desc[i].Applicable && !(State->Selected & (1UL << i)))
        {
            if (Names[0]) RtlStringCchCatW(Names, ARRAYSIZE(Names), L", ");
            RtlStringCchCatW(Names, ARRAYSIZE(Names), State->Desc[i].Id);
            State->AnyOff = TRUE;
        }
    }
    if (State->AnyOff)
        SetupLogFormat("components left out: %S", Names);

    BuildOmitGlobs(State);
}

BOOLEAN
NTAPI
ComponentsSetChoice(
    _Inout_ PCOMPONENTS_STATE State,
    _In_ ULONG Profile,
    _In_ ULONG Selected)
{
    ULONG i;

    if (Profile >= COMPONENT_PROFILE_COUNT)
        Profile = COMPONENT_PROFILE_STANDARD;
    State->Profile = Profile;

    /* every component gets an explicit answer: the person at the keyboard decided each one */
    for (i = 0; i < COMPONENT_MAX; ++i)
    {
        if (i >= State->Count || !State->Desc[i].Applicable)
            State->Explicit[i] = COMPONENT_UNSET;
        else
            State->Explicit[i] = (Selected & (1UL << i)) ? COMPONENT_YES : COMPONENT_NO;
    }
    State->Selected = ComponentsResolve(State->Count, State->Desc, Profile, State->Explicit);

    if (State->Selected == ComponentsApplicableMask(State->Count, State->Desc) &&
        Profile == COMPONENT_PROFILE_STANDARD)
    {
        /* Nothing left out: this is the installation without the page, in every detail (no record, no log line) */
        State->Record = FALSE;
        State->AnyOff = FALSE;
        State->Resolved = FALSE;
        return FALSE;
    }

    State->Record = TRUE;
    CommitSelection(State);
    return TRUE;
}

ULONG
NTAPI
ComponentsProfileSelection(
    _In_ PCOMPONENTS_STATE State,
    _In_ ULONG Profile)
{
    COMPONENT_CHOICE Unset[COMPONENT_MAX];

    /* "standard" is everything that exists in this edition, whatever the Profiles lines of a damaged or older
     * components.inf say: Enter on the page must never leave something out that the person did not choose */
    if (Profile == COMPONENT_PROFILE_STANDARD)
        return ComponentsApplicableMask(State->Count, State->Desc);

    RtlFillMemory(Unset, sizeof(Unset), (UCHAR)COMPONENT_UNSET);
    return ComponentsResolve(State->Count, State->Desc, Profile, Unset);
}

PCWSTR
NTAPI
ComponentsGetText(
    _In_ PCOMPONENTS_STATE State,
    _In_ ULONG Index,
    _In_ PCWSTR Key,
    _Out_writes_(Size) PWSTR Buffer,
    _In_ ULONG Size)
{
    INFCONTEXT Context;

    Buffer[0] = UNICODE_NULL;
    if (Index < State->Count &&
        SpInfFindFirstLine(State->Inf, State->Desc[Index].Id, Key, &Context))
    {
        (void)SpInfGetStringField(&Context, 1, Buffer, Size, NULL);
    }
    return Buffer;
}

PCWSTR
NTAPI
ComponentsGetProfileText(
    _In_ PCOMPONENTS_STATE State,
    _In_ ULONG Profile,
    _In_ ULONG Field,
    _Out_writes_(Size) PWSTR Buffer,
    _In_ ULONG Size)
{
    INFCONTEXT Context;

    Buffer[0] = UNICODE_NULL;
    if (SpInfFindFirstLine(State->Inf, L"ProfileText", ComponentProfileName(Profile), &Context))
        (void)SpInfGetStringField(&Context, Field, Buffer, Size, NULL);
    return Buffer;
}

PCWSTR
NTAPI
ComponentsGetName(
    _In_ PCOMPONENTS_STATE State,
    _In_ ULONG Index,
    _Out_writes_(Size) PWSTR Buffer,
    _In_ ULONG Size)
{
    return GetDisplayName(State, Index, Buffer, Size);
}

BOOLEAN
NTAPI
ComponentsIsFileOmitted(
    _In_ PCOMPONENTS_STATE State,
    _In_ PCWSTR RelativePath)
{
    ULONG i;

    State->TotalFiles++;
    for (i = 0; i < OmitGlobCount; ++i)
    {
        if (ComponentGlobMatch(OmitGlobs[i], RelativePath))
        {
            State->SkippedFiles++;
            return TRUE;
        }
    }
    return FALSE;
}

BOOLEAN
NTAPI
ComponentsIsDirectoryOmitted(
    _In_ PCOMPONENTS_STATE State,
    _In_ PCWSTR RelativeDir)
{
    WCHAR Probe[MAX_PATH];
    ULONG i;

    UNREFERENCED_PARAMETER(State);
    /* a directory the file filter would leave empty: a file of any name inside it is left out */
    if (!RelativeDir[0] || RelativeDir[0] == L'\\' ||
        FAILED(RtlStringCchPrintfW(Probe, ARRAYSIZE(Probe), L"%s\\x", RelativeDir)))
    {
        return FALSE;
    }
    for (i = 0; i < OmitGlobCount; ++i)
    {
        if (ComponentGlobMatch(OmitGlobs[i], Probe))
            return TRUE;
    }
    return FALSE;
}

BOOLEAN
NTAPI
ComponentsIsRegistryOmitted(
    _In_ PCOMPONENTS_STATE State,
    _In_ PCWSTR Root,
    _In_ PCWSTR Key,
    _In_opt_ PCWSTR Value)
{
    WCHAR KeyPath[MAX_PATH], ValuePath[MAX_PATH + 64];
    ULONG i;

    if (!State->OmitRegCount)
        return FALSE;
    if (FAILED(RtlStringCchPrintfW(KeyPath, ARRAYSIZE(KeyPath), L"%s\\%s", Root, Key)))
        return FALSE;
    ValuePath[0] = UNICODE_NULL;
    if (Value && Value[0])
        RtlStringCchPrintfW(ValuePath, ARRAYSIZE(ValuePath), L"%s|%s", KeyPath, Value);

    for (i = 0; i < State->OmitRegCount; ++i)
    {
        if (ComponentGlobMatch(State->OmitReg[i], KeyPath) ||
            (ValuePath[0] && ComponentGlobMatch(State->OmitReg[i], ValuePath)))
        {
            return TRUE;
        }
    }
    return FALSE;
}

PCWSTR
NTAPI
ComponentsFeatureBlockedBy(
    _In_ PCOMPONENTS_STATE State,
    _In_ PCWSTR FeatureId)
{
    ULONG i, Index;
    PCWSTR Value;

    for (i = 0; i < State->Count; ++i)
    {
        if (!State->Desc[i].Applicable || (State->Selected & (1UL << i)))
            continue;
        for (Index = 1; (Value = GetKeyField(State->Inf, State->Desc[i].Id, L"FeaturesNeed", Index)) != NULL; ++Index)
        {
            if (!_wcsicmp(Value, FeatureId))
                return State->Desc[i].Id;
        }
    }
    return NULL;
}


/* REGISTRY *****************************************************************/

/* "a, b, c" of the values from Index 1 on, into Buffer */
static VOID
JoinList(
    _In_ PCOMPONENTS_STATE State,
    _In_ PCWSTR Section,
    _In_ PCWSTR Key,
    _Out_writes_(Size) PWSTR Buffer,
    _In_ ULONG Size)
{
    ULONG Index;
    PCWSTR Value;

    Buffer[0] = UNICODE_NULL;
    for (Index = 1; (Value = GetKeyField(State->Inf, Section, Key, Index)) != NULL; ++Index)
    {
        if (Buffer[0])
            RtlStringCchCatW(Buffer, Size, L",");
        RtlStringCchCatW(Buffer, Size, Value);
    }
}

static VOID
SetSz(
    _In_ PCWSTR Key,
    _In_ PCWSTR Name,
    _In_ PCWSTR Text)
{
    (void)SetRegistryValue(L"HKLM", Key, Name, REG_SZ, (PVOID)Text, (ULONG)((wcslen(Text) + 1) * sizeof(WCHAR)));
}

static VOID
SetDword(
    _In_ PCWSTR Key,
    _In_ PCWSTR Name,
    _In_ ULONG Number)
{
    (void)SetRegistryValue(L"HKLM", Key, Name, REG_DWORD, &Number, sizeof(Number));
}

static VOID
GetSourceVersion(
    _Out_writes_(Size) PWSTR Buffer,
    _In_ ULONG Size)
{
    RTL_OSVERSIONINFOW Version = {sizeof(Version)};

    if (NT_SUCCESS(RtlGetVersion(&Version)))
        RtlStringCchPrintfW(Buffer, Size, L"%lu.%lu.%lu", Version.dwMajorVersion, Version.dwMinorVersion, Version.dwBuildNumber);
    else
        RtlStringCchCopyW(Buffer, Size, L"unknown");
}

BOOLEAN
NTAPI
ComponentsApplyRegistry(
    _In_ PCOMPONENTS_STATE State)
{
    WCHAR Section[COMPONENT_ID_MAX + 8];
    WCHAR Key[128];
    WCHAR List[256];
    WCHAR Version[64];
    WCHAR DisplayName[120];
    PCWSTR Text;
    ULONG i;

    if (!State || !State->Resolved)
        return TRUE;

    /* The registry lines of the components that are left out */
    for (i = 0; i < State->Count; ++i)
    {
        if (!State->Desc[i].Applicable || (State->Selected & (1UL << i)))
            continue;
        RtlStringCchPrintfW(Section, ARRAYSIZE(Section), L"%s.Off", State->Desc[i].Id);
        (void)ImportRegistrySection(State->Inf, Section);
    }
    /* and of the profile (the shell of "core") */
    RtlStringCchPrintfW(Section, ARRAYSIZE(Section), L"Profile.%s", ComponentProfileName(State->Profile));
    (void)ImportRegistrySection(State->Inf, Section);

    if (!State->Record)
        return TRUE;

    /* The record of the selection: what the later add/remove of components reads */
    GetSourceVersion(Version, ARRAYSIZE(Version));
    SetSz(COMPONENTS_REG_KEY, L"Profile", ComponentProfileName(State->Profile));
    SetSz(COMPONENTS_REG_KEY, L"SourceVersion", Version);
    if (State->MediumId[0])
        SetSz(COMPONENTS_REG_KEY, L"MediumId", State->MediumId);
    SetDword(COMPONENTS_REG_KEY, L"AnyOff", State->AnyOff ? 1 : 0);
    /* how many lines of the hive inf files were not added for the components that are left out (the setup log is
     * written before the hives are built, so it cannot say) */
    SetDword(COMPONENTS_REG_KEY, L"RegistryLinesSkipped", State->RegSkipped);

    for (i = 0; i < State->Count; ++i)
    {
        if (!State->Desc[i].Applicable)
            continue;
        RtlStringCchPrintfW(Key, ARRAYSIZE(Key), COMPONENTS_REG_KEY L"\\%s", State->Desc[i].Id);
        SetDword(Key, L"Installed", (State->Selected & (1UL << i)) ? 1 : 0);
        Text = GetDisplayName(State, i, DisplayName, ARRAYSIZE(DisplayName));
        if (Text[0])
            SetSz(Key, L"Name", Text);
        JoinList(State, State->Desc[i].Id, L"FeaturesNeed", List, ARRAYSIZE(List));
        if (List[0])
            SetSz(Key, L"FeaturesNeed", List);
        JoinList(State, State->Desc[i].Id, L"FeaturesOwn", List, ARRAYSIZE(List));
        if (List[0])
            SetSz(Key, L"FeaturesOwn", List);
    }
    return TRUE;
}

NTSTATUS
NTAPI
ComponentsWriteManifest(
    _In_ PCOMPONENTS_STATE State,
    _In_ PCWSTR DestinationPath,
    _In_ PCWSTR SourcePath)
{
    NTSTATUS Status;
    WCHAR PathBuffer[MAX_PATH];
    WCHAR Version[64];
    WCHAR DisplayName[120];
    CHAR Line[400];
    UNICODE_STRING FileName;
    OBJECT_ATTRIBUTES ObjectAttributes;
    IO_STATUS_BLOCK IoStatusBlock;
    HANDLE FileHandle;
    ULONG i;
    PCWSTR Text;

    if (!State || !State->Resolved || !State->Record)
        return STATUS_SUCCESS;

    Status = CombinePaths(PathBuffer, ARRAYSIZE(PathBuffer), 2, DestinationPath, L"Panther");
    if (!NT_SUCCESS(Status))
        return Status;
    (void)SetupCreateDirectory(PathBuffer);
    Status = CombinePaths(PathBuffer, ARRAYSIZE(PathBuffer), 2, DestinationPath, L"Panther\\components.txt");
    if (!NT_SUCCESS(Status))
        return Status;

    RtlInitUnicodeString(&FileName, PathBuffer);
    InitializeObjectAttributes(&ObjectAttributes, &FileName, OBJ_CASE_INSENSITIVE, NULL, NULL);
    Status = NtCreateFile(&FileHandle, FILE_WRITE_DATA | SYNCHRONIZE, &ObjectAttributes, &IoStatusBlock,
                          NULL, FILE_ATTRIBUTE_NORMAL, 0, FILE_OVERWRITE_IF,
                          FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("ComponentsWriteManifest: cannot create '%S' (Status 0x%08lx)\n", PathBuffer, Status);
        return Status;
    }

#define PUT(...) \
    do { \
        RtlStringCbPrintfA(Line, sizeof(Line), __VA_ARGS__); \
        NtWriteFile(FileHandle, NULL, NULL, NULL, &IoStatusBlock, Line, (ULONG)strlen(Line), NULL, NULL); \
    } while (0)

    GetSourceVersion(Version, ARRAYSIZE(Version));
    PUT("; Components of this installation (written by setup; HKLM\\SOFTWARE\\ReactOS\\Nitro\\Components holds the same)\r\n");
    PUT("[Selection]\r\nProfile=%S\r\nSourceVersion=%S\r\nSource=%S\r\n", ComponentProfileName(State->Profile), Version, SourcePath);
    PUT("FilesInQueue=%lu\r\nFilesOmitted=%lu\r\n", State->TotalFiles, State->SkippedFiles);
    PUT("\r\n[Installed]\r\n");
    for (i = 0; i < State->Count; ++i)
    {
        if (State->Desc[i].Applicable && (State->Selected & (1UL << i)))
        {
            Text = GetDisplayName(State, i, DisplayName, ARRAYSIZE(DisplayName));
            PUT("%S=%S\r\n", State->Desc[i].Id, Text);
        }
    }
    PUT("\r\n[Omitted]\r\n");
    for (i = 0; i < State->Count; ++i)
    {
        if (State->Desc[i].Applicable && !(State->Selected & (1UL << i)))
        {
            Text = GetDisplayName(State, i, DisplayName, ARRAYSIZE(DisplayName));
            PUT("%S=%S\r\n", State->Desc[i].Id, Text);
        }
    }
#undef PUT

    NtClose(FileHandle);
    return STATUS_SUCCESS;
}

static VOID
FreeRecordedState(
    _In_ PCOMPONENTS_STATE State)
{
    SpInfCloseInfFile(State->Inf);
    RtlFreeHeap(RtlGetProcessHeap(), 0, State);
}

/*
 * What an earlier installation recorded (components.txt), read without the INF parser: the display names in it
 * are free text. Section [Selection] Profile=, then [Installed] and [Omitted] with one id per line.
 */
#define RECORD_MAX  0x10000

PCOMPONENTS_STATE
NTAPI
ComponentsLoadRecorded(
    _In_ PCWSTR SourcePath,
    _In_ LCID LocaleId,
    _In_ PCWSTR InstallationDirectory)
{
    PCOMPONENTS_STATE State;
    WCHAR PathBuffer[MAX_PATH];
    UNICODE_STRING FileName;
    OBJECT_ATTRIBUTES ObjectAttributes;
    IO_STATUS_BLOCK IoStatusBlock;
    HANDLE FileHandle;
    NTSTATUS Status;
    PCHAR Buffer, Line, End, Next;
    ULONG Length, Section = 0, Profile = COMPONENT_PROFILE_STANDARD, i;
    BOOLEAN Any = FALSE;

    if (!NT_SUCCESS(CombinePaths(PathBuffer, ARRAYSIZE(PathBuffer), 2, InstallationDirectory, L"Panther\\components.txt")))
        return NULL;
    if (!DoesFileExist(NULL, PathBuffer))
        return NULL;     /* installed without a selection: everything is there */

    State = ComponentsLoad(SourcePath, LocaleId);
    if (!State)
    {
        SetupLogFormat("update: the installation recorded a component selection but this medium has no components.inf: installing everything");
        return NULL;
    }

    RtlInitUnicodeString(&FileName, PathBuffer);
    InitializeObjectAttributes(&ObjectAttributes, &FileName, OBJ_CASE_INSENSITIVE, NULL, NULL);
    Status = NtCreateFile(&FileHandle, FILE_READ_DATA | SYNCHRONIZE, &ObjectAttributes, &IoStatusBlock,
                          NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN,
                          FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
    Buffer = NT_SUCCESS(Status) ? RtlAllocateHeap(RtlGetProcessHeap(), 0, RECORD_MAX + 1) : NULL;
    if (!Buffer)
    {
        if (NT_SUCCESS(Status)) NtClose(FileHandle);
        SetupLogFormat("update: cannot read the recorded component selection (0x%08lx): installing everything", Status);
        FreeRecordedState(State);
        return NULL;
    }
    Status = NtReadFile(FileHandle, NULL, NULL, NULL, &IoStatusBlock, Buffer, RECORD_MAX, NULL, NULL);
    NtClose(FileHandle);
    Length = NT_SUCCESS(Status) ? (ULONG)IoStatusBlock.Information : 0;
    Buffer[Length] = '\0';

    RtlFillMemory(State->Explicit, sizeof(State->Explicit), (UCHAR)COMPONENT_UNSET);
    for (Line = Buffer; *Line; Line = Next)
    {
        PCHAR Eq;
        WCHAR Id[COMPONENT_ID_MAX];
        LONG Index;

        End = Line;
        while (*End && *End != '\r' && *End != '\n')
            ++End;
        Next = End;
        while (*Next == '\r' || *Next == '\n')
            ++Next;
        if (*End)
            *End = '\0';

        if (*Line == ';' || !*Line)
            continue;
        if (*Line == '[')
        {
            Section = !_strnicmp(Line, "[Selection]", 11) ? 1 :
                      !_strnicmp(Line, "[Installed]", 11) ? 2 :
                      !_strnicmp(Line, "[Omitted]", 9) ? 3 : 0;
            continue;
        }
        Eq = strchr(Line, '=');
        if (!Eq || !Section)
            continue;
        *Eq = '\0';

        if (Section == 1)
        {
            WCHAR Value[32];
            ULONG n;

            if (_stricmp(Line, "Profile"))
                continue;
            for (n = 0; n < ARRAYSIZE(Value) - 1 && Eq[1 + n]; ++n)
                Value[n] = (WCHAR)(UCHAR)Eq[1 + n];
            Value[n] = UNICODE_NULL;
            if (!ComponentParseProfile(Value, &Profile))
                Profile = COMPONENT_PROFILE_STANDARD;
            continue;
        }

        for (i = 0; i < ARRAYSIZE(Id) - 1 && Line[i] && Line[i] != ' '; ++i)
            Id[i] = (WCHAR)(UCHAR)Line[i];
        Id[i] = UNICODE_NULL;
        Index = ComponentFindIndex(State->Count, State->Desc, Id);
        if (Index < 0 || !State->Desc[Index].Applicable)
            continue;
        State->Explicit[Index] = (Section == 2) ? COMPONENT_YES : COMPONENT_NO;
        if (Section == 3)
            Any = TRUE;
    }
    RtlFreeHeap(RtlGetProcessHeap(), 0, Buffer);

    if (!Any && Profile == COMPONENT_PROFILE_STANDARD)
    {
        /* nothing left out, or a record that names nothing this medium knows: the same as no record */
        SetupLogFormat("update: the recorded component selection leaves nothing out, or has no entry this medium knows: installing everything");
        FreeRecordedState(State);
        return NULL;
    }

    State->Profile = Profile;
    State->Selected = ComponentsResolve(State->Count, State->Desc, Profile, State->Explicit);
    State->Record = TRUE;
    SetupLogFormat("update: keeping the component selection of the installation (components.txt)");
    CommitSelection(State);
    return State;
}

/* EOF */
