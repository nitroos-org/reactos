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

#define COMPONENT_GLOB_MAX  256

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

    /* The ids first: Depends and Conflicts refer to them */
    Ok = SpInfFindFirstLine(State->Inf, L"Components", NULL, &Context);
    for (; Ok && State->Count < COMPONENT_MAX; Ok = SpInfFindNextLine(&Context, &Context))
    {
        if (!INF_GetDataField(&Context, 0, &Value) || !*Value || wcslen(Value) >= COMPONENT_ID_MAX)
            continue;
        RtlStringCchCopyW(State->Desc[State->Count].Id, COMPONENT_ID_MAX, Value);
        State->Count++;
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
    }

    return State;
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

/* Collect the file patterns of the components that are left out */
static VOID
BuildOmitGlobs(
    _In_ PCOMPONENTS_STATE State)
{
    ULONG i, Index;
    PCWSTR Value;

    OmitGlobCount = 0;
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
    }
}

VOID
NTAPI
ComponentsApplyAnswerFile(
    _In_ PCOMPONENTS_STATE State,
    _In_ HINF AnswerInf)
{
    INFCONTEXT Context;
    PCWSTR Key, Value;
    WCHAR Names[400];
    BOOLEAN Ok;
    ULONG i;

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
                SetupLogLine("bad value for Profile in [Components] (standard, minimal or core expected): using standard");
            }
            continue;
        }

        switch (ComponentSetAnswer(State->Count, State->Desc, State->Explicit, Key, Value))
        {
            case COMPONENT_ANSWER_UNKNOWN:
                SetupLogFormat("unknown component id \"%S\" in [Components]: ignored", Key);
                break;
            case COMPONENT_ANSWER_NOT_HERE:
                SetupLogFormat("component \"%S\" does not exist in this edition: ignored", Key);
                break;
            case COMPONENT_ANSWER_BAD:
                SetupLogFormat("bad value for component %S (yes or no expected): ignored", Key);
                break;
            default:
                break;
        }
    }

    State->Selected = ComponentsResolve(State->Count, State->Desc, State->Profile, State->Explicit);
    State->Resolved = TRUE;

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
    SetDword(COMPONENTS_REG_KEY, L"AnyOff", State->AnyOff ? 1 : 0);

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

/* EOF */
