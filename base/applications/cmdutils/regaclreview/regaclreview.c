/*
 * PROJECT:     NitroOS
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     regaclreview: a report of the settings in every account's registry hive that start or load programs
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

/*
 * Before registry key security was enforced, any local account could write any key, also in other accounts' hives
 * (an administrator's HKCU Run key, NetworkService's Software\Classes). The first enforcing boot takes back keys and
 * descriptors, but a value carries no author: a planted Run entry still runs at its account's next logon. This tool
 * lists, for every profile hive and for the .DEFAULT, LocalService and NetworkService hives, the values of the places
 * that start or load programs, with the key's last write time, the value, whether the file it names exists and who
 * owns that file; and the profile folders (ProfileList ProfileImagePath). It judges nothing: an entry is marked
 * REVIEW when what it names belongs to another account that is not an administrator, when the key may be written by
 * others, or when the key carries a label below Medium. Nothing is changed.
 *
 * Output: a text file (default %SystemRoot%\System32\LogFiles\RegAcl\review-<time>.txt, or /out <file>), one event
 * log entry (source RegAclReview), and the exit code: 0 nothing marked, 1 entries marked REVIEW, 2 a hive or a part
 * could not be read, 3 both, 4 no report (not an administrator, no file).
 *
 * Run by an administrator on demand, and once by the service controller at the boot that ran the transition to
 * enforcement (/transition: the report goes to LogFiles\RegAcl\transition-review.txt).
 *
 * Every byte of a hive is hostile here (other accounts wrote them, and this runs as SYSTEM or an administrator):
 *  - a hive that is not loaded is copied (backup semantics, read only, reparse points not followed) into a folder
 *    only SYSTEM and administrators can open, loaded from the copy at a scratch name, read, unloaded and deleted:
 *    the account's file is never opened for write and never loaded;
 *  - a path from a value is only looked at: each folder of it is opened for its attributes and owner with
 *    FILE_FLAG_OPEN_REPARSE_POINT (a reparse point is reported, never followed), nothing is executed or opened for
 *    write; paths that are not on a fixed local drive (UNC, devices, streams, wildcards) are not touched;
 *  - text from values is written escaped (control characters as \xNN) and cut at a fixed length: a value cannot
 *    forge lines of the report.
 */

#define WIN32_NO_STATUS
#include <windef.h>
#include <winbase.h>
#include <winreg.h>
#include <winnls.h>
#include <winsvc.h>
#include <aclapi.h>
#include <sddl.h>
#include <lm.h>
#include <strsafe.h>
#include <stdio.h>
#include <stdarg.h>
#include <wchar.h>

#define REVIEW_VERSION          1
#define MAX_VALUE_BYTES         (64 * 1024)
#define MAX_SHOWN_CHARS         400
#define MAX_PATH_CHARS          1024
#define MAX_SUBKEYS             20000
#define MAX_ACCOUNTS            1024
#define MAX_HIVE_COPY_BYTES     (1024ULL * 1024 * 1024)
#define EVENT_SOURCE            L"RegAclReview"

/* What a value holds (how its data is looked at) */
enum
{
    KIND_TEXT = 0,      /* listed, no path */
    KIND_CMD,           /* a command line: the program (and a rundll32 DLL) */
    KIND_LIST,          /* programs separated by commas or blanks (Winlogon Shell/Userinit, Windows Load/Run) */
    KIND_PATHLIST,      /* folders separated by semicolons (Path) */
    KIND_DIR,           /* one folder */
    KIND_FILE           /* one file */
};

/* Who owns a file or a key */
enum
{
    OWNER_UNKNOWN = 0,
    OWNER_SYSTEM,       /* SYSTEM, LocalService, NetworkService, TrustedInstaller, a service SID */
    OWNER_ADMIN,        /* Administrators, or an account in it */
    OWNER_ACCOUNT,      /* the account whose hive it is */
    OWNER_OTHER         /* anyone else: another account that is not an administrator */
};

typedef struct _HIVE
{
    WCHAR Label[128];       /* for the report: HKU\<SID> (name) */
    WCHAR Source[MAX_PATH_CHARS];
    PSID Account;           /* the hive's own account */
    HKEY Root;              /* the account's hive (or NULL) */
    HKEY Classes;           /* its classes hive (or NULL) */
    WCHAR Profile[MAX_PATH_CHARS];  /* its profile folder, for %USERPROFILE% (may be empty) */
} HIVE, *PHIVE;

/* Report text */
static PWCHAR g_Text;
static SIZE_T g_TextChars, g_TextMax;
static ULONG g_Entries, g_Marked, g_Unread;
/* AuditStats: the value RegistryAclMode of earlier kernels was found and deleted at this boot (its data) */
static DWORD g_ModeValueRemoved, g_ModeValueWas = MAXDWORD;
static BOOL g_OutOfMemory;

/* Administrators' members (SIDs), read once */
static PSID *g_Admins;
static ULONG g_AdminCount;

/* Scratch folder for hive copies, and the counter of scratch names */
static WCHAR g_Scratch[MAX_PATH];
static ULONG g_ScratchCount;

static WCHAR g_SystemRoot[MAX_PATH], g_SystemDrive[8], g_ProgramFiles[MAX_PATH], g_ProgramFilesX86[MAX_PATH],
             g_CommonFiles[MAX_PATH], g_ProgramData[MAX_PATH], g_ProfilesDir[MAX_PATH];

/* REPORT TEXT ****************************************************************/

static
VOID
Append(
    _In_ PCWSTR Text)
{
    SIZE_T Chars = wcslen(Text);
    PWCHAR Bigger;

    if (g_OutOfMemory)
        return;
    if (g_TextChars + Chars + 1 > g_TextMax)
    {
        SIZE_T Max = max(g_TextMax * 2, g_TextChars + Chars + 65536);

        Bigger = g_Text ? HeapReAlloc(GetProcessHeap(), 0, g_Text, Max * sizeof(WCHAR))
                        : HeapAlloc(GetProcessHeap(), 0, Max * sizeof(WCHAR));
        if (!Bigger)
        {
            g_OutOfMemory = TRUE;
            return;
        }
        g_Text = Bigger;
        g_TextMax = Max;
    }
    RtlCopyMemory(g_Text + g_TextChars, Text, (Chars + 1) * sizeof(WCHAR));
    g_TextChars += Chars;
}

static
VOID
Out(
    _In_ PCWSTR Format,
    ...)
{
    WCHAR Line[2048];
    va_list Args;

    va_start(Args, Format);
    StringCchVPrintfW(Line, ARRAYSIZE(Line), Format, Args);
    va_end(Args);
    Append(Line);
}

/*
 * Text from a hive, escaped into Buffer: printable characters as they are, everything else (CR, LF, TAB, other
 * control characters, unpaired surrogates) as \xNN or \uNNNN, and at most MAX_SHOWN_CHARS of it.
 */
static
VOID
EscapeText(
    _In_reads_(Chars) PCWSTR Text,
    _In_ SIZE_T Chars,
    _Out_writes_(BufferChars) PWCHAR Buffer,
    _In_ SIZE_T BufferChars)
{
    SIZE_T i, Used = 0;
    WCHAR Piece[8];

    Buffer[0] = UNICODE_NULL;
    for (i = 0; i < Chars && Text[i]; i++)
    {
        WCHAR c = Text[i];

        if (i >= MAX_SHOWN_CHARS)
        {
            StringCchCopyW(Piece, ARRAYSIZE(Piece), L"...");
        }
        else if (c < 0x20 || c == 0x7F || (c >= 0x80 && c < 0xA0) || (c >= 0xD800 && c <= 0xDFFF) ||
                 c == 0x2028 || c == 0x2029 || c == 0xFEFF)
        {
            if (c < 0x100)
                StringCchPrintfW(Piece, ARRAYSIZE(Piece), L"\\x%02X", c);
            else
                StringCchPrintfW(Piece, ARRAYSIZE(Piece), L"\\u%04X", c);
        }
        else
        {
            Piece[0] = c;
            Piece[1] = UNICODE_NULL;
        }
        if (Used + wcslen(Piece) + 1 > BufferChars)
            break;
        StringCchCopyW(Buffer + Used, BufferChars - Used, Piece);
        Used += wcslen(Piece);
        if (i >= MAX_SHOWN_CHARS)
            break;
    }
}

/* SIDS AND OWNERS ************************************************************/

static
BOOL
SidIs(
    _In_ PSID Sid,
    _In_ PCWSTR Text)
{
    PSID Known = NULL;
    BOOL Equal;

    if (!ConvertStringSidToSidW(Text, &Known))
        return FALSE;
    Equal = EqualSid(Sid, Known);
    LocalFree(Known);
    return Equal;
}

static
VOID
SidText(
    _In_opt_ PSID Sid,
    _Out_writes_(Chars) PWCHAR Buffer,
    _In_ SIZE_T Chars)
{
    PWSTR String = NULL;
    WCHAR Name[256], Domain[256];
    DWORD NameChars = ARRAYSIZE(Name), DomainChars = ARRAYSIZE(Domain);
    SID_NAME_USE Use;

    if (!Sid || !IsValidSid(Sid) || !ConvertSidToStringSidW(Sid, &String))
    {
        StringCchCopyW(Buffer, Chars, L"(none)");
        return;
    }
    if (LookupAccountSidW(NULL, Sid, Name, &NameChars, Domain, &DomainChars, &Use))
        StringCchPrintfW(Buffer, Chars, L"%s%s%s (%s)", Domain, Domain[0] ? L"\\" : L"", Name, String);
    else
        StringCchCopyW(Buffer, Chars, String);
    LocalFree(String);
}

static
VOID
LoadAdmins(VOID)
{
    PSID Admins = NULL;
    WCHAR Name[256], Domain[256];
    DWORD NameChars = ARRAYSIZE(Name), DomainChars = ARRAYSIZE(Domain), Read = 0, Total = 0, i;
    SID_NAME_USE Use;
    PLOCALGROUP_MEMBERS_INFO_0 Members = NULL;

    if (!ConvertStringSidToSidW(L"S-1-5-32-544", &Admins))
        return;
    if (LookupAccountSidW(NULL, Admins, Name, &NameChars, Domain, &DomainChars, &Use) &&
        NetLocalGroupGetMembers(NULL, Name, 0, (LPBYTE *)&Members, MAX_PREFERRED_LENGTH, &Read, &Total, NULL) ==
            NERR_Success && Members)
    {
        g_Admins = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (Read + 1) * sizeof(PSID));
        for (i = 0; g_Admins && i < Read; i++)
        {
            DWORD Length;

            if (!Members[i].lgrmi0_sid || !IsValidSid(Members[i].lgrmi0_sid))
                continue;
            Length = GetLengthSid(Members[i].lgrmi0_sid);
            g_Admins[g_AdminCount] = HeapAlloc(GetProcessHeap(), 0, Length);
            if (g_Admins[g_AdminCount] && CopySid(Length, g_Admins[g_AdminCount], Members[i].lgrmi0_sid))
                g_AdminCount++;
        }
        NetApiBufferFree(Members);
    }
    LocalFree(Admins);
}

static
ULONG
ClassifyOwner(
    _In_opt_ PSID Owner,
    _In_opt_ PSID Account)
{
    PSID_IDENTIFIER_AUTHORITY Authority;
    ULONG i;

    if (!Owner || !IsValidSid(Owner))
        return OWNER_UNKNOWN;
    if (Account && EqualSid(Owner, Account))
        return OWNER_ACCOUNT;
    if (SidIs(Owner, L"S-1-5-18") || SidIs(Owner, L"S-1-5-19") || SidIs(Owner, L"S-1-5-20"))
        return OWNER_SYSTEM;
    Authority = GetSidIdentifierAuthority(Owner);
    /* NT SERVICE\* (S-1-5-80-...), TrustedInstaller among them */
    if (Authority->Value[5] == 5 && *GetSidSubAuthorityCount(Owner) >= 1 && *GetSidSubAuthority(Owner, 0) == 80)
        return OWNER_SYSTEM;
    if (SidIs(Owner, L"S-1-5-32-544"))
        return OWNER_ADMIN;
    for (i = 0; i < g_AdminCount; i++)
    {
        if (EqualSid(Owner, g_Admins[i]))
            return OWNER_ADMIN;
    }
    return OWNER_OTHER;
}

/* FILES (looked at, never followed, executed or opened for write) ************/

typedef struct _TARGET
{
    WCHAR Path[MAX_PATH_CHARS];
    BOOL Looked;            /* the path could be looked at */
    BOOL Exists;
    BOOL Mark;              /* REVIEW */
    WCHAR Note[MAX_PATH_CHARS * 3];
} TARGET, *PTARGET;

/* Is Path a plain absolute path on a fixed local drive: X:\a\b, no stream, no wildcard, no . or .. component */
static
BOOL
PlainLocalPath(
    _In_ PCWSTR Path,
    _Out_writes_(WhyChars) PWCHAR Why,
    _In_ SIZE_T WhyChars)
{
    WCHAR Root[4];
    SIZE_T Length = wcslen(Path), i;

    if (Length < 3 || Length >= MAX_PATH_CHARS || !iswalpha(Path[0]) || Path[1] != L':' || Path[2] != L'\\')
    {
        StringCchCopyW(Why, WhyChars, L"not an absolute local path: not looked at");
        return FALSE;
    }
    for (i = 2; i < Length; i++)
    {
        if (Path[i] == L':' || Path[i] == L'*' || Path[i] == L'?' || Path[i] == L'"' || Path[i] == L'<' ||
            Path[i] == L'>' || Path[i] == L'|' || Path[i] < 0x20 || (Path[i] == L'\\' && Path[i - 1] == L'\\'))
        {
            StringCchCopyW(Why, WhyChars, L"a name the tool does not look at (stream, wildcard or device syntax)");
            return FALSE;
        }
        if (Path[i - 1] == L'\\' && Path[i] == L'.' &&
            (i + 1 == Length || Path[i + 1] == L'\\' || (Path[i + 1] == L'.' && (i + 2 == Length || Path[i + 2] == L'\\'))))
        {
            StringCchCopyW(Why, WhyChars, L"a path with . or .. components: not looked at");
            return FALSE;
        }
    }
    Root[0] = Path[0];
    Root[1] = L':';
    Root[2] = L'\\';
    Root[3] = UNICODE_NULL;
    if (GetDriveTypeW(Root) != DRIVE_FIXED)
    {
        StringCchCopyW(Why, WhyChars, L"not on a fixed local drive: not looked at");
        return FALSE;
    }
    return TRUE;
}

/* Open one path (a prefix of the target) for its attributes and owner, never following a reparse point */
static
HANDLE
OpenNoFollow(
    _In_ PCWSTR Path)
{
    return CreateFileW(Path, FILE_READ_ATTRIBUTES | READ_CONTROL,
                       FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING,
                       FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
}

static
PSID
OwnerOfHandle(
    _In_ HANDLE Handle,
    _Out_ PSECURITY_DESCRIPTOR *ToFree)
{
    PSID Owner = NULL;

    *ToFree = NULL;
    if (GetSecurityInfo(Handle, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION, &Owner, NULL, NULL, NULL, ToFree) !=
        ERROR_SUCCESS)
    {
        return NULL;
    }
    return Owner;
}

/*
 * Who besides the account, SYSTEM and the administrators the DACL of the open object gives one of Rights (an allow
 * ACE that applies to the object itself; the creator placeholders do not count): FALSE if nobody. A missing or NULL
 * DACL counts as everybody.
 */
static
BOOL
OthersMayWrite(
    _In_ HANDLE Handle,
    _In_opt_ PSID Account,
    _In_ ACCESS_MASK Rights,
    _Out_writes_(WhoChars) PWCHAR Who,
    _In_ SIZE_T WhoChars)
{
    PSECURITY_DESCRIPTOR Sd = NULL;
    PACL Dacl = NULL;
    ACE_HEADER *Ace;
    PSID Sid;
    BOOL Found = FALSE;
    DWORD i;

    Who[0] = UNICODE_NULL;
    if (GetSecurityInfo(Handle, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, &Dacl, NULL, &Sd) !=
        ERROR_SUCCESS)
    {
        return FALSE;
    }
    if (!Dacl)
    {
        StringCchCopyW(Who, WhoChars, L"everybody (no DACL)");
        Found = TRUE;
    }
    for (i = 0; !Found && Dacl && i < Dacl->AceCount; i++)
    {
        if (!GetAce(Dacl, i, (PVOID *)&Ace))
            break;
        if (Ace->AceType != ACCESS_ALLOWED_ACE_TYPE || (Ace->AceFlags & INHERIT_ONLY_ACE) ||
            Ace->AceSize < sizeof(ACCESS_ALLOWED_ACE))
        {
            continue;
        }
        Sid = (PSID)&((ACCESS_ALLOWED_ACE *)Ace)->SidStart;
        if (!IsValidSid(Sid) || !(((ACCESS_ALLOWED_ACE *)Ace)->Mask & Rights))
            continue;
        if (ClassifyOwner(Sid, Account) != OWNER_OTHER ||
            SidIs(Sid, L"S-1-3-0") || SidIs(Sid, L"S-1-3-1") || SidIs(Sid, L"S-1-3-4"))
        {
            continue;
        }
        SidText(Sid, Who, WhoChars);
        Found = TRUE;
    }
    if (Sd)
        LocalFree(Sd);
    return Found;
}

/* Rights that let someone change or replace a file, put a file into a folder, or change a folder's entries */
#define FILE_CHANGE_RIGHTS   (FILE_WRITE_DATA | FILE_APPEND_DATA | WRITE_DAC | WRITE_OWNER | DELETE | GENERIC_WRITE | GENERIC_ALL)
#define FOLDER_ADD_RIGHTS    (FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY | FILE_DELETE_CHILD | WRITE_DAC | WRITE_OWNER | \
                              GENERIC_WRITE | GENERIC_ALL)
#define FOLDER_ENTRY_RIGHTS  (FILE_DELETE_CHILD | WRITE_DAC | WRITE_OWNER | GENERIC_ALL)

/*
 * Look at a file or folder: every folder from the drive's root down and the target itself are opened one by one
 * (attributes and owner only). A reparse point on the way ends the look (reported with its owner). Marked when the
 * target or a folder on its way belongs to another account that is not an administrator (that account could change
 * or replace what this setting runs). Account: the hive's own account (its own files are not marked).
 */
static
VOID
LookAt(
    _Inout_ PTARGET Target,
    _In_opt_ PSID Account)
{
    WCHAR Prefix[MAX_PATH_CHARS], OwnerName[512], Why[128], Writer[512], WriterNote[MAX_PATH_CHARS + 600];
    WCHAR Earlier[MAX_PATH_CHARS * 3];
    SIZE_T Length = wcslen(Target->Path), i;
    BY_HANDLE_FILE_INFORMATION Info;
    PSECURITY_DESCRIPTOR Sd;
    HANDLE Handle;
    PSID Owner;
    ULONG Class;
    BOOL Writable, WriterNoted = FALSE;

    WriterNote[0] = UNICODE_NULL;
    Target->Looked = Target->Exists = Target->Mark = FALSE;
    Target->Note[0] = UNICODE_NULL;
    if (!PlainLocalPath(Target->Path, Why, ARRAYSIZE(Why)))
    {
        StringCchCopyW(Target->Note, ARRAYSIZE(Target->Note), Why);
        return;
    }

    for (i = 3; i <= Length; i++)
    {
        BOOL Last = (i == Length);

        if (!Last && Target->Path[i] != L'\\')
            continue;
        StringCchCopyNW(Prefix, ARRAYSIZE(Prefix), Target->Path, i);
        Handle = OpenNoFollow(Prefix);
        if (Handle == INVALID_HANDLE_VALUE)
        {
            DWORD Error = GetLastError();

            Target->Looked = TRUE;
            /*
             * A folder on the way that another account owns or may change stays the reason of the mark: it can put
             * the file there (Earlier: what the walk noted so far)
             */
            StringCchCopyW(Earlier, ARRAYSIZE(Earlier), Target->Note);
            if (Error == ERROR_FILE_NOT_FOUND || Error == ERROR_PATH_NOT_FOUND || Error == ERROR_INVALID_NAME)
                StringCchPrintfW(Target->Note, ARRAYSIZE(Target->Note), L"%sdoes not exist%s", Earlier, WriterNote);
            else
                StringCchPrintfW(Target->Note, ARRAYSIZE(Target->Note), L"%scannot be looked at (error %lu)%s",
                                 Earlier, Error, WriterNote);
            return;
        }
        if (!GetFileInformationByHandle(Handle, &Info))
            Info.dwFileAttributes = 0;
        Owner = OwnerOfHandle(Handle, &Sd);
        Class = ClassifyOwner(Owner, Account);
        SidText(Owner, OwnerName, ARRAYSIZE(OwnerName));
        /*
         * Who else may change it: the target itself (its data, or for a folder what goes into it), a folder on the
         * way (deleting or renaming its entries, or its permissions)
         */
        Writable = !(Info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) &&
                   OthersMayWrite(Handle, Account,
                                  !Last ? FOLDER_ENTRY_RIGHTS :
                                  (Info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ? FOLDER_ADD_RIGHTS : FILE_CHANGE_RIGHTS,
                                  Writer, ARRAYSIZE(Writer));
        CloseHandle(Handle);
        if (Sd)
            LocalFree(Sd);
        if (Writable && !WriterNoted)
        {
            WriterNoted = TRUE;
            Target->Mark = TRUE;
            StringCchPrintfW(WriterNote, ARRAYSIZE(WriterNote), L"; REVIEW: %s%s may be changed by %s",
                             Last ? L"" : L"folder ", Last ? L"it" : Prefix, Writer);
        }

        if (Info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)
        {
            Target->Looked = TRUE;
            Target->Mark = (Class == OWNER_OTHER);
            StringCchPrintfW(Target->Note, ARRAYSIZE(Target->Note),
                             L"%s is a reparse point (not followed), owner %s%s",
                             Prefix, OwnerName,
                             Target->Mark ? L"; REVIEW: owned by another account that is not an administrator" : L"");
            return;
        }
        if (Last)
        {
            Target->Looked = Target->Exists = TRUE;
            if (Class == OWNER_OTHER)
                Target->Mark = TRUE;
            StringCchPrintfW(Target->Note + wcslen(Target->Note), ARRAYSIZE(Target->Note) - wcslen(Target->Note),
                             L"exists, owner %s%s%s", OwnerName,
                             Class == OWNER_OTHER ? L"; REVIEW: owned by another account that is not an administrator" : L"",
                             WriterNote);
            return;
        }
        if (Class == OWNER_OTHER && !Target->Mark)
        {
            /* A folder on the way that another account owns: it can put another file there */
            Target->Mark = TRUE;
            StringCchPrintfW(Target->Note, ARRAYSIZE(Target->Note),
                             L"REVIEW: folder %s is owned by %s (another account, not an administrator); ", Prefix, OwnerName);
        }
    }
}

/* ENVIRONMENT REFERENCES AND COMMAND LINES ***********************************/

/* %VAR% with the system's values, and the profile's for the per-user ones; FALSE if one is not known */
static
BOOL
ExpandFor(
    _In_ PCWSTR In,
    _In_ PCWSTR Profile,
    _Out_writes_(OutChars) PWCHAR Out,
    _In_ SIZE_T OutChars)
{
    SIZE_T Used = 0;
    PCWSTR p = In, End;
    WCHAR Name[64], Value[MAX_PATH_CHARS];
    BOOL Known = TRUE;

    Out[0] = UNICODE_NULL;
    while (*p)
    {
        if (*p == L'%' && (End = wcschr(p + 1, L'%')) != NULL && (SIZE_T)(End - p - 1) < ARRAYSIZE(Name) && End > p + 1)
        {
            StringCchCopyNW(Name, ARRAYSIZE(Name), p + 1, End - p - 1);
            Value[0] = UNICODE_NULL;
            if (!_wcsicmp(Name, L"SystemRoot") || !_wcsicmp(Name, L"windir"))
                StringCchCopyW(Value, ARRAYSIZE(Value), g_SystemRoot);
            else if (!_wcsicmp(Name, L"SystemDrive"))
                StringCchCopyW(Value, ARRAYSIZE(Value), g_SystemDrive);
            else if (!_wcsicmp(Name, L"ProgramFiles") || !_wcsicmp(Name, L"ProgramW6432"))
                StringCchCopyW(Value, ARRAYSIZE(Value), g_ProgramFiles);
            else if (!_wcsicmp(Name, L"ProgramFiles(x86)"))
                StringCchCopyW(Value, ARRAYSIZE(Value), g_ProgramFilesX86);
            else if (!_wcsicmp(Name, L"CommonProgramFiles"))
                StringCchCopyW(Value, ARRAYSIZE(Value), g_CommonFiles);
            else if (!_wcsicmp(Name, L"ProgramData") || !_wcsicmp(Name, L"ALLUSERSPROFILE"))
                StringCchCopyW(Value, ARRAYSIZE(Value), g_ProgramData);
            else if (Profile[0] && !_wcsicmp(Name, L"USERPROFILE"))
                StringCchCopyW(Value, ARRAYSIZE(Value), Profile);
            else if (Profile[0] && !_wcsicmp(Name, L"APPDATA"))
                StringCchPrintfW(Value, ARRAYSIZE(Value), L"%s\\AppData\\Roaming", Profile);
            else if (Profile[0] && !_wcsicmp(Name, L"LOCALAPPDATA"))
                StringCchPrintfW(Value, ARRAYSIZE(Value), L"%s\\AppData\\Local", Profile);
            else if (Profile[0] && (!_wcsicmp(Name, L"TEMP") || !_wcsicmp(Name, L"TMP")))
                StringCchPrintfW(Value, ARRAYSIZE(Value), L"%s\\AppData\\Local\\Temp", Profile);
            if (!Value[0])
            {
                Known = FALSE;
                StringCchCopyNW(Value, ARRAYSIZE(Value), p, End - p + 1);
            }
            if (Used + wcslen(Value) + 1 > OutChars)
                return FALSE;
            StringCchCopyW(Out + Used, OutChars - Used, Value);
            Used += wcslen(Value);
            p = End + 1;
            continue;
        }
        if (Used + 2 > OutChars)
            return FALSE;
        Out[Used++] = *p++;
        Out[Used] = UNICODE_NULL;
    }
    return Known;
}

/* Does Text end (case-insensitively) with Tail */
static
BOOL
EndsWith(
    _In_ PCWSTR Text,
    _In_ SIZE_T Chars,
    _In_ PCWSTR Tail)
{
    SIZE_T TailChars = wcslen(Tail);

    return Chars >= TailChars && !_wcsnicmp(Text + Chars - TailChars, Tail, TailChars);
}

/*
 * The program a command line starts: the quoted first token, or the shortest prefix ending in a program extension
 * followed by a blank or the end, or else the first blank-separated token. *Rest: what follows it.
 */
static
VOID
ProgramOf(
    _In_ PCWSTR Command,
    _Out_writes_(ProgramChars) PWCHAR Program,
    _In_ SIZE_T ProgramChars,
    _Out_ PCWSTR *Rest)
{
    static const PCWSTR Extensions[] = { L".exe", L".com", L".bat", L".cmd", L".scr", L".dll", L".cpl", L".ocx",
                                         L".ps1", L".vbs", L".js", L".msc", L".pif", L".lnk" };
    PCWSTR p = Command, End;
    SIZE_T i, j;

    while (*p == L' ' || *p == L'\t')
        p++;
    if (*p == L'"')
    {
        End = wcschr(p + 1, L'"');
        if (!End)
            End = p + wcslen(p);
        StringCchCopyNW(Program, ProgramChars, p + 1, End - p - 1);
        *Rest = *End ? End + 1 : End;
        return;
    }
    for (i = 1; p[i - 1]; i++)
    {
        if (p[i] != UNICODE_NULL && p[i] != L' ' && p[i] != L',')
            continue;
        for (j = 0; j < ARRAYSIZE(Extensions); j++)
        {
            if (EndsWith(p, i, Extensions[j]))
            {
                StringCchCopyNW(Program, ProgramChars, p, i);
                *Rest = p + i;
                return;
            }
        }
        if (p[i] == UNICODE_NULL)
            break;
    }
    End = p;
    while (*End && *End != L' ' && *End != L'\t')
        End++;
    StringCchCopyNW(Program, ProgramChars, p, End - p);
    *Rest = End;
}

/* REGISTRY READING (bounded) *************************************************/

/* A value's data as a terminated string (REG_SZ, REG_EXPAND_SZ; REG_MULTI_SZ with its strings joined by ';') */
static
BOOL
ValueString(
    _In_ DWORD Type,
    _In_reads_bytes_(Bytes) const BYTE *Data,
    _In_ DWORD Bytes,
    _Out_writes_(Chars) PWCHAR Text,
    _In_ SIZE_T Chars)
{
    SIZE_T n = min(Bytes / sizeof(WCHAR), Chars - 1), i;

    if (Type != REG_SZ && Type != REG_EXPAND_SZ && Type != REG_MULTI_SZ)
        return FALSE;
    RtlCopyMemory(Text, Data, n * sizeof(WCHAR));
    Text[n] = UNICODE_NULL;
    if (Type == REG_MULTI_SZ)
    {
        while (n && Text[n - 1] == UNICODE_NULL)
            n--;
        for (i = 0; i < n; i++)
        {
            if (Text[i] == UNICODE_NULL)
                Text[i] = L';';
        }
        Text[n] = UNICODE_NULL;
    }
    return TRUE;
}

static
VOID
FileTimeText(
    _In_ const FILETIME *Time,
    _Out_writes_(Chars) PWCHAR Buffer,
    _In_ SIZE_T Chars)
{
    SYSTEMTIME St;

    if (!FileTimeToSystemTime(Time, &St))
    {
        StringCchCopyW(Buffer, Chars, L"?");
        return;
    }
    StringCchPrintfW(Buffer, Chars, L"%04u-%02u-%02u %02u:%02u:%02uZ",
                     St.wYear, St.wMonth, St.wDay, St.wHour, St.wMinute, St.wSecond);
}

/*
 * The key's own marks: a label below Medium (the account's Low-integrity processes may write it), or a write right
 * for anyone but the account, SYSTEM and the administrators (in a hive another account could open while nothing was
 * enforced).
 */
static
VOID
KeyMarks(
    _In_ HKEY Key,
    _In_opt_ PSID Account,
    _Out_writes_(Chars) PWCHAR Buffer,
    _In_ SIZE_T Chars,
    _Out_ PBOOL Mark)
{
    static const DWORD Write = KEY_SET_VALUE | KEY_CREATE_SUB_KEY | KEY_CREATE_LINK | DELETE | WRITE_DAC |
                               WRITE_OWNER | GENERIC_WRITE | GENERIC_ALL | MAXIMUM_ALLOWED;
    PSECURITY_DESCRIPTOR Sd = NULL;
    DWORD Length = 0, i;
    BOOL Present, Defaulted;
    PACL Acl;
    ACE_HEADER *Ace;
    WCHAR Who[512];

    *Mark = FALSE;
    Buffer[0] = UNICODE_NULL;
    RegGetKeySecurity(Key, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION,
                      NULL, &Length);
    if (!Length || Length > 256 * 1024 || !(Sd = HeapAlloc(GetProcessHeap(), 0, Length)))
        return;
    if (RegGetKeySecurity(Key, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION,
                          Sd, &Length) != ERROR_SUCCESS || !IsValidSecurityDescriptor(Sd))
    {
        HeapFree(GetProcessHeap(), 0, Sd);
        return;
    }

    if (GetSecurityDescriptorSacl(Sd, &Present, &Acl, &Defaulted) && Present && Acl)
    {
        for (i = 0; i < Acl->AceCount; i++)
        {
            if (!GetAce(Acl, i, (PVOID *)&Ace))
                break;
            if (Ace->AceType == SYSTEM_MANDATORY_LABEL_ACE_TYPE && !(Ace->AceFlags & INHERIT_ONLY_ACE) &&
                Ace->AceSize >= sizeof(SYSTEM_MANDATORY_LABEL_ACE) &&
                IsValidSid((PSID)&((SYSTEM_MANDATORY_LABEL_ACE *)Ace)->SidStart) &&
                *GetSidSubAuthorityCount((PSID)&((SYSTEM_MANDATORY_LABEL_ACE *)Ace)->SidStart) == 1 &&
                *GetSidSubAuthority((PSID)&((SYSTEM_MANDATORY_LABEL_ACE *)Ace)->SidStart, 0) < SECURITY_MANDATORY_MEDIUM_RID)
            {
                *Mark = TRUE;
                StringCchCatW(Buffer, Chars, L" REVIEW: the key is labelled below Medium (Low-integrity processes of the account may write it);");
                break;
            }
        }
    }

    if (GetSecurityDescriptorDacl(Sd, &Present, &Acl, &Defaulted))
    {
        if (!Present || !Acl)
        {
            *Mark = TRUE;
            StringCchCatW(Buffer, Chars, L" REVIEW: the key has no DACL (anybody may write it);");
        }
        else
        {
            for (i = 0; i < Acl->AceCount; i++)
            {
                PSID Sid;

                if (!GetAce(Acl, i, (PVOID *)&Ace))
                    break;
                if (Ace->AceType != ACCESS_ALLOWED_ACE_TYPE || Ace->AceSize < sizeof(ACCESS_ALLOWED_ACE))
                    continue;
                if ((Ace->AceFlags & INHERIT_ONLY_ACE))
                    continue;
                Sid = (PSID)&((ACCESS_ALLOWED_ACE *)Ace)->SidStart;
                if (!IsValidSid(Sid) || !(((ACCESS_ALLOWED_ACE *)Ace)->Mask & Write))
                    continue;
                if (ClassifyOwner(Sid, Account) == OWNER_OTHER &&
                    !SidIs(Sid, L"S-1-3-0") && !SidIs(Sid, L"S-1-3-1") && !SidIs(Sid, L"S-1-3-4"))
                {
                    *Mark = TRUE;
                    SidText(Sid, Who, ARRAYSIZE(Who));
                    StringCchCatW(Buffer, Chars, L" REVIEW: the key may be written by ");
                    StringCchCatW(Buffer, Chars, Who);
                    StringCchCatW(Buffer, Chars, L";");
                    break;
                }
            }
        }
    }
    HeapFree(GetProcessHeap(), 0, Sd);
}

/* Report one path a value names */
static
VOID
ReportTarget(
    _In_ PCWSTR Raw,
    _In_ PHIVE Hive,
    _Inout_ PBOOL Mark)
{
    TARGET Target;
    WCHAR Shown[MAX_SHOWN_CHARS * 6 + 8];

    if (!Raw[0])
        return;
    if (!ExpandFor(Raw, Hive->Profile, Target.Path, ARRAYSIZE(Target.Path)))
    {
        EscapeText(Raw, wcslen(Raw), Shown, ARRAYSIZE(Shown));
        Out(L"        -> %s: names a variable the tool does not resolve: not looked at\r\n", Shown);
        return;
    }
    LookAt(&Target, Hive->Account);
    if (Target.Mark)
        *Mark = TRUE;
    EscapeText(Target.Path, wcslen(Target.Path), Shown, ARRAYSIZE(Shown));
    Out(L"        -> %s: %s\r\n", Shown, Target.Note);
}

static
VOID
ReportCommand(
    _In_ PCWSTR Command,
    _In_ PHIVE Hive,
    _Inout_ PBOOL Mark)
{
    WCHAR Program[MAX_PATH_CHARS], Dll[MAX_PATH_CHARS], Shown[MAX_SHOWN_CHARS * 6 + 8];
    PCWSTR Rest, Comma;

    ProgramOf(Command, Program, ARRAYSIZE(Program), &Rest);
    /* Nothing, or a class identifier (DelegateExecute): no path */
    if (!Program[0] || Program[0] == L'{')
        return;
    if (!wcschr(Program, L'\\'))
    {
        EscapeText(Program, wcslen(Program), Shown, ARRAYSIZE(Shown));
        Out(L"        -> %s: found through the search path when it runs: not looked at\r\n", Shown);
    }
    else
    {
        ReportTarget(Program, Hive, Mark);
    }
    /* rundll32 <dll>,<entry>: the DLL too */
    if (EndsWith(Program, wcslen(Program), L"rundll32.exe") || EndsWith(Program, wcslen(Program), L"rundll32"))
    {
        ProgramOf(Rest, Dll, ARRAYSIZE(Dll), &Rest);
        Comma = wcschr(Dll, L',');
        if (Comma)
            Dll[Comma - Dll] = UNICODE_NULL;
        if (Dll[0] && wcschr(Dll, L'\\'))
            ReportTarget(Dll, Hive, Mark);
    }
}

/* Report the data of one value by its kind */
static
VOID
ReportData(
    _In_ ULONG Kind,
    _In_ PCWSTR Text,
    _In_ PHIVE Hive,
    _Inout_ PBOOL Mark)
{
    WCHAR Copy[MAX_PATH_CHARS * 4];
    PWCHAR Item;

    switch (Kind)
    {
        case KIND_CMD:
            ReportCommand(Text, Hive, Mark);
            break;
        case KIND_FILE:
        case KIND_DIR:
            ReportTarget(Text, Hive, Mark);
            break;
        case KIND_LIST:
        case KIND_PATHLIST:
            /* Programs separated by commas (each item's first program is looked at), folders by semicolons */
            StringCchCopyW(Copy, ARRAYSIZE(Copy), Text);
            for (Item = wcstok(Copy, Kind == KIND_LIST ? L"," : L";"); Item;
                 Item = wcstok(NULL, Kind == KIND_LIST ? L"," : L";"))
            {
                if (Kind == KIND_LIST)
                    ReportCommand(Item, Hive, Mark);
                else
                    ReportTarget(Item, Hive, Mark);
            }
            break;
        default:
            break;
    }
}

/*
 * Report the values of the key at Path below Root: all of them (Value NULL) or the one named. Missing keys and
 * values are not reported (nothing is set there).
 */
static
VOID
ReportKey(
    _In_ PHIVE Hive,
    _In_ HKEY Root,
    _In_ PCWSTR Prefix,
    _In_ PCWSTR Path,
    _In_opt_ PCWSTR Value,
    _In_ ULONG Kind)
{
    static WCHAR Name[16384], Text[MAX_VALUE_BYTES / sizeof(WCHAR) + 1];
    static BYTE Data[MAX_VALUE_BYTES];
    WCHAR Shown[MAX_SHOWN_CHARS * 6 + 8], ShownName[MAX_SHOWN_CHARS * 6 + 8], ShownPath[MAX_SHOWN_CHARS * 6 + 8],
          Time[32], Marks[1024];
    DWORD Index, NameChars, Type, Bytes, Values = 0;
    FILETIME Written;
    BOOL KeyMark, Mark, Header = FALSE;
    HKEY Key;
    LONG Error;

    Error = RegOpenKeyExW(Root, Path, 0, KEY_READ, &Key);
    if (Error == ERROR_FILE_NOT_FOUND)
        return;
    EscapeText(Path, wcslen(Path), ShownPath, ARRAYSIZE(ShownPath));
    if (Error != ERROR_SUCCESS)
    {
        Out(L"  %s\\%s: cannot be opened (error %ld)\r\n", Prefix, ShownPath, Error);
        g_Unread++;
        return;
    }
    if (RegQueryInfoKeyW(Key, NULL, NULL, NULL, NULL, NULL, NULL, &Values, NULL, NULL, NULL, &Written) != ERROR_SUCCESS)
        ZeroMemory(&Written, sizeof(Written));
    FileTimeText(&Written, Time, ARRAYSIZE(Time));
    KeyMarks(Key, Hive->Account, Marks, ARRAYSIZE(Marks), &KeyMark);

    for (Index = 0; Index < min(Values, 4096); Index++)
    {
        NameChars = ARRAYSIZE(Name);
        Bytes = sizeof(Data);
        Error = RegEnumValueW(Key, Index, Name, &NameChars, NULL, &Type, Data, &Bytes);
        if (Error == ERROR_NO_MORE_ITEMS)
            break;
        if (Error == ERROR_MORE_DATA)
        {
            /* Longer than the tool reads: named, not looked at */
            Name[min(NameChars, ARRAYSIZE(Name) - 1)] = UNICODE_NULL;
            Bytes = 0;
            Type = REG_NONE;
        }
        else if (Error != ERROR_SUCCESS)
        {
            g_Unread++;
            break;
        }
        if (Value && _wcsicmp(Name, Value))
            continue;

        if (!Header)
        {
            Out(L"  %s\\%s  (key written %s)%s\r\n", Prefix, ShownPath, Time, Marks);
            Header = TRUE;
            if (KeyMark)
                g_Marked++;
        }
        g_Entries++;
        Mark = FALSE;
        EscapeText(Name[0] ? Name : L"(default)", wcslen(Name[0] ? Name : L"(default)"), ShownName, ARRAYSIZE(ShownName));
        if (ValueString(Type, Data, Bytes, Text, ARRAYSIZE(Text)))
        {
            EscapeText(Text, wcslen(Text), Shown, ARRAYSIZE(Shown));
            Out(L"    \"%s\" %s = %s\r\n", ShownName,
                Type == REG_SZ ? L"REG_SZ" : Type == REG_EXPAND_SZ ? L"REG_EXPAND_SZ" : L"REG_MULTI_SZ", Shown);
            ReportData(Kind, Text, Hive, &Mark);
        }
        else
        {
            Out(L"    \"%s\" type %lu, %lu bytes (not text%s)\r\n", ShownName, Type, Bytes,
                Error == ERROR_MORE_DATA ? L", longer than the tool reads" : L"");
        }
        if (Mark)
        {
            g_Marked++;
            Out(L"    REVIEW\r\n");
        }
    }
    RegCloseKey(Key);
}

/* Each subkey of Path (bounded), and the value of Sub below it */
static
VOID
ReportSubkeys(
    _In_ PHIVE Hive,
    _In_ HKEY Root,
    _In_ PCWSTR Prefix,
    _In_ PCWSTR Path,
    _In_ const PCWSTR *Subs,
    _In_ ULONG SubCount,
    _In_ ULONG Kind)
{
    WCHAR Name[256], Child[MAX_PATH_CHARS];
    DWORD Index, NameChars;
    HKEY Key;
    ULONG i;

    if (RegOpenKeyExW(Root, Path, 0, KEY_ENUMERATE_SUB_KEYS, &Key) != ERROR_SUCCESS)
        return;
    for (Index = 0; Index < MAX_SUBKEYS; Index++)
    {
        NameChars = ARRAYSIZE(Name);
        if (RegEnumKeyExW(Key, Index, Name, &NameChars, NULL, NULL, NULL, NULL) != ERROR_SUCCESS)
            break;
        for (i = 0; i < SubCount; i++)
        {
            if (SUCCEEDED(StringCchPrintfW(Child, ARRAYSIZE(Child), L"%s\\%s\\%s", Path, Name, Subs[i])))
                ReportKey(Hive, Root, Prefix, Child, L"", Kind);
        }
    }
    if (Index == MAX_SUBKEYS)
        Out(L"  %s\\%s: more than %u subkeys, the rest not listed\r\n", Prefix, Path, MAX_SUBKEYS);
    RegCloseKey(Key);
}

/* The open commands of the common file types and of every URL protocol in a classes tree */
static
VOID
ReportClasses(
    _In_ PHIVE Hive,
    _In_ HKEY Classes,
    _In_ PCWSTR Prefix)
{
    static const PCWSTR Types[] =
    {
        L".exe", L".com", L".bat", L".cmd", L".scr", L".pif", L".lnk", L".msc", L".reg", L".vbs", L".js", L".ps1",
        L".txt", L".htm", L".html", L".url", L".hta", L".cpl", L".msi",
        L"exefile", L"comfile", L"batfile", L"cmdfile", L"scrfile", L"piffile", L"lnkfile", L"mscfile", L"regfile",
        L"txtfile", L"htmlfile", L"Folder", L"Directory", L"Drive", L"*", L"AllFilesystemObjects", L"ms-settings",
        L"http", L"https", L"ftp", L"mailto", L"file"
    };
    static const PCWSTR Verbs[] = { L"shell\\open\\command", L"shell\\runas\\command" };
    static const PCWSTR ClsidSubs[] = { L"InprocServer32", L"LocalServer32", L"InprocHandler32" };
    static const PCWSTR ClsidText[] = { L"TreatAs", L"ProgID" };
    WCHAR Path[MAX_PATH_CHARS], Name[256], ProgId[256];
    DWORD Index, NameChars, Bytes, Type;
    HKEY Key, Sub;
    ULONG i, j;

    /* COM classes: their servers, and where they redirect */
    ReportSubkeys(Hive, Classes, Prefix, L"CLSID", ClsidSubs, ARRAYSIZE(ClsidSubs), KIND_CMD);
    ReportSubkeys(Hive, Classes, Prefix, L"CLSID", ClsidText, ARRAYSIZE(ClsidText), KIND_TEXT);

    /* File types and their programmatic identifiers */
    for (i = 0; i < ARRAYSIZE(Types); i++)
    {
        for (j = 0; j < ARRAYSIZE(Verbs); j++)
        {
            StringCchPrintfW(Path, ARRAYSIZE(Path), L"%s\\%s", Types[i], Verbs[j]);
            ReportKey(Hive, Classes, Prefix, Path, NULL, KIND_CMD);
        }
        if (Types[i][0] != L'.')
            continue;
        /* .ext's default value names its type: that type's commands in this tree */
        if (RegOpenKeyExW(Classes, Types[i], 0, KEY_QUERY_VALUE, &Key) != ERROR_SUCCESS)
            continue;
        Bytes = sizeof(ProgId) - sizeof(WCHAR);
        ZeroMemory(ProgId, sizeof(ProgId));
        if (RegQueryValueExW(Key, NULL, NULL, &Type, (LPBYTE)ProgId, &Bytes) == ERROR_SUCCESS && Type == REG_SZ &&
            ProgId[0] && !wcschr(ProgId, L'\\'))
        {
            g_Entries++;
            Out(L"  %s\\%s (default) = ", Prefix, Types[i]);
            {
                WCHAR Shown[MAX_SHOWN_CHARS * 6 + 8];
                EscapeText(ProgId, wcslen(ProgId), Shown, ARRAYSIZE(Shown));
                Out(L"%s\r\n", Shown);
            }
            for (j = 0; j < ARRAYSIZE(Verbs); j++)
            {
                if (SUCCEEDED(StringCchPrintfW(Path, ARRAYSIZE(Path), L"%s\\%s", ProgId, Verbs[j])))
                    ReportKey(Hive, Classes, Prefix, Path, NULL, KIND_CMD);
            }
        }
        RegCloseKey(Key);
    }

    /* URL protocols: every top-level key with a "URL Protocol" value */
    if (RegOpenKeyExW(Classes, NULL, 0, KEY_ENUMERATE_SUB_KEYS, &Key) != ERROR_SUCCESS)
        return;
    for (Index = 0; Index < MAX_SUBKEYS; Index++)
    {
        NameChars = ARRAYSIZE(Name);
        if (RegEnumKeyExW(Key, Index, Name, &NameChars, NULL, NULL, NULL, NULL) != ERROR_SUCCESS)
            break;
        if (Name[0] == L'.' || !_wcsicmp(Name, L"CLSID"))
            continue;
        if (RegOpenKeyExW(Key, Name, 0, KEY_QUERY_VALUE, &Sub) != ERROR_SUCCESS)
            continue;
        if (RegQueryValueExW(Sub, L"URL Protocol", NULL, NULL, NULL, NULL) == ERROR_SUCCESS)
        {
            for (i = 0; i < ARRAYSIZE(Types); i++)
            {
                if (!_wcsicmp(Types[i], Name))
                    break;
            }
            if (i == ARRAYSIZE(Types) && SUCCEEDED(StringCchPrintfW(Path, ARRAYSIZE(Path), L"%s\\shell\\open\\command", Name)))
                ReportKey(Hive, Classes, Prefix, Path, NULL, KIND_CMD);
        }
        RegCloseKey(Sub);
    }
    RegCloseKey(Key);
}

/* Everything this tool looks at in one account's hive */
static
VOID
ReportHive(
    _In_ PHIVE Hive)
{
    static const struct
    {
        PCWSTR Path;
        PCWSTR Value;       /* NULL: every value */
        ULONG Kind;
    } Places[] =
    {
        { L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", NULL, KIND_CMD },
        { L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce", NULL, KIND_CMD },
        { L"Software\\Microsoft\\Windows\\CurrentVersion\\RunServices", NULL, KIND_CMD },
        { L"Software\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce", NULL, KIND_CMD },
        { L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run", NULL, KIND_CMD },
        { L"Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run", NULL, KIND_CMD },
        { L"Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce", NULL, KIND_CMD },
        { L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows", L"Load", KIND_LIST },
        { L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows", L"Run", KIND_LIST },
        { L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows", L"AppInit_DLLs", KIND_LIST },
        { L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", L"Shell", KIND_LIST },
        { L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", L"Userinit", KIND_LIST },
        { L"Software\\Microsoft\\Command Processor", L"AutoRun", KIND_CMD },
        { L"Environment", L"Path", KIND_PATHLIST },
        { L"Environment", L"ComSpec", KIND_FILE },
        { L"Environment", L"TEMP", KIND_DIR },
        { L"Environment", L"TMP", KIND_DIR },
        { L"Environment", L"UserInitMprLogonScript", KIND_CMD },
        { L"Environment", L"windir", KIND_DIR },
        { L"Environment", L"SystemRoot", KIND_DIR },
        { L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders", L"Startup", KIND_DIR },
        { L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders", L"Startup", KIND_DIR },
        { L"Control Panel\\Desktop", L"SCRNSAVE.EXE", KIND_FILE },
        { L"Software\\Policies\\Microsoft\\Windows\\Control Panel\\Desktop", L"SCRNSAVE.EXE", KIND_FILE },
        { L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options", NULL, KIND_TEXT },
    };
    WCHAR Name[256], Path[MAX_PATH_CHARS];
    DWORD Index, NameChars;
    HKEY Key;
    ULONG i;

    Out(L"\r\n== %s\r\n   source: %s\r\n", Hive->Label, Hive->Source);
    if (Hive->Root)
    {
        for (i = 0; i < ARRAYSIZE(Places); i++)
            ReportKey(Hive, Hive->Root, L"(hive)", Places[i].Path, Places[i].Value, Places[i].Kind);

        /* Browser helper objects of the account: their classes */
        if (RegOpenKeyExW(Hive->Root, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Browser Helper Objects",
                          0, KEY_ENUMERATE_SUB_KEYS, &Key) == ERROR_SUCCESS)
        {
            for (Index = 0; Index < MAX_SUBKEYS; Index++)
            {
                NameChars = ARRAYSIZE(Name);
                if (RegEnumKeyExW(Key, Index, Name, &NameChars, NULL, NULL, NULL, NULL) != ERROR_SUCCESS)
                    break;
                g_Entries++;
                {
                    WCHAR Shown[MAX_SHOWN_CHARS * 6 + 8];
                    EscapeText(Name, wcslen(Name), Shown, ARRAYSIZE(Shown));
                    Out(L"  (hive)\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Browser Helper Objects\\%s\r\n", Shown);
                }
                if (SUCCEEDED(StringCchPrintfW(Path, ARRAYSIZE(Path), L"Software\\Classes\\CLSID\\%s\\InprocServer32", Name)))
                    ReportKey(Hive, Hive->Root, L"(hive)", Path, L"", KIND_FILE);
                if (Hive->Classes && SUCCEEDED(StringCchPrintfW(Path, ARRAYSIZE(Path), L"CLSID\\%s\\InprocServer32", Name)))
                    ReportKey(Hive, Hive->Classes, L"(classes)", Path, L"", KIND_FILE);
            }
            RegCloseKey(Key);
        }

        /* The classes kept in the account's hive itself */
        if (RegOpenKeyExW(Hive->Root, L"Software\\Classes", 0, KEY_READ, &Key) == ERROR_SUCCESS)
        {
            ReportClasses(Hive, Key, L"(hive)\\Software\\Classes");
            RegCloseKey(Key);
        }
    }
    if (Hive->Classes)
        ReportClasses(Hive, Hive->Classes, L"(classes)");
}

/* HIVES THAT ARE NOT LOADED: A COPY, LOADED AT A SCRATCH NAME ****************/

static
BOOL
EnablePrivilege(
    _In_ PCWSTR Name)
{
    HANDLE Token;
    TOKEN_PRIVILEGES Privileges;
    BOOL Done;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &Token))
        return FALSE;
    Privileges.PrivilegeCount = 1;
    Privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    Done = LookupPrivilegeValueW(NULL, Name, &Privileges.Privileges[0].Luid) &&
           AdjustTokenPrivileges(Token, FALSE, &Privileges, 0, NULL, NULL) && GetLastError() == ERROR_SUCCESS;
    CloseHandle(Token);
    return Done;
}

/* The scratch folder: %SystemRoot%\Temp\RegAclReview.<pid>, SYSTEM and administrators only */
static
BOOL
MakeScratch(VOID)
{
    SECURITY_ATTRIBUTES Attributes;
    PSECURITY_DESCRIPTOR Sd = NULL;
    BOOL Made;

    if (FAILED(StringCchPrintfW(g_Scratch, ARRAYSIZE(g_Scratch), L"%s\\Temp\\RegAclReview.%lu.%lu",
                                g_SystemRoot, GetCurrentProcessId(), GetTickCount())) ||
        !ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)",
                                                              SDDL_REVISION_1, &Sd, NULL))
    {
        g_Scratch[0] = UNICODE_NULL;
        return FALSE;
    }
    Attributes.nLength = sizeof(Attributes);
    Attributes.lpSecurityDescriptor = Sd;
    Attributes.bInheritHandle = FALSE;
    Made = CreateDirectoryW(g_Scratch, &Attributes);
    LocalFree(Sd);
    if (!Made)
        g_Scratch[0] = UNICODE_NULL;
    return Made;
}

/* Remove what is left in the scratch folder (the copies and the log files a load made beside them), then it */
static
VOID
RemoveScratch(VOID)
{
    WCHAR Pattern[MAX_PATH], File[MAX_PATH];
    WIN32_FIND_DATAW Find;
    HANDLE Search;

    if (!g_Scratch[0])
        return;
    if (SUCCEEDED(StringCchPrintfW(Pattern, ARRAYSIZE(Pattern), L"%s\\hive*", g_Scratch)))
    {
        Search = FindFirstFileW(Pattern, &Find);
        if (Search != INVALID_HANDLE_VALUE)
        {
            do
            {
                if (!(Find.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) &&
                    SUCCEEDED(StringCchPrintfW(File, ARRAYSIZE(File), L"%s\\%s", g_Scratch, Find.cFileName)))
                {
                    DeleteFileW(File);
                }
            } while (FindNextFileW(Search, &Find));
            FindClose(Search);
        }
    }
    RemoveDirectoryW(g_Scratch);
}

/*
 * Copy the hive file at Path into the scratch folder (Copy receives its name). The file and the folders on its way
 * are opened without following reparse points; the file only for reading, with backup semantics; at most
 * MAX_HIVE_COPY_BYTES.
 */
static
BOOL
CopyHive(
    _In_ PCWSTR Path,
    _In_opt_ PSID Account,
    _Out_writes_(CopyChars) PWCHAR Copy,
    _In_ SIZE_T CopyChars,
    _Out_writes_(WhyChars) PWCHAR Why,
    _In_ SIZE_T WhyChars)
{
    TARGET Target;
    HANDLE In, Outf;
    LARGE_INTEGER Size;
    BYTE *Buffer;
    DWORD Read, Written;
    ULONGLONG Done = 0;
    BOOL Ok = FALSE;

    StringCchCopyW(Target.Path, ARRAYSIZE(Target.Path), Path);
    LookAt(&Target, Account);
    if (!Target.Exists)
    {
        StringCchPrintfW(Why, WhyChars, L"%s: %s", Path, Target.Note[0] ? Target.Note : L"not looked at");
        return FALSE;
    }
    if (!g_Scratch[0] ||
        FAILED(StringCchPrintfW(Copy, CopyChars, L"%s\\hive%lu.dat", g_Scratch, ++g_ScratchCount)))
    {
        StringCchCopyW(Why, WhyChars, L"no scratch folder");
        return FALSE;
    }
    In = CreateFileW(Path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
                     FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (In == INVALID_HANDLE_VALUE)
    {
        StringCchPrintfW(Why, WhyChars, L"%s cannot be read (error %lu)", Path, GetLastError());
        return FALSE;
    }
    if (!GetFileSizeEx(In, &Size) || (ULONGLONG)Size.QuadPart > MAX_HIVE_COPY_BYTES)
    {
        StringCchPrintfW(Why, WhyChars, L"%s: larger than the tool copies", Path);
        CloseHandle(In);
        return FALSE;
    }
    Outf = CreateFileW(Copy, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    Buffer = HeapAlloc(GetProcessHeap(), 0, 1024 * 1024);
    if (Outf != INVALID_HANDLE_VALUE && Buffer)
    {
        Ok = TRUE;
        while (Done < (ULONGLONG)Size.QuadPart)
        {
            if (!ReadFile(In, Buffer, 1024 * 1024, &Read, NULL) || Read == 0 ||
                !WriteFile(Outf, Buffer, Read, &Written, NULL) || Written != Read)
            {
                Ok = FALSE;
                break;
            }
            Done += Read;
        }
    }
    if (!Ok)
        StringCchPrintfW(Why, WhyChars, L"%s: the copy failed (error %lu)", Path, GetLastError());
    if (Buffer)
        HeapFree(GetProcessHeap(), 0, Buffer);
    if (Outf != INVALID_HANDLE_VALUE)
        CloseHandle(Outf);
    CloseHandle(In);
    return Ok;
}

/* Load the copy at HKU\RegAclReview-<n> (*Name receives it) */
static
HKEY
LoadCopy(
    _In_ PCWSTR Copy,
    _Out_writes_(NameChars) PWCHAR Name,
    _In_ SIZE_T NameChars,
    _Out_ PLONG Error)
{
    HKEY Key = NULL;

    StringCchPrintfW(Name, NameChars, L"RegAclReview-%lu-%lu", GetCurrentProcessId(), g_ScratchCount);
    *Error = RegLoadKeyW(HKEY_USERS, Name, Copy);
    if (*Error != ERROR_SUCCESS)
    {
        Name[0] = UNICODE_NULL;
        return NULL;
    }
    *Error = RegOpenKeyExW(HKEY_USERS, Name, 0, KEY_READ, &Key);
    if (*Error != ERROR_SUCCESS)
    {
        RegUnLoadKeyW(HKEY_USERS, Name);
        Name[0] = UNICODE_NULL;
        return NULL;
    }
    return Key;
}

static
VOID
UnloadCopy(
    _In_ HKEY Key,
    _Inout_ PWCHAR Name)
{
    ULONG Try;

    if (Key)
        RegCloseKey(Key);
    if (!Name[0])
        return;
    for (Try = 0; Try < 20; Try++)
    {
        if (RegUnLoadKeyW(HKEY_USERS, Name) == ERROR_SUCCESS)
            break;
        Sleep(250);
    }
    Name[0] = UNICODE_NULL;
}

/* PROFILES *******************************************************************/

/* ProfileImagePath outside the profiles folder, or a folder the account, SYSTEM or the administrators do not own */
static
VOID
ReportProfilePath(
    _In_ PCWSTR SidString,
    _In_ PSID Account,
    _In_ PCWSTR Raw,
    _Out_writes_(ExpandedChars) PWCHAR Expanded,
    _In_ SIZE_T ExpandedChars)
{
    TARGET Target;
    WCHAR Shown[MAX_SHOWN_CHARS * 6 + 8], Hive[MAX_PATH_CHARS];
    SIZE_T Dir = wcslen(g_ProfilesDir);
    BOOL Mark = FALSE, Inside;

    g_Entries++;
    EscapeText(Raw, wcslen(Raw), Shown, ARRAYSIZE(Shown));
    Out(L"  %s ProfileImagePath = %s\r\n", SidString, Shown);
    if (!ExpandFor(Raw, L"", Expanded, ExpandedChars))
    {
        Out(L"    -> names a variable the tool does not resolve: not looked at\r\n");
        Expanded[0] = UNICODE_NULL;
        return;
    }
    StringCchCopyW(Target.Path, ARRAYSIZE(Target.Path), Expanded);
    LookAt(&Target, Account);
    Inside = Dir && !_wcsnicmp(Expanded, g_ProfilesDir, Dir) && Expanded[Dir] == L'\\';
    /* The service accounts' profiles are in the system folder */
    if (!Inside && !_wcsnicmp(Expanded, g_SystemRoot, wcslen(g_SystemRoot)) &&
        (SidIs(Account, L"S-1-5-18") || SidIs(Account, L"S-1-5-19") || SidIs(Account, L"S-1-5-20")))
    {
        Inside = TRUE;
    }
    if (!Inside)
    {
        Mark = TRUE;
        EscapeText(g_ProfilesDir, wcslen(g_ProfilesDir), Shown, ARRAYSIZE(Shown));
        Out(L"    REVIEW: outside the profiles folder %s\r\n", Shown);
    }
    Out(L"    -> %s\r\n", Target.Note);
    if (Target.Mark)
        Mark = TRUE;
    /* The hive file itself */
    if (Target.Exists && SUCCEEDED(StringCchPrintfW(Hive, ARRAYSIZE(Hive), L"%s\\NTUSER.DAT", Expanded)))
    {
        StringCchCopyW(Target.Path, ARRAYSIZE(Target.Path), Hive);
        LookAt(&Target, Account);
        EscapeText(Hive, wcslen(Hive), Shown, ARRAYSIZE(Shown));
        Out(L"    -> %s: %s\r\n", Shown, Target.Note);
        if (Target.Mark)
            Mark = TRUE;
    }
    if (Mark)
    {
        g_Marked++;
        Out(L"    REVIEW\r\n");
    }
}

/* One account: its hive and its classes hive, loaded or from copies */
static
VOID
ReviewAccount(
    _In_ PCWSTR SidString,
    _In_ PSID Account,
    _In_ PCWSTR Profile)
{
    HIVE Hive;
    WCHAR Name[64], CopyPath[MAX_PATH], Why[MAX_PATH_CHARS + 64], File[MAX_PATH_CHARS], ClassesName[64], Who[512];
    WCHAR LoadedName[300];
    LONG Error;
    BOOL Copied = FALSE, ClassesCopied = FALSE;

    ZeroMemory(&Hive, sizeof(Hive));
    Name[0] = ClassesName[0] = UNICODE_NULL;
    Hive.Account = Account;
    StringCchCopyW(Hive.Profile, ARRAYSIZE(Hive.Profile), Profile);
    SidText(Account, Who, ARRAYSIZE(Who));
    StringCchPrintfW(Hive.Label, ARRAYSIZE(Hive.Label), L"%s", Who);

    /* The account's hive: loaded (its account is logged on, or a service account), or a copy of its file */
    if (RegOpenKeyExW(HKEY_USERS, SidString, 0, KEY_READ, &Hive.Root) == ERROR_SUCCESS)
    {
        StringCchPrintfW(Hive.Source, ARRAYSIZE(Hive.Source), L"loaded at HKU\\%s", SidString);
    }
    else if (Profile[0] && SUCCEEDED(StringCchPrintfW(File, ARRAYSIZE(File), L"%s\\NTUSER.DAT", Profile)))
    {
        Hive.Root = NULL;
        if (CopyHive(File, Account, CopyPath, ARRAYSIZE(CopyPath), Why, ARRAYSIZE(Why)))
        {
            Hive.Root = LoadCopy(CopyPath, Name, ARRAYSIZE(Name), &Error);
            if (Hive.Root)
            {
                Copied = TRUE;
                StringCchPrintfW(Hive.Source, ARRAYSIZE(Hive.Source),
                                 L"a copy of %s (not loaded; read from the copy, its log files not applied)", File);
            }
            else
            {
                StringCchPrintfW(Why, ARRAYSIZE(Why), L"the copy of %s could not be loaded (error %ld)", File, Error);
            }
        }
        /* Loaded meanwhile (a logon): read it there */
        if (!Hive.Root && RegOpenKeyExW(HKEY_USERS, SidString, 0, KEY_READ, &Hive.Root) == ERROR_SUCCESS)
            StringCchPrintfW(Hive.Source, ARRAYSIZE(Hive.Source), L"loaded at HKU\\%s", SidString);
        if (!Hive.Root)
            StringCchCopyW(Hive.Source, ARRAYSIZE(Hive.Source), Why);
    }
    else
    {
        StringCchCopyW(Hive.Source, ARRAYSIZE(Hive.Source), L"not loaded, no profile folder");
    }

    /* Its classes hive */
    if (SUCCEEDED(StringCchPrintfW(LoadedName, ARRAYSIZE(LoadedName), L"%s_Classes", SidString)) &&
        RegOpenKeyExW(HKEY_USERS, LoadedName, 0, KEY_READ, &Hive.Classes) == ERROR_SUCCESS)
    {
        StringCchCatW(Hive.Source, ARRAYSIZE(Hive.Source), L"; classes loaded at HKU\\");
        StringCchCatW(Hive.Source, ARRAYSIZE(Hive.Source), LoadedName);
    }
    else if (Profile[0] &&
             SUCCEEDED(StringCchPrintfW(File, ARRAYSIZE(File), L"%s\\AppData\\Local\\Microsoft\\Windows\\UsrClass.dat", Profile)))
    {
        TARGET Probe;

        Hive.Classes = NULL;
        StringCchCopyW(Probe.Path, ARRAYSIZE(Probe.Path), File);
        LookAt(&Probe, Account);
        if (Probe.Exists && CopyHive(File, Account, CopyPath, ARRAYSIZE(CopyPath), Why, ARRAYSIZE(Why)))
        {
            Hive.Classes = LoadCopy(CopyPath, ClassesName, ARRAYSIZE(ClassesName), &Error);
            ClassesCopied = (Hive.Classes != NULL);
        }
        if (ClassesCopied)
        {
            StringCchCatW(Hive.Source, ARRAYSIZE(Hive.Source), L"; classes from a copy of ");
            StringCchCatW(Hive.Source, ARRAYSIZE(Hive.Source), File);
        }
        else if (Probe.Exists)
        {
            g_Unread++;
            StringCchCatW(Hive.Source, ARRAYSIZE(Hive.Source), L"; its classes hive could not be read");
        }
    }

    if (!Hive.Root && !Hive.Classes)
        g_Unread++;
    ReportHive(&Hive);

    if (Copied)
        UnloadCopy(Hive.Root, Name);
    else if (Hive.Root)
        RegCloseKey(Hive.Root);
    if (ClassesCopied)
        UnloadCopy(Hive.Classes, ClassesName);
    else if (Hive.Classes)
        RegCloseKey(Hive.Classes);
}

/* Every profile ProfileList names, then .DEFAULT */
static
VOID
ReviewProfiles(VOID)
{
    static const PCWSTR ListPath = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList";
    WCHAR SidString[256], Raw[MAX_PATH_CHARS], Expanded[MAX_PATH_CHARS];
    struct
    {
        WCHAR Sid[256];
        WCHAR Profile[MAX_PATH_CHARS];
    } *Accounts;
    DWORD Index, Chars, Bytes, Type, Count = 0, i;
    HKEY List, Key;
    PSID Account;
    HIVE Default;

    Out(L"\r\n== Profiles (HKLM\\%s)\r\n", ListPath);
    Accounts = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, MAX_ACCOUNTS * sizeof(*Accounts));
    if (!Accounts || RegOpenKeyExW(HKEY_LOCAL_MACHINE, ListPath, 0, KEY_READ, &List) != ERROR_SUCCESS)
    {
        Out(L"  cannot be read\r\n");
        g_Unread++;
        if (Accounts)
            HeapFree(GetProcessHeap(), 0, Accounts);
        return;
    }
    for (Index = 0; Index < MAX_ACCOUNTS; Index++)
    {
        Chars = ARRAYSIZE(SidString);
        if (RegEnumKeyExW(List, Index, SidString, &Chars, NULL, NULL, NULL, NULL) != ERROR_SUCCESS)
            break;
        if (!ConvertStringSidToSidW(SidString, &Account))
            continue;
        Raw[0] = Expanded[0] = UNICODE_NULL;
        if (RegOpenKeyExW(List, SidString, 0, KEY_QUERY_VALUE, &Key) == ERROR_SUCCESS)
        {
            Bytes = sizeof(Raw) - sizeof(WCHAR);
            ZeroMemory(Raw, sizeof(Raw));
            if (RegQueryValueExW(Key, L"ProfileImagePath", NULL, &Type, (LPBYTE)Raw, &Bytes) == ERROR_SUCCESS &&
                (Type == REG_SZ || Type == REG_EXPAND_SZ))
            {
                ReportProfilePath(SidString, Account, Raw, Expanded, ARRAYSIZE(Expanded));
            }
            RegCloseKey(Key);
        }
        StringCchCopyW(Accounts[Count].Sid, ARRAYSIZE(Accounts[Count].Sid), SidString);
        StringCchCopyW(Accounts[Count].Profile, ARRAYSIZE(Accounts[Count].Profile), Expanded);
        Count++;
        LocalFree(Account);
    }
    RegCloseKey(List);

    /* The hives: SYSTEM's is .DEFAULT (below) */
    for (i = 0; i < Count; i++)
    {
        if (!_wcsicmp(Accounts[i].Sid, L"S-1-5-18") || !ConvertStringSidToSidW(Accounts[i].Sid, &Account))
            continue;
        ReviewAccount(Accounts[i].Sid, Account, Accounts[i].Profile);
        LocalFree(Account);
    }
    HeapFree(GetProcessHeap(), 0, Accounts);

    /* .DEFAULT: SYSTEM's, and the template of the logon desktop */
    ZeroMemory(&Default, sizeof(Default));
    if (ConvertStringSidToSidW(L"S-1-5-18", &Account))
    {
        Default.Account = Account;
        StringCchCopyW(Default.Label, ARRAYSIZE(Default.Label), L"HKU\\.DEFAULT (SYSTEM)");
        StringCchCopyW(Default.Source, ARRAYSIZE(Default.Source), L"loaded at HKU\\.DEFAULT");
        if (RegOpenKeyExW(HKEY_USERS, L".DEFAULT", 0, KEY_READ, &Default.Root) == ERROR_SUCCESS)
        {
            ReportHive(&Default);
            RegCloseKey(Default.Root);
        }
        else
        {
            g_Unread++;
            Out(L"\r\n== HKU\\.DEFAULT cannot be read\r\n");
        }
        LocalFree(Account);
    }
}

/* Non-SID hives under HKU (an administrator's reg load HKU\<name>): their descriptors are used as they are */
static
VOID
ReviewOtherHives(VOID)
{
    WCHAR Name[256], Shown[MAX_SHOWN_CHARS * 6 + 8];
    DWORD Index, Chars;
    PSID Sid;
    BOOL Header = FALSE;
    SIZE_T Length;

    for (Index = 0; Index < 4096; Index++)
    {
        Chars = ARRAYSIZE(Name);
        if (RegEnumKeyExW(HKEY_USERS, Index, Name, &Chars, NULL, NULL, NULL, NULL) != ERROR_SUCCESS)
            break;
        if (!_wcsicmp(Name, L".DEFAULT") || !_wcsnicmp(Name, L"RegAclReview-", 13))
            continue;
        Length = wcslen(Name);
        if (EndsWith(Name, Length, L"_Classes"))
            Name[Length - 8] = UNICODE_NULL;
        if (ConvertStringSidToSidW(Name, &Sid))
        {
            LocalFree(Sid);
            continue;
        }
        if (!Header)
        {
            Out(L"\r\n== Hives loaded at a name that is not an account's (not checked at their load; their permissions apply as stored)\r\n");
            Header = TRUE;
        }
        g_Entries++;
        g_Marked++;
        EscapeText(Name, wcslen(Name), Shown, ARRAYSIZE(Shown));
        Out(L"  HKU\\%s  REVIEW\r\n", Shown);
    }
}

/* MACHINE ********************************************************************/

/*
 * The lines of the registry audit log (LogFiles\RegAcl\audit.log and the previous audit.log.1) that name keys the
 * transition to enforcement replaced (op "restamp") or kept although others may change them (op "keptgrant").
 * The kernel writes the log (a folder only SYSTEM and administrators write); the lines are still shown escaped.
 */
static
VOID
ReportTransitionLog(VOID)
{
    static const PCWSTR Names[] = { L"audit.log.1", L"audit.log" };
    WCHAR Path[MAX_PATH], Wide[2048], Shown[MAX_SHOWN_CHARS * 6 + 8];
    char *Data, *Line, *End;
    HANDLE File;
    LARGE_INTEGER Size;
    DWORD Read;
    ULONG i, Restamps = 0, Kept = 0, Shownn = 0;
    int Chars;

    Out(L"\r\n== Keys the first enforcing boot replaced (restamp) or kept although others may change them (keptgrant)\r\n"
        L"   from LogFiles\\RegAcl\\audit.log(.1); the log keeps a bounded number of lines per boot, so the list may be incomplete\r\n");
    for (i = 0; i < ARRAYSIZE(Names); i++)
    {
        if (FAILED(StringCchPrintfW(Path, ARRAYSIZE(Path), L"%s\\System32\\LogFiles\\RegAcl\\%s", g_SystemRoot, Names[i])))
            continue;
        File = CreateFileW(Path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
                           FILE_FLAG_OPEN_REPARSE_POINT, NULL);
        if (File == INVALID_HANDLE_VALUE)
            continue;
        if (!GetFileSizeEx(File, &Size) || Size.QuadPart > 16 * 1024 * 1024 ||
            !(Data = HeapAlloc(GetProcessHeap(), 0, (SIZE_T)Size.QuadPart + 1)))
        {
            CloseHandle(File);
            continue;
        }
        if (!ReadFile(File, Data, (DWORD)Size.QuadPart, &Read, NULL))
            Read = 0;
        CloseHandle(File);
        Data[Read] = '\0';
        for (Line = Data; Line < Data + Read; Line = End + 1)
        {
            BOOL Restamp, Keep;

            End = memchr(Line, '\n', Data + Read - Line);
            if (!End)
                End = Data + Read;
            *End = '\0';
            Restamp = strstr(Line, "\"op\":\"restamp\"") != NULL;
            Keep = strstr(Line, "\"op\":\"keptgrant\"") != NULL;
            if (!Restamp && !Keep)
                continue;
            Restamp ? Restamps++ : Kept++;
            if (Shownn >= 2000)
                continue;
            Shownn++;
            Chars = MultiByteToWideChar(CP_UTF8, 0, Line, -1, Wide, ARRAYSIZE(Wide) - 1);
            Wide[Chars > 0 ? Chars : 0] = UNICODE_NULL;
            EscapeText(Wide, wcslen(Wide), Shown, ARRAYSIZE(Shown));
            Out(L"  %s%s\r\n", Keep ? L"REVIEW " : L"", Shown);
            if (Keep)
                g_Marked++;
        }
        HeapFree(GetProcessHeap(), 0, Data);
    }
    g_Entries += Restamps + Kept;
    Out(L"  %lu replaced, %lu kept although others may change them%s\r\n", Restamps, Kept,
        Shownn >= 2000 ? L" (the first 2000 shown)" : L"");
}

/*
 * The machine's own places that start programs as anyone who logs on, or as the system, and the program files of the
 * services that are not in the system folder. Listed as for the accounts (no account owns them: a file that belongs
 * to anyone but SYSTEM and the administrators is marked).
 */
static
VOID
ReviewMachine(VOID)
{
    static const struct
    {
        PCWSTR Path;
        PCWSTR Value;
        ULONG Kind;
    } Places[] =
    {
        { L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", NULL, KIND_CMD },
        { L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce", NULL, KIND_CMD },
        { L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServices", NULL, KIND_CMD },
        { L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce", NULL, KIND_CMD },
        { L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run", NULL, KIND_CMD },
        { L"SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run", NULL, KIND_CMD },
        { L"SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce", NULL, KIND_CMD },
        { L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", L"Shell", KIND_LIST },
        { L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", L"Userinit", KIND_LIST },
        { L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows", L"AppInit_DLLs", KIND_LIST },
        { L"SOFTWARE\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Windows", L"AppInit_DLLs", KIND_LIST },
        { L"SOFTWARE\\Microsoft\\Command Processor", L"AutoRun", KIND_CMD },
        { L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment", L"Path", KIND_PATHLIST },
        { L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment", L"ComSpec", KIND_FILE },
    };
    static const PCWSTR Ifeo[] =
    {
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options",
        L"SOFTWARE\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options",
    };
    WCHAR Name[256], Path[MAX_PATH_CHARS], Raw[MAX_PATH_CHARS], Expanded[MAX_PATH_CHARS], Program[MAX_PATH_CHARS];
    DWORD Index, NameChars, Bytes, Type, Services = 0, Outside = 0;
    PCWSTR Rest;
    HKEY Key, Sub;
    HIVE Machine;
    ULONG i, j;

    ZeroMemory(&Machine, sizeof(Machine));
    Machine.Root = HKEY_LOCAL_MACHINE;
    StringCchCopyW(Machine.Label, ARRAYSIZE(Machine.Label), L"HKLM (the machine)");
    Out(L"\r\n== HKLM (the machine): places that start programs for every account or as the system\r\n");
    for (i = 0; i < ARRAYSIZE(Places); i++)
        ReportKey(&Machine, HKEY_LOCAL_MACHINE, L"HKLM", Places[i].Path, Places[i].Value, Places[i].Kind);

    /* Image File Execution Options: a Debugger value starts that program in place of the one named */
    for (j = 0; j < ARRAYSIZE(Ifeo); j++)
    {
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, Ifeo[j], 0, KEY_ENUMERATE_SUB_KEYS, &Key) != ERROR_SUCCESS)
            continue;
        for (Index = 0; Index < MAX_SUBKEYS; Index++)
        {
            NameChars = ARRAYSIZE(Name);
            if (RegEnumKeyExW(Key, Index, Name, &NameChars, NULL, NULL, NULL, NULL) != ERROR_SUCCESS)
                break;
            if (SUCCEEDED(StringCchPrintfW(Path, ARRAYSIZE(Path), L"%s\\%s", Ifeo[j], Name)))
            {
                ReportKey(&Machine, HKEY_LOCAL_MACHINE, L"HKLM", Path, L"Debugger", KIND_CMD);
                ReportKey(&Machine, HKEY_LOCAL_MACHINE, L"HKLM", Path, L"VerifierDlls", KIND_TEXT);
            }
        }
        RegCloseKey(Key);
    }

    /* Services and drivers whose program file is not in the system folder (the others are counted) */
    Out(L"  services and drivers whose program is outside %s:\r\n", g_SystemRoot);
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services", 0, KEY_ENUMERATE_SUB_KEYS, &Key) ==
        ERROR_SUCCESS)
    {
        for (Index = 0; Index < MAX_SUBKEYS; Index++)
        {
            NameChars = ARRAYSIZE(Name);
            if (RegEnumKeyExW(Key, Index, Name, &NameChars, NULL, NULL, NULL, NULL) != ERROR_SUCCESS)
                break;
            for (j = 0; j < 2; j++)
            {
                if (FAILED(StringCchPrintfW(Path, ARRAYSIZE(Path), j ? L"%s\\Parameters" : L"%s", Name)) ||
                    RegOpenKeyExW(Key, Path, 0, KEY_QUERY_VALUE, &Sub) != ERROR_SUCCESS)
                {
                    continue;
                }
                ZeroMemory(Raw, sizeof(Raw));
                Bytes = sizeof(Raw) - sizeof(WCHAR);
                if (RegQueryValueExW(Sub, j ? L"ServiceDll" : L"ImagePath", NULL, &Type, (LPBYTE)Raw, &Bytes) ==
                        ERROR_SUCCESS && (Type == REG_SZ || Type == REG_EXPAND_SZ) && Raw[0])
                {
                    Services++;
                    /* Driver paths are relative to the system root (System32\drivers\x.sys, \SystemRoot\...) */
                    ExpandFor(Raw, L"", Expanded, ARRAYSIZE(Expanded));
                    ProgramOf(!_wcsnicmp(Expanded, L"\\??\\", 4) ? Expanded + 4 : Expanded, Program,
                              ARRAYSIZE(Program), &Rest);
                    if (!_wcsnicmp(Program, L"\\SystemRoot\\", 12) || !_wcsnicmp(Program, L"System32\\", 9) ||
                        (!_wcsnicmp(Program, g_SystemRoot, wcslen(g_SystemRoot)) && Program[wcslen(g_SystemRoot)] == L'\\'))
                    {
                        RegCloseKey(Sub);
                        continue;
                    }
                    Outside++;
                    StringCchPrintfW(Path, ARRAYSIZE(Path), j ? L"SYSTEM\\CurrentControlSet\\Services\\%s\\Parameters" :
                                                                L"SYSTEM\\CurrentControlSet\\Services\\%s", Name);
                    ReportKey(&Machine, HKEY_LOCAL_MACHINE, L"HKLM", Path, j ? L"ServiceDll" : L"ImagePath",
                              j ? KIND_FILE : KIND_CMD);
                }
                RegCloseKey(Sub);
            }
        }
        RegCloseKey(Key);
    }
    Out(L"  %lu service program paths, %lu outside the system folder (listed above)\r\n", Services, Outside);
    Out(L"  (service settings that name a program in the system folder, e.g. an ImagePath changed to cmd.exe, are not\r\n"
        L"  listed: compare `sc qc <name>` with a fresh install if untrusted accounts used this computer)\r\n");

    ReportTransitionLog();
}

/* MAIN ***********************************************************************/

static
BOOL
IsAdministrator(VOID)
{
    PSID Admins = NULL;
    BOOL Member = FALSE;

    if (ConvertStringSidToSidW(L"S-1-5-32-544", &Admins))
    {
        if (!CheckTokenMembership(NULL, Admins, &Member))
            Member = FALSE;
        LocalFree(Admins);
    }
    return Member;
}

static
VOID
ReadMode(
    _Out_writes_(Chars) PWCHAR Buffer,
    _In_ SIZE_T Chars)
{
    DWORD Transition = MAXDWORD, Removed = 0, Was = MAXDWORD, Bytes;
    HKEY Key;

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\RegAcl\\AuditStats", 0,
                      KEY_QUERY_VALUE, &Key) == ERROR_SUCCESS)
    {
        Bytes = sizeof(Transition);
        RegQueryValueExW(Key, L"Transition", NULL, NULL, (LPBYTE)&Transition, &Bytes);
        Bytes = sizeof(Removed);
        RegQueryValueExW(Key, L"ModeValueRemoved", NULL, NULL, (LPBYTE)&Removed, &Bytes);
        Bytes = sizeof(Was);
        RegQueryValueExW(Key, L"ModeValueWas", NULL, NULL, (LPBYTE)&Was, &Bytes);
        RegCloseKey(Key);
    }
    StringCchPrintfW(Buffer, Chars, L"registry key security is enforced (always; transition state %ld)",
                     (LONG)Transition);
    g_ModeValueRemoved = Removed;
    g_ModeValueWas = Was;
}

static
BOOL
WriteReport(
    _In_ PCWSTR Path,
    _In_ BOOL Replace)
{
    HANDLE File;
    DWORD Written;
    int Bytes;
    char *Utf8;
    BOOL Ok;

    Bytes = WideCharToMultiByte(CP_UTF8, 0, g_Text, (int)g_TextChars, NULL, 0, NULL, NULL);
    Utf8 = HeapAlloc(GetProcessHeap(), 0, Bytes + 3);
    if (!Utf8)
        return FALSE;
    Utf8[0] = (char)0xEF;
    Utf8[1] = (char)0xBB;
    Utf8[2] = (char)0xBF;
    WideCharToMultiByte(CP_UTF8, 0, g_Text, (int)g_TextChars, Utf8 + 3, Bytes, NULL, NULL);
    File = CreateFileW(Path, GENERIC_WRITE, 0, NULL, Replace ? CREATE_ALWAYS : CREATE_NEW,
                       FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    if (File == INVALID_HANDLE_VALUE)
    {
        HeapFree(GetProcessHeap(), 0, Utf8);
        return FALSE;
    }
    Ok = WriteFile(File, Utf8, Bytes + 3, &Written, NULL) && Written == (DWORD)Bytes + 3;
    CloseHandle(File);
    HeapFree(GetProcessHeap(), 0, Utf8);
    return Ok;
}

static
VOID
LogEvent(
    _In_ PCWSTR Report,
    _In_ int Exit)
{
    WCHAR Text[MAX_PATH * 2];
    PCWSTR Strings[1] = { Text };
    HANDLE Source;

    StringCchPrintfW(Text, ARRAYSIZE(Text),
                     L"Registry review: %lu entries listed, %lu marked REVIEW, %lu hives or parts not read. Report: %s",
                     g_Entries, g_Marked, g_Unread, Report);
    Source = RegisterEventSourceW(NULL, EVENT_SOURCE);
    if (!Source)
        return;
    ReportEventW(Source, g_Marked ? EVENTLOG_WARNING_TYPE : EVENTLOG_INFORMATION_TYPE, 0, 1000 + Exit, NULL, 1, 0,
                 Strings, NULL);
    DeregisterEventSource(Source);
}

static
VOID
Usage(VOID)
{
    wprintf(L"regaclreview [/out <file>] [/transition] [/print]\n"
            L"  Lists, for every account's registry hive and the service accounts' hives, the settings that start\n"
            L"  or load programs, and the profile folders. Changes nothing. Run as an administrator.\n"
            L"  /out <file>    write the report there (default %%SystemRoot%%\\System32\\LogFiles\\RegAcl\\review-<time>.txt)\n"
            L"  /transition    the report of the first boot that enforces (LogFiles\\RegAcl\\transition-review.txt)\n"
            L"  /print         also print the report\n"
            L"  Exit code: 0 nothing marked, 1 entries marked REVIEW, 2 something could not be read, 3 both,\n"
            L"  4 no report.\n");
}

int
wmain(
    int argc,
    WCHAR **argv)
{
    WCHAR Report[MAX_PATH], Mode[160], Computer[MAX_COMPUTERNAME_LENGTH + 1], Time[32];
    DWORD Chars = ARRAYSIZE(Computer);
    BOOL Transition = FALSE, Print = FALSE, Replace = FALSE;
    SYSTEMTIME Now;
    FILETIME NowFt;
    int i, Exit;

    Report[0] = UNICODE_NULL;
    for (i = 1; i < argc; i++)
    {
        if (!_wcsicmp(argv[i], L"/out") && i + 1 < argc)
        {
            StringCchCopyW(Report, ARRAYSIZE(Report), argv[++i]);
            Replace = TRUE;
        }
        else if (!_wcsicmp(argv[i], L"/transition"))
            Transition = TRUE;
        else if (!_wcsicmp(argv[i], L"/print"))
            Print = TRUE;
        else
        {
            Usage();
            return 4;
        }
    }

    if (!IsAdministrator())
    {
        fwprintf(stderr, L"regaclreview: run it as an administrator (it reads other accounts' settings)\n");
        return 4;
    }
    EnablePrivilege(SE_BACKUP_NAME);
    EnablePrivilege(SE_RESTORE_NAME);

    GetEnvironmentVariableW(L"SystemRoot", g_SystemRoot, ARRAYSIZE(g_SystemRoot));
    if (!g_SystemRoot[0])
        GetWindowsDirectoryW(g_SystemRoot, ARRAYSIZE(g_SystemRoot));
    StringCchCopyNW(g_SystemDrive, ARRAYSIZE(g_SystemDrive), g_SystemRoot, 2);
    {
        HKEY Key;
        DWORD Bytes, Type;
        WCHAR Raw[MAX_PATH];

        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion", 0,
                          KEY_QUERY_VALUE | KEY_WOW64_64KEY, &Key) == ERROR_SUCCESS)
        {
            Bytes = sizeof(g_ProgramFiles) - sizeof(WCHAR);
            RegQueryValueExW(Key, L"ProgramFilesDir", NULL, &Type, (LPBYTE)g_ProgramFiles, &Bytes);
            Bytes = sizeof(g_ProgramFilesX86) - sizeof(WCHAR);
            RegQueryValueExW(Key, L"ProgramFilesDir (x86)", NULL, &Type, (LPBYTE)g_ProgramFilesX86, &Bytes);
            Bytes = sizeof(g_CommonFiles) - sizeof(WCHAR);
            RegQueryValueExW(Key, L"CommonFilesDir", NULL, &Type, (LPBYTE)g_CommonFiles, &Bytes);
            RegCloseKey(Key);
        }
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList", 0,
                          KEY_QUERY_VALUE, &Key) == ERROR_SUCCESS)
        {
            ZeroMemory(Raw, sizeof(Raw));
            Bytes = sizeof(Raw) - sizeof(WCHAR);
            if (RegQueryValueExW(Key, L"ProfilesDirectory", NULL, &Type, (LPBYTE)Raw, &Bytes) == ERROR_SUCCESS)
                ExpandFor(Raw, L"", g_ProfilesDir, ARRAYSIZE(g_ProfilesDir));
            ZeroMemory(Raw, sizeof(Raw));
            Bytes = sizeof(Raw) - sizeof(WCHAR);
            if (RegQueryValueExW(Key, L"ProgramData", NULL, &Type, (LPBYTE)Raw, &Bytes) == ERROR_SUCCESS)
                ExpandFor(Raw, L"", g_ProgramData, ARRAYSIZE(g_ProgramData));
            RegCloseKey(Key);
        }
    }
    LoadAdmins();

    GetSystemTime(&Now);
    SystemTimeToFileTime(&Now, &NowFt);
    FileTimeText(&NowFt, Time, ARRAYSIZE(Time));
    if (!Report[0])
    {
        if (Transition)
            StringCchPrintfW(Report, ARRAYSIZE(Report), L"%s\\System32\\LogFiles\\RegAcl\\transition-review.txt", g_SystemRoot);
        else
            StringCchPrintfW(Report, ARRAYSIZE(Report), L"%s\\System32\\LogFiles\\RegAcl\\review-%04u%02u%02u-%02u%02u%02u.txt",
                             g_SystemRoot, Now.wYear, Now.wMonth, Now.wDay, Now.wHour, Now.wMinute, Now.wSecond);
    }
    if (!GetComputerNameW(Computer, &Chars))
        Computer[0] = UNICODE_NULL;
    ReadMode(Mode, ARRAYSIZE(Mode));

    Out(L"Registry review (regaclreview %u) of %s, %s%s\r\n%s\r\n", REVIEW_VERSION, Computer, Time,
        Transition ? L", first boot that enforces" : L"", Mode);
    Out(L"\r\nThis report lists; it changes nothing and judges nothing. While registry key security was not enforced,\r\n"
        L"any account could write these settings, also in other accounts' hives. Check each entry you did not make,\r\n"
        L"first the ones marked REVIEW: what they name belongs to another account that is not an administrator, the\r\n"
        L"key may be written by others, or the key is labelled below Medium. The legitimate settings of programs\r\n"
        L"(per-user installs, file types) are listed too. The last sections list the machine's own places (HKLM Run\r\n"
        L"keys, Winlogon, AppInit_DLLs, Image File Execution Options debuggers, services outside the system folder)\r\n"
        L"and the keys the first enforcing boot replaced or kept.\r\n");

    MakeScratch();
    ReviewProfiles();
    ReviewOtherHives();
    ReviewMachine();
    RemoveScratch();

    Exit = (g_Marked ? 1 : 0) | (g_Unread ? 2 : 0);
    Out(L"\r\n== Summary: %lu entries, %lu marked REVIEW, %lu hives or parts not read\r\n", g_Entries, g_Marked, g_Unread);
    if (g_OutOfMemory)
        return 4;

    if (!WriteReport(Report, Replace || Transition))
    {
        fwprintf(stderr, L"regaclreview: cannot write %s (error %lu)\n", Report, GetLastError());
        Exit = 4;
    }
    else
    {
        LogEvent(Report, Exit);
        wprintf(L"regaclreview: %lu entries, %lu marked REVIEW, %lu not read; report %s\n", g_Entries, g_Marked,
                g_Unread, Report);
    }
    if (Print)
        WriteConsoleW(GetStdHandle(STD_OUTPUT_HANDLE), g_Text, (DWORD)g_TextChars, &Chars, NULL);
    return Exit;
}
