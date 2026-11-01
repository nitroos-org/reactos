/*
 * PROJECT:     ReactOS user profile library
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     AppContainer security identifiers
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * The identifier of an AppContainer is derived from its name: the name is converted to lower case and hashed
 * with SHA-256 over its UTF-16 little-endian bytes, and the first seven 32-bit words of the hash follow the
 * authority 15 and the first sub-authority 2 (measured on Windows 10; names of 1 to 64 characters).
 */

#include "precomp.h"

#include <aclapi.h>
#include <sddl.h>

#define APPCONTAINER_NAME_MAX 64
#define APPCONTAINER_HASH_WORDS 7

/* SHA-256 after FIPS 180-4 */
typedef struct _SHA256_STATE
{
    ULONG H[8];
    ULONGLONG Bytes;
    UCHAR Block[64];
    ULONG Used;
} SHA256_STATE;

static const ULONG Sha256K[64] =
{
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

#define ROTR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

static
VOID
Sha256Transform(
    _Inout_ SHA256_STATE *State,
    _In_reads_bytes_(64) const UCHAR *Block)
{
    ULONG W[64], a, b, c, d, e, f, g, h, t1, t2;
    ULONG i;

    for (i = 0; i < 16; i++)
    {
        W[i] = ((ULONG)Block[i * 4] << 24) | ((ULONG)Block[i * 4 + 1] << 16) |
               ((ULONG)Block[i * 4 + 2] << 8) | (ULONG)Block[i * 4 + 3];
    }
    for (; i < 64; i++)
    {
        ULONG s0 = ROTR(W[i - 15], 7) ^ ROTR(W[i - 15], 18) ^ (W[i - 15] >> 3);
        ULONG s1 = ROTR(W[i - 2], 17) ^ ROTR(W[i - 2], 19) ^ (W[i - 2] >> 10);

        W[i] = W[i - 16] + s0 + W[i - 7] + s1;
    }

    a = State->H[0]; b = State->H[1]; c = State->H[2]; d = State->H[3];
    e = State->H[4]; f = State->H[5]; g = State->H[6]; h = State->H[7];
    for (i = 0; i < 64; i++)
    {
        t1 = h + (ROTR(e, 6) ^ ROTR(e, 11) ^ ROTR(e, 25)) + ((e & f) ^ (~e & g)) + Sha256K[i] + W[i];
        t2 = (ROTR(a, 2) ^ ROTR(a, 13) ^ ROTR(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }
    State->H[0] += a; State->H[1] += b; State->H[2] += c; State->H[3] += d;
    State->H[4] += e; State->H[5] += f; State->H[6] += g; State->H[7] += h;
}

static
VOID
Sha256Init(
    _Out_ SHA256_STATE *State)
{
    State->H[0] = 0x6a09e667; State->H[1] = 0xbb67ae85; State->H[2] = 0x3c6ef372; State->H[3] = 0xa54ff53a;
    State->H[4] = 0x510e527f; State->H[5] = 0x9b05688c; State->H[6] = 0x1f83d9ab; State->H[7] = 0x5be0cd19;
    State->Bytes = 0;
    State->Used = 0;
}

static
VOID
Sha256Update(
    _Inout_ SHA256_STATE *State,
    _In_reads_bytes_(Length) const UCHAR *Data,
    _In_ ULONG Length)
{
    State->Bytes += Length;
    while (Length)
    {
        ULONG Chunk = min(Length, 64 - State->Used);

        RtlCopyMemory(State->Block + State->Used, Data, Chunk);
        State->Used += Chunk;
        Data += Chunk;
        Length -= Chunk;
        if (State->Used == 64)
        {
            Sha256Transform(State, State->Block);
            State->Used = 0;
        }
    }
}

/* The first words of the hash, as 32-bit values of the little-endian byte order of the digest */
static
VOID
Sha256Final(
    _Inout_ SHA256_STATE *State,
    _Out_writes_(Words) PULONG Output,
    _In_ ULONG Words)
{
    ULONGLONG Bits = State->Bytes * 8;
    UCHAR Digest[32];
    ULONG i;

    State->Block[State->Used++] = 0x80;
    if (State->Used > 56)
    {
        RtlZeroMemory(State->Block + State->Used, 64 - State->Used);
        Sha256Transform(State, State->Block);
        State->Used = 0;
    }
    RtlZeroMemory(State->Block + State->Used, 56 - State->Used);
    for (i = 0; i < 8; i++)
        State->Block[56 + i] = (UCHAR)(Bits >> (56 - i * 8));
    Sha256Transform(State, State->Block);

    for (i = 0; i < 8; i++)
    {
        Digest[i * 4] = (UCHAR)(State->H[i] >> 24);
        Digest[i * 4 + 1] = (UCHAR)(State->H[i] >> 16);
        Digest[i * 4 + 2] = (UCHAR)(State->H[i] >> 8);
        Digest[i * 4 + 3] = (UCHAR)State->H[i];
    }
    for (i = 0; i < Words; i++)
    {
        Output[i] = (ULONG)Digest[i * 4] | ((ULONG)Digest[i * 4 + 1] << 8) |
                    ((ULONG)Digest[i * 4 + 2] << 16) | ((ULONG)Digest[i * 4 + 3] << 24);
    }
}

/*
 * @implemented
 */
HRESULT
WINAPI
DeriveAppContainerSidFromAppContainerName(
    _In_ PCWSTR pszAppContainerName,
    _Outptr_ PSID *ppsidAppContainerSid)
{
    static SID_IDENTIFIER_AUTHORITY AppPackageAuthority = { { 0, 0, 0, 0, 0, 15 } };
    WCHAR Lower[APPCONTAINER_NAME_MAX];
    ULONG Hash[APPCONTAINER_HASH_WORDS];
    SHA256_STATE State;
    SIZE_T Length;
    ULONG i;
    PSID Sid;

    if (!pszAppContainerName || !ppsidAppContainerSid)
        return E_INVALIDARG;

    for (Length = 0; Length <= APPCONTAINER_NAME_MAX && pszAppContainerName[Length]; Length++)
        ;
    if (Length == 0 || Length > APPCONTAINER_NAME_MAX)
        return E_INVALIDARG;

    for (i = 0; i < Length; i++)
        Lower[i] = RtlDowncaseUnicodeChar(pszAppContainerName[i]);

    Sha256Init(&State);
    Sha256Update(&State, (const UCHAR *)Lower, (ULONG)(Length * sizeof(WCHAR)));
    Sha256Final(&State, Hash, APPCONTAINER_HASH_WORDS);

    if (!AllocateAndInitializeSid(&AppPackageAuthority, 8, 2, Hash[0], Hash[1], Hash[2], Hash[3],
                                  Hash[4], Hash[5], Hash[6], &Sid))
    {
        return HRESULT_FROM_WIN32(GetLastError());
    }

    *ppsidAppContainerSid = Sid;
    return S_OK;
}

/*
 * PROFILES
 *
 * An AppContainer profile is, as measured on Windows 10 22H2 (CreateAppContainerProfile, once, with a throwaway
 * name, deleted again in the same probe):
 *  - HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Mappings\<SID>
 *    with the values Moniker and DisplayName (kernelbase!AppContainerRegisterSid) and an empty subkey Children;
 *  - ...\AppContainer\Storage\<name> and its subkey Children, both with the AppContainer SID in the access list;
 *  - %LOCALAPPDATA%\Packages\<name>\AC with the subfolders INetCache, INetCookies, INetHistory and Temp, the
 *    AppContainer SID in the access lists. The capabilities passed in are not stored anywhere.
 * A second create of the name fails with HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS) and leaves the result alone;
 * delete removes all of it and succeeds also for a name that does not exist. ReactOS has no AppContainer tokens,
 * so access lists are written as Windows does but nothing checks them.
 *
 * NAMES. The moniker, the Storage key and the folder carry the name in lower case. Windows takes a name as it comes:
 * create builds %LOCALAPPDATA%\Packages\<name> as a Win32 path, so "/" and "\" separate folders, "." and ".." are
 * dots of the path (".." is the folder above Packages, which then holds the AC folder), and one trailing dot of a
 * folder is dropped. delete builds the same path in the literal \\?\ form instead, so it rejects "/", "." and ".."
 * (ERROR_INVALID_NAME) and only removes the folder that has exactly that spelling. ReactOS does the same, with one
 * rule above all: it only ever creates or removes folders strictly below the canonical Packages folder (see
 * ResolveProfileRoot and DeleteProfileFolder). A name that leads out of Packages, which on Windows makes folders
 * outside of it, gets its registration and an S_OK here, but no folders. Windows leaves the root folder of a create
 * that failed behind; ReactOS rolls such a create back. Delete of a name with a trailing dot succeeds on both without
 * removing the folder, which has another spelling.
 */

/* Windows Vista and later; userenv imports it from advapi32_vista */
LONG WINAPI RegDeleteTreeW(HKEY hKey, LPCWSTR lpSubKey);

#define APPCONTAINER_MAPPINGS \
    L"Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\CurrentVersion\\AppContainer\\Mappings"
#define APPCONTAINER_STORAGE \
    L"Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\CurrentVersion\\AppContainer\\Storage"
#define APPCONTAINER_DISPLAY_NAME_MAX 512
#define APPCONTAINER_DESCRIPTION_MAX 2048
#define ACE_FLAG_CRITICAL 0x20
#define PROFILE_PATH_MAX MAX_PATH
/* What GetAppContainerFolderPath answers for a SID that is not an AppContainer SID (measured) */
#define ERROR_APPCONTAINER_NOT_AN_APPCONTAINER_SID 4250

typedef HRESULT (WINAPI *PFN_REGISTER_SID)(PSID, PCWSTR, PCWSTR);
typedef HRESULT (WINAPI *PFN_UNREGISTER_SID)(PSID);
typedef HRESULT (WINAPI *PFN_LOOKUP_MONIKER)(PSID, PWSTR *);
typedef BOOLEAN (WINAPI *PFN_FREE_MEMORY)(PVOID);
typedef LPVOID (WINAPI *PFN_COTASKMEMALLOC)(SIZE_T);

static
BOOL
IsAppContainerSid(
    _In_ PSID Sid)
{
    static SID_IDENTIFIER_AUTHORITY AppPackageAuthority = { { 0, 0, 0, 0, 0, 15 } };

    return IsValidSid(Sid) &&
           !memcmp(GetSidIdentifierAuthority(Sid), &AppPackageAuthority, sizeof(AppPackageAuthority)) &&
           *GetSidSubAuthorityCount(Sid) == 8 &&
           *GetSidSubAuthority(Sid, 0) == 2;
}

/* The registration functions of kernelbase, which userenv does not link against */
static
HRESULT
GetRegistrationFunctions(
    _Out_opt_ PFN_REGISTER_SID *Register,
    _Out_opt_ PFN_UNREGISTER_SID *Unregister,
    _Out_opt_ PFN_LOOKUP_MONIKER *Lookup,
    _Out_opt_ PFN_FREE_MEMORY *Free)
{
    HMODULE Kernelbase = LoadLibraryW(L"kernelbase.dll");

    if (!Kernelbase)
        return HRESULT_FROM_WIN32(GetLastError());
    if (Register)
        *Register = (PFN_REGISTER_SID)GetProcAddress(Kernelbase, "AppContainerRegisterSid");
    if (Unregister)
        *Unregister = (PFN_UNREGISTER_SID)GetProcAddress(Kernelbase, "AppContainerUnregisterSid");
    if (Lookup)
        *Lookup = (PFN_LOOKUP_MONIKER)GetProcAddress(Kernelbase, "AppContainerLookupMoniker");
    if (Free)
        *Free = (PFN_FREE_MEMORY)GetProcAddress(Kernelbase, "AppContainerFreeMemory");
    if ((Register && !*Register) || (Unregister && !*Unregister) || (Lookup && !*Lookup) || (Free && !*Free))
        return HRESULT_FROM_WIN32(ERROR_PROC_NOT_FOUND);
    return S_OK;
}

/* The characters that no Windows file name has: control characters and * ? " < > | */
static
BOOL
IsInvalidNameChar(
    _In_ WCHAR Char)
{
    return Char < L' ' || Char == L'*' || Char == L'?' || Char == L'"' || Char == L'<' || Char == L'>' || Char == L'|';
}

/*
 * Length of a name, 0 for no name or one of more than 64 characters. Windows answers E_INVALIDARG to both, in
 * create, delete and derive alike.
 */
static
SIZE_T
GetProfileNameLength(
    _In_opt_ PCWSTR Name)
{
    SIZE_T Length;

    if (!Name)
        return 0;
    for (Length = 0; Length <= APPCONTAINER_NAME_MAX && Name[Length]; Length++)
        ;
    return Length > APPCONTAINER_NAME_MAX ? 0 : Length;
}

/*
 * The checks of create that do not depend on the folders, measured on Windows 10 22H2: no name or more than 64
 * characters is E_INVALIDARG; a control character or one of * ? " < > | is ERROR_INVALID_NAME; a colon is
 * ERROR_DIRECTORY when it is the only one and neither first nor last (a stream name of the folder), else
 * ERROR_INVALID_NAME. Everything else is a name, among it "/", "\", "." and ".." (see ResolveProfileRoot).
 */
static
HRESULT
ValidateProfileName(
    _In_opt_ PCWSTR Name,
    _Out_ PSIZE_T NameLength)
{
    SIZE_T Length = GetProfileNameLength(Name), i, Colons = 0, FirstColon = 0;

    *NameLength = Length;
    if (Length == 0)
        return E_INVALIDARG;
    for (i = 0; i < Length; i++)
    {
        if (IsInvalidNameChar(Name[i]))
            return HRESULT_FROM_WIN32(ERROR_INVALID_NAME);
        if (Name[i] == L':' && Colons++ == 0)
            FirstColon = i;
    }
    if (Colons == 1 && FirstColon > 0 && FirstColon < Length - 1)
        return HRESULT_FROM_WIN32(ERROR_DIRECTORY);
    return Colons ? HRESULT_FROM_WIN32(ERROR_INVALID_NAME) : S_OK;
}

/* The name in lower case, which is how Windows keeps it in the moniker, the Storage key and the folder name */
static
VOID
LowerProfileName(
    _In_reads_(Length) PCWSTR Name,
    _In_ SIZE_T Length,
    _Out_writes_(APPCONTAINER_NAME_MAX + 1) PWSTR Lower)
{
    SIZE_T i;

    for (i = 0; i < Length; i++)
        Lower[i] = RtlDowncaseUnicodeChar(Name[i]);
    Lower[Length] = UNICODE_NULL;
}

/* %LOCALAPPDATA%\Packages */
static
HRESULT
GetPackagesDirectory(
    _Out_writes_(PROFILE_PATH_MAX) PWSTR Path)
{
    DWORD Length = GetEnvironmentVariableW(L"LOCALAPPDATA", Path, PROFILE_PATH_MAX);

    if (Length == 0 || Length >= PROFILE_PATH_MAX - 64)
    {
        HKEY Key;
        DWORD Type, Size = (PROFILE_PATH_MAX - 64) * sizeof(WCHAR);
        LONG Error;

        Error = RegOpenKeyExW(HKEY_CURRENT_USER,
                              L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders",
                              0, KEY_QUERY_VALUE, &Key);
        if (Error != ERROR_SUCCESS)
            return HRESULT_FROM_WIN32(ERROR_PATH_NOT_FOUND);
        Error = RegQueryValueExW(Key, L"Local AppData", NULL, &Type, (PBYTE)Path, &Size);
        RegCloseKey(Key);
        if (Error != ERROR_SUCCESS || Type != REG_SZ || Size < sizeof(WCHAR) ||
            Size >= (PROFILE_PATH_MAX - 64) * sizeof(WCHAR))
        {
            return HRESULT_FROM_WIN32(ERROR_PATH_NOT_FOUND);
        }
        Path[Size / sizeof(WCHAR)] = UNICODE_NULL;
        Length = (DWORD)wcslen(Path);
    }
    while (Length > 0 && Path[Length - 1] == L'\\')
        Path[--Length] = UNICODE_NULL;
    return StringCchCatW(Path, PROFILE_PATH_MAX, L"\\Packages");
}

/* The canonical Packages folder, without a trailing backslash */
static
HRESULT
GetCanonicalPackagesDirectory(
    _Out_writes_(PROFILE_PATH_MAX) PWSTR Path)
{
    WCHAR Packages[PROFILE_PATH_MAX];
    DWORD Length;
    HRESULT hr = GetPackagesDirectory(Packages);

    if (FAILED(hr))
        return hr;
    Length = GetFullPathNameW(Packages, PROFILE_PATH_MAX, Path, NULL);
    if (!Length || Length >= PROFILE_PATH_MAX)
        return HRESULT_FROM_WIN32(ERROR_FILENAME_EXCED_RANGE);
    while (Length > 3 && Path[Length - 1] == L'\\')
        Path[--Length] = UNICODE_NULL;
    return S_OK;
}

/* Whether Path, once made canonical, is a folder strictly below the canonical Packages folder */
static
BOOL
IsBelowPackages(
    _In_ PCWSTR Path)
{
    WCHAR FullPackages[PROFILE_PATH_MAX], FullPath[PROFILE_PATH_MAX];
    DWORD PackagesLength, PathLength;

    if (FAILED(GetCanonicalPackagesDirectory(FullPackages)))
        return FALSE;
    PackagesLength = (DWORD)wcslen(FullPackages);
    PathLength = GetFullPathNameW(Path, PROFILE_PATH_MAX, FullPath, NULL);
    if (!PackagesLength || !PathLength || PathLength >= PROFILE_PATH_MAX)
        return FALSE;
    return PathLength > PackagesLength + 1 &&
           !_wcsnicmp(FullPath, FullPackages, PackagesLength) &&
           FullPath[PackagesLength] == L'\\' &&
           FullPath[PackagesLength + 1] != UNICODE_NULL;
}

typedef enum _PROFILE_PLACE
{
    PlaceBelowPackages,     /* the folder of the profile is a folder strictly below Packages */
    PlacePackages,          /* it is Packages itself, where the AC folder is the one strictly below */
    PlaceOutside            /* it is somewhere else: no folders are made */
} PROFILE_PLACE;

/*
 * Where the folder of a profile is, as create finds it on Windows: the name (lower case) is appended to Packages as
 * a Win32 path. "/" and "\" end a folder, empty folders and "." are skipped, ".." goes up. One trailing dot of a
 * folder is dropped; a folder that then still ends in a dot or a space is not found (ERROR_PATH_NOT_FOUND).
 * This is only arithmetic on a string: nothing is opened, and the result says whether it is safe to create below it.
 */
static
HRESULT
ResolveProfileRoot(
    _In_ PCWSTR Lower,
    _Out_writes_(PROFILE_PATH_MAX) PWSTR Root,
    _Out_ PROFILE_PLACE *Place)
{
    WCHAR Packages[PROFILE_PATH_MAX];
    PCWSTR Start = Lower;
    SIZE_T Length, RootLength, PackagesLength;
    HRESULT hr;

    hr = GetCanonicalPackagesDirectory(Packages);
    if (FAILED(hr))
        return hr;
    /* the part of the path that ".." cannot leave: "X:\" or "\\server\share\" */
    if (Packages[0] && Packages[1] == L':' && Packages[2] == L'\\')
        RootLength = 3;
    else if (Packages[0] == L'\\' && Packages[1] == L'\\')
    {
        PCWSTR Slash = wcschr(Packages + 2, L'\\');

        Slash = Slash ? wcschr(Slash + 1, L'\\') : NULL;
        if (!Slash)
            return HRESULT_FROM_WIN32(ERROR_BAD_PATHNAME);
        RootLength = (SIZE_T)(Slash - Packages) + 1;
    }
    else
        return HRESULT_FROM_WIN32(ERROR_BAD_PATHNAME);

    PackagesLength = Length = wcslen(Packages);
    RtlCopyMemory(Root, Packages, (Length + 1) * sizeof(WCHAR));

    for (;;)
    {
        SIZE_T Size = 0;

        while (Start[Size] && Start[Size] != L'/' && Start[Size] != L'\\')
            Size++;
        if (Size == 0 || (Size == 1 && Start[0] == L'.'))
        {
            /* nothing */
        }
        else if (Size == 2 && Start[0] == L'.' && Start[1] == L'.')
        {
            while (Length > RootLength && Root[Length - 1] != L'\\')
                Length--;
            /* Length is behind the backslash now, or at the root */
            if (Length > RootLength)
                Length--;
            Root[Length] = UNICODE_NULL;
        }
        else
        {
            SIZE_T Kept = Size;

            if (Start[Kept - 1] == L'.')
                Kept--;
            if (Kept == 0 || Start[Kept - 1] == L'.' || Start[Kept - 1] == L' ')
                return HRESULT_FROM_WIN32(ERROR_PATH_NOT_FOUND);
            /* room for \AC\INetCookies below it */
            if (Length + 1 + Kept + 24 >= PROFILE_PATH_MAX)
                return HRESULT_FROM_WIN32(ERROR_FILENAME_EXCED_RANGE);
            if (Length > RootLength || Root[Length - 1] != L'\\')
                Root[Length++] = L'\\';
            RtlCopyMemory(Root + Length, Start, Kept * sizeof(WCHAR));
            Length += Kept;
            Root[Length] = UNICODE_NULL;
        }
        if (!Start[Size])
            break;
        Start += Size + 1;
    }

    if (Length == PackagesLength && !_wcsnicmp(Root, Packages, Length))
        *Place = PlacePackages;
    else if (Length > PackagesLength && !_wcsnicmp(Root, Packages, PackagesLength) && Root[PackagesLength] == L'\\')
        *Place = PlaceBelowPackages;
    else
        *Place = PlaceOutside;
    return S_OK;
}

/*
 * Puts an access allowed entry for the AppContainer in front of the access list of an object. Best effort: with
 * no access list (a file system without security) there is nothing to extend, and the AppContainer is not
 * enforced on ReactOS anyway.
 */
static
VOID
GrantAppContainerAccess(
    _In_ SE_OBJECT_TYPE ObjectType,
    _In_ PWSTR ObjectName,
    _In_ PSID Sid,
    _In_ DWORD AccessMask,
    _In_ BYTE AceFlags)
{
    PSECURITY_DESCRIPTOR Descriptor = NULL;
    PACL OldAcl = NULL, NewAcl;
    ACL_SIZE_INFORMATION Info;
    DWORD Size, i;
    PVOID Ace;

    if (GetNamedSecurityInfoW(ObjectName, ObjectType, DACL_SECURITY_INFORMATION, NULL, NULL, &OldAcl, NULL,
                              &Descriptor) != ERROR_SUCCESS)
    {
        return;
    }
    if (!OldAcl || !GetAclInformation(OldAcl, &Info, sizeof(Info), AclSizeInformation))
        goto Done;

    Size = OldAcl->AclSize + sizeof(ACCESS_ALLOWED_ACE) + GetLengthSid(Sid) + sizeof(DWORD);
    NewAcl = LocalAlloc(LPTR, Size);
    if (!NewAcl)
        goto Done;
    if (!InitializeAcl(NewAcl, Size, ACL_REVISION))
        goto Free;
    if (!AddAccessAllowedAceEx(NewAcl, ACL_REVISION, AceFlags, AccessMask, Sid) &&
        !AddAccessAllowedAceEx(NewAcl, ACL_REVISION, AceFlags & ~ACE_FLAG_CRITICAL, AccessMask, Sid))
    {
        goto Free;
    }
    for (i = 0; i < Info.AceCount; i++)
    {
        if (!GetAce(OldAcl, i, &Ace) || !AddAce(NewAcl, ACL_REVISION, MAXDWORD, Ace, ((PACE_HEADER)Ace)->AceSize))
            goto Free;
    }
    SetNamedSecurityInfoW(ObjectName, ObjectType, DACL_SECURITY_INFORMATION | UNPROTECTED_DACL_SECURITY_INFORMATION,
                          NULL, NULL, NewAcl, NULL);
Free:
    LocalFree(NewAcl);
Done:
    LocalFree(Descriptor);
}

/* Makes a folder; Created tells whether it is new (it is not when it exists already) */
static
BOOL
CreateProfileDirectory(
    _In_ PCWSTR Path,
    _In_ DWORD Attributes,
    _Out_ PBOOL Created)
{
    *Created = FALSE;
    if (CreateDirectoryW(Path, NULL))
        *Created = TRUE;
    else if (GetLastError() != ERROR_ALREADY_EXISTS)
        return FALSE;
    if (Attributes)
        SetFileAttributesW(Path, Attributes | FILE_ATTRIBUTE_DIRECTORY);
    return TRUE;
}

/*
 * Makes the folders of a profile under Root, which ResolveProfileRoot found. Only folders strictly below Packages
 * are made: the AC folder of Packages itself, or Root and its AC folder, and nothing at all for a root outside of
 * Packages. A failure removes what this call made (Windows leaves the root folder of a failed create behind).
 */
static
HRESULT
CreateProfileFolders(
    _In_ PCWSTR Root,
    _In_ PROFILE_PLACE Place,
    _In_ PSID Sid)
{
    static const struct
    {
        PCWSTR Name;
        DWORD Attributes;
    } Subfolders[] =
    {
        { L"INetCache", FILE_ATTRIBUTE_NOT_CONTENT_INDEXED | FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM },
        { L"INetCookies", FILE_ATTRIBUTE_NOT_CONTENT_INDEXED | FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM },
        { L"INetHistory", FILE_ATTRIBUTE_NOT_CONTENT_INDEXED | FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM },
        { L"Temp", 0 }
    };
    WCHAR Packages[PROFILE_PATH_MAX], Container[PROFILE_PATH_MAX], Path[RTL_NUMBER_OF(Subfolders) + 2][PROFILE_PATH_MAX];
    ULONG Made = 0, i;
    BOOL Created;
    HRESULT hr;

    if (Place == PlaceOutside)
        return S_OK;

    hr = GetPackagesDirectory(Packages);
    if (FAILED(hr))
        return hr;
    if (!CreateProfileDirectory(Packages, 0, &Created))
        return HRESULT_FROM_WIN32(GetLastError());

    if (Place == PlaceBelowPackages)
    {
        if (!CreateProfileDirectory(Root, 0, &Created))
            return HRESULT_FROM_WIN32(GetLastError());
        if (Created)
            StringCchCopyW(Path[Made++], PROFILE_PATH_MAX, Root);
    }

    StringCchPrintfW(Container, PROFILE_PATH_MAX, L"%ls\\AC", Root);
    if (!IsBelowPackages(Container))
        return HRESULT_FROM_WIN32(ERROR_INVALID_NAME);
    if (!CreateProfileDirectory(Container, FILE_ATTRIBUTE_NOT_CONTENT_INDEXED, &Created))
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        goto Failure;
    }
    if (Created)
        StringCchCopyW(Path[Made++], PROFILE_PATH_MAX, Container);
    GrantAppContainerAccess(SE_FILE_OBJECT, Container, Sid, FILE_ALL_ACCESS,
                            OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE | ACE_FLAG_CRITICAL);

    for (i = 0; i < RTL_NUMBER_OF(Subfolders); i++)
    {
        WCHAR Sub[PROFILE_PATH_MAX];

        StringCchPrintfW(Sub, PROFILE_PATH_MAX, L"%ls\\%ls", Container, Subfolders[i].Name);
        if (!CreateProfileDirectory(Sub, Subfolders[i].Attributes, &Created))
        {
            hr = HRESULT_FROM_WIN32(GetLastError());
            goto Failure;
        }
        if (Created)
            StringCchCopyW(Path[Made++], PROFILE_PATH_MAX, Sub);
    }
    return S_OK;

Failure:
    while (Made--)
    {
        SetFileAttributesW(Path[Made], FILE_ATTRIBUTE_NORMAL);
        RemoveDirectoryW(Path[Made]);
    }
    return hr;
}

/* The empty subkey Children of the mapping key of the SID, which Windows creates with the profile */
static
HRESULT
CreateMappingChildren(
    _In_ PSID Sid)
{
    WCHAR Path[512];
    LPWSTR SidString;
    HKEY Key;
    LONG Error;

    if (!ConvertSidToStringSidW(Sid, &SidString))
        return HRESULT_FROM_WIN32(GetLastError());
    StringCchPrintfW(Path, RTL_NUMBER_OF(Path), APPCONTAINER_MAPPINGS L"\\%ls\\Children", SidString);
    LocalFree(SidString);
    Error = RegCreateKeyExW(HKEY_CURRENT_USER, Path, 0, NULL, 0, KEY_READ | KEY_WRITE, NULL, &Key, NULL);
    if (Error != ERROR_SUCCESS)
        return HRESULT_FROM_WIN32(Error);
    RegCloseKey(Key);
    return S_OK;
}

static
HRESULT
CreateProfileStorage(
    _In_ PCWSTR Name,
    _In_ PSID Sid)
{
    WCHAR Path[APPCONTAINER_NAME_MAX + 256], Named[APPCONTAINER_NAME_MAX + 256];
    HKEY Key;
    LONG Error;

    StringCchPrintfW(Path, RTL_NUMBER_OF(Path), APPCONTAINER_STORAGE L"\\%ls", Name);
    Error = RegCreateKeyExW(HKEY_CURRENT_USER, Path, 0, NULL, 0, KEY_READ | KEY_WRITE, NULL, &Key, NULL);
    if (Error != ERROR_SUCCESS)
        return HRESULT_FROM_WIN32(Error);
    RegCloseKey(Key);
    StringCchPrintfW(Named, RTL_NUMBER_OF(Named), L"CURRENT_USER\\%ls", Path);
    GrantAppContainerAccess(SE_REGISTRY_KEY, Named, Sid, KEY_ALL_ACCESS,
                            OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE | ACE_FLAG_CRITICAL);

    StringCchCatW(Path, RTL_NUMBER_OF(Path), L"\\Children");
    Error = RegCreateKeyExW(HKEY_CURRENT_USER, Path, 0, NULL, 0, KEY_READ | KEY_WRITE, NULL, &Key, NULL);
    if (Error != ERROR_SUCCESS)
        return HRESULT_FROM_WIN32(Error);
    RegCloseKey(Key);
    return S_OK;
}

/* Removes a folder with everything in it; reparse points are removed, not followed */
static
VOID
DeleteFolderTree(
    _In_ PCWSTR Path,
    _In_ ULONG Depth)
{
    WIN32_FIND_DATAW Data;
    WCHAR Pattern[PROFILE_PATH_MAX], Child[PROFILE_PATH_MAX];
    HANDLE Find;

    /* Never remove anything but a folder below Packages */
    if (Depth == 0 && !IsBelowPackages(Path))
        return;

    if (Depth < 16 && !(GetFileAttributesW(Path) & FILE_ATTRIBUTE_REPARSE_POINT))
    {
        StringCchPrintfW(Pattern, PROFILE_PATH_MAX, L"%ls\\*", Path);
        Find = FindFirstFileW(Pattern, &Data);
        if (Find != INVALID_HANDLE_VALUE)
        {
            do
            {
                if (!wcscmp(Data.cFileName, L".") || !wcscmp(Data.cFileName, L".."))
                    continue;
                if (FAILED(StringCchPrintfW(Child, PROFILE_PATH_MAX, L"%ls\\%ls", Path, Data.cFileName)))
                    continue;
                if ((Data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) &&
                    !(Data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT))
                {
                    DeleteFolderTree(Child, Depth + 1);
                }
                else
                {
                    SetFileAttributesW(Child, FILE_ATTRIBUTE_NORMAL);
                    if (Data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
                        RemoveDirectoryW(Child);
                    else
                        DeleteFileW(Child);
                }
            } while (FindNextFileW(Find, &Data));
            FindClose(Find);
        }
    }
    SetFileAttributesW(Path, FILE_ATTRIBUTE_NORMAL);
    RemoveDirectoryW(Path);
}

/*
 * A name with a backslash makes the Storage key a nested one (Storage\a\b); Windows keeps the keys of the folders
 * in front when the profile is deleted, but a create that fails leaves nothing. Returns the path of the topmost key
 * such a create would make, empty when there is none because the name has no backslash or the key is there already.
 */
static
VOID
GetNewStorageTopKey(
    _In_ PCWSTR Name,
    _Out_writes_(APPCONTAINER_NAME_MAX + 256) PWSTR Path)
{
    PCWSTR Backslash = wcschr(Name, L'\\');
    HKEY Key;

    Path[0] = UNICODE_NULL;
    if (!Backslash)
        return;
    StringCchCopyW(Path, APPCONTAINER_NAME_MAX + 256, APPCONTAINER_STORAGE L"\\");
    StringCchCatNW(Path, APPCONTAINER_NAME_MAX + 256, Name, (SIZE_T)(Backslash - Name));
    if (RegOpenKeyExW(HKEY_CURRENT_USER, Path, 0, KEY_READ, &Key) == ERROR_SUCCESS)
    {
        RegCloseKey(Key);
        Path[0] = UNICODE_NULL;
    }
}

static
VOID
DeleteProfileStorage(
    _In_ PCWSTR Name)
{
    WCHAR Path[APPCONTAINER_NAME_MAX + 256];

    StringCchPrintfW(Path, RTL_NUMBER_OF(Path), APPCONTAINER_STORAGE L"\\%ls", Name);
    RegDeleteTreeW(HKEY_CURRENT_USER, Path);
    RegDeleteKeyW(HKEY_CURRENT_USER, Path);
}

/*
 * The folder step of delete, as Windows does it: the path is Packages\<name> in the literal form. In that form "/"
 * and the other characters that no file name has are invalid (ERROR_INVALID_NAME), and so is an empty folder name
 * between two backslashes. The folders are then looked up one by one: the first one that is not there ends the delete
 * with success (nothing to remove), as does a name with a colon (it names a stream) and a folder that ends in a dot
 * or a space (no folder has such a name). Only when the parent exists is a "." or ".." an invalid name. If every
 * folder is there, the last one goes with everything in it. Because the path has no "." or ".." folder, no empty
 * one and no "/", it cannot lead out of Packages; DeleteFolderTree checks that once more on the canonical path.
 */
static
HRESULT
DeleteProfileFolder(
    _In_ PCWSTR Lower,
    _In_ SIZE_T Length)
{
    WCHAR Path[PROFILE_PATH_MAX];
    SIZE_T i, Start = 0;
    BOOL Colon = FALSE;
    HRESULT hr;

    for (i = 0; i < Length; i++)
    {
        if (IsInvalidNameChar(Lower[i]) || Lower[i] == L'/')
            return HRESULT_FROM_WIN32(ERROR_INVALID_NAME);
        if (Lower[i] == L':')
            Colon = TRUE;
    }
    /* an empty folder name is only fine behind the last backslash */
    for (i = 0; i <= Length; i++)
    {
        if ((i == Length || Lower[i] == L'\\') && i == Start && !(i == Length && Start > 0))
            return HRESULT_FROM_WIN32(ERROR_INVALID_NAME);
        if (i == Length || Lower[i] == L'\\')
            Start = i + 1;
    }
    if (Colon)
        return S_OK;

    hr = GetPackagesDirectory(Path);
    if (FAILED(hr))
        return hr;
    for (Start = 0; Start < Length;)
    {
        SIZE_T Size = 0;

        while (Start + Size < Length && Lower[Start + Size] != L'\\')
            Size++;
        if (Size)
        {
            if ((Size == 1 && Lower[Start] == L'.') || (Size == 2 && Lower[Start] == L'.' && Lower[Start + 1] == L'.'))
                return HRESULT_FROM_WIN32(ERROR_INVALID_NAME);
            if (Lower[Start + Size - 1] == L'.' || Lower[Start + Size - 1] == L' ')
                return S_OK;
            if (wcslen(Path) + 1 + Size >= PROFILE_PATH_MAX)
                return HRESULT_FROM_WIN32(ERROR_FILENAME_EXCED_RANGE);
            StringCchCatW(Path, PROFILE_PATH_MAX, L"\\");
            StringCchCatNW(Path, PROFILE_PATH_MAX, Lower + Start, Size);
            if (GetFileAttributesW(Path) == INVALID_FILE_ATTRIBUTES)
                return S_OK;
        }
        Start += Size + 1;
    }
    DeleteFolderTree(Path, 0);
    return S_OK;
}

/*
 * @implemented
 */
HRESULT
WINAPI
CreateAppContainerProfile(
    _In_ PCWSTR pszAppContainerName,
    _In_ PCWSTR pszDisplayName,
    _In_ PCWSTR pszDescription,
    _In_reads_opt_(dwCapabilityCount) PSID_AND_ATTRIBUTES pCapabilities,
    _In_ DWORD dwCapabilityCount,
    _Outptr_ PSID *ppSidAppContainerSid)
{
    PFN_REGISTER_SID Register;
    PFN_UNREGISTER_SID Unregister;
    PSID Sid = NULL;
    WCHAR Lower[APPCONTAINER_NAME_MAX + 1], Root[PROFILE_PATH_MAX], NewTopKey[APPCONTAINER_NAME_MAX + 256];
    PROFILE_PLACE Place;
    SIZE_T Length;
    HRESULT hr;
    DWORD i;

    if (!ppSidAppContainerSid)
        return E_INVALIDARG;
    hr = ValidateProfileName(pszAppContainerName, &Length);
    if (FAILED(hr))
        return hr;
    if (dwCapabilityCount && !pCapabilities)
        return E_INVALIDARG;
    for (i = 0; i < dwCapabilityCount; i++)
    {
        if (!pCapabilities[i].Sid || !IsValidSid(pCapabilities[i].Sid))
            return E_INVALIDARG;
    }
    /* The display name and the description are optional here; their length limits are those of the documentation */
    if (pszDisplayName)
    {
        for (Length = 0; Length <= APPCONTAINER_DISPLAY_NAME_MAX && pszDisplayName[Length]; Length++)
            ;
        if (Length > APPCONTAINER_DISPLAY_NAME_MAX)
            return E_INVALIDARG;
    }
    if (pszDescription)
    {
        for (Length = 0; Length <= APPCONTAINER_DESCRIPTION_MAX && pszDescription[Length]; Length++)
            ;
        if (Length > APPCONTAINER_DESCRIPTION_MAX)
            return E_INVALIDARG;
    }

    Length = GetProfileNameLength(pszAppContainerName);
    LowerProfileName(pszAppContainerName, Length, Lower);
    /* A name Windows cannot make a folder for (ERROR_PATH_NOT_FOUND) fails before anything is registered */
    hr = ResolveProfileRoot(Lower, Root, &Place);
    if (FAILED(hr))
        return hr;

    hr = DeriveAppContainerSidFromAppContainerName(pszAppContainerName, &Sid);
    if (FAILED(hr))
        return hr;
    hr = GetRegistrationFunctions(&Register, &Unregister, NULL, NULL);
    if (FAILED(hr))
        goto Failure;
    GetNewStorageTopKey(Lower, NewTopKey);

    /* ERROR_ALREADY_EXISTS comes from here, before anything else is touched */
    hr = Register(Sid, Lower, pszDisplayName ? pszDisplayName : L"");
    if (FAILED(hr))
        goto Failure;

    hr = CreateMappingChildren(Sid);
    if (SUCCEEDED(hr))
        hr = CreateProfileStorage(Lower, Sid);
    if (SUCCEEDED(hr))
        hr = CreateProfileFolders(Root, Place, Sid);
    if (FAILED(hr))
    {
        DeleteProfileStorage(Lower);
        if (NewTopKey[0])
            RegDeleteTreeW(HKEY_CURRENT_USER, NewTopKey);
        Unregister(Sid);
        goto Failure;
    }

    *ppSidAppContainerSid = Sid;
    return S_OK;

Failure:
    FreeSid(Sid);
    return hr;
}

/*
 * @implemented
 *
 * Unlike create, delete does not check the characters of the name: the registration goes first, then the folder
 * (see DeleteProfileFolder), and what the folder step answers is the result, with the registration gone either way.
 */
HRESULT
WINAPI
DeleteAppContainerProfile(
    _In_ PCWSTR pszAppContainerName)
{
    PFN_UNREGISTER_SID Unregister;
    WCHAR Lower[APPCONTAINER_NAME_MAX + 1];
    SIZE_T Length = GetProfileNameLength(pszAppContainerName);
    PSID Sid;
    HRESULT hr, hrFolder;

    if (Length == 0)
        return E_INVALIDARG;
    LowerProfileName(pszAppContainerName, Length, Lower);

    hr = DeriveAppContainerSidFromAppContainerName(pszAppContainerName, &Sid);
    if (FAILED(hr))
        return hr;
    hr = GetRegistrationFunctions(NULL, &Unregister, NULL, NULL);
    if (SUCCEEDED(hr))
    {
        hr = Unregister(Sid);
        /* A profile that does not exist is deleted successfully (measured) */
        if (hr == HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND))
            hr = S_OK;
    }
    FreeSid(Sid);

    DeleteProfileStorage(Lower);
    hrFolder = DeleteProfileFolder(Lower, Length);
    return SUCCEEDED(hr) ? hrFolder : hr;
}

/*
 * @implemented
 *
 * The folder of an AppContainer is the AC folder of its profile, found by the moniker the SID is registered with.
 */
HRESULT
WINAPI
GetAppContainerFolderPath(
    _In_ PCWSTR pszAppContainerSid,
    _Outptr_ PWSTR *ppszPath)
{
    PFN_LOOKUP_MONIKER Lookup;
    PFN_FREE_MEMORY Free;
    PFN_COTASKMEMALLOC CoTaskMemAllocFn;
    WCHAR Root[PROFILE_PATH_MAX];
    PWSTR Moniker, Result;
    PSID Sid;
    HMODULE Ole32;
    SIZE_T Size;
    HRESULT hr;

    if (!pszAppContainerSid || !ppszPath)
        return E_INVALIDARG;
    if (!ConvertStringSidToSidW(pszAppContainerSid, &Sid))
        return HRESULT_FROM_WIN32(GetLastError());
    if (!IsAppContainerSid(Sid))
    {
        LocalFree(Sid);
        return HRESULT_FROM_WIN32(ERROR_APPCONTAINER_NOT_AN_APPCONTAINER_SID);
    }

    hr = GetRegistrationFunctions(NULL, NULL, &Lookup, &Free);
    if (FAILED(hr))
    {
        LocalFree(Sid);
        return hr;
    }
    hr = Lookup(Sid, &Moniker);
    LocalFree(Sid);
    if (FAILED(hr))
        return hr;

    /* Windows answers the moniker as it was stored, joined to Packages without any canonicalization; this only builds
       a string, no folder is opened */
    hr = GetPackagesDirectory(Root);
    if (SUCCEEDED(hr) && (FAILED(StringCchCatW(Root, PROFILE_PATH_MAX, L"\\")) ||
                          FAILED(StringCchCatW(Root, PROFILE_PATH_MAX, Moniker)) ||
                          FAILED(StringCchCatW(Root, PROFILE_PATH_MAX, L"\\AC"))))
    {
        hr = HRESULT_FROM_WIN32(ERROR_FILENAME_EXCED_RANGE);
    }
    Free(Moniker);
    if (FAILED(hr))
        return hr;

    /* The caller frees the path with CoTaskMemFree */
    Ole32 = LoadLibraryW(L"ole32.dll");
    CoTaskMemAllocFn = Ole32 ? (PFN_COTASKMEMALLOC)GetProcAddress(Ole32, "CoTaskMemAlloc") : NULL;
    if (!CoTaskMemAllocFn)
        return HRESULT_FROM_WIN32(ERROR_PROC_NOT_FOUND);
    Size = (wcslen(Root) + 1) * sizeof(WCHAR);
    Result = CoTaskMemAllocFn(Size);
    if (!Result)
        return E_OUTOFMEMORY;
    RtlCopyMemory(Result, Root, Size);
    *ppszPath = Result;
    return S_OK;
}

/*
 * @implemented
 *
 * Opens the registry key of the AppContainer the calling process runs in. ReactOS has no AppContainer processes,
 * and Windows fails with E_UNEXPECTED for a process outside an AppContainer, leaving the key alone.
 */
HRESULT
WINAPI
GetAppContainerRegistryLocation(
    _In_ REGSAM desiredAccess,
    _Out_ PHKEY phAppContainerKey)
{
    if (!phAppContainerKey)
        return E_INVALIDARG;
    return E_UNEXPECTED;
}
