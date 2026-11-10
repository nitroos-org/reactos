/*
 * PROJECT:     ReactOS Software Protection Platform client
 * LICENSE:     MIT (https://spdx.org/licenses/MIT)
 * PURPOSE:     sppc.dll: the Software Licensing client API (SLOpen, SLInstallLicense, ...)
 *
 * Windows 8 and later route every SL* call to the Software Protection service, and Office
 * (Click-to-Run's Integrator.exe included) uses this client instead of its own osppc.dll
 * there. Here the client keeps the installed license files in a directory of its own,
 * %SystemRoot%\System32\spp\store\2.0 (the 64-bit System32, whatever the bitness of the caller):
 *
 *   licenses\<file id>.xrm-ms   a license file as installed (XrML license group)
 *   index\<license id>.lic      which file a license came from, and its product SKU and
 *                               application ids (from the license's otherInfo table)
 *
 * The license file id is a GUID derived from the contents of the file, so installing the same
 * file again yields the same id and replaces the copy. The license information of a license
 * is the table in its <r:otherInfo>: licenseType, productSkuId, applicationId, ...
 *
 * Nothing here checks a signature, installs a product key or grants a right. The status
 * query reports every SKU of an application whose license is installed as unlicensed (no
 * product key is ever installed). SLConsumeRight binds an application to the handle (as
 * Windows does), and application authentication data is accepted unverified as a hint that the
 * caller is Office (see SLSetAuthenticationData). The entry points that only the service can
 * serve (offline activation, application policies, re-arm) answer SL_E_NOT_SUPPORTED or the
 * measured refusal: they exist so that a client that resolves the whole table by name
 * (Office does, and refuses to run when one name is missing) gets the answer of a platform
 * that cannot do it, not ERROR_PROC_NOT_FOUND.
 */

#include <windef.h>
#include <winbase.h>
#include <winerror.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <slpublic.h>
#include <pseh/pseh2.h>

#define SLC_MAGIC 0x434c5353 /* 'SSLC' */
#define MAX_LICENSE_FILE (16 * 1024 * 1024)
#define MAX_LICENSES_PER_FILE 256

/* What SLSetAuthenticationData was given on this handle */
#define SLC_AUTH_NONE       0 /* nothing (or an empty call) */
#define SLC_AUTH_ACCEPTED   1 /* 0x20 bytes or more of application authentication data: accepted, NOT verified */

typedef struct _SLC
{
    DWORD Magic;
    DWORD AuthState;
    BOOL Bound;        /* an application is bound to the handle: by SLConsumeRight, or by accepted authentication data */
    BOOL HasBoundSku;  /* ... and one SKU of it */
    SLID BoundApp;
    SLID BoundSku;
} SLC, *PSLC;

typedef struct _LICREC
{
    SLID Id;
    SLID Sku;
    SLID App;
    BOOL HasSku;
    BOOL HasApp;
    SIZE_T Start; /* offset of the license in the text, up to the next license */
    SIZE_T End;
} LICREC;

typedef struct _IDLIST
{
    SLID *Ids;
    UINT Count;
    UINT Capacity;
} IDLIST;

/* ---- helpers ------------------------------------------------------------------------- */

static
HRESULT
ErrorToHr(DWORD Error)
{
    return Error ? HRESULT_FROM_WIN32(Error) : E_FAIL;
}

static
BOOL
IsValidHandle(HSLC hSLC)
{
    PSLC Slc = (PSLC)hSLC;
    BOOL Valid = FALSE;

    if (!Slc)
        return FALSE;
    _SEH2_TRY
    {
        Valid = (Slc->Magic == SLC_MAGIC);
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        Valid = FALSE;
    }
    _SEH2_END;
    return Valid;
}

/* 64-bit FNV-1a with a caller-chosen offset basis: two runs over the blob give the 128 bits of the id. */
static
UINT64
Fnv1a64(UINT64 Hash, const BYTE *Data, SIZE_T Size)
{
    while (Size--)
    {
        Hash ^= *Data++;
        Hash *= 0x100000001b3ULL;
    }
    return Hash;
}

static
void
MakeFileId(const BYTE *Blob, SIZE_T Size, SLID *Id)
{
    UINT64 Lo = Fnv1a64(0xcbf29ce484222325ULL, Blob, Size);
    UINT64 Hi = Fnv1a64(0x84222325cbf29ce4ULL, Blob, Size);
    BYTE Raw[16];
    int i;

    for (i = 0; i < 8; i++)
    {
        Raw[i] = (BYTE)(Lo >> (8 * i));
        Raw[8 + i] = (BYTE)(Hi >> (8 * i));
    }
    /* A name-based (version 5 shaped) GUID */
    Raw[6] = (Raw[6] & 0x0F) | 0x50;
    Raw[8] = (Raw[8] & 0x3F) | 0x80;
    Id->Data1 = (ULONG)Raw[0] | ((ULONG)Raw[1] << 8) | ((ULONG)Raw[2] << 16) | ((ULONG)Raw[3] << 24);
    Id->Data2 = (USHORT)(Raw[4] | (Raw[5] << 8));
    Id->Data3 = (USHORT)(Raw[6] | (Raw[7] << 8));
    memcpy(Id->Data4, Raw + 8, 8);
}

static
void
PutHex(WCHAR **Out, ULONG64 Value, int Digits)
{
    static const WCHAR Hex[] = L"0123456789ABCDEF";
    int i;

    for (i = Digits - 1; i >= 0; i--)
        *(*Out)++ = Hex[(Value >> (4 * i)) & 0xF];
}

/* "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX" (36 characters, no braces) */
static
void
FormatGuid(const SLID *Id, WCHAR *Out)
{
    int i;

    PutHex(&Out, Id->Data1, 8);
    *Out++ = L'-';
    PutHex(&Out, Id->Data2, 4);
    *Out++ = L'-';
    PutHex(&Out, Id->Data3, 4);
    *Out++ = L'-';
    for (i = 0; i < 8; i++)
    {
        if (i == 2)
            *Out++ = L'-';
        PutHex(&Out, Id->Data4[i], 2);
    }
    *Out = 0;
}

static
int
HexValue(unsigned Char)
{
    if (Char >= '0' && Char <= '9')
        return Char - '0';
    if (Char >= 'a' && Char <= 'f')
        return Char - 'a' + 10;
    if (Char >= 'A' && Char <= 'F')
        return Char - 'A' + 10;
    return -1;
}

/* Exactly 36 characters, no braces; Narrow selects a char or a WCHAR buffer */
static
BOOL
ParseGuidEx(const void *Text, BOOL Narrow, SLID *Id)
{
    BYTE Raw[16];
    int Pos = 0, Out = 0;

#define CH(i) (Narrow ? (unsigned)((const unsigned char *)Text)[i] : (unsigned)((const WCHAR *)Text)[i])
    while (Out < 16)
    {
        int Hi, Lo;

        if (Pos == 8 || Pos == 13 || Pos == 18 || Pos == 23)
        {
            if (CH(Pos) != '-')
                return FALSE;
            Pos++;
        }
        Hi = HexValue(CH(Pos));
        Lo = Hi < 0 ? -1 : HexValue(CH(Pos + 1));
        if (Hi < 0 || Lo < 0)
            return FALSE;
        Raw[Out++] = (BYTE)(Hi * 16 + Lo);
        Pos += 2;
    }
#undef CH
    Id->Data1 = ((ULONG)Raw[0] << 24) | ((ULONG)Raw[1] << 16) | ((ULONG)Raw[2] << 8) | Raw[3];
    Id->Data2 = (USHORT)((Raw[4] << 8) | Raw[5]);
    Id->Data3 = (USHORT)((Raw[6] << 8) | Raw[7]);
    memcpy(Id->Data4, Raw + 8, 8);
    return TRUE;
}

/* "{XXXXXXXX-...}": 38 characters */
static
BOOL
ParseBracedGuid(const char *Text, SLID *Id)
{
    return Text[0] == '{' && Text[37] == '}' && ParseGuidEx(Text + 1, TRUE, Id);
}

static
int
CompareIds(const SLID *A, const SLID *B)
{
    int i;

    if (A->Data1 != B->Data1)
        return A->Data1 < B->Data1 ? -1 : 1;
    if (A->Data2 != B->Data2)
        return A->Data2 < B->Data2 ? -1 : 1;
    if (A->Data3 != B->Data3)
        return A->Data3 < B->Data3 ? -1 : 1;
    for (i = 0; i < 8; i++)
        if (A->Data4[i] != B->Data4[i])
            return A->Data4[i] < B->Data4[i] ? -1 : 1;
    return 0;
}

static
void
SortIds(SLID *Ids, UINT Count)
{
    UINT i, j;

    for (i = 1; i < Count; i++)
    {
        SLID Key = Ids[i];

        for (j = i; j > 0 && CompareIds(&Ids[j - 1], &Key) > 0; j--)
            Ids[j] = Ids[j - 1];
        Ids[j] = Key;
    }
}

static
BOOL
IdListAdd(IDLIST *List, const SLID *Id, BOOL Unique)
{
    UINT i;

    if (Unique)
    {
        for (i = 0; i < List->Count; i++)
            if (IsEqualGUID(&List->Ids[i], Id))
                return TRUE;
    }
    if (List->Count == List->Capacity)
    {
        UINT NewCap = List->Capacity ? List->Capacity * 2 : 32;
        SLID *New = List->Ids ? HeapReAlloc(GetProcessHeap(), 0, List->Ids, NewCap * sizeof(SLID))
                              : HeapAlloc(GetProcessHeap(), 0, NewCap * sizeof(SLID));

        if (!New)
            return FALSE;
        List->Ids = New;
        List->Capacity = NewCap;
    }
    List->Ids[List->Count++] = *Id;
    return TRUE;
}

/* ---- store layout -------------------------------------------------------------------- */

/*
 * The store lives in the 64-bit System32 for every client: a 32-bit process must see the
 * licenses the 64-bit Integrator installed, as it does with the Windows service. The
 * callers switch the WoW64 file system redirection off around the store access.
 */
static
BOOL
GetStorePath(const WCHAR *Sub, WCHAR *Path, SIZE_T Count)
{
    UINT Len = GetSystemWindowsDirectoryW(Path, (UINT)Count);

    if (Len == 0 || Len + 32 + wcslen(Sub) + 1 >= Count)
        return FALSE;
    wcscpy(Path + Len, L"\\System32\\spp\\store\\2.0");
    if (*Sub)
    {
        wcscat(Path, L"\\");
        wcscat(Path, Sub);
    }
    return TRUE;
}

typedef BOOL (WINAPI *PFN_FSREDIR_DISABLE)(PVOID *);
typedef BOOL (WINAPI *PFN_FSREDIR_REVERT)(PVOID);

static
BOOL
StoreEnter(PVOID *Old)
{
    HMODULE Kernel = GetModuleHandleW(L"kernel32.dll");
    PFN_FSREDIR_DISABLE Disable = Kernel ? (PFN_FSREDIR_DISABLE)GetProcAddress(Kernel, "Wow64DisableWow64FsRedirection") : NULL;

    *Old = NULL;
    return Disable && Disable(Old);
}

static
void
StoreLeave(BOOL Entered, PVOID Old)
{
    HMODULE Kernel = GetModuleHandleW(L"kernel32.dll");
    PFN_FSREDIR_REVERT Revert = Kernel ? (PFN_FSREDIR_REVERT)GetProcAddress(Kernel, "Wow64RevertWow64FsRedirection") : NULL;

    if (Entered && Revert)
        Revert(Old);
}

static
DWORD
EnsureDirectory(WCHAR *Dir)
{
    WCHAR *p;
    DWORD Error;

    if (CreateDirectoryW(Dir, NULL))
        return ERROR_SUCCESS;
    Error = GetLastError();
    if (Error == ERROR_ALREADY_EXISTS)
        return ERROR_SUCCESS;
    if (Error != ERROR_PATH_NOT_FOUND)
        return Error;
    /* Create the missing parents, skipping the drive */
    for (p = Dir + 3; *p; p++)
    {
        if (*p != L'\\')
            continue;
        *p = 0;
        if (!CreateDirectoryW(Dir, NULL) && GetLastError() != ERROR_ALREADY_EXISTS)
        {
            Error = GetLastError();
            *p = L'\\';
            return Error;
        }
        *p = L'\\';
    }
    if (!CreateDirectoryW(Dir, NULL) && GetLastError() != ERROR_ALREADY_EXISTS)
        return GetLastError();
    return ERROR_SUCCESS;
}

/* <store>\<Sub>\<guid><Ext> */
static
BOOL
BuildItemPath(const WCHAR *Sub, const SLID *Id, const WCHAR *Ext, WCHAR *Path, SIZE_T Count)
{
    SIZE_T Len;

    if (!GetStorePath(Sub, Path, Count))
        return FALSE;
    Len = wcslen(Path);
    if (Len + 1 + 36 + wcslen(Ext) + 1 >= Count)
        return FALSE;
    Path[Len++] = L'\\';
    FormatGuid(Id, Path + Len);
    wcscat(Path, Ext);
    return TRUE;
}

static
HRESULT
ReadWholeFile(const WCHAR *Path, BYTE **Data, DWORD *Size)
{
    HANDLE File;
    LARGE_INTEGER Length;
    DWORD Read = 0, Error;
    BYTE *Buffer;

    File = CreateFileW(Path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                       NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (File == INVALID_HANDLE_VALUE)
    {
        Error = GetLastError();
        if (Error == ERROR_FILE_NOT_FOUND || Error == ERROR_PATH_NOT_FOUND)
            return SL_E_LICENSE_FILE_NOT_INSTALLED;
        return ErrorToHr(Error);
    }
    if (!GetFileSizeEx(File, &Length) || Length.QuadPart > MAX_LICENSE_FILE)
    {
        Error = GetLastError();
        CloseHandle(File);
        return Error ? ErrorToHr(Error) : E_FAIL;
    }
    Buffer = LocalAlloc(LMEM_FIXED, Length.LowPart ? Length.LowPart : 1);
    if (!Buffer)
    {
        CloseHandle(File);
        return E_OUTOFMEMORY;
    }
    if (!ReadFile(File, Buffer, Length.LowPart, &Read, NULL) || Read != Length.LowPart)
    {
        Error = GetLastError();
        LocalFree(Buffer);
        CloseHandle(File);
        return Error ? ErrorToHr(Error) : E_FAIL;
    }
    CloseHandle(File);
    *Data = Buffer;
    *Size = Read;
    return S_OK;
}

/* Write beside the target and rename over it: a reader never sees half a file. */
static
HRESULT
WriteWholeFile(const WCHAR *Final, const void *Data, DWORD Size)
{
    WCHAR Temp[MAX_PATH];
    WCHAR *End;
    HANDLE File;
    DWORD Written = 0, Error;

    if (wcslen(Final) + 24 >= ARRAYSIZE(Temp))
        return E_FAIL;
    wcscpy(Temp, Final);
    End = Temp + wcslen(Temp);
    *End++ = L'.';
    PutHex(&End, GetCurrentProcessId(), 8);
    PutHex(&End, GetTickCount(), 8);
    wcscpy(End, L".tmp");
    File = CreateFileW(Temp, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (File == INVALID_HANDLE_VALUE)
        return ErrorToHr(GetLastError());
    if (!WriteFile(File, Data, Size, &Written, NULL) || Written != Size)
    {
        Error = GetLastError();
        CloseHandle(File);
        DeleteFileW(Temp);
        return ErrorToHr(Error);
    }
    CloseHandle(File);
    if (!MoveFileExW(Temp, Final, MOVEFILE_REPLACE_EXISTING))
    {
        Error = GetLastError();
        DeleteFileW(Temp);
        return ErrorToHr(Error);
    }
    return S_OK;
}

/* ---- license files ------------------------------------------------------------------- */

/* The text of a license file as UTF-8, NUL terminated (the files are UTF-8 with a BOM or UTF-16) */
static
char *
LicenseText(const BYTE *Blob, SIZE_T Size, SIZE_T *TextSize)
{
    char *Text;

    if (Size >= 2 && Blob[0] == 0xFF && Blob[1] == 0xFE)
    {
        int Chars = (int)((Size - 2) / 2);
        int Needed = WideCharToMultiByte(CP_UTF8, 0, (const WCHAR *)(Blob + 2), Chars, NULL, 0, NULL, NULL);

        Text = HeapAlloc(GetProcessHeap(), 0, (SIZE_T)Needed + 1);
        if (!Text)
            return NULL;
        Needed = WideCharToMultiByte(CP_UTF8, 0, (const WCHAR *)(Blob + 2), Chars, Text, Needed, NULL, NULL);
        Text[Needed] = 0;
        *TextSize = Needed;
        return Text;
    }
    Text = HeapAlloc(GetProcessHeap(), 0, Size + 1);
    if (!Text)
        return NULL;
    memcpy(Text, Blob, Size);
    Text[Size] = 0;
    *TextSize = Size;
    return Text;
}

/* ASCII case-insensitive search for Needle in [Text, Text+Len) */
static
const char *
FindAscii(const char *Text, SIZE_T Len, const char *Needle)
{
    SIZE_T NeedleLen = strlen(Needle), i, k;

    if (NeedleLen == 0 || Len < NeedleLen)
        return NULL;
    for (i = 0; i + NeedleLen <= Len; i++)
    {
        for (k = 0; k < NeedleLen; k++)
        {
            char a = Text[i + k], b = Needle[k];

            if (a >= 'A' && a <= 'Z')
                a += 'a' - 'A';
            if (b >= 'A' && b <= 'Z')
                b += 'a' - 'A';
            if (a != b)
                break;
        }
        if (k == NeedleLen)
            return Text + i;
    }
    return NULL;
}

/* The value of an <...infoStr name="Name">value</...> of the license, decoded; NULL when absent */
static
BOOL
GetInfoString(const char *Text, const LICREC *Lic, const char *Name, char *Value, SIZE_T ValueSize)
{
    char Needle[128];
    const char *p, *Begin, *End;
    SIZE_T Out = 0;

    if (strlen(Name) + 20 >= sizeof(Needle))
        return FALSE;
    strcpy(Needle, "infoStr name=\"");
    strcat(Needle, Name);
    strcat(Needle, "\">");
    p = FindAscii(Text + Lic->Start, Lic->End - Lic->Start, Needle);
    if (!p)
        return FALSE;
    Begin = p + strlen(Needle);
    End = memchr(Begin, '<', (Text + Lic->End) - Begin);
    if (!End)
        return FALSE;
    while (Begin < End && Out + 1 < ValueSize)
    {
        if (*Begin == '&')
        {
            static const struct { const char *Entity; char Char; } Entities[] =
            {
                { "&amp;", '&' }, { "&lt;", '<' }, { "&gt;", '>' }, { "&quot;", '"' }, { "&apos;", '\'' }
            };
            UINT i;

            for (i = 0; i < ARRAYSIZE(Entities); i++)
            {
                SIZE_T L = strlen(Entities[i].Entity);

                if ((SIZE_T)(End - Begin) >= L && !memcmp(Begin, Entities[i].Entity, L))
                {
                    Value[Out++] = Entities[i].Char;
                    Begin += L;
                    break;
                }
            }
            if (i < ARRAYSIZE(Entities))
                continue;
        }
        Value[Out++] = *Begin++;
    }
    Value[Out] = 0;
    return TRUE;
}

/* The licenses of a license file in file order; each runs to the start of the next one */
static
UINT
ParseLicenses(const char *Text, SIZE_T TextSize, LICREC *Out, UINT Max)
{
    static const char Needle[] = "licenseId=\"{";
    const char *p = Text, *End = Text + TextSize;
    UINT Count = 0, n;
    char Value[80];

    while (p < End && Count < Max)
    {
        SLID Id;
        const char *Hit = FindAscii(p, End - p, Needle);

        if (!Hit)
            break;
        p = Hit + sizeof(Needle) - 1;
        if ((SIZE_T)(End - Hit) < sizeof(Needle) - 1 + 37 || !ParseBracedGuid(p - 1, &Id))
            continue;
        Out[Count].Id = Id;
        Out[Count].HasSku = FALSE;
        Out[Count].HasApp = FALSE;
        Out[Count].Start = Hit - Text;
        Out[Count].End = TextSize;
        if (Count)
            Out[Count - 1].End = Hit - Text;
        Count++;
    }
    for (n = 0; n < Count; n++)
    {
        LICREC *Lic = &Out[n];

        if (GetInfoString(Text, Lic, "productSkuId", Value, sizeof(Value)) && ParseBracedGuid(Value, &Lic->Sku))
            Lic->HasSku = TRUE;
        if (GetInfoString(Text, Lic, "applicationId", Value, sizeof(Value)) && ParseBracedGuid(Value, &Lic->App))
            Lic->HasApp = TRUE;
    }
    return Count;
}

/* ---- the license index --------------------------------------------------------------- */

typedef struct _INDEXREC
{
    SLID License;
    SLID File;
    SLID Sku;
    SLID App;
    BOOL HasSku;
    BOOL HasApp;
} INDEXREC;

static
HRESULT
WriteIndex(const SLID *File, const LICREC *Lic)
{
    WCHAR Path[MAX_PATH];
    WCHAR Wide[256], *p = Wide;
    char Narrow[256];
    int Len, i;

    if (!BuildItemPath(L"index", &Lic->Id, L".lic", Path, ARRAYSIZE(Path)))
        return E_FAIL;
    wcscpy(p, L"file=");
    p += 5;
    FormatGuid(File, p);
    p += 36;
    if (Lic->HasSku)
    {
        wcscpy(p, L"\nsku=");
        p += 5;
        FormatGuid(&Lic->Sku, p);
        p += 36;
    }
    if (Lic->HasApp)
    {
        wcscpy(p, L"\napp=");
        p += 5;
        FormatGuid(&Lic->App, p);
        p += 36;
    }
    *p++ = L'\n';
    Len = (int)(p - Wide);
    for (i = 0; i < Len; i++)
        Narrow[i] = (char)Wide[i];
    return WriteWholeFile(Path, Narrow, Len);
}

static
BOOL
ParseIndex(const SLID *License, const BYTE *Data, DWORD Size, INDEXREC *Rec)
{
    const char *Text = (const char *)Data;
    DWORD i;
    BOOL Got = FALSE;

    memset(Rec, 0, sizeof(*Rec));
    Rec->License = *License;
    for (i = 0; i + 5 + 36 <= Size; i++)
    {
        if (i && Text[i - 1] != '\n')
            continue;
        if (!memcmp(Text + i, "file=", 5) && ParseGuidEx(Text + i + 5, TRUE, &Rec->File))
            Got = TRUE;
        else if (!memcmp(Text + i, "sku=", 4) && ParseGuidEx(Text + i + 4, TRUE, &Rec->Sku))
            Rec->HasSku = TRUE;
        else if (!memcmp(Text + i, "app=", 4) && ParseGuidEx(Text + i + 4, TRUE, &Rec->App))
            Rec->HasApp = TRUE;
    }
    return Got;
}

static
BOOL
ReadIndex(const SLID *License, INDEXREC *Rec)
{
    WCHAR Path[MAX_PATH];
    BYTE *Data;
    DWORD Size;
    BOOL Ok;

    if (!BuildItemPath(L"index", License, L".lic", Path, ARRAYSIZE(Path)))
        return FALSE;
    if (FAILED(ReadWholeFile(Path, &Data, &Size)))
        return FALSE;
    Ok = ParseIndex(License, Data, Size, Rec);
    LocalFree(Data);
    return Ok;
}

/* Calls Visit for every item of <store>\<Sub> named <guid><Ext> */
typedef BOOL (*VISITOR)(const SLID *Id, void *Context);

static
void
EnumItems(const WCHAR *Sub, const WCHAR *Ext, VISITOR Visit, void *Context)
{
    WCHAR Dir[MAX_PATH], Pattern[MAX_PATH];
    WIN32_FIND_DATAW Find;
    HANDLE Search;
    SIZE_T ExtLen = wcslen(Ext);

    if (!GetStorePath(Sub, Dir, ARRAYSIZE(Dir)))
        return;
    wcscpy(Pattern, Dir);
    wcscat(Pattern, L"\\*");
    wcscat(Pattern, Ext);
    Search = FindFirstFileW(Pattern, &Find);
    if (Search == INVALID_HANDLE_VALUE)
        return;
    do
    {
        SLID Id;

        if ((Find.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) || wcslen(Find.cFileName) != 36 + ExtLen ||
            _wcsicmp(Find.cFileName + 36, Ext) || !ParseGuidEx(Find.cFileName, FALSE, &Id))
            continue;
        if (!Visit(&Id, Context))
            break;
    } while (FindNextFileW(Search, &Find));
    FindClose(Search);
}

/* ---- exports ------------------------------------------------------------------------- */

HRESULT
WINAPI
SLOpen(_Out_ HSLC *phSLC)
{
    PSLC Slc;

    if (!phSLC)
        return E_INVALIDARG;
    *phSLC = NULL;
    Slc = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*Slc));
    if (!Slc)
        return E_OUTOFMEMORY;
    Slc->Magic = SLC_MAGIC;
    *phSLC = (HSLC)Slc;
    return S_OK;
}

HRESULT
WINAPI
SLClose(_In_ HSLC hSLC)
{
    PSLC Slc = (PSLC)hSLC;

    if (!IsValidHandle(hSLC))
        return E_HANDLE;
    Slc->Magic = 0;
    HeapFree(GetProcessHeap(), 0, Slc);
    return S_OK;
}

HRESULT
WINAPI
SLGetLicenseFileId(_In_ HSLC hSLC,
                   _In_ UINT cbLicenseBlob,
                   _In_reads_bytes_(cbLicenseBlob) const BYTE *pbLicenseBlob,
                   _Out_ SLID *pLicenseFileId)
{
    if (!IsValidHandle(hSLC))
        return E_HANDLE;
    if (!cbLicenseBlob || !pbLicenseBlob || !pLicenseFileId)
        return E_INVALIDARG;
    MakeFileId(pbLicenseBlob, cbLicenseBlob, pLicenseFileId);
    return S_OK;
}

static
HRESULT
SLInstallLicenseImpl(_In_ HSLC hSLC,
                 _In_ UINT cbLicenseBlob,
                 _In_reads_bytes_(cbLicenseBlob) const BYTE *pbLicenseBlob,
                 _Out_ SLID *pLicenseFileId)
{
    WCHAR Dir[MAX_PATH], Final[MAX_PATH];
    LICREC *Licenses;
    char *Text;
    SIZE_T TextSize;
    UINT Count, i;
    SLID FileId;
    HRESULT hr;
    DWORD Error;

    if (!IsValidHandle(hSLC))
        return E_HANDLE;
    if (!cbLicenseBlob || !pbLicenseBlob || !pLicenseFileId || cbLicenseBlob > MAX_LICENSE_FILE)
        return E_INVALIDARG;

    Text = LicenseText(pbLicenseBlob, cbLicenseBlob, &TextSize);
    Licenses = HeapAlloc(GetProcessHeap(), 0, MAX_LICENSES_PER_FILE * sizeof(*Licenses));
    if (!Text || !Licenses)
    {
        HeapFree(GetProcessHeap(), 0, Text);
        HeapFree(GetProcessHeap(), 0, Licenses);
        return E_OUTOFMEMORY;
    }
    Count = ParseLicenses(Text, TextSize, Licenses, MAX_LICENSES_PER_FILE);
    HeapFree(GetProcessHeap(), 0, Text);
    if (Count == 0) /* a license file holds at least one license */
    {
        HeapFree(GetProcessHeap(), 0, Licenses);
        return E_INVALIDARG;
    }

    MakeFileId(pbLicenseBlob, cbLicenseBlob, &FileId);
    if (!GetStorePath(L"licenses", Dir, ARRAYSIZE(Dir)) || !BuildItemPath(L"licenses", &FileId, L".xrm-ms", Final, ARRAYSIZE(Final)))
        hr = E_FAIL;
    else if ((Error = EnsureDirectory(Dir)) != ERROR_SUCCESS)
        hr = ErrorToHr(Error);
    else if (!GetStorePath(L"index", Dir, ARRAYSIZE(Dir)))
        hr = E_FAIL;
    else if ((Error = EnsureDirectory(Dir)) != ERROR_SUCCESS)
        hr = ErrorToHr(Error);
    else
        hr = WriteWholeFile(Final, pbLicenseBlob, cbLicenseBlob);
    for (i = 0; SUCCEEDED(hr) && i < Count; i++)
        hr = WriteIndex(&FileId, &Licenses[i]);
    HeapFree(GetProcessHeap(), 0, Licenses);
    if (FAILED(hr))
        return hr;
    *pLicenseFileId = FileId;
    return S_OK;
}

static
HRESULT
SLUninstallLicenseImpl(_In_ HSLC hSLC,
                   _In_ const SLID *pLicenseFileId)
{
    WCHAR Path[MAX_PATH];
    BYTE *Data;
    DWORD Size, Error;
    HRESULT hr;

    if (!IsValidHandle(hSLC))
        return E_HANDLE;
    if (!pLicenseFileId)
        return E_INVALIDARG;
    if (!BuildItemPath(L"licenses", pLicenseFileId, L".xrm-ms", Path, ARRAYSIZE(Path)))
        return E_FAIL;

    /* Drop the index entries of the file's licenses (those that still point at this file), then the file */
    hr = ReadWholeFile(Path, &Data, &Size);
    if (FAILED(hr))
        return hr;
    {
        SIZE_T TextSize;
        char *Text = LicenseText(Data, Size, &TextSize);
        LICREC *Licenses = HeapAlloc(GetProcessHeap(), 0, MAX_LICENSES_PER_FILE * sizeof(*Licenses));
        UINT Count = 0, i;

        if (Text && Licenses)
            Count = ParseLicenses(Text, TextSize, Licenses, MAX_LICENSES_PER_FILE);
        for (i = 0; i < Count; i++)
        {
            INDEXREC Rec;
            WCHAR IndexPath[MAX_PATH];

            if (ReadIndex(&Licenses[i].Id, &Rec) && IsEqualGUID(&Rec.File, pLicenseFileId) &&
                BuildItemPath(L"index", &Licenses[i].Id, L".lic", IndexPath, ARRAYSIZE(IndexPath)))
                DeleteFileW(IndexPath);
        }
        HeapFree(GetProcessHeap(), 0, Text);
        HeapFree(GetProcessHeap(), 0, Licenses);
    }
    LocalFree(Data);
    if (DeleteFileW(Path))
        return S_OK;
    Error = GetLastError();
    if (Error == ERROR_FILE_NOT_FOUND || Error == ERROR_PATH_NOT_FOUND)
        return SL_E_LICENSE_FILE_NOT_INSTALLED;
    return ErrorToHr(Error);
}

static
HRESULT
SLGetLicenseImpl(_In_ HSLC hSLC,
             _In_ const SLID *pLicenseFileId,
             _Out_ UINT *pcbLicenseFile,
             _Outptr_result_bytebuffer_(*pcbLicenseFile) PBYTE *ppbLicenseFile)
{
    WCHAR Path[MAX_PATH];
    HRESULT hr;
    DWORD Size;

    if (!IsValidHandle(hSLC))
        return E_HANDLE;
    if (!pLicenseFileId || !pcbLicenseFile || !ppbLicenseFile)
        return E_INVALIDARG;
    *pcbLicenseFile = 0;
    *ppbLicenseFile = NULL;
    if (!BuildItemPath(L"licenses", pLicenseFileId, L".xrm-ms", Path, ARRAYSIZE(Path)))
        return E_FAIL;
    hr = ReadWholeFile(Path, ppbLicenseFile, &Size);
    if (SUCCEEDED(hr))
        *pcbLicenseFile = Size;
    return hr;
}

typedef struct _LISTCTX
{
    SLIDTYPE Query;
    const SLID *QueryId;
    SLIDTYPE Return;
    IDLIST *List;
} LISTCTX;

/* Walks the license index for the relations that start at a SKU, an application or everything */
static
BOOL
VisitIndex(const SLID *License, void *Context)
{
    LISTCTX *Ctx = Context;
    INDEXREC Rec;

    if (!ReadIndex(License, &Rec))
        return TRUE;
    if (Ctx->Query == SL_ID_PRODUCT_SKU && !(Rec.HasSku && IsEqualGUID(&Rec.Sku, Ctx->QueryId)))
        return TRUE;
    if (Ctx->Query == SL_ID_APPLICATION && !(Rec.HasApp && IsEqualGUID(&Rec.App, Ctx->QueryId)))
        return TRUE;
    switch (Ctx->Return)
    {
        case SL_ID_LICENSE:
            return IdListAdd(Ctx->List, &Rec.License, FALSE);
        case SL_ID_LICENSE_FILE:
            return IdListAdd(Ctx->List, &Rec.File, TRUE);
        case SL_ID_PRODUCT_SKU:
            return !Rec.HasSku || IdListAdd(Ctx->List, &Rec.Sku, TRUE);
        case SL_ID_APPLICATION:
            return !Rec.HasApp || IdListAdd(Ctx->List, &Rec.App, TRUE);
        default:
            return TRUE;
    }
}

static
BOOL
VisitFile(const SLID *File, void *Context)
{
    return IdListAdd(((LISTCTX *)Context)->List, File, FALSE);
}

static
HRESULT
SLGetSLIDListImpl(_In_ HSLC hSLC,
              _In_ SLIDTYPE eQueryIdType,
              _In_opt_ const SLID *pQueryId,
              _In_ SLIDTYPE eReturnIdType,
              _Out_ UINT *pnReturnIds,
              _Outptr_result_buffer_(*pnReturnIds) SLID **ppReturnIds)
{
    IDLIST List = { NULL, 0, 0 };
    LISTCTX Ctx;
    HRESULT hr = S_OK;

    if (!IsValidHandle(hSLC))
        return E_HANDLE;
    if (!pnReturnIds || !ppReturnIds)
        return E_INVALIDARG;
    *pnReturnIds = 0;
    *ppReturnIds = NULL;
    if ((unsigned)eQueryIdType >= SL_ID_LAST || (unsigned)eReturnIdType >= SL_ID_LAST)
        return E_INVALIDARG;
    if (eQueryIdType != SL_ID_ALL_LICENSES && eQueryIdType != SL_ID_ALL_LICENSE_FILES && !pQueryId)
        return E_INVALIDARG;

    Ctx.Query = eQueryIdType;
    Ctx.QueryId = pQueryId;
    Ctx.Return = eReturnIdType;
    Ctx.List = &List;

    switch (eQueryIdType)
    {
        case SL_ID_ALL_LICENSE_FILES:
            if (eReturnIdType == SL_ID_LICENSE_FILE)
                EnumItems(L"licenses", L".xrm-ms", VisitFile, &Ctx);
            break;

        case SL_ID_ALL_LICENSES:
            if (eReturnIdType == SL_ID_LICENSE)
                EnumItems(L"index", L".lic", VisitFile, &Ctx);
            break;

        case SL_ID_LICENSE_FILE:
        {
            /* The licenses (or their SKUs, applications) of one file, in file order */
            WCHAR Path[MAX_PATH];
            BYTE *Data;
            DWORD Size;

            if (eReturnIdType != SL_ID_LICENSE && eReturnIdType != SL_ID_PRODUCT_SKU && eReturnIdType != SL_ID_APPLICATION)
                break;
            if (!BuildItemPath(L"licenses", pQueryId, L".xrm-ms", Path, ARRAYSIZE(Path)))
            {
                hr = E_FAIL;
                break;
            }
            hr = ReadWholeFile(Path, &Data, &Size);
            if (SUCCEEDED(hr))
            {
                SIZE_T TextSize;
                char *Text = LicenseText(Data, Size, &TextSize);
                LICREC *Licenses = HeapAlloc(GetProcessHeap(), 0, MAX_LICENSES_PER_FILE * sizeof(*Licenses));
                UINT Count = 0, i;

                if (Text && Licenses)
                    Count = ParseLicenses(Text, TextSize, Licenses, MAX_LICENSES_PER_FILE);
                for (i = 0; i < Count; i++)
                {
                    if (eReturnIdType == SL_ID_LICENSE)
                        IdListAdd(&List, &Licenses[i].Id, FALSE);
                    else if (eReturnIdType == SL_ID_PRODUCT_SKU && Licenses[i].HasSku)
                        IdListAdd(&List, &Licenses[i].Sku, TRUE);
                    else if (eReturnIdType == SL_ID_APPLICATION && Licenses[i].HasApp)
                        IdListAdd(&List, &Licenses[i].App, TRUE);
                }
                HeapFree(GetProcessHeap(), 0, Text);
                HeapFree(GetProcessHeap(), 0, Licenses);
                LocalFree(Data);
            }
            break;
        }

        case SL_ID_LICENSE:
        {
            /* Where one license came from */
            INDEXREC Rec;

            if (!ReadIndex(pQueryId, &Rec))
                break;
            if (eReturnIdType == SL_ID_LICENSE_FILE)
                IdListAdd(&List, &Rec.File, FALSE);
            else if (eReturnIdType == SL_ID_PRODUCT_SKU && Rec.HasSku)
                IdListAdd(&List, &Rec.Sku, FALSE);
            else if (eReturnIdType == SL_ID_APPLICATION && Rec.HasApp)
                IdListAdd(&List, &Rec.App, FALSE);
            break;
        }

        case SL_ID_PRODUCT_SKU:
        case SL_ID_APPLICATION:
            if (eReturnIdType == SL_ID_LICENSE || eReturnIdType == SL_ID_LICENSE_FILE ||
                eReturnIdType == SL_ID_PRODUCT_SKU || eReturnIdType == SL_ID_APPLICATION)
                EnumItems(L"index", L".lic", VisitIndex, &Ctx);
            break;

        default:
            break; /* product keys and store tokens: nothing installed */
    }

    if (FAILED(hr) || List.Count == 0)
    {
        HeapFree(GetProcessHeap(), 0, List.Ids);
        /* Windows 10 (measured for an installed SKU; an unknown SKU is not measured): no product key id is value not found */
        if (SUCCEEDED(hr) && eReturnIdType == SL_ID_PKEY && eQueryIdType == SL_ID_PRODUCT_SKU)
            return SL_E_VALUE_NOT_FOUND;
        return hr;
    }
    /* Windows 10 (measured): ids of a SKU or application query come back in ascending order */
    if (eQueryIdType == SL_ID_PRODUCT_SKU || eQueryIdType == SL_ID_APPLICATION)
        SortIds(List.Ids, List.Count);
    /* The caller frees with LocalFree */
    {
        SLID *Result = LocalAlloc(LMEM_FIXED, List.Count * sizeof(SLID));

        if (!Result)
        {
            HeapFree(GetProcessHeap(), 0, List.Ids);
            return E_OUTOFMEMORY;
        }
        memcpy(Result, List.Ids, List.Count * sizeof(SLID));
        *pnReturnIds = List.Count;
        *ppReturnIds = Result;
    }
    HeapFree(GetProcessHeap(), 0, List.Ids);
    return S_OK;
}

/* The otherInfo table of an installed license: licenseType, productSkuId, applicationId, ... */
static
HRESULT
SLGetLicenseInformationImpl(_In_ HSLC hSLC,
                        _In_ const SLID *pSLLicenseId,
                        _In_ PCWSTR pwszValueName,
                        _Out_opt_ SLDATATYPE *peDataType,
                        _Out_ UINT *pcbValue,
                        _Outptr_result_bytebuffer_maybenull_(*pcbValue) PBYTE *ppbValue)
{
    char Name[96], Value[1024];
    WCHAR Path[MAX_PATH];
    INDEXREC Rec;
    BYTE *Data;
    DWORD Size;
    HRESULT hr;
    SIZE_T i, TextSize;
    char *Text;
    LICREC *Licenses;
    UINT Count, k;
    BOOL Found = FALSE;
    int Chars;

    if (!IsValidHandle(hSLC))
        return E_HANDLE;
    if (!pSLLicenseId || !pwszValueName || !pcbValue || !ppbValue)
        return E_INVALIDARG;
    *pcbValue = 0;
    *ppbValue = NULL;
    for (i = 0; pwszValueName[i]; i++)
    {
        if (i + 1 >= sizeof(Name) || pwszValueName[i] > 0x7F)
            return SL_E_VALUE_NOT_FOUND;
        Name[i] = (char)pwszValueName[i];
    }
    Name[i] = 0;

    if (!ReadIndex(pSLLicenseId, &Rec) || !BuildItemPath(L"licenses", &Rec.File, L".xrm-ms", Path, ARRAYSIZE(Path)))
        return SL_E_VALUE_NOT_FOUND;
    hr = ReadWholeFile(Path, &Data, &Size);
    if (FAILED(hr))
        return SL_E_VALUE_NOT_FOUND;
    Text = LicenseText(Data, Size, &TextSize);
    Licenses = HeapAlloc(GetProcessHeap(), 0, MAX_LICENSES_PER_FILE * sizeof(*Licenses));
    LocalFree(Data);
    if (!Text || !Licenses)
    {
        HeapFree(GetProcessHeap(), 0, Text);
        HeapFree(GetProcessHeap(), 0, Licenses);
        return E_OUTOFMEMORY;
    }
    Count = ParseLicenses(Text, TextSize, Licenses, MAX_LICENSES_PER_FILE);
    for (k = 0; k < Count; k++)
    {
        if (IsEqualGUID(&Licenses[k].Id, pSLLicenseId))
        {
            Found = GetInfoString(Text, &Licenses[k], Name, Value, sizeof(Value));
            break;
        }
    }
    HeapFree(GetProcessHeap(), 0, Text);
    HeapFree(GetProcessHeap(), 0, Licenses);
    if (!Found)
        return SL_E_VALUE_NOT_FOUND;

    /* SL_DATA_SZ: UTF-16 with the terminating NUL */
    Chars = MultiByteToWideChar(CP_UTF8, 0, Value, -1, NULL, 0);
    if (Chars <= 0)
        return E_FAIL;
    *ppbValue = LocalAlloc(LMEM_FIXED, Chars * sizeof(WCHAR));
    if (!*ppbValue)
        return E_OUTOFMEMORY;
    MultiByteToWideChar(CP_UTF8, 0, Value, -1, (WCHAR *)*ppbValue, Chars);
    *pcbValue = Chars * sizeof(WCHAR);
    if (peDataType)
        *peDataType = SL_DATA_SZ;
    return S_OK;
}


/* ---- the exports that touch the store ------------------------------------------------ */

HRESULT
WINAPI
SLInstallLicense(_In_ HSLC hSLC,
                 _In_ UINT cbLicenseBlob,
                 _In_reads_bytes_(cbLicenseBlob) const BYTE *pbLicenseBlob,
                 _Out_ SLID *pLicenseFileId)
{
    PVOID Old;
    BOOL Entered = StoreEnter(&Old);
    HRESULT hr = SLInstallLicenseImpl(hSLC, cbLicenseBlob, pbLicenseBlob, pLicenseFileId);

    StoreLeave(Entered, Old);
    return hr;
}

HRESULT
WINAPI
SLUninstallLicense(_In_ HSLC hSLC,
                   _In_ const SLID *pLicenseFileId)
{
    PVOID Old;
    BOOL Entered = StoreEnter(&Old);
    HRESULT hr = SLUninstallLicenseImpl(hSLC, pLicenseFileId);

    StoreLeave(Entered, Old);
    return hr;
}

HRESULT
WINAPI
SLGetLicense(_In_ HSLC hSLC,
             _In_ const SLID *pLicenseFileId,
             _Out_ UINT *pcbLicenseFile,
             _Outptr_result_bytebuffer_(*pcbLicenseFile) PBYTE *ppbLicenseFile)
{
    PVOID Old;
    BOOL Entered = StoreEnter(&Old);
    HRESULT hr = SLGetLicenseImpl(hSLC, pLicenseFileId, pcbLicenseFile, ppbLicenseFile);

    StoreLeave(Entered, Old);
    return hr;
}

HRESULT
WINAPI
SLGetSLIDList(_In_ HSLC hSLC,
              _In_ SLIDTYPE eQueryIdType,
              _In_opt_ const SLID *pQueryId,
              _In_ SLIDTYPE eReturnIdType,
              _Out_ UINT *pnReturnIds,
              _Outptr_result_buffer_(*pnReturnIds) SLID **ppReturnIds)
{
    PVOID Old;
    BOOL Entered = StoreEnter(&Old);
    HRESULT hr = SLGetSLIDListImpl(hSLC, eQueryIdType, pQueryId, eReturnIdType, pnReturnIds, ppReturnIds);

    StoreLeave(Entered, Old);
    return hr;
}

HRESULT
WINAPI
SLGetLicenseInformation(_In_ HSLC hSLC,
                        _In_ const SLID *pSLLicenseId,
                        _In_ PCWSTR pwszValueName,
                        _Out_opt_ SLDATATYPE *peDataType,
                        _Out_ UINT *pcbValue,
                        _Outptr_result_bytebuffer_maybenull_(*pcbValue) PBYTE *ppbValue)
{
    PVOID Old;
    BOOL Entered = StoreEnter(&Old);
    HRESULT hr = SLGetLicenseInformationImpl(hSLC, pSLLicenseId, pwszValueName, peDataType, pcbValue, ppbValue);

    StoreLeave(Entered, Old);
    return hr;
}

/* ---- status and key queries ---- */

/* Windows 10 22H2 answers a status query with neither application nor SKU id with this code (measured) */
#define SL_E_STATUS_QUERY_NO_ID ((HRESULT)0xC004F002L)

/* Measured on Windows 10 22H2 (19045.2006) with Office installed, never activated (disposable copy, 2026-11-10) */
#define SL_E_CALLER_NOT_AUTHENTICATED ((HRESULT)0xC004F072L) /* SLLoadApplicationPolicies from an ordinary process */
#define SL_E_AUTHN_DATA_NOT_SET       ((HRESULT)0xC004F079L) /* SLGetAuthenticationResult: no authentication data given */
#define SL_E_AUTHN_DATA_UNVERIFIED    ((HRESULT)0xC004F07AL) /* SLGetAuthenticationResult: data given that cannot be verified */

/* The Office application id (public: Office deployment documentation) */
static const SLID OfficeAppId = {0x0ff1ce15, 0xa989, 0x479d, {0xaf, 0x46, 0xf2, 0x75, 0xc6, 0x37, 0x06, 0x63}};

/* The licensing state of one SKU: unlicensed (reason: no product key installed) unless the store says otherwise */
typedef struct _SKUSTATE
{
    SLLICENSINGSTATUS Status;
    DWORD GraceMinutes;
    DWORD TotalGraceDays;
    HRESULT Reason;
    UINT64 Validity;
} SKUSTATE;

static
void
GetSkuState(const SLID *Sku, SKUSTATE *State)
{
    memset(State, 0, sizeof(*State));
    State->Status = SL_LICENSING_STATUS_UNLICENSED;
    /* Windows 10 with Office installed and never activated (measured): status Unlicensed, no grace,
     * no validity, reason 0xC004F014 = no product key installed */
    State->Reason = SL_E_PKEY_NOT_INSTALLED;
}

HRESULT
WINAPI
SLGetLicensingStatusInformation(_In_ HSLC hSLC,
                                _In_opt_ const SLID *pAppID,
                                _In_opt_ const SLID *pProductSkuId,
                                _In_opt_ PCWSTR pwszRightName,
                                _Inout_ UINT *pnStatusCount,
                                _Outptr_result_buffer_maybenull_(*pnStatusCount) SL_LICENSING_STATUS **ppLicensingStatus)
{
    SLID *Skus = NULL;
    SL_LICENSING_STATUS *Status;
    UINT Count = 0, i;
    HRESULT hr;
    PVOID Old;
    BOOL Entered;

    if (!IsValidHandle(hSLC))
        return E_HANDLE;
    if (!pnStatusCount || !ppLicensingStatus)
        return E_INVALIDARG;
    *pnStatusCount = 0;
    *ppLicensingStatus = NULL;

    if (!pAppID && !pProductSkuId)
    {
        /* Windows 10 (measured): an unbound handle is 0xC004F002; after SLConsumeRight bound an application (and SKU)
         * to the handle, the same query answers for that application (that SKU only) */
        if (!((PSLC)hSLC)->Bound)
            return SL_E_STATUS_QUERY_NO_ID;
        pAppID = &((PSLC)hSLC)->BoundApp;
        if (((PSLC)hSLC)->HasBoundSku)
            pProductSkuId = &((PSLC)hSLC)->BoundSku;
    }

    /* The SKUs the installed licenses name for the application (or the one SKU asked for) */
    Entered = StoreEnter(&Old);
    if (pAppID)
        hr = SLGetSLIDListImpl(hSLC, SL_ID_APPLICATION, pAppID, SL_ID_PRODUCT_SKU, &Count, &Skus);
    else
        hr = SLGetSLIDListImpl(hSLC, SL_ID_PRODUCT_SKU, pProductSkuId, SL_ID_PRODUCT_SKU, &Count, &Skus);
    StoreLeave(Entered, Old);
    if (FAILED(hr))
        return hr;
    /* Windows 10 (measured): a query naming a SKU reports that SKU only (and only when it belongs to the application) */
    if (pAppID && pProductSkuId && Count)
    {
        UINT Kept = 0;

        for (i = 0; i < Count; i++)
        {
            if (IsEqualGUID(&Skus[i], pProductSkuId))
                Skus[Kept++] = Skus[i];
        }
        Count = Kept;
    }
    /* Windows (measured): an application none of whose licenses is installed is SL_E_PRODUCT_SKU_NOT_INSTALLED */
    if (!Count)
    {
        LocalFree(Skus);
        return SL_E_PRODUCT_SKU_NOT_INSTALLED;
    }

    Status = LocalAlloc(LMEM_FIXED | LMEM_ZEROINIT, Count * sizeof(*Status));
    if (!Status)
    {
        LocalFree(Skus);
        return E_OUTOFMEMORY;
    }
    for (i = 0; i < Count; i++)
    {
        SKUSTATE State;

        GetSkuState(&Skus[i], &State);
        Status[i].SkuId = Skus[i];
        Status[i].eStatus = State.Status;
        Status[i].dwGraceTime = State.GraceMinutes;
        Status[i].dwTotalGraceDays = State.TotalGraceDays;
        Status[i].hrReason = State.Reason;
        Status[i].qwValidityExpiration = State.Validity;
    }
    LocalFree(Skus);
    *pnStatusCount = Count;
    *ppLicensingStatus = Status;
    return S_OK;
}

HRESULT
WINAPI
SLGetInstalledProductKeyIds(_In_ HSLC hSLC,
                            _In_opt_ const SLID *pProductSkuId,
                            _Out_ UINT *pnProductKeyIds,
                            _Outptr_result_buffer_maybenull_(*pnProductKeyIds) SLID **ppProductKeyIds)
{
    if (!IsValidHandle(hSLC))
        return E_HANDLE;
    if (!pnProductKeyIds || !ppProductKeyIds)
        return E_INVALIDARG;
    *pnProductKeyIds = 0;
    *ppProductKeyIds = NULL;
    /* Windows 10 (measured): an installed SKU that holds no product key is SL_E_VALUE_NOT_FOUND */
    if (pProductSkuId)
    {
        SLID *Licenses = NULL;
        UINT Count = 0;
        HRESULT hr;
        PVOID Old;
        BOOL Entered = StoreEnter(&Old);

        hr = SLGetSLIDListImpl(hSLC, SL_ID_PRODUCT_SKU, pProductSkuId, SL_ID_LICENSE, &Count, &Licenses);
        StoreLeave(Entered, Old);
        if (Licenses)
            LocalFree(Licenses);
        if (SUCCEEDED(hr) && Count)
            return SL_E_VALUE_NOT_FOUND;
    }
    return S_OK;
}

HRESULT
WINAPI
SLGetPKeyInformation(_In_ HSLC hSLC,
                     _In_ const SLID *pPKeyId,
                     _In_ PCWSTR pwszValueName,
                     _Out_opt_ SLDATATYPE *peDataType,
                     _Out_ UINT *pcbValue,
                     _Outptr_result_bytebuffer_maybenull_(*pcbValue) PBYTE *ppbValue)
{
    if (!IsValidHandle(hSLC))
        return E_HANDLE;
    if (!pPKeyId || !pwszValueName || !pcbValue || !ppbValue)
        return E_INVALIDARG;
    *pcbValue = 0;
    *ppbValue = NULL;
    return SL_E_PKEY_NOT_INSTALLED;
}

HRESULT
WINAPI
SLGetPolicyInformationDWORD(_In_ HSLC hSLC,
                            _In_ PCWSTR pwszValueName,
                            _Out_ DWORD *pdwValue)
{
    if (!IsValidHandle(hSLC))
        return E_HANDLE;
    if (!pwszValueName || !pdwValue)
        return E_INVALIDARG;
    /* Windows 10 (measured, three unknown names): SL_E_RIGHT_NOT_GRANTED. No policy is ever granted here. */
    return SL_E_RIGHT_NOT_GRANTED;
}

HRESULT
WINAPI
SLGetWindowsInformationDWORD(_In_ PCWSTR pwszValueName,
                             _Out_ DWORD *pdwValue)
{
    if (!pwszValueName || !pdwValue)
        return E_INVALIDARG;
    return SL_E_VALUE_NOT_FOUND;
}

HRESULT
WINAPI
SLConsumeRight(_In_ HSLC hSLC,
               _In_opt_ const SLID *pAppId,
               _In_opt_ const SLID *pProductSkuId,
               _In_opt_ PCWSTR pwszRightName,
               _In_opt_ PVOID pvReserved)
{
    PSLC Slc = (PSLC)hSLC;
    SLID *Skus = NULL;
    UINT Count = 0, i;
    HRESULT hr;
    PVOID Old;
    BOOL Entered, Granted = FALSE, SkuOfApp = FALSE;

    if (!IsValidHandle(hSLC))
        return E_HANDLE;
    /* Windows 10 (measured): no application id is E_INVALIDARG */
    if (!pAppId)
        return E_INVALIDARG;

    /* Windows 10 (measured): an application or SKU that is not installed is 0xC004F015 and binds nothing */
    Entered = StoreEnter(&Old);
    hr = SLGetSLIDListImpl(hSLC, SL_ID_APPLICATION, pAppId, SL_ID_PRODUCT_SKU, &Count, &Skus);
    StoreLeave(Entered, Old);
    if (FAILED(hr) || !Count)
    {
        if (Skus)
            LocalFree(Skus);
        return SL_E_PRODUCT_SKU_NOT_INSTALLED;
    }
    for (i = 0; i < Count; i++)
    {
        SKUSTATE State;

        if (pProductSkuId && !IsEqualGUID(&Skus[i], pProductSkuId))
            continue;
        SkuOfApp = TRUE;
        GetSkuState(&Skus[i], &State);
        if (State.Status == SL_LICENSING_STATUS_LICENSED || State.Status == SL_LICENSING_STATUS_IN_GRACE_PERIOD)
            Granted = TRUE;
    }
    LocalFree(Skus);
    if (pProductSkuId && !SkuOfApp)
        return SL_E_PRODUCT_SKU_NOT_INSTALLED;

    /* Windows 10 (measured): the call binds the application (and the SKU) to the handle, whatever it returns; the status
     * query without ids then answers for it, and so do the policy queries once a SKU of it is in grace. It returns
     * 0xC004F013 while no SKU of it is licensed or in grace: no right is ever granted that the state does not grant. */
    Slc->Bound = TRUE;
    Slc->BoundApp = *pAppId;
    Slc->HasBoundSku = pProductSkuId != NULL;
    if (pProductSkuId)
        Slc->BoundSku = *pProductSkuId;
    return Granted ? S_OK : SL_E_RIGHT_NOT_GRANTED;
}

HRESULT
WINAPI
SLInstallProofOfPurchase(_In_ HSLC hSLC,
                         _In_ PCWSTR pwszPKeyAlgorithm,
                         _In_ PCWSTR pwszPKeyString,
                         _In_ UINT cbPKeySpecificData,
                         _In_reads_bytes_opt_(cbPKeySpecificData) PBYTE pbPKeySpecificData,
                         _Out_ SLID *pPKeyId)
{
    if (!IsValidHandle(hSLC))
        return E_HANDLE;
    if (!pwszPKeyAlgorithm || !pwszPKeyString || !pPKeyId)
        return E_INVALIDARG;
    return SL_E_NOT_SUPPORTED;
}

HRESULT
WINAPI
SLUninstallProofOfPurchase(_In_ HSLC hSLC,
                           _In_ const SLID *pPKeyId)
{
    if (!IsValidHandle(hSLC))
        return E_HANDLE;
    if (!pPKeyId)
        return E_INVALIDARG;
    return SL_E_PKEY_NOT_INSTALLED;
}

HRESULT
WINAPI
SLActivateProduct(_In_ HSLC hSLC,
                  _In_ const SLID *pProductSkuId,
                  _In_ UINT cbAppSpecificData,
                  _In_reads_bytes_opt_(cbAppSpecificData) const PVOID pvAppSpecificData,
                  _In_opt_ const PVOID pActivationInfo,
                  _In_opt_ PCWSTR pwszProxyServer,
                  _In_ WORD wProxyPort)
{
    if (!IsValidHandle(hSLC))
        return E_HANDLE;
    if (!pProductSkuId)
        return E_INVALIDARG;
    return SL_E_NOT_SUPPORTED;
}

HRESULT
WINAPI
SLDepositMigrationBlob(_In_ HSLC hSLC,
                       _In_ UINT cbBlob,
                       _In_reads_bytes_opt_(cbBlob) const BYTE *pbBlob,
                       _In_opt_ PVOID pvReserved1,
                       _In_opt_ PVOID pvReserved2)
{
    if (!IsValidHandle(hSLC))
        return E_HANDLE;
    return SL_E_NOT_SUPPORTED;
}

HRESULT
WINAPI
SLPersistApplicationPolicies(_In_ HSLC hSLC,
                             _In_ const SLID *pAppId,
                             _In_opt_ const SLID *pProductSkuId)
{
    if (!IsValidHandle(hSLC))
        return E_HANDLE;
    if (!pAppId)
        return E_INVALIDARG;
    return S_OK;
}

HRESULT
WINAPI
SLPersistRTSPayloadOverride(_In_ HSLC hSLC,
                            _In_ const SLID *pProductSkuId,
                            _In_opt_ PCWSTR pwszPayloadName)
{
    if (!IsValidHandle(hSLC))
        return E_HANDLE;
    if (!pProductSkuId)
        return E_INVALIDARG;
    return S_OK;
}

BOOL
WINAPI
DllMain(HINSTANCE hInstance, DWORD dwReason, LPVOID lpReserved)
{
    if (dwReason == DLL_PROCESS_ATTACH)
        DisableThreadLibraryCalls(hInstance);
    return TRUE;
}

/* ---- entry points of the service: this client has no service ---- */

HRESULT
WINAPI
SLGetPolicyInformation(_In_ HSLC hSLC,
                       _In_ PCWSTR pwszValueName,
                       _Out_opt_ SLDATATYPE *peDataType,
                       _Out_ UINT *pcbValue,
                       _Outptr_result_bytebuffer_maybenull_(*pcbValue) PBYTE *ppbValue)
{
    if (!IsValidHandle(hSLC))
        return E_HANDLE;
    if (!pwszValueName || !pcbValue || !ppbValue)
        return E_INVALIDARG;
    *pcbValue = 0;
    *ppbValue = NULL;
    return SL_E_RIGHT_NOT_GRANTED; /* as SLGetPolicyInformationDWORD */
}

static WCHAR *DupWide(const WCHAR *Text);

HRESULT
WINAPI
SLGetServiceInformation(_In_ HSLC hSLC,
                        _In_ PCWSTR pwszValueName,
                        _Out_opt_ SLDATATYPE *peDataType,
                        _Out_ UINT *pcbValue,
                        _Outptr_result_bytebuffer_maybenull_(*pcbValue) PBYTE *ppbValue)
{
    if (!IsValidHandle(hSLC))
        return E_HANDLE;
    if (!pwszValueName || !pcbValue || !ppbValue)
        return E_INVALIDARG;
    *pcbValue = 0;
    *ppbValue = NULL;
    /* Windows 10 (measured): "ActivePlugins" is the multi-string of the plug-in modules the service has loaded (installing
     * Office adds none) and "Version" the service version as a string; any other name is not found */
    if (!wcscmp(pwszValueName, L"ActivePlugins"))
    {
        static const WCHAR *Plugins[] = { L"sppwinob.dll", L"sppobjs.dll" };
        WCHAR Dir[MAX_PATH], *Out, *p;
        UINT DirLen, i, Chars = 1;

        DirLen = GetSystemDirectoryW(Dir, ARRAYSIZE(Dir));
        if (!DirLen || DirLen >= ARRAYSIZE(Dir) - 16)
            return E_FAIL;
        for (i = 0; i < ARRAYSIZE(Plugins); i++)
            Chars += DirLen + 1 + (UINT)wcslen(Plugins[i]) + 1;
        Out = LocalAlloc(LMEM_FIXED, Chars * sizeof(WCHAR));
        if (!Out)
            return E_OUTOFMEMORY;
        for (p = Out, i = 0; i < ARRAYSIZE(Plugins); i++)
        {
            memcpy(p, Dir, DirLen * sizeof(WCHAR));
            p += DirLen;
            *p++ = L'\\';
            wcscpy(p, Plugins[i]);
            p += wcslen(Plugins[i]) + 1;
        }
        *p = 0;
        *pcbValue = Chars * sizeof(WCHAR);
        *ppbValue = (PBYTE)Out;
        if (peDataType)
            *peDataType = SL_DATA_MULTI_SZ;
        return S_OK;
    }
    if (!wcscmp(pwszValueName, L"Version"))
    {
        OSVERSIONINFOW Ver;
        WCHAR Text[64];
        WCHAR *Out;

        memset(&Ver, 0, sizeof(Ver));
        Ver.dwOSVersionInfoSize = sizeof(Ver);
        if (!GetVersionExW(&Ver))
            return E_FAIL;
        /* major.minor.build.revision; the update revision is not tracked here */
        _snwprintf(Text, ARRAYSIZE(Text), L"%lu.%lu.%lu.0", Ver.dwMajorVersion, Ver.dwMinorVersion, Ver.dwBuildNumber);
        Out = DupWide(Text);
        if (!Out)
            return E_OUTOFMEMORY;
        *pcbValue = (UINT)((wcslen(Text) + 1) * sizeof(WCHAR));
        *ppbValue = (PBYTE)Out;
        if (peDataType)
            *peDataType = SL_DATA_SZ;
        return S_OK;
    }
    return SL_E_VALUE_NOT_FOUND;
}

/* The value names of a SKU that Windows 10 answers (measured) and the information of the SKU's license they come from */
static
const WCHAR *
SkuValueToInfoName(PCWSTR Name)
{
    static const struct { const WCHAR *Name; const WCHAR *Info; } Map[] =
    {
        { L"Name", L"productName" },
        { L"Description", L"productDescription" },
        { L"Family", L"Family" },
        { L"Author", L"productAuthor" },
        /* The bit set of the Office applications the SKU licenses: the string of the EUL's ApplicationBitmap information
         * (Word asks for it of every SKU once it has the status; without it Word stops with a licensing error) */
        { L"ApplicationBitmap", L"ApplicationBitmap" },
    };
    UINT i;

    for (i = 0; i < ARRAYSIZE(Map); i++)
        if (!wcscmp(Name, Map[i].Name))
            return Map[i].Info;
    return NULL;
}

/* The end-user license of a SKU is the one whose licenseType is msft:sl/EUL/<kind>/PUBLIC */
static
BOOL
IsPublicEulType(PCWSTR Type)
{
    SIZE_T Len = wcslen(Type);

    return !wcsncmp(Type, L"msft:sl/EUL/", 12) && Len > 12 + 7 && !wcscmp(Type + Len - 7, L"/PUBLIC");
}

static
WCHAR *
DupWide(const WCHAR *Text)
{
    SIZE_T Bytes = (wcslen(Text) + 1) * sizeof(WCHAR);
    WCHAR *Out = LocalAlloc(LMEM_FIXED, Bytes);

    if (Out)
        memcpy(Out, Text, Bytes);
    return Out;
}

static
HRESULT
SLGetProductSkuInformationImpl(_In_ HSLC hSLC,
                               _In_ const SLID *pProductSkuId,
                               _In_ PCWSTR pwszValueName,
                               _Out_opt_ SLDATATYPE *peDataType,
                               _Out_ UINT *pcbValue,
                               _Outptr_result_bytebuffer_maybenull_(*pcbValue) PBYTE *ppbValue)
{
    SLID *Licenses = NULL;
    UINT Count = 0, i;
    HRESULT hr;
    const WCHAR *Info;
    BOOL IsFileId = !wcscmp(pwszValueName, L"fileId");
    BOOL IsTypeName = wcsncmp(pwszValueName, L"msft:sl/", 8) == 0;
    SLID Found;
    BOOL HaveFound = FALSE;
    WCHAR Text[64];
    BYTE *Type;
    UINT cbType;

    hr = SLGetSLIDListImpl(hSLC, SL_ID_PRODUCT_SKU, pProductSkuId, SL_ID_LICENSE, &Count, &Licenses);
    if (FAILED(hr))
        return hr;
    if (!Count)
        return SL_E_PRODUCT_SKU_NOT_INSTALLED;
    Info = SkuValueToInfoName(pwszValueName);
    if (!Info && !IsFileId && !IsTypeName)
    {
        LocalFree(Licenses);
        return SL_E_VALUE_NOT_FOUND;
    }

    /* Find the license that answers: the SKU's end-user license, or (for a license type name) the license of that type */
    for (i = 0; i < Count && !HaveFound; i++)
    {
        Type = NULL;
        cbType = 0;
        if (FAILED(SLGetLicenseInformationImpl(hSLC, &Licenses[i], L"licenseType", NULL, &cbType, &Type)) || !Type)
            continue;
        if (IsTypeName ? !wcscmp((WCHAR *)Type, pwszValueName) : IsPublicEulType((WCHAR *)Type))
        {
            Found = Licenses[i];
            HaveFound = TRUE;
        }
        LocalFree(Type);
    }
    LocalFree(Licenses);
    if (!HaveFound)
        return SL_E_VALUE_NOT_FOUND;

    if (Info)
        return SLGetLicenseInformationImpl(hSLC, &Found, Info, peDataType, pcbValue, ppbValue);

    if (IsFileId)
    {
        INDEXREC Rec;

        if (!ReadIndex(&Found, &Rec))
            return SL_E_VALUE_NOT_FOUND;
        FormatGuid(&Rec.File, Text);
    }
    else
        FormatGuid(&Found, Text);
    /* Windows prints these ids in lower case (measured) */
    for (i = 0; Text[i]; i++)
        if (Text[i] >= L'A' && Text[i] <= L'F')
            Text[i] += L'a' - L'A';
    *ppbValue = (PBYTE)DupWide(Text);
    if (!*ppbValue)
        return E_OUTOFMEMORY;
    *pcbValue = (UINT)((wcslen(Text) + 1) * sizeof(WCHAR));
    if (peDataType)
        *peDataType = SL_DATA_SZ;
    return S_OK;
}

HRESULT
WINAPI
SLGetProductSkuInformation(_In_ HSLC hSLC,
                           _In_ const SLID *pProductSkuId,
                           _In_ PCWSTR pwszValueName,
                           _Out_opt_ SLDATATYPE *peDataType,
                           _Out_ UINT *pcbValue,
                           _Outptr_result_bytebuffer_maybenull_(*pcbValue) PBYTE *ppbValue)
{
    PVOID Old;
    BOOL Entered;
    HRESULT hr;

    if (!IsValidHandle(hSLC))
        return E_HANDLE;
    if (!pProductSkuId || !pwszValueName || !pcbValue || !ppbValue)
        return E_INVALIDARG;
    *pcbValue = 0;
    *ppbValue = NULL;

    Entered = StoreEnter(&Old);
    hr = SLGetProductSkuInformationImpl(hSLC, pProductSkuId, pwszValueName, peDataType, pcbValue, ppbValue);
    StoreLeave(Entered, Old);
    return hr;
}

/* SLGetApplicationInformation is declared in the Windows SDK's slpublic.h, not in this tree's copy */
HRESULT
WINAPI
SLGetApplicationInformation(_In_ HSLC hSLC,
                            _In_ const SLID *pApplicationId,
                            _In_ PCWSTR pwszValueName,
                            _Out_opt_ SLDATATYPE *peDataType,
                            _Out_ UINT *pcbValue,
                            _Outptr_result_bytebuffer_maybenull_(*pcbValue) PBYTE *ppbValue)
{
    if (!IsValidHandle(hSLC))
        return E_HANDLE;
    if (!pApplicationId || !pwszValueName || !pcbValue || !ppbValue)
        return E_INVALIDARG;
    *pcbValue = 0;
    *ppbValue = NULL;
    /* Windows 10 (measured: Name, Description, Version, GenuineState of the Windows and the Office application) */
    return SL_E_VALUE_NOT_FOUND;
}

HRESULT
WINAPI
SLGenerateOfflineInstallationId(_In_ HSLC hSLC,
                                _In_ const SLID *pProductSkuId,
                                _Out_ PWSTR *ppwszInstallationId)
{
    if (!IsValidHandle(hSLC))
        return E_HANDLE;
    if (!pProductSkuId || !ppwszInstallationId)
        return E_INVALIDARG;
    *ppwszInstallationId = NULL;
    return SL_E_NOT_SUPPORTED;
}

HRESULT
WINAPI
SLDepositOfflineConfirmationId(_In_ HSLC hSLC,
                               _In_ const SLID *pProductSkuId,
                               _In_ PCWSTR pwszInstallationId,
                               _In_ PCWSTR pwszConfirmationId)
{
    if (!IsValidHandle(hSLC))
        return E_HANDLE;
    if (!pProductSkuId || !pwszInstallationId || !pwszConfirmationId)
        return E_INVALIDARG;
    return SL_E_NOT_SUPPORTED;
}

/*
 * The entry points below are not in the public header and their signatures are not documented:
 * they exist on the 64-bit client only (Office 64-bit resolves them by name), take pointer sized
 * arguments that are never read, and answer that the platform cannot do it.
 */

HRESULT
WINAPI
SLGetPKeyId(_In_ HSLC hSLC,
            _In_ PCWSTR pwszPKeyAlgorithm,
            _In_ UINT cbPKeyData,
            _In_reads_bytes_(cbPKeyData) const BYTE *pbPKeyData,
            _Out_ SLID *pPKeyId)
{
    /* No product key algorithm is implemented: a key cannot be identified */
    return SL_E_NOT_SUPPORTED;
}

HRESULT WINAPI SLReArm(PVOID a0, PVOID a1, PVOID a2, PVOID a3) { return SL_E_NOT_SUPPORTED; }
HRESULT WINAPI SLRegisterPlugin(PVOID a0, PVOID a1, PVOID a2, PVOID a3) { return SL_E_NOT_SUPPORTED; }

/*
 * Application authentication data. On Windows the Software Protection service verifies the blob an application hands
 * in (Office passes 0x120 bytes) and thereby learns which application the caller is. The verification needs material
 * that exists only in Microsoft's binaries, so it cannot be done here: the blob is ACCEPTED WITHOUT BEING VERIFIED, as
 * a hint that the caller is Office, which binds the Office application to the handle. Everything that is then answered
 * for that caller is the licensing state of the installed licenses (unlicensed or in grace, as Windows reports it for
 * an Office that was never activated): nothing here fakes an activation, nor grants more than that state grants.
 *
 * Measured on Windows 10 22H2 with a blob that cannot be verified (header 0x120,1,0x10000,0x10c and filler):
 * SLSetAuthenticationData is S_OK for 0 bytes (NULL) and for 0x120 bytes, 0x8007000D (invalid data) for 0x10 bytes;
 * SLGetAuthenticationResult then is 0xC004F07A (cannot be verified) after the 0x120 bytes and 0xC004F079 (not set)
 * after the empty call; SLGetAuthenticationResult(h, NULL, NULL, NULL) is E_INVALIDARG.
 */
HRESULT
WINAPI
SLSetAuthenticationData(_In_ HSLC hSLC,
                        _In_ UINT cbData,
                        _In_reads_bytes_opt_(cbData) const BYTE *pbData,
                        _In_opt_ PVOID pvReserved1,
                        _In_opt_ PVOID pvReserved2)
{
    PSLC Slc = (PSLC)hSLC;
    BOOL Readable = TRUE;

    if (!IsValidHandle(hSLC))
        return E_HANDLE;
    if (!cbData && !pbData)
    {
        Slc->AuthState = SLC_AUTH_NONE;
        return S_OK;
    }
    if (!pbData)
        return E_INVALIDARG;
    if (cbData < 0x20)
        return HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
    _SEH2_TRY
    {
        volatile BYTE Probe = pbData[0] | pbData[cbData - 1];

        (void)Probe;
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        Readable = FALSE;
    }
    _SEH2_END;
    if (!Readable)
        return E_POINTER;

    Slc->AuthState = SLC_AUTH_ACCEPTED;
    Slc->Bound = TRUE;
    Slc->BoundApp = OfficeAppId;
    Slc->HasBoundSku = FALSE;
    return S_OK;
}

HRESULT
WINAPI
SLGetAuthenticationResult(_In_ HSLC hSLC, _In_opt_ PVOID pvA, _In_opt_ PVOID pvB, _In_opt_ PVOID pvC)
{
    PSLC Slc = (PSLC)hSLC;

    if (!IsValidHandle(hSLC))
        return E_HANDLE;
    if (!pvA && !pvB && !pvC)
        return E_INVALIDARG;
    if (Slc->AuthState == SLC_AUTH_NONE)
        return SL_E_AUTHN_DATA_NOT_SET;
    /* The data was accepted as the caller's hint (see above): the result is a success without output */
    return S_OK;
}

/* Measured: every application and SKU id, from a caller that has not authenticated, is 0xC004F072 and yields no handle */
HRESULT
WINAPI
SLLoadApplicationPolicies(_In_ const SLID *pAppId, _In_opt_ PVOID pvReserved1, _In_opt_ PVOID pvReserved2, _Out_ HSLC *phPolicies, _In_ UINT uFlags)
{
    if (phPolicies)
        *phPolicies = NULL;
    if (!pAppId)
        return E_INVALIDARG;
    return SL_E_CALLER_NOT_AUTHENTICATED;
}
HRESULT WINAPI SLUnloadApplicationPolicies(PVOID a0, PVOID a1) { return SL_E_NOT_SUPPORTED; }
HRESULT WINAPI SLGetApplicationPolicy(PVOID a0, PVOID a1, PVOID a2, PVOID a3, PVOID a4) { return SL_E_NOT_SUPPORTED; }
