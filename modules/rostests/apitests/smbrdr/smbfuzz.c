/*
 * PROJECT:     NitroOS
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     smbfuzz: a TEST engine for the SMB mini-redirector without a server: answers every
 *              request from an in-memory fake share, optionally malformed (hostile-engine tests)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

/*
 * smbfuzz [-m benign|hostile|stall|slow] [-s SEED] [-p PERCENT] [-d MS] [-j THREADS] [-t SECONDS] [-o LOG]
 *
 *   benign   every request answered well-formed (a share whose files read back a pattern)
 *   hostile  PERCENT (default 100) of the replies malformed, one mutation class per reply, chosen
 *            from SEED; the classes and the counts per opcode are logged at the end
 *   stall    takes requests and never answers them (cancel, kill and time limit tests)
 *   slow     answers after MS milliseconds (pool budget tests)
 * -n OP[,OP..]: never malform replies to these opcodes (1 = CONNECT keeps rdbss's connection setup out of a run).
 * -j: GET threads (default 1); -t: exit after SECONDS (default: run until killed); -x OP:STATUS: every
 * reply to opcode OP carries STATUS (one status from a server or a bad engine, reproducibly).
 * Every CONNECT is checked: the token handle the driver created in this process (granted access,
 * type, impersonation level, logon id against the request header, what it allows), logged as
 * "TOKEN ..." lines; handle count of this process logged every 1000 requests.
 * This tool is a test of the driver; it reads nothing from a network.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define WIN32_NO_STATUS
#include <windows.h>
#include <sddl.h>
#include <ndk/iofuncs.h>
#include <ndk/obfuncs.h>
#include <ndk/rtlfuncs.h>
#include <ntstatus.h>
#include <drivers/smbrdr/smbupcall.h>
#include "sysopen.h"

#ifndef STATUS_CONNECTION_ACTIVE
#define STATUS_CONNECTION_ACTIVE ((NTSTATUS)0xC000023BL)
#endif
#ifndef STATUS_RETRY
#define STATUS_RETRY ((NTSTATUS)0xC000022DL)
#endif

enum { MODE_BENIGN, MODE_HOSTILE, MODE_STALL, MODE_SLOW };

#define NCLASS 20
static const char *ClassName[NCLASS] = {
    "none", "magic", "version", "headersize", "totalsize", "wrong-id", "wrong-opcode", "status",
    "data-length", "data-offset", "fixed-random", "chain", "volume", "create-fields", "connect-fields",
    "duplicate", "drop", "truncate", "bitflip", "stale-id"
};

static struct
{
    int mode;
    unsigned seed;
    int percent;
    int delay;
    int threads;
    int seconds;
    FILE *log;
    int force_op;           /* -x OP:STATUS: every reply to OP gets STATUS (and is logged) */
    ULONG keep_ops;         /* -n OP[,OP..]: replies to these opcodes are never malformed (bit per opcode) */
    NTSTATUS force_status;
} opt = { MODE_BENIGN, 1, 100, 200, 1, 0, NULL, 0, 0, 0 };

static HANDLE Dev;
static CRITICAL_SECTION LogLock;
static volatile LONG NextId = 0x1000;
static volatile LONG Served, Replied, ReplyFailed, Tokens, TokenBad;
static volatile LONG Counts[SmbUpMaximumOpcode][NCLASS];
static volatile ULONGLONG LastId;

static void logmsg(const char *fmt, ...)
{
    va_list ap;
    SYSTEMTIME t;

    if (!opt.log)
        return;
    GetSystemTime(&t);
    EnterCriticalSection(&LogLock);
    fprintf(opt.log, "%02u:%02u:%02u.%03u ", t.wHour, t.wMinute, t.wSecond, t.wMilliseconds);
    va_start(ap, fmt);
    vfprintf(opt.log, fmt, ap);
    va_end(ap);
    fputc('\n', opt.log);
    fflush(opt.log);
    LeaveCriticalSection(&LogLock);
}

/* xorshift, per thread */
static ULONG rnd(ULONG *s)
{
    ULONG x = *s;
    x ^= x << 13; x ^= x >> 17; x ^= x << 5;
    return *s = x ? x : 0x9E3779B9u;
}

static const NTSTATUS SpecialStatus[] = {
    STATUS_PENDING, STATUS_REPARSE, STATUS_RETRY, STATUS_MORE_PROCESSING_REQUIRED, STATUS_CONNECTION_ACTIVE,
    STATUS_CANT_WAIT, STATUS_LOCK_NOT_GRANTED, STATUS_BUFFER_OVERFLOW, STATUS_NO_MORE_FILES,
    STATUS_NOT_FOUND, STATUS_ACCESS_VIOLATION, STATUS_SUCCESS, (NTSTATUS)0x40000000, (NTSTATUS)0x80000001,
    STATUS_OBJECT_NAME_NOT_FOUND, STATUS_SHARING_VIOLATION, STATUS_END_OF_FILE, STATUS_BUFFER_TOO_SMALL,
    STATUS_INVALID_PARAMETER, STATUS_NETWORK_CREDENTIAL_CONFLICT, STATUS_STACK_OVERFLOW, STATUS_OPLOCK_BREAK_IN_PROGRESS
};

/* Token checks on a CONNECT ************************************************/

/* NtQueryObject wants the exact size of OBJECT_BASIC_INFORMATION */

static void check_token(const SMBUP_HEADER *h, HANDLE token)
{
    OBJECT_BASIC_INFORMATION obi;
    TOKEN_STATISTICS stats;
    SECURITY_IMPERSONATION_LEVEL level = (SECURITY_IMPERSONATION_LEVEL)-1;
    TOKEN_TYPE type = 0;
    UCHAR userbuf[256];
    char *sid = NULL;
    DWORD len;
    HANDLE dup = NULL, thr = NULL, dup2 = NULL;
    DWORD dupErr = 0, openErr = 0, dup2Err = 0;
    NTSTATUS st;
    BOOL bad = FALSE;

    InterlockedIncrement(&Tokens);
    memset(&obi, 0, sizeof(obi));
    memset(&stats, 0, sizeof(stats));
    st = NtQueryObject(token, ObjectBasicInformation, &obi, sizeof(obi), NULL);
    GetTokenInformation(token, TokenType, &type, sizeof(type), &len);
    GetTokenInformation(token, TokenImpersonationLevel, &level, sizeof(level), &len);
    GetTokenInformation(token, TokenStatistics, &stats, sizeof(stats), &len);
    if (GetTokenInformation(token, TokenUser, userbuf, sizeof(userbuf), &len))
        ConvertSidToStringSidA(((TOKEN_USER *)userbuf)->User.Sid, &sid);

    /* What the handle itself allows */
    if (DuplicateTokenEx(token, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &dup))
        CloseHandle(dup);
    else
        dupErr = GetLastError();

    /* What impersonating it allows: the token opened again as the user it belongs to */
    if (SetThreadToken(NULL, token))
    {
        if (OpenThreadToken(GetCurrentThread(), TOKEN_DUPLICATE | TOKEN_QUERY, FALSE, &thr))
        {
            if (DuplicateTokenEx(thr, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &dup2))
                CloseHandle(dup2);
            else
                dup2Err = GetLastError();
            CloseHandle(thr);
        }
        else
            openErr = GetLastError();
        RevertToSelf();
    }
    else
        openErr = 0xFFFFFFFF;

    if (!NT_SUCCESS(st) || obi.GrantedAccess != (TOKEN_QUERY | TOKEN_IMPERSONATE) || type != TokenImpersonation ||
        level != SecurityImpersonation || stats.AuthenticationId.LowPart != h->LogonIdLow ||
        stats.AuthenticationId.HighPart != h->LogonIdHigh || dupErr == 0)
    {
        bad = TRUE;
        InterlockedIncrement(&TokenBad);
    }
    logmsg("TOKEN %s req=%I64u hdrlogon=%08lx%08lx tokenlogon=%08lx%08lx access=%#lx(st %08lx) type=%d level=%d "
           "user=%s dupprimary=%lu openthread-as-user=%lu dupprimary-via-impersonation=%lu",
           bad ? "BAD" : "ok", h->RequestId, h->LogonIdHigh, h->LogonIdLow, stats.AuthenticationId.HighPart,
           stats.AuthenticationId.LowPart, obi.GrantedAccess, st, (int)type, (int)level, sid ? sid : "?",
           dupErr, openErr, dup2Err);
    if (sid)
        LocalFree(sid);
}

/* The fake share ***********************************************************/

#define FAKE_EOF (1024 * 1024)

/* Directory classes the user-mode headers of this tree do not declare (public NT layouts) */
typedef struct _MY_NAMES_INFORMATION
{
    ULONG NextEntryOffset;
    ULONG FileIndex;
    ULONG FileNameLength;
    WCHAR FileName[1];
} MY_NAMES_INFORMATION;

typedef struct _MY_ID_BOTH_DIR_INFORMATION
{
    ULONG NextEntryOffset;
    ULONG FileIndex;
    LARGE_INTEGER CreationTime, LastAccessTime, LastWriteTime, ChangeTime, EndOfFile, AllocationSize;
    ULONG FileAttributes;
    ULONG FileNameLength;
    ULONG EaSize;
    CCHAR ShortNameLength;
    WCHAR ShortName[12];
    LARGE_INTEGER FileId;
    WCHAR FileName[1];
} MY_ID_BOTH_DIR_INFORMATION;

typedef struct _MY_ID_FULL_DIR_INFORMATION
{
    ULONG NextEntryOffset;
    ULONG FileIndex;
    LARGE_INTEGER CreationTime, LastAccessTime, LastWriteTime, ChangeTime, EndOfFile, AllocationSize;
    ULONG FileAttributes;
    ULONG FileNameLength;
    ULONG EaSize;
    LARGE_INTEGER FileId;
    WCHAR FileName[1];
} MY_ID_FULL_DIR_INFORMATION;

static void fill_attrs(SMBUP_FILE_ATTRIBUTES *a, BOOL dir)
{
    a->CreationTime = a->LastAccessTime = a->LastWriteTime = a->ChangeTime = 132000000000000000LL;
    a->AllocationSize = dir ? 0 : FAKE_EOF;
    a->EndOfFile = dir ? 0 : FAKE_EOF;
    a->FileAttributes = dir ? FILE_ATTRIBUTE_DIRECTORY : FILE_ATTRIBUTE_ARCHIVE;
}

static BOOL path_is_dir(const SMBUP_HEADER *h, const SMBUP_CREATE_REQUEST *r)
{
    const WCHAR *p;
    ULONG n, i;

    if (r->Path.Length == 0)
        return TRUE;
    if ((ULONGLONG)r->Path.Offset + r->Path.Length > h->TotalSize)
        return FALSE;
    p = (const WCHAR *)((const UCHAR *)h + r->Path.Offset);
    n = r->Path.Length / sizeof(WCHAR);
    /* names starting with "d" in their last component are directories */
    for (i = n; i > 0 && p[i - 1] != L'\\'; i--);
    return (r->CreateOptions & FILE_DIRECTORY_FILE) || (i < n && (p[i] == L'd' || p[i] == L'D'));
}

/* Builds a directory listing of the class into out (at most max bytes); returns the length */
static ULONG fake_directory(ULONG cls, UCHAR *out, ULONG max, ULONG index, ULONG count)
{
    static const WCHAR *names[] = { L"a.txt", L"dsub", L"file-with-a-longer-name.bin" };
    ULONG off = 0, i, prev = MAXULONG;

    for (i = index; i < min(3, index + count); i++)
    {
        const WCHAR *nm = names[i];
        ULONG nl = (ULONG)wcslen(nm) * sizeof(WCHAR), fixed, total;
        UCHAR *e = out + off;

        switch (cls)
        {
            case FileDirectoryInformation: fixed = FIELD_OFFSET(FILE_DIRECTORY_INFORMATION, FileName); break;
            case FileFullDirectoryInformation: fixed = FIELD_OFFSET(FILE_FULL_DIR_INFORMATION, FileName); break;
            case FileBothDirectoryInformation: fixed = FIELD_OFFSET(FILE_BOTH_DIR_INFORMATION, FileName); break;
            case FileNamesInformation: fixed = FIELD_OFFSET(MY_NAMES_INFORMATION, FileName); break;
            case FileIdBothDirectoryInformation: fixed = FIELD_OFFSET(MY_ID_BOTH_DIR_INFORMATION, FileName); break;
            case FileIdFullDirectoryInformation: fixed = FIELD_OFFSET(MY_ID_FULL_DIR_INFORMATION, FileName); break;
            default: return 0;
        }
        total = (fixed + nl + 7) & ~7u;
        if (off + fixed + nl > max)
            break;
        memset(e, 0, min(total, max - off));
        if (cls == FileNamesInformation)
        {
            ((MY_NAMES_INFORMATION *)e)->FileNameLength = nl;
            ((MY_NAMES_INFORMATION *)e)->FileIndex = i;
        }
        else
        {
            FILE_DIRECTORY_INFORMATION *d = (FILE_DIRECTORY_INFORMATION *)e;  /* common prefix */
            d->FileIndex = i;
            d->EndOfFile.QuadPart = (nm[0] == L'd') ? 0 : FAKE_EOF;
            d->AllocationSize = d->EndOfFile;
            d->FileAttributes = (nm[0] == L'd') ? FILE_ATTRIBUTE_DIRECTORY : FILE_ATTRIBUTE_ARCHIVE;
            d->FileNameLength = nl;
        }
        memcpy(e + fixed, nm, nl);
        if (prev != MAXULONG)
            *(ULONG *)(out + prev) = off - prev;
        prev = off;
        off += total;
        if (off > max)
            off = max;
    }
    if (prev == MAXULONG)
        return 0;
    return off;
}

/* Fills the reply for h (well-formed) in r; returns the total size */
static ULONG answer(const SMBUP_HEADER *h, UCHAR *rb, BOOL *dirlisting)
{
    SMBUP_HEADER *r = (SMBUP_HEADER *)rb;
    ULONG fixed = SMBUP_REPLY_FIXED_SIZE(h->Opcode), total;
    SMBUP_DATA_REPLY *dr = (SMBUP_DATA_REPLY *)(r + 1);
    UCHAR *data = rb + sizeof(SMBUP_HEADER) + sizeof(SMBUP_DATA_REPLY);

    memset(rb, 0, sizeof(SMBUP_HEADER) + 256);
    r->Magic = SMBUP_MAGIC;
    r->Version = SMBUP_VERSION;
    r->Opcode = h->Opcode;
    r->HeaderSize = sizeof(SMBUP_HEADER);
    r->RequestId = h->RequestId;
    r->Status = STATUS_SUCCESS;
    total = sizeof(SMBUP_HEADER) + fixed;
    *dirlisting = FALSE;

    switch (h->Opcode)
    {
        case SmbUpConnect:
        {
            const SMBUP_CONNECT_REQUEST *c = (const void *)(h + 1);
            SMBUP_CONNECT_REPLY *cr = (SMBUP_CONNECT_REPLY *)(r + 1);

            if (c->TokenHandle)
            {
                check_token(h, (HANDLE)(ULONG_PTR)c->TokenHandle);
                CloseHandle((HANDLE)(ULONG_PTR)c->TokenHandle);
            }
            else
                logmsg("TOKEN none req=%I64u", h->RequestId);
            cr->ConnectionId = (ULONGLONG)InterlockedIncrement(&NextId);
            cr->MaxReadSize = SMBUP_MAX_IO;     /* as a server with large MTU (the driver's limit) */
            cr->MaxWriteSize = SMBUP_MAX_IO;
            cr->ShareType = 1;
            logmsg("CONNECT req=%I64u logon=%08lx%08lx pid=%lu -> conn %I64x", h->RequestId, h->LogonIdHigh,
                   h->LogonIdLow, h->ProcessId, cr->ConnectionId);
            break;
        }
        case SmbUpCreate:
        {
            const SMBUP_CREATE_REQUEST *c = (const void *)(h + 1);
            SMBUP_CREATE_REPLY *cr = (SMBUP_CREATE_REPLY *)(r + 1);
            BOOL dir = path_is_dir(h, c);

            if (c->CreateOptions & FILE_NON_DIRECTORY_FILE)
                dir = FALSE;
            cr->FileId = (ULONGLONG)InterlockedIncrement(&NextId);
            cr->CreateAction = (c->CreateDisposition == FILE_CREATE) ? FILE_CREATED : FILE_OPENED;
            fill_attrs(&cr->Attributes, dir);
            break;
        }
        case SmbUpRead:
        {
            const SMBUP_IO_REQUEST *io = (const void *)(h + 1);
            ULONG n = io->Length, i;

            if (io->Offset >= FAKE_EOF)
            {
                r->Status = STATUS_END_OF_FILE;
                n = 0;
            }
            else if (io->Offset + n > FAKE_EOF)
                n = (ULONG)(FAKE_EOF - io->Offset);
            n = min(n, SMBUP_MAX_IO);
            for (i = 0; i < n; i++)
                data[i] = (UCHAR)(io->Offset + i);
            dr->Length = n;
            dr->DataOffset = n ? sizeof(SMBUP_HEADER) + sizeof(SMBUP_DATA_REPLY) : 0;
            total += n;
            break;
        }
        case SmbUpWrite:
        {
            const SMBUP_IO_REQUEST *io = (const void *)(h + 1);
            dr->Length = io->Length;
            break;
        }
        case SmbUpQueryInfo:
        {
            const SMBUP_QUERY_REQUEST *q = (const void *)(h + 1);
            ULONG n = 0;

            switch (q->InformationClass)
            {
                case FileBasicInformation:
                {
                    FILE_BASIC_INFORMATION *b = (void *)data;
                    b->CreationTime.QuadPart = b->LastAccessTime.QuadPart = 132000000000000000LL;
                    b->LastWriteTime.QuadPart = b->ChangeTime.QuadPart = 132000000000000000LL;
                    b->FileAttributes = FILE_ATTRIBUTE_ARCHIVE;
                    n = sizeof(*b);
                    break;
                }
                case FileStandardInformation:
                {
                    FILE_STANDARD_INFORMATION *s = (void *)data;
                    s->AllocationSize.QuadPart = s->EndOfFile.QuadPart = FAKE_EOF;
                    s->NumberOfLinks = 1;
                    n = sizeof(*s);
                    break;
                }
                case FileInternalInformation: ((FILE_INTERNAL_INFORMATION *)data)->IndexNumber.QuadPart = 42; n = 8; break;
                case FileEaInformation: n = sizeof(FILE_EA_INFORMATION); break;
                case FileNetworkOpenInformation:
                {
                    FILE_NETWORK_OPEN_INFORMATION *o = (void *)data;
                    o->AllocationSize.QuadPart = o->EndOfFile.QuadPart = FAKE_EOF;
                    o->FileAttributes = FILE_ATTRIBUTE_ARCHIVE;
                    n = sizeof(*o);
                    break;
                }
                case FileAttributeTagInformation: ((FILE_ATTRIBUTE_TAG_INFORMATION *)data)->FileAttributes = FILE_ATTRIBUTE_ARCHIVE; n = 8; break;
                case FileStreamInformation:
                {
                    FILE_STREAM_INFORMATION *s = (void *)data;
                    s->NextEntryOffset = 0;
                    s->StreamNameLength = 14;
                    s->StreamSize.QuadPart = s->StreamAllocationSize.QuadPart = FAKE_EOF;
                    memcpy(s->StreamName, L"::$DATA", 14);
                    n = FIELD_OFFSET(FILE_STREAM_INFORMATION, StreamName) + 14;
                    break;
                }
                default: r->Status = STATUS_INVALID_INFO_CLASS; break;
            }
            if (n > q->OutputLength)
                n = 0, r->Status = STATUS_BUFFER_TOO_SMALL;
            dr->Length = n;
            dr->DataOffset = n ? sizeof(SMBUP_HEADER) + sizeof(SMBUP_DATA_REPLY) : 0;
            total += n;
            break;
        }
        case SmbUpQueryVolume:
        {
            const SMBUP_QUERY_REQUEST *q = (const void *)(h + 1);
            ULONG n = 0;

            switch (q->InformationClass)
            {
                case FileFsVolumeInformation:
                {
                    FILE_FS_VOLUME_INFORMATION *v = (void *)data;
                    v->VolumeSerialNumber = 0x1234;
                    v->VolumeLabelLength = 8;
                    memcpy(v->VolumeLabel, L"fake", 8);
                    n = FIELD_OFFSET(FILE_FS_VOLUME_INFORMATION, VolumeLabel) + 8;
                    break;
                }
                case FileFsSizeInformation:
                {
                    FILE_FS_SIZE_INFORMATION *s = (void *)data;
                    s->TotalAllocationUnits.QuadPart = 1000000; s->AvailableAllocationUnits.QuadPart = 500000;
                    s->SectorsPerAllocationUnit = 8; s->BytesPerSector = 512;
                    n = sizeof(*s);
                    break;
                }
                case FileFsFullSizeInformation:
                {
                    FILE_FS_FULL_SIZE_INFORMATION *s = (void *)data;
                    s->TotalAllocationUnits.QuadPart = 1000000; s->CallerAvailableAllocationUnits.QuadPart = 500000;
                    s->ActualAvailableAllocationUnits.QuadPart = 500000; s->SectorsPerAllocationUnit = 8; s->BytesPerSector = 512;
                    n = sizeof(*s);
                    break;
                }
                case FileFsAttributeInformation:
                {
                    FILE_FS_ATTRIBUTE_INFORMATION *a = (void *)data;
                    a->FileSystemAttributes = FILE_CASE_PRESERVED_NAMES | FILE_UNICODE_ON_DISK;
                    a->MaximumComponentNameLength = 255;
                    a->FileSystemNameLength = 8;
                    memcpy(a->FileSystemName, L"NTFS", 8);
                    n = FIELD_OFFSET(FILE_FS_ATTRIBUTE_INFORMATION, FileSystemName) + 8;
                    break;
                }
                default: r->Status = STATUS_INVALID_INFO_CLASS; break;
            }
            dr->Length = n;
            dr->DataOffset = n ? sizeof(SMBUP_HEADER) + sizeof(SMBUP_DATA_REPLY) : 0;
            total += n;
            break;
        }
        case SmbUpQueryDirectory:
        {
            const SMBUP_DIRECTORY_REQUEST *q = (const void *)(h + 1);
            ULONG n;

            /* Odd file ids are past the end once listed: restart lists again */
            n = (q->Flags & SMBUP_DIR_RESTART_SCANS) ? fake_directory(q->InformationClass, data, min(q->OutputLength, 8192), 0,
                                                              (q->Flags & SMBUP_DIR_RETURN_SINGLE_ENTRY) ? 1 : 3) : 0;
            if (n == 0)
                r->Status = STATUS_NO_MORE_FILES;
            dr->Length = n;
            dr->DataOffset = n ? sizeof(SMBUP_HEADER) + sizeof(SMBUP_DATA_REPLY) : 0;
            total += n;
            *dirlisting = (n != 0);
            break;
        }
        default:
            /* DISCONNECT, CLOSE, FLUSH, SET_INFO, RENAME: done */
            break;
    }
    r->TotalSize = total;
    return total;
}

/* Hostile: one mutation of a well-formed reply; returns the class, the reply size in *total,
 * and in *send how many times to send it (0: drop, 2: duplicate) */
static int mutate(const SMBUP_HEADER *h, UCHAR *rb, ULONG *total, int *send, BOOL dirlisting, ULONG *s)
{
    SMBUP_HEADER *r = (SMBUP_HEADER *)rb;
    ULONG fixed = SMBUP_REPLY_FIXED_SIZE(h->Opcode);
    SMBUP_DATA_REPLY *dr = (SMBUP_DATA_REPLY *)(r + 1);
    int c = 1 + (int)(rnd(s) % (NCLASS - 1));
    ULONG x = rnd(s);

    *send = 1;
    switch (c)
    {
        case 1: r->Magic ^= 1u << (x % 32); break;
        case 2: r->Version = (USHORT)(SMBUP_VERSION + 1 + x % 5); break;
        case 3: r->HeaderSize = x % 128; if (r->HeaderSize == sizeof(SMBUP_HEADER)) r->HeaderSize++; break;
        case 4: r->TotalSize = (x & 1) ? r->TotalSize + 1 + x % 64 : (x % 2 ? 0 : r->TotalSize - 1); break;
        case 5: r->RequestId += 1 + x % 7; break;
        case 6: r->Opcode = (USHORT)(1 + x % (SmbUpMaximumOpcode + 2)); if (r->Opcode == h->Opcode) r->Opcode++; break;
        case 7:
            r->Status = (x % 4) ? SpecialStatus[x % ARRAYSIZE(SpecialStatus)] : (NTSTATUS)rnd(s);
            break;
        case 8:
            if (fixed == sizeof(SMBUP_DATA_REPLY))
                dr->Length = (x % 3 == 0) ? 0xFFFFFFFFu : (x % 3 == 1) ? dr->Length + 1 + x % 4096 : SMBUP_MAX_IO + 1;
            else
                r->Status = SpecialStatus[x % ARRAYSIZE(SpecialStatus)], c = 7;
            break;
        case 9:
            if (fixed == sizeof(SMBUP_DATA_REPLY))
                dr->DataOffset = (x % 4 == 0) ? 0 : (x % 4 == 1) ? 4 : (x % 4 == 2) ? 0xFFFFFFF0u : *total;
            else
                r->RequestId ^= 0, c = 0;
            break;
        case 10:
            if (fixed)
            {
                ULONG i;
                for (i = 0; i < fixed; i++)
                    rb[sizeof(SMBUP_HEADER) + i] = (UCHAR)rnd(s);
            }
            break;
        case 11:
            if (dirlisting && dr->Length >= 16)
            {
                UCHAR *d = rb + dr->DataOffset;
                ULONG which = x % 6;
                if (which == 0) *(ULONG *)d = rnd(s);
                else if (which == 1) *(ULONG *)d = dr->Length + 8;
                else if (which == 2) *(ULONG *)d = 3;
                else if (which == 3 && h->Opcode == SmbUpQueryDirectory) *(ULONG *)(d + 60) = rnd(s);   /* FileNameLength of most classes */
                else if (which == 4) *(ULONG *)(d + 8) = 0xFFFFFFFFu;
                else { ULONG i; for (i = 0; i < dr->Length; i += 4) *(ULONG *)(d + i) = rnd(s); }
            }
            else if (h->Opcode == SmbUpQueryInfo && dr->Length >= 8)
            {
                /* stream chain / fixed classes: random bytes */
                ULONG i;
                for (i = 0; i + 4 <= dr->Length; i += 4)
                    *(ULONG *)(rb + dr->DataOffset + i) = rnd(s);
            }
            else
                c = 0;
            break;
        case 12:
            if (h->Opcode == SmbUpQueryVolume && dr->Length >= 16)
            {
                UCHAR *d = rb + dr->DataOffset;
                if (x % 2) *(ULONG *)(d + 12) = rnd(s);     /* VolumeLabelLength / FileSystemNameLength */
                else dr->Length = 4;
            }
            else
                c = 0;
            break;
        case 13:
            if (h->Opcode == SmbUpCreate)
            {
                SMBUP_CREATE_REPLY *cr = (SMBUP_CREATE_REPLY *)(r + 1);
                switch (x % 5)
                {
                    case 0: cr->FileId = 0; break;
                    case 1: cr->CreateAction = 6 + x % 100; break;
                    case 2: cr->Attributes.EndOfFile = -1; break;
                    case 3: cr->Attributes.FileAttributes ^= FILE_ATTRIBUTE_DIRECTORY; break;
                    case 4: cr->Attributes.AllocationSize = 0x8000000000000000LL; break;
                }
            }
            else
                c = 0;
            break;
        case 14:
            if (h->Opcode == SmbUpConnect)
            {
                SMBUP_CONNECT_REPLY *cr = (SMBUP_CONNECT_REPLY *)(r + 1);
                switch (x % 4)
                {
                    case 0: cr->ConnectionId = 0; break;
                    case 1: cr->ShareType = x; break;
                    case 2: cr->MaxReadSize = 0; cr->MaxWriteSize = 0xFFFFFFFFu; break;
                    case 3: cr->ConnectionId = 1; break;   /* the same id for everyone */
                }
            }
            else
                c = 0;
            break;
        case 15: *send = 2; break;
        case 16: *send = 0; break;
        case 17: *total = sizeof(SMBUP_HEADER) + (fixed ? x % fixed : 0); r->TotalSize = *total; break;
        case 18:
        {
            ULONG i, n = 1 + x % 8;
            for (i = 0; i < n; i++)
            {
                ULONG pos = rnd(s) % *total;
                if (pos >= 16 && pos < 24) continue;   /* keep the id, so the flip reaches the checks */
                rb[pos] ^= (UCHAR)(1u << (rnd(s) % 8));
            }
            break;
        }
        case 19: r->RequestId = LastId; break;
    }
    if (c != 4 && c != 17)
        r->TotalSize = *total;
    if (c == 4)
        *total = max(sizeof(SMBUP_HEADER), min(r->TotalSize, SMBUP_MAX_MESSAGE));
    return c;
}

static DWORD WINAPI worker(LPVOID param)
{
    UCHAR *req = VirtualAlloc(NULL, SMBUP_MAX_MESSAGE, MEM_COMMIT, PAGE_READWRITE);
    UCHAR *rep = VirtualAlloc(NULL, SMBUP_MAX_MESSAGE + 4096, MEM_COMMIT, PAGE_READWRITE);
    ULONG s = opt.seed * 2654435761u + (ULONG)(ULONG_PTR)param * 40503u + 1;
    DWORD got, ret;

    if (!req || !rep)
        return 1;
    for (;;)
    {
        const SMBUP_HEADER *h = (const SMBUP_HEADER *)req;
        ULONG total;
        int cls = 0, send = 1, i;
        BOOL dirlisting;

        if (!DeviceIoControl(Dev, IOCTL_SMBRDR_ENGINE_GET, NULL, 0, req, SMBUP_MAX_MESSAGE, &got, NULL))
        {
            logmsg("GET failed %lu", GetLastError());
            printf("smbfuzz: GET failed %lu\n", GetLastError());
            ExitProcess(4);
        }
        if (got < sizeof(*h) || h->Magic != SMBUP_MAGIC || h->TotalSize != got || h->Opcode >= SmbUpMaximumOpcode ||
            got < sizeof(*h) + SMBUP_REQUEST_FIXED_SIZE(h->Opcode))
        {
            logmsg("invalid request from the driver (%lu bytes)", got);
            continue;
        }
        InterlockedIncrement(&Served);
        if ((Served % 1000) == 0)
        {
            DWORD hc = 0;
            GetProcessHandleCount(GetCurrentProcess(), &hc);
            logmsg("served %ld replied %ld reply-failed %ld tokens %ld bad-tokens %ld handles %lu", Served, Replied,
                   ReplyFailed, Tokens, TokenBad, hc);
        }
        if (h->Flags & SMBUP_FLAG_NOTIFICATION)
        {
            if (h->Opcode == SmbUpCancel)
                logmsg("CANCEL %I64u", ((const SMBUP_CANCEL_REQUEST *)(h + 1))->RequestId);
            else
                logmsg("LOGOFF %08lx%08lx", h->LogonIdHigh, h->LogonIdLow);
            continue;
        }
        if (opt.mode == MODE_STALL)
            continue;
        if (opt.mode == MODE_SLOW)
            Sleep(opt.delay);

        total = answer(h, rep, &dirlisting);
        if (opt.mode == MODE_HOSTILE && !(opt.keep_ops & (1u << h->Opcode)) && (int)(rnd(&s) % 100) < opt.percent)
            cls = mutate(h, rep, &total, &send, dirlisting, &s);
        if (opt.force_op && h->Opcode == opt.force_op)
        {
            ((SMBUP_HEADER *)rep)->Status = opt.force_status;
            cls = 7;
            logmsg("FORCED op %u req %I64u status %08lx", h->Opcode, h->RequestId, opt.force_status);
        }
        InterlockedIncrement(&Counts[h->Opcode][cls]);
        LastId = h->RequestId;
        for (i = 0; i < send; i++)
        {
            if (DeviceIoControl(Dev, IOCTL_SMBRDR_ENGINE_REPLY, rep, total, NULL, 0, &ret, NULL))
                InterlockedIncrement(&Replied);
            else
                InterlockedIncrement(&ReplyFailed);
        }
    }
}

static void summary(void)
{
    int op, c;
    DWORD hc = 0;

    GetProcessHandleCount(GetCurrentProcess(), &hc);
    logmsg("SUMMARY served %ld replied %ld reply-failed %ld tokens %ld bad-tokens %ld handles %lu", Served, Replied,
           ReplyFailed, Tokens, TokenBad, hc);
    printf("SMBFUZZ served=%ld replied=%ld reply-failed=%ld tokens=%ld bad-tokens=%ld handles=%lu\n", Served, Replied,
           ReplyFailed, Tokens, TokenBad, hc);
    for (op = 1; op < SmbUpMaximumOpcode; op++)
    {
        LONG sum = 0;
        for (c = 0; c < NCLASS; c++)
            sum += Counts[op][c];
        if (!sum)
            continue;
        printf("SMBFUZZ op %d total %ld:", op, sum);
        for (c = 0; c < NCLASS; c++)
            if (Counts[op][c])
                printf(" %s=%ld", ClassName[c], Counts[op][c]);
        printf("\n");
    }
    fflush(stdout);
}

static BOOL WINAPI on_ctrl(DWORD type)
{
    summary();
    return FALSE;
}

static BOOL start_driver(void)
{
    SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT), svc;
    BOOL ok;

    if (!scm)
        return FALSE;
    svc = OpenServiceW(scm, L"mrxsmb", SERVICE_START);
    if (!svc)
    {
        CloseServiceHandle(scm);
        return FALSE;
    }
    ok = StartServiceW(svc, 0, NULL) || GetLastError() == ERROR_SERVICE_ALREADY_RUNNING;
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return ok;
}

int wmain(int argc, WCHAR **argv)
{
    SMBUP_ATTACH attach;
    DWORD ret;
    int i;

    InitializeCriticalSection(&LogLock);
    for (i = 1; i < argc; i++)
    {
        if (!wcscmp(argv[i], L"-m") && i + 1 < argc)
        {
            i++;
            opt.mode = !wcscmp(argv[i], L"hostile") ? MODE_HOSTILE : !wcscmp(argv[i], L"stall") ? MODE_STALL :
                       !wcscmp(argv[i], L"slow") ? MODE_SLOW : MODE_BENIGN;
        }
        else if (!wcscmp(argv[i], L"-s") && i + 1 < argc) opt.seed = (unsigned)_wtoi(argv[++i]);
        else if (!wcscmp(argv[i], L"-p") && i + 1 < argc) opt.percent = _wtoi(argv[++i]);
        else if (!wcscmp(argv[i], L"-d") && i + 1 < argc) opt.delay = _wtoi(argv[++i]);
        else if (!wcscmp(argv[i], L"-j") && i + 1 < argc) opt.threads = max(1, min(32, _wtoi(argv[++i])));
        else if (!wcscmp(argv[i], L"-t") && i + 1 < argc) opt.seconds = _wtoi(argv[++i]);
        else if (!wcscmp(argv[i], L"-o") && i + 1 < argc) opt.log = _wfopen(argv[++i], L"a");
        else if (!wcscmp(argv[i], L"-n") && i + 1 < argc)
        {
            WCHAR *p = argv[++i];
            while (*p)
            {
                ULONG op = wcstoul(p, &p, 0);
                if (op < 32)
                    opt.keep_ops |= 1u << op;
                if (*p == L',')
                    p++;
                else if (*p)
                    break;
            }
        }
        else if (!wcscmp(argv[i], L"-x") && i + 1 < argc)
        {
            WCHAR *colon;
            i++;
            opt.force_op = (int)wcstoul(argv[i], &colon, 0);
            opt.force_status = (*colon == L':') ? (NTSTATUS)wcstoul(colon + 1, NULL, 0) : STATUS_UNSUCCESSFUL;
        }
    }

    start_driver();
    Dev = SmbTestOpenAsSystem(NITRO_SMBRDR_ENGINE_DOS_NAME, GENERIC_READ | GENERIC_WRITE, 0);
    if (Dev == INVALID_HANDLE_VALUE)
    {
        printf("smbfuzz: open engine device failed %lu\n", GetLastError());
        return 2;
    }
    attach.Magic = SMBUP_MAGIC;
    attach.Version = SMBUP_VERSION;
    attach.Reserved = 0;
    attach.MaxMessageSize = SMBUP_MAX_MESSAGE;
    attach.Reserved2 = 0;
    if (!DeviceIoControl(Dev, IOCTL_SMBRDR_ENGINE_ATTACH, &attach, sizeof(attach), NULL, 0, &ret, NULL))
    {
        printf("smbfuzz: attach failed %lu\n", GetLastError());
        return 3;
    }
    printf("smbfuzz: attached pid %lu mode %d seed %u percent %d threads %d\n", GetCurrentProcessId(), opt.mode,
           opt.seed, opt.percent, opt.threads);
    fflush(stdout);
    logmsg("attached pid %lu mode %d seed %u percent %d threads %d", GetCurrentProcessId(), opt.mode, opt.seed,
           opt.percent, opt.threads);
    SetConsoleCtrlHandler(on_ctrl, TRUE);

    for (i = 1; i < opt.threads; i++)
        CloseHandle(CreateThread(NULL, 0, worker, (LPVOID)(ULONG_PTR)i, 0, NULL));
    if (opt.seconds)
    {
        CloseHandle(CreateThread(NULL, 0, worker, (LPVOID)0, 0, NULL));
        Sleep(opt.seconds * 1000);
        summary();
        CloseHandle(Dev);
        return 0;
    }
    worker(NULL);
    return 0;
}
