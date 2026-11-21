/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     NTFS: after FlushFileBuffers the file's MFT record on the disk itself holds its size, data and names
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * A reader that does not replay the file system's journal (a boot loader, another system, an offline tool) sees only
 * what is written in place.  Right after each flush the test reads the file's base MFT record through the open volume
 * (a raw read of the disk) and decodes it with the documented NTFS record layout: the unnamed $DATA attribute (resident
 * value, or allocated, data and initialized sizes and the runs) and the $FILE_NAME attributes.  The record of $MFT
 * itself (number 0, at the MFT start cluster) gives the location of every other record.
 */

#include "precomp.h"
#include <winioctl.h>

#define FH_MAX_RUNS 64

typedef struct _FH_RUN { ULONGLONG Vcn, Lcn, Count; } FH_RUN;

typedef struct _FH_VOL
{
    HANDLE Volume;
    ULONG Cluster, RecordSize, Sector;
    FH_RUN MftRuns[FH_MAX_RUNS];
    ULONG MftRunCount;
} FH_VOL;

typedef struct _FH_DATA
{
    BOOLEAN Found, Resident;
    ULONGLONG Allocated, Size, Initialized;
    ULONG ResidentLength;
    UCHAR ResidentValue[700];
    FH_RUN Runs[FH_MAX_RUNS];
    ULONG RunCount;
    WCHAR Names[4][64];
    ULONG NameCount;
} FH_DATA;

/* A raw read of the volume is made of whole sectors (a disk with 4 KiB sectors refuses a 1 KiB read): read those that hold the range. */
static BOOLEAN FhRead(FH_VOL *V, ULONGLONG Offset, PVOID Buffer, ULONG Length)
{
    LARGE_INTEGER Li;
    DWORD Done;
    ULONG Sector = V->Sector ? V->Sector : 512, Span;
    ULONGLONG Start = Offset - Offset % Sector;
    PUCHAR Tmp;
    BOOLEAN Ok;
    Span = (ULONG)((Offset - Start + Length + Sector - 1) / Sector * Sector);
    Tmp = HeapAlloc(GetProcessHeap(), 0, Span);
    if (!Tmp)
        return FALSE;
    Li.QuadPart = Start;
    Ok = SetFilePointerEx(V->Volume, Li, NULL, FILE_BEGIN) && ReadFile(V->Volume, Tmp, Span, &Done, NULL) && Done == Span;
    if (Ok)
        memcpy(Buffer, Tmp + (Offset - Start), Length);
    HeapFree(GetProcessHeap(), 0, Tmp);
    return Ok;
}

/*
 * Update sequence array: the last two bytes of every 512-byte block of the record hold the sequence number, the real bytes
 * are in the array (the stride is 512 bytes whatever the disk's sector size).
 */
static BOOLEAN FhFixup(PUCHAR Rec, ULONG Size, ULONG Sector)
{
    USHORT UsaOfs = *(PUSHORT)(Rec + 4), UsaCount = *(PUSHORT)(Rec + 6), i;
    PUSHORT Usa;
    Sector = 512;
    if (memcmp(Rec, "FILE", 4) || UsaOfs + UsaCount * 2u > Size || UsaCount == 0 || (UsaCount - 1u) * Sector != Size)
        return FALSE;
    Usa = (PUSHORT)(Rec + UsaOfs);
    for (i = 1; i < UsaCount; i++)
    {
        PUSHORT End = (PUSHORT)(Rec + i * Sector - 2);
        if (*End != Usa[0])
            return FALSE;
        *End = Usa[i];
    }
    return TRUE;
}

/* Mapping pairs of a non-resident attribute into Runs. */
static ULONG FhDecodeRuns(PUCHAR P, PUCHAR End, ULONGLONG StartVcn, FH_RUN *Runs)
{
    ULONGLONG Vcn = StartVcn;
    LONGLONG Lcn = 0;
    ULONG N = 0;
    while (P < End && *P && N < FH_MAX_RUNS)
    {
        UCHAR LenBytes = *P & 0xF, OffBytes = *P >> 4, k;
        ULONGLONG Count = 0;
        LONGLONG Delta = 0;
        P++;
        if (P + LenBytes + OffBytes > End)
            break;
        for (k = 0; k < LenBytes; k++)
            Count |= (ULONGLONG)P[k] << (8 * k);
        P += LenBytes;
        for (k = 0; k < OffBytes; k++)
            Delta |= (LONGLONG)P[k] << (8 * k);
        if (OffBytes && (P[OffBytes - 1] & 0x80))
            Delta -= (LONGLONG)1 << (8 * OffBytes);
        P += OffBytes;
        Lcn += Delta;
        Runs[N].Vcn = Vcn;
        Runs[N].Lcn = OffBytes ? (ULONGLONG)Lcn : (ULONGLONG)-1;
        Runs[N].Count = Count;
        Vcn += Count;
        N++;
    }
    return N;
}

/* The fixed-up base record Number as it is on the disk; FALSE if it cannot be read or is torn. */
static BOOLEAN FhRecord(FH_VOL *V, ULONGLONG Number, PUCHAR Rec)
{
    ULONGLONG Byte = Number * V->RecordSize, Vcn = Byte / V->Cluster;
    ULONG i;
    for (i = 0; i < V->MftRunCount; i++)
    {
        FH_RUN *R = &V->MftRuns[i];
        if (Vcn >= R->Vcn && Vcn < R->Vcn + R->Count && R->Lcn != (ULONGLONG)-1)
        {
            /* A record lies inside one run when it is no larger than a cluster (checked at FhOpen) */
            ULONGLONG Off = (R->Lcn + (Vcn - R->Vcn)) * V->Cluster + Byte % V->Cluster;
            return FhRead(V, Off, Rec, V->RecordSize) && FhFixup(Rec, V->RecordSize, V->Sector);
        }
    }
    return FALSE;
}

static VOID FhParse(PUCHAR Rec, ULONG Size, FH_DATA *D)
{
    ULONG Pos = *(PUSHORT)(Rec + 0x14);
    RtlZeroMemory(D, sizeof(*D));
    while (Pos + 16 <= Size)
    {
        PUCHAR A = Rec + Pos;
        ULONG Type = *(PULONG)A, Len = *(PULONG)(A + 4);
        if (Type == 0xFFFFFFFF || Len < 16 || Pos + Len > Size)
            break;
        if (Type == 0x80 && A[9] == 0 && !D->Found)
        {
            D->Found = TRUE;
            D->Resident = A[8] == 0;
            if (D->Resident)
            {
                ULONG VLen = *(PULONG)(A + 0x10);
                USHORT VOff = *(PUSHORT)(A + 0x14);
                D->ResidentLength = VLen;
                D->Size = D->Initialized = VLen;
                if (VOff + VLen <= Len && VLen <= sizeof(D->ResidentValue))
                    memcpy(D->ResidentValue, A + VOff, VLen);
            }
            else
            {
                D->Allocated = *(PULONGLONG)(A + 0x28);
                D->Size = *(PULONGLONG)(A + 0x30);
                D->Initialized = *(PULONGLONG)(A + 0x38);
                D->RunCount = FhDecodeRuns(A + *(PUSHORT)(A + 0x20), A + Len, *(PULONGLONG)(A + 0x10), D->Runs);
            }
        }
        else if (Type == 0x30 && A[8] == 0 && D->NameCount < RTL_NUMBER_OF(D->Names))
        {
            PUCHAR Value = A + *(PUSHORT)(A + 0x14);
            UCHAR NameLength = Value[0x40], NameSpace = Value[0x41];
            if (NameSpace != 2 && NameLength < RTL_NUMBER_OF(D->Names[0]))   /* not the DOS short name */
            {
                memcpy(D->Names[D->NameCount], Value + 0x42, NameLength * sizeof(WCHAR));
                D->Names[D->NameCount][NameLength] = 0;
                D->NameCount++;
            }
        }
        Pos += Len;
    }
}

static BOOLEAN FhOpen(FH_VOL *V)
{
    WCHAR Path[8];
    NTFS_VOLUME_DATA_BUFFER Data;
    DWORD Done;
    PUCHAR Rec;
    FH_DATA D;
    _snwprintf(Path, RTL_NUMBER_OF(Path), L"\\\\.\\%c:", NtTestDir()[0]);
    V->Volume = CreateFileW(Path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (V->Volume == INVALID_HANDLE_VALUE)
        return FALSE;
    if (!DeviceIoControl(V->Volume, FSCTL_GET_NTFS_VOLUME_DATA, NULL, 0, &Data, sizeof(Data), &Done, NULL))
        return FALSE;
    V->Cluster = Data.BytesPerCluster;
    V->RecordSize = Data.BytesPerFileRecordSegment;
    V->Sector = Data.BytesPerSector;
    if (!V->Cluster || !V->RecordSize || V->RecordSize > V->Cluster || V->Cluster % V->RecordSize || !V->Sector)
        return FALSE;
    Rec = HeapAlloc(GetProcessHeap(), 0, V->RecordSize);
    if (!Rec)
        return FALSE;
    /* Record 0 ($MFT) is the first record at the MFT start cluster; its $DATA runs place every other record. */
    if (!FhRead(V, Data.MftStartLcn.QuadPart * V->Cluster, Rec, V->RecordSize) || !FhFixup(Rec, V->RecordSize, V->Sector))
    {
        HeapFree(GetProcessHeap(), 0, Rec);
        return FALSE;
    }
    FhParse(Rec, V->RecordSize, &D);
    HeapFree(GetProcessHeap(), 0, Rec);
    if (!D.Found || D.Resident || !D.RunCount)
        return FALSE;
    memcpy(V->MftRuns, D.Runs, sizeof(D.Runs));
    V->MftRunCount = D.RunCount;
    return TRUE;
}

static ULONGLONG FhNumber(HANDLE File)
{
    BY_HANDLE_FILE_INFORMATION Info;
    if (!GetFileInformationByHandle(File, &Info))
        return 0;
    return ((ULONGLONG)Info.nFileIndexHigh << 32 | Info.nFileIndexLow) & 0xFFFFFFFFFFFFull;
}

/* The disk's record of File, decoded; FALSE (and a failure) if it cannot be read. */
static BOOLEAN FhDisk(FH_VOL *V, HANDLE File, FH_DATA *D, PCSTR What)
{
    UCHAR Rec[4096];
    ULONGLONG Number = FhNumber(File);
    BOOLEAN Ok = Number && V->RecordSize <= sizeof(Rec) && FhRecord(V, Number, Rec);
    ok(Ok, "%s: the record %I64u could not be read from the disk\n", What, Number);
    if (Ok)
        FhParse(Rec, V->RecordSize, D);
    return Ok && D->Found;
}

/* The bytes [Offset, Offset + Length) of a non-resident file read from the disk through the runs of its record. */
static BOOLEAN FhDiskBytes(FH_VOL *V, FH_DATA *D, ULONGLONG Offset, PUCHAR Out, ULONG Length)
{
    PUCHAR Buf = HeapAlloc(GetProcessHeap(), 0, V->Cluster);
    BOOLEAN Ok = Buf != NULL;
    while (Ok && Length)
    {
        ULONGLONG Vcn = Offset / V->Cluster;
        ULONG In = (ULONG)(Offset % V->Cluster), Take = min(Length, V->Cluster - In), i;
        Ok = FALSE;
        for (i = 0; i < D->RunCount; i++)
        {
            if (Vcn >= D->Runs[i].Vcn && Vcn < D->Runs[i].Vcn + D->Runs[i].Count && D->Runs[i].Lcn != (ULONGLONG)-1)
            {
                Ok = FhRead(V, (D->Runs[i].Lcn + Vcn - D->Runs[i].Vcn) * V->Cluster, Buf, V->Cluster);
                break;
            }
        }
        if (Ok)
            memcpy(Out, Buf + In, Take);
        Out += Take;
        Offset += Take;
        Length -= Take;
    }
    if (Buf)
        HeapFree(GetProcessHeap(), 0, Buf);
    return Ok;
}

static VOID FhFill(PUCHAR P, ULONG Length, ULONG Seed)
{
    ULONG i;
    for (i = 0; i < Length; i++)
        P[i] = (UCHAR)(Seed * 29 + i * 13 + (i >> 9));
}

static BOOLEAN FhHasName(FH_DATA *D, PCWSTR Name)
{
    ULONG i;
    for (i = 0; i < D->NameCount; i++)
        if (!_wcsicmp(D->Names[i], Name))
            return TRUE;
    return FALSE;
}

START_TEST(NtfsFlushHome)
{
    FH_VOL V;
    FH_DATA D;
    WCHAR Path[MAX_PATH], Path2[MAX_PATH], Link[MAX_PATH];
    PUCHAR Buf, Disk;
    HANDLE File;
    DWORD Done;
    LARGE_INTEGER Li;
    ULONG Round;

    if (!NtInit("NtfsFlushHome"))
        return;
    RtlZeroMemory(&V, sizeof(V));
    if (!FhOpen(&V))
    {
        skip("The volume of %ls cannot be read raw as NTFS (error %lu)\n", NtTestDir(), GetLastError());
        if (V.Volume && V.Volume != INVALID_HANDLE_VALUE)
            CloseHandle(V.Volume);
        NtCleanup();
        return;
    }
    Buf = HeapAlloc(GetProcessHeap(), 0, 300000);
    Disk = HeapAlloc(GetProcessHeap(), 0, 4096);
    NtPath(Path, L"grow.bin");
    File = CreateFileW(Path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, 0, NULL);
    ok(File != INVALID_HANDLE_VALUE, "Creating %ls: %lu\n", Path, GetLastError());
    if (File == INVALID_HANDLE_VALUE || !Buf || !Disk)
        goto out;

    /* Appends: the size on the disk follows every flush, at once */
    for (Round = 1; Round <= 4; Round++)
    {
        FhFill(Buf, 70000, Round);
        ok(WriteFile(File, Buf, 70000, &Done, NULL) && Done == 70000, "append %lu: %lu\n", Round, GetLastError());
        ok(FlushFileBuffers(File), "flush %lu: %lu\n", Round, GetLastError());
        if (FhDisk(&V, File, &D, "append"))
        {
            ok(!D.Resident, "append %lu: resident on the disk\n", Round);
            ok(D.Size == 70000ull * Round, "append %lu: size on the disk %I64u, expected %lu\n", Round, D.Size, 70000 * Round);
            ok(D.Initialized == 70000ull * Round, "append %lu: initialized size on the disk %I64u\n", Round, D.Initialized);
            ok(D.Allocated >= D.Size, "append %lu: allocated %I64u below the size\n", Round, D.Allocated);
            /* the last appended bytes are reachable through the runs the disk's record holds */
            if (D.Size == 70000ull * Round)
            {
                ok(FhDiskBytes(&V, &D, D.Size - 4096, Disk, 4096), "append %lu: the tail is not mapped on the disk\n", Round);
                ok(!memcmp(Disk, Buf + 70000 - 4096, 4096), "append %lu: the tail on the disk differs\n", Round);
            }
        }
    }

    /* An overwrite inside the file: data reachable, sizes as they were */
    FhFill(Buf, 3000, 9);
    Li.QuadPart = 100000;
    ok(SetFilePointerEx(File, Li, NULL, FILE_BEGIN) && WriteFile(File, Buf, 3000, &Done, NULL), "overwrite: %lu\n", GetLastError());
    ok(FlushFileBuffers(File), "flush overwrite: %lu\n", GetLastError());
    if (FhDisk(&V, File, &D, "overwrite"))
    {
        ok(D.Size == 280000, "overwrite: size on the disk %I64u\n", D.Size);
        ok(FhDiskBytes(&V, &D, 100000, Disk, 3000) && !memcmp(Disk, Buf, 3000), "overwrite: the bytes on the disk differ\n");
    }

    /* Truncation */
    Li.QuadPart = 5000;
    ok(SetFilePointerEx(File, Li, NULL, FILE_BEGIN) && SetEndOfFile(File), "truncate: %lu\n", GetLastError());
    ok(FlushFileBuffers(File), "flush truncate: %lu\n", GetLastError());
    if (FhDisk(&V, File, &D, "truncate"))
        ok(D.Size == 5000 && D.Initialized <= 5000, "truncate: size on the disk %I64u, initialized %I64u\n", D.Size, D.Initialized);

    /* Extension by SetEndOfFile */
    Li.QuadPart = 200000;
    ok(SetFilePointerEx(File, Li, NULL, FILE_BEGIN) && SetEndOfFile(File), "extend: %lu\n", GetLastError());
    ok(FlushFileBuffers(File), "flush extend: %lu\n", GetLastError());
    if (FhDisk(&V, File, &D, "extend"))
        ok(D.Size == 200000 && D.Allocated >= 200000, "extend: size on the disk %I64u, allocated %I64u\n", D.Size, D.Allocated);
    CloseHandle(File);

    /* A rename, then a flush of the renamed file: the disk's record carries the new name */
    NtPath(Path2, L"renamed.bin");
    ok(MoveFileExW(Path, Path2, MOVEFILE_REPLACE_EXISTING), "rename: %lu\n", GetLastError());
    File = CreateFileW(Path2, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    ok(File != INVALID_HANDLE_VALUE, "reopen: %lu\n", GetLastError());
    if (File != INVALID_HANDLE_VALUE)
    {
        ok(FlushFileBuffers(File), "flush after the rename: %lu\n", GetLastError());
        if (FhDisk(&V, File, &D, "rename"))
            ok(FhHasName(&D, L"renamed.bin") && !FhHasName(&D, L"grow.bin"), "rename: %lu names on the disk, first '%ls'\n",
               D.NameCount, D.NameCount ? D.Names[0] : L"");
        /* a second name (hard link) */
        NtPath(Link, L"link.bin");
        ok(CreateHardLinkW(Link, Path2, NULL), "hard link: %lu\n", GetLastError());
        ok(FlushFileBuffers(File), "flush after the link: %lu\n", GetLastError());
        if (FhDisk(&V, File, &D, "link"))
            ok(FhHasName(&D, L"renamed.bin") && FhHasName(&D, L"link.bin"), "link: %lu names on the disk\n", D.NameCount);
        CloseHandle(File);
    }

    /* A small new file: its data lives in the record */
    NtPath(Path, L"small.bin");
    File = CreateFileW(Path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, 0, NULL);
    ok(File != INVALID_HANDLE_VALUE, "Creating %ls: %lu\n", Path, GetLastError());
    if (File != INVALID_HANDLE_VALUE)
    {
        FhFill(Buf, 200, 5);
        ok(WriteFile(File, Buf, 200, &Done, NULL) && Done == 200, "small write: %lu\n", GetLastError());
        ok(FlushFileBuffers(File), "small flush: %lu\n", GetLastError());
        if (FhDisk(&V, File, &D, "small"))
        {
            if (D.Resident)
                ok(D.ResidentLength == 200 && !memcmp(D.ResidentValue, Buf, 200), "small: %lu bytes on the disk\n", D.ResidentLength);
            else
                ok(D.Size == 200 && FhDiskBytes(&V, &D, 0, Disk, 200) && !memcmp(Disk, Buf, 200), "small: size on the disk %I64u\n", D.Size);
            ok(FhHasName(&D, L"small.bin"), "small: name not on the disk\n");
        }
        CloseHandle(File);
    }

out:
    if (Buf)
        HeapFree(GetProcessHeap(), 0, Buf);
    if (Disk)
        HeapFree(GetProcessHeap(), 0, Disk);
    CloseHandle(V.Volume);
    NtCleanup();
}

/* Appends to Other and flushes it: everything committed so far, the test file's changes included, is written in place. */
static VOID FhOtherFlush(HANDLE Other, PUCHAR Buf, PCSTR What)
{
    DWORD Done;
    FhFill(Buf, 20000, 77);
    ok(WriteFile(Other, Buf, 20000, &Done, NULL) && Done == 20000, "%s: append to the other file: %lu\n", What, GetLastError());
    ok(FlushFileBuffers(Other), "%s: flush of the other file: %lu\n", What, GetLastError());
}

static VOID FhSetSize(HANDLE File, LONGLONG Size, PCSTR What)
{
    LARGE_INTEGER Li;
    Li.QuadPart = Size;
    ok(SetFilePointerEx(File, Li, NULL, FILE_BEGIN) && SetEndOfFile(File), "%s: size %I64d: %lu\n", What, Size, GetLastError());
}

static VOID FhExpectSize(FH_VOL *V, HANDLE File, ULONGLONG Size, PCSTR What)
{
    FH_DATA D;
    if (FhDisk(V, File, &D, What))
        ok(D.Size == Size, "%s: size on the disk %I64u, expected %I64u\n", What, D.Size, Size);
}

/*
 * The flush may know, without reading the disk, that the file's record there already is the current one (it saw or put it
 * there itself, and nothing has written its place since).  Every change that puts the record back to a state the flush saw
 * before, after another file's flush wrote an intermediate state in place, must still reach the disk; so must changes made
 * through a second handle, and the state after the file was closed and opened again.
 */
START_TEST(NtfsFlushHomeKnown)
{
    FH_VOL V;
    FH_DATA D;
    WCHAR Path[MAX_PATH], Path2[MAX_PATH], Link[MAX_PATH], OtherPath[MAX_PATH];
    PUCHAR Buf = NULL, Disk = NULL;
    HANDLE File = INVALID_HANDLE_VALUE, File2 = INVALID_HANDLE_VALUE, Other = INVALID_HANDLE_VALUE;
    const DWORD Share = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
    DWORD Done;
    LARGE_INTEGER Li;
    ULONG Round;

    if (!NtInit("NtfsFlushHomeKnown"))
        return;
    RtlZeroMemory(&V, sizeof(V));
    if (!FhOpen(&V))
    {
        skip("The volume of %ls cannot be read raw as NTFS (error %lu)\n", NtTestDir(), GetLastError());
        if (V.Volume && V.Volume != INVALID_HANDLE_VALUE)
            CloseHandle(V.Volume);
        NtCleanup();
        return;
    }
    Buf = HeapAlloc(GetProcessHeap(), 0, 100000);
    Disk = HeapAlloc(GetProcessHeap(), 0, 8192);
    NtPath(Path, L"known.bin");
    NtPath(Path2, L"known2.bin");
    NtPath(Link, L"knownlink.bin");
    NtPath(OtherPath, L"other.bin");
    File = CreateFileW(Path, GENERIC_READ | GENERIC_WRITE, Share, NULL, CREATE_ALWAYS, 0, NULL);
    Other = CreateFileW(OtherPath, GENERIC_READ | GENERIC_WRITE, Share, NULL, CREATE_ALWAYS, 0, NULL);
    ok(File != INVALID_HANDLE_VALUE && Other != INVALID_HANDLE_VALUE, "Creating the files: %lu\n", GetLastError());
    if (File == INVALID_HANDLE_VALUE || Other == INVALID_HANDLE_VALUE || !Buf || !Disk)
        goto out;

    /* The record is put in place by the first flush; overwrites inside the file leave it as it is */
    FhFill(Buf, 70000, 1);
    ok(WriteFile(File, Buf, 70000, &Done, NULL) && Done == 70000, "write: %lu\n", GetLastError());
    ok(FlushFileBuffers(File), "flush: %lu\n", GetLastError());
    FhExpectSize(&V, File, 70000, "first flush");
    for (Round = 0; Round < 3; Round++)
    {
        FhFill(Buf, 5000, 10 + Round);
        Li.QuadPart = 8192 * Round + 100;
        ok(SetFilePointerEx(File, Li, NULL, FILE_BEGIN) && WriteFile(File, Buf, 5000, &Done, NULL), "overwrite %lu: %lu\n", Round, GetLastError());
        ok(FlushFileBuffers(File), "flush overwrite %lu: %lu\n", Round, GetLastError());
        if (FhDisk(&V, File, &D, "overwrite"))
        {
            ok(D.Size == 70000, "overwrite %lu: size on the disk %I64u\n", Round, D.Size);
            ok(FhDiskBytes(&V, &D, Li.QuadPart, Disk, 5000) && !memcmp(Disk, Buf, 5000), "overwrite %lu: the bytes on the disk differ\n", Round);
        }
    }

    /* Size: 70000 flushed; 140000 written in place by the other file's flush; back to 70000 and flushed: 70000 on the disk */
    FhSetSize(File, 140000, "extend");
    FhOtherFlush(Other, Buf, "extend");
    if (FhDisk(&V, File, &D, "extend") && D.Size != 140000)
        trace("extend: the other file's flush left size %I64u on the disk (not the intermediate state)\n", D.Size);
    FhSetSize(File, 70000, "truncate back");
    ok(FlushFileBuffers(File), "flush after the truncation: %lu\n", GetLastError());
    FhExpectSize(&V, File, 70000, "truncated back");

    /* Name: known2 flushed; known in place through the other file's flush; known2 again and flushed: known2 on the disk */
    ok(MoveFileExW(Path, Path2, 0), "rename: %lu\n", GetLastError());
    ok(FlushFileBuffers(File), "flush after the rename: %lu\n", GetLastError());
    ok(MoveFileExW(Path2, Path, 0), "rename back: %lu\n", GetLastError());
    FhOtherFlush(Other, Buf, "rename back");
    ok(MoveFileExW(Path, Path2, 0), "rename again: %lu\n", GetLastError());
    ok(FlushFileBuffers(File), "flush after the second rename: %lu\n", GetLastError());
    if (FhDisk(&V, File, &D, "renamed again"))
        ok(FhHasName(&D, L"known2.bin") && !FhHasName(&D, L"known.bin"), "renamed again: %lu names on the disk, first '%ls'\n",
           D.NameCount, D.NameCount ? D.Names[0] : L"");

    /* Links: two names flushed; one in place through the other file's flush; two again and flushed: two on the disk */
    ok(CreateHardLinkW(Link, Path2, NULL), "hard link: %lu\n", GetLastError());
    ok(FlushFileBuffers(File), "flush after the link: %lu\n", GetLastError());
    ok(DeleteFileW(Link), "delete the link: %lu\n", GetLastError());
    FhOtherFlush(Other, Buf, "unlink");
    ok(CreateHardLinkW(Link, Path2, NULL), "hard link again: %lu\n", GetLastError());
    ok(FlushFileBuffers(File), "flush after the second link: %lu\n", GetLastError());
    if (FhDisk(&V, File, &D, "linked again"))
        ok(FhHasName(&D, L"known2.bin") && FhHasName(&D, L"knownlink.bin"), "linked again: %lu names on the disk\n", D.NameCount);
    ok(DeleteFileW(Link), "delete the link: %lu\n", GetLastError());
    ok(FlushFileBuffers(File), "flush after the unlink: %lu\n", GetLastError());
    if (FhDisk(&V, File, &D, "unlinked"))
        ok(FhHasName(&D, L"known2.bin") && !FhHasName(&D, L"knownlink.bin"), "unlinked: %lu names on the disk\n", D.NameCount);

    /* A second handle changes the size; the first one flushes */
    File2 = CreateFileW(Path2, GENERIC_READ | GENERIC_WRITE, Share, NULL, OPEN_EXISTING, 0, NULL);
    ok(File2 != INVALID_HANDLE_VALUE, "second handle: %lu\n", GetLastError());
    if (File2 != INVALID_HANDLE_VALUE)
    {
        FhSetSize(File2, 90000, "second handle");
        ok(FlushFileBuffers(File), "flush through the first handle: %lu\n", GetLastError());
        FhExpectSize(&V, File, 90000, "second handle");
        CloseHandle(File2);
    }

    /* Closed and opened again: an overwrite and a flush keep size and data right on the disk */
    CloseHandle(File);
    File = CreateFileW(Path2, GENERIC_READ | GENERIC_WRITE, Share, NULL, OPEN_EXISTING, 0, NULL);
    ok(File != INVALID_HANDLE_VALUE, "reopen: %lu\n", GetLastError());
    if (File != INVALID_HANDLE_VALUE)
    {
        FhFill(Buf, 3000, 55);
        Li.QuadPart = 40000;
        ok(SetFilePointerEx(File, Li, NULL, FILE_BEGIN) && WriteFile(File, Buf, 3000, &Done, NULL), "overwrite after reopen: %lu\n", GetLastError());
        ok(FlushFileBuffers(File), "flush after reopen: %lu\n", GetLastError());
        if (FhDisk(&V, File, &D, "reopened"))
        {
            ok(D.Size == 90000, "reopened: size on the disk %I64u\n", D.Size);
            ok(FhDiskBytes(&V, &D, 40000, Disk, 3000) && !memcmp(Disk, Buf, 3000), "reopened: the bytes on the disk differ\n");
        }
    }

out:
    if (File != INVALID_HANDLE_VALUE)
        CloseHandle(File);
    if (Other != INVALID_HANDLE_VALUE)
        CloseHandle(Other);
    DeleteFileW(Path);
    DeleteFileW(Path2);
    DeleteFileW(Link);
    DeleteFileW(OtherPath);
    if (Buf)
        HeapFree(GetProcessHeap(), 0, Buf);
    if (Disk)
        HeapFree(GetProcessHeap(), 0, Disk);
    CloseHandle(V.Volume);
    NtCleanup();
}
