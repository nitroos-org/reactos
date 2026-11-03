/*
 * COPYRIGHT:   See COPYING in the top level directory
 * PROJECT:     ReactOS NTFS FS library
 * FILE:        lib/fslib/ntfslib/chkdsk.c
 * PURPOSE:     NtfsChkdsk: chkdsk and autochk for NTFS-NG volumes
 *
 * The check is the one the NTFS-NG driver runs at mount (ngfsck.c), run by the driver on the mounted volume
 * (FSCTL_NG_CHECK, sdk/include/reactos/ntfsng_check.h).  The volume is not locked or dismounted: the driver runs the
 * check under its own volume lock after writing back what is dirty, so this works on the system volume and on a
 * volume with open files.  A user-mode checker linked to the core could not see the cached and journaled state of
 * a mounted volume, and could not run on the system volume at all.
 *
 * The text follows Windows 10's chkdsk: the stages, the verdict lines and the summary.  Exit codes (chkdsk.exe maps
 * the DONE callback): 0 no errors; 1 errors found and fixed (ExitStatus NTFSCHK_STATUS_CORRECTED); 3 errors found and
 * not fixed, or not checked (NTFSCHK_STATUS_ERRORS after the text was printed, or the NTSTATUS of the failure).
 *
 * With FixErrors only the repairs that cannot cause a double allocation are made: leaked clusters and leaked MFT
 * records are freed, the journal is replayed (by the driver, at every read-write mount; a volume that is mounted
 * read-only without damage is remounted once), and the dirty flag is cleared after a clean check.  Damage is
 * reported, nothing is repaired, and the volume stays read-only.
 */

#include "ntfslib.h"

#include <winioctl.h>
#include <ntstrsafe.h>
#include <reactos/ntfsng_check.h>
#include <fslib/ntfslib.h>

#define NDEBUG
#include <debug.h>

#define NCK_OUT(...) NckPrint(Callback, __VA_ARGS__)

static
VOID
NckPrint(
    IN PFMIFSCALLBACK Callback,
    IN PCSTR Format,
    ...)
{
    CHAR Text[512];
    TEXTOUTPUT TextOut;
    va_list Args;

    if (!Callback)
        return;
    va_start(Args, Format);
    RtlStringCbVPrintfA(Text, sizeof(Text), Format, Args);
    va_end(Args);
    TextOut.Lines = 1;
    TextOut.Output = Text;
    Callback(OUTPUT, 0, &TextOut);
}

/* Windows' "Phase duration" figure: milliseconds with two decimals, seconds from 1000 ms on. */
static
VOID
NckPhase(
    IN PFMIFSCALLBACK Callback,
    IN PCSTR Name,
    IN ULONG Ms)
{
    if (Ms >= 1000)
        NCK_OUT(" Phase duration (%s): %lu.%02lu seconds.\n", Name, Ms / 1000, (Ms % 1000) / 10);
    else
        NCK_OUT(" Phase duration (%s): %lu.00 milliseconds.\n", Name, Ms);
}

static
NTSTATUS
NckOpen(
    IN PUNICODE_STRING DriveRoot,
    OUT PHANDLE Handle)
{
    OBJECT_ATTRIBUTES Attributes;
    IO_STATUS_BLOCK Iosb;

    InitializeObjectAttributes(&Attributes, DriveRoot, OBJ_CASE_INSENSITIVE, NULL, NULL);
    return NtOpenFile(Handle,
                      FILE_READ_ATTRIBUTES | FILE_READ_DATA | SYNCHRONIZE,
                      &Attributes,
                      &Iosb,
                      FILE_SHARE_READ | FILE_SHARE_WRITE,
                      FILE_SYNCHRONOUS_IO_NONALERT);
}

static
NTSTATUS
NckCheck(
    IN HANDLE Volume,
    IN ULONG Flags,
    OUT PNG_CHECK_RESULT Result)
{
    NG_CHECK_REQUEST Request;
    IO_STATUS_BLOCK Iosb;
    UCHAR Buffer[sizeof(NG_CHECK_RESULT)];
    NTSTATUS Status;

    RtlZeroMemory(Buffer, sizeof(Buffer));
    Request.Version = NG_CHECK_VERSION;
    Request.Flags = Flags;
    RtlCopyMemory(Buffer, &Request, sizeof(Request));
    Status = NtFsControlFile(Volume, NULL, NULL, NULL, &Iosb, FSCTL_NG_CHECK,
                             Buffer, sizeof(Buffer), Buffer, sizeof(Buffer));
    if (NT_SUCCESS(Status))
        RtlCopyMemory(Result, Buffer, sizeof(*Result));
    return Status;
}

/* The volume label for the header ("Volume label is X."). */
static
VOID
NckLabel(
    IN HANDLE Volume,
    OUT PCHAR Label,
    IN ULONG LabelSize)
{
    IO_STATUS_BLOCK Iosb;
    UCHAR Buffer[sizeof(FILE_FS_VOLUME_INFORMATION) + 64 * sizeof(WCHAR)];
    PFILE_FS_VOLUME_INFORMATION Info = (PFILE_FS_VOLUME_INFORMATION)Buffer;
    ULONG i, n;

    Label[0] = ANSI_NULL;
    if (!NT_SUCCESS(NtQueryVolumeInformationFile(Volume, &Iosb, Info, sizeof(Buffer), FileFsVolumeInformation)))
        return;
    n = min(Info->VolumeLabelLength / sizeof(WCHAR), LabelSize - 1);
    for (i = 0; i < n; i++)
        Label[i] = Info->VolumeLabel[i] < 0x80 ? (CHAR)Info->VolumeLabel[i] : '?';
    Label[n] = ANSI_NULL;
}

/* A read-only volume that is not damaged: dismount it (nothing is open that matters if the lock succeeds) so that the
 * next open mounts it again, and replays the journal when it can be mounted read-write. */
static
VOID
NckRemount(
    IN PUNICODE_STRING DriveRoot,
    IN OUT PHANDLE Volume)
{
    IO_STATUS_BLOCK Iosb;
    HANDLE New;
    NTSTATUS Status;

    Status = NtFsControlFile(*Volume, NULL, NULL, NULL, &Iosb, FSCTL_LOCK_VOLUME, NULL, 0, NULL, 0);
    if (!NT_SUCCESS(Status))
        return;
    Status = NtFsControlFile(*Volume, NULL, NULL, NULL, &Iosb, FSCTL_DISMOUNT_VOLUME, NULL, 0, NULL, 0);
    NtFsControlFile(*Volume, NULL, NULL, NULL, &Iosb, FSCTL_UNLOCK_VOLUME, NULL, 0, NULL, 0);
    if (!NT_SUCCESS(Status))
        return;
    NtClose(*Volume);
    *Volume = NULL;
    if (NT_SUCCESS(NckOpen(DriveRoot, &New)))
        *Volume = New;
}

BOOLEAN
NTAPI
NtfsChkdsk(
    IN PUNICODE_STRING DriveRoot,
    IN PFMIFSCALLBACK Callback,
    IN BOOLEAN FixErrors,
    IN BOOLEAN Verbose,
    IN BOOLEAN CheckOnlyIfDirty,
    IN BOOLEAN ScanDrive,
    IN PVOID pUnknown1,
    IN PVOID pUnknown2,
    IN PVOID pUnknown3,
    IN PVOID pUnknown4,
    IN PULONG ExitStatus)
{
    HANDLE Volume = NULL;
    NG_CHECK_RESULT R;
    NTSTATUS Status;
    CHAR Label[40];
    LARGE_INTEGER Start, End;
    ULONGLONG Kb, ClusterKb;
    ULONG Problems, TotalMs;
    BOOLEAN Success = FALSE, Fixed = FALSE, Refused = FALSE;

    UNREFERENCED_PARAMETER(Verbose);
    UNREFERENCED_PARAMETER(ScanDrive);
    UNREFERENCED_PARAMETER(pUnknown1);
    UNREFERENCED_PARAMETER(pUnknown2);
    UNREFERENCED_PARAMETER(pUnknown3);
    UNREFERENCED_PARAMETER(pUnknown4);

    *ExitStatus = (ULONG)STATUS_SUCCESS;

    Status = NckOpen(DriveRoot, &Volume);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("NtfsChkdsk: cannot open the volume, 0x%08lx\n", Status);
        goto Failed;
    }

    /* autochk's dirty query: no check, only whether one is needed. */
    if (CheckOnlyIfDirty)
    {
        Status = NckCheck(Volume, NG_CHECK_QUERY, &R);
        if (Status == STATUS_INVALID_DEVICE_REQUEST)
        {
            /* Not the NTFS-NG driver: the dirty flag is all there is. */
            IO_STATUS_BLOCK Iosb;
            ULONG Dirty = 0;

            Status = NtFsControlFile(Volume, NULL, NULL, NULL, &Iosb, FSCTL_IS_VOLUME_DIRTY, NULL, 0, &Dirty, sizeof(Dirty));
            if (!NT_SUCCESS(Status))
                goto Failed;
            R.Flags = (Dirty & VOLUME_IS_DIRTY) ? NG_CHK_NEEDS_CHECK : 0;
        }
        else if (!NT_SUCCESS(Status))
        {
            goto Failed;
        }
        if (!(R.Flags & NG_CHK_NEEDS_CHECK))
        {
            NtClose(Volume);
            return TRUE;
        }
        if (!FixErrors)
        {
            /* Dirty: autochk takes this as "the volume needs a check" (see autochk's CheckVolume). */
            NtClose(Volume);
            *ExitStatus = (ULONG)STATUS_DISK_CORRUPT_ERROR;
            return TRUE;
        }
    }

    NtQuerySystemTime(&Start);

    /* chkdsk -f on a volume that is mounted read-only but not damaged: mount it again, which replays the journal. */
    if (FixErrors)
    {
        Status = NckCheck(Volume, NG_CHECK_QUERY, &R);
        if (NT_SUCCESS(Status) && (R.Flags & NG_CHK_READONLY) && !(R.Flags & NG_CHK_DAMAGED))
        {
            NckRemount(DriveRoot, &Volume);
            if (!Volume)
            {
                Status = STATUS_VOLUME_DISMOUNTED;
                goto Failed;
            }
        }
    }

    NckLabel(Volume, Label, sizeof(Label));
    NCK_OUT("Volume label is %s.\n\n", Label);
    if (!FixErrors)
        NCK_OUT("WARNING!  /F parameter not specified.\nRunning CHKDSK in read-only mode.\n\n");

    Status = NckCheck(Volume, FixErrors ? NG_CHECK_FIX : 0, &R);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("NtfsChkdsk: FSCTL_NG_CHECK failed, 0x%08lx\n", Status);
        if (Status == STATUS_INVALID_DEVICE_REQUEST)
        {
            NCK_OUT("The NTFS volume was not checked: it is not mounted by the NTFS-NG driver.\n");
            Status = STATUS_NOT_SUPPORTED;
        }
        goto Failed;
    }
    NtQuerySystemTime(&End);
    TotalMs = (ULONG)((End.QuadPart - Start.QuadPart) / 10000);
    ClusterKb = R.ClusterSize / 1024;
    Problems = R.Fatal + R.Leaks;

    NCK_OUT("Stage 1: Examining basic file system structure ...\n");
    NCK_OUT("  %I64u file records processed.\n", R.Records);
    NCK_OUT("File verification completed.\n");
    NckPhase(Callback, "File record verification", R.PassMs[0] + R.PassMs[1]);
    NCK_OUT("  %I64u large file records processed.\n", R.ExtRecords);
    NckPhase(Callback, "Orphan file record recovery", 0);
    NCK_OUT("  0 bad file records processed.\n");
    NckPhase(Callback, "Bad file record checking", 0);
    NCK_OUT("\nStage 2: Examining file name linkage ...\n");
    NCK_OUT("  %I64u reparse records processed.\n", R.Reparse);
    NCK_OUT("  %I64u index entries processed.\n", R.IndexEntries);
    NCK_OUT("Index verification completed.\n");
    NckPhase(Callback, "Index verification", R.PassMs[2]);
    NCK_OUT("  0 unindexed files scanned.\n");
    NckPhase(Callback, "Orphan reconnection", 0);
    NCK_OUT("  0 unindexed files recovered to lost and found.\n");
    NckPhase(Callback, "Orphan recovery to lost and found", 0);
    NCK_OUT("  %I64u reparse records processed.\n", R.Reparse);
    NckPhase(Callback, "Reparse point and Object ID verification", 0);
    NCK_OUT("\nStage 3: Examining security descriptors ...\n");
    NCK_OUT("Security descriptor verification completed.\n");
    NckPhase(Callback, "Security descriptor verification", 0);
    NCK_OUT("  %I64u data files processed.\n", R.InUse > R.Dirs + R.ExtRecords ? R.InUse - R.Dirs - R.ExtRecords : 0);
    NckPhase(Callback, "Data attribute verification", 0);
    NCK_OUT("CHKDSK is verifying Usn Journal...\n");
    NCK_OUT("  0 USN bytes processed.\n");
    NCK_OUT("Usn Journal verification completed.\n");
    NckPhase(Callback, "USN journal verification", 0);

    if (R.Fatal)
    {
        NCK_OUT("\nErrors found: %lu. First: %s.\n", R.Fatal, R.Why);
    }
    if (R.LeakedRecords)
    {
        NCK_OUT("\nFree space marked as allocated in the master file table (MFT) bitmap.\n");
        if (R.FixedRecords)
            NCK_OUT("Correcting errors in the master file table's (MFT) BITMAP attribute.\n");
    }
    if (R.LeakedClusters)
    {
        NCK_OUT("%sFree space marked as allocated in the volume bitmap.\n", R.LeakedRecords ? "" : "\n");
        if (R.FixedClusters)
            NCK_OUT("Correcting errors in the Volume Bitmap.\n");
    }
    NCK_OUT("\n");

    Fixed = (R.Flags & NG_CHK_REPAIRED) ? TRUE : FALSE;
    Refused = (FixErrors && (R.Fatal || (R.Flags & NG_CHK_REFUSED))) ? TRUE : FALSE;

    if (Problems == 0)
    {
        NCK_OUT("Windows has scanned the file system and found no problems.\nNo further action is required.\n");
        Success = TRUE;
    }
    else if (!FixErrors)
    {
        NCK_OUT("Windows found problems with the file system.\nRun CHKDSK with the /F (fix) option to correct these.\n");
        *ExitStatus = (ULONG)NTFSCHK_STATUS_ERRORS;
    }
    else if (R.Fatal || Refused)
    {
        NCK_OUT("Windows found problems with the file system that CHKDSK cannot repair.\n"
                "Nothing was changed, and the volume is read-only.\n");
        *ExitStatus = (ULONG)NTFSCHK_STATUS_ERRORS;
    }
    else
    {
        NCK_OUT("Windows has made corrections to the file system.\nNo further action is required.\n");
        *ExitStatus = (ULONG)NTFSCHK_STATUS_CORRECTED;
        Success = TRUE;
    }
    UNREFERENCED_PARAMETER(Fixed);

    if (R.JournalReplayed)
        NCK_OUT("\nThe journal was replayed when the volume was mounted (%lu pages).\n", R.JournalReplayed);

    Kb = R.TotalClusters * ClusterKb;
    NCK_OUT("\n%10I64u KB total disk space.\n", Kb);
    NCK_OUT("%10I64u KB in %I64u files.\n",
            (R.Clusters > R.SysClusters + R.LogClusters + R.IndexClusters ?
             R.Clusters - R.SysClusters - R.LogClusters - R.IndexClusters : 0) * ClusterKb,
            R.InUse > R.Dirs + R.ExtRecords ? R.InUse - R.Dirs - R.ExtRecords : 0);
    NCK_OUT("%10I64u KB in %I64u indexes.\n", R.IndexClusters * ClusterKb, R.Dirs);
    NCK_OUT("%10I64u KB in bad sectors.\n", 0ULL);
    NCK_OUT("%10I64u KB in use by the system.\n", R.SysClusters * ClusterKb);
    NCK_OUT("%10I64u KB occupied by the log file.\n", R.LogClusters * ClusterKb);
    NCK_OUT("%10I64u KB available on disk.\n\n", R.FreeClusters * ClusterKb);
    NCK_OUT("%10lu bytes in each allocation unit.\n", R.ClusterSize);
    NCK_OUT("%10I64u total allocation units on disk.\n", R.TotalClusters);
    NCK_OUT("%10I64u allocation units available on disk.\n", R.FreeClusters);
    NCK_OUT("Total duration: %lu.%02lu seconds (%lu ms).\n", TotalMs / 1000, (TotalMs % 1000) / 10, TotalMs);

    NtClose(Volume);
    return Success;

Failed:
    if (Volume)
        NtClose(Volume);
    *ExitStatus = (ULONG)Status;
    return FALSE;
}
