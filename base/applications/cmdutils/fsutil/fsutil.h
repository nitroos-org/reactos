#ifndef __FSUTIL_H__
#define __FSUTIL_H__

#include <windows.h>
#include <winioctl.h>
#include <tchar.h>
#include <stdio.h>

/* All text goes to stdout, as in Windows fsutil. Handler == NULL: the sub-command exists in Windows
 * (and is listed in the usage text) but is not implemented here. */
typedef int (HandlerProc)(int argc, const TCHAR *argv[]);
typedef HandlerProc * pHandlerProc;

typedef struct
{
    pHandlerProc Handler;
    const TCHAR * Command;
} HandlerItem;

/* groups.c (generated from the Windows 10 22H2 output) */
extern const TCHAR TopListing[];
extern HandlerItem TopItems[];
extern const int TopItemCount;

/* Dispatch "fsutil <group> <command> ...": argv[0] is the group name */
int RunGroup(int argc,
             const TCHAR *argv[],
             const TCHAR * Listing,
             HandlerItem * List,
             int Count);

int NotImplementedMain(const TCHAR * Group, const TCHAR * Command);

#define NOTE_LOCAL_VOLUME      _T("The FSUTIL utility requires a local volume for this operation.")
#define NOTE_LOCAL_NTFS_VOLUME _T("A local NTFS volume is required for this operation.")
#define NOTE_LOCAL_ANY_FS      _T("The FSUTIL utility requires a local NTFS/ReFS/FAT/FAT32/ExFAT volume for this operation.")

/* Opens \\.\<Volume>. On failure prints the error and, when the argument names a drive that
 * does not exist (or is empty), the Note. Lenient: "C:\anything" opens \\.\C: */
HANDLE OpenVolumeArg(const TCHAR * Volume,
                     BOOLEAN Lenient,
                     DWORD Access,
                     const TCHAR * Note,
                     BOOLEAN * NoteShown);

int PrintErrorMessage(DWORD Error);

/* 1234567 -> "1,234,567" */
void FormatNumber(ULONGLONG Value, TCHAR * Buffer);
/* bytes -> "63.7 GB" (unit KB..EB), Decimals digits, optional width of the integer part */
void FormatSize(ULONGLONG Bytes, int Decimals, int Width, TCHAR * Buffer);

#endif
