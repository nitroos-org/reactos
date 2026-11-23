/*
 *	IMAGEHLP library
 *
 *	Copyright 1998	Patrik Stridvall
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

#include <stdarg.h>

#include "windef.h"
#include "winbase.h"
#include "winver.h"
#include "imagehlp.h"
#include "wine/debug.h"

#ifdef __REACTOS__
#include <delayimp.h>

/*
 * The symbol functions of this module are dbghelp's, delay-loaded. Windows' imagehlp has its own and never loads
 * dbghelp.dll, so a program may have a dbghelp.dll of its own next to it (the debuggers do), which LoadLibrary by name
 * and its import table give it (dbghelp.dll is not a known DLL). This module takes the system one by its full path,
 * a module of its own beside a program's copy, whatever the program loaded.
 */
static FARPROC WINAPI ImagehlpDelayLoadHook(unsigned Notify, PDelayLoadInfo Info)
{
    WCHAR Path[MAX_PATH];
    UINT Length;

    if (Notify != dliNotePreLoadLibrary || !Info->szDll || lstrcmpiA(Info->szDll, "dbghelp.dll") != 0)
        return NULL;
    Length = GetSystemDirectoryW(Path, MAX_PATH);
    if (!Length || Length >= MAX_PATH - 13)
        return NULL;
    lstrcpyW(Path + Length, L"\\dbghelp.dll");
    return (FARPROC)LoadLibraryW(Path);
}

PfnDliHook __pfnDliNotifyHook2 = ImagehlpDelayLoadHook;
#endif


/***********************************************************************
 *           MarkImageAsRunFromSwap (IMAGEHLP.@)
 * FIXME
 *   No documentation available.
 */

/***********************************************************************
 *           TouchFileTimes (IMAGEHLP.@)
 */
BOOL WINAPI TouchFileTimes(HANDLE FileHandle, LPSYSTEMTIME lpSystemTime)
{
  FILETIME FileTime;
  SYSTEMTIME SystemTime;

  if(lpSystemTime == NULL)
  {
    GetSystemTime(&SystemTime);
    lpSystemTime = &SystemTime;
  }

  return (SystemTimeToFileTime(lpSystemTime, &FileTime) &&
          SetFileTime(FileHandle, NULL, NULL, &FileTime));
}
