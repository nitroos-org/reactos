/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 * Pseudoconsole state shared by process creation and the console API.
 */

#ifndef KERNEL32_PSEUDOCONSOLE_H
#define KERNEL32_PSEUDOCONSOLE_H

typedef struct _BASE_PSEUDOCONSOLE
{
    ULONG Magic;
    HANDLE Process;
    HANDLE Signal;
    HANDLE Console;
    HANDLE Input;
    HANDLE Output;
    DWORD ProcessId;
} BASE_PSEUDOCONSOLE, *PBASE_PSEUDOCONSOLE;

#define BASE_PSEUDOCONSOLE_MAGIC 0x43545052

#endif
