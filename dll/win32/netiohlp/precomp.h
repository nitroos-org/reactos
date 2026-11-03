/*
 * PROJECT:     ReactOS Net IO Helper DLL
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     netsh helper for "interface portproxy": main header
 */

#ifndef _NETIOHLP_PRECOMP_H
#define _NETIOHLP_PRECOMP_H

#define WIN32_NO_STATUS
#include <stdarg.h>
#include <stdio.h>
#include <windows.h>
#include <strsafe.h>

#include <netsh.h>
#include <netsh_undoc.h>

#include "resource.h"

extern HINSTANCE hDllInstance;

DWORD WINAPI RegisterPortProxyHelper(VOID);

#endif
