/*
 * PROJECT:     NitroOS
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     guid
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

/* DO NOT USE THE PRECOMPILED HEADER FOR THIS FILE! */

#include <stdarg.h>

#define WIN32_NO_STATUS
#define _INC_WINDOWS
#define COM_NO_WINDOWS_H

#include <windef.h>
#include <winbase.h>
#include <objbase.h>
#include <initguid.h>
#include <wbemcli.h>

/* NO CODE HERE, THIS IS JUST REQUIRED FOR THE GUID DEFINITIONS */
