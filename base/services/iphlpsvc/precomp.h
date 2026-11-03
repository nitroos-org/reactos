/*
 * PROJECT:     ReactOS IP Helper Service
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Service header: port proxy (v4tov4 TCP relay)
 */

#ifndef _IPHLPSVC_PRECOMP_H
#define _IPHLPSVC_PRECOMP_H

#include <stdarg.h>
#define WIN32_NO_STATUS
#include <windef.h>
#include <winbase.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>
#include <winreg.h>
#include <winsvc.h>
#include <ndk/rtlfuncs.h>

#define PORTPROXY_KEY_ROOT   L"SYSTEM\\CurrentControlSet\\Services\\PortProxy"
#define PORTPROXY_KEY_V4TOV4 L"SYSTEM\\CurrentControlSet\\Services\\PortProxy\\v4tov4\\tcp"

DWORD PortProxyStart(VOID);
VOID PortProxyStop(VOID);

#endif
