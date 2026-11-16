/*
 * PROJECT:    NitroOS IF Monitor DLL
 * LICENSE:    GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:    LAN connections and their administrative state
 * COPYRIGHT:  Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#ifndef IFMON_ADAPTER_H
#define IFMON_ADAPTER_H

typedef struct _IF_CONN
{
    WCHAR Guid[40];         /* {GUID} of the connection */
    WCHAR Name[MAX_PATH];   /* the friendly name */
    WCHAR PnpId[MAX_PATH];  /* the device instance id */
    BOOL Disabled;          /* administratively disabled (the device is) */
    BOOL Connected;         /* the stack has an interface for it and it is operationally up */
} IF_CONN, *PIF_CONN;

DWORD
IfEnumConnections(
    _Out_ PIF_CONN *ppList,
    _Out_ PULONG pCount);

VOID
IfFreeConnections(
    _In_opt_ PIF_CONN List);

DWORD
IfSetAdminState(
    _In_ const IF_CONN *Conn,
    _In_ BOOL Enable);

BOOL
IfCallerIsAdmin(VOID);

DWORD
IfRenameConnection(
    _In_ const IF_CONN *Conn,
    _In_ PCWSTR NewName);

#endif /* IFMON_ADAPTER_H */
