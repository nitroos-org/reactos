/*
 * PROJECT:     NitroOS Firewall with Advanced Security (wf.msc)
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Shared declarations
 */
#pragma once

#define WIN32_NO_STATUS
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>
#include <windows.h>
#include <commctrl.h>
#include <commdlg.h>
#include <shellapi.h>
#include <strsafe.h>
#include <fwstore.h>

#include "resource.h"

extern HINSTANCE g_hInst;

/* wfadv.c */
PCWSTR Str(UINT id);
VOID ShowStoreError(HWND hWnd, DWORD err);
VOID NotifyMainRefresh(VOID);

/* rules.c: formatting and the shared protocol / ports / address controls */
VOID FormatProfiles(LONG mask, PWSTR out, SIZE_T cch);
VOID FormatProtocol(LONG proto, PWSTR out, SIZE_T cch);
PCWSTR AnyIfEmpty(PCWSTR s);
VOID FillProtocolCombo(HWND hCombo, BOOL portsOnly);
VOID SetProtocolCombo(HWND hDlg, UINT idCombo, UINT idNum, LONG proto);
BOOL GetProtocolCombo(HWND hDlg, UINT idCombo, UINT idNum, LONG *pProto);
VOID EnableProtoControls(HWND hDlg, UINT idCombo, UINT idNum, UINT idLPort, UINT idRPort, UINT idIcmp);
VOID GetEditText(HWND hDlg, UINT id, PWSTR out, SIZE_T cch);
VOID SetRadioEdit(HWND hDlg, UINT idAny, UINT idSel, UINT idEdit, PCWSTR value);
VOID UpdateRadioEdit(HWND hDlg, UINT idAny, UINT idSel, UINT idEdit);
BOOL GetRadioEdit(HWND hDlg, UINT idAny, UINT idSel, UINT idEdit, PWSTR out, SIZE_T cch);
BOOL BrowseForProgram(HWND hDlg, UINT idEdit);
BOOL ValidatePortsAddrs(HWND hDlg, PCWSTR lport, PCWSTR rport, PCWSTR laddr, PCWSTR raddr);

/* ruledlg.c */
BOOL EditRuleProperties(HWND hOwner, const FW_RULE *rule);

/* wizard.c */
BOOL RunNewRuleWizard(HWND hOwner, LONG dir);

/* profile.c */
VOID ShowProfileProperties(HWND hOwner);
VOID DoExportPolicy(HWND hOwner);
VOID DoImportPolicy(HWND hOwner);
VOID DoRestorePolicy(HWND hOwner);
