/*
 * PROJECT:    ReactOS NetSh
 * LICENSE:    GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:    Network Shell builtin help command and support functions
 * COPYRIGHT:  Copyright 2023 Eric Kohl <eric.kohl@reactos.org>
 */

/* INCLUDES *******************************************************************/

#include "precomp.h"

#define NDEBUG
#include <debug.h>

#define SMALL_HELP_BUFFER_SIZE  160

typedef enum
{
    Command,
    Group,
    SubContext
} HELP_TYPE, *PHELP_TYPE;

typedef struct
{
    HELP_TYPE Type;
    PWSTR pszCommand;
    HMODULE hModule;
    DWORD dwHelpId;
    union
    {
        PCOMMAND_ENTRY pCommand;
        PCOMMAND_GROUP pGroup;
        PCONTEXT_ENTRY pSubContext;
    } Pointer;
} HELP_ENTRY, *PHELP_ENTRY;


/* FUNCTIONS ******************************************************************/

static
VOID
GetContextFullName(
    _In_ PCONTEXT_ENTRY pContext,
    _Inout_ LPWSTR pszBuffer,
    _In_ DWORD cchLength)
{
    if (pContext != pRootContext)
    {
        GetContextFullName(pContext->pParentContext, pszBuffer, cchLength);
        wcscat(pszBuffer, L" ");
        wcscat(pszBuffer, pContext->pszContextName);
    }
    else
    {
        wcscpy(pszBuffer, pContext->pszContextName);
    }
}


static
BOOL
IsHidden(
    _In_ DWORD dwFlags,
    _In_ PNS_OSVERSIONCHECK pfnOsVersionCheck)
{
    if (!CheckOsVersion(pfnOsVersionCheck))
        return TRUE;

    if (((dwFlags & CMD_FLAG_LOCAL) && (g_pszMachine != NULL)) ||
        ((dwFlags & CMD_FLAG_ONLINE) && (g_bOnline == FALSE)) ||
        ((dwFlags & CMD_FLAG_INTERACTIVE) && (g_bInteractive == FALSE)) ||
        (dwFlags & CMD_FLAG_HIDDEN))
        return TRUE;

    return FALSE;
}


static
int
HelpCompare(
    _In_ const void *p1,
    _In_ const void *p2)
{
    return _wcsicmp(((PHELP_ENTRY)p1)->pszCommand, ((PHELP_ENTRY)p2)->pszCommand);
}


static
BOOL
IsInheritable(
    _In_ PCWSTR pszToken)
{
    return (_wcsicmp(pszToken, L"?") != 0) &&
           (_wcsicmp(pszToken, L"help") != 0) &&
           (_wcsicmp(pszToken, L"dump") != 0) &&
           (_wcsicmp(pszToken, L"exec") != 0);
}


/* Prints the commands, groups and sub-contexts of one context, sorted by name */
static
VOID
PrintContextSection(
    _In_ PCONTEXT_ENTRY pContext,
    _In_ BOOL bInherited)
{
    PCOMMAND_ENTRY pCommand;
    PCOMMAND_GROUP pGroup;
    PCONTEXT_ENTRY pSubContext;
    PHELP_ENTRY pHelpArray;
    DWORD dwCount = 0, dwIndex;
    WCHAR szBuffer[SMALL_HELP_BUFFER_SIZE];

    if (bInherited)
    {
        GetContextFullName(pContext, szBuffer, _countof(szBuffer));
        ConResPrintf(StdOut, IDS_INHERITED_COMMANDS, szBuffer);
    }
    else
    {
        ConResPrintf(StdOut, IDS_THIS_COMMANDS);
    }

    for (pCommand = pContext->pCommandListHead; pCommand != NULL; pCommand = pCommand->pNext)
        if (!IsHidden(pCommand->dwFlags, pCommand->pfnOsVersionCheck) &&
            (!bInherited || IsInheritable(pCommand->pwszCmdToken)))
            dwCount++;
    for (pGroup = pContext->pGroupListHead; pGroup != NULL; pGroup = pGroup->pNext)
        if (!IsHidden(pGroup->dwFlags, pGroup->pfnOsVersionCheck))
            dwCount++;
    for (pSubContext = pContext->pSubContextHead; pSubContext != NULL; pSubContext = pSubContext->pNext)
        if (!IsHidden(pSubContext->dwFlags, pSubContext->pfnOsVersionCheck))
            dwCount++;

    if (dwCount == 0)
        return;

    pHelpArray = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwCount * sizeof(HELP_ENTRY));
    if (pHelpArray == NULL)
        return;

    dwIndex = 0;
    for (pCommand = pContext->pCommandListHead; pCommand != NULL; pCommand = pCommand->pNext)
    {
        if (IsHidden(pCommand->dwFlags, pCommand->pfnOsVersionCheck) ||
            (bInherited && !IsInheritable(pCommand->pwszCmdToken)))
            continue;
        pHelpArray[dwIndex].Type = Command;
        pHelpArray[dwIndex].pszCommand = pCommand->pwszCmdToken;
        pHelpArray[dwIndex].hModule = pCommand->hModule ? pCommand->hModule : pContext->hModule;
        pHelpArray[dwIndex].dwHelpId = pCommand->dwShortCmdHelpToken;
        dwIndex++;
    }
    for (pGroup = pContext->pGroupListHead; pGroup != NULL; pGroup = pGroup->pNext)
    {
        if (IsHidden(pGroup->dwFlags, pGroup->pfnOsVersionCheck))
            continue;
        pHelpArray[dwIndex].Type = Group;
        pHelpArray[dwIndex].pszCommand = pGroup->pwszCmdGroupToken;
        pHelpArray[dwIndex].hModule = pContext->hModule;
        pHelpArray[dwIndex].dwHelpId = pGroup->dwShortCmdHelpToken;
        dwIndex++;
    }
    for (pSubContext = pContext->pSubContextHead; pSubContext != NULL; pSubContext = pSubContext->pNext)
    {
        if (IsHidden(pSubContext->dwFlags, pSubContext->pfnOsVersionCheck))
            continue;
        pHelpArray[dwIndex].Type = SubContext;
        pHelpArray[dwIndex].pszCommand = pSubContext->pszContextName;
        pHelpArray[dwIndex].Pointer.pSubContext = pSubContext;
        dwIndex++;
    }

    qsort(pHelpArray, dwCount, sizeof(HELP_ENTRY), HelpCompare);

    for (dwIndex = 0; dwIndex < dwCount; dwIndex++)
    {
        if (pHelpArray[dwIndex].Type == SubContext)
        {
            GetContextFullName(pHelpArray[dwIndex].Pointer.pSubContext, szBuffer, _countof(szBuffer));
            ConResPrintf(StdOut, IDS_CHANGE_CONTEXT, pHelpArray[dwIndex].pszCommand, szBuffer);
        }
        else
        {
            if (LoadStringW(pHelpArray[dwIndex].hModule, pHelpArray[dwIndex].dwHelpId, szBuffer, _countof(szBuffer)) == 0)
                szBuffer[0] = UNICODE_NULL;
            ConPrintf(StdOut, L"%-14s - %s", pHelpArray[dwIndex].pszCommand, szBuffer);
        }
    }

    HeapFree(GetProcessHeap(), 0, pHelpArray);
}


static
int
SubContextCompare(
    _In_ const void *p1,
    _In_ const void *p2)
{
    return _wcsicmp((*((PCONTEXT_ENTRY*)p1))->pszContextName, (*((PCONTEXT_ENTRY*)p2))->pszContextName);
}


static
VOID
PrintSubcontexts(
    _In_ PCONTEXT_ENTRY pContext)
{
    PCONTEXT_ENTRY pSubContext, *pSubContextArray = NULL;
    DWORD dwCount, dwIndex;

    if (pContext->pSubContextHead == NULL)
        return;

    dwCount = 0;
    for (pSubContext = pContext->pSubContextHead; pSubContext != NULL; pSubContext = pSubContext->pNext)
        if (!IsHidden(pSubContext->dwFlags, pSubContext->pfnOsVersionCheck))
            dwCount++;

    if (dwCount == 0)
        return;

    pSubContextArray = HeapAlloc(GetProcessHeap(), 0, dwCount * sizeof(PCONTEXT_ENTRY));
    if (pSubContextArray == NULL)
        return;

    dwIndex = 0;
    for (pSubContext = pContext->pSubContextHead; pSubContext != NULL; pSubContext = pSubContext->pNext)
        if (!IsHidden(pSubContext->dwFlags, pSubContext->pfnOsVersionCheck))
            pSubContextArray[dwIndex++] = pSubContext;

    qsort(pSubContextArray, dwCount, sizeof(PCONTEXT_ENTRY), SubContextCompare);

    ConResPrintf(StdOut, IDS_SUBCONTEXT_HEADER);
    for (dwIndex = 0; dwIndex < dwCount; dwIndex++)
    {
        ConPrintf(StdOut, L" %s", pSubContextArray[dwIndex]->pszContextName);
    }
    ConPuts(StdOut, L"\n");

    HeapFree(GetProcessHeap(), 0, pSubContextArray);
}


VOID
PrintCommandHelp(
    _In_ PCONTEXT_ENTRY pContext,
    _In_ PCOMMAND_GROUP pGroup,
    _In_ PCOMMAND_ENTRY pCommand)
{
    LPWSTR pszCommandBuffer;
    DWORD_PTR Args[2];
    DWORD dwLength = 1;
    HMODULE hModule;

    DPRINT("PrintCommandHelp(%p %p %p)\n", pContext, pGroup, pCommand);

    if (!CheckOsVersion(pCommand->pfnOsVersionCheck))
        return;

    if (((pCommand->dwFlags & CMD_FLAG_LOCAL) && (g_pszMachine != NULL)) ||
        ((pCommand->dwFlags & CMD_FLAG_ONLINE) && (g_bOnline == FALSE)) ||
        (pCommand->dwFlags & CMD_FLAG_HIDDEN))
        return;

    dwLength += wcslen(pCommand->pwszCmdToken);
    if (pGroup)
        dwLength += (wcslen(pGroup->pwszCmdGroupToken) + 1);

    pszCommandBuffer = HeapAlloc(GetProcessHeap(), 0, dwLength * sizeof(WCHAR));
    if (pszCommandBuffer == NULL)
        return;

    _swprintf(pszCommandBuffer, L"%s%s%s",
              (pGroup) ? pGroup->pwszCmdGroupToken : L"",
              (pGroup) ? L" " : L"",
              pCommand->pwszCmdToken);

    Args[0] = (DWORD_PTR)pszCommandBuffer;
    Args[1] = (DWORD_PTR)NULL;

    hModule = pCommand->hModule ? pCommand->hModule : pContext->hModule;
    ConResMsgPrintfExV(StdOut,
                       hModule,
                       FORMAT_MESSAGE_ARGUMENT_ARRAY,
                       pCommand->dwCmdHlpToken,
                       LANG_USER_DEFAULT,
                       (va_list *)&Args);
    if (g_lScriptDepth == 0)
        ConPuts(StdOut, L"\n");

    HeapFree(GetProcessHeap(), 0, pszCommandBuffer);
}


VOID
PrintGroupHelp(
    _In_ PCONTEXT_ENTRY pContext,
    _In_ LPWSTR pszGroupName,
    _In_ BOOL bRecurse)
{
    PCOMMAND_GROUP pGroup;
    PCOMMAND_ENTRY pCommand;
    WCHAR szBuffer1[SMALL_HELP_BUFFER_SIZE];
    WCHAR szBuffer2[SMALL_HELP_BUFFER_SIZE];

    ConResPrintf(StdOut, IDS_HELP_HEADER);
    ConResPrintf(StdOut, IDS_THIS_COMMANDS);

    for (pGroup = pContext->pGroupListHead; pGroup != NULL; pGroup = pGroup->pNext)
    {
        if (_wcsicmp(pszGroupName, pGroup->pwszCmdGroupToken) != 0)
            continue;

        for (pCommand = pGroup->pCommandListHead; pCommand != NULL; pCommand = pCommand->pNext)
        {
            if (IsHidden(pCommand->dwFlags, pCommand->pfnOsVersionCheck))
                continue;

            _swprintf(szBuffer1, L"%s %s", pGroup->pwszCmdGroupToken, pCommand->pwszCmdToken);
            if (LoadStringW(pCommand->hModule ? pCommand->hModule : pContext->hModule,
                            pCommand->dwShortCmdHelpToken, szBuffer2, _countof(szBuffer2)) == 0)
                szBuffer2[0] = UNICODE_NULL;
            ConPrintf(StdOut, L"%-14s - %s", szBuffer1, szBuffer2);
        }
    }
}


VOID
PrintContextHelp(
    _In_ PCONTEXT_ENTRY pContext)
{
    PCONTEXT_ENTRY pAncestor[16];
    DWORD dwDepth = 0, i;
    PCONTEXT_ENTRY p;

    ConResPrintf(StdOut, IDS_HELP_HEADER);

    /* The commands of the parent contexts are only reachable in the interactive mode */
    if (g_bInteractive)
    {
        for (p = pContext->pParentContext; p != NULL && dwDepth < _countof(pAncestor); p = p->pParentContext)
            pAncestor[dwDepth++] = p;
        for (i = dwDepth; i > 0; i--)
            PrintContextSection(pAncestor[i - 1], TRUE);
    }

    PrintContextSection(pContext, FALSE);
    PrintSubcontexts(pContext);
    ConResPrintf(StdOut, IDS_HELP_FOOTER);
    if (g_lScriptDepth == 0)
        ConPuts(StdOut, L"\n");
}
