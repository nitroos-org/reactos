/*
 * PROJECT:    ReactOS NetSh
 * LICENSE:    GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:    Network Shell command interpreter
 * COPYRIGHT:  Copyright 2023 Eric Kohl <eric.kohl@reactos.org>
 */

/* INCLUDES *******************************************************************/

#include "precomp.h"

#define NDEBUG
#include <debug.h>

typedef enum _INTERPRETER_STATE
{
    STATE_ANALYZE,
    STATE_COMMAND,
    STATE_GROUP,
    STATE_CONTEXT,
    STATE_PARENT_CONTEXT,
    STATE_DONE
} INTERPRETER_STATE;


/* GLOBALS *******************************************************************/

BOOL g_bInteractive = FALSE;
BOOL g_bCommandLine = FALSE;
LONG g_lScriptDepth = 0;
PCONTEXT_ENTRY g_pInvokeContext = NULL;


/* FUNCTIONS *****************************************************************/

BOOL
IsHelpToken(
    _In_ PCWSTR psz)
{
    return (_wcsicmp(psz, L"?") == 0) ||
           (_wcsicmp(psz, L"help") == 0) ||
           (_wcsicmp(psz, L"/?") == 0) ||
           (_wcsicmp(psz, L"-?") == 0);
}


static
PCOMMAND_ENTRY
GetGroupCommand(
    PWSTR pszCommand,
    PCOMMAND_GROUP pGroup)
{
    PCOMMAND_ENTRY pCommand;

    DPRINT("GetGroupCommand(%S %p)\n", pszCommand, pGroup);

    if (pszCommand == NULL)
        return NULL;

    pCommand = pGroup->pCommandListHead;
    while (pCommand)
    {
        if (MatchToken(pszCommand, pCommand->pwszCmdToken))
            return pCommand;

        pCommand = pCommand->pNext;
    }

    return NULL;
}


static
PCOMMAND_ENTRY
GetContextCommand(
    PWSTR pszCommand,
    PCONTEXT_ENTRY pContext)
{
    PCOMMAND_ENTRY pCommand;

    DPRINT("GetContextCommand(%S %p)\n", pszCommand, pContext);

    if (pszCommand == NULL)
        return NULL;

    pCommand = pContext->pCommandListHead;
    while (pCommand)
    {
        if (MatchToken(pszCommand, pCommand->pwszCmdToken))
            return pCommand;

        pCommand = pCommand->pNext;
    }

    return NULL;
}


static
PCOMMAND_GROUP
GetContextGroup(
    PWSTR pszGroup,
    PCONTEXT_ENTRY pContext)
{
    PCOMMAND_GROUP pGroup;

    DPRINT("GetContextGroup(%S %p)\n", pszGroup, pContext);

    if (pszGroup == NULL)
        return NULL;

    pGroup = pContext->pGroupListHead;
    while (pGroup)
    {
        if (MatchToken(pszGroup, pGroup->pwszCmdGroupToken))
            return pGroup;

        pGroup = pGroup->pNext;
    }

    return NULL;
}


static
PCONTEXT_ENTRY
GetContextSubContext(
    PWSTR pszContext,
    PCONTEXT_ENTRY pContext)
{
    PCONTEXT_ENTRY pSubContext;

    DPRINT("GetContextSubContext(%S %p)\n", pszContext, pContext);

    if (pszContext == NULL)
        return NULL;

    pSubContext = pContext->pSubContextHead;
    while (pSubContext)
    {
        if (MatchToken(pszContext, pSubContext->pszContextName))
            return pSubContext;

        pSubContext = pSubContext->pNext;
    }

    return NULL;
}


static
DWORD
InterpretCommand(
    _In_ LPWSTR *argv,
    _In_ DWORD dwArgCount,
    _Inout_ PBOOL bDone)
{
    PCONTEXT_ENTRY pTempContext, pTempSubContext = NULL;
    PCOMMAND_GROUP pGroup = NULL;
    PCOMMAND_ENTRY pCommand = NULL;
    INTERPRETER_STATE State = STATE_ANALYZE;
    DWORD dwArgIndex = 0;
    DWORD dwError = ERROR_SUCCESS;
    BOOL bDescended = FALSE;
    BOOL bHandlerSucceeded = FALSE;

    /* If no args provided */
    if (dwArgCount == 0)
        return ERROR_SUCCESS;

    if (pCurrentContext == NULL)
        pCurrentContext = pRootContext;

    /* A leading '=' can not start a command or argument */
    for (dwArgIndex = 0; dwArgIndex < dwArgCount; dwArgIndex++)
    {
        if (argv[dwArgIndex][0] == L'=')
            return ERROR_CMD_NOT_FOUND;
    }
    dwArgIndex = 0;

    /* Check for help keywords */
    if ((dwArgCount == 1) && IsHelpToken(argv[0]))
    {
        PrintContextHelp(pCurrentContext);
        return ERROR_SUCCESS;
    }

    pTempContext = pCurrentContext;
    while (dwArgIndex < dwArgCount)
    {
        switch (State)
        {
            case STATE_ANALYZE:
                DPRINT("STATE_ANALYZE\n");

                if (IsHelpToken(argv[dwArgIndex]))
                {
                    PrintContextHelp(pTempContext);
                    State = STATE_DONE;
                    break;
                }

                pCommand = GetContextCommand(argv[dwArgIndex], pTempContext);
                if (pCommand != NULL)
                {
                    State = STATE_COMMAND;
                    break;
                }

                pGroup = GetContextGroup(argv[dwArgIndex], pTempContext);
                if (pGroup != NULL)
                {
                    State = STATE_GROUP;
                    break;
                }

                pTempSubContext = GetContextSubContext(argv[dwArgIndex], pTempContext);
                if (pTempSubContext != NULL)
                {
                    State = STATE_CONTEXT;
                    break;
                }

                State = STATE_PARENT_CONTEXT;
                break;

            case STATE_COMMAND:
                DPRINT("STATE_COMMAND\n");

                if (!CheckOsVersion(pCommand->pfnOsVersionCheck))
                {
                    DPRINT("Command: Version check failed!\n");
                    dwError = ERROR_CMD_NOT_FOUND;
                    State = STATE_DONE;
                    break;
                }

                if (((pCommand->dwFlags & CMD_FLAG_LOCAL) && (g_pszMachine != NULL)) ||
                    ((pCommand->dwFlags & CMD_FLAG_ONLINE) && (g_bOnline == FALSE)))
                {
                    dwError = ERROR_CMD_NOT_FOUND;
                    State = STATE_DONE;
                    break;
                }

                /* Check for help keywords */
                if (((dwArgIndex + 1) == (dwArgCount - 1)) && IsHelpToken(argv[dwArgIndex + 1]))
                {
                    PrintCommandHelp(pTempContext, pGroup, pCommand);
                    State = STATE_DONE;
                    break;
                }

                if (pCommand->pfnCmdHandler != NULL)
                {
                    dwArgIndex++;
                    g_pInvokeContext = pTempContext;
                    dwError = pCommand->pfnCmdHandler(g_pszMachine, argv, dwArgIndex, dwArgCount, 0, NULL, bDone);
                    if (dwError != ERROR_SUCCESS)
                    {
                        if (dwError == ERROR_SHOW_USAGE || dwError == ERROR_INVALID_SYNTAX)
                        {
                            if (dwError == ERROR_INVALID_SYNTAX)
                                PrintError(NULL, ERROR_INVALID_SYNTAX);
                            PrintCommandHelp(pTempContext, pGroup, pCommand);
                            dwError = ERROR_SUPPRESS_OUTPUT;
                        }
                    }
                    else
                    {
                        bHandlerSucceeded = TRUE;

                        /* Execute the commands following a pushd command */
                        if ((_wcsicmp(pCommand->pwszCmdToken, L"pushd") == 0) &&
                            (dwArgIndex < dwArgCount))
                        {
                            State = STATE_ANALYZE;
                            break;
                        }
                    }
                }

                State = STATE_DONE;
                break;

            case STATE_GROUP:
                DPRINT("STATE_GROUP\n");

                if (!CheckOsVersion(pGroup->pfnOsVersionCheck))
                {
                    DPRINT("Group: Version check failed!\n");
                    dwError = ERROR_CMD_NOT_FOUND;
                    State = STATE_DONE;
                    break;
                }

                if (((pGroup->dwFlags & CMD_FLAG_LOCAL) && (g_pszMachine != NULL)) ||
                    ((pGroup->dwFlags & CMD_FLAG_ONLINE) && (g_bOnline == FALSE)))
                {
                    dwError = ERROR_CMD_NOT_FOUND;
                    State = STATE_DONE;
                    break;
                }

                /* Check for group without command */
                if (dwArgIndex == (dwArgCount - 1))
                {
                    PrintGroupHelp(pTempContext, pGroup->pwszCmdGroupToken, TRUE);
                    State = STATE_DONE;
                    break;
                }

                /* Check for help keywords */
                if (((dwArgIndex + 1) <= (dwArgCount - 1)) && IsHelpToken(argv[dwArgIndex + 1]))
                {
                    PrintGroupHelp(pTempContext, pGroup->pwszCmdGroupToken, TRUE);
                    State = STATE_DONE;
                    break;
                }

                dwArgIndex++;
                pCommand = GetGroupCommand(argv[dwArgIndex], pGroup);
                if (pCommand != NULL)
                {
                    State = STATE_COMMAND;
                    break;
                }

                dwError = ERROR_CMD_NOT_FOUND;
                State = STATE_DONE;
                break;

            case STATE_CONTEXT:
                DPRINT("STATE_CONTEXT\n");

                if (!CheckOsVersion(pTempSubContext->pfnOsVersionCheck))
                {
                    DPRINT("Context: Version check failed!\n");
                    dwError = ERROR_CMD_NOT_FOUND;
                    State = STATE_DONE;
                    break;
                }

                if (((pTempSubContext->dwFlags & CMD_FLAG_LOCAL) && (g_pszMachine != NULL)) ||
                    ((pTempSubContext->dwFlags & CMD_FLAG_ONLINE) && (g_bOnline == FALSE)))
                {
                    dwError = ERROR_CMD_NOT_FOUND;
                    State = STATE_DONE;
                    break;
                }

                if (pTempSubContext == pCurrentContext)
                {
                    if (dwArgIndex != (dwArgCount - 1))
                        dwError = ERROR_CMD_NOT_FOUND;

                    State = STATE_DONE;
                    break;
                }

                if (dwArgIndex == (dwArgCount - 1))
                {
                    if (g_bCommandLine && !g_bInteractive)
                    {
                        /* "netsh <context>" on the command line shows the context's commands */
                        PrintContextHelp(pTempSubContext);
                        State = STATE_DONE;
                        break;
                    }

                    DPRINT("Set current context\n");
                    pCurrentContext = pTempSubContext;
                    if (g_bInteractive && pCurrentContext->pfnConnectFn)
                        dwError = pCurrentContext->pfnConnectFn(g_pszMachine);
                    State = STATE_DONE;
                    break;
                }

                /* Check for help keywords */
                if (((dwArgIndex + 1) <= (dwArgCount - 1)) && IsHelpToken(argv[dwArgIndex + 1]))
                {
                    PrintContextHelp(pTempSubContext);
                    State = STATE_DONE;
                    break;
                }

                DPRINT("Change temorary context\n");
                pTempContext = pTempSubContext;
                bDescended = TRUE;
                State = STATE_ANALYZE;
                dwArgIndex++;
                break;

            case STATE_PARENT_CONTEXT:
                DPRINT("STATE_PARENT_CONTEXT\n");

                /* Once a sub-context was entered on the command line the command must be found there;
                 * walking up and restarting at the first argument would loop forever. */
                if (bDescended || pTempContext->pParentContext == NULL)
                {
                    dwError = ERROR_CMD_NOT_FOUND;
                    State = STATE_DONE;
                    break;
                }

                DPRINT("Change temorary context\n");
                pTempContext = pTempContext->pParentContext;
                State = STATE_ANALYZE;
                dwArgIndex = 0;
                break;

            case STATE_DONE:
                DPRINT("STATE_DONE dwError %ld\n", dwError);
                if (bHandlerSucceeded && (dwError == ERROR_SUCCESS) && (g_lScriptDepth == 0))
                    ConPuts(StdOut, L"\n");
                return dwError;
        }
    }

    /* Done */
    if (bHandlerSucceeded && (dwError == ERROR_SUCCESS) && (g_lScriptDepth == 0))
        ConPuts(StdOut, L"\n");
    return dwError;
} 


/*
 * Prints what the interpreter has to say about an error code and returns the
 * code that makes the process fail (ERROR_SUCCESS if the error was only a usage message).
 */
static
DWORD
ReportError(
    _In_ DWORD dwError,
    _In_ LPWSTR *argv,
    _In_ DWORD dwArgCount)
{
    PWSTR pszCommandString;

    switch (dwError)
    {
        case ERROR_SUCCESS:
        case ERROR_SUPPRESS_OUTPUT:
            return ERROR_SUCCESS;

        case ERROR_SCRIPT_FAILED:
            if (g_lScriptDepth == 0)
                ConPuts(StdOut, L"\n");
            return dwError;

        case ERROR_CMD_NOT_FOUND:
            pszCommandString = MergeStrings(argv, dwArgCount);
            PrintError(NULL, dwError, pszCommandString ? pszCommandString : L"");
            if (pszCommandString)
                HeapFree(GetProcessHeap(), 0, pszCommandString);
            return dwError;

        default:
            PrintError(NULL, dwError);
            if (g_lScriptDepth == 0)
                ConPuts(StdOut, L"\n");
            return dwError;
    }
}


DWORD
InterpretTokens(
    _In_ LPWSTR *argv,
    _In_ DWORD dwArgCount,
    _Inout_ PBOOL pbDone)
{
    DWORD dwError = InterpretCommand(argv, dwArgCount, pbDone);
    return ReportError(dwError, argv, dwArgCount);
}


static
DWORD
SplitLine(
    _In_ LPWSTR pszLine,
    _Out_writes_(MAX_ARGS_COUNT) LPWSTR *args_vector)
{
    DWORD dwArgCount = 0, i, len;
    BOOL bWhiteSpace = TRUE;
    BOOL bInQuotes = FALSE;
    LPWSTR ptr, pStartQuote, pEndQuote;

    memset(args_vector, 0, MAX_ARGS_COUNT * sizeof(LPWSTR));

    ptr = pszLine;
    while (*ptr != 0)
    {
        if (*ptr == L'\"')
            bInQuotes = (bInQuotes) ? FALSE : TRUE;

        if ((iswspace(*ptr) && (bInQuotes == FALSE)) || *ptr == L'\n')
        {
            *ptr = 0;
            bWhiteSpace = TRUE;
        }
        else
        {
            if ((bWhiteSpace != FALSE) && (dwArgCount < MAX_ARGS_COUNT))
            {
                args_vector[dwArgCount] = ptr;
                dwArgCount++;
            }

            bWhiteSpace = FALSE;
        }

        ptr++;
    }

    /* Remove quotation marks */
    for (i = 0; i < dwArgCount; i++)
    {
        pStartQuote = wcschr(args_vector[i], L'\"');
        if (pStartQuote)
        {
            pEndQuote = wcschr(pStartQuote + 1, L'\"');
            if (pEndQuote)
            {
                len = pEndQuote - pStartQuote;
                memmove(pStartQuote, pStartQuote + 1, (len - 1) * sizeof(WCHAR));
                *(pEndQuote - 1) = UNICODE_NULL;
            }
        }
    }

    return dwArgCount;
}


/*
 * InterpretLine(WCHAR *line):
 * The main function used for when reading commands from scripts.
 */
DWORD
InterpretLine(
    _In_ LPWSTR pszInputLine)
{
    LPWSTR args_vector[MAX_ARGS_COUNT];
    DWORD dwArgCount;
    BOOL bDone = FALSE;
    LPWSTR p;

    /* Comment lines */
    for (p = pszInputLine; *p != 0 && iswspace(*p); p++)
        ;
    if (*p == L'#')
        return ERROR_SUCCESS;

    dwArgCount = SplitLine(pszInputLine, args_vector);

    return InterpretTokens(args_vector, dwArgCount, &bDone);
}


VOID
PrintPrompt(
    _In_ PCONTEXT_ENTRY pContext)
{
    if (pContext != pRootContext)
    {
        PrintPrompt(pContext->pParentContext);
        ConPuts(StdOut, L" ");
    }

    ConPuts(StdOut, pContext->pszContextName);
}


DWORD
InterpretInteractive(VOID)
{
    DWORD dwResult = ERROR_SUCCESS;
    WCHAR input_line[MAX_STRING_SIZE];
    LPWSTR args_vector[MAX_ARGS_COUNT];
    DWORD dwArgCount;
    BOOL bDone = FALSE;

    g_bInteractive = TRUE;

    for (;;)
    {
        /* Shown just before the input where the user places commands */
        if (g_pszMachine)
            ConPrintf(StdOut, L"[%s] ", g_pszMachine);
        PrintPrompt(pCurrentContext);
        ConPuts(StdOut, L">");

        /* Get input from the user. End of input leaves the program. */
        if (fgetws(input_line, MAX_STRING_SIZE, stdin) == NULL)
            break;

        dwArgCount = SplitLine(input_line, args_vector);
        if (InterpretTokens(args_vector, dwArgCount, &bDone) != ERROR_SUCCESS)
            dwResult = ERROR_INVALID_FUNCTION;

        if (bDone)
            break;
    }

    return dwResult;
}
