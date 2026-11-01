/*
 * COPYRIGHT:       See COPYING in the top level directory
 * PROJECT:         ReactOS net command
 * FILE:            base/applications/network/net/output.c
 * PURPOSE:         Error and syntax output for the net commands that write them to standard error
 */

#include "net.h"

#define MSG_OPTION_UNKNOWN  3506

static
VOID
PrintErrMessageStringV(
    DWORD dwMessage,
    ...)
{
    va_list args;

    va_start(args, dwMessage);
    ConMsgPrintfV(StdErr,
                  FORMAT_MESSAGE_FROM_HMODULE,
                  hModuleNetMsg,
                  dwMessage,
                  LANG_USER_DEFAULT,
                  &args);
    va_end(args);
}


static
VOID
PrintExeMessage(
    PCON_STREAM Stream,
    DWORD dwMessage,
    BOOL bNewLine)
{
    PWSTR pBuffer = NULL;

    FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER |
                   FORMAT_MESSAGE_FROM_HMODULE |
                   FORMAT_MESSAGE_IGNORE_INSERTS,
                   GetModuleHandleW(NULL),
                   dwMessage,
                   LANG_USER_DEFAULT,
                   (LPWSTR)&pBuffer,
                   0,
                   NULL);
    if (pBuffer)
    {
        ConPuts(Stream, pBuffer);
        if (bNewLine)
            ConPuts(Stream, L"\n");
        LocalFree(pBuffer);
    }
}


VOID
PrintHelpMessageHint(
    DWORD dwMessage)
{
    WCHAR szNumber[16];

    StringCchPrintfW(szNumber, ARRAYSIZE(szNumber), L"%lu", dwMessage);
    PrintErrMessageStringV(3514, szNumber);
    ConPuts(StdErr, L"\n");
}


/* Messages above the NERR range with one insert, then the "More help" hint; returns the exit code of a failed command */
INT
PrintCommandError(
    DWORD dwMessage,
    PCWSTR pszInsert)
{
    PrintErrMessageStringV(dwMessage, pszInsert);
    ConPuts(StdErr, L"\n");
    PrintHelpMessageHint(dwMessage);
    return 2;
}


/* The syntax of a command, optionally preceded by a message and followed by the hint for it; returns the exit code of a syntax error */
INT
PrintCommandSyntax(
    DWORD dwSyntaxMessage,
    DWORD dwMessage,
    PCWSTR pszInsert)
{
    if (dwMessage != 0)
    {
        PrintErrMessageStringV(dwMessage, pszInsert);
        ConPuts(StdErr, L"\n");
    }

    PrintErrMessageStringV(4381);
    ConPuts(StdErr, L"\n");
    PrintExeMessage(StdErr, dwSyntaxMessage, TRUE);

    if (dwMessage != 0)
        PrintHelpMessageHint(dwMessage);

    return 1;
}


/* "The option /NAME is unknown." and the syntax of the command; returns the exit code 1 */
INT
PrintUnknownOption(
    DWORD dwSyntaxMessage,
    PCWSTR pszOption)
{
    WCHAR szOption[64];
    PWSTR pColon;

    StringCchCopyW(szOption, ARRAYSIZE(szOption), pszOption);
    pColon = wcschr(szOption, L':');
    if (pColon)
        *pColon = UNICODE_NULL;
    _wcsupr(szOption);

    return PrintCommandSyntax(dwSyntaxMessage, MSG_OPTION_UNKNOWN, szOption);
}


/* The syntax and help text without the leading line */
VOID
PrintCommandHelpText(
    DWORD dwSyntaxMessage,
    DWORD dwHelpMessage)
{
    PrintExeMessage(StdOut, dwSyntaxMessage, TRUE);
    PrintExeMessage(StdOut, dwHelpMessage, FALSE);
}


/* The text of NET command /HELP goes to standard output, unlike the syntax shown for an error */
VOID
PrintCommandHelp(
    DWORD dwSyntaxMessage,
    DWORD dwHelpMessage)
{
    PrintMessageString(4381);
    ConPuts(StdOut, L"\n");
    PrintCommandHelpText(dwSyntaxMessage, dwHelpMessage);
}


/* The text of a message in the resources of net.exe; free it with LocalFree */
PWSTR
GetExeMessage(
    DWORD dwMessage)
{
    PWSTR pBuffer = NULL;

    FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER |
                   FORMAT_MESSAGE_FROM_HMODULE |
                   FORMAT_MESSAGE_IGNORE_INSERTS,
                   GetModuleHandleW(NULL),
                   dwMessage,
                   LANG_USER_DEFAULT,
                   (LPWSTR)&pBuffer,
                   0,
                   NULL);
    return pBuffer;
}


/* Padding of any length: PrintPadding has a fixed buffer */
VOID
PrintSpaces(
    size_t nCount)
{
    while (nCount > 0)
    {
        DWORD nChunk = (DWORD)min(nCount, 256);

        PrintPadding(L' ', nChunk);
        nCount -= nChunk;
    }
}
