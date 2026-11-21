/*
 * PROJECT:         ReactOS msgina.dll
 * FILE:            dll/win32/msgina/tui.c
 * PURPOSE:         ReactOS Logon GINA DLL
 * PROGRAMMER:      Hervé Poussineau (hpoussin@reactos.org)
 */

#include "msgina.h"

#include <wincon.h>

static BOOL
TUIInitialize(
    IN OUT PGINA_CONTEXT pgContext)
{
    TRACE("TUIInitialize(%p)\n", pgContext);

    return AllocConsole();
}

static BOOL
TUIDisplayStatusMessage(
    IN PGINA_CONTEXT pgContext,
    IN HDESK hDesktop,
    IN DWORD dwOptions,
    IN PWSTR pTitle,
    IN PWSTR pMessage)
{
    static LPCWSTR newLine = L"\n";
    DWORD result;

    TRACE("TUIDisplayStatusMessage(%ws)\n", pMessage);

    UNREFERENCED_PARAMETER(pgContext);
    UNREFERENCED_PARAMETER(hDesktop);
    UNREFERENCED_PARAMETER(dwOptions);
    UNREFERENCED_PARAMETER(pTitle);

    return
        WriteConsoleW(
            GetStdHandle(STD_OUTPUT_HANDLE),
            pMessage,
            wcslen(pMessage),
            &result,
            NULL) &&
        WriteConsoleW(
            GetStdHandle(STD_OUTPUT_HANDLE),
            newLine,
            wcslen(newLine),
            &result,
            NULL);
}

static BOOL
TUIRemoveStatusMessage(
    IN PGINA_CONTEXT pgContext)
{
    UNREFERENCED_PARAMETER(pgContext);

    /* Nothing to do */
    return TRUE;
}

static BOOL
DisplayResourceText(
    IN UINT uIdResourceText,
    IN BOOL AddNewLine)
{
    WCHAR Prompt[256];
    static LPCWSTR newLine = L"\n";
    DWORD count;

    if (0 == LoadStringW(hDllInstance, uIdResourceText, Prompt, _countof(Prompt)))
        return FALSE;
    if (!WriteConsoleW(
        GetStdHandle(STD_OUTPUT_HANDLE),
        Prompt, wcslen(Prompt),
        &count, NULL))
    {
        return FALSE;
    }
    if (AddNewLine)
    {
        if (!WriteConsoleW(
            GetStdHandle(STD_OUTPUT_HANDLE),
            newLine, wcslen(newLine),
            &count, NULL))
        {
            return FALSE;
        }
    }
    return TRUE;
}

static VOID
TUIDisplaySASNotice(
    IN OUT PGINA_CONTEXT pgContext)
{
    TRACE("TUIDisplaySASNotice()\n");

    UNREFERENCED_PARAMETER(pgContext);

    DisplayResourceText(IDS_LOGGEDOUTSAS, TRUE);
    DisplayResourceText(IDS_PRESSCTRLALTDELETE, TRUE);
}

static INT
TUILoggedOnSAS(
    IN OUT PGINA_CONTEXT pgContext,
    IN DWORD dwSasType)
{
    TRACE("TUILoggedOnSAS()\n");

    UNREFERENCED_PARAMETER(pgContext);

    if (dwSasType != WLX_SAS_TYPE_CTRL_ALT_DEL)
    {
        /* Nothing to do for WLX_SAS_TYPE_TIMEOUT */
        return WLX_SAS_ACTION_NONE;
    }

    FIXME("FIXME: TUILoggedOnSAS(): Let's suppose the user wants to log off...\n");
    return WLX_SAS_ACTION_LOGOFF;
}

static BOOL
ReadString(
    IN UINT uIdResourcePrompt,
    IN OUT PWSTR Buffer,
    IN DWORD BufferLength,
    IN BOOL ShowString)
{
    DWORD count, i;
    DWORD Extra = 0;    /* characters typed that did not fit (the input is refused while there are any) */
    WCHAR charToDisplay[] = { 0, UNICODE_NULL };

    if (!SetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), 0))
        return FALSE;

    if (!FlushConsoleInputBuffer(GetStdHandle(STD_INPUT_HANDLE)))
        return FALSE;

    if (!DisplayResourceText(uIdResourcePrompt, FALSE))
        return FALSE;

    i = 0;
    for (;;)
    {
        WCHAR readChar;
        if (!ReadConsoleW(GetStdHandle(STD_INPUT_HANDLE), &readChar, 1, &count, NULL))
        {
            SecureZeroMemory(Buffer, BufferLength * sizeof(WCHAR));
            return FALSE;
        }
        if (readChar == '\r' || readChar == '\n')
        {
            /* End of string */
            charToDisplay[0] = L'\n';
            WriteConsoleW(
                GetStdHandle(STD_OUTPUT_HANDLE),
                charToDisplay,
                wcslen(charToDisplay),
                &count,
                NULL);
            break;
        }
        if (readChar == L'\b')
        {
            /* Take the last typed character back (first one that did not fit, then the stored ones) */
            if (Extra > 0)
                Extra--;
            else if (i > 0)
                i--;
            else
                continue;

            if (ShowString)
            {
                /* Wipe it from the screen: back, blank, back */
                WriteConsoleW(
                    GetStdHandle(STD_OUTPUT_HANDLE),
                    L"\b \b",
                    3,
                    &count,
                    NULL);
            }
            continue;
        }
        if (ShowString)
        {
            /* Display the char */
            charToDisplay[0] = readChar;
            WriteConsoleW(
                GetStdHandle(STD_OUTPUT_HANDLE),
                charToDisplay,
                wcslen(charToDisplay),
                &count,
                NULL);
        }
        /* The buffer is the caller's and fixed: an input that does not fit is refused, not written past its end */
        if (i + 1 < BufferLength)
            Buffer[i++] = readChar;
        else
            Extra++;
    }
    Buffer[i] = UNICODE_NULL;

    if (Extra > 0)
    {
        SecureZeroMemory(Buffer, BufferLength * sizeof(WCHAR));
        return FALSE;
    }

    if (!ShowString)
    {
        /* Still display the \n */
        static LPCWSTR newLine = L"\n";
        DWORD result;
        WriteConsoleW(
            GetStdHandle(STD_OUTPUT_HANDLE),
            newLine,
            wcslen(newLine),
            &result,
            NULL);
    }
    return TRUE;
}

static INT
TUILoggedOutSAS(
    IN OUT PGINA_CONTEXT pgContext)
{
    WCHAR UserName[256];
    WCHAR Password[256];
    NTSTATUS Status;
    NTSTATUS SubStatus = STATUS_SUCCESS;
    INT Action = WLX_SAS_ACTION_NONE;

    TRACE("TUILoggedOutSAS()\n");

    /* Ask the user for credentials */
    if (!ReadString(IDS_ASKFORUSER, UserName, _countof(UserName), TRUE))
        return WLX_SAS_ACTION_NONE;
    if (!ReadString(IDS_ASKFORPASSWORD, Password, _countof(Password), FALSE))
        return WLX_SAS_ACTION_NONE;

    Status = DoLoginTasks(pgContext, UserName, NULL, Password, &SubStatus);
    if (Status == STATUS_SUCCESS)
    {
        if (CreateProfile(pgContext, UserName, NULL, Password))
            Action = WLX_SAS_ACTION_LOGON;
    }

    /* The logon attempt is over: no password stays in this function or in the context (the stored automatic
       logon password that was read into it at start-up is not used by the text mode logon) */
    SecureZeroMemory(Password, sizeof(Password));
    SecureZeroMemory(pgContext->Password, sizeof(pgContext->Password));
    return Action;
}

static INT
TUILockedSAS(
    IN OUT PGINA_CONTEXT pgContext)
{
    WCHAR UserName[256];
    WCHAR Password[256];
    PCWSTR AccountName;
    BOOL IsSessionUser;
    NTSTATUS SubStatus;
    NTSTATUS Status;
    INT Action = WLX_SAS_ACTION_NONE;

    TRACE("TUILockedSAS()\n");

    /* A notice that cannot be shown does not unlock the workstation: the credentials are asked for all the same */
    DisplayResourceText(IDS_LOGGEDOUTSAS, TRUE);

    /* Ask the user for credentials */
    if (!ReadString(IDS_ASKFORUSER, UserName, _countof(UserName), TRUE))
        return WLX_SAS_ACTION_NONE;
    if (!ReadString(IDS_ASKFORPASSWORD, Password, _countof(Password), FALSE))
        return WLX_SAS_ACTION_NONE;

    /* Only the user of the session unlocks. The name of another account is refused without a logon attempt (no
       password is checked, nothing is counted against any account); the LSA checks the password of the session's
       user (an Unlock logon) */
    AccountName = GetUnlockUserName(pgContext, UserName);
    if (AccountName != NULL)
    {
        Status = DoUnlockLogon(pgContext, (PWSTR)AccountName, Password, &IsSessionUser, &SubStatus);
        if (NT_SUCCESS(Status))
        {
            if (IsSessionUser)
                Action = WLX_SAS_ACTION_UNLOCK_WKSTA;
        }
        else
        {
            WARN("DoUnlockLogon() failed (Status 0x%08lx)\n", Status);
        }
    }

    SecureZeroMemory(Password, sizeof(Password));
    return Action;
}

static VOID
TUIDisplayLockedNotice(
    IN OUT PGINA_CONTEXT pgContext)
{
}

GINA_UI GinaTextUI = {
    TUIInitialize,
    TUIDisplayStatusMessage,
    TUIRemoveStatusMessage,
    TUIDisplaySASNotice,
    TUILoggedOnSAS,
    TUILoggedOutSAS,
    TUILockedSAS,
    TUIDisplayLockedNotice,
};
