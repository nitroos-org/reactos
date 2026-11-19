/*
 * PROJECT:     ReactOS Setup Library
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Setup log of an unattended installation, text-mode stage.
 *              The messages (which answer file was used, which value was bad
 *              and what was used instead) are kept in memory while the target
 *              partition does not exist yet, and written to
 *              <installation directory>\Panther\unattend.log once it does.
 *              The graphical stage (syssetup) appends to the same file.
 *              A value of a secret key (a password) is never logged.
 */

/* INCLUDES *****************************************************************/

#include "precomp.h"
#include "filesup.h"

#include "setuplib.h"

#define NDEBUG
#include <debug.h>

/* GLOBALS ******************************************************************/

#define UNATTEND_LOG_SIZE   16384

static CHAR LogBuffer[UNATTEND_LOG_SIZE];
static ULONG LogLength = 0;

/* FUNCTIONS ****************************************************************/

VOID
NTAPI
SetupLogLine(
    _In_ PCSTR Text)
{
    SIZE_T Length;

    if (!Text)
        return;

    /* The serial/debug log shows it too (debug builds) */
    DbgPrint("SETUP: %s\n", Text);

    Length = strlen(Text);
    /* Keep room for the line break; a full buffer drops the rest, never overwrites */
    if (Length + 2 > UNATTEND_LOG_SIZE - LogLength)
        return;
    RtlCopyMemory(LogBuffer + LogLength, Text, Length);
    LogLength += (ULONG)Length;
    LogBuffer[LogLength++] = '\r';
    LogBuffer[LogLength++] = '\n';
}

VOID
SetupLogFormat(
    _In_ PCSTR Format,
    ...)
{
    CHAR Text[300];
    va_list Args;

    va_start(Args, Format);
    RtlStringCbVPrintfA(Text, sizeof(Text), Format, Args);
    va_end(Args);
    SetupLogLine(Text);
}

/*
 * Value parsers of the answer file. Pure functions: no side effect, nothing
 * logged here (the caller names the key in its message).
 */

/* yes/no, true/false, on/off, 1/0 (any case, surrounding blanks allowed) */
BOOLEAN
NTAPI
UnattendParseBool(
    _In_ PCWSTR Value,
    _Out_ PLONG Result)
{
    static const struct { PCWSTR Text; LONG Flag; } Words[] = {
        {L"yes", 1}, {L"true", 1}, {L"on", 1}, {L"1", 1},
        {L"no", 0}, {L"false", 0}, {L"off", 0}, {L"0", 0},
    };
    WCHAR Text[8];
    SIZE_T Length, i;

    while (*Value == L' ' || *Value == L'\t')
        ++Value;
    Length = wcslen(Value);
    while (Length && (Value[Length - 1] == L' ' || Value[Length - 1] == L'\t'))
        --Length;
    if (!Length || Length >= RTL_NUMBER_OF(Text))
        return FALSE;
    RtlCopyMemory(Text, Value, Length * sizeof(WCHAR));
    Text[Length] = UNICODE_NULL;

    for (i = 0; i < RTL_NUMBER_OF(Words); ++i)
    {
        if (!_wcsicmp(Text, Words[i].Text))
        {
            *Result = Words[i].Flag;
            return TRUE;
        }
    }
    return FALSE;
}

/* A decimal number, 0 .. Max, digits only (surrounding blanks allowed) */
BOOLEAN
NTAPI
UnattendParseUInt(
    _In_ PCWSTR Value,
    _In_ ULONG Max,
    _Out_ PULONG Result)
{
    ULONGLONG Number = 0;
    BOOLEAN Any = FALSE;

    while (*Value == L' ' || *Value == L'\t')
        ++Value;
    for (; *Value >= L'0' && *Value <= L'9'; ++Value)
    {
        Number = Number * 10 + (*Value - L'0');
        Any = TRUE;
        if (Number > Max)
            return FALSE;
    }
    while (*Value == L' ' || *Value == L'\t')
        ++Value;
    if (!Any || *Value)
        return FALSE;
    *Result = (ULONG)Number;
    return TRUE;
}

/* A keyboard layout id: 8 hexadecimal digits ("00000407"), or the 4 of a language id ("0407" or "407") */
BOOLEAN
NTAPI
UnattendParseKeyboardLayout(
    _In_ PCWSTR Value,
    _Out_writes_(9) PWSTR Klid)
{
    SIZE_T Length = wcslen(Value), i;

    if (Length < 3 || Length > 8)
        return FALSE;
    for (i = 0; i < Length; ++i)
    {
        if (!((Value[i] >= L'0' && Value[i] <= L'9') ||
              (Value[i] >= L'a' && Value[i] <= L'f') ||
              (Value[i] >= L'A' && Value[i] <= L'F')))
            return FALSE;
    }
    if (Length > 4 && Length != 8)
        return FALSE;
    for (i = 0; i < 8 - Length; ++i)
        Klid[i] = L'0';
    for (i = 0; i < Length; ++i)
        Klid[8 - Length + i] = Value[i];
    Klid[8] = UNICODE_NULL;
    return TRUE;
}

/**
 * @brief
 * Write the collected messages to <DestinationPath>\Panther\unattend.log.
 * Called once the installation directory exists; a failure is not an error
 * of the installation.
 **/
NTSTATUS
NTAPI
SetupLogWrite(
    _In_ PCWSTR DestinationPath)
{
    NTSTATUS Status;
    WCHAR PathBuffer[MAX_PATH];
    UNICODE_STRING FileName;
    OBJECT_ATTRIBUTES ObjectAttributes;
    IO_STATUS_BLOCK IoStatusBlock;
    HANDLE FileHandle;

    if (!LogLength)
        return STATUS_SUCCESS;

    Status = CombinePaths(PathBuffer, ARRAYSIZE(PathBuffer), 2, DestinationPath, L"Panther");
    if (!NT_SUCCESS(Status))
        return Status;
    Status = SetupCreateDirectory(PathBuffer);
    if (!NT_SUCCESS(Status))
        DPRINT1("SetupLogWrite: cannot create '%S' (Status 0x%08lx)\n", PathBuffer, Status);

    Status = CombinePaths(PathBuffer, ARRAYSIZE(PathBuffer), 2, DestinationPath, L"Panther\\unattend.log");
    if (!NT_SUCCESS(Status))
        return Status;

    RtlInitUnicodeString(&FileName, PathBuffer);
    InitializeObjectAttributes(&ObjectAttributes, &FileName, OBJ_CASE_INSENSITIVE, NULL, NULL);
    Status = NtCreateFile(&FileHandle,
                          FILE_WRITE_DATA | SYNCHRONIZE,
                          &ObjectAttributes,
                          &IoStatusBlock,
                          NULL,
                          FILE_ATTRIBUTE_NORMAL,
                          0,
                          FILE_OVERWRITE_IF,
                          FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
                          NULL,
                          0);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("SetupLogWrite: cannot create '%S' (Status 0x%08lx)\n", PathBuffer, Status);
        return Status;
    }

    Status = NtWriteFile(FileHandle, NULL, NULL, NULL, &IoStatusBlock,
                         LogBuffer, LogLength, NULL, NULL);
    NtClose(FileHandle);
    return Status;
}

/* EOF */
