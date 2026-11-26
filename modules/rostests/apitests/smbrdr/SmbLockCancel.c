/*
 * PROJECT:     NitroOS
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Cancelled waiting byte-range locks on a share end, and leave no range locked at the server
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

/*
 * Needs a server: NITRO_SMB_LOCK_TEST_SHARE (\\server\share, a share the test may create a file in),
 * NITRO_SMB2_TEST_USER and NITRO_SMB2_TEST_PASSWORD (as libsmb2_apitest's server test); skipped
 * without them. NITRO_SMB_LOCK_TEST_ROUNDS: rounds per kind (default 500).
 *
 * Each round: a holder handle holds [100,200) exclusive; a second handle asks for the same range
 * and waits (no LOCKFILE_FAIL_IMMEDIATELY); the request is cancelled (CancelIoEx at once, the
 * issuing thread ending, CancelSynchronousIo of a synchronous waiter, the waiting handle closed).
 * The request must end within 5 s (Windows Server 2022 as a client: at once), and after it the
 * server must not hold the range for anybody but the holder: the holder lets it go and a third
 * handle takes it at once.
 */

#include <apitest.h>
#include <winnetwk.h>
#include <stdio.h>

#define LOCK_OFFSET 100
#define LOCK_LENGTH 100
#define END_LIMIT_MS 5000

static WCHAR File[MAX_PATH];

static HANDLE OpenShareFile(BOOL Overlapped)
{
    return CreateFileW(File, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_ALWAYS,
                       Overlapped ? FILE_FLAG_OVERLAPPED : 0, NULL);
}

static DWORD LockRange(HANDLE Handle, BOOL Wait)
{
    OVERLAPPED Ov = {0};
    DWORD Done, Error = ERROR_SUCCESS;

    Ov.Offset = LOCK_OFFSET;
    Ov.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!LockFileEx(Handle, LOCKFILE_EXCLUSIVE_LOCK | (Wait ? 0 : LOCKFILE_FAIL_IMMEDIATELY), 0, LOCK_LENGTH, 0, &Ov))
    {
        Error = GetLastError();
        if (Error == ERROR_IO_PENDING)
            Error = GetOverlappedResult(Handle, &Ov, &Done, TRUE) ? ERROR_SUCCESS : GetLastError();
    }
    CloseHandle(Ov.hEvent);
    return Error;
}

static DWORD UnlockRange(HANDLE Handle)
{
    OVERLAPPED Ov = {0};
    DWORD Done, Error = ERROR_SUCCESS;

    Ov.Offset = LOCK_OFFSET;
    Ov.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!UnlockFileEx(Handle, 0, LOCK_LENGTH, 0, &Ov))
    {
        Error = GetLastError();
        if (Error == ERROR_IO_PENDING)
            Error = GetOverlappedResult(Handle, &Ov, &Done, TRUE) ? ERROR_SUCCESS : GetLastError();
    }
    CloseHandle(Ov.hEvent);
    return Error;
}

typedef struct _WAITER
{
    HANDLE Handle;
    OVERLAPPED Ov;
    volatile LONG Issued;
    DWORD Error;
} WAITER, *PWAITER;

/* An overlapped waiting lock, then the thread ends (its I/O is cancelled) */
static DWORD WINAPI IssueAndEnd(LPVOID Param)
{
    PWAITER Waiter = Param;

    if (!LockFileEx(Waiter->Handle, LOCKFILE_EXCLUSIVE_LOCK, 0, LOCK_LENGTH, 0, &Waiter->Ov) &&
        GetLastError() != ERROR_IO_PENDING)
    {
        Waiter->Error = GetLastError();
        SetEvent(Waiter->Ov.hEvent);
    }
    return 0;
}

/* A synchronous waiting lock (CancelSynchronousIo ends it) */
static DWORD WINAPI IssueSync(LPVOID Param)
{
    PWAITER Waiter = Param;

    InterlockedExchange(&Waiter->Issued, 1);
    Waiter->Error = LockFileEx(Waiter->Handle, LOCKFILE_EXCLUSIVE_LOCK, 0, LOCK_LENGTH, 0, &Waiter->Ov) ?
                    ERROR_SUCCESS : GetLastError();
    return 0;
}

typedef enum _KIND { KindCancelIoEx, KindThreadEnd, KindCancelSynchronousIo, KindClose, KindMax } KIND;
static const char *KindName[KindMax] = { "CancelIoEx", "thread end", "CancelSynchronousIo", "handle closed" };

static void TestKind(HANDLE Holder, HANDLE Checker, KIND Kind, ULONG Rounds)
{
    ULONG Round, NotEnded = 0, Slow = 0, Granted = 0, Cancelled = 0, Other = 0, LeftLocked = 0;
    DWORD Error, Start, Took;
    HANDLE Waiter = INVALID_HANDLE_VALUE;

    for (Round = 0; Round < Rounds; Round++)
    {
        WAITER W;
        HANDLE Thread = NULL;
        BOOL Ended = FALSE;
        ULONG Try;
        HANDLE Stale = INVALID_HANDLE_VALUE, StaleEvent = NULL;

        ZeroMemory(&W, sizeof(W));
        W.Ov.Offset = LOCK_OFFSET;
        W.Ov.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
        if (Waiter == INVALID_HANDLE_VALUE)
            Waiter = OpenShareFile(Kind != KindCancelSynchronousIo);
        if (Waiter == INVALID_HANDLE_VALUE)
        {
            ok(0, "%s: open failed: %lu\n", KindName[Kind], GetLastError());
            CloseHandle(W.Ov.hEvent);
            break;
        }
        W.Handle = Waiter;
        Error = ERROR_SUCCESS;
        Start = GetTickCount();

        switch (Kind)
        {
            case KindCancelIoEx:
            case KindClose:
                if (LockFileEx(Waiter, LOCKFILE_EXCLUSIVE_LOCK, 0, LOCK_LENGTH, 0, &W.Ov))
                {
                    Ended = TRUE;
                    break;
                }
                if ((Error = GetLastError()) != ERROR_IO_PENDING)
                {
                    Ended = TRUE;
                    break;
                }
                Start = GetTickCount();
                if (Kind == KindCancelIoEx)
                {
                    CancelIoEx(Waiter, &W.Ov);
                }
                else
                {
                    CloseHandle(Waiter);
                    Waiter = INVALID_HANDLE_VALUE;
                }
                if (WaitForSingleObject(W.Ov.hEvent, 15000) == WAIT_OBJECT_0)
                {
                    Ended = TRUE;
                    Error = (W.Ov.Internal == 0) ? ERROR_SUCCESS :
                            ((DWORD)W.Ov.Internal == 0xC0000120 ? ERROR_OPERATION_ABORTED : (DWORD)W.Ov.Internal);
                }
                break;

            case KindThreadEnd:
                Thread = CreateThread(NULL, 0, IssueAndEnd, &W, 0, NULL);
                /* The thread's exit waits for its cancelled I/O: a lost cancel holds the thread too */
                Try = WaitForSingleObject(Thread, 15000);
                CloseHandle(Thread);
                Start = GetTickCount();
                if (Try == WAIT_OBJECT_0 && WaitForSingleObject(W.Ov.hEvent, 15000) == WAIT_OBJECT_0)
                {
                    Ended = TRUE;
                    Error = W.Error ? W.Error :
                            (W.Ov.Internal == 0 ? ERROR_SUCCESS :
                             ((DWORD)W.Ov.Internal == 0xC0000120 ? ERROR_OPERATION_ABORTED : (DWORD)W.Ov.Internal));
                }
                break;

            case KindCancelSynchronousIo:
                Thread = CreateThread(NULL, 0, IssueSync, &W, 0, NULL);
                while (!W.Issued)
                    Sleep(0);
                Sleep(1);
                Start = GetTickCount();
                for (Try = 0; Try < 15000; Try++)
                {
                    if (WaitForSingleObject(Thread, 0) == WAIT_OBJECT_0)
                        break;
                    if (!CancelSynchronousIo(Thread) && GetLastError() == ERROR_NOT_FOUND)
                    {
                        Sleep(1);
                        continue;
                    }
                    WaitForSingleObject(Thread, 15000);
                    break;
                }
                if (WaitForSingleObject(Thread, 0) == WAIT_OBJECT_0)
                {
                    Ended = TRUE;
                    Error = W.Error;
                }
                CloseHandle(Thread);
                /* A synchronous waiter is opened again for every round */
                if (Ended)
                {
                    CloseHandle(Waiter);
                    Waiter = INVALID_HANDLE_VALUE;
                }
                break;

            default:
                break;
        }

        Took = GetTickCount() - Start;
        if (!Ended)
        {
            NotEnded++;
            /* Still pending: once the holder lets the range go (below) the server grants it; then it is
             * released again, so that the next rounds start clean */
            Stale = Waiter;
            StaleEvent = W.Ov.hEvent;
            W.Ov.hEvent = NULL;
            Waiter = INVALID_HANDLE_VALUE;
        }
        else
        {
            if (Took > END_LIMIT_MS)
                Slow++;
            if (Error == ERROR_SUCCESS)
            {
                /* The server granted it before the cancel reached it: held, as the caller learns */
                Granted++;
                if (Waiter != INVALID_HANDLE_VALUE)
                    UnlockRange(Waiter);
            }
            else if (Error == ERROR_OPERATION_ABORTED || Kind == KindClose)
            {
                /* The request of a closed handle has ended; its status is not the caller's any more */
                Cancelled++;
            }
            else
            {
                Other++;
                trace("%s round %lu: error %lu\n", KindName[Kind], Round, Error);
            }
        }
        if (W.Ov.hEvent != NULL)
            CloseHandle(W.Ov.hEvent);

        /* The server's view: nobody but the holder may hold the range */
        UnlockRange(Holder);
        if (StaleEvent != NULL)
        {
            if (WaitForSingleObject(StaleEvent, 10000) == WAIT_OBJECT_0 && W.Ov.Internal == 0 &&
                Stale != INVALID_HANDLE_VALUE)
            {
                UnlockRange(Stale);
            }
            if (Stale != INVALID_HANDLE_VALUE)
                CloseHandle(Stale);
            CloseHandle(StaleEvent);
            Stale = INVALID_HANDLE_VALUE;
            StaleEvent = NULL;
            Sleep(200);
        }
        Error = LockRange(Checker, FALSE);
        if (Error == ERROR_SUCCESS)
        {
            UnlockRange(Checker);
        }
        else
        {
            LeftLocked++;
            if (Waiter != INVALID_HANDLE_VALUE)
            {
                CloseHandle(Waiter);
                Waiter = INVALID_HANDLE_VALUE;
            }
            Sleep(200);
        }
        for (Try = 0; Try < 50 && LockRange(Holder, FALSE) != ERROR_SUCCESS; Try++)
            Sleep(100);
    }

    if (Waiter != INVALID_HANDLE_VALUE)
        CloseHandle(Waiter);
    trace("%s: %lu rounds, %lu cancelled, %lu granted, %lu other, %lu not ended, %lu slow, %lu left locked\n",
          KindName[Kind], Rounds, Cancelled, Granted, Other, NotEnded, Slow, LeftLocked);
    ok(NotEnded == 0, "%s: %lu of %lu cancelled waiting locks did not end within 15 s\n", KindName[Kind], NotEnded, Rounds);
    ok(Slow == 0, "%s: %lu of %lu cancelled waiting locks ended after more than %u ms\n", KindName[Kind], Slow, Rounds, END_LIMIT_MS);
    ok(LeftLocked == 0, "%s: after %lu of %lu cancels the range stayed locked at the server\n", KindName[Kind], LeftLocked, Rounds);
    ok(Other == 0, "%s: %lu of %lu requests ended with another error\n", KindName[Kind], Other, Rounds);
}

START_TEST(SmbLockCancel)
{
    WCHAR Share[MAX_PATH], User[128], Password[128], Value[32];
    NETRESOURCEW Resource = {0};
    HANDLE Holder, Checker;
    ULONG Rounds = 500;
    DWORD Error;
    int Kind;

    if (!GetEnvironmentVariableW(L"NITRO_SMB_LOCK_TEST_SHARE", Share, _countof(Share)) ||
        !GetEnvironmentVariableW(L"NITRO_SMB2_TEST_USER", User, _countof(User)) ||
        !GetEnvironmentVariableW(L"NITRO_SMB2_TEST_PASSWORD", Password, _countof(Password)))
    {
        skip("NITRO_SMB_LOCK_TEST_SHARE/NITRO_SMB2_TEST_USER/NITRO_SMB2_TEST_PASSWORD not set\n");
        return;
    }
    if (GetEnvironmentVariableW(L"NITRO_SMB_LOCK_TEST_ROUNDS", Value, _countof(Value)))
        Rounds = wcstoul(Value, NULL, 10);

    Resource.dwType = RESOURCETYPE_DISK;
    Resource.lpRemoteName = Share;
    Error = WNetAddConnection2W(&Resource, Password, User, 0);
    SecureZeroMemory(Password, sizeof(Password));
    ok(Error == ERROR_SUCCESS || Error == ERROR_SESSION_CREDENTIAL_CONFLICT, "WNetAddConnection2W: %lu\n", Error);

    _snwprintf(File, _countof(File) - 1, L"%s\\smblockcancel-%lu.bin", Share, GetCurrentProcessId());
    Holder = OpenShareFile(TRUE);
    Checker = OpenShareFile(TRUE);
    ok(Holder != INVALID_HANDLE_VALUE && Checker != INVALID_HANDLE_VALUE, "open %S: %lu\n", File, GetLastError());
    if (Holder == INVALID_HANDLE_VALUE || Checker == INVALID_HANDLE_VALUE)
        goto Cleanup;
    ok(LockRange(Holder, FALSE) == ERROR_SUCCESS, "the holder's lock\n");

    for (Kind = 0; Kind < KindMax; Kind++)
        TestKind(Holder, Checker, (KIND)Kind, Rounds);

    UnlockRange(Holder);
    Error = LockRange(Checker, FALSE);
    ok(Error == ERROR_SUCCESS, "the range at the end: %lu\n", Error);
    if (Error == ERROR_SUCCESS)
        UnlockRange(Checker);

Cleanup:
    if (Checker != INVALID_HANDLE_VALUE)
        CloseHandle(Checker);
    if (Holder != INVALID_HANDLE_VALUE)
    {
        CloseHandle(Holder);
        DeleteFileW(File);
    }
    WNetCancelConnection2W(Share, 0, TRUE);
}
