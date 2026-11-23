/*
 * PROJECT:     ReactOS
 * LICENSE:     GPL - See COPYING in the top level directory
 * PURPOSE:     Audio Service Plug and Play list locking mechanism
 * COPYRIGHT:   Copyright 2007 Andrew Greenwood
 */

#include "audiosrv.h"

#include <assert.h>
#include <sddl.h>
#include <namedobjtrust.h>

#define NDEBUG
#include <debug.h>

static HANDLE audio_device_list_lock = NULL;

/*
 * The lock of the list is the service's: SYSTEM and the Administrators only (it had a NULL DACL: anyone could take
 * it and stall the service). A lock of that name that someone else made first (any process can create objects in
 * the named object directory, Low integrity ones too) is not used: the service takes an unnamed one of its own.
 */
BOOL
InitializeAudioDeviceListLock(VOID)
{
    SECURITY_ATTRIBUTES security;

    security.nLength = sizeof(SECURITY_ATTRIBUTES);
    security.lpSecurityDescriptor = NULL;
    security.bInheritHandle = FALSE;
    ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:P(A;;GA;;;SY)(A;;GA;;;BA)", SDDL_REVISION_1,
                                                         &security.lpSecurityDescriptor, NULL);

    audio_device_list_lock = CreateMutexW(security.lpSecurityDescriptor ? &security : NULL,
                                          FALSE,
                                          AUDIO_LIST_LOCK_NAME);
    if (audio_device_list_lock && GetLastError() == ERROR_ALREADY_EXISTS &&
        !NamedObjectIsTrusted(audio_device_list_lock, TRUE))
    {
        DPRINT1("audiosrv: %S was made by another process, using a private lock\n", AUDIO_LIST_LOCK_NAME);
        CloseHandle(audio_device_list_lock);
        audio_device_list_lock = CreateMutexW(NULL, FALSE, NULL);
    }

    if (security.lpSecurityDescriptor)
        LocalFree(security.lpSecurityDescriptor);
    return (audio_device_list_lock != NULL);
}

VOID
KillAudioDeviceListLock(VOID)
{
    CloseHandle(audio_device_list_lock);
    audio_device_list_lock = NULL;
}

VOID
LockAudioDeviceList(VOID)
{
    assert(audio_device_list_lock != NULL);
    WaitForSingleObject(audio_device_list_lock, INFINITE);
}

VOID
UnlockAudioDeviceList(VOID)
{
    assert(audio_device_list_lock != NULL);
    ReleaseMutex(audio_device_list_lock);
}
