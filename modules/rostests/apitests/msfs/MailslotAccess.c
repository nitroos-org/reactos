/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     MIT (https://spdx.org/licenses/MIT)
 * PURPOSE:     Mailslot opens are access checked against the descriptor of the mailslot (rows measured on Windows
 *              Server 2022: a client open is refused with ERROR_ACCESS_DENIED when the DACL grants the caller
 *              nothing, also to the owner for anything but READ_CONTROL and WRITE_DAC; the descriptor of a mailslot
 *              made without one is the token's default; GetSecurityInfo and SetSecurityInfo work on a mailslot)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include <apitest.h>
#include <windows.h>
#include <sddl.h>
#include <aclapi.h>

static HANDLE
MakeSlot(PCWSTR Name, PCWSTR Sddl)
{
    SECURITY_ATTRIBUTES Sa, *PSa = NULL;
    HANDLE Slot;

    if (Sddl)
    {
        ZeroMemory(&Sa, sizeof(Sa));
        Sa.nLength = sizeof(Sa);
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(Sddl, SDDL_REVISION_1, &Sa.lpSecurityDescriptor, NULL))
            return INVALID_HANDLE_VALUE;
        PSa = &Sa;
    }
    Slot = CreateMailslotW(Name, 0, MAILSLOT_WAIT_FOREVER, PSa);
    if (PSa)
        LocalFree(Sa.lpSecurityDescriptor);
    return Slot;
}

static DWORD
OpenError(PCWSTR Name, DWORD Access)
{
    HANDLE Client = CreateFileW(Name, Access, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    DWORD Error = Client == INVALID_HANDLE_VALUE ? GetLastError() : 0;

    if (Client != INVALID_HANDLE_VALUE)
        CloseHandle(Client);
    return Error;
}

START_TEST(MailslotAccess)
{
    static const WCHAR Name[] = L"\\\\.\\mailslot\\MsfsAccessApiTest";
    HANDLE Slot;
    PSECURITY_DESCRIPTOR Sd;
    PSID Owner = NULL;
    DWORD Status;

    /* Everyone full: every open works */
    Slot = MakeSlot(Name, L"D:(A;;GA;;;WD)");
    ok(Slot != INVALID_HANDLE_VALUE, "CreateMailslot failed: %lu\n", GetLastError());
    if (Slot == INVALID_HANDLE_VALUE)
        return;
    ok_dec(OpenError(Name, GENERIC_WRITE), 0);
    ok_dec(OpenError(Name, READ_CONTROL), 0);
    CloseHandle(Slot);

    /* Only SYSTEM: the creator, a plain user or an administrator alike, gets nothing but its implicit owner rights */
    Slot = MakeSlot(Name, L"D:(A;;GA;;;SY)");
    ok(Slot != INVALID_HANDLE_VALUE, "CreateMailslot failed: %lu\n", GetLastError());
    ok_dec(OpenError(Name, GENERIC_WRITE), ERROR_ACCESS_DENIED);
    ok_dec(OpenError(Name, FILE_WRITE_DATA), ERROR_ACCESS_DENIED);
    ok_dec(OpenError(Name, FILE_READ_ATTRIBUTES), ERROR_ACCESS_DENIED);
    CloseHandle(Slot);

    /* An empty DACL grants nothing */
    Slot = MakeSlot(Name, L"D:");
    ok(Slot != INVALID_HANDLE_VALUE, "CreateMailslot failed: %lu\n", GetLastError());
    ok_dec(OpenError(Name, GENERIC_WRITE), ERROR_ACCESS_DENIED);
    CloseHandle(Slot);

    /* Everyone: read and write data, no attributes: GENERIC_WRITE works, WRITE_DAC does not */
    Slot = MakeSlot(Name, L"D:(A;;FRFW;;;WD)");
    ok(Slot != INVALID_HANDLE_VALUE, "CreateMailslot failed: %lu\n", GetLastError());
    ok_dec(OpenError(Name, GENERIC_WRITE), 0);
    CloseHandle(Slot);

    /* A mailslot made without a descriptor gets the default of the creator's token: the creator opens it, and the
       descriptor can be read: the owner is the creator */
    Slot = MakeSlot(Name, NULL);
    ok(Slot != INVALID_HANDLE_VALUE, "CreateMailslot failed: %lu\n", GetLastError());
    ok_dec(OpenError(Name, GENERIC_WRITE), 0);
    Status = GetSecurityInfo(Slot, SE_KERNEL_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, &Owner, NULL, NULL, NULL, &Sd);
    ok_dec(Status, ERROR_SUCCESS);
    if (Status == ERROR_SUCCESS)
    {
        ok(Owner != NULL && IsValidSid(Owner), "no owner\n");
        LocalFree(Sd);
    }
    CloseHandle(Slot);

    /* WRITE_DAC on the handle changes who may open: grant Everyone read+write data (CreateFile adds FILE_READ_ATTRIBUTES), then it opens */
    Slot = MakeSlot(Name, L"D:(A;;GA;;;SY)");
    ok(Slot != INVALID_HANDLE_VALUE, "CreateMailslot failed: %lu\n", GetLastError());
    ok_dec(OpenError(Name, GENERIC_WRITE), ERROR_ACCESS_DENIED);
    {
        PSECURITY_DESCRIPTOR NewSd = NULL;
        PACL Dacl = NULL;
        BOOL Present, Defaulted;

        if (ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:(A;;FRFW;;;WD)", SDDL_REVISION_1, &NewSd, NULL) &&
            GetSecurityDescriptorDacl(NewSd, &Present, &Dacl, &Defaulted))
        {
            Status = SetSecurityInfo(Slot, SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, Dacl, NULL);
            ok_dec(Status, ERROR_SUCCESS);
            if (Status == ERROR_SUCCESS)
                ok_dec(OpenError(Name, GENERIC_WRITE), 0);
        }
        else
        {
            skip("cannot build the descriptor\n");
        }
        if (NewSd)
            LocalFree(NewSd);
    }
    CloseHandle(Slot);
}
