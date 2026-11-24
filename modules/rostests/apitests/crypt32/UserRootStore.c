/*
 * PROJECT:     ReactOS API Tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Adding a certificate to the Root store of the current user (or removing it) asks the user
 * COPYRIGHT:   Copyright 2026 Tomas Srnka (tomas.srnka@e2b.dev)
 *
 * Measured on Windows Server 2022 with the same calls: CertAddCertificateContextToStore into
 * CertOpenStore(CERT_STORE_PROV_SYSTEM, CERT_SYSTEM_STORE_CURRENT_USER, "Root") shows a dialog with the name and the
 * fingerprint of the certificate; the answer Yes adds it, the answer No (or a closed dialog) fails the call with
 * ERROR_CANCELLED and adds nothing; CERT_STORE_ADD_NEW of a certificate that is there fails with CRYPT_E_EXISTS
 * without a dialog; CERT_STORE_ADD_REPLACE_EXISTING of one that is there asks about removing the old one first, then
 * about adding the new one; CertDeleteCertificateFromStore asks too (Yes removes, No: ERROR_CANCELLED). A process whose
 * window station is not visible (a service, a remote shell) cannot be asked: add and delete fail with
 * ERROR_NOT_SUPPORTED and change nothing. The machine's Root store is not asked.
 *
 * The dialogs are answered by a thread of the test itself (the buttons of the dialogs of this process); in a process
 * without a visible window station only the refusal is tested. The certificate is a throw-away self-signed root made
 * with openssl for these tests (RSA 1024, SHA-256, valid 2026-2046); it is removed again at the end.
 */

#define WIN32_NO_STATUS
#define _INC_WINDOWS
#define COM_NO_WINDOWS_H

#include <apitest.h>
#include <windef.h>
#include <winbase.h>
#include <winuser.h>
#include <wincrypt.h>

static const BYTE RootDer[] =
{
    0x30, 0x82, 0x02, 0x07, 0x30, 0x82, 0x01, 0x70, 0xa0, 0x03, 0x02, 0x01,
    0x02, 0x02, 0x14, 0x1e, 0x7e, 0xd7, 0xf8, 0x9d, 0xff, 0x6d, 0xbb, 0x80,
    0xe9, 0x48, 0x40, 0x90, 0xa0, 0xe5, 0xc6, 0xbd, 0x69, 0x7b, 0x80, 0x30,
    0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b,
    0x05, 0x00, 0x30, 0x1e, 0x31, 0x1c, 0x30, 0x1a, 0x06, 0x03, 0x55, 0x04,
    0x03, 0x0c, 0x13, 0x6b, 0x62, 0x31, 0x36, 0x20, 0x75, 0x73, 0x65, 0x72,
    0x20, 0x72, 0x6f, 0x6f, 0x74, 0x20, 0x74, 0x65, 0x73, 0x74, 0x30, 0x1e,
    0x17, 0x0d, 0x32, 0x36, 0x31, 0x31, 0x32, 0x34, 0x30, 0x32, 0x31, 0x38,
    0x34, 0x32, 0x5a, 0x17, 0x0d, 0x34, 0x36, 0x31, 0x31, 0x31, 0x39, 0x30,
    0x32, 0x31, 0x38, 0x34, 0x32, 0x5a, 0x30, 0x1e, 0x31, 0x1c, 0x30, 0x1a,
    0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x13, 0x6b, 0x62, 0x31, 0x36, 0x20,
    0x75, 0x73, 0x65, 0x72, 0x20, 0x72, 0x6f, 0x6f, 0x74, 0x20, 0x74, 0x65,
    0x73, 0x74, 0x30, 0x81, 0x9f, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48,
    0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x81, 0x8d, 0x00,
    0x30, 0x81, 0x89, 0x02, 0x81, 0x81, 0x00, 0xd8, 0xe0, 0xc2, 0x00, 0x6d,
    0xc3, 0x85, 0xf2, 0x80, 0x68, 0x98, 0x62, 0x0d, 0xbf, 0x72, 0x9f, 0x30,
    0x4e, 0xe4, 0xf4, 0x3a, 0xd5, 0xed, 0x2f, 0x18, 0xf4, 0x75, 0x34, 0x38,
    0xa4, 0xa1, 0xce, 0x05, 0x97, 0x41, 0x4e, 0x95, 0x0a, 0x5a, 0x9e, 0xb0,
    0xc0, 0x00, 0x18, 0x2a, 0x3c, 0xe7, 0x91, 0xd3, 0xc5, 0xb0, 0x8d, 0xf7,
    0xc7, 0xdf, 0x25, 0x5b, 0xc3, 0x2b, 0xfc, 0xcd, 0x0c, 0xe9, 0xeb, 0x53,
    0xcc, 0xcc, 0x7e, 0x30, 0xc6, 0xfe, 0x90, 0xbc, 0x0d, 0x45, 0xdb, 0x98,
    0x43, 0x5e, 0xf7, 0x46, 0x6c, 0xa6, 0xff, 0x9f, 0x52, 0x42, 0x96, 0x1a,
    0x1c, 0x7e, 0xfb, 0xac, 0x73, 0x49, 0xe1, 0x0d, 0xd2, 0xc7, 0xd7, 0xce,
    0xaa, 0x29, 0x62, 0xab, 0x40, 0x72, 0x64, 0x61, 0x45, 0x08, 0x0d, 0x55,
    0x59, 0x64, 0xf0, 0xd6, 0xef, 0x84, 0x31, 0x01, 0x75, 0x86, 0xe1, 0x05,
    0x40, 0x37, 0x9d, 0x02, 0x03, 0x01, 0x00, 0x01, 0xa3, 0x42, 0x30, 0x40,
    0x30, 0x0f, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x05,
    0x30, 0x03, 0x01, 0x01, 0xff, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x1d, 0x0f,
    0x01, 0x01, 0xff, 0x04, 0x04, 0x03, 0x02, 0x01, 0x06, 0x30, 0x1d, 0x06,
    0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0xba, 0x69, 0xa6, 0x61,
    0xfa, 0x5d, 0x51, 0xdb, 0xc3, 0xa1, 0xb2, 0x37, 0xdd, 0x2e, 0x03, 0xeb,
    0x09, 0xef, 0x5d, 0x4c, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
    0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x03, 0x81, 0x81, 0x00, 0x78,
    0x9f, 0x65, 0x0a, 0xe0, 0x3c, 0xaf, 0x17, 0x51, 0x82, 0x44, 0xbf, 0x86,
    0x71, 0x43, 0xa9, 0x24, 0x82, 0x14, 0x51, 0x86, 0xc1, 0xd4, 0xff, 0x05,
    0x62, 0xd6, 0x6e, 0x9c, 0xd4, 0x7a, 0x0e, 0x99, 0xf3, 0xcc, 0xa1, 0xb6,
    0x33, 0x23, 0x88, 0x06, 0x03, 0x5a, 0xd8, 0x6d, 0x98, 0xe7, 0x65, 0xf3,
    0xae, 0x6f, 0xcb, 0xb9, 0x6e, 0xf8, 0x93, 0xc7, 0x4a, 0x53, 0x8c, 0x3d,
    0xf6, 0x06, 0xbc, 0x90, 0xf2, 0xc5, 0x67, 0x9c, 0x1c, 0x75, 0x64, 0xdb,
    0x65, 0xbc, 0x22, 0xc0, 0x20, 0x2b, 0x45, 0x18, 0x80, 0xf3, 0x03, 0xb3,
    0x77, 0xf7, 0x77, 0xc6, 0x11, 0xd7, 0xd9, 0x4c, 0x62, 0xdf, 0x68, 0xc6,
    0x9b, 0x7a, 0x15, 0x4f, 0xda, 0x73, 0xb0, 0xa0, 0x19, 0x23, 0xd7, 0x9c,
    0x4d, 0xab, 0xaa, 0xba, 0x0d, 0x86, 0x31, 0x86, 0xe9, 0x58, 0xfa, 0xa9,
    0x1b, 0xea, 0xc8, 0xc3, 0x64, 0x56, 0xa3
};

/* The answers the helper thread gives to the dialogs that appear, in order: 'y' Yes, 'n' No */
static const char *g_Answers;
static volatile LONG g_Shown;       /* the number of dialogs answered */
static volatile LONG g_Stop;
static HANDLE g_Thread;

static BOOL CALLBACK FindButton(HWND hwnd, LPARAM lParam)
{
    HWND *result = (HWND *)lParam;
    WCHAR text[32], *src, *dst;
    char cls[16];

    GetClassNameA(hwnd, cls, sizeof(cls));
    if (lstrcmpiA(cls, "Button"))
        return TRUE;
    GetWindowTextW(hwnd, text, ARRAYSIZE(text));
    /* the text without the underlined letter's '&' */
    for (src = dst = text; (*dst = *src) != 0; src++)
        if (*dst != '&')
            dst++;
    if (!lstrcmpiW(text, L"Yes") && g_Answers[g_Shown] == 'y')
        *result = hwnd;
    else if (!lstrcmpiW(text, L"No") && g_Answers[g_Shown] == 'n')
        *result = hwnd;
    return TRUE;
}

static BOOL CALLBACK FindDialog(HWND hwnd, LPARAM lParam)
{
    DWORD pid = 0;
    char cls[16];
    HWND button = NULL;

    GetWindowThreadProcessId(hwnd, &pid);
    if (pid != GetCurrentProcessId() || !IsWindowVisible(hwnd))
        return TRUE;
    GetClassNameA(hwnd, cls, sizeof(cls));
    if (lstrcmpA(cls, "#32770"))
        return TRUE;
    if (!g_Answers[g_Shown])
        return TRUE;
    EnumChildWindows(hwnd, FindButton, (LPARAM)&button);
    if (button)
    {
        SendMessageW(button, BM_CLICK, 0, 0);
        InterlockedIncrement(&g_Shown);
        *(BOOL *)lParam = TRUE;
        return FALSE;
    }
    return TRUE;
}

static DWORD WINAPI Answerer(PVOID Param)
{
    while (!g_Stop)
    {
        BOOL clicked = FALSE;

        EnumWindows(FindDialog, (LPARAM)&clicked);
        Sleep(clicked ? 300 : 50);
    }
    return 0;
}

static void StartAnswers(const char *answers)
{
    g_Answers = answers;
    g_Shown = 0;
    g_Stop = 0;
    g_Thread = CreateThread(NULL, 0, Answerer, NULL, 0, NULL);
}

/* Returns the number of dialogs that were answered */
static LONG EndAnswers(void)
{
    LONG shown;

    Sleep(100);
    g_Stop = 1;
    WaitForSingleObject(g_Thread, 5000);
    CloseHandle(g_Thread);
    g_Thread = NULL;
    shown = g_Shown;
    g_Answers = "";
    return shown;
}

static int CountCerts(HCERTSTORE Store)
{
    PCCERT_CONTEXT Ctx = NULL;
    int Count = 0;

    while ((Ctx = CertEnumCertificatesInStore(Store, Ctx)) != NULL)
        Count++;
    return Count;
}

static BOOL IsInStore(HCERTSTORE Store, PCCERT_CONTEXT Cert)
{
    PCCERT_CONTEXT Found = CertFindCertificateInStore(Store, X509_ASN_ENCODING, 0, CERT_FIND_EXISTING, Cert, NULL);

    if (Found)
        CertFreeCertificateContext(Found);
    return Found != NULL;
}

static BOOL HasVisibleStation(void)
{
    USEROBJECTFLAGS Flags;
    DWORD Needed;

    return GetUserObjectInformationA(GetProcessWindowStation(), UOI_FLAGS, &Flags, sizeof(Flags), &Needed) &&
           (Flags.dwFlags & WSF_VISIBLE);
}

START_TEST(UserRootStore)
{
    PCCERT_CONTEXT Root;
    HCERTSTORE Store, Machine;
    PCCERT_CONTEXT Found;
    BOOL Ret;
    LONG Shown;
    int Before;

    Root = CertCreateCertificateContext(X509_ASN_ENCODING, RootDer, sizeof(RootDer));
    ok(Root != NULL, "CertCreateCertificateContext failed: %lu\n", GetLastError());
    if (!Root)
        return;

    Store = CertOpenStore(CERT_STORE_PROV_SYSTEM_W, 0, 0, CERT_SYSTEM_STORE_CURRENT_USER, L"Root");
    ok(Store != NULL, "CertOpenStore failed: %lu\n", GetLastError());
    if (!Store)
        return;

    /* A copy left behind by an earlier run that did not finish: removed through the registry-level answer Yes */
    if (HasVisibleStation() && IsInStore(Store, Root))
    {
        StartAnswers("y");
        Found = CertFindCertificateInStore(Store, X509_ASN_ENCODING, 0, CERT_FIND_EXISTING, Root, NULL);
        CertDeleteCertificateFromStore(Found);
        EndAnswers();
    }
    Before = CountCerts(Store);

    if (!HasVisibleStation())
    {
        /* Nobody can be asked: the call is refused, nothing changes */
        SetLastError(0xdeadbeef);
        Ret = CertAddCertificateContextToStore(Store, Root, CERT_STORE_ADD_REPLACE_EXISTING, NULL);
        ok(!Ret, "The add succeeded without a visible window station\n");
        ok(GetLastError() == ERROR_NOT_SUPPORTED, "Error is %lu, expected ERROR_NOT_SUPPORTED\n", GetLastError());
        ok(CountCerts(Store) == Before && !IsInStore(Store, Root), "The store changed\n");
        SetLastError(0xdeadbeef);
        Ret = CertAddEncodedCertificateToStore(Store, X509_ASN_ENCODING, RootDer, sizeof(RootDer),
                                               CERT_STORE_ADD_REPLACE_EXISTING, NULL);
        ok(!Ret && GetLastError() == ERROR_NOT_SUPPORTED, "CertAddEncodedCertificateToStore: %d, error %lu\n",
           Ret, GetLastError());
        skip("The process has no visible window station: the dialogs are not tested\n");
    }
    else
    {
        /* No: nothing is added */
        StartAnswers("n");
        SetLastError(0xdeadbeef);
        Ret = CertAddCertificateContextToStore(Store, Root, CERT_STORE_ADD_REPLACE_EXISTING, NULL);
        Shown = EndAnswers();
        ok(!Ret, "The add succeeded after No\n");
        ok(GetLastError() == ERROR_CANCELLED, "Error is %lu, expected ERROR_CANCELLED\n", GetLastError());
        ok(Shown == 1, "%ld dialogs\n", Shown);
        ok(CountCerts(Store) == Before && !IsInStore(Store, Root), "The store changed\n");

        /* Yes: added */
        StartAnswers("y");
        Ret = CertAddCertificateContextToStore(Store, Root, CERT_STORE_ADD_REPLACE_EXISTING, NULL);
        Shown = EndAnswers();
        ok(Ret, "The add failed after Yes: %lu\n", GetLastError());
        ok(Shown == 1, "%ld dialogs\n", Shown);
        ok(CountCerts(Store) == Before + 1 && IsInStore(Store, Root), "The certificate is not in the store\n");

        /* CERT_STORE_ADD_NEW of a certificate that is there: no dialog */
        StartAnswers("n");
        SetLastError(0xdeadbeef);
        Ret = CertAddCertificateContextToStore(Store, Root, CERT_STORE_ADD_NEW, NULL);
        Shown = EndAnswers();
        ok(!Ret && GetLastError() == CRYPT_E_EXISTS, "ADD_NEW of an existing certificate: %d, error %lx\n", Ret, GetLastError());
        ok(Shown == 0, "%ld dialogs\n", Shown);

        /* Replacing it asks twice: about removing the old one, then about adding the new one; No to the first */
        StartAnswers("n");
        SetLastError(0xdeadbeef);
        Ret = CertAddCertificateContextToStore(Store, Root, CERT_STORE_ADD_REPLACE_EXISTING, NULL);
        Shown = EndAnswers();
        ok(!Ret && GetLastError() == ERROR_CANCELLED, "Replace, No: %d, error %lu\n", Ret, GetLastError());
        ok(Shown == 1, "%ld dialogs\n", Shown);
        ok(IsInStore(Store, Root), "The certificate is gone\n");
        StartAnswers("yy");
        Ret = CertAddCertificateContextToStore(Store, Root, CERT_STORE_ADD_REPLACE_EXISTING, NULL);
        Shown = EndAnswers();
        ok(Ret, "Replace, Yes and Yes failed: %lu\n", GetLastError());
        ok(Shown == 2, "%ld dialogs\n", Shown);
        ok(CountCerts(Store) == Before + 1 && IsInStore(Store, Root), "The store is wrong after the replacement\n");

        /* Removing asks too: No keeps it, Yes removes it */
        Found = CertFindCertificateInStore(Store, X509_ASN_ENCODING, 0, CERT_FIND_EXISTING, Root, NULL);
        ok(Found != NULL, "The certificate is not found\n");
        if (Found)
        {
            PCCERT_CONTEXT Dup = CertDuplicateCertificateContext(Found);

            StartAnswers("n");
            SetLastError(0xdeadbeef);
            Ret = CertDeleteCertificateFromStore(Found);
            Shown = EndAnswers();
            ok(!Ret && GetLastError() == ERROR_CANCELLED, "Delete, No: %d, error %lu\n", Ret, GetLastError());
            ok(Shown == 1, "%ld dialogs\n", Shown);
            ok(IsInStore(Store, Root), "The certificate was removed after No\n");

            StartAnswers("y");
            Ret = CertDeleteCertificateFromStore(Dup);
            Shown = EndAnswers();
            ok(Ret, "Delete, Yes failed: %lu\n", GetLastError());
            ok(Shown == 1, "%ld dialogs\n", Shown);
            ok(CountCerts(Store) == Before && !IsInStore(Store, Root), "The certificate is still in the store\n");
        }
    }

    /* The Root store of the machine is not asked: an administrator adds and removes silently (a user who may not
     * write there is refused with an access error, not asked) */
    Machine = CertOpenStore(CERT_STORE_PROV_SYSTEM_W, 0, 0, CERT_SYSTEM_STORE_LOCAL_MACHINE, L"Root");
    if (Machine)
    {
        SetLastError(0xdeadbeef);
        Ret = CertAddCertificateContextToStore(Machine, Root, CERT_STORE_ADD_REPLACE_EXISTING, NULL);
        if (Ret)
        {
            Found = CertFindCertificateInStore(Machine, X509_ASN_ENCODING, 0, CERT_FIND_EXISTING, Root, NULL);
            ok(Found != NULL, "The certificate is not in the machine store\n");
            if (Found)
                ok(CertDeleteCertificateFromStore(Found), "Removing it failed: %lu\n", GetLastError());
        }
        else
            skip("The machine's Root store is not writable here (%lu)\n", GetLastError());
        CertCloseStore(Machine, 0);
    }
    else
        skip("The machine's Root store cannot be opened (%lu)\n", GetLastError());

    CertCloseStore(Store, 0);
    CertFreeCertificateContext(Root);
}
