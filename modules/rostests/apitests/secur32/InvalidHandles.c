/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Tests for the secur32 entry points given a handle that names nothing
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * The values are those of Windows 10 22H2 (x64 and x86): every entry point answers SEC_E_INVALID_HANDLE at
 * once for a zeroed handle, for a handle of arbitrary values and for the handle that a failed
 * AcquireCredentialsHandle leaves untouched. (DeleteSecurityContext deletes a zeroed handle without
 * error.) The handle is never followed: InitializeSecurityContextW used to hang on the leftover handle.
 */

#define SECURITY_WIN32
#include <apitest.h>
#include <sspi.h>
#include <security.h>

static void TestEntryPoints(const char *Name, PCredHandle Cred, PCtxtHandle Ctx, BOOL ZeroDelete)
{
    SECURITY_STATUS Status;
    CtxtHandle NewCtx = { 0, 0 };
    TimeStamp Expiry;
    ULONG Attr;
    BYTE Token[64];
    SecBuffer Buffer;
    SecBufferDesc Desc;
    SecPkgCredentials_NamesW Names;
    SecPkgContext_Sizes Sizes;

    Buffer.BufferType = SECBUFFER_TOKEN;
    Buffer.cbBuffer = sizeof(Token);
    Buffer.pvBuffer = Token;
    Desc.ulVersion = SECBUFFER_VERSION;
    Desc.cBuffers = 1;
    Desc.pBuffers = &Buffer;

#define CHECK(call) \
    Status = (call); \
    ok(Status == SEC_E_INVALID_HANDLE, "%s: %s = 0x%08lx\n", Name, #call, (ULONG)Status)

    CHECK(InitializeSecurityContextW(Cred, NULL, (SEC_WCHAR *)L"host", ISC_REQ_CONNECTION, 0,
                                     SECURITY_NATIVE_DREP, NULL, 0, &NewCtx, &Desc, &Attr, &Expiry));
    CHECK(InitializeSecurityContextW(NULL, Ctx, (SEC_WCHAR *)L"host", ISC_REQ_CONNECTION, 0,
                                     SECURITY_NATIVE_DREP, NULL, 0, &NewCtx, &Desc, &Attr, &Expiry));
    CHECK(InitializeSecurityContextW(Cred, Ctx, (SEC_WCHAR *)L"host", ISC_REQ_CONNECTION, 0,
                                     SECURITY_NATIVE_DREP, NULL, 0, &NewCtx, &Desc, &Attr, &Expiry));
    CHECK(InitializeSecurityContextA(Cred, NULL, (SEC_CHAR *)"host", ISC_REQ_CONNECTION, 0,
                                     SECURITY_NATIVE_DREP, NULL, 0, &NewCtx, &Desc, &Attr, &Expiry));
    CHECK(AcceptSecurityContext(Cred, NULL, &Desc, ASC_REQ_CONNECTION, SECURITY_NATIVE_DREP, &NewCtx,
                                &Desc, &Attr, &Expiry));
    CHECK(AcceptSecurityContext(Cred, Ctx, &Desc, ASC_REQ_CONNECTION, SECURITY_NATIVE_DREP, &NewCtx,
                                &Desc, &Attr, &Expiry));
    CHECK(QueryCredentialsAttributesW(Cred, SECPKG_CRED_ATTR_NAMES, &Names));
    CHECK(QueryCredentialsAttributesA(Cred, SECPKG_CRED_ATTR_NAMES, &Names));
    CHECK(QueryContextAttributesW(Ctx, SECPKG_ATTR_SIZES, &Sizes));
    CHECK(QueryContextAttributesA(Ctx, SECPKG_ATTR_SIZES, &Sizes));
    CHECK(CompleteAuthToken(Ctx, &Desc));
    CHECK(ImpersonateSecurityContext(Ctx));
    CHECK(RevertSecurityContext(Ctx));
    CHECK(MakeSignature(Ctx, 0, &Desc, 0));
    CHECK(VerifySignature(Ctx, &Desc, 0, &Attr));
    CHECK(EncryptMessage(Ctx, 0, &Desc, 0));
    CHECK(DecryptMessage(Ctx, &Desc, 0, &Attr));
    if (ZeroDelete)
    {
        Status = DeleteSecurityContext(Ctx);
        ok(Status == SEC_E_OK, "%s: DeleteSecurityContext = 0x%08lx\n", Name, (ULONG)Status);
    }
    else
    {
        CHECK(DeleteSecurityContext(Ctx));
    }
    CHECK(FreeCredentialsHandle(Cred));
#undef CHECK
}

START_TEST(InvalidHandles)
{
    CredHandle Cred;
    CtxtHandle Ctx;
    TimeStamp Expiry;
    SECURITY_STATUS Status;

    RtlZeroMemory(&Cred, sizeof(Cred));
    RtlZeroMemory(&Ctx, sizeof(Ctx));
    TestEntryPoints("zeroed", &Cred, &Ctx, TRUE);

    Cred.dwLower = Cred.dwUpper = 1;
    Ctx.dwLower = Ctx.dwUpper = 1;
    TestEntryPoints("one", &Cred, &Ctx, FALSE);

    Cred.dwLower = Cred.dwUpper = (ULONG_PTR)-1;
    Ctx.dwLower = Ctx.dwUpper = (ULONG_PTR)-1;
    TestEntryPoints("minus one", &Cred, &Ctx, FALSE);

    /* The handle that a failed AcquireCredentialsHandle leaves behind: the call does not write it */
    RtlFillMemory(&Cred, sizeof(Cred), 0xCC);
    RtlFillMemory(&Ctx, sizeof(Ctx), 0xCC);
    Status = AcquireCredentialsHandleW(NULL, (SEC_WCHAR *)L"NoSuchPackage_xyz", SECPKG_CRED_OUTBOUND, NULL,
                                       NULL, NULL, NULL, &Cred, &Expiry);
    ok(Status == SEC_E_SECPKG_NOT_FOUND, "AcquireCredentialsHandleW = 0x%08lx\n", (ULONG)Status);
    ok(Cred.dwUpper == (ULONG_PTR)-1 / 0xFF * 0xCC && Cred.dwLower == Cred.dwUpper,
       "the handle was written: %p %p\n", (void *)Cred.dwUpper, (void *)Cred.dwLower);
    TestEntryPoints("failed acquire", &Cred, &Ctx, FALSE);
}
