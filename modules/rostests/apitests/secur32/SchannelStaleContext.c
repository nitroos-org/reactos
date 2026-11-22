/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     schannel entry points given a context handle that is gone or never was
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Expected values measured on Windows Server 2022 (x64 and x86): a deleted, a zeroed and a made-up handle give
 * SEC_E_INVALID_HANDLE from QueryContextAttributes, EncryptMessage and DecryptMessage; DeleteSecurityContext of a
 * deleted handle gives SEC_E_INVALID_HANDLE too. Before the handshake is done, QueryContextAttributes(STREAM_SIZES)
 * of a live context also gives SEC_E_INVALID_HANDLE.
 */

#define SECURITY_WIN32
#include <apitest.h>
#include <wincrypt.h>
#include <sspi.h>
#include <schannel.h>

static void CheckHandle(const char *Name, PCtxtHandle Ctx)
{
    SecPkgContext_StreamSizes Sizes;
    SecPkgContext_ConnectionInfo Info;
    BYTE Buffer[256];
    SecBuffer Buffers[4];
    SecBufferDesc Desc;
    SECURITY_STATUS Status;

    ZeroMemory(&Sizes, sizeof(Sizes));
    Status = QueryContextAttributesW(Ctx, SECPKG_ATTR_STREAM_SIZES, &Sizes);
    ok(Status == SEC_E_INVALID_HANDLE, "%s: QueryContextAttributes(STREAM_SIZES) = 0x%08lx\n", Name, (ULONG)Status);
    ZeroMemory(&Info, sizeof(Info));
    Status = QueryContextAttributesW(Ctx, SECPKG_ATTR_CONNECTION_INFO, &Info);
    ok(Status == SEC_E_INVALID_HANDLE, "%s: QueryContextAttributes(CONNECTION_INFO) = 0x%08lx\n", Name, (ULONG)Status);

    ZeroMemory(Buffer, sizeof(Buffer));
    Buffers[0].BufferType = SECBUFFER_STREAM_HEADER;
    Buffers[0].cbBuffer = 5;
    Buffers[0].pvBuffer = Buffer;
    Buffers[1].BufferType = SECBUFFER_DATA;
    Buffers[1].cbBuffer = 16;
    Buffers[1].pvBuffer = Buffer + 5;
    Buffers[2].BufferType = SECBUFFER_STREAM_TRAILER;
    Buffers[2].cbBuffer = 64;
    Buffers[2].pvBuffer = Buffer + 21;
    Buffers[3].BufferType = SECBUFFER_EMPTY;
    Buffers[3].cbBuffer = 0;
    Buffers[3].pvBuffer = NULL;
    Desc.ulVersion = SECBUFFER_VERSION;
    Desc.cBuffers = 4;
    Desc.pBuffers = Buffers;
    Status = EncryptMessage(Ctx, 0, &Desc, 0);
    ok(Status == SEC_E_INVALID_HANDLE, "%s: EncryptMessage = 0x%08lx\n", Name, (ULONG)Status);

    Buffers[0].BufferType = SECBUFFER_DATA;
    Buffers[0].cbBuffer = 32;
    Buffers[0].pvBuffer = Buffer;
    Buffers[1].BufferType = SECBUFFER_EMPTY;
    Buffers[1].cbBuffer = 0;
    Buffers[2].BufferType = SECBUFFER_EMPTY;
    Buffers[2].cbBuffer = 0;
    Buffers[3].BufferType = SECBUFFER_EMPTY;
    Buffers[3].cbBuffer = 0;
    Status = DecryptMessage(Ctx, &Desc, 0, NULL);
    ok(Status == SEC_E_INVALID_HANDLE, "%s: DecryptMessage = 0x%08lx\n", Name, (ULONG)Status);
}

START_TEST(SchannelStaleContext)
{
    SCHANNEL_CRED CredData;
    CredHandle Cred;
    CtxtHandle Ctx = { 0, 0 }, Zero = { 0, 0 }, MadeUp = { 1, 1 };
    SecPkgContext_StreamSizes Sizes;
    SecBuffer Out;
    SecBufferDesc OutDesc;
    TimeStamp Expiry;
    ULONG Attr;
    SECURITY_STATUS Status;

    ZeroMemory(&CredData, sizeof(CredData));
    CredData.dwVersion = SCHANNEL_CRED_VERSION;
    CredData.dwFlags = SCH_CRED_NO_DEFAULT_CREDS | SCH_CRED_MANUAL_CRED_VALIDATION;
    Status = AcquireCredentialsHandleW(NULL, (SEC_WCHAR *)UNISP_NAME_W, SECPKG_CRED_OUTBOUND, NULL, &CredData,
                                       NULL, NULL, &Cred, &Expiry);
    ok(Status == SEC_E_OK, "AcquireCredentialsHandle = 0x%08lx\n", (ULONG)Status);
    if (Status != SEC_E_OK)
        return;

    Out.cbBuffer = 0;
    Out.BufferType = SECBUFFER_TOKEN;
    Out.pvBuffer = NULL;
    OutDesc.ulVersion = SECBUFFER_VERSION;
    OutDesc.cBuffers = 1;
    OutDesc.pBuffers = &Out;
    Status = InitializeSecurityContextW(&Cred, NULL, (SEC_WCHAR *)L"stale.reactos.test",
                                        ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_STREAM, 0, 0, NULL, 0, &Ctx, &OutDesc,
                                        &Attr, &Expiry);
    ok(Status == SEC_I_CONTINUE_NEEDED, "InitializeSecurityContext = 0x%08lx\n", (ULONG)Status);
    if (Status == SEC_I_CONTINUE_NEEDED)
    {
        ZeroMemory(&Sizes, sizeof(Sizes));
        Status = QueryContextAttributesW(&Ctx, SECPKG_ATTR_STREAM_SIZES, &Sizes);
        ok(Status == SEC_E_INVALID_HANDLE, "STREAM_SIZES before the handshake is done: 0x%08lx\n", (ULONG)Status);
        if (Out.pvBuffer)
            FreeContextBuffer(Out.pvBuffer);
        ok(DeleteSecurityContext(&Ctx) == SEC_E_OK, "DeleteSecurityContext failed\n");
        CheckHandle("deleted", &Ctx);
        Status = DeleteSecurityContext(&Ctx);
        ok(Status == SEC_E_INVALID_HANDLE, "DeleteSecurityContext of a deleted handle = 0x%08lx\n", (ULONG)Status);
    }
    CheckHandle("zeroed", &Zero);
    CheckHandle("made up", &MadeUp);
    FreeCredentialsHandle(&Cred);
}
