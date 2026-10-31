/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Tests for QueryContextAttributesExW and QueryContextAttributesExA of sspicli
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Measured on Windows 10 22H2: the functions are QueryContextAttributesW and QueryContextAttributesA, whatever
 * the size that is passed (0, 4 or more than the structure change nothing). PowerShell 7 imports the W one.
 */

#include <apitest.h>
#include <string.h>
#include <windef.h>
#include <winbase.h>

#define SECURITY_WIN32
#include <sspi.h>
#include <security.h>

typedef SECURITY_STATUS (SEC_ENTRY *QueryContextAttributesEx_t)(PCtxtHandle, ULONG, PVOID, ULONG);

static SECURITY_STATUS g_codes[16];

static BOOL make_context(CtxtHandle *ctx, CredHandle *client, CredHandle *server)
{
    SecBufferDesc client_out, client_in, server_out;
    SecBuffer client_out_buf, client_in_buf, server_out_buf;
    BYTE token1[4096], token2[4096];
    CtxtHandle server_ctx;
    TimeStamp ts;
    ULONG attrs;
    SECURITY_STATUS status;

    status = AcquireCredentialsHandleW(NULL, (SEC_WCHAR *)L"NTLM", SECPKG_CRED_OUTBOUND, NULL, NULL, NULL, NULL, client, &ts);
    if (status != SEC_E_OK)
        return FALSE;
    status = AcquireCredentialsHandleW(NULL, (SEC_WCHAR *)L"NTLM", SECPKG_CRED_INBOUND, NULL, NULL, NULL, NULL, server, &ts);
    if (status != SEC_E_OK)
        return FALSE;

    client_out_buf.BufferType = SECBUFFER_TOKEN;
    client_out_buf.cbBuffer = sizeof(token1);
    client_out_buf.pvBuffer = token1;
    client_out.ulVersion = SECBUFFER_VERSION;
    client_out.cBuffers = 1;
    client_out.pBuffers = &client_out_buf;
    status = InitializeSecurityContextW(client, NULL, (SEC_WCHAR *)L"host", ISC_REQ_CONNECTION, 0,
                                        SECURITY_NATIVE_DREP, NULL, 0, ctx, &client_out, &attrs, &ts);
    if (status != SEC_I_CONTINUE_NEEDED)
        return FALSE;

    client_in_buf = client_out_buf;
    client_in.ulVersion = SECBUFFER_VERSION;
    client_in.cBuffers = 1;
    client_in.pBuffers = &client_in_buf;
    server_out_buf.BufferType = SECBUFFER_TOKEN;
    server_out_buf.cbBuffer = sizeof(token2);
    server_out_buf.pvBuffer = token2;
    server_out.ulVersion = SECBUFFER_VERSION;
    server_out.cBuffers = 1;
    server_out.pBuffers = &server_out_buf;
    status = AcceptSecurityContext(server, NULL, &client_in, ASC_REQ_CONNECTION, SECURITY_NATIVE_DREP,
                                   &server_ctx, &server_out, &attrs, &ts);
    if (status != SEC_I_CONTINUE_NEEDED)
        return FALSE;

    client_in_buf = server_out_buf;
    client_out_buf.cbBuffer = sizeof(token1);
    status = InitializeSecurityContextW(client, ctx, (SEC_WCHAR *)L"host", ISC_REQ_CONNECTION, 0,
                                        SECURITY_NATIVE_DREP, &client_in, 0, ctx, &client_out, &attrs, &ts);
    return status == SEC_E_OK;
}

START_TEST(QueryContextAttributesEx)
{
    static const struct { ULONG attribute; ULONG size; } attributes[] =
    {
        { SECPKG_ATTR_SIZES, sizeof(SecPkgContext_Sizes) },
        { SECPKG_ATTR_NAMES, sizeof(SecPkgContext_NamesW) },
        { SECPKG_ATTR_PACKAGE_INFO, sizeof(SecPkgContext_PackageInfoW) },
        { SECPKG_ATTR_LIFESPAN, sizeof(SecPkgContext_Lifespan) },
        { SECPKG_ATTR_STREAM_SIZES, sizeof(SecPkgContext_StreamSizes) },
        { 0x7fff, 8 },
    };
    HMODULE module = LoadLibraryA("sspicli.dll");
    QueryContextAttributesEx_t exw, exa;
    CtxtHandle ctx, bad = { 0, 0 };
    CredHandle client, server;
    BYTE expected[256], actual[256];
    SECURITY_STATUS status, expected_status;
    ULONG sizes[5];
    size_t i, j;

    ok(module != NULL, "sspicli.dll is not loaded\n");
    if (!module)
        return;
    exw = (QueryContextAttributesEx_t)GetProcAddress(module, "QueryContextAttributesExW");
    exa = (QueryContextAttributesEx_t)GetProcAddress(module, "QueryContextAttributesExA");
    ok(exw != NULL, "QueryContextAttributesExW is not exported\n");
    ok(exa != NULL, "QueryContextAttributesExA is not exported\n");
    if (!exw || !exa)
        return;

    /* an invalid handle, whatever the arguments */
    memset(actual, 0, sizeof(actual));
    status = exw(&bad, SECPKG_ATTR_SIZES, actual, sizeof(SecPkgContext_Sizes));
    ok(status == SEC_E_INVALID_HANDLE, "ExW with a bad handle: %lx\n", status);
    status = exa(&bad, SECPKG_ATTR_SIZES, actual, sizeof(SecPkgContext_Sizes));
    ok(status == SEC_E_INVALID_HANDLE, "ExA with a bad handle: %lx\n", status);
    status = exw(NULL, SECPKG_ATTR_SIZES, actual, sizeof(SecPkgContext_Sizes));
    ok(status == SEC_E_INVALID_HANDLE, "ExW with no handle: %lx\n", status);

    if (!make_context(&ctx, &client, &server))
    {
        skip("no NTLM context between two credentials\n");
        return;
    }

    for (i = 0; i < ARRAYSIZE(attributes); i++)
    {
        sizes[0] = attributes[i].size;
        sizes[1] = 0;
        sizes[2] = attributes[i].size - 1;
        sizes[3] = attributes[i].size + 8;
        sizes[4] = 4;

        memset(expected, 0, sizeof(expected));
        expected_status = QueryContextAttributesW(&ctx, attributes[i].attribute, expected);
        for (j = 0; j < ARRAYSIZE(sizes); j++)
        {
            memset(actual, 0, sizeof(actual));
            status = exw(&ctx, attributes[i].attribute, actual, sizes[j]);
            g_codes[0] = status;
            ok(status == expected_status, "attribute %lx size %lu: ExW %lx, QueryContextAttributesW %lx\n",
               attributes[i].attribute, sizes[j], status, expected_status);
            if (status == SEC_E_OK && attributes[i].attribute == SECPKG_ATTR_SIZES)
                ok(!memcmp(actual, expected, sizeof(SecPkgContext_Sizes)), "the sizes differ\n");
        }
        memset(actual, 0, sizeof(actual));
        status = exa(&ctx, attributes[i].attribute, actual, attributes[i].size);
        ok(status == expected_status, "attribute %lx: ExA %lx, expected %lx\n", attributes[i].attribute, status,
           expected_status);
    }
    ok(expected_status == SEC_E_UNSUPPORTED_FUNCTION || expected_status == SEC_E_INVALID_HANDLE ||
       expected_status == SEC_E_OK || expected_status != 0, "the unknown attribute is ok\n");

    DeleteSecurityContext(&ctx);
    FreeCredentialsHandle(&client);
    FreeCredentialsHandle(&server);
}
