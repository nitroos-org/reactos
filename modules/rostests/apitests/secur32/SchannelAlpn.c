/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     schannel offers the protocols of an input SECBUFFER_APPLICATION_PROTOCOLS buffer in the ALPN extension
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Expected values measured on Windows Server 2022 (x64 and x86, probe schalpn, no network): the first
 * InitializeSecurityContext call of a client with a list for ProtoNegoExt ALPN (2) sends the extension 16 with the
 * names (an NPN list, extension 1, sends none), an empty list fails with SEC_E_ILLEGAL_MESSAGE, and
 * QueryContextAttributes(SECPKG_ATTR_APPLICATION_PROTOCOL) before the handshake is done is SEC_E_INVALID_HANDLE.
 * What the server chooses needs a server (not tested here).
 */

#define SECURITY_WIN32
#include <apitest.h>
#include <wincrypt.h>
#include <sspi.h>
#include <schannel.h>

#ifndef SECBUFFER_APPLICATION_PROTOCOLS
#define SECBUFFER_APPLICATION_PROTOCOLS 18
#endif
#ifndef SECPKG_ATTR_APPLICATION_PROTOCOL
#define SECPKG_ATTR_APPLICATION_PROTOCOL 35
#endif

#include <pshpack1.h>
typedef struct { ULONG Lists; ULONG Ext; USHORT Size; UCHAR Names[64]; } ALPN_INPUT;
#include <poppack.h>

/* The ALPN extension of a ClientHello as "name,name" ("" for an empty one), NULL when there is none */
static BOOL FindAlpn(const BYTE *Data, ULONG Size, char *Names)
{
    ULONG Pos, End, ExtEnd;

    Names[0] = 0;
    if (Size < 50 || Data[0] != 0x16 || Data[5] != 1)
        return FALSE;
    End = min(Size, 5 + (ULONG)((Data[3] << 8) | Data[4]));
    Pos = 11 + 32;
    Pos += 1 + Data[Pos];
    Pos += 2 + ((Data[Pos] << 8) | Data[Pos + 1]);
    Pos += 1 + Data[Pos];
    if (Pos + 2 > End)
        return FALSE;
    ExtEnd = min(End, Pos + 2 + ((Data[Pos] << 8) | Data[Pos + 1]));
    Pos += 2;
    while (Pos + 4 <= ExtEnd)
    {
        USHORT Type = (Data[Pos] << 8) | Data[Pos + 1], Length = (Data[Pos + 2] << 8) | Data[Pos + 3];

        if (Type == 16 && Pos + 6 <= ExtEnd)
        {
            ULONG p = Pos + 6, e = min(ExtEnd, Pos + 4 + Length);
            ULONG out = 0;

            while (p < e && out < 100)
            {
                UCHAR l = Data[p++];

                if (out)
                    Names[out++] = ',';
                memcpy(Names + out, Data + p, l);
                out += l;
                p += l;
            }
            Names[out] = 0;
            return TRUE;
        }
        Pos += 4 + Length;
    }
    return FALSE;
}

static void Case(PCSTR Title, const char *List, ULONG Ext, BOOL Input, BOOL ExpectExtension, const char *ExpectNames,
                 SECURITY_STATUS ExpectedStatus)
{
    SCHANNEL_CRED Cred;
    CredHandle Handle;
    CtxtHandle Ctx = { 0, 0 };
    TimeStamp Expiry;
    ULONG Attr;
    SECURITY_STATUS Status;
    SecBuffer In[2], Out;
    SecBufferDesc InDesc, OutDesc;
    ALPN_INPUT Alpn;
    char Names[128];
    ULONG Length = 0;
    SecPkgContext_ApplicationProtocol Protocol;

    ZeroMemory(&Cred, sizeof(Cred));
    Cred.dwVersion = SCHANNEL_CRED_VERSION;
    Cred.dwFlags = SCH_CRED_NO_DEFAULT_CREDS | SCH_CRED_MANUAL_CRED_VALIDATION;
    Status = AcquireCredentialsHandleW(NULL, (SEC_WCHAR *)UNISP_NAME_W, SECPKG_CRED_OUTBOUND, NULL, &Cred, NULL, NULL,
                                       &Handle, &Expiry);
    ok(Status == SEC_E_OK, "%s: AcquireCredentialsHandle 0x%08lx\n", Title, (ULONG)Status);
    if (Status != SEC_E_OK)
        return;

    ZeroMemory(&Alpn, sizeof(Alpn));
    Alpn.Ext = Ext;
    if (List)
    {
        const char *p = List;

        while (*p)
        {
            const char *q = strchr(p, ',');
            int l = q ? (int)(q - p) : (int)strlen(p);

            Alpn.Names[Length++] = (UCHAR)l;
            memcpy(Alpn.Names + Length, p, l);
            Length += l;
            p += l + (q ? 1 : 0);
        }
    }
    Alpn.Size = (USHORT)Length;
    Alpn.Lists = sizeof(ULONG) + sizeof(USHORT) + Length;
    In[0].BufferType = SECBUFFER_APPLICATION_PROTOCOLS;
    In[0].pvBuffer = &Alpn;
    In[0].cbBuffer = sizeof(ULONG) + sizeof(ULONG) + sizeof(USHORT) + Length;
    In[1].BufferType = SECBUFFER_EMPTY;
    In[1].pvBuffer = NULL;
    In[1].cbBuffer = 0;
    InDesc.ulVersion = SECBUFFER_VERSION;
    InDesc.cBuffers = 2;
    InDesc.pBuffers = In;
    Out.BufferType = SECBUFFER_TOKEN;
    Out.pvBuffer = NULL;
    Out.cbBuffer = 0;
    OutDesc.ulVersion = SECBUFFER_VERSION;
    OutDesc.cBuffers = 1;
    OutDesc.pBuffers = &Out;

    Status = InitializeSecurityContextW(&Handle, NULL, (SEC_WCHAR *)L"alpn.test.example",
                                        ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_STREAM | ISC_REQ_CONFIDENTIALITY, 0, 0,
                                        Input ? &InDesc : NULL, 0, &Ctx, &OutDesc, &Attr, &Expiry);
    ok(Status == ExpectedStatus, "%s: InitializeSecurityContext 0x%08lx, expected 0x%08lx\n", Title, (ULONG)Status,
       (ULONG)ExpectedStatus);
    if (Status == SEC_I_CONTINUE_NEEDED && Out.pvBuffer)
    {
        BOOL Found = FindAlpn(Out.pvBuffer, Out.cbBuffer, Names);

        ok(Found == ExpectExtension, "%s: ALPN extension %s, expected %s\n", Title, Found ? "present" : "absent",
           ExpectExtension ? "present" : "absent");
        if (Found && ExpectNames)
            ok(!strcmp(Names, ExpectNames), "%s: ALPN names \"%s\", expected \"%s\"\n", Title, Names, ExpectNames);
        FreeContextBuffer(Out.pvBuffer);

        ZeroMemory(&Protocol, sizeof(Protocol));
        Status = QueryContextAttributesW(&Ctx, SECPKG_ATTR_APPLICATION_PROTOCOL, &Protocol);
        ok(Status == SEC_E_INVALID_HANDLE, "%s: APPLICATION_PROTOCOL before the handshake: 0x%08lx\n", Title, (ULONG)Status);
        DeleteSecurityContext(&Ctx);
    }
    FreeCredentialsHandle(&Handle);
}

START_TEST(SchannelAlpn)
{
    Case("no buffer", NULL, 0, FALSE, FALSE, NULL, SEC_I_CONTINUE_NEEDED);
    Case("h2 and http/1.1", "h2,http/1.1", 2, TRUE, TRUE, "h2,http/1.1", SEC_I_CONTINUE_NEEDED);
    Case("http/1.1", "http/1.1", 2, TRUE, TRUE, "http/1.1", SEC_I_CONTINUE_NEEDED);
    Case("foo/1", "foo/1", 2, TRUE, TRUE, "foo/1", SEC_I_CONTINUE_NEEDED);
    Case("NPN list", "h2", 1, TRUE, FALSE, NULL, SEC_I_CONTINUE_NEEDED);
    Case("empty list", "", 2, TRUE, FALSE, NULL, SEC_E_ILLEGAL_MESSAGE);
}
