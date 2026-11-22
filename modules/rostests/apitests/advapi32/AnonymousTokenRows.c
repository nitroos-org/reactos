/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     GetTokenInformation rows of the anonymous logon token (ImpersonateAnonymousToken), measured on
 *              Windows Server 2022: TokenOrigin is 0:0, TokenDefaultDacl has Everyone and ANONYMOUS LOGON
 *              with 0x000F01FF each. Documentation: GetTokenInformation, TOKEN_ORIGIN, TOKEN_DEFAULT_DACL.
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"

START_TEST(AnonymousTokenRows)
{
    HANDLE Token;
    TOKEN_ORIGIN Origin;
    UCHAR Buffer[512];
    PTOKEN_DEFAULT_DACL Default = (PTOKEN_DEFAULT_DACL)Buffer;
    DWORD Length;
    UINT i;
    PACCESS_ALLOWED_ACE Ace;

    if (!ImpersonateAnonymousToken(GetCurrentThread()))
    {
        skip("ImpersonateAnonymousToken failed with %lu\n", GetLastError());
        return;
    }

    if (!OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &Token))
    {
        ok(0, "OpenThreadToken failed with %lu\n", GetLastError());
        RevertToSelf();
        return;
    }

    memset(&Origin, 0x55, sizeof(Origin));
    ok(GetTokenInformation(Token, TokenOrigin, &Origin, sizeof(Origin), &Length),
       "TokenOrigin failed with %lu\n", GetLastError());
    ok(Origin.OriginatingLogonSession.LowPart == 0 && Origin.OriginatingLogonSession.HighPart == 0,
       "TokenOrigin is %lx:%lx, expected 0:0\n",
       Origin.OriginatingLogonSession.HighPart, Origin.OriginatingLogonSession.LowPart);

    ok(GetTokenInformation(Token, TokenDefaultDacl, Buffer, sizeof(Buffer), &Length),
       "TokenDefaultDacl failed with %lu\n", GetLastError());
    ok(Default->DefaultDacl != NULL, "no default DACL\n");
    if (Default->DefaultDacl)
    {
        ok(Default->DefaultDacl->AceCount == 2, "AceCount %u, expected 2\n", Default->DefaultDacl->AceCount);
        for (i = 0; i < Default->DefaultDacl->AceCount && i < 2; i++)
        {
            ok(GetAce(Default->DefaultDacl, i, (PVOID *)&Ace), "GetAce(%u) failed\n", i);
            ok(Ace->Header.AceType == ACCESS_ALLOWED_ACE_TYPE, "ace %u type %u\n", i, Ace->Header.AceType);
            ok(Ace->Mask == 0x000F01FF, "ace %u mask %lx, expected f01ff\n", i, Ace->Mask);
        }
    }

    CloseHandle(Token);
    RevertToSelf();
}
