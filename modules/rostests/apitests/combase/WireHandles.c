/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Tests for the HMONITOR_User*, HRGN_User* and *_User*64 wire handle helpers and the
 *              CStdStubBuffer exports of combase.dll (and the ole32.dll forwards to them)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Measured on Windows 10 22H2 (x64 and x86): ole32 forwards these names to combase; HMONITOR and HRGN
 * marshal exactly like HWND; the *64 helpers of the plain handle types are the same code as the 32 ones
 * (8 bytes: WDT_INPROC_CALL + the handle as a LONG; MSHCTX_DIFFERENTMACHINE raises RPC_S_INVALID_TAG).
 */

#include <apitest.h>
#include <stdio.h>
#include <string.h>
#include <windef.h>
#include <winbase.h>
#include <wingdi.h>
#include <winuser.h>
#include <objbase.h>
#include <pseh/pseh2.h>

#define WIRE_INPROC 0x48746457 /* WDT_INPROC_CALL, 'WdtH' */

typedef ULONG (WINAPI *USERSIZE_t)(ULONG *, ULONG, void *);
typedef unsigned char *(WINAPI *USERMARSHAL_t)(ULONG *, unsigned char *, void *);
typedef void (WINAPI *USERFREE_t)(ULONG *, void *);

typedef struct
{
    ULONG Flags;
    void *pad[16];
} CB;

/* run the helper with SEH so that the RPC exceptions it raises can be checked */
static ULONG call_size(USERSIZE_t fn, ULONG ctx, ULONG start, void *h, DWORD *exc)
{
    CB cb;
    ULONG ret = 0;
    memset(&cb, 0, sizeof(cb));
    cb.Flags = MAKELONG(ctx, 0x10);
    *exc = 0;
    _SEH2_TRY
    {
        ret = fn(&cb.Flags, start, h);
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        *exc = _SEH2_GetExceptionCode();
    }
    _SEH2_END;
    return ret;
}

static unsigned char *call_marshal(USERMARSHAL_t fn, ULONG ctx, unsigned char *buf, void *h, DWORD *exc)
{
    CB cb;
    unsigned char *ret = NULL;
    memset(&cb, 0, sizeof(cb));
    cb.Flags = MAKELONG(ctx, 0x10);
    *exc = 0;
    _SEH2_TRY
    {
        ret = fn(&cb.Flags, buf, h);
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        *exc = _SEH2_GetExceptionCode();
    }
    _SEH2_END;
    return ret;
}

static void test_handle_family(HMODULE combase, HMODULE ole32, const char *family, void *handle, BOOL has64, BOOL ole32_has64)
{
    static const char *const kinds[] = { "Size", "Marshal", "Unmarshal", "Free" };
    char name[64];
    int variant, k;

    for (variant = 0; variant < (has64 ? 2 : 1); variant++)
    {
        const char *suffix = variant ? "64" : "";
        FARPROC cb[4], ol[4];
        USERSIZE_t size;
        USERMARSHAL_t marshal, unmarshal;
        USERFREE_t freefn;
        unsigned char raw[64], *buf, *end;
        ULONG ret;
        DWORD exc;
        void *h2;
        CB flags;

        for (k = 0; k < 4; k++)
        {
            sprintf(name, "%s_User%s%s", family, kinds[k], suffix);
            cb[k] = GetProcAddress(combase, name);
            ol[k] = GetProcAddress(ole32, name);
            ok(cb[k] != NULL, "combase!%s is not exported\n", name);
            if (variant == 0 || ole32_has64)
                ok(ol[k] != NULL, "ole32!%s is not exported\n", name);
            if (cb[k] && ol[k])
                ok(cb[k] == ol[k], "ole32!%s is not forwarded to combase\n", name);
        }
        if (!cb[0] || !cb[1] || !cb[2] || !cb[3])
            continue;
        size = (USERSIZE_t)cb[0];
        marshal = (USERMARSHAL_t)cb[1];
        unmarshal = (USERMARSHAL_t)cb[2];
        freefn = (USERFREE_t)cb[3];

        buf = (unsigned char *)(((ULONG_PTR)raw + 15) & ~(ULONG_PTR)15);

        /* a local handle takes 8 bytes, aligned to 4 */
        ret = call_size(size, MSHCTX_LOCAL, 0, handle, &exc);
        ok(exc == 0 && ret == 8, "%s_UserSize%s: ret %lu exc %#lx\n", family, suffix, ret, exc);
        ret = call_size(size, MSHCTX_LOCAL, 5, handle, &exc);
        ok(exc == 0 && ret == 16, "%s_UserSize%s from 5: ret %lu exc %#lx\n", family, suffix, ret, exc);
        ret = call_size(size, MSHCTX_INPROC, 0, handle, &exc);
        ok(exc == 0 && ret == 8, "%s_UserSize%s inproc: ret %lu exc %#lx\n", family, suffix, ret, exc);

        /* a local handle cannot go to another machine */
        ret = call_size(size, MSHCTX_DIFFERENTMACHINE, 0, handle, &exc);
        ok(exc == RPC_S_INVALID_TAG, "%s_UserSize%s remote: exception %#lx\n", family, suffix, exc);
        memset(raw, 0xcc, sizeof(raw));
        end = call_marshal(marshal, MSHCTX_DIFFERENTMACHINE, buf, handle, &exc);
        ok(exc == RPC_S_INVALID_TAG && end == NULL, "%s_UserMarshal%s remote: exception %#lx\n", family, suffix, exc);

        memset(raw, 0xcc, sizeof(raw));
        end = call_marshal(marshal, MSHCTX_LOCAL, buf, handle, &exc);
        ok(exc == 0 && end == buf + 8, "%s_UserMarshal%s: end %p (buf %p) exc %#lx\n", family, suffix, end, buf, exc);
        if (end == buf + 8)
        {
            ok(*(DWORD *)buf == WIRE_INPROC, "%s_UserMarshal%s: context %#lx\n", family, suffix, *(DWORD *)buf);
            ok(*(LONG *)(buf + 4) == (LONG)(LONG_PTR)*(void **)handle, "%s_UserMarshal%s: handle %#lx\n", family, suffix, *(DWORD *)(buf + 4));
        }

        /* an unaligned buffer is rounded up to 4 */
        memset(raw, 0xcc, sizeof(raw));
        end = call_marshal(marshal, MSHCTX_LOCAL, buf + 1, handle, &exc);
        ok(exc == 0 && end == buf + 12, "%s_UserMarshal%s unaligned: end %p (buf %p) exc %#lx\n", family, suffix, end, buf, exc);

        memset(raw, 0xcc, sizeof(raw));
        end = call_marshal(marshal, MSHCTX_LOCAL, buf, handle, &exc);
        h2 = NULL;
        end = call_marshal(unmarshal, MSHCTX_LOCAL, buf, &h2, &exc);
        ok(exc == 0 && end == buf + 8, "%s_UserUnmarshal%s: end %p exc %#lx\n", family, suffix, end, exc);
        ok(h2 == *(void **)handle, "%s_UserUnmarshal%s: handle %p, expected %p\n", family, suffix, h2, *(void **)handle);

        memset(&flags, 0, sizeof(flags));
        flags.Flags = MAKELONG(MSHCTX_LOCAL, 0x10);
        freefn(&flags.Flags, &h2); /* does nothing, must not crash or free the handle */
    }
}

/* the standard stub buffer: struct layout of rpcproxy.h's CStdStubBuffer */
typedef struct
{
    void *lpVtbl;
    LONG RefCount;
    void *pvServerObject;
    void *pCallFactoryVtbl;
    const IID *pAsyncIID;
    void *pPSFactory;
    void *pRMBVtbl;
} StdStubBuffer;

typedef ULONG (WINAPI *AddRef_t)(void *);

static void test_stub_buffer(HMODULE combase)
{
    static const char *const names[] =
    {
        "CStdStubBuffer_AddRef", "CStdStubBuffer_Connect", "CStdStubBuffer_CountRefs",
        "CStdStubBuffer_DebugServerQueryInterface", "CStdStubBuffer_DebugServerRelease",
        "CStdStubBuffer_Disconnect", "CStdStubBuffer_Invoke", "CStdStubBuffer_IsIIDSupported",
        "CStdStubBuffer_QueryInterface", "CStdAsyncStubBuffer_AddRef", "CStdAsyncStubBuffer_Disconnect",
        "NdrCStdStubBuffer_Release", "NdrCStdStubBuffer2_Release",
    };
    HMODULE ole32 = LoadLibraryA("ole32.dll");
    StdStubBuffer stub;
    AddRef_t addref, async_addref;
    ULONG ret;
    size_t i;

    for (i = 0; i < sizeof(names) / sizeof(names[0]); i++)
    {
        ok(GetProcAddress(combase, names[i]) != NULL, "combase!%s is not exported\n", names[i]);
        /* ole32 exports only the async ones, as forwards */
        if (!strncmp(names[i], "CStdAsync", 9))
            ok(GetProcAddress(ole32, names[i]) == GetProcAddress(combase, names[i]), "ole32!%s is not forwarded\n", names[i]);
    }

    addref = (AddRef_t)GetProcAddress(combase, "CStdStubBuffer_AddRef");
    async_addref = (AddRef_t)GetProcAddress(combase, "CStdAsyncStubBuffer_AddRef");
    if (!addref || !async_addref)
        return;
    memset(&stub, 0, sizeof(stub));
    stub.RefCount = 1;
    ret = addref(&stub);
    ok(ret == 2, "CStdStubBuffer_AddRef returned %lu\n", ret);
    ret = async_addref(&stub);
    ok(ret == 3, "CStdAsyncStubBuffer_AddRef returned %lu\n", ret);
    ok(stub.RefCount == 3, "RefCount is %ld\n", stub.RefCount);
}

START_TEST(WireHandles)
{
    HMODULE combase = LoadLibraryA("combase.dll");
    HMODULE ole32 = LoadLibraryA("ole32.dll");
    static const char *const plain[] = { "HACCEL", "HBRUSH", "HDC", "HICON", "HMENU", "HWND" };
    void *fake = (void *)(ULONG_PTR)0x12345;
    HRGN rgn;
    POINT pt = { 0, 0 };
    HMONITOR mon;
    size_t i;
#ifdef _WIN64
    const BOOL has64 = TRUE;
#else
    const BOOL has64 = FALSE;
#endif

    if (!combase || !ole32)
    {
        skip("combase.dll or ole32.dll is missing\n");
        return;
    }

    for (i = 0; i < sizeof(plain) / sizeof(plain[0]); i++)
        test_handle_family(combase, ole32, plain[i], &fake, has64, has64);

    rgn = CreateRectRgn(1, 2, 11, 12);
    ok(rgn != NULL, "CreateRectRgn failed\n");
    /* ole32 has no HRGN_User*64 */
    test_handle_family(combase, ole32, "HRGN", &rgn, has64, FALSE);
    if (rgn)
        DeleteObject(rgn);

    mon = MonitorFromPoint(pt, MONITOR_DEFAULTTOPRIMARY);
    if (!mon)
        mon = (HMONITOR)(ULONG_PTR)0x10001;
    test_handle_family(combase, ole32, "HMONITOR", &mon, has64, has64);

    test_stub_buffer(combase);
}
