/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Tests for the table-driven QueryInterface helper QISearch
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Rows measured on Windows Server 2022.
 */

#include <apitest.h>
#include <shlwapi.h>
#include <initguid.h>

DEFINE_GUID(IID_TestA, 0xaaaaaaaa, 1, 2, 3, 3, 3, 3, 3, 3, 3, 3);
DEFINE_GUID(IID_TestB, 0xbbbbbbbb, 1, 2, 3, 3, 3, 3, 3, 3, 3, 3);
DEFINE_GUID(IID_TestC, 0xcccccccc, 1, 2, 3, 3, 3, 3, 3, 3, 3, 3);

static LONG s_AddRefs;

static ULONG WINAPI Obj_AddRef(IUnknown *This)
{
    return InterlockedIncrement(&s_AddRefs);
}

START_TEST(QISearch)
{
    typedef HRESULT (WINAPI *PFN_QISearch)(void *, const QITAB *, REFIID, void **);
    HMODULE hShlwapi = GetModuleHandleW(L"shlwapi.dll");
    PFN_QISearch pByName, pByOrdinal;
    void *vtbl[3] = { NULL, (void *)Obj_AddRef, NULL };
    struct { void *Itf1; void *Itf2; } obj = { vtbl, vtbl };
    QITAB tab[3];
    void *out;
    HRESULT hr;

    pByName = (PFN_QISearch)GetProcAddress(hShlwapi, "QISearch");
    pByOrdinal = (PFN_QISearch)GetProcAddress(hShlwapi, (LPCSTR)219);
    ok(pByName != NULL, "QISearch is not exported by name\n");
    ok(pByOrdinal != NULL, "QISearch is not exported by ordinal 219\n");
    if (!pByName || !pByOrdinal)
    {
        skip("QISearch is missing\n");
        return;
    }
    ok(pByName == pByOrdinal, "name %p, ordinal %p\n", pByName, pByOrdinal);

    tab[0].piid = &IID_TestA;
    tab[0].dwOffset = 0;
    tab[1].piid = &IID_TestB;
    tab[1].dwOffset = sizeof(void *);
    tab[2].piid = NULL;
    tab[2].dwOffset = 0;

    s_AddRefs = 0;
    out = (void *)1;
    hr = pByName(&obj, tab, &IID_TestA, &out);
    ok_hex(hr, S_OK);
    ok(out == &obj.Itf1, "out = %p\n", out);
    ok_long(s_AddRefs, 1);

    out = (void *)1;
    hr = pByName(&obj, tab, &IID_TestB, &out);
    ok_hex(hr, S_OK);
    ok(out == &obj.Itf2, "out = %p\n", out);
    ok_long(s_AddRefs, 2);

    out = (void *)1;
    hr = pByName(&obj, tab, &IID_TestC, &out);
    ok_hex(hr, E_NOINTERFACE);
    ok(out == NULL, "out = %p\n", out);
    ok_long(s_AddRefs, 2);

    /* IID_IUnknown is answered with the first table entry although the table does not list it */
    out = (void *)1;
    hr = pByName(&obj, tab, &IID_IUnknown, &out);
    ok_hex(hr, S_OK);
    ok(out == &obj.Itf1, "out = %p\n", out);

    tab[0].piid = &IID_TestB;
    tab[0].dwOffset = sizeof(void *);
    tab[1].piid = &IID_TestA;
    tab[1].dwOffset = 0;
    out = (void *)1;
    hr = pByName(&obj, tab, &IID_IUnknown, &out);
    ok_hex(hr, S_OK);
    ok(out == &obj.Itf2, "out = %p\n", out);

    hr = pByName(&obj, tab, &IID_TestA, NULL);
    ok_hex(hr, E_POINTER);
}
