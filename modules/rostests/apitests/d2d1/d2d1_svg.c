/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     ID2D1DeviceContext5::CreateSvgDocument returns a real SVG document: the root <svg> element,
 *              the tree (append, insert, replace, remove), attributes, text, FindElementById, viewport size
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Interface ids and vtable order come from reactos/d2d1_svg.h (microsoft/windows-rs only). Cases
 * that are not measured on Windows (NULL arguments, error codes of invalid trees) are marked and
 * only check that the call does not crash and does not succeed.
 */

#define COBJMACROS
#include <initguid.h>
#include <windows.h>
#include <d3d11.h>
#include <d2d1_3.h>
#include <reactos/d2d1_svg.h>

#include "wine/test.h"

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#endif

static ID2D1DeviceContext5 *create_context(ID3D11Device **d3d_device, ID2D1Device **d2d_device)
{
    static const D3D_DRIVER_TYPE types[] = {D3D_DRIVER_TYPE_HARDWARE, D3D_DRIVER_TYPE_WARP};
    ID2D1DeviceContext *context = NULL;
    ID2D1DeviceContext5 *context5 = NULL;
    IDXGIDevice *dxgi_device;
    unsigned int i;
    HRESULT hr = E_FAIL;

    *d3d_device = NULL;
    *d2d_device = NULL;
    for (i = 0; i < 2 && FAILED(hr); ++i)
        hr = D3D11CreateDevice(NULL, types[i], NULL, D3D11_CREATE_DEVICE_BGRA_SUPPORT, NULL, 0,
                D3D11_SDK_VERSION, d3d_device, NULL, NULL);
    if (FAILED(hr))
        return NULL;
    hr = ID3D11Device_QueryInterface(*d3d_device, &IID_IDXGIDevice, (void **)&dxgi_device);
    ok(hr == S_OK, "QueryInterface failed, hr %#lx\n", hr);
    hr = D2D1CreateDevice(dxgi_device, NULL, d2d_device);
    IDXGIDevice_Release(dxgi_device);
    if (FAILED(hr))
        return NULL;
    hr = ID2D1Device_CreateDeviceContext(*d2d_device, D2D1_DEVICE_CONTEXT_OPTIONS_NONE, &context);
    if (FAILED(hr))
        return NULL;
    hr = ID2D1DeviceContext_QueryInterface(context, &IID_ID2D1DeviceContext5, (void **)&context5);
    ID2D1DeviceContext_Release(context);
    if (FAILED(hr))
        trace("ID2D1DeviceContext5 is not available, hr %#lx\n", hr);
    return context5;
}

static void check_tag(ID2D1SvgElement *element, const WCHAR *expected)
{
    WCHAR buffer[32];
    UINT32 len = ID2D1SvgElement_GetTagNameLength(element);
    HRESULT hr;

    ok(len == wcslen(expected), "tag length %u, expected %u\n", len, (unsigned)wcslen(expected));
    hr = ID2D1SvgElement_GetTagName(element, buffer, ARRAY_SIZE(buffer));
    ok(hr == S_OK, "GetTagName failed, hr %#lx\n", hr);
    ok(!wcscmp(buffer, expected), "tag %s, expected %s\n", wine_dbgstr_w(buffer), wine_dbgstr_w(expected));
}

static void test_document(ID2D1DeviceContext5 *context)
{
    ID2D1SvgDocument *doc;
    ID2D1SvgElement *root, *root2, *a, *b, *c, *got, *parent;
    ID2D1SvgDocument *got_doc;
    ID2D1Factory *factory;
    IUnknown *unk;
    D2D1_SIZE_F size, vp = {200.0f, 100.0f};
    ULONG ref;
    HRESULT hr;

    hr = ID2D1DeviceContext5_CreateSvgDocument(context, NULL, vp, &doc);
    ok(hr == S_OK, "CreateSvgDocument failed, hr %#lx\n", hr);
    if (FAILED(hr))
        return;

    /* the interface */
    hr = ID2D1SvgDocument_QueryInterface(doc, &IID_IUnknown, (void **)&unk);
    ok(hr == S_OK, "QueryInterface(IUnknown) failed, hr %#lx\n", hr);
    IUnknown_Release(unk);
    hr = ID2D1SvgDocument_QueryInterface(doc, &IID_ID2D1Resource, (void **)&unk);
    ok(hr == S_OK, "QueryInterface(ID2D1Resource) failed, hr %#lx\n", hr);
    IUnknown_Release(unk);
    hr = ID2D1SvgDocument_QueryInterface(doc, &IID_ID2D1SvgElement, (void **)&unk);
    ok(hr == E_NOINTERFACE, "QueryInterface(ID2D1SvgElement) returned %#lx\n", hr);
    ID2D1SvgDocument_GetFactory(doc, &factory);
    ok(factory != NULL, "GetFactory returned NULL\n");
    if (factory)
        ID2D1Factory_Release(factory);

    /* viewport */
    memset(&size, 0xcc, sizeof(size));
    ID2D1SvgDocument_GetViewportSize(doc, &size);
    ok(size.width == 200.0f && size.height == 100.0f, "viewport %.1f x %.1f\n", size.width, size.height);
    size.width = 31.5f;
    size.height = 7.0f;
    hr = ID2D1SvgDocument_SetViewportSize(doc, size);
    ok(hr == S_OK, "SetViewportSize failed, hr %#lx\n", hr);
    memset(&size, 0, sizeof(size));
    ID2D1SvgDocument_GetViewportSize(doc, &size);
    ok(size.width == 31.5f && size.height == 7.0f, "viewport %.1f x %.1f\n", size.width, size.height);

    /* the empty document has a root <svg> element without parent, children, attributes */
    root = NULL;
    ID2D1SvgDocument_GetRoot(doc, &root);
    ok(root != NULL, "the empty document has no root element\n");
    if (!root)
    {
        ID2D1SvgDocument_Release(doc);
        return;
    }
    check_tag(root, L"svg");
    ok(!ID2D1SvgElement_IsTextContent(root), "root is a text content element\n");
    ok(!ID2D1SvgElement_HasChildren(root), "root has children\n");
    ok(ID2D1SvgElement_GetSpecifiedAttributeCount(root) == 0, "root has attributes\n");
    parent = (void *)0xdeadbeef;
    ID2D1SvgElement_GetParent(root, &parent);
    ok(parent == NULL, "root has a parent %p\n", parent);
    got_doc = NULL;
    ID2D1SvgElement_GetDocument(root, &got_doc);
    ok(got_doc == doc, "GetDocument returned %p, expected %p\n", got_doc, doc);
    if (got_doc)
        ID2D1SvgDocument_Release(got_doc);
    root2 = NULL;
    ID2D1SvgDocument_GetRoot(doc, &root2);
    ok(root2 == root, "GetRoot returned %p, then %p\n", root, root2);
    if (root2)
        ID2D1SvgElement_Release(root2);

    /* children: CreateChild appends; InsertChildBefore, GetFirst/Last/Previous/Next */
    hr = ID2D1SvgElement_CreateChild(root, L"g", &a);
    ok(hr == S_OK, "CreateChild failed, hr %#lx\n", hr);
    hr = ID2D1SvgElement_CreateChild(root, L"rect", &b);
    ok(hr == S_OK, "CreateChild failed, hr %#lx\n", hr);
    check_tag(a, L"g");
    check_tag(b, L"rect");
    ok(ID2D1SvgElement_HasChildren(root), "root has no children\n");
    ID2D1SvgElement_GetFirstChild(root, &got);
    ok(got == a, "first child %p, expected %p\n", got, a);
    if (got)
        ID2D1SvgElement_Release(got);
    ID2D1SvgElement_GetLastChild(root, &got);
    ok(got == b, "last child %p, expected %p\n", got, b);
    if (got)
        ID2D1SvgElement_Release(got);
    ID2D1SvgElement_GetParent(a, &got);
    ok(got == root, "parent %p, expected %p\n", got, root);
    if (got)
        ID2D1SvgElement_Release(got);

    hr = ID2D1SvgElement_CreateChild(a, L"circle", &c);
    ok(hr == S_OK, "CreateChild failed, hr %#lx\n", hr);
    /* c is a child of a; it cannot be appended to root while it has a parent (not measured: error code) */
    hr = ID2D1SvgElement_AppendChild(root, c);
    ok(FAILED(hr), "AppendChild of an element with a parent returned %#lx\n", hr);
    hr = ID2D1SvgElement_RemoveChild(a, c);
    ok(hr == S_OK, "RemoveChild failed, hr %#lx\n", hr);
    ID2D1SvgElement_GetParent(c, &got);
    ok(got == NULL, "removed child has a parent %p\n", got);
    hr = ID2D1SvgElement_InsertChildBefore(root, c, b);
    ok(hr == S_OK, "InsertChildBefore failed, hr %#lx\n", hr);
    /* order is now a, c, b */
    hr = ID2D1SvgElement_GetNextChild(root, a, &got);
    ok(hr == S_OK && got == c, "next of a: hr %#lx, %p, expected %p\n", hr, got, c);
    if (got)
        ID2D1SvgElement_Release(got);
    hr = ID2D1SvgElement_GetNextChild(root, b, &got);
    ok(hr == S_OK && got == NULL, "next of b: hr %#lx, %p\n", hr, got);
    hr = ID2D1SvgElement_GetPreviousChild(root, b, &got);
    ok(hr == S_OK && got == c, "previous of b: hr %#lx, %p, expected %p\n", hr, got, c);
    if (got)
        ID2D1SvgElement_Release(got);
    hr = ID2D1SvgElement_GetPreviousChild(root, a, &got);
    ok(hr == S_OK && got == NULL, "previous of a: hr %#lx, %p\n", hr, got);
    /* a cannot become a child of its own descendant (not measured: error code) */
    ID2D1SvgElement_RemoveChild(root, a);
    hr = ID2D1SvgElement_AppendChild(c, a);
    ok(hr == S_OK, "AppendChild failed, hr %#lx\n", hr);
    ID2D1SvgElement_RemoveChild(root, c);
    hr = ID2D1SvgElement_AppendChild(a, c);
    ok(FAILED(hr), "AppendChild of an ancestor returned %#lx\n", hr);
    hr = ID2D1SvgElement_AppendChild(root, c);
    ok(hr == S_OK, "AppendChild failed, hr %#lx\n", hr);
    {
        unsigned int n = 0;
        ID2D1SvgElement *e = NULL, *next;
        ID2D1SvgElement_GetFirstChild(root, &e);
        while (e)
        {
            ++n;
            next = NULL;
            ID2D1SvgElement_GetNextChild(root, e, &next);
            ID2D1SvgElement_Release(e);
            e = next;
        }
        ok(n == 2, "root has %u children, expected 2\n", n);
    }
    hr = ID2D1SvgElement_RemoveChild(root, c);
    ok(hr == S_OK, "RemoveChild failed, hr %#lx\n", hr);
    hr = ID2D1SvgElement_RemoveChild(root, c);
    ok(FAILED(hr), "RemoveChild of a non-child returned %#lx\n", hr);
    hr = ID2D1SvgElement_ReplaceChild(root, c, b);
    ok(hr == S_OK, "ReplaceChild failed, hr %#lx\n", hr);
    ID2D1SvgElement_GetParent(b, &got);
    ok(got == NULL, "replaced child has a parent %p\n", got);
    ID2D1SvgElement_GetParent(c, &got);
    ok(got == root, "new child has parent %p\n", got);
    if (got)
        ID2D1SvgElement_Release(got);

    /* attributes: string, POD, round trip, enumeration, removal, FindElementById */
    {
        WCHAR buf[64];
        UINT32 len;
        BOOL inherited = TRUE;
        BOOL spec;
        FLOAT f = 0.0f, f2 = 0.5f;
        D2D1_COLOR_F col = {1.0f, 0.5f, 0.25f, 1.0f}, col2;
        UINT32 u = 0;

        spec = ID2D1SvgElement_IsAttributeSpecified(a, L"fill", &inherited);
        ok(!spec, "fill is specified on a fresh element\n");
        hr = ID2D1SvgElement_SetAttributeValueString(a, L"id", D2D1_SVG_ATTRIBUTE_STRING_TYPE_SVG, L"icon-a");
        ok(hr == S_OK, "SetAttributeValue (string) failed, hr %#lx\n", hr);
        hr = ID2D1SvgElement_SetAttributeValueString(a, L"class", D2D1_SVG_ATTRIBUTE_STRING_TYPE_SVG, L"x y");
        ok(hr == S_OK, "SetAttributeValue (string) failed, hr %#lx\n", hr);
        f = 3.5f;
        hr = ID2D1SvgElement_SetAttributeValuePOD(a, L"stroke-width", D2D1_SVG_ATTRIBUTE_POD_TYPE_FLOAT, &f, sizeof(f));
        ok(hr == S_OK, "SetAttributeValue (float) failed, hr %#lx\n", hr);
        hr = ID2D1SvgElement_SetAttributeValuePOD(a, L"stop-color", D2D1_SVG_ATTRIBUTE_POD_TYPE_COLOR, &col, sizeof(col));
        ok(hr == S_OK, "SetAttributeValue (color) failed, hr %#lx\n", hr);
        hr = ID2D1SvgElement_SetAttributeValuePOD(a, L"stroke-width", D2D1_SVG_ATTRIBUTE_POD_TYPE_FLOAT, &f2, 3);
        ok(FAILED(hr), "SetAttributeValue with a wrong size returned %#lx\n", hr);

        spec = ID2D1SvgElement_IsAttributeSpecified(a, L"id", &inherited);
        ok(spec && !inherited, "id: specified %d, inherited %d\n", spec, inherited);
        ok(ID2D1SvgElement_GetSpecifiedAttributeCount(a) == 4, "attribute count %u\n",
                ID2D1SvgElement_GetSpecifiedAttributeCount(a));
        len = 0;
        hr = ID2D1SvgElement_GetAttributeValueLength(a, L"class", D2D1_SVG_ATTRIBUTE_STRING_TYPE_SVG, &len);
        ok(hr == S_OK && len == 3, "GetAttributeValueLength: hr %#lx, %u\n", hr, len);
        hr = ID2D1SvgElement_GetAttributeValueString(a, L"class", D2D1_SVG_ATTRIBUTE_STRING_TYPE_SVG, buf, ARRAY_SIZE(buf));
        ok(hr == S_OK && !wcscmp(buf, L"x y"), "GetAttributeValue (string): hr %#lx, %s\n", hr, wine_dbgstr_w(buf));
        hr = ID2D1SvgElement_GetAttributeValueString(a, L"class", D2D1_SVG_ATTRIBUTE_STRING_TYPE_SVG, buf, 3);
        ok(hr == E_NOT_SUFFICIENT_BUFFER, "GetAttributeValue (small buffer) returned %#lx\n", hr);
        f = 0.0f;
        hr = ID2D1SvgElement_GetAttributeValuePOD(a, L"stroke-width", D2D1_SVG_ATTRIBUTE_POD_TYPE_FLOAT, &f, sizeof(f));
        ok(hr == S_OK && f == 3.5f, "GetAttributeValue (float): hr %#lx, %.2f\n", hr, f);
        memset(&col2, 0, sizeof(col2));
        hr = ID2D1SvgElement_GetAttributeValuePOD(a, L"stop-color", D2D1_SVG_ATTRIBUTE_POD_TYPE_COLOR, &col2, sizeof(col2));
        ok(hr == S_OK && !memcmp(&col, &col2, sizeof(col)), "GetAttributeValue (color): hr %#lx\n", hr);
        hr = ID2D1SvgElement_GetAttributeValuePOD(a, L"stroke-width", D2D1_SVG_ATTRIBUTE_POD_TYPE_FILL_MODE, &u, sizeof(u));
        ok(FAILED(hr), "GetAttributeValue with another POD type returned %#lx\n", hr);
        hr = ID2D1SvgElement_GetAttributeValuePOD(a, L"missing", D2D1_SVG_ATTRIBUTE_POD_TYPE_FLOAT, &f, sizeof(f));
        ok(FAILED(hr), "GetAttributeValue of a missing attribute returned %#lx\n", hr);
        len = 0;
        hr = ID2D1SvgElement_GetSpecifiedAttributeNameLength(a, 0, &len, &inherited);
        ok(hr == S_OK && len == 2, "GetSpecifiedAttributeNameLength(0): hr %#lx, %u\n", hr, len);
        hr = ID2D1SvgElement_GetSpecifiedAttributeName(a, 0, buf, ARRAY_SIZE(buf), &inherited);
        ok(hr == S_OK && !wcscmp(buf, L"id"), "GetSpecifiedAttributeName(0): hr %#lx, %s\n", hr, wine_dbgstr_w(buf));
        hr = ID2D1SvgElement_GetSpecifiedAttributeName(a, 4, buf, ARRAY_SIZE(buf), &inherited);
        ok(FAILED(hr), "GetSpecifiedAttributeName(4) returned %#lx\n", hr);

        /* overwrite keeps one attribute */
        hr = ID2D1SvgElement_SetAttributeValueString(a, L"class", D2D1_SVG_ATTRIBUTE_STRING_TYPE_SVG, L"z");
        ok(hr == S_OK, "overwrite failed, hr %#lx\n", hr);
        ok(ID2D1SvgElement_GetSpecifiedAttributeCount(a) == 4, "attribute count %u after overwrite\n",
                ID2D1SvgElement_GetSpecifiedAttributeCount(a));

        got = NULL;
        hr = ID2D1SvgDocument_FindElementById(doc, L"icon-a", &got);
        ok(hr == S_OK && got == a, "FindElementById: hr %#lx, %p, expected %p\n", hr, got, a);
        if (got)
            ID2D1SvgElement_Release(got);
        got = (void *)0xdeadbeef;
        hr = ID2D1SvgDocument_FindElementById(doc, L"nope", &got);
        ok(SUCCEEDED(hr) ? got == NULL : TRUE, "FindElementById (missing) hr %#lx, %p\n", hr, got);

        hr = ID2D1SvgElement_RemoveAttribute(a, L"class");
        ok(hr == S_OK, "RemoveAttribute failed, hr %#lx\n", hr);
        ok(!ID2D1SvgElement_IsAttributeSpecified(a, L"class", NULL), "class is still specified\n");
        ok(ID2D1SvgElement_GetSpecifiedAttributeCount(a) == 3, "attribute count %u\n",
                ID2D1SvgElement_GetSpecifiedAttributeCount(a));

        /* text value */
        ok(ID2D1SvgElement_GetTextValueLength(a) == 0, "text length %u\n", ID2D1SvgElement_GetTextValueLength(a));
        hr = ID2D1SvgElement_SetTextValue(a, L"hello", 5);
        ok(hr == S_OK, "SetTextValue failed, hr %#lx\n", hr);
        ok(ID2D1SvgElement_GetTextValueLength(a) == 5, "text length %u\n", ID2D1SvgElement_GetTextValueLength(a));
        hr = ID2D1SvgElement_GetTextValue(a, buf, ARRAY_SIZE(buf));
        ok(hr == S_OK && !wcscmp(buf, L"hello"), "GetTextValue: hr %#lx, %s\n", hr, wine_dbgstr_w(buf));
    }

    /* SetRoot: an element of the document without parent; the old root loses its document role */
    hr = ID2D1SvgElement_CreateChild(root, L"svg", &got);
    ok(hr == S_OK, "CreateChild failed, hr %#lx\n", hr);
    hr = ID2D1SvgDocument_SetRoot(doc, got);
    ok(FAILED(hr), "SetRoot of an element with a parent returned %#lx\n", hr);
    ID2D1SvgElement_Release(got);

    /* lifetime: elements survive the release of the document and drop their document */
    ID2D1SvgElement_AddRef(root);
    ref = ID2D1SvgDocument_Release(doc);
    ok(ref == 0, "document refcount %lu\n", ref);
    got_doc = (void *)0xdeadbeef;
    ID2D1SvgElement_GetDocument(a, &got_doc);
    ok(got_doc == NULL, "element still has a document %p\n", got_doc);
    check_tag(a, L"g");
    ID2D1SvgElement_Release(root);
    ID2D1SvgElement_Release(root);
    ID2D1SvgElement_Release(a);
    ID2D1SvgElement_Release(b);
    ID2D1SvgElement_Release(c);
}

static void test_null_args(ID2D1DeviceContext5 *context)
{
    ID2D1SvgDocument *doc = NULL;
    ID2D1SvgElement *root = NULL, *e = NULL;
    D2D1_SIZE_F vp = {10.0f, 10.0f};
    HRESULT hr;

    /* Not measured on Windows: these only check that NULL arguments do not crash and fail. */
    hr = ID2D1DeviceContext5_CreateSvgDocument(context, NULL, vp, NULL);
    ok(FAILED(hr), "CreateSvgDocument with a NULL output returned %#lx\n", hr);

    hr = ID2D1DeviceContext5_CreateSvgDocument(context, NULL, vp, &doc);
    ok(hr == S_OK, "CreateSvgDocument failed, hr %#lx\n", hr);
    if (FAILED(hr))
        return;
    ID2D1SvgDocument_GetRoot(doc, &root);
    hr = ID2D1SvgElement_AppendChild(root, NULL);
    ok(FAILED(hr), "AppendChild(NULL) returned %#lx\n", hr);
    hr = ID2D1SvgElement_CreateChild(root, NULL, &e);
    ok(FAILED(hr) && !e, "CreateChild(NULL tag) returned %#lx\n", hr);
    hr = ID2D1SvgElement_SetAttributeValueString(root, NULL, D2D1_SVG_ATTRIBUTE_STRING_TYPE_SVG, L"x");
    ok(FAILED(hr), "SetAttributeValue(NULL name) returned %#lx\n", hr);
    hr = ID2D1SvgElement_SetAttributeValueString(root, L"x", D2D1_SVG_ATTRIBUTE_STRING_TYPE_SVG, NULL);
    ok(FAILED(hr), "SetAttributeValue(NULL value) returned %#lx\n", hr);
    hr = ID2D1SvgElement_GetTagName(root, NULL, 0);
    ok(FAILED(hr), "GetTagName(NULL) returned %#lx\n", hr);
    hr = ID2D1SvgDocument_FindElementById(doc, NULL, &e);
    ok(FAILED(hr), "FindElementById(NULL) returned %#lx\n", hr);
    ID2D1SvgElement_Release(root);
    ID2D1SvgDocument_Release(doc);
}

static void test_iids(void)
{
    /* the ids come from windows-rs */
    static const GUID doc_iid = {0x86b88e4d, 0xafa4, 0x4d7b, {0x88, 0xe4, 0x68, 0xa5, 0x1c, 0x4a, 0x0a, 0xec}};
    static const GUID elem_iid = {0xac7b67a6, 0x183e, 0x49c1, {0xa8, 0x23, 0x0e, 0xbe, 0x40, 0xb0, 0xdb, 0x29}};

    ok(IsEqualGUID(&IID_ID2D1SvgDocument, &doc_iid), "ID2D1SvgDocument iid\n");
    ok(IsEqualGUID(&IID_ID2D1SvgElement, &elem_iid), "ID2D1SvgElement iid\n");
}

START_TEST(d2d1_svg)
{
    ID3D11Device *d3d_device;
    ID2D1Device *d2d_device;
    ID2D1DeviceContext5 *context;

    test_iids();

    if (!(context = create_context(&d3d_device, &d2d_device)))
    {
        skip("No Direct2D device context with SVG support\n");
        return;
    }
    test_document(context);
    test_null_args(context);
    ID2D1DeviceContext5_Release(context);
    ID2D1Device_Release(d2d_device);
    ID3D11Device_Release(d3d_device);
}
