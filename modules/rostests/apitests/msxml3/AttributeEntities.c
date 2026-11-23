/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Entity references in attribute values: the DOM and SAX of msxml3 and msxml6, and xmllite reading
 *              the document from a stream that returns a few bytes per Read
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Windows Server 2022 (probes on the reference): "&lt;" and "&gt;" in an attribute value are expanded by
 * DOMDocument30/60 and SAXXMLReader30/60; xmllite reads the document whole whatever number of bytes the stream
 * returns per Read (1 to 4096 tried) and returns the expanded values.
 */

#define COBJMACROS
#include <apitest.h>
#include <windef.h>
#include <winbase.h>
#include <ole2.h>
#include <oleauto.h>
#include <msxml2.h>
#include <xmllite.h>

#define DEFINE_GUID_(name, a, b, c, d0, d1, d2, d3, d4, d5, d6, d7) \
    static const GUID name = { a, b, c, { d0, d1, d2, d3, d4, d5, d6, d7 } }

DEFINE_GUID_(TEST_DOMDocument30, 0xF5078F32, 0xC551, 0x11D3, 0x89, 0xB9, 0x00, 0x00, 0xF8, 0x1F, 0xE2, 0x21);
DEFINE_GUID_(TEST_DOMDocument60, 0x88D96A05, 0xF192, 0x11D4, 0xA6, 0x5F, 0x00, 0x40, 0x96, 0x32, 0x51, 0xE5);
DEFINE_GUID_(TEST_SAXXMLReader30, 0x3124C396, 0xFB13, 0x4836, 0xA6, 0xAD, 0x13, 0x17, 0xF1, 0x71, 0x36, 0x88);
DEFINE_GUID_(TEST_SAXXMLReader60, 0x88D96A0C, 0xF192, 0x11D4, 0xA6, 0x5F, 0x00, 0x40, 0x96, 0x32, 0x51, 0xE5);
DEFINE_GUID_(TEST_IID_IXMLDOMDocument, 0x2933BF81, 0x7B36, 0x11D2, 0xB2, 0x0E, 0x00, 0xC0, 0x4F, 0x98, 0x3E, 0x60);
DEFINE_GUID_(TEST_IID_ISAXXMLReader, 0xA4F96ED0, 0xF829, 0x476E, 0x81, 0xC0, 0xCD, 0xC7, 0xBD, 0x2A, 0x08, 0x02);
DEFINE_GUID_(TEST_IID_IXmlReader, 0x7279FC81, 0x709D, 0x4095, 0xB6, 0x3D, 0x69, 0xFE, 0x4B, 0x0D, 0x90, 0x30);

static const char Document[] =
    "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<AutoVisualizer>"
    "<Type Name=\"Concurrency::multitype_join&lt;*,*&gt;\"><DisplayString>{x}</DisplayString></Type>"
    "<Type Name=\"std::vector&lt;bool,*&gt;\" Priority=\"Medium&amp;\"/>"
    "</AutoVisualizer>\n";
static const WCHAR *Expected[] = { L"Concurrency::multitype_join<*,*>", L"std::vector<bool,*>", L"Medium&" };

static void TestDom(const GUID *Clsid, const char *Name)
{
    IXMLDOMDocument *Doc = NULL;
    IXMLDOMNodeList *List = NULL;
    IXMLDOMNode *Node = NULL;
    VARIANT_BOOL Ok = VARIANT_FALSE;
    WCHAR Text[512];
    BSTR Xml, Query, Value = NULL;
    HRESULT hr;

    hr = CoCreateInstance(Clsid, NULL, CLSCTX_INPROC_SERVER, &TEST_IID_IXMLDOMDocument, (void **)&Doc);
    ok(hr == S_OK, "%s: CoCreateInstance 0x%08lx\n", Name, hr);
    if (FAILED(hr))
        return;
    MultiByteToWideChar(CP_UTF8, 0, Document, -1, Text, _countof(Text));
    Xml = SysAllocString(Text);
    hr = IXMLDOMDocument_loadXML(Doc, Xml, &Ok);
    ok(hr == S_OK && Ok == VARIANT_TRUE, "%s: loadXML 0x%08lx %d\n", Name, hr, Ok);
    Query = SysAllocString(L"//Type/@Name");
    if (Ok == VARIANT_TRUE && SUCCEEDED(IXMLDOMDocument_selectNodes(Doc, Query, &List)) && List)
    {
        if (IXMLDOMNodeList_nextNode(List, &Node) == S_OK && Node)
        {
            ok(IXMLDOMNode_get_text(Node, &Value) == S_OK && Value && !wcscmp(Value, Expected[0]),
               "%s: attribute \"%ls\"\n", Name, Value ? Value : L"(none)");
            SysFreeString(Value);
            IXMLDOMNode_Release(Node);
        }
        else
        {
            ok(FALSE, "%s: no attribute node\n", Name);
        }
        IXMLDOMNodeList_Release(List);
    }
    SysFreeString(Query);
    SysFreeString(Xml);
    IXMLDOMDocument_Release(Doc);
}

static void TestSax(const GUID *Clsid, const char *Name)
{
    ISAXXMLReader *Reader = NULL;
    WCHAR Text[512];
    VARIANT Input;
    HRESULT hr;

    hr = CoCreateInstance(Clsid, NULL, CLSCTX_INPROC_SERVER, &TEST_IID_ISAXXMLReader, (void **)&Reader);
    ok(hr == S_OK, "%s: CoCreateInstance 0x%08lx\n", Name, hr);
    if (FAILED(hr))
        return;
    MultiByteToWideChar(CP_UTF8, 0, Document, -1, Text, _countof(Text));
    VariantInit(&Input);
    V_VT(&Input) = VT_BSTR;
    V_BSTR(&Input) = SysAllocString(Text);
    hr = ISAXXMLReader_parse(Reader, Input);
    ok(hr == S_OK, "%s: parse 0x%08lx\n", Name, hr);
    VariantClear(&Input);
    ISAXXMLReader_Release(Reader);
}

/* A stream that returns at most Chunk bytes per Read */
typedef struct
{
    IStream IStream_iface;
    const char *Data;
    ULONG Length, Position, Chunk;
} CHUNK_STREAM;

static HRESULT WINAPI Chunk_QueryInterface(IStream *This, REFIID riid, void **ppv)
{
    if (IsEqualIID(riid, &IID_IUnknown) || IsEqualIID(riid, &IID_IStream) || IsEqualIID(riid, &IID_ISequentialStream))
    {
        *ppv = This;
        return S_OK;
    }
    *ppv = NULL;
    return E_NOINTERFACE;
}
static ULONG WINAPI Chunk_AddRef(IStream *This) { return 2; }
static ULONG WINAPI Chunk_Release(IStream *This) { return 1; }
static HRESULT WINAPI Chunk_Read(IStream *This, void *pv, ULONG cb, ULONG *pcbRead)
{
    CHUNK_STREAM *Stream = CONTAINING_RECORD(This, CHUNK_STREAM, IStream_iface);
    ULONG Count = min(min(cb, Stream->Chunk), Stream->Length - Stream->Position);

    memcpy(pv, Stream->Data + Stream->Position, Count);
    Stream->Position += Count;
    if (pcbRead)
        *pcbRead = Count;
    return Count ? S_OK : S_FALSE;
}
static HRESULT WINAPI Chunk_Write(IStream *This, const void *pv, ULONG cb, ULONG *pcbWritten) { return E_NOTIMPL; }
static HRESULT WINAPI Chunk_Seek(IStream *This, LARGE_INTEGER dlibMove, DWORD dwOrigin, ULARGE_INTEGER *plibNewPosition) { return E_NOTIMPL; }
static HRESULT WINAPI Chunk_SetSize(IStream *This, ULARGE_INTEGER libNewSize) { return E_NOTIMPL; }
static HRESULT WINAPI Chunk_CopyTo(IStream *This, IStream *pstm, ULARGE_INTEGER cb, ULARGE_INTEGER *pcbRead, ULARGE_INTEGER *pcbWritten) { return E_NOTIMPL; }
static HRESULT WINAPI Chunk_Commit(IStream *This, DWORD grfCommitFlags) { return E_NOTIMPL; }
static HRESULT WINAPI Chunk_Revert(IStream *This) { return E_NOTIMPL; }
static HRESULT WINAPI Chunk_LockRegion(IStream *This, ULARGE_INTEGER libOffset, ULARGE_INTEGER cb, DWORD dwLockType) { return E_NOTIMPL; }
static HRESULT WINAPI Chunk_UnlockRegion(IStream *This, ULARGE_INTEGER libOffset, ULARGE_INTEGER cb, DWORD dwLockType) { return E_NOTIMPL; }
static HRESULT WINAPI Chunk_Stat(IStream *This, STATSTG *pstatstg, DWORD grfStatFlag) { return E_NOTIMPL; }
static HRESULT WINAPI Chunk_Clone(IStream *This, IStream **ppstm) { return E_NOTIMPL; }

static const IStreamVtbl ChunkVtbl =
{
    Chunk_QueryInterface, Chunk_AddRef, Chunk_Release, Chunk_Read, Chunk_Write, Chunk_Seek, Chunk_SetSize,
    Chunk_CopyTo, Chunk_Commit, Chunk_Revert, Chunk_LockRegion, Chunk_UnlockRegion, Chunk_Stat, Chunk_Clone
};

typedef HRESULT (WINAPI *FN_CreateXmlReader)(REFIID, void **, IMalloc *);

static void TestXmlLite(FN_CreateXmlReader pCreateXmlReader, ULONG Chunk)
{
    CHUNK_STREAM Stream;
    IXmlReader *Reader = NULL;
    XmlNodeType Type;
    const WCHAR *Value;
    ULONG Attributes = 0;
    HRESULT hr;

    Stream.IStream_iface.lpVtbl = (IStreamVtbl *)&ChunkVtbl;
    Stream.Data = Document;
    Stream.Length = sizeof(Document) - 1;
    Stream.Position = 0;
    Stream.Chunk = Chunk;

    hr = pCreateXmlReader(&TEST_IID_IXmlReader, (void **)&Reader, NULL);
    ok(hr == S_OK, "CreateXmlReader 0x%08lx\n", hr);
    if (FAILED(hr))
        return;
    hr = IXmlReader_SetInput(Reader, (IUnknown *)&Stream.IStream_iface);
    ok(hr == S_OK, "%lu bytes per read: SetInput 0x%08lx\n", Chunk, hr);
    for (;;)
    {
        hr = IXmlReader_Read(Reader, &Type);
        if (hr != S_OK)
            break;
        if (Type != XmlNodeType_Element)
            continue;
        while (IXmlReader_MoveToNextAttribute(Reader) == S_OK)
        {
            Value = NULL;
            IXmlReader_GetValue(Reader, &Value, NULL);
            if (Attributes < _countof(Expected))
                ok(Value && !wcscmp(Value, Expected[Attributes]), "%lu bytes per read: attribute %lu \"%ls\"\n",
                   Chunk, Attributes, Value ? Value : L"(none)");
            Attributes++;
        }
    }
    ok(hr == S_FALSE, "%lu bytes per read: Read 0x%08lx at the end\n", Chunk, hr);
    ok(Attributes == _countof(Expected), "%lu bytes per read: %lu attributes\n", Chunk, Attributes);
    IXmlReader_Release(Reader);
}

START_TEST(AttributeEntities)
{
    static const ULONG Chunks[] = { 1, 2, 3, 5, 8, 13, 64, 4096 };
    FN_CreateXmlReader pCreateXmlReader;
    HMODULE XmlLite;
    ULONG i;

    CoInitialize(NULL);
    TestDom(&TEST_DOMDocument30, "DOMDocument30");
    TestDom(&TEST_DOMDocument60, "DOMDocument60");
    TestSax(&TEST_SAXXMLReader30, "SAXXMLReader30");
    TestSax(&TEST_SAXXMLReader60, "SAXXMLReader60");

    XmlLite = LoadLibraryW(L"xmllite.dll");
    pCreateXmlReader = XmlLite ? (FN_CreateXmlReader)GetProcAddress(XmlLite, "CreateXmlReader") : NULL;
    ok(pCreateXmlReader != NULL, "no CreateXmlReader\n");
    if (pCreateXmlReader)
    {
        for (i = 0; i < _countof(Chunks); i++)
            TestXmlLite(pCreateXmlReader, Chunks[i]);
    }
    CoUninitialize();
}
