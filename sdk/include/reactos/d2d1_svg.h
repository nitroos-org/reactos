/*
 * ID2D1SvgDocument and the SVG attribute / element interfaces of Direct2D.
 *
 * Provenance (clean room): interface IDs, enum values, structure members and the
 * vtable member order of every interface in this file were taken ONLY from
 * microsoft/windows-rs (MIT / Apache-2.0), repository commit
 * cd03f9369a896b62151242c1c3321e695df63cfc, file
 * crates/libs/windows/src/Windows/Win32/d2d/mod.rs:
 *   ID2D1SvgAttribute        c9cdb0dd-f8c9-4e70-b7c2-301c80292c5e  (ID2D1SvgAttribute_Vtbl)
 *   ID2D1SvgDocument         86b88e4d-afa4-4d7b-88e4-68a51c4a0aec  (ID2D1SvgDocument_Vtbl)
 *   ID2D1SvgElement          ac7b67a6-183e-49c1-a823-0ebe40b0db29  (ID2D1SvgElement_Vtbl)
 *   ID2D1SvgPaint            d59bab0a-68a2-455b-a5dc-9eb2854e2490  (ID2D1SvgPaint_Vtbl)
 *   ID2D1SvgPathData         c095e4f4-bb98-43d6-9745-4d1b84ec9888  (ID2D1SvgPathData_Vtbl)
 *   ID2D1SvgPointCollection  9dbe4c0d-3572-4dd9-9825-5530813bb712  (ID2D1SvgPointCollection_Vtbl)
 *   ID2D1SvgStrokeDashArray  f1c0ca52-92a3-4f00-b4ce-f35691efd9d9  (ID2D1SvgStrokeDashArray_Vtbl)
 *   D2D1_SVG_* enums and structures: same file, constants "D2D1_SVG_*".
 * (windows-rs calls the first-child method GetTopWindow; the slot is the first-child getter,
 * it is named GetFirstChild here.)
 * No SDK IDL or header, no winmd, no disassembly and no leaked source was used.
 * Semantics not given by the public documentation are marked "verify on oracle" at the code.
 */

#ifndef __REACTOS_D2D1_SVG_H
#define __REACTOS_D2D1_SVG_H

#include <d2d1_3.h>

#ifdef __cplusplus
extern "C" {
#endif

DEFINE_GUID(IID_ID2D1SvgAttribute,       0xc9cdb0dd, 0xf8c9, 0x4e70, 0xb7, 0xc2, 0x30, 0x1c, 0x80, 0x29, 0x2c, 0x5e);
DEFINE_GUID(IID_ID2D1SvgDocument,        0x86b88e4d, 0xafa4, 0x4d7b, 0x88, 0xe4, 0x68, 0xa5, 0x1c, 0x4a, 0x0a, 0xec);
DEFINE_GUID(IID_ID2D1SvgElement,         0xac7b67a6, 0x183e, 0x49c1, 0xa8, 0x23, 0x0e, 0xbe, 0x40, 0xb0, 0xdb, 0x29);
DEFINE_GUID(IID_ID2D1SvgPaint,           0xd59bab0a, 0x68a2, 0x455b, 0xa5, 0xdc, 0x9e, 0xb2, 0x85, 0x4e, 0x24, 0x90);
DEFINE_GUID(IID_ID2D1SvgPathData,        0xc095e4f4, 0xbb98, 0x43d6, 0x97, 0x45, 0x4d, 0x1b, 0x84, 0xec, 0x98, 0x88);
DEFINE_GUID(IID_ID2D1SvgPointCollection, 0x9dbe4c0d, 0x3572, 0x4dd9, 0x98, 0x25, 0x55, 0x30, 0x81, 0x3b, 0xb7, 0x12);
DEFINE_GUID(IID_ID2D1SvgStrokeDashArray, 0xf1c0ca52, 0x92a3, 0x4f00, 0xb4, 0xce, 0xf3, 0x56, 0x91, 0xef, 0xd9, 0xd9);

#ifndef D2D1_SVG_ATTRIBUTE_POD_TYPE_FLOAT
typedef enum D2D1_SVG_PAINT_TYPE
{
    D2D1_SVG_PAINT_TYPE_NONE = 0,
    D2D1_SVG_PAINT_TYPE_COLOR = 1,
    D2D1_SVG_PAINT_TYPE_CURRENT_COLOR = 2,
    D2D1_SVG_PAINT_TYPE_URI = 3,
    D2D1_SVG_PAINT_TYPE_URI_NONE = 4,
    D2D1_SVG_PAINT_TYPE_URI_COLOR = 5,
    D2D1_SVG_PAINT_TYPE_URI_CURRENT_COLOR = 6,
    D2D1_SVG_PAINT_TYPE_FORCE_DWORD = 0xffffffff
} D2D1_SVG_PAINT_TYPE;

typedef enum D2D1_SVG_LENGTH_UNITS
{
    D2D1_SVG_LENGTH_UNITS_NUMBER = 0,
    D2D1_SVG_LENGTH_UNITS_PERCENTAGE = 1,
    D2D1_SVG_LENGTH_UNITS_FORCE_DWORD = 0xffffffff
} D2D1_SVG_LENGTH_UNITS;

typedef enum D2D1_SVG_ATTRIBUTE_STRING_TYPE
{
    D2D1_SVG_ATTRIBUTE_STRING_TYPE_SVG = 0,
    D2D1_SVG_ATTRIBUTE_STRING_TYPE_ID = 1,
    D2D1_SVG_ATTRIBUTE_STRING_TYPE_FORCE_DWORD = 0xffffffff
} D2D1_SVG_ATTRIBUTE_STRING_TYPE;

typedef enum D2D1_SVG_ATTRIBUTE_POD_TYPE
{
    D2D1_SVG_ATTRIBUTE_POD_TYPE_FLOAT = 0,
    D2D1_SVG_ATTRIBUTE_POD_TYPE_COLOR = 1,
    D2D1_SVG_ATTRIBUTE_POD_TYPE_FILL_MODE = 2,
    D2D1_SVG_ATTRIBUTE_POD_TYPE_DISPLAY = 3,
    D2D1_SVG_ATTRIBUTE_POD_TYPE_OVERFLOW = 4,
    D2D1_SVG_ATTRIBUTE_POD_TYPE_LINE_CAP = 5,
    D2D1_SVG_ATTRIBUTE_POD_TYPE_LINE_JOIN = 6,
    D2D1_SVG_ATTRIBUTE_POD_TYPE_VISIBILITY = 7,
    D2D1_SVG_ATTRIBUTE_POD_TYPE_MATRIX = 8,
    D2D1_SVG_ATTRIBUTE_POD_TYPE_UNIT_TYPE = 9,
    D2D1_SVG_ATTRIBUTE_POD_TYPE_EXTEND_MODE = 10,
    D2D1_SVG_ATTRIBUTE_POD_TYPE_PRESERVE_ASPECT_RATIO = 11,
    D2D1_SVG_ATTRIBUTE_POD_TYPE_VIEWBOX = 12,
    D2D1_SVG_ATTRIBUTE_POD_TYPE_LENGTH = 13,
    D2D1_SVG_ATTRIBUTE_POD_TYPE_FORCE_DWORD = 0xffffffff
} D2D1_SVG_ATTRIBUTE_POD_TYPE;

typedef enum D2D1_SVG_PATH_COMMAND
{
    D2D1_SVG_PATH_COMMAND_CLOSE_PATH = 0,
    D2D1_SVG_PATH_COMMAND_MOVE_ABSOLUTE = 1,
    D2D1_SVG_PATH_COMMAND_MOVE_RELATIVE = 2,
    D2D1_SVG_PATH_COMMAND_LINE_ABSOLUTE = 3,
    D2D1_SVG_PATH_COMMAND_LINE_RELATIVE = 4,
    D2D1_SVG_PATH_COMMAND_CUBIC_ABSOLUTE = 5,
    D2D1_SVG_PATH_COMMAND_CUBIC_RELATIVE = 6,
    D2D1_SVG_PATH_COMMAND_QUADRADIC_ABSOLUTE = 7,
    D2D1_SVG_PATH_COMMAND_QUADRADIC_RELATIVE = 8,
    D2D1_SVG_PATH_COMMAND_ARC_ABSOLUTE = 9,
    D2D1_SVG_PATH_COMMAND_ARC_RELATIVE = 10,
    D2D1_SVG_PATH_COMMAND_HORIZONTAL_ABSOLUTE = 11,
    D2D1_SVG_PATH_COMMAND_HORIZONTAL_RELATIVE = 12,
    D2D1_SVG_PATH_COMMAND_VERTICAL_ABSOLUTE = 13,
    D2D1_SVG_PATH_COMMAND_VERTICAL_RELATIVE = 14,
    D2D1_SVG_PATH_COMMAND_CUBIC_SMOOTH_ABSOLUTE = 15,
    D2D1_SVG_PATH_COMMAND_CUBIC_SMOOTH_RELATIVE = 16,
    D2D1_SVG_PATH_COMMAND_QUADRADIC_SMOOTH_ABSOLUTE = 17,
    D2D1_SVG_PATH_COMMAND_QUADRADIC_SMOOTH_RELATIVE = 18,
    D2D1_SVG_PATH_COMMAND_FORCE_DWORD = 0xffffffff
} D2D1_SVG_PATH_COMMAND;

typedef struct D2D1_SVG_LENGTH
{
    FLOAT value;
    D2D1_SVG_LENGTH_UNITS units;
} D2D1_SVG_LENGTH;

typedef struct D2D1_SVG_VIEWBOX
{
    FLOAT x;
    FLOAT y;
    FLOAT width;
    FLOAT height;
} D2D1_SVG_VIEWBOX;
#endif

#ifndef __cplusplus

typedef struct ID2D1SvgAttribute ID2D1SvgAttribute;
typedef struct ID2D1SvgElement ID2D1SvgElement;
typedef struct ID2D1SvgPaint ID2D1SvgPaint;
typedef struct ID2D1SvgPathData ID2D1SvgPathData;
typedef struct ID2D1SvgPointCollection ID2D1SvgPointCollection;
typedef struct ID2D1SvgStrokeDashArray ID2D1SvgStrokeDashArray;
#ifndef __ID2D1SvgDocument_FWD_DEFINED__
typedef struct ID2D1SvgDocument ID2D1SvgDocument;
#endif

/* slots 0-3: IUnknown and ID2D1Resource::GetFactory */
#define D2D1_SVG_RESOURCE_METHODS(T) \
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(T *This, REFIID riid, void **out); \
    ULONG (STDMETHODCALLTYPE *AddRef)(T *This); \
    ULONG (STDMETHODCALLTYPE *Release)(T *This); \
    void (STDMETHODCALLTYPE *GetFactory)(T *This, ID2D1Factory **factory);

#define D2D1_SVG_ATTRIBUTE_METHODS(T) \
    D2D1_SVG_RESOURCE_METHODS(T) \
    void (STDMETHODCALLTYPE *GetElement)(T *This, ID2D1SvgElement **element); \
    HRESULT (STDMETHODCALLTYPE *Clone)(T *This, ID2D1SvgAttribute **attribute);

typedef struct ID2D1SvgAttributeVtbl { D2D1_SVG_ATTRIBUTE_METHODS(ID2D1SvgAttribute) } ID2D1SvgAttributeVtbl;
struct ID2D1SvgAttribute { const ID2D1SvgAttributeVtbl *lpVtbl; };

typedef struct ID2D1SvgDocumentVtbl
{
    D2D1_SVG_RESOURCE_METHODS(ID2D1SvgDocument)
    HRESULT (STDMETHODCALLTYPE *SetViewportSize)(ID2D1SvgDocument *This, D2D1_SIZE_F viewport_size);
    D2D1_SIZE_F *(STDMETHODCALLTYPE *GetViewportSize)(ID2D1SvgDocument *This, D2D1_SIZE_F *size);
    HRESULT (STDMETHODCALLTYPE *SetRoot)(ID2D1SvgDocument *This, ID2D1SvgElement *root);
    void (STDMETHODCALLTYPE *GetRoot)(ID2D1SvgDocument *This, ID2D1SvgElement **root);
    HRESULT (STDMETHODCALLTYPE *FindElementById)(ID2D1SvgDocument *This, const WCHAR *id, ID2D1SvgElement **element);
    HRESULT (STDMETHODCALLTYPE *Serialize)(ID2D1SvgDocument *This, IStream *output_xml_stream, ID2D1SvgElement *subtree);
    HRESULT (STDMETHODCALLTYPE *Deserialize)(ID2D1SvgDocument *This, IStream *input_xml_stream, ID2D1SvgElement **subtree);
    HRESULT (STDMETHODCALLTYPE *CreatePaint)(ID2D1SvgDocument *This, D2D1_SVG_PAINT_TYPE paint_type,
            const D2D1_COLOR_F *color, const WCHAR *id, ID2D1SvgPaint **paint);
    HRESULT (STDMETHODCALLTYPE *CreateStrokeDashArray)(ID2D1SvgDocument *This, const D2D1_SVG_LENGTH *dashes,
            UINT32 dashes_count, ID2D1SvgStrokeDashArray **array);
    HRESULT (STDMETHODCALLTYPE *CreatePointCollection)(ID2D1SvgDocument *This, const D2D1_POINT_2F *points,
            UINT32 points_count, ID2D1SvgPointCollection **point_collection);
    HRESULT (STDMETHODCALLTYPE *CreatePathData)(ID2D1SvgDocument *This, const FLOAT *segment_data,
            UINT32 segment_data_count, const D2D1_SVG_PATH_COMMAND *commands, UINT32 commands_count,
            ID2D1SvgPathData **path_data);
} ID2D1SvgDocumentVtbl;
struct ID2D1SvgDocument { const ID2D1SvgDocumentVtbl *lpVtbl; };

typedef struct ID2D1SvgElementVtbl
{
    D2D1_SVG_RESOURCE_METHODS(ID2D1SvgElement)
    void (STDMETHODCALLTYPE *GetDocument)(ID2D1SvgElement *This, ID2D1SvgDocument **document);
    HRESULT (STDMETHODCALLTYPE *GetTagName)(ID2D1SvgElement *This, WCHAR *name, UINT32 name_count);
    UINT32 (STDMETHODCALLTYPE *GetTagNameLength)(ID2D1SvgElement *This);
    BOOL (STDMETHODCALLTYPE *IsTextContent)(ID2D1SvgElement *This);
    void (STDMETHODCALLTYPE *GetParent)(ID2D1SvgElement *This, ID2D1SvgElement **parent);
    BOOL (STDMETHODCALLTYPE *HasChildren)(ID2D1SvgElement *This);
    void (STDMETHODCALLTYPE *GetFirstChild)(ID2D1SvgElement *This, ID2D1SvgElement **child);
    void (STDMETHODCALLTYPE *GetLastChild)(ID2D1SvgElement *This, ID2D1SvgElement **child);
    HRESULT (STDMETHODCALLTYPE *GetPreviousChild)(ID2D1SvgElement *This, ID2D1SvgElement *reference_child,
            ID2D1SvgElement **previous_child);
    HRESULT (STDMETHODCALLTYPE *GetNextChild)(ID2D1SvgElement *This, ID2D1SvgElement *reference_child,
            ID2D1SvgElement **next_child);
    HRESULT (STDMETHODCALLTYPE *InsertChildBefore)(ID2D1SvgElement *This, ID2D1SvgElement *new_child,
            ID2D1SvgElement *reference_child);
    HRESULT (STDMETHODCALLTYPE *AppendChild)(ID2D1SvgElement *This, ID2D1SvgElement *new_child);
    HRESULT (STDMETHODCALLTYPE *ReplaceChild)(ID2D1SvgElement *This, ID2D1SvgElement *new_child,
            ID2D1SvgElement *old_child);
    HRESULT (STDMETHODCALLTYPE *RemoveChild)(ID2D1SvgElement *This, ID2D1SvgElement *old_child);
    HRESULT (STDMETHODCALLTYPE *CreateChild)(ID2D1SvgElement *This, const WCHAR *tag_name, ID2D1SvgElement **new_child);
    BOOL (STDMETHODCALLTYPE *IsAttributeSpecified)(ID2D1SvgElement *This, const WCHAR *name, BOOL *inherited);
    UINT32 (STDMETHODCALLTYPE *GetSpecifiedAttributeCount)(ID2D1SvgElement *This);
    HRESULT (STDMETHODCALLTYPE *GetSpecifiedAttributeName)(ID2D1SvgElement *This, UINT32 index, WCHAR *name,
            UINT32 name_count, BOOL *inherited);
    HRESULT (STDMETHODCALLTYPE *GetSpecifiedAttributeNameLength)(ID2D1SvgElement *This, UINT32 index,
            UINT32 *name_length, BOOL *inherited);
    HRESULT (STDMETHODCALLTYPE *RemoveAttribute)(ID2D1SvgElement *This, const WCHAR *name);
    HRESULT (STDMETHODCALLTYPE *SetTextValue)(ID2D1SvgElement *This, const WCHAR *name, UINT32 name_count);
    HRESULT (STDMETHODCALLTYPE *GetTextValue)(ID2D1SvgElement *This, WCHAR *name, UINT32 name_count);
    UINT32 (STDMETHODCALLTYPE *GetTextValueLength)(ID2D1SvgElement *This);
    HRESULT (STDMETHODCALLTYPE *SetAttributeValue)(ID2D1SvgElement *This, const WCHAR *name, ID2D1SvgAttribute *value);
    HRESULT (STDMETHODCALLTYPE *SetAttributeValuePOD)(ID2D1SvgElement *This, const WCHAR *name,
            D2D1_SVG_ATTRIBUTE_POD_TYPE type, const void *value, UINT32 value_size);
    HRESULT (STDMETHODCALLTYPE *SetAttributeValueString)(ID2D1SvgElement *This, const WCHAR *name,
            D2D1_SVG_ATTRIBUTE_STRING_TYPE type, const WCHAR *value);
    HRESULT (STDMETHODCALLTYPE *GetAttributeValue)(ID2D1SvgElement *This, const WCHAR *name, REFIID riid, void **value);
    HRESULT (STDMETHODCALLTYPE *GetAttributeValuePOD)(ID2D1SvgElement *This, const WCHAR *name,
            D2D1_SVG_ATTRIBUTE_POD_TYPE type, void *value, UINT32 value_size);
    HRESULT (STDMETHODCALLTYPE *GetAttributeValueString)(ID2D1SvgElement *This, const WCHAR *name,
            D2D1_SVG_ATTRIBUTE_STRING_TYPE type, WCHAR *value, UINT32 value_count);
    HRESULT (STDMETHODCALLTYPE *GetAttributeValueLength)(ID2D1SvgElement *This, const WCHAR *name,
            D2D1_SVG_ATTRIBUTE_STRING_TYPE type, UINT32 *length);
} ID2D1SvgElementVtbl;
struct ID2D1SvgElement { const ID2D1SvgElementVtbl *lpVtbl; };

#define ID2D1SvgDocument_QueryInterface(p, a, b) (p)->lpVtbl->QueryInterface(p, a, b)
#define ID2D1SvgDocument_AddRef(p) (p)->lpVtbl->AddRef(p)
#define ID2D1SvgDocument_Release(p) (p)->lpVtbl->Release(p)
#define ID2D1SvgDocument_GetFactory(p, a) (p)->lpVtbl->GetFactory(p, a)
#define ID2D1SvgDocument_SetViewportSize(p, a) (p)->lpVtbl->SetViewportSize(p, a)
#define ID2D1SvgDocument_GetViewportSize(p, a) (p)->lpVtbl->GetViewportSize(p, a)
#define ID2D1SvgDocument_SetRoot(p, a) (p)->lpVtbl->SetRoot(p, a)
#define ID2D1SvgDocument_GetRoot(p, a) (p)->lpVtbl->GetRoot(p, a)
#define ID2D1SvgDocument_FindElementById(p, a, b) (p)->lpVtbl->FindElementById(p, a, b)
#define ID2D1SvgDocument_Serialize(p, a, b) (p)->lpVtbl->Serialize(p, a, b)
#define ID2D1SvgDocument_Deserialize(p, a, b) (p)->lpVtbl->Deserialize(p, a, b)

#define ID2D1SvgElement_QueryInterface(p, a, b) (p)->lpVtbl->QueryInterface(p, a, b)
#define ID2D1SvgElement_AddRef(p) (p)->lpVtbl->AddRef(p)
#define ID2D1SvgElement_Release(p) (p)->lpVtbl->Release(p)
#define ID2D1SvgElement_GetDocument(p, a) (p)->lpVtbl->GetDocument(p, a)
#define ID2D1SvgElement_GetTagName(p, a, b) (p)->lpVtbl->GetTagName(p, a, b)
#define ID2D1SvgElement_GetTagNameLength(p) (p)->lpVtbl->GetTagNameLength(p)
#define ID2D1SvgElement_IsTextContent(p) (p)->lpVtbl->IsTextContent(p)
#define ID2D1SvgElement_GetParent(p, a) (p)->lpVtbl->GetParent(p, a)
#define ID2D1SvgElement_HasChildren(p) (p)->lpVtbl->HasChildren(p)
#define ID2D1SvgElement_GetFirstChild(p, a) (p)->lpVtbl->GetFirstChild(p, a)
#define ID2D1SvgElement_GetLastChild(p, a) (p)->lpVtbl->GetLastChild(p, a)
#define ID2D1SvgElement_GetPreviousChild(p, a, b) (p)->lpVtbl->GetPreviousChild(p, a, b)
#define ID2D1SvgElement_GetNextChild(p, a, b) (p)->lpVtbl->GetNextChild(p, a, b)
#define ID2D1SvgElement_InsertChildBefore(p, a, b) (p)->lpVtbl->InsertChildBefore(p, a, b)
#define ID2D1SvgElement_AppendChild(p, a) (p)->lpVtbl->AppendChild(p, a)
#define ID2D1SvgElement_ReplaceChild(p, a, b) (p)->lpVtbl->ReplaceChild(p, a, b)
#define ID2D1SvgElement_RemoveChild(p, a) (p)->lpVtbl->RemoveChild(p, a)
#define ID2D1SvgElement_CreateChild(p, a, b) (p)->lpVtbl->CreateChild(p, a, b)
#define ID2D1SvgElement_IsAttributeSpecified(p, a, b) (p)->lpVtbl->IsAttributeSpecified(p, a, b)
#define ID2D1SvgElement_GetSpecifiedAttributeCount(p) (p)->lpVtbl->GetSpecifiedAttributeCount(p)
#define ID2D1SvgElement_GetSpecifiedAttributeName(p, a, b, c, d) (p)->lpVtbl->GetSpecifiedAttributeName(p, a, b, c, d)
#define ID2D1SvgElement_GetSpecifiedAttributeNameLength(p, a, b, c) (p)->lpVtbl->GetSpecifiedAttributeNameLength(p, a, b, c)
#define ID2D1SvgElement_RemoveAttribute(p, a) (p)->lpVtbl->RemoveAttribute(p, a)
#define ID2D1SvgElement_SetTextValue(p, a, b) (p)->lpVtbl->SetTextValue(p, a, b)
#define ID2D1SvgElement_GetTextValue(p, a, b) (p)->lpVtbl->GetTextValue(p, a, b)
#define ID2D1SvgElement_GetTextValueLength(p) (p)->lpVtbl->GetTextValueLength(p)
#define ID2D1SvgElement_SetAttributeValue(p, a, b) (p)->lpVtbl->SetAttributeValue(p, a, b)
#define ID2D1SvgElement_SetAttributeValuePOD(p, a, b, c, d) (p)->lpVtbl->SetAttributeValuePOD(p, a, b, c, d)
#define ID2D1SvgElement_SetAttributeValueString(p, a, b, c) (p)->lpVtbl->SetAttributeValueString(p, a, b, c)
#define ID2D1SvgElement_GetAttributeValue(p, a, b, c) (p)->lpVtbl->GetAttributeValue(p, a, b, c)
#define ID2D1SvgElement_GetAttributeValuePOD(p, a, b, c, d) (p)->lpVtbl->GetAttributeValuePOD(p, a, b, c, d)
#define ID2D1SvgElement_GetAttributeValueString(p, a, b, c, d) (p)->lpVtbl->GetAttributeValueString(p, a, b, c, d)
#define ID2D1SvgElement_GetAttributeValueLength(p, a, b, c) (p)->lpVtbl->GetAttributeValueLength(p, a, b, c)

#endif /* !__cplusplus */

#ifdef __cplusplus
}
#endif

#endif
