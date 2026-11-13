/*
 * ID2D1SvgDocument / ID2D1SvgElement: the SVG document tree of Direct2D.
 *
 * Original work for this tree (Wine upstream has only stubs here).  Interface ids, vtable
 * member order and enum values come only from microsoft/windows-rs, see
 * sdk/include/reactos/d2d1_svg.h for the file and commit per interface.  Behaviour that
 * neither Microsoft's public documentation nor the Windows-rs metadata gives is marked
 * "verify on oracle".
 *
 * Implemented: the document (viewport, root, FindElementById) and the element (tag name,
 * parent / children, attributes as string, POD value or attribute object, text value).
 * Not implemented yet and logged with FIXME: Serialize, Deserialize, Create{Paint,
 * StrokeDashArray,PointCollection,PathData} and the drawing of a document.
 *
 * This program is free software; you can redistribute it and/or modify it under the
 * terms of the GNU Lesser General Public License as published by the Free Software
 * Foundation; either version 2.1 of the License, or (at your option) any later version.
 */

#include "d2d1_private.h"

/* the ids of the SVG interfaces are defined here (the private header only declares them elsewhere) */
#undef DEFINE_GUID
#define DEFINE_GUID(name, l, w1, w2, b1, b2, b3, b4, b5, b6, b7, b8) \
    const GUID name = { l, w1, w2, { b1, b2, b3, b4, b5, b6, b7, b8 } }
#include "reactos/d2d1_svg.h"

WINE_DEFAULT_DEBUG_CHANNEL(d2d);

struct d2d_svg_element;

struct d2d_svg_document
{
    ID2D1SvgDocument ID2D1SvgDocument_iface;
    LONG refcount;

    ID2D1Factory *factory;
    D2D1_SIZE_F viewport;
    struct d2d_svg_element *root;
    struct list elements; /* every element created by this document (weak links) */
};

enum d2d_svg_attr_kind
{
    D2D_SVG_ATTR_STRING,
    D2D_SVG_ATTR_POD,
    D2D_SVG_ATTR_OBJECT,
};

struct d2d_svg_attr
{
    struct list entry;
    WCHAR *name;
    enum d2d_svg_attr_kind kind;
    WCHAR *string;
    D2D1_SVG_ATTRIBUTE_STRING_TYPE string_type;
    D2D1_SVG_ATTRIBUTE_POD_TYPE pod_type;
    void *pod;
    UINT32 pod_size;
    ID2D1SvgAttribute *object;
};

struct d2d_svg_element
{
    ID2D1SvgElement ID2D1SvgElement_iface;
    LONG refcount;

    struct d2d_svg_document *document; /* weak, cleared when the document goes away */
    struct list document_entry;
    struct d2d_svg_element *parent;    /* weak */
    struct list children;              /* d2d_svg_child_link, each holds a reference */
    struct list sibling_entry;         /* entry in parent->children */
    WCHAR *tag;
    WCHAR *text;
    struct list attributes;
};

static const ID2D1SvgDocumentVtbl d2d_svg_document_vtbl;
static const ID2D1SvgElementVtbl d2d_svg_element_vtbl;

static inline struct d2d_svg_document *impl_from_ID2D1SvgDocument(ID2D1SvgDocument *iface)
{
    return CONTAINING_RECORD(iface, struct d2d_svg_document, ID2D1SvgDocument_iface);
}

static inline struct d2d_svg_element *impl_from_ID2D1SvgElement(ID2D1SvgElement *iface)
{
    return CONTAINING_RECORD(iface, struct d2d_svg_element, ID2D1SvgElement_iface);
}

/* our own element, or NULL for NULL / a foreign implementation */
static struct d2d_svg_element *unsafe_impl_from_ID2D1SvgElement(ID2D1SvgElement *iface)
{
    if (!iface || iface->lpVtbl != &d2d_svg_element_vtbl)
        return NULL;
    return impl_from_ID2D1SvgElement(iface);
}

static WCHAR *svg_wcsdup(const WCHAR *s)
{
    size_t len = wcslen(s) + 1;
    WCHAR *r = malloc(len * sizeof(*r));

    if (r)
        memcpy(r, s, len * sizeof(*r));
    return r;
}

static HRESULT svg_copy_string(const WCHAR *src, WCHAR *dst, UINT32 count)
{
    size_t len = wcslen(src);

    if (!dst || count < len + 1)
        return E_NOT_SUFFICIENT_BUFFER;
    memcpy(dst, src, (len + 1) * sizeof(*dst));
    return S_OK;
}

static UINT32 svg_pod_size(D2D1_SVG_ATTRIBUTE_POD_TYPE type)
{
    switch (type)
    {
        case D2D1_SVG_ATTRIBUTE_POD_TYPE_FLOAT: return sizeof(FLOAT);
        case D2D1_SVG_ATTRIBUTE_POD_TYPE_COLOR: return sizeof(D2D1_COLOR_F);
        case D2D1_SVG_ATTRIBUTE_POD_TYPE_FILL_MODE:
        case D2D1_SVG_ATTRIBUTE_POD_TYPE_DISPLAY:
        case D2D1_SVG_ATTRIBUTE_POD_TYPE_OVERFLOW:
        case D2D1_SVG_ATTRIBUTE_POD_TYPE_LINE_CAP:
        case D2D1_SVG_ATTRIBUTE_POD_TYPE_LINE_JOIN:
        case D2D1_SVG_ATTRIBUTE_POD_TYPE_VISIBILITY:
        case D2D1_SVG_ATTRIBUTE_POD_TYPE_UNIT_TYPE:
        case D2D1_SVG_ATTRIBUTE_POD_TYPE_EXTEND_MODE: return sizeof(UINT32);
        case D2D1_SVG_ATTRIBUTE_POD_TYPE_MATRIX: return sizeof(D2D1_MATRIX_3X2_F);
        case D2D1_SVG_ATTRIBUTE_POD_TYPE_PRESERVE_ASPECT_RATIO: return 3 * sizeof(UINT32);
        case D2D1_SVG_ATTRIBUTE_POD_TYPE_VIEWBOX: return sizeof(D2D1_SVG_VIEWBOX);
        case D2D1_SVG_ATTRIBUTE_POD_TYPE_LENGTH: return sizeof(D2D1_SVG_LENGTH);
        default: return 0;
    }
}

/* ---------------------------------------------------------------- attributes */

static void svg_attr_clear_value(struct d2d_svg_attr *attr)
{
    free(attr->string);
    free(attr->pod);
    if (attr->object)
        IUnknown_Release((IUnknown *)attr->object);
    attr->string = NULL;
    attr->pod = NULL;
    attr->object = NULL;
}

static void svg_attr_free(struct d2d_svg_attr *attr)
{
    svg_attr_clear_value(attr);
    free(attr->name);
    free(attr);
}

static struct d2d_svg_attr *svg_element_find_attr(struct d2d_svg_element *element, const WCHAR *name)
{
    struct d2d_svg_attr *attr;

    LIST_FOR_EACH_ENTRY(attr, &element->attributes, struct d2d_svg_attr, entry)
    {
        if (!wcscmp(attr->name, name))
            return attr;
    }
    return NULL;
}

/* the attribute slot for name, existing (value cleared) or new at the end */
static struct d2d_svg_attr *svg_element_attr_slot(struct d2d_svg_element *element, const WCHAR *name)
{
    struct d2d_svg_attr *attr;

    if ((attr = svg_element_find_attr(element, name)))
    {
        svg_attr_clear_value(attr);
        return attr;
    }
    if (!(attr = calloc(1, sizeof(*attr))))
        return NULL;
    if (!(attr->name = svg_wcsdup(name)))
    {
        free(attr);
        return NULL;
    }
    list_add_tail(&element->attributes, &attr->entry);
    return attr;
}

/* ---------------------------------------------------------------- element */

static void svg_element_unlink_child(struct d2d_svg_element *child)
{
    list_remove(&child->sibling_entry);
    child->parent = NULL;
}

static void svg_element_destroy(struct d2d_svg_element *element)
{
    struct d2d_svg_element *child, *next;
    struct d2d_svg_attr *attr, *attr_next;

    LIST_FOR_EACH_ENTRY_SAFE(child, next, &element->children, struct d2d_svg_element, sibling_entry)
    {
        svg_element_unlink_child(child);
        ID2D1SvgElement_Release(&child->ID2D1SvgElement_iface);
    }
    LIST_FOR_EACH_ENTRY_SAFE(attr, attr_next, &element->attributes, struct d2d_svg_attr, entry)
    {
        list_remove(&attr->entry);
        svg_attr_free(attr);
    }
    if (element->document)
        list_remove(&element->document_entry);
    free(element->tag);
    free(element->text);
    free(element);
}

static HRESULT STDMETHODCALLTYPE d2d_svg_element_QueryInterface(ID2D1SvgElement *iface, REFIID iid, void **out)
{
    TRACE("iface %p, iid %s, out %p.\n", iface, debugstr_guid(iid), out);

    if (IsEqualGUID(iid, &IID_ID2D1SvgElement)
            || IsEqualGUID(iid, &IID_ID2D1Resource)
            || IsEqualGUID(iid, &IID_IUnknown))
    {
        ID2D1SvgElement_AddRef(iface);
        *out = iface;
        return S_OK;
    }

    WARN("%s not implemented, returning E_NOINTERFACE.\n", debugstr_guid(iid));
    *out = NULL;
    return E_NOINTERFACE;
}

static ULONG STDMETHODCALLTYPE d2d_svg_element_AddRef(ID2D1SvgElement *iface)
{
    struct d2d_svg_element *element = impl_from_ID2D1SvgElement(iface);
    ULONG refcount = InterlockedIncrement(&element->refcount);

    TRACE("%p increasing refcount to %lu.\n", iface, refcount);
    return refcount;
}

static ULONG STDMETHODCALLTYPE d2d_svg_element_Release(ID2D1SvgElement *iface)
{
    struct d2d_svg_element *element = impl_from_ID2D1SvgElement(iface);
    ULONG refcount = InterlockedDecrement(&element->refcount);

    TRACE("%p decreasing refcount to %lu.\n", iface, refcount);
    if (!refcount)
        svg_element_destroy(element);
    return refcount;
}

static void STDMETHODCALLTYPE d2d_svg_element_GetFactory(ID2D1SvgElement *iface, ID2D1Factory **factory)
{
    struct d2d_svg_element *element = impl_from_ID2D1SvgElement(iface);

    TRACE("iface %p, factory %p.\n", iface, factory);

    *factory = element->document ? element->document->factory : NULL;
    if (*factory)
        ID2D1Factory_AddRef(*factory);
}

static void STDMETHODCALLTYPE d2d_svg_element_GetDocument(ID2D1SvgElement *iface, ID2D1SvgDocument **document)
{
    struct d2d_svg_element *element = impl_from_ID2D1SvgElement(iface);

    TRACE("iface %p, document %p.\n", iface, document);

    *document = element->document ? &element->document->ID2D1SvgDocument_iface : NULL;
    if (*document)
        ID2D1SvgDocument_AddRef(*document);
}

static HRESULT STDMETHODCALLTYPE d2d_svg_element_GetTagName(ID2D1SvgElement *iface, WCHAR *name, UINT32 name_count)
{
    struct d2d_svg_element *element = impl_from_ID2D1SvgElement(iface);

    TRACE("iface %p, name %p, name_count %u.\n", iface, name, name_count);

    return svg_copy_string(element->tag, name, name_count);
}

static UINT32 STDMETHODCALLTYPE d2d_svg_element_GetTagNameLength(ID2D1SvgElement *iface)
{
    struct d2d_svg_element *element = impl_from_ID2D1SvgElement(iface);

    TRACE("iface %p.\n", iface);

    return wcslen(element->tag);
}

static BOOL STDMETHODCALLTYPE d2d_svg_element_IsTextContent(ID2D1SvgElement *iface)
{
    TRACE("iface %p.\n", iface);

    /* FALSE for every element we create; text nodes of a parsed document are not modelled yet. */
    return FALSE;
}

static void STDMETHODCALLTYPE d2d_svg_element_GetParent(ID2D1SvgElement *iface, ID2D1SvgElement **parent)
{
    struct d2d_svg_element *element = impl_from_ID2D1SvgElement(iface);

    TRACE("iface %p, parent %p.\n", iface, parent);

    *parent = element->parent ? &element->parent->ID2D1SvgElement_iface : NULL;
    if (*parent)
        ID2D1SvgElement_AddRef(*parent);
}

static BOOL STDMETHODCALLTYPE d2d_svg_element_HasChildren(ID2D1SvgElement *iface)
{
    struct d2d_svg_element *element = impl_from_ID2D1SvgElement(iface);

    TRACE("iface %p.\n", iface);

    return !list_empty(&element->children);
}

static void svg_return_child(struct list *entry, ID2D1SvgElement **out)
{
    *out = NULL;
    if (entry)
    {
        struct d2d_svg_element *child = LIST_ENTRY(entry, struct d2d_svg_element, sibling_entry);
        *out = &child->ID2D1SvgElement_iface;
        ID2D1SvgElement_AddRef(*out);
    }
}

static void STDMETHODCALLTYPE d2d_svg_element_GetFirstChild(ID2D1SvgElement *iface, ID2D1SvgElement **child)
{
    struct d2d_svg_element *element = impl_from_ID2D1SvgElement(iface);

    TRACE("iface %p, child %p.\n", iface, child);

    svg_return_child(list_head(&element->children), child);
}

static void STDMETHODCALLTYPE d2d_svg_element_GetLastChild(ID2D1SvgElement *iface, ID2D1SvgElement **child)
{
    struct d2d_svg_element *element = impl_from_ID2D1SvgElement(iface);

    TRACE("iface %p, child %p.\n", iface, child);

    svg_return_child(list_tail(&element->children), child);
}

static HRESULT STDMETHODCALLTYPE d2d_svg_element_GetPreviousChild(ID2D1SvgElement *iface,
        ID2D1SvgElement *reference_child, ID2D1SvgElement **previous_child)
{
    struct d2d_svg_element *element = impl_from_ID2D1SvgElement(iface);
    struct d2d_svg_element *ref = unsafe_impl_from_ID2D1SvgElement(reference_child);

    TRACE("iface %p, reference_child %p, previous_child %p.\n", iface, reference_child, previous_child);

    *previous_child = NULL;
    /* verify on oracle: a reference that is not a child of this element (and NULL) */
    if (!ref || ref->parent != element)
        return E_INVALIDARG;
    svg_return_child(list_prev(&element->children, &ref->sibling_entry), previous_child);
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE d2d_svg_element_GetNextChild(ID2D1SvgElement *iface,
        ID2D1SvgElement *reference_child, ID2D1SvgElement **next_child)
{
    struct d2d_svg_element *element = impl_from_ID2D1SvgElement(iface);
    struct d2d_svg_element *ref = unsafe_impl_from_ID2D1SvgElement(reference_child);

    TRACE("iface %p, reference_child %p, next_child %p.\n", iface, reference_child, next_child);

    *next_child = NULL;
    if (!ref || ref->parent != element)
        return E_INVALIDARG;
    svg_return_child(list_next(&element->children, &ref->sibling_entry), next_child);
    return S_OK;
}

static BOOL svg_is_ancestor_or_self(struct d2d_svg_element *candidate, struct d2d_svg_element *element)
{
    for (; element; element = element->parent)
    {
        if (element == candidate)
            return TRUE;
    }
    return FALSE;
}

/* a child that can be put into element: ours, same document, not in a tree, not the document root,
 * not an ancestor of element */
static HRESULT svg_check_new_child(struct d2d_svg_element *element, struct d2d_svg_element *child)
{
    if (!child)
        return E_INVALIDARG;
    if (child->document != element->document)
        return E_INVALIDARG;
    if (child->parent || (child->document && child->document->root == child))
        return D2DERR_WRONG_STATE; /* verify on oracle */
    if (svg_is_ancestor_or_self(child, element))
        return E_INVALIDARG;
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE d2d_svg_element_InsertChildBefore(ID2D1SvgElement *iface,
        ID2D1SvgElement *new_child, ID2D1SvgElement *reference_child)
{
    struct d2d_svg_element *element = impl_from_ID2D1SvgElement(iface);
    struct d2d_svg_element *child = unsafe_impl_from_ID2D1SvgElement(new_child);
    struct d2d_svg_element *ref = unsafe_impl_from_ID2D1SvgElement(reference_child);
    HRESULT hr;

    TRACE("iface %p, new_child %p, reference_child %p.\n", iface, new_child, reference_child);

    if (reference_child && (!ref || ref->parent != element))
        return E_INVALIDARG;
    if (FAILED(hr = svg_check_new_child(element, child)))
        return hr;

    ID2D1SvgElement_AddRef(&child->ID2D1SvgElement_iface);
    child->parent = element;
    if (ref)
        list_add_before(&ref->sibling_entry, &child->sibling_entry);
    else
        list_add_tail(&element->children, &child->sibling_entry);
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE d2d_svg_element_AppendChild(ID2D1SvgElement *iface, ID2D1SvgElement *new_child)
{
    TRACE("iface %p, new_child %p.\n", iface, new_child);

    return d2d_svg_element_InsertChildBefore(iface, new_child, NULL);
}

static HRESULT STDMETHODCALLTYPE d2d_svg_element_ReplaceChild(ID2D1SvgElement *iface,
        ID2D1SvgElement *new_child, ID2D1SvgElement *old_child)
{
    struct d2d_svg_element *element = impl_from_ID2D1SvgElement(iface);
    struct d2d_svg_element *child = unsafe_impl_from_ID2D1SvgElement(new_child);
    struct d2d_svg_element *old = unsafe_impl_from_ID2D1SvgElement(old_child);
    HRESULT hr;

    TRACE("iface %p, new_child %p, old_child %p.\n", iface, new_child, old_child);

    if (!old || old->parent != element)
        return E_INVALIDARG;
    if (child == old)
        return S_OK;
    if (FAILED(hr = svg_check_new_child(element, child)))
        return hr;

    ID2D1SvgElement_AddRef(&child->ID2D1SvgElement_iface);
    child->parent = element;
    list_add_before(&old->sibling_entry, &child->sibling_entry);
    svg_element_unlink_child(old);
    ID2D1SvgElement_Release(&old->ID2D1SvgElement_iface);
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE d2d_svg_element_RemoveChild(ID2D1SvgElement *iface, ID2D1SvgElement *old_child)
{
    struct d2d_svg_element *element = impl_from_ID2D1SvgElement(iface);
    struct d2d_svg_element *old = unsafe_impl_from_ID2D1SvgElement(old_child);

    TRACE("iface %p, old_child %p.\n", iface, old_child);

    if (!old || old->parent != element)
        return E_INVALIDARG;
    svg_element_unlink_child(old);
    ID2D1SvgElement_Release(&old->ID2D1SvgElement_iface);
    return S_OK;
}

static HRESULT svg_element_create(struct d2d_svg_document *document, const WCHAR *tag,
        struct d2d_svg_element **out)
{
    struct d2d_svg_element *element;

    if (!(element = calloc(1, sizeof(*element))))
        return E_OUTOFMEMORY;
    if (!(element->tag = svg_wcsdup(tag)) || !(element->text = svg_wcsdup(L"")))
    {
        free(element->tag);
        free(element);
        return E_OUTOFMEMORY;
    }
    element->ID2D1SvgElement_iface.lpVtbl = &d2d_svg_element_vtbl;
    element->refcount = 1;
    element->document = document;
    list_add_tail(&document->elements, &element->document_entry);
    list_init(&element->children);
    list_init(&element->attributes);
    *out = element;
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE d2d_svg_element_CreateChild(ID2D1SvgElement *iface, const WCHAR *tag_name,
        ID2D1SvgElement **new_child)
{
    struct d2d_svg_element *element = impl_from_ID2D1SvgElement(iface);
    struct d2d_svg_element *child;
    HRESULT hr;

    TRACE("iface %p, tag_name %s, new_child %p.\n", iface, debugstr_w(tag_name), new_child);

    if (!new_child)
        return E_INVALIDARG;
    *new_child = NULL;
    if (!tag_name || !element->document)
        return E_INVALIDARG;

    /* The new element is appended as the last child (documented); verify on oracle: tag name
     * validity checks, the unknown-tag case. */
    if (FAILED(hr = svg_element_create(element->document, tag_name, &child)))
        return hr;
    child->parent = element;
    list_add_tail(&element->children, &child->sibling_entry);
    ID2D1SvgElement_AddRef(&child->ID2D1SvgElement_iface);
    *new_child = &child->ID2D1SvgElement_iface;
    return S_OK;
}

static BOOL STDMETHODCALLTYPE d2d_svg_element_IsAttributeSpecified(ID2D1SvgElement *iface, const WCHAR *name,
        BOOL *inherited)
{
    struct d2d_svg_element *element = impl_from_ID2D1SvgElement(iface);
    BOOL specified;

    TRACE("iface %p, name %s, inherited %p.\n", iface, debugstr_w(name), inherited);

    /* verify on oracle: inherited properties (fill, stroke, ...) of a parent are reported
     * through *inherited; we only report attributes set on this element. */
    specified = name && svg_element_find_attr(element, name) != NULL;
    if (inherited)
        *inherited = FALSE;
    return specified;
}

static UINT32 STDMETHODCALLTYPE d2d_svg_element_GetSpecifiedAttributeCount(ID2D1SvgElement *iface)
{
    struct d2d_svg_element *element = impl_from_ID2D1SvgElement(iface);

    TRACE("iface %p.\n", iface);

    return list_count(&element->attributes);
}

static struct d2d_svg_attr *svg_element_attr_at(struct d2d_svg_element *element, UINT32 index)
{
    struct d2d_svg_attr *attr;

    LIST_FOR_EACH_ENTRY(attr, &element->attributes, struct d2d_svg_attr, entry)
    {
        if (!index--)
            return attr;
    }
    return NULL;
}

static HRESULT STDMETHODCALLTYPE d2d_svg_element_GetSpecifiedAttributeName(ID2D1SvgElement *iface, UINT32 index,
        WCHAR *name, UINT32 name_count, BOOL *inherited)
{
    struct d2d_svg_element *element = impl_from_ID2D1SvgElement(iface);
    struct d2d_svg_attr *attr;

    TRACE("iface %p, index %u, name %p, name_count %u, inherited %p.\n", iface, index, name, name_count, inherited);

    if (inherited)
        *inherited = FALSE;
    if (!(attr = svg_element_attr_at(element, index)))
        return E_INVALIDARG; /* verify on oracle */
    return svg_copy_string(attr->name, name, name_count);
}

static HRESULT STDMETHODCALLTYPE d2d_svg_element_GetSpecifiedAttributeNameLength(ID2D1SvgElement *iface,
        UINT32 index, UINT32 *name_length, BOOL *inherited)
{
    struct d2d_svg_element *element = impl_from_ID2D1SvgElement(iface);
    struct d2d_svg_attr *attr;

    TRACE("iface %p, index %u, name_length %p, inherited %p.\n", iface, index, name_length, inherited);

    if (inherited)
        *inherited = FALSE;
    if (!name_length)
        return E_INVALIDARG;
    if (!(attr = svg_element_attr_at(element, index)))
        return E_INVALIDARG;
    *name_length = wcslen(attr->name);
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE d2d_svg_element_RemoveAttribute(ID2D1SvgElement *iface, const WCHAR *name)
{
    struct d2d_svg_element *element = impl_from_ID2D1SvgElement(iface);
    struct d2d_svg_attr *attr;

    TRACE("iface %p, name %s.\n", iface, debugstr_w(name));

    if (!name)
        return E_INVALIDARG;
    /* verify on oracle: removing an attribute that is not specified */
    if (!(attr = svg_element_find_attr(element, name)))
        return S_OK;
    list_remove(&attr->entry);
    svg_attr_free(attr);
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE d2d_svg_element_SetTextValue(ID2D1SvgElement *iface, const WCHAR *name,
        UINT32 name_count)
{
    struct d2d_svg_element *element = impl_from_ID2D1SvgElement(iface);
    WCHAR *text;

    TRACE("iface %p, name %s, name_count %u.\n", iface, debugstr_wn(name, name_count), name_count);

    if (!name && name_count)
        return E_INVALIDARG;
    if (!(text = malloc((name_count + 1) * sizeof(*text))))
        return E_OUTOFMEMORY;
    if (name_count)
        memcpy(text, name, name_count * sizeof(*text));
    text[name_count] = 0;
    free(element->text);
    element->text = text;
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE d2d_svg_element_GetTextValue(ID2D1SvgElement *iface, WCHAR *name, UINT32 name_count)
{
    struct d2d_svg_element *element = impl_from_ID2D1SvgElement(iface);

    TRACE("iface %p, name %p, name_count %u.\n", iface, name, name_count);

    return svg_copy_string(element->text, name, name_count);
}

static UINT32 STDMETHODCALLTYPE d2d_svg_element_GetTextValueLength(ID2D1SvgElement *iface)
{
    struct d2d_svg_element *element = impl_from_ID2D1SvgElement(iface);

    TRACE("iface %p.\n", iface);

    return wcslen(element->text);
}

static HRESULT STDMETHODCALLTYPE d2d_svg_element_SetAttributeValue(ID2D1SvgElement *iface, const WCHAR *name,
        ID2D1SvgAttribute *value)
{
    struct d2d_svg_element *element = impl_from_ID2D1SvgElement(iface);
    struct d2d_svg_attr *attr;

    TRACE("iface %p, name %s, value %p.\n", iface, debugstr_w(name), value);

    if (!name || !value)
        return E_INVALIDARG;
    if (!(attr = svg_element_attr_slot(element, name)))
        return E_OUTOFMEMORY;
    attr->kind = D2D_SVG_ATTR_OBJECT;
    attr->object = value;
    IUnknown_AddRef((IUnknown *)value);
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE d2d_svg_element_SetAttributeValuePOD(ID2D1SvgElement *iface, const WCHAR *name,
        D2D1_SVG_ATTRIBUTE_POD_TYPE type, const void *value, UINT32 value_size)
{
    struct d2d_svg_element *element = impl_from_ID2D1SvgElement(iface);
    struct d2d_svg_attr *attr;
    UINT32 size = svg_pod_size(type);

    TRACE("iface %p, name %s, type %u, value %p, value_size %u.\n", iface, debugstr_w(name), type, value, value_size);

    if (!name || !value || !size || value_size != size) /* verify on oracle: size checks */
        return E_INVALIDARG;
    if (!(attr = svg_element_attr_slot(element, name)))
        return E_OUTOFMEMORY;
    if (!(attr->pod = malloc(size)))
    {
        list_remove(&attr->entry);
        svg_attr_free(attr);
        return E_OUTOFMEMORY;
    }
    memcpy(attr->pod, value, size);
    attr->kind = D2D_SVG_ATTR_POD;
    attr->pod_type = type;
    attr->pod_size = size;
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE d2d_svg_element_SetAttributeValueString(ID2D1SvgElement *iface, const WCHAR *name,
        D2D1_SVG_ATTRIBUTE_STRING_TYPE type, const WCHAR *value)
{
    struct d2d_svg_element *element = impl_from_ID2D1SvgElement(iface);
    struct d2d_svg_attr *attr;
    WCHAR *copy;

    TRACE("iface %p, name %s, type %u, value %s.\n", iface, debugstr_w(name), type, debugstr_w(value));

    if (!name || !value)
        return E_INVALIDARG;
    if (type != D2D1_SVG_ATTRIBUTE_STRING_TYPE_SVG && type != D2D1_SVG_ATTRIBUTE_STRING_TYPE_ID)
        return E_INVALIDARG;
    if (!(copy = svg_wcsdup(value)))
        return E_OUTOFMEMORY;
    if (!(attr = svg_element_attr_slot(element, name)))
    {
        free(copy);
        return E_OUTOFMEMORY;
    }
    attr->kind = D2D_SVG_ATTR_STRING;
    attr->string = copy;
    attr->string_type = type;
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE d2d_svg_element_GetAttributeValue(ID2D1SvgElement *iface, const WCHAR *name,
        REFIID riid, void **value)
{
    struct d2d_svg_element *element = impl_from_ID2D1SvgElement(iface);
    struct d2d_svg_attr *attr;

    TRACE("iface %p, name %s, riid %s, value %p.\n", iface, debugstr_w(name), debugstr_guid(riid), value);

    if (!value)
        return E_INVALIDARG;
    *value = NULL;
    if (!name || !riid)
        return E_INVALIDARG;
    if (!(attr = svg_element_find_attr(element, name)))
        return HRESULT_FROM_WIN32(ERROR_NOT_FOUND); /* verify on oracle: not specified */
    if (attr->kind != D2D_SVG_ATTR_OBJECT)
    {
        FIXME("Attribute %s is not an attribute object (no conversion from string / POD yet).\n", debugstr_w(name));
        return E_INVALIDARG;
    }
    return IUnknown_QueryInterface((IUnknown *)attr->object, riid, value);
}

static HRESULT STDMETHODCALLTYPE d2d_svg_element_GetAttributeValuePOD(ID2D1SvgElement *iface, const WCHAR *name,
        D2D1_SVG_ATTRIBUTE_POD_TYPE type, void *value, UINT32 value_size)
{
    struct d2d_svg_element *element = impl_from_ID2D1SvgElement(iface);
    struct d2d_svg_attr *attr;
    UINT32 size = svg_pod_size(type);

    TRACE("iface %p, name %s, type %u, value %p, value_size %u.\n", iface, debugstr_w(name), type, value, value_size);

    if (!name || !value || !size || value_size != size)
        return E_INVALIDARG;
    if (!(attr = svg_element_find_attr(element, name)))
        return HRESULT_FROM_WIN32(ERROR_NOT_FOUND);
    if (attr->kind != D2D_SVG_ATTR_POD || attr->pod_type != type)
    {
        FIXME("Attribute %s: no conversion to POD type %u (stored kind %d).\n", debugstr_w(name), type, attr->kind);
        return E_INVALIDARG;
    }
    memcpy(value, attr->pod, size);
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE d2d_svg_element_GetAttributeValueString(ID2D1SvgElement *iface, const WCHAR *name,
        D2D1_SVG_ATTRIBUTE_STRING_TYPE type, WCHAR *value, UINT32 value_count)
{
    struct d2d_svg_element *element = impl_from_ID2D1SvgElement(iface);
    struct d2d_svg_attr *attr;

    TRACE("iface %p, name %s, type %u, value %p, value_count %u.\n", iface, debugstr_w(name), type, value, value_count);

    if (!name || !value)
        return E_INVALIDARG;
    if (!(attr = svg_element_find_attr(element, name)))
        return HRESULT_FROM_WIN32(ERROR_NOT_FOUND);
    if (attr->kind != D2D_SVG_ATTR_STRING)
    {
        FIXME("Attribute %s: no conversion to a string (stored kind %d).\n", debugstr_w(name), attr->kind);
        return E_INVALIDARG;
    }
    return svg_copy_string(attr->string, value, value_count);
}

static HRESULT STDMETHODCALLTYPE d2d_svg_element_GetAttributeValueLength(ID2D1SvgElement *iface, const WCHAR *name,
        D2D1_SVG_ATTRIBUTE_STRING_TYPE type, UINT32 *length)
{
    struct d2d_svg_element *element = impl_from_ID2D1SvgElement(iface);
    struct d2d_svg_attr *attr;

    TRACE("iface %p, name %s, type %u, length %p.\n", iface, debugstr_w(name), type, length);

    if (!name || !length)
        return E_INVALIDARG;
    if (!(attr = svg_element_find_attr(element, name)))
        return HRESULT_FROM_WIN32(ERROR_NOT_FOUND);
    if (attr->kind != D2D_SVG_ATTR_STRING)
    {
        FIXME("Attribute %s: no conversion to a string (stored kind %d).\n", debugstr_w(name), attr->kind);
        return E_INVALIDARG;
    }
    *length = wcslen(attr->string);
    return S_OK;
}

static const ID2D1SvgElementVtbl d2d_svg_element_vtbl =
{
    d2d_svg_element_QueryInterface,
    d2d_svg_element_AddRef,
    d2d_svg_element_Release,
    d2d_svg_element_GetFactory,
    d2d_svg_element_GetDocument,
    d2d_svg_element_GetTagName,
    d2d_svg_element_GetTagNameLength,
    d2d_svg_element_IsTextContent,
    d2d_svg_element_GetParent,
    d2d_svg_element_HasChildren,
    d2d_svg_element_GetFirstChild,
    d2d_svg_element_GetLastChild,
    d2d_svg_element_GetPreviousChild,
    d2d_svg_element_GetNextChild,
    d2d_svg_element_InsertChildBefore,
    d2d_svg_element_AppendChild,
    d2d_svg_element_ReplaceChild,
    d2d_svg_element_RemoveChild,
    d2d_svg_element_CreateChild,
    d2d_svg_element_IsAttributeSpecified,
    d2d_svg_element_GetSpecifiedAttributeCount,
    d2d_svg_element_GetSpecifiedAttributeName,
    d2d_svg_element_GetSpecifiedAttributeNameLength,
    d2d_svg_element_RemoveAttribute,
    d2d_svg_element_SetTextValue,
    d2d_svg_element_GetTextValue,
    d2d_svg_element_GetTextValueLength,
    d2d_svg_element_SetAttributeValue,
    d2d_svg_element_SetAttributeValuePOD,
    d2d_svg_element_SetAttributeValueString,
    d2d_svg_element_GetAttributeValue,
    d2d_svg_element_GetAttributeValuePOD,
    d2d_svg_element_GetAttributeValueString,
    d2d_svg_element_GetAttributeValueLength,
};

/* ---------------------------------------------------------------- document */

static HRESULT STDMETHODCALLTYPE d2d_svg_document_QueryInterface(ID2D1SvgDocument *iface, REFIID iid, void **out)
{
    TRACE("iface %p, iid %s, out %p.\n", iface, debugstr_guid(iid), out);

    if (IsEqualGUID(iid, &IID_ID2D1SvgDocument)
            || IsEqualGUID(iid, &IID_ID2D1Resource)
            || IsEqualGUID(iid, &IID_IUnknown))
    {
        ID2D1SvgDocument_AddRef(iface);
        *out = iface;
        return S_OK;
    }

    WARN("%s not implemented, returning E_NOINTERFACE.\n", debugstr_guid(iid));
    *out = NULL;
    return E_NOINTERFACE;
}

static ULONG STDMETHODCALLTYPE d2d_svg_document_AddRef(ID2D1SvgDocument *iface)
{
    struct d2d_svg_document *document = impl_from_ID2D1SvgDocument(iface);
    ULONG refcount = InterlockedIncrement(&document->refcount);

    TRACE("%p increasing refcount to %lu.\n", iface, refcount);
    return refcount;
}

static ULONG STDMETHODCALLTYPE d2d_svg_document_Release(ID2D1SvgDocument *iface)
{
    struct d2d_svg_document *document = impl_from_ID2D1SvgDocument(iface);
    ULONG refcount = InterlockedDecrement(&document->refcount);
    struct d2d_svg_element *element, *next;

    TRACE("%p decreasing refcount to %lu.\n", iface, refcount);
    if (!refcount)
    {
        /* Elements may outlive the document (the client holds them): they lose their document. */
        LIST_FOR_EACH_ENTRY_SAFE(element, next, &document->elements, struct d2d_svg_element, document_entry)
        {
            list_remove(&element->document_entry);
            element->document = NULL;
        }
        if (document->root)
        {
            document->root->parent = NULL;
            ID2D1SvgElement_Release(&document->root->ID2D1SvgElement_iface);
        }
        ID2D1Factory_Release(document->factory);
        free(document);
    }
    return refcount;
}

static void STDMETHODCALLTYPE d2d_svg_document_GetFactory(ID2D1SvgDocument *iface, ID2D1Factory **factory)
{
    struct d2d_svg_document *document = impl_from_ID2D1SvgDocument(iface);

    TRACE("iface %p, factory %p.\n", iface, factory);

    *factory = document->factory;
    ID2D1Factory_AddRef(*factory);
}

static HRESULT STDMETHODCALLTYPE d2d_svg_document_SetViewportSize(ID2D1SvgDocument *iface, D2D1_SIZE_F viewport_size)
{
    struct d2d_svg_document *document = impl_from_ID2D1SvgDocument(iface);

    TRACE("iface %p, viewport_size %.8e x %.8e.\n", iface, viewport_size.width, viewport_size.height);

    /* verify on oracle: negative / NaN sizes */
    if (!(viewport_size.width >= 0.0f) || !(viewport_size.height >= 0.0f))
        return E_INVALIDARG;
    document->viewport = viewport_size;
    return S_OK;
}

static D2D1_SIZE_F * STDMETHODCALLTYPE d2d_svg_document_GetViewportSize(ID2D1SvgDocument *iface, D2D1_SIZE_F *size)
{
    struct d2d_svg_document *document = impl_from_ID2D1SvgDocument(iface);

    TRACE("iface %p, size %p.\n", iface, size);

    *size = document->viewport;
    return size;
}

static HRESULT STDMETHODCALLTYPE d2d_svg_document_SetRoot(ID2D1SvgDocument *iface, ID2D1SvgElement *root)
{
    struct d2d_svg_document *document = impl_from_ID2D1SvgDocument(iface);
    struct d2d_svg_element *element = unsafe_impl_from_ID2D1SvgElement(root);

    TRACE("iface %p, root %p.\n", iface, root);

    /* verify on oracle: NULL root, an element that already has a parent, a root that is not <svg> */
    if (root && (!element || element->document != document || element->parent))
        return E_INVALIDARG;
    if (element == document->root)
        return S_OK;
    if (element)
        ID2D1SvgElement_AddRef(root);
    if (document->root)
    {
        document->root->parent = NULL;
        ID2D1SvgElement_Release(&document->root->ID2D1SvgElement_iface);
    }
    document->root = element;
    return S_OK;
}

static void STDMETHODCALLTYPE d2d_svg_document_GetRoot(ID2D1SvgDocument *iface, ID2D1SvgElement **root)
{
    struct d2d_svg_document *document = impl_from_ID2D1SvgDocument(iface);

    TRACE("iface %p, root %p.\n", iface, root);

    *root = document->root ? &document->root->ID2D1SvgElement_iface : NULL;
    if (*root)
        ID2D1SvgElement_AddRef(*root);
}

static struct d2d_svg_element *svg_find_by_id(struct d2d_svg_element *element, const WCHAR *id)
{
    struct d2d_svg_attr *attr;
    struct d2d_svg_element *child, *found;

    if ((attr = svg_element_find_attr(element, L"id")) && attr->kind == D2D_SVG_ATTR_STRING
            && !wcscmp(attr->string, id))
        return element;
    LIST_FOR_EACH_ENTRY(child, &element->children, struct d2d_svg_element, sibling_entry)
    {
        if ((found = svg_find_by_id(child, id)))
            return found;
    }
    return NULL;
}

static HRESULT STDMETHODCALLTYPE d2d_svg_document_FindElementById(ID2D1SvgDocument *iface, const WCHAR *id,
        ID2D1SvgElement **svg_element)
{
    struct d2d_svg_document *document = impl_from_ID2D1SvgDocument(iface);
    struct d2d_svg_element *found = NULL;

    TRACE("iface %p, id %s, svg_element %p.\n", iface, debugstr_w(id), svg_element);

    if (!svg_element)
        return E_INVALIDARG;
    *svg_element = NULL;
    if (!id)
        return E_INVALIDARG;
    if (document->root)
        found = svg_find_by_id(document->root, id);
    /* verify on oracle: an id that is not in the document (S_OK with NULL assumed) */
    if (found)
    {
        *svg_element = &found->ID2D1SvgElement_iface;
        ID2D1SvgElement_AddRef(*svg_element);
    }
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE d2d_svg_document_Serialize(ID2D1SvgDocument *iface, IStream *output_xml_stream,
        ID2D1SvgElement *subtree)
{
    FIXME("iface %p, output_xml_stream %p, subtree %p stub!\n", iface, output_xml_stream, subtree);

    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE d2d_svg_document_Deserialize(ID2D1SvgDocument *iface, IStream *input_xml_stream,
        ID2D1SvgElement **subtree)
{
    FIXME("iface %p, input_xml_stream %p, subtree %p stub!\n", iface, input_xml_stream, subtree);

    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE d2d_svg_document_CreatePaint(ID2D1SvgDocument *iface,
        D2D1_SVG_PAINT_TYPE paint_type, const D2D1_COLOR_F *color, const WCHAR *id, ID2D1SvgPaint **paint)
{
    FIXME("iface %p, paint_type %u, color %p, id %s, paint %p stub!\n", iface, paint_type, color,
            debugstr_w(id), paint);

    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE d2d_svg_document_CreateStrokeDashArray(ID2D1SvgDocument *iface,
        const D2D1_SVG_LENGTH *dashes, UINT32 dashes_count, ID2D1SvgStrokeDashArray **array)
{
    FIXME("iface %p, dashes %p, dashes_count %u, array %p stub!\n", iface, dashes, dashes_count, array);

    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE d2d_svg_document_CreatePointCollection(ID2D1SvgDocument *iface,
        const D2D1_POINT_2F *points, UINT32 points_count, ID2D1SvgPointCollection **point_collection)
{
    FIXME("iface %p, points %p, points_count %u, point_collection %p stub!\n", iface, points, points_count,
            point_collection);

    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE d2d_svg_document_CreatePathData(ID2D1SvgDocument *iface,
        const FLOAT *segment_data, UINT32 segment_data_count, const D2D1_SVG_PATH_COMMAND *commands,
        UINT32 commands_count, ID2D1SvgPathData **path_data)
{
    FIXME("iface %p, segment_data %p, segment_data_count %u, commands %p, commands_count %u, path_data %p stub!\n",
            iface, segment_data, segment_data_count, commands, commands_count, path_data);

    return E_NOTIMPL;
}

static const ID2D1SvgDocumentVtbl d2d_svg_document_vtbl =
{
    d2d_svg_document_QueryInterface,
    d2d_svg_document_AddRef,
    d2d_svg_document_Release,
    d2d_svg_document_GetFactory,
    d2d_svg_document_SetViewportSize,
    d2d_svg_document_GetViewportSize,
    d2d_svg_document_SetRoot,
    d2d_svg_document_GetRoot,
    d2d_svg_document_FindElementById,
    d2d_svg_document_Serialize,
    d2d_svg_document_Deserialize,
    d2d_svg_document_CreatePaint,
    d2d_svg_document_CreateStrokeDashArray,
    d2d_svg_document_CreatePointCollection,
    d2d_svg_document_CreatePathData,
};

HRESULT d2d_svg_document_create(ID2D1Factory *factory, IStream *input_xml_stream, D2D1_SIZE_F viewport_size,
        ID2D1SvgDocument **out)
{
    struct d2d_svg_document *document;
    struct d2d_svg_element *root;
    HRESULT hr;

    if (!out)
        return E_INVALIDARG; /* verify on oracle: a NULL output pointer */
    *out = NULL;

    if (input_xml_stream)
        FIXME("Parsing the input stream %p is not implemented, creating an empty document.\n", input_xml_stream);
    if (!(viewport_size.width >= 0.0f) || !(viewport_size.height >= 0.0f))
        return E_INVALIDARG; /* verify on oracle */

    if (!(document = calloc(1, sizeof(*document))))
        return E_OUTOFMEMORY;
    document->ID2D1SvgDocument_iface.lpVtbl = &d2d_svg_document_vtbl;
    document->refcount = 1;
    document->factory = factory;
    ID2D1Factory_AddRef(factory);
    document->viewport = viewport_size;
    list_init(&document->elements);

    /* The empty document: a root <svg> element. */
    if (FAILED(hr = svg_element_create(document, L"svg", &root)))
    {
        ID2D1SvgDocument_Release(&document->ID2D1SvgDocument_iface);
        return hr;
    }
    document->root = root;

    TRACE("Created SVG document %p, viewport %.8e x %.8e.\n", document, viewport_size.width, viewport_size.height);
    *out = &document->ID2D1SvgDocument_iface;
    return S_OK;
}
