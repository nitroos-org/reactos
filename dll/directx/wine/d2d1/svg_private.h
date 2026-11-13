/*
 * Private structures of the SVG document tree (shared by svg.c and svg_draw.c).
 *
 * This program is free software; you can redistribute it and/or modify it under the
 * terms of the GNU Lesser General Public License as published by the Free Software
 * Foundation; either version 2.1 of the License, or (at your option) any later version.
 */

#ifndef __D2D1_SVG_PRIVATE_H
#define __D2D1_SVG_PRIVATE_H

#include "d2d1_private.h"
#include "reactos/d2d1_svg.h"

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

struct d2d_svg_document *unsafe_impl_from_ID2D1SvgDocument(ID2D1SvgDocument *iface);
void d2d_svg_draw_document(struct d2d_svg_document *document, ID2D1DeviceContext *context);

#endif
