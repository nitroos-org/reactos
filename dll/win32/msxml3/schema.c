/*
 * Schema cache implementation
 *
 * Copyright 2007 Huw Davies
 * Copyright 2010 Adam Martinson for CodeWeavers
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

#define COBJMACROS

#include <assert.h>
#include <stdarg.h>
#include <libxml/xmlerror.h>
#include <libxml/tree.h>
#include <libxml/xmlschemas.h>
#include <libxml/schemasInternals.h>
#include <libxml/hash.h>
#include <libxml/parser.h>
#include <libxml/parserInternals.h>
#include <libxml/xmlIO.h>
#include <libxml/xmlversion.h>
#include <libxml/xpath.h>

#include "windef.h"
#include "winbase.h"
#include "winuser.h"
#include "ole2.h"
#include "msxml6.h"

#include "wine/debug.h"

#include "msxml_private.h"

WINE_DEFAULT_DEBUG_CHANNEL(msxml);

/* We use a chained hashtable, which can hold any number of schemas
 * TODO: grow/shrink hashtable depending on load factor
 * TODO: implement read-only where appropriate
 */

/* This is just the number of buckets, should be prime */
#define DEFAULT_HASHTABLE_SIZE 17

xmlDocPtr XDR_to_XSD_doc(xmlDocPtr xdr_doc, xmlChar const* nsURI);

static const xmlChar XSD_schema[] = "schema";
static const xmlChar XSD_nsURI[] = "http://www.w3.org/2001/XMLSchema";
static const xmlChar XDR_schema[] = "Schema";
static const xmlChar XDR_nsURI[] = "urn:schemas-microsoft-com:xml-data";
static const xmlChar DT_nsURI[] = "urn:schemas-microsoft-com:datatypes";

static xmlChar *        datatypes_src;
static int              datatypes_len;
static HGLOBAL          datatypes_handle;
static HRSRC            datatypes_rsrc;
static xmlSchemaPtr     datatypes_schema;

static const WCHAR      emptyW[] = {0};

/* Supported types:
 * msxml3 - XDR only
 * msxml4 - XDR & XSD
 * msxml5 - XDR & XSD
 * mxsml6 - XSD only
 *
 * CacheType_NS is a special type used for read-only collection build with
 * IXMLDOMDocument2::namespaces()
 */
typedef enum  {
    CacheEntryType_Invalid,
    CacheEntryType_XDR,
    CacheEntryType_XSD,
    CacheEntryType_NS
} CacheEntryType;

typedef struct
{
    DispatchEx dispex;
    IXMLDOMSchemaCollection2 IXMLDOMSchemaCollection2_iface;
    LONG ref;

    MSXML_VERSION version;
    xmlHashTablePtr cache;
    xmlChar **uris;
    int allocated;
    int count;

    VARIANT_BOOL validateOnLoad;
    int read_only;
} schema_cache;

typedef struct
{
    CacheEntryType type;
    xmlSchemaPtr schema;
    xmlDocPtr doc;
    LONG ref;
} cache_entry;

static const tid_t schema_cache_se_tids[] = {
    IXMLDOMSchemaCollection_tid,
    IXMLDOMSchemaCollection2_tid,
    NULL_tid
};

/* datatypes lookup stuff
 * generated with help from gperf */
#define DT_MIN_STR_LEN 2
#define DT_MAX_STR_LEN 11
#define DT_MIN_HASH_VALUE 2
#define DT_MAX_HASH_VALUE 115

static const xmlChar DT_bin_base64[] = "bin.base64";
static const xmlChar DT_bin_hex[] = "bin.hex";
static const xmlChar DT_boolean[] = "boolean";
static const xmlChar DT_char[] = "char";
static const xmlChar DT_date[] = "date";
static const xmlChar DT_date_tz[] = "date.tz";
static const xmlChar DT_dateTime[] = "dateTime";
static const xmlChar DT_dateTime_tz[] = "dateTime.tz";
static const xmlChar DT_entity[] = "entity";
static const xmlChar DT_entities[] = "entities";
static const xmlChar DT_enumeration[] = "enumeration";
static const xmlChar DT_fixed_14_4[] = "fixed.14.4";
static const xmlChar DT_float[] = "float";
static const xmlChar DT_i1[] = "i1";
static const xmlChar DT_i2[] = "i2";
static const xmlChar DT_i4[] = "i4";
static const xmlChar DT_i8[] = "i8";
static const xmlChar DT_id[] = "id";
static const xmlChar DT_idref[] = "idref";
static const xmlChar DT_idrefs[] = "idrefs";
static const xmlChar DT_int[] = "int";
static const xmlChar DT_nmtoken[] = "nmtoken";
static const xmlChar DT_nmtokens[] = "nmtokens";
static const xmlChar DT_notation[] = "notation";
static const xmlChar DT_number[] = "number";
static const xmlChar DT_r4[] = "r4";
static const xmlChar DT_r8[] = "r8";
static const xmlChar DT_string[] = "string";
static const xmlChar DT_time[] = "time";
static const xmlChar DT_time_tz[] = "time.tz";
static const xmlChar DT_ui1[] = "ui1";
static const xmlChar DT_ui2[] = "ui2";
static const xmlChar DT_ui4[] = "ui4";
static const xmlChar DT_ui8[] = "ui8";
static const xmlChar DT_uri[] = "uri";
static const xmlChar DT_uuid[] = "uuid";

static const OLECHAR wDT_bin_base64[] = {'b','i','n','.','b','a','s','e','6','4',0};
static const OLECHAR wDT_bin_hex[] = {'b','i','n','.','h','e','x',0};
static const OLECHAR wDT_boolean[] = {'b','o','o','l','e','a','n',0};
static const OLECHAR wDT_char[] = {'c','h','a','r',0};
static const OLECHAR wDT_date[] = {'d','a','t','e',0};
static const OLECHAR wDT_date_tz[] = {'d','a','t','e','.','t','z',0};
static const OLECHAR wDT_dateTime[] = {'d','a','t','e','T','i','m','e',0};
static const OLECHAR wDT_dateTime_tz[] = {'d','a','t','e','T','i','m','e','.','t','z',0};
static const OLECHAR wDT_entity[] = {'e','n','t','i','t','y',0};
static const OLECHAR wDT_entities[] = {'e','n','t','i','t','i','e','s',0};
static const OLECHAR wDT_enumeration[] = {'e','n','u','m','e','r','a','t','i','o','n',0};
static const OLECHAR wDT_fixed_14_4[] = {'f','i','x','e','d','.','1','4','.','4',0};
static const OLECHAR wDT_float[] = {'f','l','o','a','t',0};
static const OLECHAR wDT_i1[] = {'i','1',0};
static const OLECHAR wDT_i2[] = {'i','2',0};
static const OLECHAR wDT_i4[] = {'i','4',0};
static const OLECHAR wDT_i8[] = {'i','8',0};
static const OLECHAR wDT_id[] = {'i','d',0};
static const OLECHAR wDT_idref[] = {'i','d','r','e','f',0};
static const OLECHAR wDT_idrefs[] = {'i','d','r','e','f','s',0};
static const OLECHAR wDT_int[] = {'i','n','t',0};
static const OLECHAR wDT_nmtoken[] = {'n','m','t','o','k','e','n',0};
static const OLECHAR wDT_nmtokens[] = {'n','m','t','o','k','e','n','s',0};
static const OLECHAR wDT_notation[] = {'n','o','t','a','t','i','o','n',0};
static const OLECHAR wDT_number[] = {'n','u','m','b','e','r',0};
static const OLECHAR wDT_r4[] = {'r','4',0};
static const OLECHAR wDT_r8[] = {'r','8',0};
static const OLECHAR wDT_string[] = {'s','t','r','i','n','g',0};
static const OLECHAR wDT_time[] = {'t','i','m','e',0};
static const OLECHAR wDT_time_tz[] = {'t','i','m','e','.','t','z',0};
static const OLECHAR wDT_ui1[] = {'u','i','1',0};
static const OLECHAR wDT_ui2[] = {'u','i','2',0};
static const OLECHAR wDT_ui4[] = {'u','i','4',0};
static const OLECHAR wDT_ui8[] = {'u','i','8',0};
static const OLECHAR wDT_uri[] = {'u','r','i',0};
static const OLECHAR wDT_uuid[] = {'u','u','i','d',0};

static const BYTE hash_assoc_values[] =
{
    116, 116, 116, 116, 116, 116, 116, 116, 116, 116,
    116, 116, 116, 116, 116, 116, 116, 116, 116, 116,
    116, 116, 116, 116, 116, 116, 116, 116, 116, 116,
    116, 116, 116, 116, 116, 116, 116, 116, 116, 116,
    116, 116, 116, 116, 116, 116,  10, 116, 116,  55,
     45, 116,   5, 116,   0, 116,   0, 116, 116, 116,
    116, 116, 116, 116, 116,   5,   0,   0,  20,   0,
      0,  10,   0,   0, 116,   0,   0,   0,  15,   5,
    116, 116,  10,   0,   0,   0, 116, 116,   0,   0,
     10, 116, 116, 116, 116, 116, 116,   5,   0,   0,
     20,   0,   0,  10,   0,   0, 116,   0,   0,   0,
     15,   5, 116, 116,  10,   0,   0,   0, 116, 116,
      0,   0,  10, 116, 116, 116, 116, 116, 116, 116,
    116, 116, 116, 116, 116, 116, 116, 116, 116, 116,
    116, 116, 116, 116, 116, 116, 116, 116, 116, 116,
    116, 116, 116, 116, 116, 116, 116, 116, 116, 116,
    116, 116, 116, 116, 116, 116, 116, 116, 116, 116,
    116, 116, 116, 116, 116, 116, 116, 116, 116, 116,
    116, 116, 116, 116, 116, 116, 116, 116, 116, 116,
    116, 116, 116, 116, 116, 116, 116, 116, 116, 116,
    116, 116, 116, 116, 116, 116, 116, 116, 116, 116,
    116, 116, 116, 116, 116, 116, 116, 116, 116, 116,
    116, 116, 116, 116, 116, 116, 116, 116, 116, 116,
    116, 116, 116, 116, 116, 116, 116, 116, 116, 116,
    116, 116, 116, 116, 116, 116, 116, 116, 116, 116,
    116, 116, 116, 116, 116, 116
};

static void LIBXML2_LOG_CALLBACK parser_error(void* ctx, char const* msg, ...)
{
    va_list ap;
    va_start(ap, msg);
    LIBXML2_CALLBACK_ERR(Schema_parse, msg, ap);
    va_end(ap);
}

static void LIBXML2_LOG_CALLBACK parser_warning(void* ctx, char const* msg, ...)
{
    va_list ap;
    va_start(ap, msg);
    LIBXML2_CALLBACK_WARN(Schema_parse, msg, ap);
    va_end(ap);
}

static void parser_serror(void* ctx, const xmlError* err)
{
    LIBXML2_CALLBACK_SERROR(Schema_parse, err);
}

static inline xmlSchemaPtr Schema_parse(xmlSchemaParserCtxtPtr spctx)
{
    TRACE("(%p)\n", spctx);

    xmlSchemaSetParserErrors(spctx, parser_error, parser_warning, NULL);
    xmlSchemaSetParserStructuredErrors(spctx, parser_serror, NULL);
    return xmlSchemaParse(spctx);
}

static void LIBXML2_LOG_CALLBACK validate_error(void* ctx, char const* msg, ...)
{
    va_list ap;
    va_start(ap, msg);
    LIBXML2_CALLBACK_ERR(Schema_validate_tree, msg, ap);
    va_end(ap);
}

static void LIBXML2_LOG_CALLBACK validate_warning(void* ctx, char const* msg, ...)
{
    va_list ap;
    va_start(ap, msg);
    LIBXML2_CALLBACK_WARN(Schema_validate_tree, msg, ap);
    va_end(ap);
}

static void validate_serror(void* ctx, const xmlError* err)
{
    LIBXML2_CALLBACK_SERROR(Schema_validate_tree, err);
}

static HRESULT schema_cache_get_item(IUnknown *iface, LONG index, VARIANT *item)
{
    V_VT(item) = VT_BSTR;
    return IXMLDOMSchemaCollection2_get_namespaceURI((IXMLDOMSchemaCollection2*)iface, index, &V_BSTR(item));
}

static const struct enumvariant_funcs schemacache_enumvariant = {
    schema_cache_get_item,
    NULL
};

static inline HRESULT Schema_validate_tree(xmlSchemaPtr schema, xmlNodePtr tree)
{
    xmlSchemaValidCtxtPtr svctx;
    int err;

    TRACE("(%p, %p)\n", schema, tree);
    /* TODO: if validateOnLoad property is false,
     *       we probably need to validate the schema here. */
    svctx = xmlSchemaNewValidCtxt(schema);
    xmlSchemaSetValidErrors(svctx, validate_error, validate_warning, NULL);
    xmlSchemaSetValidStructuredErrors(svctx, validate_serror, NULL);

    if (tree->type == XML_DOCUMENT_NODE)
        err = xmlSchemaValidateDoc(svctx, (xmlDocPtr)tree);
    else
        err = xmlSchemaValidateOneElement(svctx, tree);

    xmlSchemaFreeValidCtxt(svctx);
    return err? S_FALSE : S_OK;
}

static DWORD dt_hash(xmlChar const* str, int len /* calculated if -1 */)
{
    DWORD hval = (len == -1)? xmlStrlen(str) : len;

    switch (hval)
    {
        default:
            hval += hash_assoc_values[str[10]];
            /*FALLTHROUGH*/
        case 10:
            hval += hash_assoc_values[str[9]];
            /*FALLTHROUGH*/
        case 9:
            hval += hash_assoc_values[str[8]];
            /*FALLTHROUGH*/
        case 8:
            hval += hash_assoc_values[str[7]];
            /*FALLTHROUGH*/
        case 7:
            hval += hash_assoc_values[str[6]];
            /*FALLTHROUGH*/
        case 6:
            hval += hash_assoc_values[str[5]];
            /*FALLTHROUGH*/
        case 5:
            hval += hash_assoc_values[str[4]];
            /*FALLTHROUGH*/
        case 4:
            hval += hash_assoc_values[str[3]];
            /*FALLTHROUGH*/
        case 3:
            hval += hash_assoc_values[str[2]];
            /*FALLTHROUGH*/
        case 2:
            hval += hash_assoc_values[str[1]];
            /*FALLTHROUGH*/
        case 1:
            hval += hash_assoc_values[str[0]];
            break;
    }
    return hval;
}

static DWORD dt_hash_bstr(OLECHAR const* bstr, int len /* calculated if -1 */)
{
    DWORD hval = (len == -1)? lstrlenW(bstr) : len;

    switch (hval)
    {
        default:
            hval += (bstr[10] & 0xFF00)? 116 : hash_assoc_values[bstr[10]];
            /*FALLTHROUGH*/
        case 10:
            hval += (bstr[9] & 0xFF00)? 116 : hash_assoc_values[bstr[9]];
            /*FALLTHROUGH*/
        case 9:
            hval += (bstr[8] & 0xFF00)? 116 : hash_assoc_values[bstr[8]];
            /*FALLTHROUGH*/
        case 8:
            hval += (bstr[7] & 0xFF00)? 116 : hash_assoc_values[bstr[7]];
            /*FALLTHROUGH*/
        case 7:
            hval += (bstr[6] & 0xFF00)? 116 : hash_assoc_values[bstr[6]];
            /*FALLTHROUGH*/
        case 6:
            hval += (bstr[5] & 0xFF00)? 116 : hash_assoc_values[bstr[5]];
            /*FALLTHROUGH*/
        case 5:
            hval += (bstr[4] & 0xFF00)? 116 : hash_assoc_values[bstr[4]];
            /*FALLTHROUGH*/
        case 4:
            hval += (bstr[3] & 0xFF00)? 116 : hash_assoc_values[bstr[3]];
            /*FALLTHROUGH*/
        case 3:
            hval += (bstr[2] & 0xFF00)? 116 : hash_assoc_values[bstr[2]];
            /*FALLTHROUGH*/
        case 2:
            hval += (bstr[1] & 0xFF00)? 116 : hash_assoc_values[bstr[1]];
            /*FALLTHROUGH*/
        case 1:
            hval += (bstr[0] & 0xFF00)? 116 : hash_assoc_values[bstr[0]];
            break;
    }
    return hval;
}

static const xmlChar *const DT_string_table[LAST_DT] =
{
    DT_bin_base64,
    DT_bin_hex,
    DT_boolean,
    DT_char,
    DT_date,
    DT_date_tz,
    DT_dateTime,
    DT_dateTime_tz,
    DT_entity,
    DT_entities,
    DT_enumeration,
    DT_fixed_14_4,
    DT_float,
    DT_i1,
    DT_i2,
    DT_i4,
    DT_i8,
    DT_id,
    DT_idref,
    DT_idrefs,
    DT_int,
    DT_nmtoken,
    DT_nmtokens,
    DT_notation,
    DT_number,
    DT_r4,
    DT_r8,
    DT_string,
    DT_time,
    DT_time_tz,
    DT_ui1,
    DT_ui2,
    DT_ui4,
    DT_ui8,
    DT_uri,
    DT_uuid
};

static const WCHAR *const DT_wstring_table[LAST_DT] =
{
    wDT_bin_base64,
    wDT_bin_hex,
    wDT_boolean,
    wDT_char,
    wDT_date,
    wDT_date_tz,
    wDT_dateTime,
    wDT_dateTime_tz,
    wDT_entity,
    wDT_entities,
    wDT_enumeration,
    wDT_fixed_14_4,
    wDT_float,
    wDT_i1,
    wDT_i2,
    wDT_i4,
    wDT_i8,
    wDT_id,
    wDT_idref,
    wDT_idrefs,
    wDT_int,
    wDT_nmtoken,
    wDT_nmtokens,
    wDT_notation,
    wDT_number,
    wDT_r4,
    wDT_r8,
    wDT_string,
    wDT_time,
    wDT_time_tz,
    wDT_ui1,
    wDT_ui2,
    wDT_ui4,
    wDT_ui8,
    wDT_uri,
    wDT_uuid
};

static const XDR_DT DT_lookup_table[] =
{
    -1, -1,
    DT_I8,
    DT_UI8,
    DT_TIME,
    -1, -1,
    DT_I4,
    DT_UI4,
    -1, -1, -1,
    DT_R8,
    DT_URI,
    -1,
    DT_FLOAT,
    -1,
    DT_R4,
    DT_INT,
    DT_CHAR,
    -1,
    DT_ENTITY,
    DT_ID,
    DT_ENTITIES,
    DT_UUID,
    -1, -1,
    DT_TIME_TZ,
    -1,
    DT_DATE,
    -1,
    DT_NUMBER,
    DT_BIN_HEX,
    DT_DATETIME,
    -1,
    DT_IDREF,
    DT_IDREFS,
    DT_BOOLEAN,
    -1, -1, -1,
    DT_STRING,
    DT_NMTOKEN,
    DT_NMTOKENS,
    -1,
    DT_BIN_BASE64,
    -1,
    DT_I2,
    DT_UI2,
    -1, -1, -1,
    DT_DATE_TZ,
    DT_NOTATION,
    -1, -1,
    DT_DATETIME_TZ,
    DT_I1,
    DT_UI1,
    -1, -1,
    DT_ENUMERATION,
    -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1,
    DT_FIXED_14_4
};

XDR_DT str_to_dt(xmlChar const* str, int len /* calculated if -1 */)
{
    DWORD hash = dt_hash(str, len);
    XDR_DT dt = DT_INVALID;

    if (hash <= DT_MAX_HASH_VALUE)
        dt = DT_lookup_table[hash];

    if (dt != DT_INVALID && xmlStrcasecmp(str, DT_string_table[dt]) == 0)
        return dt;

    return DT_INVALID;
}

XDR_DT bstr_to_dt(OLECHAR const* bstr, int len /* calculated if -1 */)
{
    DWORD hash = dt_hash_bstr(bstr, len);
    XDR_DT dt = DT_INVALID;

    if (hash <= DT_MAX_HASH_VALUE)
        dt = DT_lookup_table[hash];

    if (dt != DT_INVALID && lstrcmpiW(bstr, DT_wstring_table[dt]) == 0)
        return dt;

    return DT_INVALID;
}

xmlChar const* dt_to_str(XDR_DT dt)
{
    if (dt == DT_INVALID)
        return NULL;

    return DT_string_table[dt];
}

OLECHAR const* dt_to_bstr(XDR_DT dt)
{
    if (dt == DT_INVALID)
        return NULL;

    return DT_wstring_table[dt];
}

const char* debugstr_dt(XDR_DT dt)
{
    return debugstr_a(dt != DT_INVALID ? (const char*)DT_string_table[dt] : NULL);
}

HRESULT dt_validate(XDR_DT dt, xmlChar const* content)
{
    xmlDocPtr tmp_doc;
    xmlNodePtr node;
    xmlNsPtr ns;
    HRESULT hr;

    TRACE("(dt:%s, %s)\n", debugstr_dt(dt), debugstr_a((char const*)content));

    if (!datatypes_schema)
    {
        xmlSchemaParserCtxtPtr spctx;
        assert(datatypes_src != NULL);
        spctx = xmlSchemaNewMemParserCtxt((char const*)datatypes_src, datatypes_len);
        datatypes_schema = Schema_parse(spctx);
        xmlSchemaFreeParserCtxt(spctx);
    }

    switch (dt)
    {
        case DT_INVALID:
            return E_FAIL;
        case DT_BIN_BASE64:
        case DT_BIN_HEX:
        case DT_BOOLEAN:
        case DT_CHAR:
        case DT_DATE:
        case DT_DATE_TZ:
        case DT_DATETIME:
        case DT_DATETIME_TZ:
        case DT_FIXED_14_4:
        case DT_FLOAT:
        case DT_I1:
        case DT_I2:
        case DT_I4:
        case DT_I8:
        case DT_INT:
        case DT_NMTOKEN:
        case DT_NMTOKENS:
        case DT_NUMBER:
        case DT_R4:
        case DT_R8:
        case DT_STRING:
        case DT_TIME:
        case DT_TIME_TZ:
        case DT_UI1:
        case DT_UI2:
        case DT_UI4:
        case DT_UI8:
        case DT_URI:
        case DT_UUID:
            if (!datatypes_schema)
            {
                ERR("failed to load schema for urn:schemas-microsoft-com:datatypes, "
                    "you're probably using an old version of libxml2: " LIBXML_DOTTED_VERSION "\n");

                /* Hopefully they don't need much in the way of XDR datatypes support... */
                return S_OK;
            }

            if (content && xmlStrlen(content))
            {
                tmp_doc = xmlNewDoc(NULL);
                node = xmlNewChild((xmlNodePtr)tmp_doc, NULL, dt_to_str(dt), content);
                ns = xmlNewNs(node, DT_nsURI, BAD_CAST "dt");
                xmlSetNs(node, ns);
                xmlDocSetRootElement(tmp_doc, node);

                hr = Schema_validate_tree(datatypes_schema, (xmlNodePtr)tmp_doc);
                xmlFreeDoc(tmp_doc);
            }
            else
            {   /* probably the node is being created manually and has no content yet */
                hr = S_OK;
            }
            return hr;
        default:
            FIXME("need to handle dt:%s\n", debugstr_dt(dt));
            return S_OK;
    }
}

static inline xmlChar const* get_node_nsURI(xmlNodePtr node)
{
    return (node->ns != NULL)? node->ns->href : NULL;
}

static inline cache_entry* get_entry(schema_cache* This, xmlChar const* nsURI)
{
    return (!nsURI)? xmlHashLookup(This->cache, BAD_CAST "") :
                     xmlHashLookup(This->cache, nsURI);
}

static inline xmlSchemaPtr get_node_schema(schema_cache* This, xmlNodePtr node)
{
    cache_entry* entry = get_entry(This, get_node_nsURI(node));
    return (!entry)? NULL : entry->schema;
}

static xmlExternalEntityLoader _external_entity_loader;

static xmlParserInputPtr external_entity_loader(const char *URL, const char *ID,
                                                xmlParserCtxtPtr ctxt)
{
    xmlParserInputPtr input;

    TRACE("(%s %s %p)\n", debugstr_a(URL), debugstr_a(ID), ctxt);

    assert(MSXML_hInstance != NULL);
    assert(datatypes_rsrc != NULL);
    assert(datatypes_handle != NULL);
    assert(datatypes_src != NULL);

    /* TODO: if the desired schema is in the cache, load it from there */
    if (lstrcmpA(URL, "urn:schemas-microsoft-com:datatypes") == 0)
    {
        TRACE("loading built-in schema for %s\n", URL);
        input = xmlNewStringInputStream(ctxt, datatypes_src);
    }
    else
    {
        input = _external_entity_loader(URL, ID, ctxt);
    }

    return input;
}

void schemasInit(void)
{
    xmlChar* buf;
    if (!(datatypes_rsrc = FindResourceA(MSXML_hInstance, "DATATYPES", "XML")))
    {
        FIXME("failed to find resource for %s\n", DT_nsURI);
        return;
    }

    if (!(datatypes_handle = LoadResource(MSXML_hInstance, datatypes_rsrc)))
    {
        FIXME("failed to load resource for %s\n", DT_nsURI);
        return;
    }
    buf = LockResource(datatypes_handle);
    datatypes_len = SizeofResource(MSXML_hInstance, datatypes_rsrc);

    /* Resource is loaded as raw data,
     * need a null-terminated string */
    while (buf[datatypes_len - 1] != '>') datatypes_len--;
    datatypes_src = malloc(datatypes_len + 1);
    memcpy(datatypes_src, buf, datatypes_len);
    datatypes_src[datatypes_len] = 0;

    if (xmlGetExternalEntityLoader() != external_entity_loader)
    {
        _external_entity_loader = xmlGetExternalEntityLoader();
        xmlSetExternalEntityLoader(external_entity_loader);
    }
}

void schemasCleanup(void)
{
    xmlSchemaFree(datatypes_schema);
    free(datatypes_src);
    xmlSetExternalEntityLoader(_external_entity_loader);
}

static LONG cache_entry_add_ref(cache_entry* entry)
{
    LONG ref = InterlockedIncrement(&entry->ref);
    TRACE("%p, refcount %ld.\n", entry, ref);
    return ref;
}

static LONG cache_entry_release(cache_entry* entry)
{
    LONG ref = InterlockedDecrement(&entry->ref);
    TRACE("%p, refcount %ld.\n", entry, ref);

    if (ref == 0)
    {
        if (entry->type == CacheEntryType_XSD)
        {
            xmldoc_release(entry->doc);
            entry->schema->doc = NULL;
            xmlSchemaFree(entry->schema);
        }
        else if (entry->type == CacheEntryType_XDR)
        {
            xmldoc_release(entry->doc);
            xmldoc_release(entry->schema->doc);
            entry->schema->doc = NULL;
            xmlSchemaFree(entry->schema);
        }

        free(entry);
    }
    return ref;
}

static const struct IXMLDOMSchemaCollection2Vtbl XMLDOMSchemaCollection2Vtbl;

static inline schema_cache* impl_from_IXMLDOMSchemaCollection2(IXMLDOMSchemaCollection2* iface)
{
    return CONTAINING_RECORD(iface, schema_cache, IXMLDOMSchemaCollection2_iface);
}

static inline schema_cache* impl_from_IXMLDOMSchemaCollection(IXMLDOMSchemaCollection* iface)
{
    return CONTAINING_RECORD(iface, schema_cache, IXMLDOMSchemaCollection2_iface);
}

static inline schema_cache* unsafe_impl_from_IXMLDOMSchemaCollection(IXMLDOMSchemaCollection *iface)
{
    return iface->lpVtbl == (void*)&XMLDOMSchemaCollection2Vtbl ? impl_from_IXMLDOMSchemaCollection(iface) : NULL;
}

static inline CacheEntryType cache_type_from_xmlDocPtr(xmlDocPtr schema)
{
    xmlNodePtr root = NULL;
    if (schema)
        root = xmlDocGetRootElement(schema);
    if (root && root->ns)
    {

        if (xmlStrEqual(root->name, XDR_schema) &&
            xmlStrEqual(root->ns->href, XDR_nsURI))
        {
            return CacheEntryType_XDR;
        }
        else if (xmlStrEqual(root->name, XSD_schema) &&
                 xmlStrEqual(root->ns->href, XSD_nsURI))
        {
            return CacheEntryType_XSD;
        }
    }
    return CacheEntryType_Invalid;
}

static BOOL link_datatypes(xmlDocPtr schema)
{
    xmlNodePtr root, next, child;
    xmlNsPtr ns;

    assert(xmlGetExternalEntityLoader() == external_entity_loader);
    root = xmlDocGetRootElement(schema);
    if (!root)
        return FALSE;

    for (ns = root->nsDef; ns != NULL; ns = ns->next)
    {
        if (xmlStrEqual(ns->href, DT_nsURI))
            break;
    }

    if (!ns)
        return FALSE;

    next = xmlFirstElementChild(root);
    child = xmlNewChild(root, NULL, BAD_CAST "import", NULL);
    if (next) child = xmlAddPrevSibling(next, child);
    xmlSetProp(child, BAD_CAST "namespace", DT_nsURI);
    xmlSetProp(child, BAD_CAST "schemaLocation", DT_nsURI);

    return TRUE;
}

/* msxml accepts the .NET-style escapes \uXXXX and \xXX in xs:pattern, inside and outside of character
 * classes, each one standing for the single character it names (also when that is a regex metacharacter).
 * libxml2's regexp compiler takes \u only outside of character classes and has no \x, so the schema copy
 * handed to libxml2 gets every pattern rewritten with the literal characters (metacharacters escaped).
 *
 * Code points libxml2 cannot hold literally are mapped as follows:
 *  - U+0000: NUL ends the C string, it becomes U+0001. Neither can occur in XML text, so no XML instance
 *    sees a difference.
 *  - U+D800-U+DFFF: msxml matches UTF-16 code units, libxml2 code points. A surrogate or surrogate range in
 *    a character class becomes U+10000-U+10FFFF (all and only the characters made of surrogates), the part
 *    outside of the surrogates is kept. Outside of a class a high + low surrogate pair of escapes becomes
 *    the one supplementary character, a lone surrogate becomes U+FFFF, which no XML text contains either.
 *    Not equivalent: a class of high surrogates followed by a class of low surrogates (msxml matches one
 *    supplementary character with it, libxml2 would need two).
 * Everything else, U+FFFE and U+FFFF included, is passed on as UTF-8. Other escapes are left alone, so
 * malformed ones (\u41, \U0041) are still rejected by libxml2 as msxml rejects them. */
typedef struct
{
    xmlChar *buf;
    int len, cap;
    BOOL oom;
} pat_buf;

static void pat_putc(pat_buf *b, unsigned char c)
{
    if (b->oom) return;
    if (b->len + 1 >= b->cap)
    {
        int cap = b->cap ? b->cap * 2 : 64;
        xmlChar *n = xmlRealloc(b->buf, cap);
        if (!n) { b->oom = TRUE; return; }
        b->buf = n;
        b->cap = cap;
    }
    b->buf[b->len++] = c;
}

static void pat_put_cp(pat_buf *b, unsigned int cp)
{
    static const char meta[] = "\\|.-^?*+{}()[]";
    const char *m;

    for (m = meta; *m; m++)
        if ((unsigned int)*m == cp) { pat_putc(b, '\\'); break; }

    if (cp < 0x80) pat_putc(b, cp);
    else if (cp < 0x800)
    {
        pat_putc(b, 0xc0 | (cp >> 6));
        pat_putc(b, 0x80 | (cp & 0x3f));
    }
    else if (cp < 0x10000)
    {
        pat_putc(b, 0xe0 | (cp >> 12));
        pat_putc(b, 0x80 | ((cp >> 6) & 0x3f));
        pat_putc(b, 0x80 | (cp & 0x3f));
    }
    else
    {
        pat_putc(b, 0xf0 | (cp >> 18));
        pat_putc(b, 0x80 | ((cp >> 12) & 0x3f));
        pat_putc(b, 0x80 | ((cp >> 6) & 0x3f));
        pat_putc(b, 0x80 | (cp & 0x3f));
    }
}

static int pat_hex(const xmlChar *s, int digits)
{
    int i, v = 0;

    for (i = 0; i < digits; i++)
    {
        if (s[i] >= '0' && s[i] <= '9') v = v * 16 + s[i] - '0';
        else if (s[i] >= 'a' && s[i] <= 'f') v = v * 16 + s[i] - 'a' + 10;
        else if (s[i] >= 'A' && s[i] <= 'F') v = v * 16 + s[i] - 'A' + 10;
        else return -1;
    }
    return v;
}

/* \uXXXX or \xXX at s: the code point and the length of the escape, else -1 */
static int pat_escape_cp(const xmlChar *s, int *len)
{
    if (s[0] != '\\') return -1;
    if (s[1] == 'u') { *len = 6; return pat_hex(s + 2, 4); }
    if (s[1] == 'x') { *len = 4; return pat_hex(s + 2, 2); }
    return -1;
}

/* one endpoint of a class range: an escape or a plain character; -1 for [ ] or another escape */
static int pat_class_endpoint(const xmlChar *s, int *len)
{
    int cp = pat_escape_cp(s, len);

    if (cp >= 0) return cp;
    if (*s == 0 || *s == '\\' || *s == '[' || *s == ']') return -1;
    *len = 4;
    cp = xmlGetUTF8Char(s, len);
    if (cp < 0) *len = 1;
    return cp;
}

static void pat_put_class_range(pat_buf *b, unsigned int lo, unsigned int hi)
{
    if (lo == 0) lo = 1;
    if (hi == 0) hi = 1;
    if (lo <= 0xdfff && hi >= 0xd800)
    {
        if (lo < 0xd800)
        {
            pat_put_cp(b, lo);
            if (lo != 0xd7ff) { pat_putc(b, '-'); pat_put_cp(b, 0xd7ff); }
        }
        pat_put_cp(b, 0x10000);
        pat_putc(b, '-');
        pat_put_cp(b, 0x10ffff);
        if (hi > 0xdfff)
        {
            pat_put_cp(b, 0xe000);
            if (hi != 0xe000) { pat_putc(b, '-'); pat_put_cp(b, hi); }
        }
        return;
    }
    pat_put_cp(b, lo);
    if (hi != lo) { pat_putc(b, '-'); pat_put_cp(b, hi); }
}

/* returns a new string (xmlFree), or NULL when the pattern has no \u or \x escape to rewrite */
static xmlChar *rewrite_msxml_pattern(const xmlChar *p)
{
    pat_buf b = { NULL, 0, 0, FALSE };
    const xmlChar *s = p;
    BOOL changed = FALSE;
    int depth = 0, cp, cp2, len, len2;

    while (*s)
    {
        if (depth == 0)
        {
            if ((cp = pat_escape_cp(s, &len)) >= 0)
            {
                changed = TRUE;
                s += len;
                if (cp >= 0xd800 && cp <= 0xdbff && (cp2 = pat_escape_cp(s, &len2)) >= 0xdc00 && cp2 <= 0xdfff)
                {
                    cp = 0x10000 + ((cp - 0xd800) << 10) + (cp2 - 0xdc00);
                    s += len2;
                }
                else if (cp >= 0xd800 && cp <= 0xdfff) cp = 0xffff;
                else if (cp == 0) cp = 1;
                pat_put_cp(&b, cp);
            }
            else if (*s == '\\' && s[1])
            {
                /* any other escape, \p{..} \- \( ... */
                pat_putc(&b, *s++);
                pat_putc(&b, *s++);
            }
            else if (*s == '[')
            {
                depth++;
                pat_putc(&b, *s++);
                if (*s == '^') pat_putc(&b, *s++);
            }
            else pat_putc(&b, *s++);
            continue;
        }

        /* inside a character class */
        if (*s == ']')
        {
            depth--;
            pat_putc(&b, *s++);
        }
        else if (s[0] == '-' && s[1] == '[')
        {
            /* subtraction, -[...] */
            depth++;
            pat_putc(&b, *s++);
            pat_putc(&b, *s++);
            if (*s == '^') pat_putc(&b, *s++);
        }
        else if ((cp = pat_class_endpoint(s, &len)) < 0)
        {
            /* \p{..} \d ..., a nested [ or a malformed byte: pass on, libxml2 judges it */
            BOOL prop = s[0] == '\\' && (s[1] == 'p' || s[1] == 'P') && s[2] == '{';

            if (*s == '\\' && s[1]) pat_putc(&b, *s++);
            pat_putc(&b, *s++);
            while (prop && *s)
            {
                pat_putc(&b, *s);
                if (*s++ == '}') break;
            }
        }
        else if (s[len] == '-' && s[len + 1] != ']' && s[len + 1] != '[' &&
                 (cp2 = pat_class_endpoint(s + len + 1, &len2)) >= 0)
        {
            changed |= s[0] == '\\' || s[len + 1] == '\\';
            pat_put_class_range(&b, cp, cp2);
            s += len + 1 + len2;
        }
        else
        {
            changed |= s[0] == '\\';
            pat_put_class_range(&b, cp, cp);
            s += len;
        }
    }

    if (!changed || b.oom)
    {
        xmlFree(b.buf);
        return NULL;
    }
    b.buf[b.len] = 0;
    return b.buf;
}

typedef struct
{
    xmlNodePtr node;
    xmlChar *orig;
} pattern_orig;

static BOOL is_xsd_pattern_node(xmlNodePtr node)
{
    return node->type == XML_ELEMENT_NODE && node->ns && node->ns->href &&
           !xmlStrcmp(node->ns->href, BAD_CAST "http://www.w3.org/2001/XMLSchema") &&
           !xmlStrcmp(node->name, BAD_CAST "pattern");
}

/* Rewrites the value of every xs:pattern in the schema document for libxml2; the original values are
 * returned in *orig, to put back once the schema is compiled. */
static void xsd_rewrite_patterns(xmlNodePtr node, pattern_orig **orig, int *count, int *cap)
{
    for (; node; node = node->next)
    {
        if (is_xsd_pattern_node(node))
        {
            xmlChar *val = xmlGetNoNsProp(node, BAD_CAST "value");
            xmlChar *new_val = val ? rewrite_msxml_pattern(val) : NULL;

            if (new_val)
            {
                if (*count == *cap)
                {
                    int new_cap = *cap ? *cap * 2 : 8;
                    pattern_orig *n = realloc(*orig, new_cap * sizeof(**orig));
                    if (!n) { xmlFree(new_val); xmlFree(val); continue; }
                    *orig = n;
                    *cap = new_cap;
                }
                (*orig)[*count].node = node;
                (*orig)[(*count)++].orig = val;
                xmlSetProp(node, BAD_CAST "value", new_val);
                xmlFree(new_val);
                continue;
            }
            xmlFree(val);
        }
        if (node->children) xsd_rewrite_patterns(node->children, orig, count, cap);
    }
}

static cache_entry* cache_entry_from_xsd_doc(xmlDocPtr doc, xmlChar const* nsURI, MSXML_VERSION v)
{
    cache_entry* entry = malloc(sizeof(cache_entry));
    xmlSchemaParserCtxtPtr spctx;
    xmlDocPtr new_doc = xmlCopyDoc(doc, 1);
    pattern_orig *orig = NULL;
    int i, orig_count = 0, orig_cap = 0;

    link_datatypes(new_doc);
    xsd_rewrite_patterns(new_doc->children, &orig, &orig_count, &orig_cap);

    /* TODO: if the nsURI is different from the default xmlns or targetNamespace,
     *       do we need to do something special here? */
    entry->type = CacheEntryType_XSD;
    entry->ref = 0;
    spctx = xmlSchemaNewDocParserCtxt(new_doc);

    if ((entry->schema = Schema_parse(spctx)))
    {
        /* the schema document is exposed to the caller, give it its own pattern values back */
        for (i = 0; i < orig_count; i++) xmlSetProp(orig[i].node, BAD_CAST "value", orig[i].orig);
        xmldoc_init(entry->schema->doc, v);
        entry->doc = entry->schema->doc;
        xmldoc_add_ref(entry->doc);
    }
    else
    {
        FIXME("failed to parse doc\n");
        xmlFreeDoc(new_doc);
        free(entry);
        entry = NULL;
    }
    for (i = 0; i < orig_count; i++) xmlFree(orig[i].orig);
    free(orig);
    xmlSchemaFreeParserCtxt(spctx);
    return entry;
}

static cache_entry* cache_entry_from_xdr_doc(xmlDocPtr doc, xmlChar const* nsURI, MSXML_VERSION version)
{
    cache_entry* entry = malloc(sizeof(cache_entry));
    xmlSchemaParserCtxtPtr spctx;
    xmlDocPtr new_doc = xmlCopyDoc(doc, 1), xsd_doc = XDR_to_XSD_doc(doc, nsURI);

    link_datatypes(xsd_doc);

    entry->type = CacheEntryType_XDR;
    entry->ref = 0;
    spctx = xmlSchemaNewDocParserCtxt(xsd_doc);

    if ((entry->schema = Schema_parse(spctx)))
    {
        entry->doc = new_doc;
        xmldoc_init(entry->schema->doc, version);
        xmldoc_init(entry->doc, version);
        xmldoc_add_ref(entry->doc);
        xmldoc_add_ref(entry->schema->doc);
    }
    else
    {
        FIXME("failed to parse doc\n");
        xmlFreeDoc(new_doc);
        xmlFreeDoc(xsd_doc);
        free(entry);
        entry = NULL;
    }
    xmlSchemaFreeParserCtxt(spctx);

    return entry;
}

static cache_entry* cache_entry_from_url(VARIANT url, xmlChar const* nsURI, MSXML_VERSION version)
{
    cache_entry* entry;
    IXMLDOMDocument3* domdoc = NULL;
    xmlDocPtr doc = NULL;
    HRESULT hr = dom_document_create(version, (void **)&domdoc);
    VARIANT_BOOL b = VARIANT_FALSE;
    CacheEntryType type = CacheEntryType_Invalid;

    if (hr != S_OK)
    {
        FIXME("failed to create domdoc\n");
        return NULL;
    }
    assert(domdoc != NULL);
    assert(V_VT(&url) == VT_BSTR);

    hr = IXMLDOMDocument3_load(domdoc, url, &b);
    if (hr != S_OK)
    {
        ERR("load() returned %#lx.\n", hr);
        if (b != VARIANT_TRUE)
        {
            FIXME("Failed to load doc at %s\n", debugstr_w(V_BSTR(&url)));
            IXMLDOMDocument3_Release(domdoc);
            return NULL;
        }
    }
    doc = xmlNodePtr_from_domnode((IXMLDOMNode*)domdoc, XML_DOCUMENT_NODE)->doc;
    type = cache_type_from_xmlDocPtr(doc);

    switch (type)
    {
        case CacheEntryType_XSD:
            entry = cache_entry_from_xsd_doc(doc, nsURI, version);
            break;
        case CacheEntryType_XDR:
            entry = cache_entry_from_xdr_doc(doc, nsURI, version);
            break;
        default:
            entry = NULL;
            FIXME("invalid schema\n");
            break;
    }
    IXMLDOMDocument3_Release(domdoc);

    return entry;
}

static void cache_free(void* data, const xmlChar* name /* ignored */)
{
    cache_entry_release((cache_entry*)data);
}

/* returns index or -1 if not found */
static int cache_free_uri(schema_cache *cache, const xmlChar *uri)
{
    int i;

    for (i = 0; i < cache->count; i++)
        if (xmlStrEqual(cache->uris[i], uri))
        {
            free(cache->uris[i]);
            return i;
        }

    return -1;
}

static void cache_add_entry(schema_cache *cache, const xmlChar *uri, cache_entry *entry)
{
    int i;

    /* meaning no entry found with this name */
    if (xmlHashRemoveEntry(cache->cache, uri, cache_free))
    {
        if (cache->count == cache->allocated)
        {
            cache->allocated *= 2;
            cache->uris = realloc(cache->uris, cache->allocated * sizeof(xmlChar*));
        }
        i = cache->count++;
    }
    else
        i = cache_free_uri(cache, uri);

    cache->uris[i] = strdupxmlChar(uri);
    xmlHashAddEntry(cache->cache, uri, entry);
}

static void cache_remove_entry(schema_cache *cache, const xmlChar *uri)
{
    /* adjust index if entry was really removed */
    if (xmlHashRemoveEntry(cache->cache, uri, cache_free) == 0)
    {
        int i = cache_free_uri(cache, uri);
        if (i == -1) return;
        /* shift array */
        if (i != --cache->count)
            memmove(&cache->uris[i], &cache->uris[i+1], (cache->count-i)*sizeof(xmlChar*));
    }
}

/* This one adds all namespaces defined in document to a cache, without anything
   associated with uri obviously.
   Unfortunately namespace:: axis implementation in libxml2 differs from what we need,
   it uses additional node type to describe namespace definition attribute while
   in msxml it's expected to be a normal attribute - as a workaround document is
   queried at libxml2 level here. */
HRESULT cache_from_doc_ns(IXMLDOMSchemaCollection2 *iface, xmlnode *node)
{
    schema_cache* This = impl_from_IXMLDOMSchemaCollection2(iface);
    static const xmlChar query[] = "//*/namespace::*";
    xmlXPathObjectPtr nodeset;
    xmlXPathContextPtr ctxt;

    This->read_only = 1;

    ctxt = xmlXPathNewContext(node->node->doc);

    nodeset = xmlXPathEvalExpression(query, ctxt);
    xmlXPathFreeContext(ctxt);

    if (nodeset)
    {
        int pos = 0, len = xmlXPathNodeSetGetLength(nodeset->nodesetval);

        while (pos < len)
        {
            xmlNodePtr node = xmlXPathNodeSetItem(nodeset->nodesetval, pos);
            if (node->type == XML_NAMESPACE_DECL)
            {
                static const xmlChar defns[] = "http://www.w3.org/XML/1998/namespace";
                xmlNsPtr ns = (xmlNsPtr)node;
                cache_entry *entry;

                /* filter out default uri */
                if (xmlStrEqual(ns->href, defns))
                {
                    pos++;
                    continue;
                }

                entry = malloc(sizeof(cache_entry));
                entry->type = CacheEntryType_NS;
                entry->ref = 1;
                entry->schema = NULL;
                entry->doc = NULL;

                cache_add_entry(This, ns->href, entry);
            }
            pos++;
        }

        xmlXPathFreeObject(nodeset);
    }

    return S_OK;
}

static HRESULT WINAPI schema_cache_QueryInterface(IXMLDOMSchemaCollection2* iface,
                                                  REFIID riid, void** ppvObject)
{
    schema_cache* This = impl_from_IXMLDOMSchemaCollection2(iface);

    TRACE("(%p)->(%s %p)\n", This, debugstr_guid(riid), ppvObject);

    if ( IsEqualIID(riid, &IID_IUnknown) ||
         IsEqualIID(riid, &IID_IDispatch) ||
         IsEqualIID(riid, &IID_IXMLDOMSchemaCollection) ||
         IsEqualIID(riid, &IID_IXMLDOMSchemaCollection2) )
    {
        *ppvObject = iface;
    }
    else if(This->version == MSXML6 && IsEqualIID(riid, &CLSID_XMLSchemaCache60))
    {
        /*
         * Version 6 can be queried for an interface with IID equal to CLSID.
         * There is no public interface with that IID and returned pointer
         * is equal to returned IXMLDOMSchemaCollection2 iface. We assume
         * that it's just another way for querying IXMLDOMSchemaCollection2
         * interface. Office 2013 ClickToRun installer uses this.
         */
        WARN("riid CLSID_XMLSchemaCache60, returning IXMLDOMSchemaCollection2 interface.\n");
        *ppvObject = iface;
    }
    else if (dispex_query_interface(&This->dispex, riid, ppvObject))
    {
        return *ppvObject ? S_OK : E_NOINTERFACE;
    }
    else if(IsEqualGUID( riid, &IID_ISupportErrorInfo ))
    {
        return node_create_supporterrorinfo(schema_cache_se_tids, ppvObject);
    }
    else
    {
        FIXME("interface %s not implemented\n", debugstr_guid(riid));
        *ppvObject = NULL;
        return E_NOINTERFACE;
    }

    IXMLDOMSchemaCollection2_AddRef(iface);

    return S_OK;
}

static ULONG WINAPI schema_cache_AddRef(IXMLDOMSchemaCollection2* iface)
{
    schema_cache* This = impl_from_IXMLDOMSchemaCollection2(iface);
    LONG ref = InterlockedIncrement(&This->ref);
    TRACE("%p, refcount %ld.\n", iface, ref);
    return ref;
}

static ULONG WINAPI schema_cache_Release(IXMLDOMSchemaCollection2* iface)
{
    schema_cache* This = impl_from_IXMLDOMSchemaCollection2(iface);
    LONG ref = InterlockedDecrement(&This->ref);
    TRACE("%p, refcount %ld.\n", iface, ref);

    if (!ref)
    {
        int i;

        for (i = 0; i < This->count; i++)
            free(This->uris[i]);
        free(This->uris);
        xmlHashFree(This->cache, cache_free);
        free(This);
    }

    return ref;
}

static HRESULT WINAPI schema_cache_GetTypeInfoCount(IXMLDOMSchemaCollection2* iface,
                                                    UINT* pctinfo)
{
    schema_cache* This = impl_from_IXMLDOMSchemaCollection2(iface);
    return IDispatchEx_GetTypeInfoCount(&This->dispex.IDispatchEx_iface, pctinfo);
}

static HRESULT WINAPI schema_cache_GetTypeInfo(IXMLDOMSchemaCollection2* iface,
                                               UINT iTInfo, LCID lcid, ITypeInfo** ppTInfo)
{
    schema_cache* This = impl_from_IXMLDOMSchemaCollection2(iface);
    return IDispatchEx_GetTypeInfo(&This->dispex.IDispatchEx_iface,
        iTInfo, lcid, ppTInfo);
}

static HRESULT WINAPI schema_cache_GetIDsOfNames(IXMLDOMSchemaCollection2* iface,
                                                 REFIID riid, LPOLESTR* rgszNames,
                                                 UINT cNames, LCID lcid, DISPID* rgDispId)
{
    schema_cache* This = impl_from_IXMLDOMSchemaCollection2(iface);
    return IDispatchEx_GetIDsOfNames(&This->dispex.IDispatchEx_iface,
        riid, rgszNames, cNames, lcid, rgDispId);
}

static HRESULT WINAPI schema_cache_Invoke(IXMLDOMSchemaCollection2* iface,
                                          DISPID dispIdMember, REFIID riid, LCID lcid,
                                          WORD wFlags, DISPPARAMS* pDispParams,
                                          VARIANT* pVarResult, EXCEPINFO* pExcepInfo,
                                          UINT* puArgErr)
{
    schema_cache* This = impl_from_IXMLDOMSchemaCollection2(iface);
    return IDispatchEx_Invoke(&This->dispex.IDispatchEx_iface,
        dispIdMember, riid, lcid, wFlags, pDispParams, pVarResult, pExcepInfo, puArgErr);
}

static HRESULT WINAPI schema_cache_add(IXMLDOMSchemaCollection2* iface, BSTR uri, VARIANT var)
{
    schema_cache* This = impl_from_IXMLDOMSchemaCollection2(iface);
    xmlChar* name;

    TRACE("(%p)->(%s %s)\n", This, debugstr_w(uri), debugstr_variant(&var));

    if (This->read_only) return E_FAIL;

    name = uri ? xmlchar_from_wchar(uri) : xmlchar_from_wchar(emptyW);

    switch (V_VT(&var))
    {
        case VT_NULL:
            {
                cache_remove_entry(This, name);
            }
            break;

        case VT_BSTR:
            {
                cache_entry* entry = cache_entry_from_url(var, name, This->version);

                if (entry)
                {
                    cache_entry_add_ref(entry);
                }
                else
                {
                    free(name);
                    return E_FAIL;
                }

                cache_add_entry(This, name, entry);
            }
            break;

        case VT_DISPATCH:
        case VT_UNKNOWN:
            {
                xmlDocPtr doc = NULL;
                cache_entry* entry;
                CacheEntryType type;
                IXMLDOMNode* domnode = NULL;
                IUnknown_QueryInterface(V_UNKNOWN(&var), &IID_IXMLDOMNode, (void**)&domnode);

                if (domnode)
                {
                    DOMNodeType type;

                    IXMLDOMNode_get_nodeType(domnode, &type);
                    switch (type)
                    {
                    case NODE_ELEMENT:
                    {
                        IXMLDOMDocument *domdoc;
                        VARIANT_BOOL b;
                        BSTR xml;

                        IXMLDOMNode_get_xml(domnode, &xml);
                        dom_document_create(This->version, (void **)&domdoc);
                        IXMLDOMDocument_loadXML(domdoc, xml, &b);
                        SysFreeString(xml);
                        doc = xmlNodePtr_from_domnode((IXMLDOMNode*)domdoc, XML_DOCUMENT_NODE)->doc;
                        break;
                    }
                    default:
                        doc = xmlNodePtr_from_domnode(domnode, XML_DOCUMENT_NODE)->doc;
                        break;
                    }
                }

                if (!doc)
                {
                    IXMLDOMNode_Release(domnode);
                    free(name);
                    return E_INVALIDARG;
                }
                type = cache_type_from_xmlDocPtr(doc);

                if (type == CacheEntryType_XSD)
                {
                    entry = cache_entry_from_xsd_doc(doc, name, This->version);
                }
                else if (type == CacheEntryType_XDR)
                {
                    entry = cache_entry_from_xdr_doc(doc, name, This->version);
                }
                else
                {
                    WARN("invalid schema!\n");
                    entry = NULL;
                }

                IXMLDOMNode_Release(domnode);

                if (entry)
                {
                    cache_entry_add_ref(entry);
                }
                else
                {
                    free(name);
                    return E_FAIL;
                }

                cache_add_entry(This, name, entry);
            }
            break;

        default:
            FIXME("arg type is not supported, %s\n", debugstr_variant(&var));
            free(name);
            return E_INVALIDARG;
    }
    free(name);
    return S_OK;
}

static HRESULT WINAPI schema_cache_get(IXMLDOMSchemaCollection2* iface, BSTR uri,
                                       IXMLDOMNode** node)
{
    schema_cache* This = impl_from_IXMLDOMSchemaCollection2(iface);
    cache_entry* entry;
    xmlChar* name;

    TRACE("(%p)->(%s %p)\n", This, debugstr_w(uri), node);

    if (This->version == MSXML6)
    {
        if (node) *node = NULL;
        return E_NOTIMPL;
    }

    if (!node)
        return E_POINTER;

    *node = NULL;

    name = uri ? xmlchar_from_wchar(uri) : xmlchar_from_wchar(emptyW);
    entry = (cache_entry*) xmlHashLookup(This->cache, name);
    free(name);

    /* TODO: this should be read-only */
    if (entry && entry->doc)
        return get_domdoc_from_xmldoc(entry->doc, (IXMLDOMDocument3**)node);

    return S_OK;
}

static HRESULT WINAPI schema_cache_remove(IXMLDOMSchemaCollection2* iface, BSTR uri)
{
    schema_cache* This = impl_from_IXMLDOMSchemaCollection2(iface);
    xmlChar* name;

    TRACE("(%p)->(%s)\n", This, debugstr_w(uri));

    if (This->version == MSXML6) return E_NOTIMPL;

    name = uri ? xmlchar_from_wchar(uri) : xmlchar_from_wchar(emptyW);
    cache_remove_entry(This, name);
    free(name);
    return S_OK;
}

static HRESULT WINAPI schema_cache_get_length(IXMLDOMSchemaCollection2* iface, LONG* length)
{
    schema_cache* This = impl_from_IXMLDOMSchemaCollection2(iface);
    TRACE("(%p)->(%p)\n", This, length);

    if (!length)
        return E_POINTER;

    *length = This->count;
    return S_OK;
}

static HRESULT WINAPI schema_cache_get_namespaceURI(IXMLDOMSchemaCollection2* iface,
                                                    LONG index, BSTR* uri)
{
    schema_cache* This = impl_from_IXMLDOMSchemaCollection2(iface);

    TRACE("%p, %ld, %p.\n", iface, index, uri);

    if (!uri)
        return E_POINTER;

    if (This->version == MSXML6)
        *uri = NULL;

    if (index >= This->count)
        return E_FAIL;

    *uri = bstr_from_xmlChar(This->uris[index]);
    return S_OK;
}

static void cache_copy(void* data, void* dest, const xmlChar* name)
{
    schema_cache* This = (schema_cache*) dest;
    cache_entry* entry = (cache_entry*) data;

    if (xmlHashLookup(This->cache, name) == NULL)
    {
        cache_entry_add_ref(entry);
        cache_add_entry(This, name, entry);
    }
}

static HRESULT WINAPI schema_cache_addCollection(IXMLDOMSchemaCollection2* iface,
                                                 IXMLDOMSchemaCollection* collection)
{
    schema_cache* This = impl_from_IXMLDOMSchemaCollection2(iface);
    schema_cache* That;

    TRACE("(%p)->(%p)\n", This, collection);

    if (!collection)
        return E_POINTER;

    That = unsafe_impl_from_IXMLDOMSchemaCollection(collection);
    if (!That)
    {
        ERR("external collection implementation\n");
        return E_FAIL;
    }

    /* TODO: detect errors while copying & return E_FAIL */
    xmlHashScan(That->cache, cache_copy, This);

    return S_OK;
}

static HRESULT WINAPI schema_cache_get__newEnum(IXMLDOMSchemaCollection2* iface, IUnknown** enumv)
{
    schema_cache* This = impl_from_IXMLDOMSchemaCollection2(iface);
    TRACE("(%p)->(%p)\n", This, enumv);
    return create_enumvariant((IUnknown*)iface, TRUE, &schemacache_enumvariant, (IEnumVARIANT**)enumv);
}

static HRESULT WINAPI schema_cache_validate(IXMLDOMSchemaCollection2* iface)
{
    schema_cache* This = impl_from_IXMLDOMSchemaCollection2(iface);
    FIXME("(%p): stub\n", This);
    return E_NOTIMPL;
}

static HRESULT WINAPI schema_cache_put_validateOnLoad(IXMLDOMSchemaCollection2* iface,
                                                      VARIANT_BOOL value)
{
    schema_cache* This = impl_from_IXMLDOMSchemaCollection2(iface);
    FIXME("(%p)->(%d): stub\n", This, value);

    This->validateOnLoad = value;
    /* it's ok to disable it, cause we don't validate on load anyway */
    if (value == VARIANT_FALSE) return S_OK;

    return E_NOTIMPL;
}

static HRESULT WINAPI schema_cache_get_validateOnLoad(IXMLDOMSchemaCollection2* iface,
                                                      VARIANT_BOOL* value)
{
    schema_cache* This = impl_from_IXMLDOMSchemaCollection2(iface);
    TRACE("(%p)->(%p)\n", This, value);

    if (!value) return E_POINTER;
    *value = This->validateOnLoad;

    return S_OK;
}

static HRESULT WINAPI schema_cache_getSchema(IXMLDOMSchemaCollection2* iface,
                                             BSTR namespaceURI, ISchema** schema)
{
    schema_cache* This = impl_from_IXMLDOMSchemaCollection2(iface);
    FIXME("(%p)->(%s %p): stub\n", This, debugstr_w(namespaceURI), schema);
    if (schema)
        *schema = NULL;
    return E_NOTIMPL;
}

static HRESULT WINAPI schema_cache_getDeclaration(IXMLDOMSchemaCollection2* iface,
                                                  IXMLDOMNode* node, ISchemaItem** item)
{
    schema_cache* This = impl_from_IXMLDOMSchemaCollection2(iface);
    FIXME("(%p)->(%p %p): stub\n", This, node, item);
    if (item)
        *item = NULL;
    return E_NOTIMPL;
}

static const struct IXMLDOMSchemaCollection2Vtbl XMLDOMSchemaCollection2Vtbl =
{
    schema_cache_QueryInterface,
    schema_cache_AddRef,
    schema_cache_Release,
    schema_cache_GetTypeInfoCount,
    schema_cache_GetTypeInfo,
    schema_cache_GetIDsOfNames,
    schema_cache_Invoke,
    schema_cache_add,
    schema_cache_get,
    schema_cache_remove,
    schema_cache_get_length,
    schema_cache_get_namespaceURI,
    schema_cache_addCollection,
    schema_cache_get__newEnum,
    schema_cache_validate,
    schema_cache_put_validateOnLoad,
    schema_cache_get_validateOnLoad,
    schema_cache_getSchema,
    schema_cache_getDeclaration
};

static xmlSchemaElementPtr lookup_schema_elemDecl(xmlSchemaPtr schema, xmlNodePtr node)
{
    xmlSchemaElementPtr decl = NULL;
    xmlChar const* nsURI = get_node_nsURI(node);

    TRACE("(%p, %p)\n", schema, node);

    if (xmlStrEqual(nsURI, schema->targetNamespace))
        decl = xmlHashLookup(schema->elemDecl, node->name);

    if (!decl && xmlHashSize(schema->schemasImports) > 1)
    {
        FIXME("declaration not found in main schema - need to check schema imports!\n");
        /*xmlSchemaImportPtr import;
        if (nsURI == NULL)
            import = xmlHashLookup(schema->schemasImports, XML_SCHEMAS_NO_NAMESPACE);
        else
            import = xmlHashLookup(schema->schemasImports, node->ns->href);

        if (import != NULL)
            decl = xmlHashLookup(import->schema->elemDecl, node->name);*/
    }

    return decl;
}

static inline xmlNodePtr lookup_schema_element(xmlSchemaPtr schema, xmlNodePtr node)
{
    xmlSchemaElementPtr decl = lookup_schema_elemDecl(schema, node);
    while (decl != NULL && decl->refDecl != NULL)
        decl = decl->refDecl;
    return (decl != NULL)? decl->node : NULL;
}

HRESULT SchemaCache_validate_tree(IXMLDOMSchemaCollection2* iface, xmlNodePtr tree)
{
    schema_cache* This = impl_from_IXMLDOMSchemaCollection2(iface);
    xmlSchemaPtr schema;

    TRACE("(%p, %p)\n", This, tree);

    if (!tree)
        return E_POINTER;

    if (tree->type == XML_DOCUMENT_NODE)
        tree = xmlDocGetRootElement(tree->doc);

    schema = get_node_schema(This, tree);
    /* TODO: if the ns is not in the cache, and it's a URL,
     *       do we try to load from that? */
    if (schema)
        return Schema_validate_tree(schema, tree);
    else
        WARN("no schema found for xmlns=%s\n", get_node_nsURI(tree));

    return E_FAIL;
}

XDR_DT SchemaCache_get_node_dt(IXMLDOMSchemaCollection2* iface, xmlNodePtr node)
{
    schema_cache* This = impl_from_IXMLDOMSchemaCollection2(iface);
    xmlSchemaPtr schema = get_node_schema(This, node);
    XDR_DT dt = DT_INVALID;

    TRACE("(%p, %p)\n", This, node);

    if (node->ns && xmlStrEqual(node->ns->href, DT_nsURI))
    {
        dt = str_to_dt(node->name, -1);
    }
    else if (schema)
    {
        xmlChar* str;
        xmlNodePtr schema_node = lookup_schema_element(schema, node);

        str = xmlGetNsProp(schema_node, BAD_CAST "dt", DT_nsURI);
        if (str)
        {
            dt = str_to_dt(str, -1);
            xmlFree(str);
        }
    }

    return dt;
}

static const tid_t schemacache_iface_tids[] = {
    IXMLDOMSchemaCollection2_tid,
    0
};

static dispex_static_data_t schemacache_dispex = {
    NULL,
    IXMLDOMSchemaCollection2_tid,
    NULL,
    schemacache_iface_tids
};

HRESULT SchemaCache_create(MSXML_VERSION version, void** obj)
{
    schema_cache* This = malloc(sizeof(schema_cache));
    if (!This)
        return E_OUTOFMEMORY;

    TRACE("(%d %p)\n", version, obj);

    This->IXMLDOMSchemaCollection2_iface.lpVtbl = &XMLDOMSchemaCollection2Vtbl;
    This->cache = xmlHashCreate(DEFAULT_HASHTABLE_SIZE);
    This->allocated = 10;
    This->count = 0;
    This->uris = malloc(This->allocated * sizeof(xmlChar*));
    This->ref = 1;
    This->version = version;
    This->validateOnLoad = VARIANT_TRUE;
    This->read_only = 0;
    init_dispex(&This->dispex, (IUnknown*)&This->IXMLDOMSchemaCollection2_iface, &schemacache_dispex);

    *obj = &This->IXMLDOMSchemaCollection2_iface;
    return S_OK;
}
