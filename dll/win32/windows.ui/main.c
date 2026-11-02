/*
 * PROJECT:     ReactOS Windows.UI
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     The WinRT class Windows.UI.ViewManagement.UISettings
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Qt 6.8 (qwindows.dll) creates a UISettings through C++/WinRT to read the system colours. When the class
 * is not registered C++/WinRT throws hresult_class_not_registered, nothing catches it and the application
 * dies while the Windows platform theme is created. This class reports the colour scheme and the accent
 * colour of the current user and the metrics Windows 10 has by default. Its change events are accepted
 * and never raised.
 */

#include <stdarg.h>

#include "windef.h"
#include "winbase.h"
#include "winreg.h"
#include "winuser.h"
#include "winerror.h"
#include "objbase.h"
#include "initguid.h"
#include "inspectable.h"
#include "activation.h"
#include "winstring.h"
#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(windowsui);

static const WCHAR class_name[] = L"Windows.UI.ViewManagement.UISettings";

DEFINE_GUID(IID_IUISettings,  0x85361600, 0x1c63, 0x4627, 0xbc, 0xb1, 0x3a, 0x89, 0xe0, 0xbc, 0x9c, 0x55);
DEFINE_GUID(IID_IUISettings2, 0xbad82401, 0x2721, 0x44f9, 0xbb, 0x91, 0x2b, 0xb2, 0x28, 0xbe, 0x44, 0x2f);
DEFINE_GUID(IID_IUISettings3, 0x03021be4, 0x5254, 0x4781, 0x81, 0x94, 0x51, 0x68, 0xf7, 0xd0, 0x6d, 0x7b);
DEFINE_GUID(IID_IUISettings4, 0x52bb3002, 0x919b, 0x4d6b, 0x9b, 0x78, 0x8d, 0xd6, 0x6f, 0xf4, 0xb9, 0x3b);
DEFINE_GUID(IID_IUISettings5, 0x5349d588, 0x0cb5, 0x5f05, 0xbd, 0x34, 0x70, 0x6b, 0x32, 0x31, 0xf0, 0xbd);
DEFINE_GUID(IID_IUISettings6, 0xaef19bd7, 0xfe31, 0x5a04, 0xad, 0xa4, 0x46, 0x9a, 0xae, 0xc6, 0xdf, 0xa9);

typedef struct { UINT8 A, R, G, B; } UiColor;
typedef struct { float Width, Height; } UiSize;

/* Windows.UI.ViewManagement.UIColorType */
enum
{
    UIColorType_Background, UIColorType_Foreground,
    UIColorType_AccentDark3, UIColorType_AccentDark2, UIColorType_AccentDark1,
    UIColorType_Accent,
    UIColorType_AccentLight1, UIColorType_AccentLight2, UIColorType_AccentLight3,
    UIColorType_Complement
};

typedef struct UISettings UISettings;

#define BASE_METHODS(T) \
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(T *This, REFIID iid, void **out); \
    ULONG (STDMETHODCALLTYPE *AddRef)(T *This); \
    ULONG (STDMETHODCALLTYPE *Release)(T *This); \
    HRESULT (STDMETHODCALLTYPE *GetIids)(T *This, ULONG *count, IID **iids); \
    HRESULT (STDMETHODCALLTYPE *GetRuntimeClassName)(T *This, HSTRING *name); \
    HRESULT (STDMETHODCALLTYPE *GetTrustLevel)(T *This, TrustLevel *level);

#define DECLARE_IFACE(T) \
    typedef struct T T; \
    struct T { const T##Vtbl *lpVtbl; UISettings *obj; };

typedef struct IUISettingsX IUISettingsX;
typedef struct { BASE_METHODS(IUISettingsX)
    HRESULT (STDMETHODCALLTYPE *get_HandPreference)(IUISettingsX *This, INT32 *value);
    HRESULT (STDMETHODCALLTYPE *get_CursorSize)(IUISettingsX *This, UiSize *value);
    HRESULT (STDMETHODCALLTYPE *get_ScrollBarSize)(IUISettingsX *This, UiSize *value);
    HRESULT (STDMETHODCALLTYPE *get_ScrollBarArrowSize)(IUISettingsX *This, UiSize *value);
    HRESULT (STDMETHODCALLTYPE *get_ScrollBarThumbBoxSize)(IUISettingsX *This, UiSize *value);
    HRESULT (STDMETHODCALLTYPE *get_MessageDuration)(IUISettingsX *This, UINT32 *value);
    HRESULT (STDMETHODCALLTYPE *get_AnimationsEnabled)(IUISettingsX *This, BOOLEAN *value);
    HRESULT (STDMETHODCALLTYPE *get_CaretBrowsingEnabled)(IUISettingsX *This, BOOLEAN *value);
    HRESULT (STDMETHODCALLTYPE *get_CaretBlinkRate)(IUISettingsX *This, UINT32 *value);
    HRESULT (STDMETHODCALLTYPE *get_CaretWidth)(IUISettingsX *This, UINT32 *value);
    HRESULT (STDMETHODCALLTYPE *get_DoubleClickTime)(IUISettingsX *This, UINT32 *value);
    HRESULT (STDMETHODCALLTYPE *get_MouseHoverTime)(IUISettingsX *This, UINT32 *value);
    HRESULT (STDMETHODCALLTYPE *UIElementColor)(IUISettingsX *This, INT32 element, UiColor *value);
} IUISettingsVtbl;
typedef struct { BASE_METHODS(IUISettingsX)
    HRESULT (STDMETHODCALLTYPE *get_TextScaleFactor)(IUISettingsX *This, double *value);
    HRESULT (STDMETHODCALLTYPE *add_TextScaleFactorChanged)(IUISettingsX *This, void *handler, INT64 *token);
    HRESULT (STDMETHODCALLTYPE *remove_TextScaleFactorChanged)(IUISettingsX *This, INT64 token);
} IUISettings2Vtbl;
typedef struct { BASE_METHODS(IUISettingsX)
    HRESULT (STDMETHODCALLTYPE *GetColorValue)(IUISettingsX *This, INT32 color, UiColor *value);
    HRESULT (STDMETHODCALLTYPE *add_ColorValuesChanged)(IUISettingsX *This, void *handler, INT64 *token);
    HRESULT (STDMETHODCALLTYPE *remove_ColorValuesChanged)(IUISettingsX *This, INT64 token);
} IUISettings3Vtbl;
typedef struct { BASE_METHODS(IUISettingsX)
    HRESULT (STDMETHODCALLTYPE *get_AdvancedEffectsEnabled)(IUISettingsX *This, BOOLEAN *value);
    HRESULT (STDMETHODCALLTYPE *add_AdvancedEffectsEnabledChanged)(IUISettingsX *This, void *handler, INT64 *token);
    HRESULT (STDMETHODCALLTYPE *remove_AdvancedEffectsEnabledChanged)(IUISettingsX *This, INT64 token);
} IUISettings4Vtbl;
typedef struct { BASE_METHODS(IUISettingsX)
    HRESULT (STDMETHODCALLTYPE *get_AutoHideScrollBars)(IUISettingsX *This, BOOLEAN *value);
    HRESULT (STDMETHODCALLTYPE *add_AutoHideScrollBarsChanged)(IUISettingsX *This, void *handler, INT64 *token);
    HRESULT (STDMETHODCALLTYPE *remove_AutoHideScrollBarsChanged)(IUISettingsX *This, INT64 token);
} IUISettings5Vtbl;
typedef struct { BASE_METHODS(IUISettingsX)
    HRESULT (STDMETHODCALLTYPE *add_AnimationsEnabledChanged)(IUISettingsX *This, void *handler, INT64 *token);
    HRESULT (STDMETHODCALLTYPE *remove_AnimationsEnabledChanged)(IUISettingsX *This, INT64 token);
    HRESULT (STDMETHODCALLTYPE *add_MessageDurationChanged)(IUISettingsX *This, void *handler, INT64 *token);
    HRESULT (STDMETHODCALLTYPE *remove_MessageDurationChanged)(IUISettingsX *This, INT64 token);
} IUISettings6Vtbl;

struct IUISettingsX { const void *lpVtbl; UISettings *obj; };

struct UISettings
{
    IUISettingsX i1, i2, i3, i4, i5, i6;
    LONG ref;
    INT64 next_token;
};

#define OBJ(This) ((This)->obj)

static HRESULT query_interface(UISettings *obj, REFIID iid, void **out)
{
    if (!out)
        return E_POINTER;
    *out = NULL;
    if (IsEqualGUID(iid, &IID_IUnknown) || IsEqualGUID(iid, &IID_IInspectable) ||
        IsEqualGUID(iid, &IID_IAgileObject) || IsEqualGUID(iid, &IID_IUISettings))
        *out = &obj->i1;
    else if (IsEqualGUID(iid, &IID_IUISettings2))
        *out = &obj->i2;
    else if (IsEqualGUID(iid, &IID_IUISettings3))
        *out = &obj->i3;
    else if (IsEqualGUID(iid, &IID_IUISettings4))
        *out = &obj->i4;
    else if (IsEqualGUID(iid, &IID_IUISettings5))
        *out = &obj->i5;
    else if (IsEqualGUID(iid, &IID_IUISettings6))
        *out = &obj->i6;
    else
        return E_NOINTERFACE;
    InterlockedIncrement(&obj->ref);
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE ui_QueryInterface(IUISettingsX *This, REFIID iid, void **out)
{
    return query_interface(OBJ(This), iid, out);
}

static ULONG STDMETHODCALLTYPE ui_AddRef(IUISettingsX *This)
{
    return InterlockedIncrement(&OBJ(This)->ref);
}

static ULONG STDMETHODCALLTYPE ui_Release(IUISettingsX *This)
{
    UISettings *obj = OBJ(This);
    ULONG ref = InterlockedDecrement(&obj->ref);

    if (!ref)
        HeapFree(GetProcessHeap(), 0, obj);
    return ref;
}

static HRESULT STDMETHODCALLTYPE ui_GetIids(IUISettingsX *This, ULONG *count, IID **iids)
{
    static const GUID *list[] = { &IID_IUISettings, &IID_IUISettings2, &IID_IUISettings3,
                                  &IID_IUISettings4, &IID_IUISettings5, &IID_IUISettings6 };
    IID *copy = CoTaskMemAlloc(ARRAYSIZE(list) * sizeof(IID));
    ULONG i;

    if (!copy)
        return E_OUTOFMEMORY;
    for (i = 0; i < ARRAYSIZE(list); i++)
        copy[i] = *list[i];
    *count = ARRAYSIZE(list);
    *iids = copy;
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE ui_GetRuntimeClassName(IUISettingsX *This, HSTRING *name)
{
    return WindowsCreateString(class_name, ARRAYSIZE(class_name) - 1, name);
}

static HRESULT STDMETHODCALLTYPE ui_GetTrustLevel(IUISettingsX *This, TrustLevel *level)
{
    *level = BaseTrust;
    return S_OK;
}

#define BASE_ENTRIES ui_QueryInterface, ui_AddRef, ui_Release, ui_GetIids, ui_GetRuntimeClassName, ui_GetTrustLevel

static HRESULT get_uint(UINT32 *value, UINT32 v)
{
    if (!value) return E_POINTER;
    *value = v;
    return S_OK;
}

static HRESULT get_size(UiSize *value, float v)
{
    if (!value) return E_POINTER;
    value->Width = value->Height = v;
    return S_OK;
}

static HRESULT get_bool(BOOLEAN *value, BOOLEAN v)
{
    if (!value) return E_POINTER;
    *value = v;
    return S_OK;
}

/* Handlers are accepted and never called: the settings do not change while a process runs */
static HRESULT add_handler(UISettings *obj, void *handler, INT64 *token)
{
    if (!handler)
        return E_INVALIDARG;
    if (!token)
        return E_POINTER;
    *token = ++obj->next_token;
    return S_OK;
}

static UiColor make_color(UINT8 r, UINT8 g, UINT8 b)
{
    UiColor c;
    c.A = 255; c.R = r; c.G = g; c.B = b;
    return c;
}

static BOOL read_dword(HKEY root, const WCHAR *path, const WCHAR *name, DWORD *value)
{
    DWORD size = sizeof(*value), type;
    HKEY key;
    LONG ret;

    if (RegOpenKeyExW(root, path, 0, KEY_READ, &key))
        return FALSE;
    ret = RegQueryValueExW(key, name, NULL, &type, (BYTE *)value, &size);
    RegCloseKey(key);
    return !ret && type == REG_DWORD && size == sizeof(*value);
}

/* Apps use the light theme unless the user turned it off */
static BOOL apps_use_light_theme(void)
{
    DWORD value;

    if (read_dword(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize",
                   L"AppsUseLightTheme", &value))
        return value != 0;
    return TRUE;
}

/* The accent colour is stored as 0xAABBGGRR; the Windows default blue is 0078D7 */
static UiColor accent_color(void)
{
    DWORD value;

    if (read_dword(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\DWM", L"AccentColor", &value))
        return make_color(value & 0xff, (value >> 8) & 0xff, (value >> 16) & 0xff);
    return make_color(0x00, 0x78, 0xd7);
}

static UINT8 scale_dark(UINT8 c, int percent) { return (UINT8)(c * percent / 100); }
static UINT8 scale_light(UINT8 c, int percent) { return (UINT8)(c + (255 - c) * percent / 100); }

static UiColor color_value(INT32 type)
{
    UiColor a = accent_color();
    BOOL light = apps_use_light_theme();

    switch (type)
    {
    case UIColorType_Background: return light ? make_color(255, 255, 255) : make_color(0, 0, 0);
    case UIColorType_Foreground: return light ? make_color(0, 0, 0) : make_color(255, 255, 255);
    case UIColorType_AccentDark3: return make_color(scale_dark(a.R, 55), scale_dark(a.G, 55), scale_dark(a.B, 55));
    case UIColorType_AccentDark2: return make_color(scale_dark(a.R, 75), scale_dark(a.G, 75), scale_dark(a.B, 75));
    case UIColorType_AccentDark1: return make_color(scale_dark(a.R, 89), scale_dark(a.G, 89), scale_dark(a.B, 89));
    case UIColorType_Accent: return a;
    case UIColorType_AccentLight1: return make_color(scale_light(a.R, 27), scale_light(a.G, 27), scale_light(a.B, 27));
    case UIColorType_AccentLight2: return make_color(scale_light(a.R, 47), scale_light(a.G, 47), scale_light(a.B, 47));
    case UIColorType_AccentLight3: return make_color(scale_light(a.R, 70), scale_light(a.G, 70), scale_light(a.B, 70));
    default: return make_color(0, 0, 0);
    }
}

static UiColor sys_color(int index)
{
    DWORD c = GetSysColor(index);
    return make_color(GetRValue(c), GetGValue(c), GetBValue(c));
}

/* IUISettings */
static HRESULT STDMETHODCALLTYPE ui1_get_HandPreference(IUISettingsX *This, INT32 *value)
{
    if (!value) return E_POINTER;
    *value = GetSystemMetrics(SM_MENUDROPALIGNMENT) ? 0 /* LeftHanded */ : 1 /* RightHanded */;
    return S_OK;
}
static HRESULT STDMETHODCALLTYPE ui1_get_CursorSize(IUISettingsX *This, UiSize *value) { return get_size(value, 32.0f); }
static HRESULT STDMETHODCALLTYPE ui1_get_ScrollBarSize(IUISettingsX *This, UiSize *value) { return get_size(value, (float)GetSystemMetrics(SM_CXVSCROLL)); }
static HRESULT STDMETHODCALLTYPE ui1_get_ScrollBarArrowSize(IUISettingsX *This, UiSize *value) { return get_size(value, (float)GetSystemMetrics(SM_CXVSCROLL)); }
static HRESULT STDMETHODCALLTYPE ui1_get_ScrollBarThumbBoxSize(IUISettingsX *This, UiSize *value) { return get_size(value, (float)GetSystemMetrics(SM_CXVSCROLL)); }
static HRESULT STDMETHODCALLTYPE ui1_get_MessageDuration(IUISettingsX *This, UINT32 *value) { return get_uint(value, 5); }
static HRESULT STDMETHODCALLTYPE ui1_get_AnimationsEnabled(IUISettingsX *This, BOOLEAN *value) { return get_bool(value, TRUE); }
static HRESULT STDMETHODCALLTYPE ui1_get_CaretBrowsingEnabled(IUISettingsX *This, BOOLEAN *value) { return get_bool(value, FALSE); }
static HRESULT STDMETHODCALLTYPE ui1_get_CaretBlinkRate(IUISettingsX *This, UINT32 *value) { return get_uint(value, GetCaretBlinkTime()); }
static HRESULT STDMETHODCALLTYPE ui1_get_CaretWidth(IUISettingsX *This, UINT32 *value) { return get_uint(value, 1); }
static HRESULT STDMETHODCALLTYPE ui1_get_DoubleClickTime(IUISettingsX *This, UINT32 *value) { return get_uint(value, GetDoubleClickTime()); }
static HRESULT STDMETHODCALLTYPE ui1_get_MouseHoverTime(IUISettingsX *This, UINT32 *value) { return get_uint(value, 400); }

/* Windows.UI.ViewManagement.UIElementType 0..12 are the classic system colours */
static HRESULT STDMETHODCALLTYPE ui1_UIElementColor(IUISettingsX *This, INT32 element, UiColor *value)
{
    static const int map[] = { COLOR_ACTIVECAPTION, COLOR_BACKGROUND, COLOR_BTNFACE, COLOR_BTNTEXT,
                               COLOR_CAPTIONTEXT, COLOR_GRAYTEXT, COLOR_HIGHLIGHT, COLOR_HIGHLIGHTTEXT,
                               COLOR_HOTLIGHT, COLOR_INACTIVECAPTION, COLOR_INACTIVECAPTIONTEXT,
                               COLOR_WINDOW, COLOR_WINDOWTEXT };

    if (!value)
        return E_POINTER;
    if (element < 0 || element >= (INT32)ARRAYSIZE(map))
        return E_INVALIDARG;
    *value = sys_color(map[element]);
    return S_OK;
}

static const IUISettingsVtbl vtbl1 =
{
    BASE_ENTRIES,
    ui1_get_HandPreference, ui1_get_CursorSize, ui1_get_ScrollBarSize, ui1_get_ScrollBarArrowSize,
    ui1_get_ScrollBarThumbBoxSize, ui1_get_MessageDuration, ui1_get_AnimationsEnabled,
    ui1_get_CaretBrowsingEnabled, ui1_get_CaretBlinkRate, ui1_get_CaretWidth, ui1_get_DoubleClickTime,
    ui1_get_MouseHoverTime, ui1_UIElementColor,
};

/* IUISettings2 */
static HRESULT STDMETHODCALLTYPE ui2_get_TextScaleFactor(IUISettingsX *This, double *value)
{
    if (!value) return E_POINTER;
    *value = 1.0;
    return S_OK;
}
static HRESULT STDMETHODCALLTYPE ui2_add(IUISettingsX *This, void *handler, INT64 *token) { return add_handler(OBJ(This), handler, token); }
static HRESULT STDMETHODCALLTYPE ui_remove(IUISettingsX *This, INT64 token) { return S_OK; }

static const IUISettings2Vtbl vtbl2 = { BASE_ENTRIES, ui2_get_TextScaleFactor, ui2_add, ui_remove };

/* IUISettings3 */
static HRESULT STDMETHODCALLTYPE ui3_GetColorValue(IUISettingsX *This, INT32 color, UiColor *value)
{
    if (!value)
        return E_POINTER;
    if (color < UIColorType_Background || color > UIColorType_Complement)
        return E_INVALIDARG;
    *value = color_value(color);
    return S_OK;
}

static const IUISettings3Vtbl vtbl3 = { BASE_ENTRIES, ui3_GetColorValue, ui2_add, ui_remove };

/* IUISettings4 */
static HRESULT STDMETHODCALLTYPE ui4_get_AdvancedEffectsEnabled(IUISettingsX *This, BOOLEAN *value) { return get_bool(value, TRUE); }

static const IUISettings4Vtbl vtbl4 = { BASE_ENTRIES, ui4_get_AdvancedEffectsEnabled, ui2_add, ui_remove };

/* IUISettings5 */
static HRESULT STDMETHODCALLTYPE ui5_get_AutoHideScrollBars(IUISettingsX *This, BOOLEAN *value) { return get_bool(value, TRUE); }

static const IUISettings5Vtbl vtbl5 = { BASE_ENTRIES, ui5_get_AutoHideScrollBars, ui2_add, ui_remove };

/* IUISettings6 */
static const IUISettings6Vtbl vtbl6 = { BASE_ENTRIES, ui2_add, ui_remove, ui2_add, ui_remove };

static HRESULT create_settings(IInspectable **instance)
{
    UISettings *obj = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*obj));

    if (!obj)
        return E_OUTOFMEMORY;
    obj->i1.lpVtbl = &vtbl1; obj->i1.obj = obj;
    obj->i2.lpVtbl = &vtbl2; obj->i2.obj = obj;
    obj->i3.lpVtbl = &vtbl3; obj->i3.obj = obj;
    obj->i4.lpVtbl = &vtbl4; obj->i4.obj = obj;
    obj->i5.lpVtbl = &vtbl5; obj->i5.obj = obj;
    obj->i6.lpVtbl = &vtbl6; obj->i6.obj = obj;
    obj->ref = 1;
    *instance = (IInspectable *)&obj->i1;
    return S_OK;
}

/* The activation factory: one static object that lives as long as the DLL */
static struct
{
    IActivationFactory IActivationFactory_iface;
    LONG ref;
} factory;

static HRESULT STDMETHODCALLTYPE factory_QueryInterface(IActivationFactory *This, REFIID iid, void **out)
{
    if (!out)
        return E_POINTER;
    if (IsEqualGUID(iid, &IID_IUnknown) || IsEqualGUID(iid, &IID_IInspectable) ||
        IsEqualGUID(iid, &IID_IAgileObject) || IsEqualGUID(iid, &IID_IActivationFactory))
    {
        *out = This;
        InterlockedIncrement(&factory.ref);
        return S_OK;
    }
    *out = NULL;
    return E_NOINTERFACE;
}

static ULONG STDMETHODCALLTYPE factory_AddRef(IActivationFactory *This) { return InterlockedIncrement(&factory.ref); }
static ULONG STDMETHODCALLTYPE factory_Release(IActivationFactory *This) { return InterlockedDecrement(&factory.ref); }

static HRESULT STDMETHODCALLTYPE factory_GetIids(IActivationFactory *This, ULONG *count, IID **iids)
{
    IID *list = CoTaskMemAlloc(sizeof(IID));

    if (!list)
        return E_OUTOFMEMORY;
    list[0] = IID_IActivationFactory;
    *count = 1;
    *iids = list;
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE factory_GetRuntimeClassName(IActivationFactory *This, HSTRING *name)
{
    return WindowsCreateString(class_name, ARRAYSIZE(class_name) - 1, name);
}

static HRESULT STDMETHODCALLTYPE factory_GetTrustLevel(IActivationFactory *This, TrustLevel *level)
{
    *level = BaseTrust;
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE factory_ActivateInstance(IActivationFactory *This, IInspectable **instance)
{
    TRACE("(%p)\n", instance);
    if (!instance)
        return E_POINTER;
    return create_settings(instance);
}

static const IActivationFactoryVtbl factory_vtbl =
{
    factory_QueryInterface, factory_AddRef, factory_Release, factory_GetIids,
    factory_GetRuntimeClassName, factory_GetTrustLevel, factory_ActivateInstance,
};

HRESULT WINAPI DllGetActivationFactory(HSTRING classid, IActivationFactory **out)
{
    LPCWSTR name = WindowsGetStringRawBuffer(classid, NULL);

    TRACE("(%p, %p)\n", classid, out);

    if (!out)
        return E_POINTER;
    *out = NULL;

    if (!name || _wcsicmp(name, class_name) != 0)
        return CLASS_E_CLASSNOTAVAILABLE;

    *out = &factory.IActivationFactory_iface;
    InterlockedIncrement(&factory.ref);
    return S_OK;
}

/* Objects hold code from this DLL: stay loaded */
HRESULT WINAPI DllCanUnloadNow(void)
{
    return S_FALSE;
}

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, void *reserved)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(instance);
        factory.IActivationFactory_iface.lpVtbl = (IActivationFactoryVtbl *)&factory_vtbl;
        factory.ref = 1;
    }
    return TRUE;
}
