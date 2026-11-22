/*
 * FolderItemVerb(s) implementation
 *
 * Copyright 2015 Mark Jansen
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

#include "precomp.h"

WINE_DEFAULT_DEBUG_CHANNEL(shell);


CFolderItemVerb::CFolderItemVerb()
{
}

CFolderItemVerb::~CFolderItemVerb()
{
}

void CFolderItemVerb::Init(IContextMenu* menu, BSTR name)
{
    m_contextmenu = menu;
    m_name.m_str = name;
}

// *** FolderItemVerb methods ***

HRESULT STDMETHODCALLTYPE CFolderItemVerb::get_Application(IDispatch **ppid)
{
    TRACE("(%p, %p)\n", this, ppid);

    if (ppid)
        *ppid = NULL;

    return E_NOTIMPL;
}

HRESULT STDMETHODCALLTYPE CFolderItemVerb::get_Parent(IDispatch **ppid)
{
    TRACE("(%p, %p)\n", this, ppid);

    if (ppid)
        *ppid = NULL;

    return E_NOTIMPL;
}

HRESULT STDMETHODCALLTYPE CFolderItemVerb::get_Name(BSTR *pbs)
{
    if (!pbs)
        return E_POINTER;
    *pbs = SysAllocString(m_name);
    return S_OK;
}

HRESULT STDMETHODCALLTYPE CFolderItemVerb::DoIt()
{
    TRACE("(%p, %p)\n", this);
    return E_NOTIMPL;
}






CFolderItemVerbs::CFolderItemVerbs()
    :m_menu(NULL)
    ,m_count(0)
{
}

CFolderItemVerbs::~CFolderItemVerbs()
{
    DestroyMenu(m_menu);
}

HRESULT CFolderItemVerbs::Init(IContextMenu &cm)
{
    m_contextmenu = &cm;
    m_menu = CreatePopupMenu();
    HRESULT hr = m_contextmenu->QueryContextMenu(m_menu, 0, FCIDM_SHVIEWFIRST, FCIDM_SHVIEWLAST, CMF_NORMAL);
    if (FAILED(hr))
        return hr;

    m_count = GetMenuItemCount(m_menu);
    return hr;
}

HRESULT CFolderItemVerbs::Init(LPCITEMIDLIST idlist)
{
    CComPtr<IContextMenu> pCM;
    HRESULT hr = SHELL_GetUIObjectOfAbsoluteItem(NULL, idlist, IID_PPV_ARG(IContextMenu, &pCM));
    if (FAILED_UNEXPECTEDLY(hr))
        return hr;
    return Init(*static_cast<IContextMenu*>(pCM));
}


// *** FolderItemVerbs methods ***
HRESULT STDMETHODCALLTYPE CFolderItemVerbs::get_Count(LONG *plCount)
{
    if (!plCount)
        return E_INVALIDARG;
    *plCount = m_count;
    return S_OK;
}

HRESULT STDMETHODCALLTYPE CFolderItemVerbs::get_Application(IDispatch **ppid)
{
    TRACE("(%p, %p)\n", this, ppid);

    if (ppid)
        *ppid = NULL;

    return E_NOTIMPL;
}

HRESULT STDMETHODCALLTYPE CFolderItemVerbs::get_Parent(IDispatch **ppid)
{
    TRACE("(%p, %p)\n", this, ppid);

    if (ppid)
        *ppid = NULL;

    return E_NOTIMPL;
}

HRESULT STDMETHODCALLTYPE CFolderItemVerbs::Item(VARIANT indexVar, FolderItemVerb **ppid)
{
    if (!ppid)
        return E_POINTER;

    CComVariant var;

    HRESULT hr = VariantChangeType(&var, &indexVar, 0, VT_I4);
    if (FAILED_UNEXPECTEDLY(hr))
        return E_INVALIDARG;

    int index = V_I4(&var);
    if (index > m_count)
        return S_FALSE;

    BSTR name = NULL;
    if (index == m_count)
    {
        name = SysAllocStringLen(NULL, 0);
    }
    else
    {
        MENUITEMINFOW info = { sizeof(info), 0 };
        info.fMask = MIIM_STRING;
        if (!GetMenuItemInfoW(m_menu, index, TRUE, &info))
            return E_FAIL;
        name = SysAllocStringLen(NULL, info.cch);
        if (name)
        {
            info.dwTypeData = name;
            info.cch++;
            GetMenuItemInfoW(m_menu, index, TRUE, &info);
        }
    }

    if (!name)
        return E_OUTOFMEMORY;

    CFolderItemVerb* verb = new CComObject<CFolderItemVerb>();
    verb->Init(m_contextmenu, name);
    verb->AddRef();
    *ppid = verb;

    return S_OK;
}

HRESULT STDMETHODCALLTYPE CFolderItemVerbs::_NewEnum(IUnknown **ppunk)
{
    TRACE("(%p, %p)\n", this, ppunk);
    if (!ppunk)
        return E_POINTER;
    *ppunk = NULL;
    return ShellObjectCreatorInit<CFolderItemVerbsEnum>(this, IID_PPV_ARG(IUnknown, ppunk));
}


CFolderItemVerbsEnum::CFolderItemVerbsEnum() : m_Verbs(NULL), m_Pos(0)
{
}

CFolderItemVerbsEnum::~CFolderItemVerbsEnum()
{
}

HRESULT CFolderItemVerbsEnum::Initialize(CFolderItemVerbs *verbs)
{
    m_Keep = static_cast<IDispatch*>(verbs);
    m_Verbs = verbs;
    m_Pos = 0;
    return S_OK;
}

HRESULT STDMETHODCALLTYPE CFolderItemVerbsEnum::Next(ULONG celt, VARIANT *rgVar, ULONG *pCeltFetched)
{
    ULONG fetched = 0;
    HRESULT hr = S_OK;

    if (pCeltFetched)
        *pCeltFetched = 0;
    if (!rgVar)
        return E_POINTER;
    if (!pCeltFetched && celt != 1)
        return E_INVALIDARG;

    for (ULONG i = 0; i < celt; i++)
        VariantInit(&rgVar[i]);

    while (fetched < celt && m_Pos < m_Verbs->GetCount())
    {
        CComVariant index(m_Pos);
        CComPtr<FolderItemVerb> verb;

        hr = m_Verbs->Item(index, &verb);
        if (hr != S_OK)
        {
            hr = FAILED(hr) ? hr : E_FAIL;
            break;
        }
        V_VT(&rgVar[fetched]) = VT_DISPATCH;
        hr = verb->QueryInterface(IID_PPV_ARG(IDispatch, &V_DISPATCH(&rgVar[fetched])));
        if (FAILED(hr))
        {
            V_VT(&rgVar[fetched]) = VT_EMPTY;
            break;
        }
        fetched++;
        m_Pos++;
    }

    if (FAILED(hr))
    {
        for (ULONG i = 0; i < fetched; i++)
            VariantClear(&rgVar[i]);
        m_Pos -= fetched;
        fetched = 0;
    }
    if (pCeltFetched)
        *pCeltFetched = fetched;
    return FAILED(hr) ? hr : (fetched == celt ? S_OK : S_FALSE);
}

HRESULT STDMETHODCALLTYPE CFolderItemVerbsEnum::Skip(ULONG celt)
{
    LONG count = m_Verbs->GetCount();

    if ((ULONGLONG)m_Pos + celt > (ULONGLONG)count)
    {
        m_Pos = count;
        return S_FALSE;
    }
    m_Pos += celt;
    return S_OK;
}

HRESULT STDMETHODCALLTYPE CFolderItemVerbsEnum::Reset()
{
    m_Pos = 0;
    return S_OK;
}

HRESULT STDMETHODCALLTYPE CFolderItemVerbsEnum::Clone(IEnumVARIANT **ppEnum)
{
    if (!ppEnum)
        return E_POINTER;
    *ppEnum = NULL;

    CComPtr<IUnknown> unk;
    HRESULT hr = ShellObjectCreatorInit<CFolderItemVerbsEnum>(m_Verbs, IID_PPV_ARG(IUnknown, &unk));
    if (FAILED(hr))
        return hr;
    hr = unk->QueryInterface(IID_PPV_ARG(IEnumVARIANT, ppEnum));
    if (SUCCEEDED(hr))
        (*ppEnum)->Skip(m_Pos);     // the clone continues at the same position
    return hr;
}


