/*
 * PROJECT:     shell32
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     CLSID_KnownFolderManager class registration (the implementation is in wine/shellpath.c)
 */

#ifndef _CKNOWNFOLDERMANAGER_H_
#define _CKNOWNFOLDERMANAGER_H_

extern "C" HRESULT WINAPI KnownFolderManager_Constructor(IUnknown *punk, REFIID riid, void **ppv);

/* An ATL object map entry for the Wine IKnownFolderManager object: the class factory is the stock one,
 * the creator forwards to the Wine constructor */
class CKnownFolderManager :
    public CComCoClass<CKnownFolderManager, &CLSID_KnownFolderManager>,
    public CComObjectRootEx<CComMultiThreadModelNoCS>
{
public:
    struct _CreatorClass
    {
        static HRESULT WINAPI CreateInstance(void *pv, REFIID riid, LPVOID *ppv)
        {
            return KnownFolderManager_Constructor(static_cast<IUnknown *>(pv), riid, ppv);
        }
    };

    DECLARE_REGISTRY_RESOURCEID(IDR_KNOWNFOLDERMANAGER)
};

#endif // _CKNOWNFOLDERMANAGER_H_
