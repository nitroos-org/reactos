/*
 * PROJECT:     shell32
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     IFileOperation implementation
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#ifndef _CFILEOPERATION_H_
#define _CFILEOPERATION_H_

class CFileOperation :
    public CComCoClass<CFileOperation, &CLSID_FileOperation>,
    public CComObjectRootEx<CComMultiThreadModelNoCS>,
    public IFileOperation
{
public:
    enum OP_TYPE { OP_RENAME, OP_MOVE, OP_COPY, OP_DELETE, OP_NEW };

    struct OPERATION
    {
        OP_TYPE type;
        CComPtr<IShellItem> psiItem;        // source item; NULL for OP_NEW
        CComPtr<IShellItem> psiFolder;      // destination folder; NULL for rename and delete
        CStringW strName;                   // new name, copy name or the name of the new item
        CStringW strTemplate;               // OP_NEW: template file
        DWORD dwAttributes;                 // OP_NEW
        CComPtr<IFileOperationProgressSink> pSink; // per item sink
    };

    CFileOperation();
    ~CFileOperation();

    // *** IFileOperation methods ***
    STDMETHOD(Advise)(IFileOperationProgressSink *pfops, DWORD *pdwCookie) override;
    STDMETHOD(Unadvise)(DWORD dwCookie) override;
    STDMETHOD(SetOperationFlags)(DWORD dwOperationFlags) override;
    STDMETHOD(SetProgressMessage)(LPCWSTR pszMessage) override;
    STDMETHOD(SetProgressDialog)(IOperationsProgressDialog *popd) override;
    STDMETHOD(SetProperties)(IPropertyChangeArray *pproparray) override;
    STDMETHOD(SetOwnerWindow)(HWND hwndOwner) override;
    STDMETHOD(ApplyPropertiesToItem)(IShellItem *psiItem) override;
    STDMETHOD(ApplyPropertiesToItems)(IUnknown *punkItems) override;
    STDMETHOD(RenameItem)(IShellItem *psiItem, LPCWSTR pszNewName, IFileOperationProgressSink *pfopsItem) override;
    STDMETHOD(RenameItems)(IUnknown *pUnkItems, LPCWSTR pszNewName) override;
    STDMETHOD(MoveItem)(IShellItem *psiItem, IShellItem *psiDestinationFolder, LPCWSTR pszNewName,
                        IFileOperationProgressSink *pfopsItem) override;
    STDMETHOD(MoveItems)(IUnknown *punkItems, IShellItem *psiDestinationFolder) override;
    STDMETHOD(CopyItem)(IShellItem *psiItem, IShellItem *psiDestinationFolder, LPCWSTR pszCopyName,
                        IFileOperationProgressSink *pfopsItem) override;
    STDMETHOD(CopyItems)(IUnknown *punkItems, IShellItem *psiDestinationFolder) override;
    STDMETHOD(DeleteItem)(IShellItem *psiItem, IFileOperationProgressSink *pfopsItem) override;
    STDMETHOD(DeleteItems)(IUnknown *punkItems) override;
    STDMETHOD(NewItem)(IShellItem *psiDestinationFolder, DWORD dwFileAttributes, LPCWSTR pszName,
                       LPCWSTR pszTemplateName, IFileOperationProgressSink *pfopsItem) override;
    STDMETHOD(PerformOperations)() override;
    STDMETHOD(GetAnyOperationsAborted)(BOOL *pfAnyOperationsAborted) override;

DECLARE_REGISTRY_RESOURCEID(IDR_FILEOPERATION)
DECLARE_NOT_AGGREGATABLE(CFileOperation)
DECLARE_PROTECT_FINAL_CONSTRUCT()

BEGIN_COM_MAP(CFileOperation)
    COM_INTERFACE_ENTRY_IID(IID_IFileOperation, IFileOperation)
END_COM_MAP()

private:
    HRESULT QueueItems(OP_TYPE type, IUnknown *punkItems, IShellItem *psiFolder, LPCWSTR pszName);
    HRESULT Queue(OP_TYPE type, IShellItem *psiItem, IShellItem *psiFolder, LPCWSTR pszName,
                  IFileOperationProgressSink *pSink, DWORD dwAttributes = 0, LPCWSTR pszTemplate = NULL);
    HRESULT RunOne(OPERATION &op);
    DWORD GetTransferFlags(OP_TYPE type) const;
    void ClearOps();

    DWORD m_dwFlags;
    HWND m_hwndOwner;
    BOOL m_bAborted;
    DWORD m_dwNextCookie;
    CAtlList<OPERATION *> m_Ops;
    struct SINK { DWORD dwCookie; CComPtr<IFileOperationProgressSink> pSink; };
    CAtlList<SINK> m_Sinks;
};

#endif // _CFILEOPERATION_H_
