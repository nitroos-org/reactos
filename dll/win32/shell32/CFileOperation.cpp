/*
 * PROJECT:     shell32
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     IFileOperation implementation
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Operations are queued by RenameItem, MoveItem, CopyItem, DeleteItem and NewItem and run in order by
 * PerformOperations, which calls the progress sinks around each one. The file system work is done by the
 * Win32 and SHFileOperation code paths shell32 already has; there is no progress dialog.
 */

#include "precomp.h"

WINE_DEFAULT_DEBUG_CHANNEL(shell);


// Transfer flags (TSF_*) the sinks see; the values were measured on Windows 10 with FOF_NO_UI
#define TSF_RENAME_EXIST         0x1
#define TSF_OVERWRITE_EXIST      0x2
#define TSF_NO_SECURITY          0x8
#define TSF_COPY_CREATION_TIME   0x10
#define TSF_COPY_WRITE_TIME      0x20
#define TSF_COPY_LOCALIZED_NAME  0x200
// Result of an operation that finished without processing child items (a rename, or a move or delete in place)
#define COPYENGINE_S_DONT_PROCESS_CHILDREN 0x00270008

// Returns the file system path of an item
static HRESULT GetItemPath(IShellItem *psi, CStringW &strPath)
{
    LPWSTR pszName = NULL;
    HRESULT hr = psi->GetDisplayName(SIGDN_FILESYSPATH, &pszName);
    if (FAILED(hr))
        return hr;
    strPath = pszName;
    CoTaskMemFree(pszName);
    return S_OK;
}

// Joins a folder path and a name
static CStringW JoinPath(const CStringW &strFolder, const CStringW &strName)
{
    CStringW str = strFolder;
    if (!str.IsEmpty() && str[str.GetLength() - 1] != L'\\')
        str += L'\\';
    return str + strName;
}

static CStringW FileName(const CStringW &strPath)
{
    LPCWSTR psz = PathFindFileNameW(strPath);
    return psz;
}

// A source that is gone fails with the Win32 error, which SHFileOperation does not report
static HRESULT CheckSource(const CStringW &strSrc)
{
    if (GetFileAttributesW(strSrc) == INVALID_FILE_ATTRIBUTES)
        return HRESULT_FROM_WIN32(GetLastError());
    return S_OK;
}

// SHFileOperation takes double null terminated lists
static HRESULT ShellOp(UINT wFunc, const CStringW &strFrom, const CStringW *pstrTo, DWORD dwFlags, HWND hwnd)
{
    CAtlArray<WCHAR> From, To;
    From.SetCount(strFrom.GetLength() + 2);
    CopyMemory(From.GetData(), (LPCWSTR)strFrom, strFrom.GetLength() * sizeof(WCHAR));
    From[strFrom.GetLength()] = From[strFrom.GetLength() + 1] = L'\0';
    SHFILEOPSTRUCTW op = { 0 };
    op.hwnd = hwnd;
    op.wFunc = wFunc;
    op.pFrom = From.GetData();
    if (pstrTo)
    {
        To.SetCount(pstrTo->GetLength() + 2);
        CopyMemory(To.GetData(), (LPCWSTR)*pstrTo, pstrTo->GetLength() * sizeof(WCHAR));
        To[pstrTo->GetLength()] = To[pstrTo->GetLength() + 1] = L'\0';
        op.pTo = To.GetData();
    }
    op.fFlags = (FILEOP_FLAGS)(dwFlags & 0xFFFF) & ~FOF_MULTIDESTFILES;
    int nError = SHFileOperationW(&op);
    if (nError)
    {
        // DE_ errors are not Win32 errors, except those in the Win32 range
        switch (nError)
        {
            case DE_SAMEFILE: case DE_DESTSAMETREE:
                return HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS);
            case DE_OPCANCELLED:
                return HRESULT_FROM_WIN32(ERROR_CANCELLED);
            case DE_ACCESSDENIEDSRC:
                return E_ACCESSDENIED;
            case DE_PATHTOODEEP: case DE_FILENAMETOOLONG:
                return HRESULT_FROM_WIN32(ERROR_FILENAME_EXCED_RANGE);
            case DE_FILEDESTISFLD: case DE_DESTSUBTREE:
                return HRESULT_FROM_WIN32(ERROR_INVALID_PARAMETER);
            default:
                return HRESULT_FROM_WIN32(nError < 0x7C || nError > 0xFFFF ? ERROR_GEN_FAILURE : nError);
        }
    }
    if (op.fAnyOperationsAborted)
        return HRESULT_FROM_WIN32(ERROR_CANCELLED);
    return S_OK;
}

CFileOperation::CFileOperation()
    : m_dwFlags(0)
    , m_hwndOwner(NULL)
    , m_bAborted(FALSE)
    , m_dwNextCookie(1)
{
}

CFileOperation::~CFileOperation()
{
    ClearOps();
}

void CFileOperation::ClearOps()
{
    while (!m_Ops.IsEmpty())
        delete m_Ops.RemoveHead();
}

STDMETHODIMP CFileOperation::Advise(IFileOperationProgressSink *pfops, DWORD *pdwCookie)
{
    if (!pfops || !pdwCookie)
        return E_INVALIDARG;
    SINK s;
    s.dwCookie = m_dwNextCookie++;
    s.pSink = pfops;
    m_Sinks.AddTail(s);
    *pdwCookie = s.dwCookie;
    return S_OK;
}

STDMETHODIMP CFileOperation::Unadvise(DWORD dwCookie)
{
    // A cookie that was handed out is accepted again after its sink is gone
    if (dwCookie == 0 || dwCookie >= m_dwNextCookie)
        return E_INVALIDARG;
    for (POSITION pos = m_Sinks.GetHeadPosition(); pos;)
    {
        POSITION posThis = pos;
        if (m_Sinks.GetNext(pos).dwCookie == dwCookie)
        {
            m_Sinks.RemoveAt(posThis);
            break;
        }
    }
    return S_OK;
}

STDMETHODIMP CFileOperation::SetOperationFlags(DWORD dwOperationFlags)
{
    m_dwFlags = dwOperationFlags;
    return S_OK;
}

STDMETHODIMP CFileOperation::SetProgressMessage(LPCWSTR pszMessage)
{
    return E_NOTIMPL;
}

STDMETHODIMP CFileOperation::SetProgressDialog(IOperationsProgressDialog *popd)
{
    return popd ? S_OK : E_INVALIDARG;
}

STDMETHODIMP CFileOperation::SetProperties(IPropertyChangeArray *pproparray)
{
    return S_OK;
}

STDMETHODIMP CFileOperation::SetOwnerWindow(HWND hwndOwner)
{
    m_hwndOwner = hwndOwner;
    return S_OK;
}

STDMETHODIMP CFileOperation::ApplyPropertiesToItem(IShellItem *psiItem)
{
    return psiItem ? S_OK : E_INVALIDARG;
}

STDMETHODIMP CFileOperation::ApplyPropertiesToItems(IUnknown *punkItems)
{
    return punkItems ? S_OK : E_INVALIDARG;
}

HRESULT CFileOperation::Queue(OP_TYPE type, IShellItem *psiItem, IShellItem *psiFolder, LPCWSTR pszName,
                              IFileOperationProgressSink *pSink, DWORD dwAttributes, LPCWSTR pszTemplate)
{
    OPERATION *pOp = new OPERATION;
    if (!pOp)
        return E_OUTOFMEMORY;
    pOp->type = type;
    pOp->psiItem = psiItem;
    pOp->psiFolder = psiFolder;
    if (pszName)
        pOp->strName = pszName;
    if (pszTemplate)
        pOp->strTemplate = pszTemplate;
    pOp->dwAttributes = dwAttributes;
    pOp->pSink = pSink;
    m_Ops.AddTail(pOp);
    return S_OK;
}

HRESULT CFileOperation::QueueItems(OP_TYPE type, IUnknown *punkItems, IShellItem *psiFolder, LPCWSTR pszName)
{
    if (!punkItems)
        return E_INVALIDARG;

    // The items come as an IShellItemArray or an IDataObject; a single IShellItem is taken as well
    CComPtr<IShellItemArray> pArray;
    HRESULT hr = punkItems->QueryInterface(IID_PPV_ARG(IShellItemArray, &pArray));
    if (FAILED(hr))
    {
        CComPtr<IShellItem> psi;
        if (SUCCEEDED(punkItems->QueryInterface(IID_PPV_ARG(IShellItem, &psi))))
            return Queue(type, psi, psiFolder, pszName, NULL);

        CComPtr<IDataObject> pData;
        hr = punkItems->QueryInterface(IID_PPV_ARG(IDataObject, &pData));
        if (FAILED(hr))
            return E_NOINTERFACE;
        hr = SHCreateShellItemArrayFromDataObject(pData, IID_PPV_ARG(IShellItemArray, &pArray));
        if (FAILED(hr))
            return hr;
    }

    DWORD cItems = 0;
    hr = pArray->GetCount(&cItems);
    if (FAILED(hr))
        return hr;
    for (DWORD i = 0; i < cItems; ++i)
    {
        CComPtr<IShellItem> psi;
        hr = pArray->GetItemAt(i, &psi);
        if (FAILED(hr))
            return hr;
        hr = Queue(type, psi, psiFolder, pszName, NULL);
        if (FAILED(hr))
            return hr;
    }
    return S_OK;
}

STDMETHODIMP CFileOperation::RenameItem(IShellItem *psiItem, LPCWSTR pszNewName, IFileOperationProgressSink *pfopsItem)
{
    if (!psiItem || !pszNewName)
        return E_INVALIDARG;
    return Queue(OP_RENAME, psiItem, NULL, pszNewName, pfopsItem);
}

STDMETHODIMP CFileOperation::RenameItems(IUnknown *pUnkItems, LPCWSTR pszNewName)
{
    if (!pszNewName)
        return E_INVALIDARG;
    return QueueItems(OP_RENAME, pUnkItems, NULL, pszNewName);
}

STDMETHODIMP CFileOperation::MoveItem(IShellItem *psiItem, IShellItem *psiDestinationFolder, LPCWSTR pszNewName,
                                      IFileOperationProgressSink *pfopsItem)
{
    if (!psiItem || !psiDestinationFolder)
        return E_INVALIDARG;
    return Queue(OP_MOVE, psiItem, psiDestinationFolder, pszNewName, pfopsItem);
}

STDMETHODIMP CFileOperation::MoveItems(IUnknown *punkItems, IShellItem *psiDestinationFolder)
{
    if (!psiDestinationFolder)
        return E_INVALIDARG;
    return QueueItems(OP_MOVE, punkItems, psiDestinationFolder, NULL);
}

STDMETHODIMP CFileOperation::CopyItem(IShellItem *psiItem, IShellItem *psiDestinationFolder, LPCWSTR pszCopyName,
                                      IFileOperationProgressSink *pfopsItem)
{
    if (!psiItem || !psiDestinationFolder)
        return E_INVALIDARG;
    return Queue(OP_COPY, psiItem, psiDestinationFolder, pszCopyName, pfopsItem);
}

STDMETHODIMP CFileOperation::CopyItems(IUnknown *punkItems, IShellItem *psiDestinationFolder)
{
    if (!psiDestinationFolder)
        return E_INVALIDARG;
    return QueueItems(OP_COPY, punkItems, psiDestinationFolder, NULL);
}

STDMETHODIMP CFileOperation::DeleteItem(IShellItem *psiItem, IFileOperationProgressSink *pfopsItem)
{
    if (!psiItem)
        return E_INVALIDARG;
    return Queue(OP_DELETE, psiItem, NULL, NULL, pfopsItem);
}

STDMETHODIMP CFileOperation::DeleteItems(IUnknown *punkItems)
{
    return QueueItems(OP_DELETE, punkItems, NULL, NULL);
}

STDMETHODIMP CFileOperation::NewItem(IShellItem *psiDestinationFolder, DWORD dwFileAttributes, LPCWSTR pszName,
                                     LPCWSTR pszTemplateName, IFileOperationProgressSink *pfopsItem)
{
    if (!psiDestinationFolder || !pszName)
        return E_INVALIDARG;
    return Queue(OP_NEW, NULL, psiDestinationFolder, pszName, pfopsItem, dwFileAttributes, pszTemplateName);
}

// The flags the sinks get with an item: what happens on a name collision, and the property copying that goes
// with the operation type
DWORD CFileOperation::GetTransferFlags(OP_TYPE type) const
{
    DWORD dwTsf = TSF_COPY_LOCALIZED_NAME;
    if (m_dwFlags & FOF_RENAMEONCOLLISION)
        dwTsf |= TSF_RENAME_EXIST;
    else if (m_dwFlags & FOF_NOCONFIRMATION)
        dwTsf |= TSF_OVERWRITE_EXIST;

    switch (type)
    {
        case OP_COPY:
            dwTsf |= TSF_NO_SECURITY | TSF_COPY_WRITE_TIME;
            break;
        case OP_MOVE:
            dwTsf |= TSF_COPY_CREATION_TIME | TSF_COPY_WRITE_TIME;
            break;
        case OP_RENAME:
            dwTsf &= ~(TSF_OVERWRITE_EXIST | TSF_RENAME_EXIST);
            dwTsf |= TSF_COPY_CREATION_TIME | TSF_COPY_WRITE_TIME;
            break;
        default:
            break;
    }
    return dwTsf;
}

// The sinks are called in this order: those added with Advise, then the item's own sink for the "Pre" calls,
// the item sink, then the others for the "Post" calls.
#define CALL_PRE(op, call) \
    do { \
        for (POSITION pos_ = m_Sinks.GetHeadPosition(); pos_;) \
        { \
            CComPtr<IFileOperationProgressSink> pSink_ = m_Sinks.GetNext(pos_).pSink; \
            pSink_->call; \
        } \
        if ((op).pSink) \
            (op).pSink->call; \
    } while (0)

#define CALL_POST(op, call) \
    do { \
        if ((op).pSink) \
            (op).pSink->call; \
        for (POSITION pos_ = m_Sinks.GetHeadPosition(); pos_;) \
        { \
            CComPtr<IFileOperationProgressSink> pSink_ = m_Sinks.GetNext(pos_).pSink; \
            pSink_->call; \
        } \
    } while (0)

HRESULT CFileOperation::RunOne(OPERATION &op)
{
    CStringW strSrc, strFolder, strDest;
    HRESULT hr;
    CComPtr<IShellItem> psiNew;
    const DWORD dwTsf = GetTransferFlags(op.type);

    if (op.psiItem)
    {
        hr = GetItemPath(op.psiItem, strSrc);
        if (FAILED(hr))
            return hr;
    }
    if (op.psiFolder)
    {
        hr = GetItemPath(op.psiFolder, strFolder);
        if (FAILED(hr))
            return hr;
    }

    // The sinks get an empty name when none was given, and the name used afterwards
    LPCWSTR pszGiven = op.strName;
    switch (op.type)
    {
        case OP_RENAME:
        {
            CStringW strDir = strSrc;
            PathRemoveFileSpecW(strDir.GetBuffer());
            strDir.ReleaseBuffer();
            strDest = JoinPath(strDir, op.strName);
            CALL_PRE(op, PreRenameItem(dwTsf, op.psiItem, pszGiven));
            hr = MoveFileW(strSrc, strDest) ? COPYENGINE_S_DONT_PROCESS_CHILDREN : HRESULT_FROM_WIN32(GetLastError());
            if (SUCCEEDED(hr))
                SHCreateItemFromParsingName(strDest, NULL, IID_PPV_ARG(IShellItem, &psiNew));
            CALL_POST(op, PostRenameItem(dwTsf, op.psiItem, pszGiven, hr, psiNew));
            break;
        }
        case OP_MOVE:
        case OP_COPY:
        {
            CStringW strName = op.strName.IsEmpty() ? FileName(strSrc) : op.strName;
            strDest = JoinPath(strFolder, strName);
            const BOOL bMove = (op.type == OP_MOVE);
            if (bMove)
                CALL_PRE(op, PreMoveItem(dwTsf, op.psiItem, op.psiFolder, pszGiven));
            else
                CALL_PRE(op, PreCopyItem(dwTsf, op.psiItem, op.psiFolder, pszGiven));
            hr = CheckSource(strSrc);
            if (SUCCEEDED(hr))
                hr = ShellOp(bMove ? FO_MOVE : FO_COPY, strSrc, &strDest, m_dwFlags, m_hwndOwner);
            if (SUCCEEDED(hr))
            {
                SHCreateItemFromParsingName(strDest, NULL, IID_PPV_ARG(IShellItem, &psiNew));
                if (bMove)
                    hr = COPYENGINE_S_DONT_PROCESS_CHILDREN;
            }
            if (bMove)
                CALL_POST(op, PostMoveItem(dwTsf, op.psiItem, op.psiFolder, strName, hr, psiNew));
            else
                CALL_POST(op, PostCopyItem(dwTsf, op.psiItem, op.psiFolder, strName, hr, psiNew));
            break;
        }
        case OP_DELETE:
            CALL_PRE(op, PreDeleteItem(dwTsf, op.psiItem));
            hr = CheckSource(strSrc);
            if (SUCCEEDED(hr))
                hr = ShellOp(FO_DELETE, strSrc, NULL, m_dwFlags, m_hwndOwner);
            if (SUCCEEDED(hr))
                hr = COPYENGINE_S_DONT_PROCESS_CHILDREN;
            CALL_POST(op, PostDeleteItem(dwTsf, op.psiItem, hr, NULL));
            break;
        case OP_NEW:
        {
            strDest = JoinPath(strFolder, op.strName);
            LPCWSTR pszTemplate = op.strTemplate.IsEmpty() ? NULL : (LPCWSTR)op.strTemplate;
            CALL_PRE(op, PreNewItem(dwTsf, op.psiFolder, op.strName));
            if (op.dwAttributes & FILE_ATTRIBUTE_DIRECTORY)
            {
                hr = CreateDirectoryW(strDest, NULL) ? S_OK : HRESULT_FROM_WIN32(GetLastError());
            }
            else if (pszTemplate)
            {
                hr = CopyFileW(pszTemplate, strDest, TRUE) ? S_OK : HRESULT_FROM_WIN32(GetLastError());
            }
            else
            {
                HANDLE hFile = CreateFileW(strDest, GENERIC_WRITE, 0, NULL, CREATE_NEW,
                                           op.dwAttributes ? op.dwAttributes : FILE_ATTRIBUTE_NORMAL, NULL);
                if (hFile == INVALID_HANDLE_VALUE)
                {
                    hr = HRESULT_FROM_WIN32(GetLastError());
                }
                else
                {
                    CloseHandle(hFile);
                    hr = S_OK;
                }
            }
            if (SUCCEEDED(hr))
                SHCreateItemFromParsingName(strDest, NULL, IID_PPV_ARG(IShellItem, &psiNew));
            CALL_POST(op, PostNewItem(dwTsf, op.psiFolder, op.strName, pszTemplate, op.dwAttributes, hr, psiNew));
            break;
        }
        default:
            hr = E_UNEXPECTED;
    }
    return hr;
}

STDMETHODIMP CFileOperation::PerformOperations()
{
    // Nothing queued, as after a previous call
    if (m_Ops.IsEmpty())
        return E_UNEXPECTED;

    for (POSITION pos = m_Sinks.GetHeadPosition(); pos;)
    {
        CComPtr<IFileOperationProgressSink> pSink = m_Sinks.GetNext(pos).pSink;
        pSink->StartOperations();
    }

    // A failing operation does not stop the others and is not an error of this call; it is reported to the
    // sinks and sets the "aborted" flag
    while (!m_Ops.IsEmpty())
    {
        OPERATION *pOp = m_Ops.RemoveHead();
        if (FAILED(RunOne(*pOp)))
            m_bAborted = TRUE;
        delete pOp;
    }

    for (POSITION pos = m_Sinks.GetHeadPosition(); pos;)
    {
        CComPtr<IFileOperationProgressSink> pSink = m_Sinks.GetNext(pos).pSink;
        pSink->FinishOperations(S_OK);
    }
    return S_OK;
}

STDMETHODIMP CFileOperation::GetAnyOperationsAborted(BOOL *pfAnyOperationsAborted)
{
    if (!pfAnyOperationsAborted)
        return E_POINTER;
    *pfAnyOperationsAborted = m_bAborted;
    return S_OK;
}
