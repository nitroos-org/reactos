/*
 * PROJECT:     Recycle bin management
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Deals with recycle bins of Windows 2000/XP/2003
 * COPYRIGHT:   Copyright 2006-2007 Hervé Poussineau (hpoussin@reactos.org)
 *              Copyright 2024 Katayama Hirofumi MZ (katayama.hirofumi.mz@gmail.com)
 */

#include "recyclebin_private.h"
#include <atlstr.h>
#include <shlwapi.h>
#include "sddl.h"
#include <aclapi.h>

EXTERN_C HRESULT WINAPI SHUpdateRecycleBinIcon(void);

class CZZWStr
{
    LPWSTR m_sz;

public:
    ~CZZWStr() { SHFree(m_sz); }
    CZZWStr() : m_sz(NULL) {}
    CZZWStr(const CZZWStr&) = delete;
    CZZWStr& operator=(const CZZWStr&) = delete;

    bool Initialize(LPCWSTR Str)
    {
        SIZE_T cch = wcslen(Str) + 1;
        m_sz = (LPWSTR)SHAlloc((cch + 1) * sizeof(*Str));
        if (!m_sz)
            return false;
        CopyMemory(m_sz, Str, cch * sizeof(*Str));
        m_sz[cch] = UNICODE_NULL; // Double-null terminate
        return true;
    }
    inline LPWSTR c_str() { return m_sz; }
};

static int SHELL_SingleFileOperation(HWND hWnd, UINT Op, LPCWSTR pszFrom, LPCWSTR pszTo, FILEOP_FLAGS Flags)
{
    CZZWStr szzFrom, szzTo;
    if (!szzFrom.Initialize(pszFrom) || !szzTo.Initialize(pszTo))
        return ERROR_OUTOFMEMORY; // Note: Not one of the DE errors but also not in the DE range
    SHFILEOPSTRUCTW fos = { hWnd, Op, szzFrom.c_str(), szzTo.c_str(), Flags };
    return SHFileOperationW(&fos);
}

static BOOL
IntDeleteRecursive(
    IN LPCWSTR FullName)
{
    DWORD RemovableAttributes = FILE_ATTRIBUTE_READONLY;
    WIN32_FIND_DATAW FindData;
    HANDLE hSearch = INVALID_HANDLE_VALUE;
    LPWSTR FullPath = NULL, pFilePart;
    DWORD FileAttributes;
    SIZE_T dwLength;
    BOOL ret = FALSE;

    FileAttributes = GetFileAttributesW(FullName);
    if (FileAttributes == INVALID_FILE_ATTRIBUTES)
    {
        if (GetLastError() == ERROR_FILE_NOT_FOUND)
            ret = TRUE;
        goto cleanup;
    }
    if (FileAttributes & RemovableAttributes)
    {
        if (!SetFileAttributesW(FullName, FileAttributes & ~RemovableAttributes))
            goto cleanup;
    }
    if (FileAttributes & FILE_ATTRIBUTE_DIRECTORY)
    {
        /* Prepare file specification */
        dwLength = wcslen(FullName);
        FullPath = (LPWSTR)HeapAlloc(GetProcessHeap(), 0, (dwLength + 1 + MAX_PATH + 1) * sizeof(WCHAR));
        if (!FullPath)
        {
            SetLastError(ERROR_NOT_ENOUGH_MEMORY);
            goto cleanup;
        }
        wcscpy(FullPath, FullName);
        if (FullPath[dwLength - 1] != '\\')
        {
            FullPath[dwLength] = '\\';
            dwLength++;
        }
        pFilePart = &FullPath[dwLength];
        wcscpy(pFilePart, L"*");

        /* Enumerate contents, and delete it */
        hSearch = FindFirstFileW(FullPath, &FindData);
        if (hSearch == INVALID_HANDLE_VALUE)
            goto cleanup;
        do
        {
            if (!(FindData.cFileName[0] == '.' &&
                (FindData.cFileName[1] == '\0' || (FindData.cFileName[1] == '.' && FindData.cFileName[2] == '\0'))))
            {
                wcscpy(pFilePart, FindData.cFileName);
                if (!IntDeleteRecursive(FullPath))
                {
                    FindClose(hSearch);
                    goto cleanup;
                }
            }
        }
        while (FindNextFileW(hSearch, &FindData));
        FindClose(hSearch);
        if (GetLastError() != ERROR_NO_MORE_FILES)
            goto cleanup;

        /* Remove (now empty) directory */
        if (!RemoveDirectoryW(FullName))
            goto cleanup;
    }
    else
    {
        if (!DeleteFileW(FullName))
            goto cleanup;
    }
    ret = TRUE;

cleanup:
    HeapFree(GetProcessHeap(), 0, FullPath);
    return ret;
}

/* A bin that has no folder yet: nothing to list */
class RecycleBin5EmptyEnum : public IRecycleBinEnumList
{
public:
    RecycleBin5EmptyEnum() : m_ref(1) { }
    virtual ~RecycleBin5EmptyEnum() { }
    STDMETHODIMP QueryInterface(REFIID riid, void **ppvObject) override
    {
        if (!ppvObject)
            return E_POINTER;
        if (IsEqualIID(riid, IID_IUnknown) || IsEqualIID(riid, IID_IRecycleBinEnumList))
        {
            *ppvObject = static_cast<IRecycleBinEnumList *>(this);
            AddRef();
            return S_OK;
        }
        *ppvObject = NULL;
        return E_NOINTERFACE;
    }
    STDMETHODIMP_(ULONG) AddRef() override { return InterlockedIncrement(&m_ref); }
    STDMETHODIMP_(ULONG) Release() override
    {
        ULONG refCount = InterlockedDecrement(&m_ref);
        if (refCount == 0)
            delete this;
        return refCount;
    }
    STDMETHODIMP Next(DWORD, IRecycleBinFile **, DWORD *pceltFetched) override
    {
        if (pceltFetched)
            *pceltFetched = 0;
        return S_FALSE;
    }
    STDMETHODIMP Skip(DWORD) override { return S_OK; }
    STDMETHODIMP Reset() override { return S_OK; }

private:
    LONG m_ref;
};

class RecycleBin5 : public IRecycleBin5
{
public:
    RecycleBin5();
    virtual ~RecycleBin5();

    HRESULT Init(_In_ LPCWSTR VolumePath);

    /* IUnknown interface */
    STDMETHODIMP QueryInterface(_In_ REFIID riid, _Out_ void **ppvObject) override;
    STDMETHODIMP_(ULONG) AddRef() override;
    STDMETHODIMP_(ULONG) Release() override;

    /* IRecycleBin interface */
    STDMETHODIMP DeleteFile(_In_ LPCWSTR szFileName) override;
    STDMETHODIMP EmptyRecycleBin() override;
    STDMETHODIMP EnumObjects(_Out_ IRecycleBinEnumList **ppEnumList) override;
    STDMETHODIMP GetDirectory(LPWSTR szPath) override
    {
        if (!m_Folder[0])
            return E_UNEXPECTED;
        lstrcpynW(szPath, m_Folder, MAX_PATH);
        return S_OK;
    }

    /* IRecycleBin5 interface */
    STDMETHODIMP Delete(
        _In_ LPCWSTR pDeletedFileName,
        _In_ DELETED_FILE_RECORD *pDeletedFile) override;
    STDMETHODIMP Restore(
        _In_ LPCWSTR pDeletedFileName,
        _In_ DELETED_FILE_RECORD *pDeletedFile) override;
    STDMETHODIMP RemoveFromDatabase(
        _In_ LPCWSTR pDeletedFileName,
        _In_ DELETED_FILE_RECORD *pDeletedFile) override;
    STDMETHODIMP OnClosing(_In_ IRecycleBinEnumList *prbel) override;

protected:
    HRESULT EnsureCreated();

    LONG m_ref;
    HANDLE m_hInfo;
    HANDLE m_hInfoMapped;
    DWORD m_EnumeratorCount;
    PSID m_OwnerSid; /* the user's SID, kept until the folder is made (the first delete on the volume) */
    CStringW m_VolumePath;
    CStringW m_Folder; /* [drive]:\[RECYCLE_BIN_DIRECTORY]\{SID} */
};

STDMETHODIMP RecycleBin5::QueryInterface(_In_ REFIID riid, _Out_ void **ppvObject)
{
    TRACE("(%p, %s, %p)\n", this, debugstr_guid(&riid), ppvObject);

    if (!ppvObject)
        return E_POINTER;

    if (IsEqualIID(riid, IID_IUnknown) || IsEqualIID(riid, IID_IRecycleBin))
        *ppvObject = static_cast<IRecycleBin5 *>(this);
    else if (IsEqualIID(riid, IID_IRecycleBin5))
        *ppvObject = static_cast<IRecycleBin5 *>(this);
    else
    {
        *ppvObject = NULL;
        return E_NOINTERFACE;
    }

    AddRef();
    return S_OK;
}

STDMETHODIMP_(ULONG) RecycleBin5::AddRef()
{
    TRACE("(%p)\n", this);
    return InterlockedIncrement(&m_ref);
}

RecycleBin5::~RecycleBin5()
{
    TRACE("(%p)\n", this);

    if (m_hInfo && m_hInfo != INVALID_HANDLE_VALUE)
        CloseHandle(m_hInfo);
    if (m_hInfoMapped)
        CloseHandle(m_hInfoMapped);
    if (m_OwnerSid)
        HeapFree(GetProcessHeap(), 0, m_OwnerSid);
}

STDMETHODIMP_(ULONG) RecycleBin5::Release()
{
    TRACE("(%p)\n", this);

    ULONG refCount = InterlockedDecrement(&m_ref);
    if (refCount == 0)
        delete this;
    return refCount;
}

STDMETHODIMP RecycleBin5::DeleteFile(_In_ LPCWSTR szFileName)
{
    LPWSTR szFullName = NULL;
    DWORD dwBufferLength = 0;
    LPWSTR lpFilePart;
    LPCWSTR Extension;
    CStringW DeletedFileName;
    WCHAR szUniqueId[64];
    DWORD len;
    HANDLE hFile = INVALID_HANDLE_VALUE;
    PINFO2_HEADER pHeader = NULL;
    PDELETED_FILE_RECORD pDeletedFile;
    ULARGE_INTEGER FileSize;
    DWORD dwAttributes, dwEntries;
    SYSTEMTIME SystemTime;
    DWORD ClusterSize, BytesPerSector, SectorsPerCluster;
    HRESULT hr;
    WIN32_FIND_DATAW wfd = {};

    TRACE("(%p, %s)\n", this, debugstr_w(szFileName));

    if (m_EnumeratorCount != 0)
        return HRESULT_FROM_WIN32(ERROR_SHARING_VIOLATION);

    /* The folder of the bin is made by the first delete on the volume, not when the bin is looked at */
    hr = EnsureCreated();
    if (FAILED(hr))
        return hr;

    /* Get full file name */
    while (TRUE)
    {
        len = GetFullPathNameW(szFileName, dwBufferLength, szFullName, &lpFilePart);
        if (len == 0)
        {
            if (szFullName)
                CoTaskMemFree(szFullName);
            return HResultFromWin32(GetLastError());
        }
        else if (len < dwBufferLength)
            break;
        if (szFullName)
            CoTaskMemFree(szFullName);
        dwBufferLength = len;
        szFullName = (LPWSTR)CoTaskMemAlloc(dwBufferLength * sizeof(WCHAR));
        if (!szFullName)
            return HRESULT_FROM_WIN32(ERROR_NOT_ENOUGH_MEMORY);
    }

    /* Check if file exists */
    dwAttributes = GetFileAttributesW(szFullName);
    if (dwAttributes == INVALID_FILE_ATTRIBUTES)
    {
        CoTaskMemFree(szFullName);
        return HResultFromWin32(GetLastError());
    }

    if (dwBufferLength < 2 || szFullName[1] != ':')
    {
        /* Not a local file */
        CoTaskMemFree(szFullName);
        return HRESULT_FROM_WIN32(ERROR_INVALID_NAME);
    }

    hFile = CreateFileW(szFullName, 0, 0, NULL, OPEN_EXISTING, (dwAttributes & FILE_ATTRIBUTE_DIRECTORY) ? FILE_FLAG_BACKUP_SEMANTICS : 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        hr = HResultFromWin32(GetLastError());
        goto cleanup;
    }

    /* Increase INFO2 file size */
    CloseHandle(m_hInfoMapped);
    SetFilePointer(m_hInfo, sizeof(DELETED_FILE_RECORD), NULL, FILE_END);
    SetEndOfFile(m_hInfo);
    m_hInfoMapped = CreateFileMappingW(m_hInfo, NULL, PAGE_READWRITE | SEC_COMMIT, 0, 0, NULL);
    if (!m_hInfoMapped)
    {
        hr = HResultFromWin32(GetLastError());
        goto cleanup;
    }

    /* Open INFO2 file */
    pHeader = (PINFO2_HEADER)MapViewOfFile(m_hInfoMapped, FILE_MAP_WRITE, 0, 0, 0);
    if (!pHeader)
    {
        hr = HResultFromWin32(GetLastError());
        goto cleanup;
    }

    /* Get number of entries */
    FileSize.u.LowPart = GetFileSize(m_hInfo, &FileSize.u.HighPart);
    if (FileSize.u.LowPart < sizeof(INFO2_HEADER))
    {
        hr = HResultFromWin32(GetLastError());
        goto cleanup;
    }
    dwEntries = (DWORD)((FileSize.QuadPart - sizeof(INFO2_HEADER)) / sizeof(DELETED_FILE_RECORD)) - 1;
    pDeletedFile = ((PDELETED_FILE_RECORD)(pHeader + 1)) + dwEntries;

    /* Get file size */
#if 0
    if (!GetFileSizeEx(hFile, (PLARGE_INTEGER)&FileSize))
    {
        hr = HResultFromWin32(GetLastError());
        goto cleanup;
    }
#else
    FileSize.u.LowPart = GetFileSize(hFile, &FileSize.u.HighPart);
    if (FileSize.u.LowPart == INVALID_FILE_SIZE && GetLastError() != NO_ERROR)
    {
        hr = HResultFromWin32(GetLastError());
        goto cleanup;
    }
#endif
    /* Check if file size is > 4Gb */
    if (FileSize.u.HighPart != 0)
    {
        /* Yes, this recyclebin can't support this file */
        hr = HRESULT_FROM_WIN32(ERROR_NOT_SUPPORTED);
        goto cleanup;
    }
    pHeader->dwTotalLogicalSize += FileSize.u.LowPart;

    /* Generate new name */
    Extension = PathFindExtensionW(szFullName);
    ZeroMemory(pDeletedFile, sizeof(DELETED_FILE_RECORD));
    if (dwEntries == 0)
        pDeletedFile->dwRecordUniqueId = 0;
    else
    {
        PDELETED_FILE_RECORD pLastDeleted = ((PDELETED_FILE_RECORD)(pHeader + 1)) + dwEntries - 1;
        pDeletedFile->dwRecordUniqueId = pLastDeleted->dwRecordUniqueId + 1;
    }

    pDeletedFile->dwDriveNumber = tolower(szFullName[0]) - 'a';
    _ultow(pDeletedFile->dwRecordUniqueId, szUniqueId, 10);

    DeletedFileName = m_Folder;
    DeletedFileName += L"\\D";
    DeletedFileName += (WCHAR)(L'a' + pDeletedFile->dwDriveNumber);
    DeletedFileName += szUniqueId;
    DeletedFileName += Extension;

    /* Get cluster size */
    if (!GetDiskFreeSpaceW(m_VolumePath, &SectorsPerCluster, &BytesPerSector, NULL, NULL))
    {
        hr = HResultFromWin32(GetLastError());
        goto cleanup;
    }
    ClusterSize = BytesPerSector * SectorsPerCluster;

    /* Get current time */
    GetSystemTime(&SystemTime);
    if (!SystemTimeToFileTime(&SystemTime, &pDeletedFile->DeletionTime))
    {
        hr = HResultFromWin32(GetLastError());
        goto cleanup;
    }
    pDeletedFile->dwPhysicalFileSize = ROUND_UP(FileSize.u.LowPart, ClusterSize);

    /* Set name */
    wcscpy(pDeletedFile->FileNameW, szFullName);
    if (WideCharToMultiByte(CP_ACP, 0, pDeletedFile->FileNameW, -1, pDeletedFile->FileNameA, MAX_PATH, NULL, NULL) == 0)
    {
        hr = HRESULT_FROM_WIN32(ERROR_INVALID_NAME);
        SetLastError(ERROR_INVALID_NAME);
        goto cleanup;
    }

    wfd.dwFileAttributes = dwAttributes;
    wfd.nFileSizeLow = FileSize.u.LowPart;
    GetFileTime(hFile, &wfd.ftCreationTime, &wfd.ftLastAccessTime, &wfd.ftLastWriteTime);

    /* Move file */
    if (MoveFileW(szFullName, DeletedFileName))
        hr = S_OK;
    else
        hr = HResultFromWin32(GetLastError());

    if (SUCCEEDED(hr))
    {
        RECYCLEBINFILEIDENTITY ident = { pDeletedFile->DeletionTime, DeletedFileName };
        CRecycleBin_NotifyRecycled(szFullName, &wfd, &ident);
    }

cleanup:
    if (pHeader)
        UnmapViewOfFile(pHeader);
    if (hFile != INVALID_HANDLE_VALUE)
        CloseHandle(hFile);
    CoTaskMemFree(szFullName);
    return hr;
}

STDMETHODIMP RecycleBin5::EmptyRecycleBin()
{
    TRACE("(%p)\n", this);

    while (TRUE)
    {
        IRecycleBinEnumList *prbel;
        HRESULT hr = EnumObjects(&prbel);
        if (!SUCCEEDED(hr))
            return hr;

        IRecycleBinFile *prbf;
        hr = prbel->Next(1, &prbf, NULL);
        prbel->Release();
        if (hr == S_FALSE)
            return S_OK;
        hr = prbf->Delete();
        prbf->Release();
        if (!SUCCEEDED(hr))
            return hr;
    }
}

STDMETHODIMP RecycleBin5::EnumObjects(_Out_ IRecycleBinEnumList **ppEnumList)
{
    TRACE("(%p, %p)\n", this, ppEnumList);

    IUnknown *pUnk;
    if (m_hInfo == INVALID_HANDLE_VALUE)
    {
        /* Nothing was ever deleted to this volume's bin: it has no folder yet, and reading it makes none */
        *ppEnumList = new RecycleBin5EmptyEnum();
        return *ppEnumList ? S_OK : E_OUTOFMEMORY;
    }
    HRESULT hr = RecycleBin5Enum_Constructor(this, m_hInfo, m_hInfoMapped, m_Folder, &pUnk);
    if (!SUCCEEDED(hr))
        return hr;

    IRecycleBinEnumList *prbel;
    hr = pUnk->QueryInterface(IID_IRecycleBinEnumList, (void **)&prbel);
    if (SUCCEEDED(hr))
    {
        m_EnumeratorCount++;
        *ppEnumList = prbel;
    }

    pUnk->Release();
    return hr;
}

STDMETHODIMP RecycleBin5::Delete(
    _In_ LPCWSTR pDeletedFileName,
    _In_ DELETED_FILE_RECORD *pDeletedFile)
{

    TRACE("(%p, %s, %p)\n", this, debugstr_w(pDeletedFileName), pDeletedFile);

    int res = IntDeleteRecursive(pDeletedFileName);
    if (!res)
        return HResultFromWin32(GetLastError());
    res = RemoveFromDatabase(pDeletedFileName, pDeletedFile);
    if (res == 0)
        SHUpdateRecycleBinIcon(); // Full --> Empty
    return res;
}

STDMETHODIMP RecycleBin5::Restore(
    _In_ LPCWSTR pDeletedFileName,
    _In_ DELETED_FILE_RECORD *pDeletedFile)
{

    TRACE("(%p, %s, %p)\n", this, debugstr_w(pDeletedFileName), pDeletedFile);

    int res = SHELL_SingleFileOperation(NULL, FO_MOVE, pDeletedFileName, pDeletedFile->FileNameW, 0);
    if (res)
    {
        ERR("SHFileOperationW failed with 0x%x\n", res);
        return E_FAIL;
    }
    res = RemoveFromDatabase(pDeletedFileName, pDeletedFile);
    if (res == 0)
        SHUpdateRecycleBinIcon(); // Full --> Empty
    return res;
}

STDMETHODIMP RecycleBin5::RemoveFromDatabase(
    _In_ LPCWSTR pDeletedFileName,
    _In_ DELETED_FILE_RECORD *pDeletedFile)
{
    ULARGE_INTEGER FileSize;
    PINFO2_HEADER pHeader;
    DELETED_FILE_RECORD *pRecord, *pLast;
    DWORD dwEntries, i;

    TRACE("(%p, %s, %p)\n", this, debugstr_w(pDeletedFileName), pDeletedFile);

    if (m_EnumeratorCount != 0)
        return HRESULT_FROM_WIN32(ERROR_SHARING_VIOLATION);
    if (m_hInfo == INVALID_HANDLE_VALUE || !m_hInfoMapped)
        return HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND);

    pHeader = (PINFO2_HEADER)MapViewOfFile(m_hInfoMapped, FILE_MAP_WRITE, 0, 0, 0);
    if (!pHeader)
        return HRESULT_FROM_WIN32(GetLastError());

    FileSize.u.LowPart = GetFileSize(m_hInfo, &FileSize.u.HighPart);
    if (FileSize.u.LowPart == 0)
    {
        UnmapViewOfFile(pHeader);
        return HRESULT_FROM_WIN32(GetLastError());
    }
    dwEntries = (DWORD)((FileSize.QuadPart - sizeof(INFO2_HEADER)) / sizeof(DELETED_FILE_RECORD));

    pRecord = (DELETED_FILE_RECORD *)(pHeader + 1);
    for (i = 0; i < dwEntries; i++)
    {
        if (pRecord->dwRecordUniqueId == pDeletedFile->dwRecordUniqueId)
        {
            /* Clear last entry in the file */
            MoveMemory(pRecord, pRecord + 1, (dwEntries - i - 1) * sizeof(DELETED_FILE_RECORD));
            pLast = pRecord + (dwEntries - i - 1);
            ZeroMemory(pLast, sizeof(DELETED_FILE_RECORD));
            UnmapViewOfFile(pHeader);

            /* Resize file */
            CloseHandle(m_hInfoMapped);
            SetFilePointer(m_hInfo, -(LONG)sizeof(DELETED_FILE_RECORD), NULL, FILE_END);
            SetEndOfFile(m_hInfo);
            m_hInfoMapped = CreateFileMappingW(m_hInfo, NULL, PAGE_READWRITE | SEC_COMMIT, 0, 0, NULL);
            if (!m_hInfoMapped)
                return HResultFromWin32(GetLastError());
            dwEntries--;
            return FAILED((int)dwEntries) ? INT_MAX : dwEntries;
        }
        pRecord++;
    }

    UnmapViewOfFile(pHeader);
    return HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND);
}

STDMETHODIMP RecycleBin5::OnClosing(_In_ IRecycleBinEnumList *prbel)
{
    TRACE("(%p, %p)\n", this, prbel);
    m_EnumeratorCount--;
    return S_OK;
}

/* The descriptor of the folder of one user: full control for the user, SYSTEM and the Administrators, nobody else,
 * not inheriting from the volume root (protected). The ACEs are inherited by what the folder gets later. */
static HRESULT
RecycleBin5_OwnerDescriptor(
    _In_ PSID OwnerSid,
    _Out_ PSECURITY_DESCRIPTOR *Descriptor)
{
    LPWSTR StringSid = NULL;
    WCHAR Sddl[256];

    *Descriptor = NULL;
    if (!ConvertSidToStringSidW(OwnerSid, &StringSid))
        return HRESULT_FROM_WIN32(GetLastError());
    if (wcslen(StringSid) + 64 >= _countof(Sddl))
    {
        LocalFree(StringSid);
        return HRESULT_FROM_WIN32(ERROR_INVALID_PARAMETER);
    }
    /* The order of Windows Server 2022's $Recycle.Bin\<SID> (measured on the system volume and on a second volume):
     * Administrators, SYSTEM, the user; and the label Low, NO_WRITE_UP, inherit-only for what is put into the folder
     * (the items get S:AI(ML;ID;NW;;;LW), a moved file keeps its own) */
    wsprintfW(Sddl, L"D:P(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)(A;OICI;FA;;;%s)S:AI(ML;OICIIO;NW;;;LW)", StringSid);
    LocalFree(StringSid);
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(Sddl, SDDL_REVISION_1, Descriptor, NULL))
        return HRESULT_FROM_WIN32(GetLastError());
    return S_OK;
}

/* The descriptor of the folder that holds the per-user folders of a volume other than the system volume, which the
 * shell makes as the first user who deletes there (Windows Server 2022, measured with a standard user and with an
 * administrator on a second NTFS volume: the creator owns it, the DACL is protected and is not the root's; the same
 * for both): the Administrators and SYSTEM full control, inherited, the Users only list, add subfolder and read,
 * for the folder itself, and the label Low (NO_WRITE_UP) for what is made in it */
static HRESULT
RecycleBin5_RootDescriptor(
    _Out_ PSECURITY_DESCRIPTOR *Descriptor)
{
    *Descriptor = NULL;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:P(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)(A;NP;0x1201ad;;;BU)S:AI(ML;OICIIO;NW;;;LW)",
                                                              SDDL_REVISION_1, Descriptor, NULL))
        return HRESULT_FROM_WIN32(GetLastError());
    return S_OK;
}

static HRESULT
RecycleBin5_Create(
    _In_ LPCWSTR Folder,
    _In_ PSID OwnerSid OPTIONAL)
{
    LPWSTR BufferName = NULL;
    LPWSTR Separator; /* Pointer into BufferName buffer */
    LPWSTR FileName; /* Pointer into BufferName buffer */
    LPCSTR DesktopIniContents = "[.ShellClassInfo]\r\nCLSID={645FF040-5081-101B-9F08-00AA002F954E}\r\n";
    INFO2_HEADER Info2Contents[] = { { 5, 0, 0, 0x320, 0 } };
    DWORD BytesToWrite, BytesWritten;
    SIZE_T Needed;
    HANDLE hFile = INVALID_HANDLE_VALUE;
    PSECURITY_DESCRIPTOR OwnerDescriptor = NULL;
    HRESULT hr;

    Needed = (wcslen(Folder) + 1 + max(wcslen(RECYCLE_BIN_FILE_NAME), wcslen(L"desktop.ini")) + 1) * sizeof(WCHAR);
    BufferName = (LPWSTR)HeapAlloc(GetProcessHeap(), 0, Needed);
    if (!BufferName)
    {
        hr = ERROR_NOT_ENOUGH_MEMORY;
        goto cleanup;
    }

    wcscpy(BufferName, Folder);
    Separator = wcsstr(&BufferName[3], L"\\");
    if (Separator)
        *Separator = UNICODE_NULL;
    {
        SECURITY_ATTRIBUTES RootAttributes = { sizeof(RootAttributes), NULL, FALSE };
        PSECURITY_DESCRIPTOR RootDescriptor = NULL;

        /* The folder of the volume is made with its own descriptor, not the one of the volume root, when the
         * volume stores ACLs (that is when the folder of a user is made below it); one that is there stays as it is */
        if (Separator && OwnerSid && SUCCEEDED(RecycleBin5_RootDescriptor(&RootDescriptor)))
            RootAttributes.lpSecurityDescriptor = RootDescriptor;
        if (!CreateDirectoryW(BufferName, RootDescriptor ? &RootAttributes : NULL) && GetLastError() != ERROR_ALREADY_EXISTS)
        {
            hr = HRESULT_FROM_WIN32(GetLastError());
            LocalFree(RootDescriptor);
            goto cleanup;
        }
        LocalFree(RootDescriptor);
    }
    SetFileAttributesW(BufferName, FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN);
    if (Separator)
    {
        SECURITY_ATTRIBUTES Attributes = { sizeof(Attributes), NULL, FALSE };

        *Separator = L'\\';
        if (OwnerSid)
        {
            /* Only the user, SYSTEM and the Administrators may open it: the folder is created with that descriptor,
             * so that it never has the one of the volume root */
            hr = RecycleBin5_OwnerDescriptor(OwnerSid, &OwnerDescriptor);
            if (FAILED(hr))
                goto cleanup;
            Attributes.lpSecurityDescriptor = OwnerDescriptor;
        }
        if (!CreateDirectoryW(BufferName, OwnerSid ? &Attributes : NULL))
        {
            if (GetLastError() != ERROR_ALREADY_EXISTS)
            {
                hr = HRESULT_FROM_WIN32(GetLastError());
                goto cleanup;
            }
            if (OwnerSid)
            {
                /* A folder that is there already (a failed earlier creation) is given the descriptor too */
                PACL Dacl = NULL;
                BOOL Present = FALSE, Defaulted = FALSE;
                DWORD rc;

                if (!GetSecurityDescriptorDacl(OwnerDescriptor, &Present, &Dacl, &Defaulted) || !Present)
                {
                    hr = HRESULT_FROM_WIN32(GetLastError() ? GetLastError() : ERROR_INVALID_ACL);
                    goto cleanup;
                }
                rc = SetNamedSecurityInfoW(BufferName, SE_FILE_OBJECT,
                                           DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                                           NULL, NULL, Dacl, NULL);
                if (rc != ERROR_SUCCESS)
                {
                    hr = HRESULT_FROM_WIN32(rc);
                    goto cleanup;
                }

                /* ... and the label, if it has none (an older folder); a refusal leaves the folder as it is */
                {
                    PACL Sacl = NULL, CurrentSacl = NULL;
                    PSECURITY_DESCRIPTOR Current = NULL;

                    Present = FALSE;
                    if (GetSecurityDescriptorSacl(OwnerDescriptor, &Present, &Sacl, &Defaulted) && Present && Sacl &&
                        GetNamedSecurityInfoW(BufferName, SE_FILE_OBJECT, LABEL_SECURITY_INFORMATION, NULL, NULL, NULL,
                                              &CurrentSacl, &Current) == ERROR_SUCCESS)
                    {
                        if (CurrentSacl == NULL || CurrentSacl->AceCount == 0)
                            SetNamedSecurityInfoW(BufferName, SE_FILE_OBJECT, LABEL_SECURITY_INFORMATION,
                                                  NULL, NULL, NULL, Sacl);
                        LocalFree(Current);
                    }
                }
            }
        }
    }

    wcscat(BufferName, L"\\");
    FileName = &BufferName[wcslen(BufferName)];

    /* Create desktop.ini */
    wcscpy(FileName, L"desktop.ini");
    hFile = CreateFileW(BufferName, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        goto cleanup;
    }
    BytesToWrite = (UINT)strlen(DesktopIniContents);
    if (!WriteFile(hFile, DesktopIniContents, (DWORD)BytesToWrite, &BytesWritten, NULL))
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        goto cleanup;
    }
    if (BytesWritten != BytesToWrite)
    {
        hr = E_FAIL;
        goto cleanup;
    }
    CloseHandle(hFile);
    hFile = INVALID_HANDLE_VALUE;

    /* Create empty INFO2 file */
    wcscpy(FileName, RECYCLE_BIN_FILE_NAME);
    hFile = CreateFileW(BufferName, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        goto cleanup;
    }
    BytesToWrite = sizeof(Info2Contents);
    if (!WriteFile(hFile, Info2Contents, (DWORD)BytesToWrite, &BytesWritten, NULL))
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        goto cleanup;
    }
    if (BytesWritten == BytesToWrite)
        hr = S_OK;
    else
        hr = E_FAIL;

cleanup:
    if (OwnerDescriptor)
        LocalFree(OwnerDescriptor);
    HeapFree(GetProcessHeap(), 0, BufferName);
    if (hFile != INVALID_HANDLE_VALUE)
        CloseHandle(hFile);
    return hr;
}

RecycleBin5::RecycleBin5()
    : m_ref(1)
    , m_hInfo(NULL)
    , m_hInfoMapped(NULL)
    , m_EnumeratorCount(0)
    , m_OwnerSid(NULL)
{
}

/* The folder, desktop.ini and INFO2 of the bin are made when something is deleted to it */
HRESULT RecycleBin5::EnsureCreated()
{
    HRESULT hr;

    if (m_hInfo && m_hInfo != INVALID_HANDLE_VALUE)
        return S_OK;

    hr = RecycleBin5_Create(m_Folder, m_OwnerSid);
    if (FAILED(hr))
        return hr;

    CStringW InfoName = m_Folder;
    InfoName += L"\\" RECYCLE_BIN_FILE_NAME;
    m_hInfo = CreateFileW(InfoName, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (m_hInfo == INVALID_HANDLE_VALUE)
        return HRESULT_FROM_WIN32(GetLastError());
    m_hInfoMapped = CreateFileMappingW(m_hInfo, NULL, PAGE_READWRITE | SEC_COMMIT, 0, 0, NULL);
    if (!m_hInfoMapped)
        return HRESULT_FROM_WIN32(GetLastError());
    return S_OK;
}

HRESULT RecycleBin5::Init(_In_ LPCWSTR VolumePath)
{
    DWORD FileSystemFlags;
    LPCWSTR RecycleBinDirectory;
    HANDLE tokenHandle = INVALID_HANDLE_VALUE;
    PTOKEN_USER TokenUserInfo = NULL;
    LPWSTR StringSid = NULL;
    DWORD Needed;
    INT len;
    HRESULT hr;

    m_VolumePath = VolumePath;

    /* Get information about file system */
    if (!GetVolumeInformationW(VolumePath, NULL, 0, NULL, NULL, &FileSystemFlags, NULL, 0))
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        goto cleanup;
    }

    if (!(FileSystemFlags & FILE_PERSISTENT_ACLS))
    {
        RecycleBinDirectory = RECYCLE_BIN_DIRECTORY_WITHOUT_ACL;
    }
    else
    {
        RecycleBinDirectory = RECYCLE_BIN_DIRECTORY_WITH_ACL;

        /* Get user SID */
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tokenHandle))
        {
            hr = HRESULT_FROM_WIN32(GetLastError());
            goto cleanup;
        }
        if (GetTokenInformation(tokenHandle, TokenUser, NULL, 0, &Needed))
        {
            hr = E_FAIL;
            goto cleanup;
        }
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
        {
            hr = HRESULT_FROM_WIN32(GetLastError());
            goto cleanup;
        }
        TokenUserInfo = (PTOKEN_USER)HeapAlloc(GetProcessHeap(), 0, Needed);
        if (!TokenUserInfo)
        {
            hr = E_OUTOFMEMORY;
            goto cleanup;
        }
        if (!GetTokenInformation(tokenHandle, TokenUser, TokenUserInfo, (DWORD)Needed, &Needed))
        {
            hr = HRESULT_FROM_WIN32(GetLastError());
            goto cleanup;
        }
        if (!ConvertSidToStringSidW(TokenUserInfo->User.Sid, &StringSid))
        {
            hr = HRESULT_FROM_WIN32(GetLastError());
            goto cleanup;
        }
    }

    m_Folder = VolumePath;
    m_Folder += RecycleBinDirectory;
    if (StringSid)
    {
        m_Folder += L'\\';
        m_Folder += StringSid;
    }
    len = m_Folder.GetLength();
    m_Folder += L"\\" RECYCLE_BIN_FILE_NAME;

    m_hInfo = CreateFileW(m_Folder, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (m_hInfo == INVALID_HANDLE_VALUE &&
        (GetLastError() == ERROR_PATH_NOT_FOUND || GetLastError() == ERROR_FILE_NOT_FOUND))
    {
        /* Windows makes the folder at the first delete on the volume: keep what that needs and write nothing now */
        if (TokenUserInfo)
        {
            DWORD SidLength = GetLengthSid(TokenUserInfo->User.Sid);
            m_OwnerSid = (PSID)HeapAlloc(GetProcessHeap(), 0, SidLength);
            if (!m_OwnerSid || !CopySid(SidLength, m_OwnerSid, TokenUserInfo->User.Sid))
            {
                hr = E_OUTOFMEMORY;
                goto cleanup;
            }
        }
        m_Folder = m_Folder.Left(len);
        hr = S_OK;
        goto cleanup;
    }

    if (m_hInfo == INVALID_HANDLE_VALUE)
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        goto cleanup;
    }

    m_hInfoMapped = CreateFileMappingW(m_hInfo, NULL, PAGE_READWRITE | SEC_COMMIT, 0, 0, NULL);
    if (!m_hInfoMapped)
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        goto cleanup;
    }

    m_Folder = m_Folder.Left(len);
    hr = S_OK;

cleanup:
    if (tokenHandle != INVALID_HANDLE_VALUE)
        CloseHandle(tokenHandle);
    HeapFree(GetProcessHeap(), 0, TokenUserInfo);
    if (StringSid)
        LocalFree(StringSid);
    return hr;
}

EXTERN_C
HRESULT RecycleBin5_Constructor(_In_ LPCWSTR VolumePath, _Out_ IUnknown **ppUnknown)
{
    if (!ppUnknown)
        return E_POINTER;

    *ppUnknown = NULL;

    RecycleBin5 *pThis = new RecycleBin5();
    if (!pThis)
        return E_OUTOFMEMORY;

    HRESULT hr = pThis->Init(VolumePath);
    if (FAILED(hr))
    {
        delete pThis;
        return hr;
    }

    *ppUnknown = static_cast<IRecycleBin5 *>(pThis);
    return S_OK;
}
