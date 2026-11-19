/*
 * COPYRIGHT:       See COPYING in the top level directory
 * PROJECT:         shell32.dll
 * FILE:            dll/win32/shell32/stubs.c
 * PURPOSE:         shell32.dll stubs
 * PROGRAMMER:      Dmitry Chapyshev (dmitry@reactos.org)
 * NOTES:           If you implement a function, remove it from this file
 * UPDATE HISTORY:
 *      03/02/2009  Created
 */


#include "precomp.h"

WINE_DEFAULT_DEBUG_CHANNEL(shell);

/*
 * Unimplemented
 */
EXTERN_C VOID
WINAPI
CheckDiskSpace(VOID)
{
    FIXME("CheckDiskSpace() stub\n");
}

/*
 * Unimplemented
 */
EXTERN_C VOID
WINAPI
SHReValidateDarwinCache(VOID)
{
    FIXME("SHReValidateDarwinCache() stub\n");
}

/*
 * Unimplemented
 */
EXTERN_C FILEDESCRIPTOR*
WINAPI
GetFileDescriptor(FILEGROUPDESCRIPTOR *pFileGroupDesc, BOOL bUnicode, INT iIndex, LPWSTR lpName)
{
    FIXME("GetFileDescriptor() stub\n");
    return NULL;
}

/*
 * Unimplemented
 */
EXTERN_C BOOL
WINAPI
MakeShellURLFromPathW(LPCWSTR lpPath, LPWSTR lpUrl, INT cchMax)
{
    FIXME("MakeShellURLFromPathW() stub\n");
    lpUrl = NULL;
    return FALSE;
}

/*
 * Unimplemented
 */
EXTERN_C BOOL
WINAPI
MakeShellURLFromPathA(LPCSTR lpPath, LPSTR lpUrl, INT cchMax)
{
    WCHAR szPath[MAX_PATH], szURL[MAX_PATH];
    BOOL ret;
    SHAnsiToUnicode(lpPath, szPath, _countof(szPath));
    ret = MakeShellURLFromPathW(szPath, szURL, _countof(szURL));
    SHUnicodeToAnsi(szURL, lpUrl, cchMax);
    return ret;
}

/*
 * Unimplemented
 */
EXTERN_C HRESULT
WINAPI
SHParseDarwinIDFromCacheW(LPCWSTR lpUnknown1, LPWSTR lpUnknown2)
{
    FIXME("SHParseDarwinIDFromCacheW() stub\n");
    lpUnknown2 = NULL;
    return E_FAIL;
}

/*
 * Unimplemented
 */
EXTERN_C HRESULT
WINAPI
SHCopyMonikerToTemp(IMoniker *pMoniker, LPCWSTR lpInput, LPWSTR lpOutput, INT cchMax)
{
    /* Unimplemented in XP SP3 */
    TRACE("SHCopyMonikerToTemp() stub\n");
    return E_FAIL;
}

/*
 * Unimplemented
 */
EXTERN_C HLOCAL
WINAPI
CheckWinIniForAssocs(VOID)
{
    FIXME("CheckWinIniForAssocs() stub\n");
    return NULL;
}

/*
 * Unimplemented
 */
EXTERN_C HRESULT
WINAPI
SHGetSetFolderCustomSettingsW(LPSHFOLDERCUSTOMSETTINGSW pfcs,
                              LPCWSTR pszPath,
                              DWORD dwReadWrite)
{
    FIXME("SHGetSetFolderCustomSettingsW() stub\n");
    return E_FAIL;
}

/*
 * Unimplemented
 */
EXTERN_C HRESULT
WINAPI
SHGetSetFolderCustomSettingsA(LPSHFOLDERCUSTOMSETTINGSA pfcs,
                              LPCSTR pszPath,
                              DWORD dwReadWrite)
{
    FIXME("SHGetSetFolderCustomSettingsA() stub\n");
    return E_FAIL;
}

/*
 * Unimplemented
 */
EXTERN_C HRESULT
WINAPI
CDefFolderMenu_Create(LPITEMIDLIST pidlFolder,
                      HWND hwnd,
                      UINT uidl,
                      PCUITEMID_CHILD_ARRAY *apidl,
                      IShellFolder *psf,
                      LPFNDFMCALLBACK lpfn,
                      HKEY hProgID,
                      HKEY hBaseProgID,
                      IContextMenu **ppcm)
{
    FIXME("CDefFolderMenu_Create() stub\n");
    return E_FAIL;
}

/*
 * Unimplemented
 */
EXTERN_C VOID
WINAPI
SHWaitOp_Operate(LPVOID lpUnknown1, DWORD dwUnknown2)
{
    FIXME("SHWaitOp_Operate() stub\n");
}

/*
 * Unimplemented
 */
EXTERN_C INT
WINAPI
RealDriveTypeFlags(INT iDrive, BOOL bUnknown)
{
    FIXME("RealDriveTypeFlags() stub\n");
    return 1;
}

/*
 * Unimplemented
 */
EXTERN_C LONG
WINAPI
ShellHookProc(INT iCode, WPARAM wParam, LPARAM lParam)
{
    /* Unimplemented in WinXP SP3 */
    TRACE("ShellHookProc() stub\n");
    return 0;
}

/*
 * Unimplemented
 */
EXTERN_C BOOL
WINAPI
SheShortenPathW(LPWSTR lpPath, BOOL bShorten)
{
    FIXME("SheShortenPathW() stub\n");
    return FALSE;
}

/*
 * Unimplemented
 */
EXTERN_C BOOL
WINAPI
SheShortenPathA(LPSTR lpPath, BOOL bShorten)
{
    BOOL ret;
    WCHAR szPath[MAX_PATH];
    MultiByteToWideChar(CP_ACP, 0, lpPath, -1, szPath, _countof(szPath));
    ret = SheShortenPathW(szPath, bShorten);
    WideCharToMultiByte(CP_ACP, 0, szPath, -1, lpPath, MAX_PATH, NULL, NULL);
    return ret;
}

/*
 * Unimplemented
 */
EXTERN_C INT
WINAPI
SheSetCurDrive(INT iIndex)
{
    FIXME("SheSetCurDrive() stub\n");
    return 1;
}

/*
 * Unimplemented
 */
EXTERN_C INT
WINAPI
SheGetPathOffsetW(LPWSTR lpPath)
{
    FIXME("SheGetPathOffsetW() stub\n");
    return 0;
}

/*
 * Unimplemented
 */
EXTERN_C BOOL
WINAPI
SheGetDirExW(LPWSTR lpDrive,
             LPDWORD lpCurDirLen,
             LPWSTR lpCurDir)
{
    FIXME("SheGetDirExW() stub\n");
    return FALSE;
}

/*
 * Unimplemented
 */
EXTERN_C INT
WINAPI
SheGetCurDrive(VOID)
{
    FIXME("SheGetCurDrive() stub\n");
    return 1;
}

/*
 * Unimplemented
 */
EXTERN_C INT
WINAPI
SheFullPathW(LPWSTR lpFullName, DWORD dwPathSize, LPWSTR lpBuffer)
{
    FIXME("SheFullPathW() stub\n");
    return 0;
}

/*
 * Unimplemented
 */
EXTERN_C INT
WINAPI
SheFullPathA(LPSTR lpFullName, DWORD dwPathSize, LPSTR lpBuffer)
{
    FIXME("SheFullPathA() stub\n");
    return 0;
}

/*
 * Unimplemented
 */
EXTERN_C BOOL
WINAPI
SheConvertPathW(LPWSTR lpCmd, LPWSTR lpFileName, UINT uCmdLen)
{
    FIXME("SheConvertPathW() stub\n");
    return FALSE;
}

/*
 * Unimplemented
 */
EXTERN_C INT
WINAPI
SheChangeDirExW(LPWSTR lpDir)
{
    FIXME("SheChangeDirExW() stub\n");
    return 0;
}

/*
 * Unimplemented
 */
EXTERN_C INT
WINAPI
SheChangeDirExA(LPSTR lpDir)
{
    FIXME("SheChangeDirExA() stub\n");
    return 0;
}

/*
 * Unimplemented
 */
EXTERN_C BOOL
WINAPI
SHInvokePrinterCommandW(HWND hwnd,
                        UINT uAction,
                        LPCWSTR lpBuf1,
                        LPCWSTR lpBuf2,
                        BOOL fModal)
{
    FIXME("SHInvokePrinterCommandW() stub\n");
    return FALSE;
}

/*
 * Unimplemented
 */
EXTERN_C BOOL
WINAPI
SHInvokePrinterCommandA(HWND hwnd,
                        UINT uAction,
                        LPCSTR lpBuf1,
                        LPCSTR lpBuf2,
                        BOOL fModal)
{
    FIXME("SHInvokePrinterCommandA() stub\n");
    return FALSE;
}

/*
 * Unimplemented
 */
EXTERN_C BOOL
WINAPI
SHCreateProcessAsUserW(PSHCREATEPROCESSINFOW pscpi)
{
    FIXME("SHCreateProcessAsUserW() stub\n");
    return FALSE;
}

/*
 * Unimplemented
 */
EXTERN_C VOID
WINAPI
PrintersGetCommand_RunDLL(HWND hwnd, HINSTANCE hInstance, LPWSTR pszCmdLine, int nCmdShow)
{
    FIXME("PrintersGetCommand_RunDLL() stub\n");
}

/*
 * Unimplemented
 */
EXTERN_C VOID
WINAPI
PrintersGetCommand_RunDLLA(HWND hwnd, HINSTANCE hInstance, LPSTR pszCmdLine, int nCmdShow)
{
    FIXME("PrintersGetCommand_RunDLLA() stub\n");
}

/*
 * Unimplemented
 */
EXTERN_C VOID
WINAPI
PrintersGetCommand_RunDLLW(HWND hwnd, HINSTANCE hInstance, LPWSTR pszCmdLine, int nCmdShow)
{
    FIXME("PrintersGetCommand_RunDLLW() stub\n");
}

/*
 * Unimplemented
 */
EXTERN_C IShellFolderViewCB*
WINAPI
SHGetShellFolderViewCB(HWND hwnd)
{
    FIXME("SHGetShellFolderViewCB() stub\n");
    return NULL;
}

/*
 * Unimplemented
 */
EXTERN_C INT
WINAPI
SHLookupIconIndexA(LPCSTR lpName, INT iIndex, UINT uFlags)
{
    FIXME("SHLookupIconIndexA() stub\n");
    return 0;
}

/*
 * Unimplemented
 */
EXTERN_C INT
WINAPI
SHLookupIconIndexW(LPCWSTR lpName, INT iIndex, UINT uFlags)
{
    FIXME("SHLookupIconIndexW() stub\n");
    return 0;
}

/*
 * Unimplemented
 */
EXTERN_C HANDLE
WINAPI
PifMgr_OpenProperties(LPCWSTR lpAppPath, LPCWSTR lpPifPath, UINT hInfIndex, UINT options)
{
    FIXME("PifMgr_OpenProperties() stub\n");
    return 0;
}

/*
 * Unimplemented
 */
EXTERN_C INT
WINAPI
PifMgr_GetProperties(HANDLE hHandle, LPCSTR lpName, LPVOID lpUnknown, INT iUnknown, UINT uUnknown)
{
    FIXME("PifMgr_GetProperties() stub\n");
    return 0;
}

/*
 * Unimplemented
 */
EXTERN_C INT
WINAPI
PifMgr_SetProperties(HANDLE hHandle, LPCSTR lpName, LPCVOID lpUnknown, INT iUnknown, UINT uUnknown)
{
    FIXME("PifMgr_SetProperties() stub\n");
    return 0;
}

/*
 * Unimplemented
 */
EXTERN_C HRESULT
WINAPI
SHStartNetConnectionDialogW(
    _In_ HWND hwnd,
    _In_ LPCWSTR pszRemoteName,
    _In_ DWORD dwType)
{
    /* The Map Network Drive dialog of mpr */
    CONNECTDLGSTRUCTW Dialog;
    NETRESOURCEW Resource;
    DWORD Error;

    ZeroMemory(&Dialog, sizeof(Dialog));
    ZeroMemory(&Resource, sizeof(Resource));
    Resource.dwType = dwType;
    Resource.lpRemoteName = (LPWSTR)pszRemoteName;
    Dialog.cbStructure = sizeof(Dialog);
    Dialog.hwndOwner = hwnd;
    Dialog.lpConnRes = &Resource;
    Error = WNetConnectionDialog1W(&Dialog);
    if (Error == NO_ERROR)
        return S_OK;
    return Error == (DWORD)-1 ? S_FALSE : HRESULT_FROM_WIN32(Error);
}

/*
 * Unimplemented
 */
EXTERN_C HANDLE
WINAPI
PifMgr_CloseProperties(HANDLE hHandle, UINT uUnknown)
{
    FIXME("PifMgr_CloseProperties() stub\n");
    return NULL;
}

/*
 * Unimplemented
 */
EXTERN_C BOOL
WINAPI
DAD_DragEnterEx2(HWND hwndTarget,
                 POINT ptStart,
                 IDataObject *pdtObject)
{
    FIXME("DAD_DragEnterEx2() stub\n");
    return FALSE;
}

/*
 * Unimplemented
 */
EXTERN_C UINT
WINAPI
SHGetNetResource(LPVOID lpUnknown1, UINT iIndex, LPVOID lpUnknown2, UINT cchMax)
{
    FIXME("SHGetNetResource() stub\n");
    return 0;
}

/*
 * Unimplemented
 */
EXTERN_C BOOL
WINAPI
DragQueryInfo(HDROP hDrop, DRAGINFO *pDragInfo)
{
    FIXME("DragQueryInfo() stub\n");
    return FALSE;
}

/*
 * Unimplemented
 */
EXTERN_C LPVOID
WINAPI
DDECreatePostNotify(LPVOID lpUnknown)
{
    FIXME("DDECreatePostNotify() stub\n");
    return NULL;
}

/*
 * Unimplemented
 */
EXTERN_C VOID
WINAPI
AppCompat_RunDLLW(HWND hwnd, HINSTANCE hInstance, LPWSTR pszCmdLine, int nCmdShow)
{
    FIXME("AppCompat_RunDLLW() stub\n");
}

/*
 * Unimplemented
 */
EXTERN_C VOID
WINAPI
Control_RunDLLAsUserW(HWND hwnd, HINSTANCE hInstance, LPWSTR pszCmdLine, int nCmdShow)
{
    FIXME("Control_RunDLLAsUserW() stub\n");
}

/*
 * Unimplemented
 */
EXTERN_C UINT
WINAPI
DragQueryFileAorW(HDROP hDrop, UINT iIndex, LPWSTR lpFile, UINT ucb, BOOL bUnicode, BOOL bShorten)
{
    FIXME("DragQueryFileAorW() stub\n");
    return 0;
}

/*
 * Unimplemented
 */
EXTERN_C DWORD
WINAPI
SHNetConnectionDialog(HWND hwndOwner,
                      LPCWSTR lpstrRemoteName,
                      DWORD dwType)
{
    FIXME("SHNetConnectionDialog() stub\n");
    return ERROR_INVALID_PARAMETER;
}

/*
 * Unimplemented
 */
EXTERN_C BOOL
WINAPI
DAD_SetDragImageFromListView(HWND hwnd, POINT pt)
{
    FIXME("DAD_SetDragImageFromListView() stub\n");
    return FALSE;
}

/*
 * Unimplemented
 */
EXTERN_C void
WINAPI
SHHandleDiskFull(HWND hwndOwner, UINT uDrive)
{
    FIXME("SHHandleDiskFull() stub\n");
}

/*
 * Unimplemented
 */
EXTERN_C BOOL
WINAPI
ILGetPseudoNameW(LPCITEMIDLIST pidl1, LPCITEMIDLIST pidl2, LPWSTR szStr, INT iUnknown)
{
    /* Unimplemented in WinXP SP3 */
    TRACE("ILGetPseudoNameW() stub\n");
    *szStr = 0;
    return FALSE;
}

/*
 * Unimplemented
 */
EXTERN_C VOID
WINAPI
SHGlobalDefect(DWORD dwUnknown)
{
    /* Unimplemented in WinXP SP3 */
    TRACE("SHGlobalDefect() stub\n");
}

/*
 * Unimplemented
 */
EXTERN_C LPITEMIDLIST
WINAPI
Printers_GetPidl(LPCITEMIDLIST pidl, LPCWSTR lpName, DWORD dwUnknown1, DWORD dwUnknown2)
{
    FIXME("Printers_GetPidl() stub\n");
    return NULL;
}

/*
 * Unimplemented
 */
EXTERN_C LONG
WINAPI
Printers_AddPrinterPropPages(LPVOID lpUnknown1, LPVOID lpUnknown2)
{
    FIXME("Printers_AddPrinterPropPages() stub\n");
    return 0;
}

/*
 * Unimplemented
 */
EXTERN_C WORD
WINAPI
ExtractIconResInfoW(
    _In_ HANDLE hHandle,
    _In_ LPCWSTR lpFileName,
    _In_ WORD wIndex,
    _Out_ LPWORD lpSize,
    _Out_ LPHANDLE lpIcon)
{
    FIXME("ExtractIconResInfoW() stub\n");
    return 0;
}

/*
 * Unimplemented
 */
EXTERN_C DWORD
WINAPI
ExtractVersionResource16W(LPWSTR lpName, LPHANDLE lpHandle)
{
    FIXME("ExtractVersionResource16W() stub\n");
    return 0;
}

/*
 * Unimplemented
 */
EXTERN_C BOOL*
WINAPI
FindExeDlgProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    FIXME("FindExeDlgProc() stub\n");
    return 0;
}

/*
 * Unimplemented
 */
EXTERN_C HANDLE
WINAPI
InternalExtractIconListW(HANDLE hHandle,
                         LPWSTR lpFileName,
                         LPINT lpCount)
{
    FIXME("InternalExtractIconListW() stub\n");
    return NULL;
}

/*
 * Unimplemented
 */
EXTERN_C HANDLE
WINAPI
InternalExtractIconListA(HANDLE hHandle,
                         LPSTR lpFileName,
                         LPINT lpCount)
{
    FIXME("InternalExtractIconListA() stub\n");
    return NULL;
}

/*
 * Unimplemented
 */
EXTERN_C HRESULT
WINAPI
FirstUserLogon(LPWSTR lpUnknown1, LPWSTR lpUnknown2)
{
    FIXME("FirstUserLogon() stub\n");
    return E_FAIL;
}

/*
 * Unimplemented
 */
EXTERN_C HRESULT
WINAPI
SHSetFolderPathW(
    _In_ INT csidl,
    _In_ HANDLE hToken,
    _In_ DWORD dwFlags,
    _In_ LPCWSTR pszPath)
{
    FIXME("SHSetFolderPathW() stub\n");
    return E_FAIL;
}

/*
 * Unimplemented
 */
EXTERN_C HRESULT
WINAPI
SHGetUserPicturePathW(LPCWSTR lpPath, int csidl, LPVOID lpUnknown)
{
    FIXME("SHGetUserPicturePathW() stub\n");
    return E_FAIL;
}

/*
 * Unimplemented
 */
EXTERN_C HRESULT
WINAPI
SHSetUserPicturePathW(LPCWSTR lpPath, int csidl, LPVOID lpUnknown)
{
    FIXME("SHGetUserPicturePathA() stub\n");
    return E_FAIL;
}

/*
 * Unimplemented
 */
EXTERN_C DWORD
WINAPI
SHGetProcessDword(DWORD dwUnknown1, DWORD dwUnknown2)
{
    /* Unimplemented in WinXP SP3 */
    TRACE("SHGetProcessDword() stub\n");
    return 0;
}

EXTERN_C
DWORD WINAPI CheckStagingArea(VOID)
{
    /* Called by native explorer */
    return 0;
}

/*
 * Unimplemented
 */

EXTERN_C HRESULT
WINAPI
GetAppPathFromLink(IShellItem* pItem,
                   LPWSTR pwszPathBuffer,
                   DWORD dwBufferLen)
{
    FIXME("GetAppPathFromLink() stub\n");
    return S_OK;
}

/*
 * Unimplemented
 */
EXTERN_C HRESULT
WINAPI
GetCurrentProcessExplicitAppUserModelID(PWSTR *AppID)
{
    return SHStrDupW(L"ROS FixMe", AppID);
}

/*
 * Unimplemented
 */
HRESULT WINAPI
SetCurrentProcessExplicitAppUserModelID(PCWSTR AppID)
{
    FIXME("SetCurrentProcessExplicitAppUserModelID stub\n");
    return S_OK;
}

/*
 * Unimplemented
 */
EXTERN_C DWORD
WINAPI
RunInstallUninstallStubs(VOID)
{
    FIXME("RunInstallUninstallStubs() stub!\n");
    return 0;
}

/*
 * Unimplemented
 */
EXTERN_C HRESULT
WINAPI
SHQueryUserNotificationState(QUERY_USER_NOTIFICATION_STATE *pquns)
{
    FIXME("SHQueryUserNotificationState() stub\n");
    if (!pquns)
        return E_INVALIDARG;
    *pquns = QUNS_ACCEPTS_NOTIFICATIONS;
    return S_OK;
}

/*
 * NT 6 exports that used to be raising stubs (EXCEPTION_WINE_STUB killed every caller).
 * They are not implemented: each one fails with the documented error and clears its outputs.
 */

/*
 * Unimplemented
 */
EXTERN_C VOID
WINAPI
PrepareDiscForBurnRunDllW(HWND hwnd, HINSTANCE hInstance, LPWSTR pszCmdLine, INT nCmdShow)
{
    FIXME("PrepareDiscForBurnRunDllW(%p, %p, %s, %d) stub\n", hwnd, hInstance, debugstr_w(pszCmdLine), nCmdShow);
}

/*
 * Unimplemented
 */
EXTERN_C HRESULT
WINAPI
AssocCreateForClasses(const VOID *rgClasses, ULONG cClasses, REFIID riid, PVOID *ppv)
{
    FIXME("AssocCreateForClasses(%p, %lu, %s, %p) stub\n", rgClasses, cClasses, debugstr_guid(&riid), ppv);
    if (ppv)
        *ppv = NULL;
    return E_NOTIMPL;
}

/*
 * Unimplemented
 */
EXTERN_C HRESULT
WINAPI
AssocGetDetailsOfPropKey(IShellFolder *psf, PCUITEMID_CHILD pidl, const PROPERTYKEY *pkey,
                         VARIANT *pv, BOOL *pfFoundPropKey)
{
    FIXME("AssocGetDetailsOfPropKey(%p, %p, %p, %p, %p) stub\n", psf, pidl, pkey, pv, pfFoundPropKey);
    if (pv)
        VariantInit(pv);
    if (pfFoundPropKey)
        *pfFoundPropKey = FALSE;
    return E_NOTIMPL;
}

/*
 * Unimplemented
 */
EXTERN_C BOOL
WINAPI
InitNetworkAddressControl(VOID)
{
    FIXME("InitNetworkAddressControl() stub\n");
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return FALSE;
}

/*
 * Unimplemented
 */
EXTERN_C HRESULT
WINAPI
SHAddDefaultPropertiesByExt(PCWSTR pszExt, IPropertyStore *pPropStore)
{
    FIXME("SHAddDefaultPropertiesByExt(%s, %p) stub\n", debugstr_w(pszExt), pPropStore);
    return E_NOTIMPL;
}

/*
 * Unimplemented
 */
EXTERN_C HRESULT
WINAPI
SHAssocEnumHandlers(PCWSTR pszExtra, ASSOC_FILTER afFilter, IEnumAssocHandlers **ppEnumHandler)
{
    FIXME("SHAssocEnumHandlers(%s, 0x%x, %p) stub\n", debugstr_w(pszExtra), afFilter, ppEnumHandler);
    if (ppEnumHandler)
        *ppEnumHandler = NULL;
    return E_NOTIMPL;
}

/*
 * Unimplemented
 */
EXTERN_C HRESULT
WINAPI
SHAssocEnumHandlersForProtocolByApplication(PCWSTR protocol, REFIID riid, PVOID *enumHandlers)
{
    FIXME("SHAssocEnumHandlersForProtocolByApplication(%s, %s, %p) stub\n",
          debugstr_w(protocol), debugstr_guid(&riid), enumHandlers);
    if (enumHandlers)
        *enumHandlers = NULL;
    return E_NOTIMPL;
}

/*
 * Unimplemented
 */
EXTERN_C VOID
WINAPI
SHChangeNotifyRegisterThread(INT status)
{
    FIXME("SHChangeNotifyRegisterThread(%d) stub\n", status);
}

/*
 * Unimplemented
 */
EXTERN_C HRESULT
WINAPI
SHCreateDefaultPropertiesOp(IShellItem *psi, IFileOperation **ppFileOp)
{
    FIXME("SHCreateDefaultPropertiesOp(%p, %p) stub\n", psi, ppFileOp);
    if (ppFileOp)
        *ppFileOp = NULL;
    return E_NOTIMPL;
}

/*
 * Unimplemented
 */
EXTERN_C VOID
WINAPI
SHCreateLocalServerRunDll(HWND hwnd, HINSTANCE hInstance, LPSTR pszCmdLine, INT nCmdShow)
{
    FIXME("SHCreateLocalServerRunDll(%p, %p, %s, %d) stub\n", hwnd, hInstance, debugstr_a(pszCmdLine), nCmdShow);
}

/*
 * Unimplemented
 */
EXTERN_C HRESULT
WINAPI
SHEnableServiceObject(REFCLSID rclsid, BOOL fEnable)
{
    FIXME("SHEnableServiceObject(%s, %d) stub\n", debugstr_guid(&rclsid), fEnable);
    return E_NOTIMPL;
}

/*
 * Unimplemented
 */
EXTERN_C HRESULT
WINAPI
SHGetDriveMedia(PCWSTR pszDrive, DWORD *pdwMediaContent)
{
    FIXME("SHGetDriveMedia(%s, %p) stub\n", debugstr_w(pszDrive), pdwMediaContent);
    if (pdwMediaContent)
        *pdwMediaContent = 0;
    return E_NOTIMPL;
}

/*
 * Unimplemented
 */
EXTERN_C HRESULT
WINAPI
SHGetTemporaryPropertyForItem(IShellItem *psi, REFPROPERTYKEY propkey, PROPVARIANT *ppropvar)
{
    FIXME("SHGetTemporaryPropertyForItem(%p, %p, %p) stub\n", psi, &propkey, ppropvar);
    if (ppropvar)
        PropVariantInit(ppropvar);
    return E_NOTIMPL;
}

/*
 * Unimplemented
 */
EXTERN_C HRESULT
WINAPI
SHSetTemporaryPropertyForItem(IShellItem *psi, REFPROPERTYKEY propkey, REFPROPVARIANT propvar)
{
    FIXME("SHSetTemporaryPropertyForItem(%p, %p, %p) stub\n", psi, &propkey, &propvar);
    return E_NOTIMPL;
}

/*
 * Unimplemented
 */
EXTERN_C HRESULT
WINAPI
SHSetDefaultProperties(HWND hwnd, IShellItem *psi, DWORD dwFileOpFlags, IFileOperationProgressSink *pfops)
{
    FIXME("SHSetDefaultProperties(%p, %p, 0x%lx, %p) stub\n", hwnd, psi, dwFileOpFlags, pfops);
    return E_NOTIMPL;
}

/*
 * Unimplemented
 */
EXTERN_C VOID
WINAPI
WaitForExplorerRestartW(HWND hwnd, HINSTANCE hInstance, LPWSTR pszCmdLine, INT nCmdShow)
{
    FIXME("WaitForExplorerRestartW(%p, %p, %s, %d) stub\n", hwnd, hInstance, debugstr_w(pszCmdLine), nCmdShow);
}

/*
 * Unimplemented
 */
EXTERN_C HRESULT
WINAPI
StgMakeUniqueName(IStorage *pstgParent, PCWSTR pszFileSpec, DWORD grfMode, REFIID riid, PVOID *ppv)
{
    FIXME("StgMakeUniqueName(%p, %s, 0x%lx, %s, %p) stub\n", pstgParent, debugstr_w(pszFileSpec), grfMode,
          debugstr_guid(&riid), ppv);
    if (ppv)
        *ppv = NULL;
    return E_NOTIMPL;
}

typedef struct _NOTIFYICONIDENTIFIER_
{
    DWORD cbSize;
    HWND hWnd;
    UINT uID;
    GUID guidItem;
} NOTIFYICONIDENTIFIER_;

/*
 * Unimplemented: the tray does not report icon positions, so no icon is ever found
 */
EXTERN_C HRESULT
WINAPI
Shell_NotifyIconGetRect(const NOTIFYICONIDENTIFIER_ *identifier, RECT *iconLocation)
{
    FIXME("Shell_NotifyIconGetRect(%p, %p) stub\n", identifier, iconLocation);
    if (!identifier || !iconLocation)
        return E_POINTER;
    SetRectEmpty(iconLocation);
    if (identifier->cbSize != sizeof(*identifier))
        return E_INVALIDARG;
    return E_FAIL;
}
