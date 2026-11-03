
#define STANDALONE
#include <wine/test.h>

extern void func_AddCommas(void);
extern void func_AssocCreateElement(void);
extern void func_Control_RunDLLW(void);
extern void func_CFSFolder(void);
extern void func_CFolderItems(void);
extern void func_CFontsFolder(void);
extern void func_CheckEscapes(void);
extern void func_CIDLData(void);
extern void func_CKnownFolderManager(void);
extern void func_CMyComputer(void);
extern void func_CommandLineToArgvW(void);
extern void func_CShellDesktop(void);
extern void func_CShellDispatch(void);
extern void func_CShellItem(void);
extern void func_CShellLink(void);
extern void func_CShellLinkPropertyStore(void);
extern void func_CUserNotification(void);
extern void func_DragDrop(void);
extern void func_DriveTools(void);
extern void func_ExtractIconEx(void);
extern void func_FindExecutable(void);
extern void func_FormerStubs(void);
extern void func_GetDisplayNameOf(void);
extern void func_GUIDFromString(void);
extern void func_ILCreateFromPath(void);
extern void func_ILIsEqual(void);
extern void func_Int64ToString(void);
extern void func_ApplicationActivationManager(void);
extern void func_IApplicationAssociationRegistration(void);
extern void func_UserChoiceHandlers(void);
extern void func_IFileOperation(void);
extern void func_IDestinationList(void);
extern void func_IQueryAssociations(void);
extern void func_IShellFolderViewCB(void);
extern void func_LockServer(void);
extern void func_menu(void);
extern void func_OpenAs_RunDLL(void);
extern void func_PathIsEqualOrSubFolder(void);
extern void func_PathIsSlow(void);
extern void func_PathIsTemporary(void);
extern void func_PathMakeUniqueName(void);
extern void func_PathProcessCommand(void);
extern void func_PathResolve(void);
extern void func_ProfileListAccess(void);
extern void func_PIDL(void);
extern void func_RealShellExecuteEx(void);
extern void func_RegenerateUserEnvironment(void);
extern void func_SHAppBarMessage(void);
extern void func_SHChangeNotify(void);
extern void func_SHCreateDataObject(void);
extern void func_SHCreateSessionKey(void);
extern void func_SHCreateFileDataObject(void);
extern void func_SHCreateFileExtractIconW(void);
extern void func_SHDefExtractIcon(void);
extern void func_SHEnumerateUnreadMailAccountsW(void);
extern void func_SHEmptyRecycleBin(void);
extern void func_SHEvaluateSystemCommandTemplate(void);
extern void func_She(void);
extern void func_ShellExec_RunDLL(void);
extern void func_ShellExecCmdLine(void);
extern void func_ShellExecuteEx(void);
extern void func_ShellExecuteExLnk(void);
extern void func_ShellExecuteRunAs(void);
extern void func_ShellExecuteLinkDir(void);
extern void func_ShellExecuteW(void);
extern void func_ShellFolder(void);
extern void func_ShellHook(void);
extern void func_ShellState(void);
extern void func_SHGetAttributesFromDataObject(void);
extern void func_SHGetComputerDisplayNameW(void);
extern void func_SHGetPropertyStoreForWindow(void);
extern void func_SHGetFileInfo(void);
extern void func_SHBindToFolderIDListParent(void);
extern void func_SHGetKnownFolderPath(void);
extern void func_SHGetPathFromIDListEx(void);
extern void func_SHGetStockIconInfo(void);
extern void func_SHGetNewLinkInfo(void);
extern void func_SHGetUnreadMailCountW(void);
extern void func_SHGetUserDisplayName(void);
extern void func_SHIsBadInterfacePtr(void);
extern void func_SHLimitInputEdit(void);
extern void func_SHParseDisplayName(void);
extern void func_SHShouldShowWizards(void);
extern void func_SHSimpleIDListFromPath(void);
extern void func_SHRestricted(void);
extern void func_SHSetUnreadMailCountW(void);
extern void func_StrRStr(void);
extern void func_TaskbarFullscreen(void);

const struct test winetest_testlist[] =
{
    { "AddCommas", func_AddCommas },
    { "AssocCreateElement", func_AssocCreateElement },
    { "Control_RunDLLW", func_Control_RunDLLW },
    { "CFSFolder", func_CFSFolder },
    { "CFolderItems", func_CFolderItems },
    { "CFontsFolder", func_CFontsFolder },
    { "CheckEscapes", func_CheckEscapes },
    { "CIDLData", func_CIDLData },
    { "CKnownFolderManager", func_CKnownFolderManager },
    { "CMyComputer", func_CMyComputer },
    { "CommandLineToArgvW", func_CommandLineToArgvW },
    { "CShellDesktop", func_CShellDesktop },
    { "CShellDispatch", func_CShellDispatch },
    { "CShellItem", func_CShellItem },
    { "CShellLink", func_CShellLink },
    { "CShellLinkPropertyStore", func_CShellLinkPropertyStore },
    //{ "CUserNotification", func_CUserNotification }, // Test is broken on Win 2003
    { "DragDrop", func_DragDrop },
    { "DriveTools", func_DriveTools },
    { "ExtractIconEx", func_ExtractIconEx },
    { "FindExecutable", func_FindExecutable },
    { "FormerStubs", func_FormerStubs },
    { "GetDisplayNameOf", func_GetDisplayNameOf },
    { "GUIDFromString", func_GUIDFromString },
    { "ILCreateFromPath", func_ILCreateFromPath },
    { "ILIsEqual", func_ILIsEqual },
    { "Int64ToString", func_Int64ToString },
    { "ApplicationActivationManager", func_ApplicationActivationManager },
    { "IApplicationAssociationRegistration", func_IApplicationAssociationRegistration },
    { "UserChoiceHandlers", func_UserChoiceHandlers },
    { "IFileOperation", func_IFileOperation },
    { "IDestinationList", func_IDestinationList },
    { "IQueryAssociations", func_IQueryAssociations },
    { "IShellFolderViewCB", func_IShellFolderViewCB },
    { "LockServer", func_LockServer },
    { "menu", func_menu },
    //{ "OpenAs_RunDLL", func_OpenAs_RunDLL }, // Test hangs on Win 2003
    { "PathIsEqualOrSubFolder", func_PathIsEqualOrSubFolder },
    { "PathIsSlow", func_PathIsSlow },
    { "PathIsTemporary", func_PathIsTemporary },
    { "PathMakeUniqueName", func_PathMakeUniqueName },
    { "PathProcessCommand", func_PathProcessCommand },
    { "PathResolve", func_PathResolve },
    { "ProfileListAccess", func_ProfileListAccess },
    { "PIDL", func_PIDL },
    { "RealShellExecuteEx", func_RealShellExecuteEx },
    { "RegenerateUserEnvironment", func_RegenerateUserEnvironment },
    { "SHAppBarMessage", func_SHAppBarMessage },
    { "SHChangeNotify", func_SHChangeNotify },
    { "SHCreateDataObject", func_SHCreateDataObject },
    { "SHCreateSessionKey", func_SHCreateSessionKey },
    { "SHCreateFileDataObject", func_SHCreateFileDataObject },
    { "SHCreateFileExtractIconW", func_SHCreateFileExtractIconW },
    { "SHDefExtractIcon", func_SHDefExtractIcon },
    { "SHEnumerateUnreadMailAccountsW", func_SHEnumerateUnreadMailAccountsW },
    { "SHEmptyRecycleBin", func_SHEmptyRecycleBin },
    { "SHEvaluateSystemCommandTemplate", func_SHEvaluateSystemCommandTemplate },
    { "She", func_She },
    //{ "ShellExec_RunDLL", func_ShellExec_RunDLL }, Broke on Windows
    //{ "ShellExecCmdLine", func_ShellExecCmdLine }, Broke on Windows
    { "ShellExecuteEx", func_ShellExecuteEx }, // Mostly broken on Windows, only simple tests enabled
    { "ShellExecuteExLnk", func_ShellExecuteExLnk },
    { "ShellExecuteRunAs", func_ShellExecuteRunAs },
    //{ "ShellExecuteW", func_ShellExecuteW }, Broke on Windows
    { "ShellExecuteLinkDir", func_ShellExecuteLinkDir },
    { "ShellFolder", func_ShellFolder },
    { "ShellHook", func_ShellHook },
    { "ShellState", func_ShellState },
    { "SHGetAttributesFromDataObject", func_SHGetAttributesFromDataObject },
    { "SHGetComputerDisplayNameW", func_SHGetComputerDisplayNameW },
    { "SHGetPropertyStoreForWindow", func_SHGetPropertyStoreForWindow },
    { "SHGetFileInfo", func_SHGetFileInfo },
    { "SHBindToFolderIDListParent", func_SHBindToFolderIDListParent },
    { "SHGetKnownFolderPath", func_SHGetKnownFolderPath },
    { "SHGetPathFromIDListEx", func_SHGetPathFromIDListEx },
    { "SHGetStockIconInfo", func_SHGetStockIconInfo },
    { "SHGetNewLinkInfo", func_SHGetNewLinkInfo },
    { "SHGetUnreadMailCountW", func_SHGetUnreadMailCountW },
    { "SHGetUserDisplayName", func_SHGetUserDisplayName },
    { "SHIsBadInterfacePtr", func_SHIsBadInterfacePtr },
    { "SHLimitInputEdit", func_SHLimitInputEdit },
    { "SHParseDisplayName", func_SHParseDisplayName },
    { "SHShouldShowWizards", func_SHShouldShowWizards },
    { "SHSimpleIDListFromPath", func_SHSimpleIDListFromPath },
    { "SHRestricted", func_SHRestricted },
    { "SHSetUnreadMailCountW", func_SHSetUnreadMailCountW },
    { "StrRStr", func_StrRStr },
    { "TaskbarFullscreen", func_TaskbarFullscreen },

    { 0, 0 }
};
