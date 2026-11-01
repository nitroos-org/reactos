
#define STANDALONE
#include <apitest.h>

extern void func_AttachThreadInput(void);
extern void func_AttachThreadInputQueue(void);
extern void func_AutoRotation(void);
extern void func_CharFuncs(void);
extern void func_CloseWindow(void);
extern void func_CopyImage(void);
extern void func_CalculatePopupWindowPosition(void);
extern void func_CreateDialog(void);
extern void func_CreateIconFromResourceEx(void);
extern void func_CreateWindowEx(void);
extern void func_DeferWindowPos(void);
extern void func_DestroyCursorIcon(void);
extern void func_DM_REPOSITION(void);
extern void func_DpiFunctions(void);
extern void func_DpiProcess(void);
extern void func_DrawIconEx(void);
extern void func_DrawText(void);
extern void func_EditInk(void);
extern void func_desktop(void);
extern void func_DesktopHeapNonInteractive(void);
extern void func_ClipboardFormatListener(void);
extern void func_ClipboardSynthBitmap(void);
extern void func_ConsoleClipText(void);
extern void func_EmptyClipboard(void);
extern void func_EnumDisplayDevices(void);
extern void func_EnumDisplaySettings(void);
extern void func_FrameChangedClient(void);
extern void func_FrameMetrics(void);
extern void func_FramelessCaptionDrag(void);
extern void func_GetClassInfo(void);
extern void func_GetDCEx(void);
extern void func_GetIconInfo(void);
extern void func_GetKeyState(void);
extern void func_GetMessageTime(void);
extern void func_GetPeekMessage(void);
extern void func_GetSetWindowInt(void);
extern void func_GetSystemMetrics(void);
extern void func_GetUpdatedClipboardFormats(void);
extern void func_GetUserObjectInformation(void);
extern void func_GetWindowPlacement(void);
extern void func_GW_ENABLEDPOPUP(void);
extern void func_Handle32(void);
extern void func_HookChainUnhookUaf(void);
extern void func_HookFamilies(void);
extern void func_HungWindow(void);
extern void func_InitializeLpkHooks(void);
extern void func_IsDialogMessage(void);
extern void func_IsServerSideWindow(void);
extern void func_IsWindowArranged(void);
extern void func_KbdLayout(void);
extern void func_keybd_event(void);
extern void func_MouseHookTransport(void);
extern void func_MouseWheel(void);
extern void func_KeyboardLLHook(void);
extern void func_LoadImage(void);
extern void func_LoadImageGCC(void);
extern void func_LoadImagePngIcon(void);
extern void func_LookupIconIdFromDirectoryEx(void);
extern void func_MenuItemData(void);
extern void func_MenuUI(void);
extern void func_MessageStateAnalyzer(void);
extern void func_MsgWaitForMultipleObjectsEx(void);
extern void func_NCRButtonDown(void);
extern void func_NcPaintActive(void);
extern void func_NcPaintClient(void);
extern void func_NcPaintRgn(void);
extern void func_NextDlgItem(void);
extern void func_PrintWindow(void);
extern void func_PrivateExtractIcons(void);
extern void func_ProcessConnectTerminate(void);
extern void func_RawInput(void);
extern void func_RealGetWindowClass(void);
extern void func_RedrawWindow(void);
extern void func_RegisterHotKey(void);
extern void func_RegisterClassEx(void);
extern void func_ScrollBarRedraw(void);
extern void func_ScrollBarWndExtra(void);
extern void func_ScrollDC(void);
extern void func_ScrollWindowEx(void);
extern void func_SendMessageCallbackSenderDied(void);
extern void func_SendMessageSenderDied(void);
extern void func_SendMessageTimeout(void);
extern void func_SetActiveWindow(void);
extern void func_SetCoalescableTimer(void);
extern void func_SetCursorPos(void);
extern void func_SetFocus(void);
extern void func_SetParent(void);
extern void func_SetProp(void);
extern void func_SetScrollInfo(void);
extern void func_SetScrollRange(void);
extern void func_SetWindowPlacement(void);
extern void func_SetWindowPosOwned(void);
extern void func_ShowWindow(void);
extern void func_ShowWindowFrame(void);
extern void func_SwitchDesktop(void);
extern void func_SuspendResumeNotification(void);
extern void func_SwitchToThisWindow(void);
extern void func_SysCommandHidden(void);
extern void func_SystemParametersInfo(void);
extern void func_SystemMenu(void);
extern void func_TrackMouseEvent(void);
extern void func_TrackPopupMenuEx(void);
extern void func_UnicodeToAnsiMessage(void);
extern void func_UpdateLayeredWindow(void);
extern void func_UserHandleGrantAccess(void);
extern void func_VirtualKey(void);
extern void func_WinEventHook(void);
extern void func_WmPrint(void);
extern void func_WndProc(void);
extern void func_Win8User(void);
extern void func_PhysicalCoords(void);
extern void func_DialogDpiBehavior(void);
extern void func_GetIconInfoEx(void);
extern void func_CreateDesktopEx(void);
extern void func_DesktopHeapLeak(void);
extern void func_ShutdownBlockReason(void);
extern void func_PointerDeviceFunctions(void);
extern void func_wsprintfApi(void);

const struct test winetest_testlist[] =
{
    { "AttachThreadInput", func_AttachThreadInput },
    { "AttachThreadInputQueue", func_AttachThreadInputQueue },
    { "AutoRotation", func_AutoRotation },
    { "CharFuncs", func_CharFuncs },
    { "CloseWindow", func_CloseWindow },
    { "CopyImage", func_CopyImage },
    { "CalculatePopupWindowPosition", func_CalculatePopupWindowPosition },
    { "CreateDialog", func_CreateDialog },
    { "CreateIconFromResourceEx", func_CreateIconFromResourceEx },
    { "CreateWindowEx", func_CreateWindowEx },
    { "DeferWindowPos", func_DeferWindowPos },
    { "DestroyCursorIcon", func_DestroyCursorIcon },
    { "DM_REPOSITION", func_DM_REPOSITION },
    { "DpiFunctions", func_DpiFunctions },
    { "DpiProcess", func_DpiProcess },
    { "DrawIconEx", func_DrawIconEx },
    { "DrawText", func_DrawText },
    { "EditInk", func_EditInk },
    { "desktop", func_desktop },
    { "DesktopHeapNonInteractive", func_DesktopHeapNonInteractive },
    { "ClipboardFormatListener", func_ClipboardFormatListener },
    { "ClipboardSynthBitmap", func_ClipboardSynthBitmap },
    { "ConsoleClipText", func_ConsoleClipText },
    { "EmptyClipboard", func_EmptyClipboard },
    { "EnumDisplayDevices", func_EnumDisplayDevices },
    { "EnumDisplaySettings", func_EnumDisplaySettings },
    { "FrameChangedClient", func_FrameChangedClient },
    { "FrameMetrics", func_FrameMetrics },
    { "FramelessCaptionDrag", func_FramelessCaptionDrag },
    { "GetClassInfo", func_GetClassInfo },
    { "GetDCEx", func_GetDCEx },
    { "GetIconInfo", func_GetIconInfo },
    { "GetKeyState", func_GetKeyState },
    { "GetMessageTime", func_GetMessageTime },
    { "GetPeekMessage", func_GetPeekMessage },
    { "GetSetWindowInt", func_GetSetWindowInt },
    { "GetSystemMetrics", func_GetSystemMetrics },
    { "GetUpdatedClipboardFormats", func_GetUpdatedClipboardFormats },
    { "GetUserObjectInformation", func_GetUserObjectInformation },
    { "GetWindowPlacement", func_GetWindowPlacement },
    { "GW_ENABLEDPOPUP", func_GW_ENABLEDPOPUP },
    { "Handle32", func_Handle32 },
    { "HookChainUnhookUaf", func_HookChainUnhookUaf },
    { "HookFamilies", func_HookFamilies },
    { "HungWindow", func_HungWindow },
    { "InitializeLpkHooks", func_InitializeLpkHooks },
    { "IsDialogMessage", func_IsDialogMessage },
    { "IsServerSideWindow", func_IsServerSideWindow },
    { "IsWindowArranged", func_IsWindowArranged },
    { "KbdLayout", func_KbdLayout },
    { "keybd_event", func_keybd_event },
    { "MouseHookTransport", func_MouseHookTransport },
    { "MouseWheel", func_MouseWheel },
    { "KeyboardLLHook", func_KeyboardLLHook },
    { "LoadImage", func_LoadImage },
    { "LoadImageGCC", func_LoadImageGCC },
    { "LoadImagePngIcon", func_LoadImagePngIcon },
    { "LookupIconIdFromDirectoryEx", func_LookupIconIdFromDirectoryEx },
    { "MenuItemData", func_MenuItemData },
    { "MenuUI", func_MenuUI },
    { "MessageStateAnalyzer", func_MessageStateAnalyzer },
    { "MsgWaitForMultipleObjectsEx", func_MsgWaitForMultipleObjectsEx },
    { "NCRButtonDown", func_NCRButtonDown },
    { "NcPaintActive", func_NcPaintActive },
    { "NcPaintClient", func_NcPaintClient },
    { "NcPaintRgn", func_NcPaintRgn },
    { "NextDlgItem", func_NextDlgItem },
    { "PrintWindow", func_PrintWindow },
    { "PrivateExtractIcons", func_PrivateExtractIcons },
    { "ProcessConnectTerminate", func_ProcessConnectTerminate },
    { "RawInput", func_RawInput },
    { "RealGetWindowClass", func_RealGetWindowClass },
    { "RedrawWindow", func_RedrawWindow },
    { "RegisterHotKey", func_RegisterHotKey },
    { "RegisterClassEx", func_RegisterClassEx },
    { "ScrollBarRedraw", func_ScrollBarRedraw },
    { "ScrollBarWndExtra", func_ScrollBarWndExtra },
    { "ScrollDC", func_ScrollDC },
    { "ScrollWindowEx", func_ScrollWindowEx },
    { "SendMessageCallbackSenderDied", func_SendMessageCallbackSenderDied },
    { "SendMessageSenderDied", func_SendMessageSenderDied },
    { "SendMessageTimeout", func_SendMessageTimeout },
    { "SetActiveWindow", func_SetActiveWindow },
    { "SetCoalescableTimer", func_SetCoalescableTimer },
    { "SetCursorPos", func_SetCursorPos },
    { "SetFocus", func_SetFocus },
    { "SetParent", func_SetParent },
    { "SetProp", func_SetProp },
    { "SetScrollInfo", func_SetScrollInfo },
    { "SetScrollRange", func_SetScrollRange },
    { "SetWindowPlacement", func_SetWindowPlacement },
    { "SetWindowPosOwned", func_SetWindowPosOwned },
    { "ShowWindow", func_ShowWindow },
    { "ShowWindowFrame", func_ShowWindowFrame },
    { "SwitchDesktop", func_SwitchDesktop },
    { "SuspendResumeNotification", func_SuspendResumeNotification },
    { "SwitchToThisWindow", func_SwitchToThisWindow },
    { "SysCommandHidden", func_SysCommandHidden },
    { "SystemMenu", func_SystemMenu },
    { "SystemParametersInfo", func_SystemParametersInfo },
    { "TrackMouseEvent", func_TrackMouseEvent },
    { "TrackPopupMenuEx", func_TrackPopupMenuEx },
    { "UnicodeToAnsiMessage", func_UnicodeToAnsiMessage },
    { "UpdateLayeredWindow", func_UpdateLayeredWindow },
    { "UserHandleGrantAccess", func_UserHandleGrantAccess },
    { "VirtualKey", func_VirtualKey },
    { "Win8User", func_Win8User },
    { "PhysicalCoords", func_PhysicalCoords },
    { "DialogDpiBehavior", func_DialogDpiBehavior },
    { "GetIconInfoEx", func_GetIconInfoEx },
    { "CreateDesktopEx", func_CreateDesktopEx },
    { "DesktopHeapLeak", func_DesktopHeapLeak },
    { "ShutdownBlockReason", func_ShutdownBlockReason },
    { "PointerDeviceFunctions", func_PointerDeviceFunctions },
    { "WinEventHook", func_WinEventHook },
    { "WmPrint", func_WmPrint },
    { "WndProc", func_WndProc },
    { "wsprintfApi", func_wsprintfApi },
    { 0, 0 }
};

