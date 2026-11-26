
#define STANDALONE
#include <apitest.h>

extern void func_AttachThreadInput(void);
extern void func_AttachThreadInputQueue(void);
extern void func_AniEmpty(void);
extern void func_AniMalformed(void);
extern void func_AutoRotation(void);
extern void func_BroadcastHung(void);
extern void func_LifetimeActivePrevFreed(void);
extern void func_LifetimeAttachSharedQueue(void);
extern void func_LifetimeBeingActivatedExit(void);
extern void func_LifetimeBroadcastDesktops(void);
extern void func_LifetimeBroadcastListExitLeak(void);
extern void func_LifetimeCallbackExitLeak(void);
extern void func_LifetimeCaptureWinEvent(void);
extern void func_LifetimeCbtActivateRecursion(void);
extern void func_LifetimeEventProcExitThread(void);
extern void func_LifetimeForegroundWinEvent(void);
extern void func_LifetimeCreateNameExitLeak(void);
extern void func_LifetimeDesktopHeldDelete(void);
extern void func_LifetimeDesktopKeptByMenus(void);
extern void func_LifetimeDesktopSenderHeld(void);
extern void func_LifetimeFreeExitClass(void);
extern void func_LifetimeHookExitLeak(void);
extern void func_LifetimeHookNamesExitLeak(void);
extern void func_LifetimeImcOtherThreadEnds(void);
extern void func_LifetimeImeWindowGoneInNotify(void);
extern void func_LifetimeInfoCallbacks(void);
extern void func_LifetimeKeyboardLayoutWalk(void);
extern void func_LifetimeLayoutSenderEnds(void);
extern void func_LifetimeOtherDesktopOwner(void);
extern void func_LifetimeOwnerDestroyRace(void);
extern void func_LifetimeOwnerReparentedFreed(void);
extern void func_LifetimeSendSenderEnds(void);
extern void func_LifetimeSenderCopyTerminated(void);
extern void func_LifetimeSentCopyExitLeak(void);
extern void func_LifetimeSetActiveHookAttach(void);
extern void func_LifetimeSetFocusTopDestroy(void);
extern void func_LifetimeWinEventUnhook(void);
extern void func_LifetimeWindowListExitLeak(void);
extern void func_CharFuncs(void);
extern void func_ClassDCThreadExit(void);
extern void func_CloseWindow(void);
extern void func_CopyImage(void);
extern void func_CalculatePopupWindowPosition(void);
extern void func_ChangeDisplaySettings(void);
extern void func_CreateDialog(void);
extern void func_CreateIconFromResourceEx(void);
extern void func_CreateWindowEx(void);
extern void func_DeferWindowPos(void);
extern void func_DestroyCursorIcon(void);
extern void func_DestroyCurrentCursor(void);
extern void func_DM_REPOSITION(void);
extern void func_DpiFunctions(void);
extern void func_DpiProcess(void);
extern void func_DrawIconEx(void);
extern void func_DrawText(void);
extern void func_EditChildUserObjects(void);
extern void func_EditInk(void);
extern void func_desktop(void);
extern void func_DesktopHeapNonInteractive(void);
extern void func_DesktopOtherThreadApis(void);
extern void func_ClipboardFormatListener(void);
extern void func_ClipboardInteractiveRows(void);
extern void func_ClipboardSetData(void);
extern void func_ClipboardMedBatch(void);
extern void func_ClipboardMetafileLifetime(void);
extern void func_ClipboardPoolCharge(void);
extern void func_ClipboardSynthBitmap(void);
extern void func_ConsoleClipText(void);
extern void func_DisplayModeCycle(void);
extern void func_EmptyClipboard(void);
extern void func_EnumDisplayDevices(void);
extern void func_EnumDisplaySettings(void);
extern void func_EnumDisplaySettingsThreads(void);
extern void func_EndTask(void);
extern void func_ExitWindowsEx(void);
extern void func_FrameChangedClient(void);
extern void func_FrameMetrics(void);
extern void func_FramelessCaptionDrag(void);
extern void func_GetClassInfo(void);
extern void func_GetDCEx(void);
extern void func_GetIconInfo(void);
extern void func_GetKeyState(void);
extern void func_GetMessageTime(void);
extern void func_GetPeekMessage(void);
extern void func_PostMessageLimit(void);
extern void func_GetSetWindowInt(void);
extern void func_GetSystemMetrics(void);
extern void func_GetUpdatedClipboardFormats(void);
extern void func_GetUserObjectInformation(void);
extern void func_GetWindowPlacement(void);
extern void func_GW_ENABLEDPOPUP(void);
extern void func_Handle32(void);
extern void func_HandleQuota(void);
extern void func_HandleQuotaChild(void);
extern void func_UserHandleTable(void);
extern void func_HookInputBatch(void);
extern void func_UserLowsBatch(void);
extern void func_HookChainUnhookUaf(void);
extern void func_ForegroundIdleHook(void);
extern void func_HookFamilies(void);
extern void func_HungWindow(void);
extern void func_WindowNestingLimit(void);
extern void func_WindowPosChanged(void);
extern void func_WindowRgnHandles(void);
extern void func_PowerSettingNotification(void);
extern void func_ScreenSaverSecurePolicy(void);
extern void func_OwnerZOrderNotice(void);
extern void func_OwnedWindowThreadExit(void);
extern void func_NcPaintLayered(void);
extern void func_SetWindowPosFlags(void);
extern void func_SetParentCrossProcess(void);
extern void func_SetParentKillOrder(void);
extern void func_SetParentLoop(void);
extern void func_SetCursorParentDestroys(void);
extern void func_SetWindowPosLastError(void);
extern void func_WmCancelModeLastError(void);
extern void func_LastInputInfo(void);
extern void func_WmGetDlgCode(void);
extern void func_WmDdeml(void);
extern void func_WmDde(void);
extern void func_WmMenuDragIme(void);
extern void func_WmPointerMessages(void);
extern void func_InitializeLpkHooks(void);
extern void func_InputDesktopDeleted(void);
extern void func_InputDesktopRouting(void);
extern void func_IsDialogMessage(void);
extern void func_IsServerSideWindow(void);
extern void func_IsWindowArranged(void);
extern void func_JobUIRestrictions(void);
extern void func_KbdLayout(void);
extern void func_keybd_event(void);
extern void func_MouseHookTransport(void);
extern void func_MouseWheel(void);
extern void func_WmCharAnsi(void);
extern void func_KeyboardLLHook(void);
extern void func_WallpaperAccess(void);
extern void func_LoadImage(void);
extern void func_LoadImageGCC(void);
extern void func_LoadImagePngIcon(void);
extern void func_LookupIconIdFromDirectoryEx(void);
extern void func_MenuItemData(void);
extern void func_MenuUI(void);
extern void func_MessageStateAnalyzer(void);
extern void func_ForegroundQuantumShare(void);
extern void func_MessageWakeBoost(void);
extern void func_MsgWaitForMultipleObjectsEx(void);
extern void func_NCRButtonDown(void);
extern void func_NcPaintActive(void);
extern void func_NcPaintClient(void);
extern void func_NcPaintRgn(void);
extern void func_NextDlgItem(void);
extern void func_OwnDcDestroy(void);
extern void func_PaintDesktopSwitch(void);
extern void func_PrintWindow(void);
extern void func_ExtractIconAni(void);
extern void func_PrivateExtractIcons(void);
extern void func_PngIconRows(void);
extern void func_ProcessConnectTerminate(void);
extern void func_RawInput(void);
extern void func_RealGetWindowClass(void);
extern void func_RedirDesktop(void);
extern void func_RedirIntegrity(void);
extern void func_RedirGlassKeep(void);
extern void func_RedirPresent(void);
extern void func_RedirScroll(void);
extern void func_RedrawWindow(void);
extern void func_RegisterHotKey(void);
extern void func_RegisterClassEx(void);
extern void func_SaveBits(void);
extern void func_ScrollBarRedraw(void);
extern void func_ScrollBarWndExtra(void);
extern void func_ScrollDC(void);
extern void func_ScrollWindowEx(void);
extern void func_SendMessageCallbackSenderDied(void);
extern void func_SendMessageCallbackReceiverExit(void);
extern void func_SendMessageSenderDied(void);
extern void func_SendMessageTimeout(void);
extern void func_SendMessageCopyData(void);
extern void func_SendMessageGetText(void);
extern void func_SetActiveWindow(void);
extern void func_SetCoalescableTimer(void);
extern void func_SetCursorPos(void);
extern void func_SetSystemCursor(void);
extern void func_SetFocus(void);
extern void func_SetFocusCallbacks(void);
extern void func_SetParent(void);
extern void func_SetProp(void);
extern void func_SetScrollInfo(void);
extern void func_SetScrollRange(void);
extern void func_SetSysColorsWinsta(void);
extern void func_SetWindowPlacement(void);
extern void func_SetWindowPosOwned(void);
extern void func_ScreenDesktopReads(void);
extern void func_ScreenDesktopSerial(void);
extern void func_SetWindowRgn(void);
extern void func_ShowWindow(void);
extern void func_SizeNoMaxTrack(void);
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
extern void func_LayeredCompose(void);
extern void func_UpdateLayeredWindow(void);
extern void func_UserHandleGrantAccess(void);
extern void func_UserSrvRegistration(void);
extern void func_VirtualKey(void);
extern void func_Wow64WinArguments(void);
extern void func_WinEventHook(void);
extern void func_WinEventInContext(void);
extern void func_XprocMessages(void);
extern void func_WindowStationLeak(void);
extern void func_WmPrint(void);
extern void func_WndProc(void);
extern void func_Win8User(void);
extern void func_PhysicalCoords(void);
extern void func_DialogDpiBehavior(void);
extern void func_GetIconInfoEx(void);
extern void func_CreateDesktopEx(void);
extern void func_DesktopHeapLeak(void);
extern void func_DesktopLabels(void);
extern void func_DesktopViewNoAddressSpace(void);
extern void func_DesktopCloseUserObjects(void);
extern void func_DesktopWindowSiblings(void);
extern void func_ShutdownBlockReason(void);
extern void func_PointerDeviceFunctions(void);
extern void func_wsprintfApi(void);

const struct test winetest_testlist[] =
{
    { "AttachThreadInput", func_AttachThreadInput },
    { "AttachThreadInputQueue", func_AttachThreadInputQueue },
    { "AutoRotation", func_AutoRotation },
    { "BroadcastHung", func_BroadcastHung },
    { "AniEmpty", func_AniEmpty },
    { "AniMalformed", func_AniMalformed },
    { "LifetimeActivePrevFreed", func_LifetimeActivePrevFreed },
    { "LifetimeAttachSharedQueue", func_LifetimeAttachSharedQueue },
    { "LifetimeBeingActivatedExit", func_LifetimeBeingActivatedExit },
    { "LifetimeBroadcastDesktops", func_LifetimeBroadcastDesktops },
    { "LifetimeBroadcastListExitLeak", func_LifetimeBroadcastListExitLeak },
    { "LifetimeCallbackExitLeak", func_LifetimeCallbackExitLeak },
    { "LifetimeCaptureWinEvent", func_LifetimeCaptureWinEvent },
    { "LifetimeCbtActivateRecursion", func_LifetimeCbtActivateRecursion },
    { "LifetimeEventProcExitThread", func_LifetimeEventProcExitThread },
    { "LifetimeForegroundWinEvent", func_LifetimeForegroundWinEvent },
    { "LifetimeCreateNameExitLeak", func_LifetimeCreateNameExitLeak },
    { "LifetimeDesktopHeldDelete", func_LifetimeDesktopHeldDelete },
    { "LifetimeDesktopKeptByMenus", func_LifetimeDesktopKeptByMenus },
    { "LifetimeDesktopSenderHeld", func_LifetimeDesktopSenderHeld },
    { "LifetimeFreeExitClass", func_LifetimeFreeExitClass },
    { "LifetimeHookExitLeak", func_LifetimeHookExitLeak },
    { "LifetimeHookNamesExitLeak", func_LifetimeHookNamesExitLeak },
    { "LifetimeImcOtherThreadEnds", func_LifetimeImcOtherThreadEnds },
    { "LifetimeImeWindowGoneInNotify", func_LifetimeImeWindowGoneInNotify },
    { "LifetimeInfoCallbacks", func_LifetimeInfoCallbacks },
    { "LifetimeKeyboardLayoutWalk", func_LifetimeKeyboardLayoutWalk },
    { "LifetimeLayoutSenderEnds", func_LifetimeLayoutSenderEnds },
    { "LifetimeOtherDesktopOwner", func_LifetimeOtherDesktopOwner },
    { "LifetimeOwnerDestroyRace", func_LifetimeOwnerDestroyRace },
    { "LifetimeOwnerReparentedFreed", func_LifetimeOwnerReparentedFreed },
    { "LifetimeSendSenderEnds", func_LifetimeSendSenderEnds },
    { "LifetimeSenderCopyTerminated", func_LifetimeSenderCopyTerminated },
    { "LifetimeSentCopyExitLeak", func_LifetimeSentCopyExitLeak },
    { "LifetimeSetActiveHookAttach", func_LifetimeSetActiveHookAttach },
    { "LifetimeSetFocusTopDestroy", func_LifetimeSetFocusTopDestroy },
    { "LifetimeWinEventUnhook", func_LifetimeWinEventUnhook },
    { "LifetimeWindowListExitLeak", func_LifetimeWindowListExitLeak },
    { "CharFuncs", func_CharFuncs },
    { "ClassDCThreadExit", func_ClassDCThreadExit },
    { "CloseWindow", func_CloseWindow },
    { "CopyImage", func_CopyImage },
    { "CalculatePopupWindowPosition", func_CalculatePopupWindowPosition },
    { "ChangeDisplaySettings", func_ChangeDisplaySettings },
    { "CreateDialog", func_CreateDialog },
    { "CreateIconFromResourceEx", func_CreateIconFromResourceEx },
    { "CreateWindowEx", func_CreateWindowEx },
    { "DeferWindowPos", func_DeferWindowPos },
    { "DestroyCursorIcon", func_DestroyCursorIcon },
    { "DestroyCurrentCursor", func_DestroyCurrentCursor },
    { "DM_REPOSITION", func_DM_REPOSITION },
    { "DpiFunctions", func_DpiFunctions },
    { "DpiProcess", func_DpiProcess },
    { "DrawIconEx", func_DrawIconEx },
    { "DrawText", func_DrawText },
    { "EditChildUserObjects", func_EditChildUserObjects },
    { "EditInk", func_EditInk },
    { "desktop", func_desktop },
    { "DesktopHeapNonInteractive", func_DesktopHeapNonInteractive },
    { "DesktopOtherThreadApis", func_DesktopOtherThreadApis },
    { "ClipboardFormatListener", func_ClipboardFormatListener },
    { "ClipboardInteractiveRows", func_ClipboardInteractiveRows },
    { "ClipboardSetData", func_ClipboardSetData },
    { "ClipboardMedBatch", func_ClipboardMedBatch },
    { "ClipboardMetafileLifetime", func_ClipboardMetafileLifetime },
    { "ClipboardPoolCharge", func_ClipboardPoolCharge },
    { "ClipboardSynthBitmap", func_ClipboardSynthBitmap },
    { "ConsoleClipText", func_ConsoleClipText },
    { "DisplayModeCycle", func_DisplayModeCycle },
    { "EmptyClipboard", func_EmptyClipboard },
    { "EnumDisplayDevices", func_EnumDisplayDevices },
    { "EnumDisplaySettings", func_EnumDisplaySettings },
    { "EnumDisplaySettingsThreads", func_EnumDisplaySettingsThreads },
    { "EndTask", func_EndTask },
    { "ExitWindowsEx", func_ExitWindowsEx },
    { "FrameChangedClient", func_FrameChangedClient },
    { "FrameMetrics", func_FrameMetrics },
    { "FramelessCaptionDrag", func_FramelessCaptionDrag },
    { "GetClassInfo", func_GetClassInfo },
    { "GetDCEx", func_GetDCEx },
    { "GetIconInfo", func_GetIconInfo },
    { "GetKeyState", func_GetKeyState },
    { "GetMessageTime", func_GetMessageTime },
    { "GetPeekMessage", func_GetPeekMessage },
    { "PostMessageLimit", func_PostMessageLimit },
    { "GetSetWindowInt", func_GetSetWindowInt },
    { "GetSystemMetrics", func_GetSystemMetrics },
    { "GetUpdatedClipboardFormats", func_GetUpdatedClipboardFormats },
    { "GetUserObjectInformation", func_GetUserObjectInformation },
    { "GetWindowPlacement", func_GetWindowPlacement },
    { "GW_ENABLEDPOPUP", func_GW_ENABLEDPOPUP },
    { "Handle32", func_Handle32 },
    { "HandleQuota", func_HandleQuota },
    { "HandleQuotaChild", func_HandleQuotaChild },
    { "UserHandleTable", func_UserHandleTable },
    { "HookInputBatch", func_HookInputBatch },
    { "UserLowsBatch", func_UserLowsBatch },
    { "HookChainUnhookUaf", func_HookChainUnhookUaf },
    { "ForegroundIdleHook", func_ForegroundIdleHook },
    { "HookFamilies", func_HookFamilies },
    { "HungWindow", func_HungWindow },
    { "WindowNestingLimit", func_WindowNestingLimit },
    { "WindowPosChanged", func_WindowPosChanged },
    { "WindowRgnHandles", func_WindowRgnHandles },
    { "PowerSettingNotification", func_PowerSettingNotification },
    { "ScreenSaverSecurePolicy", func_ScreenSaverSecurePolicy },
    { "OwnerZOrderNotice", func_OwnerZOrderNotice },
    { "OwnedWindowThreadExit", func_OwnedWindowThreadExit },
    { "NcPaintLayered", func_NcPaintLayered },
    { "SetWindowPosFlags", func_SetWindowPosFlags },
    { "SetParentCrossProcess", func_SetParentCrossProcess },
    { "SetParentKillOrder", func_SetParentKillOrder },
    { "SetParentLoop", func_SetParentLoop },
    { "SetCursorParentDestroys", func_SetCursorParentDestroys },
    { "SetWindowPosLastError", func_SetWindowPosLastError },
    { "LastInputInfo", func_LastInputInfo },
    { "WmCancelModeLastError", func_WmCancelModeLastError },
    { "WmGetDlgCode", func_WmGetDlgCode },
    { "WmDdeml", func_WmDdeml },
    { "WmDde", func_WmDde },
    { "WmMenuDragIme", func_WmMenuDragIme },
    { "WmPointerMessages", func_WmPointerMessages },
    { "InitializeLpkHooks", func_InitializeLpkHooks },
    { "InputDesktopDeleted", func_InputDesktopDeleted },
    { "InputDesktopRouting", func_InputDesktopRouting },
    { "IsDialogMessage", func_IsDialogMessage },
    { "IsServerSideWindow", func_IsServerSideWindow },
    { "IsWindowArranged", func_IsWindowArranged },
    { "JobUIRestrictions", func_JobUIRestrictions },
    { "KbdLayout", func_KbdLayout },
    { "keybd_event", func_keybd_event },
    { "MouseHookTransport", func_MouseHookTransport },
    { "MouseWheel", func_MouseWheel },
    { "WmCharAnsi", func_WmCharAnsi },
    { "KeyboardLLHook", func_KeyboardLLHook },
    { "LoadImage", func_LoadImage },
    { "LoadImageGCC", func_LoadImageGCC },
    { "WallpaperAccess", func_WallpaperAccess },
    { "LoadImagePngIcon", func_LoadImagePngIcon },
    { "LookupIconIdFromDirectoryEx", func_LookupIconIdFromDirectoryEx },
    { "MenuItemData", func_MenuItemData },
    { "MenuUI", func_MenuUI },
    { "MessageStateAnalyzer", func_MessageStateAnalyzer },
    { "ForegroundQuantumShare", func_ForegroundQuantumShare },
    { "MessageWakeBoost", func_MessageWakeBoost },
    { "MsgWaitForMultipleObjectsEx", func_MsgWaitForMultipleObjectsEx },
    { "NCRButtonDown", func_NCRButtonDown },
    { "NcPaintActive", func_NcPaintActive },
    { "NcPaintClient", func_NcPaintClient },
    { "NcPaintRgn", func_NcPaintRgn },
    { "NextDlgItem", func_NextDlgItem },
    { "OwnDcDestroy", func_OwnDcDestroy },
    { "PaintDesktopSwitch", func_PaintDesktopSwitch },
    { "PrintWindow", func_PrintWindow },
    { "ExtractIconAni", func_ExtractIconAni },
    { "PrivateExtractIcons", func_PrivateExtractIcons },
    { "ProcessConnectTerminate", func_ProcessConnectTerminate },
    { "RawInput", func_RawInput },
    { "PngIconRows", func_PngIconRows },
    { "RealGetWindowClass", func_RealGetWindowClass },
    { "RedirDesktop", func_RedirDesktop },
    { "RedirIntegrity", func_RedirIntegrity },
    { "RedirGlassKeep", func_RedirGlassKeep },
    { "RedirPresent", func_RedirPresent },
    { "RedirScroll", func_RedirScroll },
    { "RedrawWindow", func_RedrawWindow },
    { "RegisterHotKey", func_RegisterHotKey },
    { "RegisterClassEx", func_RegisterClassEx },
    { "SaveBits", func_SaveBits },
    { "ScrollBarRedraw", func_ScrollBarRedraw },
    { "ScrollBarWndExtra", func_ScrollBarWndExtra },
    { "ScrollDC", func_ScrollDC },
    { "ScrollWindowEx", func_ScrollWindowEx },
    { "SendMessageCallbackSenderDied", func_SendMessageCallbackSenderDied },
    { "SendMessageCallbackReceiverExit", func_SendMessageCallbackReceiverExit },
    { "SendMessageSenderDied", func_SendMessageSenderDied },
    { "SendMessageTimeout", func_SendMessageTimeout },
    { "SendMessageCopyData", func_SendMessageCopyData },
    { "SendMessageGetText", func_SendMessageGetText },
    { "SetActiveWindow", func_SetActiveWindow },
    { "SetCoalescableTimer", func_SetCoalescableTimer },
    { "SetCursorPos", func_SetCursorPos },
    { "SetSystemCursor", func_SetSystemCursor },
    { "SetFocus", func_SetFocus },
    { "SetFocusCallbacks", func_SetFocusCallbacks },
    { "SetParent", func_SetParent },
    { "SetProp", func_SetProp },
    { "SetScrollInfo", func_SetScrollInfo },
    { "SetScrollRange", func_SetScrollRange },
    { "SetSysColorsWinsta", func_SetSysColorsWinsta },
    { "SetWindowPlacement", func_SetWindowPlacement },
    { "SetWindowPosOwned", func_SetWindowPosOwned },
    { "ScreenDesktopReads", func_ScreenDesktopReads },
    { "ScreenDesktopSerial", func_ScreenDesktopSerial },
    { "SetWindowRgn", func_SetWindowRgn },
    { "ShowWindow", func_ShowWindow },
    { "SizeNoMaxTrack", func_SizeNoMaxTrack },
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
    { "LayeredCompose", func_LayeredCompose },
    { "UpdateLayeredWindow", func_UpdateLayeredWindow },
    { "UserHandleGrantAccess", func_UserHandleGrantAccess },
    { "UserSrvRegistration", func_UserSrvRegistration },
    { "VirtualKey", func_VirtualKey },
    { "Win8User", func_Win8User },
    { "PhysicalCoords", func_PhysicalCoords },
    { "DialogDpiBehavior", func_DialogDpiBehavior },
    { "GetIconInfoEx", func_GetIconInfoEx },
    { "CreateDesktopEx", func_CreateDesktopEx },
    { "DesktopHeapLeak", func_DesktopHeapLeak },
    { "DesktopLabels", func_DesktopLabels },
    { "DesktopViewNoAddressSpace", func_DesktopViewNoAddressSpace },
    { "DesktopCloseUserObjects", func_DesktopCloseUserObjects },
    { "DesktopWindowSiblings", func_DesktopWindowSiblings },
    { "ShutdownBlockReason", func_ShutdownBlockReason },
    { "PointerDeviceFunctions", func_PointerDeviceFunctions },
    { "Wow64WinArguments", func_Wow64WinArguments },
    { "WinEventHook", func_WinEventHook },
    { "WinEventInContext", func_WinEventInContext },
    { "XprocMessages", func_XprocMessages },
    { "WindowStationLeak", func_WindowStationLeak },
    { "WmPrint", func_WmPrint },
    { "WndProc", func_WndProc },
    { "wsprintfApi", func_wsprintfApi },
    { 0, 0 }
};

