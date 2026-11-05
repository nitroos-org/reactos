add_subdirectory(makeimg)
add_subdirectory(mousehook)
add_subdirectory(wevhook)

list(APPEND SOURCE
    AttachThreadInput.c
    AttachThreadInputQueue.c
    AutoRotation.c
    BroadcastHung.c
    ../include/msgtrace.c
    CharFuncs.c
    CloseWindow.c
    CopyImage.c
    CalculatePopupWindowPosition.c
    CreateDialog.c
    CreateIconFromResourceEx.c
    CreateWindowEx.c
    DeferWindowPos.c
    DestroyCursorIcon.c
    DM_REPOSITION.c
    DpiFunctions.c
    DrawIconEx.c
    DrawText.c
    EditChildUserObjects.c
    EditInk.c
    desktop.c
    DesktopHeapNonInteractive.c
    DesktopOtherThreadApis.c
    ClipboardFormatListener.c
    ClipboardSynthBitmap.c
    ConsoleClipText.c
    EmptyClipboard.c
    EndTask.c
    EnumDisplayDevices.c
    EnumDisplaySettings.c
    ExitWindowsEx.c
    FrameChangedClient.c
    FrameMetrics.c
    FramelessCaptionDrag.c
    GetClassInfo.c
    GetDCEx.c
    GetIconInfo.c
    GetKeyState.c
    GetMessageTime.c
    GetPeekMessage.c
    GetSetWindowInt.c
    GetSystemMetrics.c
    GetUpdatedClipboardFormats.c
    GetUserObjectInformation.c
    GetWindowPlacement.c
    GW_ENABLEDPOPUP.c
    Handle32.c
    HookChainUnhookUaf.c
    HookFamilies.c
    HungWindow.c
    WindowPosChanged.c
    PowerSettingNotification.c
    OwnerZOrderNotice.c
    WmCancelModeLastError.c
    InitializeLpkHooks.c
    IsDialogMessage.c
    IsServerSideWindow.c
    IsWindowArranged.c
    KbdLayout.c
    ForegroundQuantumShare.c
    keybd_event.c
    MouseHookTransport.c
    MouseWheel.c
    KeyboardLLHook.c
    LoadImage.c
    LoadImageGCC.c
    LoadImagePngIcon.c
    LookupIconIdFromDirectoryEx.c
    MenuItemData.c
    MenuUI.c
    MessageStateAnalyzer.c
    MessageWakeBoost.c
    MsgWaitForMultipleObjectsEx.c
    NCRButtonDown.c
    NcPaintActive.c
    NcPaintClient.c
    NcPaintRgn.c
    NextDlgItem.c
    PaintDesktopSwitch.c
    PrivateExtractIcons.c
    ProcessConnectTerminate.c
    RawInput.c
    RealGetWindowClass.c
    RedrawWindow.c
    RegisterClassEx.c
    RegisterHotKey.c
    ScrollBarRedraw.c
    ScrollBarWndExtra.c
    ScrollDC.c
    ScrollWindowEx.c
    SendMessageCallbackSenderDied.c
    SendMessageSenderDied.c
    SendMessageTimeout.c
    SetActiveWindow.c
    SetCoalescableTimer.c
    SetCursorPos.c
    SetFocus.c
    SetParent.c
    SetProp.c
    SetScrollInfo.c
    SetScrollRange.c
    SetWindowPlacement.c
    SetWindowPosOwned.c
    SetWindowRgn.c
    ShowWindow.c
    ShowWindowFrame.c
    SwitchDesktop.c
    SuspendResumeNotification.c
    SwitchToThisWindow.c
    SysCommandHidden.c
    SystemMenu.c
    SystemParametersInfo.c
    TrackMouseEvent.c
    TrackPopupMenuEx.c
    UnicodeToAnsiMessage.c
    UpdateLayeredWindow.c
    UserHandleGrantAccess.c
    VirtualKey.c
    Win8User.c
    WinEventHook.c
    WindowStationLeak.c
    WmPrint.c
    WndProc.c
    PhysicalCoords.c
    DialogDpiBehavior.c
    GetIconInfoEx.c
    CreateDesktopEx.c
    DesktopHeapLeak.c
    DesktopCloseUserObjects.c
    DesktopWindowSiblings.c
    ShutdownBlockReason.c
    PointerDeviceFunctions.c
    wsprintf.c)

list(APPEND PCH_SKIP_SOURCE
    testlist.c)

add_executable(user32_apitest
    ${SOURCE}
    ${PCH_SKIP_SOURCE}
    user32_apitest.rc
    user32_apitest_1bpp.rc)

target_link_libraries(user32_apitest wine ${PSEH_LIB})
set_module_type(user32_apitest win32cui)
add_importlibs(user32_apitest advapi32 imm32 gdi32 user32 msvcrt kernel32 ntdll)
add_pch(user32_apitest precomp.h "${PCH_SKIP_SOURCE}")
add_dependencies(user32_apitest user32_wevhook1 user32_wevhook2)
add_rostests_file(TARGET user32_apitest)
add_dependencies(user32_apitest user32_mousehook)

add_executable(user32_apitest_menuui user32_apitest_menuui.c)
set_module_type(user32_apitest_menuui win32gui UNICODE)
add_importlibs(user32_apitest_menuui user32 msvcrt kernel32)
add_rostests_file(TARGET user32_apitest_menuui)
add_dependencies(user32_apitest user32_apitest_menuui)

add_executable(user32_apitest_connect user32_apitest_connect.c)
set_module_type(user32_apitest_connect win32cui UNICODE)
add_importlibs(user32_apitest_connect msvcrt kernel32)
add_rostests_file(TARGET user32_apitest_connect)
add_dependencies(user32_apitest user32_apitest_connect)

add_executable(user32_apitest_dpi user32_apitest_dpi.c)
set_module_type(user32_apitest_dpi win32cui)
add_importlibs(user32_apitest_dpi gdi32 user32 msvcrt kernel32)
add_rostests_file(TARGET user32_apitest_dpi)
add_dependencies(user32_apitest user32_apitest_dpi)

add_rostests_file(FILE "${CMAKE_CURRENT_SOURCE_DIR}/verclasstest1.manifest")
add_rostests_file(FILE "${CMAKE_CURRENT_SOURCE_DIR}/verclasstest2.manifest")
