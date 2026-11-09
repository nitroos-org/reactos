
#define STANDALONE
#include <apitest.h>

extern void func_NtGdiDdCreateDirectDrawObject(void);
extern void func_NtGdiDdCreateDirectDrawObject(void);
extern void func_NtGdiDdCreateSurface(void);
extern void func_NtGdiDdDeleteDirectDrawObject(void);
extern void func_NtGdiDdQueryDirectDrawObject(void);

extern void func_NtGdiArcInternal(void);
extern void func_NtGdiBitBlt(void);
extern void func_NtGdiCombineRgn(void);
extern void func_NtGdiCreateBitmap(void);
extern void func_NtGdiCreateCompatibleBitmap(void);
extern void func_NtGdiCreateCompatibleDC(void);
extern void func_NtGdiCreateDIBSection(void);
extern void func_NtGdiCreateDIBSectionCaptureValid(void);
extern void func_NtGdiCreateDIBSectionCaptureInvalid(void);
extern void func_NtGdiCreateDIBSectionCaptureStraddle(void);
extern void func_NtGdiCreateDIBSectionCaptureBitsPtr(void);
extern void func_NtGdiCreateDIBSectionSizeMath(void);
extern void func_NtGdiCreateDIBitmapInternal(void);
extern void func_NtGdiDeleteObjectApp(void);
extern void func_NtGdiDoPalette(void);
extern void func_NtGdiEngCreatePalette(void);
extern void func_NtGdiEnumFontOpen(void);
extern void func_NtGdiExcludeClipRect(void);
extern void func_NtGdiExtCreateRegion(void);
extern void func_NtGdiExtSelectClipRgn(void);
extern void func_NtGdiExtTextOutW(void);
//extern void func_NtGdiFlushUserBatch(void);
extern void func_NtGdiGetBitmapBits(void);
extern void func_NtGdiGetDIBitsInternal(void);
extern void func_NtGdiGetFontResourceInfoInternalW(void);
extern void func_NtGdiGetFontResourceInfoLength(void);
extern void func_NtGdiGetRandomRgn(void);
extern void func_NtGdiGetStockObject(void);
extern void func_NtGdiIntersectClipRect(void);
extern void func_NtGdiLineTo(void);
extern void func_NtGdiOffsetClipRgn(void);
extern void func_NtGdiPolyPolyDraw(void);
extern void func_NtGdiRestoreDC(void);
extern void func_NtGdiSaveDC(void);
extern void func_NtGdiSelectBitmap(void);
extern void func_NtGdiSelectBrush(void);
extern void func_NtGdiSelectFont(void);
extern void func_NtGdiSelectPen(void);
extern void func_NtGdiSetBitmapBits(void);
extern void func_NtGdiSetDIBitsToDeviceInternal(void);
extern void func_NtGdiSetPixel(void);
extern void func_NtGdiStretchDIBitsInternal(void);
extern void func_NtGdiTransformPoints(void);
extern void func_NtUserBuildHwndList(void);
//extern void func_NtUserCallHwnd(void);
//extern void func_NtUserCallHwndLock(void);
//extern void func_NtUserCallHwndOpt(void);
//extern void func_NtUserCallHwndParam(void);
//extern void func_NtUserCallHwndParamLock(void);
//extern void func_NtUserCallNoParam(void);
//extern void func_NtUserCallOneParam(void);
extern void func_NtUserClipboardHandles(void);
extern void func_NtUserLowsBatch(void);
extern void func_NtUserConvertMemHandle(void);
extern void func_NtUserCountClipboardFormats(void);
extern void func_NtUserCreateAcceleratorTable(void);
extern void func_NtUserCreateWindowEx(void);
//extern void func_NtUserEnumDisplayMonitors(void);
extern void func_NtUserEnumDisplaySettings(void);
extern void func_NtUserFindExistingCursorIcon(void);
extern void func_NtUserGetAsyncKeyState(void);
extern void func_NtUserGetAtomNameValid(void);
extern void func_NtUserGetAtomNameInvalid(void);
extern void func_NtUserGetAtomNameConcurrent(void);
extern void func_NtUserGetClassInfo(void);
extern void func_NtUserGetCursorInfo(void);
//extern void func_NtUserGetIconInfo(void);
extern void func_NtUserGetIconInfoProbe(void);
extern void func_NtUserGetKeyboardLayoutName(void);
extern void func_NtUserGetThreadState(void);
extern void func_NtUserGetTitleBarInfo(void);
extern void func_NtUserMessageCallAsync(void);
extern void func_NtUserMessageCallPackParam(void);
extern void func_NtUserProcessConnect(void);
extern void func_NtUserRedrawWindow(void);
extern void func_NtUserSBGetParms(void);
extern void func_NtUserScrollDC(void);
extern void func_NtUserSelectPalette(void);
extern void func_NtUserSetTimer(void);
extern void func_NtUserSetWindowsHookExModule(void);
extern void func_NtUserSystemParametersInfo(void);
extern void func_NtUserThunkedMenuInfo(void);
extern void func_NtUserGetMenuItemRectProbe(void);
extern void func_NtUserMenuInfoItemBound(void);
extern void func_NtUserMenuStaleIndexAfterRemove(void);
extern void func_NtUserPopupMenuClassExtra(void);
extern void func_NtUserDesktopWindowPosProbe(void);
extern void func_NtUserServerSideFnidForge(void);
extern void func_NtUserRegisterUserApiHookGate(void);
extern void func_NtUserGetWOWClassPtr(void);
extern void func_NtUserCallNextHookZero(void);
extern void func_NtUserToUnicodeEx(void);
extern void func_NtUserUpdatePerUserSystemParameters(void);

const struct test winetest_testlist[] =
{
    /* ntdd*/
    { "NtGdiDdCreateDirectDrawObject", func_NtGdiDdCreateDirectDrawObject },
    { "NtGdiDdCreateSurface", func_NtGdiDdCreateSurface },
    { "NtGdiDdDeleteDirectDrawObject", func_NtGdiDdDeleteDirectDrawObject },
    // { "NtGdiDdQueryDirectDrawObject", func_NtGdiDdQueryDirectDrawObject },
    { "NtGdiArcInternal", func_NtGdiArcInternal },

    /* ntgdi */
    { "NtGdiBitBlt", func_NtGdiBitBlt },
    { "NtGdiCombineRgn", func_NtGdiCombineRgn },
    { "NtGdiCreateBitmap", func_NtGdiCreateBitmap },
    { "NtGdiCreateCompatibleBitmap", func_NtGdiCreateCompatibleBitmap },
    { "NtGdiCreateCompatibleDC", func_NtGdiCreateCompatibleDC },
    { "NtGdiCreateDIBSection", func_NtGdiCreateDIBSection },
    { "NtGdiCreateDIBSectionCaptureValid", func_NtGdiCreateDIBSectionCaptureValid },
    { "NtGdiCreateDIBSectionCaptureInvalid", func_NtGdiCreateDIBSectionCaptureInvalid },
    { "NtGdiCreateDIBSectionCaptureStraddle", func_NtGdiCreateDIBSectionCaptureStraddle },
    { "NtGdiCreateDIBSectionCaptureBitsPtr", func_NtGdiCreateDIBSectionCaptureBitsPtr },
    { "NtGdiCreateDIBSectionSizeMath", func_NtGdiCreateDIBSectionSizeMath },
    { "NtGdiCreateDIBitmapInternal", func_NtGdiCreateDIBitmapInternal },
    { "NtGdiDeleteObjectApp", func_NtGdiDeleteObjectApp },
    { "NtGdiDoPalette", func_NtGdiDoPalette },
    { "NtGdiEngCreatePalette", func_NtGdiEngCreatePalette },
    { "NtGdiEnumFontOpen", func_NtGdiEnumFontOpen },
    { "NtGdiExcludeClipRect", func_NtGdiExcludeClipRect },
    { "NtGdiExtCreateRegion", func_NtGdiExtCreateRegion },
    { "NtGdiExtSelectClipRgn", func_NtGdiExtSelectClipRgn },
    { "NtGdiExtTextOutW", func_NtGdiExtTextOutW },
    //{ "NtGdiFlushUserBatch", func_NtGdiFlushUserBatch },
    { "NtGdiGetBitmapBits", func_NtGdiGetBitmapBits },
    { "NtGdiGetDIBitsInternal", func_NtGdiGetDIBitsInternal },
    //{ "NtGdiGetFontResourceInfoInternalW", func_NtGdiGetFontResourceInfoInternalW },
    { "NtGdiGetFontResourceInfoLength", func_NtGdiGetFontResourceInfoLength },
    { "NtGdiGetRandomRgn", func_NtGdiGetRandomRgn },
    { "NtGdiGetStockObject", func_NtGdiGetStockObject },
    { "NtGdiIntersectClipRect", func_NtGdiIntersectClipRect },
    { "NtGdiLineTo", func_NtGdiLineTo },
    { "NtGdiOffsetClipRgn", func_NtGdiOffsetClipRgn },
    { "NtGdiPolyPolyDraw", func_NtGdiPolyPolyDraw },
    { "NtGdiRestoreDC", func_NtGdiRestoreDC },
    { "NtGdiSaveDC", func_NtGdiSaveDC },
    { "NtGdiSelectBitmap", func_NtGdiSelectBitmap },
    { "NtGdiSelectBrush", func_NtGdiSelectBrush },
    { "NtGdiSelectFont", func_NtGdiSelectFont },
    { "NtGdiSelectPen", func_NtGdiSelectPen },
    { "NtGdiSetBitmapBits", func_NtGdiSetBitmapBits },
    { "NtGdiSetDIBitsToDeviceInternal", func_NtGdiSetDIBitsToDeviceInternal },
    { "NtGdiSetPixel", func_NtGdiSetPixel },
    { "NtGdiStretchDIBitsInternal", func_NtGdiStretchDIBitsInternal },
    { "NtGdiTransformPoints", func_NtGdiTransformPoints },

    /* ntuser */
    { "NtUserBuildHwndList", func_NtUserBuildHwndList },
    //{ "NtUserCallHwnd", func_NtUserCallHwnd },
    //{ "NtUserCallHwndLock", func_NtUserCallHwndLock },
    //{ "NtUserCallHwndOpt", func_NtUserCallHwndOpt },
    //{ "NtUserCallHwndParam", func_NtUserCallHwndParam },
    //{ "NtUserCallHwndParamLock", func_NtUserCallHwndParamLock },
    //{ "NtUserCallNoParam", func_NtUserCallNoParam },
    //{ "NtUserCallOneParam", func_NtUserCallOneParam },
    { "NtUserClipboardHandles", func_NtUserClipboardHandles },
    { "NtUserLowsBatch", func_NtUserLowsBatch },
    { "NtUserConvertMemHandle", func_NtUserConvertMemHandle },
    { "NtUserCountClipboardFormats", func_NtUserCountClipboardFormats },
    { "NtUserCreateAcceleratorTable", func_NtUserCreateAcceleratorTable },
    { "NtUserCreateWindowEx", func_NtUserCreateWindowEx },
    //{ "NtUserEnumDisplayMonitors", func_NtUserEnumDisplayMonitors },
    { "NtUserEnumDisplaySettings", func_NtUserEnumDisplaySettings },
    { "NtUserFindExistingCursorIcon", func_NtUserFindExistingCursorIcon },
    { "NtUserGetAsyncKeyState", func_NtUserGetAsyncKeyState },
    { "NtUserGetAtomNameValid", func_NtUserGetAtomNameValid },
    { "NtUserGetAtomNameInvalid", func_NtUserGetAtomNameInvalid },
    { "NtUserGetAtomNameConcurrent", func_NtUserGetAtomNameConcurrent },
    { "NtUserGetClassInfo", func_NtUserGetClassInfo },
    { "NtUserGetCursorInfo", func_NtUserGetCursorInfo },
    //{ "NtUserGetIconInfo", func_NtUserGetIconInfo },
    { "NtUserGetIconInfoProbe", func_NtUserGetIconInfoProbe },
    { "NtUserGetKeyboardLayoutName", func_NtUserGetKeyboardLayoutName },
    { "NtUserGetThreadState", func_NtUserGetThreadState },
    { "NtUserGetTitleBarInfo", func_NtUserGetTitleBarInfo },
    { "NtUserMessageCallAsync", func_NtUserMessageCallAsync },
    { "NtUserMessageCallPackParam", func_NtUserMessageCallPackParam },
    { "NtUserProcessConnect", func_NtUserProcessConnect },
    { "NtUserRedrawWindow", func_NtUserRedrawWindow },
    { "NtUserSBGetParms", func_NtUserSBGetParms },
    { "NtUserScrollDC", func_NtUserScrollDC },
    { "NtUserSelectPalette", func_NtUserSelectPalette },
    { "NtUserSetTimer", func_NtUserSetTimer },
    { "NtUserSetWindowsHookExModule", func_NtUserSetWindowsHookExModule },
    { "NtUserSystemParametersInfo", func_NtUserSystemParametersInfo },
    { "NtUserThunkedMenuInfo", func_NtUserThunkedMenuInfo },
    { "NtUserGetMenuItemRectProbe", func_NtUserGetMenuItemRectProbe },
    { "NtUserMenuInfoItemBound", func_NtUserMenuInfoItemBound },
    { "NtUserMenuStaleIndexAfterRemove", func_NtUserMenuStaleIndexAfterRemove },
    { "NtUserPopupMenuClassExtra", func_NtUserPopupMenuClassExtra },
    { "NtUserDesktopWindowPosProbe", func_NtUserDesktopWindowPosProbe },
    { "NtUserServerSideFnidForge", func_NtUserServerSideFnidForge },
    { "NtUserRegisterUserApiHookGate", func_NtUserRegisterUserApiHookGate },
    { "NtUserGetWOWClassPtr", func_NtUserGetWOWClassPtr },
    { "NtUserCallNextHookZero", func_NtUserCallNextHookZero },
    { "NtUserToUnicodeEx", func_NtUserToUnicodeEx },
    { "NtUserUpdatePerUserSystemParameters", func_NtUserUpdatePerUserSystemParameters },

    { 0, 0 }
};
