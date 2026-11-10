#!/usr/bin/env python3
"""Maintainer tool; outputs are checked in, Python is not a build dependency.

ReactOS catalogue prototypes + measured target layouts + handle policy.
Unknown carriers and mismatched aggregates are rejected, never forwarded.
"""
import csv
import pathlib
import re

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent.parent
rules = dict(re.findall(r'"(\w+)\|\w+\|(SIGN|ZERO)\|TRUNCATE"',
                       (ROOT / 'sdk/cmake/wow64handles.cmake').read_text()))
signed = set('INT int LONG BOOL LPARAM LRESULT LONG_PTR INT_PTR'.split())
unsigned = set('ACCESS_MASK ARCTYPE ATOM BYTE COLORREF DWORD FLONG GETCPD LFTYPE SIZE_T UINT UINT_PTR ULONG ULONG_PTR USHORT WCHAR WORD WPARAM D3DKMT_SCHEDULINGPRIORITYCLASS'.split())
# HANDLE aliases whose semantic family differs from the NT default.
overrides = {
    ('NtUserGetDCEx', 'hRegion'): 'ZERO',
    ('NtUserSetProp', 'Data'): 'ZERO',
}
# These GDI entry points explicitly carry NT process/event handles.
nt_gdi = {'NtGdiDdDDIGetProcessSchedulingPriorityClass',
          'NtGdiDdDDISetProcessSchedulingPriorityClass',
          'NtGdiDdDDIReleaseProcessVidPnSourceOwners'}
manual = set('''NtUserProcessConnect NtUserInitializeClientPfnArrays
NtUserRegisterClassExWOW NtUserUnregisterClass NtUserCreateWindowEx NtUserGetClassInfo
NtUserSetClipboardData
NtUserGetMessage NtUserPeekMessage NtUserDispatchMessage NtUserTranslateMessage
NtUserBeginPaint NtUserEndPaint NtUserDefSetText NtUserQueryWindow NtUserMessageCall NtUserCallOneParam
NtUserCallTwoParam NtUserCallHwndParam NtUserCallHwndParamLock
NtUserCallNoParam NtUserCallHwnd NtUserCallHwndLock NtUserCallHwndOpt
NtUserGetThreadState NtUserGetObjectInformation NtUserSetWindowLong
NtUserSetClassLong NtUserSetClassLongPtr NtUserMonitorFromPoint NtUserDragDetect
NtUserWindowFromPoint NtGdiOpenDCW NtUserFindExistingCursorIcon
NtUserBuildHwndList NtUserCallMsgFilter NtUserFindWindowEx NtUserFlashWindowEx
NtUserGetAtomName NtUserGetClassName NtUserGetClipboardData NtUserGetComboBoxInfo
NtUserGetCursorInfo NtUserGetGUIThreadInfo NtUserGetIconInfo NtUserGetKeyboardLayoutList
NtUserGetKeyboardLayoutName NtUserGetMenuBarInfo NtUserRegisterWindowMessage
NtUserSystemParametersInfo NtUserThunkedMenuInfo NtUserThunkedMenuItemInfo
NtUserTrackMouseEvent NtUserTranslateAccelerator
NtUserSetCursorIconData NtUserQueryInputContext NtUserUpdateInputContext
NtUserSetWindowsHookEx NtUserCallNextHookEx
NtUserEnumDisplayMonitors
NtGdiCreateDIBSection NtGdiDoPalette NtGdiExtCreatePen NtGdiExtGetObjectW
NtGdiPolyPolyDraw NtGdiStartDoc NtGdiGetOutlineTextMetricsInternalW'''.split())
# Hand-coded in the per-bucket files (gdi_extra.c, user_input.c, user_ime.c, user_display.c, user_misc.c),
# reached through the dispatcher's default: chain after generated.inc; listed so a catalogue reclassification
# cannot emit a typed pass-through that shadows them.
manual |= set('''NtGdiConsoleTextOut NtGdiCreateColorSpace NtGdiDxgGenericThunk NtGdiEnumObjects NtGdiExtEscape
NtGdiGetCharacterPlacementW NtGdiGetFontFileInfo NtGdiPolyPatBlt NtGdiPolyTextOutW
NtUserBuildHimcList NtUserBuildPropList NtUserChangeDisplaySettings NtUserConsoleControl
NtUserCreateDesktop NtUserCreateWindowStation NtUserDrawCaptionTemp NtUserEnumDisplayDevices
NtUserEnumDisplaySettings NtUserGetImeHotKey NtUserGetImeInfoEx NtUserGetMouseMovePointsEx
NtUserGetRawInputBuffer NtUserGetRawInputData NtUserGetRawInputDeviceInfo
NtUserGetRawInputDeviceList NtUserGetRegisteredRawInputDevices NtUserGetWOWClass
NtUserLoadKeyboardLayoutEx NtUserOpenDesktop NtUserOpenWindowStation NtUserQueryInformationThread
NtUserRealInternalGetMessage NtUserRegisterRawInputDevices NtUserResolveDesktop NtUserSendInput
NtUserSetCursorContents NtUserSetImeInfoEx NtUserSetInformationThread NtUserSetWindowWord'''.split())
# d3dkmt.c: structures with pointers or handles that are wider natively, and the adapter-callback calls
manual |= set('''NtGdiDdDDIOpenAdapterFromHdc NtGdiDdDDIOpenAdapterFromDeviceName NtGdiDdDDICreateDevice
NtGdiDdDDISetVidPnSourceOwner NtGdiDdDDIQueryAdapterInfo NtGdiDdDDICheckOcclusion
NtGdiDdDDICreateDCFromMemory NtGdiDdDDIDestroyDCFromMemory
NtGdiDdDDICreateAllocation NtGdiDdDDICreateContext NtGdiDdDDICreateOverlay NtGdiDdDDIDestroyAllocation
NtGdiDdDDIEscape NtGdiDdDDIFlipOverlay NtGdiDdDDIGetDisplayModeList NtGdiDdDDIGetMultisampleMethodList
NtGdiDdDDIGetPresentHistory NtGdiDdDDIGetRuntimeData NtGdiDdDDIInvalidateActiveVidPn NtGdiDdDDILock
NtGdiDdDDIOpenResource NtGdiDdDDIPresent NtGdiDdDDIQueryAllocationResidency NtGdiDdDDIQueryResourceInfo
NtGdiDdDDIQueryStatistics NtGdiDdDDIRender NtGdiDdDDISetAllocationPriority NtGdiDdDDISetGammaRamp
NtGdiDdDDIUnlock NtGdiDdDDIUpdateOverlay'''.split())
_svc32 = (ROOT/'win32ss/w32ksvc32.h').read_text()
services = set('Nt'+n for n in re.findall(r'SVC_\((\w+),', _svc32))
# w32ksvc32.h declares the checked-build-only services under #if DBG, and the
# W64_ enum (wow64win.h) is built from that same header, so their cases are
# emitted under the same guard: present in DBG builds, absent in Release.
dbg_services = set()
for block in re.findall(r'^#if\s+DBG\b(.*?)^#endif', _svc32, flags=re.S | re.M):
    dbg_services |= set('Nt'+n for n in re.findall(r'SVC_\((\w+),', block))
def guarded(name, line):
    return f'#if DBG\n{line}\n#endif' if name in dbg_services else line
# Reviewed fixed-width structures absent from the measured catalogue. Each
# has only fixed-width fields (SID ends in a DWORD array). Scalar arrays have
# the same representation on both targets. Unknown names are rejected.
invariant = {'SBDATA', 'SETCLIPBDATA', 'SETSCROLLBARINFO', 'INT', 'COLORREF',
             'LUID', 'SID', 'TPMPARAMS', '-'}
layouts = {}
for row in csv.DictReader((HERE/'catalog/layouts-real.tsv').open(), delimiter='\t'):
    layouts.setdefault(row['struct'], []).append(row)
rows = []
for name in ('userA','userB','gdi'):
    rows.extend(csv.DictReader((HERE/f'catalog/{name}.tsv').open(), delimiter='\t'))
code = ['/* Generated by generate.py; do not edit. */']
coverage = ['name\tclass\timplementation\tdetail']
prototypes = []
failure = ['/* Generated return kinds for failed or unsupported translations. */']
deferred = {'NtUserSetWindowsHookAW': 'HOOKPROC callback translation not implemented'}
for row in rows:
    name, cls = row['name'], row['class']
    reason = ''
    if row['i386_args'] != '-' and name in services and row['args'].startswith('NTSTATUS '):
        failure.append(guarded(name, f'case W64_{name}: return (ULONG_PTR)(LONG_PTR)Status;'))
    if name in dbg_services and row['i386_args'] == '-':
        reason = 'checked-build-only i386 service; catalogue has no i386 argument count'
    elif name not in services or row['i386_args'] == '-': reason = 'no i386 service entry'
    elif name in manual:
        coverage.append(f'{name}\t{cls}\tmanual\tsee user.c, userextra.c, gdi.c and the bucket files')
        continue
    elif name in deferred: reason = deferred[name]
    elif cls[0] not in 'AB': reason = 'requires private structure or selector translation'
    proto = row['args']
    if not reason:
        # B structs are accepted only when the measured layouts agree.
        for typ in row['structs'].split(','):
            typ = typ.strip().rstrip('[]')
            if typ not in layouts and typ not in invariant:
                reason = f'no authoritative layout for {typ}'
                break
            for field in layouts.get(typ, []):
                if (field['i386_offset'],field['i386_size']) != (field['amd64_offset'],field['amd64_size']):
                    reason = f'measured {typ}.{field["field"]} differs'
                    break
    if not reason:
        params = proto.split(name,1)[1].strip()[1:-1]
        params = re.sub(r'\b_\w+_\([^)]*\)|\b_\w+_\b|\b(?:IN|OUT|OPTIONAL)\b','',params)
        args = []
        for i, arg in enumerate(params.split(',')):
            arg = arg.strip()
            if not arg or arg.upper() == 'VOID': continue
            m = re.fullmatch(r'(.*?)\b(\w+)\s*(?:\[[^]]*\])?',arg)
            if not m:
                reason = 'unparsed parameter'; break
            typ, pname = m[1].strip(),m[2]
            base = re.sub(r'\b(?:const|CONST)\b', '', typ).strip()
            mode = overrides.get((name,pname),rules.get(base))
            if base == 'HANDLE' and name.startswith('NtGdi'):
                if name in nt_gdi: mode = 'SIGN'
                elif name == 'NtGdiDvpReleaseNotification':
                    reason = 'opaque video-port/event handle semantics'; break
                else: mode = 'ZERO'
            if base == 'HSURF':
                reason = 'kernel surface pointer cannot round-trip'; break
            if mode:
                val = f'(LONG_PTR)(LONG)a[{i}]' if mode == 'SIGN' else f'(ULONG_PTR)a[{i}]'
            elif base in signed: val = f'(LONG)a[{i}]'
            elif base in unsigned: val = f'a[{i}]'
            elif '*' in base or base.startswith(('P','LP')) or base in ('TIMERPROC','HOOKPROC'):
                # Four-byte aggregate PALETTEENTRY is handled below, not as pointer.
                if base == 'PALETTEENTRY':
                    args.append(f'*(const PALETTEENTRY *)&a[{i}]'); continue
                val = f'(ULONG_PTR)a[{i}]'
            elif base == 'BLENDFUNCTION':
                args.append(f'*(const BLENDFUNCTION *)&a[{i}]'); continue
            else:
                reason = f'unknown carrier {typ}'; break
            args.append(f'({typ})({val})')
        if len(args) != int(row['i386_args']): reason = reason or 'aggregate/slot mismatch'
    if reason:
        coverage.append(f'{name}\t{cls}\tunsupported\t{reason}')
    else:
        ret = proto.split(name,1)[0].replace('NTAPI','').strip()
        call = f'{name}({", ".join(args)})'
        code.append(guarded(name, f'case W64_{name}: ' + (f'{call}; return 0;' if ret == 'VOID' else f'return (ULONG_PTR){call};')))
        coverage.append(f'{name}\t{cls}\tgenerated\ttyped arguments; handle policy; measured layouts'
                        + ('; checked (DBG) builds only' if name in dbg_services else ''))
        # Header declarations remain authoritative; compiler checks each typed call.
(HERE/'generated.inc').write_text('\n'.join(code)+'\n')
(HERE/'coverage.tsv').write_text('\n'.join(coverage)+'\n')
(HERE/'failure.inc').write_text('\n'.join(failure)+'\n')
# Known system pointer messages without a reviewed packer must never reach
# win32k with a guest layout. WM_USER and above belong to the target class or
# application; catalogue control protocols must not block another class's
# scalar message with the same number.
converted = {'WM_CREATE','WM_NCCREATE','WM_NCCALCSIZE','WM_WINDOWPOSCHANGING','WM_WINDOWPOSCHANGED',
             'WM_MEASUREITEM','WM_DRAWITEM','WM_COPYDATA',
             # reviewed in user.c: scalar handles, or (GETDLGCODE) a raw same-thread MSG pointer
             'WM_GETDLGCODE','WM_NEXTDLGCTL','WM_PARENTNOTIFY'}
blocked = {}
for row in csv.DictReader((HERE/'catalog/messages.tsv').open(),delimiter='\t'):
    if row['class'] in ('C','D') and row['message'] not in converted:
        try: value=int(row['value'],0)
        except ValueError: continue
        if value >= 0x400: continue
        blocked.setdefault(value,[]).append(row['message'])
(HERE/'messages-unsupported.inc').write_text('/* Generated from message catalogue. */\n' +
    ''.join(f'case 0x{value:04x}: /* {", ".join(names)} */\n' for value,names in sorted(blocked.items())))
print(f'{len(code)-1} generated, {len(manual)} manual designations, {len(rows)} catalogue rows')
