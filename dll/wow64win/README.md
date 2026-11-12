# ReactOS win32k translation

This module is built and installed only with BUILD_WOW64_ENABLED. Native
system-service stubs follow w32ksvc64.h; guest dispatch IDs follow the i386
view of w32ksvc32.h. Native user32 is not loaded into the guest process.

`generate.py` is a maintainer tool, not a build dependency. Its checked-in
outputs translate catalogue A/B calls using declared argument types, the
phase-3b handle table, and measured RosBE layouts. Shared wide structures
are native-layout buffers; private syscall and callback buffers remain
ordinary i386 structures. Missing measured layouts require an explicit
reviewed invariant entry. Unknown carriers and hook-dependent arguments
are unsupported. `coverage.tsv` records every catalogue service, including
services with no guest entry. Generated coverage is implementation coverage,
not evidence that every service has passed runtime tests.

`d3dkmt.c` translates the NtGdiDdDDI services whose structures carry pointers
or handles. The native win32k has no display-driver adapter interface, so it
answers STATUS_PROCEDURE_NOT_FOUND and gdi32_vista falls back to its software
adapter; the guest services pass the native status through, with the structure
converted both ways, instead of reporting an unsupported service. Calls that only
an adapter callback would read (allocation, context, lock, present, render, ...)
report that status without reaching the native service.

`user.c` handles creation, class registration, messages, painting, wide
process connection and selector-dependent calls. `userextra.c` translates
menus, system parameters, cursor/icon metadata, clipboard queries and
control information. `gdi.c` translates DIB sections, object queries and
the StartDoc stub. `callback.c` creates a
nested CPU frame on the native call stack, packs arguments on the guest
stack, enters i386 ntdll's callback dispatcher, and widens returned data
before NtCallbackReturn. The previous CPU frame and guest exception chain
are restored on ordinary callback return. Creation strings are packed
relative to their translated CREATESTRUCT, matching ReactOS user32.

Cross-callback RtlUnwind transfers the active guest continuation to the
surviving CPU frame as each native callback is popped. Exception-chain
removal remains with the i386 unwinder. Callback allocation touches guest
stack pages in order to grow the guard page, preserving the reserved stack
guarantee. Normal returns preserve changes to x87 and MXCSR control state.

System messages with a pointer lParam: WM_CREATE, WM_NCCREATE, WM_NCCALCSIZE, WM_WINDOWPOS*, WM_MEASUREITEM,
WM_DRAWITEM, WM_COPYDATA and WM_HELP (HELPINFO, 28/40 bytes) are translated in both directions, including the
kernel-to-window callbacks. win32k keeps no size for WM_COMPAREITEM, WM_DELETEITEM, WM_MDICREATE, WM_MENUGETOBJECT and
CB_GETCOMBOBOXINFO and hands the pointer to the window procedure unread, so a guest pointer travels as it is
(zero-extended) when the receiver is a window of this process and the send waits for it; a window of another process,
SendNotifyMessage and callback sends are refused. WM_NEXTMENU (MDINEXTMENU, 12/24 bytes, written back) is translated in both directions, including the menu loop's own
send to the owner window. WM_DROPOBJECT, WM_QUERYDROPOBJECT, WM_BEGINDRAG, WM_DRAGLOOP, WM_DRAGSELECT, WM_DRAGMOVE (a
DROPSTRUCT win32k never reads) and WM_IME_REQUEST / the pointer commands of WM_IME_CONTROL (IMC_GET/SETCANDIDATEPOS,
COMPOSITIONFONT, COMPOSITIONWINDOW: flat records) travel like the owner-draw messages above, as a same-process guest
pointer; WM_IME_REQUEST, which is not in win32k's pointer table, is also allowed for SendNotifyMessage and callback sends
inside the process, as on i386. The scalar IME commands, WM_IME_NOTIFY and WM_IME_SYSTEM carry no pointer. WM_COPYGLOBALDATA
is a flat block of wParam bytes at the guest pointer: win32k copies it, the receiving user32 makes the new global block.
Still unsupported with a non-NULL lParam: WM_DDE_ADVISE/ACK/DATA/POKE/EXECUTE (and the DDEPOST / DDEGET callbacks).

Current limits include hooks on threads of other processes, journal hooks,
DDE conversation callbacks, IME callbacks,
remaining private structures, printer driver pointers, and unconverted
pointer messages. DDE initialization and string handles work; StartDoc
retains the native service's stub result. Arbitrary
application-defined messages retain their normal integer transport; the
application must define its own cross-bitness protocol.

The explicit `wow64_first_window` and `wow64_win32k_abi` targets are excluded
from normal images. Run the same PE32 executables on i386 and WoW64. The GUI
fixture requires an external mouse click and checks creation payloads,
painting, button notification, destruction and class unregistration.
Additional explicit fixtures cover four exception/unwind paths, a 32-position
stack-boundary sweep, menus/edit/list/combobox controls, clipboard, timers,
common dialogs and a native driver for the guest notepad/regedit executables.
All remain excluded from default image contents. The unwind fixture can run
its child cases through guest CreateProcess or accept individual case numbers.
Installer fixtures also cover outline-font offsets, input contexts, monitor
handles, the thread desktop, and CALLWND hook payloads. Hooks may target the
threads of the calling process, or be global; win32k runs a global hook only
in the setter's process (low-level, keyboard and mouse hooks on the setter's
thread). CBT, message-filter, keyboard, mouse, low-level, shell and idle hook
records are translated both ways, including CallNextHookEx and the CBT
CREATEWND/MOVESIZE writeback. A WH_DEBUG call carries the DEBUGHOOKINFO of the
hook about to run and, for the MSG, mouse, CBT rectangle/activate/click/create
and CALLWND(RET) records, a translated copy of the record its lParam points to
(the CBT_CREATEWND copy has the CREATESTRUCT behind it, the CALLWND ones the data
their message lParam points to). CALLWND message payload coverage follows the
window-message translator.
The `wow64_message_hook` fixture covers current-thread GETMESSAGE hooks,
chaining, signed hook results and MSG writeback for PeekMessage/GetMessage.
WM_NOTIFY records, including application-defined NMHDR extensions, retain
their guest layout when sent to a window on the calling guest thread. The
kernel does not capture these records; hooks and the window procedure receive
the original guest pointer. Other-thread and broadcast WM_NOTIFY remain
unsupported. `wow64_notify` checks delivery, hooks, signed results and writes
to the original record.

Regenerate with `python3 dll/wow64win/generate.py`. On the build host, run
`TMPDIR=<scratch-directory> python3 dll/wow64win/tests/generator.py <source>`
to verify determinism, handle-policy propagation, rejection of measured
layout drift, and failure/message metadata.
