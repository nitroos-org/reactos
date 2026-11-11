# Console WoW64 comparisons

The three `*_wow64_apitest` targets compile selected kernel32, ntdll and
advapi32 API-test sources with the ordinary Wine test runner. This keeps the
console comparison independent of unrelated GUI/network imports in the full
API-test executables. The full targets remain available.

Build the targets for i386 and run **the same executable files** on native i386
and amd64 with WoW64 enabled. Use the same i386 runtime DLLs on both systems,
set `WINETEST_PLATFORM=reactos`, and record individual test summaries and exits.
An unsupported process launch or missing summary is not a passing test.

The explicit i386 target `wow64_gui_load` is a separate GUI DLL load smoke
test and is not installed in default images. Run it on the WoW64 image to
load user32, gdi32 and imm32 through the ordinary loader, print their loaded
paths, and call SetRect and GdiGetBatchLimit without creating a window. DLL
initialization itself requires win32k translation; a failure here remains
a failure even when the wide DLLs compile and are packaged correctly.
The host-side `sdk/cmake/tests/syswow64-wide.py` checks the Ninja compile
commands (including layout pins and shared rtl sources), guest-only wide
definitions, and the cabinet/live-image copies after `syswow64_stage`.

The selection covers current directories, environment variables, drive types,
code pages, integer SEH, NT registry queries, ACL-bearing registry creation,
registry enumeration and value queries. `Wow64Environment` adds process
queries and filesystem views; `RegWow64` checks isolated and shared registry
keys, root-relative view selection and view-specific deletion. Also run
`RegWow64` as a native amd64 executable to check explicit 32-bit selectors.

`NtQueryKey` checks the physical Wow6432Node name when running under WoW64.
Its existing assumption of at least five software subkeys depends on image
contents. `RtlDetermineDosPathNameType` reports a skip if the optional
`RtlDetermineDosPathNameType_Ustr` export is absent. Keep these residuals in
the comparison rather than suppressing assertions or classifying skips as
passes.

This selection does not establish general service, RPC, network or GUI
support. Guest APCs, additional threads, software exception raising and
floating-point/debug exception contexts require further work. The registry policy follows the Windows 7 shared/redirected matrix for
machine Software and machine/per-user Classes, including the five redirected
COM/media subtrees. Windows 7 does not reflect registry writes. General
registry symbolic-link view propagation remains a separate gate.

Review regression fixtures cover integer continuation and native partial
contexts, Unicode/compressed registry ancestry, native object-name length
bounds, physical roots, nested view creation, repeated separators, volatile
Classes and the shared/redirected matrix. Environment fixtures cover redirected
delete, all six shared directories, native filesystem controls, architecture
variables, installed Program Files values and native environment-block creation.
Native calls without registry selectors are explicit controls; native i386
continues to ignore selectors. The additional guest-thread limitation means
these tests do not claim concurrent guest redirection-isolation coverage.

## Stream sockets

Build the explicit `wow64_socket` target for i386. Its default mode uses public
Winsock interfaces and can also run on Windows: loopback bind/listen/connect,
accept, getsockname, scatter/gather send, receive, nonblocking mode, FIONREAD,
two-socket select, pending receive capture/completion, shutdown and EOF.

The `--bind-abi` and `--afd-abi` modes exercise ReactOS's private AFD/TCP
contracts and must only run on ReactOS. They check TDI handle replies, query
context alignment, IOSB/buffer canaries, pending poll readiness, timeout and
cancellation. WoW64-only malformed requests cover short outputs, invalid
descriptor pointers and allocation-size overflow. Compare the same PE32
fixture on native i386 and WoW64; their counts differ for these private checks.

The `--http` mode requires QEMU user networking and a host loopback HTTP server
on port 18463. Serve a page containing `Local HTTP page loaded.` and wait for
guest DHCP before launching it. The fixture requires an HTTP 200 response,
the page marker and EOF. The `--datagram` mode binds a fresh TCP and a UDP socket
to the wildcard and the loopback address, then runs a UDP sendto/recvfrom and a
connected-UDP exchange on loopback. It guards 32-bit `bind()`: wshtcpip's bind
notification queries the TCP driver through the 32-bit TCP query layout, so a
tcpip.sys built without `BUILD_WOW64_ENABLED` (for instance a driver swapped into a
WoW64 image from a default amd64 build) fails every x86 bind with WSAEINVAL while
x64 passes. Build any driver swapped into a WoW64 image with the same WoW64 options.
All modes print a summary, return nonzero on failure and have a 15-second watchdog.
These tests do not cover the remaining event-select or extended accept/connect
translations.

## System root-store lifetime

The explicit PE32 `wow64_root_store` target opens the local-machine Root store,
enumerates certificates and their SHA-1 properties, closes it with outstanding
reference checking, and repeats three times. Run the executable twice in
separate processes to cover both initial import and a populated registry cache.
It requires an image with installed system root certificates and a registered
cryptographic provider. On a runtime staged into the older WoW64 test image,
register the guest `rsaenh.dll` first, as for the installer tests, and use the
WIN7SP1 compatibility layer. An empty store is a failed prerequisite, not a
passing lifetime test. Use the same executable on native i386 and WoW64.
