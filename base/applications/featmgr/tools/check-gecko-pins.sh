#!/bin/bash
# check-gecko-pins.sh [SRCROOT]
# The Wine Gecko download of appwiz's add-on prompt (dll/cpl/appwiz/addons.c) and the featmgr catalog entry
# (base/applications/featmgr/catalog/components.ini, [wine-gecko] x86 and [wine-gecko-x64]) must name the same
# sources and checksums: an install by either is then seen by the other. Compares the URL and the SHA-1 of each
# architecture and exits 1 on any difference. Pure text check, nothing is downloaded.
root=${1:-$(cd "$(dirname "$0")/../../../.." && pwd)}
addons=$root/dll/cpl/appwiz/addons.c
comp=$root/base/applications/featmgr/catalog/components.ini
fail=0
# addons.c: the SHA-1 under #ifdef __i386__ / x86_64, and the two URLs
a_x86_sha=$(awk '/#ifdef __i386__/{f=1} f&&/GECKO_SHA/{print; exit}' "$addons" | sed 's/.*"\([0-9a-f]*\)".*/\1/')
a_x64_sha=$(awk '/defined\(__x86_64__\)/{f=1} f&&/GECKO_SHA/{print; exit}' "$addons" | sed 's/.*"\([0-9a-f]*\)".*/\1/')
a_x64_url=$(grep -m1 'GeckoUrl\[\] = L"https[^"]*x86_64' "$addons" | sed 's/.*L"\([^"]*\)".*/\1/')
a_x86_url=$(grep -m1 'GeckoUrl\[\] = L"https[^"]*x86\.msi' "$addons" | sed 's/.*L"\([^"]*\)".*/\1/')
sect() { tr -d '\r' < "$comp" | awk -v s="[$1]" '$0==s{f=1;next} /^\[/{f=0} f&&index($0,"'"$2"'=")==1{sub(/^[^=]*=/,"");print;exit}'; }
c_x86_url=$(sect wine-gecko Url);      c_x86_sha=$(sect wine-gecko Sha1)
c_x64_url=$(sect wine-gecko-x64 Url);  c_x64_sha=$(sect wine-gecko-x64 Sha1)
chk() { if [ -n "$2" ] && [ "$2" = "$3" ]; then echo "ok   $1: $2"; else echo "FAIL $1: appwiz='$2' featmgr='$3'"; fail=1; fi; }
chk "x86 url"      "$a_x86_url" "$c_x86_url"
chk "x86 sha1"     "$a_x86_sha" "$c_x86_sha"
chk "x86_64 url"   "$a_x64_url" "$c_x64_url"
chk "x86_64 sha1"  "$a_x64_sha" "$c_x64_sha"
exit $fail
