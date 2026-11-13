#!/bin/bash
# Rebuild data/icudtl.dat: ICU 64.2 data filtered to the locales the ReactOS NLS knows (see README.ReactOS, "Data file").
#   build-filtered-data.sh WORKDIR LOCALES_FILE OUT_DAT
# Env: JOBS (make -j, default nproc).
# WORKDIR is empty or new; it receives the unpacked ICU sources and the build. Needs Linux, gcc/g++, make, python3, curl.
#   LOCALES_FILE  one ICU locale name per line (en_GB, sr_Latn_RS, zh_Hant, ...): the locales .NET may enumerate, i.e. those
#                 for which GetLocaleInfoEx(name, LOCALE_SNAME) succeeds. Their parents and root are kept as data, not listed.
set -euo pipefail
W=$(realpath -m "$1"); L=$(realpath "$2"); OUT=$(realpath -m "$3")
mkdir -p "$W"; cd "$W"
base=https://github.com/unicode-org/icu/releases/download/release-64-2
[ -f src.tgz ]  || curl -sL -o src.tgz  $base/icu4c-64_2-src.tgz
[ -f data.zip ] || curl -sL -o data.zip $base/icu4c-64_2-data.zip
echo "627d5d8478e6d96fc8c90fed4851239079a561a6a8b9e48b0892f24e82d31d6c  src.tgz" | sha256sum -c -
echo "fba0e89f5b3f285d722a83317647bffee69b6f1eb8d067d5da03c5677c45e510  data.zip" | sha256sum -c -
mkdir -p unpack && tar xzf src.tgz -C unpack && python3 -I -m zipfile -e data.zip unpack/icu/source
S=$W/unpack/icu/source
rm -f "$S/data/in/icudt64l.dat"     # else make copies the prebuilt unfiltered package instead of building from source
# Filter: only the locale files of the listed locales and their ancestors (includeChildren false: no en_150 just for "en").
# yue is data only: the CLDR 35 rbnf fallback of zh_Hant_HK.
python3 -I - "$L" "$W/filter.json" <<PY
import json, sys
n = [l.strip() for l in open(sys.argv[1]) if l.strip()] + ["yue"]
json.dump({"localeFilter": {"filterType": "locale", "includeChildren": False, "includeScripts": False,
           "whitelist": sorted(set(n))}}, open(sys.argv[2], "w"), indent=1)
PY
mkdir -p build && cd build
ICU_DATA_FILTER_FILE=$W/filter.json $S/runConfigureICU Linux --disable-shared --enable-static \
  --with-data-packaging=archive --disable-samples --disable-tests --disable-extras --disable-layoutex > ../configure.log 2>&1
make -j"${JOBS:-$(nproc)}" > ../make.log 2>&1
B=$W/build/data/out/build/icudt64l
export LD_LIBRARY_PATH=$W/build/lib:$W/build/stubdata
# The ICU 64.2 filter drops the res_index.res requests (they have no input file), so write them here. Root index =
# exactly the listed locales (what uloc_getAvailable() and so .NET CultureInfo.GetCultures() enumerate); sub trees = what is there.
gen() { # tree names...
  local tree=$1; shift; local t; t=$(mktemp -d)
  { echo "res_index:table(nofallback) {"; [ "$tree" = . ] && echo '    CLDRVersion { "35.1" }'
    echo "    InstalledLocales {"; for n in "$@"; do echo "        $n {\"\"}"; done; echo "    }"; echo "}"; } > $t/res_index.txt
  mkdir -p "$B/$tree"; $W/build/bin/genrb -s $t -d "$B/$tree" -i "$B" -k res_index.txt; rm -rf $t
}
gen . $(sort "$L")
for t in brkitr coll curr lang rbnf region unit zone; do
  gen $t $(cd $B/$t && ls *.res | sed 's/\.res$//' | grep -v -x -e root -e res_index | sort)
done
( cd $B && find . -type f -not -name '*.lst' | sed 's|^\./||' | sort ) > $W/pkg.lst
# the item names take the package prefix from the output file name, which must be icudt64l.dat
mkdir -p $W/pkgout && $W/build/bin/icupkg -t l -s $B -a $W/pkg.lst new $W/pkgout/icudt64l.dat 2>&1 | sort -u | head -20
cp $W/pkgout/icudt64l.dat "$OUT"
