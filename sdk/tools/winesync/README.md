# winesync: keeping NitroOS's Wine-derived modules in step with upstream Wine

This directory has two tools that work on the same module configs.

| Tool | What it does | When to use it |
|---|---|---|
| `winewatch.py` (NitroOS) | `scan`: finds, per module, the Wine tag it was imported from and how far behind Wine it is; writes the report and the module configs. `merge`: syncs one module to a Wine tag with a 3-way merge. `check`: lists `media/doc/WINESYNC.txt` claims the files contradict. Needs only `python3` and `git` >= 2.38. | Everything routine. This is the recommended path. |
| `winesync.py` (upstream ReactOS) | Replays every Wine commit that touched a module, one ReactOS commit per Wine commit, optionally with wine-staging patches. Needs `pygit2` and `PyYAML`, a Wine clone, a wine-staging clone, and a `winesync.cfg` in the current directory. | Modules that are byte-identical to a Wine tag and for which the per-commit history is wanted. It breaks on the first rejected hunk, so it is poor for modules with local changes. |

Configs: `<module>.cfg` here are the 15 hand-written upstream configs (they also map headers and programs). `modules/<module>.cfg`
are generated, one per Wine-derived module of `dll/win32` and `dll/directx/wine`. A module name that exists at top level wins;
`winesync.py` and `winewatch.py merge` look in both places. Do not hand-edit the `wine:` tag of a generated config to "fix" a module:
it records the Wine tag the tree currently matches, and `merge` moves it.

Wine reference clone: a full-history blobless clone is enough and costs about 1 GB.

    git clone --filter=blob:none https://gitlab.winehq.org/wine/wine.git wine
    git -C wine fetch --tags origin        # on every new Wine release

Blobs are fetched on demand (batched by the tool). `winewatch.py scan` also needs a ReactOS-upstream ref, `upstream/master`,
in the NitroOS worktree: the NitroOS-local commits are `git log upstream/master..HEAD -- <module>`.

## How the detection works

1. Wine's history is indexed once per run (`git log --raw` over `dlls/`, `programs/`, `include/`; the history is linear, so a
   commit's position orders everything). For every blob, that gives the interval of Wine history in which it was the content of
   a path. Release tags map to positions.
2. For each module the ReactOS files are hashed (raw bytes, as `git hash-object --no-filters`; the same blob id Wine would
   have). A file whose blob equals Wine's blob at the same path (or anywhere in `dlls/<module>/` if Wine moved it) is an *exact
   match*, valid for the tags inside its interval. This is the `git log --find-object` idea, answered from one pass over the
   history instead of one `git log` per file.
3. The module's imported tag is the tag range where the most files match; the lowest tag of that range is the merge base (the
   WINESYNC.txt claim is used instead when it lies in the range). A module with no or a handful of exact files gets the
   closest candidate by diff size instead and is marked `*`.
4. Per module, with trees limited to the files both sides have: Wine changes base to dev and base to stable (the "lines behind"),
   ReactOS-local changes against base, and a `git merge-tree --write-tree` of base, ReactOS and the dev tag for the clean/conflict
   pre-check. Nothing is written to the NitroOS tree by `scan`; the helper objects go to the Wine clone's object database.
5. Class: (a) clean (<=15% local diff, no code conflicts, no files added/removed upstream), (b) needs porting (conflicts, 15-40%
   local diff, or files added/removed), (c) ROS-diverged (>40% local diff, no Wine base, or listed in `class-overrides.tsv`).

The report (`process/WINESYNC-REPORT.md` in the harness) is regenerated, not edited:

    cd /root/ros/winesync   # any directory; the clones are arguments
    python3 src/sdk/tools/winesync/winewatch.py scan --wine wine --ros src \
        --out-md WINESYNC-REPORT.md --out-tsv wine-map.tsv --out-json scan.json

Add `--write-configs` to (re)write `modules/*.cfg` from the detected tags. It takes about 15 minutes on the first run (blob fetches).

## Adding a module config

Normally `scan --write-configs` does it for every module that has a `dlls/<name>` in Wine. By hand (modules outside
`dll/win32` and `dll/directx/wine`, or ones that need header/program mappings), create `modules/<name>.cfg`:

    directories:
      dlls/winhttp: dll/win32/winhttp                       # Wine directory: ReactOS directory (flat; list subdirectories separately)
      dlls/winhttp/tests: modules/rostests/winetests/winhttp
      programs/msiexec: base/system/msiexec
    files:
      include/winhttp.h: sdk/include/psdk/winhttp.h         # single files, e.g. headers
    tags:
      wine: wine-10.0                                       # the Wine tag the tree currently equals

Rules: the tag must be one the tree really equals (use `scan` output, not the WINESYNC.txt claim); one Wine path maps to one ReactOS
path; do not map Wine headers that ReactOS carries differently (its `sdk/include/psdk` headers are often reworked).
Module names for configs are ReactOS directory names (`d3dx9_36`, `hhctrl.ocx`). Shared-source families (d3dx9_24..43,
d3dcompiler_33..47) are synced through their primary module; the others only hold a `.spec` and `version.rc`.

## Syncing a module to a tag

    python3 sdk/tools/winesync/winewatch.py merge winhttp wine-11.21 --wine ../wine --ros . --dry-run   # look first
    python3 sdk/tools/winesync/winewatch.py merge winhttp wine-11.21 --wine ../wine --ros .

`merge` builds three trees from the files both sides have (Wine at the config's base tag, the ReactOS files, Wine at the target tag)
and runs `git merge-tree --write-tree`. Where only Wine changed a file, the Wine version arrives; where only ReactOS changed it,
the ReactOS version stays; where both changed it, the hunks are merged and conflicts are written into the file as markers (the
command then exits 1). It also removes files Wine deleted (if ReactOS never touched them), prints new Wine files that ReactOS does not have,
bumps `tags.wine` in the config and rewrites the module's line in `media/doc/WINESYNC.txt`. It never commits and refuses a dirty module path.

After it runs: resolve conflict markers, add the new files it listed (and the matching `CMakeLists.txt` entries) if the new Wine
code needs them, build i386 and amd64 in Release and Debug, run the module's winetests on the base build and on the fix (same
counts or better; the `todo_ros`/`broken` lines may only shrink), then commit one module per commit:

    git commit -m "[WINHTTP] Sync to Wine-11.21"

## ReactOS/NitroOS-local diffs

* The 3-way merge keeps them. A local hunk that Wine has also changed conflicts; resolve by keeping the Wine change and re-applying
  the ReactOS intent on top, not by dropping either. If Wine's version already fixes the same bug, drop the local hunk and say so in the commit.
* Keep local changes minimal and fenced: `#ifdef __REACTOS__` (or the fork's equivalent) around hunks that cannot go away; a
  one-line comment says why. A sync that has to resolve an unfenced local hunk should fence it.
* A module with many local changes (class b or c in the report) is not bulk-synced. For class (c) never sync the directory: take
  single functions or test files (the `kernel32` profile.c and `setupapi` disk-space imports were done that way) and note them in WINESYNC.txt.
* Local NitroOS commits are listed per module in the report; read them before a sync of that module.
* A dependency the new Wine code needs (a newer ntdll/kernelbase API, `win32u`, mmdevapi, the NT 6.x split at 0x603) is not
  a conflict the merge can find: the build or the winetests show it. Then stay on the old tag, record why in WINESYNC.txt, and open a ticket.

## Keeping media/doc/WINESYNC.txt honest

`media/doc/WINESYNC.txt` is a hand-kept claim; the files are the evidence. Rules:

* Every sync commit changes the module's line to `Synced to Wine-<tag>` (`merge` does it). Partial imports say so: `Synced to Wine-11.19 (profile.c only)`.
* A module whose tree equals no Wine version says `Forked at Wine-<tag>` (with the reason, as dsound does).
* The weekly scan's "WINESYNC.txt discrepancies" table lists every module whose claim is not inside the detected tag range; fix the claim
  (or find the stray local change) in the same sync batch. `winewatch.py check scan.json` prints the same list.
* New Wine-derived modules get a line when added, under the right heading.

## Licence notes

* Wine is LGPL-2.1-or-later. The NitroOS/ReactOS tree's default is GPL-2.0-or-later; LGPL code is compatible and stays LGPL: keep every
  file's copyright and licence header exactly as Wine has it (a sync that removes a header is a bug). Do not relicense Wine files.
* New files that only exist on the ReactOS side use the normal ReactOS header (SPDX `GPL-2.0-or-later` or `LGPL-2.1-or-later` for code
  that is meant to flow back to Wine). Code taken from Wine-staging keeps its LGPL header.
* Local patches to a Wine file are under that file's licence.
* Wine-staging patches (`winesync.py` third argument) bring their own authors; keep the commit message trailer the tool writes.
* **Clean-room rule: Wine source is fine as a source; Microsoft source never is.** Never obtain, read or keep leaked or otherwise
  non-public Microsoft source code, not even to validate behaviour, and do not copy code, tables or structure layouts out of Microsoft
  binaries. Use documented behaviour, Wine's tests and black-box oracle probes. If a Wine file's licence or provenance looks wrong
  (a header that claims Microsoft authorship, `#include`s from a Microsoft SDK internal), stop and ask. See `OPERATING.md` in the harness.
* We do not upstream (no pushes or issues to Wine or ReactOS); this tool only pulls.

## Files

* `winewatch.py`: the tool. `class-overrides.tsv`: modules forced to a class (the ReactOS-native ones), with the reason; edit it, then rescan.
* `modules/*.cfg`: generated per-module configs. `*.cfg` at top level: the original hand-written ones.
* `winesync.py`: the upstream commit-replay tool (unchanged apart from reading `modules/<name>.cfg` too).
