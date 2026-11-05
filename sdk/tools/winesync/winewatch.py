#!/usr/bin/env python3
# PROJECT:     NitroOS / ReactOS
# LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
# PURPOSE:     Wine sync tooling: detect the Wine version each module was imported from,
#              report how far behind Wine each module is, generate module configs for
#              winesync.py, and sync a module to a Wine tag with a 3-way merge.
#              Needs only python3 and git (>= 2.38); no pygit2, no PyYAML.
#
# Subcommands:  scan | merge | check     (see README.md in this directory)

import argparse
import bisect
import collections
import json
import os
import re
import subprocess
import sys
import tempfile
import time

ZERO = '0' * 40
EMPTY_TREE = '4b825dc642cb6eb9a060e54bf8d69288fbee4904'
RELTAG = re.compile(r'^wine-(\d+(?:\.\d+)+)$')
HERE = os.path.dirname(os.path.abspath(__file__))
ROS_PARENTS = ('dll/win32', 'dll/directx/wine')
TESTS_PARENT = 'modules/rostests/winetests'
# Wine files that never exist on the ReactOS side (build system, translations, ...)
IGNORE_UPSTREAM = re.compile(r'(^|/)(Makefile\.in|\.gitignore|po/.*|.*\.po|.*\.pot)$')


def log(msg):
    print(msg, file=sys.stderr, flush=True)


class Repo:
    """Thin git wrapper."""

    def __init__(self, path):
        self.path = path

    def run(self, *args, input=None, env=None, check=True):
        e = dict(os.environ)
        if env:
            e.update(env)
        p = subprocess.run(['git', '-C', self.path] + list(args), input=input,
                           capture_output=True, env=e)
        if check and p.returncode != 0:
            raise RuntimeError('git %s failed (%d): %s' % (' '.join(args[:3]), p.returncode,
                                                           p.stderr.decode('utf-8', 'replace')[:400]))
        return p

    def out(self, *args, **kw):
        return self.run(*args, **kw).stdout.decode('utf-8', 'replace')

    def make_tree(self, entries):
        """entries: {path: oid} (regular files) -> tree oid, via a throw-away index."""
        with tempfile.TemporaryDirectory() as td:
            env = {'GIT_INDEX_FILE': os.path.join(td, 'index')}
            data = ''.join('100644 %s\t%s\n' % (oid, path) for path, oid in sorted(entries.items()))
            self.run('update-index', '--add', '--index-info', input=data.encode(), env=env)
            return self.out('write-tree', env=env).strip()

    def commit_of(self, tree):
        """git merge-tree wants commits: wrap a tree in a parentless commit."""
        env = {'GIT_AUTHOR_NAME': 'winewatch', 'GIT_AUTHOR_EMAIL': 'winewatch@localhost',
               'GIT_COMMITTER_NAME': 'winewatch', 'GIT_COMMITTER_EMAIL': 'winewatch@localhost'}
        return self.out('commit-tree', tree, '-m', 'winewatch', env=env).strip()

    def merge3(self, base_tree, ours_tree, theirs_tree):
        """3-way merge of three trees -> (rc, merged_tree, [conflicted paths]); rc 0 clean, 1 conflicts."""
        b, o, t = (self.commit_of(x) for x in (base_tree, ours_tree, theirs_tree))
        p = self.run('merge-tree', '--write-tree', '--name-only', '--no-messages', '--merge-base=' + b, o, t,
                     check=False)
        lines = p.stdout.decode('utf-8', 'replace').splitlines()
        if p.returncode > 1 or not lines:
            raise RuntimeError('merge-tree failed: ' + p.stderr.decode('utf-8', 'replace')[:300])
        return p.returncode, lines[0].strip(), ([l for l in lines[1:] if l.strip()] if p.returncode == 1 else [])

    def prefetch(self, oids):
        """Fetch missing blobs of a blobless clone in batches (one round trip per 1500 objects)."""
        if getattr(self, 'present', None) is None:
            self.present = set(self.out('cat-file', '--batch-all-objects', '--batch-check=%(objectname)').split())
        need = sorted(set(oids) - self.present)
        for i in range(0, len(need), 1500):
            self.run('fetch', '-q', 'origin', '--no-tags', '--no-write-fetch-head', *need[i:i + 1500], check=False)
        self.present.update(need)


# ---------------------------------------------------------------------------------------------
# Wine history index
# ---------------------------------------------------------------------------------------------
class WineHistory:
    def __init__(self, wine_path, branch='master'):
        self.repo = Repo(wine_path)
        t0 = time.time()
        revs = self.repo.out('rev-list', '--reverse', branch).split()
        self.pos = {h: i for i, h in enumerate(revs)}
        self.head = revs[-1]
        tags = []  # release tags on the (linear) master history
        for line in self.repo.out('for-each-ref', '--format=%(refname:strip=2) %(objectname) %(*objectname)',
                                  'refs/tags').splitlines():
            f = line.split()
            if not RELTAG.match(f[0]):
                continue
            commit = f[2] if len(f) > 2 else f[1]
            if commit in self.pos:
                tags.append((self.pos[commit], f[0]))
        tags.sort()
        self.tagpos = [p for p, _ in tags]
        self.tagname = [n for _, n in tags]
        self.tagidx = {n: i for i, n in enumerate(self.tagname)}
        # blob oid -> [(path, start_pos, end_pos)]: the blob was the content of path for positions in [start, end)
        self.iv = collections.defaultdict(list)
        self.dlldirs = set()
        INF = len(revs) + 1
        cur = {}
        pos = -1
        raw = self.repo.run('log', '--reverse', '--no-renames', '--raw', '--no-abbrev', '--format=C %H',
                            branch, '--', 'dlls', 'programs', 'include').stdout
        for line in raw.decode('utf-8', 'replace').splitlines():
            if line.startswith('C '):
                pos = self.pos[line[2:]]
            elif line.startswith(':'):
                meta, path = line.split('\t', 1)
                new = meta.split()[3]
                old = cur.pop(path, None)
                if old:
                    self.iv[old[0]].append((path, old[1], pos))
                if new != ZERO:
                    cur[path] = (new, pos)
                if path.startswith('dlls/'):
                    self.dlldirs.add(path.split('/')[1])
        for path, (oid, s) in cur.items():
            self.iv[oid].append((path, s, INF))
        log('wine history: %d commits, %d release tags, %d blob states, %.0fs'
            % (len(revs), len(tags), len(self.iv), time.time() - t0))

    def rev_pos(self, rev):
        c = self.repo.out('rev-parse', '--verify', rev + '^{commit}').strip()
        return self.pos.get(c)

    def resolvable(self, rev):
        return self.repo.run('rev-parse', '--verify', '-q', rev + '^{commit}', check=False).returncode == 0

    def tag_range(self, s, e):
        """indexes of the release tags whose position lies in [s, e)"""
        return bisect.bisect_left(self.tagpos, s), bisect.bisect_left(self.tagpos, e) - 1

    def detect(self, dll, files):
        """files: {rel: oid} (rel as in dlls/<dll>/<rel>) -> (lo_tag, hi_tag, n_exact) or None.
        The range is where the most ReactOS blobs equal the Wine blob at the same path."""
        n = len(self.tagname)
        diff = [0] * (n + 2)
        prefix = 'dlls/%s/' % dll
        for rel, oid in files.items():
            ivs = self.iv.get(oid)
            if not ivs:
                continue
            same = [iv for iv in ivs if iv[0] == prefix + rel] or [iv for iv in ivs if iv[0].startswith(prefix)]
            ranges = sorted(r for r in (self.tag_range(s, e) for _, s, e in same) if r[0] <= r[1])
            if not ranges:
                continue
            merged = [list(ranges[0])]
            for lo, hi in ranges[1:]:
                if lo <= merged[-1][1] + 1:
                    merged[-1][1] = max(merged[-1][1], hi)
                else:
                    merged.append([lo, hi])
            for lo, hi in merged:
                diff[lo] += 1
                diff[hi + 1] -= 1
        counts, c = [], 0
        for i in range(n):
            c += diff[i]
            counts.append(c)
        best = max(counts) if counts else 0
        if best == 0:
            return None
        hi = max(i for i in range(n) if counts[i] == best)
        lo = hi
        while lo > 0 and counts[lo - 1] == best:
            lo -= 1
        return self.tagname[lo], self.tagname[hi], best

    def tag_span(self, lo, hi):
        """(first position of tag lo, position where tag hi+1 starts) for 'is rev inside the range' checks"""
        li, hi_i = self.tagidx[lo], self.tagidx[hi]
        end = self.tagpos[hi_i + 1] if hi_i + 1 < len(self.tagpos) else 10 ** 9
        return self.tagpos[li], end


# ---------------------------------------------------------------------------------------------
# ReactOS side
# ---------------------------------------------------------------------------------------------
class Ros:
    def __init__(self, path):
        self.repo = Repo(path)
        self.path = path
        self.files = [f for f in self.repo.out('ls-files', '-z').split('\0') if f]

    def under(self, prefix):
        prefix = prefix.rstrip('/') + '/'
        return [f for f in self.files if f.startswith(prefix)]


def hash_into(wine, ros_path, paths):
    """Write ReactOS worktree files into the Wine object db (raw bytes) so git can diff/merge them."""
    out = {}
    paths = list(paths)
    for i in range(0, len(paths), 4000):
        chunk = paths[i:i + 4000]
        inp = ''.join(os.path.join(ros_path, p) + '\n' for p in chunk)
        res = wine.out('hash-object', '-w', '--no-filters', '--stdin-paths', input=inp.encode()).split()
        out.update(zip(chunk, res))
    return out


def load_cfg(path):
    """Read a winesync module .cfg (PyYAML if present, else a reader for the simple subset used here)."""
    try:
        import yaml
        with open(path) as f:
            c = yaml.safe_load(f)
    except ImportError:
        c, sect = {}, None
        with open(path) as f:
            for line in f:
                line = line.split('#', 1)[0].rstrip()
                if not line.strip():
                    continue
                if not line.startswith(' '):
                    k, _, v = line.partition(':')
                    sect = k.strip()
                    c[sect] = {}
                else:
                    k, _, v = line.strip().partition(': ')
                    c[sect][k.strip()] = v.strip()
    c['directories'] = c.get('directories') or {}
    c['files'] = c.get('files') or {}
    return c


def find_cfg(module):
    for p in (os.path.join(HERE, module + '.cfg'), os.path.join(HERE, 'modules', module + '.cfg')):
        if os.path.isfile(p):
            return p
    raise SystemExit('no config for module %r (looked in %s and modules/)' % (module, HERE))


def parse_winesync_txt(path):
    """{ros_dir: (comment, hint_rev_or_None)} from media/doc/WINESYNC.txt"""
    out = {}
    if not os.path.isfile(path):
        return out
    for line in open(path, encoding='utf-8', errors='replace'):
        m = re.match(r'^((?:dll|base|sdk|modules)/\S+)\s*(?:=>\s*\S+)?\s*#\s*(.*)$', line.rstrip())
        if not m:
            continue
        d, comment = m.group(1), m.group(2)
        hint = None
        mc = re.search(r'\(([0-9a-f]{10,40})\)', comment)
        mt = re.search(r'(?:Wine|WineStaging|wine)-(\d+\.\d+(?:\.\d+)?)', comment)
        if mc and 'dev' in comment:
            hint = mc.group(1)
        elif mt:
            hint = 'wine-' + mt.group(1)
        out[d] = (comment, hint)
    return out


def load_overrides(path):
    out = {}
    if os.path.isfile(path):
        for line in open(path):
            if line.startswith('#') or not line.strip():
                continue
            f = line.rstrip('\n').split('\t')
            if len(f) >= 2:
                out[f[0]] = (f[1], f[2] if len(f) > 2 else '')
    return out


# ---------------------------------------------------------------------------------------------
# scan
# ---------------------------------------------------------------------------------------------
class Scanner:
    def __init__(self, args):
        self.args = args
        self.hist = WineHistory(args.wine)
        self.wine = self.hist.repo
        self.ros = Ros(args.ros)
        self.dev = args.dev or self.hist.tagname[-1]
        self.stable = args.stable or [n for n in self.hist.tagname if re.match(r'^wine-\d+\.0$', n)][-1]
        self.treecache = {}
        self.txt = parse_winesync_txt(os.path.join(args.ros, 'media/doc/WINESYNC.txt'))
        self.over = load_overrides(os.path.join(HERE, 'class-overrides.tsv'))
        self.handcfg = {}
        for f in sorted(os.listdir(HERE)):
            if f.endswith('.cfg'):
                try:
                    self.handcfg[f[:-4]] = load_cfg(os.path.join(HERE, f))
                except Exception:
                    pass

    def wine_dll(self, rev, dll):
        """{rel: oid} for dlls/<dll> at rev (one ls-tree per rev, cached)."""
        if rev not in self.treecache:
            d = collections.defaultdict(dict)
            for ent in self.wine.out('ls-tree', '-r', '-z', rev, 'dlls').split('\0'):
                if ent:
                    meta, path = ent.split('\t', 1)
                    parts = path.split('/', 2)
                    if len(parts) == 3:
                        d[parts[1]][parts[2]] = meta.split()[2]
            self.treecache[rev] = d
        return self.treecache[rev].get(dll, {})

    def discover(self):
        mods, seen = [], set()
        for parent in ROS_PARENTS:
            names = sorted({f[len(parent) + 1:].split('/')[0] for f in self.ros.files
                            if f.startswith(parent + '/') and f.count('/') > parent.count('/') + 1})
            for name in names:
                if name in seen or name not in self.hist.dlldirs:
                    continue
                seen.add(name)
                tdir = TESTS_PARENT + '/' + name
                mods.append({'name': name, 'parent': parent, 'rdir': parent + '/' + name,
                             'tdir': tdir if self.ros.under(tdir) else None})
        return mods

    def module_files(self, m, blobs):
        ours = {f[len(m['rdir']) + 1:]: blobs[f] for f in self.ros.under(m['rdir'])}
        if m['tdir']:
            ours.update({'tests/' + f[len(m['tdir']) + 1:]: blobs[f] for f in self.ros.under(m['tdir'])})
        return ours

    def numstat(self, a, b):
        """(code_lines, test_lines, code_files, test_files) changed between two trees"""
        code = tests = cf = tf = 0
        for line in self.wine.out('diff', '--numstat', '--no-renames', a, b).splitlines():
            ad, de, path = line.split('\t', 2)
            n = 0 if ad == '-' else int(ad) + int(de)
            if path.startswith('tests/'):
                tests += n
                tf += 1
            else:
                code += n
                cf += 1
        return code, tests, cf, tf

    def stats(self, m, ours, base, dev, stable):
        """3-way pre-check and line statistics (trees limited to the files both sides have)."""
        dll = m['name']
        wb, wd, ws = self.wine_dll(base, dll), self.wine_dll(dev, dll), self.wine_dll(stable, dll)
        common = {r: o for r, o in ours.items() if r in wb}
        res = {'n_common': len(common), 'ros_only': len(ours) - len(common)}
        if not common:
            return res
        B = {r: wb[r] for r in common}
        T = {r: wd[r] for r in common if r in wd}
        S = {r: ws[r] for r in common if r in ws}
        self.wine.prefetch(list(B.values()) + list(T.values()) + list(S.values()))
        tb, to, tt = self.wine.make_tree(B), self.wine.make_tree(common), self.wine.make_tree(T)
        res['up_code'], res['up_tests'], res['up_files'], res['up_tfiles'] = self.numstat(tb, tt)
        res['loc_code'], res['loc_tests'], res['loc_files'], res['loc_tfiles'] = self.numstat(tb, to)
        tot_c = tot_t = 0  # total lines of the common base files = diff against the empty tree
        for line in self.wine.out('diff', '--numstat', '--no-renames', EMPTY_TREE, tb).splitlines():
            ad, _, path = line.split('\t', 2)
            n = 0 if ad == '-' else int(ad)
            if path.startswith('tests/'):
                tot_t += n
            else:
                tot_c += n
        res['tot_code'], res['tot_tests'] = tot_c, tot_t
        res['removed_up'] = sorted(r for r in common if r not in wd)
        res['new_up'] = sorted(r for r in wd if r not in ours and not IGNORE_UPSTREAM.search(r))
        bp, sp = self.hist.rev_pos(base), self.hist.rev_pos(stable)
        if bp <= sp:
            res['st_code'], res['st_tests'], _, _ = self.numstat(tb, self.wine.make_tree(S))
        else:
            res['st_code'] = res['st_tests'] = 0
            res['st_ahead'] = True
        res['merge_rc'], _, res['conflicts'] = self.wine.merge3(tb, to, tt)
        return res

    def local_commits(self, m):
        paths = [m['rdir']] + ([m['tdir']] if m['tdir'] else [])
        out = self.ros.repo.out('log', '--no-merges', '--format=%h %s', 'upstream/master..HEAD', '--', *paths)
        lines = [l for l in out.splitlines() if l]
        return len(lines), lines[:3]

    def claim_check(self, hint, lo, hi):
        if not hint:
            return 'no claim'
        if not self.hist.resolvable(hint):
            return 'claim unresolvable'
        hp = self.hist.rev_pos(hint)
        s, e = self.hist.tag_span(lo, hi)
        if s <= hp < e:
            return 'ok'
        return 'claims NEWER than the files' if hp >= e else 'claims OLDER than the files'

    def scan(self):
        mods = self.discover()
        log('modules: %d' % len(mods))
        allpaths = []
        for m in mods:
            allpaths += self.ros.under(m['rdir'])
            if m['tdir']:
                allpaths += self.ros.under(m['tdir'])
        blobs = hash_into(self.wine, self.args.ros, allpaths)
        results = []
        for k, m in enumerate(mods):
            name = m['name']
            ours = self.module_files(m, blobs)
            det = self.hist.detect(name, ours)
            comment, hint = self.txt.get(m['rdir'], ('', None))
            r = dict(m)
            r.update(n_files=len(ours), claim=comment, hint=hint, hand_cfg=name in self.handcfg)
            if name in self.handcfg:
                r['cfg_tag'] = (self.handcfg[name].get('tags') or {}).get('wine')
            base, how = None, ''
            if det:
                lo, hi, nex = det
                r.update(tag_lo=lo, tag_hi=hi, n_exact=nex)
                base, how = lo, 'blob'
                r['claim_check'] = self.claim_check(hint, lo, hi)
                if r['claim_check'] == 'ok':
                    base = hint
            else:
                r.update(tag_lo=None, tag_hi=None, n_exact=0, claim_check='no exact blob (all files modified)')
            weak = (not det) or (det[2] * 2 < len(ours) and det[2] < 5)
            if weak:  # few or no byte-identical files: pick the closest candidate by diff size
                best = None
                for c in dict.fromkeys(x for x in (hint, base, 'wine-10.0', self.dev) if x):
                    if not self.hist.resolvable(c):
                        continue
                    s = self.stats(m, ours, c, self.dev, self.stable)
                    if 'loc_code' not in s:
                        continue
                    score = s['loc_code'] + s['loc_tests']
                    if best is None or score < best[0]:
                        best = (score, c, s)
                if best:
                    base, how = best[1], ('closest' if not det else 'blob+closest')
                    r['stats'] = best[2]
            r['local_n'], r['local_subj'] = self.local_commits(m)
            if base is None:
                r.update(base=None, how='none', cls='c', why='no common files with Wine', stats={})
                results.append(r)
                continue
            r['base'], r['how'] = base, how
            if 'stats' not in r:
                r['stats'] = self.stats(m, ours, base, self.dev, self.stable)
            bp = self.hist.rev_pos(base)
            r['base_tags_behind'] = sum(1 for p in self.hist.tagpos if p > bp)
            r['cls'], r['why'] = self.classify(r)
            results.append(r)
            if (k + 1) % 50 == 0:
                log('  %d/%d' % (k + 1, len(mods)))
        return results

    def classify(self, r):
        name = r['name']
        if name in self.over:
            return self.over[name][0], 'override: ' + self.over[name][1]
        s = r['stats']
        if not s.get('n_common'):
            return 'c', 'no common files with Wine'
        full = (s['loc_code'] + s['loc_tests']) / max(1, s['tot_code'] + s['tot_tests'])
        if r['how'] == 'closest' and full > 0.40:
            return 'c', 'no exact files; closest base still differs by %d%%' % (full * 100)
        ratio = s['loc_code'] / max(1, s['tot_code'])
        if ratio > 0.40:
            return 'c', 'ROS-diverged: %d%% of code lines differ from base' % (ratio * 100)
        code_conf = [c for c in s.get('conflicts', []) if not c.startswith('tests/')]
        if code_conf:
            return 'b', '%d code file(s) conflict in the 3-way pre-check' % len(code_conf)
        if any(not x.startswith('tests/') for x in s.get('new_up', []) + s.get('removed_up', [])):
            return 'b', 'files added/removed upstream (CMake/spec edits needed)'
        if ratio > 0.15:
            return 'b', 'ROS differs from base by %d%% of code lines' % (ratio * 100)
        if s.get('up_code', 0) + s.get('up_tests', 0) == 0:
            return 'a', 'already current'
        return 'a', 'clean 3-way merge'


# ---------------------------------------------------------------------------------------------
# output
# ---------------------------------------------------------------------------------------------
def short(tag):
    if not tag:
        return '-'
    return tag[5:] if tag.startswith('wine-') else tag[:11]


def write_reports(results, sc, md_path, tsv_path, json_path):
    dev, stable = sc.dev, sc.stable
    cnt = collections.Counter(r['cls'] for r in results)
    now = time.strftime('%Y-%m-%dT%H:%MZ', time.gmtime())
    fork = sc.ros.repo.out('rev-parse', '--short=11', 'HEAD').strip()

    def row(r):
        s = r.get('stats', {})
        tag = '-'
        if r.get('base'):
            tag = short(r['base'])
            if r.get('tag_hi') and r['tag_hi'] != r['tag_lo']:
                tag += ' (..%s)' % short(r['tag_hi'])
            if r['how'] != 'blob':
                tag += ' *'
        cf = len([c for c in s.get('conflicts', []) if not c.startswith('tests/')])
        ratio = '%d%%' % (100 * s['loc_code'] / max(1, s['tot_code'])) if s.get('tot_code') else '-'
        st = 'ahead' if s.get('st_ahead') else str(s.get('st_code', '-'))
        return '| %s | %d/%d | %s | %s | %s | %s | %s | %s (%s) | %s | %d |' % (
            r['rdir'].replace('dll/', ''), r['n_exact'], r['n_files'], tag, r.get('base_tags_behind', '-'),
            s.get('up_code', '-'), st, s.get('up_tests', '-'), s.get('loc_code', '-'), ratio,
            cf if s.get('n_common') else '-', r['local_n'])

    hdr = ('| module | exact/files | imported Wine tag | tags behind | Δdev lines | Δstable lines | Δdev test lines '
           '| ROS-local diff lines (share) | conflicting files | NitroOS commits |\n'
           '|---|---|---|---|---|---|---|---|---|---|')
    L = ['# WINESYNC report: ReactOS/NitroOS Wine-derived modules vs upstream Wine', '',
         'Generated %s by `sdk/tools/winesync/winewatch.py scan`. Fork `%s`, Wine master `%s`, latest dev `%s`, '
         'latest stable `%s`.' % (now, fork, sc.hist.head[:11], dev, stable), '',
         '**%d modules** (dll/win32 + dll/directx/wine with a Wine `dlls/<name>` counterpart): class (a) clean: **%d**, '
         '(b) needs porting: **%d**, (c) ROS-diverged / do not sync as a directory: **%d**.'
         % (len(results), cnt['a'], cnt['b'], cnt['c']), '',
         'How to read it. *imported Wine tag*: the Wine tag range in which the most ReactOS files are byte-identical to '
         'Wine\'s file at the same path (`..X` = the same files are also identical up to tag X; the lowest tag is the merge base, '
         'or the WINESYNC.txt claim when it lies inside the range); `*` = no or too few exact matches, closest candidate by '
         'diff size. *Δdev / Δstable lines*: added+deleted lines Wine changed, between the imported tag and %s / %s, in the '
         'files ReactOS carries (code files; tests in their own column; `ahead` = imported tag newer than stable). '
         '*ROS-local diff*: lines ReactOS/NitroOS changed relative to the imported tag (share of the module\'s code lines). '
         '*conflicting files*: code files that conflict in a `git merge-tree` of base, ReactOS and %s. *NitroOS commits*: '
         'non-merge commits in the fork, not in upstream ReactOS, touching the module or its winetests. '
         'Classes: (a) local diff <=15%%, no merge conflicts, no files added/removed upstream; (b) conflicts, a 15-40%% local '
         'diff, or files added/removed upstream; (c) >40%% local diff, no Wine base, or listed in `class-overrides.tsv` '
         '(ReactOS-native implementation of a Wine-named DLL).' % (dev, stable, dev), '',
         '## Most behind: lines Wine changed since the imported tag (classes a and b)', '',
         '| module | class | imported | tags behind | Δdev lines | Δdev test lines |', '|---|---|---|---|---|---|']
    cand = [r for r in results if r.get('stats', {}).get('up_code') is not None and r['cls'] in 'ab']
    cand.sort(key=lambda r: -(r['stats']['up_code'] + r['stats']['up_tests']))
    for r in cand[:30]:
        s = r['stats']
        L.append('| %s | %s | %s | %s | %d | %d |' % (r['rdir'].replace('dll/', ''), r['cls'], short(r['base']),
                                                       r['base_tags_behind'], s['up_code'], s['up_tests']))
    old = sorted((r for r in results if r.get('base_tags_behind') is not None), key=lambda r: -r['base_tags_behind'])
    L += ['', 'Oldest imports (tags behind): ' + ', '.join('%s (%s, %d)' % (r['name'], short(r['base']), r['base_tags_behind'])
                                                         for r in old[:15]), '',
          '## WINESYNC.txt discrepancies (file evidence vs the claim; fix the claim or investigate)', '',
          '| module | WINESYNC.txt says | evidence | verdict |', '|---|---|---|---|']
    ndis = 0
    for r in results:
        if r['claim_check'] == 'ok':
            continue
        ndis += 1
        ev = '%s..%s (%d/%d exact)' % (short(r['tag_lo']), short(r['tag_hi']), r['n_exact'], r['n_files']) \
            if r.get('tag_lo') else 'no exact file match'
        L.append('| %s | %s | %s | %s |' % (r['rdir'].replace('dll/', ''), (r['claim'] or '(no entry)')[:60].replace('|', '/'),
                                         ev, r['claim_check']))
    L += ['', '%d of %d modules: claim missing, unresolvable, or contradicted by the files.' % (ndis, len(results)), '']
    hc = [r for r in results if r.get('cfg_tag') and r.get('base') and r['cfg_tag'] != r['base'] and r.get('tag_lo')]
    if hc:
        L += ['## Hand-written configs whose `tags.wine` disagrees with the files', '',
              'These configs predate the scan. `winewatch.py merge` and `winesync.py` would replay from the config tag, '
              'so they re-apply (or conflict on) changes that are already in the tree. Correct the tag after checking.', '',
              '| module | config says | files match |', '|---|---|---|']
        L += ['| %s | %s | %s..%s |' % (r['name'], short(r['cfg_tag']), short(r['tag_lo']), short(r['tag_hi'])) for r in hc]
        L.append('')
    for cls, title in (('a', '(a) clean: bulk-syncable'), ('b', '(b) needs porting: one ticket each'),
                       ('c', '(c) ROS-diverged: never sync the directory; cherry-pick functions/tests only')):
        L += ['## Class ' + title, '', hdr]
        L += [row(r) for r in sorted((x for x in results if x['cls'] == cls), key=lambda x: x['rdir'])]
        L.append('')
        if cls != 'a':
            L += ['Reasons: ' + '; '.join('%s: %s' % (r['name'], r['why']) for r in results if r['cls'] == cls), '']
    L += ['## NitroOS-local patches (module, count, newest three subjects)', '']
    for r in sorted(results, key=lambda x: -x['local_n']):
        if r['local_n']:
            L.append('- `%s` (%d): %s' % (r['rdir'].replace('dll/', ''), r['local_n'],
                                          ' / '.join(s.split(' ', 1)[1][:70] for s in r['local_subj'])))
    L.append('')
    with open(md_path, 'w') as f:
        f.write('\n'.join(L))
    with open(tsv_path, 'w') as f:
        f.write('module\trdir\twine_dir\ttests_dir\tclass\tbase\ttag_lo\ttag_hi\texact\tfiles\ttags_behind\tup_code\t'
                'up_tests\tst_code\tloc_code\ttot_code\tconflicts\tclaim_check\tlocal_commits\twhy\n')
        for r in results:
            s = r.get('stats', {})
            f.write('\t'.join(str(x) for x in (
                r['name'], r['rdir'], 'dlls/' + r['name'], r['tdir'] or '', r['cls'], r.get('base') or '',
                r.get('tag_lo') or '', r.get('tag_hi') or '', r['n_exact'], r['n_files'], r.get('base_tags_behind', ''),
                s.get('up_code', ''), s.get('up_tests', ''), s.get('st_code', ''), s.get('loc_code', ''),
                s.get('tot_code', ''), len(s.get('conflicts', [])), r['claim_check'], r['local_n'], r['why'])) + '\n')
    if json_path:
        with open(json_path, 'w') as f:
            json.dump(results, f, indent=1)


def write_configs(results, sc):
    outdir = os.path.join(HERE, 'modules')
    os.makedirs(outdir, exist_ok=True)
    n = 0
    for r in results:
        name = r['name']
        if name in sc.handcfg:
            continue  # a hand-written top-level config of that name keeps priority
        subdirs = sorted({os.path.dirname(f[len(r['rdir']) + 1:]) for f in sc.ros.under(r['rdir'])
                          if '/' in f[len(r['rdir']) + 1:]})
        det = '%s..%s' % (short(r.get('tag_lo')), short(r.get('tag_hi'))) if r.get('tag_lo') else 'no exact match'
        lines = ['# generated by winewatch.py scan --write-configs; class %s, blob-detected %s' % (r['cls'], det),
                 'directories:', '  dlls/%s: %s' % (name, r['rdir'])]
        lines += ['  dlls/%s/%s: %s/%s' % (name, sd, r['rdir'], sd) for sd in subdirs]
        if r['tdir']:
            lines.append('  dlls/%s/tests: %s' % (name, r['tdir']))
        lines += ['files: {}', 'tags:', '  wine: %s' % (r.get('base') or 'wine-10.0')]
        with open(os.path.join(outdir, name + '.cfg'), 'w') as f:
            f.write('\n'.join(lines) + '\n')
        n += 1
    log('wrote %d configs to %s' % (n, outdir))


def cmd_scan(args):
    sc = Scanner(args)
    results = sc.scan()
    write_reports(results, sc, args.out_md, args.out_tsv, args.out_json)
    if args.write_configs:
        write_configs(results, sc)
    cnt = collections.Counter(r['cls'] for r in results)
    print('modules=%d a=%d b=%d c=%d' % (len(results), cnt['a'], cnt['b'], cnt['c']))


# ---------------------------------------------------------------------------------------------
# merge: sync one module to a Wine tag with a 3-way merge (base = the config's tags.wine)
# ---------------------------------------------------------------------------------------------
def cmd_merge(args):
    cfgp = find_cfg(args.module)
    cfg = load_cfg(cfgp)
    wine, ros = Repo(args.wine), Ros(args.ros)
    base = (cfg.get('tags') or {}).get('wine')
    target = args.tag
    if not base:
        raise SystemExit('config has no tags.wine (the imported base)')
    for rev in (base, target):
        if wine.run('rev-parse', '--verify', '-q', rev + '^{commit}', check=False).returncode:
            raise SystemExit('unknown Wine revision %s (fetch tags into the Wine clone)' % rev)
    dirs = sorted(cfg['directories'].items(), key=lambda kv: -len(kv[1]))
    ours_path = {}  # ReactOS path -> Wine path (longest ReactOS directory wins)
    for f in ros.files:
        for wd, rd in dirs:
            if f.startswith(rd + '/'):
                ours_path[f] = wd + f[len(rd):]
                break
    for wf, rf in cfg['files'].items():
        if rf in ros.files:
            ours_path[rf] = wf
    mpaths = sorted({rd for _, rd in dirs} | set(cfg['files'].values()))
    status = ros.repo.out('status', '--porcelain', '--', *mpaths).strip()
    if status and not args.force:
        raise SystemExit('uncommitted changes in the module paths (use --force to ignore):\n' + status)
    blobs = hash_into(wine, args.ros, ours_path)
    ours = {ours_path[f]: blobs[f] for f in ours_path}
    rev_map = {w: f for f, w in ours_path.items()}

    def wine_tree(rev):
        d = {}
        for ent in wine.out('ls-tree', '-r', '-z', rev, '--', *sorted({wd for wd, _ in dirs} | set(cfg['files']))).split('\0'):
            if ent:
                meta, path = ent.split('\t', 1)
                d[path] = meta.split()[2]
        return d

    wb, wt = wine_tree(base), wine_tree(target)
    common = {p: o for p, o in ours.items() if p in wb}
    B = {p: wb[p] for p in common}
    T = {p: wt[p] for p in common if p in wt}
    wine.prefetch(list(B.values()) + list(T.values()))
    tb, to, tt = wine.make_tree(B), wine.make_tree(common), wine.make_tree(T)
    rc, merged, conflicts = wine.merge3(tb, to, tt)
    mt = {}
    for ent in wine.out('ls-tree', '-r', '-z', merged).split('\0'):
        if ent:
            meta, path = ent.split('\t', 1)
            mt[path] = meta.split()[2]
    changed = [(wp, rev_map[wp], mt[wp]) for wp, oid in sorted(common.items()) if wp in mt and mt[wp] != oid]
    removed = [rev_map[wp] for wp in sorted(common) if wp not in mt]
    new_up = sorted(p for p in wt if p not in wb and p not in ours and not IGNORE_UPSTREAM.search(p))
    print('merge %s: %s -> %s' % (args.module, base, target))
    print('  %d file(s) changed, %d removed upstream, %d conflicting, %d ReactOS-only file(s) untouched'
          % (len(changed), len(removed), len(conflicts), len(ours) - len(common)))
    if new_up:
        print('  NEW upstream files, not imported (add them and edit CMakeLists.txt by hand if wanted):')
        for p in new_up:
            print('    ' + p)
    if args.dry_run:
        for wp, rp, _ in changed:
            print('  would update', rp)
        for rp in removed:
            print('  would remove', rp)
        for c in conflicts:
            print('  CONFLICT', rev_map.get(c, c))
        return
    for wp, rp, oid in changed:
        with open(os.path.join(args.ros, rp), 'wb') as f:
            f.write(wine.run('cat-file', 'blob', oid).stdout)
    for rp in removed:
        ros.repo.run('rm', '-q', '-f', '--', rp)
    for c in conflicts:
        print('  CONFLICT (markers written): %s' % rev_map.get(c, c))
    with open(cfgp) as f:
        txt = f.read()
    with open(cfgp, 'w') as f:
        f.write(re.sub(r'(^\s*wine:\s*)\S+', r'\g<1>' + target, txt, flags=re.M))
    ver = target[5:] if target.startswith('wine-') else target
    wtxt = os.path.join(args.ros, 'media/doc/WINESYNC.txt')
    done = False
    if os.path.isfile(wtxt) and not args.no_winesync_txt:
        rdirs = {rd for _, rd in dirs}
        lines = open(wtxt, encoding='utf-8').read().split('\n')
        for i, line in enumerate(lines):
            m = re.match(r'^(\S+)(\s*(?:=>\s*\S+)?\s*#\s*)(.*)$', line)
            if m and m.group(1) in rdirs:
                new = re.sub(r'(Synced to |Forked at )?(Wine|WineStaging|wine)-[\w.\-]+(\s*\([0-9a-f]+\))?',
                             'Synced to Wine-' + ver, m.group(3), count=1)
                if new == m.group(3):
                    new = 'Synced to Wine-%s (was: %s)' % (ver, m.group(3))
                lines[i] = m.group(1) + m.group(2) + new
                done = True
                break
        if done:
            open(wtxt, 'w', encoding='utf-8').write('\n'.join(lines))
    print('  WINESYNC.txt %s' % ('updated' if done else 'NOT updated: edit by hand'))
    print('  %s now has tags.wine = %s' % (os.path.relpath(cfgp, args.ros), target))
    print('Next: review `git diff`, build, run the winetests base vs fix, commit "[%s] Sync to Wine-%s".'
          % (args.module.upper(), ver))
    return 1 if conflicts else 0


def cmd_check(args):
    """List WINESYNC.txt lines that a previous scan's JSON contradicts."""
    res = json.load(open(args.json))
    bad = [r for r in res if r['claim_check'] != 'ok']
    for r in bad:
        print('%-40s %-40s %s' % (r['rdir'], (r['claim'] or '(none)')[:40], r['claim_check']))
    print('%d/%d modules need a WINESYNC.txt fix or a look' % (len(bad), len(res)))
    return 1 if bad and args.strict else 0


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest='cmd', required=True)
    p = sub.add_parser('scan', help='detect the imported Wine tag per module, write the behind-by report')
    p.add_argument('--wine', required=True, help='full-history (blobless is fine) Wine clone')
    p.add_argument('--ros', required=True, help='ReactOS/NitroOS worktree (needs a upstream/master ref)')
    p.add_argument('--dev', help='latest dev tag (default: newest wine-X.Y tag)')
    p.add_argument('--stable', help='latest stable tag (default: newest wine-N.0)')
    p.add_argument('--out-md', default='WINESYNC-REPORT.md')
    p.add_argument('--out-tsv', default='wine-map.tsv')
    p.add_argument('--out-json', default=None)
    p.add_argument('--write-configs', action='store_true', help='also write modules/<name>.cfg for every module')
    p.set_defaults(fn=cmd_scan)
    p = sub.add_parser('merge', help='3-way sync of one module to a Wine tag (leaves the changes uncommitted)')
    p.add_argument('module', help='module name; <module>.cfg or modules/<module>.cfg')
    p.add_argument('tag', help='target Wine tag, e.g. wine-11.21')
    p.add_argument('--wine', required=True)
    p.add_argument('--ros', required=True)
    p.add_argument('--dry-run', action='store_true')
    p.add_argument('--force', action='store_true')
    p.add_argument('--no-winesync-txt', action='store_true')
    p.set_defaults(fn=cmd_merge)
    p = sub.add_parser('check', help='list WINESYNC.txt lines the last scan contradicts')
    p.add_argument('json')
    p.add_argument('--strict', action='store_true')
    p.set_defaults(fn=cmd_check)
    args = ap.parse_args()
    for k in ('wine', 'ros'):
        if getattr(args, k, None):
            setattr(args, k, os.path.abspath(getattr(args, k)))
    sys.exit(args.fn(args) or 0)


if __name__ == '__main__':
    main()
