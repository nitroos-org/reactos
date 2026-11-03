#!/usr/bin/env python3
"""ngdamage.py DISK.raw OP [args]   offline NTFS damage injection for the ntchk lane (partition 1 of a raw MBR disk).
OPs (each prints what it did):
  info                       geometry, $MFT size, free clusters
  leak-cluster [N]           mark N (default 3) free clusters used in $Bitmap (a leak: nothing references them)
  leak-record [N]            mark N (default 2) unused MFT records used in $MFT:$BITMAP
  crosslink A B              make file A's first run start at file B's first run (name = last path component, single-run files)
  clear-lcnbit NAME          clear a used cluster's bit of file NAME in $Bitmap (cluster in use but free)
  clear-mftbit NAME          clear the $MFT:$BITMAP bit of file NAME's record (record in use but free)
  runs NAME                  print a file's runs
"""
import sys, struct, json, subprocess, os

class Vol:
    def __init__(s, disk):
        s.f = open(disk, 'r+b')
        j = json.loads(subprocess.check_output(['sfdisk', '-J', disk]))
        s.base = j['partitiontable']['partitions'][0]['start'] * 512
        b = s.rd(0, 512)
        assert b[3:7] == b'NTFS', 'not NTFS'
        s.bps = struct.unpack_from('<H', b, 11)[0]
        s.spc = b[13]
        s.cs = s.bps * s.spc
        s.nsect = struct.unpack_from('<Q', b, 0x28)[0]
        s.nclus = s.nsect // s.spc
        s.mftlcn = struct.unpack_from('<Q', b, 0x30)[0]
        c = struct.unpack_from('<b', b, 0x40)[0]
        s.rs = c * s.cs if c > 0 else 1 << (-c)
        s.mftrl = None
        r0 = s.rec_raw(0)
        s.mftrl = s.runs_of(r0, 0x80, None)
        s.mftsize = s.attr_size(r0, 0x80, None)
        s.nrec = s.mftsize // s.rs
    def rd(s, off, n):
        s.f.seek(s.base + off); return s.f.read(n)
    def wr(s, off, d):
        s.f.seek(s.base + off); s.f.write(d)
    def rec_off(s, n):
        if s.mftrl is None:
            return s.mftlcn * s.cs + n * s.rs
        pos = n * s.rs
        for vcn, lcn, ln in s.mftrl:
            if vcn * s.cs <= pos < (vcn + ln) * s.cs:
                return lcn * s.cs + pos - vcn * s.cs
        raise Exception('record %d outside the $MFT runs' % n)
    def rec_raw(s, n):
        return bytearray(s.rd(s.rec_off(n), s.rs))
    def rec(s, n):
        """record with fixups removed"""
        r = s.rec_raw(n)
        uo, uc = struct.unpack_from('<HH', r, 4)
        usn = r[uo:uo + 2]
        for i in range(1, uc):
            e = i * 512 - 2
            if e + 2 > len(r): break
            assert r[e:e + 2] == usn, 'bad fixup rec %d' % n
            r[e:e + 2] = r[uo + 2 * i:uo + 2 * i + 2]
        return r
    def put_rec(s, n, r):
        r = bytearray(r)
        uo, uc = struct.unpack_from('<HH', r, 4)
        usn = bytes(r[uo:uo + 2])
        for i in range(1, uc):
            e = i * 512 - 2
            r[uo + 2 * i:uo + 2 * i + 2] = r[e:e + 2]
            r[e:e + 2] = usn
        s.wr(s.rec_off(n), bytes(r))
        # mirror of the first records
        if n < 4:
            pass
    def attrs(s, r):
        o = struct.unpack_from('<H', r, 0x14)[0]
        while o + 8 <= len(r):
            t = struct.unpack_from('<I', r, o)[0]
            if t == 0xFFFFFFFF: return
            ln = struct.unpack_from('<I', r, o + 4)[0]
            nr = r[o + 8]; nl = r[o + 9]
            nm = bytes(r[o + struct.unpack_from('<H', r, o + 10)[0]:][:nl * 2]).decode('utf-16le') if nl else ''
            yield o, t, nr, nm, ln
            o += ln
    def find(s, r, typ, name):
        for o, t, nr, nm, ln in s.attrs(r):
            if t == typ and (name is None or nm == name) and (name is not None or nm == ''):
                return o, nr, ln
        return None
    def decode_runs(s, r, o, ln):
        mp = struct.unpack_from('<H', r, o + 0x20)[0]
        p = o + mp; vcn = struct.unpack_from('<Q', r, o + 0x10)[0]; lcn = 0; out = []
        while p < o + ln and r[p]:
            h = r[p]; ls = h & 15; os_ = h >> 4; p += 1
            L = int.from_bytes(r[p:p + ls], 'little'); p += ls
            if os_:
                d = int.from_bytes(r[p:p + os_], 'little', signed=True); p += os_
                lcn += d; out.append((vcn, lcn, L))
            else:
                out.append((vcn, -1, L))
            vcn += L
        return out
    def runs_of(s, r, typ, name):
        a = s.find(r, typ, name)
        if not a: return None
        o, nr, ln = a
        assert nr, 'resident'
        return s.decode_runs(r, o, ln)
    def attr_size(s, r, typ, name):
        o, nr, ln = s.find(r, typ, name)
        if nr: return struct.unpack_from('<Q', r, o + 0x30)[0]
        return struct.unpack_from('<I', r, o + 0x10)[0]
    def read_stream(s, runs, size):
        out = bytearray()
        for vcn, lcn, ln in runs:
            if lcn < 0: out += bytes(ln * s.cs)
            else: out += s.rd(lcn * s.cs, ln * s.cs)
        return out[:size]
    def stream_off(s, runs, byte):
        for vcn, lcn, ln in runs:
            if vcn * s.cs <= byte < (vcn + ln) * s.cs:
                return lcn * s.cs + byte - vcn * s.cs
        raise Exception('offset outside runs')
    def lcnbmp(s):
        r = s.rec(6)
        runs = s.runs_of(r, 0x80, None)
        return runs, s.attr_size(r, 0x80, None)
    def mftbmp(s):
        r = s.rec(0)
        runs = s.runs_of(r, 0xB0, None)
        return runs, s.attr_size(r, 0xB0, None)
    def bit_get(s, st, i):
        runs, size = st
        b = s.rd(s.stream_off(runs, i >> 3), 1)[0]
        return (b >> (i & 7)) & 1
    def bit_set(s, st, i, v):
        runs, size = st
        off = s.stream_off(runs, i >> 3)
        b = s.rd(off, 1)[0]
        b = (b | (1 << (i & 7))) if v else (b & ~(1 << (i & 7)) & 0xFF)
        s.wr(off, bytes([b]))
    def name_of(s, r):
        for o, t, nr, nm, ln in s.attrs(r):
            if t == 0x30 and not nr:
                vo = struct.unpack_from('<H', r, o + 0x14)[0]
                nl = r[o + vo + 64]; ns = r[o + vo + 65]
                if ns == 2: continue
                return bytes(r[o + vo + 66:o + vo + 66 + nl * 2]).decode('utf-16le')
        return None
    def lookup(s, name):
        for n in range(24, s.nrec):
            try:
                r = s.rec(n)
            except Exception:
                continue
            if r[:4] != b'FILE' or not (struct.unpack_from('<H', r, 0x16)[0] & 1): continue
            if struct.unpack_from('<Q', r, 0x20)[0] & 0xFFFFFFFFFFFF: continue
            nm = s.name_of(r)
            if nm and nm.lower() == name.lower():
                return n
        raise Exception('file %s not found' % name)

def audit(v):
    ref = {}
    inuse = set()
    for n in range(v.nrec):
        try:
            r = v.rec(n)
        except Exception:
            continue
        if r[:4] != b'FILE' or not (struct.unpack_from('<H', r, 0x16)[0] & 1): continue
        inuse.add(n)
        for o, t, nr, nm, ln in v.attrs(r):
            if not nr: continue
            for vcn, lcn, L in v.decode_runs(r, o, ln):
                if lcn < 0: continue
                for c in range(lcn, lcn + L):
                    ref[c] = ref.get(c, 0) + 1
    lr, ls = v.lcnbmp()
    bm = v.read_stream(lr, ls)
    def bit(c): return (bm[c >> 3] >> (c & 7)) & 1
    leaked = [c for c in range(v.nclus) if bit(c) and c not in ref]
    freeref = [c for c in ref if c < v.nclus and not bit(c)]
    cross = [c for c, k in ref.items() if k > 1]
    mr, ms = v.mftbmp()
    mm = v.read_stream(mr, ms)
    def mbit(n): return (mm[n >> 3] >> (n & 7)) & 1
    lrec = [n for n in range(24, v.nrec) if mbit(n) and n not in inuse]
    nbit = [n for n in inuse if not mbit(n)]
    print('AUDIT leaked_clusters=%d free_but_referenced=%d crosslinked=%d leaked_records=%s inuse_without_bit=%s' % (
        len(leaked), len(freeref), len(cross), lrec, sorted(nbit)))

def main():
    v = Vol(sys.argv[1]); op = sys.argv[2]; a = sys.argv[3:]
    if op == 'info':
        lb = v.lcnbmp(); free = sum(1 for i in range(v.nclus) if not v.bit_get(lb, i)) if v.nclus < 5000000 else -1
        print('cs=%d rs=%d nclus=%d mftlcn=%d mftsize=%d nrec=%d free=%d' % (v.cs, v.rs, v.nclus, v.mftlcn, v.mftsize, v.nrec, free)); return
    if op == 'leak-cluster':
        n = int(a[0]) if a else 3
        lb = v.lcnbmp(); got = []
        for i in range(v.nclus - 1, 0, -1):
            if not v.bit_get(lb, i):
                v.bit_set(lb, i, 1); got.append(i)
                if len(got) == n: break
        print('leaked clusters', got); return
    if op == 'leak-record':
        n = int(a[0]) if a else 2
        mb = v.mftbmp(); got = []
        for i in range(v.nrec - 1, 24, -1):
            if not v.bit_get(mb, i):
                r = v.rec_raw(i)
                if r[:4] == b'FILE' and (struct.unpack_from('<H', r, 0x16)[0] & 1): continue
                v.bit_set(mb, i, 1); got.append(i)
                if len(got) == n: break
        print('leaked records', got); return
    if op == 'audit':
        audit(v); return
    if op == 'runs':
        n = v.lookup(a[0]); r = v.rec(n); print(n, v.runs_of(r, 0x80, None)); return
    if op == 'crosslink':
        na, nb = v.lookup(a[0]), v.lookup(a[1])
        rb = v.rec(nb); runsb = v.runs_of(rb, 0x80, None)
        ra = v.rec(na); o, nr, ln = v.find(ra, 0x80, None); runsa = v.decode_runs(ra, o, ln)
        assert len(runsa) == 1 and len(runsb) == 1, 'single-run files needed: %s %s' % (runsa, runsb)
        new = runsb[0][1]
        L = runsa[0][2]
        mp = struct.unpack_from('<H', ra, o + 0x20)[0] + o
        h = ra[mp]; ls = h & 15; os_ = h >> 4
        newoff = new.to_bytes(os_, 'little', signed=True) if new < (1 << (8 * os_ - 1)) else None
        assert newoff is not None, 'offset needs more bytes'
        ra[mp + 1 + ls:mp + 1 + ls + os_] = newoff
        v.put_rec(na, ra)
        print('crosslinked %s (rec %d, was lcn %d) onto lcn %d of %s (rec %d)' % (a[0], na, runsa[0][1], new, a[1], nb)); return
    if op == 'clear-lcnbit':
        n = v.lookup(a[0]); r = v.rec(n); runs = v.runs_of(r, 0x80, None)
        lb = v.lcnbmp(); l = runs[0][1]; v.bit_set(lb, l, 0)
        print('cleared $Bitmap bit of cluster', l, 'of', a[0], 'rec', n); return
    if op == 'clear-mftbit':
        n = v.lookup(a[0]); mb = v.mftbmp(); v.bit_set(mb, n, 0)
        print('cleared $MFT:$BITMAP bit of record', n, a[0]); return
    print(__doc__); sys.exit(2)
main()
