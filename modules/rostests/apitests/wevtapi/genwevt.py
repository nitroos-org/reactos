#!/usr/bin/env python3
# Writes the WEVT_TEMPLATE resource (the binary form of an event manifest that the message compiler makes) of
# one publisher as an .rc fragment. Usage: genwevt.py testmanifest.dat > testmanifest.wevt.rc
import re
import struct
import sys
import uuid

IN_TYPES = ['', 'win:UnicodeString', 'win:AnsiString', 'win:Int8', 'win:UInt8', 'win:Int16', 'win:UInt16', 'win:Int32',
            'win:UInt32', 'win:Int64', 'win:UInt64', 'win:Float', 'win:Double', 'win:Boolean', 'win:Binary', 'win:GUID',
            'win:Pointer', 'win:FILETIME', 'win:SYSTEMTIME', 'win:SID', 'win:HexInt32', 'win:HexInt64']
OUT_TYPES = ['', 'xs:string', 'xs:dateTime', 'xs:byte', 'xs:unsignedByte', 'xs:short', 'xs:unsignedShort', 'xs:int',
             'xs:unsignedInt', 'xs:long', 'xs:unsignedLong', 'xs:float', 'xs:double', 'xs:boolean', 'xs:GUID',
             'xs:hexBinary', 'win:HexInt8', 'win:HexInt16', 'win:HexInt32', 'win:HexInt64', 'win:PID', 'win:TID',
             'win:Port', 'win:IPv4', 'win:IPv6', 'win:SocketAddress', 'win:CIMDateTime', 'win:ETWTimestamp', 'win:XML',
             'win:ErrorCode', 'win:Win32Error', 'win:NTSTATUS', 'win:HResult']
NONE = 0xffffffff


def align(b):
    return b + b'\0' * (-len(b) % 4)


def name_blob(s):
    raw = s.encode('utf-16-le') + b'\0\0'
    return align(struct.pack('<I', len(raw) + 4) + raw)


class Writer:
    """Collects sections at known offsets: the offsets of what a section holds are absolute in the resource."""
    def __init__(self):
        self.parts = []
        self.size = 0

    def add(self, blob):
        off = self.size
        self.parts.append(blob)
        self.size += len(blob)
        return off


def parse(path):
    d = {'channels': [], 'levels': [], 'opcodes': [], 'tasks': [], 'keywords': [], 'events': []}
    for line in open(path, encoding='utf-8'):
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        f = line.split(' ')
        if f[0] == 'provider':
            d['guid'] = uuid.UUID(f[1]).bytes_le
            d['name'] = f[2]
        elif f[0] == 'channel':
            d['channels'].append((int(f[1]), f[2]))
        elif f[0] in ('level', 'opcode', 'keyword'):
            d[f[0] + 's'].append((f[1], int(f[2])))
        elif f[0] == 'task':
            d['tasks'].append((f[1], int(f[2]), uuid.UUID(f[3]).bytes_le))
        elif f[0] == 'event':
            fields = []
            # - is an event with no template, = an event with a template that has no data
            if f[8] not in ('-', '='):
                for item in f[8].split(','):
                    n, i, o = item.split('|')
                    fields.append((n, IN_TYPES.index(i), OUT_TYPES.index(o)))
            d['events'].append((int(f[1]), int(f[2]), int(f[3]), int(f[4]), int(f[5]), int(f[6]), int(f[7], 0), tuple(fields) if f[8] != '-' else None))
    return d


def build(d):
    # layout: CRIM header, provider table, WEVT header with its descriptors, then the sections one after the other
    nsec = 7
    wevt_off = 16 + 20
    sec_off = wevt_off + 20 + nsec * 8
    out = Writer()
    out.size = sec_off
    secs = {}

    def named_section(sig, entries, entry_size, make):
        # entries are written behind a header of 12 bytes; the names go behind the entries
        head = 12
        names = Writer()
        base = out.size
        names.size = base + head + len(entries) * entry_size
        body = b''
        for e in entries:
            body += make(e, names)
        blob = struct.pack('<4sII', sig, head + len(body) + sum(len(p) for p in names.parts), len(entries)) + body + b''.join(names.parts)
        secs[sig] = out.add(blob)

    named_section(b'CHAN', d['channels'], 16, lambda e, w: struct.pack('<IIII', e[0], w.add(name_blob(e[1])), 0, NONE))
    named_section(b'KEYW', d['keywords'], 16, lambda e, w: struct.pack('<QII', e[1], NONE, w.add(name_blob(e[0]))))
    named_section(b'LEVL', d['levels'], 12, lambda e, w: struct.pack('<III', e[1], NONE, w.add(name_blob(e[0]))))
    # an opcode is the high word of its value (what readers of the metadata, .NET among them, take it from)
    named_section(b'OPCO', d['opcodes'], 12, lambda e, w: struct.pack('<III', e[1] << 16, NONE, w.add(name_blob(e[0]))))
    named_section(b'TASK', d['tasks'], 28, lambda e, w: struct.pack('<II16sI', e[1], NONE, e[2], w.add(name_blob(e[0]))))

    # templates: the distinct lists of data, each a TEMP with a short fragment, its descriptors and their names
    templates = {}
    ttbl_off = out.size
    body = b''
    pos = ttbl_off + 12
    for ev in d['events']:
        fields = ev[7]
        if fields is None or fields in templates:
            continue
        frag = align(b'\x0f\x01\x01\x00')
        items_off = pos + 40 + len(frag)
        names_off = items_off + 20 * len(fields)
        names = b''
        items = b''
        for n, i, o in fields:
            items += struct.pack('<IBBHIII', 0, i, o, 0, 0, 0, names_off + len(names))
            names += name_blob(n)
        size = 40 + len(frag) + len(items) + len(names)
        temp = struct.pack('<4sIIII', b'TEMP', size, len(fields), len(fields), items_off) + struct.pack('<I', 0) + \
            uuid.uuid5(uuid.NAMESPACE_OID, repr(fields)).bytes_le + frag + items + names
        assert len(temp) == size
        templates[fields] = pos
        body += temp
        pos += size
    secs[b'TTBL'] = out.add(struct.pack('<4sII', b'TTBL', 12 + len(body), len(templates)) + body)

    ev = b''
    for (eid, ver, ch, lvl, op, task, kw, fields) in d['events']:
        ev += struct.pack('<HBBBBHQII', eid, ver, ch, lvl, op, task, kw, NONE, templates.get(fields, NONE) if fields is not None else NONE) + b'\0' * 24
    secs[b'EVNT'] = out.add(struct.pack('<4sIII', b'EVNT', 16 + len(ev), len(d['events']), 0) + ev)

    wevt = struct.pack('<4sIIII', b'WEVT', out.size - wevt_off, NONE, nsec, 0)
    for sig in (b'CHAN', b'EVNT', b'KEYW', b'LEVL', b'OPCO', b'TASK', b'TTBL'):
        wevt += struct.pack('<II', secs[sig], 0)
    head = struct.pack('<4sIHHI', b'CRIM', out.size, 3, 1, 1) + d['guid'] + struct.pack('<I', wevt_off)
    blob = head + wevt + b''.join(out.parts)
    assert len(blob) == out.size
    return blob


def main():
    d = parse(sys.argv[1])
    blob = align(build(d))
    words = struct.unpack('<%dI' % (len(blob) // 4), blob)
    print('/* Generated by genwevt.py from the .dat file; do not edit. The WEVT_TEMPLATE resource of %s. */' % d['name'])
    print('1 WEVT_TEMPLATE')
    print('BEGIN')
    for i in range(0, len(words), 8):
        print('    ' + ', '.join('0x%08xL' % w for w in words[i:i + 8]) + (',' if i + 8 < len(words) else ''))
    print('END')


main()
