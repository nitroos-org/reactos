#!/usr/bin/env python3
"""Generate msg_fixtures.h for the CMS EnvelopedData tests of crypt32_winetest msg.c.

usage: gen_msg_fixtures.py OUTFILE
       gen_msg_fixtures.py OUTFILE --extra msg_fixtures.h

The second form writes only the messages of msg_fixtures2.h: more messages for the certificate A of an existing
msg_fixtures.h (its key and certificate stay as they are).

Everything is made up on the spot: two throwaway 2048 bit RSA test keys A and B (the private keys are in the
header because the tests decrypt with them; nobody should use them for anything else), their self signed
certificates, and EnvelopedData messages with known content keys: well formed ones for each content cipher
and recipient identifier, and damaged ones for the error paths.
"""
import datetime, os, struct, sys
from cryptography import x509
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding as apad, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.x509.oid import NameOID

PLAIN = b'hello CMS enveloped world, 0123456789abcdef!'

def tlv(tag, c):
    n = len(c)
    if n < 0x80: h = bytes([tag, n])
    elif n < 0x100: h = bytes([tag, 0x81, n])
    elif n < 0x10000: h = bytes([tag, 0x82, n >> 8, n & 255])
    else: h = bytes([tag, 0x83, n >> 16, (n >> 8) & 255, n & 255])
    return h + c

def oid(s):
    a = [int(x) for x in s.split('.')]
    out = bytes([a[0] * 40 + a[1]])
    for v in a[2:]:
        t = [v & 0x7f]; v >>= 7
        while v: t.append((v & 0x7f) | 0x80); v >>= 7
        out += bytes(reversed(t))
    return tlv(6, out)

def integer(v):
    return tlv(2, v.to_bytes(max(1, (v.bit_length() + 8) // 8), 'big'))

NULL = b'\x05\x00'
def algid(o, params=NULL): return tlv(0x30, oid(o) + params)

OID_DATA = '1.2.840.113549.1.7.1'
OID_ENVELOPED = '1.2.840.113549.1.7.3'
OID_RSA = '1.2.840.113549.1.1.1'
OID_OAEP = '1.2.840.113549.1.1.7'
OID_MGF1 = '1.2.840.113549.1.1.8'
OID_SHA1 = '1.3.14.3.2.26'
OID_SHA256 = '2.16.840.1.101.3.4.2.1'
OID_AES = {16: '2.16.840.1.101.3.4.1.2', 24: '2.16.840.1.101.3.4.1.22', 32: '2.16.840.1.101.3.4.1.42'}
OID_3DES = '1.2.840.113549.3.7'
OID_DES = '1.3.14.3.2.7'
OID_RC2 = '1.2.840.113549.3.2'
OID_RC4 = '1.2.840.113549.3.4'

# ---- RC2 (RFC 2268), only for the fixtures ----
PI = bytes([
    0xd9, 0x78, 0xf9, 0xc4, 0x19, 0xdd, 0xb5, 0xed, 0x28, 0xe9, 0xfd, 0x79, 0x4a, 0xa0, 0xd8, 0x9d,
    0xc6, 0x7e, 0x37, 0x83, 0x2b, 0x76, 0x53, 0x8e, 0x62, 0x4c, 0x64, 0x88, 0x44, 0x8b, 0xfb, 0xa2,
    0x17, 0x9a, 0x59, 0xf5, 0x87, 0xb3, 0x4f, 0x13, 0x61, 0x45, 0x6d, 0x8d, 0x09, 0x81, 0x7d, 0x32,
    0xbd, 0x8f, 0x40, 0xeb, 0x86, 0xb7, 0x7b, 0x0b, 0xf0, 0x95, 0x21, 0x22, 0x5c, 0x6b, 0x4e, 0x82,
    0x54, 0xd6, 0x65, 0x93, 0xce, 0x60, 0xb2, 0x1c, 0x73, 0x56, 0xc0, 0x14, 0xa7, 0x8c, 0xf1, 0xdc,
    0x12, 0x75, 0xca, 0x1f, 0x3b, 0xbe, 0xe4, 0xd1, 0x42, 0x3d, 0xd4, 0x30, 0xa3, 0x3c, 0xb6, 0x26,
    0x6f, 0xbf, 0x0e, 0xda, 0x46, 0x69, 0x07, 0x57, 0x27, 0xf2, 0x1d, 0x9b, 0xbc, 0x94, 0x43, 0x03,
    0xf8, 0x11, 0xc7, 0xf6, 0x90, 0xef, 0x3e, 0xe7, 0x06, 0xc3, 0xd5, 0x2f, 0xc8, 0x66, 0x1e, 0xd7,
    0x08, 0xe8, 0xea, 0xde, 0x80, 0x52, 0xee, 0xf7, 0x84, 0xaa, 0x72, 0xac, 0x35, 0x4d, 0x6a, 0x2a,
    0x96, 0x1a, 0xd2, 0x71, 0x5a, 0x15, 0x49, 0x74, 0x4b, 0x9f, 0xd0, 0x5e, 0x04, 0x18, 0xa4, 0xec,
    0xc2, 0xe0, 0x41, 0x6e, 0x0f, 0x51, 0xcb, 0xcc, 0x24, 0x91, 0xaf, 0x50, 0xa1, 0xf4, 0x70, 0x39,
    0x99, 0x7c, 0x3a, 0x85, 0x23, 0xb8, 0xb4, 0x7a, 0xfc, 0x02, 0x36, 0x5b, 0x25, 0x55, 0x97, 0x31,
    0x2d, 0x5d, 0xfa, 0x98, 0xe3, 0x8a, 0x92, 0xae, 0x05, 0xdf, 0x29, 0x10, 0x67, 0x6c, 0xba, 0xc9,
    0xd3, 0x00, 0xe6, 0xcf, 0xe1, 0x9e, 0xa8, 0x2c, 0x63, 0x16, 0x01, 0x3f, 0x58, 0xe2, 0x89, 0xa9,
    0x0d, 0x38, 0x34, 0x1b, 0xab, 0x33, 0xff, 0xb0, 0xbb, 0x48, 0x0c, 0x5f, 0xb9, 0xb1, 0xcd, 0x2e,
    0xc5, 0xf3, 0xdb, 0x47, 0xe5, 0xa5, 0x9c, 0x77, 0x0a, 0xa6, 0x20, 0x68, 0xfe, 0x7f, 0xc1, 0xad,
])

def rc2_schedule(key, bits):
    t = len(key); t8 = (bits + 7) // 8; tm = 255 % (2 ** (8 + bits - 8 * t8))
    L = bytearray(key) + bytearray(128 - t)
    for i in range(t, 128): L[i] = PI[(L[i - 1] + L[i - t]) & 255]
    L[128 - t8] = PI[L[128 - t8] & tm]
    for i in range(127 - t8, -1, -1): L[i] = PI[L[i + 1] ^ L[i + t8]]
    return [L[2 * i] | (L[2 * i + 1] << 8) for i in range(64)]

def rc2_block(K, blk):
    r = list(struct.unpack('<4H', blk)); j = 0
    rol = lambda x, n: ((x << n) | (x >> (16 - n))) & 0xffff
    def mix(i):
        nonlocal j
        r[i] = (r[i] + K[j] + (r[(i - 1) % 4] & r[(i - 2) % 4]) + (~r[(i - 1) % 4] & 0xffff & r[(i - 3) % 4])) & 0xffff
        j += 1; r[i] = rol(r[i], (1, 2, 3, 5)[i])
    def mash(i): r[i] = (r[i] + K[r[(i - 1) % 4] & 63]) & 0xffff
    for n in range(16):
        for i in range(4): mix(i)
        if n in (4, 10):
            for i in range(4): mash(i)
    return struct.pack('<4H', *r)

def rc2_cbc(key, bits, iv, data):
    p = padding.PKCS7(64).padder(); data = p.update(data) + p.finalize()
    K = rc2_schedule(key, bits); out = b''; prev = iv
    for i in range(0, len(data), 8):
        blk = bytes(a ^ b for a, b in zip(data[i:i + 8], prev)); prev = rc2_block(K, blk); out += prev
    return out

def rc4(key, data):
    S = list(range(256)); j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 255; S[i], S[j] = S[j], S[i]
    out = bytearray(); i = j = 0
    for c in data:
        i = (i + 1) & 255; j = (j + S[i]) & 255; S[i], S[j] = S[j], S[i]; out.append(c ^ S[(S[i] + S[j]) & 255])
    return bytes(out)

# ---- keys and certificates ----
def le(n, size): return n.to_bytes(size, 'little')
def be(n, size): return n.to_bytes(size, 'big')

def capi_blob(key):
    pn = key.private_numbers(); pub = pn.public_numbers
    bits = key.key_size; h = bits // 8; q = bits // 16
    return (struct.pack('<BBHI', 7, 2, 0, 0xA400) + struct.pack('<III', 0x32415352, bits, pub.e) + le(pub.n, h) +
            le(pn.p, q) + le(pn.q, q) + le(pn.dmp1, q) + le(pn.dmq1, q) + le(pn.iqmp, q) + le(pn.d, h))

def cng_blob(key):
    pn = key.private_numbers(); pub = pn.public_numbers
    bits = key.key_size; h = bits // 8; q = bits // 16
    pe = be(pub.e, (pub.e.bit_length() + 7) // 8)
    return struct.pack('<IIIIII', 0x32415352, bits, len(pe), h, q, q) + pe + be(pub.n, h) + be(pn.p, q) + be(pn.q, q)

def make_cert(serial, cn):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.datetime(2024, 1, 1)
    cert = (x509.CertificateBuilder().subject_name(subj).issuer_name(subj).public_key(key.public_key())
            .serial_number(serial).not_valid_before(now).not_valid_after(now + datetime.timedelta(days=36500))
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False)
            .add_extension(x509.KeyUsage(True, False, True, True, False, False, False, False, False), True)
            .sign(key, hashes.SHA256()))
    return key, cert

# ---- messages ----
def issuer_serial(cert): return tlv(0x30, cert.issuer.public_bytes() + integer(cert.serial_number))
def ski(cert): return tlv(0x80, x509.SubjectKeyIdentifier.from_public_key(cert.public_key()).digest)

def oaep_params(hash_oid):
    if hash_oid == OID_SHA1: return b'\x30\x00'
    h = algid(hash_oid)
    return tlv(0x30, tlv(0xa0, h) + tlv(0xa1, tlv(0x30, oid(OID_MGF1) + h)))

def ktri(cert, cek, use_ski=False, oaep=None, enc_len_delta=0):
    pub = cert.public_key()
    if oaep:
        hm = {OID_SHA1: hashes.SHA1(), OID_SHA256: hashes.SHA256()}[oaep]
        wrapped = pub.encrypt(cek, apad.OAEP(mgf=apad.MGF1(hm), algorithm=hm, label=None))
        ea = algid(OID_OAEP, oaep_params(oaep))
    else:
        wrapped = pub.encrypt(cek, apad.PKCS1v15()); ea = algid(OID_RSA)
    if enc_len_delta: wrapped = wrapped[:enc_len_delta]
    return tlv(0x30, integer(2 if use_ski else 0) + (ski(cert) if use_ski else issuer_serial(cert)) + ea + tlv(4, wrapped))

CIPHERS = {
    'aes128': (OID_AES[16], 16, 16), 'aes192': (OID_AES[24], 24, 16), 'aes256': (OID_AES[32], 32, 16),
    '3des': (OID_3DES, 24, 8), 'des': (OID_DES, 8, 8), 'rc2_40': (OID_RC2, 5, 8), 'rc2_56': (OID_RC2, 7, 8),
    'rc2_64': (OID_RC2, 8, 8), 'rc2_128': (OID_RC2, 16, 8), 'rc4': (OID_RC4, 16, 0), 'rc4_40': (OID_RC4, 5, 0),
}
RC2_VERSION = {40: 160, 56: 52, 64: 120, 128: 58}

def content(name, cek, iv, data):
    if name.startswith('aes'): return cbc(algorithms.AES, cek, iv, data), tlv(4, iv)
    if name == '3des': return cbc(algorithms.TripleDES, cek, iv, data), tlv(4, iv)
    if name == 'des': return cbc(algorithms.TripleDES, cek, iv, data), tlv(4, iv)
    if name.startswith('rc2'):
        bits = int(name.split('_')[1])
        return rc2_cbc(cek, bits, iv, data), tlv(0x30, integer(RC2_VERSION[bits]) + tlv(4, iv))
    if name == 'rc4': return rc4(cek, data), b''
    if name == 'rc4_40':
        salt = os.urandom(11); return rc4(cek + salt, data), tlv(4, salt)
    raise KeyError(name)

def cbc(alg, key, iv, data):
    p = padding.PKCS7(alg.block_size).padder(); data = p.update(data) + p.finalize()
    e = Cipher(alg(key), modes.CBC(iv)).encryptor()
    return e.update(data) + e.finalize()

def build(recips, name='aes256', mut=None, originator=None, attrs=None, cek=None):
    """recips: list of (cert, dict(use_ski=, oaep=)); mut: damage to apply"""
    mut = mut or {}
    oid_, kl, ivl = CIPHERS[name]
    cek = cek or os.urandom(kl); iv = os.urandom(ivl) if ivl else b''
    ct, params = content(name, cek, iv, PLAIN)
    if 'ct' in mut: ct = mut['ct'](ct)
    if 'params' in mut: params = mut['params'](iv)
    recs = sorted(ktri(c, mut.get('wrap', cek), **o) for c, o in recips)
    ver = 0
    if any(o.get('use_ski') for c, o in recips) or originator or attrs: ver = 2
    ct_tlv = mut['ct_tlv'](ct) if 'ct_tlv' in mut else tlv(0x80, ct)
    eci = tlv(0x30, oid(OID_DATA) + algid(mut.get('alg', oid_), params if params else NULL) + ct_tlv)
    body = integer(mut.get('version', ver))
    if originator: body += tlv(0xa0, tlv(0xa0, b''.join(sorted(originator))))
    body += tlv(0x31, b''.join(recs)) + eci
    if attrs: body += tlv(0xa1, b''.join(attrs))
    return tlv(0x30, body)

def info(ev): return tlv(0x30, oid(OID_ENVELOPED) + tlv(0xa0, ev))

def carray(name, data):
    s = 'static const BYTE %s[] =\n{\n' % name
    for i in range(0, len(data), 12):
        s += '    ' + ', '.join('0x%02x' % c for c in data[i:i + 12]) + ',\n'
    return s + '};\n\n'

def main():
    ka, ca = make_cert((0x8f << 120) | int.from_bytes(os.urandom(15), 'big'), 'CMS test A')
    kb, cb = make_cert(int.from_bytes(os.urandom(7), 'big') | 1, 'CMS test B')
    A = (ca, {}); ASKI = (ca, dict(use_ski=True)); B = (cb, {})
    out = '/* generated by gen_msg_fixtures.py, do not edit. The keys are throwaway test keys. */\n\n'
    out += carray('cms_cert_a', ca.public_bytes(serialization.Encoding.DER))
    out += carray('cms_cert_b', cb.public_bytes(serialization.Encoding.DER))
    out += carray('cms_key_a_capi', capi_blob(ka)) + carray('cms_key_a_cng', cng_blob(ka))
    out += carray('cms_key_b_capi', capi_blob(kb)) + carray('cms_key_b_cng', cng_blob(kb))
    msgs = {}
    for n in CIPHERS: msgs[n] = info(build([A], n))
    msgs['ski'] = info(build([ASKI]))
    msgs['oaep_sha1'] = info(build([(ca, dict(oaep=OID_SHA1))]))
    msgs['oaep_sha256'] = info(build([(ca, dict(oaep=OID_SHA256))]))
    msgs['two'] = info(build([A, B]))
    msgs['ber_segments'] = info(build([A], mut=dict(ct_tlv=lambda c: b'\xa0\x80' + tlv(4, c[:20]) + tlv(4, c[20:]) + b'\0\0')))
    ev = build([A])
    hl = 2 if ev[1] < 0x80 else 2 + (ev[1] & 0x7f)
    msgs['ber_indefinite'] = b'\x30\x80' + oid(OID_ENVELOPED) + b'\xa0\x80\x30\x80' + ev[hl:] + b'\0' * 6
    msgs['originator'] = info(build([A], originator=[ca.public_bytes(serialization.Encoding.DER)],
                                    attrs=[tlv(0x30, oid('1.2.3.4.5') + tlv(0x31, tlv(4, b'\x01\x02')))]))
    msgs['version5'] = info(build([A], mut=dict(version=5)))
    msgs['unknown_alg'] = info(build([A], mut=dict(alg='1.2.3.4.5.6.7.8.9.10')))
    msgs['iv_short'] = info(build([A], mut=dict(params=lambda iv: tlv(4, iv[:8]))))
    msgs['null_params'] = info(build([A], mut=dict(params=lambda iv: NULL)))
    msgs['bad_padding'] = info(build([A], mut=dict(ct=lambda c: c[:-1] + bytes([c[-1] ^ 1]))))
    msgs['short_content'] = info(build([A], mut=dict(ct=lambda c: c[:-1])))
    msgs['empty_content'] = info(build([A], mut=dict(ct=lambda c: b'')))
    msgs['cek17'] = info(build([A], mut=dict(wrap=os.urandom(17))))
    for n, m in msgs.items(): out += carray('cms_msg_' + n, m)
    open(sys.argv[1], 'w').write(out)

def extra():
    import re
    text = open(sys.argv[3]).read()
    m = re.search(r'cms_cert_a\[\] =\s*\{(.*?)\};', text, re.S)
    ca = x509.load_der_x509_certificate(bytes(int(x, 16) for x in re.findall(r'0x([0-9a-f]{2})', m.group(1))))
    out = '/* generated by gen_msg_fixtures.py --extra, do not edit. */\n\n'
    msgs = {
        # content key wrapped with RSAES-OAEP, content cipher 3DES / RC2 (the AES messages above are OAEP too): to
        # see what a CryptoAPI key makes of OAEP apart from the content cipher
        'oaep_3des': info(build([(ca, dict(oaep=OID_SHA1))], '3des')),
        'oaep_rc2_40': info(build([(ca, dict(oaep=OID_SHA1))], 'rc2_40')),
        'oaep_3des_sha256': info(build([(ca, dict(oaep=OID_SHA256))], '3des')),
    }
    for n, m in msgs.items(): out += carray('cms_msg_' + n, m)
    open(sys.argv[1], 'w').write(out)

if len(sys.argv) > 3 and sys.argv[2] == '--extra': extra()
else: main()
