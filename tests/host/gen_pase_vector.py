#!/usr/bin/env python3
"""Generate an independent PASE responder vector for tests/host/test_matter_pase_sm.c.

Not run by make test. It produced the constants pasted into that suite,
and it lives here so they can be regenerated and audited rather than taken on
trust:

    python3 tests/host/gen_pase_vector.py src/matter_spake2p.c

Nothing here comes from the C under test. P-256 is plain Python integer math,
the transcript follows RFC 9383 + Matter's ordering, and the prover and the
verifier sides are computed with their DIFFERENT formulas and asserted equal --
that agreement is the check that the vector is right, not that it is self
consistent with one implementation.

M and N are read out of src/matter_spake2p.c rather than
retyped, and then checked to be on the curve, so a transcription slip cannot
survive into the vector.
"""
import hashlib
import hmac
import re
import sys

# ------------------------------------------------------------------ P-256 ---
P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
A = P - 3
B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
N_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
GX = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
GY = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5


def is_on_curve(pt):
    if pt is None:
        return True
    x, y = pt
    return (y * y - (x * x * x + A * x + B)) % P == 0


def add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    if p1 == p2:
        lam = (3 * x1 * x1 + A) * pow(2 * y1, P - 2, P) % P
    else:
        lam = (y2 - y1) * pow(x2 - x1, P - 2, P) % P
    x3 = (lam * lam - x1 - x2) % P
    return (x3, (lam * (x1 - x3) - y1) % P)


def neg(pt):
    return None if pt is None else (pt[0], (-pt[1]) % P)


def mul(k, pt):
    r, acc = None, pt
    k %= N_ORDER
    while k:
        if k & 1:
            r = add(r, acc)
        acc = add(acc, acc)
        k >>= 1
    return r


def enc(pt):
    x, y = pt
    return b"\x04" + x.to_bytes(32, "big") + y.to_bytes(32, "big")


def dec(b):
    assert len(b) == 65 and b[0] == 4, "uncompressed point expected"
    return (int.from_bytes(b[1:33], "big"), int.from_bytes(b[33:], "big"))


G = (GX, GY)
assert is_on_curve(G), "base point off curve"
assert mul(N_ORDER, G) is None, "order does not annihilate G"

# ------------------------------------------------- M and N, read from the C ---
SRC = sys.argv[1]
src = open(SRC).read()


def const_bytes(name):
    m = re.search(name + r"\[\w+\]\s*=\s*\{(.*?)\}\s*;", src, re.S)
    if not m:
        raise SystemExit("could not find " + name)
    vals = re.findall(r"0[xX][0-9a-fA-F]{2}", m.group(1))
    return bytes(int(v, 16) for v in vals)


M_B = const_bytes("matter_spake2p_M")
N_B = const_bytes("matter_spake2p_N")
assert len(M_B) == 65 and len(N_B) == 65, (len(M_B), len(N_B))
M, N = dec(M_B), dec(N_B)
assert is_on_curve(M), "M off curve -- transcription error"
assert is_on_curve(N), "N off curve -- transcription error"

# ------------------------------------------------------------- the fixture ---
# The request is a REAL one, captured off an iPhone commissioning a Matter
# accessory (already in tests/host/test_matter_pase.c).
REQ = bytes.fromhex(
    "15300120a882bce8bfdeab50e04ac596bfc05024db5902b7512ed9b278cfaacc125230122502b6e42403002804"
    "35052501f40125022c012503a00f24041224050b2606000004012407011818"
)
INITIATOR_RANDOM = REQ[4:36]

PASSCODE = 20202021
SALT = bytes(range(0x40, 0x60))  # 32 bytes, 0x40..0x5f
ITERATIONS = 1000
RESPONDER_RANDOM = bytes(range(0x80, 0xA0))  # 32 bytes, 0x80..0x9f
RESPONDER_SESSION_ID = 0x1234
# Ephemeral scalars. Supplied to the code under test as 40 raw bytes that it
# reduces mod the group order, exactly as it will on target.
X_WS = bytes(range(0x01, 0x29))  # 40 bytes, commissioner side
Y_WS = bytes(range(0xC0, 0xE8))  # 40 bytes, responder side


# ------------------------------------------------------------ Matter TLV -----
def tlv_octstr(tag, val):
    assert len(val) < 256
    return bytes([0x30, tag, len(val)]) + val


def tlv_uint(tag, val):
    if val < 0x100:
        return bytes([0x24, tag, val])
    if val < 0x10000:
        return bytes([0x25, tag]) + val.to_bytes(2, "little")
    return bytes([0x26, tag]) + val.to_bytes(4, "little")


def tlv_struct(tag, body):
    return bytes([0x35, tag]) + body + b"\x18"


resp = b"\x15"
resp += tlv_octstr(1, INITIATOR_RANDOM)
resp += tlv_octstr(2, RESPONDER_RANDOM)
resp += tlv_uint(3, RESPONDER_SESSION_ID)
resp += tlv_struct(4, tlv_uint(1, ITERATIONS) + tlv_octstr(2, SALT))
resp += b"\x18"

# ------------------------------------------------------------- SPAKE2+ -------
ws = hashlib.pbkdf2_hmac("sha256", PASSCODE.to_bytes(4, "little"), SALT, ITERATIONS, 80)
w0 = int.from_bytes(ws[:40], "big") % N_ORDER
w1 = int.from_bytes(ws[40:], "big") % N_ORDER
L = mul(w1, G)

x = int.from_bytes(X_WS, "big") % N_ORDER
y = int.from_bytes(Y_WS, "big") % N_ORDER

pA = add(mul(x, G), mul(w0, M))
pB = add(mul(y, G), mul(w0, N))
assert is_on_curve(pA) and is_on_curve(pB)

# Verifier (our device) and prover (the commissioner) reach Z and V by
# different routes. Agreement is what makes this a reference rather than a
# restatement.
Z_verifier = mul(y, add(pA, neg(mul(w0, M))))
V_verifier = mul(y, L)
Z_prover = mul(x, add(pB, neg(mul(w0, N))))
V_prover = mul(w1, add(pB, neg(mul(w0, N))))
assert Z_verifier == Z_prover, "Z disagrees between the two sides"
assert V_verifier == V_prover, "V disagrees between the two sides"
Z, V = Z_verifier, V_verifier

context = hashlib.sha256(b"CHIP PAKE V1 Commissioning" + REQ + resp).digest()


def tt_elem(b):
    return len(b).to_bytes(8, "little") + b


TT = b"".join(
    tt_elem(e)
    for e in (
        context,
        b"",
        b"",
        M_B,
        N_B,
        enc(pA),
        enc(pB),
        enc(Z),
        enc(V),
        w0.to_bytes(32, "big"),
    )
)
assert len(TT) == 534, len(TT)

h = hashlib.sha256(TT).digest()
Ka, Ke = h[:16], h[16:]


def hkdf(ikm, salt, info, length):
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    out, t, i = b"", b"", 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        out += t
        i += 1
    return out[:length]


kc = hkdf(Ka, b"", b"ConfirmationKeys", 32)
KcA, KcB = kc[:16], kc[16:]
cA = hmac.new(KcA, enc(pB), hashlib.sha256).digest()
cB = hmac.new(KcB, enc(pA), hashlib.sha256).digest()

session = hkdf(Ke, b"", b"SessionKeys", 48)

# ------------------------------------------------------------------ output ---
def c_hex(name, b):
    s = b.hex()
    print('static const char *const %s =' % name)
    chunks = [s[i : i + 88] for i in range(0, len(s), 88)]
    for i, c in enumerate(chunks):
        end = ";" if i == len(chunks) - 1 else ""
        print('\t"%s"%s' % (c, end))


print("/* generated by scratchpad/gen_pase_vector.py -- do not hand-edit */")
c_hex("K_SALT", SALT)
c_hex("K_RESP_RANDOM", RESPONDER_RANDOM)
c_hex("K_Y_WS", Y_WS)
c_hex("K_W0", w0.to_bytes(32, "big"))
c_hex("K_L", enc(L))
c_hex("K_EXPECT_RESP", resp)
c_hex("K_PA", enc(pA))
c_hex("K_EXPECT_PB", enc(pB))
c_hex("K_Z", enc(Z))
c_hex("K_V", enc(V))
c_hex("K_EXPECT_CB", cB)
c_hex("K_CA", cA)
c_hex("K_EXPECT_KE", Ke)
c_hex("K_EXPECT_I2R", session[:16])
c_hex("K_EXPECT_R2I", session[16:32])
c_hex("K_EXPECT_ATTEST", session[32:])
print("/* response is %d bytes, transcript %d */" % (len(resp), len(TT)))
