#!/usr/bin/env python3
"""Derive a SPAKE2+ verifier (w0 and L) for a Matter setup passcode.

A Matter device never stores its setup passcode. It stores the verifier, which
is what PBKDF2 over the passcode yields plus one scalar multiplication:

    w0s || w1s = PBKDF2-HMAC-SHA256(passcode as LE uint32, salt, iterations, 80)
    w0 = w0s mod n     w1 = w1s mod n     L = w1 * G

Someone who reads the flash gets w0 and L, which are enough to VERIFY a
commissioner that knows the passcode and not enough to impersonate one. That is
the whole point of the augmented form, and the reason this runs here rather than
on the device: L needs a base-point multiply, which is not one of the four
SPAKE2+ operations the device's crypto backend provides.

Usage:

    scripts/spake2p_verifier.py                     # CHIP's test pairing
    scripts/spake2p_verifier.py --passcode 12345678 --salt-b64 <...>

The output goes into CONFIG_TINYMATTER_SPAKE2P_VERIFIER and friends
(Kconfig). Print nothing anywhere it will be logged: the
verifier is not a secret in the way the passcode is, but it identifies the
device and there is no reason to scatter it.
"""
import argparse
import base64
import hashlib

# P-256 (SEC 2, secp256r1).
P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
A = P - 3
B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
G = (
    0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
    0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5,
)


def on_curve(pt):
    """Test whether a point satisfies the secp256r1 curve equation."""
    if pt is None:
        return True
    x, y = pt
    return (y * y - (x * x * x + A * x + B)) % P == 0


def add(p1, p2):
    """Add two points on the secp256r1 elliptic curve using the tangent-and-chord method; return None for the point at infinity."""
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


def mul(k, pt):
    r, acc = None, pt
    k %= N
    while k:
        if k & 1:
            r = add(r, acc)
        acc = add(acc, acc)
        k >>= 1
    return r


def derive(passcode, salt, iterations):
    """The 97-byte verifier: w0 (32) then L (65, uncompressed)."""
    # Bounds the device also enforces (matter_pase.h, from CHIPCryptoPAL.h:86-89).
    if not 16 <= len(salt) <= 32:
        raise SystemExit(f"salt must be 16..32 bytes, got {len(salt)}")
    if not 1000 <= iterations <= 100000:
        raise SystemExit("iterations must be 1000..100000")
    if not 0 < passcode < (1 << 27):
        raise SystemExit("passcode must fit 27 bits")

    # LITTLE-endian uint32. Getting this backwards produces a verifier that is
    # wrong in a way nothing detects until a commissioner's cA fails.
    ws = hashlib.pbkdf2_hmac("sha256", passcode.to_bytes(4, "little"), salt, iterations, 80)
    w0 = int.from_bytes(ws[:40], "big") % N
    w1 = int.from_bytes(ws[40:], "big") % N
    L = mul(w1, G)

    assert on_curve(L) and mul(N, L) is None, "L is not a valid P-256 point"
    assert 0 < w0 < N and 0 < w1 < N

    l_bytes = b"\x04" + L[0].to_bytes(32, "big") + L[1].to_bytes(32, "big")
    return w0.to_bytes(32, "big") + l_bytes


# Verhoeff, over the dihedral group D5. Matter uses it for the manual code's
# check digit because it catches every single-digit error and every adjacent
# transposition, which is what a person typing eleven digits into a phone gets
# wrong. Tables are the standard ones, not derived here.
_MUL = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6], [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8], [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2], [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4], [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
]
_PERM = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2], [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0], [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5], [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
]
_INV = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9]


def manual_code(discriminator, passcode):
    """The 11-digit manual pairing code, short form (no vendor/product id).

    Matter core 5.1.4.1. The digits are the discriminator's top 2 bits, then
    its next 2 bits packed above the passcode's low 14, then the passcode's
    high 13, then a check digit -- so BOTH numbers are recoverable from the
    code, which is why a commissioner needs nothing else to find the device.
    """
    digits = "%01d%05d%04d" % (
        (discriminator >> 10) & 0x3,
        ((discriminator & 0x300) << 6) | (passcode & 0x3FFF),
        passcode >> 14,
    )
    check = 0
    for i, ch in enumerate(reversed(digits)):
        check = _MUL[check][_PERM[(i + 1) % 8][int(ch)]]
    return digits + str(_INV[check])


def read_config(path):
    """The five symbols the setup code needs, out of a Zephyr .config."""
    wanted = {
        "CONFIG_TINYMATTER_DISCRIMINATOR": None,
        "CONFIG_TINYMATTER_SETUP_PASSCODE": None,
        "CONFIG_TINYMATTER_SPAKE2P_SALT": None,
        "CONFIG_TINYMATTER_SPAKE2P_ITERATIONS": None,
        "CONFIG_TINYMATTER_SPAKE2P_VERIFIER": None,
    }
    try:
        with open(path) as f:
            for line in f:
                if "=" not in line or line.startswith("#"):
                    continue
                key, _, val = line.strip().partition("=")
                if key in wanted:
                    wanted[key] = val.strip('"')
    except OSError as e:
        raise SystemExit(f"cannot read {path}: {e}")

    missing = [k for k, v in wanted.items() if v is None]
    if missing:
        raise SystemExit(
            "not a tinymatter BLE build -- missing %s in %s" % (", ".join(missing), path)
        )
    return wanted


def from_config(path):
    """Print the setup code for an image ALREADY BUILT, and prove it first.

    The device stores a verifier and never the passcode, so nothing on the
    board can print this and nothing on the board can notice the two drifting
    apart. Here they can be checked against each other: re-derive the verifier
    from the passcode symbol and compare. A mismatch means the code below would
    be entered, accepted by the phone, and fail at Pake3 looking exactly like a
    typo -- so it is an error, not a warning.
    """
    cfg = read_config(path)
    discriminator = int(cfg["CONFIG_TINYMATTER_DISCRIMINATOR"], 0)
    passcode = int(cfg["CONFIG_TINYMATTER_SETUP_PASSCODE"], 0)
    salt = bytes.fromhex(cfg["CONFIG_TINYMATTER_SPAKE2P_SALT"])
    iterations = int(cfg["CONFIG_TINYMATTER_SPAKE2P_ITERATIONS"], 0)

    built = cfg["CONFIG_TINYMATTER_SPAKE2P_VERIFIER"].lower()
    ours = derive(passcode, salt, iterations).hex()
    if built != ours:
        raise SystemExit(
            "  SETUP CODE UNKNOWN: the verifier in this build is not the one\n"
            "  passcode %d produces with this salt and %d iterations.\n"
            "  One of CONFIG_TINYMATTER_SETUP_PASSCODE or\n"
            "  CONFIG_TINYMATTER_SPAKE2P_VERIFIER was changed without the\n"
            "  other. Regenerate with: scripts/spake2p_verifier.py --passcode <p>"
            % (passcode, iterations)
        )

    code = manual_code(discriminator, passcode)
    print(
        "  setup code  %s-%s-%s   ·  discriminator 0x%04X, verifier checked"
        % (code[0:4], code[4:7], code[7:11], discriminator)
    )


def main():
    """Derive the 97-byte SPAKE2+ verifier (w0 then L) from passcode, salt and iteration count; print Matter Kconfig with setup code and print the verifier hex; if --from-config is set, read a built .config, verify its SPAKE2+ constants, and print the setup code."""
    ap = argparse.ArgumentParser(description=__doc__)
    # CHIP's own test pairing, so the defaults commission with a stock
    # chip-tool and with Apple Home using the standard setup code.
    ap.add_argument("--passcode", type=int, default=20202021)
    ap.add_argument("--salt-b64", default="U1BBS0UyUCBLZXkgU2FsdA==")
    ap.add_argument("--salt-hex", default=None, help="overrides --salt-b64")
    ap.add_argument("--iterations", type=int, default=1000)
    ap.add_argument(
        "--from-config",
        metavar="DOTCONFIG",
        default=None,
        help="print the setup code for a built image, after checking its verifier",
    )
    args = ap.parse_args()

    if args.from_config:
        from_config(args.from_config)
        return

    salt = bytes.fromhex(args.salt_hex) if args.salt_hex else base64.b64decode(args.salt_b64)
    blob = derive(args.passcode, salt, args.iterations)

    print(f"setup code  {manual_code(0x0F00, args.passcode)}  (with discriminator 0x0F00)")
    print(f"passcode    {args.passcode}")
    print(f"salt        {salt.hex()}  ({len(salt)} bytes)")
    print(f"iterations  {args.iterations}")
    print()
    print("CONFIG_TINYMATTER_SETUP_PASSCODE=%d" % args.passcode)
    print("CONFIG_TINYMATTER_SPAKE2P_SALT=\"%s\"" % salt.hex())
    print("CONFIG_TINYMATTER_SPAKE2P_ITERATIONS=%d" % args.iterations)
    print("CONFIG_TINYMATTER_SPAKE2P_VERIFIER=\"%s\"" % blob.hex())
    print()
    print(f"# {len(blob)} bytes: w0 (32) then L (65, uncompressed)")


# Guarded so the derivation helpers can be imported rather than copied: a second
# copy of the curve arithmetic is exactly the kind of drift --from-config exists
# to catch. Running this file directly is unchanged.
if __name__ == "__main__":
    main()
