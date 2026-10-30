#!/usr/bin/env python3
# Solve the seed-bound SHA-256 PoW exactly the way challenge.js and the
# verifier (cookies.go verifyPowSHA256 / the C plugin) do: find the first
# nonce where sha256("<seed>:<nonce>") has >= difficulty leading zero bits,
# then print the _bv cookie "<issued>.pow2.<nonce_b36>.0".
#
# Usage: powsolve.py <seed_hex> <issued_unix> <difficulty> [nth]
#   nth (default 1): print the nth nonce that clears the difficulty rather
#   than the first -- another answer to the same seed, which the verifier
#   accepts just the same (scenario 71: a nonce is not a pass's identity).
import hashlib
import string
import sys

seed, issued, diff = sys.argv[1], sys.argv[2], int(sys.argv[3])
nth = int(sys.argv[4]) if len(sys.argv) > 4 else 1
DIG = string.digits + string.ascii_lowercase
n = 0
while True:
    h = hashlib.sha256(f"{seed}:{n}".encode()).digest()
    bits = 0
    for byte in h:
        if byte == 0:
            bits += 8
            continue
        while not (byte & 0x80):
            bits += 1
            byte <<= 1
        break
    if bits >= diff:
        nth -= 1
        if nth <= 0:
            m, b36 = n, ""
            while m:
                b36 = DIG[m % 36] + b36
                m //= 36
            print(f"{issued}.pow2.{b36 or '0'}.0")
            break
    n += 1
