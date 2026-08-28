#!/usr/bin/env python3
"""Poseidon x5_8 over BN254 -- reference implementation for the test harness.

This is NOT part of the product. The RP computes commitments in C
(src/core/charra_poseidon.c); this exists so zk/gen_prover_toml.py can build
a Prover.toml without invoking the C, keeping the circuit testable on its own.

It is the implementation that was validated against the circuit's own output
for all 33 entries of the real log before charra_poseidon.c was written from
it -- so if the C and this disagree, this one is the reference.

Constants come from the Noir library the circuit compiles against, sliced
the same way zk/extract_poseidon_consts.py slices them.
"""

import hashlib
import pathlib
import re

P = 0x30644E72E131A029B85045B68181585D2833E84879B9709143E1F593F0000001
T, RF, RP = 8, 8, 64
SPARSE_STRIDE = 2 * T - 1
MAX_PATH, LIMB_BYTES, LIMBS = 136, 31, 5

_LIB = (pathlib.Path.home() / "nargo/github.com/noir-lang/poseidon/v0.3.0"
        / "src/poseidon/bn254/consts.nr")

_cache = {}


def _consts():
    if _cache:
        return _cache
    if not _LIB.exists():
        raise SystemExit(
            f"{_LIB} not found. Run `nargo compile` in zk/circuit to fetch the "
            "dependency.")
    src = _LIB.read_text()
    i = src.index("fn x5_8_config")
    ends = [k for k in (src.find("\nfn ", i + 10), src.find("\npub fn ", i + 10))
            if k != -1]
    body = src[i:min(ends)] if ends else src[i:]
    h = [int(x, 16) for x in re.findall(r"0x[0-9a-fA-F]+", body)]
    want = 128 + 64 + 64 + RP * SPARSE_STRIDE
    if len(h) != want:
        raise SystemExit(f"expected {want} constants, found {len(h)} -- the "
                         "library layout changed")
    _cache.update(rc=h[:128], mds=h[128:192], pre=h[192:256], sparse=h[256:])
    return _cache


def _sigma(s):
    return [pow(x, 5, P) for x in s]


def _apply_matrix(m, v):
    # Transposed, exactly as Noir's apply_matrix: out[i] = sum_j v[j]*m[j][i].
    return [sum(v[j] * m[j * T + i] for j in range(T)) % P for i in range(T)]


def permute(state):
    c = _consts()
    rc, mds, pre, sparse = c["rc"], c["mds"], c["pre"], c["sparse"]
    s = [(state[i] + rc[i]) % P for i in range(T)]

    for r in range(RF // 2 - 1):
        s = _sigma(s)
        s = [(s[i] + rc[T * (r + 1) + i]) % P for i in range(T)]
        s = _apply_matrix(mds, s)

    s = _sigma(s)
    s = [(s[i] + rc[T * (RF // 2) + i]) % P for i in range(T)]
    s = _apply_matrix(pre, s)

    for r in range(RP):
        s[0] = pow(s[0], 5, P)
        s[0] = (s[0] + rc[(RF // 2 + 1) * T + r]) % P
        # new0 uses the OLD state, so compute it before updating s[1..T).
        new0 = sum(sparse[SPARSE_STRIDE * r + j] * s[j] for j in range(T)) % P
        for k in range(1, T):
            s[k] = (s[k] + s[0] * sparse[SPARSE_STRIDE * r + T + k - 1]) % P
        s[0] = new0

    for r in range(RF // 2 - 1):
        s = _sigma(s)
        s = [(s[i] + rc[(RF // 2 + 1) * T + RP + r * T + i]) % P
             for i in range(T)]
        s = _apply_matrix(mds, s)

    s = _sigma(s)
    return _apply_matrix(mds, s)


def hash_7(inputs):
    """Noir's hash_7: inputs land at state[1..8], state[0] stays zero."""
    assert len(inputs) == 7
    st = [0] * T
    for i, v in enumerate(inputs):
        st[i + 1] = v
    return permute(st)[0]


def commit(path, path_len, salt):
    """Poseidon commitment to a measured path -- mirrors commit.nr."""
    if len(path) > MAX_PATH:
        raise ValueError(f"path of {len(path)} B exceeds MAX_PATH {MAX_PATH}")
    padded = path + b"\x00" * (MAX_PATH - len(path))
    limbs = []
    for l in range(LIMBS):
        acc = 0
        for j in range(LIMB_BYTES):
            idx = l * LIMB_BYTES + j
            if idx < MAX_PATH:          # the last limb is only partly used
                acc = acc * 256 + padded[idx]
        limbs.append(acc)
    return hash_7(limbs + [path_len, salt % P])


def test_salt(i):
    """Deterministic stand-in for a CSPRNG salt -- harness only.

    The real RP draws these from charra_random_bytes(). Reusing or omitting a
    salt makes the commitments brute-forceable over the small space of
    plausible system paths, and linkable across attestation runs.
    """
    return int.from_bytes(
        hashlib.sha256(f"charra-zk-test-salt-{i}".encode()).digest()[:31],
        "big")
