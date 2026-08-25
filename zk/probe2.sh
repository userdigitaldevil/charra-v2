#!/bin/sh
# Phase 1 probe, second pass: the stdlib no longer carries sha256/poseidon
# (see probe.sh), so pull them in as git dependencies and find out what they
# actually export.
#
# Discovers the newest release tag of each library rather than hardcoding
# one, then compiles a tiny circuit per candidate API name and reports which
# the compiler accepts. Needs only `nargo` and network access.
#
# Run:  ./zk/probe2.sh

set -e

PROBE=/tmp/nrprobe2
SHA_REPO=https://github.com/noir-lang/sha256
POS_REPO=https://github.com/noir-lang/poseidon

# Newest vX.Y.Z tag on a remote, without cloning it.
latest_tag() {
    git ls-remote --tags --refs "$1" 2>/dev/null \
        | awk -F/ '{print $NF}' \
        | grep -E '^v?[0-9]+\.[0-9]+\.[0-9]+$' \
        | sort -V \
        | tail -1
}

echo "Discovering library versions..."
SHA_TAG=$(latest_tag "$SHA_REPO" || true)
POS_TAG=$(latest_tag "$POS_REPO" || true)

if [ -z "$SHA_TAG" ] || [ -z "$POS_TAG" ]; then
    echo "  could not list tags (no network?). Found:"
    echo "    sha256:   '${SHA_TAG:-none}'"
    echo "    poseidon: '${POS_TAG:-none}'"
    echo "  Check the repos' releases pages and set SHA_TAG/POS_TAG by hand."
    exit 1
fi
echo "  sha256   $SHA_TAG"
echo "  poseidon $POS_TAG"
echo

scaffold() {
    rm -rf "$PROBE"
    mkdir -p "$PROBE/src"
    cat > "$PROBE/Nargo.toml" <<EOF
[package]
name = "probe"
type = "bin"
authors = [""]

[dependencies]
sha256 = { tag = "$SHA_TAG", git = "$SHA_REPO" }
poseidon = { tag = "$POS_TAG", git = "$POS_REPO" }
EOF
    printf '%s\n' "$1" > "$PROBE/src/main.nr"
}

# Before probing API names, check the dependencies resolve at all -- if they
# do not, every candidate below fails for that reason and the per-API
# results would be meaningless.
echo "Checking dependencies resolve..."
scaffold 'fn main(x: Field) -> pub Field { x + 1 }'
if ! (cd "$PROBE" && nargo compile 2>/tmp/nrprobe2.err); then
    echo "  FAILED -- dependencies did not resolve. Compiler said:"
    sed 's/^/    /' /tmp/nrprobe2.err
    exit 1
fi
echo "  ok"
echo

try() {
    scaffold "$2"
    if (cd "$PROBE" && nargo compile >/dev/null 2>&1); then
        echo "  AVAILABLE   $1"
        return 0
    fi
    echo "  missing     $1"
    return 1
}

echo "SHA-256 API:"
SHA_FIXED=''
try "sha256::sha256" \
    'fn main(x: [u8; 64]) -> pub [u8; 32] { sha256::sha256(x) }' \
    && SHA_FIXED='sha256::sha256(x)'
try "sha256::digest" \
    'fn main(x: [u8; 64]) -> pub [u8; 32] { sha256::digest(x) }' \
    && [ -z "$SHA_FIXED" ] && SHA_FIXED='sha256::digest(x)'

SHA_VAR=''
try "sha256::sha256_var  (variable length)" \
    'fn main(x: [u8; 64], n: u64) -> pub [u8; 32] { sha256::sha256_var(x, n) }' \
    && SHA_VAR='sha256::sha256_var(x, n)'
try "sha256::sha256::sha256_var" \
    'fn main(x: [u8; 64], n: u64) -> pub [u8; 32] { sha256::sha256::sha256_var(x, n) }' \
    && [ -z "$SHA_VAR" ] && SHA_VAR='sha256::sha256::sha256_var(x, n)'

echo
echo "Poseidon API:"
try "poseidon::bn254::hash_2" \
    'fn main(a: Field, b: Field) -> pub Field { poseidon::bn254::hash_2([a, b]) }' || true
try "poseidon::poseidon::bn254::hash_2" \
    'fn main(a: Field, b: Field) -> pub Field { poseidon::poseidon::bn254::hash_2([a, b]) }' || true
try "poseidon::poseidon2::Poseidon2::hash" \
    'fn main(a: Field, b: Field) -> pub Field { poseidon::poseidon2::Poseidon2::hash([a, b], 2) }' || true

echo
echo "Cost of one 128-byte SHA-256 (our max template_data is 124 -> 3 blocks):"
if [ -n "$SHA_VAR" ]; then
    echo "  (using the variable-length form)"
    scaffold "fn main(x: [u8; 128], n: u64) -> pub [u8; 32] { ${SHA_VAR%(x, n)}(x, n) }"
elif [ -n "$SHA_FIXED" ]; then
    echo "  (using the fixed-length form -- no sha256_var found)"
    scaffold "fn main(x: [u8; 128]) -> pub [u8; 32] { ${SHA_FIXED%(x)}(x) }"
else
    echo "  no working SHA-256 API found; skipping"
    exit 1
fi
(cd "$PROBE" && nargo info) 2>&1 | tail -20

echo
echo "Working Nargo.toml dependency block:"
echo "  [dependencies]"
echo "  sha256 = { tag = \"$SHA_TAG\", git = \"$SHA_REPO\" }"
echo "  poseidon = { tag = \"$POS_TAG\", git = \"$POS_REPO\" }"
