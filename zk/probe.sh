#!/bin/sh
# Phase 1 probe: which hash APIs does this Noir version expose, and what does
# one SHA-256 block cost?
#
# Noir 1.0.0-beta moved some hashes out of the stdlib into standalone
# libraries, and the exact surface differs between releases -- so rather than
# assume, compile one tiny circuit per candidate API and report which ones
# the compiler accepts. Needs only `nargo`; `bb` is not involved.
#
# Run:  ./zk/probe.sh

set -e

PROBE=/tmp/nrprobe

scaffold() {
    rm -rf "$PROBE"
    mkdir -p "$PROBE/src"
    cat > "$PROBE/Nargo.toml" <<'EOF'
[package]
name = "probe"
type = "bin"
authors = [""]
EOF
    printf '%s\n' "$1" > "$PROBE/src/main.nr"
}

try() {
    scaffold "$2"
    if (cd "$PROBE" && nargo compile >/dev/null 2>&1); then
        echo "  AVAILABLE   $1"
        return 0
    fi
    echo "  missing     $1"
    return 1
}

echo "Noir version:"
nargo --version | head -1
echo

echo "Hash API probe:"

try "std::hash::sha256 (fixed length)" \
    'fn main(x: [u8; 64]) -> pub [u8; 32] { std::hash::sha256(x) }' || true

SHA_VAR=0
try "std::hash::sha256_var (variable length)" \
    'fn main(x: [u8; 64], n: u64) -> pub [u8; 32] { std::hash::sha256_var(x, n) }' \
    && SHA_VAR=1

try "std::hash::poseidon::bn254::hash_2" \
    'fn main(a: Field, b: Field) -> pub Field { std::hash::poseidon::bn254::hash_2([a, b]) }' || true

try "std::hash::poseidon2" \
    'fn main(a: Field, b: Field) -> pub Field { std::hash::poseidon2::Poseidon2::hash([a, b], 2) }' || true

echo
echo "Cost of one 128-byte SHA-256 (our max template_data, 3 blocks):"
if [ "$SHA_VAR" -eq 1 ]; then
    scaffold 'fn main(x: [u8; 128], n: u64) -> pub [u8; 32] { std::hash::sha256_var(x, n) }'
else
    scaffold 'fn main(x: [u8; 128]) -> pub [u8; 32] { std::hash::sha256(x) }'
fi
(cd "$PROBE" && nargo info) 2>&1 | tail -20 || \
    echo "  (nargo info failed -- paste the error)"

echo
echo "If every hash above is 'missing', the stdlib no longer carries them and"
echo "we add noir-lang/sha256 and noir-lang/poseidon as Nargo.toml deps."
