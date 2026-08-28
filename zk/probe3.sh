#!/bin/sh
# Phase 1 probe, third pass. probe2.sh found `sha256::digest` but no
# variable-length entry point -- and our template_data spans 62..124 bytes,
# i.e. 2 OR 3 SHA-256 blocks, so a fixed-length hash cannot serve every
# entry.
#
# The fallback is to drive the compression function directly and mux the
# right intermediate state. That needs `sha256_compression`. Rather than
# guess at more API names, read the cached library source and list what it
# actually exports.
#
# Run:  ./zk/probe3.sh

set -e

PROBE=/tmp/nrprobe3

echo "=== Cached library sources ==="
# nargo caches git dependencies under ~/.nargo; the exact layout varies by
# version, so search rather than assume a path.
SHA_SRC=$(find "$HOME/.nargo" -type d -name "*sha256*" 2>/dev/null | head -3)
POS_SRC=$(find "$HOME/.nargo" -type d -name "*poseidon*" 2>/dev/null | head -3)
echo "sha256:   ${SHA_SRC:-(not found)}"
echo "poseidon: ${POS_SRC:-(not found)}"
echo

if [ -n "$SHA_SRC" ]; then
    echo "=== sha256: public API ==="
    find $SHA_SRC -name '*.nr' 2>/dev/null | while read -r f; do
        if grep -qE '^\s*pub (fn|mod|struct)' "$f"; then
            echo "--- ${f#$HOME/.nargo/} ---"
            grep -nE '^\s*pub (fn|mod|struct)|^\s*mod ' "$f" | sed 's/^/    /'
        fi
    done
    echo
fi

if [ -n "$POS_SRC" ]; then
    echo "=== poseidon: public API (hash arity we can use) ==="
    find $POS_SRC -name '*.nr' 2>/dev/null | while read -r f; do
        grep -nE '^\s*pub fn (hash_[0-9]+|hash)\b' "$f" 2>/dev/null \
            | sed "s|^|    ${f##*/}:|"
    done
    echo
fi

# --- is the compression primitive reachable? ---------------------------------
# This is the one that decides whether the manual-padding fallback is
# straightforward or genuinely painful.

scaffold() {
    rm -rf "$PROBE"
    mkdir -p "$PROBE/src"
    cat > "$PROBE/Nargo.toml" <<'EOF'
[package]
name = "probe"
type = "bin"
authors = [""]

[dependencies]
sha256 = { tag = "v0.3.0", git = "https://github.com/noir-lang/sha256" }
EOF
    printf '%s\n' "$1" > "$PROBE/src/main.nr"
}

try() {
    scaffold "$2"
    if (cd "$PROBE" && nargo compile >/dev/null 2>&1); then
        echo "  AVAILABLE   $1"
    else
        echo "  missing     $1"
    fi
}

echo "=== SHA-256 compression primitive ==="
try "std::hash::sha256_compression" \
    'fn main(m: [u32; 16], s: [u32; 8]) -> pub [u32; 8] { std::hash::sha256_compression(m, s) }'
try "std::sha256::sha256_compression" \
    'fn main(m: [u32; 16], s: [u32; 8]) -> pub [u32; 8] { std::sha256::sha256_compression(m, s) }'
try "sha256::sha256_compression" \
    'fn main(m: [u32; 16], s: [u32; 8]) -> pub [u32; 8] { sha256::sha256_compression(m, s) }'

echo
echo "=== does digest() take an arbitrary compile-time length? ==="
try "sha256::digest on [u8; 62]  (our shortest template_data)" \
    'fn main(x: [u8; 62]) -> pub [u8; 32] { sha256::digest(x) }'
try "sha256::digest on [u8; 124] (our longest template_data)" \
    'fn main(x: [u8; 124]) -> pub [u8; 32] { sha256::digest(x) }'

echo
echo "If sha256_compression is AVAILABLE anywhere above, the manual-padding"
echo "fallback is straightforward. If not, say so and we reconsider the"
echo "approach before writing the circuit."
