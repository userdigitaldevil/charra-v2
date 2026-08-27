#!/bin/sh
# Find a barretenberg build this container's glibc can actually run.
#
# bb 5.0.0-nightly.20260522 (the newest version bbup's map knows) needs
# GLIBC 2.34; the charra dev container is older. Aztec ships no static
# build, so the question is simply which of the older bb releases were
# linked against a glibc old enough to run here.
#
# Each candidate is downloaded to a scratch dir and asked for its version.
# Nothing is installed and PATH is untouched -- this only reports.

echo "container:"
ldd --version 2>&1 | head -1
grep -E '^(NAME|VERSION)=' /etc/os-release 2>/dev/null
echo

ARCH=amd64
PLAT=linux
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

# Newest first. The paired Noir beta is what nargo would have to be pinned
# to if that bb is the one that runs -- see bb-versions.json.
for pair in \
    "5.0.0-nightly.20260522:beta.22" \
    "4.0.0-nightly.20260120:beta.19" \
    "3.0.0-nightly.20251104:beta.17" \
    "1.2.0:beta.13" \
    "0.87.0:beta.12" \
    "0.84.0:beta.6" \
    "0.82.2:beta.3"
do
    v=${pair%%:*}
    noir=${pair##*:}
    printf '%-28s (noir %-9s) ' "$v" "$noir"

    url="https://github.com/AztecProtocol/barretenberg/releases/download/v${v}/barretenberg-${ARCH}-${PLAT}.tar.gz"
    alt="https://github.com/AztecProtocol/aztec-packages/releases/download/v${v}/barretenberg-${ARCH}-${PLAT}.tar.gz"

    rm -rf "$TMP/x"; mkdir -p "$TMP/x"
    if ! curl -sL --fail "$url" -o "$TMP/b.tar.gz" 2>/dev/null; then
        if ! curl -sL --fail "$alt" -o "$TMP/b.tar.gz" 2>/dev/null; then
            echo "no such release"
            continue
        fi
    fi

    if ! tar xzf "$TMP/b.tar.gz" -C "$TMP/x" 2>/dev/null; then
        echo "bad archive"
        continue
    fi

    bin=$(find "$TMP/x" -name bb -type f 2>/dev/null | head -1)
    if [ -z "$bin" ]; then
        echo "no bb binary inside"
        continue
    fi
    chmod +x "$bin"

    out=$("$bin" --version 2>&1)
    if echo "$out" | grep -q GLIBC; then
        need=$(echo "$out" | grep -o 'GLIBC_[0-9.]*' | sort -V | tail -1)
        echo "needs $need -- too new"
    else
        echo "RUNS  ($(echo "$out" | head -1))"
    fi
done

echo
echo "Any line saying RUNS is usable; pin nargo to that row's noir version."
