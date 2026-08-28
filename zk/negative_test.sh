#!/bin/sh
# Soundness smoke test.
#
# A solved witness proves the circuit ACCEPTS the truth. It proves nothing
# about whether the circuit would also accept a lie -- an assertion that was
# accidentally trivial (comparing a value to itself, say, or a chain that
# silently ignored its inputs) would solve just as happily. Since the whole
# design rests on one assertion, that is worth checking directly.
#
# Each case below corrupts the witness in a way a dishonest RP would want to
# get away with, and the circuit must refuse to solve it.
#
# Run:  ./zk/negative_test.sh

cd "$(dirname "$0")/.." || exit 1

run_case() {
    mode="$1"
    desc="$2"
    printf '  %-28s ' "$mode"
    if ! ./zk/gen_prover_toml.py --tamper "$mode" >/dev/null 2>&1; then
        echo "GEN FAILED"
        return 1
    fi
    if (cd zk/circuit && nargo execute >/dev/null 2>&1); then
        echo "ACCEPTED -- circuit is UNSOUND ($desc)"
        return 1
    fi
    echo "rejected"
    return 0
}

echo "positive control (must be accepted):"
./zk/gen_prover_toml.py --full >/dev/null 2>&1 || { echo "  gen failed"; exit 1; }
printf '  %-28s ' "honest witness"
if (cd zk/circuit && nargo execute >/dev/null 2>&1); then
    echo "accepted"
else
    echo "REJECTED -- the honest witness should solve; fix that first"
    exit 1
fi

echo
echo "negative cases (each must be rejected):"
bad=0
run_case path  "a substituted file path" || bad=$((bad + 1))
run_case hash  "a falsified file hash"   || bad=$((bad + 1))
run_case order "reordered entries"       || bad=$((bad + 1))
run_case drop  "a removed entry"         || bad=$((bad + 1))
run_case commit "a commitment that does not match its path" || bad=$((bad + 1))
run_case nreal  "entries hidden by understating n_real"    || bad=$((bad + 1))

# Leave the honest witness in place so a later run is not surprised by a
# tampered Prover.toml sitting on disk.
./zk/gen_prover_toml.py --full >/dev/null 2>&1

echo
if [ "$bad" -ne 0 ]; then
    echo "$bad case(s) wrong -- do NOT trust the pcrdigest_a assertion yet."
    exit 1
fi
echo "All tampering rejected; honest witness accepted."
