#!/bin/sh
# End-to-end test of the proof watcher, standing in for the C side.
#
# Exercises exactly what the RP and Verifier will do: stage a prove job from a
# witness dump, collect the proof, hand it back as a verify job, and read the
# verdict. Then hand over a proof whose public inputs have been altered and
# require the verdict to flip -- because a Verifier that says "verified" to
# everything is worse than no Verifier at all.
#
# Run on the host, with nargo and bb on PATH:
#     export PATH="$HOME/.nargo/bin:$HOME/.bb-native:$PATH"
#     ./zk/test_watcher.sh

set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
JOBS="$ROOT/zk/jobs"
STAGING="$JOBS/.staging"
W="$ROOT/zk/proof_watcher.sh"

fail() { printf '\nFAILED: %s\n' "$1" >&2; exit 1; }

[ -f "$ROOT/zk/witness.json" ] || fail "zk/witness.json missing"

rm -rf "$JOBS"
mkdir -p "$STAGING"

# submit <id> <kind>; caller has already populated $STAGING/<id>
submit() {
    echo "$2" > "$STAGING/$1/kind"
    mv "$STAGING/$1" "$JOBS/$1"     # atomic: the watcher never sees a partial job
}

check_done() {
    [ -f "$JOBS/$1/done" ] || fail "job $1 never completed"
    st=$(cat "$JOBS/$1/status")
    [ "$st" = "ok" ] || fail "job $1 status: $st$(printf '\n--- log ---\n'; tail -20 "$JOBS/$1/log" 2>/dev/null)"
}

echo "=== 1. prove ==="
mkdir -p "$STAGING/j1"
cp "$ROOT/zk/witness.json" "$STAGING/j1/witness.json"
submit j1 prove
"$W" --once || fail "watcher errored"
check_done j1
[ -s "$JOBS/j1/proof" ] || fail "no proof produced"
[ -s "$JOBS/j1/public_inputs" ] || fail "no public inputs produced"
echo "    proof $(wc -c < "$JOBS/j1/proof" | tr -d ' ') B, public inputs $(wc -c < "$JOBS/j1/public_inputs" | tr -d ' ') B"

echo
echo "=== 2. verify the honest proof ==="
mkdir -p "$STAGING/j2"
cp "$JOBS/j1/proof" "$JOBS/j1/public_inputs" "$STAGING/j2/"
submit j2 verify
"$W" --once || fail "watcher errored"
check_done j2
r=$(cat "$JOBS/j2/result")
[ "$r" = "verified" ] || fail "honest proof came back '$r'"
echo "    verdict: $r"

echo
echo "=== 3. verify a proof whose public inputs were altered ==="
mkdir -p "$STAGING/j3"
cp "$JOBS/j1/proof" "$STAGING/j3/proof"
python3 -c "
d = bytearray(open('$JOBS/j1/public_inputs','rb').read())
d[-1] ^= 1                      # last byte of the final commitment
open('$STAGING/j3/public_inputs','wb').write(bytes(d))
" || fail "could not tamper"
submit j3 verify
"$W" --once || fail "watcher errored"
check_done j3
r=$(cat "$JOBS/j3/result")
[ "$r" = "rejected" ] || fail "tampered proof came back '$r' -- verification is not binding"
echo "    verdict: $r"

echo
echo "=== 4. witnesses that do not replay ==="
# XOR rather than assignment. Setting a byte to a fixed value is not a
# tamper if it already held that value -- entry 0 is boot_aggregate and its
# file_hash is all zeros, so "set the first byte to 00" changed nothing and
# this case silently proved an untouched witness.
tamper_case() {
    id=$1; desc=$2; script=$3
    printf '  %-38s ' "$desc"
    rm -rf "${STAGING:?}/$id"; mkdir -p "$STAGING/$id"
    python3 -c "
import json
w = json.load(open('$ROOT/zk/witness.json'))
$script
json.dump(w, open('$STAGING/$id/witness.json','w'))
" || fail "could not build bad witness for $id"

    # Guard against another silent no-op: the file must actually differ.
    if cmp -s "$ROOT/zk/witness.json" "$STAGING/$id/witness.json" 2>/dev/null; then
        fail "$id: tamper was a no-op"
    fi

    submit "$id" prove
    "$W" --once >/dev/null 2>&1 || fail "watcher errored"
    [ -f "$JOBS/$id/done" ] || fail "job $id never completed"
    st=$(cat "$JOBS/$id/status")
    case "$st" in
        *"does not replay"*) echo "refused" ;;
        ok) fail "$desc still produced a proof" ;;
        *) fail "unexpected status: $st" ;;
    esac
}

tamper_case j4 "a flipped file_hash bit" "
b = bytearray.fromhex(w['entries'][1]['file_hash']); b[0] ^= 0xff
w['entries'][1]['file_hash'] = b.hex()"

tamper_case j5 "a flipped pcrdigest_a bit" "
b = bytearray.fromhex(w['pcrdigest_a']); b[0] ^= 0xff
w['pcrdigest_a'] = b.hex()"

tamper_case j6 "a substituted path" "
e = w['entries'][1]
e['path'] = '/tmp/evil' + e['path'][9:]"

echo
echo "Prove, verify, tampered-verify and three non-replaying witnesses all behaved correctly."
