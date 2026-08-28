#!/bin/sh
# SUPERSEDED -- kept as a record of how the per-entry stage was validated.
#
# This drove the single-entry circuit, which took one finished entry and
# checked its template_digest. main.nr now takes the whole 33-entry log at
# once, so its signature no longer matches what gen_prover_toml.py <index>
# emits and this script cannot run as-is. Its job is done by the full-log
# execute plus zk/negative_test.sh.
#
# Result when it last applied: 33/33 entries reproduced in-circuit, both
# block-count paths covered (2 blocks x31, 3 blocks x2).
#
# One entry solving proves the circuit works for one length. This runs every
# entry in the log through it, which is what actually exercises both
# block-count paths -- a padding-offset bug would typically pass the 2-block
# entries and fail only the 3-block ones (or the reverse), so checking a
# single entry can look like success while the circuit is wrong for a third
# of the log.
#
# Run:  ./zk/check_all_entries.sh

cd "$(dirname "$0")/.." || exit 1

echo "This harness targeted the single-entry circuit and is superseded." >&2
echo "Use instead:" >&2
echo "    ./zk/gen_prover_toml.py --full && (cd zk/circuit && nargo execute)" >&2
echo "    ./zk/negative_test.sh" >&2
exit 1

if [ ! -f zk/witness.json ]; then
    echo "zk/witness.json not found -- run:" >&2
    echo "    make dump_witness && ./bin/dump_witness > zk/witness.json" >&2
    exit 1
fi

N=$(python3 -c "import json;print(len(json.load(open('zk/witness.json'))['entries']))")

# Block-count spread, so a run that silently only covered one path is
# visible rather than reassuring.
python3 - <<'EOF'
import json, collections
w = json.load(open('zk/witness.json'))
c = collections.Counter(-(-(e['template_data_len'] + 9) // 64) for e in w['entries'])
print("block-count spread: " + ", ".join(f"{n} blocks x{c[n]}" for n in sorted(c)))
EOF

echo "checking $N entries..."
pass=0
fail=0
failed=""
i=0
while [ "$i" -lt "$N" ]; do
    if ! ./zk/gen_prover_toml.py "$i" >/dev/null 2>&1; then
        fail=$((fail + 1))
        failed="$failed $i(gen)"
    elif (cd zk/circuit && nargo execute >/dev/null 2>&1); then
        pass=$((pass + 1))
    else
        fail=$((fail + 1))
        failed="$failed $i"
    fi
    i=$((i + 1))
done

echo "  passed: $pass"
if [ "$fail" -ne 0 ]; then
    echo "  FAILED:$failed"
    echo
    echo "Re-run one of them to see the error:"
    set -- $failed
    echo "    ./zk/gen_prover_toml.py $1 && (cd zk/circuit && nargo execute)"
    exit 1
fi

echo
echo "Every entry's template_digest reproduced in-circuit. Phase 3 complete."
