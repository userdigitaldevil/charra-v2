#!/bin/sh
# Does `bb verify` actually bind the public inputs?
#
# It verified without being handed a public-inputs path, which has two very
# different explanations: it defaulted to ./target/public_inputs, or it is
# not checking them at all. If the latter, Verifier-side verification is
# vacuous -- a proof would verify against any claimed pcrdigest_a and any
# claimed set of commitments, which is the entire property we need.
#
# So: corrupt the public inputs and require that verification FAILS.
#
# Run from the repo root, on a host where bb runs:
#     ./zk/verify_binding_test.sh

cd "$(dirname "$0")/circuit" || exit 1
T=./target

for f in "$T/vk" "$T/proof" "$T/public_inputs"; do
    [ -f "$f" ] || { echo "missing $f -- run bb write_vk and bb prove first" >&2; exit 1; }
done

# ABI layout, confirmed by size: 44064 bytes / 32 = 1377 fields, one field
# per *byte* of each byte-array input.
#   fields    0..1055  file_hashes   (33 x 32)
#   fields 1056..1311  other_pcrs    (8 x 32)
#   fields 1312..1343  pcrdigest_a   (32)
#   fields 1344..1376  commitments   (33, the circuit's return value)
PCRDIGEST_BYTE=42015   # last byte of pcrdigest_a's first field
COMMIT_BYTE=44063      # last byte of the final commitment

cp "$T/public_inputs" "$T/public_inputs.bak" || exit 1
restore() { mv -f "$T/public_inputs.bak" "$T/public_inputs"; }
trap restore EXIT INT TERM

echo "control: untouched public inputs"
printf '  %-34s ' "as generated"
if bb verify -k "$T/vk" -p "$T/proof" >/dev/null 2>&1; then
    echo "verified"
else
    echo "REJECTED -- the honest proof should verify; fix that first"
    exit 1
fi

echo
echo "tampered public inputs (each must be rejected):"
bad=0
for pair in "$PCRDIGEST_BYTE:pcrdigest_a" "$COMMIT_BYTE:a commitment"; do
    off=${pair%%:*}
    what=${pair##*:}
    printf '  %-34s ' "flipped a bit in $what"
    python3 -c "
import sys
p = '$T/public_inputs'
d = bytearray(open(p,'rb').read())
d[$off] ^= 1
open(p,'wb').write(d)
" || { echo "could not tamper"; bad=$((bad+1)); continue; }

    if bb verify -k "$T/vk" -p "$T/proof" >/dev/null 2>&1; then
        echo "VERIFIED -- public inputs are NOT bound"
        bad=$((bad + 1))
    else
        echo "rejected"
    fi
    cp "$T/public_inputs.bak" "$T/public_inputs"
done

echo
if [ "$bad" -ne 0 ]; then
    cat <<'MSG'
bb verify is not binding the public inputs from that path. Find the flag
that passes them explicitly (bb verify --help) and use it everywhere --
until then, Verifier-side verification proves nothing about WHICH log was
attested, only that some valid proof exists.
MSG
    exit 1
fi
echo "Public inputs are bound: tampering with them breaks verification."
