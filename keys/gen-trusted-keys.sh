#!/bin/sh
# Writes the trust anchor the roles read at runtime.
#
# One step, and it needs the TPM: bin/provision_trusted_keys reads the
# Attester's and the RP's public signing keys out of the TPM and writes them
# to keys/trusted_keys.txt. There is no CA and there are no certificates --
# the file IS the trust decision, see src/core/charra_trusted_keys.h.
#
# It must run against the same TPM the daemons will use, and must be re-run
# whenever that TPM is reset: both keys are derived from the hierarchy seed,
# so wiping the NVChip silently changes them and every signature check would
# then fail against a stale anchor.
#
# run_daemon.sh already calls this after resetting the TPM. Run it by hand
# only when provisioning a TPM some other way.

set -e

OUT="trusted_keys.txt"

# Run from the repo root: the tool's default paths are repo-relative, the
# same way every role resolves keys/.
cd "$(dirname "$0")/.."

# Clean up a partial trust anchor if anything below fails.
trap 'rm -f "keys/$OUT.tmp"' EXIT

if [ ! -x bin/provision_trusted_keys ]; then
    echo "bin/provision_trusted_keys is missing -- run 'make provision_trusted_keys' first." >&2
    exit 1
fi

echo "Reading the public signing keys from the TPM ..."
# Write to a temporary file and move it into place only on success. A failed
# TPM call would otherwise leave a truncated anchor behind, which every role
# would read as "no identity is trusted" -- a far more confusing failure than
# the one that actually happened.
./bin/provision_trusted_keys --out "keys/$OUT.tmp"
mv "keys/$OUT.tmp" "keys/$OUT"

echo "Wrote keys/$OUT:"
grep -c 'BEGIN PUBLIC KEY' "keys/$OUT" | sed 's/^/  public keys: /'
