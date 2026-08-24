# Warning
The keys in this folder are only supposed to be used for testing, in actual production environments they MUST be changed!

# Generating keys:
* Generate keypair: `openssl ecparam -genkey -name prime256v1 -out <name>.der -outform DER`
* Generate public key file: `openssl ec -in <name>.der -inform DER -pubout -out <name>.pub.der -outform DER`

The `*.der` / `*.pub.der` pairs above are the DTLS raw-public-key identities
for the CoAP transport (`attester`, `relying_party`, `verifier`). They have
nothing to do with attestation identity -- see below for that.

# The attestation trust anchor

`trusted_keys.txt` is the entire identity mechanism of this PoC. It holds
the public halves of the two TPM-resident signing keys, in PEM:

* `attester` -- the restricted quoting key that signs every `Quote_a`
* `relying-party` -- the unrestricted key that signs every `Quote_r`

A signing key is trusted **if and only if it appears in this file**. There
are no certificates, no CA, no chain to validate, no expiry and no
revocation; nothing is provisioned or renewed at runtime. See
`src/core/charra_trusted_keys.h` for what that does and does not establish.

The file is generated, not committed:

```sh
make provision_trusted_keys
./keys/gen-trusted-keys.sh
```

Both keys are derived from the TPM's owner-hierarchy seed, so **wiping the
simulator's NVChip changes them and invalidates this file**. Regenerate it
after any TPM reset -- `run_live_test.sh` already does this automatically.
Skipping that step produces signature checks that fail as "key not in the
trust anchor", which reads as a rejected identity rather than a stale file.
