# Warning
The keys in this folder are only supposed to be used for testing, in actual production environments they MUST be changed!

# Generating keys:
* Generate keypair: `openssl ecparam -genkey -name prime256v1 -out <name>.der -outform DER`
* Generate public key file: `openssl ec -in <name>.der -inform DER -pubout -out <name>.pub.der -outform DER`

The `*.der` / `*.pub.der` pairs above are the DTLS raw-public-key identities
for the CoAP transport (`attester`, `relying_party`, `verifier`). For
`attester` and `relying_party` that is still all they are -- and DTLS is
currently off, so even that role goes unused (see `src/relying_party.c`).

`verifier.der` is the exception: it doubles as the key every Verifier signs
its `/appraise` verdict with (`src/core/charra_verdict.h`), since all
Verifier instances currently share one keypair. That signature is checked
against `verifier.pub.der` by the RP (`verifier_public_key_path` in
`src/relying_party.c`), independently of DTLS being on or off. Neither
pairing is attestation identity in the AK sense -- see below for that.

# The attestation trust anchor

`trusted_keys.txt` is the entire identity mechanism of this PoC. It holds
the public halves of the two TPM-resident signing keys, in PEM:

* `attester` -- the restricted quoting key that signs every `Quote_a`,
  read from the **Attester's** TPM (`:2321` under `run_daemon.sh`)
* `relying-party` -- the unrestricted key that signs every `Quote_r`,
  read from the **RP's** TPM (`:2325`)

Two separate simulators, not one. `TPM2_CreatePrimary` *derives* a key from
the hierarchy seed rather than generating one, so a single shared TPM would
make both AKs two templates over the same secret -- and either role could
then derive the other's key. Separate NVChips make them unrelated by
construction.

That is also why `provision_trusted_keys` takes `--role`: a run without it
emits BOTH identities from whichever TPM it is pointed at, which would put
a key the RP's own TPM can derive into the entry labelled `attester`. Since
`TPM2_Quote` accepts restricted and unrestricted keys alike, the RP could
then issue genuine quotes that pass the Verifier's check. One TPM, one
role, one key -- see the comments in `gen-trusted-keys.sh`.

A signing key is trusted **if and only if it appears in this file**. There
are no certificates, no CA, no chain to validate, no expiry and no
revocation; nothing is provisioned or renewed at runtime. See
`src/core/charra_trusted_keys.h` for what that does and does not establish.

The file is generated, not committed:

```sh
make provision_trusted_keys
./keys/gen-trusted-keys.sh
```

Each key is derived from its own TPM's owner-hierarchy seed, so **wiping
either simulator's NVChip changes that key and invalidates this file**.
Regenerate it after any TPM reset -- `run_daemon.sh` already does this
automatically.
Skipping that step produces signature checks that fail as "key not in the
trust anchor", which reads as a rejected identity rather than a stale file.
