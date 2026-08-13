# Warning
The keys in this folder are only supposed to be used for testing, in actual production environments they MUST be changed!

# Generating keys:
* Generate keypair: `openssl ecparam -genkey -name prime256v1 -out <name>.der -outform DER`
* Generate public key file: `openssl ec -in <name>.der -inform DER -pubout -out <name>.pub.der -outform DER`

# EK/AK certificate check test PKI

`gen-ak-pki.sh` generates the test-only PKI backing the Verifier's Step
3a/3b item 1 EK/AK certificate check:
* `verifier-ca.{key,crt}` — the Verifier's own Privacy CA, signs AK
  certificates issued via `/certify_ak`.
* `manufacturer-root.{key,crt}` — synthetic stand-in for a real TPM
  manufacturer root (the dev-env's software TPM has no genuine one).
* `rp-ek.{key,crt}` / `attester-ek.{key,crt}` — synthetic EK certificates
  for RP and Attester, signed by `manufacturer-root`. Plain openssl RSA
  keys for now, not yet the TPM simulator's own endorsement-hierarchy key.
* `test-ak.key` — a plain RSA key pair standing in for "an AK," with no
  certificate of its own; `charra_crypto_sign_ak_certificate()` mints one
  for it in tests.

Re-run `./gen-ak-pki.sh` to regenerate all of the above.
