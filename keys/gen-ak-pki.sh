#!/usr/bin/env bash
# Generates the test-only PKI for the EK/AK certificate check (Step 3a/3b
# item 1, DRA-TLS spec): the Verifier's own Privacy-CA pair (signs AK
# certificates issued via /certify_ak) and a synthetic "manufacturer" root
# that signs EK certificates for RP and Attester.
#
# The synthetic manufacturer root stands in for a real TPM manufacturer CA,
# since the dev-env's software TPM simulator has no genuine one. Likewise,
# the RP/Attester "EK" keys generated here are plain openssl RSA keys, NOT
# yet the real TPM-resident EK objects the simulator's endorsement hierarchy
# would create -- wiring this to the simulator's actual EK is follow-up work
# once end-to-end MakeCredential/ActivateCredential testing starts.
#
# Test only -- as with every other key in this directory, do not reuse any
# of this in a real deployment.
#
# Certs are generated in DER, not PEM: that's the format they'd actually
# travel over CoAP in (compact binary, no reason to send text), and it
# means charra_crypto_verify_x509_cert_chain() callers never need to deal
# with PEM's NUL-termination requirement. Private keys stay PEM -- mbedtls
# auto-detects either, and PEM keys are easier to inspect by hand.
set -euo pipefail
cd "$(dirname "$0")"

echo "Generating Verifier's Privacy CA pair..."
openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout verifier-ca.key -out verifier-ca.crt -outform DER \
    -days 3650 -subj "/CN=CHARRA Verifier CA (test only)"

echo "Generating synthetic TPM manufacturer root..."
openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout manufacturer-root.key -out manufacturer-root.crt -outform DER \
    -days 3650 -subj "/CN=CHARRA Synthetic TPM Manufacturer Root (test only)"
# CAfile below needs PEM regardless of the leaf/root DER output above.
openssl x509 -in manufacturer-root.crt -inform DER \
    -out manufacturer-root.pem.crt -outform PEM

echo "Generating RP's synthetic EK certificate..."
openssl req -newkey rsa:2048 -nodes \
    -keyout rp-ek.key -out rp-ek.csr \
    -subj "/CN=CHARRA RP synthetic EK (test only)"
openssl x509 -req -in rp-ek.csr \
    -CA manufacturer-root.pem.crt -CAkey manufacturer-root.key -CAcreateserial \
    -out rp-ek.crt -outform DER -days 3650
rm -f rp-ek.csr

echo "Generating Attester's synthetic EK certificate..."
openssl req -newkey rsa:2048 -nodes \
    -keyout attester-ek.key -out attester-ek.csr \
    -subj "/CN=CHARRA Attester synthetic EK (test only)"
openssl x509 -req -in attester-ek.csr \
    -CA manufacturer-root.pem.crt -CAkey manufacturer-root.key -CAcreateserial \
    -out attester-ek.crt -outform DER -days 3650
rm -f attester-ek.csr manufacturer-root.pem.crt manufacturer-root.pem.srl

echo "Generating a plain test AK key pair (no cert of its own -- gets one"
echo "minted fresh by charra_crypto_sign_ak_certificate() in tests)..."
openssl genrsa -out test-ak.key 2048 2>/dev/null

echo "Done. Generated (DER certs, PEM keys): verifier-ca.{key,crt}, manufacturer-root.{key,crt}, rp-ek.{key,crt}, attester-ek.{key,crt}, test-ak.key"
