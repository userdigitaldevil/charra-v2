/* SPDX-License-Identifier: BSD-3-Clause */
/*****************************************************************************
 * Copyright 2019-2020, Fraunhofer Institute for Secure Information Technology
 * SIT. All rights reserved.
 ****************************************************************************/

/**
 * @file crypto_util.h
 * @author Michael Eckel (michael.eckel@sit.fraunhofer.de)
 * @brief Provides related crypto functions.
 * @version 0.1
 * @date 2019-12-22
 *
 * @copyright Copyright 2019, Fraunhofer Institute for Secure Information
 * Technology SIT. All rights reserved.
 *
 * @license BSD 3-Clause "New" or "Revised" License (SPDX-License-Identifier:
 * BSD-3-Clause).
 */

#ifndef CRYPTO_UTIL_H
#define CRYPTO_UTIL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>

#include <tss2/tss2_tpm2_types.h>

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/pk.h>
#include <mbedtls/rsa.h>
#include <mbedtls/x509_crt.h>

#include "../common/charra_error.h"

/* hashing functions */

CHARRA_RC hash_sha1(const size_t data_len, const uint8_t* const data,
        uint8_t digest[TPM2_SHA1_DIGEST_SIZE]);

CHARRA_RC hash_sha1_array(const size_t count, const uint8_t* const array,
        uint8_t digest[TPM2_SHA1_DIGEST_SIZE]);

CHARRA_RC hash_sha256(const size_t data_len, const uint8_t* const data,
        uint8_t digest[TPM2_SHA256_DIGEST_SIZE]);

CHARRA_RC hash_sha256_array(uint8_t* data[TPM2_SHA256_DIGEST_SIZE],
        const size_t data_len, uint8_t digest[TPM2_SHA256_DIGEST_SIZE]);

CHARRA_RC hash_sha384(const size_t data_len, const uint8_t* const data,
        uint8_t digest[TPM2_SHA384_DIGEST_SIZE]);

CHARRA_RC hash_sha384_array(const size_t count, const uint8_t* const array,
        uint8_t digest[TPM2_SHA384_DIGEST_SIZE]);

CHARRA_RC hash_sha512(const size_t data_len, const uint8_t* const data,
        uint8_t digest[TPM2_SHA512_DIGEST_SIZE]);

CHARRA_RC hash_sha512_array(const size_t count, const uint8_t* const array,
        uint8_t digest[TPM2_SHA512_DIGEST_SIZE]);

CHARRA_RC hash_sm3_256(const size_t data_len, const uint8_t* const data,
        uint8_t digest[TPM2_SM3_256_DIGEST_SIZE]);

CHARRA_RC hash_sm3_256_array(const size_t count, const uint8_t* const array,
        uint8_t digest[TPM2_SM3_256_DIGEST_SIZE]);

CHARRA_RC charra_crypto_hash(mbedtls_md_type_t hash_algo,
        const uint8_t* const data, const size_t data_len,
        uint8_t digest[MBEDTLS_MD_MAX_SIZE]);

CHARRA_RC charra_crypto_tpm_pub_key_to_mbedtls_pub_key(
        const TPM2B_PUBLIC* tpm_rsa_pub_key,
        mbedtls_rsa_context* mbedtls_rsa_pub_key);

CHARRA_RC charra_crypto_rsa_verify_signature_hashed(
        mbedtls_rsa_context* mbedtls_rsa_pub_key, mbedtls_md_type_t hash_algo,
        const unsigned char* data_digest, const unsigned char* signature);

CHARRA_RC charra_crypto_rsa_verify_signature(
        mbedtls_rsa_context* mbedtls_rsa_pub_key, mbedtls_md_type_t hash_algo,
        const unsigned char* data, size_t data_len,
        const unsigned char* signature);

/**
 * @brief Verify a TPM Quote's signature with mbedTLS (defense in depth,
 * independent of any TPM-based check).
 *
 * @param[out] out_valid the signature's actual validity; only meaningful
 * when this function itself returns true.
 * @returns false only on a hard error converting tpm2_public_key to an
 * mbedTLS key; true otherwise (check *out_valid for the actual result).
 */
bool charra_crypto_verify_quote_signature_mbedtls(
        TPM2B_PUBLIC* tpm2_public_key, const uint8_t* attestation_data,
        uint32_t attestation_data_len, TPMT_SIGNATURE* signature,
        bool* out_valid);

/* --- software RSA keypair (no TPM involved) ------------------------------
 *
 * Used by the Relying Party to sign Quote_r. This is an ordinary software
 * key, not a TPM-resident AK: it proves the same RP produced a given
 * (PCR_r, nonce) pair, but carries no hardware-rooted identity. Replacing it
 * with a certified AK is tracked in CHARRA_V2_NOTES.md.
 */

/** Size of the RP's RSA key. */
#define CHARRA_RSA_KEY_BITS 2048
/** Bytes an RSA-2048 signature occupies. */
#define CHARRA_RSA_SIGNATURE_LEN (CHARRA_RSA_KEY_BITS / 8)
/** Generous upper bound on the DER encoding of an RSA-2048 public key. */
#define CHARRA_RSA_PUB_KEY_DER_MAX 512

/**
 * @brief Generate a fresh RSA keypair configured for RSA-PSS/SHA-256.
 *
 * @param[out] key an uninitialized context; on success it is initialized and
 * holds the new keypair. Caller must mbedtls_pk_free() it.
 */
CHARRA_RC charra_crypto_rsa_generate_keypair(mbedtls_pk_context* key);

/**
 * @brief DER-encode a keypair's public half.
 *
 * @param[out] der_out buffer of at least CHARRA_RSA_PUB_KEY_DER_MAX bytes
 * @param[out] der_len_out bytes written into der_out
 */
CHARRA_RC charra_crypto_rsa_public_key_to_der(mbedtls_pk_context* key,
        uint8_t* der_out, size_t der_out_size, uint32_t* der_len_out);

/**
 * @brief Sign data with RSA-PSS over SHA-256.
 *
 * Matches what charra_crypto_rsa_verify_signature() expects, so a verifier
 * can check it with the existing helper once it has parsed the public key.
 *
 * @param[out] signature_out buffer of at least CHARRA_RSA_SIGNATURE_LEN
 * bytes
 */
CHARRA_RC charra_crypto_rsa_sign(mbedtls_pk_context* key,
        const unsigned char* data, size_t data_len,
        unsigned char* signature_out);

/**
 * @brief Compute PCR composite digest from PCR values and check if it matches
 * with the digest given in attest_struct.
 *
 * @param pcr_values 2D array of pcr values
 * @param pcr_values_len number of PCR values in pcr_values
 * @param attest_struct structure holding the digest to check against
 * @returns CHARRA_RC_SUCCESS on matching digests, CHARRA_RC_NO_MATCH
 * on non-matching digests, CHARRA_RC_ERROR on error
 */
CHARRA_RC compute_and_check_PCR_digest(uint8_t** pcr_values,
        uint32_t pcr_value_len, const TPMS_ATTEST* const attest_struct);

/* --- EK/AK certificate chain verification (Step 3a/3b item 1) ---------- */

/**
 * @brief Initialize and seed an mbedtls CSPRNG, ready to pass as the
 * (f_rng, p_rng) pair several mbedtls APIs need -- key parsing (blinding),
 * certificate signing, MakeCredential's seed generation. Same
 * entropy/ctr_drbg setup charra_random_bytes() (charra_util.c) already
 * uses internally, exposed here since callers of the functions above need
 * the raw seeded context itself, not just random bytes out of it.
 *
 * @param[out] ctr_drbg_out caller-owned; on CHARRA_RC_SUCCESS must be
 * cleaned up with charra_crypto_seeded_rng_free().
 * @param[out] entropy_out same lifetime as ctr_drbg_out; kept alive
 * alongside it since ctr_drbg_out holds a pointer into it.
 * @returns CHARRA_RC_SUCCESS, or CHARRA_RC_CRYPTO_ERROR if seeding fails.
 */
CHARRA_RC charra_crypto_seeded_rng_init(
        mbedtls_ctr_drbg_context* ctr_drbg_out,
        mbedtls_entropy_context* entropy_out);

/** @brief Frees a context pair from charra_crypto_seeded_rng_init(). */
void charra_crypto_seeded_rng_free(
        mbedtls_ctr_drbg_context* ctr_drbg, mbedtls_entropy_context* entropy);

/**
 * @brief Verify that leaf_cert chains to trusted_root and is currently
 * within its validity window (NotBefore/NotAfter, checked against the
 * system clock as a normal part of mbedtls_x509_crt_verify()).
 *
 * Single-root trust store -- verifies against exactly one trusted
 * certificate, no intermediate chain support, matching the two-tier PKI
 * this project uses (root CA signs the leaf directly). Does not check
 * revocation (no CRL/OCSP); the Verifier stays a passive server, so no
 * live OCSP-style outbound query is made -- see CHARRA_V2_NOTES.md for the
 * local-revocation-list alternative if that's ever needed.
 *
 * @param[in] leaf_cert_der leaf certificate bytes, DER or PEM
 * @param[in] leaf_cert_len length of leaf_cert_der
 * @param[in] trusted_root_der trusted root certificate bytes, DER or PEM
 * @param[in] trusted_root_len length of trusted_root_der
 * @param[out] leaf_out parsed leaf certificate; on CHARRA_RC_SUCCESS the
 * caller owns it and must mbedtls_x509_crt_free() it (matching this
 * file's existing init-then-caller-frees convention). Lets the caller
 * inspect the certified public key afterward, e.g. via
 * charra_crypto_verify_cert_public_key_matches_tpm_public_key() below.
 * @returns CHARRA_RC_SUCCESS if the chain verifies and the cert is
 * currently valid, CHARRA_RC_VERIFICATION_FAILED if verification fails
 * (expired, wrong root, bad signature, ...), CHARRA_RC_CRYPTO_ERROR if
 * either certificate fails to parse, CHARRA_RC_BAD_ARGUMENT on bad input.
 */
CHARRA_RC charra_crypto_verify_x509_cert_chain(const uint8_t* leaf_cert_der,
        size_t leaf_cert_len, const uint8_t* trusted_root_der,
        size_t trusted_root_len, mbedtls_x509_crt* leaf_out);

/**
 * @brief Days remaining until a certificate's "not after" date. Readability
 * aid only, not a validity check.
 *
 * @param[in] cert a parsed certificate.
 * @returns days until expiry (negative if already expired).
 */
long charra_crypto_x509_days_until_expiry(const mbedtls_x509_crt* cert);

/**
 * @brief Log a successfully chain-verified certificate's subject, issuer,
 * serial, and days-until-expiry at INFO level.
 */
void charra_crypto_log_cert_summary(
        const char* label, const mbedtls_x509_crt* cert);

/**
 * @brief Parse a "YYYYMMDDHHMMSS" UTC timestamp (the format
 * charra_crypto_sign_ak_certificate()'s not_before_utc/not_after_utc take)
 * into a time_t.
 *
 * @returns true and sets *out on success, false on a malformed string.
 */
bool charra_crypto_parse_utc_yyyymmddhhmmss(const char* s, time_t* out);

/**
 * @brief Formats a time_t as the "YYYYMMDDHHMMSS" UTC string
 * charra_crypto_sign_ak_certificate() expects -- the inverse of
 * charra_crypto_parse_utc_yyyymmddhhmmss() above.
 *
 * Lets certificate validity be expressed as a duration from issuance
 * (now -> now + validity) rather than a fixed absolute window: with a fixed
 * not_after, a certificate issued later simply lives for less time, which
 * is wrong once the issuer is a long-running process.
 *
 * @param[out] out receives 14 characters plus a NUL terminator.
 * @returns true on success.
 */
bool charra_crypto_format_utc_yyyymmddhhmmss(time_t t, char out[15]);

/**
 * @brief Confirm a certificate's embedded RSA public key is the same key
 * as a TPM2B_PUBLIC -- ties "this certificate is valid" to "this
 * certificate actually vouches for the key that signed this specific
 * quote", not just some unrelated key.
 *
 * @returns CHARRA_RC_SUCCESS if the keys match, CHARRA_RC_VERIFICATION_FAILED
 * if they don't (or the cert's key isn't RSA), CHARRA_RC_CRYPTO_ERROR /
 * CHARRA_RC_BAD_ARGUMENT on error.
 */
CHARRA_RC charra_crypto_verify_cert_public_key_matches_tpm_public_key(
        const mbedtls_x509_crt* cert, const TPM2B_PUBLIC* tpm_pub_key);

/**
 * @brief Same purpose as
 * charra_crypto_verify_cert_public_key_matches_tpm_public_key() above, for
 * a signer key presented as a DER-encoded RSA public key instead of a
 * TPM2B_PUBLIC -- the shape msg_rp_evidence_dto's rp_public_key travels in
 * (RP's Quote_r-signing AK is TPM-resident, but its public half is
 * exported and marshaled as plain DER, the same convention
 * charra_crypto_rsa_public_key_to_der() already uses elsewhere, rather
 * than as a raw TPM2B_PUBLIC).
 *
 * @param[in] der_pub_key DER-encoded RSA public key (e.g. rp_public_key)
 * @param[in] der_pub_key_len length of der_pub_key
 * @returns CHARRA_RC_SUCCESS if the keys match, CHARRA_RC_VERIFICATION_FAILED
 * if they don't (or either key isn't RSA), CHARRA_RC_CRYPTO_ERROR /
 * CHARRA_RC_BAD_ARGUMENT on error.
 */
CHARRA_RC charra_crypto_verify_cert_public_key_matches_der_key(
        const mbedtls_x509_crt* cert, const uint8_t* der_pub_key,
        size_t der_pub_key_len);

/**
 * @brief Validate an AK certificate for a "validate EK/AK certificate"
 * check (DRA-TLS spec Step 2a/3a/3b item 1): the certificate chains to
 * trusted_ca_der, and its embedded public key matches the key that
 * actually signed the corresponding quote -- not some other, unrelated
 * key. Combines charra_crypto_verify_x509_cert_chain() and
 * charra_crypto_verify_cert_public_key_matches_tpm_public_key(), the
 * pairing every caller of this check needs.
 *
 * Only the AK certificate is checked here, not a separate EK certificate.
 * In this project's design the EK is validated once, at AK-provisioning
 * time (see /certify_ak, charra_crypto_build_ek_tpm2b_public_from_cert()),
 * against the manufacturer root -- never re-sent or re-checked on every
 * quote. The AK certificate chaining to the issuing CA is what stands in
 * for that already-completed EK check from here on, which is why this
 * function alone satisfies the spec's "EK/AK" item, not just the "AK"
 * half of it.
 *
 * Deliberately generic over the caller: the Verifier uses this for both
 * Evidence_r and Evidence_a' (Step 3a/3b item 1, against its own CA
 * certificate as trusted_ca_der); the RP is expected to use the exact same
 * function for its own Step 2a item 1, validating the Attester's AK
 * certificate against that same CA certificate (which the RP would need
 * distributed to it, same as any trust anchor). No caller-specific state.
 *
 * @param[in] ak_cert_der the AK certificate (DER) to validate
 * @param[in] ak_cert_der_len length of ak_cert_der
 * @param[in] trusted_ca_der the trusted CA certificate (DER) ak_cert_der is
 * expected to chain to
 * @param[in] trusted_ca_der_len length of trusted_ca_der
 * @param[in] tpm2_public_key the key that actually signed the
 * corresponding quote
 * @param[out] serial_out if non-NULL, receives the certificate's 16-byte
 * serial number (same format as charra_crypto_sign_ak_certificate()'s
 * serial_out) whenever the chain check succeeds -- lets the caller cross-
 * check the serial against charra_ak_state.h's issuance/revocation record
 * for it. Left untouched if the chain check itself fails, since there is
 * then no trustworthy serial to report.
 * @returns CHARRA_RC_SUCCESS if the certificate chains to trusted_ca_der
 * and its key matches tpm2_public_key, CHARRA_RC_VERIFICATION_FAILED if
 * either check fails, CHARRA_RC_BAD_ARGUMENT / CHARRA_RC_CRYPTO_ERROR on
 * error.
 */
CHARRA_RC charra_crypto_verify_ekak_certificate(const uint8_t* ak_cert_der,
        uint32_t ak_cert_der_len, const uint8_t* trusted_ca_der,
        size_t trusted_ca_der_len, TPM2B_PUBLIC* tpm2_public_key,
        uint8_t serial_out[16]);

/**
 * @brief Reconstruct the standard TCG RSA-2048 EK TPM2B_PUBLIC (the fixed
 * "low range" template real EK certificates are issued against) from an
 * already chain-verified EK certificate's embedded RSA public key.
 *
 * Needed because Esys_MakeCredential (via
 * charra_tpm_make_credential_for_ak()) takes the EK's full TPM2B_PUBLIC,
 * not just its bare RSA key: the object's Name -- what ties the wrapped
 * credential to one specific TPM object -- is computed from the whole
 * public area (nameAlg, objectAttributes, authPolicy, parameters), not the
 * modulus alone. A real Privacy CA is expected to know this fixed,
 * TCG-standard template rather than receive it over the wire; only the
 * modulus itself (and the confirmation that the exponent is the
 * TPM-conventional 65537) comes from the certificate.
 *
 * The exact template values here (objectAttributes 0x300b2, the authPolicy
 * digest) were confirmed empirically against a real EK created with
 * `tpm2_createek -G rsa` against this project's TPM simulator, not just
 * recalled from the TCG spec.
 *
 * @param[in] ek_cert an already chain-verified EK certificate (see
 * charra_crypto_verify_x509_cert_chain())
 * @param[out] ek_public_key_out
 * @returns CHARRA_RC_SUCCESS, CHARRA_RC_BAD_ARGUMENT, or
 * CHARRA_RC_VERIFICATION_FAILED if the cert's key isn't a 2048-bit RSA key
 * with the standard 65537 exponent.
 */
CHARRA_RC charra_crypto_build_ek_tpm2b_public_from_cert(
        const mbedtls_x509_crt* ek_cert, TPM2B_PUBLIC* ek_public_key_out);

/* --- AK certificate issuance (Verifier acting as Privacy CA) ----------- */

/**
 * @brief Sign a new AK certificate for ak_public_key, issued by the
 * Verifier's own Privacy CA -- the certificate
 * charra_crypto_verify_x509_cert_chain() later validates on every
 * /appraise call (Step 3a/3b item 1).
 *
 * @param[in] ak_public_key the AK's public key to certify
 * @param[in] subject_name certificate subject, comma-separated OID=value
 * pairs, e.g. "CN=CHARRA RP AK"
 * @param[in] issuer_name must match the CA certificate's own subject name
 * exactly, e.g. "CN=CHARRA Verifier CA (test only)" (see
 * keys/gen-ak-pki.sh) -- mbedtls does not read this from ca_private_key_path
 * itself, since that path names only the private key, not the certificate
 * @param[in] not_before_utc validity start, "YYYYMMDDHHMMSS" UTC
 * @param[in] not_after_utc validity end, "YYYYMMDDHHMMSS" UTC
 * @param[in] ca_private_key_path path to the CA's private key file (PEM or
 * DER); this is the key that signs the new certificate
 * @param[out] ak_cert_der_out malloc'd DER-encoded certificate; caller
 * frees.
 * @param[out] ak_cert_der_len_out length of ak_cert_der_out
 * @param[out] serial_out the certificate's own 16-byte serial number, as
 * written into it (not merely echoed back -- the actual bytes placed in the
 * DER, sign bit already cleared). Lets the caller record which serial was
 * just issued (see charra_ak_state.h) without having to re-parse the DER it
 * just received back.
 * @returns CHARRA_RC_SUCCESS, CHARRA_RC_BAD_ARGUMENT if any argument is
 * NULL, CHARRA_RC_CRYPTO_ERROR on any mbedtls failure, CHARRA_RC_ERROR on
 * allocation failure.
 */
CHARRA_RC charra_crypto_sign_ak_certificate(const TPM2B_PUBLIC* ak_public_key,
        const char* subject_name, const char* issuer_name,
        const char* not_before_utc, const char* not_after_utc,
        const char* ca_private_key_path, uint8_t** ak_cert_der_out,
        uint32_t* ak_cert_der_len_out, uint8_t serial_out[16]);

/* --- AES-256-GCM (wraps the AK certificate under the MakeCredential
 * secret, see msg_certify_ak_response_dto) ------------------------------- */

#define CHARRA_AES256GCM_KEY_LEN 32
#define CHARRA_AES256GCM_NONCE_LEN 12
#define CHARRA_AES256GCM_TAG_LEN 16

/**
 * @brief AES-256-GCM encrypt plaintext under key, with a freshly generated
 * random nonce (not caller-supplied -- a new nonce per call is what keeps
 * reusing the same key safe).
 *
 * @param[in] key CHARRA_AES256GCM_KEY_LEN (32) bytes
 * @param[out] nonce_out CHARRA_AES256GCM_NONCE_LEN (12) bytes
 * @param[out] tag_out CHARRA_AES256GCM_TAG_LEN (16) bytes
 * @param[out] ciphertext_out malloc'd, plaintext_len bytes; caller frees.
 * Same length as plaintext -- GCM is a stream cipher, no padding.
 * @returns CHARRA_RC_SUCCESS, CHARRA_RC_BAD_ARGUMENT, CHARRA_RC_CRYPTO_ERROR,
 * CHARRA_RC_ERROR on allocation failure.
 */
CHARRA_RC charra_crypto_aes256gcm_encrypt(
        const uint8_t key[CHARRA_AES256GCM_KEY_LEN],
        const uint8_t* plaintext, size_t plaintext_len,
        uint8_t nonce_out[CHARRA_AES256GCM_NONCE_LEN],
        uint8_t tag_out[CHARRA_AES256GCM_TAG_LEN], uint8_t** ciphertext_out);

/**
 * @brief AES-256-GCM authenticated decrypt -- verifies tag before
 * returning plaintext (uses mbedtls_gcm_auth_decrypt(), not the
 * non-authenticating mbedtls_gcm_crypt_and_tag() in decrypt mode).
 *
 * @param[out] plaintext_out malloc'd, ciphertext_len bytes; caller frees.
 * Left NULL if authentication fails.
 * @returns CHARRA_RC_SUCCESS, CHARRA_RC_BAD_ARGUMENT,
 * CHARRA_RC_VERIFICATION_FAILED if the tag doesn't match (wrong key or
 * tampered ciphertext), CHARRA_RC_CRYPTO_ERROR on other mbedtls failure,
 * CHARRA_RC_ERROR on allocation failure.
 */
CHARRA_RC charra_crypto_aes256gcm_decrypt(
        const uint8_t key[CHARRA_AES256GCM_KEY_LEN],
        const uint8_t* ciphertext, size_t ciphertext_len,
        const uint8_t nonce[CHARRA_AES256GCM_NONCE_LEN],
        const uint8_t tag[CHARRA_AES256GCM_TAG_LEN], uint8_t** plaintext_out);

#endif /* SITIMA_CRYPTO_H */
