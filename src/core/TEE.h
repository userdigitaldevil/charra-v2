/**
 * @file TEE.h
 * @brief Simulated TEE the RP's appraisal-and-redaction step runs "inside".
 *
 * A real TEE (SGX enclave, AWS Nitro Enclave, ...) can attest, to a remote
 * party, both the exact code it is running (a measurement of the enclave
 * image, computed by the loader from whatever it was handed to load -- the
 * TEE itself has no opinion on what the "correct" code is) and a
 * caller-supplied REPORT_DATA value, bound together in one signed
 * Attestation Document, under a key that never leaves the enclave. This
 * module simulates that primitive in software, for this PoC only: "the
 * enclave image" is approximated by hashing whatever source files the
 * caller passes to tee_hash_files() -- this module does not itself know or
 * care which files those are, exactly as a real TEE's measurement mechanism
 * does not decide what belongs in the enclave -- and "the key that never
 * leaves the enclave" is an RSA keypair generated once, lazily, on first
 * use, and kept only in TEE.c's own static storage -- nothing outside this
 * file ever sees the private half, mirroring how a real enclave's sealing
 * key is never exported.
 *
 * WHERE THE TRUST COMES FROM. A real enclave's Attestation Document is
 * signed by a hardware key chaining to a vendor root, which is what makes
 * it unforgeable. This module has no such root: the keypair below is
 * generated per process and travels inline. On its own that proves
 * nothing -- a dishonest RP could generate its own keypair, sign any
 * document it liked, and attach the matching public key. What closes that
 * gap here is OUTSIDE this file: the RP certifies this public key with
 * AK_r (see rp_evidence.c), and AK_r is in keys/trusted_keys.txt. The
 * Verifier therefore reaches this key by a chain it already trusts --
 * anchor -> AK_r -> TEE key -> document -- rather than by believing what
 * arrived beside the signature.
 *
 * What remains outside that chain, and cannot be closed without real
 * hardware isolation: an attacker able to modify TEE.c itself, or able to
 * run the genuine code and then lie about the result before it is signed.
 *
 * The point is narrower than "the RP is honest". It closes the specific
 * gap the /qualify handshake leaves open, where nothing stops the RP from
 * redacting a fabricated log instead of the Attester's genuine, TPM-signed
 * one, or from running different cleaning logic than the Verifier expects,
 * and having that go undetected.
 *
 * CHARRA_TRUST_MODE_ZK closes the same gap differently, and more strongly:
 * this file NAMES the code that ran, while the proof shows the redaction was
 * actually done correctly -- see src/core/charra_zk.h. The two are exclusive
 * alternatives, chosen by --trust-mode, and neither runs in the other's
 * mode.
 *
 * The Verifier never calls into this file at all -- see rp_evidence.c and
 * verifier_appraise.c for why.
 */

#ifndef CHARRA_TEE_H
#define CHARRA_TEE_H

#include <stddef.h>
#include <stdint.h>

#include "../common/charra_error.h"
#include "../util/crypto_util.h"

/**
 * @brief Hashes the given files together, in the order given, into one
 * SHA-256 digest.
 *
 * The TEE only hashes what it is told; it has no built-in notion of "the
 * appraisal code" -- that is the caller's own knowledge of what it is
 * vouching for (see rp_evidence.c's rp_appraisal_code_files), the same way
 * a real TEE's measurement covers whatever image its loader was given, not
 * a list the TEE hardware itself maintains.
 *
 * Order is part of the measurement: the same files listed differently hash
 * differently, so both sides must agree on the order as well as the set.
 *
 * @param[in] file_paths paths relative to the repository root, which is
 * also the working directory every binary is always started from
 */
CHARRA_RC tee_hash_files(const char* const* file_paths, size_t file_count,
        uint8_t hash_out[TPM2_SHA256_DIGEST_SIZE]);

/**
 * @brief One simulated TEE attestation.
 *
 * file_hash identifies the code measured by tee_attestation()'s file_paths
 * argument; report_data is caller-supplied and binds this attestation to
 * one particular appraisal -- the RP sets it to
 * hash(verifier_nonce || pcrdigest_a || log_r), so it cannot be replayed
 * against a different nonce, a different Attester evidence, or a different
 * redacted log.
 */
typedef struct {
    uint8_t file_hash[TPM2_SHA256_DIGEST_SIZE];
    uint8_t report_data[TPM2_SHA256_DIGEST_SIZE];
} tee_attestation_document;

/**
 * @brief Fills in an Attestation Document: file_hash from
 * tee_hash_files(file_paths, file_count, ...), report_data copied verbatim
 * from the caller. Does not sign it -- see tee_sign().
 */
CHARRA_RC tee_attestation(const char* const* file_paths, size_t file_count,
        const uint8_t report_data[TPM2_SHA256_DIGEST_SIZE],
        tee_attestation_document* doc_out);

/**
 * @brief Signs an Attestation Document under the TEE's private key.
 *
 * Signs file_hash || report_data, in that order -- the concatenation, not
 * a hash of it, since charra_crypto_rsa_sign() hashes what it is given.
 *
 * The keypair is generated lazily, once per process, on whichever of
 * tee_sign() or tee_public_key_der() is called first, and reused for the
 * rest of the process's lifetime.
 */
CHARRA_RC tee_sign(const tee_attestation_document* doc,
        uint8_t signature_out[CHARRA_RSA_SIGNATURE_LEN]);

/**
 * @brief DER-encodes the TEE's public key, so the RP can forward it to a
 * Verifier that has no other way to learn it. Unlike AK_r (looked up in
 * the trust anchor, see charra_trusted_keys.h), the TEE's key is not
 * pre-shared, so it has to ship alongside every signature it produces --
 * and therefore has to be certified by AK_r before a Verifier may believe
 * it. See the file comment above.
 */
CHARRA_RC tee_public_key_der(uint8_t* der_out, size_t der_out_size,
        uint32_t* der_len_out);

#endif /* CHARRA_TEE_H */
