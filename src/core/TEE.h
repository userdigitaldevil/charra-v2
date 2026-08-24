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
 * This proves nothing against an attacker able to modify TEE.c itself (a
 * real TEE's guarantee comes from hardware isolation this PoC does not
 * have). The point is narrower: it closes the specific gap the rest of the
 * codebase leaves open, where nothing stops the RP from redacting a
 * fabricated log instead of the Attester's genuine, TPM-signed one, or from
 * running different cleaning logic than the Verifier expects, and having
 * that go undetected.
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
 * @param[in] file_paths paths relative to the repository root, which is
 * also the working directory every binary is always started from (see
 * CHARRA_V2_NOTES.md)
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
 * pre-shared, so it has to ship alongside every signature it produces.
 */
CHARRA_RC tee_public_key_der(uint8_t* der_out, size_t der_out_size,
        uint32_t* der_len_out);

#endif /* CHARRA_TEE_H */
