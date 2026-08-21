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

/* --- file-backed signing keys ------------------------------------------
 *
 * For identities that are NOT TPM-resident -- today just the Verifier's
 * verdict key, an EC P-256 pair in keys/. Everything above this point is
 * RSA-only because it serves AKs, which are TPM primaries; these two go
 * through mbedTLS's generic pk interface instead, so the algorithm is
 * whatever the key file says it is.
 *
 * Both hash with SHA-256 internally, and both re-read the key file on
 * every call -- see the note above their definitions.
 */

/**
 * @brief SHA-256 data, then sign the digest with the private key at
 * private_key_path.
 *
 * @param[out] signature_out receives at most signature_out_cap bytes;
 * fails rather than truncating if the signature is longer.
 */
CHARRA_RC charra_crypto_pk_sign_file(const char* private_key_path,
        const uint8_t* data, size_t data_len, uint8_t* signature_out,
        size_t signature_out_cap, size_t* signature_len_out);

/**
 * @brief The inverse: SHA-256 data and check signature under the public
 * key at public_key_path.
 *
 * @returns CHARRA_RC_SUCCESS if the signature is valid,
 * CHARRA_RC_VERIFICATION_FAILED if it is not, CHARRA_RC_CRYPTO_ERROR if
 * the key could not be read or the digest not computed -- three outcomes,
 * because "no key file" is a deployment fault and "bad signature" is an
 * attack, and the caller may want to say so differently.
 */
CHARRA_RC charra_crypto_pk_verify_file(const char* public_key_path,
        const uint8_t* data, size_t data_len, const uint8_t* signature,
        size_t signature_len);

/* --- AK_r's RSA parameters ------------------------------------------------
 *
 * The key the Relying Party signs Quote_r with is TPM-resident: derived
 * from the owner hierarchy on demand by
 * tpm2_create_primary_key_rsa2048_unrestricted(), never held in software
 * and never written to disk (see rp_signing_key.h). These constants only
 * fix its size, which the wire DTOs need in order to declare fixed-width
 * signature fields.
 */

/** Size of AK_r, and of the Attester's AK -- both are RSA-2048 primaries. */
#define CHARRA_RSA_KEY_BITS 2048
/** Bytes an RSA-2048 signature occupies. */
#define CHARRA_RSA_SIGNATURE_LEN (CHARRA_RSA_KEY_BITS / 8)

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

#endif /* SITIMA_CRYPTO_H */
