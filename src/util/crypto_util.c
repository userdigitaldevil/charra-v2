/* SPDX-License-Identifier: BSD-3-Clause */
/*****************************************************************************
 * Copyright 2019, Fraunhofer Institute for Secure Information Technology SIT.
 * All rights reserved.
 ****************************************************************************/

/**
 * @file crypto_util.c
 * @author Michael Eckel (michael.eckel@sit.fraunhofer.de)
 * @brief Provides IMA related crypto functions.
 * @version 0.1
 * @date 2019-12-22
 *
 * @copyright Copyright 2019, Fraunhofer Institute for Secure Information
 * Technology SIT. All rights reserved.
 *
 * @license BSD 3-Clause "New" or "Revised" License (SPDX-License-Identifier:
 * BSD-3-Clause).
 */

#include "crypto_util.h"

/* system includes */
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include <mbedtls/pk.h>
#include <mbedtls/rsa.h>
#include <mbedtls/sha1.h>
#include <mbedtls/sha256.h>
#include <mbedtls/sha512.h>
#include <tss2/tss2_tpm2_types.h>

static const unsigned char crypto_util_rng_personalization[] =
        "CHARRA_crypto_util_seeded_rng";

#include "../common/charra_error.h"
#include "../util/charra_util.h"
#include "../util/io_util.h"

/* hashing functions */

CHARRA_RC hash_sha1(const size_t data_len, const uint8_t* const data,
        uint8_t digest[TPM2_SHA1_DIGEST_SIZE]) {
    CHARRA_RC r = CHARRA_RC_SUCCESS;

    /* init */
    mbedtls_sha1_context ctx = {0};
    mbedtls_sha1_init(&ctx);

    /* hash */
    if ((mbedtls_sha1_starts(&ctx)) != 0) {
        r = CHARRA_RC_CRYPTO_ERROR;
        goto error;
    }

    if ((mbedtls_sha1_update(&ctx, data, data_len)) != 0) {
        r = CHARRA_RC_CRYPTO_ERROR;
        goto error;
    }

    if ((mbedtls_sha1_finish(&ctx, digest)) != 0) {
        r = CHARRA_RC_CRYPTO_ERROR;
        goto error;
    }

error:
    /* free */
    mbedtls_sha1_free(&ctx);

    return r;
}

CHARRA_RC hash_sha256(const size_t data_len, const uint8_t* const data,
        uint8_t digest[TPM2_SHA256_DIGEST_SIZE]) {
    CHARRA_RC r = CHARRA_RC_SUCCESS;

    /* init */
    mbedtls_sha256_context ctx = {0};
    mbedtls_sha256_init(&ctx);

    /* hash */
    if ((mbedtls_sha256_starts(&ctx, 0)) != 0) {
        r = CHARRA_RC_CRYPTO_ERROR;
        goto error;
    }

    if ((mbedtls_sha256_update(&ctx, data, data_len)) != 0) {
        r = CHARRA_RC_CRYPTO_ERROR;
        goto error;
    }

    if ((mbedtls_sha256_finish(&ctx, digest)) != 0) {
        r = CHARRA_RC_CRYPTO_ERROR;
        goto error;
    }

error:
    /* free */
    mbedtls_sha256_free(&ctx);

    return r;
}

CHARRA_RC hash_sha256_array(uint8_t* data[TPM2_SHA256_DIGEST_SIZE],
        const size_t data_len, uint8_t digest[TPM2_SHA256_DIGEST_SIZE]) {
    CHARRA_RC r = CHARRA_RC_SUCCESS;

    /* init */
    mbedtls_sha256_context ctx = {0};
    mbedtls_sha256_init(&ctx);

    /* hash */
    if ((mbedtls_sha256_starts(&ctx, 0)) != 0) {
        r = CHARRA_RC_CRYPTO_ERROR;
        goto error;
    }

    for (size_t i = 0; i < data_len; ++i) {
        if ((mbedtls_sha256_update(&ctx, data[i], TPM2_SHA256_DIGEST_SIZE)) !=
                0) {
            r = CHARRA_RC_CRYPTO_ERROR;
            goto error;
        }
    }

    if ((mbedtls_sha256_finish(&ctx, digest)) != 0) {
        r = CHARRA_RC_CRYPTO_ERROR;
        goto error;
    }

error:
    /* free */
    mbedtls_sha256_free(&ctx);

    return r;
}

CHARRA_RC hash_sha512(const size_t data_len, const uint8_t* const data,
        uint8_t digest[TPM2_SHA512_DIGEST_SIZE]) {
    CHARRA_RC r = CHARRA_RC_SUCCESS;

    /* init */
    mbedtls_sha512_context ctx = {0};
    mbedtls_sha512_init(&ctx);

    /* hash */
    if ((mbedtls_sha512_starts(&ctx, 0)) != 0) {  // 0 = SHA512
        r = CHARRA_RC_CRYPTO_ERROR;
        goto error;
    }

    if ((mbedtls_sha512_update(&ctx, data, data_len)) != 0) {
        r = CHARRA_RC_CRYPTO_ERROR;
        goto error;
    }

    if ((mbedtls_sha512_finish(&ctx, digest)) != 0) {
        r = CHARRA_RC_CRYPTO_ERROR;
        goto error;
    }

error:
    /* free */
    mbedtls_sha512_free(&ctx);

    return r;
}

CHARRA_RC charra_crypto_hash(mbedtls_md_type_t hash_algo,
        const uint8_t* const data, const size_t data_len,
        uint8_t digest[MBEDTLS_MD_MAX_SIZE]) {
    CHARRA_RC r = CHARRA_RC_SUCCESS;

    /* init and setup */
    const mbedtls_md_info_t* hash_info = mbedtls_md_info_from_type(hash_algo);
    mbedtls_md_context_t ctx = {0};
    mbedtls_md_init(&ctx);
    if ((mbedtls_md_setup(&ctx, hash_info, 0)) != 0) {  // 0 = do not use HMAC
        r = CHARRA_RC_CRYPTO_ERROR;
        goto error;
    }

    /* hash */
    if ((mbedtls_md_starts(&ctx)) != 0) {
        r = CHARRA_RC_CRYPTO_ERROR;
        goto error;
    }

    if ((mbedtls_md_update(&ctx, data, data_len)) != 0) {
        r = CHARRA_RC_CRYPTO_ERROR;
        goto error;
    }

    if ((mbedtls_md_finish(&ctx, digest)) != 0) {
        r = CHARRA_RC_CRYPTO_ERROR;
        goto error;
    }

error:
    /* free */
    mbedtls_md_free(&ctx);

    return r;
}

CHARRA_RC charra_crypto_tpm_pub_key_to_mbedtls_pub_key(
        const TPM2B_PUBLIC* tpm_rsa_pub_key,
        mbedtls_rsa_context* mbedtls_rsa_pub_key) {
    CHARRA_RC r = CHARRA_RC_SUCCESS;
    int mbedtls_r = 0;

    /* construct a RSA public key from modulus and exponent */
    mbedtls_mpi n = {0}; /* modulus */
    mbedtls_mpi e = {0}; /* exponent */

    /* init mbed TLS structures */
    mbedtls_rsa_init(mbedtls_rsa_pub_key);
    if (mbedtls_rsa_set_padding(mbedtls_rsa_pub_key, MBEDTLS_RSA_PKCS_V21,
                MBEDTLS_MD_NONE) != 0) {
        r = CHARRA_RC_CRYPTO_ERROR;
        charra_log_error("mbedtls_rsa_set_padding");
        goto error;
    }
    mbedtls_mpi_init(&n);
    mbedtls_mpi_init(&e);

    /* set modulus */
    if ((mbedtls_r = mbedtls_mpi_read_binary(&n,
                 (const unsigned char*)
                         tpm_rsa_pub_key->publicArea.unique.rsa.buffer,
                 (size_t)tpm_rsa_pub_key->publicArea.unique.rsa.size)) != 0) {
        r = CHARRA_RC_CRYPTO_ERROR;
        charra_log_error("mbedtls_mpi_read_binary");
        goto error;
    }

    { /* set exponent from TPM public key (if 0 set it to 65537) */
        uint32_t exp = 65537; /* set default exponent */
        if (tpm_rsa_pub_key->publicArea.parameters.rsaDetail.exponent != 0) {
            exp = tpm_rsa_pub_key->publicArea.parameters.rsaDetail.exponent;
        }

        if ((mbedtls_r = mbedtls_mpi_lset(&e, (mbedtls_mpi_sint)exp)) != 0) {
            r = CHARRA_RC_CRYPTO_ERROR;
            charra_log_error("mbedtls_mpi_lset");
            goto error;
        }
    }

    if ((mbedtls_r = mbedtls_rsa_import(
                 mbedtls_rsa_pub_key, &n, NULL, NULL, NULL, &e)) != 0) {
        r = CHARRA_RC_CRYPTO_ERROR;
        charra_log_error("mbedtls_rsa_import");
        goto error;
    }

    if ((mbedtls_r = mbedtls_rsa_complete(mbedtls_rsa_pub_key)) != 0) {
        r = CHARRA_RC_CRYPTO_ERROR;
        charra_log_error("mbedtls_rsa_complete");
        goto error;
    }

    if ((mbedtls_r = mbedtls_rsa_check_pubkey(mbedtls_rsa_pub_key)) != 0) {
        r = CHARRA_RC_CRYPTO_ERROR;
        charra_log_error("mbedtls_rsa_check_pubkey");
        goto error;
    }

    /* cleanup */
    mbedtls_mpi_free(&n);
    mbedtls_mpi_free(&e);

    return CHARRA_RC_SUCCESS;

error:
    /* cleanup */
    mbedtls_rsa_free(mbedtls_rsa_pub_key);
    mbedtls_mpi_free(&n);
    mbedtls_mpi_free(&e);

    return r;
}

CHARRA_RC charra_crypto_rsa_verify_signature_hashed(
        mbedtls_rsa_context* mbedtls_rsa_pub_key, mbedtls_md_type_t hash_algo,
        const unsigned char* data_digest, const unsigned char* signature) {
    CHARRA_RC charra_r = CHARRA_RC_SUCCESS;
    int mbedtls_r = 0;

    /* get hash digest size */
    const mbedtls_md_info_t* md_info = mbedtls_md_info_from_type(hash_algo);
    if (md_info == NULL) {
        charra_r = CHARRA_RC_CRYPTO_ERROR;
        charra_log_error("mbedtls_md_info_from_type");
        goto error;
    }
    uint8_t hash_digest_size = mbedtls_md_get_size(md_info);

    /* verify signature */
    if ((mbedtls_r = mbedtls_rsa_rsassa_pss_verify(mbedtls_rsa_pub_key,
                 hash_algo, hash_digest_size, data_digest, signature)) != 0) {
        charra_r = CHARRA_RC_CRYPTO_ERROR;
        goto error;
    }

error:
    return charra_r;
}

CHARRA_RC charra_crypto_rsa_verify_signature(
        mbedtls_rsa_context* mbedtls_rsa_pub_key, mbedtls_md_type_t hash_algo,
        const unsigned char* data, size_t data_len,
        const unsigned char* signature) {
    CHARRA_RC charra_r = CHARRA_RC_SUCCESS;

    /* hash data */
    uint8_t data_digest[MBEDTLS_MD_MAX_SIZE] = {0};
    if ((charra_r = charra_crypto_hash(hash_algo, data, data_len,
                 data_digest)) != CHARRA_RC_SUCCESS) {
        goto error;
    }

    /* verify signature */
    if ((charra_r = charra_crypto_rsa_verify_signature_hashed(
                 mbedtls_rsa_pub_key, hash_algo, data_digest, signature)) !=
            0) {
        charra_r = CHARRA_RC_CRYPTO_ERROR;
        goto error;
    }

error:
    return charra_r;
}

bool charra_crypto_verify_quote_signature_mbedtls(
        TPM2B_PUBLIC* tpm2_public_key, const uint8_t* attestation_data,
        uint32_t attestation_data_len, TPMT_SIGNATURE* signature,
        bool* out_valid) {
    *out_valid = false;

    charra_log_info(
            "[crypto_util] Converting TPM public key to mbedTLS public key ...");
    mbedtls_rsa_context mbedtls_rsa_pub_key = {0};
    if (charra_crypto_tpm_pub_key_to_mbedtls_pub_key(
                tpm2_public_key, &mbedtls_rsa_pub_key) != CHARRA_RC_SUCCESS) {
        charra_log_error("[crypto_util] mbedTLS RSA error");
        return false;
    }

    charra_log_info(
            "[crypto_util] Verifying TPM Quote signature with mbedTLS ...");
    if (charra_crypto_rsa_verify_signature(&mbedtls_rsa_pub_key,
                MBEDTLS_MD_SHA256, attestation_data,
                (size_t)attestation_data_len,
                signature->signature.rsapss.sig.buffer) == CHARRA_RC_SUCCESS) {
        charra_log_info("[crypto_util]     => TPM Quote signature is valid!");
        *out_valid = true;
    } else {
        charra_log_error(
                "[crypto_util]     => TPM Quote signature is NOT valid!");
    }
    mbedtls_rsa_free(&mbedtls_rsa_pub_key);
    return true;
}

CHARRA_RC compute_and_check_PCR_digest(uint8_t** pcr_values,
        uint32_t pcr_values_len, const TPMS_ATTEST* const attest_struct) {
    uint8_t pcr_composite_digest[TPM2_SHA256_DIGEST_SIZE] = {0};
    /* TODO use crypto-agile (generic) version
     * charra_compute_pcr_composite_digest_from_ptr_array(), once
     * implemented, instead of hash_sha256_array() (then maybe remove
     * hash_sha256_array() function) */
    CHARRA_RC charra_r =
            hash_sha256_array(pcr_values, pcr_values_len, pcr_composite_digest);
    if (charra_r != CHARRA_RC_SUCCESS) {
        return CHARRA_RC_ERROR;
    }
    bool matching = charra_verify_tpm2_quote_pcr_composite_digest(
            attest_struct, pcr_composite_digest, TPM2_SHA256_DIGEST_SIZE);
    charra_print_hex(CHARRA_LOG_DEBUG, sizeof(pcr_composite_digest),
            pcr_composite_digest,
            "                                              0x", "\n", false);
    if (matching) {
        return CHARRA_RC_SUCCESS;
    } else {
        return CHARRA_RC_NO_MATCH;
    }
}

/* --- software RSA keypair ----------------------------------------------- */

/**
 * @brief Seed a CTR_DRBG from the platform entropy source.
 *
 * Both contexts are initialized here and must be freed by the caller in the
 * reverse order (drbg then entropy).
 */
static CHARRA_RC seed_drbg(mbedtls_entropy_context* entropy,
        mbedtls_ctr_drbg_context* drbg) {
    static const char pers[] = "charra-relying-party";

    mbedtls_entropy_init(entropy);
    mbedtls_ctr_drbg_init(drbg);
    if (mbedtls_ctr_drbg_seed(drbg, mbedtls_entropy_func, entropy,
                (const unsigned char*)pers, sizeof(pers) - 1) != 0) {
        charra_log_error("[crypto_util] Could not seed the DRBG.");
        mbedtls_ctr_drbg_free(drbg);
        mbedtls_entropy_free(entropy);
        return CHARRA_RC_CRYPTO_ERROR;
    }
    return CHARRA_RC_SUCCESS;
}

CHARRA_RC charra_crypto_rsa_generate_keypair(mbedtls_pk_context* key) {
    if (key == NULL) {
        return CHARRA_RC_BAD_ARGUMENT;
    }

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context drbg;
    CHARRA_RC charra_r = seed_drbg(&entropy, &drbg);
    if (charra_r != CHARRA_RC_SUCCESS) {
        return charra_r;
    }

    mbedtls_pk_init(key);
    if (mbedtls_pk_setup(key, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA)) != 0) {
        charra_log_error("[crypto_util] Could not set up the PK context.");
        charra_r = CHARRA_RC_CRYPTO_ERROR;
        goto cleanup;
    }
    if (mbedtls_rsa_gen_key(mbedtls_pk_rsa(*key), mbedtls_ctr_drbg_random,
                &drbg, CHARRA_RSA_KEY_BITS, 65537) != 0) {
        charra_log_error("[crypto_util] RSA key generation failed.");
        mbedtls_pk_free(key);
        charra_r = CHARRA_RC_CRYPTO_ERROR;
        goto cleanup;
    }
    /* PSS with SHA-256, matching charra_crypto_rsa_verify_signature() */
    if (mbedtls_rsa_set_padding(mbedtls_pk_rsa(*key), MBEDTLS_RSA_PKCS_V21,
                MBEDTLS_MD_SHA256) != 0) {
        charra_log_error("[crypto_util] Could not select RSA-PSS padding.");
        mbedtls_pk_free(key);
        charra_r = CHARRA_RC_CRYPTO_ERROR;
        goto cleanup;
    }

cleanup:
    mbedtls_ctr_drbg_free(&drbg);
    mbedtls_entropy_free(&entropy);
    return charra_r;
}

CHARRA_RC charra_crypto_rsa_public_key_to_der(mbedtls_pk_context* key,
        uint8_t* der_out, size_t der_out_size, uint32_t* der_len_out) {
    if (key == NULL || der_out == NULL || der_len_out == NULL) {
        return CHARRA_RC_BAD_ARGUMENT;
    }

    /* mbedtls_pk_write_pubkey_der() writes at the END of the buffer and
     * returns the length, so the encoding has to be moved to the front. */
    int len = mbedtls_pk_write_pubkey_der(key, der_out, der_out_size);
    if (len < 0) {
        charra_log_error("[crypto_util] Could not DER-encode the public key.");
        return CHARRA_RC_CRYPTO_ERROR;
    }
    memmove(der_out, der_out + der_out_size - (size_t)len, (size_t)len);
    *der_len_out = (uint32_t)len;
    return CHARRA_RC_SUCCESS;
}

CHARRA_RC charra_crypto_rsa_sign(mbedtls_pk_context* key,
        const unsigned char* data, size_t data_len,
        unsigned char* signature_out) {
    if (key == NULL || data == NULL || signature_out == NULL) {
        return CHARRA_RC_BAD_ARGUMENT;
    }

    uint8_t digest[TPM2_SHA256_DIGEST_SIZE] = {0};
    if (hash_sha256(data_len, data, digest) != CHARRA_RC_SUCCESS) {
        return CHARRA_RC_CRYPTO_ERROR;
    }

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context drbg;
    CHARRA_RC charra_r = seed_drbg(&entropy, &drbg);
    if (charra_r != CHARRA_RC_SUCCESS) {
        return charra_r;
    }

    /* PSS salt is random, so two signings over identical data never produce
     * identical bytes -- a verifier must compare the signed VALUES, never
     * raw signature bytes. */
    if (mbedtls_rsa_rsassa_pss_sign(mbedtls_pk_rsa(*key),
                mbedtls_ctr_drbg_random, &drbg, MBEDTLS_MD_SHA256,
                TPM2_SHA256_DIGEST_SIZE, digest, signature_out) != 0) {
        charra_log_error("[crypto_util] RSA-PSS signing failed.");
        charra_r = CHARRA_RC_CRYPTO_ERROR;
    }

    mbedtls_ctr_drbg_free(&drbg);
    mbedtls_entropy_free(&entropy);
    return charra_r;
}

