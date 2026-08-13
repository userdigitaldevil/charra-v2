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
#include <stdlib.h>

#include <mbedtls/gcm.h>
#include <mbedtls/pk.h>
#include <mbedtls/rsa.h>
#include <mbedtls/sha1.h>
#include <mbedtls/sha256.h>
#include <mbedtls/sha512.h>
#include <mbedtls/x509_crt.h>
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

/* --- EK/AK certificate chain verification (Step 3a/3b item 1) ---------- */

CHARRA_RC charra_crypto_verify_x509_cert_chain(const uint8_t* leaf_cert_der,
        size_t leaf_cert_len, const uint8_t* trusted_root_der,
        size_t trusted_root_len, mbedtls_x509_crt* leaf_out) {
    if (leaf_cert_der == NULL || leaf_cert_len == 0 ||
            trusted_root_der == NULL || trusted_root_len == 0 ||
            leaf_out == NULL) {
        return CHARRA_RC_BAD_ARGUMENT;
    }

    CHARRA_RC charra_r = CHARRA_RC_SUCCESS;
    int mbedtls_r = 0;

    mbedtls_x509_crt trusted_root = {0};
    mbedtls_x509_crt_init(&trusted_root);
    mbedtls_x509_crt_init(leaf_out);

    if ((mbedtls_r = mbedtls_x509_crt_parse(
                 &trusted_root, trusted_root_der, trusted_root_len)) != 0) {
        charra_log_error(
                "mbedtls_x509_crt_parse (trusted root): mbedtls error %d",
                mbedtls_r);
        charra_r = CHARRA_RC_CRYPTO_ERROR;
        goto cleanup;
    }
    if ((mbedtls_r = mbedtls_x509_crt_parse(
                 leaf_out, leaf_cert_der, leaf_cert_len)) != 0) {
        charra_log_error("mbedtls_x509_crt_parse (leaf): mbedtls error %d",
                mbedtls_r);
        charra_r = CHARRA_RC_CRYPTO_ERROR;
        goto cleanup;
    }

    uint32_t verify_flags = 0;
    if ((mbedtls_r = mbedtls_x509_crt_verify(leaf_out, &trusted_root, NULL,
                 NULL, &verify_flags, NULL, NULL)) != 0) {
        char flags_str[256] = {0};
        mbedtls_x509_crt_verify_info(
                flags_str, sizeof(flags_str), "  ", verify_flags);
        charra_log_error("mbedtls_x509_crt_verify failed: %s", flags_str);
        charra_r = CHARRA_RC_VERIFICATION_FAILED;
        goto cleanup;
    }

cleanup:
    mbedtls_x509_crt_free(&trusted_root);
    if (charra_r != CHARRA_RC_SUCCESS) {
        mbedtls_x509_crt_free(leaf_out);
    }
    return charra_r;
}

CHARRA_RC charra_crypto_seeded_rng_init(
        mbedtls_ctr_drbg_context* ctr_drbg_out,
        mbedtls_entropy_context* entropy_out) {
    if (ctr_drbg_out == NULL || entropy_out == NULL) {
        return CHARRA_RC_BAD_ARGUMENT;
    }

    mbedtls_entropy_init(entropy_out);
    mbedtls_ctr_drbg_init(ctr_drbg_out);

    if (mbedtls_ctr_drbg_seed(ctr_drbg_out, mbedtls_entropy_func, entropy_out,
                crypto_util_rng_personalization,
                sizeof(crypto_util_rng_personalization)) != 0) {
        charra_log_error("mbedtls_ctr_drbg_seed");
        mbedtls_ctr_drbg_free(ctr_drbg_out);
        mbedtls_entropy_free(entropy_out);
        return CHARRA_RC_CRYPTO_ERROR;
    }

    mbedtls_ctr_drbg_set_prediction_resistance(
            ctr_drbg_out, MBEDTLS_CTR_DRBG_PR_ON);
    return CHARRA_RC_SUCCESS;
}

void charra_crypto_seeded_rng_free(
        mbedtls_ctr_drbg_context* ctr_drbg, mbedtls_entropy_context* entropy) {
    if (ctr_drbg != NULL) {
        mbedtls_ctr_drbg_free(ctr_drbg);
    }
    if (entropy != NULL) {
        mbedtls_entropy_free(entropy);
    }
}

CHARRA_RC charra_crypto_verify_cert_public_key_matches_tpm_public_key(
        const mbedtls_x509_crt* cert, const TPM2B_PUBLIC* tpm_pub_key) {
    if (cert == NULL || tpm_pub_key == NULL) {
        return CHARRA_RC_BAD_ARGUMENT;
    }

    if (mbedtls_pk_get_type(&cert->pk) != MBEDTLS_PK_RSA) {
        charra_log_error(
                "charra_crypto_verify_cert_public_key_matches_tpm_public_key: "
                "certificate's public key is not RSA");
        return CHARRA_RC_VERIFICATION_FAILED;
    }

    CHARRA_RC charra_r = CHARRA_RC_SUCCESS;
    mbedtls_rsa_context tpm_rsa_pub_key = {0};
    if ((charra_r = charra_crypto_tpm_pub_key_to_mbedtls_pub_key(
                 tpm_pub_key, &tpm_rsa_pub_key)) != CHARRA_RC_SUCCESS) {
        return charra_r;
    }

    mbedtls_rsa_context* cert_rsa_pub_key = mbedtls_pk_rsa(cert->pk);

    mbedtls_mpi cert_modulus = {0}, cert_exponent = {0};
    mbedtls_mpi tpm_modulus = {0}, tpm_exponent = {0};
    mbedtls_mpi_init(&cert_modulus);
    mbedtls_mpi_init(&cert_exponent);
    mbedtls_mpi_init(&tpm_modulus);
    mbedtls_mpi_init(&tpm_exponent);

    bool keys_match = false;
    if (mbedtls_rsa_export(cert_rsa_pub_key, &cert_modulus, NULL, NULL, NULL,
                &cert_exponent) == 0 &&
            mbedtls_rsa_export(&tpm_rsa_pub_key, &tpm_modulus, NULL, NULL,
                    NULL, &tpm_exponent) == 0) {
        keys_match =
                (mbedtls_mpi_cmp_mpi(&cert_modulus, &tpm_modulus) == 0) &&
                (mbedtls_mpi_cmp_mpi(&cert_exponent, &tpm_exponent) == 0);
    } else {
        charra_log_error(
                "charra_crypto_verify_cert_public_key_matches_tpm_public_key: "
                "mbedtls_rsa_export failed");
        charra_r = CHARRA_RC_CRYPTO_ERROR;
    }

    mbedtls_mpi_free(&cert_modulus);
    mbedtls_mpi_free(&cert_exponent);
    mbedtls_mpi_free(&tpm_modulus);
    mbedtls_mpi_free(&tpm_exponent);
    mbedtls_rsa_free(&tpm_rsa_pub_key);

    if (charra_r != CHARRA_RC_SUCCESS) {
        return charra_r;
    }
    return keys_match ? CHARRA_RC_SUCCESS : CHARRA_RC_VERIFICATION_FAILED;
}

CHARRA_RC charra_crypto_verify_cert_public_key_matches_der_key(
        const mbedtls_x509_crt* cert, const uint8_t* der_pub_key,
        size_t der_pub_key_len) {
    if (cert == NULL || der_pub_key == NULL || der_pub_key_len == 0) {
        return CHARRA_RC_BAD_ARGUMENT;
    }

    if (mbedtls_pk_get_type(&cert->pk) != MBEDTLS_PK_RSA) {
        charra_log_error(
                "charra_crypto_verify_cert_public_key_matches_der_key: "
                "certificate's public key is not RSA");
        return CHARRA_RC_VERIFICATION_FAILED;
    }

    mbedtls_pk_context der_key;
    mbedtls_pk_init(&der_key);
    if (mbedtls_pk_parse_public_key(&der_key, der_pub_key, der_pub_key_len) !=
            0) {
        charra_log_error(
                "charra_crypto_verify_cert_public_key_matches_der_key: "
                "mbedtls_pk_parse_public_key failed");
        mbedtls_pk_free(&der_key);
        return CHARRA_RC_CRYPTO_ERROR;
    }
    if (mbedtls_pk_get_type(&der_key) != MBEDTLS_PK_RSA) {
        charra_log_error(
                "charra_crypto_verify_cert_public_key_matches_der_key: "
                "der_pub_key is not RSA");
        mbedtls_pk_free(&der_key);
        return CHARRA_RC_VERIFICATION_FAILED;
    }

    CHARRA_RC charra_r = CHARRA_RC_SUCCESS;
    mbedtls_rsa_context* cert_rsa_pub_key = mbedtls_pk_rsa(cert->pk);
    mbedtls_rsa_context* der_rsa_pub_key = mbedtls_pk_rsa(der_key);

    mbedtls_mpi cert_modulus = {0}, cert_exponent = {0};
    mbedtls_mpi der_modulus = {0}, der_exponent = {0};
    mbedtls_mpi_init(&cert_modulus);
    mbedtls_mpi_init(&cert_exponent);
    mbedtls_mpi_init(&der_modulus);
    mbedtls_mpi_init(&der_exponent);

    bool keys_match = false;
    if (mbedtls_rsa_export(cert_rsa_pub_key, &cert_modulus, NULL, NULL, NULL,
                &cert_exponent) == 0 &&
            mbedtls_rsa_export(der_rsa_pub_key, &der_modulus, NULL, NULL,
                    NULL, &der_exponent) == 0) {
        keys_match = (mbedtls_mpi_cmp_mpi(&cert_modulus, &der_modulus) == 0) &&
                (mbedtls_mpi_cmp_mpi(&cert_exponent, &der_exponent) == 0);
    } else {
        charra_log_error(
                "charra_crypto_verify_cert_public_key_matches_der_key: "
                "mbedtls_rsa_export failed");
        charra_r = CHARRA_RC_CRYPTO_ERROR;
    }

    mbedtls_mpi_free(&cert_modulus);
    mbedtls_mpi_free(&cert_exponent);
    mbedtls_mpi_free(&der_modulus);
    mbedtls_mpi_free(&der_exponent);
    mbedtls_pk_free(&der_key);

    if (charra_r != CHARRA_RC_SUCCESS) {
        return charra_r;
    }
    return keys_match ? CHARRA_RC_SUCCESS : CHARRA_RC_VERIFICATION_FAILED;
}

CHARRA_RC charra_crypto_verify_ekak_certificate(const uint8_t* ak_cert_der,
        uint32_t ak_cert_der_len, const uint8_t* trusted_ca_der,
        size_t trusted_ca_der_len, TPM2B_PUBLIC* tpm2_public_key,
        uint8_t serial_out[16]) {
    if (ak_cert_der == NULL || trusted_ca_der == NULL ||
            tpm2_public_key == NULL) {
        return CHARRA_RC_BAD_ARGUMENT;
    }

    mbedtls_x509_crt ak_cert_leaf;
    CHARRA_RC charra_r = charra_crypto_verify_x509_cert_chain(ak_cert_der,
            ak_cert_der_len, trusted_ca_der, trusted_ca_der_len,
            &ak_cert_leaf);
    if (charra_r != CHARRA_RC_SUCCESS) {
        return charra_r;
    }

    if (serial_out != NULL) {
        if (ak_cert_leaf.serial.len == 16) {
            memcpy(serial_out, ak_cert_leaf.serial.p, 16);
        } else {
            /* not a serial charra_crypto_sign_ak_certificate() could have
             * issued -- zero it out rather than leave a stale/garbage
             * value a caller might mistake for a real lookup key */
            memset(serial_out, 0, 16);
        }
    }

    charra_r = charra_crypto_verify_cert_public_key_matches_tpm_public_key(
            &ak_cert_leaf, tpm2_public_key);
    mbedtls_x509_crt_free(&ak_cert_leaf);
    return charra_r;
}

CHARRA_RC charra_crypto_build_ek_tpm2b_public_from_cert(
        const mbedtls_x509_crt* ek_cert, TPM2B_PUBLIC* ek_public_key_out) {
    if (ek_cert == NULL || ek_public_key_out == NULL) {
        return CHARRA_RC_BAD_ARGUMENT;
    }

    if (mbedtls_pk_get_type(&ek_cert->pk) != MBEDTLS_PK_RSA) {
        charra_log_error("charra_crypto_build_ek_tpm2b_public_from_cert: "
                         "certificate's public key is not RSA");
        return CHARRA_RC_VERIFICATION_FAILED;
    }
    mbedtls_rsa_context* cert_rsa_pub_key = mbedtls_pk_rsa(ek_cert->pk);

    CHARRA_RC charra_r = CHARRA_RC_SUCCESS;
    mbedtls_mpi modulus, exponent;
    mbedtls_mpi_init(&modulus);
    mbedtls_mpi_init(&exponent);

    if (mbedtls_rsa_export(cert_rsa_pub_key, &modulus, NULL, NULL, NULL,
                &exponent) != 0) {
        charra_log_error("charra_crypto_build_ek_tpm2b_public_from_cert: "
                         "mbedtls_rsa_export failed");
        charra_r = CHARRA_RC_CRYPTO_ERROR;
        goto cleanup;
    }

    if (mbedtls_mpi_cmp_int(&exponent, 65537) != 0) {
        charra_log_error("charra_crypto_build_ek_tpm2b_public_from_cert: "
                         "EK certificate's RSA exponent is not the "
                         "TPM-conventional 65537");
        charra_r = CHARRA_RC_VERIFICATION_FAILED;
        goto cleanup;
    }

    size_t modulus_size = mbedtls_mpi_size(&modulus);
    if (modulus_size != 256) { /* RSA 2048 = 256 bytes */
        charra_log_error("charra_crypto_build_ek_tpm2b_public_from_cert: "
                         "EK certificate's RSA key is not 2048-bit "
                         "(got %zu bytes)",
                modulus_size);
        charra_r = CHARRA_RC_VERIFICATION_FAILED;
        goto cleanup;
    }

    memset(ek_public_key_out, 0, sizeof(*ek_public_key_out));
    ek_public_key_out->publicArea.type = TPM2_ALG_RSA;
    ek_public_key_out->publicArea.nameAlg = TPM2_ALG_SHA256;
    ek_public_key_out->publicArea.objectAttributes =
            TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_FIXEDPARENT |
            TPMA_OBJECT_SENSITIVEDATAORIGIN | TPMA_OBJECT_ADMINWITHPOLICY |
            TPMA_OBJECT_RESTRICTED | TPMA_OBJECT_DECRYPT;

    /* the standard TCG "low range" RSA 2048 EK authPolicy digest -- fixed
     * across every compliant EK, not specific to this key */
    static const uint8_t ek_auth_policy[32] = {0x83, 0x71, 0x97, 0x67, 0x44,
            0x84, 0xb3, 0xf8, 0x1a, 0x90, 0xcc, 0x8d, 0x46, 0xa5, 0xd7, 0x24,
            0xfd, 0x52, 0xd7, 0x6e, 0x06, 0x52, 0x0b, 0x64, 0xf2, 0xa1, 0xda,
            0x1b, 0x33, 0x14, 0x69, 0xaa};
    ek_public_key_out->publicArea.authPolicy.size = sizeof(ek_auth_policy);
    memcpy(ek_public_key_out->publicArea.authPolicy.buffer, ek_auth_policy,
            sizeof(ek_auth_policy));

    ek_public_key_out->publicArea.parameters.rsaDetail.symmetric.algorithm =
            TPM2_ALG_AES;
    ek_public_key_out->publicArea.parameters.rsaDetail.symmetric.keyBits.aes =
            128;
    ek_public_key_out->publicArea.parameters.rsaDetail.symmetric.mode.aes =
            TPM2_ALG_CFB;
    ek_public_key_out->publicArea.parameters.rsaDetail.scheme.scheme =
            TPM2_ALG_NULL;
    ek_public_key_out->publicArea.parameters.rsaDetail.keyBits = 2048;
    ek_public_key_out->publicArea.parameters.rsaDetail.exponent =
            0; /* 0 = TPM-conventional default of 65537, already confirmed
                * above */

    ek_public_key_out->publicArea.unique.rsa.size = (uint16_t)modulus_size;
    if (mbedtls_mpi_write_binary(&modulus,
                ek_public_key_out->publicArea.unique.rsa.buffer,
                modulus_size) != 0) {
        charra_log_error("charra_crypto_build_ek_tpm2b_public_from_cert: "
                         "mbedtls_mpi_write_binary failed");
        charra_r = CHARRA_RC_CRYPTO_ERROR;
        goto cleanup;
    }

cleanup:
    mbedtls_mpi_free(&modulus);
    mbedtls_mpi_free(&exponent);
    return charra_r;
}

/* --- AK certificate issuance (Verifier acting as Privacy CA) ----------- */

CHARRA_RC charra_crypto_sign_ak_certificate(const TPM2B_PUBLIC* ak_public_key,
        const char* subject_name, const char* issuer_name,
        const char* not_before_utc, const char* not_after_utc,
        const char* ca_private_key_path, uint8_t** ak_cert_der_out,
        uint32_t* ak_cert_der_len_out, uint8_t serial_out[16]) {
    if (ak_public_key == NULL || subject_name == NULL || issuer_name == NULL ||
            not_before_utc == NULL || not_after_utc == NULL ||
            ca_private_key_path == NULL || ak_cert_der_out == NULL ||
            ak_cert_der_len_out == NULL || serial_out == NULL) {
        return CHARRA_RC_BAD_ARGUMENT;
    }
    *ak_cert_der_out = NULL;
    *ak_cert_der_len_out = 0;

    CHARRA_RC charra_r = CHARRA_RC_SUCCESS;
    int mbedtls_r = 0;

    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;
    if ((charra_r = charra_crypto_seeded_rng_init(&ctr_drbg, &entropy)) !=
            CHARRA_RC_SUCCESS) {
        return charra_r;
    }

    mbedtls_pk_context ca_private_key;
    mbedtls_pk_init(&ca_private_key);
    mbedtls_pk_context ak_key_for_writer;
    mbedtls_pk_init(&ak_key_for_writer);
    mbedtls_rsa_context ak_rsa_pub_key = {0};
    bool ak_rsa_pub_key_inited = false;
    mbedtls_x509write_cert crt;
    mbedtls_x509write_crt_init(&crt);
    uint8_t* der_write_buf = NULL;

    /* load the CA's private key -- this is what signs the new certificate */
    if ((mbedtls_r = mbedtls_pk_parse_keyfile(&ca_private_key,
                 ca_private_key_path, NULL, mbedtls_ctr_drbg_random,
                 &ctr_drbg)) != 0) {
        charra_log_error(
                "mbedtls_pk_parse_keyfile (CA key): mbedtls error %d",
                mbedtls_r);
        charra_r = CHARRA_RC_CRYPTO_ERROR;
        goto cleanup;
    }

    /* convert the AK's TPM2B_PUBLIC into an mbedtls RSA public key, then
     * wrap it in a pk_context -- mbedtls_x509write_crt_set_subject_key()
     * takes a pk_context, not a bare RSA context */
    if ((charra_r = charra_crypto_tpm_pub_key_to_mbedtls_pub_key(
                 ak_public_key, &ak_rsa_pub_key)) != CHARRA_RC_SUCCESS) {
        goto cleanup;
    }
    ak_rsa_pub_key_inited = true;
    if ((mbedtls_r = mbedtls_pk_setup(&ak_key_for_writer,
                 mbedtls_pk_info_from_type(MBEDTLS_PK_RSA))) != 0) {
        charra_log_error("mbedtls_pk_setup: mbedtls error %d", mbedtls_r);
        charra_r = CHARRA_RC_CRYPTO_ERROR;
        goto cleanup;
    }
    if ((mbedtls_r = mbedtls_rsa_copy(mbedtls_pk_rsa(ak_key_for_writer),
                 &ak_rsa_pub_key)) != 0) {
        charra_log_error("mbedtls_rsa_copy: mbedtls error %d", mbedtls_r);
        charra_r = CHARRA_RC_CRYPTO_ERROR;
        goto cleanup;
    }

    /* build the certificate */
    mbedtls_x509write_crt_set_version(&crt, MBEDTLS_X509_CRT_VERSION_3);
    mbedtls_x509write_crt_set_md_alg(&crt, MBEDTLS_MD_SHA256);
    mbedtls_x509write_crt_set_subject_key(&crt, &ak_key_for_writer);
    mbedtls_x509write_crt_set_issuer_key(&crt, &ca_private_key);

    if ((mbedtls_r = mbedtls_x509write_crt_set_subject_name(
                 &crt, subject_name)) != 0) {
        charra_log_error(
                "mbedtls_x509write_crt_set_subject_name: mbedtls error %d",
                mbedtls_r);
        charra_r = CHARRA_RC_CRYPTO_ERROR;
        goto cleanup;
    }
    if ((mbedtls_r = mbedtls_x509write_crt_set_issuer_name(
                 &crt, issuer_name)) != 0) {
        charra_log_error(
                "mbedtls_x509write_crt_set_issuer_name: mbedtls error %d",
                mbedtls_r);
        charra_r = CHARRA_RC_CRYPTO_ERROR;
        goto cleanup;
    }
    if ((mbedtls_r = mbedtls_x509write_crt_set_validity(
                 &crt, not_before_utc, not_after_utc)) != 0) {
        charra_log_error(
                "mbedtls_x509write_crt_set_validity: mbedtls error %d",
                mbedtls_r);
        charra_r = CHARRA_RC_CRYPTO_ERROR;
        goto cleanup;
    }

    /* serial number: fresh random bytes, not a sequential counter -- the
     * AK-provisioning state module (charra_ak_state.h) tracks issuance by
     * (EK fingerprint, serial) pairs, not by handing out sequential serials
     * itself, and randomness is good enough for this test PKI's purposes */
    uint8_t serial[16] = {0};
    if ((mbedtls_r = mbedtls_ctr_drbg_random(
                 &ctr_drbg, serial, sizeof(serial))) != 0) {
        charra_log_error(
                "mbedtls_ctr_drbg_random (serial): mbedtls error %d",
                mbedtls_r);
        charra_r = CHARRA_RC_CRYPTO_ERROR;
        goto cleanup;
    }
    serial[0] &= 0x7f; /* clear the sign bit -- DER INTEGER must be positive */
    memcpy(serial_out, serial, sizeof(serial));
    if ((mbedtls_r = mbedtls_x509write_crt_set_serial_raw(
                 &crt, serial, sizeof(serial))) != 0) {
        charra_log_error(
                "mbedtls_x509write_crt_set_serial_raw: mbedtls error %d",
                mbedtls_r);
        charra_r = CHARRA_RC_CRYPTO_ERROR;
        goto cleanup;
    }

    /* not a CA certificate -- it may only be used as a leaf, matching the
     * single-root, no-intermediate-chain PKI this project uses */
    if ((mbedtls_r = mbedtls_x509write_crt_set_basic_constraints(
                 &crt, 0, -1)) != 0) {
        charra_log_error("mbedtls_x509write_crt_set_basic_constraints: "
                         "mbedtls error %d",
                mbedtls_r);
        charra_r = CHARRA_RC_CRYPTO_ERROR;
        goto cleanup;
    }

    /* mbedtls_x509write_crt_der() fills the buffer from the END; the
     * return value is the actual encoded length, and the encoding starts
     * at der_write_buf + der_write_buf_capacity - written_len */
    const size_t der_write_buf_capacity = 4096;
    if ((der_write_buf = malloc(der_write_buf_capacity)) == NULL) {
        charra_r = CHARRA_RC_ERROR;
        goto cleanup;
    }
    int written_len = mbedtls_x509write_crt_der(&crt, der_write_buf,
            der_write_buf_capacity, mbedtls_ctr_drbg_random, &ctr_drbg);
    if (written_len < 0) {
        charra_log_error(
                "mbedtls_x509write_crt_der: mbedtls error %d", written_len);
        charra_r = CHARRA_RC_CRYPTO_ERROR;
        goto cleanup;
    }

    uint8_t* final_der = malloc((size_t)written_len);
    if (final_der == NULL) {
        charra_r = CHARRA_RC_ERROR;
        goto cleanup;
    }
    memcpy(final_der,
            der_write_buf + der_write_buf_capacity - (size_t)written_len,
            (size_t)written_len);
    *ak_cert_der_out = final_der;
    *ak_cert_der_len_out = (uint32_t)written_len;

cleanup:
    free(der_write_buf);
    mbedtls_x509write_crt_free(&crt);
    mbedtls_pk_free(&ak_key_for_writer);
    if (ak_rsa_pub_key_inited) {
        mbedtls_rsa_free(&ak_rsa_pub_key);
    }
    mbedtls_pk_free(&ca_private_key);
    charra_crypto_seeded_rng_free(&ctr_drbg, &entropy);
    return charra_r;
}

/* --- AES-256-GCM (wraps the AK certificate under the MakeCredential
 * secret, see msg_certify_ak_response_dto) ------------------------------- */

CHARRA_RC charra_crypto_aes256gcm_encrypt(
        const uint8_t key[CHARRA_AES256GCM_KEY_LEN],
        const uint8_t* plaintext, size_t plaintext_len,
        uint8_t nonce_out[CHARRA_AES256GCM_NONCE_LEN],
        uint8_t tag_out[CHARRA_AES256GCM_TAG_LEN], uint8_t** ciphertext_out) {
    if (key == NULL || (plaintext == NULL && plaintext_len > 0) ||
            nonce_out == NULL || tag_out == NULL || ciphertext_out == NULL) {
        return CHARRA_RC_BAD_ARGUMENT;
    }
    *ciphertext_out = NULL;

    CHARRA_RC charra_r = CHARRA_RC_SUCCESS;
    int mbedtls_r = 0;

    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;
    if ((charra_r = charra_crypto_seeded_rng_init(&ctr_drbg, &entropy)) !=
            CHARRA_RC_SUCCESS) {
        return charra_r;
    }

    if ((mbedtls_r = mbedtls_ctr_drbg_random(
                 &ctr_drbg, nonce_out, CHARRA_AES256GCM_NONCE_LEN)) != 0) {
        charra_log_error(
                "mbedtls_ctr_drbg_random (GCM nonce): mbedtls error %d",
                mbedtls_r);
        charra_r = CHARRA_RC_CRYPTO_ERROR;
        goto cleanup_rng;
    }

    uint8_t* ciphertext = NULL;
    if (plaintext_len > 0) {
        if ((ciphertext = malloc(plaintext_len)) == NULL) {
            charra_r = CHARRA_RC_ERROR;
            goto cleanup_rng;
        }
    }

    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);
    if ((mbedtls_r = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key,
                 CHARRA_AES256GCM_KEY_LEN * 8)) != 0) {
        charra_log_error("mbedtls_gcm_setkey: mbedtls error %d", mbedtls_r);
        charra_r = CHARRA_RC_CRYPTO_ERROR;
        goto cleanup_gcm;
    }

    if ((mbedtls_r = mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT,
                 plaintext_len, nonce_out, CHARRA_AES256GCM_NONCE_LEN, NULL,
                 0, plaintext, ciphertext, CHARRA_AES256GCM_TAG_LEN,
                 tag_out)) != 0) {
        charra_log_error(
                "mbedtls_gcm_crypt_and_tag: mbedtls error %d", mbedtls_r);
        charra_r = CHARRA_RC_CRYPTO_ERROR;
        goto cleanup_gcm;
    }

    *ciphertext_out = ciphertext;
    ciphertext = NULL;

cleanup_gcm:
    mbedtls_gcm_free(&gcm);
    if (charra_r != CHARRA_RC_SUCCESS) {
        free(ciphertext);
    }
cleanup_rng:
    charra_crypto_seeded_rng_free(&ctr_drbg, &entropy);
    return charra_r;
}

CHARRA_RC charra_crypto_aes256gcm_decrypt(
        const uint8_t key[CHARRA_AES256GCM_KEY_LEN],
        const uint8_t* ciphertext, size_t ciphertext_len,
        const uint8_t nonce[CHARRA_AES256GCM_NONCE_LEN],
        const uint8_t tag[CHARRA_AES256GCM_TAG_LEN], uint8_t** plaintext_out) {
    if (key == NULL || (ciphertext == NULL && ciphertext_len > 0) ||
            nonce == NULL || tag == NULL || plaintext_out == NULL) {
        return CHARRA_RC_BAD_ARGUMENT;
    }
    *plaintext_out = NULL;

    CHARRA_RC charra_r = CHARRA_RC_SUCCESS;
    int mbedtls_r = 0;

    uint8_t* plaintext = NULL;
    if (ciphertext_len > 0) {
        if ((plaintext = malloc(ciphertext_len)) == NULL) {
            return CHARRA_RC_ERROR;
        }
    }

    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);
    if ((mbedtls_r = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key,
                 CHARRA_AES256GCM_KEY_LEN * 8)) != 0) {
        charra_log_error("mbedtls_gcm_setkey: mbedtls error %d", mbedtls_r);
        charra_r = CHARRA_RC_CRYPTO_ERROR;
        goto cleanup;
    }

    if ((mbedtls_r = mbedtls_gcm_auth_decrypt(&gcm, ciphertext_len, nonce,
                 CHARRA_AES256GCM_NONCE_LEN, NULL, 0, tag,
                 CHARRA_AES256GCM_TAG_LEN, ciphertext, plaintext)) != 0) {
        if (mbedtls_r == MBEDTLS_ERR_GCM_AUTH_FAILED) {
            charra_r = CHARRA_RC_VERIFICATION_FAILED;
        } else {
            charra_log_error(
                    "mbedtls_gcm_auth_decrypt: mbedtls error %d", mbedtls_r);
            charra_r = CHARRA_RC_CRYPTO_ERROR;
        }
        goto cleanup;
    }

    *plaintext_out = plaintext;
    plaintext = NULL;

cleanup:
    mbedtls_gcm_free(&gcm);
    if (charra_r != CHARRA_RC_SUCCESS) {
        free(plaintext);
    }
    return charra_r;
}
