/**
 * @file TEE.c
 * @brief See TEE.h.
 */

#include "TEE.h"

#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#include "../common/charra_log.h"
#include "../util/io_util.h"

#define LOG_NAME "TEE"

CHARRA_RC tee_hash_files(const char* const* file_paths, size_t file_count,
        uint8_t hash_out[TPM2_SHA256_DIGEST_SIZE]) {
    if (file_paths == NULL || file_count == 0 || hash_out == NULL) {
        return CHARRA_RC_BAD_ARGUMENT;
    }

    /* Concatenate every given file's bytes, in the order given, into one
     * buffer and hash it once -- these are small source files (tens of KB
     * total), so there is no reason to reach for an incremental hash API
     * that nothing else in the codebase uses. */
    uint8_t* combined = NULL;
    size_t combined_len = 0;
    CHARRA_RC result = CHARRA_RC_SUCCESS;

    for (size_t i = 0; i < file_count; i++) {
        char* content = NULL;
        size_t content_len = 0;
        if (charra_io_read_file(file_paths[i], &content, &content_len) !=
                CHARRA_RC_SUCCESS) {
            charra_log_error(
                    "[" LOG_NAME "] Could not read file to measure '%s'.",
                    file_paths[i]);
            result = CHARRA_RC_ERROR;
            break;
        }

        uint8_t* grown = realloc(combined, combined_len + content_len);
        if (grown == NULL) {
            charra_io_free_file_buffer(&content);
            result = CHARRA_RC_ERROR;
            break;
        }
        combined = grown;
        memcpy(combined + combined_len, content, content_len);
        combined_len += content_len;
        charra_io_free_file_buffer(&content);
    }

    if (result == CHARRA_RC_SUCCESS) {
        result = hash_sha256(combined_len, combined, hash_out);
    }
    free(combined);
    return result;
}

CHARRA_RC tee_attestation(const char* const* file_paths, size_t file_count,
        const uint8_t report_data[TPM2_SHA256_DIGEST_SIZE],
        tee_attestation_document* doc_out) {
    if (report_data == NULL || doc_out == NULL) {
        return CHARRA_RC_BAD_ARGUMENT;
    }

    CHARRA_RC result =
            tee_hash_files(file_paths, file_count, doc_out->file_hash);
    if (result != CHARRA_RC_SUCCESS) {
        charra_log_error(
                "[" LOG_NAME "] Could not measure the given files; "
                "refusing to attest.");
        return result;
    }
    memcpy(doc_out->report_data, report_data, TPM2_SHA256_DIGEST_SIZE);
    return CHARRA_RC_SUCCESS;
}

/* --- the TEE's private key: never read from outside this file ----------
 * Generated lazily, once per process, the first time it is needed -- same
 * pattern the RP's own AK keypair uses (ensure_rp_ak_keypair() in
 * rp_identity.c), and for the same reason: a fresh identity per process run
 * is a fine simplification for a PoC, and it means there is no key file on
 * disk to provision or protect. Guarded by one mutex covering both
 * generation and every use, since mbedTLS's RSA context is not safe for
 * concurrent signing from multiple threads and the RP appraises for several
 * Verifiers concurrently. */
static pthread_mutex_t tee_key_mutex = PTHREAD_MUTEX_INITIALIZER;
static bool tee_key_ready = false;
static mbedtls_pk_context tee_key;
static uint8_t tee_key_public_der[CHARRA_RSA_PUB_KEY_DER_MAX];
static uint32_t tee_key_public_der_len = 0;

/** Must be called with tee_key_mutex held. */
static CHARRA_RC tee_ensure_keypair_locked(void) {
    if (tee_key_ready) {
        return CHARRA_RC_SUCCESS;
    }
    CHARRA_RC result = charra_crypto_rsa_generate_keypair(&tee_key);
    if (result != CHARRA_RC_SUCCESS) {
        charra_log_error(
                "[" LOG_NAME "] Could not generate the TEE's keypair.");
        return result;
    }
    result = charra_crypto_rsa_public_key_to_der(&tee_key, tee_key_public_der,
            sizeof(tee_key_public_der), &tee_key_public_der_len);
    if (result != CHARRA_RC_SUCCESS) {
        charra_log_error(
                "[" LOG_NAME "] Could not DER-encode the TEE's public key.");
        return result;
    }
    tee_key_ready = true;
    return CHARRA_RC_SUCCESS;
}

CHARRA_RC tee_sign(const tee_attestation_document* doc,
        uint8_t signature_out[CHARRA_RSA_SIGNATURE_LEN]) {
    if (doc == NULL || signature_out == NULL) {
        return CHARRA_RC_BAD_ARGUMENT;
    }

    uint8_t signed_data[sizeof(doc->file_hash) + sizeof(doc->report_data)];
    memcpy(signed_data, doc->file_hash, sizeof(doc->file_hash));
    memcpy(signed_data + sizeof(doc->file_hash), doc->report_data,
            sizeof(doc->report_data));

    pthread_mutex_lock(&tee_key_mutex);
    CHARRA_RC result = tee_ensure_keypair_locked();
    if (result == CHARRA_RC_SUCCESS) {
        result = charra_crypto_rsa_sign(
                &tee_key, signed_data, sizeof(signed_data), signature_out);
    }
    pthread_mutex_unlock(&tee_key_mutex);
    return result;
}

CHARRA_RC tee_public_key_der(uint8_t* der_out, size_t der_out_size,
        uint32_t* der_len_out) {
    if (der_out == NULL || der_len_out == NULL) {
        return CHARRA_RC_BAD_ARGUMENT;
    }

    pthread_mutex_lock(&tee_key_mutex);
    CHARRA_RC result = tee_ensure_keypair_locked();
    if (result == CHARRA_RC_SUCCESS) {
        if (der_out_size < tee_key_public_der_len) {
            result = CHARRA_RC_BAD_ARGUMENT;
        } else {
            memcpy(der_out, tee_key_public_der, tee_key_public_der_len);
            *der_len_out = tee_key_public_der_len;
        }
    }
    pthread_mutex_unlock(&tee_key_mutex);
    return result;
}
