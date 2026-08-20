/**
 * @file rp_signing_key.c
 * @brief See rp_signing_key.h.
 */

#include "rp_signing_key.h"

#include <pthread.h>
#include <string.h>

#include <tss2/tss2_esys.h>
#include <tss2/tss2_tctildr.h>

#include "../common/charra_log.h"
#include "../util/crypto_util.h"
#include "../util/tpm2_util.h"
#include "rp_shared.h"

#define LOG_NAME "relying party"

/**
 * @brief Open a TPM connection and derive the signing primary on it.
 *
 * Caller owns the connection on success and must flush the handle, then
 * Esys_Finalize() and Tss2_TctiLdr_Finalize(). On failure nothing is left
 * open -- Esys_Finalize() tears down client-side state only, so an
 * orphaned handle would sit in the TPM's small transient-object table
 * until the TPM itself restarted.
 */
static CHARRA_RC open_tpm_and_derive_key(ESYS_CONTEXT** esys_ctx_out,
        TSS2_TCTI_CONTEXT** tcti_ctx_out, ESYS_TR* key_handle_out,
        TPM2B_PUBLIC** key_public_out) {
    *esys_ctx_out = NULL;
    *tcti_ctx_out = NULL;
    *key_handle_out = ESYS_TR_NONE;
    if (key_public_out != NULL) {
        *key_public_out = NULL;
    }

    TSS2_TCTI_CONTEXT* tcti_ctx = NULL;
    ESYS_CONTEXT* esys_ctx = NULL;

    TSS2_RC tss_r = Tss2_TctiLdr_Initialize(getenv("CHARRA_TCTI"), &tcti_ctx);
    if (tss_r != TSS2_RC_SUCCESS) {
        charra_log_error(
                "[" LOG_NAME "] Tss2_TctiLdr_Initialize failed: 0x%x.", tss_r);
        return CHARRA_RC_TPM;
    }
    if ((tss_r = Esys_Initialize(&esys_ctx, tcti_ctx, NULL)) !=
            TSS2_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Esys_Initialize failed: 0x%x.", tss_r);
        Tss2_TctiLdr_Finalize(&tcti_ctx);
        return CHARRA_RC_TPM;
    }

    ESYS_TR key_handle = ESYS_TR_NONE;
    TPM2B_PUBLIC* key_public = NULL;
    if ((tss_r = tpm2_create_primary_key_rsa2048_unrestricted(
                 esys_ctx, &key_handle, &key_public)) != TSS2_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Could not derive the RP's signing "
                         "key: 0x%x.",
                tss_r);
        Esys_Finalize(&esys_ctx);
        Tss2_TctiLdr_Finalize(&tcti_ctx);
        return CHARRA_RC_TPM;
    }

    *esys_ctx_out = esys_ctx;
    *tcti_ctx_out = tcti_ctx;
    *key_handle_out = key_handle;
    if (key_public_out != NULL) {
        *key_public_out = key_public;
    } else {
        Esys_Free(key_public);
    }
    return CHARRA_RC_SUCCESS;
}

CHARRA_RC rp_sign_with_ak(const uint8_t* data, size_t data_len,
        uint8_t* signature_out, TPM2B_PUBLIC* ak_public_key_out) {
    if (data == NULL || signature_out == NULL) {
        return CHARRA_RC_BAD_ARGUMENT;
    }

    uint8_t digest_bytes[TPM2_SHA256_DIGEST_SIZE] = {0};
    if (hash_sha256(data_len, data, digest_bytes) != CHARRA_RC_SUCCESS) {
        return CHARRA_RC_CRYPTO_ERROR;
    }

    pthread_mutex_lock(&rp_tpm_mutex);

    ESYS_CONTEXT* esys_ctx = NULL;
    TSS2_TCTI_CONTEXT* tcti_ctx = NULL;
    ESYS_TR key_handle = ESYS_TR_NONE;
    TPM2B_PUBLIC* key_public = NULL;
    CHARRA_RC charra_r = open_tpm_and_derive_key(
            &esys_ctx, &tcti_ctx, &key_handle, &key_public);
    if (charra_r != CHARRA_RC_SUCCESS) {
        pthread_mutex_unlock(&rp_tpm_mutex);
        return charra_r;
    }

    /* Taken from the same derivation that is about to sign, which is the
     * whole point: the caller cannot end up publishing a key its signature
     * does not verify under. */
    if (ak_public_key_out != NULL) {
        *ak_public_key_out = *key_public;
    }
    Esys_Free(key_public);

    TPM2B_DIGEST digest = {.size = sizeof(digest_bytes)};
    memcpy(digest.buffer, digest_bytes, sizeof(digest_bytes));

    TPMT_SIG_SCHEME scheme = {.scheme = TPM2_ALG_RSAPSS,
            .details.rsapss.hashAlg = TPM2_ALG_SHA256};

    /* Null ticket: tells the TPM this digest did NOT come from the TPM
     * itself -- required, and only accepted, because the key is
     * unrestricted. See this module's header. */
    TPMT_TK_HASHCHECK null_ticket = {
            .tag = TPM2_ST_HASHCHECK, .hierarchy = TPM2_RH_NULL, .digest = {0}};

    TPMT_SIGNATURE* signature = NULL;
    TSS2_RC tss_r = Esys_Sign(esys_ctx, key_handle, ESYS_TR_PASSWORD,
            ESYS_TR_NONE, ESYS_TR_NONE, &digest, &scheme, &null_ticket,
            &signature);

    Esys_FlushContext(esys_ctx, key_handle);
    Esys_Finalize(&esys_ctx);
    Tss2_TctiLdr_Finalize(&tcti_ctx);
    pthread_mutex_unlock(&rp_tpm_mutex);

    if (tss_r != TSS2_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Esys_Sign failed: 0x%x.", tss_r);
        return CHARRA_RC_TPM;
    }

    memcpy(signature_out, signature->signature.rsapss.sig.buffer,
            signature->signature.rsapss.sig.size);
    Esys_Free(signature);
    return CHARRA_RC_SUCCESS;
}
