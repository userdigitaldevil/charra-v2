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
#include "../core/charra_event_log.h"
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
/**
 * @brief Open a TPM connection, deriving nothing.
 *
 * Split out because replaying a log into a PCR needs a connection but no
 * key: PCR_Reset and PCR_Extend authorise against the PCR, not against an
 * object. Deriving an RSA-2048 primary just to throw it away would add a
 * measurable cost to an operation that never uses it.
 */
static CHARRA_RC open_tpm(
        ESYS_CONTEXT** esys_ctx_out, TSS2_TCTI_CONTEXT** tcti_ctx_out) {
    *esys_ctx_out = NULL;
    *tcti_ctx_out = NULL;

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

    *esys_ctx_out = esys_ctx;
    *tcti_ctx_out = tcti_ctx;
    return CHARRA_RC_SUCCESS;
}

static CHARRA_RC open_tpm_and_derive_key(ESYS_CONTEXT** esys_ctx_out,
        TSS2_TCTI_CONTEXT** tcti_ctx_out, ESYS_TR* key_handle_out,
        TPM2B_PUBLIC** key_public_out) {
    *key_handle_out = ESYS_TR_NONE;
    if (key_public_out != NULL) {
        *key_public_out = NULL;
    }

    ESYS_CONTEXT* esys_ctx = NULL;
    TSS2_TCTI_CONTEXT* tcti_ctx = NULL;
    CHARRA_RC charra_r = open_tpm(&esys_ctx, &tcti_ctx);
    if (charra_r != CHARRA_RC_SUCCESS) {
        return charra_r;
    }

    TSS2_RC tss_r = TSS2_RC_SUCCESS;
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

/**
 * @brief Extend one digest into RP_REPLAY_PCR_INDEX.
 *
 * The log carries SHA-1 or SHA-256 template digests; the PCR bank is
 * SHA-256. A SHA-1 digest is zero-padded to 32 bytes, which is exactly
 * what charra_pcr_extend() does in software, so the two replays agree.
 */
static TSS2_RC extend_one(
        ESYS_CONTEXT* ctx, const uint8_t* digest, uint16_t digest_len) {
    TPML_DIGEST_VALUES values = {.count = 1,
            .digests = {{.hashAlg = TPM2_ALG_SHA256, .digest = {{0}}}}};
    if (digest_len > TPM2_SHA256_DIGEST_SIZE) {
        return TSS2_ESYS_RC_BAD_VALUE;
    }
    memcpy(values.digests[0].digest.sha256, digest, digest_len);
    return tpm2_pcr_extend(ctx, RP_REPLAY_PCR_INDEX, &values);
}

CHARRA_RC rp_replay_log_into_pcr(const uint8_t* log, uint32_t log_len) {
    if (log == NULL && log_len != 0) {
        return CHARRA_RC_BAD_ARGUMENT;
    }

    /* Which digest size this log uses -- decided before the TPM is opened,
     * so a malformed log costs no TPM round trip. */
    uint16_t digest_len = 0;
    if (log_len != 0 &&
            charra_event_log_ima_detect_digest_len(log, log_len, &digest_len) !=
                    CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] log_r does not parse; cannot replay "
                         "it into a PCR.");
        return CHARRA_RC_MARSHALING_ERROR;
    }

    pthread_mutex_lock(&rp_tpm_mutex);

    ESYS_CONTEXT* esys_ctx = NULL;
    TSS2_TCTI_CONTEXT* tcti_ctx = NULL;
    CHARRA_RC charra_r = open_tpm(&esys_ctx, &tcti_ctx);
    if (charra_r != CHARRA_RC_SUCCESS) {
        pthread_mutex_unlock(&rp_tpm_mutex);
        return charra_r;
    }
    charra_r = CHARRA_RC_TPM;

    /* Rewind first: the PCR still holds the previous cycle's replay, and
     * extending on top of it would attest a value matching no log at all. */
    TSS2_RC tss_r = tpm2_pcr_reset(esys_ctx, RP_REPLAY_PCR_INDEX);
    if (tss_r != TSS2_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Could not reset PCR %d: 0x%x.",
                RP_REPLAY_PCR_INDEX, tss_r);
        goto cleanup;
    }

    uint32_t offset = 0;
    uint32_t extended = 0;
    while (offset < log_len) {
        charra_event_log_entry entry = {0};
        if (charra_event_log_parse_entry(
                    log, log_len, &offset, digest_len, &entry) !=
                CHARRA_RC_SUCCESS) {
            charra_log_error("[" LOG_NAME "] log_r is malformed at byte %u.",
                    offset);
            charra_r = CHARRA_RC_MARSHALING_ERROR;
            goto cleanup;
        }
        if (entry.pcr_index != CHARRA_IMA_PCR_INDEX) {
            continue;
        }
        if ((tss_r = extend_one(esys_ctx, entry.template_digest,
                     entry.template_digest_len)) != TSS2_RC_SUCCESS) {
            charra_log_error("[" LOG_NAME "] Could not extend PCR %d: 0x%x.",
                    RP_REPLAY_PCR_INDEX, tss_r);
            charra_r = CHARRA_RC_TPM;
            goto cleanup;
        }
        extended++;
    }

    charra_log_info("[" LOG_NAME "] Replayed %u log_r entr(ies) into PCR %d; "
                    "every Verifier this cycle quotes that one replay.",
            extended, RP_REPLAY_PCR_INDEX);
    charra_r = CHARRA_RC_SUCCESS;

cleanup:
    Esys_Finalize(&esys_ctx);
    Tss2_TctiLdr_Finalize(&tcti_ctx);
    pthread_mutex_unlock(&rp_tpm_mutex);
    return charra_r;
}

CHARRA_RC rp_quote_pcr_with_ak(const uint8_t* nonce, uint32_t nonce_len,
        uint8_t* attest_out, uint32_t attest_cap, uint32_t* attest_len_out,
        uint8_t* signature_out, TPM2B_PUBLIC* ak_public_key_out) {
    if (nonce == NULL || nonce_len == 0 || attest_out == NULL ||
            attest_len_out == NULL || signature_out == NULL) {
        return CHARRA_RC_BAD_ARGUMENT;
    }
    if (nonce_len > sizeof(((TPM2B_DATA*)0)->buffer)) {
        charra_log_error("[" LOG_NAME "] Nonce too long for qualifyingData.");
        return CHARRA_RC_BAD_ARGUMENT;
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
    if (ak_public_key_out != NULL) {
        *ak_public_key_out = *key_public;
    }
    Esys_Free(key_public);

    TPM2B_ATTEST* attest = NULL;
    TPMT_SIGNATURE* signature = NULL;
    charra_r = CHARRA_RC_TPM;

    TPML_PCR_SELECTION selection = {.count = 1,
            .pcrSelections = {{.hash = TPM2_ALG_SHA256, .sizeofSelect = 3,
                    .pcrSelect = {0, 0, 0}}}};
    selection.pcrSelections[0].pcrSelect[RP_REPLAY_PCR_INDEX / 8] =
            (BYTE)(1 << (RP_REPLAY_PCR_INDEX % 8));

    TPM2B_DATA qualifying_data = {.size = (UINT16)nonce_len};
    memcpy(qualifying_data.buffer, nonce, nonce_len);

    TSS2_RC tss_r = tpm2_quote(esys_ctx, key_handle, &selection,
            &qualifying_data, &attest, &signature);
    if (tss_r != TSS2_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] TPM2_Quote over PCR %d failed: 0x%x.",
                RP_REPLAY_PCR_INDEX, tss_r);
        goto cleanup;
    }

    if (attest->size > attest_cap) {
        charra_log_error("[" LOG_NAME "] Quote_r attestation data is %u bytes, "
                         "larger than the %u-byte field carrying it.",
                attest->size, attest_cap);
        charra_r = CHARRA_RC_ERROR;
        goto cleanup;
    }
    memcpy(attest_out, attest->attestationData, attest->size);
    *attest_len_out = attest->size;
    memcpy(signature_out, signature->signature.rsapss.sig.buffer,
            signature->signature.rsapss.sig.size);
    charra_r = CHARRA_RC_SUCCESS;

cleanup:
    if (attest != NULL) {
        Esys_Free(attest);
    }
    if (signature != NULL) {
        Esys_Free(signature);
    }
    Esys_FlushContext(esys_ctx, key_handle);
    Esys_Finalize(&esys_ctx);
    Tss2_TctiLdr_Finalize(&tcti_ctx);
    pthread_mutex_unlock(&rp_tpm_mutex);
    return charra_r;
}
