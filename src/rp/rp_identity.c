/**
 * @file rp_identity.c
 * @brief See rp_identity.h.
 */

#include "rp_identity.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <mbedtls/x509_crt.h>
#include <tss2/tss2_tctildr.h>

#include "../common/charra_log.h"
#include "../common/charra_macro.h"
#include "../core/charra_ak_state.h"
#include "../core/charra_identity_key_mgr.h"
#include "../core/charra_marshaling.h"
#include "../util/crypto_util.h"
#include "../util/io_util.h"
#include "rp_coap.h"
#include "rp_shared.h"

#define LOG_NAME "relying party"

static coap_response_t coap_certify_ak_response_handler(
        coap_session_t* session CHARRA_UNUSED,
        const coap_pdu_t* sent CHARRA_UNUSED, const coap_pdu_t* received,
        const coap_mid_t mid CHARRA_UNUSED) {
    processing_certify_ak_response = true;

    int coap_r = 0;
    size_t data_len = 0;
    const uint8_t* data = NULL;
    size_t data_offset = 0;
    size_t data_total_len = 0;
    if ((coap_r = coap_get_data_large(
                 received, &data_len, &data, &data_offset, &data_total_len)) ==
            0) {
        charra_log_error(
                "[" LOG_NAME "] /certify_ak: Could not get CoAP PDU data.");
        certify_ak_rc = CHARRA_RC_ERROR;
        goto cleanup;
    }

    if ((certify_ak_rc = charra_unmarshal_certify_ak_response(
                 data_len, data, &certify_ak_response)) != CHARRA_RC_SUCCESS) {
        charra_log_error(
                "[" LOG_NAME "] /certify_ak: Could not parse CBOR response.");
        goto cleanup;
    }

cleanup:
    processing_certify_ak_response = false;
    return COAP_RESPONSE_OK;
}

/**
 * @brief One /certify_ak round trip (either leg -- req->kind picks which).
 *
 * Serialized on rp_ak_reprovision_mutex: certify_ak_response and friends
 * are shared globals. The response is snapshotted out before unlocking, so
 * ownership of its heap field moves to the caller and a sibling thread's
 * next call can't overwrite or free memory this one still needs. The mutex
 * is never held across the caller's TPM work, preserving the existing
 * "reprovision mutex, then TPM mutex, never nested" lock discipline.
 */
CHARRA_RC rp_certify_ak_exchange(const char* host, unsigned int port,
        const msg_certify_ak_request_dto* req,
        msg_certify_ak_response_dto* response_out) {
    uint8_t* req_buf = NULL;
    uint32_t req_buf_len = 0;
    CHARRA_RC result = charra_marshal_certify_ak_request(
            req, &req_buf_len, &req_buf);
    if (result != CHARRA_RC_SUCCESS) {
        charra_log_error(
                "[" LOG_NAME "] Could not marshal /certify_ak request.");
        return result;
    }

    pthread_mutex_lock(&rp_ak_reprovision_mutex);
    certify_ak_rc = CHARRA_RC_ERROR;
    memset(&certify_ak_response, 0, sizeof(certify_ak_response));

    result = rp_coap_exchange(&(rp_coap_request){
            .host = host, .port = port,
            .uri_path = "certify_ak",
            .body = req_buf, .body_len = req_buf_len,
            .on_response = coap_certify_ak_response_handler,
            .response_pending = &processing_certify_ak_response,
            .timeout_seconds = verifier_response_timeout,
            .dtls_rpk_peer_public_key_path = dtls_rpk_verifier_public_key_path,
        });
    free(req_buf);

    if (result == CHARRA_RC_SUCCESS && certify_ak_rc != CHARRA_RC_SUCCESS) {
        result = certify_ak_rc;
    }

    *response_out = certify_ak_response;
    certify_ak_response.ak_certificate = NULL;
    certify_ak_response.ak_certificate_len = 0;
    pthread_mutex_unlock(&rp_ak_reprovision_mutex);

    if (result != CHARRA_RC_SUCCESS) {
        charra_free_if_not_null(response_out->ak_certificate);
        memset(response_out, 0, sizeof(*response_out));
    }
    return result;
}

/**
 * @brief Open a fresh TPM connection, recreate RP's EK (deterministic --
 * see charra_identity_key_mgr_create_ek()), and load the AK from its persisted
 * public/private blobs. Caller must hold rp_tpm_mutex and Esys_Finalize()/
 * Tss2_TctiLdr_Finalize() the returned contexts when done -- this is the
 * short-lived-connection building block every TPM operation past initial
 * AK creation uses (provisioning's ActivateCredential step, and later
 * every Quote_r signing), so no single RP operation holds the TPM
 * simulator's one connection slot for longer than that operation itself
 * needs. See rp_tpm_mutex's own comment for why this matters.
 */
CHARRA_RC rp_open_tpm_and_load_ak(ESYS_CONTEXT** esys_ctx_out,
        TSS2_TCTI_CONTEXT** tcti_ctx_out, ESYS_TR* ek_handle_out,
        ESYS_TR* ak_handle_out, TPM2B_NAME** ak_name_out) {
    TSS2_RC tss_r = 0;
    if ((tss_r = Tss2_TctiLdr_Initialize(getenv("CHARRA_TCTI"), tcti_ctx_out)) !=
            TSS2_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Tss2_TctiLdr_Initialize.");
        return CHARRA_RC_ERROR;
    }
    if ((tss_r = Esys_Initialize(esys_ctx_out, *tcti_ctx_out, NULL)) !=
            TSS2_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Esys_Initialize.");
        Tss2_TctiLdr_Finalize(tcti_ctx_out);
        return CHARRA_RC_ERROR;
    }

    TPM2B_PUBLIC* ek_public = NULL;
    CHARRA_RC result = charra_identity_key_mgr_create_ek(
            *esys_ctx_out, ek_handle_out, &ek_public);
    Esys_Free(ek_public);
    if (result != CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Could not recreate RP's EK.");
        goto error;
    }

    TPM2B_PUBLIC ak_public = {0};
    TPM2B_PRIVATE ak_private = {0};
    if ((result = charra_identity_key_mgr_load_public(
                 rp_ak_public_path, &ak_public)) != CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Could not load AK public key.");
        goto error;
    }
    if ((result = charra_identity_key_mgr_load_private(
                 rp_ak_private_path, &ak_private)) != CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Could not load AK private area.");
        goto error;
    }
    if ((result = charra_identity_key_mgr_load_ak(*esys_ctx_out, *ek_handle_out,
                 &ak_public, &ak_private, ak_handle_out, ak_name_out)) !=
            CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Could not load RP's AK.");
        goto error;
    }
    return CHARRA_RC_SUCCESS;

error:
    /* Esys_Finalize() only tears down client-side state -- it does NOT
     * send TPM2_FlushContext, so any handle that did get loaded before the
     * failure (e.g. the EK, if only the AK's load failed) would otherwise
     * sit orphaned in the TPM's small transient-object table until the
     * simulator itself is restarted. Flush anything that's actually valid
     * before closing. */
    if (*ek_handle_out != ESYS_TR_NONE) {
        Esys_FlushContext(*esys_ctx_out, *ek_handle_out);
    }
    if (*ak_handle_out != ESYS_TR_NONE) {
        Esys_FlushContext(*esys_ctx_out, *ak_handle_out);
    }
    Esys_Finalize(esys_ctx_out);
    Tss2_TctiLdr_Finalize(tcti_ctx_out);
    return result;
}

/**
 * @brief Mint RP's own EK certificate under the synthetic manufacturer CA,
 * or reload the one cached from a previous run.
 *
 * charra_identity_key_mgr_create_ek() reproduces the same EK every time, so
 * the certificate only ever has to be minted once. A real device would never
 * hold the manufacturer key itself -- it is burned in at TPM-manufacture
 * time -- but this synthetic PKI has no manufacturer, the same simplification
 * /certify_ak's own EK check already documents.
 */
static CHARRA_RC rp_ensure_ek_certificate(TPM2B_PUBLIC* ek_public) {
    if (charra_io_file_exists(rp_ek_cert_cache_path) == CHARRA_RC_SUCCESS) {
        return CHARRA_RC_SUCCESS; /* already minted by an earlier run */
    }

    CHARRA_RC result = CHARRA_RC_ERROR;
    char* manufacturer_root_der = NULL;
    size_t manufacturer_root_der_len = 0;
    mbedtls_x509_crt manufacturer_root_cert;
    bool root_cert_inited = false;
    uint8_t* ek_cert_der = NULL;

    if ((result = charra_io_read_file(manufacturer_root_cert_path,
                 &manufacturer_root_der, &manufacturer_root_der_len)) !=
            CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Could not read the manufacturer root "
                         "certificate ('%s').",
                manufacturer_root_cert_path);
        goto cleanup;
    }

    mbedtls_x509_crt_init(&manufacturer_root_cert);
    root_cert_inited = true;
    if (mbedtls_x509_crt_parse(&manufacturer_root_cert,
                (uint8_t*)manufacturer_root_der,
                manufacturer_root_der_len) != 0) {
        charra_log_error("[" LOG_NAME "] Could not parse the manufacturer "
                         "root certificate.");
        result = CHARRA_RC_CRYPTO_ERROR;
        goto cleanup;
    }

    char issuer_name[256] = {0};
    if (mbedtls_x509_dn_gets(issuer_name, sizeof(issuer_name),
                &manufacturer_root_cert.subject) <= 0) {
        charra_log_error("[" LOG_NAME "] Could not read the manufacturer root "
                         "subject name.");
        result = CHARRA_RC_CRYPTO_ERROR;
        goto cleanup;
    }

    uint8_t ek_serial[CHARRA_AK_STATE_SERIAL_LEN] = {0};
    uint32_t ek_cert_der_len = 0;
    if ((result = charra_crypto_sign_ak_certificate(ek_public,
                 "CN=CHARRA RP EK (test only)", issuer_name,
                 rp_ek_cert_not_before_utc, rp_ek_cert_not_after_utc,
                 manufacturer_root_key_path, &ek_cert_der, &ek_cert_der_len,
                 ek_serial)) != CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Could not mint RP's EK certificate.");
        goto cleanup;
    }
    if ((result = charra_io_write_file(rp_ek_cert_cache_path, ek_cert_der,
                 ek_cert_der_len)) != CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Could not cache RP's EK certificate.");
        goto cleanup;
    }

cleanup:
    charra_free_if_not_null(ek_cert_der);
    if (root_cert_inited) {
        mbedtls_x509_crt_free(&manufacturer_root_cert);
    }
    charra_io_free_file_buffer(&manufacturer_root_der);
    return result;
}

/**
 * @brief Create the TPM-resident EK+AK pair and persist the AK's blobs.
 *
 * One exit path, so no error can skip a flush: Esys_Finalize() tears down
 * client-side state only -- it does not send TPM2_FlushContext -- and every
 * handle left unflushed sits in the TPM's small transient-object table until
 * the simulator is restarted.
 */
static CHARRA_RC rp_create_and_persist_ak(TPM2B_PUBLIC* ak_public_out) {
    CHARRA_RC result = CHARRA_RC_ERROR;
    ESYS_CONTEXT* esys_ctx = NULL;
    TSS2_TCTI_CONTEXT* tcti_ctx = NULL;
    ESYS_TR ek_handle = ESYS_TR_NONE;
    ESYS_TR ak_handle = ESYS_TR_NONE;
    TPM2B_PUBLIC* ek_public = NULL;
    TPM2B_PUBLIC* ak_public = NULL;
    TPM2B_PRIVATE* ak_private = NULL;
    TPM2B_NAME* ak_name = NULL;

    if (Tss2_TctiLdr_Initialize(getenv("CHARRA_TCTI"), &tcti_ctx) !=
            TSS2_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Tss2_TctiLdr_Initialize.");
        return CHARRA_RC_ERROR;
    }
    if (Esys_Initialize(&esys_ctx, tcti_ctx, NULL) != TSS2_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Esys_Initialize.");
        Tss2_TctiLdr_Finalize(&tcti_ctx);
        return CHARRA_RC_ERROR;
    }

    if ((result = charra_identity_key_mgr_create_ek(
                 esys_ctx, &ek_handle, &ek_public)) != CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Could not create RP's EK.");
        goto cleanup;
    }
    if ((result = rp_ensure_ek_certificate(ek_public)) != CHARRA_RC_SUCCESS) {
        goto cleanup;
    }
    if ((result = charra_identity_key_mgr_create_ak(esys_ctx, ek_handle,
                 &ak_handle, &ak_public, &ak_private, &ak_name)) !=
            CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Could not create RP's AK.");
        goto cleanup;
    }
    if ((result = charra_identity_key_mgr_save_public(
                 rp_ak_public_path, ak_public)) != CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Could not persist the AK public key.");
        goto cleanup;
    }
    if ((result = charra_identity_key_mgr_save_private(
                 rp_ak_private_path, ak_private)) != CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Could not persist the AK private area.");
        goto cleanup;
    }
    *ak_public_out = *ak_public;
    result = CHARRA_RC_SUCCESS;

cleanup:
    Esys_Free(ek_public);
    Esys_Free(ak_public);
    Esys_Free(ak_private);
    Esys_Free(ak_name);
    if (ak_handle != ESYS_TR_NONE) {
        Esys_FlushContext(esys_ctx, ak_handle);
    }
    if (ek_handle != ESYS_TR_NONE) {
        Esys_FlushContext(esys_ctx, ek_handle);
    }
    Esys_Finalize(&esys_ctx);
    Tss2_TctiLdr_Finalize(&tcti_ctx);
    return result;
}

CHARRA_RC ensure_rp_ak_keypair(void) {
    pthread_mutex_lock(&rp_tpm_mutex);
    if (rp_ak_keypair_ready) {
        pthread_mutex_unlock(&rp_tpm_mutex);
        return CHARRA_RC_SUCCESS;
    }

    charra_log_info(
            "[" LOG_NAME "]  +------------ RP TPM Identity --------------+");

    CHARRA_RC result = CHARRA_RC_ERROR;
    TPM2B_PUBLIC ak_public = {0};
    const bool cached =
            charra_io_file_exists(rp_ak_public_path) == CHARRA_RC_SUCCESS &&
            charra_io_file_exists(rp_ak_private_path) == CHARRA_RC_SUCCESS;

    if (cached) {
        /* Pure file read -- no TPM needed. The AK is only loaded into the TPM
         * when actually signing or certifying (rp_open_tpm_and_load_ak()). */
        charra_log_info("[" LOG_NAME "] Reloading the previously provisioned "
                        "RP AK keypair.");
        result = charra_identity_key_mgr_load_public(
                rp_ak_public_path, &ak_public);
        if (result != CHARRA_RC_SUCCESS) {
            charra_log_error(
                    "[" LOG_NAME "] Could not load the cached AK public key.");
            goto cleanup;
        }
    } else {
        charra_log_info(
                "[" LOG_NAME "] No cached RP AK keypair -- creating one.");
        if ((result = rp_create_and_persist_ak(&ak_public)) !=
                CHARRA_RC_SUCCESS) {
            goto cleanup;
        }
    }

    if ((result = charra_identity_key_mgr_public_key_to_der(&ak_public,
                 rp_public_key_der, sizeof(rp_public_key_der),
                 &rp_public_key_der_len)) != CHARRA_RC_SUCCESS) {
        charra_log_error(
                "[" LOG_NAME "] Could not DER-encode RP's AK public key.");
        goto cleanup;
    }
    rp_ak_keypair_ready = true;

cleanup:
    pthread_mutex_unlock(&rp_tpm_mutex);
    return result;
}


/**
 * @brief Fill in a /certify_ak CHALLENGE request from the persisted AK.
 *
 * Opens its own short-lived TPM connection and closes it before returning,
 * which is critical rather than tidy: the Verifier's /certify_ak handler
 * needs its own connection for Esys_MakeCredential, and the dev TPM
 * simulator serves one client at a time. Holding this open across the CoAP
 * wait deadlocked the Verifier outright -- observed directly, killing the
 * stuck RP unblocked a handler that had been sitting mid-MakeCredential.
 */
static CHARRA_RC rp_build_certify_ak_challenge_request(
        const char* ek_cert, size_t ek_cert_len,
        msg_certify_ak_request_dto* request_out) {
    CHARRA_RC result = CHARRA_RC_ERROR;
    ESYS_CONTEXT* esys_ctx = NULL;
    TSS2_TCTI_CONTEXT* tcti_ctx = NULL;
    ESYS_TR ek_handle = ESYS_TR_NONE;
    ESYS_TR ak_handle = ESYS_TR_NONE;
    TPM2B_NAME* ak_name = NULL;
    TPM2B_PUBLIC ak_public = {0};

    pthread_mutex_lock(&rp_tpm_mutex);
    if ((result = rp_open_tpm_and_load_ak(&esys_ctx, &tcti_ctx, &ek_handle,
                 &ak_handle, &ak_name)) != CHARRA_RC_SUCCESS) {
        charra_log_error(
                "[" LOG_NAME "] Could not open a TPM connection to load RP's AK.");
        pthread_mutex_unlock(&rp_tpm_mutex);
        return result;
    }

    if ((result = charra_identity_key_mgr_load_public(
                 rp_ak_public_path, &ak_public)) != CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Could not load the AK public key for "
                         "the /certify_ak request.");
        goto cleanup;
    }

    request_out->kind = CHARRA_CERTIFY_AK_CHALLENGE;
    request_out->subject = CHARRA_CERTIFY_AK_SUBJECT_RP;
    request_out->ek_certificate = (uint8_t*)ek_cert;
    request_out->ek_certificate_len = (uint32_t)ek_cert_len;
    request_out->ak_public_key_len = sizeof(ak_public);
    memcpy(request_out->ak_public_key, &ak_public, sizeof(ak_public));
    /* Copy only the meaningful prefix (size field + size bytes) and zero the
     * rest: Esys_TR_GetName() leaves the tail of the TPM2B_NAME allocation
     * uninitialised, and copying the whole struct put those heap bytes
     * straight onto the wire (caught by valgrind, via libcoap reading them
     * while building the PDU). The field stays fixed-size, so the wire format
     * is unchanged -- the tail is deterministic zeros instead of stale heap. */
    request_out->ak_name_len = sizeof(*ak_name);
    memset(request_out->ak_name, 0, sizeof(request_out->ak_name));
    memcpy(request_out->ak_name, ak_name,
            sizeof(ak_name->size) + ak_name->size);
    result = CHARRA_RC_SUCCESS;

cleanup:
    Esys_Free(ak_name);
    Esys_FlushContext(esys_ctx, ak_handle);
    Esys_FlushContext(esys_ctx, ek_handle);
    Esys_Finalize(&esys_ctx);
    Tss2_TctiLdr_Finalize(&tcti_ctx);
    pthread_mutex_unlock(&rp_tpm_mutex);
    return result;
}

/**
 * @brief Recover the CHALLENGE secret with TPM2_ActivateCredential.
 *
 * Only the TPM holding the EK this challenge was wrapped to can do this,
 * which is exactly what the Verifier's CONFIRM leg then checks.
 * *secret_out is Esys-allocated; the caller frees it with Esys_Free().
 */
static CHARRA_RC rp_activate_challenge_credential(
        const msg_certify_ak_response_dto* challenge,
        TPM2B_DIGEST** secret_out) {
    CHARRA_RC result = CHARRA_RC_ERROR;
    ESYS_CONTEXT* esys_ctx = NULL;
    TSS2_TCTI_CONTEXT* tcti_ctx = NULL;
    ESYS_TR ek_handle = ESYS_TR_NONE;
    ESYS_TR ak_handle = ESYS_TR_NONE;
    TPM2B_NAME* ak_name = NULL;

    pthread_mutex_lock(&rp_tpm_mutex);
    if ((result = rp_open_tpm_and_load_ak(&esys_ctx, &tcti_ctx, &ek_handle,
                 &ak_handle, &ak_name)) != CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Could not reopen the TPM connection "
                         "for ActivateCredential.");
        pthread_mutex_unlock(&rp_tpm_mutex);
        return result;
    }
    Esys_Free(ak_name);

    if ((result = charra_identity_key_mgr_activate_credential(esys_ctx,
                 ak_handle, ek_handle,
                 (TPM2B_ID_OBJECT*)challenge->credential_blob,
                 (TPM2B_ENCRYPTED_SECRET*)challenge->wrapped_secret,
                 secret_out)) != CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] ActivateCredential failed -- this AK "
                         "is not genuinely bound to this EK, or the TPM "
                         "rejected the request.");
    }

    Esys_FlushContext(esys_ctx, ak_handle);
    Esys_FlushContext(esys_ctx, ek_handle);
    Esys_Finalize(&esys_ctx);
    Tss2_TctiLdr_Finalize(&tcti_ctx);
    pthread_mutex_unlock(&rp_tpm_mutex);
    return result;
}

CHARRA_RC ensure_rp_ak_certificate(int verifier_index) {
    /* Cleared up front, not only set on the cache-hit paths: leaving a stale
     * true here made the run summary report "cached" forever once the first
     * cache hit had happened, including on cycles that re-issued. */
    rp_ak_cert_was_cached[verifier_index] = false;

    if (rp_ak_cert_ready[verifier_index] &&
            !charra_cert_needs_renewal(rp_ak_cert_expires_at[verifier_index])) {
        /* No work happens on this path, so it's "cached" for the summary. */
        rp_ak_cert_was_cached[verifier_index] = true;
        return CHARRA_RC_SUCCESS;
    }
    if (rp_ak_cert_ready[verifier_index]) {
        /* Held in memory but expiring: a long-running daemon has to notice
         * this, so the check is on every call rather than at startup. */
        charra_log_info("[" LOG_NAME "] In-memory AK certificate for Verifier "
                        "%d is near expiry -- re-provisioning.",
                verifier_index + 1);
        charra_free_if_not_null(rp_ak_cert_der[verifier_index]);
        rp_ak_cert_der[verifier_index] = NULL;
        rp_ak_cert_der_len[verifier_index] = 0;
        rp_ak_cert_ready[verifier_index] = false;
    }

    CHARRA_RC result = ensure_rp_ak_keypair();
    if (result != CHARRA_RC_SUCCESS) {
        return result;
    }

    const char* verifier_host = verifiers[verifier_index].ip_address;
    unsigned int verifier_port = verifiers[verifier_index].port_number;

    charra_log_info("[" LOG_NAME "]  +------------ RP AK Certificate "
                    "(Verifier %s:%u) --------------+",
            verifier_host, verifier_port);

    char cert_path[96] = {0};
    snprintf(cert_path, sizeof(cert_path),
            "state/relying-party/ak-certificates/rp-ak-certificate-%u.der",
            verifier_port);

    if (charra_io_file_exists(cert_path) == CHARRA_RC_SUCCESS) {
        char* cert_buf = NULL;
        size_t cert_buf_len = 0;
        if ((result = charra_io_read_file(cert_path, &cert_buf,
                     &cert_buf_len)) != CHARRA_RC_SUCCESS) {
            charra_log_error(
                    "[" LOG_NAME "] Could not read cached AK certificate.");
            return result;
        }
        uint8_t* cert_der = malloc(cert_buf_len);
        if (cert_der == NULL) {
            charra_io_free_file_buffer(&cert_buf);
            return CHARRA_RC_ERROR;
        }
        memcpy(cert_der, cert_buf, cert_buf_len);
        charra_io_free_file_buffer(&cert_buf);

        /* Expiry is acted on, not just printed: this cache is keyed on the
         * file existing, and the Verifier gives no separate signal for a
         * stale certificate -- it simply votes NO. Without this check an
         * expired certificate would be resent every cycle and rejected
         * every cycle, with nothing ever re-provisioning it. Renew slightly
         * early so it never lapses mid-cycle. */
        bool cache_usable = false;
        mbedtls_x509_crt cached_cert;
        mbedtls_x509_crt_init(&cached_cert);
        if (mbedtls_x509_crt_parse(&cached_cert, cert_der, cert_buf_len) ==
                0) {
            long days_left =
                    charra_crypto_x509_days_until_expiry(&cached_cert);
            if (!charra_cert_needs_renewal(
                        charra_crypto_x509_expiry_time(&cached_cert))) {
                cache_usable = true;
                rp_ak_cert_expires_at[verifier_index] =
                        charra_crypto_x509_expiry_time(&cached_cert);
                charra_log_info("[" LOG_NAME "] Reloading previously issued "
                                "AK certificate for this Verifier (cached, "
                                "expires in %ld day(s)).",
                        days_left);
            } else {
                charra_log_info("[" LOG_NAME "] Cached AK certificate for "
                                "this Verifier expires in %ld day(s) -- "
                                "re-provisioning via /certify_ak.",
                        days_left);
            }
        } else {
            charra_log_error("[" LOG_NAME "] Cached AK certificate for this "
                             "Verifier does not parse -- re-provisioning.");
        }
        mbedtls_x509_crt_free(&cached_cert);

        if (cache_usable) {
            rp_ak_cert_der[verifier_index] = cert_der;
            rp_ak_cert_der_len[verifier_index] = (uint32_t)cert_buf_len;
            rp_ak_cert_ready[verifier_index] = true;
            rp_ak_cert_was_cached[verifier_index] = true;
            return CHARRA_RC_SUCCESS;
        }
        charra_free_if_not_null(cert_der);
    }

    charra_log_info("[" LOG_NAME "] No cached AK certificate for this "
                    "Verifier -- provisioning via /certify_ak.");

    char* ek_cert_buf = NULL;
    size_t ek_cert_buf_len = 0;
    if ((result = charra_io_read_file(rp_ek_cert_cache_path, &ek_cert_buf,
                 &ek_cert_buf_len)) != CHARRA_RC_SUCCESS) {
        charra_log_error(
                "[" LOG_NAME "] Could not read RP's EK certificate.");
        return result;
    }

    msg_certify_ak_request_dto req = {0};
    if ((result = rp_build_certify_ak_challenge_request(
                 ek_cert_buf, ek_cert_buf_len, &req)) != CHARRA_RC_SUCCESS) {
        charra_io_free_file_buffer(&ek_cert_buf);
        return result;
    }

    charra_log_info("[" LOG_NAME "] /certify_ak: requesting a CHALLENGE ...");
    msg_certify_ak_response_dto challenge = {0};
    if ((result = rp_certify_ak_exchange(
                 verifier_host, verifier_port, &req, &challenge)) !=
            CHARRA_RC_SUCCESS) {
        charra_log_error(
                "[" LOG_NAME "] /certify_ak CHALLENGE leg did not complete.");
        charra_io_free_file_buffer(&ek_cert_buf);
        return result;
    }

    struct timespec activate_start, activate_end;
    clock_gettime(CLOCK_MONOTONIC, &activate_start);
    TPM2B_DIGEST* credential = NULL;
    result = rp_activate_challenge_credential(&challenge, &credential);
    clock_gettime(CLOCK_MONOTONIC, &activate_end);
    charra_free_if_not_null(challenge.ak_certificate);
    if (result != CHARRA_RC_SUCCESS) {
        charra_io_free_file_buffer(&ek_cert_buf);
        return result;
    }
    double activate_duration =
            (activate_end.tv_sec - activate_start.tv_sec) +
            (activate_end.tv_nsec - activate_start.tv_nsec) / 1e9;

    charra_log_info("[" LOG_NAME "] ActivateCredential recovered the %u-byte "
                    "challenge secret in %.3fs.",
            credential->size, activate_duration);

    if (credential->size != CHARRA_CERTIFY_AK_SECRET_LEN) {
        charra_log_error("[" LOG_NAME "] Recovered secret has unexpected "
                         "size %u (expected %d).",
                credential->size, CHARRA_CERTIFY_AK_SECRET_LEN);
        Esys_Free(credential);
        charra_io_free_file_buffer(&ek_cert_buf);
        return CHARRA_RC_VERIFICATION_FAILED;
    }

    /* --- CONFIRM: echo the secret back. Only on a match does the Verifier
     * sign, record, and release the certificate. ------------------------- */
    msg_certify_ak_request_dto confirm_req = {0};
    confirm_req.kind = CHARRA_CERTIFY_AK_CONFIRM;
    confirm_req.ek_certificate = (uint8_t*)ek_cert_buf;
    confirm_req.ek_certificate_len = (uint32_t)ek_cert_buf_len;
    confirm_req.secret_len = credential->size;
    memcpy(confirm_req.secret, credential->buffer, credential->size);
    Esys_Free(credential);

    charra_log_info("[" LOG_NAME "] /certify_ak: echoing the secret back "
                    "(CONFIRM) ...");
    msg_certify_ak_response_dto confirmed = {0};
    result = rp_certify_ak_exchange(
            verifier_host, verifier_port, &confirm_req, &confirmed);
    charra_io_free_file_buffer(&ek_cert_buf);
    if (result != CHARRA_RC_SUCCESS) {
        charra_log_error(
                "[" LOG_NAME "] /certify_ak CONFIRM leg did not complete.");
        return result;
    }
    if (confirmed.ak_certificate_len == 0 ||
            confirmed.ak_certificate == NULL) {
        charra_log_error("[" LOG_NAME "] /certify_ak CONFIRM returned no "
                         "certificate.");
        charra_free_if_not_null(confirmed.ak_certificate);
        return CHARRA_RC_ERROR;
    }

    uint8_t* cert_der = confirmed.ak_certificate;
    uint32_t cert_der_len = confirmed.ak_certificate_len;

    if ((result = charra_io_write_file(cert_path, cert_der, cert_der_len)) !=
            CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Could not cache AK certificate.");
        charra_free_if_not_null(cert_der);
        return result;
    }

    rp_ak_cert_der[verifier_index] = cert_der;
    rp_ak_cert_der_len[verifier_index] = cert_der_len;
    /* Record the freshly issued certificate's expiry too, not just the
     * cached one's: leaving it at 0 would mark this certificate as needing
     * renewal on the very next call, costing one pointless /certify_ak per
     * Verifier per process. */
    rp_ak_cert_expires_at[verifier_index] = 0;
    rp_ak_cert_ready[verifier_index] = true;

    /* One parse for both the expiry and the log line. Leaving expires_at at 0
     * would mark this certificate as due for renewal on the very next call,
     * costing a pointless /certify_ak per Verifier per process. */
    mbedtls_x509_crt issued;
    mbedtls_x509_crt_init(&issued);
    if (mbedtls_x509_crt_parse(&issued, cert_der, cert_der_len) == 0) {
        rp_ak_cert_expires_at[verifier_index] = charra_crypto_x509_expiry_time(&issued);
        charra_log_info("[" LOG_NAME "] RP AK certified by this Verifier "
                        "(freshly provisioned, %u-byte certificate, expires "
                        "in %ld day(s)).",
                cert_der_len, charra_crypto_x509_days_until_expiry(&issued));
    } else {
        charra_log_info("[" LOG_NAME "] RP AK certified by this Verifier "
                        "(freshly provisioned, %u-byte certificate).",
                cert_der_len);
    }
    mbedtls_x509_crt_free(&issued);
    return CHARRA_RC_SUCCESS;
}
