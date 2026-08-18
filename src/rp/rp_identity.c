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

    result = rp_coap_fetch(host, port, "certify_ak", req_buf, req_buf_len,
            coap_certify_ak_response_handler, &processing_certify_ak_response);
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

void invalidate_cached_rp_ak_certificate(int verifier_index) {
    char cert_path[96] = {0};
    snprintf(cert_path, sizeof(cert_path),
            "state/relying-party/ak-certificates/rp-ak-certificate-%u.der",
            verifiers[verifier_index].port_number);
    remove(cert_path);
    charra_free_if_not_null(rp_ak_cert_der[verifier_index]);
    rp_ak_cert_der[verifier_index] = NULL;
    rp_ak_cert_der_len[verifier_index] = 0;
    rp_ak_cert_ready[verifier_index] = false;
    rp_ak_cert_was_cached[verifier_index] = false;
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

    bool cached = charra_io_file_exists(rp_ak_public_path) ==
                    CHARRA_RC_SUCCESS &&
            charra_io_file_exists(rp_ak_private_path) == CHARRA_RC_SUCCESS;

    if (cached) {
        /* No TPM needed at all here: this is a pure file read. The AK
         * itself is only ever loaded into the TPM when actually signing or
         * certifying (see rp_open_tpm_and_load_ak()). */
        charra_log_info(
                "[" LOG_NAME "] Reloading previously provisioned RP AK "
                "keypair.");
        if ((result = charra_identity_key_mgr_load_public(
                     rp_ak_public_path, &ak_public)) != CHARRA_RC_SUCCESS) {
            charra_log_error("[" LOG_NAME "] Could not load cached AK public "
                             "key.");
            pthread_mutex_unlock(&rp_tpm_mutex);
            return result;
        }
    } else {
        charra_log_info(
                "[" LOG_NAME "] No cached RP AK keypair -- creating one.");

        /* --- TPM session (mutex-held): create EK + AK, persist blobs.
         * Closed before returning -- every other TPM use in this file
         * (signing, certifying) opens its own short-lived connection; see
         * rp_tpm_mutex's own comment for why holding one open longer than
         * one operation needs is a real problem on this dev TPM
         * simulator, not just tidiness. */
        ESYS_CONTEXT* esys_ctx = NULL;
        TSS2_TCTI_CONTEXT* tcti_ctx = NULL;
        ESYS_TR ek_handle = ESYS_TR_NONE;
        ESYS_TR ak_handle = ESYS_TR_NONE;
        TPM2B_NAME* ak_name = NULL;
        TPM2B_PUBLIC* ek_public = NULL;
        TPM2B_PRIVATE ak_private = {0};
        uint8_t* ek_cert_der = NULL;
        size_t ek_cert_der_len = 0;
        bool ek_cert_der_from_read_file = false;

        TSS2_RC tss_r = 0;
        if ((tss_r = Tss2_TctiLdr_Initialize(
                     getenv("CHARRA_TCTI"), &tcti_ctx)) != TSS2_RC_SUCCESS) {
            charra_log_error("[" LOG_NAME "] Tss2_TctiLdr_Initialize.");
            pthread_mutex_unlock(&rp_tpm_mutex);
            return CHARRA_RC_ERROR;
        }
        if ((tss_r = Esys_Initialize(&esys_ctx, tcti_ctx, NULL)) !=
                TSS2_RC_SUCCESS) {
            charra_log_error("[" LOG_NAME "] Esys_Initialize.");
            Tss2_TctiLdr_Finalize(&tcti_ctx);
            pthread_mutex_unlock(&rp_tpm_mutex);
            return CHARRA_RC_ERROR;
        }

        if ((result = charra_identity_key_mgr_create_ek(
                     esys_ctx, &ek_handle, &ek_public)) != CHARRA_RC_SUCCESS) {
            charra_log_error("[" LOG_NAME "] Could not create RP's EK.");
            Esys_Finalize(&esys_ctx);
            Tss2_TctiLdr_Finalize(&tcti_ctx);
            pthread_mutex_unlock(&rp_tpm_mutex);
            return result;
        }

        /* --- RP's own EK certificate: cached after the first mint, since
         * charra_identity_key_mgr_create_ek() reproduces the same EK every time
         * anyway --------------------------------------------------------- */
        if (charra_io_file_exists(rp_ek_cert_cache_path) == CHARRA_RC_SUCCESS) {
            char* buf = NULL;
            size_t buf_len = 0;
            if ((result = charra_io_read_file(
                         rp_ek_cert_cache_path, &buf, &buf_len)) !=
                    CHARRA_RC_SUCCESS) {
                charra_log_error(
                        "[" LOG_NAME "] Could not read cached EK certificate.");
                Esys_Free(ek_public);
                Esys_FlushContext(esys_ctx, ek_handle);
                Esys_Finalize(&esys_ctx);
                Tss2_TctiLdr_Finalize(&tcti_ctx);
                pthread_mutex_unlock(&rp_tpm_mutex);
                return result;
            }
            ek_cert_der = (uint8_t*)buf;
            ek_cert_der_len = buf_len;
            ek_cert_der_from_read_file = true;
        } else {
            char* manufacturer_root_der = NULL;
            size_t manufacturer_root_der_len = 0;
            if ((result = charra_io_read_file(manufacturer_root_cert_path,
                         &manufacturer_root_der,
                         &manufacturer_root_der_len)) != CHARRA_RC_SUCCESS) {
                charra_log_error("[" LOG_NAME "] Could not read manufacturer "
                                 "root certificate ('%s').",
                        manufacturer_root_cert_path);
                Esys_Free(ek_public);
                Esys_FlushContext(esys_ctx, ek_handle);
                Esys_Finalize(&esys_ctx);
                Tss2_TctiLdr_Finalize(&tcti_ctx);
                pthread_mutex_unlock(&rp_tpm_mutex);
                return result;
            }
            mbedtls_x509_crt manufacturer_root_cert;
            mbedtls_x509_crt_init(&manufacturer_root_cert);
            if (mbedtls_x509_crt_parse(&manufacturer_root_cert,
                        (uint8_t*)manufacturer_root_der,
                        manufacturer_root_der_len) != 0) {
                charra_log_error("[" LOG_NAME "] Could not parse "
                                 "manufacturer root certificate.");
                charra_io_free_file_buffer(&manufacturer_root_der);
                Esys_Free(ek_public);
                Esys_FlushContext(esys_ctx, ek_handle);
                Esys_Finalize(&esys_ctx);
                Tss2_TctiLdr_Finalize(&tcti_ctx);
                pthread_mutex_unlock(&rp_tpm_mutex);
                return CHARRA_RC_CRYPTO_ERROR;
            }
            char issuer_name[256] = {0};
            if (mbedtls_x509_dn_gets(issuer_name, sizeof(issuer_name),
                        &manufacturer_root_cert.subject) <= 0) {
                charra_log_error("[" LOG_NAME "] Could not read manufacturer "
                                 "root subject name.");
                mbedtls_x509_crt_free(&manufacturer_root_cert);
                charra_io_free_file_buffer(&manufacturer_root_der);
                Esys_Free(ek_public);
                Esys_FlushContext(esys_ctx, ek_handle);
                Esys_Finalize(&esys_ctx);
                Tss2_TctiLdr_Finalize(&tcti_ctx);
                pthread_mutex_unlock(&rp_tpm_mutex);
                return CHARRA_RC_CRYPTO_ERROR;
            }
            mbedtls_x509_crt_free(&manufacturer_root_cert);
            charra_io_free_file_buffer(&manufacturer_root_der);

            uint8_t ek_serial[16] = {0};
            uint32_t ek_cert_der_len_u32 = 0;
            if ((result = charra_crypto_sign_ak_certificate(ek_public,
                         "CN=CHARRA RP EK (test only)", issuer_name,
                         rp_ek_cert_not_before_utc, rp_ek_cert_not_after_utc,
                         manufacturer_root_key_path, &ek_cert_der,
                         &ek_cert_der_len_u32, ek_serial)) !=
                    CHARRA_RC_SUCCESS) {
                charra_log_error(
                        "[" LOG_NAME "] Could not mint RP's EK certificate.");
                Esys_Free(ek_public);
                Esys_FlushContext(esys_ctx, ek_handle);
                Esys_Finalize(&esys_ctx);
                Tss2_TctiLdr_Finalize(&tcti_ctx);
                pthread_mutex_unlock(&rp_tpm_mutex);
                return result;
            }
            ek_cert_der_len = ek_cert_der_len_u32;
            if ((result = charra_io_write_file(rp_ek_cert_cache_path,
                         ek_cert_der, ek_cert_der_len)) != CHARRA_RC_SUCCESS) {
                charra_log_error(
                        "[" LOG_NAME "] Could not cache RP's EK certificate.");
                Esys_Free(ek_public);
                Esys_FlushContext(esys_ctx, ek_handle);
                Esys_Finalize(&esys_ctx);
                Tss2_TctiLdr_Finalize(&tcti_ctx);
                pthread_mutex_unlock(&rp_tpm_mutex);
                charra_free_if_not_null(ek_cert_der);
                return result;
            }
        }
        Esys_Free(ek_public);
        if (ek_cert_der_from_read_file) {
            free(ek_cert_der);
        } else {
            charra_free_if_not_null(ek_cert_der);
        }

        /* --- create the AK, persist its blobs -------------------------- */
        TPM2B_PUBLIC* ak_public_p = NULL;
        TPM2B_PRIVATE* ak_private_p = NULL;
        if ((result = charra_identity_key_mgr_create_ak(esys_ctx, ek_handle,
                     &ak_handle, &ak_public_p, &ak_private_p, &ak_name)) !=
                CHARRA_RC_SUCCESS) {
            charra_log_error("[" LOG_NAME "] Could not create RP's AK.");
            Esys_FlushContext(esys_ctx, ek_handle);
            Esys_Finalize(&esys_ctx);
            Tss2_TctiLdr_Finalize(&tcti_ctx);
            pthread_mutex_unlock(&rp_tpm_mutex);
            return result;
        }
        ak_public = *ak_public_p;
        ak_private = *ak_private_p;
        Esys_Free(ak_public_p);
        Esys_Free(ak_private_p);
        Esys_Free(ak_name);

        if ((result = charra_identity_key_mgr_save_public(
                     rp_ak_public_path, &ak_public)) != CHARRA_RC_SUCCESS) {
            charra_log_error("[" LOG_NAME "] Could not persist AK public key.");
            Esys_FlushContext(esys_ctx, ak_handle);
            Esys_FlushContext(esys_ctx, ek_handle);
            Esys_Finalize(&esys_ctx);
            Tss2_TctiLdr_Finalize(&tcti_ctx);
            pthread_mutex_unlock(&rp_tpm_mutex);
            return result;
        }
        if ((result = charra_identity_key_mgr_save_private(
                     rp_ak_private_path, &ak_private)) != CHARRA_RC_SUCCESS) {
            charra_log_error(
                    "[" LOG_NAME "] Could not persist AK private area.");
            Esys_FlushContext(esys_ctx, ak_handle);
            Esys_FlushContext(esys_ctx, ek_handle);
            Esys_Finalize(&esys_ctx);
            Tss2_TctiLdr_Finalize(&tcti_ctx);
            pthread_mutex_unlock(&rp_tpm_mutex);
            return result;
        }

        Esys_FlushContext(esys_ctx, ak_handle);
        Esys_FlushContext(esys_ctx, ek_handle);
        Esys_Finalize(&esys_ctx);
        Tss2_TctiLdr_Finalize(&tcti_ctx);
    }

    if ((result = charra_identity_key_mgr_public_key_to_der(&ak_public,
                 rp_public_key_der, sizeof(rp_public_key_der),
                 &rp_public_key_der_len)) != CHARRA_RC_SUCCESS) {
        charra_log_error(
                "[" LOG_NAME "] Could not DER-encode RP's AK public key.");
        pthread_mutex_unlock(&rp_tpm_mutex);
        return result;
    }

    rp_ak_keypair_ready = true;
    pthread_mutex_unlock(&rp_tpm_mutex);
    return CHARRA_RC_SUCCESS;
}

CHARRA_RC ensure_rp_ak_certificate(int verifier_index) {
    if (rp_ak_cert_ready[verifier_index]) {
        /* No work happens on this path, so it's "cached" for the summary. */
        rp_ak_cert_was_cached[verifier_index] = true;
        return CHARRA_RC_SUCCESS;
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

        /* Informational only -- the Verifier enforces expiry, not this. */
        mbedtls_x509_crt cached_cert;
        mbedtls_x509_crt_init(&cached_cert);
        if (mbedtls_x509_crt_parse(&cached_cert, cert_der, cert_buf_len) ==
                0) {
            charra_log_info("[" LOG_NAME "] Reloading previously issued AK "
                            "certificate for this Verifier (cached, expires "
                            "in %ld day(s)).",
                    charra_crypto_x509_days_until_expiry(&cached_cert));
        } else {
            charra_log_info("[" LOG_NAME "] Reloading previously issued AK "
                            "certificate for this Verifier (cached).");
        }
        mbedtls_x509_crt_free(&cached_cert);

        rp_ak_cert_der[verifier_index] = cert_der;
        rp_ak_cert_der_len[verifier_index] = (uint32_t)cert_buf_len;
        rp_ak_cert_ready[verifier_index] = true;
        rp_ak_cert_was_cached[verifier_index] = true;
        return CHARRA_RC_SUCCESS;
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

    /* --- TPM session #1 (mutex-held): load the already-persisted AK to
     * get ak_public + ak_name, then CLOSE the connection before the
     * /certify_ak round trip below -- critical, not cosmetic: the
     * Verifier's own /certify_ak handler needs its own TPM connection to
     * complete Esys_MakeCredential, and the dev TPM simulator accepts only
     * one client connection at a time. Holding this connection open across
     * the CoAP wait deadlocks the Verifier's response indefinitely
     * (confirmed directly while developing this: killing an RP stuck here
     * immediately unblocked the Verifier's handler, which had been sitting
     * mid-MakeCredential the whole time). ------------------------------ */
    pthread_mutex_lock(&rp_tpm_mutex);
    ESYS_CONTEXT* esys_ctx = NULL;
    TSS2_TCTI_CONTEXT* tcti_ctx = NULL;
    ESYS_TR ek_handle = ESYS_TR_NONE;
    ESYS_TR ak_handle = ESYS_TR_NONE;
    TPM2B_NAME* ak_name = NULL;
    if ((result = rp_open_tpm_and_load_ak(&esys_ctx, &tcti_ctx, &ek_handle,
                 &ak_handle, &ak_name)) != CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Could not open TPM connection to "
                         "load RP's AK.");
        pthread_mutex_unlock(&rp_tpm_mutex);
        charra_io_free_file_buffer(&ek_cert_buf);
        return result;
    }

    TPM2B_PUBLIC ak_public = {0};
    if ((result = charra_identity_key_mgr_load_public(rp_ak_public_path,
                 &ak_public)) != CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Could not load AK public key for "
                         "/certify_ak request.");
        Esys_Free(ak_name);
        Esys_FlushContext(esys_ctx, ak_handle);
        Esys_FlushContext(esys_ctx, ek_handle);
        Esys_Finalize(&esys_ctx);
        Tss2_TctiLdr_Finalize(&tcti_ctx);
        pthread_mutex_unlock(&rp_tpm_mutex);
        charra_io_free_file_buffer(&ek_cert_buf);
        return result;
    }

    /* --- CHALLENGE request, built now while ak_name is still valid, sent
     * AFTER the TPM connection below is closed -------------------------- */
    msg_certify_ak_request_dto req = {0};
    req.kind = CHARRA_CERTIFY_AK_CHALLENGE;
    req.subject = CHARRA_CERTIFY_AK_SUBJECT_RP;
    req.ek_certificate = (uint8_t*)ek_cert_buf;
    req.ek_certificate_len = (uint32_t)ek_cert_buf_len;
    req.ak_public_key_len = sizeof(ak_public);
    memcpy(req.ak_public_key, &ak_public, sizeof(ak_public));
    /* Copy only the meaningful prefix (size field + size bytes) and
     * zero the rest: Esys_TR_GetName() leaves the tail of the
     * TPM2B_NAME allocation uninitialised, and copying the whole
     * struct put those heap bytes straight onto the wire (caught by
     * valgrind via libcoap reading them while building the PDU).
     * The field stays fixed-size, so the wire format is unchanged --
     * the tail is now deterministic zeros instead of stale heap. */
    req.ak_name_len = sizeof(*ak_name);
    memset(req.ak_name, 0, sizeof(req.ak_name));
    memcpy(req.ak_name, ak_name, sizeof(ak_name->size) + ak_name->size);
    Esys_Free(ak_name);

    Esys_FlushContext(esys_ctx, ak_handle);
    Esys_FlushContext(esys_ctx, ek_handle);
    Esys_Finalize(&esys_ctx);
    Tss2_TctiLdr_Finalize(&tcti_ctx);
    pthread_mutex_unlock(&rp_tpm_mutex);

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

    /* --- TPM session #2: recover the challenge secret via
     * ActivateCredential. Only this TPM can, which is exactly what the
     * Verifier's CONFIRM leg is about to check. --------------------------- */
    charra_log_info("[" LOG_NAME "] Waiting on TPM mutex for "
                    "ActivateCredential (TPM session #2) ...");
    pthread_mutex_lock(&rp_tpm_mutex);
    ESYS_TR ek_handle2 = ESYS_TR_NONE;
    ESYS_TR ak_handle2 = ESYS_TR_NONE;
    TPM2B_NAME* ak_name2 = NULL;
    struct timespec activate_start, activate_end;
    clock_gettime(CLOCK_MONOTONIC, &activate_start);
    if ((result = rp_open_tpm_and_load_ak(&esys_ctx, &tcti_ctx, &ek_handle2,
                 &ak_handle2, &ak_name2)) != CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Could not reopen TPM connection "
                         "for ActivateCredential.");
        pthread_mutex_unlock(&rp_tpm_mutex);
        charra_free_if_not_null(challenge.ak_certificate);
        charra_io_free_file_buffer(&ek_cert_buf);
        return result;
    }
    Esys_Free(ak_name2);

    TPM2B_DIGEST* credential = NULL;
    if ((result = charra_identity_key_mgr_activate_credential(esys_ctx,
                 ak_handle2, ek_handle2,
                 (TPM2B_ID_OBJECT*)challenge.credential_blob,
                 (TPM2B_ENCRYPTED_SECRET*)challenge.wrapped_secret,
                 &credential)) != CHARRA_RC_SUCCESS) {
        charra_log_error(
                "[" LOG_NAME "] ActivateCredential failed -- this AK is not "
                "genuinely bound to this EK, or the TPM rejected the "
                "request.");
        Esys_FlushContext(esys_ctx, ak_handle2);
        Esys_FlushContext(esys_ctx, ek_handle2);
        Esys_Finalize(&esys_ctx);
        Tss2_TctiLdr_Finalize(&tcti_ctx);
        pthread_mutex_unlock(&rp_tpm_mutex);
        charra_free_if_not_null(challenge.ak_certificate);
        charra_io_free_file_buffer(&ek_cert_buf);
        return result;
    }
    Esys_FlushContext(esys_ctx, ak_handle2);
    Esys_FlushContext(esys_ctx, ek_handle2);
    Esys_Finalize(&esys_ctx);
    Tss2_TctiLdr_Finalize(&tcti_ctx);
    pthread_mutex_unlock(&rp_tpm_mutex);
    clock_gettime(CLOCK_MONOTONIC, &activate_end);
    double activate_duration =
            (activate_end.tv_sec - activate_start.tv_sec) +
            (activate_end.tv_nsec - activate_start.tv_nsec) / 1e9;
    charra_free_if_not_null(challenge.ak_certificate);

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
    rp_ak_cert_ready[verifier_index] = true;

    mbedtls_x509_crt new_cert;
    mbedtls_x509_crt_init(&new_cert);
    if (mbedtls_x509_crt_parse(&new_cert, cert_der, cert_der_len) == 0) {
        charra_log_info("[" LOG_NAME "] RP AK certified by this Verifier "
                        "(freshly provisioned, %u-byte certificate, expires "
                        "in %ld day(s)).",
                cert_der_len, charra_crypto_x509_days_until_expiry(&new_cert));
    } else {
        charra_log_info("[" LOG_NAME "] RP AK certified by this Verifier "
                        "(freshly provisioned, %u-byte certificate).",
                cert_der_len);
    }
    mbedtls_x509_crt_free(&new_cert);
    return CHARRA_RC_SUCCESS;
}
