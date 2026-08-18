/**
 * @file rp_attester_identity.c
 * @brief See rp_attester_identity.h.
 *
 * The three CoAP response handlers stay with the legs that drive them:
 * each writes its own dedicated globals, because a libcoap callback cannot
 * return data to its caller.
 */

#include "rp_attester_identity.h"

#include <errno.h>
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
#include "../core/charra_key_mgr.h"
#include "../core/charra_marshaling.h"
#include "../util/crypto_util.h"
#include "../util/io_util.h"
#include "rp_coap.h"
#include "rp_identity.h"
#include "rp_shared.h"

#define LOG_NAME "relying party"



static coap_response_t coap_activate_credential_response_handler(
        coap_session_t* session CHARRA_UNUSED,
        const coap_pdu_t* sent CHARRA_UNUSED, const coap_pdu_t* received,
        const coap_mid_t mid CHARRA_UNUSED) {
    processing_activate_credential_response = true;

    int coap_r = 0;
    size_t data_len = 0;
    const uint8_t* data = NULL;
    size_t data_offset = 0;
    size_t data_total_len = 0;
    if ((coap_r = coap_get_data_large(
                 received, &data_len, &data, &data_offset, &data_total_len)) ==
            0) {
        charra_log_error("[" LOG_NAME
                         "] ACTIVATE: Could not get CoAP PDU data.");
        activate_credential_rc = CHARRA_RC_ERROR;
        goto cleanup;
    }

    if ((activate_credential_rc = charra_unmarshal_activate_credential_response(
                 data_len, data, &activate_credential_response)) !=
            CHARRA_RC_SUCCESS) {
        charra_log_error(
                "[" LOG_NAME "] ACTIVATE: Could not parse CBOR response.");
        goto cleanup;
    }

cleanup:
    processing_activate_credential_response = false;
    return COAP_RESPONSE_OK;
}

static coap_response_t coap_ak_identity_response_handler(
        coap_session_t* session CHARRA_UNUSED,
        const coap_pdu_t* sent CHARRA_UNUSED, const coap_pdu_t* received,
        const coap_mid_t mid CHARRA_UNUSED) {
    processing_ak_identity_response = true;

    int coap_r = 0;
    size_t data_len = 0;
    const uint8_t* data = NULL;
    size_t data_offset = 0;
    size_t data_total_len = 0;
    if ((coap_r = coap_get_data_large(
                 received, &data_len, &data, &data_offset, &data_total_len)) ==
            0) {
        charra_log_error("[" LOG_NAME "] /certify_ak_of_attester (FETCH): "
                         "Could not get CoAP PDU data.");
        ak_identity_rc = CHARRA_RC_ERROR;
        goto cleanup;
    }

    if ((ak_identity_rc = charra_unmarshal_ak_identity_response(
                 data_len, data, &ak_identity_response)) != CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] /certify_ak_of_attester (FETCH): "
                         "Could not parse CBOR response.");
        goto cleanup;
    }

cleanup:
    processing_ak_identity_response = false;
    return COAP_RESPONSE_OK;
}

static coap_response_t coap_certify_ak_of_attester_deliver_response_handler(
        coap_session_t* session CHARRA_UNUSED,
        const coap_pdu_t* sent CHARRA_UNUSED,
        const coap_pdu_t* received CHARRA_UNUSED,
        const coap_mid_t mid CHARRA_UNUSED) {
    /* No payload to parse -- a non-error CoAP response code alone means
     * the Attester unwrapped and persisted the delivered certificate; the
     * caller only waits on rp_coap_fetch()'s own transport-level result. */
    processing_certify_ak_of_attester_deliver_response = true;
    processing_certify_ak_of_attester_deliver_response = false;
    return COAP_RESPONSE_OK;
}

CHARRA_RC ensure_attester_identity_provisioned(void) {
    /* Fast path, no lock and no file I/O: an in-memory expiry, re-checked
     * every call so a daemon notices its own certificate ageing out. */
    if (attester_identity_provisioned &&
            !charra_cert_needs_renewal(attester_ak_cert_rp_expires_at)) {
        return CHARRA_RC_SUCCESS;
    }

    /* Everything below touches ak_identity_response, attester_identity_cached
     * and the FETCH processing flag, none of which have locks of their own:
     * they were written when this function provably ran once, before any
     * Verifier thread existed. Expiry-driven renewal breaks that assumption
     * -- a thread reaches here through
     * ensure_attester_identity_certified_by_verifier() -- so serialise here
     * and re-check after acquiring, since another thread may have just
     * finished the work we were about to repeat. */
    pthread_mutex_lock(&attester_identity_provision_mutex);
    if (attester_identity_provisioned &&
            !charra_cert_needs_renewal(attester_ak_cert_rp_expires_at)) {
        pthread_mutex_unlock(&attester_identity_provision_mutex);
        return CHARRA_RC_SUCCESS;
    }

    if (charra_io_file_exists(attester_ak_cert_rp_cache_path) ==
            CHARRA_RC_SUCCESS) {
        char* cached_buf = NULL;
        size_t cached_len = 0;
        bool cache_usable = false;
        if (charra_io_read_file(attester_ak_cert_rp_cache_path, &cached_buf,
                    &cached_len) == CHARRA_RC_SUCCESS) {
            mbedtls_x509_crt cached_cert;
            mbedtls_x509_crt_init(&cached_cert);
            if (mbedtls_x509_crt_parse(&cached_cert, (uint8_t*)cached_buf,
                        cached_len) == 0) {
                long days_left =
                        charra_crypto_x509_days_until_expiry(&cached_cert);
                if (!charra_cert_needs_renewal(
                            charra_cert_expiry_time(&cached_cert))) {
                    cache_usable = true;
                    attester_ak_cert_rp_expires_at =
                            charra_cert_expiry_time(&cached_cert);
                    charra_log_info("[" LOG_NAME "] Attester identity already "
                                    "provisioned (cached, RP-issued "
                                    "certificate expires in %ld day(s)).",
                            days_left);
                } else {
                    charra_log_info("[" LOG_NAME "] RP-issued Attester AK "
                                    "certificate expires in %ld day(s) -- "
                                    "re-certifying.",
                            days_left);
                }
            } else {
                charra_log_error("[" LOG_NAME "] Cached RP-issued Attester AK "
                                 "certificate does not parse -- "
                                 "re-certifying.");
            }
            mbedtls_x509_crt_free(&cached_cert);
            charra_io_free_file_buffer(&cached_buf);
        }
        if (cache_usable) {
            attester_identity_provisioned = true;
            pthread_mutex_unlock(&attester_identity_provision_mutex);
            return CHARRA_RC_SUCCESS;
        }
        attester_identity_provisioned = false;
    }

    charra_log_info("[" LOG_NAME "]  +------------ Attester Identity "
                    "Provisioning --------------+");

    CHARRA_RC result = CHARRA_RC_ERROR;

    /* --- 1. FETCH: get the Attester's EK cert + AK public key + AK name */
    msg_certify_ak_of_attester_request_dto fetch_req = {0};
    fetch_req.kind = CHARRA_CERTIFY_AK_OF_ATTESTER_FETCH;
    uint8_t* fetch_req_buf = NULL;
    uint32_t fetch_req_buf_len = 0;
    if ((result = charra_marshal_certify_ak_of_attester_request(&fetch_req,
                 &fetch_req_buf_len, &fetch_req_buf)) != CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Could not marshal "
                         "/certify_ak_of_attester FETCH request.");
        pthread_mutex_unlock(&attester_identity_provision_mutex);
        return result;
    }

    ak_identity_rc = CHARRA_RC_ERROR;
    result = rp_coap_fetch(attester_host, attester_port,
            "certify_ak_of_attester", fetch_req_buf, fetch_req_buf_len,
            coap_ak_identity_response_handler, &processing_ak_identity_response);
    free(fetch_req_buf);
    if (result != CHARRA_RC_SUCCESS) {
        charra_log_error(
                "[" LOG_NAME "] /certify_ak_of_attester FETCH round trip "
                "failed.");
        pthread_mutex_unlock(&attester_identity_provision_mutex);
        return result;
    }
    if (ak_identity_rc != CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] /certify_ak_of_attester FETCH did "
                         "not complete successfully.");
        pthread_mutex_unlock(&attester_identity_provision_mutex);
        return ak_identity_rc;
    }

    /* Snapshot + release ownership of the shared global's heap field, same
     * convention certify_ak_response uses (see ensure_rp_ak_certificate()
     * below). Safe without a mutex: this whole function runs once, before
     * any per-Verifier thread starts. */
    msg_ak_identity_response_dto identity = ak_identity_response;
    ak_identity_response.ek_certificate = NULL;
    ak_identity_response.ek_certificate_len = 0;

    charra_log_info(
            "[" LOG_NAME "] Received Attester identity: EK certificate %u "
            "byte(s), AK public key %u byte(s).",
            identity.ek_certificate_len, identity.ak_public_key_len);

    /* --- 2. RP-CA local gate: the Attester's EK must chain to the
     * manufacturer root. Hard fail-closed -- the caller is expected to
     * abort the whole attestation cycle on any error return from here on,
     * per "the RP validates the Attester's EK/AK itself" (CHARRA_V2_NOTES.md). */
    char* manufacturer_root_der = NULL;
    size_t manufacturer_root_der_len = 0;
    if ((result = charra_io_read_file(manufacturer_root_cert_path,
                 &manufacturer_root_der, &manufacturer_root_der_len)) !=
            CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Could not read manufacturer root "
                         "certificate ('%s').",
                manufacturer_root_cert_path);
        charra_free_if_not_null(identity.ek_certificate);
        pthread_mutex_unlock(&attester_identity_provision_mutex);
        return result;
    }

    mbedtls_x509_crt attester_ek_leaf_cert;
    if ((result = charra_crypto_verify_x509_cert_chain(identity.ek_certificate,
                 identity.ek_certificate_len, (uint8_t*)manufacturer_root_der,
                 manufacturer_root_der_len, &attester_ek_leaf_cert)) !=
            CHARRA_RC_SUCCESS) {
        charra_log_error(
                "[" LOG_NAME "]     => RP's own EK/AK check of the Attester "
                "FAILED -- Attester's EK certificate does NOT verify "
                "against the manufacturer root. Aborting.");
        charra_io_free_file_buffer(&manufacturer_root_der);
        charra_free_if_not_null(identity.ek_certificate);
        pthread_mutex_unlock(&attester_identity_provision_mutex);
        return CHARRA_RC_VERIFICATION_FAILED;
    }
    charra_crypto_log_cert_summary(
            "Attester's EK cert (RP's own check)", &attester_ek_leaf_cert);
    charra_log_info(
            "[" LOG_NAME "]     => RP's own EK/AK check of the Attester "
            "passed!");

    TPM2B_PUBLIC attester_ek_public_key = {0};
    if ((result = charra_crypto_build_ek_tpm2b_public_from_cert(
                 &attester_ek_leaf_cert, &attester_ek_public_key)) !=
            CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Could not reconstruct Attester's "
                         "EK TPM2B_PUBLIC from certificate.");
        mbedtls_x509_crt_free(&attester_ek_leaf_cert);
        charra_io_free_file_buffer(&manufacturer_root_der);
        charra_free_if_not_null(identity.ek_certificate);
        pthread_mutex_unlock(&attester_identity_provision_mutex);
        return result;
    }
    mbedtls_x509_crt_free(&attester_ek_leaf_cert);
    charra_io_free_file_buffer(&manufacturer_root_der);

    TPM2B_PUBLIC* attester_ak_public_key =
            (TPM2B_PUBLIC*)identity.ak_public_key;
    TPM2B_NAME* attester_ak_name = (TPM2B_NAME*)identity.ak_name;

    /* --- 3. RP-CA track: sign, wrap, deliver -------------------------- */
    /* Validity runs from now, so a long-running RP always issues a full
     * window rather than an ever-shrinking one. */
    time_t rp_cert_issued_at = time(NULL);
    time_t rp_cert_expires_at =
            rp_cert_issued_at + attester_ak_cert_validity_seconds;
    char attester_ak_cert_not_before_utc[15] = {0};
    char attester_ak_cert_not_after_utc[15] = {0};
    uint8_t rp_ca_serial[16] = {0};
    uint8_t* rp_signed_cert_der = NULL;
    uint32_t rp_signed_cert_der_len = 0;
    {
        mbedtls_x509_crt rp_ca_cert;
        mbedtls_x509_crt_init(&rp_ca_cert);
        char* rp_ca_cert_der_buf = NULL;
        size_t rp_ca_cert_der_buf_len = 0;
        if ((result = charra_io_read_file(rp_ca_cert_path, &rp_ca_cert_der_buf,
                     &rp_ca_cert_der_buf_len)) != CHARRA_RC_SUCCESS) {
            charra_log_error("[" LOG_NAME "] Could not read RP CA "
                             "certificate ('%s').",
                    rp_ca_cert_path);
            charra_free_if_not_null(identity.ek_certificate);
            pthread_mutex_unlock(&attester_identity_provision_mutex);
            return result;
        }
        if (mbedtls_x509_crt_parse(&rp_ca_cert, (uint8_t*)rp_ca_cert_der_buf,
                    rp_ca_cert_der_buf_len) != 0) {
            charra_log_error("[" LOG_NAME "] Could not parse RP CA "
                             "certificate.");
            charra_io_free_file_buffer(&rp_ca_cert_der_buf);
            charra_free_if_not_null(identity.ek_certificate);
            pthread_mutex_unlock(&attester_identity_provision_mutex);
            return CHARRA_RC_CRYPTO_ERROR;
        }
        char rp_ca_subject_name[256] = {0};
        if (mbedtls_x509_dn_gets(rp_ca_subject_name,
                    sizeof(rp_ca_subject_name), &rp_ca_cert.subject) <= 0) {
            charra_log_error(
                    "[" LOG_NAME "] Could not read RP CA subject name.");
            mbedtls_x509_crt_free(&rp_ca_cert);
            charra_io_free_file_buffer(&rp_ca_cert_der_buf);
            charra_free_if_not_null(identity.ek_certificate);
            pthread_mutex_unlock(&attester_identity_provision_mutex);
            return CHARRA_RC_CRYPTO_ERROR;
        }
        mbedtls_x509_crt_free(&rp_ca_cert);
        charra_io_free_file_buffer(&rp_ca_cert_der_buf);

        if (!charra_crypto_format_utc_yyyymmddhhmmss(
                    rp_cert_issued_at, attester_ak_cert_not_before_utc) ||
                !charra_crypto_format_utc_yyyymmddhhmmss(rp_cert_expires_at,
                        attester_ak_cert_not_after_utc)) {
            charra_log_error("[" LOG_NAME "] Could not format Attester AK "
                             "certificate validity window.");
            charra_free_if_not_null(identity.ek_certificate);
            pthread_mutex_unlock(&attester_identity_provision_mutex);
            return CHARRA_RC_ERROR;
        }
        if ((result = charra_crypto_sign_ak_certificate(attester_ak_public_key,
                     "CN=CHARRA Attester AK (RP-issued)", rp_ca_subject_name,
                     attester_ak_cert_not_before_utc,
                     attester_ak_cert_not_after_utc, rp_ca_key_path,
                     &rp_signed_cert_der, &rp_signed_cert_der_len,
                     rp_ca_serial)) != CHARRA_RC_SUCCESS) {
            charra_log_error("[" LOG_NAME "] Could not sign Attester's AK "
                             "certificate with RP's own CA.");
            charra_free_if_not_null(identity.ek_certificate);
            pthread_mutex_unlock(&attester_identity_provision_mutex);
            return result;
        }
    }
    charra_log_info(
            "[" LOG_NAME "] Attester's AK certificate signed by RP's own CA "
            "(%u byte(s)).",
            rp_signed_cert_der_len);

    uint8_t rp_aes_key[CHARRA_AES256GCM_KEY_LEN] = {0};
    {
        mbedtls_ctr_drbg_context ctr_drbg;
        mbedtls_entropy_context entropy;
        if ((result = charra_crypto_seeded_rng_init(&ctr_drbg, &entropy)) !=
                CHARRA_RC_SUCCESS) {
            charra_log_error("[" LOG_NAME "] Could not seed RNG.");
            charra_free_if_not_null(rp_signed_cert_der);
            charra_free_if_not_null(identity.ek_certificate);
            pthread_mutex_unlock(&attester_identity_provision_mutex);
            return result;
        }
        int mbedtls_r = mbedtls_ctr_drbg_random(
                &ctr_drbg, rp_aes_key, sizeof(rp_aes_key));
        charra_crypto_seeded_rng_free(&ctr_drbg, &entropy);
        if (mbedtls_r != 0) {
            charra_log_error(
                    "[" LOG_NAME "] Could not generate AES key.");
            charra_free_if_not_null(rp_signed_cert_der);
            charra_free_if_not_null(identity.ek_certificate);
            pthread_mutex_unlock(&attester_identity_provision_mutex);
            return CHARRA_RC_CRYPTO_ERROR;
        }
    }

    uint8_t rp_aes_gcm_nonce[CHARRA_AES256GCM_NONCE_LEN] = {0};
    uint8_t rp_aes_gcm_tag[CHARRA_AES256GCM_TAG_LEN] = {0};
    uint8_t* rp_cert_ciphertext = NULL;
    if ((result = charra_crypto_aes256gcm_encrypt(rp_aes_key, rp_signed_cert_der,
                 rp_signed_cert_der_len, rp_aes_gcm_nonce, rp_aes_gcm_tag,
                 &rp_cert_ciphertext)) != CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Could not encrypt RP-signed AK "
                         "certificate.");
        charra_free_if_not_null(rp_signed_cert_der);
        charra_free_if_not_null(identity.ek_certificate);
        pthread_mutex_unlock(&attester_identity_provision_mutex);
        return result;
    }

    pthread_mutex_lock(&rp_tpm_mutex);
    ESYS_CONTEXT* esys_ctx = NULL;
    TSS2_TCTI_CONTEXT* tcti_ctx = NULL;
    TSS2_RC tss_r = 0;
    if ((tss_r = Tss2_TctiLdr_Initialize(getenv("CHARRA_TCTI"), &tcti_ctx)) !=
            TSS2_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Tss2_TctiLdr_Initialize.");
        pthread_mutex_unlock(&rp_tpm_mutex);
        charra_free_if_not_null(rp_cert_ciphertext);
        charra_free_if_not_null(rp_signed_cert_der);
        charra_free_if_not_null(identity.ek_certificate);
        pthread_mutex_unlock(&attester_identity_provision_mutex);
        return CHARRA_RC_ERROR;
    }
    if ((tss_r = Esys_Initialize(&esys_ctx, tcti_ctx, NULL)) !=
            TSS2_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Esys_Initialize.");
        Tss2_TctiLdr_Finalize(&tcti_ctx);
        pthread_mutex_unlock(&rp_tpm_mutex);
        charra_free_if_not_null(rp_cert_ciphertext);
        charra_free_if_not_null(rp_signed_cert_der);
        charra_free_if_not_null(identity.ek_certificate);
        pthread_mutex_unlock(&attester_identity_provision_mutex);
        return CHARRA_RC_ERROR;
    }

    TPM2B_DIGEST rp_credential = {0};
    rp_credential.size = sizeof(rp_aes_key);
    memcpy(rp_credential.buffer, rp_aes_key, sizeof(rp_aes_key));

    TPM2B_ID_OBJECT* rp_credential_blob = NULL;
    TPM2B_ENCRYPTED_SECRET* rp_wrapped_secret = NULL;
    result = charra_tpm_make_credential_for_ak(esys_ctx, &attester_ek_public_key,
            attester_ak_name, &rp_credential, &rp_credential_blob,
            &rp_wrapped_secret);
    Esys_Finalize(&esys_ctx);
    Tss2_TctiLdr_Finalize(&tcti_ctx);
    pthread_mutex_unlock(&rp_tpm_mutex);
    if (result != CHARRA_RC_SUCCESS) {
        charra_log_error(
                "[" LOG_NAME "] Esys_MakeCredential (RP-CA leg) failed.");
        charra_free_if_not_null(rp_cert_ciphertext);
        charra_free_if_not_null(rp_signed_cert_der);
        charra_free_if_not_null(identity.ek_certificate);
        pthread_mutex_unlock(&attester_identity_provision_mutex);
        return result;
    }

    /* --- record issuance in RP's own ledger, independent of any
     * Verifier's ------------------------------------------------------- */
    uint8_t attester_ek_fingerprint[32] = {0};
    if (hash_sha256(identity.ek_certificate_len, identity.ek_certificate,
                attester_ek_fingerprint) == CHARRA_RC_SUCCESS) {
        charra_ak_state_record rp_ak_record = {0};
        memcpy(rp_ak_record.ek_fingerprint, attester_ek_fingerprint,
                sizeof(rp_ak_record.ek_fingerprint));
        rp_ak_record.ak_name_len = identity.ak_name_len;
        memcpy(rp_ak_record.ak_name, identity.ak_name, identity.ak_name_len);
        memcpy(rp_ak_record.serial, rp_ca_serial, sizeof(rp_ak_record.serial));
        rp_ak_record.issued_at = time(NULL);
        /* Exactly the value stamped into the certificate above. */
        rp_ak_record.expires_at = rp_cert_expires_at;
        if (charra_ak_state_renew(attester_ak_state_file_path,
                    attester_ek_fingerprint, &rp_ak_record) !=
                CHARRA_RC_SUCCESS) {
            charra_log_error("[" LOG_NAME "] Could not record RP-issued "
                             "Attester AK certificate in state.");
        }
    }

    /* --- deliver to the Attester via /certify_ak_of_attester DELIVER_RP */
    msg_certify_ak_of_attester_request_dto deliver_rp_req = {0};
    deliver_rp_req.kind = CHARRA_CERTIFY_AK_OF_ATTESTER_DELIVER_RP;
    deliver_rp_req.credential_blob_len = sizeof(*rp_credential_blob);
    memcpy(deliver_rp_req.credential_blob, rp_credential_blob,
            deliver_rp_req.credential_blob_len);
    deliver_rp_req.wrapped_secret_len = sizeof(*rp_wrapped_secret);
    memcpy(deliver_rp_req.wrapped_secret, rp_wrapped_secret,
            deliver_rp_req.wrapped_secret_len);
    memcpy(deliver_rp_req.aes_gcm_nonce, rp_aes_gcm_nonce,
            sizeof(rp_aes_gcm_nonce));
    memcpy(deliver_rp_req.aes_gcm_tag, rp_aes_gcm_tag, sizeof(rp_aes_gcm_tag));
    deliver_rp_req.ak_certificate_len = rp_signed_cert_der_len;
    deliver_rp_req.ak_certificate = rp_cert_ciphertext;

    Esys_Free(rp_credential_blob);
    Esys_Free(rp_wrapped_secret);

    uint8_t* deliver_rp_buf = NULL;
    uint32_t deliver_rp_buf_len = 0;
    result = charra_marshal_certify_ak_of_attester_request(
            &deliver_rp_req, &deliver_rp_buf_len, &deliver_rp_buf);
    charra_free_if_not_null(rp_cert_ciphertext);
    if (result != CHARRA_RC_SUCCESS) {
        charra_log_error(
                "[" LOG_NAME "] Could not marshal DELIVER_RP request.");
        charra_free_if_not_null(identity.ek_certificate);
        charra_free_if_not_null(rp_signed_cert_der);
        pthread_mutex_unlock(&attester_identity_provision_mutex);
        return result;
    }

    result = rp_coap_fetch(attester_host, attester_port,
            "certify_ak_of_attester", deliver_rp_buf, deliver_rp_buf_len,
            coap_certify_ak_of_attester_deliver_response_handler,
            &processing_certify_ak_of_attester_deliver_response);
    free(deliver_rp_buf);
    if (result != CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] DELIVER_RP round trip to the "
                         "Attester failed.");
        charra_free_if_not_null(identity.ek_certificate);
        charra_free_if_not_null(rp_signed_cert_der);
        pthread_mutex_unlock(&attester_identity_provision_mutex);
        return result;
    }
    charra_log_info("[" LOG_NAME "] RP-CA leg delivered to the Attester.");

    /* Cache now, mirroring ensure_rp_ak_certificate(): only once we
     * genuinely trust the bytes (RP signed them itself, and delivery to
     * the Attester just succeeded). File presence is what gates skipping
     * this whole function on a future call/process restart. */
    if (charra_io_write_file(attester_ak_cert_rp_cache_path, rp_signed_cert_der,
                rp_signed_cert_der_len) != CHARRA_RC_SUCCESS) {
        charra_log_error(
                "[" LOG_NAME "] Could not cache RP-issued Attester AK "
                "certificate.");
    }
    charra_free_if_not_null(rp_signed_cert_der);

    /* Cache the fetched identity itself (not just the RP-signed cert) --
     * ensure_attester_identity_certified_by_verifier() below reuses this
     * for every Verifier rather than re-FETCHing per Verifier. Deep copy:
     * `identity` is a local about to go out of scope. */
    attester_identity_cached = identity;
    attester_identity_cached.ek_certificate = NULL;
    if (identity.ek_certificate_len > 0) {
        attester_identity_cached.ek_certificate =
                malloc(identity.ek_certificate_len);
        if (attester_identity_cached.ek_certificate == NULL) {
            charra_log_error("[" LOG_NAME "] Could not cache Attester "
                             "identity for per-Verifier certification.");
            charra_free_if_not_null(identity.ek_certificate);
            pthread_mutex_unlock(&attester_identity_provision_mutex);
            return CHARRA_RC_ERROR;
        }
        memcpy(attester_identity_cached.ek_certificate, identity.ek_certificate,
                identity.ek_certificate_len);
        attester_identity_cached.ek_certificate_len = identity.ek_certificate_len;
    }
    charra_free_if_not_null(identity.ek_certificate);

    charra_log_info(
            "[" LOG_NAME "] Attester identity provisioned (RP's own CA); "
            "ready for per-Verifier certification.");
    /* The window RP just signed into the certificate, so the renewal check
     * has a real deadline rather than 0 ("unknown"), which would re-certify
     * on the very next call. */
    attester_ak_cert_rp_expires_at = rp_cert_expires_at;
    attester_identity_provisioned = true;
    pthread_mutex_unlock(&attester_identity_provision_mutex);
    return CHARRA_RC_SUCCESS;
}

/**
 * @brief Make attester_identity_cached usable, FETCHing it if needed.
 *
 * ensure_attester_identity_provisioned() populates the cache only on its
 * FETCH path; when the RP-CA certificate is already on disk it returns
 * early, so in every RP process after the first the struct is all zeros.
 * Any per-Verifier relay in such a process would then put an EMPTY EK
 * certificate on the wire -- the Verifier logs a 7-byte /certify_ak and
 * rejects it, which reads as the Attester having a bad EK rather than RP
 * never having asked for one. Reachable without any rejection at all: add
 * a Verifier, or lose one per-Verifier cache file, and restart RP.
 *
 * Re-runs RP's own manufacturer-root gate on the fetched EK certificate.
 * That gate is the reason ensure_attester_identity_provisioned() is
 * fail-closed, and a cache file on disk is not evidence that this process
 * ever ran it.
 */
static CHARRA_RC ensure_attester_identity_fetched(void) {
    if (attester_identity_cached.ek_certificate_len > 0) {
        return CHARRA_RC_SUCCESS;
    }

    CHARRA_RC result = CHARRA_RC_ERROR;
    msg_certify_ak_of_attester_request_dto fetch_req = {0};
    fetch_req.kind = CHARRA_CERTIFY_AK_OF_ATTESTER_FETCH;
    uint8_t* fetch_req_buf = NULL;
    uint32_t fetch_req_buf_len = 0;
    if ((result = charra_marshal_certify_ak_of_attester_request(&fetch_req,
                 &fetch_req_buf_len, &fetch_req_buf)) != CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Could not marshal "
                         "/certify_ak_of_attester FETCH request.");
        return result;
    }

    charra_log_info("[" LOG_NAME "] Attester identity not held by this "
                    "process yet -- FETCHing it before the relay.");
    ak_identity_rc = CHARRA_RC_ERROR;
    result = rp_coap_fetch(attester_host, attester_port,
            "certify_ak_of_attester", fetch_req_buf, fetch_req_buf_len,
            coap_ak_identity_response_handler,
            &processing_ak_identity_response);
    free(fetch_req_buf);
    if (result != CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] /certify_ak_of_attester FETCH round "
                         "trip failed.");
        return result;
    }
    if (ak_identity_rc != CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] /certify_ak_of_attester FETCH did "
                         "not complete successfully.");
        return ak_identity_rc;
    }

    /* Take ownership of the shared global's heap field, same convention as
     * the FETCH in ensure_attester_identity_provisioned(). */
    msg_ak_identity_response_dto identity = ak_identity_response;
    ak_identity_response.ek_certificate = NULL;
    ak_identity_response.ek_certificate_len = 0;

    char* manufacturer_root_der = NULL;
    size_t manufacturer_root_der_len = 0;
    if ((result = charra_io_read_file(manufacturer_root_cert_path,
                 &manufacturer_root_der, &manufacturer_root_der_len)) !=
            CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Could not read manufacturer root "
                         "certificate ('%s').",
                manufacturer_root_cert_path);
        charra_free_if_not_null(identity.ek_certificate);
        return result;
    }
    mbedtls_x509_crt attester_ek_leaf_cert;
    if ((result = charra_crypto_verify_x509_cert_chain(identity.ek_certificate,
                 identity.ek_certificate_len, (uint8_t*)manufacturer_root_der,
                 manufacturer_root_der_len, &attester_ek_leaf_cert)) !=
            CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "]     => Attester's EK certificate "
                         "does NOT verify against the manufacturer root. "
                         "Aborting.");
        charra_io_free_file_buffer(&manufacturer_root_der);
        charra_free_if_not_null(identity.ek_certificate);
        return CHARRA_RC_VERIFICATION_FAILED;
    }
    mbedtls_x509_crt_free(&attester_ek_leaf_cert);
    charra_io_free_file_buffer(&manufacturer_root_der);

    attester_identity_cached = identity;
    charra_log_info("[" LOG_NAME "] Attester identity cached (EK certificate "
                    "%u byte(s), AK public key %u byte(s)).",
            attester_identity_cached.ek_certificate_len,
            attester_identity_cached.ak_public_key_len);
    return CHARRA_RC_SUCCESS;
}

CHARRA_RC ensure_attester_identity_certified_by_verifier(
        int verifier_index) {
    if (attester_ak_cert_by_verifier_ready[verifier_index] &&
            !charra_cert_needs_renewal(
                    attester_ak_cert_by_verifier_expires_at[verifier_index])) {
        return CHARRA_RC_SUCCESS;
    }
    if (attester_ak_cert_by_verifier_ready[verifier_index]) {
        charra_log_info("[" LOG_NAME "] In-memory Attester AK certificate for "
                        "Verifier %d is near expiry -- re-provisioning.",
                verifier_index + 1);
        charra_free_if_not_null(
                attester_ak_cert_by_verifier_der[verifier_index]);
        attester_ak_cert_by_verifier_der[verifier_index] = NULL;
        attester_ak_cert_by_verifier_der_len[verifier_index] = 0;
        attester_ak_cert_by_verifier_ready[verifier_index] = false;
    }

    CHARRA_RC result = ensure_attester_identity_provisioned();
    if (result != CHARRA_RC_SUCCESS) {
        return result;
    }

    const char* verifier_host = verifiers[verifier_index].ip_address;
    unsigned int verifier_port = verifiers[verifier_index].port_number;

    char cert_path[112] = {0};
    snprintf(cert_path, sizeof(cert_path),
            "state/relying-party/attester-ak-certificates/"
            "attester-ak-certificate-verifier-%u.der",
            verifier_port);

    if (charra_io_file_exists(cert_path) == CHARRA_RC_SUCCESS) {
        char* cert_buf = NULL;
        size_t cert_buf_len = 0;
        if ((result = charra_io_read_file(cert_path, &cert_buf,
                     &cert_buf_len)) != CHARRA_RC_SUCCESS) {
            charra_log_error("[" LOG_NAME "] Could not read cached "
                             "Attester AK certificate for this Verifier.");
            return result;
        }
        uint8_t* cert_der = malloc(cert_buf_len);
        if (cert_der == NULL) {
            charra_io_free_file_buffer(&cert_buf);
            return CHARRA_RC_ERROR;
        }
        memcpy(cert_der, cert_buf, cert_buf_len);
        charra_io_free_file_buffer(&cert_buf);

        /* Expiry is acted on, not merely logged. The cache is keyed only
         * on the file existing, and the Verifier gives RP no distinct
         * signal for "the Attester's certificate is stale" the way a 4.01
         * does for RP's own -- Step 3b folds it into an ordinary failed
         * vote. So without this check an expired certificate would be
         * reloaded and re-sent every cycle, rejected every cycle, and
         * never re-provisioned: a permanent stuck state only a manual
         * delete of state/relying-party/attester-ak-certificates/ could
         * clear. Re-provision slightly early, so renewal never lands in
         * the middle of the cycle that needs the certificate. */
        bool cache_usable = false;
        mbedtls_x509_crt cached_cert;
        mbedtls_x509_crt_init(&cached_cert);
        if (mbedtls_x509_crt_parse(&cached_cert, cert_der, cert_buf_len) ==
                0) {
            long days_left =
                    charra_crypto_x509_days_until_expiry(&cached_cert);
            if (!charra_cert_needs_renewal(
                        charra_cert_expiry_time(&cached_cert))) {
                cache_usable = true;
                attester_ak_cert_by_verifier_expires_at[verifier_index] =
                        charra_cert_expiry_time(&cached_cert);
                charra_log_info("[" LOG_NAME "] Reloading previously issued "
                                "Attester AK certificate for Verifier %s:%u "
                                "(cached, expires in %ld day(s)).",
                        verifier_host, verifier_port, days_left);
            } else {
                charra_log_info("[" LOG_NAME "] Cached Attester AK "
                                "certificate for Verifier %s:%u expires in "
                                "%ld day(s) -- re-provisioning.",
                        verifier_host, verifier_port, days_left);
            }
        } else {
            charra_log_error("[" LOG_NAME "] Cached Attester AK certificate "
                             "for Verifier %s:%u does not parse -- "
                             "re-provisioning.",
                    verifier_host, verifier_port);
        }
        mbedtls_x509_crt_free(&cached_cert);

        if (cache_usable) {
            attester_ak_cert_by_verifier_der[verifier_index] = cert_der;
            attester_ak_cert_by_verifier_der_len[verifier_index] =
                    (uint32_t)cert_buf_len;
    attester_ak_cert_by_verifier_ready[verifier_index] = true;
            return CHARRA_RC_SUCCESS;
        }
        /* Fall through to the full relay below, which overwrites the file. */
        charra_free_if_not_null(cert_der);
    }

    charra_log_info("[" LOG_NAME "]  +------------ Attester Identity "
                    "Certification (Verifier %s:%u) --------------+",
            verifier_host, verifier_port);

    pthread_mutex_lock(&attester_identity_relay_mutex);

    msg_certify_ak_request_dto verifier_req = {0};
    verifier_req.kind = CHARRA_CERTIFY_AK_CHALLENGE;
    verifier_req.subject = CHARRA_CERTIFY_AK_SUBJECT_ATTESTER;
    /* Past the on-disk cache check, so the relay really is going to run:
     * make sure this process actually holds the Attester's identity before
     * putting it on the wire. */
    if ((result = ensure_attester_identity_fetched()) != CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Cannot relay /certify_ak without the "
                         "Attester's identity.");
        return result;
    }

    verifier_req.ek_certificate = attester_identity_cached.ek_certificate;
    verifier_req.ek_certificate_len =
            attester_identity_cached.ek_certificate_len;
    verifier_req.ak_public_key_len = attester_identity_cached.ak_public_key_len;
    memcpy(verifier_req.ak_public_key, attester_identity_cached.ak_public_key,
            attester_identity_cached.ak_public_key_len);
    verifier_req.ak_name_len = attester_identity_cached.ak_name_len;
    memcpy(verifier_req.ak_name, attester_identity_cached.ak_name,
            attester_identity_cached.ak_name_len);

    msg_certify_ak_response_dto verifier_challenge = {0};
    result = rp_certify_ak_exchange(
            verifier_host, verifier_port, &verifier_req, &verifier_challenge);
    if (result != CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Relayed /certify_ak CHALLENGE to "
                         "the Verifier failed.");
        pthread_mutex_unlock(&attester_identity_relay_mutex);
        return result;
    }

    /* --- relay the challenge to the Attester: only its TPM can activate
     * it, so the secret it returns is the possession proof the RP itself
     * could not have produced. ----------------------------------------- */
    msg_certify_ak_of_attester_request_dto activate_req = {0};
    activate_req.kind = CHARRA_CERTIFY_AK_OF_ATTESTER_ACTIVATE;
    activate_req.credential_blob_len = verifier_challenge.credential_blob_len;
    memcpy(activate_req.credential_blob, verifier_challenge.credential_blob,
            verifier_challenge.credential_blob_len);
    activate_req.wrapped_secret_len = verifier_challenge.wrapped_secret_len;
    memcpy(activate_req.wrapped_secret, verifier_challenge.wrapped_secret,
            verifier_challenge.wrapped_secret_len);
    charra_free_if_not_null(verifier_challenge.ak_certificate);

    uint8_t* activate_buf = NULL;
    uint32_t activate_buf_len = 0;
    result = charra_marshal_certify_ak_of_attester_request(
            &activate_req, &activate_buf_len, &activate_buf);
    if (result != CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Could not marshal ACTIVATE request.");
        pthread_mutex_unlock(&attester_identity_relay_mutex);
        return result;
    }

    activate_credential_rc = CHARRA_RC_ERROR;
    memset(&activate_credential_response, 0,
            sizeof(activate_credential_response));
    result = rp_coap_fetch(attester_host, attester_port,
            "certify_ak_of_attester", activate_buf, activate_buf_len,
            coap_activate_credential_response_handler,
            &processing_activate_credential_response);
    free(activate_buf);
    if (result == CHARRA_RC_SUCCESS && activate_credential_rc !=
            CHARRA_RC_SUCCESS) {
        result = activate_credential_rc;
    }
    if (result != CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Attester could not activate the "
                         "Verifier's challenge.");
        pthread_mutex_unlock(&attester_identity_relay_mutex);
        return result;
    }
    charra_log_info("[" LOG_NAME "] Attester activated the Verifier's "
                    "challenge (%u-byte secret recovered).",
            activate_credential_response.secret_len);

    /* --- CONFIRM on the Attester's behalf, echoing its secret --- */
    msg_certify_ak_request_dto verifier_confirm = {0};
    verifier_confirm.kind = CHARRA_CERTIFY_AK_CONFIRM;
    verifier_confirm.ek_certificate = attester_identity_cached.ek_certificate;
    verifier_confirm.ek_certificate_len =
            attester_identity_cached.ek_certificate_len;
    verifier_confirm.secret_len = activate_credential_response.secret_len;
    memcpy(verifier_confirm.secret, activate_credential_response.secret,
            activate_credential_response.secret_len);

    msg_certify_ak_response_dto verifier_cert_response = {0};
    result = rp_certify_ak_exchange(verifier_host, verifier_port,
            &verifier_confirm, &verifier_cert_response);
    if (result != CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Relayed /certify_ak CONFIRM to the "
                         "Verifier failed.");
        pthread_mutex_unlock(&attester_identity_relay_mutex);
        return result;
    }
    if (verifier_cert_response.ak_certificate_len == 0) {
        charra_log_error("[" LOG_NAME "] Verifier's CONFIRM returned no "
                         "certificate for the Attester.");
        charra_free_if_not_null(verifier_cert_response.ak_certificate);
        pthread_mutex_unlock(&attester_identity_relay_mutex);
        return CHARRA_RC_ERROR;
    }

    charra_log_info(
            "[" LOG_NAME "] Verifier certified the Attester's AK (relayed).");

    /* --- deliver a copy to the Attester too, for its own records. RP
     * itself is what actually forwards the right certificate to each
     * Verifier during /appraise (charra_rp_build_evidence_message()
     * substitutes attester_ak_cert_by_verifier_der[] directly), so this
     * leg is informational only now, not load-bearing -- non-fatal on
     * failure, and harmless if a later Verifier's copy overwrites it
     * (attester.c caches only the most recent one). --------------------- */
    msg_certify_ak_of_attester_request_dto deliver_verifier_req = {0};
    deliver_verifier_req.kind = CHARRA_CERTIFY_AK_OF_ATTESTER_DELIVER_VERIFIER;
    deliver_verifier_req.ak_certificate_len =
            verifier_cert_response.ak_certificate_len;
    deliver_verifier_req.ak_certificate = verifier_cert_response.ak_certificate;

    uint8_t* deliver_verifier_buf = NULL;
    uint32_t deliver_verifier_buf_len = 0;
    if (charra_marshal_certify_ak_of_attester_request(&deliver_verifier_req,
                &deliver_verifier_buf_len, &deliver_verifier_buf) !=
            CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Could not marshal DELIVER_VERIFIER "
                         "request (non-fatal).");
    } else if (rp_coap_fetch(attester_host, attester_port,
                       "certify_ak_of_attester", deliver_verifier_buf,
                       deliver_verifier_buf_len,
                       coap_certify_ak_of_attester_deliver_response_handler,
                       &processing_certify_ak_of_attester_deliver_response) !=
            CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] DELIVER_VERIFIER round trip to the "
                         "Attester failed (non-fatal -- RP already holds "
                         "the certificate itself).");
    }
    free(deliver_verifier_buf);

    pthread_mutex_unlock(&attester_identity_relay_mutex);

    if ((result = charra_io_write_file(cert_path,
                 verifier_cert_response.ak_certificate,
                 verifier_cert_response.ak_certificate_len)) !=
            CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Could not cache Attester AK "
                         "certificate for this Verifier.");
        charra_free_if_not_null(verifier_cert_response.ak_certificate);
        return result;
    }

    attester_ak_cert_by_verifier_der[verifier_index] =
            verifier_cert_response.ak_certificate;
    attester_ak_cert_by_verifier_der_len[verifier_index] =
            verifier_cert_response.ak_certificate_len;
    /* Expiry of the freshly issued certificate -- see the same note in
     * ensure_rp_ak_certificate(). */
    {
        mbedtls_x509_crt issued;
        mbedtls_x509_crt_init(&issued);
        attester_ak_cert_by_verifier_expires_at[verifier_index] = 0;
        if (mbedtls_x509_crt_parse(&issued,
                    verifier_cert_response.ak_certificate,
                    verifier_cert_response.ak_certificate_len) == 0) {
            attester_ak_cert_by_verifier_expires_at[verifier_index] =
                    charra_cert_expiry_time(&issued);
        }
        mbedtls_x509_crt_free(&issued);
    }
    attester_ak_cert_by_verifier_ready[verifier_index] = true;

    charra_log_info(
            "[" LOG_NAME "] Attester's AK certified by Verifier %s:%u "
            "(%u-byte certificate).",
            verifier_host, verifier_port,
            verifier_cert_response.ak_certificate_len);

    return CHARRA_RC_SUCCESS;
}

/**
 * @brief Sends RP's Step 2a verdict to the Attester (/attest_result).
 *
 * The spec's Step 2a says "-> fail: negative proof to Attester", but the
 * Attester is the server of /attest -- its evidence is the final message of
 * that exchange, leaving RP no reply slot to reject it in. So the verdict
 * goes as a separate RP-initiated request, which also keeps the Attester a
 * pure passive responder.
 *
 * Deliberately called from get_evidence() *after* its CoAP loop finishes,
 * never from inside coap_attester_handler(): starting a second exchange
 * from within a libcoap response callback re-enters the stack while the
 * first context is still mid-dispatch.
 *
 * Advisory: a failure to deliver is logged and otherwise ignored -- the
 * appraisal verdict itself is already decided.
 */
void rp_send_attestation_result(bool accepted, const char* reason) {
    msg_attestation_result_dto res = {0};
    res.accepted = accepted ? 1 : 0;
    if (reason != NULL) {
        size_t len = strlen(reason);
        if (len > sizeof(res.reason)) {
            len = sizeof(res.reason);
        }
        res.reason_len = (uint32_t)len;
        memcpy(res.reason, reason, len);
    }

    uint8_t* buf = NULL;
    uint32_t buf_len = 0;
    if (charra_marshal_attestation_result(&res, &buf_len, &buf) !=
            CHARRA_RC_SUCCESS) {
        charra_log_error(
                "[" LOG_NAME "] Could not marshal /attest_result verdict.");
        return;
    }

    if (rp_coap_fetch(attester_host, attester_port, "attest_result", buf,
                buf_len, coap_certify_ak_of_attester_deliver_response_handler,
                &processing_certify_ak_of_attester_deliver_response) !=
            CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Could not deliver /attest_result "
                         "verdict to the Attester (non-fatal).");
    } else {
        charra_log_info("[" LOG_NAME "] Sent Step 2a verdict (%s) to the "
                        "Attester.",
                accepted ? "accepted" : "REJECTED");
    }
    free(buf);
}
