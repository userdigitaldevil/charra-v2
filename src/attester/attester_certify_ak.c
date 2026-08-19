/**
 * @file attester_certify_ak.c
 * @brief See attester_certify_ak.h.
 *
 * /certify_ak_of_attester: the RP-mediated provisioning of this Attester's
 * AK identity. Owns the two certificate paths the DELIVER legs write.
 */


#include "attester_certify_ak.h"
#include "../common/charra_log.h"
#include <tss2/tss2_tctildr.h>

#include "../common/charra_macro.h"
#include "../core/charra_identity_key_mgr.h"
#include "../core/charra_marshaling.h"
#include "../util/coap_util.h"
#include "../util/io_util.h"
#include "attester_shared.h"
#include "attester_identity.h"
#include "attester_util.h"

#define LOG_NAME "attester"

/* The two independently-issued certificates for this Attester's identity --
 * one per CA, neither trusting the other's issuance (see
 * CHARRA_CERTIFY_AK_OF_ATTESTER_* in charra_dto.h). Written here by the
 * DELIVER legs; read fresh from disk by /attest on every call rather than
 * cached, since DELIVER_VERIFIER can rewrite the second at any time. */
char* attester_ak_cert_rp_path =
        "state/attester/ak-certificates/attester-ak-certificate-rp.der";
char* attester_ak_cert_verifier_path =
        "state/attester/ak-certificates/attester-ak-certificate-verifier.der";

/**
 * @brief /certify_ak_of_attester: the Attester's single resource for all
 * three legs of getting its own AK certified, always RP-initiated -- see
 * CHARRA_CERTIFY_AK_OF_ATTESTER_* in charra_dto.h.
 */
void coap_certify_ak_of_attester_handler(
        struct coap_resource_t* resource, struct coap_session_t* session,
        const struct coap_pdu_t* request, const struct coap_string_t* query,
        struct coap_pdu_t* response) {
    int coap_r = 0;
    CHARRA_RC charra_r = CHARRA_RC_ERROR;
    coap_pdu_code_t response_code = COAP_RESPONSE_CODE_INTERNAL_ERROR;
    /* Declared and zeroed here, before any 'goto cleanup', so the cleanup
     * block can always safely free req.ak_certificate -- same convention
     * this file's coap_attest_handler() and verifier.c's handlers use. */
    msg_certify_ak_of_attester_request_dto req = {0};
    uint8_t* marshaled_response = NULL;
    uint32_t marshaled_response_len = 0;

    charra_coap_log_peer_address(LOG_NAME, "/certify_ak_of_attester", session);

    if ((charra_r = ensure_attester_ak_keypair()) != CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] /certify_ak_of_attester: could not "
                         "ensure Attester AK identity.");
        goto cleanup;
    }

    size_t data_len = 0;
    const uint8_t* data = NULL;
    if (!charra_coap_get_payload(request, LOG_NAME, "/certify_ak_of_attester",
                &data, &data_len, NULL)) {
        response_code = COAP_RESPONSE_CODE_BAD_REQUEST;
        goto cleanup;
    }

    if ((charra_r = charra_unmarshal_certify_ak_of_attester_request(
                 data_len, data, &req)) != CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] /certify_ak_of_attester: could not "
                         "parse CBOR request.");
        response_code = COAP_RESPONSE_CODE_BAD_REQUEST;
        goto cleanup;
    }

    if (req.kind == CHARRA_CERTIFY_AK_OF_ATTESTER_FETCH) {
        charra_log_info("[" LOG_NAME "] /certify_ak_of_attester: FETCH -- "
                        "sending EK certificate + AK identity.");

        char* ek_cert_buf = NULL;
        size_t ek_cert_buf_len = 0;
        if ((charra_r = charra_io_read_file(attester_ek_cert_cache_path,
                     &ek_cert_buf, &ek_cert_buf_len)) != CHARRA_RC_SUCCESS) {
            charra_log_error("[" LOG_NAME "] /certify_ak_of_attester: could "
                             "not read Attester's EK certificate.");
            goto cleanup;
        }

        TPM2B_PUBLIC ak_public = {0};
        if ((charra_r = charra_identity_key_mgr_load_public(attester_ak_public_path,
                     &ak_public)) != CHARRA_RC_SUCCESS) {
            charra_log_error("[" LOG_NAME "] /certify_ak_of_attester: could "
                             "not load AK public key.");
            charra_io_free_file_buffer(&ek_cert_buf);
            goto cleanup;
        }

        /* --- short TPM session purely to read the AK's TPM2B_NAME; no
         * ActivateCredential or signing happens on the FETCH leg. --- */
        ESYS_CONTEXT* esys_ctx = NULL;
        TSS2_TCTI_CONTEXT* tcti_ctx = NULL;
        ESYS_TR ek_handle = ESYS_TR_NONE;
        ESYS_TR ak_handle = ESYS_TR_NONE;
        TPM2B_NAME* ak_name = NULL;
        if ((charra_r = attester_open_tpm_and_load_ak(&esys_ctx, &tcti_ctx,
                     &ek_handle, &ak_handle, &ak_name, NULL)) !=
                CHARRA_RC_SUCCESS) {
            charra_log_error("[" LOG_NAME "] /certify_ak_of_attester: could "
                             "not open TPM connection to load AK.");
            charra_io_free_file_buffer(&ek_cert_buf);
            goto cleanup;
        }

        msg_ak_identity_response_dto resp = {0};
        resp.ek_certificate = (uint8_t*)ek_cert_buf;
        resp.ek_certificate_len = (uint32_t)ek_cert_buf_len;
        resp.ak_public_key_len = sizeof(ak_public);
        memcpy(resp.ak_public_key, &ak_public, sizeof(ak_public));
        /* Copy only the meaningful prefix (size field + size bytes) and
         * zero the rest: Esys_TR_GetName() leaves the tail of the
         * TPM2B_NAME allocation uninitialised, and copying the whole
         * struct put those heap bytes straight onto the wire (caught by
         * valgrind via libcoap reading them while building the PDU).
         * The field stays fixed-size, so the wire format is unchanged --
         * the tail is now deterministic zeros instead of stale heap. */
        resp.ak_name_len = sizeof(*ak_name);
        memset(resp.ak_name, 0, sizeof(resp.ak_name));
        memcpy(resp.ak_name, ak_name,
                sizeof(ak_name->size) + ak_name->size);

        Esys_Free(ak_name);
        Esys_FlushContext(esys_ctx, ak_handle);
        Esys_FlushContext(esys_ctx, ek_handle);
        Esys_Finalize(&esys_ctx);
        Tss2_TctiLdr_Finalize(&tcti_ctx);

        charra_r = charra_marshal_ak_identity_response(
                &resp, &marshaled_response_len, &marshaled_response);
        charra_io_free_file_buffer(&ek_cert_buf);
        if (charra_r != CHARRA_RC_SUCCESS) {
            charra_log_error("[" LOG_NAME "] /certify_ak_of_attester: could "
                             "not marshal FETCH response.");
            goto cleanup;
        }
        response_code = COAP_RESPONSE_CODE_CONTENT;
    } else if (req.kind == CHARRA_CERTIFY_AK_OF_ATTESTER_ACTIVATE) {
        /* A Verifier's /certify_ak CHALLENGE, relayed. Activating it proves
         * this TPM holds the EK/AK; the RP relays the secret back as that
         * Verifier's CONFIRM. */
        charra_log_info("[" LOG_NAME "] /certify_ak_of_attester: ACTIVATE -- "
                        "recovering the Verifier's challenge secret.");

        ESYS_CONTEXT* esys_ctx = NULL;
        TSS2_TCTI_CONTEXT* tcti_ctx = NULL;
        ESYS_TR ek_handle = ESYS_TR_NONE;
        ESYS_TR ak_handle = ESYS_TR_NONE;
        TPM2B_NAME* ak_name = NULL;
        if ((charra_r = attester_open_tpm_and_load_ak(&esys_ctx, &tcti_ctx,
                     &ek_handle, &ak_handle, &ak_name, NULL)) !=
                CHARRA_RC_SUCCESS) {
            charra_log_error("[" LOG_NAME "] /certify_ak_of_attester: could "
                             "not open TPM connection for ActivateCredential.");
            goto cleanup;
        }
        Esys_Free(ak_name);

        TPM2B_DIGEST* credential = NULL;
        charra_r = charra_identity_key_mgr_activate_credential(esys_ctx,
                ak_handle, ek_handle, (TPM2B_ID_OBJECT*)req.credential_blob,
                (TPM2B_ENCRYPTED_SECRET*)req.wrapped_secret, &credential);
        Esys_FlushContext(esys_ctx, ak_handle);
        Esys_FlushContext(esys_ctx, ek_handle);
        Esys_Finalize(&esys_ctx);
        Tss2_TctiLdr_Finalize(&tcti_ctx);
        if (charra_r != CHARRA_RC_SUCCESS) {
            charra_log_error(
                    "[" LOG_NAME "] /certify_ak_of_attester: ActivateCredential "
                    "failed -- this AK is not genuinely bound to this EK.");
            response_code = COAP_RESPONSE_CODE_UNAUTHORIZED;
            goto cleanup;
        }

        msg_activate_credential_response_dto activate_resp = {0};
        if (credential->size > sizeof(activate_resp.secret)) {
            charra_log_error("[" LOG_NAME "] /certify_ak_of_attester: "
                             "recovered secret is unexpectedly large (%u).",
                    credential->size);
            Esys_Free(credential);
            charra_r = CHARRA_RC_ERROR;
            goto cleanup;
        }
        activate_resp.secret_len = credential->size;
        memcpy(activate_resp.secret, credential->buffer, credential->size);
        Esys_Free(credential);

        if ((charra_r = charra_marshal_activate_credential_response(
                     &activate_resp, &marshaled_response_len,
                     &marshaled_response)) != CHARRA_RC_SUCCESS) {
            charra_log_error("[" LOG_NAME "] /certify_ak_of_attester: could "
                             "not marshal ACTIVATE response.");
            goto cleanup;
        }

        charra_log_info("[" LOG_NAME "] /certify_ak_of_attester: ACTIVATE -- "
                        "returning the %u-byte secret to the RP.",
                activate_resp.secret_len);
        response_code = COAP_RESPONSE_CODE_CONTENT;
    } else if (req.kind == CHARRA_CERTIFY_AK_OF_ATTESTER_DELIVER_RP ||
            req.kind == CHARRA_CERTIFY_AK_OF_ATTESTER_DELIVER_VERIFIER) {
        bool is_rp_leg = (req.kind == CHARRA_CERTIFY_AK_OF_ATTESTER_DELIVER_RP);
        const char* leg_name = is_rp_leg ? "DELIVER_RP" : "DELIVER_VERIFIER";
        const char* out_path = is_rp_leg ? attester_ak_cert_rp_path
                                         : attester_ak_cert_verifier_path;
        charra_log_info("[" LOG_NAME "] /certify_ak_of_attester: %s -- "
                        "persisting delivered AK certificate.",
                leg_name);

        uint8_t* ak_cert_der = NULL;

        if (is_rp_leg) {
            /* RP is the CA on this leg and still uses the one-shot wrapped
             * form, so unwrapping here is what proves EK/AK possession. */
            ESYS_CONTEXT* esys_ctx = NULL;
            TSS2_TCTI_CONTEXT* tcti_ctx = NULL;
            ESYS_TR ek_handle = ESYS_TR_NONE;
            ESYS_TR ak_handle = ESYS_TR_NONE;
            TPM2B_NAME* ak_name = NULL;
            if ((charra_r = attester_open_tpm_and_load_ak(&esys_ctx, &tcti_ctx,
                         &ek_handle, &ak_handle, &ak_name, NULL)) !=
                    CHARRA_RC_SUCCESS) {
                charra_log_error(
                        "[" LOG_NAME "] /certify_ak_of_attester: could not "
                        "open TPM connection for ActivateCredential.");
                goto cleanup;
            }
            Esys_Free(ak_name);

            TPM2B_DIGEST* credential = NULL;
            charra_r = charra_identity_key_mgr_activate_credential(esys_ctx,
                    ak_handle, ek_handle, (TPM2B_ID_OBJECT*)req.credential_blob,
                    (TPM2B_ENCRYPTED_SECRET*)req.wrapped_secret, &credential);
            Esys_FlushContext(esys_ctx, ak_handle);
            Esys_FlushContext(esys_ctx, ek_handle);
            Esys_Finalize(&esys_ctx);
            Tss2_TctiLdr_Finalize(&tcti_ctx);
            if (charra_r != CHARRA_RC_SUCCESS) {
                charra_log_error("[" LOG_NAME
                                 "] /certify_ak_of_attester: ActivateCredential "
                                 "failed -- this AK is not genuinely bound to "
                                 "this EK.");
                response_code = COAP_RESPONSE_CODE_UNAUTHORIZED;
                goto cleanup;
            }

            charra_r = charra_crypto_aes256gcm_decrypt(credential->buffer,
                    req.ak_certificate, req.ak_certificate_len,
                    req.aes_gcm_nonce, req.aes_gcm_tag, &ak_cert_der);
            Esys_Free(credential);
            if (charra_r != CHARRA_RC_SUCCESS) {
                charra_log_error("[" LOG_NAME "] /certify_ak_of_attester: could "
                                 "not decrypt delivered AK certificate.");
                goto cleanup;
            }
        }

        charra_r = charra_io_write_file(out_path,
                is_rp_leg ? ak_cert_der : req.ak_certificate,
                req.ak_certificate_len);
        free(ak_cert_der);
        if (charra_r != CHARRA_RC_SUCCESS) {
            charra_log_error("[" LOG_NAME "] /certify_ak_of_attester: could "
                             "not persist delivered AK certificate.");
            goto cleanup;
        }

        charra_log_info("[" LOG_NAME "] /certify_ak_of_attester: %s "
                        "certificate persisted (%u byte(s)).",
                leg_name, req.ak_certificate_len);
        response_code = COAP_RESPONSE_CODE_CONTENT;
    } else {
        charra_log_error(
                "[" LOG_NAME "] /certify_ak_of_attester: unknown kind %u.",
                req.kind);
        response_code = COAP_RESPONSE_CODE_BAD_REQUEST;
        goto cleanup;
    }

cleanup:
    coap_pdu_set_code(response, response_code);
    if (marshaled_response != NULL) {
        if ((coap_r = coap_add_data_large_response(resource, session, request,
                     response, query, COAP_MEDIATYPE_APPLICATION_CBOR, -1, 0,
                     marshaled_response_len, marshaled_response, attester_release_data,
                     marshaled_response)) == 0) {
            charra_log_error("[" LOG_NAME "] /certify_ak_of_attester: error "
                             "invoking coap_add_data_large_response().");
        }
    } else {
        /* DELIVER_RP/DELIVER_VERIFIER (and every error path): a bare
         * ack -- same "code-only response" convention /qualify/submit
         * uses when there's no payload worth sending back. */
        coap_add_data_large_response(resource, session, request, response,
                query, COAP_MEDIATYPE_TEXT_PLAIN, -1, 0, 0, NULL, NULL, NULL);
    }
    /* req.ak_certificate is heap-allocated by charra_unmarshal_certify_ak_
     * of_attester_request() -- this handler's own to free, same convention
     * as verifier.c's coap_qualify_submit_handler(). */
    charra_free_if_not_null(req.ak_certificate);
}
