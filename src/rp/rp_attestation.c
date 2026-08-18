/**
 * @file rp_attestation.c
 * @brief See rp_attestation.h.
 *
 * All four CoAP response handlers live here with the phases that drive
 * them: each writes dedicated globals that its caller reads back, since a
 * libcoap callback cannot return data.
 */

#include "rp_attestation.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "../common/charra_log.h"
#include "../common/charra_macro.h"
#include "../core/charra_dto.h"
#include "../core/charra_marshaling.h"
#include "../util/charra_util.h"
#include "../util/coap_util.h"
#include "../util/io_util.h"
#include "rp_attester_identity.h"
#include "rp_coap.h"
#include "rp_evidence.h"
#include "rp_identity.h"
#include "rp_qualification.h"
#include "rp_shared.h"

#define LOG_NAME "relying party"

static CHARRA_RC create_attestation_request(msg_attestation_request_dto* attestation_request) {
    CHARRA_RC err = CHARRA_RC_ERROR;
    
    /* generate nonce */
    const uint32_t nonce_len = 20;
    uint8_t nonce[nonce_len];
    if (USE_TPM_FOR_RANDOM_NONCE_GENERATION) {
        if ((err = charra_random_bytes_from_tpm(nonce_len, nonce)) !=
                CHARRA_RC_SUCCESS) {
            charra_log_error("[" LOG_NAME "] Could not get random bytes "
                             "from TPM for nonce: CHARRA_RC=%d.",
                    err);
            return err;
        }
    } else {
        if ((err = charra_random_bytes(nonce_len, nonce)) !=
                CHARRA_RC_SUCCESS) {
            charra_log_error(
                    "[" LOG_NAME "] Could not get random bytes for nonce: "
                    "CHARRA_RC=%d.",
                    err);
            return err;
        }
    }

    charra_log_info("[" LOG_NAME "] Generated nonce of length %d:", nonce_len);
    charra_print_hex(CHARRA_LOG_INFO, nonce_len, nonce,
            "                                                  0x", "\n",
            false);

    /* build attestation request */
    msg_attestation_request_dto req = {
            .hello = false,
            .sig_key_id_len = TPM_SIG_KEY_ID_LEN,
            .sig_key_id = {0},  // must be memcpy'd, see below
            .nonce_len = nonce_len,
            .nonce = {0},  // must be memcpy'd, see below
            .pcr_selections_len = 1,
            .pcr_selections = {{
                    .tcg_hash_alg_id = TPM2_ALG_SHA256,
                    .pcrs_len = tpm_pcr_selection_len,
                    .pcrs = {0}  // must be memcpy'd, see below
            }},
            .event_log_path_len =
                    (use_ima_event_log || use_ima_test_log) ? ((use_ima_event_log) ? strlen(ima_event_log_path) : strlen(ima_test_log_path)) : 0,
            .event_log_path =
                    (use_ima_event_log || use_ima_test_log) ? ((use_ima_event_log) ? (uint8_t*)ima_event_log_path : (uint8_t*)ima_test_log_path) : NULL,
    };
    memcpy(req.sig_key_id, TPM_SIG_KEY_ID, TPM_SIG_KEY_ID_LEN);
    memcpy(req.nonce, nonce, nonce_len);
    memcpy(req.pcr_selections->pcrs, tpm_pcr_selection, tpm_pcr_selection_len);

    /* set output param(s) */
    *attestation_request = req;

    /* return result */
    return CHARRA_RC_SUCCESS;
}

static coap_response_t coap_attester_handler(
        coap_session_t* session CHARRA_UNUSED,
        const coap_pdu_t* sent CHARRA_UNUSED,
        const coap_pdu_t* received,
        const coap_mid_t mid CHARRA_UNUSED) {
    int coap_r = 0;

    processing_attestation_response = true;

    coap_show_pdu(LOG_DEBUG, received);

    /* --- receive incoming data --- */

    /* get data */
    size_t data_len = 0;
    const uint8_t* data = NULL;
    size_t data_offset = 0;
    size_t data_total_len = 0;
    if ((coap_r = coap_get_data_large(
                 received, &data_len, &data, &data_offset, &data_total_len)) == 0) {
        charra_log_error("[" LOG_NAME "] Could not get CoAP PDU data.");
        attestation_rc = CHARRA_RC_ERROR;
        goto cleanup;
    } else {
        // charra_log_info(
        //         "[" LOG_NAME "] Received data of length %zu.", data_len);
        charra_log_info("[" LOG_NAME "] Received evidence of total length %zu.",
                data_total_len);
    }

    /* unmarshal data */
    // charra_log_info("[" LOG_NAME "] Parsing received CBOR data.\n");
    msg_attestation_response_dto res = {0};
    if ((attestation_rc = charra_unmarshal_attestation_response(
                 data_len, data, &res)) != CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Could not parse CBOR data.");
        goto cleanup;
    }
    /* appraise the evidence locally before forwarding any of it */
    if (!charra_rp_appraise_evidence(&res)) {
        attestation_rc = CHARRA_RC_VERIFICATION_FAILED;
        /* res is fully unmarshaled by now and owns heap buffers; it never
         * reaches last_response on this path, so free it here. */
        charra_free_attestation_response(&res);
        goto cleanup;
    }

    /* NOT actually forwarding yet -- charra_rp_prepare_evidence() (privacy
     * cleaning: redact the log, build Quote_r) still has to run first, in
     * get_attestation_results() below. The real "Forwarding evidence to the
     * verifiers" log is there, after that redaction succeeds. */
    charra_log_info(
            "[" LOG_NAME "] Evidence appraised locally; privacy-cleaning "
            "before forwarding to the Verifiers.");
    /* Store last response, releasing the previous cycle's buffers first --
     * a plain struct assignment would otherwise orphan them once this
     * handler runs more than once (daemon mode). Safe here: get_evidence()
     * completes fully before get_attestation_results() spawns the Verifier
     * threads that read last_response, so nothing still points into the
     * old buffers by the time this runs again. */
    charra_free_attestation_response(&last_response);
    last_response = res;

cleanup:

    processing_attestation_response = false;
    return COAP_RESPONSE_OK;
}

static coap_response_t coap_verifier_handler_nonce(coap_session_t* session,
        const coap_pdu_t* sent CHARRA_UNUSED, const coap_pdu_t* received,
        const coap_mid_t mid CHARRA_UNUSED) {
    int* index = coap_session_get_app_data(session);

    size_t data_len = 0;
    const uint8_t* data = NULL;
    size_t data_offset = 0;
    size_t data_total_len = 0;
    if (coap_get_data_large(received, &data_len, &data, &data_offset,
                &data_total_len) == 0) {
        charra_log_error("[" LOG_NAME "] Verifier returned no nonce.");
        goto cleanup;
    }
    if (index == NULL || data_len == 0 ||
            data_len > sizeof(verifier_nonces[0])) {
        charra_log_error("[" LOG_NAME "] Verifier nonce has an unusable "
                         "length (%zu bytes).",
                data_len);
        goto cleanup;
    }

    memcpy(verifier_nonces[*index], data, data_len);
    verifier_nonce_lens[*index] = (uint32_t)data_len;
    charra_log_info("[" LOG_NAME "] Received nonce of %zu bytes from Verifier "
                    "n\u00b0 %d.",
            data_len, *index + 1);

cleanup:
    if (index != NULL) {
        processing_nonce_response[*index] = false;
    }
    return COAP_RESPONSE_OK;
}

static coap_response_t coap_verifier_handler_appraisal(coap_session_t* session,
        const coap_pdu_t* sent CHARRA_UNUSED,
        const coap_pdu_t* received,
        const coap_mid_t mid CHARRA_UNUSED) {
            
    int* current_thread_index = coap_session_get_app_data(session);
    processing_appraisal_response[*current_thread_index] = true;

    rp_ak_cert_rejected[*current_thread_index] = false;
    rp_qualification_rejected[*current_thread_index] = false;

    if (coap_pdu_get_code(received) == COAP_RESPONSE_CODE_UNAUTHORIZED) {
        /* Verifier rejected our AK certificate specifically (see
         * verifier.c's coap_appraise_handler, Step 3a item 1), not the
         * evidence itself -- signal the caller to re-provision via
         * /certify_ak and retry, rather than just recording a failed
         * vote a blind retry could never fix. */
        charra_log_info("[" LOG_NAME "] Verifier n° %d (port %u) rejected "
                        "our AK certificate as invalid or expired.",
                *current_thread_index + 1,
                verifiers[*current_thread_index].port_number);
        snprintf(rejection_reason[*current_thread_index],
                sizeof(rejection_reason[*current_thread_index]),
                "AK certificate rejected as invalid or expired");
        rp_ak_cert_rejected[*current_thread_index] = true;
        attestation_results[*current_thread_index] = false;
        goto cleanup;
    }

    if (coap_pdu_get_code(received) == COAP_RESPONSE_CODE_FORBIDDEN) {
        /* Verifier rejected our qualification specifically (see verifier.c's
         * coap_appraise_handler, Step 3a item 1b) -- either we never
         * qualified with it, or a grant we thought was still valid (per our
         * own local cache, rp_qualified_until) has expired on its end.
         * Either way, the message text says which; log it, then signal the
         * caller to invalidate the local cache, redo /qualify +
         * /qualify/submit, and retry -- same one-retry pattern as the AK
         * certificate case above. */
        size_t forbidden_data_len = 0;
        const uint8_t* forbidden_data = NULL;
        size_t forbidden_data_offset = 0;
        size_t forbidden_data_total_len = 0;
        if (coap_get_data_large(received, &forbidden_data_len,
                    &forbidden_data, &forbidden_data_offset,
                    &forbidden_data_total_len) != 0) {
            charra_log_info("[" LOG_NAME "] Verifier n° %d (port %u): %.*s",
                    *current_thread_index + 1,
                    verifiers[*current_thread_index].port_number,
                    (int)forbidden_data_len, (const char*)forbidden_data);
            int n = (int)forbidden_data_len <
                                    (int)sizeof(
                                            rejection_reason[0]) - 1
                            ? (int)forbidden_data_len
                            : (int)sizeof(rejection_reason[0]) - 1;
            snprintf(rejection_reason[*current_thread_index],
                    sizeof(rejection_reason[*current_thread_index]), "%.*s",
                    n, (const char*)forbidden_data);
        } else {
            charra_log_info("[" LOG_NAME "] Verifier n° %d (port %u) "
                            "rejected our qualification.",
                    *current_thread_index + 1,
                    verifiers[*current_thread_index].port_number);
            snprintf(rejection_reason[*current_thread_index],
                    sizeof(rejection_reason[*current_thread_index]),
                    "qualification rejected");
        }
        rp_qualification_rejected[*current_thread_index] = true;
        attestation_results[*current_thread_index] = false;
        goto cleanup;
    }

    int coap_r = 0;
    size_t data_len = 0;
    const uint8_t* data = NULL;
    size_t data_offset = 0;
    size_t data_total_len = 0;
    if ((coap_r = coap_get_data_large(
                 received, &data_len, &data, &data_offset, &data_total_len)) == 0) {
        charra_log_error("[" LOG_NAME "] Could not get CoAP PDU data.");
        attestation_rc = CHARRA_RC_ERROR;
        goto cleanup;
    }

    const char* successful_message = "Attestation successful!\0";

    /* memcmp against the exact sent length, not strcmp on data: data points
     * into the PDU buffer as received (data_len bytes, per
     * coap_add_data_large_response()'s strlen()-based length on the
     * Verifier's side), with no guaranteed NUL terminator past it. */
    if (data_len == strlen(successful_message) &&
            memcmp(data, successful_message, data_len) == 0) {
        attestation_results[*current_thread_index] = true;
    } else {
        charra_log_info("[" LOG_NAME "] False\n");
        attestation_results[*current_thread_index] = false;
    }

cleanup:
    processing_appraisal_response[*current_thread_index] = false;
    return COAP_RESPONSE_OK;
}

static coap_response_t coap_trust_manager_handler(coap_session_t* session,
                                        const coap_pdu_t* sent CHARRA_UNUSED,
                                        const coap_pdu_t* received,
                                        const coap_mid_t mid CHARRA_UNUSED) {
    
    processing_trust_manager_response = true;
    int coap_r = 0;
    int num_verifiers = *(int *)coap_session_get_app_data(session); 
    /* get data */
    size_t data_len = 0;
    const uint8_t* data = NULL;
    size_t data_offset = 0;
    size_t data_total_len = 0;
    if ((coap_r = coap_get_data_large(
                 received, &data_len, &data, &data_offset, &data_total_len)) == 0) {
        charra_log_error("[" LOG_NAME "] Could not get CoAP PDU data.");
        goto cleanup;
    } else {
        charra_log_info(
                "[" LOG_NAME "] Received data of length %zu.", data_len);
        charra_log_info("[" LOG_NAME "] Received data of total length %zu.",
                data_total_len);
    }

    /* Unmarshal via the same shared, tested CBOR marshal/unmarshal pattern
     * every other endpoint in this codebase uses (charra_marshaling.c) --
     * replaces the hand-packed raw-byte layout this used to parse
     * manually, with no bounds check tying the response's declared length
     * to how many records it actually contains. That gap is exactly what
     * once let a Trust Manager response shorter (or, via a since-fixed
     * response_len bug on the Trust Manager side, longer) than expected
     * be silently over- or mis-read -- see CHARRA_V2_NOTES.md.
     * charra_unmarshal_get_verifiers_response() rejects a malformed or
     * oversized response outright instead. */
    msg_get_verifiers_response_dto resp = {0};
    CHARRA_RC charra_r = charra_unmarshal_get_verifiers_response(
            (uint32_t)data_total_len, data, &resp);
    if (charra_r != CHARRA_RC_SUCCESS) {
        charra_log_error(
                "[" LOG_NAME "] Could not parse CBOR response: CHARRA_RC=%d.",
                charra_r);
        goto cleanup;
    }

    /* Trust Manager can legitimately return FEWER records than
     * num_verifiers requested, if some of the requested IDs aren't in its
     * verifiers_config.txt (see trust_manager.c's "Lookup summary: ...
     * missing" log) -- copy only as many as actually arrived. num_verifiers
     * itself was already bounds-checked against MAX_VERIFIERS before this
     * request was ever sent (see get_verifiers()), so verifiers[] below
     * can't overflow either way. */
    size_t verifiers_to_copy = resp.verifiers_len;
    if (verifiers_to_copy > (size_t)num_verifiers) {
        charra_log_error(
                "[" LOG_NAME "] Trust Manager returned %u verifier "
                "record(s), more than the %d requested -- ignoring the "
                "extra.",
                resp.verifiers_len, num_verifiers);
        verifiers_to_copy = (size_t)num_verifiers;
    } else if (verifiers_to_copy < (size_t)num_verifiers) {
        charra_log_error(
                "[" LOG_NAME "] Trust Manager returned %u verifier "
                "record(s), expected %d -- some requested Verifier ID(s) "
                "are missing from its configuration.",
                resp.verifiers_len, num_verifiers);
    }

    for (size_t i = 0; i < verifiers_to_copy; i++) {
        snprintf(verifiers[i].ip_address, sizeof(verifiers[i].ip_address),
                "%s", resp.verifiers[i].ip_address);
        verifiers[i].port_number = resp.verifiers[i].port_number;
    }

    /* Print the received verifier information */
    for (size_t i = 0; i < verifiers_to_copy; i++) {
            charra_log_info(
            "[" LOG_NAME
            "] Verifier ID %d: IP Address = %s, Port Number = %u", verifier_list[i], verifiers[i].ip_address, verifiers[i].port_number);
    }

cleanup:
    processing_trust_manager_response = false;
    return COAP_RESPONSE_OK;
}

CHARRA_RC get_verifiers(int* verifier_list, int num_verifiers) {

    if (num_verifiers > MAX_VERIFIERS) {
        charra_log_error(
                "[" LOG_NAME "] Requested %d verifier(s), but this process "
                "only has room for %d (MAX_VERIFIERS) -- refusing to "
                "overflow verifier_list/verifiers/attestation_results.",
                num_verifiers, MAX_VERIFIERS);
        return CHARRA_RC_BAD_ARGUMENT;
    }

    charra_log_info("[" LOG_NAME "]  +------------ Interaction with the Trust Manager --------------+");

    CHARRA_RC result = EXIT_FAILURE;

    coap_context_t* coap_context = NULL;
    coap_session_t* coap_session = NULL;
    coap_optlist_t* coap_options = NULL;
    /* Declared/NULLed here, not at first use further down, so the
     * request-marshaling failure's own 'goto cleanup' (and every other
     * early exit) can safely charra_free_if_not_null() it -- same
     * hoisted-declaration convention this file already uses elsewhere
     * (e.g. get_attestation_results_thread()'s own comment on this exact
     * pattern). */
    uint8_t* req_buf = NULL;

    charra_log_info("[" LOG_NAME "] Initializing CoAP in block-wise mode.");
    if ((coap_context = charra_coap_new_context(true)) == NULL) {
        charra_log_error("[" LOG_NAME "] Cannot create CoAP context.");
        result = CHARRA_RC_COAP_ERROR;
        goto cleanup;
    }

    charra_log_info(
            "[" LOG_NAME "] Creating CoAP client session using UDP.");
    if ((coap_session = charra_coap_new_client_session(coap_context,
                    trust_manager_host, trust_manager_port, COAP_PROTO_UDP)) == NULL) {
        charra_log_error("[" LOG_NAME
                            "] Cannot create client session based on UDP.");
        result = CHARRA_RC_COAP_ERROR;
        goto cleanup;
    }

    charra_log_info("[" LOG_NAME "] Registering CoAP response handler.");
    coap_register_response_handler(coap_context, coap_trust_manager_handler);

    coap_session_set_app_data(coap_session, (void *)&num_verifiers);

    /* Marshal the request via the shared, tested CBOR marshal/unmarshal
     * pattern (charra_marshaling.c), replacing the raw int[] this used to
     * send directly over the wire with no shared format definition tying
     * it to trust_manager.c's own decoder. num_verifiers is already
     * bounds-checked against MAX_VERIFIERS (10) above, well under
     * CHARRA_MAX_REQUESTED_VERIFIERS (32), so the DTO's own fixed array
     * can't overflow here. */
    msg_get_verifiers_request_dto req = {0};
    req.verifier_ids_len = (uint32_t)num_verifiers;
    for (int i = 0; i < num_verifiers; ++i) {
        req.verifier_ids[i] = verifier_list[i];
    }
    uint32_t req_buf_len = 0;
    if ((result = charra_marshal_get_verifiers_request(
                 &req, &req_buf_len, &req_buf)) != CHARRA_RC_SUCCESS) {
        charra_log_error(
                "[" LOG_NAME "] Could not marshal /get_verifiers request.");
        goto cleanup;
    }

    /* create CoAP option for content type */
    uint8_t coap_mediatype_cbor_buf_n[4] = {0};
    unsigned int coap_mediatype_cbor_buf_len_n = 0;
    if ((coap_mediatype_cbor_buf_len_n = coap_encode_var_safe(
                 coap_mediatype_cbor_buf_n, sizeof(coap_mediatype_cbor_buf_n),
                 COAP_MEDIATYPE_APPLICATION_CBOR)) == 0) {
        charra_log_error(
                "[" LOG_NAME "] Cannot create option for CONTENT_TYPE.");
        result = CHARRA_RC_COAP_ERROR;
        goto cleanup;
    }

    charra_log_info("[" LOG_NAME "] Adding CoAP option URI_PATH.");
    if (coap_insert_optlist(
                &coap_options, coap_new_optlist(COAP_OPTION_URI_PATH, 13,
                                       (const uint8_t*)"get_verifiers")) != 1) {
        charra_log_error("[" LOG_NAME "] Cannot add CoAP option URI_PATH.");
        result = CHARRA_RC_COAP_ERROR;
        goto cleanup;
    }

    charra_log_info("[" LOG_NAME "] Adding CoAP option CONTENT_TYPE.");
    if (coap_insert_optlist(&coap_options,
                coap_new_optlist(COAP_OPTION_CONTENT_TYPE,
                                       coap_mediatype_cbor_buf_len_n,
                                       coap_mediatype_cbor_buf_n)) != 1) {
        charra_log_error("[" LOG_NAME "] Cannot add CoAP option CONTENT_TYPE.");
        result = CHARRA_RC_COAP_ERROR;
        goto cleanup;
    }    

    /* new CoAP request PDU */
    coap_pdu_t* pdu = NULL;
    charra_log_info("[" LOG_NAME "] Creating request PDU.");
    if ((pdu = charra_coap_new_request(coap_session, COAP_MESSAGE_TYPE_CON,
                 COAP_REQUEST_FETCH, &coap_options, req_buf, req_buf_len)) ==
            NULL) {
        charra_log_error("[" LOG_NAME "] Cannot create request PDU.");
        result = CHARRA_RC_ERROR;
        goto cleanup;
    }

    /* set timeout length */
    coap_fixed_point_t coap_timeout = {trust_manager_response_timeout, 0};
    coap_session_set_ack_timeout(coap_session, coap_timeout);

    /* send CoAP PDU */
    coap_mid_t mid = COAP_INVALID_MID;
    charra_log_info("[" LOG_NAME "] Sending CoAP message.");
    if ((mid = coap_send_large(coap_session, pdu)) == COAP_INVALID_MID) {
        charra_log_error("[" LOG_NAME "] Cannot send CoAP message.");
        result = CHARRA_RC_COAP_ERROR;
        goto cleanup;
    }

    int coap_io_process_time = -1;
    /* processing and waiting for response */
    charra_log_info("[" LOG_NAME "] Processing and waiting for response ...");
    /* Real wall-clock elapsed time, not a sum of coap_io_process()'s own
     * self-reported per-call durations -- that undercounts real time under
     * concurrent load (see rp_coap_fetch()'s docstring comment for the
     * full explanation; this replaces the previous "not 100% accurate...
     * should be good enough" comment that turned out not to be, once
     * actually exercised under 5-way Verifier contention). */
    struct timespec wait_start, wait_now;
    clock_gettime(CLOCK_MONOTONIC, &wait_start);
    while (!processing_trust_manager_response && coap_io_pending(coap_context)) {
        /* process CoAP I/O */
        if ((coap_io_process_time = coap_io_process(
                     coap_context, COAP_IO_PROCESS_TIME_MS)) == -1) {
            charra_log_error(
                    "[" LOG_NAME "] Error during CoAP I/O processing.");
            result = CHARRA_RC_COAP_ERROR;
            goto cleanup;
        }
        clock_gettime(CLOCK_MONOTONIC, &wait_now);
        double elapsed_ms = (wait_now.tv_sec - wait_start.tv_sec) * 1000.0 +
                             (wait_now.tv_nsec - wait_start.tv_nsec) / 1e6;
        if (elapsed_ms >= (trust_manager_response_timeout * 1000)) {
            charra_log_error("[" LOG_NAME
                             "] Timeout after %.0f ms while waiting for or "
                             "processing attestation response.",
                    elapsed_ms);
            result = CHARRA_RC_TIMEOUT;
            goto cleanup;
        }
    }

    result = CHARRA_RC_SUCCESS;

cleanup:
    charra_free_if_not_null(req_buf);
    /* free CoAP memory */
    charra_free_if_not_null_ex(coap_options, coap_delete_optlist);
    charra_free_if_not_null_ex(coap_session, coap_session_release);
    charra_free_if_not_null_ex(coap_context, coap_free_context);

    /* No coap_cleanup() here: it tears down libcoap's *global* state, so
     * calling it per cycle (and from each Verifier thread) would pull the
     * ground out from under contexts still in use and from the next
     * cycle's. Done exactly once, at process exit in main(). */

    return result;

}

CHARRA_RC get_evidence() {

    charra_log_info("[" LOG_NAME "]  +------------ Interaction with the Attester --------------+");

    CHARRA_RC result = EXIT_FAILURE;

    coap_context_t* coap_context = NULL;
    coap_session_t* coap_session = NULL;
    coap_optlist_t* coap_options = NULL;
    uint8_t* req_buf = NULL;  // TODO(any): make dynamic

    if (use_dtls_psk && use_dtls_rpk) {
        charra_log_error(
                "[" LOG_NAME "] Configuration enables both DTSL with PSK "
                "and DTSL with PKI. Aborting!");
        goto cleanup;
    }

    if (use_dtls_psk || use_dtls_rpk) {
        // print TLS version when in debug mode
        coap_show_tls_version(LOG_DEBUG);
    }

    if (use_dtls_psk && !coap_dtls_is_supported()) {
        charra_log_error("[" LOG_NAME "] CoAP does not support DTLS but the "
                         "configuration enables DTLS. Aborting!");
        goto cleanup;
    }

    /* create CoAP context */
    charra_log_info("[" LOG_NAME "] Initializing CoAP in block-wise mode.");
    if ((coap_context = charra_coap_new_context(true)) == NULL) {
        charra_log_error("[" LOG_NAME "] Cannot create CoAP context.");
        result = CHARRA_RC_COAP_ERROR;
        goto cleanup;
    }

    /* register CoAP response handler */
    charra_log_info("[" LOG_NAME "] Registering CoAP response handler.");
    coap_register_response_handler(
            coap_context, coap_attester_handler);

    if (use_dtls_psk) {
        charra_log_info("[" LOG_NAME
                        "] Creating CoAP client session using DTLS with PSK.");
        if ((coap_session = charra_coap_new_client_session_psk(
                     coap_context,
                     attester_host, attester_port, COAP_PROTO_DTLS, dtls_psk_identity,
                     (uint8_t*)dtls_psk_key, strlen(dtls_psk_key))) == NULL) {
            charra_log_error(
                    "[" LOG_NAME
                    "] Cannot create client session based on DTLS-PSK.");
            result = CHARRA_RC_ERROR;
            goto cleanup;
        }
    } else if (use_dtls_rpk) {
        charra_log_info(
                "[" LOG_NAME "] Creating CoAP client session using DTLS-RPK.");
        coap_dtls_pki_t dtls_pki = {0};

        result = charra_coap_setup_dtls_pki_for_rpk(&dtls_pki,
                dtls_rpk_private_key_path, dtls_rpk_public_key_path,
                dtls_rpk_attester_public_key_path, dtls_rpk_verify_peer_public_key);
        if (result != CHARRA_RC_SUCCESS) {
            charra_log_error("[" LOG_NAME
                             "] Error while setting up DTLS-RPK structure.");
            goto cleanup;
        }

        if ((coap_session = charra_coap_new_client_session_pki(
                     coap_context,
                     attester_host, attester_port, COAP_PROTO_DTLS,
                     &dtls_pki)) == NULL) {
            charra_log_error(
                    "[" LOG_NAME
                    "] Cannot create client session based on DTLS-RPK.");
            result = CHARRA_RC_ERROR;
            goto cleanup;
        }
    } else {
        charra_log_info(
                "[" LOG_NAME "] Creating CoAP client session using UDP.");
        if ((coap_session = charra_coap_new_client_session(
                     coap_context,
                     attester_host, attester_port, COAP_PROTO_UDP)) == NULL) {
            charra_log_error("[" LOG_NAME
                             "] Cannot create client session based on UDP.");
            result = CHARRA_RC_COAP_ERROR;
            goto cleanup;
        }
    }

    /* define needed variables */
    msg_attestation_request_dto req = {0};
    uint32_t req_buf_len = 0;
    coap_pdu_t* pdu = NULL;
    coap_mid_t mid = COAP_INVALID_MID;
    int coap_io_process_time = -1;

    /* create CoAP option for content type */
    uint8_t coap_mediatype_cbor_buf[4] = {0};
    unsigned int coap_mediatype_cbor_buf_len = 0;
    if ((coap_mediatype_cbor_buf_len = coap_encode_var_safe(
                 coap_mediatype_cbor_buf, sizeof(coap_mediatype_cbor_buf),
                 COAP_MEDIATYPE_APPLICATION_CBOR)) == 0) {
        charra_log_error(
                "[" LOG_NAME "] Cannot create option for CONTENT_TYPE.");
        result = CHARRA_RC_COAP_ERROR;
        goto cleanup;
    }

    
    /* create attestation request */
    charra_log_info("[" LOG_NAME "] Creating attestation request.");
    if ((result = create_attestation_request(&req)) != CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Cannot create attestation request.");
        goto cleanup;
    } else {
        /* store request data */
        last_request = req;
    }


    /* marshal attestation request */
    charra_log_info(
            "[" LOG_NAME "] Marshaling attestation request data to CBOR.");
    if ((result = charra_marshal_attestation_request(
                 &req, &req_buf_len, &req_buf)) != CHARRA_RC_SUCCESS) {
        charra_log_error(
                "[" LOG_NAME "] Marshaling attestation request data failed.");
        goto cleanup;
    }

    /* CoAP options */
    charra_log_info("[" LOG_NAME "] Adding CoAP option URI_PATH.");
    if (coap_insert_optlist(&coap_options,
                coap_new_optlist(COAP_OPTION_URI_PATH, 6,
                                       (const uint8_t*)"attest")) != 1) {
        charra_log_error("[" LOG_NAME "] Cannot add CoAP option URI_PATH.");
        result = CHARRA_RC_COAP_ERROR;
        goto cleanup;
    }
    charra_log_info("[" LOG_NAME "] Adding CoAP option CONTENT_TYPE.");
    if (coap_insert_optlist(&coap_options,
                coap_new_optlist(COAP_OPTION_CONTENT_TYPE,
                                       coap_mediatype_cbor_buf_len,
                                       coap_mediatype_cbor_buf)) != 1) {
        charra_log_error("[" LOG_NAME "] Cannot add CoAP option CONTENT_TYPE.");
        result = CHARRA_RC_COAP_ERROR;
        goto cleanup;
    }

    /* new CoAP request PDU */
    charra_log_info("[" LOG_NAME "] Creating request PDU.");
    if ((pdu = charra_coap_new_request(coap_session,
                 COAP_MESSAGE_TYPE_CON, COAP_REQUEST_FETCH,
                 &coap_options, req_buf, req_buf_len)) ==
            NULL) {
        charra_log_error("[" LOG_NAME "] Cannot create request PDU.");
        result = CHARRA_RC_ERROR;
        goto cleanup;
    }

    /* set timeout length */
    coap_fixed_point_t coap_timeout = {attester_response_timeout, 0};
    coap_session_set_ack_timeout(coap_session, coap_timeout);

    /* send CoAP PDU */
    charra_log_info("[" LOG_NAME "] Sending attestation request.");
    if ((mid = coap_send_large(coap_session, pdu)) ==
            COAP_INVALID_MID) {
        charra_log_error("[" LOG_NAME "] Cannot send CoAP message.");
        result = CHARRA_RC_COAP_ERROR;
        goto cleanup;
    }

    /* processing and waiting for response */
    charra_log_info("[" LOG_NAME "] Processing and waiting for response ...");
    /* Real wall-clock elapsed time -- see rp_coap_fetch()'s docstring
     * comment for why this replaced a self-reported-duration sum. */
    struct timespec wait_start, wait_now;
    clock_gettime(CLOCK_MONOTONIC, &wait_start);
    while (!processing_attestation_response && coap_io_pending(coap_context)) {
        /* process CoAP I/O */
        if ((coap_io_process_time = coap_io_process(
                     coap_context, COAP_IO_PROCESS_TIME_MS)) == -1) {
            charra_log_error(
                    "[" LOG_NAME "] Error during CoAP I/O processing.");
            result = CHARRA_RC_COAP_ERROR;
            goto cleanup;
        }
        clock_gettime(CLOCK_MONOTONIC, &wait_now);
        double elapsed_ms = (wait_now.tv_sec - wait_start.tv_sec) * 1000.0 +
                             (wait_now.tv_nsec - wait_start.tv_nsec) / 1e6;
        if (elapsed_ms >= (attester_response_timeout * 1000)) {
            charra_log_error("[" LOG_NAME
                             "] Timeout after %.0f ms while waiting for or "
                             "processing attestation response.",
                    elapsed_ms);
            result = CHARRA_RC_TIMEOUT;
            goto cleanup;
        }
    }

    result = CHARRA_RC_SUCCESS;

cleanup:
    /* free CoAP memory */
    charra_free_if_not_null_ex(coap_options, coap_delete_optlist);
    charra_free_if_not_null_ex(coap_session, coap_session_release);
    charra_free_if_not_null_ex(coap_context, coap_free_context);

    /* free variables */
    charra_free_if_not_null(req_buf);

    /* Step 2a's verdict back to the Attester -- only meaningful once we
     * actually appraised something, so not on a transport failure or a
     * timeout, where there was no verdict to report. Sent here rather than
     * from the response handler; see rp_send_attestation_result(). */
    if (attestation_rc == CHARRA_RC_VERIFICATION_FAILED) {
        rp_send_attestation_result(
                false, "Step 2a local verification failed");
    } else if (result == CHARRA_RC_SUCCESS &&
               attestation_rc == CHARRA_RC_SUCCESS) {
        rp_send_attestation_result(true, "Step 2a local verification passed");
    }

    /* No coap_cleanup() here: it tears down libcoap's *global* state, so
     * calling it per cycle (and from each Verifier thread) would pull the
     * ground out from under contexts still in use and from the next
     * cycle's. Done exactly once, at process exit in main(). */

    return result;
}

void* get_attestation_results_thread(void *arg) {

    CHARRA_RC result = EXIT_FAILURE;

    int current_thread_index = *(int*)arg;
    verifier_info verifier_info = verifiers[current_thread_index];

    /* Tags this thread's log lines so 5 concurrent Verifier threads don't
     * interleave into one indistinguishable stream. */
    char log_prefix[32] = {0};
    snprintf(log_prefix, sizeof(log_prefix), "[V%d:%u]",
            current_thread_index + 1, verifier_info.port_number);
    charra_log_set_thread_prefix(log_prefix);

    /* cleanup/error below never sets attestation_results[] explicitly, so
     * without this reset an early failure would silently keep a stale PASS
     * from a previous run and get counted toward the vote. Fail closed. */
    attestation_results[current_thread_index] = false;
    rejection_reason[current_thread_index][0] = '\0';
    verifier_latency_ms[current_thread_index] = -1;

     /* set varaibles here such that they are valid in case of an 'goto cleanup'
     */
    coap_context_t* coap_context = NULL;
    coap_session_t* coap_session = NULL;
    coap_optlist_t* coap_options = NULL;
    /* Declared here, not at first use further down, for the same reason as
     * the three above: several earlier goto cleanup jumps in this function
     * would otherwise skip their initializers, leaving cleanup's unconditional
     * charra_free_if_not_null() calls to free() an indeterminate pointer.
     * coap_context_verifier_appraisal/_session_/_options_ used to be
     * declared only right before the appraisal-request section, well after
     * the "Verifier did not supply a nonce" goto cleanup a few lines below
     * this one -- a verifier that timed out on /nonce meant this function
     * jumped straight to cleanup and called coap_free_context()/
     * coap_session_release()/coap_delete_optlist() on garbage stack
     * pointers, corrupting the heap (observed live as "double free or
     * corruption (out)"). Hoisted here for the same reason as the other
     * five. */
    uint8_t* nonce_req_buf = NULL;
    uint32_t nonce_req_buf_len = 0;
    uint8_t* res_buf = NULL;
    uint32_t res_buf_len = 0;
    coap_context_t* coap_context_verifier_appraisal = NULL;
    coap_session_t* coap_session_verifier_appraisal = NULL;
    coap_optlist_t* coap_options_verifier_appraisal = NULL;

    /* RP qualification is now handled once, up front, by
     * get_attestation_results() before any thread starts (see
     * rp_perform_qualification_handshake_once()) -- the shared
     * qualification ledger means one Verifier's answer is every Verifier's
     * answer, so nothing to do here. This thread still needs its OWN
     * Verifier's AK *certificate* though (orthogonal, still per-Verifier --
     * charra_rp_build_evidence_message() below only checks rp_ak_cert_
     * ready[current_thread_index], it doesn't provision it). */
    if (ensure_rp_ak_certificate(current_thread_index) != CHARRA_RC_SUCCESS) {
        charra_log_error(
                "[" LOG_NAME "] Verifier n° %d (port %u): RP AK certificate "
                "not provisioned; proceeding to /appraise anyway.",
                current_thread_index + 1,
                verifiers[current_thread_index].port_number);
    }

    /* Symmetric with the above: the Attester's AK certificate, issued by
     * THIS Verifier's own CA, is also per-Verifier now (see
     * ensure_attester_identity_certified_by_verifier()'s docstring). */
    if (ensure_attester_identity_certified_by_verifier(current_thread_index) !=
            CHARRA_RC_SUCCESS) {
        charra_log_error(
                "[" LOG_NAME "] Verifier n° %d (port %u): Attester AK "
                "certificate not provisioned; proceeding to /appraise "
                "anyway.",
                current_thread_index + 1,
                verifiers[current_thread_index].port_number);
    }

    if (use_dtls_psk && use_dtls_rpk) {
        charra_log_error(
                "[" LOG_NAME "] Configuration enables both DTSL with PSK "
                "and DTSL with PKI. Aborting!");
        goto cleanup;
    }

    if (use_dtls_psk || use_dtls_rpk) {
        // print TLS version when in debug mode
        coap_show_tls_version(LOG_DEBUG);
    }

    if (use_dtls_psk && !coap_dtls_is_supported()) {
        charra_log_error("[" LOG_NAME "] CoAP does not support DTLS but the "
                         "configuration enables DTLS. Aborting!");
        goto cleanup;
    }

    /* create CoAP context */
    if ((coap_context = charra_coap_new_context(true)) == NULL) {
        charra_log_error("[" LOG_NAME "] Cannot create CoAP context.");
        result = CHARRA_RC_COAP_ERROR;
        goto cleanup;
    }

    if (use_dtls_psk) {
        charra_log_info("[" LOG_NAME
                        "] Creating CoAP client session using DTLS with PSK.");
        if ((coap_session = charra_coap_new_client_session_psk(
                     coap_context, verifier_info.ip_address, verifier_info.port_number,
                     COAP_PROTO_DTLS, dtls_psk_identity, (uint8_t*)dtls_psk_key,
                     strlen(dtls_psk_key))) == NULL) {
            charra_log_error(
                    "[" LOG_NAME
                    "] Cannot create client session based on DTLS-PSK.");
            result = CHARRA_RC_ERROR;
            goto cleanup;
        }
    } else if (use_dtls_rpk) {
        charra_log_info(
                "[" LOG_NAME "] Creating CoAP client session using DTLS-RPK.");
        coap_dtls_pki_t dtls_pki = {0};

        result = charra_coap_setup_dtls_pki_for_rpk(&dtls_pki,
                dtls_rpk_private_key_path, dtls_rpk_public_key_path,
                dtls_rpk_verifier_public_key_path, dtls_rpk_verify_peer_public_key);
        if (result != CHARRA_RC_SUCCESS) {
            charra_log_error("[" LOG_NAME
                             "] Error while setting up DTLS-RPK structure.");
            goto cleanup;
        }

        if ((coap_session = charra_coap_new_client_session_pki(
                     coap_context, verifier_info.ip_address, verifier_info.port_number,
                     COAP_PROTO_DTLS, &dtls_pki)) == NULL) {
            charra_log_error(
                    "[" LOG_NAME
                    "] Cannot create client session based on DTLS-RPK.");
            result = CHARRA_RC_ERROR;
            goto cleanup;
        }
    } else {
        if ((coap_session = charra_coap_new_client_session(
                     coap_context, verifier_info.ip_address, verifier_info.port_number,
                     COAP_PROTO_UDP)) == NULL) {
            charra_log_error("[" LOG_NAME
                             "] Cannot create client session based on UDP.");
            result = CHARRA_RC_COAP_ERROR;
            goto cleanup;
        }
    }

    /* --- Interaction with the Verifier (sending the nonce) * ---------------------------------------------------------------*/
    coap_pdu_t* pdu_n = NULL;
    coap_mid_t mid_n = COAP_INVALID_MID;
    int coap_io_process_time_n = -1;
    
    /* create CoAP option for content type */
    uint8_t coap_mediatype_cbor_buf_n[4] = {0};
    unsigned int coap_mediatype_cbor_buf_len_n = 0;
    if ((coap_mediatype_cbor_buf_len_n = coap_encode_var_safe(
                 coap_mediatype_cbor_buf_n, sizeof(coap_mediatype_cbor_buf_n),
                 COAP_MEDIATYPE_APPLICATION_CBOR)) == 0) {
        charra_log_error(
                "[" LOG_NAME "] Cannot create option for CONTENT_TYPE.");
        result = CHARRA_RC_COAP_ERROR;
        goto cleanup;
    }

    /* Ask the Verifier for a nonce: send the same attestation request RP
     * already built for the Attester (last_request, stable and read-only by
     * now -- populated once in get_evidence(), which always completes
     * before get_attestation_results() spawns this thread). verifier.c's
     * coap_nonce_handler() unmarshals this exact DTO -- keeping req.nonce
     * for its own separate Quote_a freshness check -- then generates and
     * returns its own fresh challenge as the response body, a genuinely
     * Verifier-picked value rather than an echo of what RP just sent (see
     * verifier_challenge_nonce's comment in verifier.c for why that
     * distinction matters). An empty request body here made unmarshaling
     * fail immediately ("Could not get CoAP PDU data"), which is why RP
     * never received a nonce and Quote_r could never be built, before this
     * was fixed. */
    if ((result = charra_marshal_attestation_request(
                 &last_request, &nonce_req_buf_len, &nonce_req_buf)) !=
            CHARRA_RC_SUCCESS) {
        charra_log_error(
                "[" LOG_NAME "] Could not marshal /nonce request body.");
        goto cleanup;
    }

    coap_session_set_app_data(coap_session, (void*)&current_thread_index);
    coap_register_response_handler(coap_context, coap_verifier_handler_nonce);
    verifier_nonce_lens[current_thread_index] = 0;
    processing_nonce_response[current_thread_index] = true;
    charra_log_info("[" LOG_NAME "] Requesting a nonce from Verifier n\u00b0 %d ...",
            current_thread_index + 1);


    /* CoAP options */
    if (coap_insert_optlist(
                &coap_options, coap_new_optlist(COAP_OPTION_URI_PATH, 5,
                                       (const uint8_t*)"nonce")) != 1) {
        charra_log_error("[" LOG_NAME "] Cannot add CoAP option URI_PATH.");
        result = CHARRA_RC_COAP_ERROR;
        goto cleanup;
    }
    if (coap_insert_optlist(&coap_options,
                coap_new_optlist(COAP_OPTION_CONTENT_TYPE,
                                       coap_mediatype_cbor_buf_len_n,
                                       coap_mediatype_cbor_buf_n)) != 1) {
        charra_log_error("[" LOG_NAME "] Cannot add CoAP option CONTENT_TYPE.");
        result = CHARRA_RC_COAP_ERROR;
        goto cleanup;
    }

    if ((pdu_n = charra_coap_new_request(coap_session, COAP_MESSAGE_TYPE_CON, COAP_REQUEST_FETCH,
                 &coap_options, nonce_req_buf, nonce_req_buf_len)) ==
            NULL) {
        charra_log_error("[" LOG_NAME "] Cannot create request PDU.");
        result = CHARRA_RC_ERROR;
        goto cleanup;
    }

    coap_fixed_point_t coap_timeout_n = {verifier_response_timeout, 0};
    coap_session_set_ack_timeout(coap_session, coap_timeout_n);

    if ((mid_n = coap_send_large(coap_session, pdu_n)) == COAP_INVALID_MID) {
        charra_log_error("[" LOG_NAME "] Cannot send CoAP message.");
        result = CHARRA_RC_COAP_ERROR;
        goto cleanup;
    }


    /* Real wall-clock elapsed time -- see rp_coap_fetch()'s docstring
     * comment for why this replaced a self-reported-duration sum. */
    struct timespec wait_start_n, wait_now_n;
    clock_gettime(CLOCK_MONOTONIC, &wait_start_n);
    while (processing_nonce_response[current_thread_index] &&
            coap_io_pending(coap_context)) {
        /* process CoAP I/O */
        if ((coap_io_process_time_n = coap_io_process(
                     coap_context, COAP_IO_PROCESS_TIME_MS)) == -1) {
            charra_log_error(
                    "[" LOG_NAME "] Error during CoAP I/O processing.");
            result = CHARRA_RC_COAP_ERROR;
            goto cleanup;
        }
        clock_gettime(CLOCK_MONOTONIC, &wait_now_n);
        double elapsed_ms_n =
                (wait_now_n.tv_sec - wait_start_n.tv_sec) * 1000.0 +
                (wait_now_n.tv_nsec - wait_start_n.tv_nsec) / 1e6;
        if (elapsed_ms_n >= (verifier_response_timeout * 1000)) {
            charra_log_error("[" LOG_NAME
                             "] Timeout after %.0f ms while waiting for or "
                             "processing attestation response.",
                    elapsed_ms_n);
            result = CHARRA_RC_TIMEOUT;
            goto cleanup;
        }
    }

    if (verifier_nonce_lens[current_thread_index] == 0) {
        charra_log_error("[" LOG_NAME "] Verifier n\u00b0 %d did not supply a "
                         "nonce; cannot build Quote_r.",
                current_thread_index + 1);
        result = CHARRA_RC_ERROR;
        goto cleanup;
    }

    /* --- Interaction with the Verifier (sending Quote_r and log_r) * ---------------------------------------------------------------*/
    if (use_dtls_psk && use_dtls_rpk) {
        charra_log_error(
                "[" LOG_NAME "] Configuration enables both DTSL with PSK "
                "and DTSL with PKI. Aborting!");
        goto cleanup;
    }

    if (use_dtls_psk || use_dtls_rpk) {
        // print TLS version when in debug mode
        coap_show_tls_version(LOG_DEBUG);
    }

    if (use_dtls_psk && !coap_dtls_is_supported()) {
        charra_log_error("[" LOG_NAME "] CoAP does not support DTLS but the "
                         "configuration enables DTLS. Aborting!");
        goto cleanup;
    }

    /* create CoAP context */

    //charra_log_info("[" LOG_NAME "] Initializing CoAP in block-wise mode.");
    if ((coap_context_verifier_appraisal = charra_coap_new_context(true)) == NULL) {
        charra_log_error("[" LOG_NAME "] Cannot create CoAP context.");
        result = CHARRA_RC_COAP_ERROR;
        goto cleanup;
    }

    /* register CoAP response handler */
    //charra_log_info("[" LOG_NAME "] Registering CoAP response handler.");
    coap_register_response_handler(
            coap_context_verifier_appraisal, coap_verifier_handler_appraisal);

    if (use_dtls_psk) {
        charra_log_info("[" LOG_NAME
                        "] Creating CoAP client session using DTLS with PSK.");
        if ((coap_session_verifier_appraisal = charra_coap_new_client_session_psk(
                     coap_context_verifier_appraisal, verifier_info.ip_address, verifier_info.port_number,
                     COAP_PROTO_DTLS, dtls_psk_identity, (uint8_t*)dtls_psk_key,
                     strlen(dtls_psk_key))) == NULL) {
            charra_log_error(
                    "[" LOG_NAME
                    "] Cannot create client session based on DTLS-PSK.");
            result = CHARRA_RC_ERROR;
            goto cleanup;
        }
    } else if (use_dtls_rpk) {
        charra_log_info(
                "[" LOG_NAME "] Creating CoAP client session using DTLS-RPK.");
        coap_dtls_pki_t dtls_pki = {0};

        result = charra_coap_setup_dtls_pki_for_rpk(&dtls_pki,
                dtls_rpk_private_key_path, dtls_rpk_public_key_path,
                dtls_rpk_verifier_public_key_path, dtls_rpk_verify_peer_public_key);
        if (result != CHARRA_RC_SUCCESS) {
            charra_log_error("[" LOG_NAME
                             "] Error while setting up DTLS-RPK structure.");
            goto cleanup;
        }

        if ((coap_session_verifier_appraisal = charra_coap_new_client_session_pki(
                     coap_context_verifier_appraisal, verifier_info.ip_address, verifier_info.port_number,
                     COAP_PROTO_DTLS, &dtls_pki)) == NULL) {
            charra_log_error(
                    "[" LOG_NAME
                    "] Cannot create client session based on DTLS-RPK.");
            result = CHARRA_RC_ERROR;
            goto cleanup;
        }
    } else {
        //charra_log_info("[" LOG_NAME "] Creating CoAP client session using UDP.");
        if ((coap_session_verifier_appraisal = charra_coap_new_client_session(
                     coap_context_verifier_appraisal, verifier_info.ip_address, verifier_info.port_number,
                     COAP_PROTO_UDP)) == NULL) {
            charra_log_error("[" LOG_NAME
                             "] Cannot create client session based on UDP.");
            result = CHARRA_RC_COAP_ERROR;
            goto cleanup;
        }
    }

    /* create CoAP option for content type */
    uint8_t coap_mediatype_cbor_buf_v[4] = {0};
    unsigned int coap_mediatype_cbor_buf_len_v = 0;
    if ((coap_mediatype_cbor_buf_len_v = coap_encode_var_safe(
                 coap_mediatype_cbor_buf_v, sizeof(coap_mediatype_cbor_buf_v),
                 COAP_MEDIATYPE_APPLICATION_CBOR)) == 0) {
        charra_log_error(
                "[" LOG_NAME "] Cannot create option for CONTENT_TYPE.");
        result = CHARRA_RC_COAP_ERROR;
        goto cleanup;
    }

    /* CoAP options -- built once, reused for both the first attempt and any
     * AK-certificate-rejection retry below: charra_coap_new_request() only
     * reads from this list, it does not consume or free it. */
    if (coap_insert_optlist(
                &coap_options_verifier_appraisal, coap_new_optlist(COAP_OPTION_URI_PATH, 8,
                                       (const uint8_t*)"appraise")) != 1) {
        charra_log_error("[" LOG_NAME "] Cannot add CoAP option URI_PATH.");
        result = CHARRA_RC_COAP_ERROR;
        goto cleanup;
    }
    if (coap_insert_optlist(&coap_options_verifier_appraisal,
                coap_new_optlist(COAP_OPTION_CONTENT_TYPE,
                                       coap_mediatype_cbor_buf_len_v,
                                       coap_mediatype_cbor_buf_v)) != 1) {
        charra_log_error("[" LOG_NAME "] Cannot add CoAP option CONTENT_TYPE.");
        result = CHARRA_RC_COAP_ERROR;
        goto cleanup;
    }

    coap_fixed_point_t coap_timeout_v = {verifier_response_timeout, 0};
    coap_session_set_ack_timeout(coap_session_verifier_appraisal, coap_timeout_v);
    coap_session_set_app_data(coap_session_verifier_appraisal, &current_thread_index);

    /* Build and marshal the RP evidence message (Quote_r bound to this
     * Verifier's nonce, the RP public key, log_r, the nonce the RP sent to
     * the Attester, and the Attester's evidence minus its raw event log),
     * send it, and wait for the Verifier's response. Retried once if the
     * Verifier's only complaint was our AK certificate being invalid or
     * expired (see coap_verifier_handler_appraisal and verifier.c's Step 3a
     * item 1): re-provision via /certify_ak and try again with a fresh
     * certificate, rather than just recording a failed vote a blind retry
     * could never fix. Retried the same way if the complaint was instead
     * our qualification being missing or expired (Step 3a item 1b): forget
     * the local cache and redo /qualify + /qualify/submit. The two never
     * overlap in one response (coap_appraise_handler checks the AK
     * certificate first and returns immediately on failure, before ever
     * reaching the qualification check), so at most one of
     * rp_ak_cert_rejected/rp_qualification_rejected is ever true here. Not
     * retried for any other kind of failure. */
    long total_appraisal_wait_ms = 0;
    for (int attempt = 0; attempt < 2; ++attempt) {
        charra_free_if_not_null(res_buf);
        res_buf = NULL;
        res_buf_len = 0;

        /* No cross-thread locking needed here (unlike the /certify_ak CoAP
         * round trip itself, still guarded by rp_ak_reprovision_mutex,
         * see ensure_rp_ak_certificate()): this thread is the only one
         * that ever reads or writes rp_ak_cert_der[current_thread_index],
         * since each Verifier's certificate is now independently owned by
         * its own thread's array slot. */
        charra_r = charra_rp_build_evidence_message(
                current_thread_index, &res_buf_len, &res_buf);
        if (charra_r != CHARRA_RC_SUCCESS) {
            charra_log_error(
                    "[" LOG_NAME "] Error building RP evidence message.");
            goto error;
        }
        charra_log_info("[" LOG_NAME "] Sending %u bytes of RP evidence to "
                        "Verifier n\u00b0 %d.",
                res_buf_len, current_thread_index + 1);

        coap_pdu_t* pdu_v = NULL;
        if ((pdu_v = charra_coap_new_request(coap_session_verifier_appraisal, COAP_MESSAGE_TYPE_CON, COAP_REQUEST_FETCH,
                     &coap_options_verifier_appraisal, res_buf, res_buf_len)) ==
                NULL) {
            charra_log_error("[" LOG_NAME "] Cannot create request PDU.");
            result = CHARRA_RC_ERROR;
            goto cleanup;
        }

        if (coap_send_large(coap_session_verifier_appraisal, pdu_v) == COAP_INVALID_MID) {
            charra_log_error("[" LOG_NAME "] Cannot send CoAP message.");
            result = CHARRA_RC_COAP_ERROR;
            goto cleanup;
        }

        /* processing and waiting for response */
        processing_appraisal_response[current_thread_index] = false;
        /* Real elapsed time, not a self-reported-duration sum -- see
         * rp_coap_fetch() above. */
        struct timespec wait_start_v, wait_now_v;
        clock_gettime(CLOCK_MONOTONIC, &wait_start_v);
        double elapsed_ms_v = 0;
        while (!processing_appraisal_response[current_thread_index] &&
                coap_io_pending(coap_context_verifier_appraisal)) {
            int coap_io_process_time_v = coap_io_process(
                    coap_context_verifier_appraisal, COAP_IO_PROCESS_TIME_MS);
            if (coap_io_process_time_v == -1) {
                charra_log_error(
                        "[" LOG_NAME "] Error during CoAP I/O processing.");
                result = CHARRA_RC_COAP_ERROR;
                goto cleanup;
            }
            clock_gettime(CLOCK_MONOTONIC, &wait_now_v);
            elapsed_ms_v = (wait_now_v.tv_sec - wait_start_v.tv_sec) * 1000.0 +
                           (wait_now_v.tv_nsec - wait_start_v.tv_nsec) / 1e6;
            if (elapsed_ms_v >= (verifier_response_timeout * 1000)) {
                charra_log_error("[" LOG_NAME
                                 "] Timeout after %.0f ms while waiting for or "
                                 "processing attestation response.",
                        elapsed_ms_v);
                result = CHARRA_RC_TIMEOUT;
                goto cleanup;
            }
        }

        total_appraisal_wait_ms += (long)elapsed_ms_v;
        verifier_latency_ms[current_thread_index] = total_appraisal_wait_ms;

        bool rejected = rp_ak_cert_rejected[current_thread_index] ||
                        rp_qualification_rejected[current_thread_index];
        if (!rejected || attempt == 1) {
            break;
        }

        if (rp_ak_cert_rejected[current_thread_index]) {
            charra_log_info("[" LOG_NAME "] Re-provisioning RP AK "
                            "certificate after rejection by Verifier n\u00b0 "
                            "%d (reason: %s) ...",
                    current_thread_index + 1,
                    rejection_reason[current_thread_index]);
            invalidate_cached_rp_ak_certificate(current_thread_index);
            CHARRA_RC reprovision_rc =
                    ensure_rp_ak_certificate(current_thread_index);

            if (reprovision_rc != CHARRA_RC_SUCCESS) {
                charra_log_error(
                        "[" LOG_NAME "] Could not re-provision RP AK "
                        "certificate; giving up on Verifier n\u00b0 %d.",
                        current_thread_index + 1);
                break;
            }
        } else {
            charra_log_info("[" LOG_NAME "] Re-qualifying with Verifier "
                            "n\u00b0 %d after rejection (reason: %s) ...",
                    current_thread_index + 1,
                    rejection_reason[current_thread_index]);
            invalidate_cached_rp_qualification();
            /* Margin 0: the cache was just invalidated above, so this must
             * qualify now regardless of any renewal-window policy. */
            CHARRA_RC requalify_rc = rp_perform_qualification_handshake_once(
                    rp_num_verifiers_this_cycle, 0);

            if (requalify_rc != CHARRA_RC_SUCCESS) {
                charra_log_error(
                        "[" LOG_NAME "] Could not re-qualify; giving up on "
                        "Verifier n\u00b0 %d.",
                        current_thread_index + 1);
                break;
            }
        }
    }

    result = attestation_rc;
error:
    result = EXIT_FAILURE;

cleanup:
    /* free CoAP memory */
    charra_free_if_not_null_ex(coap_options, coap_delete_optlist);
    charra_free_if_not_null_ex(coap_session, coap_session_release);
    charra_free_if_not_null_ex(coap_context, coap_free_context);

    charra_free_if_not_null_ex(coap_options_verifier_appraisal, coap_delete_optlist);
    charra_free_if_not_null_ex(coap_session_verifier_appraisal, coap_session_release);
    charra_free_if_not_null_ex(coap_context_verifier_appraisal, coap_free_context);
    /* free variables */
    charra_free_if_not_null(res_buf);
    charra_free_if_not_null(nonce_req_buf);

    /* No coap_cleanup() here: it tears down libcoap's *global* state, so
     * calling it per cycle (and from each Verifier thread) would pull the
     * ground out from under contexts still in use and from the next
     * cycle's. Done exactly once, at process exit in main(). */

    return NULL;
}

CHARRA_RC get_attestation_results(int num_verifiers) {
    /* Privacy-clean once, before any verifier thread starts: the redaction
     * is randomised, so doing it per thread would give each Verifier a
     * different log_r for the same attestation. */
    if (charra_rp_prepare_evidence() != CHARRA_RC_SUCCESS) {
        charra_rp_release_evidence();
        return CHARRA_RC_ERROR;
    }

    /* Qualify once, before any verifier thread starts -- the qualification
     * ledger is shared across all Verifiers (see qualification_state_file_
     * path in verifier.c), so one Verifier's answer is every Verifier's
     * answer. No Verifier will accept /appraise without it, so abort here
     * rather than spawning threads that would all fail identically. */
    rp_num_verifiers_this_cycle = num_verifiers;
    /* Margin 0: this is the attestation path -- it needs a valid
     * qualification, but has no reason to renew one that is still good.
     * Daemon mode does early renewal from its idle window instead. */
    if (rp_perform_qualification_handshake_once(num_verifiers, 0) !=
            CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Could not qualify with any "
                         "reachable Verifier; aborting attestation run.");
        charra_rp_release_evidence();
        return CHARRA_RC_ERROR;
    }

    CHARRA_RC result = EXIT_FAILURE;

    charra_log_info("[" LOG_NAME "] Forwarding (redacted) evidence to the verifiers.");
    charra_log_info("[" LOG_NAME "]  +------------ Interaction with the Verifiers --------------+");

    pthread_t threads[num_verifiers];
    int indexes[num_verifiers];

    for (int i = 0; i < num_verifiers; ++i) {
        indexes[i] = i;
        if (pthread_create(&threads[i], NULL, get_attestation_results_thread, &indexes[i]) != 0) {
            charra_log_error("[" LOG_NAME"] Error creating thread");
            goto error;
        } else {
            charra_log_info("[" LOG_NAME "] Forwarding evidence to Verifier n° %d (port %u) ...", i+1, verifiers[i].port_number);
        }
    }

    for (int i = 0; i < num_verifiers; ++i) {
        pthread_join(threads[i], NULL);
    }

    /* Identity readiness, as of right now -- not "did we redo either this
     * cycle": rp_ak_cert_ready[] is per-Verifier, rp_qualified_until is now
     * a single shared value (qualifying is Verifier-agnostic); both are
     * independently cached on disk and only get touched when their cache
     * was missing or expired, so most cycles this just reports cache state
     * untouched this round. */
    int num_not_ready = 0;
    time_t readiness_now = time(NULL);
    bool qualified = rp_qualified_until > readiness_now;
    for (int i = 0; i < num_verifiers; ++i) {
        bool ak_ready = rp_ak_cert_ready[i];
        if (ak_ready && qualified) {
            charra_log_info(
                    "[" LOG_NAME "] Verifier %d (port %u): ready (AK "
                    "certified, qualified).",
                    i + 1, verifiers[i].port_number);
        } else {
            num_not_ready++;
            charra_log_info(
                    "[" LOG_NAME "] Verifier %d (port %u): NOT fully ready "
                    "(AK certified: %s, qualified: %s).",
                    i + 1, verifiers[i].port_number,
                    ak_ready ? "yes" : "no", qualified ? "yes" : "no");
        }
    }
    if (num_not_ready > 0) {
        charra_log_info("[" LOG_NAME "] %d/%d Verifier(s) not yet fully "
                        "ready (missing AK certificate and/or "
                        "qualification).",
                num_not_ready, num_verifiers);
    }

    for (int i = 0; i < num_verifiers; ++i) {
        charra_log_info("[" LOG_NAME "] Verifier %d (port %u): %s", i+1, verifiers[i].port_number, attestation_results[i] ? "Attestation successful!" : "Attestation failed!");
    }

    int num_true = 0;
    for (int i = 0; i < num_verifiers; ++i) {
        if (attestation_results[i]) {
            num_true++;
        }
    }

    if (2 * num_true > num_verifiers) {
        charra_log_info("[" LOG_NAME "] Attestation successful by majority "
                        "vote! (%d/%d Verifiers passed)",
                num_true, num_verifiers);
    } else {
        charra_log_info("[" LOG_NAME "] Attestation failed by majority "
                        "vote! (%d/%d Verifiers passed)",
                num_true, num_verifiers);
    }

    /* --- one-screen run summary --------------------------------------- */
    charra_log_info("[" LOG_NAME "]  +------------ Run Summary --------------+");
    charra_log_info(
            "[" LOG_NAME "] log_r: %u bytes redacted from a %u-byte raw log.",
            rp_log_r_len, last_response.event_log_len);
    for (int i = 0; i < num_verifiers; ++i) {
        const char* reason;
        if (attestation_results[i]) {
            reason = "OK";
        } else if (rejection_reason[i][0] != '\0') {
            reason = rejection_reason[i];
        } else {
            reason = "appraisal failed (see per-Verifier log above)";
        }
        char latency_str[16];
        if (verifier_latency_ms[i] < 0) {
            snprintf(latency_str, sizeof(latency_str), "  n/a");
        } else {
            snprintf(latency_str, sizeof(latency_str), "%5ld", verifier_latency_ms[i]);
        }
        charra_log_info("[" LOG_NAME
                        "] Verifier %d (%s:%u): %-4s | AK %-6s | %s ms | "
                        "%s",
                i + 1, verifiers[i].ip_address, verifiers[i].port_number,
                attestation_results[i] ? "PASS" : "FAIL",
                rp_ak_cert_was_cached[i] ? "cached" : "fresh",
                latency_str, reason);
    }

    result = CHARRA_RC_SUCCESS;


error:
    charra_rp_release_evidence();
    return result;

}