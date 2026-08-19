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

CHARRA_RC get_verifiers(int* requested_ids, int num_verifiers) {
    if (num_verifiers > MAX_VERIFIERS) {
        charra_log_error(
                "[" LOG_NAME "] Requested %d verifier(s), but this process "
                "only has room for %d (MAX_VERIFIERS) -- refusing to "
                "overflow requested_ids/verifiers/attestation_results.",
                num_verifiers, MAX_VERIFIERS);
        return CHARRA_RC_BAD_ARGUMENT;
    }

    charra_log_info("[" LOG_NAME "]  +------------ Interaction with the Trust Manager --------------+");

    /* Marshal via the shared, tested CBOR pattern (charra_marshaling.c),
     * replacing the raw int[] this used to put on the wire with no shared
     * format definition tying it to trust_manager.c's decoder. num_verifiers
     * is bounds-checked above, well under CHARRA_MAX_REQUESTED_VERIFIERS, so
     * the DTO's fixed array cannot overflow. */
    msg_get_verifiers_request_dto req = {0};
    req.verifier_ids_len = (uint32_t)num_verifiers;
    for (int i = 0; i < num_verifiers; ++i) {
        req.verifier_ids[i] = requested_ids[i];
    }

    uint8_t* req_buf = NULL;
    uint32_t req_buf_len = 0;
    CHARRA_RC result = charra_marshal_get_verifiers_request(
            &req, &req_buf_len, &req_buf);
    if (result != CHARRA_RC_SUCCESS) {
        charra_log_error(
                "[" LOG_NAME "] Could not marshal the /get_verifiers request.");
        return result;
    }

    /* The Trust Manager has no configured DTLS-RPK peer key, so this
     * exchange is plain UDP even under --rpk. */
    result = rp_coap_exchange(&(rp_coap_request){
            .host = trust_manager_host, .port = trust_manager_port,
            .uri_path = "get_verifiers",
            .body = req_buf, .body_len = req_buf_len,
            .on_response = coap_trust_manager_handler,
            .response_pending = &processing_trust_manager_response,
            .session_app_data = &num_verifiers,
            .timeout_seconds = trust_manager_response_timeout,
            .dtls_rpk_peer_public_key_path = NULL,
    });

    charra_free_if_not_null(req_buf);
    return result;
}

CHARRA_RC get_evidence(void) {
    charra_log_info("[" LOG_NAME "]  +------------ Interaction with the Attester --------------+");

    charra_log_info("[" LOG_NAME "] Creating attestation request.");
    msg_attestation_request_dto req = {0};
    CHARRA_RC result = create_attestation_request(&req);
    if (result != CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Cannot create attestation request.");
        return result;
    }
    /* Kept for the whole cycle: its nonce is what Quote_a must answer, and
     * the /nonce exchange below re-sends this exact DTO. */
    last_request = req;

    uint8_t* req_buf = NULL;
    uint32_t req_buf_len = 0;
    if ((result = charra_marshal_attestation_request(
                 &req, &req_buf_len, &req_buf)) != CHARRA_RC_SUCCESS) {
        charra_log_error(
                "[" LOG_NAME "] Marshaling attestation request data failed.");
        return result;
    }

    charra_log_info("[" LOG_NAME "] Sending attestation request.");
    result = rp_coap_exchange(&(rp_coap_request){
            .host = attester_host, .port = attester_port,
            .uri_path = "attest",
            .body = req_buf, .body_len = req_buf_len,
            .on_response = coap_attester_handler,
            .response_pending = &processing_attestation_response,
            .timeout_seconds = attester_response_timeout,
            .dtls_rpk_peer_public_key_path = dtls_rpk_attester_public_key_path,
    });
    charra_free_if_not_null(req_buf);

    /* Step 2a's verdict back to the Attester -- only meaningful once we
     * actually appraised something, so not on a transport failure or a
     * timeout, where there was no verdict to report. Sent here rather than
     * from the response handler; see rp_send_attestation_result(). */
    if (attestation_rc == CHARRA_RC_VERIFICATION_FAILED) {
        rp_send_attestation_result(false, "Step 2a local verification failed");
    } else if (result == CHARRA_RC_SUCCESS &&
               attestation_rc == CHARRA_RC_SUCCESS) {
        rp_send_attestation_result(true, "Step 2a local verification passed");
    }

    return result;
}

void* get_attestation_results_thread(void* arg) {
    const int verifier_index = *(int*)arg;
    const verifier_info* verifier = &verifiers[verifier_index];

    /* Tags this thread's log lines so concurrent Verifier threads don't
     * interleave into one indistinguishable stream. */
    char log_prefix[32] = {0};
    snprintf(log_prefix, sizeof(log_prefix), "[V%d:%u]", verifier_index + 1,
            verifier->port_number);
    charra_log_set_thread_prefix(log_prefix);

    /* Fail closed: nothing below sets these on an early exit, so without the
     * reset a stale PASS from a previous cycle would be counted in the vote. */
    attestation_results[verifier_index] = false;
    verifier_latency_ms[verifier_index] = -1;

    /* Qualification is handled once, up front, by get_attestation_results()
     * before any thread starts -- the ledger is shared, so one Verifier's
     * answer is every Verifier's. These two are still per-Verifier: this
     * Verifier's certificate for RP's AK, and its certificate for the
     * Attester's. Both are best-effort -- send the evidence either way and
     * let the Verifier judge Step 3a/3b and record its own decision. */
    if (ensure_rp_ak_certificate(verifier_index) != CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Could not provision RP's AK "
                         "certificate; forwarding evidence anyway.");
    }
    if (ensure_attester_identity_certified_by_verifier(verifier_index) !=
            CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Could not provision the Attester's "
                         "AK certificate; forwarding evidence anyway.");
    }

    /* --- ask this Verifier for its own freshness challenge --------------
     * The body is the same attestation request RP built for the Attester:
     * verifier.c's coap_nonce_handler() unmarshals it, keeps req.nonce for
     * Quote_a's separate freshness check, and answers with a nonce IT chose.
     * An empty body here made that unmarshal fail, which is why RP once
     * never received a nonce and Quote_r could not be built. */
    uint8_t* nonce_req_buf = NULL;
    uint32_t nonce_req_buf_len = 0;
    if (charra_marshal_attestation_request(&last_request, &nonce_req_buf_len,
                &nonce_req_buf) != CHARRA_RC_SUCCESS) {
        charra_log_error(
                "[" LOG_NAME "] Could not marshal the /nonce request body.");
        return NULL;
    }

    verifier_nonce_lens[verifier_index] = 0;
    charra_log_info("[" LOG_NAME "] Requesting a nonce from Verifier n\u00b0 %d ...",
            verifier_index + 1);
    CHARRA_RC result = rp_coap_exchange(&(rp_coap_request){
            .host = verifier->ip_address, .port = verifier->port_number,
            .uri_path = "nonce",
            .body = nonce_req_buf, .body_len = nonce_req_buf_len,
            .on_response = coap_verifier_handler_nonce,
            .response_pending = &processing_nonce_response[verifier_index],
            .session_app_data = (void*)&verifier_index,
            .timeout_seconds = verifier_response_timeout,
            .dtls_rpk_peer_public_key_path = dtls_rpk_verifier_public_key_path,
    });
    charra_free_if_not_null(nonce_req_buf);
    if (result != CHARRA_RC_SUCCESS ||
            verifier_nonce_lens[verifier_index] == 0) {
        charra_log_error("[" LOG_NAME "] Verifier n\u00b0 %d did not supply a "
                         "nonce; cannot build Quote_r.",
                verifier_index + 1);
        return NULL;
    }

    /* --- send Quote_r + log_r for appraisal ---------------------------- */
    uint8_t* evidence_buf = NULL;
    uint32_t evidence_buf_len = 0;
    /* Local, not a shared global: every Verifier thread runs this, so one
     * thread's failure must not be readable as another's. */
    if (charra_rp_build_evidence_message(verifier_index, &evidence_buf_len,
                &evidence_buf) != CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Error building RP evidence message.");
        return NULL;
    }
    charra_log_info(
            "[" LOG_NAME "] Sending %u bytes of RP evidence to Verifier n\u00b0 %d.",
            evidence_buf_len, verifier_index + 1);

    struct timespec appraisal_start, appraisal_end;
    clock_gettime(CLOCK_MONOTONIC, &appraisal_start);
    /* One attempt: the Verifier's answer is a vote, not an instruction to
     * retry. */
    result = rp_coap_exchange(&(rp_coap_request){
            .host = verifier->ip_address, .port = verifier->port_number,
            .uri_path = "appraise",
            .body = evidence_buf, .body_len = evidence_buf_len,
            .on_response = coap_verifier_handler_appraisal,
            .response_pending = &processing_appraisal_response[verifier_index],
            .session_app_data = (void*)&verifier_index,
            .timeout_seconds = verifier_response_timeout,
            .dtls_rpk_peer_public_key_path = dtls_rpk_verifier_public_key_path,
    });
    clock_gettime(CLOCK_MONOTONIC, &appraisal_end);
    charra_free_if_not_null(evidence_buf);

    if (result == CHARRA_RC_SUCCESS) {
        verifier_latency_ms[verifier_index] =
                (long)((appraisal_end.tv_sec - appraisal_start.tv_sec) * 1000 +
                        (appraisal_end.tv_nsec - appraisal_start.tv_nsec) /
                                1000000);
    }
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
     * path in verifier/verifier_shared.h), so one Verifier's answer is every Verifier's
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

    CHARRA_RC result = CHARRA_RC_ERROR;

    charra_log_info("[" LOG_NAME "] Forwarding (redacted) evidence to the verifiers.");
    charra_log_info("[" LOG_NAME "]  +------------ Interaction with the Verifiers --------------+");

    pthread_t threads[num_verifiers];
    int indexes[num_verifiers];

    for (int i = 0; i < num_verifiers; ++i) {
        indexes[i] = i;
        if (pthread_create(&threads[i], NULL, get_attestation_results_thread, &indexes[i]) != 0) {
            charra_log_error("[" LOG_NAME"] Error creating thread");
            goto done;
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

    /* Fail-closed majority over every configured Verifier. A Verifier
     * counts as a pass only if it appraised the evidence and accepted it.
     * Everything else is a NO: any failed check (Step 3a's RP EK/AK,
     * Quote_r, RP nonce; Step 3b's Attester EK/AK, Quote_a, Attester
     * nonce), a rejection we could not recover from, an unreachable
     * Verifier, or evidence we never managed to send. Not completing the
     * exchange is never a reason to accept. */
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
        } else if (verifier_latency_ms[i] < 0) {
            /* Never completed an /appraise round trip, so the Verifier
             * never judged anything -- still a NO, but "appraisal failed"
             * would point at a per-Verifier log that does not exist. */
            reason = "no response from Verifier (unreachable or timed out)";
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
                /* "issued", not "fresh": freshness is a RATS term of art
                 * for replay resistance (see the nonce checks above), and
                 * this column is about certificate provenance -- reused from
                 * cache, or issued by /certify_ak this cycle. */
                rp_ak_cert_was_cached[i] ? "cached" : "issued",
                latency_str, reason);
    }

    result = CHARRA_RC_SUCCESS;

    /* Common exit, not an error-only one -- the success path falls in here. */
done:
    charra_rp_release_evidence();
    return result;

}