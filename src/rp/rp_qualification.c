/**
 * @file rp_qualification.c
 * @brief See rp_qualification.h.
 *
 * The two CoAP response handlers live here alongside the handshake that
 * drives them: each is paired with its own module-private globals (a
 * libcoap callback cannot return data), and separating a handler from the
 * globals it writes would break silently rather than fail to link.
 */

#include "rp_qualification.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "../common/charra_log.h"
#include "../common/charra_macro.h"
#include "../core/charra_dto.h"
#include "../core/charra_event_log.h"
#include "../core/charra_marshaling.h"
#include "../core/charra_rp_qualification.h"
#include "../core/charra_sdk.h"
#include "../util/coap_util.h"
#include "../util/io_util.h"
#include "rp_coap.h"
#include "rp_signing_key.h"
#include "rp_shared.h"

#define LOG_NAME "relying party"

static coap_response_t coap_qualify_response_handler(
        coap_session_t* session CHARRA_UNUSED,
        const coap_pdu_t* sent CHARRA_UNUSED, const coap_pdu_t* received,
        const coap_mid_t mid CHARRA_UNUSED) {
    processing_qualify_response = true;

    size_t data_len = 0;
    const uint8_t* data = NULL;
    if (!charra_coap_get_payload(
                received, LOG_NAME, "/qualify response", &data, &data_len,
                NULL)) {
        qualify_response_rc = CHARRA_RC_ERROR;
        goto cleanup;
    }

    msg_qualify_response_dto resp = {0};
    if ((qualify_response_rc = charra_unmarshal_qualify_response(
                 data_len, data, &resp)) != CHARRA_RC_SUCCESS) {
        charra_log_error(
                "[" LOG_NAME "] /qualify: Could not parse CBOR response.");
        goto cleanup;
    }

    charra_free_if_not_null(qualify_challenge_log);
    qualify_challenge_log = resp.challenge_log;
    qualify_challenge_log_len = resp.challenge_log_len;
    memcpy(qualify_challenge_salt, resp.salt, sizeof(qualify_challenge_salt));

cleanup:
    processing_qualify_response = false;
    return COAP_RESPONSE_OK;
}

static coap_response_t coap_qualify_submit_response_handler(
        coap_session_t* session CHARRA_UNUSED,
        const coap_pdu_t* sent CHARRA_UNUSED, const coap_pdu_t* received,
        const coap_mid_t mid CHARRA_UNUSED) {
    processing_qualify_submit_response = true;

    /* The Verifier answers with its verdict AND the deadline it granted --
     * see msg_qualify_submit_response_dto for why the RP needs the latter. */
    size_t data_len = 0;
    const uint8_t* data = NULL;
    qualify_submit_qualified = false;
    qualify_submit_expires_at = 0;
    if (charra_coap_get_payload(received, LOG_NAME, "/qualify/submit response",
                &data, &data_len, NULL)) {
        msg_qualify_submit_response_dto resp = {0};
        if (charra_unmarshal_qualify_submit_response(
                    (uint32_t)data_len, data, &resp) == CHARRA_RC_SUCCESS) {
            qualify_submit_qualified =
                    coap_pdu_get_code(received) ==
                            COAP_RESPONSE_CODE_CONTENT &&
                    resp.qualified != 0;
            qualify_submit_expires_at = (time_t)resp.expires_at;
        } else {
            charra_log_error("[" LOG_NAME "] /qualify/submit: could not "
                             "parse the Verifier's response.");
        }
    }

    processing_qualify_submit_response = false;
    return COAP_RESPONSE_OK;
}

CHARRA_RC rp_perform_qualification_handshake_once(int num_verifiers) {
    /* Fast path: the grant we already hold is still valid. Re-checked
     * against the wall clock on every call rather than latched into a
     * boolean, so a daemon whose run outlives its grant actually notices
     * and re-qualifies instead of being voted down forever. */
    if (time(NULL) < rp_qualified_until) {
        return CHARRA_RC_SUCCESS;
    }

    CHARRA_RC result = CHARRA_RC_ERROR;

    /* Held across the whole handshake below, not just individual field
     * accesses: every one of qualify_challenge_log/_len/_salt,
     * qualify_response_rc, processing_qualify_response,
     * qualify_submit_qualified, and processing_qualify_submit_response is
     * a single shared global -- see rp_qualification_mutex's own comment
     * for why this still matters even though the handshake itself now
     * runs once per cycle. */
    pthread_mutex_lock(&rp_qualification_mutex);

    /* Re-checked under the lock, which is what actually makes the "first
     * thread re-qualifies, the rest short-circuit" behaviour true. The
     * check above the lock is only a fast path: two threads can both pass
     * it, and without this second look both would run the full handshake,
     * the second discarding a grant it had just renewed. */
    if (time(NULL) < rp_qualified_until) {
        pthread_mutex_unlock(&rp_qualification_mutex);
        return CHARRA_RC_SUCCESS;
    }

    /* Qualify ONCE, with the first Verifier reachable for /qualify. A
     * transport failure moves on to the next candidate, but a received
     * verdict -- qualified or not -- ends the search: every Verifier runs
     * the same check against the same synthetic log, so a second opinion
     * would be the same opinion.
     *
     * One handshake suffices because the Verifier that ran it records the
     * result in a file all of them read (verifier_qualified_rps.h), so
     * every sibling honours it without the RP contacting them. */
    for (int verifier_index = 0; verifier_index < num_verifiers;
            ++verifier_index) {
        const verifier_info* verifier = &verifiers[verifier_index];
        uint8_t* redacted_log = NULL;
        uint32_t redacted_log_len = 0;

        charra_log_info(
                "[" LOG_NAME "]  +------------ RP Qualification (Verifier "
                "n° %d, port %u) --------------+",
                verifier_index + 1, verifier->port_number);

        /* --- 1. fetch a fresh challenge --- */
        qualify_response_rc = CHARRA_RC_ERROR;
        result = rp_coap_exchange(&(rp_coap_request){
            .host = verifier->ip_address, .port = verifier->port_number,
            .uri_path = "qualify",
            .body = NULL, .body_len = 0,
            .on_response = coap_qualify_response_handler,
            .response_pending = &processing_qualify_response,
            .timeout_seconds = verifier_response_timeout,
            .dtls_rpk_peer_public_key_path = dtls_rpk_verifier_public_key_path,
        });
        if (result != CHARRA_RC_SUCCESS || qualify_response_rc != CHARRA_RC_SUCCESS) {
            charra_log_error(
                    "[" LOG_NAME "] Verifier n° %d (port %u) unreachable "
                    "for /qualify, trying next Verifier.",
                    verifier_index + 1, verifier->port_number);
            continue;
        }
        charra_log_info("[" LOG_NAME "] Received a %u-byte challenge log.",
                qualify_challenge_log_len);

        /* --- 2. redact it with the exact same pipeline real evidence uses --- */
        result = charra_sdk_redact_ima_log(qualify_challenge_log,
                qualify_challenge_log_len, qualify_challenge_salt,
                &redacted_log, &redacted_log_len);
        if (result != CHARRA_RC_SUCCESS) {
            charra_log_error("[" LOG_NAME "] Could not redact the "
                             "qualification challenge log.");
            goto done;
        }

        /* --- 3. replay the redacted log into its PCR digest --- */
        uint8_t submitted_pcr_digest[TPM2_SHA256_DIGEST_SIZE] = {0};
        result = charra_replay_ima_log(redacted_log, redacted_log_len,
                CHARRA_IMA_PCR_INDEX, submitted_pcr_digest);
        if (result != CHARRA_RC_SUCCESS) {
            charra_log_error("[" LOG_NAME "] Could not replay the redacted "
                             "challenge log.");
            charra_free_if_not_null(redacted_log);
            goto done;
        }

        /* --- 4. sign the PCR digest with RP's TPM-resident key, the same
         * call charra_rp_build_evidence_message() uses for Quote_r --- */
        uint8_t rp_signature[CHARRA_RSA_SIGNATURE_LEN] = {0};
        TPM2B_PUBLIC ak_public_key = {0};
        result = rp_sign_with_ak(submitted_pcr_digest,
                sizeof(submitted_pcr_digest), rp_signature,
                &ak_public_key);
        if (result != CHARRA_RC_SUCCESS) {
            charra_log_error(
                    "[" LOG_NAME "] Could not sign the qualification PCR "
                    "digest.");
            charra_free_if_not_null(redacted_log);
            goto done;
        }

        /* --- 5. submit --- */
        msg_qualify_submit_request_dto submit_req = {
                .submitted_redacted_log_len = redacted_log_len,
                .submitted_redacted_log = redacted_log,
                .rp_signature_len = sizeof(rp_signature),
                .rp_public_key_len = sizeof(ak_public_key),
        };
        memcpy(submit_req.submitted_pcr_digest, submitted_pcr_digest,
                sizeof(submitted_pcr_digest));
        memcpy(submit_req.rp_signature, rp_signature, sizeof(rp_signature));
        /* From the same derivation that signed, as in the evidence path. */
        memcpy(submit_req.rp_public_key, &ak_public_key,
                sizeof(ak_public_key));

        uint8_t* submit_buf = NULL;
        uint32_t submit_buf_len = 0;
        result = charra_marshal_qualify_submit_request(
                &submit_req, &submit_buf_len, &submit_buf);
        if (result != CHARRA_RC_SUCCESS) {
            charra_log_error(
                    "[" LOG_NAME "] Could not marshal /qualify/submit "
                    "request.");
            charra_free_if_not_null(redacted_log);
            goto done;
        }

        result = rp_coap_exchange(&(rp_coap_request){
            .host = verifier->ip_address, .port = verifier->port_number,
            .uri_path = "qualify_submit",
            .body = submit_buf, .body_len = submit_buf_len,
            .on_response = coap_qualify_submit_response_handler,
            .response_pending = &processing_qualify_submit_response,
            .timeout_seconds = verifier_response_timeout,
            .dtls_rpk_peer_public_key_path = dtls_rpk_verifier_public_key_path,
        });
        charra_free_if_not_null(submit_buf);
        if (result != CHARRA_RC_SUCCESS) {
            charra_log_error(
                    "[" LOG_NAME "] Verifier n° %d (port %u) unreachable "
                    "for /qualify_submit, trying next Verifier.",
                    verifier_index + 1, verifier->port_number);
            charra_free_if_not_null(redacted_log);
            continue;
        }

        if (qualify_submit_qualified) {
            charra_log_info(
                    "[" LOG_NAME "] |  RP QUALIFIED with Verifier n° %d "
                    "(port %u)  |",
                    verifier_index + 1, verifier->port_number);
            /* Exactly what the Verifier said it granted -- no local guess
             * at the window. The authoritative copy is the Verifier-side
             * shared file; this one lets the RP re-qualify before the
             * grant lapses rather than after being voted down. */
            rp_qualified_until = qualify_submit_expires_at;
            charra_log_info(
                    "[" LOG_NAME "] Qualification valid until %lld (%lld "
                    "second(s) from now, as granted by this Verifier); every "
                    "Verifier honours it from the list they all read.",
                    (long long)rp_qualified_until,
                    (long long)(rp_qualified_until - time(NULL)));
            result = CHARRA_RC_SUCCESS;
        } else {
            charra_log_error(
                    "[" LOG_NAME
                    "] |  RP NOT QUALIFIED with Verifier n° %d (port %u)  |",
                    verifier_index + 1, verifier->port_number);
            result = CHARRA_RC_VERIFICATION_FAILED;
        }
        charra_free_if_not_null(redacted_log);
        goto done;
    }

    charra_log_error("[" LOG_NAME "] Could not qualify: no Verifier was "
                     "reachable for /qualify.");
    result = CHARRA_RC_ERROR;

done:

    charra_free_if_not_null(qualify_challenge_log);
    qualify_challenge_log = NULL;
    qualify_challenge_log_len = 0;
    pthread_mutex_unlock(&rp_qualification_mutex);
    return result;
}
