/**
 * @file verifier_nonce.c
 * @brief See verifier_nonce.h.
 */

#include "verifier_nonce.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <tss2/tss2_mu.h>
#include <tss2/tss2_tctildr.h>
#include <tss2/tss2_tpm2_types.h>

#include "../common/charra_log.h"
#include "../common/charra_macro.h"
#include "../core/charra_ak_state.h"
#include "../core/charra_dto.h"
#include "../core/charra_helper.h"
#include "../core/charra_key_mgr.h"
#include "../core/charra_marshaling.h"
#include "../core/charra_qualification_state.h"
#include "../core/charra_rp_qualification.h"
#include "../util/cbor_util.h"
#include "../util/charra_util.h"
#include "../util/coap_util.h"
#include "../util/crypto_util.h"
#include "../util/io_util.h"
#include "../util/tpm2_util.h"
#include "verifier_shared.h"
#include "verifier_util.h"

#define LOG_NAME "verifier"

void coap_nonce_handler(struct coap_resource_t* resource,
                                struct coap_session_t* session,
                                const struct coap_pdu_t* request,
                                const struct coap_string_t* query,
                                struct coap_pdu_t* response) {
    CHARRA_RC charra_r = CHARRA_RC_SUCCESS;
    int coap_r = 0;

    /* Clear delimiter between attestation rounds -- without this, a busy
     * Verifier's log (interleaved /certify_ak, /qualify, /qualify_submit,
     * /appraise handling across many rounds) has no visible boundary
     * between one round's requests and the next. /nonce is the best
     * available anchor for "a new round started": on every round after the
     * first with a given RP identity, it genuinely IS the first request
     * (RP's AK certificate and qualification are both cached by then, so
     * neither /certify_ak nor /qualify/qualify_submit get called at all
     * that round -- see relying_party.c's rp_perform_qualification_
     * handshake()). Only on an RP's very first round with this Verifier
     * does the delimiter print a little late, after /certify_ak and
     * /qualify already ran -- acceptable since that round is already
     * self-evidently distinctive in the log (EK/AK certification and
     * qualification-challenge lines that never repeat afterward). Mirrors
     * relying_party.c's own "Starting new attestation run" delimiter. */
    attestation_round_counter++;
    charra_log_info("[" LOG_NAME
                    "] ============================================================");
    charra_log_info(
            "[" LOG_NAME "] Starting attestation round #%u.",
            attestation_round_counter);
    charra_log_info("[" LOG_NAME
                    "] ============================================================");
    log_peer_address("/nonce", session);

    /* --- receive incoming data --- */
    coap_show_pdu(LOG_DEBUG, request);

    /* get data */
    size_t data_len = 0;
    const uint8_t* data = NULL;
    size_t data_offset = 0;
    size_t data_total_len = 0;
    if ((coap_r = coap_get_data_large(
                 request, &data_len, &data, &data_offset, &data_total_len)) == 0) {
        charra_log_error("[" LOG_NAME "] Could not get CoAP PDU data.");
        goto error;
    } else {
        charra_log_info(
                "[" LOG_NAME "] Received nonce of length %zu.", data_len);
        charra_log_info("[" LOG_NAME "] Received nonce of total length %zu.",
                data_total_len);
    }

    /* unmarshal data */
    charra_log_info("[" LOG_NAME "] Parsing received CBOR data.");
    msg_attestation_request_dto req = {0};
    if ((charra_r = charra_unmarshal_attestation_request(
                 data_len, data, &req)) != CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Could not parse CBOR data.");
        goto error;
    }

    /* nonce RP gave the Attester -- kept in last_request for Quote_a's own
     * freshness check (Step 3b item 3); NOT used for Quote_r's, see
     * verifier_challenge_nonce's own comment above. */
    if (req.nonce_len > sizeof(TPMU_HA)) {
        charra_log_error("[" LOG_NAME "] Nonce too long.");
        goto error;
    }
    last_request = req;

    /* Generate the Verifier's own freshness challenge and send THAT back as
     * this response's body -- not req.nonce. A challenge RP picked itself
     * and merely echoed back would prove nothing about freshness from the
     * Verifier's side (RP could replay an old Quote_r over a nonce it
     * already knows will "match"); the challenger has to pick the value.
     * RP's coap_verifier_handler_nonce() stores whatever comes back here as
     * verifier_nonce and signs it into Quote_r, which Step 3a item 3 below
     * then checks against verifier_challenge_nonce. Without a response
     * body at all, RP's client-side nonce wait loop fails every time
     * ("Verifier returned no nonce") -- this handler previously never sent
     * one, before it was fixed to (at the time) echo req.nonce. */
    if ((charra_r = charra_random_bytes(sizeof(verifier_challenge_nonce),
                 verifier_challenge_nonce)) != CHARRA_RC_SUCCESS) {
        charra_log_error(
                "[" LOG_NAME "] Could not generate a random nonce.");
        goto error;
    }
    verifier_challenge_nonce_len = sizeof(verifier_challenge_nonce);

    if ((coap_r = coap_add_data_large_response(resource, session, request,
                 response, query, COAP_MEDIATYPE_APPLICATION_OCTET_STREAM, -1,
                 0, verifier_challenge_nonce_len, verifier_challenge_nonce,
                 NULL, NULL)) == 0) {
        charra_log_error("[" LOG_NAME "] /nonce: Error invoking "
                         "coap_add_data_large_response().");
        goto error;
    }
    coap_pdu_set_code(response, COAP_RESPONSE_CODE_CONTENT);
    return;

error:
    coap_pdu_set_code(response, COAP_RESPONSE_CODE_BAD_REQUEST);
    return;
}
