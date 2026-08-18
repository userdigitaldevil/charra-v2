/**
 * @file verifier_nonce.c
 * @brief See verifier_nonce.h.
 *
 * Owns the per-round challenge state it produces: the nonce the RP gave the
 * Attester (kept for Step 3b item 3) and this Verifier's own challenge for
 * Quote_r (Step 3a item 3). Both are consumed by verifier_appraise.c, which
 * reaches them through verifier_shared.h.
 */

#include "verifier_nonce.h"

#include <stdlib.h>
#include <string.h>

#include <tss2/tss2_tpm2_types.h>

#include "../common/charra_log.h"
#include "../common/charra_macro.h"
#include "../core/charra_dto.h"
#include "../core/charra_marshaling.h"
#include "../util/charra_util.h"
#include "../util/coap_util.h"
#include "verifier_shared.h"

#define LOG_NAME "verifier"

msg_attestation_request_dto last_request = {0};

uint8_t verifier_challenge_nonce[TPM2_SHA256_DIGEST_SIZE] = {0};
uint32_t verifier_challenge_nonce_len = 0;

/* Rounds served, purely for the log delimiter below. Not derived from the
 * RP's own run numbering -- this Verifier only knows how many rounds it was
 * itself asked to join. */
static unsigned int attestation_round_counter = 0;

void coap_nonce_handler(struct coap_resource_t* resource,
                                struct coap_session_t* session,
                                const struct coap_pdu_t* request,
                                const struct coap_string_t* query,
                                struct coap_pdu_t* response) {
    CHARRA_RC charra_r = CHARRA_RC_SUCCESS;
    int coap_r = 0;

    /* Round delimiter. /nonce is the best anchor for "a new round started":
     * from an RP's second round on, its AK certificate and qualification are
     * both cached, so /certify_ak and /qualify don't run at all and /nonce
     * genuinely is the round's first request. Only a first round prints the
     * delimiter late, and that round is self-evident in the log anyway.
     * Mirrors relying_party.c's "Starting new attestation run". */
    attestation_round_counter++;
    charra_log_info("[" LOG_NAME
                    "] ============================================================");
    charra_log_info(
            "[" LOG_NAME "] Starting attestation round #%u.",
            attestation_round_counter);
    charra_log_info("[" LOG_NAME
                    "] ============================================================");
    charra_coap_log_peer_address(LOG_NAME, "/nonce", session);

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
    }
    charra_log_info("[" LOG_NAME "] Received nonce of length %zu (%zu total).",
            data_len, data_total_len);

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
     * verifier_challenge_nonce below. */
    if (req.nonce_len > sizeof(req.nonce)) {
        charra_log_error("[" LOG_NAME "] Nonce too long.");
        charra_free_if_not_null(req.event_log_path);
        goto error;
    }
    /* charra_unmarshal_attestation_request() heap-allocates event_log_path,
     * so the round being replaced has to be released before the struct
     * assignment drops the only pointer to it. */
    charra_free_if_not_null(last_request.event_log_path);
    last_request = req;

    /* Generate the Verifier's OWN freshness challenge and send THAT back,
     * not req.nonce: a value the RP picked itself proves nothing about
     * freshness, since it could replay an old Quote_r over a nonce it
     * already knows will match. The challenger has to pick the value. RP
     * signs whatever comes back here into Quote_r, which Step 3a item 3
     * checks against verifier_challenge_nonce. */
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
}
