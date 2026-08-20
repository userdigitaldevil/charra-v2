/**
 * @file attester_result.c
 * @brief See attester_result.h.
 *
 * /attest_result: RP's Step 2a verdict on evidence this Attester produced.
 */



#include "attester_result.h"
#include "../common/charra_log.h"
#include "../common/charra_macro.h"
#include "../core/charra_marshaling.h"
#include "../util/coap_util.h"

#define LOG_NAME "attester"

void coap_attest_result_handler(
        struct coap_resource_t* resource CHARRA_UNUSED,
        struct coap_session_t* session, const struct coap_pdu_t* request,
        const struct coap_string_t* query CHARRA_UNUSED,
        struct coap_pdu_t* response) {
    charra_coap_log_peer_address(LOG_NAME, "/attest_result", session);

    size_t data_len = 0;
    const uint8_t* data = NULL;
    if (!charra_coap_get_payload(
                request, LOG_NAME, "/attest_result", &data, &data_len, NULL)) {
        coap_pdu_set_code(response, COAP_RESPONSE_CODE_BAD_REQUEST);
        return;
    }

    msg_attestation_result_dto res = {0};
    if (charra_unmarshal_attestation_result((uint32_t)data_len, data, &res) !=
            CHARRA_RC_SUCCESS) {
        charra_log_error(
                "[" LOG_NAME "] /attest_result: could not parse CBOR data.");
        coap_pdu_set_code(response, COAP_RESPONSE_CODE_BAD_REQUEST);
        return;
    }

    if (res.accepted) {
        charra_log_info("[" LOG_NAME "]  +--- RP ACCEPTED this Attester's "
                        "evidence (Step 2a passed) ---+");
    } else {
        /* Logged at ERROR precisely so it is visible: this is the only
         * signal the Attester ever gets that its own evidence was thrown
         * out, and on a real base station it is what would drive an alert
         * or a re-measurement. */
        charra_log_error("[" LOG_NAME "]  +--- RP REJECTED this Attester's "
                         "evidence (Step 2a failed) ---+");
        if (res.reason_len > 0) {
            charra_log_error("[" LOG_NAME "] /attest_result: reason: %.*s",
                    (int)res.reason_len, (const char*)res.reason);
        }
    }

    coap_pdu_set_code(response, COAP_RESPONSE_CODE_CONTENT);
}
