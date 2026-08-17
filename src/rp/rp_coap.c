/**
 * @file rp_coap.c
 * @brief See rp_coap.h.
 */

#include "rp_coap.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "../common/charra_log.h"
#include "../common/charra_macro.h"
#include "../util/coap_util.h"
#include "rp_shared.h"

#define LOG_NAME "relying party"

/**
 * @brief Send req_buf (may be NULL/0 for an empty body) as a CoAP FETCH
 * request to ip_address:port/uri_path, registering response_handler, and
 * block until libcoap has nothing left pending for the exchange, an I/O
 * error occurs, or verifier_response_timeout is exceeded.
 *
 * Factors out the create-context/create-session/build-and-send-PDU/wait-
 * for-response/tear-down sequence every one-shot RP-as-client exchange in
 * this file repeats (ensure_rp_ak_certificate()'s /certify_ak call,
 * rp_perform_qualification_handshake_once()'s /qualify and /qualify/submit).
 * response_handler is expected to record the exchange's actual content-
 * level result (parsed data, or a parse failure) in its own dedicated
 * global, the same way coap_certify_ak_response_handler() does for
 * certify_ak_rc -- this function only reports whether the CoAP transport
 * itself completed, not whether the response's content was valid.
 *
 * @param[in,out] processing_flag caller's own dedicated "response handler
 * is currently running" flag (e.g. &processing_qualify_response), reset to
 * false here before sending -- same flag every response handler in this
 * file already toggles true/false around its own body.
 */
CHARRA_RC rp_coap_fetch(const char* ip_address, unsigned int port,
        const char* uri_path, const uint8_t* req_buf, uint32_t req_buf_len,
        coap_response_handler_t response_handler, bool* processing_flag) {
    CHARRA_RC result = CHARRA_RC_ERROR;
    coap_context_t* coap_context = NULL;
    coap_session_t* coap_session = NULL;
    coap_optlist_t* coap_options = NULL;

    if ((coap_context = charra_coap_new_context(true)) == NULL) {
        charra_log_error(
                "[" LOG_NAME "] Cannot create CoAP context for /%s.", uri_path);
        return CHARRA_RC_COAP_ERROR;
    }
    coap_register_response_handler(coap_context, response_handler);

    if ((coap_session = charra_coap_new_client_session(
                 coap_context, ip_address, port, COAP_PROTO_UDP)) == NULL) {
        charra_log_error(
                "[" LOG_NAME "] Cannot create /%s client session.", uri_path);
        charra_free_if_not_null_ex(coap_context, coap_free_context);
        return CHARRA_RC_COAP_ERROR;
    }

    uint8_t coap_mediatype_cbor_buf[4] = {0};
    unsigned int coap_mediatype_cbor_buf_len = coap_encode_var_safe(
            coap_mediatype_cbor_buf, sizeof(coap_mediatype_cbor_buf),
            COAP_MEDIATYPE_APPLICATION_CBOR);
    coap_insert_optlist(&coap_options,
            coap_new_optlist(COAP_OPTION_URI_PATH, strlen(uri_path),
                    (const uint8_t*)uri_path));
    coap_insert_optlist(&coap_options,
            coap_new_optlist(COAP_OPTION_CONTENT_TYPE,
                    coap_mediatype_cbor_buf_len, coap_mediatype_cbor_buf));

    coap_pdu_t* pdu = charra_coap_new_request(coap_session,
            COAP_MESSAGE_TYPE_CON, COAP_REQUEST_FETCH, &coap_options, req_buf,
            req_buf_len);
    if (pdu == NULL) {
        charra_log_error(
                "[" LOG_NAME "] Cannot create /%s request PDU.", uri_path);
        charra_free_if_not_null_ex(coap_options, coap_delete_optlist);
        charra_free_if_not_null_ex(coap_session, coap_session_release);
        charra_free_if_not_null_ex(coap_context, coap_free_context);
        return CHARRA_RC_ERROR;
    }

    coap_fixed_point_t coap_timeout = {verifier_response_timeout, 0};
    coap_session_set_ack_timeout(coap_session, coap_timeout);

    if (coap_send_large(coap_session, pdu) == COAP_INVALID_MID) {
        charra_log_error("[" LOG_NAME "] Cannot send /%s request.", uri_path);
        charra_free_if_not_null_ex(coap_options, coap_delete_optlist);
        charra_free_if_not_null_ex(coap_session, coap_session_release);
        charra_free_if_not_null_ex(coap_context, coap_free_context);
        return CHARRA_RC_COAP_ERROR;
    }

    *processing_flag = false;
    /* Real elapsed time (CLOCK_MONOTONIC), not a sum of coap_io_process()'s
     * self-reported per-call durations -- that undercounts time spent
     * scheduled out under concurrent load. Also sidesteps the same
     * counter-overflow class of bug a uint16_t/uint32_t millisecond
     * accumulator would otherwise have for large timeouts (see
     * CHARRA_V2_NOTES.md). */
    struct timespec wait_start, wait_now;
    clock_gettime(CLOCK_MONOTONIC, &wait_start);
    int coap_io_process_time = -1;
    result = CHARRA_RC_SUCCESS;
    while (!(*processing_flag) && coap_io_pending(coap_context)) {
        if ((coap_io_process_time = coap_io_process(
                     coap_context, COAP_IO_PROCESS_TIME_MS)) == -1) {
            charra_log_error(
                    "[" LOG_NAME "] Error during CoAP I/O processing for /%s.",
                    uri_path);
            result = CHARRA_RC_COAP_ERROR;
            break;
        }
        clock_gettime(CLOCK_MONOTONIC, &wait_now);
        double elapsed_ms = (wait_now.tv_sec - wait_start.tv_sec) * 1000.0 +
                             (wait_now.tv_nsec - wait_start.tv_nsec) / 1e6;
        if (elapsed_ms >= (verifier_response_timeout * 1000)) {
            charra_log_error(
                    "[" LOG_NAME "] Timeout after %.0f ms waiting for /%s "
                    "response.",
                    elapsed_ms, uri_path);
            result = CHARRA_RC_TIMEOUT;
            break;
        }
    }

    charra_free_if_not_null_ex(coap_options, coap_delete_optlist);
    charra_free_if_not_null_ex(coap_session, coap_session_release);
    charra_free_if_not_null_ex(coap_context, coap_free_context);
    return result;
}
