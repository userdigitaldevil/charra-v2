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
 * @brief Open a client session in whichever DTLS mode is configured.
 *
 * Falls back to plain UDP when neither --psk nor --rpk is set, and also when
 * the caller names no peer key -- see the field's comment in rp_coap.h.
 */
static coap_session_t* rp_coap_open_session(coap_context_t* context,
        const char* host, unsigned int port,
        const char* peer_public_key_path) {
    if (dtls_config.use_psk && dtls_config.use_rpk) {
        charra_log_error("[" LOG_NAME "] Both DTLS-PSK and DTLS-RPK are "
                         "enabled; refusing to guess which to use.");
        return NULL;
    }
    if (dtls_config.use_psk && !coap_dtls_is_supported()) {
        charra_log_error("[" LOG_NAME "] DTLS is enabled but this libcoap "
                         "build does not support it.");
        return NULL;
    }

    if (dtls_config.use_psk) {
        return charra_coap_new_client_session_psk(context, host, port,
                COAP_PROTO_DTLS, dtls_config.psk_identity, (uint8_t*)dtls_config.psk_key,
                strlen(dtls_config.psk_key));
    }
    if (dtls_config.use_rpk && peer_public_key_path != NULL) {
        coap_dtls_pki_t dtls_pki = {0};
        if (charra_coap_setup_dtls_pki_for_rpk(&dtls_pki,
                    dtls_config.rpk_private_key_path, dtls_config.rpk_public_key_path,
                    (char*)peer_public_key_path,
                    dtls_config.rpk_verify_peer_public_key) != CHARRA_RC_SUCCESS) {
            charra_log_error(
                    "[" LOG_NAME "] Could not set up the DTLS-RPK structure.");
            return NULL;
        }
        return charra_coap_new_client_session_pki(
                context, host, port, COAP_PROTO_DTLS, &dtls_pki);
    }
    return charra_coap_new_client_session(context, host, port, COAP_PROTO_UDP);
}

/**
 * @brief Block until the handler clears response_pending, libcoap runs out
 * of pending I/O, an I/O error occurs, or the timeout elapses.
 *
 * Elapsed time comes from CLOCK_MONOTONIC rather than summing
 * coap_io_process()'s self-reported per-call durations: those undercount
 * time spent scheduled out under concurrent load, and a millisecond
 * accumulator in a fixed-width integer overflows for large timeouts.
 */
static CHARRA_RC rp_coap_wait_for_response(coap_context_t* context,
        const char* uri_path, bool* response_pending,
        uint16_t timeout_seconds) {
    struct timespec wait_start, wait_now;
    clock_gettime(CLOCK_MONOTONIC, &wait_start);

    while (*response_pending && coap_io_pending(context)) {
        if (coap_io_process(context, COAP_IO_PROCESS_TIME_MS) == -1) {
            charra_log_error(
                    "[" LOG_NAME "] Error during CoAP I/O processing for /%s.",
                    uri_path);
            return CHARRA_RC_COAP_ERROR;
        }
        clock_gettime(CLOCK_MONOTONIC, &wait_now);
        double elapsed_ms = (wait_now.tv_sec - wait_start.tv_sec) * 1000.0 +
                            (wait_now.tv_nsec - wait_start.tv_nsec) / 1e6;
        if (elapsed_ms >= (timeout_seconds * 1000)) {
            charra_log_error("[" LOG_NAME "] Timeout after %.0f ms waiting "
                             "for the /%s response.",
                    elapsed_ms, uri_path);
            return CHARRA_RC_TIMEOUT;
        }
    }
    return CHARRA_RC_SUCCESS;
}

CHARRA_RC rp_coap_exchange(const rp_coap_request* request) {
    CHARRA_RC result = CHARRA_RC_ERROR;
    coap_context_t* context = NULL;
    coap_session_t* session = NULL;
    coap_optlist_t* options = NULL;

    if ((context = charra_coap_new_context(true)) == NULL) {
        charra_log_error(
                "[" LOG_NAME "] Cannot create the CoAP context for /%s.",
                request->uri_path);
        result = CHARRA_RC_COAP_ERROR;
        goto cleanup;
    }
    coap_register_response_handler(context, request->on_response);

    if ((session = rp_coap_open_session(context, request->host, request->port,
                 request->dtls_rpk_peer_public_key_path)) == NULL) {
        charra_log_error(
                "[" LOG_NAME "] Cannot create the /%s client session.",
                request->uri_path);
        result = CHARRA_RC_COAP_ERROR;
        goto cleanup;
    }
    if (request->session_app_data != NULL) {
        coap_session_set_app_data(session, request->session_app_data);
    }

    uint8_t mediatype_buf[4] = {0};
    unsigned int mediatype_buf_len = coap_encode_var_safe(mediatype_buf,
            sizeof(mediatype_buf), COAP_MEDIATYPE_APPLICATION_CBOR);
    if (coap_insert_optlist(&options,
                coap_new_optlist(COAP_OPTION_URI_PATH,
                        strlen(request->uri_path),
                        (const uint8_t*)request->uri_path)) != 1 ||
            coap_insert_optlist(&options,
                    coap_new_optlist(COAP_OPTION_CONTENT_TYPE,
                            mediatype_buf_len, mediatype_buf)) != 1) {
        charra_log_error("[" LOG_NAME "] Cannot build the /%s CoAP options.",
                request->uri_path);
        result = CHARRA_RC_COAP_ERROR;
        goto cleanup;
    }

    coap_pdu_t* pdu = charra_coap_new_request(session, COAP_MESSAGE_TYPE_CON,
            COAP_REQUEST_FETCH, &options, request->body, request->body_len);
    if (pdu == NULL) {
        charra_log_error("[" LOG_NAME "] Cannot create the /%s request PDU.",
                request->uri_path);
        result = CHARRA_RC_ERROR;
        goto cleanup;
    }

    coap_fixed_point_t ack_timeout = {request->timeout_seconds, 0};
    coap_session_set_ack_timeout(session, ack_timeout);

    /* Raised before the send, not after: libcoap can dispatch the response
     * from inside coap_send_large(), and a flag raised afterwards would then
     * never be observed falling. */
    *request->response_pending = true;
    if (coap_send_large(session, pdu) == COAP_INVALID_MID) {
        charra_log_error("[" LOG_NAME "] Cannot send the /%s request.",
                request->uri_path);
        *request->response_pending = false;
        result = CHARRA_RC_COAP_ERROR;
        goto cleanup;
    }

    result = rp_coap_wait_for_response(context, request->uri_path,
            request->response_pending, request->timeout_seconds);

cleanup:
    charra_free_if_not_null_ex(options, coap_delete_optlist);
    charra_free_if_not_null_ex(session, coap_session_release);
    charra_free_if_not_null_ex(context, coap_free_context);
    /* No coap_cleanup() here: it tears down libcoap's *global* state, so
     * calling it per exchange (and from each Verifier thread) would pull the
     * ground out from under contexts still in use. Done once, in main(). */
    return result;
}
