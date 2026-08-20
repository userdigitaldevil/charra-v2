/**
 * @file rp_coap.h
 * @brief The Relying Party's one-shot CoAP client exchange.
 *
 * Every RP-as-client request -- /get_verifiers, /attest, /attest_result,
 * /nonce, /appraise, /qualify, /qualify_submit, /attest, /attest_result,
 * /get_verifiers -- is the same create-context, create-session,
 * build-PDU, send, wait, tear-down sequence, so it lives here once.
 */

#ifndef CHARRA_RP_COAP_H
#define CHARRA_RP_COAP_H

#include <coap3/coap.h>
#include <stdbool.h>
#include <stdint.h>

#include "../common/charra_error.h"

/**
 * @brief One request/response exchange, described in full.
 *
 * A struct rather than a parameter list because the exchanges differ along
 * six axes and a positional call of that width is unreadable at the call
 * site -- and misordering two same-typed arguments would compile.
 */
typedef struct {
    /** Peer to talk to, and the resource to FETCH. */
    const char* host;
    unsigned int port;
    const char* uri_path;

    /** Request body; may be NULL/0 for an empty one. */
    const uint8_t* body;
    uint32_t body_len;

    /** Handler libcoap invokes for the response. It reports the exchange's
     * content-level result through its own dedicated global -- a libcoap
     * callback cannot return data. See rp_shared.h. */
    coap_response_handler_t on_response;

    /** Set true here before sending; the handler clears it once it has dealt
     * with the response, which is what ends the wait below. Must therefore be
     * a flag the handler actually clears on every path, including its error
     * paths. */
    bool* response_pending;

    /** Attached to the session with coap_session_set_app_data(), for handlers
     * shared by several concurrent exchanges: five Verifier threads run
     * through one handler, and this pointer is how each response is matched
     * to the thread that asked for it. NULL when the handler needs no
     * context. Must outlive the call. */
    void* session_app_data;

    /** Wall-clock ceiling on the wait, and libcoap's ack_timeout. */
    uint16_t timeout_seconds;

    /** Peer's public key for DTLS-RPK, used only when --rpk is in force.
     * NULL forces plain UDP regardless -- the Trust Manager exchange has no
     * configured peer key. */
    const char* dtls_rpk_peer_public_key_path;
} rp_coap_request;

/**
 * @brief Perform one exchange: send the request, then block until the
 * handler has dealt with the response, libcoap has nothing left pending, an
 * I/O error occurs, or timeout_seconds elapses.
 *
 * Reports only whether the CoAP transport completed. Whether the *content*
 * was valid is the handler's to record.
 */
CHARRA_RC rp_coap_exchange(const rp_coap_request* request);

#endif /* CHARRA_RP_COAP_H */
