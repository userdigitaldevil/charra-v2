/**
 * @file rp_coap.h
 * @brief The Relying Party's one-shot CoAP client exchange.
 *
 * Every RP-as-client request in this codebase -- /certify_ak, /qualify,
 * /qualify_submit, /certify_ak_of_attester, /attest_result -- is the same
 * create-context, create-session, send-PDU, wait, tear-down sequence, so it
 * lives here once.
 */

#ifndef CHARRA_RP_COAP_H
#define CHARRA_RP_COAP_H

#include <coap3/coap.h>
#include <stdbool.h>
#include <stdint.h>

#include "../common/charra_error.h"

/**
 * @brief Send req_buf (may be NULL/0) as a CoAP FETCH to
 * ip_address:port/uri_path, registering response_handler, and block until
 * libcoap has nothing pending, an I/O error occurs, or
 * verifier_response_timeout is exceeded.
 *
 * Reports only whether the CoAP transport completed. The handler is
 * expected to record the exchange's content-level result in its own
 * dedicated global -- see rp_shared.h for why that pattern exists.
 *
 * @param[in,out] processing_flag the caller's own "handler is running"
 * flag, reset to false here before sending.
 */
CHARRA_RC rp_coap_fetch(const char* ip_address, unsigned int port,
        const char* uri_path, const uint8_t* req_buf, uint32_t req_buf_len,
        coap_response_handler_t response_handler, bool* processing_flag);

#endif /* CHARRA_RP_COAP_H */
