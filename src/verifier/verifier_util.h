/**
 * @file verifier_util.h
 * @brief Small helpers shared by the Verifier's CoAP resource handlers.
 */

#ifndef CHARRA_VERIFIER_UTIL_H
#define CHARRA_VERIFIER_UTIL_H

#include <coap3/coap.h>
#include <stddef.h>
#include <stdint.h>

/**
 * @brief Formats the leading bytes of a buffer as a lowercase hex string,
 * for compact identity fingerprints/serials/nonces inline in log lines.
 *
 * @param out_len buffer size in out; at most (out_len - 1) / 2 bytes of buf
 * are rendered, silently truncating anything beyond that. out_len == 0 is a
 * no-op rather than an out-of-bounds write.
 */
void hex_prefix(const uint8_t* buf, size_t buf_len, char* out, size_t out_len);

/** @brief Logs the requesting peer's address:port, to tell which physical
 * connection a round's log lines belong to. */
void log_peer_address(
        const char* endpoint_name, struct coap_session_t* session);

/** @brief coap_add_data_large_response() release callback: frees the
 * marshaled response buffer once libcoap has finished sending it. */
void release_response_data(
        struct coap_session_t* session, void* app_ptr);

#endif /* CHARRA_VERIFIER_UTIL_H */
