/**
 * @file verifier_util.c
 * @brief See verifier_util.h.
 */

#include "verifier_util.h"

#include <stdio.h>
#include <string.h>

#include "../common/charra_log.h"
#include "../common/charra_macro.h"
#include "../util/coap_util.h"
#include "verifier_shared.h"

#define LOG_NAME "verifier"

/**
 * @brief Formats the leading bytes of a buffer as a lowercase hex string,
 * for compact identity fingerprints/serials/nonces inline in log lines --
 * a full 32-byte EK fingerprint or 16-byte AK serial is unwieldy to print
 * in full every time, but a short prefix is still enough to tell two
 * different identities/values apart at a glance across a busy log.
 *
 * @param out_len buffer size in out; at most (out_len - 1) / 2 bytes of buf
 * are rendered, silently truncating anything beyond that. out_len == 0 is
 * a no-op (not an out-of-bounds write): every current call site passes a
 * non-zero literal buffer size, but out_len - 1 would otherwise underflow
 * (it's size_t) into a huge max_bytes and write far past out.
 */
void hex_prefix(
        const uint8_t* buf, size_t buf_len, char* out, size_t out_len) {
    if (out_len == 0) {
        return;
    }
    size_t max_bytes = (out_len - 1) / 2;
    size_t n = buf_len < max_bytes ? buf_len : max_bytes;
    for (size_t i = 0; i < n; ++i) {
        snprintf(out + (i * 2), 3, "%02x", buf[i]);
    }
    out[n * 2] = '\0';
}

/**
 * @brief Logs the requesting peer's address:port for a CoAP handler --
 * useful once several RPs (or several redundant requests from the same RP)
 * can hit one Verifier, to tell which physical connection a given round's
 * log lines belong to, beyond just the identity fingerprints logged
 * elsewhere.
 */
void log_peer_address(
        const char* endpoint_name, struct coap_session_t* session) {
    const coap_address_t* remote = coap_session_get_addr_remote(session);
    if (remote == NULL) {
        return;
    }
    unsigned char addr_buf[64] = {0};
    size_t addr_len = coap_print_addr(remote, addr_buf, sizeof(addr_buf) - 1);
    addr_buf[addr_len] = '\0';
    charra_log_info("[" LOG_NAME "] %s: request from %s.", endpoint_name,
            (const char*)addr_buf);
}
void release_response_data(
        struct coap_session_t* session CHARRA_UNUSED, void* app_ptr) {
    charra_free_and_null(app_ptr);
}
