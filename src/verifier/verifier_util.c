/**
 * @file verifier_util.c
 * @brief See verifier_util.h.
 */

#include "verifier_util.h"

#include <stdio.h>

#include "../common/charra_macro.h"

/* out_len == 0 returns rather than writing: out_len - 1 is size_t, so it
 * would otherwise underflow into a huge max_bytes. */
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

void release_response_data(
        struct coap_session_t* session CHARRA_UNUSED, void* app_ptr) {
    charra_free_and_null(app_ptr);
}
