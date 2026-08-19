/**
 * @file hex_util.c
 * @brief See hex_util.h.
 */

#include "hex_util.h"

static const char hex_digits[] = "0123456789abcdef";

/** @brief One ASCII hex character's value, or -1 if it is not a hex digit. */
static int hex_nibble(const char c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

void charra_hex_encode(const uint8_t* data, size_t data_len, char* out) {
    for (size_t i = 0; i < data_len; i++) {
        out[2 * i] = hex_digits[(data[i] >> 4) & 0xf];
        out[2 * i + 1] = hex_digits[data[i] & 0xf];
    }
    out[2 * data_len] = '\0';
}

/* out_len == 0 returns rather than writing: out_len - 1 is size_t, so it
 * would otherwise underflow into a huge byte count. */
void charra_hex_encode_prefix(
        const uint8_t* data, size_t data_len, char* out, size_t out_len) {
    if (out_len == 0) {
        return;
    }
    const size_t max_bytes = (out_len - 1) / 2;
    charra_hex_encode(data, data_len < max_bytes ? data_len : max_bytes, out);
}

bool charra_hex_decode(const char* hex, size_t byte_len, uint8_t* out) {
    if (hex == NULL || out == NULL) {
        return false;
    }
    for (size_t i = 0; i < byte_len; i++) {
        const int hi = hex_nibble(hex[2 * i]);
        const int lo = hex_nibble(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) {
            return false;
        }
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return true;
}
