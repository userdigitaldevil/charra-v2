/**
 * @file hex_util.c
 * @brief See hex_util.h.
 */

#include "hex_util.h"

#include <stdio.h>

void charra_hex_encode(const uint8_t* data, size_t data_len, char* out) {
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < data_len; i++) {
        out[2 * i] = digits[(data[i] >> 4) & 0xf];
        out[2 * i + 1] = digits[data[i] & 0xf];
    }
    out[2 * data_len] = '\0';
}

bool charra_hex_decode(const char* hex, size_t byte_len, uint8_t* out) {
    for (size_t i = 0; i < byte_len; i++) {
        unsigned int byte = 0;
        if (sscanf(hex + 2 * i, "%2x", &byte) != 1) {
            return false;
        }
        out[i] = (uint8_t)byte;
    }
    return true;
}
