/**
 * @file hex_util.h
 * @brief Lowercase hex conversion for fixed-length byte fields.
 */

#ifndef CHARRA_HEX_UTIL_H
#define CHARRA_HEX_UTIL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/**
 * @brief Encodes data_len bytes as 2*data_len lowercase hex chars plus a
 * terminating NUL, so out must hold 2*data_len + 1 bytes.
 */
void charra_hex_encode(const uint8_t* data, size_t data_len, char* out);

/**
 * @brief Encodes as many of data_len's bytes as fit in out_len (including
 * the NUL), truncating rather than overflowing. For log lines, where a
 * readable prefix of a long field is enough.
 */
void charra_hex_encode_prefix(
        const uint8_t* data, size_t data_len, char* out, size_t out_len);

/**
 * @brief Decodes exactly byte_len*2 hex chars from hex into out. Returns
 * false on any non-hex character or if hex is shorter than byte_len*2.
 */
bool charra_hex_decode(const char* hex, size_t byte_len, uint8_t* out);

#endif /* CHARRA_HEX_UTIL_H */
