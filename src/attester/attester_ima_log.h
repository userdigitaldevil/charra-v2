/**
 * @file attester_ima_log.h
 * @brief The Attester's IMA measurement log: conversion, caching, and
 * replay into the TPM's PCRs.
 */

#ifndef CHARRA_ATTESTER_IMA_LOG_H
#define CHARRA_ATTESTER_IMA_LOG_H

#include <stdint.h>

#include <tss2/tss2_esys.h>

#include "../common/charra_error.h"

/**
 * @brief Converts an ASCII IMA measurement log ("PCR <idx> <digest> ima-ng
 * <alg>:<hash> <path>" per line) into the binary TLV format the rest of
 * CHARRA parses.
 *
 * template_data is rebuilt in the real ima-ng layout and template_digest is
 * recomputed as SHA256(template_data), so the resulting log satisfies its
 * own self-consistency check by construction.
 *
 * @param[in] path the ASCII log to read
 * @param[out] log_out malloc'd binary log; caller frees
 * @param[out] log_len_out length of log_out
 * @return CHARRA_RC_SUCCESS, CHARRA_RC_MARSHALING_ERROR if the file holds no
 * parseable ASCII entries (i.e. it is not an ASCII log), otherwise an error.
 */
CHARRA_RC charra_ima_log_ascii_to_binary(
        const char* path, uint8_t** log_out, uint32_t* log_len_out);

/**
 * @brief Extends every entry of a binary IMA log into the PCR it names.
 *
 * @param esys_ctx[in,out] The ESAPI context.
 */
CHARRA_RC charra_extend_pcrs_from_binary_log(
        ESYS_CONTEXT* esys_ctx, const uint8_t* log, uint32_t log_len);

/**
 * @brief Returns the Attester's binary IMA log, loading and caching it on
 * first use.
 *
 * The returned pointer is owned by this module and stays valid for the
 * process's lifetime -- the PCRs were extended from exactly these bytes, so
 * every response has to carry exactly these bytes.
 */
CHARRA_RC charra_get_ima_log(
        const char* path, const uint8_t** log_out, uint32_t* log_len_out);

#endif /* CHARRA_ATTESTER_IMA_LOG_H */
