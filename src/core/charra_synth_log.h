/**
 * @file charra_synth_log.h
 * @brief Synthetic IMA event log generation, for the Verifier's RP
 * qualification check.
 *
 * Per the "RP Access Check Process": before trusting an RP to redact real
 * evidence, the Verifier fabricates a log containing realistic-looking
 * sensitive content, runs its own redaction logic on it to record the
 * expected ("golden") result, then sends the RAW fabricated log to the RP.
 * If the RP's own redaction produces the same result, it has proven its
 * pipeline works without ever having touched real Attester data.
 *
 * This module only produces the raw, unredacted synthetic log -- the input
 * side of that check. It knows nothing about redaction.
 *
 * The generated log is genuinely well-formed: it uses the exact same binary
 * TLV layout charra_event_log.c parses, with a valid template_digest for
 * each entry (SHA256 of the entry's own template_data, exactly as IMA
 * computes it), so it is valid input to charra_replay_ima_log() and to
 * whatever redaction logic is exercised against it.
 */

#ifndef CHARRA_SYNTH_LOG_H
#define CHARRA_SYNTH_LOG_H

#include <inttypes.h>

#include "../common/charra_error.h"

/**
 * @brief Generate a synthetic IMA event log with fabricated sensitive-looking
 * content.
 *
 * Deterministic: the same (num_entries, seed) always produces byte-identical
 * output. This is fabricated test data, not a secret, so a simple seeded
 * construction is used rather than a cryptographic RNG -- determinism is more
 * useful here than unpredictability, since the Verifier needs to be able to
 * regenerate or re-check exactly what it sent.
 *
 * Every entry targets CHARRA_IMA_PCR_INDEX, uses the "ima-ng" template, and
 * carries a template_data built as "sha256:" + a fabricated 32-byte file
 * digest + NUL + a plausible-looking sensitive path drawn from a small fixed
 * pool. template_digest is the real SHA256 of that template_data, so the
 * output is valid input to charra_replay_ima_log().
 *
 * @param[in] num_entries how many entries to generate; must be > 0
 * @param[in] seed determines the fabricated content; same seed -> same log
 * @param[out] log_out receives a malloc'd buffer; caller must free() it
 * @param[out] log_len_out receives the length of *log_out
 * @returns CHARRA_RC_SUCCESS, CHARRA_RC_BAD_ARGUMENT on bad arguments,
 * CHARRA_RC_ERROR on allocation failure, CHARRA_RC_CRYPTO_ERROR if hashing
 * fails.
 */
CHARRA_RC charra_synth_generate_ima_log(uint32_t num_entries, uint32_t seed,
        uint8_t** log_out, uint32_t* log_len_out);

#endif /* CHARRA_SYNTH_LOG_H */
