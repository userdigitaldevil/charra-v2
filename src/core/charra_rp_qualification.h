/**
 * @file charra_rp_qualification.h
 * @brief Verifier-side state and checks for the RP qualification handshake.
 *
 * Implements the Verifier's half of the "RP Access Check Process" (see
 * CHARRA_V2_NOTES.md, "RP access/qualification check"): before an RP is
 * trusted to redact real Attester evidence, the Verifier fabricates a log,
 * redacts it itself to get the "golden answer", sends the raw log to the RP,
 * and checks whether the RP's own redaction matches.
 *
 * This module only covers the parts that need no TSS2/libcoap: generating
 * the challenge + golden answer, and comparing the RP's submission against
 * it. Sending the challenge over the wire and parsing a real Quote_R are
 * separate, not-yet-built concerns (see notes, "Not yet built").
 */

#ifndef CHARRA_RP_QUALIFICATION_H
#define CHARRA_RP_QUALIFICATION_H

#include <inttypes.h>
#include <stdbool.h>
#include <time.h>

#include <tss2/tss2_tpm2_types.h>

#include "../common/charra_error.h"
#include "charra_sdk.h"

/** Default for how long a passed qualification stays valid before re-check
 * is required; override at runtime with
 * charra_rp_qualification_set_validity_seconds().
 *
 * Short on purpose: the point of qualification is ongoing assurance that
 * the RP still runs the correct PATH_Clean SDK, and a day-long grant makes
 * that a once-a-day check. It also has to stay larger than
 * relying_party.c's RP_DEFAULT_QUALIFY_MARGIN_S -- a margin at or above
 * this window can never be satisfied, so RP would renew on every idle pass
 * and the cache would stop meaning anything. Both are checked against each
 * other at startup (see parse_rp_command_line()). */
#define CHARRA_RP_QUALIFICATION_VALIDITY_SECONDS (5 * 60)

/**
 * @brief Set/get the qualification validity window actually in force.
 *
 * Deliberately a runtime value rather than the compile-time macro alone:
 * the window is a contract between two *separate* binaries -- the Verifier
 * writes `expires_at` into its ledger from it, and the RP independently
 * computes the same deadline for its own client-side cache (nothing on the
 * wire carries the expiry: `/qualify/submit` answers with a bare status
 * string). Both therefore expose the same `--qualification-validity` flag
 * and must be given matching values.
 *
 * A mismatch is self-correcting rather than fatal, which is why this is a
 * flag on both sides instead of a wire-format change: if the RP over-
 * estimates, the Verifier rejects the next `/appraise` with "qualification
 * expired" and RP's existing retry path (see rp_qualification_rejected)
 * re-qualifies and resubmits; if it under-estimates, it merely re-qualifies
 * earlier than it had to.
 */
void charra_rp_qualification_set_validity_seconds(time_t seconds);
time_t charra_rp_qualification_get_validity_seconds(void);

/**
 * @brief One RP's qualification round: the golden answer plus pass/fail
 * state.
 *
 * Owns golden_log (malloc'd); free with
 * charra_rp_qualification_state_free().
 */
typedef struct {
    /** Redacted log the Verifier computed itself -- the RP must match this
     * byte for byte. */
    uint8_t* golden_log;
    uint32_t golden_log_len;
    /** PCR the golden log replays to; checked against Quote_R's pcrDigest. */
    uint8_t golden_pcr[TPM2_SHA256_DIGEST_SIZE];
    /** True only from a passing charra_rp_qualification_check() until
     * expires_at. */
    bool qualified;
    time_t expires_at;
} rp_qualification_state;

/**
 * @brief Fabricate a qualification challenge and precompute the golden
 * answer.
 *
 * Generates a synthetic IMA log, redacts it locally with salt to fill in
 * *state_out (golden_log, golden_pcr), and separately returns the raw
 * (unredacted) log for the caller to send to the RP -- the RP is expected
 * to redact it (with the same salt, also sent to it) and submit the result
 * back for charra_rp_qualification_check().
 *
 * *state_out starts unqualified (qualified = false, expires_at = 0).
 *
 * @param[in] num_entries synthetic log size; must be > 0
 * @param[in] seed determines the fabricated content; same seed -> same
 * challenge
 * @param[in] salt exactly CHARRA_SDK_PATH_SALT_LEN bytes, passed straight
 * to charra_sdk_redact_ima_log() -- the caller is expected to send this
 * same salt to the RP, so its own redaction of challenge_log_out comes out
 * byte-identical to golden_log here. See charra_sdk.h for why sharing a
 * salt is only ever safe for this synthetic, Verifier-fabricated log.
 * @param[out] state_out golden answer for this challenge; caller must
 * eventually pass it to charra_rp_qualification_state_free()
 * @param[out] challenge_log_out receives a malloc'd buffer; caller must
 * free() it
 * @param[out] challenge_log_len_out receives the length of
 * *challenge_log_out
 * @returns CHARRA_RC_SUCCESS, CHARRA_RC_BAD_ARGUMENT on bad arguments,
 * CHARRA_RC_ERROR on allocation failure, CHARRA_RC_CRYPTO_ERROR if hashing
 * fails
 */
CHARRA_RC charra_rp_qualification_generate(uint32_t num_entries,
        uint32_t seed, const uint8_t salt[CHARRA_SDK_PATH_SALT_LEN],
        rp_qualification_state* state_out, uint8_t** challenge_log_out,
        uint32_t* challenge_log_len_out);

/**
 * @brief Check an RP's qualification submission against the golden answer.
 *
 * Compares submitted_log against state->golden_log byte for byte, and
 * submitted_pcr_digest against state->golden_pcr. Both must match for the RP
 * to qualify. Per the design, only pcrDigest/extraData from Quote_R ever
 * enter this comparison -- never raw signature bytes, since RSA-PSS salting
 * makes two honest signings over identical data differ anyway. Verifying
 * Quote_R's signature itself is a separate, not-yet-built step; the caller
 * is expected to have done that before calling this function.
 *
 * On match, sets state->qualified = true and state->expires_at = now +
 * CHARRA_RP_QUALIFICATION_VALIDITY_SECONDS. On mismatch, sets
 * state->qualified = false and state->expires_at = 0.
 *
 * @param[in,out] state golden answer to check against; updated in place
 * @param[in] submitted_log the RP's redacted log; may be NULL only if
 * submitted_log_len is 0
 * @param[in] submitted_log_len length of submitted_log
 * @param[in] submitted_pcr_digest pcrDigest extracted from the RP's Quote_R
 * @param[in] now current time, used to set state->expires_at
 * @returns CHARRA_RC_SUCCESS if the RP qualified, CHARRA_RC_VERIFICATION_FAILED
 * if it did not, CHARRA_RC_BAD_ARGUMENT on bad arguments
 */
CHARRA_RC charra_rp_qualification_check(rp_qualification_state* state,
        const uint8_t* submitted_log, uint32_t submitted_log_len,
        const uint8_t submitted_pcr_digest[TPM2_SHA256_DIGEST_SIZE],
        time_t now);

/**
 * @brief Is state's qualified/expires_at pair (as of the last charra_rp_
 * qualification_check() call against it) still within its validity window?
 *
 * NOT what coap_appraise_handler() actually gates on -- state only ever
 * describes one Verifier process's single in-flight challenge round, with
 * no notion of which RP it was for (see rp_qualification_state's own
 * docstring). The real, identity-bound, persisted-across-restarts gate is
 * charra_qualification_state_is_valid() (charra_qualification_state.h),
 * looked up by the RP's ek_fingerprint. This function is kept for what it
 * actually is: a plain validity check on one state struct, exercised
 * directly by tests.
 *
 * @param[in] state state to check
 * @param[in] now current time
 * @returns true iff state->qualified and state->expires_at is still in the
 * future
 */
bool charra_rp_qualification_is_valid(
        const rp_qualification_state* state, time_t now);

/**
 * @brief Free state->golden_log and reset *state to an empty, unqualified
 * state. Safe to call on an already-freed or zero-initialized state.
 */
void charra_rp_qualification_state_free(rp_qualification_state* state);

#endif /* CHARRA_RP_QUALIFICATION_H */
