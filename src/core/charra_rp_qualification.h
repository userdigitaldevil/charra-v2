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
 * it. Carrying the challenge over the wire, authenticating the submitter
 * and recording the resulting grant are verifier_qualify.c's job.
 */

#ifndef CHARRA_RP_QUALIFICATION_H
#define CHARRA_RP_QUALIFICATION_H

#include <inttypes.h>
#include <stdbool.h>
#include <time.h>

#include <tss2/tss2_tpm2_types.h>

#include "../common/charra_error.h"
#include "charra_sdk.h"

/** Default lifetime of the GRANT a passing /qualify leads to; override at
 * runtime with charra_rp_qualification_set_validity_seconds().
 *
 * The one thing here with a lifetime. Identity has none -- a key is
 * trusted while it appears in the trust anchor -- but behaviour goes
 * stale: an RP can swap its redaction pipeline the moment after passing.
 * The resulting deadline is stamped into qualified_rps.txt; a lapsed
 * record counts as not qualified. */
#define CHARRA_RP_QUALIFICATION_VALIDITY_SECONDS (3 * 60)

/**
 * @brief Set/get the qualification validity window actually in force.
 *
 * Runtime rather than the macro alone so --qualification-validity can
 * reach charra_rp_qualification_check(), which stamps state->expires_at.
 *
 * Only the VERIFIER has this flag. The deadline is computed once, here,
 * then recorded in qualified_rps.txt for every sibling to honour verbatim
 * AND returned to the RP in the /qualify_submit response. One authority,
 * one number, nothing to keep in sync -- which matters because /appraise
 * never says WHY it voted no, so an RP guessing the window could never
 * learn it had guessed short.
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
 * *state_out (golden_log), and separately returns the raw (unredacted) log
 * for the caller to send to the RP -- the RP is expected to redact it
 * (with the same salt, also sent to it) and submit the result back for
 * charra_rp_qualification_check().
 *
 * No PCR is involved anywhere in this handshake. The question it answers
 * is "does this RP's redaction pipeline produce the same bytes mine
 * does", and a byte-for-byte log comparison answers it completely -- two
 * identical logs replay to the same PCR by construction, so a PCR check
 * would be restating the log check.
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
 * Compares submitted_log against state->golden_log byte for byte. That is
 * the whole test: the RP redacted the same challenge with the same salt,
 * so a correct pipeline reproduces the golden log exactly.
 *
 * Authenticating WHO submitted it is a separate step the caller does
 * first -- the grant is recorded against a key fingerprint, so an
 * unsigned submission could win a grant in someone else's name. See
 * coap_qualify_submit_handler().
 *
 * On match, sets state->qualified = true and state->expires_at = now +
 * the window in force (see charra_rp_qualification_get_validity_seconds())
 * -- the deadline the caller then records and returns. On mismatch, sets
 * state->qualified = false and state->expires_at = 0.
 *
 * A state with no challenge outstanding (golden_log NULL/empty) is rejected
 * outright: its all-zero golden answer would otherwise be matched by an
 * empty submission. Callers should consume the state after
 * this returns, so one challenge answers exactly one submission.
 *
 * @param[in,out] state golden answer to check against; updated in place
 * @param[in] submitted_log the RP's redacted log; may be NULL only if
 * submitted_log_len is 0
 * @param[in] submitted_log_len length of submitted_log
 * @param[in] now current time, used to set state->expires_at
 * @returns CHARRA_RC_SUCCESS if the RP qualified, CHARRA_RC_VERIFICATION_FAILED
 * if it did not, CHARRA_RC_BAD_ARGUMENT on bad arguments
 */
CHARRA_RC charra_rp_qualification_check(rp_qualification_state* state,
        const uint8_t* submitted_log, uint32_t submitted_log_len,
        time_t now);

/**
 * @brief Is state's qualified/expires_at pair (as of the last charra_rp_
 * qualification_check() call against it) still within its validity window?
 *
 * NOT what coap_appraise_handler() actually gates on -- state only ever
 * describes one Verifier process's single in-flight challenge round, with
 * no notion of which RP it was for (see rp_qualification_state's own
 * docstring). The real, identity-bound gate is
 * verifier_qualified_rps_is_qualified() (verifier_qualified_rps.h),
 * looked up by the SHA-256 of AK_r's public key. This function is kept for
 * what it actually is: a plain validity check on one state struct,
 * exercised directly by tests.
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
