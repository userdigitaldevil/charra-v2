/**
 * @file charra_rp_qualification.c
 * @brief Verifier-side RP qualification handshake. See
 * charra_rp_qualification.h.
 */

#include "charra_rp_qualification.h"

#include <stdlib.h>
#include <string.h>

#include "charra_event_log.h"
#include "charra_sdk.h"
#include "charra_synthetic_log.h"

/* Runtime-settable qualification window -- see the setter's docstring in
 * charra_rp_qualification.h for why this is not just the macro. */
static time_t qualification_validity_seconds =
        CHARRA_RP_QUALIFICATION_VALIDITY_SECONDS;

void charra_rp_qualification_set_validity_seconds(time_t seconds) {
    if (seconds > 0) {
        qualification_validity_seconds = seconds;
    }
}

time_t charra_rp_qualification_get_validity_seconds(void) {
    return qualification_validity_seconds;
}

CHARRA_RC charra_rp_qualification_generate(uint32_t num_entries,
        uint32_t seed, const uint8_t salt[CHARRA_SDK_PATH_SALT_LEN],
        rp_qualification_state* state_out, uint8_t** challenge_log_out,
        uint32_t* challenge_log_len_out) {
    if (salt == NULL || state_out == NULL || challenge_log_out == NULL ||
            challenge_log_len_out == NULL) {
        return CHARRA_RC_BAD_ARGUMENT;
    }

    uint8_t* raw_log = NULL;
    uint32_t raw_log_len = 0;
    CHARRA_RC rc = charra_synth_generate_ima_log(
            num_entries, seed, &raw_log, &raw_log_len);
    if (rc != CHARRA_RC_SUCCESS) {
        return rc;
    }

    memset(state_out, 0, sizeof(*state_out));
    rc = charra_sdk_redact_ima_log(raw_log, raw_log_len, salt,
            &state_out->golden_log, &state_out->golden_log_len);
    if (rc != CHARRA_RC_SUCCESS) {
        free(raw_log);
        return rc;
    }

    rc = charra_replay_ima_log(state_out->golden_log,
            state_out->golden_log_len, CHARRA_IMA_PCR_INDEX,
            state_out->golden_pcr);
    if (rc != CHARRA_RC_SUCCESS) {
        free(raw_log);
        charra_rp_qualification_state_free(state_out);
        return rc;
    }

    *challenge_log_out = raw_log;
    *challenge_log_len_out = raw_log_len;
    return CHARRA_RC_SUCCESS;
}

CHARRA_RC charra_rp_qualification_check(rp_qualification_state* state,
        const uint8_t* submitted_log, uint32_t submitted_log_len,
        const uint8_t submitted_pcr_digest[TPM2_SHA256_DIGEST_SIZE],
        time_t now) {
    if (state == NULL || submitted_pcr_digest == NULL ||
            (submitted_log == NULL && submitted_log_len != 0)) {
        return CHARRA_RC_BAD_ARGUMENT;
    }

    bool log_matches = submitted_log_len == state->golden_log_len &&
            (submitted_log_len == 0 ||
                    memcmp(submitted_log, state->golden_log,
                            submitted_log_len) == 0);
    bool pcr_matches = memcmp(submitted_pcr_digest, state->golden_pcr,
                                TPM2_SHA256_DIGEST_SIZE) == 0;

    if (log_matches && pcr_matches) {
        state->qualified = true;
        state->expires_at =
                now + charra_rp_qualification_get_validity_seconds();
        return CHARRA_RC_SUCCESS;
    }

    state->qualified = false;
    state->expires_at = 0;
    return CHARRA_RC_VERIFICATION_FAILED;
}

bool charra_rp_qualification_is_valid(
        const rp_qualification_state* state, time_t now) {
    return state != NULL && state->qualified && now < state->expires_at;
}

void charra_rp_qualification_state_free(rp_qualification_state* state) {
    if (state == NULL) {
        return;
    }
    free(state->golden_log);
    memset(state, 0, sizeof(*state));
}
