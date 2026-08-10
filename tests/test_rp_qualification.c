/**
 * @file test_rp_qualification.c
 * @brief Standalone tests for the Verifier's RP qualification handshake.
 *
 * Simulates both sides in-process: an "honest RP" runs the same
 * charra_sdk_redact_ima_log() the Verifier expects, a "dishonest RP" does
 * not, and both submissions are checked against the golden answer
 * charra_rp_qualification_generate() computed.
 *
 * Build and run:  make test_rp_qualification && ./bin/test_rp_qualification
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../src/core/charra_event_log.h"
#include "../src/core/charra_rp_qualification.h"
#include "../src/core/charra_sdk.h"

static unsigned int tests_run = 0;
static unsigned int tests_failed = 0;

static void check(const char* name, bool condition) {
    tests_run++;
    if (condition) {
        printf("  PASS  %s\n", name);
    } else {
        tests_failed++;
        printf("  FAIL  %s\n", name);
    }
}

/** Redact + replay a log the way an honest RP would, to get its pcrDigest. */
static void honest_rp_respond(const uint8_t* challenge_log,
        uint32_t challenge_log_len, uint8_t** rp_log_out,
        uint32_t* rp_log_len_out, uint8_t rp_pcr_out[TPM2_SHA256_DIGEST_SIZE]) {
    charra_sdk_redact_ima_log(
            challenge_log, challenge_log_len, rp_log_out, rp_log_len_out);
    charra_replay_ima_log(*rp_log_out, *rp_log_len_out, CHARRA_IMA_PCR_INDEX,
            rp_pcr_out);
}

static void test_generate_produces_golden_state_and_challenge(void) {
    printf("\ngenerate() produces a challenge log and an unqualified golden state\n");

    rp_qualification_state state = {0};
    uint8_t* challenge_log = NULL;
    uint32_t challenge_log_len = 0;
    CHARRA_RC rc = charra_rp_qualification_generate(
            5, 42, &state, &challenge_log, &challenge_log_len);

    check("generation succeeds", rc == CHARRA_RC_SUCCESS);
    check("challenge log is non-empty",
            challenge_log != NULL && challenge_log_len > 0);
    check("golden log is non-empty",
            state.golden_log != NULL && state.golden_log_len > 0);
    check("starts unqualified", !state.qualified);
    check("starts with no expiry", state.expires_at == 0);

    free(challenge_log);
    charra_rp_qualification_state_free(&state);
}

static void test_honest_rp_qualifies(void) {
    printf("\nan RP that redacts correctly qualifies\n");

    rp_qualification_state state = {0};
    uint8_t* challenge_log = NULL;
    uint32_t challenge_log_len = 0;
    charra_rp_qualification_generate(
            6, 7, &state, &challenge_log, &challenge_log_len);

    uint8_t* rp_log = NULL;
    uint32_t rp_log_len = 0;
    uint8_t rp_pcr[TPM2_SHA256_DIGEST_SIZE] = {0};
    honest_rp_respond(
            challenge_log, challenge_log_len, &rp_log, &rp_log_len, rp_pcr);

    time_t now = 1000;
    CHARRA_RC rc = charra_rp_qualification_check(
            &state, rp_log, rp_log_len, rp_pcr, now);

    check("check succeeds", rc == CHARRA_RC_SUCCESS);
    check("state is qualified", state.qualified);
    check("expiry is in the future",
            state.expires_at ==
                    now + CHARRA_RP_QUALIFICATION_VALIDITY_SECONDS);
    check("currently valid", charra_rp_qualification_is_valid(&state, now));
    check("no longer valid after expiry",
            !charra_rp_qualification_is_valid(&state,
                    now + CHARRA_RP_QUALIFICATION_VALIDITY_SECONDS + 1));

    free(challenge_log);
    free(rp_log);
    charra_rp_qualification_state_free(&state);
}

static void test_rp_submitting_unredacted_log_rejected(void) {
    printf("\nan RP that submits the raw (unredacted) log fails\n");

    rp_qualification_state state = {0};
    uint8_t* challenge_log = NULL;
    uint32_t challenge_log_len = 0;
    charra_rp_qualification_generate(
            4, 99, &state, &challenge_log, &challenge_log_len);

    /* Dishonest/broken RP: submits the untouched challenge log instead of
     * redacting it -- still hashes to some PCR, just not the golden one. */
    uint8_t rp_pcr[TPM2_SHA256_DIGEST_SIZE] = {0};
    charra_replay_ima_log(challenge_log, challenge_log_len,
            CHARRA_IMA_PCR_INDEX, rp_pcr);

    CHARRA_RC rc = charra_rp_qualification_check(
            &state, challenge_log, challenge_log_len, rp_pcr, 1000);

    check("check fails", rc == CHARRA_RC_VERIFICATION_FAILED);
    check("state stays unqualified", !state.qualified);
    check("expiry stays cleared", state.expires_at == 0);

    free(challenge_log);
    charra_rp_qualification_state_free(&state);
}

static void test_correct_log_but_wrong_pcr_rejected(void) {
    printf("\ncorrect log with a mismatched pcrDigest still fails\n");
    printf("(log and PCR are checked independently, not one implying the other)\n");

    rp_qualification_state state = {0};
    uint8_t* challenge_log = NULL;
    uint32_t challenge_log_len = 0;
    charra_rp_qualification_generate(
            4, 5, &state, &challenge_log, &challenge_log_len);

    uint8_t* rp_log = NULL;
    uint32_t rp_log_len = 0;
    uint8_t rp_pcr[TPM2_SHA256_DIGEST_SIZE] = {0};
    honest_rp_respond(
            challenge_log, challenge_log_len, &rp_log, &rp_log_len, rp_pcr);

    uint8_t wrong_pcr[TPM2_SHA256_DIGEST_SIZE];
    memset(wrong_pcr, 0xAA, sizeof(wrong_pcr));

    CHARRA_RC rc = charra_rp_qualification_check(
            &state, rp_log, rp_log_len, wrong_pcr, 1000);

    check("check fails", rc == CHARRA_RC_VERIFICATION_FAILED);
    check("state stays unqualified", !state.qualified);

    free(challenge_log);
    free(rp_log);
    charra_rp_qualification_state_free(&state);
}

static void test_is_valid_false_before_any_check(void) {
    printf("\na freshly generated state is never valid\n");

    rp_qualification_state state = {0};
    uint8_t* challenge_log = NULL;
    uint32_t challenge_log_len = 0;
    charra_rp_qualification_generate(
            3, 1, &state, &challenge_log, &challenge_log_len);

    check("not valid at time 0", !charra_rp_qualification_is_valid(&state, 0));
    check("not valid at a later time",
            !charra_rp_qualification_is_valid(&state, 999999));

    free(challenge_log);
    charra_rp_qualification_state_free(&state);
}

static void test_state_free_is_idempotent(void) {
    printf("\nstate_free() is safe to call twice and on a zeroed state\n");

    rp_qualification_state state = {0};
    uint8_t* challenge_log = NULL;
    uint32_t challenge_log_len = 0;
    charra_rp_qualification_generate(
            3, 2, &state, &challenge_log, &challenge_log_len);

    charra_rp_qualification_state_free(&state);
    check("golden_log cleared", state.golden_log == NULL);
    check("golden_log_len cleared", state.golden_log_len == 0);

    charra_rp_qualification_state_free(&state);
    check("second free does not crash (reached this line)", true);

    free(challenge_log);
}

static void test_bad_arguments(void) {
    printf("\nbad arguments\n");

    rp_qualification_state state = {0};
    uint8_t* log = NULL;
    uint32_t log_len = 0;
    uint8_t pcr[TPM2_SHA256_DIGEST_SIZE] = {0};

    check("generate: NULL state_out rejected",
            charra_rp_qualification_generate(1, 1, NULL, &log, &log_len) ==
                    CHARRA_RC_BAD_ARGUMENT);
    check("generate: NULL challenge_log_out rejected",
            charra_rp_qualification_generate(
                    1, 1, &state, NULL, &log_len) == CHARRA_RC_BAD_ARGUMENT);
    check("generate: NULL challenge_log_len_out rejected",
            charra_rp_qualification_generate(1, 1, &state, &log, NULL) ==
                    CHARRA_RC_BAD_ARGUMENT);

    check("check: NULL state rejected",
            charra_rp_qualification_check(NULL, log, log_len, pcr, 0) ==
                    CHARRA_RC_BAD_ARGUMENT);
    check("check: NULL pcr digest rejected",
            charra_rp_qualification_check(&state, log, log_len, NULL, 0) ==
                    CHARRA_RC_BAD_ARGUMENT);
    check("check: NULL log with non-zero length rejected",
            charra_rp_qualification_check(&state, NULL, 10, pcr, 0) ==
                    CHARRA_RC_BAD_ARGUMENT);

    check("is_valid: NULL state is simply invalid",
            !charra_rp_qualification_is_valid(NULL, 0));
}

int main(void) {
    printf("RP qualification handshake tests\n");
    printf("=================================\n");

    test_generate_produces_golden_state_and_challenge();
    test_honest_rp_qualifies();
    test_rp_submitting_unredacted_log_rejected();
    test_correct_log_but_wrong_pcr_rejected();
    test_is_valid_false_before_any_check();
    test_state_free_is_idempotent();
    test_bad_arguments();

    printf("\n=================================\n");
    printf("%u tests, %u failed\n", tests_run, tests_failed);

    return (tests_failed == 0) ? 0 : 1;
}
