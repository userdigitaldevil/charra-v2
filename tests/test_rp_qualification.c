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
#include "../src/util/crypto_util.h"
#include "../src/core/charra_sdk.h"

static unsigned int tests_run = 0;
static unsigned int tests_failed = 0;

/* Stand-in for what coap_qualify_handler() generates fresh per challenge
 * and sends alongside the log in msg_qualify_response_dto -- these tests
 * play both Verifier and RP in-process, so one fixed salt is enough to
 * exercise the shared-salt handshake. */
static const uint8_t test_salt[CHARRA_SDK_PATH_SALT_LEN] = {
        0x24, 0x68, 0xac, 0xf0, 0x13, 0x57, 0x9b, 0xdf, 0x02, 0x46, 0x8a, 0xce,
        0x11, 0x55, 0x99, 0xdd, 0x21, 0x65, 0xa9, 0xed, 0x30, 0x74, 0xb8, 0xfc,
        0x41, 0x85, 0xc9, 0x0d, 0x50, 0x94, 0xd8, 0x1c};

static void check(const char* name, bool condition) {
    tests_run++;
    if (condition) {
        printf("  PASS  %s\n", name);
    } else {
        tests_failed++;
        printf("  FAIL  %s\n", name);
    }
}

/**
 * @brief Redact + replay a log the way an honest RP would, to get its
 * pcrDigest -- using the same salt the Verifier sent alongside the
 * challenge (test_salt here), the same way rp_perform_qualification_
 * handshake() uses qualify_challenge_salt in relying_party.c.
 */
static void honest_rp_respond(const uint8_t* challenge_log,
        uint32_t challenge_log_len, uint8_t** rp_log_out,
        uint32_t* rp_log_len_out, uint8_t rp_pcr_out[TPM2_SHA256_DIGEST_SIZE]) {
    charra_sdk_redact_ima_log(challenge_log, challenge_log_len, test_salt,
            rp_log_out, rp_log_len_out);
    charra_replay_ima_log(*rp_log_out, *rp_log_len_out, CHARRA_IMA_PCR_INDEX,
            rp_pcr_out);
}

static void test_generate_produces_golden_state_and_challenge(void) {
    printf("\ngenerate() produces a challenge log and an unqualified golden state\n");

    rp_qualification_state state = {0};
    uint8_t* challenge_log = NULL;
    uint32_t challenge_log_len = 0;
    CHARRA_RC rc = charra_rp_qualification_generate(
            5, 42, test_salt, &state, &challenge_log, &challenge_log_len);

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
            6, 7, test_salt, &state, &challenge_log, &challenge_log_len);

    uint8_t* rp_log = NULL;
    uint32_t rp_log_len = 0;
    uint8_t rp_pcr[TPM2_SHA256_DIGEST_SIZE] = {0};
    honest_rp_respond(
            challenge_log, challenge_log_len, &rp_log, &rp_log_len, rp_pcr);

    time_t now = 1000;
    CHARRA_RC rc = charra_rp_qualification_check(
            &state, rp_log, rp_log_len, now);

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
            4, 99, test_salt, &state, &challenge_log, &challenge_log_len);

    /* Dishonest/broken RP: submits the untouched challenge log instead of
     * redacting it -- still hashes to some PCR, just not the golden one. */
    uint8_t rp_pcr[TPM2_SHA256_DIGEST_SIZE] = {0};
    charra_replay_ima_log(challenge_log, challenge_log_len,
            CHARRA_IMA_PCR_INDEX, rp_pcr);

    CHARRA_RC rc = charra_rp_qualification_check(
            &state, challenge_log, challenge_log_len, 1000);

    check("check fails", rc == CHARRA_RC_VERIFICATION_FAILED);
    check("state stays unqualified", !state.qualified);
    check("expiry stays cleared", state.expires_at == 0);

    free(challenge_log);
    charra_rp_qualification_state_free(&state);
}

/* The comparison is byte-for-byte, so a single flipped bit anywhere in an
 * otherwise-perfect redaction must fail. Worth pinning explicitly: a
 * length-only or prefix-only comparison would pass this. */
static void test_one_byte_off_rejected(void) {
    printf("\na redaction that differs by ONE byte is rejected\n");

    rp_qualification_state state = {0};
    uint8_t* challenge_log = NULL;
    uint32_t challenge_log_len = 0;
    charra_rp_qualification_generate(
            4, 5, test_salt, &state, &challenge_log, &challenge_log_len);

    uint8_t* rp_log = NULL;
    uint32_t rp_log_len = 0;
    uint8_t rp_pcr[TPM2_SHA256_DIGEST_SIZE] = {0};
    honest_rp_respond(
            challenge_log, challenge_log_len, &rp_log, &rp_log_len, rp_pcr);

    check("sanity: the honest redaction passes",
            charra_rp_qualification_check(&state, rp_log, rp_log_len, 1000) ==
                    CHARRA_RC_SUCCESS);

    /* Same length, one byte different, in the middle. */
    rp_log[rp_log_len / 2] ^= 0x01;
    CHARRA_RC rc =
            charra_rp_qualification_check(&state, rp_log, rp_log_len, 1000);

    check("check fails", rc == CHARRA_RC_VERIFICATION_FAILED);
    check("state stays unqualified", !state.qualified);
    check("expiry stays cleared", state.expires_at == 0);

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
            3, 1, test_salt, &state, &challenge_log, &challenge_log_len);

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
            3, 2, test_salt, &state, &challenge_log, &challenge_log_len);

    charra_rp_qualification_state_free(&state);
    check("golden_log cleared", state.golden_log == NULL);
    check("golden_log_len cleared", state.golden_log_len == 0);

    charra_rp_qualification_state_free(&state);
    check("second free does not crash (reached this line)", true);

    free(challenge_log);
}

static void test_no_outstanding_challenge_rejects_empty_submission(void) {
    printf("\nno outstanding challenge rejects an empty submission "
           "(regression: V-1)\n");

    /* A zeroed state -- a Verifier that never served /qualify, or one whose
     * challenge was already consumed -- has golden_log_len 0, which an
     * empty submission would match by accident, qualifying a caller that
     * never ran the SDK. */
    rp_qualification_state state = {0};

    check("empty submission against a zeroed state is REJECTED",
            charra_rp_qualification_check(&state, NULL, 0, time(NULL)) !=
                    CHARRA_RC_SUCCESS);
    check("state is not left marked qualified", !state.qualified);

    /* Same, for a state consumed after a real challenge. */
    uint8_t* challenge_log = NULL;
    uint32_t challenge_log_len = 0;
    charra_rp_qualification_generate(
            4, 77, test_salt, &state, &challenge_log, &challenge_log_len);
    charra_rp_qualification_state_free(&state);

    check("empty log + zero digest against a CONSUMED state is REJECTED",
            charra_rp_qualification_check(&state, NULL, 0, time(NULL)) !=
                    CHARRA_RC_SUCCESS);

    free(challenge_log);
}

static void test_bad_arguments(void) {
    printf("\nbad arguments\n");

    rp_qualification_state state = {0};
    uint8_t* log = NULL;
    uint32_t log_len = 0;

    check("generate: NULL salt rejected",
            charra_rp_qualification_generate(
                    1, 1, NULL, &state, &log, &log_len) ==
                    CHARRA_RC_BAD_ARGUMENT);
    check("generate: NULL state_out rejected",
            charra_rp_qualification_generate(
                    1, 1, test_salt, NULL, &log, &log_len) ==
                    CHARRA_RC_BAD_ARGUMENT);
    check("generate: NULL challenge_log_out rejected",
            charra_rp_qualification_generate(1, 1, test_salt, &state, NULL,
                    &log_len) == CHARRA_RC_BAD_ARGUMENT);
    check("generate: NULL challenge_log_len_out rejected",
            charra_rp_qualification_generate(
                    1, 1, test_salt, &state, &log, NULL) ==
                    CHARRA_RC_BAD_ARGUMENT);

    check("check: NULL state rejected",
            charra_rp_qualification_check(NULL, log, log_len, 0) ==
                    CHARRA_RC_BAD_ARGUMENT);
    check("check: NULL log with non-zero length rejected",
            charra_rp_qualification_check(&state, NULL, 10, 0) ==
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
    test_one_byte_off_rejected();
    test_is_valid_false_before_any_check();
    test_state_free_is_idempotent();
    test_no_outstanding_challenge_rejects_empty_submission();
    test_bad_arguments();

    printf("\n=================================\n");
    printf("%u tests, %u failed\n", tests_run, tests_failed);

    return (tests_failed == 0) ? 0 : 1;
}
