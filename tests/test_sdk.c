/**
 * @file test_sdk.c
 * @brief Standalone tests for the Verifier's redaction SDK.
 *
 * Builds on charra_synth_generate_ima_log() -- exactly how these two modules
 * are meant to be used together in the qualification check: generate a
 * synthetic log, then redact it, exactly as the RP would.
 *
 * Build and run:  make test_sdk && ./bin/test_sdk
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../src/core/charra_event_log.h"
#include "../src/core/charra_sdk.h"
#include "../src/core/charra_synthetic_log.h"

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

static void test_redacted_log_is_valid_replay_input(void) {
    printf("\nredacted log is valid input to charra_replay_ima_log()\n");

    uint8_t* raw_log = NULL;
    uint32_t raw_log_len = 0;
    charra_synth_generate_ima_log(5, 42, &raw_log, &raw_log_len);

    uint8_t* redacted = NULL;
    uint32_t redacted_len = 0;
    CHARRA_RC rc = charra_sdk_redact_ima_log(
            raw_log, raw_log_len, &redacted, &redacted_len);
    check("redaction succeeds", rc == CHARRA_RC_SUCCESS);
    check("redacted log is non-empty", redacted != NULL && redacted_len > 0);

    uint8_t pcr[TPM2_SHA256_DIGEST_SIZE] = {0};
    CHARRA_RC replay_rc = charra_replay_ima_log(
            redacted, redacted_len, CHARRA_IMA_PCR_INDEX, pcr);
    check("redacted log replays successfully",
            replay_rc == CHARRA_RC_SUCCESS);

    free(raw_log);
    free(redacted);
}

static void test_redacted_pcr_differs_from_raw(void) {
    printf("\nredacting changes the replayed PCR (digest was recomputed)\n");

    uint8_t* raw_log = NULL;
    uint32_t raw_log_len = 0;
    charra_synth_generate_ima_log(4, 7, &raw_log, &raw_log_len);

    uint8_t* redacted = NULL;
    uint32_t redacted_len = 0;
    charra_sdk_redact_ima_log(raw_log, raw_log_len, &redacted, &redacted_len);

    uint8_t pcr_raw[TPM2_SHA256_DIGEST_SIZE] = {0};
    uint8_t pcr_redacted[TPM2_SHA256_DIGEST_SIZE] = {0};
    charra_replay_ima_log(raw_log, raw_log_len, CHARRA_IMA_PCR_INDEX, pcr_raw);
    charra_replay_ima_log(
            redacted, redacted_len, CHARRA_IMA_PCR_INDEX, pcr_redacted);

    /* Unlike path-only redaction (which preserves template_digest and thus
     * the replayed PCR), THIS design recomputes template_digest from the
     * redacted content -- so the PCR is expected, deliberately, to change.
     * See "Consequences of recomputing template_digest" in the notes. */
    check("raw and redacted logs replay to DIFFERENT PCR values",
            memcmp(pcr_raw, pcr_redacted, sizeof(pcr_raw)) != 0);

    free(raw_log);
    free(redacted);
}

static void test_deterministic(void) {
    printf("\nredacting the same log twice gives identical output\n");

    uint8_t* raw_log = NULL;
    uint32_t raw_log_len = 0;
    charra_synth_generate_ima_log(6, 123, &raw_log, &raw_log_len);

    uint8_t *redacted_a = NULL, *redacted_b = NULL;
    uint32_t len_a = 0, len_b = 0;
    charra_sdk_redact_ima_log(raw_log, raw_log_len, &redacted_a, &len_a);
    charra_sdk_redact_ima_log(raw_log, raw_log_len, &redacted_b, &len_b);

    check("lengths match", len_a == len_b);
    check("bytes match exactly",
            len_a == len_b && memcmp(redacted_a, redacted_b, len_a) == 0);

    free(raw_log);
    free(redacted_a);
    free(redacted_b);
}

static void test_different_entries_redact_differently(void) {
    printf("\ndifferent original paths produce different redacted digests\n");
    printf("(i.e. redaction does not collapse every entry to one constant)\n");

    /* charra_synth_generate_ima_log cycles through several different fake
     * paths, so a handful of entries should not all redact to the same
     * template_digest. */
    uint8_t* raw_log = NULL;
    uint32_t raw_log_len = 0;
    charra_synth_generate_ima_log(4, 99, &raw_log, &raw_log_len);

    uint8_t* redacted = NULL;
    uint32_t redacted_len = 0;
    charra_sdk_redact_ima_log(raw_log, raw_log_len, &redacted, &redacted_len);

    /* Walk the redacted log and collect each entry's template_digest. */
    uint16_t digest_len = 0;
    charra_event_log_ima_detect_digest_len(redacted, redacted_len, &digest_len);

    uint8_t digests[4][TPM2_SHA256_DIGEST_SIZE];
    uint32_t num_entries = 0;
    uint32_t offset = 0;
    while (offset < redacted_len && num_entries < 4) {
        charra_event_log_entry entry = {0};
        CHARRA_RC rc = charra_event_log_parse_entry(
                redacted, redacted_len, &offset, digest_len, &entry);
        if (rc != CHARRA_RC_SUCCESS) {
            break;
        }
        memcpy(digests[num_entries], entry.template_digest, digest_len);
        num_entries++;
    }
    check("collected 4 entries from the redacted log", num_entries == 4);

    bool all_same = true;
    for (uint32_t i = 1; i < num_entries; ++i) {
        if (memcmp(digests[0], digests[i], TPM2_SHA256_DIGEST_SIZE) != 0) {
            all_same = false;
            break;
        }
    }
    check("entries do NOT all share the same redacted digest", !all_same);

    free(raw_log);
    free(redacted);
}

static void test_empty_log(void) {
    printf("\nempty log redacts to an empty log\n");

    uint8_t* redacted = NULL;
    uint32_t redacted_len = 999;
    CHARRA_RC rc = charra_sdk_redact_ima_log(NULL, 0, &redacted, &redacted_len);

    check("succeeds", rc == CHARRA_RC_SUCCESS);
    check("output is NULL", redacted == NULL);
    check("output length is 0", redacted_len == 0);
}

static void test_bad_arguments(void) {
    printf("\nbad arguments\n");

    uint8_t* out = NULL;
    uint32_t out_len = 0;
    uint8_t dummy[4] = {0};

    check("NULL redacted_log_out rejected",
            charra_sdk_redact_ima_log(dummy, sizeof(dummy), NULL, &out_len) ==
                    CHARRA_RC_BAD_ARGUMENT);
    check("NULL redacted_log_len_out rejected",
            charra_sdk_redact_ima_log(dummy, sizeof(dummy), &out, NULL) ==
                    CHARRA_RC_BAD_ARGUMENT);
    check("NULL raw_log with non-zero length rejected",
            charra_sdk_redact_ima_log(NULL, 10, &out, &out_len) ==
                    CHARRA_RC_BAD_ARGUMENT);
}

static void test_malformed_log_rejected(void) {
    printf("\nmalformed input is rejected, not silently redacted\n");

    uint8_t garbage[] = {0x01, 0x02, 0x03};
    uint8_t* out = NULL;
    uint32_t out_len = 0;
    CHARRA_RC rc = charra_sdk_redact_ima_log(
            garbage, sizeof(garbage), &out, &out_len);
    check("truncated/garbage log rejected", rc != CHARRA_RC_SUCCESS);
}

int main(void) {
    printf("Verifier redaction SDK tests\n");
    printf("=============================\n");

    test_redacted_log_is_valid_replay_input();
    test_redacted_pcr_differs_from_raw();
    test_deterministic();
    test_different_entries_redact_differently();
    test_empty_log();
    test_bad_arguments();
    test_malformed_log_rejected();

    printf("\n=============================\n");
    printf("%u tests, %u failed\n", tests_run, tests_failed);

    return (tests_failed == 0) ? 0 : 1;
}
