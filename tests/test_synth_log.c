/**
 * @file test_synth_log.c
 * @brief Standalone tests for synthetic IMA log generation.
 *
 * The strongest check available: the generator's own output is fed straight
 * into charra_replay_ima_log(), the already-proven replay function. If the
 * generator produces well-formed entries, replay must succeed.
 *
 * Build and run:  make test_synth_log && ./bin/test_synth_log
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../src/core/charra_event_log.h"
#include "../src/core/charra_synth_log.h"

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

static void test_generates_valid_replayable_log(void) {
    printf("\ngenerated log is valid input to charra_replay_ima_log()\n");

    uint8_t* log = NULL;
    uint32_t log_len = 0;
    CHARRA_RC rc = charra_synth_generate_ima_log(5, 42, &log, &log_len);
    check("generation succeeds", rc == CHARRA_RC_SUCCESS);
    check("log is non-empty", log != NULL && log_len > 0);

    uint8_t pcr[TPM2_SHA256_DIGEST_SIZE] = {0};
    CHARRA_RC replay_rc =
            charra_replay_ima_log(log, log_len, CHARRA_IMA_PCR_INDEX, pcr);
    check("generated log replays successfully",
            replay_rc == CHARRA_RC_SUCCESS);

    uint8_t zero[TPM2_SHA256_DIGEST_SIZE] = {0};
    check("replayed PCR is non-trivial (not all-zero)",
            memcmp(pcr, zero, sizeof(zero)) != 0);

    free(log);
}

static void test_deterministic_same_seed(void) {
    printf("\nsame (num_entries, seed) produces identical output\n");

    uint8_t *log_a = NULL, *log_b = NULL;
    uint32_t len_a = 0, len_b = 0;
    charra_synth_generate_ima_log(7, 1234, &log_a, &len_a);
    charra_synth_generate_ima_log(7, 1234, &log_b, &len_b);

    check("lengths match", len_a == len_b);
    check("bytes match exactly",
            len_a == len_b && memcmp(log_a, log_b, len_a) == 0);

    free(log_a);
    free(log_b);
}

static void test_different_seed_differs(void) {
    printf("\ndifferent seed produces different content\n");

    uint8_t *log_a = NULL, *log_b = NULL;
    uint32_t len_a = 0, len_b = 0;
    charra_synth_generate_ima_log(5, 1, &log_a, &len_a);
    charra_synth_generate_ima_log(5, 2, &log_b, &len_b);

    bool differs = (len_a != len_b) ||
                    (memcmp(log_a, log_b, len_a) != 0);
    check("output differs across seeds", differs);

    free(log_a);
    free(log_b);
}

static void test_entry_count_scales(void) {
    printf("\nmore entries produce a larger, still-valid log\n");

    uint8_t *log_1 = NULL, *log_10 = NULL;
    uint32_t len_1 = 0, len_10 = 0;
    charra_synth_generate_ima_log(1, 99, &log_1, &len_1);
    charra_synth_generate_ima_log(10, 99, &log_10, &len_10);

    check("10 entries produce a longer log than 1 entry", len_10 > len_1);

    uint8_t pcr[TPM2_SHA256_DIGEST_SIZE] = {0};
    CHARRA_RC rc =
            charra_replay_ima_log(log_10, len_10, CHARRA_IMA_PCR_INDEX, pcr);
    check("10-entry log replays successfully", rc == CHARRA_RC_SUCCESS);

    free(log_1);
    free(log_10);
}

static void test_content_contains_fake_paths(void) {
    printf("\ngenerated log actually contains sensitive-looking content\n");

    uint8_t* log = NULL;
    uint32_t log_len = 0;
    charra_synth_generate_ima_log(3, 7, &log, &log_len);

    /* one of the known fake paths must appear somewhere in the raw bytes --
     * confirms there is something for a redaction routine to find and strip
     */
    const char* needle = "/etc/company/api_keys.conf";
    size_t needle_len = strlen(needle);
    bool found = false;
    for (uint32_t i = 0; i + needle_len <= log_len; ++i) {
        if (memcmp(log + i, needle, needle_len) == 0) {
            found = true;
            break;
        }
    }
    check("a known fake sensitive path appears in the raw log", found);

    free(log);
}

static void test_bad_arguments(void) {
    printf("\nbad arguments\n");

    uint8_t* log = NULL;
    uint32_t log_len = 0;
    check("zero entries rejected",
            charra_synth_generate_ima_log(0, 1, &log, &log_len) ==
                    CHARRA_RC_BAD_ARGUMENT);
    check("NULL log_out rejected",
            charra_synth_generate_ima_log(1, 1, NULL, &log_len) ==
                    CHARRA_RC_BAD_ARGUMENT);
    check("NULL log_len_out rejected",
            charra_synth_generate_ima_log(1, 1, &log, NULL) ==
                    CHARRA_RC_BAD_ARGUMENT);
}

int main(void) {
    printf("Synthetic IMA log generation tests\n");
    printf("===================================\n");

    test_generates_valid_replayable_log();
    test_deterministic_same_seed();
    test_different_seed_differs();
    test_entry_count_scales();
    test_content_contains_fake_paths();
    test_bad_arguments();

    printf("\n===================================\n");
    printf("%u tests, %u failed\n", tests_run, tests_failed);

    return (tests_failed == 0) ? 0 : 1;
}
