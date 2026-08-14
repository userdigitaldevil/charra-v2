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
            raw_log, raw_log_len, NULL, &redacted, &redacted_len);
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
    charra_sdk_redact_ima_log(
            raw_log, raw_log_len, NULL, &redacted, &redacted_len);

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

static void test_salted_nondeterministic(void) {
    printf("\nredacting the same log twice gives the same length but "
           "different bytes (fresh salt per call)\n");

    uint8_t* raw_log = NULL;
    uint32_t raw_log_len = 0;
    charra_synth_generate_ima_log(6, 123, &raw_log, &raw_log_len);

    uint8_t *redacted_a = NULL, *redacted_b = NULL;
    uint32_t len_a = 0, len_b = 0;
    charra_sdk_redact_ima_log(raw_log, raw_log_len, NULL, &redacted_a, &len_a);
    charra_sdk_redact_ima_log(raw_log, raw_log_len, NULL, &redacted_b, &len_b);

    /* with salt == NULL, a fresh salt is generated per call and never
     * transmitted, so two redactions of the identical input must land on
     * different path hashes -- this is what stops equal paths correlating
     * across separate redactions. */
    check("lengths match", len_a == len_b);
    check("bytes differ (salt is fresh per call, not reused)",
            len_a == len_b && memcmp(redacted_a, redacted_b, len_a) != 0);

    free(raw_log);
    free(redacted_a);
    free(redacted_b);
}

static void test_shared_salt_is_deterministic(void) {
    printf("\nredacting the same log twice with the same explicit salt "
           "gives identical bytes\n");

    uint8_t* raw_log = NULL;
    uint32_t raw_log_len = 0;
    charra_synth_generate_ima_log(6, 123, &raw_log, &raw_log_len);

    uint8_t salt[CHARRA_SDK_PATH_SALT_LEN];
    memset(salt, 0x42, sizeof(salt));

    uint8_t *redacted_a = NULL, *redacted_b = NULL;
    uint32_t len_a = 0, len_b = 0;
    charra_sdk_redact_ima_log(
            raw_log, raw_log_len, salt, &redacted_a, &len_a);
    charra_sdk_redact_ima_log(
            raw_log, raw_log_len, salt, &redacted_b, &len_b);

    /* this is the whole point of the salt parameter: the RP qualification
     * handshake needs the RP's redaction to byte-match the Verifier's own
     * golden-log redaction of the same challenge, which only works if both
     * use the same salt. */
    check("lengths match", len_a == len_b);
    check("bytes match (same salt given explicitly both times)",
            len_a == len_b && memcmp(redacted_a, redacted_b, len_a) == 0);

    uint8_t* redacted_random = NULL;
    uint32_t len_random = 0;
    charra_sdk_redact_ima_log(
            raw_log, raw_log_len, NULL, &redacted_random, &len_random);
    check("differs from a NULL-salt (random) redaction of the same log",
            len_random != len_a ||
                    memcmp(redacted_random, redacted_a, len_a) != 0);

    free(raw_log);
    free(redacted_a);
    free(redacted_b);
    free(redacted_random);
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
    charra_sdk_redact_ima_log(
            raw_log, raw_log_len, NULL, &redacted, &redacted_len);

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

static void test_file_digest_preserved_path_redacted(void) {
    printf("\nfile-content digest survives redaction unchanged; path does not\n");

    uint8_t* raw_log = NULL;
    uint32_t raw_log_len = 0;
    charra_synth_generate_ima_log(1, 42, &raw_log, &raw_log_len);

    uint8_t* redacted = NULL;
    uint32_t redacted_len = 0;
    charra_sdk_redact_ima_log(
            raw_log, raw_log_len, NULL, &redacted, &redacted_len);

    /* pull the file-content digest straight out of the RAW entry's
     * template_data: u32(d_len) + "sha256:" (7 bytes) + digest (32 bytes)
     * + u32(n_len) + path + NUL -- the real ima-ng two-field layout */
    uint16_t raw_digest_len = 0;
    charra_event_log_ima_detect_digest_len(
            raw_log, raw_log_len, &raw_digest_len);
    uint32_t raw_offset = 0;
    charra_event_log_entry raw_entry = {0};
    charra_event_log_parse_entry(
            raw_log, raw_log_len, &raw_offset, raw_digest_len, &raw_entry);
    const char* prefix = "sha256:";
    uint32_t prefix_len = (uint32_t)strlen(prefix);
    uint32_t d_len_prefix = (uint32_t)sizeof(uint32_t);
    check("raw template_data is at least prefix+digest long",
            raw_entry.template_data_len >=
                    d_len_prefix + prefix_len + TPM2_SHA256_DIGEST_SIZE);
    const uint8_t* raw_file_digest =
            raw_entry.template_data + d_len_prefix + prefix_len;

    /* now pull the redacted entry's template_data apart the same way */
    uint16_t redacted_digest_len = 0;
    charra_event_log_ima_detect_digest_len(
            redacted, redacted_len, &redacted_digest_len);
    uint32_t red_offset = 0;
    charra_event_log_entry red_entry = {0};
    charra_event_log_parse_entry(redacted, redacted_len, &red_offset,
            redacted_digest_len, &red_entry);

    check("redacted template_data is exactly 79 bytes "
          "(4-byte d-ng length + 7-byte prefix + 32-byte file digest "
          "+ 4-byte n-ng length + 32-byte path hash)",
            red_entry.template_data_len == 79);
    check("redacted template_data starts with \"sha256:\" after its d-ng "
          "length prefix",
            red_entry.template_data_len >= d_len_prefix + prefix_len &&
                    memcmp(red_entry.template_data + d_len_prefix, prefix,
                            prefix_len) == 0);
    check("file-content digest is preserved byte-for-byte",
            red_entry.template_data_len >=
                    d_len_prefix + prefix_len + TPM2_SHA256_DIGEST_SIZE &&
                    memcmp(red_entry.template_data + d_len_prefix + prefix_len,
                            raw_file_digest, TPM2_SHA256_DIGEST_SIZE) == 0);

    /* the sensitive path must not appear anywhere in the redacted log */
    const char* needle = "/etc/company/api_keys.conf";
    size_t needle_len = strlen(needle);
    bool path_found = false;
    for (uint32_t i = 0; i + needle_len <= redacted_len; ++i) {
        if (memcmp(redacted + i, needle, needle_len) == 0) {
            path_found = true;
            break;
        }
    }
    check("the raw path does NOT appear anywhere in the redacted log",
            !path_found);

    free(raw_log);
    free(redacted);
}

static void test_empty_log(void) {
    printf("\nempty log redacts to an empty log\n");

    uint8_t* redacted = NULL;
    uint32_t redacted_len = 999;
    CHARRA_RC rc =
            charra_sdk_redact_ima_log(NULL, 0, NULL, &redacted, &redacted_len);

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
            charra_sdk_redact_ima_log(
                    dummy, sizeof(dummy), NULL, NULL, &out_len) ==
                    CHARRA_RC_BAD_ARGUMENT);
    check("NULL redacted_log_len_out rejected",
            charra_sdk_redact_ima_log(
                    dummy, sizeof(dummy), NULL, &out, NULL) ==
                    CHARRA_RC_BAD_ARGUMENT);
    check("NULL raw_log with non-zero length rejected",
            charra_sdk_redact_ima_log(NULL, 10, NULL, &out, &out_len) ==
                    CHARRA_RC_BAD_ARGUMENT);
}

static void test_malformed_log_rejected(void) {
    printf("\nmalformed input is rejected, not silently redacted\n");

    uint8_t garbage[] = {0x01, 0x02, 0x03};
    uint8_t* out = NULL;
    uint32_t out_len = 0;
    CHARRA_RC rc = charra_sdk_redact_ima_log(
            garbage, sizeof(garbage), NULL, &out, &out_len);
    check("truncated/garbage log rejected", rc != CHARRA_RC_SUCCESS);
}

int main(void) {
    printf("Verifier redaction SDK tests\n");
    printf("=============================\n");

    test_redacted_log_is_valid_replay_input();
    test_redacted_pcr_differs_from_raw();
    test_salted_nondeterministic();
    test_shared_salt_is_deterministic();
    test_different_entries_redact_differently();
    test_file_digest_preserved_path_redacted();
    test_empty_log();
    test_bad_arguments();
    test_malformed_log_rejected();

    printf("\n=============================\n");
    printf("%u tests, %u failed\n", tests_run, tests_failed);

    return (tests_failed == 0) ? 0 : 1;
}
