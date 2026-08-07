/**
 * @file test_event_log.c
 * @brief Standalone tests for IMA event log replay.
 *
 * Needs no TPM, no network and no /sys: logs are synthesised in memory and the
 * expected PCR value is computed independently by chaining extends by hand.
 *
 * Build and run:  make test_event_log && ./bin/test_event_log
 */

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "../src/core/charra_event_log.h"
#include "../src/util/crypto_util.h"

#define LOG_BUF_SIZE 4096

static unsigned int tests_run = 0;
static unsigned int tests_failed = 0;

/* --- tiny assert helpers ------------------------------------------------ */

static void check(const char* name, bool condition) {
    tests_run++;
    if (condition) {
        printf("  PASS  %s\n", name);
    } else {
        tests_failed++;
        printf("  FAIL  %s\n", name);
    }
}

static void print_hex(const char* label, const uint8_t* buf, size_t len) {
    printf("        %s = ", label);
    for (size_t i = 0; i < len; ++i) {
        printf("%02x", buf[i]);
    }
    printf("\n");
}

/* --- log construction --------------------------------------------------- */

typedef struct {
    uint8_t buf[LOG_BUF_SIZE];
    size_t len;
} test_log;

static void log_reset(test_log* log) { log->len = 0; }

static void append_u32(test_log* log, uint32_t value) {
    log->buf[log->len++] = (uint8_t)(value & 0xff);
    log->buf[log->len++] = (uint8_t)((value >> 8) & 0xff);
    log->buf[log->len++] = (uint8_t)((value >> 16) & 0xff);
    log->buf[log->len++] = (uint8_t)((value >> 24) & 0xff);
}

static void append_bytes(test_log* log, const void* data, size_t len) {
    memcpy(log->buf + log->len, data, len);
    log->len += len;
}

/** Append one well-formed entry. */
static void append_entry(test_log* log, uint32_t pcr_index,
        const uint8_t* digest, uint16_t digest_len, const char* name,
        const char* data) {
    uint32_t name_len = (uint32_t)strlen(name);
    uint32_t data_len = (uint32_t)strlen(data);

    append_u32(log, pcr_index);
    append_bytes(log, digest, digest_len);
    append_u32(log, name_len);
    append_bytes(log, name, name_len);
    append_u32(log, data_len);
    append_bytes(log, data, data_len);
}

/** A distinct, reproducible 32-byte digest for a given seed. */
static void make_digest(uint8_t seed, uint8_t digest[TPM2_SHA256_DIGEST_SIZE]) {
    memset(digest, seed, TPM2_SHA256_DIGEST_SIZE);
}

/* --- reference implementation ------------------------------------------- */

/**
 * @brief Extend by hand: acc := SHA256(acc || digest), zero-padded.
 *
 * Deliberately written out separately from the code under test so the test
 * asserts against the definition of a PCR extend rather than against itself.
 */
static void reference_extend(uint8_t acc[TPM2_SHA256_DIGEST_SIZE],
        const uint8_t* digest, uint16_t digest_len) {
    uint8_t buf[TPM2_SHA256_DIGEST_SIZE * 2] = {0};
    memcpy(buf, acc, TPM2_SHA256_DIGEST_SIZE);
    memcpy(buf + TPM2_SHA256_DIGEST_SIZE, digest, digest_len);
    hash_sha256(sizeof(buf), buf, acc);
}

/* --- tests -------------------------------------------------------------- */

static void test_empty_log(void) {
    printf("\nempty log\n");
    uint8_t pcr[TPM2_SHA256_DIGEST_SIZE] = {0xff};
    uint8_t zero[TPM2_SHA256_DIGEST_SIZE] = {0};

    CHARRA_RC rc = charra_replay_ima_log(NULL, 0, CHARRA_IMA_PCR_INDEX, pcr);
    check("empty log succeeds", rc == CHARRA_RC_SUCCESS);
    check("empty log replays to the all-zero PCR",
            memcmp(pcr, zero, sizeof(zero)) == 0);
}

static void test_single_entry(void) {
    printf("\nsingle entry\n");
    test_log log;
    log_reset(&log);

    uint8_t digest[TPM2_SHA256_DIGEST_SIZE];
    make_digest(0xa1, digest);
    append_entry(&log, CHARRA_IMA_PCR_INDEX, digest, sizeof(digest), "ima-ng",
            "sha256:deadbeef /usr/bin/bash");

    uint8_t expected[TPM2_SHA256_DIGEST_SIZE] = {0};
    reference_extend(expected, digest, sizeof(digest));

    uint8_t actual[TPM2_SHA256_DIGEST_SIZE] = {0};
    CHARRA_RC rc = charra_replay_ima_log(
            log.buf, (uint32_t)log.len, CHARRA_IMA_PCR_INDEX, actual);

    check("single entry parses", rc == CHARRA_RC_SUCCESS);
    check("single entry matches SHA256(0 || digest)",
            memcmp(actual, expected, sizeof(expected)) == 0);
    if (memcmp(actual, expected, sizeof(expected)) != 0) {
        print_hex("expected", expected, sizeof(expected));
        print_hex("actual  ", actual, sizeof(actual));
    }
}

static void test_multiple_entries_chain(void) {
    printf("\nmultiple entries chain in order\n");
    test_log log;
    log_reset(&log);

    uint8_t expected[TPM2_SHA256_DIGEST_SIZE] = {0};
    for (uint8_t i = 1; i <= 5; ++i) {
        uint8_t digest[TPM2_SHA256_DIGEST_SIZE];
        make_digest(i, digest);
        append_entry(&log, CHARRA_IMA_PCR_INDEX, digest, sizeof(digest),
                "ima-ng", "sha256:aa /some/path");
        reference_extend(expected, digest, sizeof(digest));
    }

    uint8_t actual[TPM2_SHA256_DIGEST_SIZE] = {0};
    CHARRA_RC rc = charra_replay_ima_log(
            log.buf, (uint32_t)log.len, CHARRA_IMA_PCR_INDEX, actual);

    check("five entries parse", rc == CHARRA_RC_SUCCESS);
    check("five entries produce the chained value",
            memcmp(actual, expected, sizeof(expected)) == 0);
}

static void test_order_matters(void) {
    printf("\nreordering changes the result\n");
    uint8_t d1[TPM2_SHA256_DIGEST_SIZE], d2[TPM2_SHA256_DIGEST_SIZE];
    make_digest(0x11, d1);
    make_digest(0x22, d2);

    test_log forward, backward;
    log_reset(&forward);
    log_reset(&backward);
    append_entry(&forward, CHARRA_IMA_PCR_INDEX, d1, sizeof(d1), "ima-ng", "a");
    append_entry(&forward, CHARRA_IMA_PCR_INDEX, d2, sizeof(d2), "ima-ng", "b");
    append_entry(&backward, CHARRA_IMA_PCR_INDEX, d2, sizeof(d2), "ima-ng", "b");
    append_entry(&backward, CHARRA_IMA_PCR_INDEX, d1, sizeof(d1), "ima-ng", "a");

    uint8_t pcr_fwd[TPM2_SHA256_DIGEST_SIZE] = {0};
    uint8_t pcr_bwd[TPM2_SHA256_DIGEST_SIZE] = {0};
    charra_replay_ima_log(
            forward.buf, (uint32_t)forward.len, CHARRA_IMA_PCR_INDEX, pcr_fwd);
    charra_replay_ima_log(backward.buf, (uint32_t)backward.len,
            CHARRA_IMA_PCR_INDEX, pcr_bwd);

    check("swapping two entries changes the replayed PCR",
            memcmp(pcr_fwd, pcr_bwd, sizeof(pcr_fwd)) != 0);
}

static void test_dropped_entry_detected(void) {
    printf("\ndropping an entry changes the result\n");
    test_log full, truncated;
    log_reset(&full);
    log_reset(&truncated);

    for (uint8_t i = 1; i <= 3; ++i) {
        uint8_t digest[TPM2_SHA256_DIGEST_SIZE];
        make_digest(i, digest);
        append_entry(&full, CHARRA_IMA_PCR_INDEX, digest, sizeof(digest),
                "ima-ng", "x");
        if (i != 2) { /* drop the middle entry */
            append_entry(&truncated, CHARRA_IMA_PCR_INDEX, digest,
                    sizeof(digest), "ima-ng", "x");
        }
    }

    uint8_t pcr_full[TPM2_SHA256_DIGEST_SIZE] = {0};
    uint8_t pcr_dropped[TPM2_SHA256_DIGEST_SIZE] = {0};
    charra_replay_ima_log(
            full.buf, (uint32_t)full.len, CHARRA_IMA_PCR_INDEX, pcr_full);
    charra_replay_ima_log(truncated.buf, (uint32_t)truncated.len,
            CHARRA_IMA_PCR_INDEX, pcr_dropped);

    check("removing an entry changes the replayed PCR",
            memcmp(pcr_full, pcr_dropped, sizeof(pcr_full)) != 0);
}

static void test_other_pcr_skipped(void) {
    printf("\nentries for other PCRs are skipped\n");
    test_log mixed, only_target;
    log_reset(&mixed);
    log_reset(&only_target);

    uint8_t d_target[TPM2_SHA256_DIGEST_SIZE];
    uint8_t d_other[TPM2_SHA256_DIGEST_SIZE];
    make_digest(0x77, d_target);
    make_digest(0x88, d_other);

    /* one entry for PCR 11 interleaved between two for the target PCR */
    append_entry(&mixed, CHARRA_IMA_PCR_INDEX, d_target, sizeof(d_target),
            "ima-ng", "a");
    append_entry(&mixed, 11, d_other, sizeof(d_other), "ima-ng", "other-pcr");
    append_entry(&mixed, CHARRA_IMA_PCR_INDEX, d_target, sizeof(d_target),
            "ima-ng", "b");

    append_entry(&only_target, CHARRA_IMA_PCR_INDEX, d_target,
            sizeof(d_target), "ima-ng", "a");
    append_entry(&only_target, CHARRA_IMA_PCR_INDEX, d_target,
            sizeof(d_target), "ima-ng", "b");

    uint8_t pcr_mixed[TPM2_SHA256_DIGEST_SIZE] = {0};
    uint8_t pcr_clean[TPM2_SHA256_DIGEST_SIZE] = {0};
    CHARRA_RC rc = charra_replay_ima_log(
            mixed.buf, (uint32_t)mixed.len, CHARRA_IMA_PCR_INDEX, pcr_mixed);
    charra_replay_ima_log(only_target.buf, (uint32_t)only_target.len,
            CHARRA_IMA_PCR_INDEX, pcr_clean);

    check("mixed-PCR log parses", rc == CHARRA_RC_SUCCESS);
    check("PCR 11 entry does not affect the PCR 10 replay",
            memcmp(pcr_mixed, pcr_clean, sizeof(pcr_mixed)) == 0);
}

static void test_redaction_does_not_change_replay(void) {
    printf("\nredacting template_data does not change the replay\n");
    test_log original, redacted;
    log_reset(&original);
    log_reset(&redacted);

    uint8_t digest[TPM2_SHA256_DIGEST_SIZE];
    make_digest(0x5a, digest);

    /* same digest, different template_data of a different length */
    append_entry(&original, CHARRA_IMA_PCR_INDEX, digest, sizeof(digest),
            "ima-ng", "sha256:abcd sensitive/myfile.extension");
    append_entry(&redacted, CHARRA_IMA_PCR_INDEX, digest, sizeof(digest),
            "ima-ng", "sha256:abcd XXX/myfile.extension");

    uint8_t pcr_original[TPM2_SHA256_DIGEST_SIZE] = {0};
    uint8_t pcr_redacted[TPM2_SHA256_DIGEST_SIZE] = {0};
    charra_replay_ima_log(original.buf, (uint32_t)original.len,
            CHARRA_IMA_PCR_INDEX, pcr_original);
    charra_replay_ima_log(redacted.buf, (uint32_t)redacted.len,
            CHARRA_IMA_PCR_INDEX, pcr_redacted);

    check("logs differ in length",
            original.len != redacted.len);
    check("redacted log replays to the same PCR",
            memcmp(pcr_original, pcr_redacted, sizeof(pcr_original)) == 0);
}

static void test_empty_template_data(void) {
    printf("\ntemplate_data may be empty\n");
    test_log with_data, without_data;
    log_reset(&with_data);
    log_reset(&without_data);

    uint8_t digest[TPM2_SHA256_DIGEST_SIZE];
    make_digest(0x3c, digest);
    append_entry(&with_data, CHARRA_IMA_PCR_INDEX, digest, sizeof(digest),
            "ima-ng", "sha256:abcd /usr/bin/bash");
    append_entry(&without_data, CHARRA_IMA_PCR_INDEX, digest, sizeof(digest),
            "ima-ng", "");

    uint8_t pcr_with[TPM2_SHA256_DIGEST_SIZE] = {0};
    uint8_t pcr_without[TPM2_SHA256_DIGEST_SIZE] = {0};
    CHARRA_RC rc = charra_replay_ima_log(without_data.buf,
            (uint32_t)without_data.len, CHARRA_IMA_PCR_INDEX, pcr_without);
    charra_replay_ima_log(with_data.buf, (uint32_t)with_data.len,
            CHARRA_IMA_PCR_INDEX, pcr_with);

    check("entry with data_len 0 parses", rc == CHARRA_RC_SUCCESS);
    check("digest-only entry replays identically",
            memcmp(pcr_with, pcr_without, sizeof(pcr_with)) == 0);
}

static void test_sha1_digests_zero_padded(void) {
    printf("\nSHA-1 sized digests are detected and zero-padded\n");
    test_log log;
    log_reset(&log);

    uint8_t digest[TPM2_SHA1_DIGEST_SIZE];
    memset(digest, 0x9e, sizeof(digest));
    append_entry(&log, CHARRA_IMA_PCR_INDEX, digest, sizeof(digest), "ima-ng",
            "sha1:abcd /usr/bin/bash");

    uint16_t detected = 0;
    CHARRA_RC det_rc = charra_event_log_ima_detect_digest_len(
            log.buf, (uint32_t)log.len, &detected);
    check("digest length detected as 20", det_rc == CHARRA_RC_SUCCESS &&
                                                  detected ==
                                                          TPM2_SHA1_DIGEST_SIZE);

    uint8_t expected[TPM2_SHA256_DIGEST_SIZE] = {0};
    reference_extend(expected, digest, sizeof(digest));

    uint8_t actual[TPM2_SHA256_DIGEST_SIZE] = {0};
    CHARRA_RC rc = charra_replay_ima_log(
            log.buf, (uint32_t)log.len, CHARRA_IMA_PCR_INDEX, actual);

    check("SHA-1 log replays", rc == CHARRA_RC_SUCCESS);
    check("SHA-1 digest is zero-padded to 32 bytes before extending",
            memcmp(actual, expected, sizeof(expected)) == 0);
}

static void test_truncated_log_rejected(void) {
    printf("\nmalformed logs are rejected\n");
    test_log log;
    log_reset(&log);

    uint8_t digest[TPM2_SHA256_DIGEST_SIZE];
    make_digest(0x42, digest);
    append_entry(&log, CHARRA_IMA_PCR_INDEX, digest, sizeof(digest), "ima-ng",
            "sha256:abcd /usr/bin/bash");

    uint8_t pcr[TPM2_SHA256_DIGEST_SIZE] = {0};

    /* cut the last byte off: template_data is now shorter than data_len */
    CHARRA_RC rc = charra_replay_ima_log(
            log.buf, (uint32_t)log.len - 1, CHARRA_IMA_PCR_INDEX, pcr);
    check("truncated log rejected", rc != CHARRA_RC_SUCCESS);

    /* a header fragment with no body at all */
    rc = charra_replay_ima_log(log.buf, 6, CHARRA_IMA_PCR_INDEX, pcr);
    check("fragment shorter than one entry rejected", rc != CHARRA_RC_SUCCESS);

    /* trailing garbage after a valid entry */
    test_log trailing;
    log_reset(&trailing);
    append_entry(&trailing, CHARRA_IMA_PCR_INDEX, digest, sizeof(digest),
            "ima-ng", "x");
    append_bytes(&trailing, "\x01\x02\x03", 3);
    rc = charra_replay_ima_log(
            trailing.buf, (uint32_t)trailing.len, CHARRA_IMA_PCR_INDEX, pcr);
    check("trailing garbage rejected", rc != CHARRA_RC_SUCCESS);
}

static void test_oversized_length_rejected(void) {
    printf("\nhostile length fields are rejected\n");
    test_log log;
    log_reset(&log);

    uint8_t digest[TPM2_SHA256_DIGEST_SIZE];
    make_digest(0x42, digest);

    /* data_len claims almost 4 GiB; the check must not overflow and pass */
    append_u32(&log, CHARRA_IMA_PCR_INDEX);
    append_bytes(&log, digest, sizeof(digest));
    append_u32(&log, 6);
    append_bytes(&log, "ima-ng", 6);
    append_u32(&log, 0xfffffff0u);
    append_bytes(&log, "short", 5);

    uint8_t pcr[TPM2_SHA256_DIGEST_SIZE] = {0};
    CHARRA_RC rc = charra_replay_ima_log(
            log.buf, (uint32_t)log.len, CHARRA_IMA_PCR_INDEX, pcr);
    check("huge data_len rejected without overflow", rc != CHARRA_RC_SUCCESS);

    /* name_len far beyond any real template name */
    log_reset(&log);
    append_u32(&log, CHARRA_IMA_PCR_INDEX);
    append_bytes(&log, digest, sizeof(digest));
    append_u32(&log, 0xfffffff0u);
    append_bytes(&log, "ima-ng", 6);
    rc = charra_replay_ima_log(
            log.buf, (uint32_t)log.len, CHARRA_IMA_PCR_INDEX, pcr);
    check("huge name_len rejected", rc != CHARRA_RC_SUCCESS);
}

static void test_legacy_ima_template_rejected(void) {
    printf("\nlegacy \"ima\" template is rejected, not guessed at\n");
    test_log log;
    log_reset(&log);

    uint8_t digest[TPM2_SHA256_DIGEST_SIZE];
    make_digest(0x13, digest);
    append_entry(&log, CHARRA_IMA_PCR_INDEX, digest, sizeof(digest), "ima",
            "legacy layout");

    uint8_t pcr[TPM2_SHA256_DIGEST_SIZE] = {0};
    CHARRA_RC rc = charra_replay_ima_log(
            log.buf, (uint32_t)log.len, CHARRA_IMA_PCR_INDEX, pcr);
    check("legacy ima template rejected", rc != CHARRA_RC_SUCCESS);
}

static void test_bad_arguments(void) {
    printf("\nbad arguments\n");
    test_log log;
    log_reset(&log);
    uint8_t digest[TPM2_SHA256_DIGEST_SIZE];
    make_digest(0x01, digest);
    append_entry(&log, CHARRA_IMA_PCR_INDEX, digest, sizeof(digest), "ima-ng",
            "x");

    uint8_t pcr[TPM2_SHA256_DIGEST_SIZE] = {0};
    check("NULL output rejected",
            charra_replay_ima_log(log.buf, (uint32_t)log.len,
                    CHARRA_IMA_PCR_INDEX, NULL) == CHARRA_RC_BAD_ARGUMENT);
    check("NULL log with non-zero length rejected",
            charra_replay_ima_log(NULL, 10, CHARRA_IMA_PCR_INDEX, pcr) ==
                    CHARRA_RC_BAD_ARGUMENT);

    charra_pcr_accumulator acc;
    charra_pcr_reset(&acc);
    check("zero-length digest rejected",
            charra_pcr_extend(&acc, digest, 0) == CHARRA_RC_BAD_ARGUMENT);
    check("oversized digest rejected",
            charra_pcr_extend(&acc, digest, TPM2_SHA256_DIGEST_SIZE + 1) ==
                    CHARRA_RC_BAD_ARGUMENT);
}

static void test_unmatched_target_pcr(void) {
    printf("\nlog with no entries for the target PCR\n");
    test_log log;
    log_reset(&log);

    uint8_t digest[TPM2_SHA256_DIGEST_SIZE];
    make_digest(0x99, digest);
    append_entry(&log, 11, digest, sizeof(digest), "ima-ng", "x");

    uint8_t pcr[TPM2_SHA256_DIGEST_SIZE] = {0xaa};
    uint8_t zero[TPM2_SHA256_DIGEST_SIZE] = {0};
    CHARRA_RC rc = charra_replay_ima_log(
            log.buf, (uint32_t)log.len, CHARRA_IMA_PCR_INDEX, pcr);

    check("log with only other PCRs still succeeds", rc == CHARRA_RC_SUCCESS);
    check("target PCR stays all-zero (a warning is logged)",
            memcmp(pcr, zero, sizeof(zero)) == 0);
}

/* --- main --------------------------------------------------------------- */

int main(void) {
    printf("IMA event log replay tests\n");
    printf("==========================\n");

    test_empty_log();
    test_single_entry();
    test_multiple_entries_chain();
    test_order_matters();
    test_dropped_entry_detected();
    test_other_pcr_skipped();
    test_redaction_does_not_change_replay();
    test_empty_template_data();
    test_sha1_digests_zero_padded();
    test_truncated_log_rejected();
    test_oversized_length_rejected();
    test_legacy_ima_template_rejected();
    test_bad_arguments();
    test_unmatched_target_pcr();

    printf("\n==========================\n");
    printf("%u tests, %u failed\n", tests_run, tests_failed);

    return (tests_failed == 0) ? 0 : 1;
}
