/**
 * @file test_parser_util.c
 * @brief Tests for parser_util.h -- reading reference-PCR files.
 *
 * These two functions parse `reference-pcrs.txt`, the only file whose
 * contents the Attester's appraisal is compared against. A parser that
 * silently accepts a malformed line does not fail loudly; it produces a
 * reference value nobody intended, and the mismatch surfaces much later as
 * a failed attestation.
 *
 * NOTE on parse_pcr_value(): it scans BACKWARDS from `start` looking for
 * the "0x" that precedes the digest, reading start[-2] and start[-1]. It
 * is only ever called with a pointer into the middle of a loaded file, so
 * the tests here do the same. Passing the first byte of an allocation
 * would read out of bounds -- worth knowing before reusing it elsewhere.
 *
 * Build and run:  make test_parser_util && ./bin/test_parser_util
 */

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include <tss2/tss2_tpm2_types.h>

#include "../src/util/parser_util.h"

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

/* --- parse_pcr_index ---------------------------------------------------- */

static void test_pcr_index(void) {
    printf("\nparse_pcr_index accepts 0..31 and nothing else\n");

    char buf[16];
    bool all_ok = true;
    for (int i = 0; i < TPM2_MAX_PCRS; ++i) {
        snprintf(buf, sizeof(buf), "%d", i);
        if (parse_pcr_index(buf) != i) {
            printf("        (first failure at %d)\n", i);
            all_ok = false;
            break;
        }
    }
    check("every index below TPM2_MAX_PCRS parses to itself", all_ok);

    char at_max[16];
    snprintf(at_max, sizeof(at_max), "%d", TPM2_MAX_PCRS);
    check("TPM2_MAX_PCRS itself is rejected", parse_pcr_index(at_max) == -1);
    check("well past the end is rejected", parse_pcr_index("999") == -1);

    /* Regression. strtoul() accepts a leading '-' and wraps the negated
     * value into unsigned; narrowing that to int could land back inside
     * 0..31, so "-4294967286" used to be accepted as PCR 10. Every one of
     * these must be an error, not an index. */
    check("a negative index is rejected", parse_pcr_index("-1") < 0);
    check("a large negative index is rejected",
            parse_pcr_index("-99999") < 0);
    check("a negative index that wraps into range is rejected (was PCR 10)",
            parse_pcr_index("-4294967286") < 0);
    check("a negative index that wraps to zero is rejected",
            parse_pcr_index("-4294967296") < 0);
    check("a negative index behind whitespace is rejected",
            parse_pcr_index("  -4294967295") < 0);
}

static void test_pcr_index_rejects_non_numbers(void) {
    printf("\nparse_pcr_index rejects what is not a number\n");

    check("an empty string is rejected", parse_pcr_index("") == -1);
    check("letters are rejected", parse_pcr_index("abc") == -1);
    check("a lone sign is rejected", parse_pcr_index("+") == -1);

    /* strtoul stops at the first non-digit rather than failing, so these
     * document what actually happens: a trailing suffix is ignored. That
     * is lenient, but it is the behaviour the reference-file format
     * relies on -- "10:" and "10 sha256:" both name PCR 10. */
    check("a trailing colon is ignored", parse_pcr_index("10:") == 10);
    check("trailing text is ignored", parse_pcr_index("7 sha256") == 7);
    check("leading whitespace is skipped", parse_pcr_index("  3") == 3);
}

/* --- parse_pcr_value ---------------------------------------------------- */

/** Wraps a line the way a loaded file does, so the backwards scan in
 * parse_pcr_value() has real bytes behind `start`. */
static CHARRA_RC parse_line(const char* line, uint8_t* out) {
    static char buf[512];
    memset(buf, ' ', sizeof(buf));
    size_t len = strlen(line);
    if (len + 8 >= sizeof(buf)) {
        return CHARRA_RC_ERROR;
    }
    memcpy(buf + 4, line, len);
    char* start = buf + 4;
    char* eol = start + len;
    return parse_pcr_value(start, eol, out);
}

static void test_pcr_value(void) {
    printf("\nparse_pcr_value reads a 32-byte digest after \"0x\"\n");

    /* The shape reference-pcrs.txt actually holds. */
    const char* line =
            "10 : 0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c"
            "1d1e1f20";
    uint8_t value[TPM2_SHA256_DIGEST_SIZE] = {0};
    check("parses a well-formed line",
            parse_line(line, value) == CHARRA_RC_SUCCESS);

    bool bytes_ok = true;
    for (uint32_t i = 0; i < sizeof(value); ++i) {
        bytes_ok = bytes_ok && value[i] == (uint8_t)(i + 1);
    }
    check("every one of the 32 bytes is right", bytes_ok);

    /* All-zero and all-ff, the two values most likely to be confused with
     * "unset". */
    char zeros[80] = {0};
    strcpy(zeros, "0x");
    for (int i = 0; i < 64; ++i) {
        strcat(zeros, "0");
    }
    uint8_t zval[TPM2_SHA256_DIGEST_SIZE];
    memset(zval, 0xaa, sizeof(zval));
    bool all_zero = parse_line(zeros, zval) == CHARRA_RC_SUCCESS;
    for (uint32_t i = 0; i < sizeof(zval); ++i) {
        all_zero = all_zero && zval[i] == 0;
    }
    check("an all-zero digest parses as all zero", all_zero);

    char ffs[80] = {0};
    strcpy(ffs, "0x");
    for (int i = 0; i < 64; ++i) {
        strcat(ffs, "f");
    }
    uint8_t fval[TPM2_SHA256_DIGEST_SIZE] = {0};
    bool all_ff = parse_line(ffs, fval) == CHARRA_RC_SUCCESS;
    for (uint32_t i = 0; i < sizeof(fval); ++i) {
        all_ff = all_ff && fval[i] == 0xff;
    }
    check("an all-ff digest parses as all ff", all_ff);

    /* Uppercase hex, which a human-edited file will contain sooner or
     * later. */
    const char* upper =
            "0xAABBCCDDEEFF00112233445566778899AABBCCDDEEFF0011223344556677"
            "8899";
    uint8_t uval[TPM2_SHA256_DIGEST_SIZE] = {0};
    check("uppercase hex parses",
            parse_line(upper, uval) == CHARRA_RC_SUCCESS &&
                    uval[0] == 0xaa && uval[31] == 0x99);
}

static void test_pcr_value_rejects_truncation(void) {
    printf("\nparse_pcr_value rejects short and malformed digests\n");

    /* One nibble short of a full digest: the most likely real-world
     * corruption, and the one that must not yield a half-filled value. */
    char short_line[80] = {0};
    strcpy(short_line, "0x");
    for (int i = 0; i < 63; ++i) {
        strcat(short_line, "a");
    }
    uint8_t v[TPM2_SHA256_DIGEST_SIZE] = {0};
    check("a digest one character short is rejected",
            parse_line(short_line, v) != CHARRA_RC_SUCCESS);

    check("a line with no 0x marker is rejected",
            parse_line("10 : deadbeef", v) != CHARRA_RC_SUCCESS);
    check("an empty line is rejected", parse_line("", v) != CHARRA_RC_SUCCESS);
    check("\"0x\" with nothing after it is rejected",
            parse_line("0x", v) != CHARRA_RC_SUCCESS);

    /* strtoul on a two-character window: "zz" is not hex and must fail
     * rather than silently becoming 0. */
    char bad_hex[80] = {0};
    strcpy(bad_hex, "0xzz");
    for (int i = 0; i < 60; ++i) {
        strcat(bad_hex, "a");
    }
    check("non-hex characters inside the digest are rejected",
            parse_line(bad_hex, v) != CHARRA_RC_SUCCESS);
}

int main(void) {
    printf("parser_util tests\n");
    printf("=================\n");

    test_pcr_index();
    test_pcr_index_rejects_non_numbers();
    test_pcr_value();
    test_pcr_value_rejects_truncation();

    printf("\n=================\n");
    printf("%u tests, %u failed\n", tests_run, tests_failed);

    return (tests_failed == 0) ? 0 : 1;
}
