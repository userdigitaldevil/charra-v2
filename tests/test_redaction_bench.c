/**
 * @file test_redaction_bench.c
 * @brief Times charra_sdk_redact_ima_log() over the vendor evidence log.
 *
 * Not a pass/fail suite -- it reports numbers. Built and run like the other
 * suites so it links against exactly the code a run uses, rather than a copy:
 *
 *     make bin/test_redaction_bench && bin/test_redaction_bench
 *
 * The log is read from argv[1], defaulting to ima_test_logs.txt. Both entry
 * points are measured, because they cost very different amounts: the SHA-256
 * one every ordinary cycle uses, and the Poseidon one --trust-mode=zk uses,
 * whose commitment is chosen to be cheap inside a circuit rather than out of
 * one.
 */

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "../src/common/charra_log.h"
#include "../src/core/charra_event_log.h"
#include "../src/core/charra_ima_ascii.h"
#include "../src/core/charra_sdk.h"
#include "../src/core/charra_zk.h"
#include "../src/util/tpm2_util.h"

#define ITERATIONS 100

static double now_s(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (double)t.tv_sec + (double)t.tv_nsec / 1e9;
}

/** Mean and sample standard deviation, in milliseconds. */
static void stats(const double* v, int n, double* mean_ms, double* sd_ms) {
    double sum = 0.0;
    for (int i = 0; i < n; i++) {
        sum += v[i];
    }
    const double mean = sum / n;
    double acc = 0.0;
    for (int i = 0; i < n; i++) {
        acc += (v[i] - mean) * (v[i] - mean);
    }
    *mean_ms = mean * 1e3;
    *sd_ms = (n > 1) ? sqrt(acc / (n - 1)) * 1e3 : 0.0;
}

/**
 * @brief Count the entries, adopting whichever template-digest width the log
 * uses. A log converted from ASCII keeps its original width -- the vendor
 * evidence carries 20-byte SHA-1 digests, not SHA-256 -- and redaction
 * preserves it (charra_sdk.c), so assuming one here counted zero.
 */
static uint32_t count_entries(
        const uint8_t* log, uint32_t log_len, uint16_t* digest_len_out) {
    const uint16_t widths[] = {TPM2_SHA1_DIGEST_SIZE, TPM2_SHA256_DIGEST_SIZE};
    for (unsigned w = 0; w < sizeof(widths) / sizeof(widths[0]); w++) {
        uint32_t off = 0, n = 0;
        charra_event_log_entry e = {0};
        while (off < log_len &&
                charra_event_log_parse_entry(
                        log, log_len, &off, widths[w], &e) ==
                        CHARRA_RC_SUCCESS) {
            n++;
        }
        if (n > 0 && off == log_len) { /* consumed the whole log */
            *digest_len_out = widths[w];
            return n;
        }
    }
    return 0;
}

int main(int argc, char** argv) {
    charra_log_set_level(CHARRA_LOG_ERROR); /* keep per-entry chatter out */
    const char* path = (argc > 1) ? argv[1] : "ima_test_logs.txt";

    uint8_t* log = NULL;
    uint32_t log_len = 0;
    if (charra_ima_ascii_read_file(path, &log, &log_len) != CHARRA_RC_SUCCESS) {
        fprintf(stderr, "could not read '%s'\n", path);
        return 1;
    }
    uint16_t digest_len = 0;
    const uint32_t entries = count_entries(log, log_len, &digest_len);
    if (entries == 0) {
        fprintf(stderr, "'%s' parsed to zero entries\n", path);
        free(log);
        return 1;
    }

    printf("log            %s\n", path);
    printf("entries        %u\n", entries);
    printf("raw log_a      %u bytes\n", log_len);
    printf("template hash  %s\n", (digest_len == TPM2_SHA1_DIGEST_SIZE)
                                           ? "SHA-1 (20 B)" : "SHA-256 (32 B)");
    printf("iterations     %d\n\n", ITERATIONS);

    double* sha = malloc(sizeof(double) * ITERATIONS);
    double* pos = malloc(sizeof(double) * ITERATIONS);
    if (sha == NULL || pos == NULL) {
        free(sha);
        free(pos);
        free(log);
        return 1;
    }
    uint32_t out_len_sha = 0, out_len_pos = 0;

    /* --- SHA-256: every ordinary cycle ---------------------------------- */
    for (int i = 0; i < ITERATIONS; i++) {
        uint8_t* out = NULL;
        uint32_t out_len = 0;
        const double t0 = now_s();
        const CHARRA_RC rc = charra_sdk_redact_ima_log(
                log, log_len, NULL, CHARRA_SDK_DEFAULT_LABEL, &out, &out_len);
        sha[i] = now_s() - t0;
        if (rc != CHARRA_RC_SUCCESS) {
            fprintf(stderr, "SHA-256 redaction failed on iteration %d\n", i);
            return 1;
        }
        out_len_sha = out_len;
        free(out);
    }

    /* --- Poseidon: --trust-mode=zk only --------------------------------- */
    int pos_ok = 1;
    for (int i = 0; i < ITERATIONS && pos_ok; i++) {
        uint8_t* out = NULL;
        uint32_t out_len = 0;
        charra_zk_witness w = {0};
        const double t0 = now_s();
        const CHARRA_RC rc = charra_sdk_redact_ima_log_with_witness(
                log, log_len, CHARRA_SDK_DEFAULT_LABEL, &out, &out_len, &w);
        pos[i] = now_s() - t0;
        if (rc != CHARRA_RC_SUCCESS) {
            fprintf(stderr, "note: Poseidon redaction unavailable "
                            "(rc=%d on iteration %d)\n",
                    (int)rc, i);
            pos_ok = 0;
        } else {
            out_len_pos = out_len;
        }
        free(out);
        memset(&w, 0, sizeof(w)); /* the witness holds real paths and salts */
    }

    /* --- software replay: what a Verifier does, and what GTA's server does
     * for the whole of its check. No TPM involved. ----------------------- */
    double* rep = malloc(sizeof(double) * ITERATIONS);
    int rep_ok = (rep != NULL);
    if (rep_ok) {
        uint8_t* red = NULL;
        uint32_t red_len = 0;
        if (charra_sdk_redact_ima_log(log, log_len, NULL,
                    CHARRA_SDK_DEFAULT_LABEL, &red, &red_len) !=
                CHARRA_RC_SUCCESS) {
            rep_ok = 0;
        } else {
            for (int i = 0; i < ITERATIONS; i++) {
                uint8_t pcr[TPM2_SHA256_DIGEST_SIZE] = {0};
                const double t0 = now_s();
                const CHARRA_RC rc = charra_replay_ima_log(
                        red, red_len, CHARRA_IMA_PCR_INDEX, pcr);
                rep[i] = now_s() - t0;
                if (rc != CHARRA_RC_SUCCESS) {
                    rep_ok = 0;
                    break;
                }
            }
            free(red);
        }
    }

    double m = 0.0, sd = 0.0;
    stats(sha, ITERATIONS, &m, &sd);
    printf("SHA-256 (default, every cycle)\n");
    printf("  log_r        %u bytes\n", out_len_sha);
    printf("  whole log    %.3f ms +/- %.3f\n", m, sd);
    printf("  per entry    %.4f ms\n\n", m / entries);

    if (pos_ok) {
        stats(pos, ITERATIONS, &m, &sd);
        printf("Poseidon (--trust-mode=zk)\n");
        printf("  log_r        %u bytes\n", out_len_pos);
        printf("  whole log    %.3f ms +/- %.3f\n", m, sd);
        printf("  per entry    %.4f ms\n", m / entries);
    }

    if (rep_ok) {
        stats(rep, ITERATIONS, &m, &sd);
        printf("\nSoftware replay of log_r (no TPM -- what a Verifier does)\n");
        printf("  whole log    %.3f ms +/- %.3f\n", m, sd);
        printf("  per entry    %.4f ms\n", m / entries);
    }

    free(rep);
    free(sha);
    free(pos);
    free(log);
    return 0;
}
