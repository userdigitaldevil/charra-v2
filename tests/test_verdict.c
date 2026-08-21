/**
 * @file test_verdict.c
 * @brief Tests for the signed /appraise verdict (charra_verdict.h).
 *
 * Plays both sides in-process against the real key files in keys/: sign
 * with the private half, verify with the public one. The negative cases
 * are the point -- a verdict that survives a tampered signature, a stale
 * nonce or swapped evidence would be no better than the plain string it
 * replaced.
 *
 * Build and run:  make test_verdict && ./bin/test_verdict
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../src/core/charra_verdict.h"

#define PRIVATE_KEY "keys/verifier.der"
#define PUBLIC_KEY "keys/verifier.pub.der"

static unsigned int tests_run = 0;
static unsigned int tests_failed = 0;

/* Stand-ins for the round state the two sides really share: the nonce the
 * Verifier issued from /nonce, and the digest of the evidence it appraised. */
static const uint8_t nonce[TPM2_SHA256_DIGEST_SIZE] = {
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
        0xcc, 0xdd, 0xee, 0xff, 0x00, 0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a,
        0x69, 0x78, 0x87, 0x96, 0xa5, 0xb4, 0xc3, 0xd2, 0xe1, 0xf0};
static const uint8_t digest[TPM2_SHA256_DIGEST_SIZE] = {
        0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12,
        0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c};

static const time_t now = 1700000000;

static void check(const char* name, bool condition) {
    tests_run++;
    if (condition) {
        printf("  PASS  %s\n", name);
    } else {
        tests_failed++;
        printf("  FAIL  %s\n", name);
    }
}

/** Sign a verdict the way coap_appraise_handler() does. */
static CHARRA_RC sign(bool accepted, uint32_t* len_out, uint8_t** out) {
    charra_verdict v = {
            .accepted = accepted,
            .challenge_nonce_len = sizeof(nonce),
            .signed_at = (uint64_t)now,
    };
    memcpy(v.challenge_nonce, nonce, sizeof(nonce));
    memcpy(v.evidence_digest, digest, sizeof(digest));
    return charra_verdict_sign(&v, PRIVATE_KEY, len_out, out);
}

/** Verify it the way the RP's response handler does. */
static CHARRA_RC verify(
        uint32_t len, const uint8_t* data, bool* accepted_out) {
    return charra_verdict_verify(len, data, PUBLIC_KEY, nonce, sizeof(nonce),
            digest, now, accepted_out);
}

static void test_round_trip(void) {
    printf("\na signed verdict round-trips, carrying its verdict bit\n");

    for (int i = 0; i < 2; ++i) {
        bool accepted = (i == 1);
        uint8_t* buf = NULL;
        uint32_t buf_len = 0;
        check("signing succeeds",
                sign(accepted, &buf_len, &buf) == CHARRA_RC_SUCCESS);

        bool got = !accepted;
        check("verification succeeds",
                verify(buf_len, buf, &got) == CHARRA_RC_SUCCESS);
        check(accepted ? "an accepted verdict arrives as accepted"
                       : "a rejected verdict arrives as rejected",
                got == accepted);
        free(buf);
    }
}

/* Every byte of the message is either payload or signature, so flipping a
 * bit anywhere must break it -- there is no slack field to hide in. */
static void test_tampering_rejected(void) {
    printf("\nflipping any single byte invalidates the verdict\n");

    uint8_t* original = NULL;
    uint32_t len = 0;
    sign(true, &len, &original);

    unsigned int accepted_anyway = 0;
    for (uint32_t i = 0; i < len; ++i) {
        uint8_t* buf = malloc(len);
        memcpy(buf, original, len);
        buf[i] ^= 0x01;

        bool got = false;
        if (verify(len, buf, &got) == CHARRA_RC_SUCCESS && got) {
            accepted_anyway++;
        }
        free(buf);
    }
    free(original);

    check("no single-byte mutation is accepted", accepted_anyway == 0);
}

static void test_wrong_nonce_rejected(void) {
    printf("\na verdict from another round is rejected (nonce binding)\n");

    uint8_t* buf = NULL;
    uint32_t len = 0;
    sign(true, &len, &buf);

    /* Same key, same evidence, correct signature -- only the round moved
     * on. This is the replay a captured YES would attempt. */
    uint8_t other_nonce[sizeof(nonce)] = {0};
    memcpy(other_nonce, nonce, sizeof(nonce));
    other_nonce[0] ^= 0xff;

    bool got = false;
    check("check fails",
            charra_verdict_verify(len, buf, PUBLIC_KEY, other_nonce,
                    sizeof(other_nonce), digest, now,
                    &got) == CHARRA_RC_VERIFICATION_FAILED);
    check("no verdict is reported", !got);

    /* The len != 0 term in the nonce comparison: with nothing outstanding,
     * memcmp of zero bytes matches and would qualify anyone. */
    check("an empty expected nonce is REJECTED, not matched",
            charra_verdict_verify(len, buf, PUBLIC_KEY, other_nonce, 0, digest,
                    now, &got) == CHARRA_RC_VERIFICATION_FAILED);
    free(buf);
}

static void test_wrong_evidence_rejected(void) {
    printf("\na verdict cast over other evidence is rejected\n");

    uint8_t* buf = NULL;
    uint32_t len = 0;
    sign(true, &len, &buf);

    uint8_t other_digest[sizeof(digest)] = {0};
    memcpy(other_digest, digest, sizeof(digest));
    other_digest[sizeof(other_digest) - 1] ^= 0x01;

    bool got = false;
    check("check fails",
            charra_verdict_verify(len, buf, PUBLIC_KEY, nonce, sizeof(nonce),
                    other_digest, now,
                    &got) == CHARRA_RC_VERIFICATION_FAILED);
    check("no verdict is reported", !got);
    free(buf);
}

static void test_stale_timestamp_rejected(void) {
    printf("\na timestamp outside the skew window is rejected\n");

    uint8_t* buf = NULL;
    uint32_t len = 0;
    sign(true, &len, &buf);

    bool got = false;
    check("just inside the window is accepted",
            charra_verdict_verify(len, buf, PUBLIC_KEY, nonce, sizeof(nonce),
                    digest, now + CHARRA_VERDICT_SKEW_SECONDS,
                    &got) == CHARRA_RC_SUCCESS);
    check("just outside is rejected",
            charra_verdict_verify(len, buf, PUBLIC_KEY, nonce, sizeof(nonce),
                    digest, now + CHARRA_VERDICT_SKEW_SECONDS + 1,
                    &got) == CHARRA_RC_VERIFICATION_FAILED);
    /* Symmetric: a clock ahead of ours is as suspect as one behind. */
    check("outside in the other direction is rejected too",
            charra_verdict_verify(len, buf, PUBLIC_KEY, nonce, sizeof(nonce),
                    digest, now - CHARRA_VERDICT_SKEW_SECONDS - 1,
                    &got) == CHARRA_RC_VERIFICATION_FAILED);
    free(buf);
}

static void test_wrong_key_rejected(void) {
    printf("\na verdict signed by another key is rejected\n");

    uint8_t* buf = NULL;
    uint32_t len = 0;
    sign(true, &len, &buf);

    /* A real, valid keypair -- just not the Verifier's. */
    bool got = false;
    check("check fails under the Attester's public key",
            charra_verdict_verify(len, buf, "keys/attester.pub.der", nonce,
                    sizeof(nonce), digest, now,
                    &got) == CHARRA_RC_VERIFICATION_FAILED);
    check("no verdict is reported", !got);
    free(buf);
}

static void test_garbage_rejected(void) {
    printf("\nnon-verdict input is rejected, not misread\n");

    bool got = false;
    const uint8_t garbage[] = {0xde, 0xad, 0xbe, 0xef};
    check("random bytes are rejected",
            verify(sizeof(garbage), garbage, &got) != CHARRA_RC_SUCCESS);
    check("an empty message is rejected",
            verify(0, garbage, &got) != CHARRA_RC_SUCCESS);
    check("no verdict is reported", !got);
}

static void test_bad_arguments(void) {
    printf("\nbad arguments\n");

    uint8_t* buf = NULL;
    uint32_t len = 0;
    charra_verdict v = {.challenge_nonce_len = sizeof(v.challenge_nonce) + 1};

    check("sign: NULL verdict rejected",
            charra_verdict_sign(NULL, PRIVATE_KEY, &len, &buf) ==
                    CHARRA_RC_BAD_ARGUMENT);
    check("sign: NULL key path rejected",
            charra_verdict_sign(&v, NULL, &len, &buf) ==
                    CHARRA_RC_BAD_ARGUMENT);
    check("sign: oversized nonce rejected",
            charra_verdict_sign(&v, PRIVATE_KEY, &len, &buf) ==
                    CHARRA_RC_BAD_ARGUMENT);
    check("sign: a missing key file is an error, not a crash",
            charra_verdict_sign(&(charra_verdict){0}, "keys/does-not-exist.der",
                    &len, &buf) != CHARRA_RC_SUCCESS);

    bool got = false;
    check("verify: NULL data rejected",
            charra_verdict_verify(0, NULL, PUBLIC_KEY, nonce, sizeof(nonce),
                    digest, now, &got) == CHARRA_RC_BAD_ARGUMENT);
    check("verify: NULL key path rejected",
            charra_verdict_verify(4, (const uint8_t*)"\x00\x00\x00\x00", NULL,
                    nonce, sizeof(nonce), digest, now,
                    &got) == CHARRA_RC_BAD_ARGUMENT);
    check("verify: NULL accepted_out rejected",
            charra_verdict_verify(4, (const uint8_t*)"\x00\x00\x00\x00",
                    PUBLIC_KEY, nonce, sizeof(nonce), digest, now,
                    NULL) == CHARRA_RC_BAD_ARGUMENT);
}

int main(void) {
    printf("Signed verdict tests\n");
    printf("====================\n");

    test_round_trip();
    test_tampering_rejected();
    test_wrong_nonce_rejected();
    test_wrong_evidence_rejected();
    test_stale_timestamp_rejected();
    test_wrong_key_rejected();
    test_garbage_rejected();
    test_bad_arguments();

    printf("\n====================\n");
    printf("%u tests, %u failed\n", tests_run, tests_failed);

    return (tests_failed == 0) ? 0 : 1;
}
