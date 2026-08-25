/**
 * @file test_rp_evidence_marshaling.c
 * @brief Standalone tests for charra_marshal_rp_evidence()/
 * charra_unmarshal_rp_evidence() -- the RP->Verifier evidence message
 * (Quote_r + Quote_a + log_r).
 *
 * This is the message that actually travels on every /appraise. Every
 * fixed-size field here is memcpy'd into a fixed-size array from
 * attacker-reachable input, so each one gets an oversized-input test,
 * hand-encoded with QCBOR directly -- the normal encoder cannot produce an
 * oversized field, since it reads from the same fixed-size struct it
 * encodes into.
 *
 * Build and run:  make test_rp_evidence_marshaling && ./bin/test_rp_evidence_marshaling
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <qcbor/qcbor.h>

#include "../src/core/charra_dto.h"
#include "../src/core/charra_marshaling.h"

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

/* --- round trip ---------------------------------------------------------- */

static void test_round_trips(void) {
    printf("\nRP evidence survives marshal -> unmarshal unchanged\n");

    msg_rp_evidence_dto ev = {0};
    ev.rp_attestation_data_len = sizeof(ev.rp_attestation_data);
    memset(ev.rp_attestation_data, 0x11, ev.rp_attestation_data_len);
    ev.rp_signature_len = sizeof(ev.rp_signature);
    memset(ev.rp_signature, 0x22, ev.rp_signature_len);
    ev.rp_public_key_len = sizeof(ev.rp_public_key);
    memset(ev.rp_public_key, 0x33, ev.rp_public_key_len);
    ev.attester_nonce_len = sizeof(ev.attester_nonce);
    memset(ev.attester_nonce, 0x44, ev.attester_nonce_len);
    ev.attestation_data_len = sizeof(ev.attestation_data);
    memset(ev.attestation_data, 0x55, ev.attestation_data_len);
    ev.tpm2_signature_len = sizeof(ev.tpm2_signature);
    memset(ev.tpm2_signature, 0x66, ev.tpm2_signature_len);
    ev.tpm2_public_key_len = sizeof(ev.tpm2_public_key);
    memset(ev.tpm2_public_key, 0x77, ev.tpm2_public_key_len);

    uint8_t log_r[900];
    memset(log_r, 0x88, sizeof(log_r));
    ev.log_r = log_r;
    ev.log_r_len = sizeof(log_r);

    uint32_t marshaled_len = 0;
    uint8_t* marshaled = NULL;
    CHARRA_RC rc = charra_marshal_rp_evidence(&ev, &marshaled_len, &marshaled);
    check("marshaling succeeds", rc == CHARRA_RC_SUCCESS);
    if (rc != CHARRA_RC_SUCCESS) {
        return;
    }

    msg_rp_evidence_dto res = {0};
    rc = charra_unmarshal_rp_evidence(marshaled_len, marshaled, &res);
    check("unmarshaling succeeds", rc == CHARRA_RC_SUCCESS);

    check("rp_attestation_data round-trips",
            res.rp_attestation_data_len == ev.rp_attestation_data_len &&
                    memcmp(res.rp_attestation_data, ev.rp_attestation_data,
                            ev.rp_attestation_data_len) == 0);
    check("rp_signature round-trips",
            res.rp_signature_len == ev.rp_signature_len &&
                    memcmp(res.rp_signature, ev.rp_signature,
                            ev.rp_signature_len) == 0);
    check("rp_public_key round-trips",
            res.rp_public_key_len == ev.rp_public_key_len &&
                    memcmp(res.rp_public_key, ev.rp_public_key,
                            ev.rp_public_key_len) == 0);
    check("attester_nonce round-trips",
            res.attester_nonce_len == ev.attester_nonce_len &&
                    memcmp(res.attester_nonce, ev.attester_nonce,
                            ev.attester_nonce_len) == 0);
    check("attestation_data round-trips",
            res.attestation_data_len == ev.attestation_data_len &&
                    memcmp(res.attestation_data, ev.attestation_data,
                            ev.attestation_data_len) == 0);
    check("tpm2_signature round-trips",
            res.tpm2_signature_len == ev.tpm2_signature_len &&
                    memcmp(res.tpm2_signature, ev.tpm2_signature,
                            ev.tpm2_signature_len) == 0);
    check("tpm2_public_key round-trips",
            res.tpm2_public_key_len == ev.tpm2_public_key_len &&
                    memcmp(res.tpm2_public_key, ev.tpm2_public_key,
                            ev.tpm2_public_key_len) == 0);
    check("log_r round-trips",
            res.log_r_len == ev.log_r_len &&
                    memcmp(res.log_r, ev.log_r, ev.log_r_len) == 0);

    free(marshaled);
}

/* log_r is the only field with no fixed upper bound (borrowed, like
 * event_log elsewhere) -- confirm an empty one parses rather than being
 * treated as an error. */
static void test_empty_log_r_accepted(void) {
    printf("\nRP evidence with an empty log_r parses\n");

    msg_rp_evidence_dto ev = {0};
    ev.rp_attestation_data_len = 4;
    ev.rp_signature_len = 4;
    ev.rp_public_key_len = 4;
    ev.attester_nonce_len = 4;
    ev.attestation_data_len = 4;
    ev.tpm2_signature_len = 4;
    ev.tpm2_public_key_len = 4;

    uint32_t marshaled_len = 0;
    uint8_t* marshaled = NULL;
    CHARRA_RC rc = charra_marshal_rp_evidence(&ev, &marshaled_len, &marshaled);
    check("marshaling succeeds", rc == CHARRA_RC_SUCCESS);
    if (rc != CHARRA_RC_SUCCESS) {
        return;
    }

    msg_rp_evidence_dto res = {0};
    rc = charra_unmarshal_rp_evidence(marshaled_len, marshaled, &res);
    check("unmarshaling succeeds", rc == CHARRA_RC_SUCCESS);
    check("log_r_len is 0", res.log_r_len == 0);

    free(marshaled);
}

/* --- bounds -------------------------------------------------------------- */

/** One byte string per field, in the exact order
 * charra_marshal_rp_evidence_internal() encodes them, so any single field
 * can be made oversized while the rest stay valid. */
typedef struct {
    const uint8_t* ptr;
    size_t len;
} raw_field;

#define RAW_FIELD_COUNT 8

static void encode_raw_evidence(const raw_field f[RAW_FIELD_COUNT],
        uint8_t** out, size_t* out_len) {
    size_t cap = 256;
    for (int i = 0; i < RAW_FIELD_COUNT; i++) {
        cap += f[i].len;
    }
    uint8_t* buf = malloc(cap);

    QCBOREncodeContext ec = {0};
    QCBOREncode_Init(&ec, (UsefulBuf){.ptr = buf, .len = cap});
    QCBOREncode_OpenArray(&ec);
    for (int i = 0; i < RAW_FIELD_COUNT; i++) {
        QCBOREncode_AddBytes(
                &ec, (UsefulBufC){.ptr = f[i].ptr, .len = f[i].len});
    }
    QCBOREncode_CloseArray(&ec);

    UsefulBufC buf_out = {0};
    QCBOREncode_Finish(&ec, &buf_out);
    *out = buf;
    *out_len = buf_out.len;
}

/** Fills every field with a small valid value; callers then oversize one. */
static void fill_valid(
        raw_field f[RAW_FIELD_COUNT], const uint8_t* small, size_t small_len) {
    for (int i = 0; i < RAW_FIELD_COUNT; i++) {
        f[i].ptr = small;
        f[i].len = small_len;
    }
}

static void expect_rejected(const char* name, raw_field f[RAW_FIELD_COUNT]) {
    uint8_t* raw = NULL;
    size_t raw_len = 0;
    encode_raw_evidence(f, &raw, &raw_len);

    msg_rp_evidence_dto res = {0};
    CHARRA_RC rc = charra_unmarshal_rp_evidence((uint32_t)raw_len, raw, &res);
    check(name, rc == CHARRA_RC_MARSHALING_ERROR);

    free(raw);
}

#define OVERSIZED_FIELD_TEST(idx, field, label)                                \
    do {                                                                       \
        printf("\nan oversized %s is rejected, not overflowed\n", label);       \
        uint8_t big[sizeof(((msg_rp_evidence_dto*)0)->field) + 1];              \
        memset(big, 0x41, sizeof(big));                                        \
        raw_field f[RAW_FIELD_COUNT];                                          \
        fill_valid(f, small, sizeof(small));                                   \
        f[idx].ptr = big;                                                      \
        f[idx].len = sizeof(big);                                              \
        expect_rejected("rejected with CHARRA_RC_MARSHALING_ERROR", f);        \
    } while (0)

static void test_oversized_fields_rejected(void) {
    uint8_t small[4] = {0};

    OVERSIZED_FIELD_TEST(0, rp_attestation_data, "rp_attestation_data");
    OVERSIZED_FIELD_TEST(1, rp_signature, "rp_signature");
    OVERSIZED_FIELD_TEST(2, rp_public_key, "rp_public_key");
    OVERSIZED_FIELD_TEST(3, attester_nonce, "attester_nonce");
    OVERSIZED_FIELD_TEST(4, attestation_data, "attestation_data");
    OVERSIZED_FIELD_TEST(5, tpm2_signature, "tpm2_signature");
    OVERSIZED_FIELD_TEST(6, tpm2_public_key, "tpm2_public_key");
}

/* A truncated array must fail rather than leave later fields uninitialised. */
static void test_truncated_message_rejected(void) {
    printf("\na message with too few fields is rejected\n");

    uint8_t small[4] = {0};

    size_t cap = 256;
    uint8_t* buf = malloc(cap);
    QCBOREncodeContext ec = {0};
    QCBOREncode_Init(&ec, (UsefulBuf){.ptr = buf, .len = cap});
    QCBOREncode_OpenArray(&ec);
    QCBOREncode_AddBytes(&ec, (UsefulBufC){.ptr = small, .len = sizeof(small)});
    QCBOREncode_CloseArray(&ec);
    UsefulBufC buf_out = {0};
    QCBOREncode_Finish(&ec, &buf_out);

    msg_rp_evidence_dto res = {0};
    CHARRA_RC rc =
            charra_unmarshal_rp_evidence((uint32_t)buf_out.len, buf, &res);
    check("rejected with CHARRA_RC_MARSHALING_ERROR",
            rc == CHARRA_RC_MARSHALING_ERROR);

    free(buf);
}

int main(void) {
    printf("RP evidence (msg_rp_evidence_dto) marshaling tests\n");
    printf("================================================\n");

    test_round_trips();
    test_empty_log_r_accepted();
    test_oversized_fields_rejected();
    test_truncated_message_rejected();

    printf("\n================================================\n");
    printf("%u tests, %u failed\n", tests_run, tests_failed);

    return (tests_failed == 0) ? 0 : 1;
}
