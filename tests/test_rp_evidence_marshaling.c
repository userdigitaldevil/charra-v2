/**
 * @file test_rp_evidence_marshaling.c
 * @brief Standalone tests for charra_marshal_rp_evidence()/
 * charra_unmarshal_rp_evidence() -- the RP->Verifier evidence message
 * (Quote_r + log_r + Quote_a + both AK certificates).
 *
 * This is the message that actually travels on every /appraise, yet it was
 * the one message type with no bounds-check test of its own:
 * tests/test_rp_appraisal_marshaling.c covers msg_rp_appraisal_dto, which
 * is dead code (nothing outside charra_marshaling.c and that test calls
 * it). Every fixed-size field here is memcpy'd into a fixed-size array from
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
    memset(ev.pcr_r, 0x11, sizeof(ev.pcr_r));
    ev.verifier_nonce_len = sizeof(ev.verifier_nonce);
    memset(ev.verifier_nonce, 0x22, ev.verifier_nonce_len);
    ev.rp_signature_len = sizeof(ev.rp_signature);
    memset(ev.rp_signature, 0x33, ev.rp_signature_len);
    ev.rp_public_key_len = sizeof(ev.rp_public_key);
    memset(ev.rp_public_key, 0x44, ev.rp_public_key_len);
    ev.attester_nonce_len = sizeof(ev.attester_nonce);
    memset(ev.attester_nonce, 0x55, ev.attester_nonce_len);
    ev.attestation_data_len = sizeof(ev.attestation_data);
    memset(ev.attestation_data, 0x66, ev.attestation_data_len);
    ev.tpm2_signature_len = sizeof(ev.tpm2_signature);
    memset(ev.tpm2_signature, 0x77, ev.tpm2_signature_len);
    ev.tpm2_public_key_len = sizeof(ev.tpm2_public_key);
    memset(ev.tpm2_public_key, 0x88, ev.tpm2_public_key_len);

    uint8_t ak_cert_rp[300];
    memset(ak_cert_rp, 0x99, sizeof(ak_cert_rp));
    ev.ak_certificate_rp = ak_cert_rp;
    ev.ak_certificate_rp_len = sizeof(ak_cert_rp);

    uint8_t ak_cert_v[280];
    memset(ak_cert_v, 0xAA, sizeof(ak_cert_v));
    ev.ak_certificate_attester_by_verifier = ak_cert_v;
    ev.ak_certificate_attester_by_verifier_len = sizeof(ak_cert_v);

    uint8_t ak_cert_rp_a[260];
    memset(ak_cert_rp_a, 0xBB, sizeof(ak_cert_rp_a));
    ev.ak_certificate_attester_by_rp = ak_cert_rp_a;
    ev.ak_certificate_attester_by_rp_len = sizeof(ak_cert_rp_a);

    uint8_t log_r[900];
    memset(log_r, 0xCC, sizeof(log_r));
    ev.log_r = log_r;
    ev.log_r_len = sizeof(log_r);

    memset(ev.tee_file_hash, 0xDD, sizeof(ev.tee_file_hash));
    memset(ev.tee_report_data, 0xEE, sizeof(ev.tee_report_data));
    ev.tee_signature_len = sizeof(ev.tee_signature);
    memset(ev.tee_signature, 0xFF, ev.tee_signature_len);
    ev.tee_public_key_len = sizeof(ev.tee_public_key);
    memset(ev.tee_public_key, 0x12, ev.tee_public_key_len);

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

    check("pcr_r round-trips",
            memcmp(res.pcr_r, ev.pcr_r, sizeof(ev.pcr_r)) == 0);
    check("verifier_nonce round-trips",
            res.verifier_nonce_len == ev.verifier_nonce_len &&
                    memcmp(res.verifier_nonce, ev.verifier_nonce,
                            ev.verifier_nonce_len) == 0);
    check("rp_signature round-trips",
            res.rp_signature_len == ev.rp_signature_len &&
                    memcmp(res.rp_signature, ev.rp_signature,
                            ev.rp_signature_len) == 0);
    check("rp_public_key round-trips",
            res.rp_public_key_len == ev.rp_public_key_len &&
                    memcmp(res.rp_public_key, ev.rp_public_key,
                            ev.rp_public_key_len) == 0);
    check("ak_certificate_rp round-trips",
            res.ak_certificate_rp_len == ev.ak_certificate_rp_len &&
                    memcmp(res.ak_certificate_rp, ev.ak_certificate_rp,
                            ev.ak_certificate_rp_len) == 0);
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
    check("ak_certificate_attester_by_verifier round-trips",
            res.ak_certificate_attester_by_verifier_len ==
                            ev.ak_certificate_attester_by_verifier_len &&
                    memcmp(res.ak_certificate_attester_by_verifier,
                            ev.ak_certificate_attester_by_verifier,
                            ev.ak_certificate_attester_by_verifier_len) == 0);
    check("ak_certificate_attester_by_rp round-trips",
            res.ak_certificate_attester_by_rp_len ==
                            ev.ak_certificate_attester_by_rp_len &&
                    memcmp(res.ak_certificate_attester_by_rp,
                            ev.ak_certificate_attester_by_rp,
                            ev.ak_certificate_attester_by_rp_len) == 0);
    check("log_r round-trips",
            res.log_r_len == ev.log_r_len &&
                    memcmp(res.log_r, ev.log_r, ev.log_r_len) == 0);
    check("tee_file_hash round-trips",
            memcmp(res.tee_file_hash, ev.tee_file_hash,
                    sizeof(ev.tee_file_hash)) == 0);
    check("tee_report_data round-trips",
            memcmp(res.tee_report_data, ev.tee_report_data,
                    sizeof(ev.tee_report_data)) == 0);
    check("tee_signature round-trips",
            res.tee_signature_len == ev.tee_signature_len &&
                    memcmp(res.tee_signature, ev.tee_signature,
                            ev.tee_signature_len) == 0);
    check("tee_public_key round-trips",
            res.tee_public_key_len == ev.tee_public_key_len &&
                    memcmp(res.tee_public_key, ev.tee_public_key,
                            ev.tee_public_key_len) == 0);

    free(marshaled);
}

/* An Attester that has not completed its provisioning legs sends empty
 * certificates -- a normal shape here, not an edge case, so it must parse
 * rather than be rejected or crash. */
static void test_empty_certificates_accepted(void) {
    printf("\nRP evidence with empty certificates and empty log_r parses\n");

    msg_rp_evidence_dto ev = {0};
    ev.verifier_nonce_len = 4;
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
    check("ak_certificate_rp_len is 0", res.ak_certificate_rp_len == 0);
    check("ak_certificate_attester_by_verifier_len is 0",
            res.ak_certificate_attester_by_verifier_len == 0);
    check("ak_certificate_attester_by_rp_len is 0",
            res.ak_certificate_attester_by_rp_len == 0);
    check("log_r_len is 0", res.log_r_len == 0);

    free(marshaled);
}

/* --- bounds -------------------------------------------------------------- */

/** One byte string per field, in the exact order
 * charra_marshal_rp_evidence_internal() encodes them, so any single field
 * can be made oversized while the rest stay valid. Indices 12/13
 * (tee_file_hash/tee_report_data) are exact-size fields, like pcr_r. */
typedef struct {
    const uint8_t* ptr;
    size_t len;
} raw_field;

#define RAW_FIELD_COUNT 16

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
static void fill_valid(raw_field f[RAW_FIELD_COUNT], const uint8_t* small,
        size_t small_len, const uint8_t* pcr, size_t pcr_len) {
    f[0].ptr = pcr;
    f[0].len = pcr_len; /* pcr_r -- exact size, not a cap */
    for (int i = 1; i < 12; i++) {
        f[i].ptr = small;
        f[i].len = small_len;
    }
    f[12].ptr = pcr;
    f[12].len = pcr_len; /* tee_file_hash -- exact size, not a cap */
    f[13].ptr = pcr;
    f[13].len = pcr_len; /* tee_report_data -- exact size, not a cap */
    f[14].ptr = small;
    f[14].len = small_len; /* tee_signature */
    f[15].ptr = small;
    f[15].len = small_len; /* tee_public_key */
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
        fill_valid(f, small, sizeof(small), pcr, sizeof(pcr));                 \
        f[idx].ptr = big;                                                      \
        f[idx].len = sizeof(big);                                              \
        expect_rejected("rejected with CHARRA_RC_MARSHALING_ERROR", f);        \
    } while (0)

static void test_oversized_fields_rejected(void) {
    uint8_t small[4] = {0};
    uint8_t pcr[TPM2_SHA256_DIGEST_SIZE] = {0};

    OVERSIZED_FIELD_TEST(1, verifier_nonce, "verifier_nonce");
    OVERSIZED_FIELD_TEST(2, rp_signature, "rp_signature");
    OVERSIZED_FIELD_TEST(3, rp_public_key, "rp_public_key");
    OVERSIZED_FIELD_TEST(5, attester_nonce, "attester_nonce");
    OVERSIZED_FIELD_TEST(6, attestation_data, "attestation_data");
    OVERSIZED_FIELD_TEST(7, tpm2_signature, "tpm2_signature");
    OVERSIZED_FIELD_TEST(8, tpm2_public_key, "tpm2_public_key");
    OVERSIZED_FIELD_TEST(14, tee_signature, "tee_signature");
    OVERSIZED_FIELD_TEST(15, tee_public_key, "tee_public_key");
}

/* pcr_r is checked for an EXACT length rather than a cap -- it is a SHA-256
 * digest, so a short one is as wrong as a long one. tee_file_hash and
 * tee_report_data are the same shape, so this table drives all three. */
static void test_wrong_size_exact_fields_rejected(void) {
    uint8_t small[4] = {0};

    static const struct {
        int idx;
        const char* label;
    } exact_fields[] = {
            {0, "pcr_r"},
            {12, "tee_file_hash"},
            {13, "tee_report_data"},
    };

    for (size_t i = 0; i < sizeof(exact_fields) / sizeof(exact_fields[0]);
            i++) {
        printf("\na %s of the wrong size (short or long) is rejected\n",
                exact_fields[i].label);

        uint8_t too_long[TPM2_SHA256_DIGEST_SIZE + 1];
        memset(too_long, 0x41, sizeof(too_long));
        raw_field f[RAW_FIELD_COUNT];
        uint8_t pcr[TPM2_SHA256_DIGEST_SIZE] = {0};
        fill_valid(f, small, sizeof(small), pcr, sizeof(pcr));
        f[exact_fields[i].idx].ptr = too_long;
        f[exact_fields[i].idx].len = sizeof(too_long);
        expect_rejected("oversized field rejected", f);

        uint8_t too_short[TPM2_SHA256_DIGEST_SIZE - 1];
        memset(too_short, 0x41, sizeof(too_short));
        fill_valid(f, small, sizeof(small), pcr, sizeof(pcr));
        f[exact_fields[i].idx].ptr = too_short;
        f[exact_fields[i].idx].len = sizeof(too_short);
        expect_rejected("undersized field rejected", f);
    }
}

/* A truncated array must fail rather than leave later fields uninitialised. */
static void test_truncated_message_rejected(void) {
    printf("\na message with too few fields is rejected\n");

    uint8_t small[4] = {0};
    uint8_t pcr[TPM2_SHA256_DIGEST_SIZE] = {0};
    (void)small; /* only pcr_r and one more field are encoded below */

    size_t cap = 256;
    uint8_t* buf = malloc(cap);
    QCBOREncodeContext ec = {0};
    QCBOREncode_Init(&ec, (UsefulBuf){.ptr = buf, .len = cap});
    QCBOREncode_OpenArray(&ec);
    QCBOREncode_AddBytes(&ec, (UsefulBufC){.ptr = pcr, .len = sizeof(pcr)});
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
    test_empty_certificates_accepted();
    test_oversized_fields_rejected();
    test_wrong_size_exact_fields_rejected();
    test_truncated_message_rejected();

    printf("\n================================================\n");
    printf("%u tests, %u failed\n", tests_run, tests_failed);

    return (tests_failed == 0) ? 0 : 1;
}
