/**
 * @file test_marshaling_bounds.c
 * @brief Standalone tests for charra_unmarshal_attestation_response()'s
 * bounds checks on attestation_data/tpm2_signature/tpm2_public_key.
 *
 * Before the fix, these three fields were memcpy'd out of attacker-supplied
 * CBOR byte strings straight into fixed-size struct fields with no length
 * check -- an oversized field would overflow msg_attestation_response_dto.
 * This builds malformed CBOR directly with QCBOR (bypassing the normal
 * encoder, which can't produce an oversized field since it reads its input
 * from the same fixed-size struct) to confirm oversized fields are now
 * rejected rather than overflowing.
 *
 * Build and run:  make test_marshaling_bounds && ./bin/test_marshaling_bounds
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

/**
 * @brief Hand-encode the same 4-byte-string root array
 * charra_marshal_attestation_response() produces, but from raw buffers
 * instead of a msg_attestation_response_dto -- so a field can be made
 * larger than its struct destination allows, which the DTO-based encoder
 * can never do.
 */
static void encode_raw(const uint8_t* attestation_data, size_t attestation_data_len,
        const uint8_t* tpm2_signature, size_t tpm2_signature_len,
        const uint8_t* tpm2_public_key, size_t tpm2_public_key_len,
        const uint8_t* event_log, size_t event_log_len, uint8_t** out,
        size_t* out_len) {
    size_t cap = attestation_data_len + tpm2_signature_len +
            tpm2_public_key_len + event_log_len + 64;
    uint8_t* buf = malloc(cap);

    QCBOREncodeContext ec = {0};
    UsefulBuf buf_in = {.ptr = buf, .len = cap};
    QCBOREncode_Init(&ec, buf_in);
    QCBOREncode_OpenArray(&ec);
    QCBOREncode_AddBytes(&ec,
            (UsefulBufC){.ptr = attestation_data, .len = attestation_data_len});
    QCBOREncode_AddBytes(&ec,
            (UsefulBufC){.ptr = tpm2_signature, .len = tpm2_signature_len});
    QCBOREncode_AddBytes(&ec,
            (UsefulBufC){.ptr = tpm2_public_key, .len = tpm2_public_key_len});
    QCBOREncode_AddBytes(
            &ec, (UsefulBufC){.ptr = event_log, .len = event_log_len});
    QCBOREncode_CloseArray(&ec);

    UsefulBufC buf_out = {0};
    QCBOREncode_Finish(&ec, &buf_out);
    *out = buf;
    *out_len = buf_out.len;
}

static void test_legitimate_message_at_exact_boundary_size(void) {
    printf("\nfields at exactly their max allowed size round-trip successfully\n");
    printf("(this is what a genuine Attester sends -- attester.c uses attest_buf->size,\n");
    printf(" which is bounded by sizeof(TPMS_ATTEST); see charra_marshaling.c bounds checks)\n");

    msg_attestation_response_dto req = {0};
    req.attestation_data_len = sizeof(req.attestation_data);
    memset(req.attestation_data, 0xAB, req.attestation_data_len);
    req.tpm2_signature_len = sizeof(req.tpm2_signature);
    memset(req.tpm2_signature, 0xCD, req.tpm2_signature_len);
    req.tpm2_public_key_len = sizeof(req.tpm2_public_key);
    memset(req.tpm2_public_key, 0xEF, req.tpm2_public_key_len);
    uint8_t event_log[16];
    memset(event_log, 0x11, sizeof(event_log));
    req.event_log_len = sizeof(event_log);
    req.event_log = event_log;

    uint32_t marshaled_len = 0;
    uint8_t* marshaled = NULL;
    CHARRA_RC rc =
            charra_marshal_attestation_response(&req, &marshaled_len, &marshaled);
    check("marshaling succeeds", rc == CHARRA_RC_SUCCESS);

    msg_attestation_response_dto res = {0};
    rc = charra_unmarshal_attestation_response(marshaled_len, marshaled, &res);
    check("unmarshaling succeeds", rc == CHARRA_RC_SUCCESS);
    check("attestation_data round-trips",
            res.attestation_data_len == req.attestation_data_len &&
                    memcmp(res.attestation_data, req.attestation_data,
                            req.attestation_data_len) == 0);
    check("tpm2_signature round-trips",
            res.tpm2_signature_len == req.tpm2_signature_len &&
                    memcmp(res.tpm2_signature, req.tpm2_signature,
                            req.tpm2_signature_len) == 0);
    check("tpm2_public_key round-trips",
            res.tpm2_public_key_len == req.tpm2_public_key_len &&
                    memcmp(res.tpm2_public_key, req.tpm2_public_key,
                            req.tpm2_public_key_len) == 0);

    free(marshaled);
    free(res.event_log);
}

static void test_oversized_attestation_data_rejected(void) {
    printf("\nattestation_data one byte over its max size is rejected, not overflowed\n");

    uint8_t oversized[sizeof(((msg_attestation_response_dto*)0)->attestation_data) + 1];
    memset(oversized, 0x41, sizeof(oversized));
    uint8_t small[8] = {0};

    uint8_t* raw = NULL;
    size_t raw_len = 0;
    encode_raw(oversized, sizeof(oversized), small, sizeof(small), small,
            sizeof(small), NULL, 0, &raw, &raw_len);

    msg_attestation_response_dto res = {0};
    CHARRA_RC rc = charra_unmarshal_attestation_response(
            (uint32_t)raw_len, raw, &res);
    check("rejected with CHARRA_RC_MARSHALING_ERROR",
            rc == CHARRA_RC_MARSHALING_ERROR);

    free(raw);
    free(res.event_log);
}

static void test_oversized_tpm2_signature_rejected(void) {
    printf("\ntpm2_signature one byte over its max size is rejected, not overflowed\n");

    uint8_t small[8] = {0};
    uint8_t oversized[sizeof(((msg_attestation_response_dto*)0)->tpm2_signature) + 1];
    memset(oversized, 0x42, sizeof(oversized));

    uint8_t* raw = NULL;
    size_t raw_len = 0;
    encode_raw(small, sizeof(small), oversized, sizeof(oversized), small,
            sizeof(small), NULL, 0, &raw, &raw_len);

    msg_attestation_response_dto res = {0};
    CHARRA_RC rc = charra_unmarshal_attestation_response(
            (uint32_t)raw_len, raw, &res);
    check("rejected with CHARRA_RC_MARSHALING_ERROR",
            rc == CHARRA_RC_MARSHALING_ERROR);

    free(raw);
    free(res.event_log);
}

static void test_oversized_tpm2_public_key_rejected(void) {
    printf("\ntpm2_public_key one byte over its max size is rejected, not overflowed\n");

    uint8_t small[8] = {0};
    uint8_t oversized[sizeof(((msg_attestation_response_dto*)0)->tpm2_public_key) + 1];
    memset(oversized, 0x43, sizeof(oversized));

    uint8_t* raw = NULL;
    size_t raw_len = 0;
    encode_raw(small, sizeof(small), small, sizeof(small), oversized,
            sizeof(oversized), NULL, 0, &raw, &raw_len);

    msg_attestation_response_dto res = {0};
    CHARRA_RC rc = charra_unmarshal_attestation_response(
            (uint32_t)raw_len, raw, &res);
    check("rejected with CHARRA_RC_MARSHALING_ERROR",
            rc == CHARRA_RC_MARSHALING_ERROR);

    free(raw);
    free(res.event_log);
}

static void test_large_event_log_still_accepted(void) {
    printf("\nevent_log has no fixed-size destination, so a large one is still fine\n");
    printf("(it's heap-allocated in the unmarshaler, unlike the other three fields)\n");

    uint8_t small[8] = {0};
    uint8_t big_event_log[4096];
    memset(big_event_log, 0x55, sizeof(big_event_log));

    uint8_t* raw = NULL;
    size_t raw_len = 0;
    encode_raw(small, sizeof(small), small, sizeof(small), small, sizeof(small),
            big_event_log, sizeof(big_event_log), &raw, &raw_len);

    msg_attestation_response_dto res = {0};
    CHARRA_RC rc = charra_unmarshal_attestation_response(
            (uint32_t)raw_len, raw, &res);
    check("accepted", rc == CHARRA_RC_SUCCESS);
    check("event_log round-trips",
            res.event_log_len == sizeof(big_event_log) &&
                    memcmp(res.event_log, big_event_log, sizeof(big_event_log)) ==
                            0);

    free(raw);
    free(res.event_log);
}

int main(void) {
    printf("Attestation response marshaling bounds-check tests\n");
    printf("====================================================\n");

    test_legitimate_message_at_exact_boundary_size();
    test_oversized_attestation_data_rejected();
    test_oversized_tpm2_signature_rejected();
    test_oversized_tpm2_public_key_rejected();
    test_large_event_log_still_accepted();

    printf("\n====================================================\n");
    printf("%u tests, %u failed\n", tests_run, tests_failed);

    return (tests_failed == 0) ? 0 : 1;
}
