/**
 * @file test_marshaling_bounds.c
 * @brief Standalone tests for the bounds checks in
 * charra_unmarshal_attestation_response() (attestation_data/tpm2_signature/
 * tpm2_public_key) and charra_unmarshal_attestation_request() (key ID,
 * nonce, and the two nested PCR-selection array lengths).
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
 * @brief Hand-encode the same 5-byte-string root array
 * charra_marshal_attestation_response() produces, but from raw buffers
 * instead of a msg_attestation_response_dto -- so a field can be made
 * larger than its struct destination allows, which the DTO-based encoder
 * can never do. ak_certificate/ak_certificate_len may be NULL/0 -- none of
 * this file's tests exercise that field's own bounds (it has none, same as
 * event_log).
 */
static void encode_raw(const uint8_t* attestation_data, size_t attestation_data_len,
        const uint8_t* tpm2_signature, size_t tpm2_signature_len,
        const uint8_t* tpm2_public_key, size_t tpm2_public_key_len,
        const uint8_t* event_log, size_t event_log_len,
        const uint8_t* ak_certificate, size_t ak_certificate_len,
        uint8_t** out, size_t* out_len) {
    size_t cap = attestation_data_len + tpm2_signature_len +
            tpm2_public_key_len + event_log_len + ak_certificate_len + 64;
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
    QCBOREncode_AddBytes(&ec,
            (UsefulBufC){.ptr = ak_certificate, .len = ak_certificate_len});
    /* ak-certificate-attester-by-rp -- always empty, none of this file's
     * tests exercise it */
    QCBOREncode_AddBytes(&ec, (UsefulBufC){.ptr = NULL, .len = 0});
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
            sizeof(small), NULL, 0, NULL, 0, &raw, &raw_len);

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
            sizeof(small), NULL, 0, NULL, 0, &raw, &raw_len);

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
            sizeof(oversized), NULL, 0, NULL, 0, &raw, &raw_len);

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
            big_event_log, sizeof(big_event_log), NULL, 0, &raw, &raw_len);

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


/* --- attestation REQUEST bounds -----------------------------------------
 *
 * Same class of bug as the response tests above, on the message the
 * Verifier's /nonce and the Attester's /attest both decode -- and reachable
 * without any credential, since it is parsed before anything is verified.
 * All four fields below were copied out with no length check at all, into a
 * stack-allocated msg_attestation_request_dto. */

/**
 * @brief Hand-encode the 5-element root array
 * charra_marshal_attestation_request() produces, from raw buffers rather
 * than a DTO, so a field can be made larger than its destination allows.
 * pcr_banks/pcrs_per_bank control the two nested array lengths.
 */
static void encode_raw_request(const uint8_t* key_id, size_t key_id_len,
        const uint8_t* nonce, size_t nonce_len, size_t pcr_banks,
        size_t pcrs_per_bank, uint8_t** out, size_t* out_len) {
    size_t cap = key_id_len + nonce_len +
            (pcr_banks * (pcrs_per_bank + 8)) + 128;
    uint8_t* buf = malloc(cap);

    QCBOREncodeContext ec = {0};
    QCBOREncode_Init(&ec, (UsefulBuf){.ptr = buf, .len = cap});
    QCBOREncode_OpenArray(&ec);
    QCBOREncode_AddBool(&ec, true);
    QCBOREncode_AddBytes(&ec, (UsefulBufC){.ptr = key_id, .len = key_id_len});
    QCBOREncode_AddBytes(&ec, (UsefulBufC){.ptr = nonce, .len = nonce_len});
    QCBOREncode_OpenArray(&ec);
    for (size_t i = 0; i < pcr_banks; ++i) {
        QCBOREncode_OpenArray(&ec);
        QCBOREncode_AddUInt64(&ec, 0x000B); /* TPM2_ALG_SHA256 */
        QCBOREncode_OpenArray(&ec);
        for (size_t j = 0; j < pcrs_per_bank; ++j) {
            QCBOREncode_AddUInt64(&ec, j);
        }
        QCBOREncode_CloseArray(&ec);
        QCBOREncode_CloseArray(&ec);
    }
    QCBOREncode_CloseArray(&ec);
    QCBOREncode_AddBytes(&ec, (UsefulBufC){.ptr = NULL, .len = 0});
    QCBOREncode_CloseArray(&ec);

    UsefulBufC buf_out = {0};
    QCBOREncode_Finish(&ec, &buf_out);
    *out = buf;
    *out_len = buf_out.len;
}

static void check_request_rejected(const char* name, const uint8_t* key_id,
        size_t key_id_len, const uint8_t* nonce, size_t nonce_len,
        size_t pcr_banks, size_t pcrs_per_bank) {
    uint8_t* raw = NULL;
    size_t raw_len = 0;
    encode_raw_request(key_id, key_id_len, nonce, nonce_len, pcr_banks,
            pcrs_per_bank, &raw, &raw_len);

    msg_attestation_request_dto res = {0};
    CHARRA_RC rc =
            charra_unmarshal_attestation_request((uint32_t)raw_len, raw, &res);
    check(name, rc == CHARRA_RC_MARSHALING_ERROR);

    free(raw);
    free(res.event_log_path);
}

static void test_request_at_exact_boundary_accepted(void) {
    printf("\na request with every field at exactly its max size is accepted\n");

    msg_attestation_request_dto probe = {0};
    uint8_t key_id[sizeof(probe.sig_key_id)];
    memset(key_id, 0x5A, sizeof(key_id));
    uint8_t nonce[sizeof(probe.nonce)];
    memset(nonce, 0xA5, sizeof(nonce));
    const size_t max_banks =
            sizeof(probe.pcr_selections) / sizeof(probe.pcr_selections[0]);
    const size_t max_pcrs = sizeof(probe.pcr_selections[0].pcrs);

    uint8_t* raw = NULL;
    size_t raw_len = 0;
    encode_raw_request(key_id, sizeof(key_id), nonce, sizeof(nonce), max_banks,
            max_pcrs, &raw, &raw_len);

    msg_attestation_request_dto res = {0};
    CHARRA_RC rc =
            charra_unmarshal_attestation_request((uint32_t)raw_len, raw, &res);
    check("accepted", rc == CHARRA_RC_SUCCESS);
    check("key ID round-trips",
            res.sig_key_id_len == sizeof(key_id) &&
                    memcmp(res.sig_key_id, key_id, sizeof(key_id)) == 0);
    check("nonce round-trips",
            res.nonce_len == sizeof(nonce) &&
                    memcmp(res.nonce, nonce, sizeof(nonce)) == 0);
    check("PCR selections round-trip", res.pcr_selections_len == max_banks &&
                                               res.pcr_selections[0].pcrs_len ==
                                                       max_pcrs);

    free(raw);
    free(res.event_log_path);
}

static void test_oversized_request_key_id_rejected(void) {
    printf("\na key ID one byte over its max size is rejected, not overflowed\n");

    uint8_t oversized[sizeof(((msg_attestation_request_dto*)0)->sig_key_id) + 1];
    memset(oversized, 0x41, sizeof(oversized));
    uint8_t nonce[8] = {0};
    check_request_rejected("rejected with CHARRA_RC_MARSHALING_ERROR",
            oversized, sizeof(oversized), nonce, sizeof(nonce), 1, 4);
}

static void test_oversized_request_nonce_rejected(void) {
    printf("\na nonce one byte over its max size is rejected, not overflowed\n");

    uint8_t key_id[8] = {0};
    uint8_t oversized[sizeof(((msg_attestation_request_dto*)0)->nonce) + 1];
    memset(oversized, 0x42, sizeof(oversized));
    check_request_rejected("rejected with CHARRA_RC_MARSHALING_ERROR", key_id,
            sizeof(key_id), oversized, sizeof(oversized), 1, 4);
}

static void test_too_many_pcr_selections_rejected(void) {
    printf("\none PCR selection too many is rejected, not overflowed\n");

    msg_attestation_request_dto probe = {0};
    uint8_t key_id[8] = {0};
    uint8_t nonce[8] = {0};
    check_request_rejected("rejected with CHARRA_RC_MARSHALING_ERROR", key_id,
            sizeof(key_id), nonce, sizeof(nonce),
            (sizeof(probe.pcr_selections) / sizeof(probe.pcr_selections[0])) + 1,
            4);
}

static void test_too_many_pcrs_per_selection_rejected(void) {
    printf("\none PCR too many inside a selection is rejected, not overflowed\n");

    msg_attestation_request_dto probe = {0};
    uint8_t key_id[8] = {0};
    uint8_t nonce[8] = {0};
    check_request_rejected("rejected with CHARRA_RC_MARSHALING_ERROR", key_id,
            sizeof(key_id), nonce, sizeof(nonce), 1,
            sizeof(probe.pcr_selections[0].pcrs) + 1);
}

int main(void) {
    printf("Attestation message marshaling bounds-check tests\n");
    printf("====================================================\n");

    test_legitimate_message_at_exact_boundary_size();
    test_oversized_attestation_data_rejected();
    test_oversized_tpm2_signature_rejected();
    test_oversized_tpm2_public_key_rejected();
    test_large_event_log_still_accepted();
    test_request_at_exact_boundary_accepted();
    test_oversized_request_key_id_rejected();
    test_oversized_request_nonce_rejected();
    test_too_many_pcr_selections_rejected();
    test_too_many_pcrs_per_selection_rejected();

    printf("\n====================================================\n");
    printf("%u tests, %u failed\n", tests_run, tests_failed);

    return (tests_failed == 0) ? 0 : 1;
}
