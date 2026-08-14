/**
 * @file test_rp_appraisal_marshaling.c
 * @brief Standalone tests for charra_marshal_rp_appraisal()/
 * charra_unmarshal_rp_appraisal() -- the wire format for the RP->Verifier
 * /appraise message (msg_rp_appraisal_dto in charra_dto.h): Attester's
 * Quote_a, RP's own Quote_r, both parties' AK certificates, and log_r.
 *
 * Covers round-tripping (marshal then unmarshal reproduces the original
 * DTO, including the ak_certificate/ak_certificate_rp fields being
 * empty -- the Attester's is empty on every live run today, see
 * CHARRA_V2_NOTES.md's "Temporary: Verifier accepts an empty Attester AK
 * certificate") and, matching test_certify_ak_marshaling.c's technique,
 * that oversized fixed-size fields are rejected rather than overflowing
 * their destination arrays -- hand-encoded with QCBOR directly, since the
 * normal encoder can't produce an oversized field (it reads from the same
 * fixed-size struct it's encoding into).
 *
 * Build and run:  make test_rp_appraisal_marshaling && ./bin/test_rp_appraisal_marshaling
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

static void test_round_trips(void) {
    printf("\nmsg_rp_appraisal_dto survives marshal -> unmarshal unchanged\n");

    msg_rp_appraisal_dto req = {0};

    req.attestation_data_len = sizeof(req.attestation_data);
    memset(req.attestation_data, 0x11, req.attestation_data_len);
    req.tpm2_signature_len = sizeof(req.tpm2_signature);
    memset(req.tpm2_signature, 0x12, req.tpm2_signature_len);
    req.tpm2_public_key_len = sizeof(req.tpm2_public_key);
    memset(req.tpm2_public_key, 0x13, req.tpm2_public_key_len);

    uint8_t ak_cert[900];
    memset(ak_cert, 0x14, sizeof(ak_cert));
    req.ak_certificate = ak_cert;
    req.ak_certificate_len = sizeof(ak_cert);

    req.attestation_data_rp_len = sizeof(req.attestation_data_rp);
    memset(req.attestation_data_rp, 0x21, req.attestation_data_rp_len);
    req.tpm2_signature_rp_len = sizeof(req.tpm2_signature_rp);
    memset(req.tpm2_signature_rp, 0x22, req.tpm2_signature_rp_len);
    req.tpm2_public_key_rp_len = sizeof(req.tpm2_public_key_rp);
    memset(req.tpm2_public_key_rp, 0x23, req.tpm2_public_key_rp_len);

    uint8_t ak_cert_rp[950];
    memset(ak_cert_rp, 0x24, sizeof(ak_cert_rp));
    req.ak_certificate_rp = ak_cert_rp;
    req.ak_certificate_rp_len = sizeof(ak_cert_rp);

    uint8_t event_log[4096];
    memset(event_log, 0x31, sizeof(event_log));
    req.event_log = event_log;
    req.event_log_len = sizeof(event_log);

    uint32_t marshaled_len = 0;
    uint8_t* marshaled = NULL;
    CHARRA_RC rc =
            charra_marshal_rp_appraisal(&req, &marshaled_len, &marshaled);
    check("marshaling succeeds", rc == CHARRA_RC_SUCCESS);

    msg_rp_appraisal_dto res = {0};
    rc = charra_unmarshal_rp_appraisal(marshaled_len, marshaled, &res);
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
    check("ak_certificate round-trips",
            res.ak_certificate_len == req.ak_certificate_len &&
                    memcmp(res.ak_certificate, req.ak_certificate,
                            req.ak_certificate_len) == 0);
    check("attestation_data_rp round-trips",
            res.attestation_data_rp_len == req.attestation_data_rp_len &&
                    memcmp(res.attestation_data_rp, req.attestation_data_rp,
                            req.attestation_data_rp_len) == 0);
    check("tpm2_signature_rp round-trips",
            res.tpm2_signature_rp_len == req.tpm2_signature_rp_len &&
                    memcmp(res.tpm2_signature_rp, req.tpm2_signature_rp,
                            req.tpm2_signature_rp_len) == 0);
    check("tpm2_public_key_rp round-trips",
            res.tpm2_public_key_rp_len == req.tpm2_public_key_rp_len &&
                    memcmp(res.tpm2_public_key_rp, req.tpm2_public_key_rp,
                            req.tpm2_public_key_rp_len) == 0);
    check("ak_certificate_rp round-trips",
            res.ak_certificate_rp_len == req.ak_certificate_rp_len &&
                    memcmp(res.ak_certificate_rp, req.ak_certificate_rp,
                            req.ak_certificate_rp_len) == 0);
    check("event_log round-trips",
            res.event_log_len == req.event_log_len &&
                    memcmp(res.event_log, req.event_log,
                            req.event_log_len) == 0);

    free(marshaled);
    free(res.ak_certificate);
    free(res.ak_certificate_rp);
    free(res.event_log);
}

static void test_empty_ak_certificate_accepted(void) {
    printf("\na zero-length ak_certificate is accepted, not crashed on -- "
           "this is what every live run hits today, since the Attester has "
           "no /certify_ak client yet (see CHARRA_V2_NOTES.md)\n");

    msg_rp_appraisal_dto req = {0};
    req.attestation_data_len = 8;
    req.tpm2_signature_len = 8;
    req.tpm2_public_key_len = 8;
    /* ak_certificate/ak_certificate_len left zeroed -- the empty case */
    req.attestation_data_rp_len = 8;
    req.tpm2_signature_rp_len = 8;
    req.tpm2_public_key_rp_len = 8;
    uint8_t ak_cert_rp[16] = {0};
    req.ak_certificate_rp = ak_cert_rp;
    req.ak_certificate_rp_len = sizeof(ak_cert_rp);
    uint8_t event_log[16] = {0};
    req.event_log = event_log;
    req.event_log_len = sizeof(event_log);

    uint32_t marshaled_len = 0;
    uint8_t* marshaled = NULL;
    CHARRA_RC rc =
            charra_marshal_rp_appraisal(&req, &marshaled_len, &marshaled);
    check("marshaling a zero-length ak_certificate succeeds",
            rc == CHARRA_RC_SUCCESS);

    msg_rp_appraisal_dto res = {0};
    rc = charra_unmarshal_rp_appraisal(marshaled_len, marshaled, &res);
    check("unmarshaling succeeds", rc == CHARRA_RC_SUCCESS);
    check("ak_certificate_len is 0", res.ak_certificate_len == 0);

    free(marshaled);
    free(res.ak_certificate);
    free(res.ak_certificate_rp);
    free(res.event_log);
}

/** Hand-encodes the 9-byte-string array msg_rp_appraisal_dto's wire format
 * uses, bypassing the DTO-based encoder the same way
 * test_certify_ak_marshaling.c's encode_raw_*() helpers do -- lets a single
 * field be made oversized without the normal encoder rejecting it first
 * (it reads from the same fixed-size struct it would be encoding into). */
static void encode_raw(const uint8_t* attestation_data, size_t attestation_data_len,
        const uint8_t* tpm2_signature, size_t tpm2_signature_len,
        const uint8_t* tpm2_public_key, size_t tpm2_public_key_len,
        const uint8_t* ak_certificate, size_t ak_certificate_len,
        const uint8_t* attestation_data_rp, size_t attestation_data_rp_len,
        const uint8_t* tpm2_signature_rp, size_t tpm2_signature_rp_len,
        const uint8_t* tpm2_public_key_rp, size_t tpm2_public_key_rp_len,
        const uint8_t* ak_certificate_rp, size_t ak_certificate_rp_len,
        const uint8_t* event_log, size_t event_log_len, uint8_t** out,
        size_t* out_len) {
    size_t cap = attestation_data_len + tpm2_signature_len +
            tpm2_public_key_len + ak_certificate_len +
            attestation_data_rp_len + tpm2_signature_rp_len +
            tpm2_public_key_rp_len + ak_certificate_rp_len + event_log_len +
            128;
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
    QCBOREncode_AddBytes(&ec,
            (UsefulBufC){.ptr = ak_certificate, .len = ak_certificate_len});
    QCBOREncode_AddBytes(&ec,
            (UsefulBufC){.ptr = attestation_data_rp,
                    .len = attestation_data_rp_len});
    QCBOREncode_AddBytes(&ec,
            (UsefulBufC){.ptr = tpm2_signature_rp,
                    .len = tpm2_signature_rp_len});
    QCBOREncode_AddBytes(&ec,
            (UsefulBufC){.ptr = tpm2_public_key_rp,
                    .len = tpm2_public_key_rp_len});
    QCBOREncode_AddBytes(&ec,
            (UsefulBufC){.ptr = ak_certificate_rp,
                    .len = ak_certificate_rp_len});
    QCBOREncode_AddBytes(
            &ec, (UsefulBufC){.ptr = event_log, .len = event_log_len});
    QCBOREncode_CloseArray(&ec);

    UsefulBufC buf_out = {0};
    QCBOREncode_Finish(&ec, &buf_out);
    *out = buf;
    *out_len = buf_out.len;
}

static void test_oversized_tpm2_public_key_rejected(void) {
    printf("\na tpm2_public_key (Quote_a's) one byte over its max size is "
           "rejected, not overflowed -- the exact field the original "
           "unbounded-memcpy audit finding was about\n");

    uint8_t small[8] = {0};
    uint8_t oversized[sizeof(((msg_rp_appraisal_dto*)0)->tpm2_public_key) +
            1];
    memset(oversized, 0x41, sizeof(oversized));

    uint8_t* raw = NULL;
    size_t raw_len = 0;
    encode_raw(small, sizeof(small), small, sizeof(small), oversized,
            sizeof(oversized), small, sizeof(small), small, sizeof(small),
            small, sizeof(small), small, sizeof(small), small, sizeof(small),
            small, sizeof(small), &raw, &raw_len);

    msg_rp_appraisal_dto res = {0};
    CHARRA_RC rc = charra_unmarshal_rp_appraisal((uint32_t)raw_len, raw, &res);
    check("rejected with CHARRA_RC_MARSHALING_ERROR",
            rc == CHARRA_RC_MARSHALING_ERROR);

    free(raw);
    free(res.ak_certificate);
    free(res.ak_certificate_rp);
    free(res.event_log);
}

static void test_oversized_attestation_data_rejected(void) {
    printf("\nan attestation_data (Quote_a's) one byte over its max size is "
           "rejected, not overflowed\n");

    uint8_t small[8] = {0};
    uint8_t oversized[sizeof(((msg_rp_appraisal_dto*)0)->attestation_data) +
            1];
    memset(oversized, 0x42, sizeof(oversized));

    uint8_t* raw = NULL;
    size_t raw_len = 0;
    encode_raw(oversized, sizeof(oversized), small, sizeof(small), small,
            sizeof(small), small, sizeof(small), small, sizeof(small), small,
            sizeof(small), small, sizeof(small), small, sizeof(small), small,
            sizeof(small), &raw, &raw_len);

    msg_rp_appraisal_dto res = {0};
    CHARRA_RC rc = charra_unmarshal_rp_appraisal((uint32_t)raw_len, raw, &res);
    check("rejected with CHARRA_RC_MARSHALING_ERROR",
            rc == CHARRA_RC_MARSHALING_ERROR);

    free(raw);
    free(res.ak_certificate);
    free(res.ak_certificate_rp);
    free(res.event_log);
}

static void test_oversized_tpm2_signature_rp_rejected(void) {
    printf("\na tpm2_signature_rp (RP's own Quote_r) one byte over its max "
           "size is rejected, not overflowed -- covers the '_rp' side of "
           "the DTO, not just the Attester-facing fields above\n");

    uint8_t small[8] = {0};
    uint8_t oversized
            [sizeof(((msg_rp_appraisal_dto*)0)->tpm2_signature_rp) + 1];
    memset(oversized, 0x43, sizeof(oversized));

    uint8_t* raw = NULL;
    size_t raw_len = 0;
    encode_raw(small, sizeof(small), small, sizeof(small), small,
            sizeof(small), small, sizeof(small), small, sizeof(small),
            oversized, sizeof(oversized), small, sizeof(small), small,
            sizeof(small), small, sizeof(small), &raw, &raw_len);

    msg_rp_appraisal_dto res = {0};
    CHARRA_RC rc = charra_unmarshal_rp_appraisal((uint32_t)raw_len, raw, &res);
    check("rejected with CHARRA_RC_MARSHALING_ERROR",
            rc == CHARRA_RC_MARSHALING_ERROR);

    free(raw);
    free(res.ak_certificate);
    free(res.ak_certificate_rp);
    free(res.event_log);
}

int main(void) {
    printf("msg_rp_appraisal_dto marshaling tests\n");
    printf("================================================\n");

    test_round_trips();
    test_empty_ak_certificate_accepted();
    test_oversized_tpm2_public_key_rejected();
    test_oversized_attestation_data_rejected();
    test_oversized_tpm2_signature_rp_rejected();

    printf("\n================================================\n");
    printf("%u tests, %u failed\n", tests_run, tests_failed);

    return (tests_failed == 0) ? 0 : 1;
}
