/**
 * @file test_certify_ak_marshaling.c
 * @brief Standalone tests for charra_marshal_certify_ak_request()/
 * charra_unmarshal_certify_ak_request() and the response-side equivalents
 * -- the wire format for the /certify_ak provisioning exchange (Verifier
 * acting as Privacy CA).
 *
 * Covers round-tripping (marshal then unmarshal reproduces the original
 * DTO) and, matching test_marshaling_bounds.c's technique, that oversized
 * fixed-size fields are rejected rather than overflowing their destination
 * arrays -- hand-encoded with QCBOR directly, since the normal encoder
 * can't produce an oversized field (it reads from the same fixed-size
 * struct it's encoding into).
 *
 * Build and run:  make test_certify_ak_marshaling && ./bin/test_certify_ak_marshaling
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

/* --- /certify_ak request -------------------------------------------------- */

static void test_request_round_trips(void) {
    printf("\n/certify_ak request survives marshal -> unmarshal unchanged\n");

    msg_certify_ak_request_dto req = {0};
    uint8_t ek_cert[900];
    memset(ek_cert, 0x11, sizeof(ek_cert));
    req.ek_certificate = ek_cert;
    req.ek_certificate_len = sizeof(ek_cert);
    req.ak_public_key_len = sizeof(req.ak_public_key);
    memset(req.ak_public_key, 0x22, req.ak_public_key_len);
    req.ak_name_len = sizeof(req.ak_name);
    memset(req.ak_name, 0x33, req.ak_name_len);

    uint32_t marshaled_len = 0;
    uint8_t* marshaled = NULL;
    CHARRA_RC rc =
            charra_marshal_certify_ak_request(&req, &marshaled_len, &marshaled);
    check("marshaling succeeds", rc == CHARRA_RC_SUCCESS);

    msg_certify_ak_request_dto res = {0};
    rc = charra_unmarshal_certify_ak_request(marshaled_len, marshaled, &res);
    check("unmarshaling succeeds", rc == CHARRA_RC_SUCCESS);

    check("ek_certificate round-trips",
            res.ek_certificate_len == req.ek_certificate_len &&
                    memcmp(res.ek_certificate, req.ek_certificate,
                            req.ek_certificate_len) == 0);
    check("ak_public_key round-trips",
            res.ak_public_key_len == req.ak_public_key_len &&
                    memcmp(res.ak_public_key, req.ak_public_key,
                            req.ak_public_key_len) == 0);
    check("ak_name round-trips",
            res.ak_name_len == req.ak_name_len &&
                    memcmp(res.ak_name, req.ak_name, req.ak_name_len) == 0);

    free(marshaled);
    free(res.ek_certificate);
}

static void test_request_empty_ek_certificate_accepted(void) {
    printf("\n/certify_ak request with a zero-length ek_certificate is "
           "accepted, not crashed on\n");

    msg_certify_ak_request_dto req = {0};
    req.ak_public_key_len = 4;
    req.ak_name_len = 4;

    uint32_t marshaled_len = 0;
    uint8_t* marshaled = NULL;
    CHARRA_RC rc =
            charra_marshal_certify_ak_request(&req, &marshaled_len, &marshaled);
    check("marshaling a zero-length ek_certificate succeeds",
            rc == CHARRA_RC_SUCCESS);

    msg_certify_ak_request_dto res = {0};
    rc = charra_unmarshal_certify_ak_request(marshaled_len, marshaled, &res);
    check("unmarshaling succeeds", rc == CHARRA_RC_SUCCESS);
    check("ek_certificate_len is 0", res.ek_certificate_len == 0);

    free(marshaled);
    free(res.ek_certificate);
}

/** Hand-encodes a 3-byte-string array with an oversized second field
 * (ak_public_key), bypassing the DTO-based encoder the same way
 * test_marshaling_bounds.c's encode_raw() does. */
static void encode_raw_request(const uint8_t* ek_cert, size_t ek_cert_len,
        const uint8_t* ak_pub, size_t ak_pub_len, const uint8_t* ak_name,
        size_t ak_name_len, uint8_t** out, size_t* out_len) {
    size_t cap = ek_cert_len + ak_pub_len + ak_name_len + 64;
    uint8_t* buf = malloc(cap);

    QCBOREncodeContext ec = {0};
    UsefulBuf buf_in = {.ptr = buf, .len = cap};
    QCBOREncode_Init(&ec, buf_in);
    QCBOREncode_OpenArray(&ec);
    QCBOREncode_AddBytes(
            &ec, (UsefulBufC){.ptr = ek_cert, .len = ek_cert_len});
    QCBOREncode_AddBytes(&ec, (UsefulBufC){.ptr = ak_pub, .len = ak_pub_len});
    QCBOREncode_AddBytes(
            &ec, (UsefulBufC){.ptr = ak_name, .len = ak_name_len});
    QCBOREncode_CloseArray(&ec);

    UsefulBufC buf_out = {0};
    QCBOREncode_Finish(&ec, &buf_out);
    *out = buf;
    *out_len = buf_out.len;
}

static void test_request_oversized_ak_public_key_rejected(void) {
    printf("\nan ak_public_key one byte over its max size is rejected, not "
           "overflowed\n");

    uint8_t small[8] = {0};
    uint8_t oversized[sizeof(((msg_certify_ak_request_dto*)0)->ak_public_key) +
            1];
    memset(oversized, 0x41, sizeof(oversized));

    uint8_t* raw = NULL;
    size_t raw_len = 0;
    encode_raw_request(small, sizeof(small), oversized, sizeof(oversized),
            small, sizeof(small), &raw, &raw_len);

    msg_certify_ak_request_dto res = {0};
    CHARRA_RC rc = charra_unmarshal_certify_ak_request(
            (uint32_t)raw_len, raw, &res);
    check("rejected with CHARRA_RC_MARSHALING_ERROR",
            rc == CHARRA_RC_MARSHALING_ERROR);

    free(raw);
    free(res.ek_certificate);
}

static void test_request_oversized_ak_name_rejected(void) {
    printf("\nan ak_name one byte over its max size is rejected, not "
           "overflowed\n");

    uint8_t small[8] = {0};
    uint8_t oversized[sizeof(((msg_certify_ak_request_dto*)0)->ak_name) + 1];
    memset(oversized, 0x42, sizeof(oversized));

    uint8_t* raw = NULL;
    size_t raw_len = 0;
    encode_raw_request(small, sizeof(small), small, sizeof(small), oversized,
            sizeof(oversized), &raw, &raw_len);

    msg_certify_ak_request_dto res = {0};
    CHARRA_RC rc = charra_unmarshal_certify_ak_request(
            (uint32_t)raw_len, raw, &res);
    check("rejected with CHARRA_RC_MARSHALING_ERROR",
            rc == CHARRA_RC_MARSHALING_ERROR);

    free(raw);
    free(res.ek_certificate);
}

/* --- /certify_ak response ------------------------------------------------- */

static void test_response_round_trips(void) {
    printf("\n/certify_ak response survives marshal -> unmarshal unchanged\n");

    msg_certify_ak_response_dto req = {0};
    req.credential_blob_len = sizeof(req.credential_blob);
    memset(req.credential_blob, 0x51, req.credential_blob_len);
    req.wrapped_secret_len = sizeof(req.wrapped_secret);
    memset(req.wrapped_secret, 0x52, req.wrapped_secret_len);
    memset(req.aes_gcm_nonce, 0x53, sizeof(req.aes_gcm_nonce));
    memset(req.aes_gcm_tag, 0x54, sizeof(req.aes_gcm_tag));
    uint8_t ak_cert[950];
    memset(ak_cert, 0x55, sizeof(ak_cert));
    req.ak_certificate = ak_cert;
    req.ak_certificate_len = sizeof(ak_cert);

    uint32_t marshaled_len = 0;
    uint8_t* marshaled = NULL;
    CHARRA_RC rc = charra_marshal_certify_ak_response(
            &req, &marshaled_len, &marshaled);
    check("marshaling succeeds", rc == CHARRA_RC_SUCCESS);

    msg_certify_ak_response_dto res = {0};
    rc = charra_unmarshal_certify_ak_response(marshaled_len, marshaled, &res);
    check("unmarshaling succeeds", rc == CHARRA_RC_SUCCESS);

    check("credential_blob round-trips",
            res.credential_blob_len == req.credential_blob_len &&
                    memcmp(res.credential_blob, req.credential_blob,
                            req.credential_blob_len) == 0);
    check("wrapped_secret round-trips",
            res.wrapped_secret_len == req.wrapped_secret_len &&
                    memcmp(res.wrapped_secret, req.wrapped_secret,
                            req.wrapped_secret_len) == 0);
    check("aes_gcm_nonce round-trips",
            memcmp(res.aes_gcm_nonce, req.aes_gcm_nonce,
                    sizeof(req.aes_gcm_nonce)) == 0);
    check("aes_gcm_tag round-trips",
            memcmp(res.aes_gcm_tag, req.aes_gcm_tag,
                    sizeof(req.aes_gcm_tag)) == 0);
    check("ak_certificate round-trips",
            res.ak_certificate_len == req.ak_certificate_len &&
                    memcmp(res.ak_certificate, req.ak_certificate,
                            req.ak_certificate_len) == 0);

    free(marshaled);
    free(res.ak_certificate);
}

static void encode_raw_response(const uint8_t* cred_blob, size_t cred_len,
        const uint8_t* secret, size_t secret_len, const uint8_t* nonce,
        size_t nonce_len, const uint8_t* tag, size_t tag_len,
        const uint8_t* ak_cert, size_t ak_cert_len, uint8_t** out,
        size_t* out_len) {
    size_t cap = cred_len + secret_len + nonce_len + tag_len + ak_cert_len +
            64;
    uint8_t* buf = malloc(cap);

    QCBOREncodeContext ec = {0};
    UsefulBuf buf_in = {.ptr = buf, .len = cap};
    QCBOREncode_Init(&ec, buf_in);
    QCBOREncode_OpenArray(&ec);
    QCBOREncode_AddBytes(
            &ec, (UsefulBufC){.ptr = cred_blob, .len = cred_len});
    QCBOREncode_AddBytes(&ec, (UsefulBufC){.ptr = secret, .len = secret_len});
    QCBOREncode_AddBytes(&ec, (UsefulBufC){.ptr = nonce, .len = nonce_len});
    QCBOREncode_AddBytes(&ec, (UsefulBufC){.ptr = tag, .len = tag_len});
    QCBOREncode_AddBytes(
            &ec, (UsefulBufC){.ptr = ak_cert, .len = ak_cert_len});
    QCBOREncode_CloseArray(&ec);

    UsefulBufC buf_out = {0};
    QCBOREncode_Finish(&ec, &buf_out);
    *out = buf;
    *out_len = buf_out.len;
}

static void test_response_oversized_credential_blob_rejected(void) {
    printf("\na credential_blob one byte over its max size is rejected, not "
           "overflowed\n");

    uint8_t small[8] = {0};
    uint8_t oversized
            [sizeof(((msg_certify_ak_response_dto*)0)->credential_blob) + 1];
    memset(oversized, 0x61, sizeof(oversized));

    uint8_t* raw = NULL;
    size_t raw_len = 0;
    encode_raw_response(oversized, sizeof(oversized), small, sizeof(small),
            small, 12, small, 16, small, sizeof(small), &raw, &raw_len);

    msg_certify_ak_response_dto res = {0};
    CHARRA_RC rc = charra_unmarshal_certify_ak_response(
            (uint32_t)raw_len, raw, &res);
    check("rejected with CHARRA_RC_MARSHALING_ERROR",
            rc == CHARRA_RC_MARSHALING_ERROR);

    free(raw);
    free(res.ak_certificate);
}

static void test_response_wrong_size_nonce_rejected(void) {
    printf("\nan aes_gcm_nonce of the wrong size (not just oversized) is "
           "rejected\n");

    uint8_t small[8] = {0};
    uint8_t wrong_size_nonce[11] = {0}; /* must be exactly 12 */

    uint8_t* raw = NULL;
    size_t raw_len = 0;
    encode_raw_response(small, sizeof(small), small, sizeof(small),
            wrong_size_nonce, sizeof(wrong_size_nonce), small, 16, small,
            sizeof(small), &raw, &raw_len);

    msg_certify_ak_response_dto res = {0};
    CHARRA_RC rc = charra_unmarshal_certify_ak_response(
            (uint32_t)raw_len, raw, &res);
    check("rejected with CHARRA_RC_MARSHALING_ERROR",
            rc == CHARRA_RC_MARSHALING_ERROR);

    free(raw);
    free(res.ak_certificate);
}

static void test_response_wrong_size_tag_rejected(void) {
    printf("\nan aes_gcm_tag of the wrong size (not just oversized) is "
           "rejected\n");

    uint8_t small[8] = {0};
    uint8_t nonce[12] = {0};
    uint8_t wrong_size_tag[17] = {0}; /* must be exactly 16 */

    uint8_t* raw = NULL;
    size_t raw_len = 0;
    encode_raw_response(small, sizeof(small), small, sizeof(small), nonce,
            sizeof(nonce), wrong_size_tag, sizeof(wrong_size_tag), small,
            sizeof(small), &raw, &raw_len);

    msg_certify_ak_response_dto res = {0};
    CHARRA_RC rc = charra_unmarshal_certify_ak_response(
            (uint32_t)raw_len, raw, &res);
    check("rejected with CHARRA_RC_MARSHALING_ERROR",
            rc == CHARRA_RC_MARSHALING_ERROR);

    free(raw);
    free(res.ak_certificate);
}

int main(void) {
    printf("/certify_ak request/response marshaling tests\n");
    printf("================================================\n");

    test_request_round_trips();
    test_request_empty_ek_certificate_accepted();
    test_request_oversized_ak_public_key_rejected();
    test_request_oversized_ak_name_rejected();
    test_response_round_trips();
    test_response_oversized_credential_blob_rejected();
    test_response_wrong_size_nonce_rejected();
    test_response_wrong_size_tag_rejected();

    printf("\n================================================\n");
    printf("%u tests, %u failed\n", tests_run, tests_failed);

    return (tests_failed == 0) ? 0 : 1;
}
