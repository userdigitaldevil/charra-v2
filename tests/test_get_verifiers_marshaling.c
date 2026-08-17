/**
 * @file test_get_verifiers_marshaling.c
 * @brief Standalone tests for charra_marshal_get_verifiers_request()/
 * charra_unmarshal_get_verifiers_request() and the response-side
 * equivalents -- the wire format for the RP<->Trust Manager /get_verifiers
 * exchange (msg_get_verifiers_request_dto / msg_get_verifiers_response_dto
 * in charra_dto.h).
 *
 * This replaced a hand-packed raw-byte layout that trust_manager.c and
 * relying_party.c each independently encoded/decoded with no shared code
 * and no test coverage -- exactly how a response_len miscalculation on the
 * Trust Manager side went unnoticed (see CHARRA_V2_NOTES.md). These tests
 * cover round-tripping (marshal then unmarshal reproduces the original
 * DTO, including a response with fewer verifiers than requested -- the
 * normal "some Verifier IDs missing from configuration" case) and, mirroring
 * test_certify_ak_marshaling.c's technique, that an oversized field/count
 * is rejected rather than overflowing its destination array -- hand-encoded
 * with QCBOR directly, since the normal encoder can't produce an oversized
 * field (it reads from the same fixed-size struct it's encoding into).
 *
 * Build and run:  make test_get_verifiers_marshaling && ./bin/test_get_verifiers_marshaling
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

/* --- /get_verifiers request ----------------------------------------------- */

static void test_request_round_trips(void) {
    printf("\n/get_verifiers request survives marshal -> unmarshal unchanged\n");

    msg_get_verifiers_request_dto req = {0};
    req.verifier_ids_len = 5;
    for (uint32_t i = 0; i < req.verifier_ids_len; ++i) {
        req.verifier_ids[i] = (int32_t)(i + 1);
    }

    uint32_t marshaled_len = 0;
    uint8_t* marshaled = NULL;
    CHARRA_RC rc = charra_marshal_get_verifiers_request(
            &req, &marshaled_len, &marshaled);
    check("marshaling succeeds", rc == CHARRA_RC_SUCCESS);

    msg_get_verifiers_request_dto res = {0};
    rc = charra_unmarshal_get_verifiers_request(marshaled_len, marshaled, &res);
    check("unmarshaling succeeds", rc == CHARRA_RC_SUCCESS);

    check("verifier_ids_len round-trips",
            res.verifier_ids_len == req.verifier_ids_len);
    check("verifier_ids round-trips",
            memcmp(res.verifier_ids, req.verifier_ids,
                    req.verifier_ids_len * sizeof(req.verifier_ids[0])) == 0);

    free(marshaled);
}

static void test_request_empty_accepted(void) {
    printf("\n/get_verifiers request with zero verifier_ids is accepted, "
           "not crashed on\n");

    msg_get_verifiers_request_dto req = {0};

    uint32_t marshaled_len = 0;
    uint8_t* marshaled = NULL;
    CHARRA_RC rc = charra_marshal_get_verifiers_request(
            &req, &marshaled_len, &marshaled);
    check("marshaling succeeds", rc == CHARRA_RC_SUCCESS);

    msg_get_verifiers_request_dto res = {0};
    rc = charra_unmarshal_get_verifiers_request(marshaled_len, marshaled, &res);
    check("unmarshaling succeeds", rc == CHARRA_RC_SUCCESS);
    check("verifier_ids_len is 0", res.verifier_ids_len == 0);

    free(marshaled);
}

static void test_request_oversized_id_count_rejected(void) {
    printf("\na verifier-ids array one entry over its max count is "
           "rejected, not overflowed\n");

    size_t cap = 4096;
    uint8_t* buf = malloc(cap);
    QCBOREncodeContext ec = {0};
    UsefulBuf buf_in = {.ptr = buf, .len = cap};
    QCBOREncode_Init(&ec, buf_in);
    QCBOREncode_OpenArray(&ec);
    QCBOREncode_OpenArray(&ec);
    for (int i = 0; i < CHARRA_MAX_REQUESTED_VERIFIERS + 1; ++i) {
        QCBOREncode_AddInt64(&ec, i);
    }
    QCBOREncode_CloseArray(&ec);
    QCBOREncode_CloseArray(&ec);
    UsefulBufC buf_out = {0};
    QCBOREncode_Finish(&ec, &buf_out);

    msg_get_verifiers_request_dto res = {0};
    CHARRA_RC rc = charra_unmarshal_get_verifiers_request(
            (uint32_t)buf_out.len, buf, &res);
    check("rejected with CHARRA_RC_MARSHALING_ERROR",
            rc == CHARRA_RC_MARSHALING_ERROR);

    free(buf);
}

/* --- /get_verifiers response ---------------------------------------------- */

static void test_response_round_trips(void) {
    printf("\n/get_verifiers response survives marshal -> unmarshal "
           "unchanged\n");

    msg_get_verifiers_response_dto req = {0};
    req.verifiers_len = 3;
    snprintf(req.verifiers[0].ip_address, sizeof(req.verifiers[0].ip_address),
            "127.0.0.1");
    req.verifiers[0].port_number = 5684;
    snprintf(req.verifiers[1].ip_address, sizeof(req.verifiers[1].ip_address),
            "192.168.1.42");
    req.verifiers[1].port_number = 5685;
    snprintf(req.verifiers[2].ip_address, sizeof(req.verifiers[2].ip_address),
            "10.0.0.1");
    req.verifiers[2].port_number = 65535;

    uint32_t marshaled_len = 0;
    uint8_t* marshaled = NULL;
    CHARRA_RC rc = charra_marshal_get_verifiers_response(
            &req, &marshaled_len, &marshaled);
    check("marshaling succeeds", rc == CHARRA_RC_SUCCESS);

    msg_get_verifiers_response_dto res = {0};
    rc = charra_unmarshal_get_verifiers_response(
            marshaled_len, marshaled, &res);
    check("unmarshaling succeeds", rc == CHARRA_RC_SUCCESS);

    check("verifiers_len round-trips", res.verifiers_len == req.verifiers_len);
    bool all_match = true;
    for (uint32_t i = 0; i < req.verifiers_len; ++i) {
        if (strcmp(res.verifiers[i].ip_address, req.verifiers[i].ip_address) !=
                        0 ||
                res.verifiers[i].port_number != req.verifiers[i].port_number) {
            all_match = false;
        }
    }
    check("every verifier's ip_address/port_number round-trips", all_match);

    free(marshaled);
}

static void test_response_fewer_than_requested_accepted(void) {
    printf("\n/get_verifiers response with zero verifiers (all requested "
           "IDs missing) is accepted, not crashed on -- the normal shape "
           "of a partial Trust Manager lookup\n");

    msg_get_verifiers_response_dto req = {0};

    uint32_t marshaled_len = 0;
    uint8_t* marshaled = NULL;
    CHARRA_RC rc = charra_marshal_get_verifiers_response(
            &req, &marshaled_len, &marshaled);
    check("marshaling succeeds", rc == CHARRA_RC_SUCCESS);

    msg_get_verifiers_response_dto res = {0};
    rc = charra_unmarshal_get_verifiers_response(
            marshaled_len, marshaled, &res);
    check("unmarshaling succeeds", rc == CHARRA_RC_SUCCESS);
    check("verifiers_len is 0", res.verifiers_len == 0);

    free(marshaled);
}

static void test_response_oversized_ip_address_rejected(void) {
    printf("\na Verifier ip_address one byte over its max size is "
           "rejected, not overflowed\n");

    uint8_t oversized_ip[CHARRA_VERIFIER_IP_MAXLEN + 1];
    memset(oversized_ip, 'A', sizeof(oversized_ip));

    size_t cap = 4096;
    uint8_t* buf = malloc(cap);
    QCBOREncodeContext ec = {0};
    UsefulBuf buf_in = {.ptr = buf, .len = cap};
    QCBOREncode_Init(&ec, buf_in);
    QCBOREncode_OpenArray(&ec);
    QCBOREncode_OpenArray(&ec);
    QCBOREncode_OpenArray(&ec);
    QCBOREncode_AddBytes(&ec,
            (UsefulBufC){.ptr = oversized_ip, .len = sizeof(oversized_ip)});
    QCBOREncode_AddUInt64(&ec, 5684);
    QCBOREncode_CloseArray(&ec);
    QCBOREncode_CloseArray(&ec);
    QCBOREncode_CloseArray(&ec);
    UsefulBufC buf_out = {0};
    QCBOREncode_Finish(&ec, &buf_out);

    msg_get_verifiers_response_dto res = {0};
    CHARRA_RC rc = charra_unmarshal_get_verifiers_response(
            (uint32_t)buf_out.len, buf, &res);
    check("rejected with CHARRA_RC_MARSHALING_ERROR",
            rc == CHARRA_RC_MARSHALING_ERROR);

    free(buf);
}

static void test_response_oversized_verifier_count_rejected(void) {
    printf("\na verifiers array one entry over its max count is rejected, "
           "not overflowed\n");

    size_t cap = 8192;
    uint8_t* buf = malloc(cap);
    QCBOREncodeContext ec = {0};
    UsefulBuf buf_in = {.ptr = buf, .len = cap};
    QCBOREncode_Init(&ec, buf_in);
    QCBOREncode_OpenArray(&ec);
    QCBOREncode_OpenArray(&ec);
    for (int i = 0; i < CHARRA_MAX_REQUESTED_VERIFIERS + 1; ++i) {
        QCBOREncode_OpenArray(&ec);
        QCBOREncode_AddBytes(&ec, (UsefulBufC){.ptr = "1.2.3.4", .len = 7});
        QCBOREncode_AddUInt64(&ec, 1000 + (unsigned)i);
        QCBOREncode_CloseArray(&ec);
    }
    QCBOREncode_CloseArray(&ec);
    QCBOREncode_CloseArray(&ec);
    UsefulBufC buf_out = {0};
    QCBOREncode_Finish(&ec, &buf_out);

    msg_get_verifiers_response_dto res = {0};
    CHARRA_RC rc = charra_unmarshal_get_verifiers_response(
            (uint32_t)buf_out.len, buf, &res);
    check("rejected with CHARRA_RC_MARSHALING_ERROR",
            rc == CHARRA_RC_MARSHALING_ERROR);

    free(buf);
}

int main(void) {
    printf("/get_verifiers request/response marshaling tests\n");
    printf("================================================\n");

    test_request_round_trips();
    test_request_empty_accepted();
    test_request_oversized_id_count_rejected();
    test_response_round_trips();
    test_response_fewer_than_requested_accepted();
    test_response_oversized_ip_address_rejected();
    test_response_oversized_verifier_count_rejected();

    printf("\n================================================\n");
    printf("%u tests, %u failed\n", tests_run, tests_failed);

    return (tests_failed == 0) ? 0 : 1;
}
