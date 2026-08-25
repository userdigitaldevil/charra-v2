/**
 * @file test_message_marshaling.c
 * @brief Round-trip tests for the six wire messages that had none.
 *
 * `msg_rp_evidence_dto` and the two `/get_verifiers` messages already have
 * their own suites; this covers the rest of charra_marshaling.c:
 * `/attest` request and response, `/attest_result`, `/qualify` response,
 * and both halves of `/qualify_submit`.
 *
 * Every message is a positional CBOR array with no labels, so field ORDER
 * is the schema. A marshaller and unmarshaller that disagree about order
 * still round-trip within one process -- these tests would not catch that
 * on their own -- but they do catch a field dropped from one side, a
 * length written without its bytes, and a bound checked against the wrong
 * sizeof. Cross-version compatibility is not a goal here: both ends are
 * built from this tree.
 *
 * Build and run:  make test_message_marshaling && ./bin/test_message_marshaling
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

/** Fills a buffer with a recognisable, position-dependent pattern, so a
 * field copied from the wrong offset does not accidentally match. */
static void fill(uint8_t* buf, size_t len, uint8_t seed) {
    for (size_t i = 0; i < len; ++i) {
        buf[i] = (uint8_t)(seed + i * 7u);
    }
}

/* --- /attest request ---------------------------------------------------- */

static void test_attestation_request(void) {
    printf("\nmsg_attestation_request_dto round-trips\n");

    msg_attestation_request_dto req = {0};
    req.hello = true;
    req.sig_key_id_len = 8;
    memcpy(req.sig_key_id, "attester", 8);
    req.nonce_len = 20;
    fill(req.nonce, req.nonce_len, 0x41);
    req.pcr_selections_len = 1;
    req.pcr_selections[0].tcg_hash_alg_id = TPM2_ALG_SHA256;
    req.pcr_selections[0].pcrs_len = 9;
    const uint8_t pcrs[] = {0, 1, 2, 3, 4, 5, 6, 7, 10};
    memcpy(req.pcr_selections[0].pcrs, pcrs, sizeof(pcrs));
    const char* path = "/sys/kernel/security/ima/binary_runtime_measurements";
    req.event_log_path_len = (uint32_t)strlen(path);
    req.event_log_path = (uint8_t*)path;

    uint8_t* buf = NULL;
    uint32_t buf_len = 0;
    check("marshals",
            charra_marshal_attestation_request(&req, &buf_len, &buf) ==
                    CHARRA_RC_SUCCESS);

    msg_attestation_request_dto out = {0};
    check("unmarshals",
            charra_unmarshal_attestation_request(buf_len, buf, &out) ==
                    CHARRA_RC_SUCCESS);

    check("hello survives", out.hello == req.hello);
    check("sig_key_id survives",
            out.sig_key_id_len == req.sig_key_id_len &&
                    memcmp(out.sig_key_id, req.sig_key_id,
                            req.sig_key_id_len) == 0);
    check("nonce survives",
            out.nonce_len == req.nonce_len &&
                    memcmp(out.nonce, req.nonce, req.nonce_len) == 0);
    check("PCR selection count survives",
            out.pcr_selections_len == req.pcr_selections_len);
    check("PCR bank and indices survive",
            out.pcr_selections[0].tcg_hash_alg_id == TPM2_ALG_SHA256 &&
                    out.pcr_selections[0].pcrs_len == sizeof(pcrs) &&
                    memcmp(out.pcr_selections[0].pcrs, pcrs,
                            sizeof(pcrs)) == 0);
    check("event log path survives",
            out.event_log_path_len == req.event_log_path_len &&
                    memcmp(out.event_log_path, path,
                            req.event_log_path_len) == 0);

    free(out.event_log_path);
    free(buf);
}

static void test_attestation_request_empty_log_path(void) {
    printf("\nan /attest request with no event log path round-trips\n");

    /* The Attester falls back to its own default when the path is empty,
     * so zero length has to survive as zero rather than becoming a stray
     * allocation or a parse error. */
    msg_attestation_request_dto req = {0};
    req.hello = true;
    req.sig_key_id_len = 8;
    memcpy(req.sig_key_id, "attester", 8);
    req.nonce_len = 20;
    fill(req.nonce, req.nonce_len, 0x11);
    req.event_log_path_len = 0;
    req.event_log_path = NULL;

    uint8_t* buf = NULL;
    uint32_t buf_len = 0;
    check("marshals with an empty path",
            charra_marshal_attestation_request(&req, &buf_len, &buf) ==
                    CHARRA_RC_SUCCESS);

    msg_attestation_request_dto out = {0};
    check("unmarshals",
            charra_unmarshal_attestation_request(buf_len, buf, &out) ==
                    CHARRA_RC_SUCCESS);
    check("path length stays zero", out.event_log_path_len == 0);
    check("nonce is unaffected",
            out.nonce_len == req.nonce_len &&
                    memcmp(out.nonce, req.nonce, req.nonce_len) == 0);

    free(out.event_log_path);
    free(buf);
}

/* --- /attest response --------------------------------------------------- */

static void test_attestation_response(void) {
    printf("\nmsg_attestation_response_dto round-trips\n");

    msg_attestation_response_dto res = {0};
    res.attestation_data_len = 160;
    fill(res.attestation_data, res.attestation_data_len, 0x01);
    res.tpm2_signature_len = 280;
    fill(res.tpm2_signature, res.tpm2_signature_len, 0x02);
    res.tpm2_public_key_len = 300;
    fill(res.tpm2_public_key, res.tpm2_public_key_len, 0x03);
    uint8_t log[512];
    fill(log, sizeof(log), 0x04);
    res.event_log_len = sizeof(log);
    res.event_log = log;

    uint8_t* buf = NULL;
    uint32_t buf_len = 0;
    check("marshals",
            charra_marshal_attestation_response(&res, &buf_len, &buf) ==
                    CHARRA_RC_SUCCESS);

    msg_attestation_response_dto out = {0};
    check("unmarshals",
            charra_unmarshal_attestation_response(buf_len, buf, &out) ==
                    CHARRA_RC_SUCCESS);

    check("Quote_a attestation data survives",
            out.attestation_data_len == res.attestation_data_len &&
                    memcmp(out.attestation_data, res.attestation_data,
                            res.attestation_data_len) == 0);
    check("signature survives",
            out.tpm2_signature_len == res.tpm2_signature_len &&
                    memcmp(out.tpm2_signature, res.tpm2_signature,
                            res.tpm2_signature_len) == 0);
    check("public key survives",
            out.tpm2_public_key_len == res.tpm2_public_key_len &&
                    memcmp(out.tpm2_public_key, res.tpm2_public_key,
                            res.tpm2_public_key_len) == 0);
    check("event log survives",
            out.event_log_len == res.event_log_len &&
                    memcmp(out.event_log, log, sizeof(log)) == 0);

    free(out.event_log);
    free(buf);
}

/* --- /attest_result ----------------------------------------------------- */

static void test_attestation_result(void) {
    printf("\nmsg_attestation_result_dto round-trips, both verdicts\n");

    for (int i = 0; i < 2; ++i) {
        msg_attestation_result_dto r = {0};
        r.accepted = (uint32_t)i;
        const char* why = i ? "Step 2a local verification passed"
                            : "Step 2a local verification failed";
        r.reason_len = (uint32_t)strlen(why);
        memcpy(r.reason, why, r.reason_len);

        uint8_t* buf = NULL;
        uint32_t buf_len = 0;
        check("marshals",
                charra_marshal_attestation_result(&r, &buf_len, &buf) ==
                        CHARRA_RC_SUCCESS);

        msg_attestation_result_dto out = {0};
        check("unmarshals",
                charra_unmarshal_attestation_result(buf_len, buf, &out) ==
                        CHARRA_RC_SUCCESS);
        check(i ? "accepted survives as accepted"
                : "rejected survives as rejected",
                out.accepted == r.accepted);
        check("reason survives",
                out.reason_len == r.reason_len &&
                        memcmp(out.reason, why, r.reason_len) == 0);
        free(buf);
    }

    /* The reason is optional, and an empty one must not be mistaken for a
     * malformed message. */
    msg_attestation_result_dto bare = {.accepted = 1, .reason_len = 0};
    uint8_t* buf = NULL;
    uint32_t buf_len = 0;
    msg_attestation_result_dto out = {0};
    check("an empty reason round-trips",
            charra_marshal_attestation_result(&bare, &buf_len, &buf) ==
                            CHARRA_RC_SUCCESS &&
                    charra_unmarshal_attestation_result(buf_len, buf, &out) ==
                            CHARRA_RC_SUCCESS &&
                    out.accepted == 1 && out.reason_len == 0);
    free(buf);
}

/* --- /qualify ----------------------------------------------------------- */

static void test_qualify_response(void) {
    printf("\nmsg_qualify_response_dto round-trips (challenge + salt)\n");

    uint8_t challenge[400];
    fill(challenge, sizeof(challenge), 0x30);

    msg_qualify_response_dto q = {0};
    q.challenge_log_len = sizeof(challenge);
    q.challenge_log = challenge;
    fill(q.salt, sizeof(q.salt), 0x90);

    uint8_t* buf = NULL;
    uint32_t buf_len = 0;
    check("marshals",
            charra_marshal_qualify_response(&q, &buf_len, &buf) ==
                    CHARRA_RC_SUCCESS);

    msg_qualify_response_dto out = {0};
    check("unmarshals",
            charra_unmarshal_qualify_response(buf_len, buf, &out) ==
                    CHARRA_RC_SUCCESS);
    check("challenge log survives",
            out.challenge_log_len == q.challenge_log_len &&
                    memcmp(out.challenge_log, challenge,
                            sizeof(challenge)) == 0);
    /* The salt is the one value deliberately put on the wire; if it did
     * not survive byte-exact, every honest RP would fail qualification. */
    check("salt survives byte-exact",
            memcmp(out.salt, q.salt, sizeof(q.salt)) == 0);

    free(out.challenge_log);
    free(buf);
}

static void test_qualify_submit(void) {
    printf("\nboth halves of /qualify_submit round-trip\n");

    uint8_t redacted[300];
    fill(redacted, sizeof(redacted), 0x50);

    msg_qualify_submit_request_dto req = {0};
    req.submitted_redacted_log_len = sizeof(redacted);
    req.submitted_redacted_log = redacted;
    req.rp_signature_len = CHARRA_RSA_SIGNATURE_LEN;
    fill(req.rp_signature, req.rp_signature_len, 0x60);
    req.rp_public_key_len = 300;
    fill(req.rp_public_key, req.rp_public_key_len, 0x70);

    uint8_t* buf = NULL;
    uint32_t buf_len = 0;
    check("request marshals",
            charra_marshal_qualify_submit_request(&req, &buf_len, &buf) ==
                    CHARRA_RC_SUCCESS);

    msg_qualify_submit_request_dto out = {0};
    check("request unmarshals",
            charra_unmarshal_qualify_submit_request(buf_len, buf, &out) ==
                    CHARRA_RC_SUCCESS);
    check("submitted log survives",
            out.submitted_redacted_log_len == sizeof(redacted) &&
                    memcmp(out.submitted_redacted_log, redacted,
                            sizeof(redacted)) == 0);
    check("signature survives",
            out.rp_signature_len == req.rp_signature_len &&
                    memcmp(out.rp_signature, req.rp_signature,
                            req.rp_signature_len) == 0);
    check("public key survives",
            out.rp_public_key_len == req.rp_public_key_len &&
                    memcmp(out.rp_public_key, req.rp_public_key,
                            req.rp_public_key_len) == 0);
    free(out.submitted_redacted_log);
    free(buf);

    /* Response: a grant and its deadline. expires_at is 64-bit on purpose
     * -- a 32-bit epoch would wrap in 2038, and the RP reads this to
     * decide when to re-qualify. */
    msg_qualify_submit_response_dto resp = {
            .qualified = 1, .expires_at = 4102444800ull};
    uint8_t* rbuf = NULL;
    uint32_t rbuf_len = 0;
    msg_qualify_submit_response_dto rout = {0};
    check("response round-trips",
            charra_marshal_qualify_submit_response(
                    &resp, &rbuf_len, &rbuf) == CHARRA_RC_SUCCESS &&
                    charra_unmarshal_qualify_submit_response(
                            rbuf_len, rbuf, &rout) == CHARRA_RC_SUCCESS);
    check("qualified survives", rout.qualified == 1);
    check("a post-2038 deadline survives intact",
            rout.expires_at == resp.expires_at);
    free(rbuf);

    /* The refusal case carries no deadline, and zero must stay zero. */
    msg_qualify_submit_response_dto no = {.qualified = 0, .expires_at = 0};
    uint8_t* nbuf = NULL;
    uint32_t nbuf_len = 0;
    msg_qualify_submit_response_dto nout = {.qualified = 9, .expires_at = 9};
    check("a refusal round-trips as a refusal",
            charra_marshal_qualify_submit_response(&no, &nbuf_len, &nbuf) ==
                            CHARRA_RC_SUCCESS &&
                    charra_unmarshal_qualify_submit_response(
                            nbuf_len, nbuf, &nout) == CHARRA_RC_SUCCESS &&
                    nout.qualified == 0 && nout.expires_at == 0);
    free(nbuf);
}

/* --- garbage in -------------------------------------------------------- */

static void test_garbage_rejected(void) {
    printf("\nnon-CBOR input is rejected by every unmarshaller\n");

    const uint8_t garbage[] = {0xde, 0xad, 0xbe, 0xef, 0x00, 0xff};
    const uint32_t n = (uint32_t)sizeof(garbage);

    msg_attestation_request_dto a = {0};
    msg_attestation_response_dto b = {0};
    msg_attestation_result_dto c = {0};
    msg_qualify_response_dto d = {0};
    msg_qualify_submit_request_dto e = {0};
    msg_qualify_submit_response_dto f = {0};

    check("/attest request rejects garbage",
            charra_unmarshal_attestation_request(n, garbage, &a) !=
                    CHARRA_RC_SUCCESS);
    check("/attest response rejects garbage",
            charra_unmarshal_attestation_response(n, garbage, &b) !=
                    CHARRA_RC_SUCCESS);
    check("/attest_result rejects garbage",
            charra_unmarshal_attestation_result(n, garbage, &c) !=
                    CHARRA_RC_SUCCESS);
    check("/qualify response rejects garbage",
            charra_unmarshal_qualify_response(n, garbage, &d) !=
                    CHARRA_RC_SUCCESS);
    check("/qualify_submit request rejects garbage",
            charra_unmarshal_qualify_submit_request(n, garbage, &e) !=
                    CHARRA_RC_SUCCESS);
    check("/qualify_submit response rejects garbage",
            charra_unmarshal_qualify_submit_response(n, garbage, &f) !=
                    CHARRA_RC_SUCCESS);

    /* A truncated but otherwise valid message: the length prefix promises
     * more than the buffer holds. */
    msg_qualify_submit_response_dto resp = {.qualified = 1, .expires_at = 42};
    uint8_t* buf = NULL;
    uint32_t buf_len = 0;
    charra_marshal_qualify_submit_response(&resp, &buf_len, &buf);
    msg_qualify_submit_response_dto trunc = {0};
    check("a truncated message is rejected",
            charra_unmarshal_qualify_submit_response(
                    buf_len - 1, buf, &trunc) != CHARRA_RC_SUCCESS);
    free(buf);
}

int main(void) {
    printf("Wire message marshaling tests\n");
    printf("=============================\n");

    test_attestation_request();
    test_attestation_request_empty_log_path();
    test_attestation_response();
    test_attestation_result();
    test_qualify_response();
    test_qualify_submit();
    test_garbage_rejected();

    printf("\n=============================\n");
    printf("%u tests, %u failed\n", tests_run, tests_failed);

    return (tests_failed == 0) ? 0 : 1;
}
