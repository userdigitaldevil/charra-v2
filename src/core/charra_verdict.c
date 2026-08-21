/**
 * @file charra_verdict.c
 * @brief See charra_verdict.h.
 */

#include "charra_verdict.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <qcbor/qcbor.h>

#include "../common/charra_log.h"
#include "../util/cbor_util.h"
#include "../util/crypto_util.h"

#define LOG_NAME "verdict"

/* --- encoding ----------------------------------------------------------
 *
 * QCBOR sizes a message by encoding it into a NULL buffer first, so every
 * encoder here runs twice: once to measure, once for real. encode_alloc()
 * is that dance, done once instead of per message. */

typedef CHARRA_RC (*encode_fn)(
        const void* src, UsefulBuf buf_in, UsefulBufC* buf_out);

static CHARRA_RC encode_alloc(encode_fn encode, const void* src,
        uint32_t* out_len, uint8_t** out) {
    UsefulBuf buf_in = {.len = SIZE_MAX, .ptr = NULL};
    UsefulBufC buf_out = {0};
    CHARRA_RC charra_r = encode(src, buf_in, &buf_out);
    if (charra_r != CHARRA_RC_SUCCESS) {
        return charra_r;
    }

    buf_in.len = buf_out.len;
    if ((buf_in.ptr = malloc(buf_in.len)) == NULL) {
        charra_log_error("[" LOG_NAME "] Allocating %zu bytes failed.",
                buf_in.len);
        return CHARRA_RC_MARSHALING_ERROR;
    }

    if ((charra_r = encode(src, buf_in, &buf_out)) != CHARRA_RC_SUCCESS) {
        free(buf_in.ptr);
        return charra_r;
    }

    *out_len = (uint32_t)buf_out.len;
    *out = (uint8_t*)buf_out.ptr;
    return CHARRA_RC_SUCCESS;
}

static CHARRA_RC finish(QCBOREncodeContext* ec, UsefulBufC* buf_out) {
    return QCBOREncode_Finish(ec, buf_out) == QCBOR_SUCCESS
                   ? CHARRA_RC_SUCCESS
                   : CHARRA_RC_MARSHALING_ERROR;
}

static CHARRA_RC encode_payload(
        const void* src, UsefulBuf buf_in, UsefulBufC* buf_out) {
    const charra_verdict* v = src;

    QCBOREncodeContext ec = {0};
    QCBOREncode_Init(&ec, buf_in);
    QCBOREncode_OpenArray(&ec);
    QCBOREncode_AddUInt64(&ec, v->accepted ? 1 : 0);
    QCBOREncode_AddBytes(&ec, (UsefulBufC){.ptr = v->challenge_nonce,
                                     .len = v->challenge_nonce_len});
    QCBOREncode_AddBytes(&ec, (UsefulBufC){.ptr = v->evidence_digest,
                                     .len = sizeof(v->evidence_digest)});
    QCBOREncode_AddUInt64(&ec, v->signed_at);
    QCBOREncode_CloseArray(&ec);

    return finish(&ec, buf_out);
}

/** payload and signature, both already bytes -- what encode_alloc() wraps. */
typedef struct {
    UsefulBufC payload;
    UsefulBufC signature;
} signed_message;

static CHARRA_RC encode_message(
        const void* src, UsefulBuf buf_in, UsefulBufC* buf_out) {
    const signed_message* m = src;

    QCBOREncodeContext ec = {0};
    QCBOREncode_Init(&ec, buf_in);
    QCBOREncode_OpenArray(&ec);
    QCBOREncode_AddBytes(&ec, m->payload);
    QCBOREncode_AddBytes(&ec, m->signature);
    QCBOREncode_CloseArray(&ec);

    return finish(&ec, buf_out);
}

CHARRA_RC charra_verdict_sign(const charra_verdict* verdict,
        const char* private_key_path, uint32_t* marshaled_data_len,
        uint8_t** marshaled_data) {
    if (verdict == NULL || private_key_path == NULL ||
            marshaled_data_len == NULL || marshaled_data == NULL ||
            verdict->challenge_nonce_len > sizeof(verdict->challenge_nonce)) {
        return CHARRA_RC_BAD_ARGUMENT;
    }

    uint8_t* payload = NULL;
    uint32_t payload_len = 0;
    CHARRA_RC charra_r =
            encode_alloc(encode_payload, verdict, &payload_len, &payload);
    if (charra_r != CHARRA_RC_SUCCESS) {
        return charra_r;
    }

    uint8_t signature[CHARRA_VERDICT_MAX_SIGNATURE_LEN] = {0};
    size_t signature_len = 0;
    charra_r = charra_crypto_pk_sign_file(private_key_path, payload,
            payload_len, signature, sizeof(signature), &signature_len);
    if (charra_r == CHARRA_RC_SUCCESS) {
        signed_message message = {
                .payload = {.ptr = payload, .len = payload_len},
                .signature = {.ptr = signature, .len = signature_len},
        };
        charra_r = encode_alloc(
                encode_message, &message, marshaled_data_len, marshaled_data);
    }

    free(payload);
    return charra_r;
}

/* --- verification ------------------------------------------------------ */

/** Logs and answers in one line, so each check below stays one statement. */
static bool check(bool ok, const char* what) {
    if (!ok) {
        charra_log_error("[" LOG_NAME "] Rejecting the verdict: %s.", what);
    }
    return ok;
}

CHARRA_RC charra_verdict_verify(uint32_t marshaled_data_len,
        const uint8_t* marshaled_data, const char* public_key_path,
        const uint8_t* expected_nonce, uint32_t expected_nonce_len,
        const uint8_t expected_evidence_digest[TPM2_SHA256_DIGEST_SIZE],
        time_t now, bool* accepted_out) {
    if (marshaled_data == NULL || public_key_path == NULL ||
            expected_evidence_digest == NULL || accepted_out == NULL) {
        return CHARRA_RC_BAD_ARGUMENT;
    }

    QCBORError cborerr = QCBOR_SUCCESS;
    QCBORDecodeContext dc = {0};
    QCBORItem item = {0};
    QCBORDecode_Init(&dc, (UsefulBufC){marshaled_data, marshaled_data_len},
            QCBOR_DECODE_MODE_NORMAL);

    if ((cborerr = charra_cbor_get_next(&dc, &item, QCBOR_TYPE_ARRAY)))
        goto cbor_parse_error;

    if ((cborerr = charra_cbor_get_next(&dc, &item, QCBOR_TYPE_BYTE_STRING)))
        goto cbor_parse_error;
    UsefulBufC payload = item.val.string;

    if ((cborerr = charra_cbor_get_next(&dc, &item, QCBOR_TYPE_BYTE_STRING)))
        goto cbor_parse_error;
    UsefulBufC signature = item.val.string;

    if ((cborerr = QCBORDecode_Finish(&dc)))
        goto cbor_parse_error;

    /* Over the payload exactly as received: nothing is re-encoded, so a
     * decoder quirk on either side cannot turn a good signature bad. */
    if (!check(charra_crypto_pk_verify_file(public_key_path, payload.ptr,
                       payload.len, signature.ptr,
                       signature.len) == CHARRA_RC_SUCCESS,
                "signature is not valid under the Verifier's public key")) {
        return CHARRA_RC_VERIFICATION_FAILED;
    }

    /* Signed, so the fields below can be trusted to be what the Verifier
     * wrote -- the remaining question is whether they describe THIS round. */
    charra_verdict v = {0};
    QCBORDecode_Init(&dc, payload, QCBOR_DECODE_MODE_NORMAL);

    if ((cborerr = charra_cbor_get_next(&dc, &item, QCBOR_TYPE_ARRAY)))
        goto cbor_parse_error;

    if ((cborerr = charra_cbor_get_next(&dc, &item, QCBOR_TYPE_INT64)))
        goto cbor_parse_error;
    v.accepted = item.val.uint64 != 0;

    if ((cborerr = charra_cbor_get_next(&dc, &item, QCBOR_TYPE_BYTE_STRING)))
        goto cbor_parse_error;
    if (item.val.string.len > sizeof(v.challenge_nonce)) {
        charra_log_error("[" LOG_NAME "] Nonce exceeds the maximum size.");
        return CHARRA_RC_MARSHALING_ERROR;
    }
    v.challenge_nonce_len = (uint32_t)item.val.string.len;
    memcpy(v.challenge_nonce, item.val.string.ptr, v.challenge_nonce_len);

    if ((cborerr = charra_cbor_get_next(&dc, &item, QCBOR_TYPE_BYTE_STRING)))
        goto cbor_parse_error;
    if (item.val.string.len != sizeof(v.evidence_digest)) {
        charra_log_error("[" LOG_NAME "] Evidence digest is not %zu bytes.",
                sizeof(v.evidence_digest));
        return CHARRA_RC_MARSHALING_ERROR;
    }
    memcpy(v.evidence_digest, item.val.string.ptr, sizeof(v.evidence_digest));

    if ((cborerr = charra_cbor_get_next(&dc, &item, QCBOR_TYPE_INT64)))
        goto cbor_parse_error;
    v.signed_at = item.val.uint64;

    if ((cborerr = QCBORDecode_Finish(&dc)))
        goto cbor_parse_error;

    /* The len != 0 term is load-bearing, not defensive: memcmp(_, _, 0) is
     * 0, so with no challenge outstanding an empty nonce would match. */
    if (!check(expected_nonce_len != 0 &&
                       v.challenge_nonce_len == expected_nonce_len &&
                       memcmp(v.challenge_nonce, expected_nonce,
                               expected_nonce_len) == 0,
                "nonce is not the challenge this Verifier issued for this "
                "round")) {
        return CHARRA_RC_VERIFICATION_FAILED;
    }

    if (!check(memcmp(v.evidence_digest, expected_evidence_digest,
                       sizeof(v.evidence_digest)) == 0,
                "it was cast over different evidence than we sent")) {
        return CHARRA_RC_VERIFICATION_FAILED;
    }

    /* Compared as int64, never cast to time_t: signed_at is whatever the
     * signer chose, up to UINT64_MAX, and narrowing it would wrap a
     * far-future stamp into a plausible one. Both operands are bounded to
     * INT64_MAX first, so the subtraction cannot overflow. */
    if (!check(v.signed_at <= (uint64_t)INT64_MAX && now >= 0,
                "its timestamp is not a representable time")) {
        return CHARRA_RC_VERIFICATION_FAILED;
    }
    int64_t skew = (int64_t)v.signed_at - (int64_t)now;
    if (skew < 0) {
        skew = -skew;
    }
    if (!check(skew <= CHARRA_VERDICT_SKEW_SECONDS,
                "its timestamp is outside the accepted window")) {
        return CHARRA_RC_VERIFICATION_FAILED;
    }

    *accepted_out = v.accepted;
    return CHARRA_RC_SUCCESS;

cbor_parse_error:
    charra_log_error("[" LOG_NAME "] CBOR parser: %s.",
            qcbor_err_to_str(cborerr));
    return CHARRA_RC_MARSHALING_ERROR;
}
