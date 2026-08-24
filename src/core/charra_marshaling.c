/* SPDX-License-Identifier: BSD-3-Clause */
/*****************************************************************************
 * Copyright 2019, Fraunhofer Institute for Secure Information Technology SIT.
 * All rights reserved.
 ****************************************************************************/

/**
 * @file charra_marshaling.c
 * @author Michael Eckel (michael.eckel@sit.fraunhofer.de)
 * @brief
 * @version 0.1
 * @date 2019-09-19
 *
 * @copyright Copyright 2019, Fraunhofer Institute for Secure Information
 * Technology SIT. All rights reserved.
 *
 * @license BSD 3-Clause "New" or "Revised" License (SPDX-License-Identifier:
 * BSD-3-Clause).
 */

#include "charra_marshaling.h"

#include <assert.h>
#include <inttypes.h>
#include <qcbor/UsefulBuf.h>
#include <qcbor/qcbor.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <tss2/tss2_tpm2_types.h>

#include "../common/charra_log.h"
#include "../common/charra_macro.h"
#include "../core/charra_dto.h"
#include "../util/cbor_util.h"
#include "../util/tpm2_util.h"

static CHARRA_RC charra_marshal_attestation_request_internal(
        const msg_attestation_request_dto* attestation_request,
        UsefulBuf buf_in, UsefulBufC* buf_out) {
    charra_log_trace("<ENTER> %s()", __func__);

    /* verify input */
    assert(attestation_request != NULL);
    assert(attestation_request->pcr_selections_len <= TPM2_NUM_PCR_BANKS);
    assert(attestation_request->pcr_selections != NULL);
    assert(attestation_request->pcr_selections->pcrs_len <= TPM2_MAX_PCRS);
    assert(attestation_request->pcr_selections->pcrs != NULL);
    assert(attestation_request->nonce_len <= sizeof(TPMU_HA));
    assert(attestation_request->nonce != NULL);
    if (attestation_request->event_log_path_len != 0) {
        assert(attestation_request->event_log_path != NULL);
    }

    QCBOREncodeContext ec = {0};

    QCBOREncode_Init(&ec, buf_in);

    /* root array */
    QCBOREncode_OpenArray(&ec);

    /* encode "hello" */
    QCBOREncode_AddBool(&ec, attestation_request->hello);

    /* encode "key-id" */
    UsefulBufC key_id = {attestation_request->sig_key_id,
            attestation_request->sig_key_id_len};
    QCBOREncode_AddBytes(&ec, key_id);

    /* encode "nonce" */
    UsefulBufC nonce = {
            attestation_request->nonce, attestation_request->nonce_len};
    QCBOREncode_AddBytes(&ec, nonce);

    /* encode "pcr-selections" */
    QCBOREncode_OpenArray(&ec);
    for (uint32_t i = 0; i < attestation_request->pcr_selections_len; ++i) {
        QCBOREncode_OpenArray(&ec);
        QCBOREncode_AddInt64(
                &ec, attestation_request->pcr_selections[i].tcg_hash_alg_id);
        {
            /* open array: pcrs_array_encoder */
            QCBOREncode_OpenArray(&ec);
            for (uint32_t j = 0;
                    j < attestation_request->pcr_selections[i].pcrs_len; ++j) {
                QCBOREncode_AddUInt64(
                        &ec, attestation_request->pcr_selections[i].pcrs[j]);
            }
            /* close array: pcrs_array_encoder */
            QCBOREncode_CloseArray(&ec);
        }
        /* close array: pcr_selection_array_encoder */
        QCBOREncode_CloseArray(&ec);
    }

    /* close array: pcr_selections_array_encoder */
    QCBOREncode_CloseArray(&ec);

    /* encode "event_log_path" */
    UsefulBufC event_log_path = {.ptr = attestation_request->event_log_path,
            .len = attestation_request->event_log_path_len};
    QCBOREncode_AddBytes(&ec, event_log_path);

    /* close array: root_array_encoder */
    QCBOREncode_CloseArray(&ec);

    if (QCBOREncode_Finish(&ec, buf_out) == QCBOR_SUCCESS) {
        return CHARRA_RC_SUCCESS;
    } else {
        return CHARRA_RC_MARSHALING_ERROR;
    }
}

CHARRA_RC charra_marshal_attestation_request_size(
        const msg_attestation_request_dto* attestation_request,
        size_t* marshaled_data_len) {
    charra_log_trace("<ENTER> %s()", __func__);

    CHARRA_RC charra_r = CHARRA_RC_SUCCESS;

    /* passing this buffer instructs QCBOR to return only the size and do no
     * actual encoding */
    UsefulBuf buf_in = {.len = SIZE_MAX, .ptr = NULL};
    UsefulBufC buf_out = {0};

    if ((charra_r = charra_marshal_attestation_request_internal(
                 attestation_request, buf_in, &buf_out)) == CHARRA_RC_SUCCESS) {
        *marshaled_data_len = buf_out.len;
    }

    return charra_r;
}

CHARRA_RC charra_marshal_attestation_request(
        const msg_attestation_request_dto* attestation_request,
        uint32_t* marshaled_data_len, uint8_t** marshaled_data) {
    charra_log_trace("<ENTER> %s()", __func__);

    CHARRA_RC charra_r = CHARRA_RC_SUCCESS;

    /* verify input */
    assert(attestation_request != NULL);
    assert(attestation_request->pcr_selections_len <= TPM2_NUM_PCR_BANKS);
    assert(attestation_request->pcr_selections != NULL);
    assert(attestation_request->pcr_selections->pcrs_len <= TPM2_MAX_PCRS);
    assert(attestation_request->pcr_selections->pcrs != NULL);
    assert(attestation_request->nonce_len <= sizeof(TPMU_HA));
    assert(attestation_request->nonce != NULL);
    if (attestation_request->event_log_path_len != 0) {
        assert(attestation_request->event_log_path != NULL);
    }

    /* compute size of marshaled data */
    UsefulBuf buf_in = {.len = 0, .ptr = NULL};
    if ((charra_r = charra_marshal_attestation_request_size(
                 attestation_request, &(buf_in.len))) != CHARRA_RC_SUCCESS) {
        charra_log_error("Could not compute size of marshaled data.");
        return charra_r;
    }
    charra_log_debug("Size of marshaled data is %zu bytes.", buf_in.len);

    /* allocate buffer size */
    if ((buf_in.ptr = malloc(buf_in.len)) == NULL) {
        charra_log_error("Allocating %zu bytes of memory failed.", buf_in.len);
        return CHARRA_RC_MARSHALING_ERROR;
    }
    charra_log_debug("Allocated %zu bytes of memory.", buf_in.len);

    /* encode */
    UsefulBufC buf_out = {.len = 0, .ptr = NULL};
    if ((charra_r = charra_marshal_attestation_request_internal(
                 attestation_request, buf_in, &buf_out)) != CHARRA_RC_SUCCESS) {
        charra_log_error("Could not marshal data.");
        return charra_r;
    }

    /* set output parameters */
    *marshaled_data_len = buf_out.len;
    *marshaled_data = (uint8_t*)buf_out.ptr;

    return charra_r;
}

// TODO implement this function using QCBOREncode_* functions
CHARRA_RC charra_unmarshal_attestation_request(
        const uint32_t marshaled_data_len, const uint8_t* marshaled_data,
        msg_attestation_request_dto* attestation_request) {
    msg_attestation_request_dto req = {0};
    /* Declared here, initialized to NULL, so the cleanup below can free it
     * on every 'goto cbor_parse_error' -- including ones that precede the
     * allocation. Mirrors charra_unmarshal_attestation_response(). */
    uint8_t* event_log_path = NULL;

    QCBORError cborerr = QCBOR_SUCCESS;
    UsefulBufC marshaled_data_buf = {marshaled_data, marshaled_data_len};
    QCBORDecodeContext dc = {0};
    QCBORItem item = {0};

    QCBORDecode_Init(&dc, marshaled_data_buf, QCBOR_DECODE_MODE_NORMAL);

    if (charra_cbor_get_next(&dc, &item, QCBOR_TYPE_ARRAY))
        goto cbor_parse_error;

    /* parse "hello" (bool) */
    if ((cborerr = charra_cbor_get_next(&dc, &item, CHARRA_CBOR_TYPE_BOOLEAN)))
        goto cbor_parse_error;
    req.hello = charra_cbor_get_bool_val(&item);

    /* Every length below is checked against its destination before the copy:
     * this is unauthenticated input (the Verifier's /nonce and the Attester's
     * /attest both decode it) and every destination is a fixed-size field of
     * a stack-allocated req. */

    /* parse "key-id" (bytes) */
    if ((cborerr = charra_cbor_get_next(&dc, &item, QCBOR_TYPE_BYTE_STRING)))
        goto cbor_parse_error;
    req.sig_key_id_len = item.val.string.len;
    if (req.sig_key_id_len > sizeof(req.sig_key_id)) {
        charra_log_error("CBOR parser: key ID exceeds maximum allowed size.");
        goto cbor_parse_error;
    }
    memcpy(&(req.sig_key_id), item.val.string.ptr, req.sig_key_id_len);

    /* parse "nonce" (bytes) */
    if ((cborerr = charra_cbor_get_next(&dc, &item, QCBOR_TYPE_BYTE_STRING)))
        goto cbor_parse_error;
    req.nonce_len = item.val.string.len;
    if (req.nonce_len > sizeof(req.nonce)) {
        charra_log_error("CBOR parser: nonce exceeds maximum allowed size.");
        goto cbor_parse_error;
    }
    memcpy(&(req.nonce), item.val.string.ptr, req.nonce_len);

    /* parse array "pcr-selections" */
    if ((cborerr = charra_cbor_get_next(&dc, &item, QCBOR_TYPE_ARRAY)))
        goto cbor_parse_error;

    /* initialize array and array length */
    req.pcr_selections_len = (uint32_t)item.val.uCount;
    if (req.pcr_selections_len >
            sizeof(req.pcr_selections) / sizeof(req.pcr_selections[0])) {
        charra_log_error("CBOR parser: too many PCR selections.");
        goto cbor_parse_error;
    }

    /* go through all elements */
    for (uint32_t i = 0; i < req.pcr_selections_len; ++i) {
        /* parse array "pcr-selection" */
        if ((cborerr = charra_cbor_get_next(&dc, &item, QCBOR_TYPE_ARRAY)))
            goto cbor_parse_error;

        /* parse "tcg-hash-alg-id" (UINT16) */
        if ((cborerr = charra_cbor_get_next(&dc, &item, QCBOR_TYPE_INT64)))
            goto cbor_parse_error;
        req.pcr_selections[i].tcg_hash_alg_id = (uint16_t)item.val.uint64;

        /* parse array "pcrs" */
        if ((cborerr = charra_cbor_get_next(&dc, &item, QCBOR_TYPE_ARRAY)))
            goto cbor_parse_error;

        /* initialize array and array length */
        req.pcr_selections[i].pcrs_len = (uint32_t)item.val.uCount;
        if (req.pcr_selections[i].pcrs_len >
                sizeof(req.pcr_selections[i].pcrs)) {
            charra_log_error(
                    "CBOR parser: too many PCRs in a PCR selection.");
            goto cbor_parse_error;
        }

        /* go through all elements */
        for (uint32_t j = 0; j < req.pcr_selections[i].pcrs_len; ++j) {
            if ((cborerr = charra_cbor_get_next(&dc, &item, QCBOR_TYPE_INT64)))
                goto cbor_parse_error;
            req.pcr_selections[i].pcrs[j] = (uint8_t)item.val.uint64;
        }
    }

    /* parse "event-log-path" (bytes) */
    if ((cborerr = charra_cbor_get_next(&dc, &item, QCBOR_TYPE_BYTE_STRING)))
        goto cbor_parse_error;
    req.event_log_path_len = item.val.string.len;
    if (req.event_log_path_len != 0) {
        event_log_path = (uint8_t*)malloc(req.event_log_path_len);
        if (event_log_path == NULL) {
            goto cbor_parse_error;
        } else {
            req.event_log_path = event_log_path;
            if (memcpy(req.event_log_path, item.val.string.ptr,
                        req.event_log_path_len) == NULL) {
                goto cbor_parse_error;
            }
        }
    }

    /* expect end of CBOR data */
    if ((cborerr = QCBORDecode_Finish(&dc))) {
        charra_log_error("CBOR parser: expected end of input, but could not "
                         "find it. Continuing.");
        goto cbor_parse_error;
    }

    /* set output */
    *attestation_request = req;

    return CHARRA_RC_SUCCESS;

cbor_parse_error:
    charra_log_error("CBOR parser: %s", qcbor_err_to_str(cborerr));
    charra_log_info("CBOR parser: skipping parsing.");

    /* clean up */
    charra_free_if_not_null(event_log_path);

    return CHARRA_RC_MARSHALING_ERROR;
}

static CHARRA_RC charra_marshal_attestation_response_internal(
        const msg_attestation_response_dto* attestation_response,
        UsefulBuf buf_in, UsefulBufC* buf_out) {
    charra_log_trace("<ENTER> %s()", __func__);

    /* verify input */
    assert(attestation_response != NULL);
    assert(attestation_response->attestation_data != NULL);
    assert(attestation_response->tpm2_signature != NULL);
    assert(attestation_response->tpm2_public_key != NULL);
    if (attestation_response->event_log_len != 0) {
        assert(attestation_response->event_log != NULL);
    }

    QCBOREncodeContext ec = {0};

    QCBOREncode_Init(&ec, buf_in);

    /* root array */
    QCBOREncode_OpenArray(&ec);

    /* encode "attestation-data" */
    UsefulBufC attestation_data = {
            .ptr = attestation_response->attestation_data,
            .len = attestation_response->attestation_data_len};
    QCBOREncode_AddBytes(&ec, attestation_data);

    /* encode "tpm2-signature" */
    UsefulBufC tpm2_signature = {.ptr = attestation_response->tpm2_signature,
            .len = attestation_response->tpm2_signature_len};
    QCBOREncode_AddBytes(&ec, tpm2_signature);

    /* encode "tpm2-key-signature" */
    UsefulBufC tpm2_public_key = {.ptr = attestation_response->tpm2_public_key,
            .len = attestation_response->tpm2_public_key_len};
    QCBOREncode_AddBytes(&ec, tpm2_public_key);

    /* encode "event-log" */
    UsefulBufC event_log = {.ptr = attestation_response->event_log,
            .len = attestation_response->event_log_len};
    QCBOREncode_AddBytes(&ec, event_log);

    /* close array: root_array_encoder */
    QCBOREncode_CloseArray(&ec);

    if (QCBOREncode_Finish(&ec, buf_out) == QCBOR_SUCCESS) {
        return CHARRA_RC_SUCCESS;
    } else {
        return CHARRA_RC_MARSHALING_ERROR;
    }
}

CHARRA_RC charra_marshal_attestation_response_size(
        const msg_attestation_response_dto* attestation_response,
        size_t* marshaled_data_len) {
    charra_log_trace("<ENTER> %s()", __func__);

    CHARRA_RC charra_r = CHARRA_RC_SUCCESS;

    /* passing this buffer instructs QCBOR to return only the size and do no
     * actual encoding */
    UsefulBuf buf_in = {.len = SIZE_MAX, .ptr = NULL};
    UsefulBufC buf_out = {0};

    if ((charra_r = charra_marshal_attestation_response_internal(
                 attestation_response, buf_in, &buf_out)) ==
            CHARRA_RC_SUCCESS) {
        *marshaled_data_len = buf_out.len;
    }

    return charra_r;
}

CHARRA_RC charra_marshal_attestation_response(
        const msg_attestation_response_dto* attestation_response,
        uint32_t* marshaled_data_len, uint8_t** marshaled_data) {
    charra_log_trace("<ENTER> %s()", __func__);

    CHARRA_RC charra_r = CHARRA_RC_SUCCESS;

    /* verify input */
    assert(attestation_response != NULL);
    assert(attestation_response->attestation_data != NULL);
    assert(attestation_response->tpm2_signature != NULL);
    assert(attestation_response->tpm2_public_key != NULL);
    if (attestation_response->event_log_len != 0) {
        assert(attestation_response->event_log != NULL);
    }

    /* compute size of marshaled data */
    UsefulBuf buf_in = {.len = 0, .ptr = NULL};
    if ((charra_r = charra_marshal_attestation_response_size(
                 attestation_response, &(buf_in.len))) != CHARRA_RC_SUCCESS) {
        charra_log_error("Could not compute size of marshaled data.");
        return charra_r;
    }
    charra_log_debug("Size of marshaled data is %zu bytes.", buf_in.len);

    /* allocate buffer size */
    if ((buf_in.ptr = malloc(buf_in.len)) == NULL) {
        charra_log_error("Allocating %zu bytes of memory failed.", buf_in.len);
        return CHARRA_RC_MARSHALING_ERROR;
    }
    charra_log_debug("Allocated %zu bytes of memory.", buf_in.len);

    /* encode */
    UsefulBufC buf_out = {.len = 0, .ptr = NULL};
    if ((charra_r = charra_marshal_attestation_response_internal(
                 attestation_response, buf_in, &buf_out)) !=
            CHARRA_RC_SUCCESS) {
        charra_log_error("Could not marshal data.");
        return charra_r;
    }

    /* set output parameters */
    *marshaled_data_len = buf_out.len;
    *marshaled_data = (uint8_t*)buf_out.ptr;

    return charra_r;
}

// TODO(any): Implement this function using  QCBORDecode_* functions.
CHARRA_RC charra_unmarshal_attestation_response(
        const uint32_t marshaled_data_len, const uint8_t* marshaled_data,
        msg_attestation_response_dto* attestation_response) {
    msg_attestation_response_dto res = {0};
    /* Declared here, initialized to NULL, so every 'goto cbor_parse_error'
     * below -- including ones added before this point used to sit -- can
     * safely charra_free_if_not_null() it without reading an
     * uninitialized/indeterminate pointer. */
    uint8_t* event_log = NULL;

    QCBORError cborerr = QCBOR_SUCCESS;
    UsefulBufC marshaled_data_buf = {marshaled_data, marshaled_data_len};
    QCBORDecodeContext dc = {0};
    QCBORItem item = {0};

    QCBORDecode_Init(&dc, marshaled_data_buf, QCBOR_DECODE_MODE_NORMAL);

    /* parse root array */
    if ((cborerr = charra_cbor_get_next(&dc, &item, QCBOR_TYPE_ARRAY)))
        goto cbor_parse_error;

    /* parse "attestation-data" (bytes) */
    if ((cborerr = charra_cbor_get_next(&dc, &item, QCBOR_TYPE_BYTE_STRING)))
        goto cbor_parse_error;
    res.attestation_data_len = item.val.string.len;
    if (res.attestation_data_len > sizeof(res.attestation_data)) {
        charra_log_error(
                "CBOR parser: attestation data exceeds maximum allowed size.");
        goto cbor_parse_error;
    }
    memcpy(&(res.attestation_data), item.val.string.ptr,
            res.attestation_data_len);

    /* parse "tpm2-signature" (bytes) */
    if ((cborerr = charra_cbor_get_next(&dc, &item, QCBOR_TYPE_BYTE_STRING)))
        goto cbor_parse_error;
    res.tpm2_signature_len = item.val.string.len;
    if (res.tpm2_signature_len > sizeof(res.tpm2_signature)) {
        charra_log_error(
                "CBOR parser: TPM2 signature exceeds maximum allowed size.");
        goto cbor_parse_error;
    }
    memcpy(&(res.tpm2_signature), item.val.string.ptr, res.tpm2_signature_len);

    /* parse "tpm2_public_key" (bytes) */
    if ((cborerr = charra_cbor_get_next(&dc, &item, QCBOR_TYPE_BYTE_STRING)))
        goto cbor_parse_error;
    res.tpm2_public_key_len = item.val.string.len;
    if (res.tpm2_public_key_len > sizeof(res.tpm2_public_key)) {
        charra_log_error(
                "CBOR parser: TPM2 public key exceeds maximum allowed size.");
        goto cbor_parse_error;
    }
    memcpy(&(res.tpm2_public_key), item.val.string.ptr,
            res.tpm2_public_key_len);

    /* parse "event-log" (bytes) */
    if ((cborerr = charra_cbor_get_next(&dc, &item, QCBOR_TYPE_BYTE_STRING)))
        goto cbor_parse_error;
    res.event_log_len = item.val.string.len;
    event_log = (uint8_t*)malloc(res.event_log_len);
    if (event_log == NULL) {
        goto cbor_parse_error;
    } else {
        res.event_log = event_log;
        if (memcpy(res.event_log, item.val.string.ptr, res.event_log_len) ==
                NULL) {
            goto cbor_parse_error;
        }
    }

    if ((cborerr = QCBORDecode_Finish(&dc))) {
        charra_log_error("CBOR parser: expected end of input, but could not "
                         "find it. Continuing.");
        goto cbor_parse_error;
    }

    /* set output */
    *attestation_response = res;

    return CHARRA_RC_SUCCESS;

cbor_parse_error:
    charra_log_error("CBOR parser: %s", qcbor_err_to_str(cborerr));
    charra_log_info("CBOR parser: skipping parsing.");

    /* clean up */
    charra_free_if_not_null(event_log);

    return CHARRA_RC_MARSHALING_ERROR;
}

/* --- RP evidence (RP -> Verifier) ---------------------------------------- */

/**
 * @brief Encodes an RP evidence DTO into buf_in.
 *
 * Field order here is the wire format -- it is a plain positional array with
 * no labels, so this order and charra_unmarshal_rp_evidence()'s must never
 * diverge.
 */
static CHARRA_RC charra_marshal_rp_evidence_internal(
        const msg_rp_evidence_dto* rp_evidence, UsefulBuf buf_in,
        UsefulBufC* buf_out) {
    charra_log_trace("<ENTER> %s()", __func__);

    assert(rp_evidence != NULL);
    if (rp_evidence->log_r_len != 0) {
        assert(rp_evidence->log_r != NULL);
    }

    QCBOREncodeContext ec = {0};
    QCBOREncode_Init(&ec, buf_in);
    QCBOREncode_OpenArray(&ec);

    /* Quote_r: the TPM's own signed attestation */
    QCBOREncode_AddBytes(&ec,
            (UsefulBufC){.ptr = rp_evidence->rp_attestation_data,
                    .len = rp_evidence->rp_attestation_data_len});
    QCBOREncode_AddBytes(&ec,
            (UsefulBufC){.ptr = rp_evidence->rp_signature,
                    .len = rp_evidence->rp_signature_len});

    /* RP public key */
    QCBOREncode_AddBytes(&ec,
            (UsefulBufC){.ptr = rp_evidence->rp_public_key,
                    .len = rp_evidence->rp_public_key_len});

    /* nonce the RP sent to the Attester */
    QCBOREncode_AddBytes(&ec,
            (UsefulBufC){.ptr = rp_evidence->attester_nonce,
                    .len = rp_evidence->attester_nonce_len});

    /* Attester's evidence, minus its event log */
    QCBOREncode_AddBytes(&ec,
            (UsefulBufC){.ptr = rp_evidence->attestation_data,
                    .len = rp_evidence->attestation_data_len});
    QCBOREncode_AddBytes(&ec,
            (UsefulBufC){.ptr = rp_evidence->tpm2_signature,
                    .len = rp_evidence->tpm2_signature_len});
    QCBOREncode_AddBytes(&ec,
            (UsefulBufC){.ptr = rp_evidence->tpm2_public_key,
                    .len = rp_evidence->tpm2_public_key_len});

    /* log_r */
    QCBOREncode_AddBytes(&ec,
            (UsefulBufC){.ptr = rp_evidence->log_r,
                    .len = rp_evidence->log_r_len});

    /* simulated TEE Attestation Document (see TEE.h) */
    QCBOREncode_AddBytes(&ec,
            (UsefulBufC){.ptr = rp_evidence->tee_file_hash,
                    .len = sizeof(rp_evidence->tee_file_hash)});
    QCBOREncode_AddBytes(&ec,
            (UsefulBufC){.ptr = rp_evidence->tee_report_data,
                    .len = sizeof(rp_evidence->tee_report_data)});
    QCBOREncode_AddBytes(&ec,
            (UsefulBufC){.ptr = rp_evidence->tee_signature,
                    .len = rp_evidence->tee_signature_len});
    QCBOREncode_AddBytes(&ec,
            (UsefulBufC){.ptr = rp_evidence->tee_public_key,
                    .len = rp_evidence->tee_public_key_len});

    QCBOREncode_CloseArray(&ec);

    return (QCBOREncode_Finish(&ec, buf_out) == QCBOR_SUCCESS)
                   ? CHARRA_RC_SUCCESS
                   : CHARRA_RC_MARSHALING_ERROR;
}

CHARRA_RC charra_marshal_rp_evidence(const msg_rp_evidence_dto* rp_evidence,
        uint32_t* marshaled_data_len, uint8_t** marshaled_data) {
    charra_log_trace("<ENTER> %s()", __func__);

    CHARRA_RC charra_r = CHARRA_RC_SUCCESS;
    assert(rp_evidence != NULL);
    assert(marshaled_data_len != NULL);
    assert(marshaled_data != NULL);

    /* a SIZE_MAX-length NULL buffer instructs QCBOR to size only, not encode */
    UsefulBuf buf_in = {.len = 0, .ptr = NULL};
    UsefulBufC buf_size = {.len = 0, .ptr = NULL};
    if ((charra_r = charra_marshal_rp_evidence_internal(rp_evidence,
                 (UsefulBuf){.len = SIZE_MAX, .ptr = NULL}, &buf_size)) !=
            CHARRA_RC_SUCCESS) {
        charra_log_error("Could not compute size of marshaled RP evidence.");
        return charra_r;
    }
    buf_in.len = buf_size.len;
    charra_log_debug("Size of marshaled RP evidence is %zu bytes.", buf_in.len);

    if ((buf_in.ptr = malloc(buf_in.len)) == NULL) {
        charra_log_error("Allocating %zu bytes of memory failed.", buf_in.len);
        return CHARRA_RC_MARSHALING_ERROR;
    }

    UsefulBufC buf_out = {.len = 0, .ptr = NULL};
    if ((charra_r = charra_marshal_rp_evidence_internal(
                 rp_evidence, buf_in, &buf_out)) != CHARRA_RC_SUCCESS) {
        charra_log_error("Could not marshal RP evidence.");
        free(buf_in.ptr);
        return charra_r;
    }

    *marshaled_data_len = buf_out.len;
    *marshaled_data = (uint8_t*)buf_out.ptr;
    return charra_r;
}

CHARRA_RC charra_unmarshal_rp_evidence(const uint32_t marshaled_data_len,
        const uint8_t* marshaled_data, msg_rp_evidence_dto* rp_evidence) {
    charra_log_trace("<ENTER> %s()", __func__);

    msg_rp_evidence_dto res = {0};
    QCBORError cborerr = QCBOR_SUCCESS;
    UsefulBufC marshaled_data_buf = {marshaled_data, marshaled_data_len};
    QCBORDecodeContext dc = {0};
    QCBORItem item = {0};

    QCBORDecode_Init(&dc, marshaled_data_buf, QCBOR_DECODE_MODE_NORMAL);

    if ((cborerr = charra_cbor_get_next(&dc, &item, QCBOR_TYPE_ARRAY)))
        goto cbor_parse_error;

    /* Every length is checked against its destination before the copy: this
     * is attacker-reachable input and the destinations are fixed-size. */

    /* Quote_r: the TPM's own signed attestation */
    if ((cborerr = charra_cbor_get_next(&dc, &item, QCBOR_TYPE_BYTE_STRING)))
        goto cbor_parse_error;
    res.rp_attestation_data_len = item.val.string.len;
    if (res.rp_attestation_data_len > sizeof(res.rp_attestation_data)) {
        charra_log_error(
                "CBOR parser: Quote_r attestation data exceeds maximum size.");
        goto cbor_parse_error;
    }
    memcpy(res.rp_attestation_data, item.val.string.ptr,
            res.rp_attestation_data_len);

    /* RP signature */
    if ((cborerr = charra_cbor_get_next(&dc, &item, QCBOR_TYPE_BYTE_STRING)))
        goto cbor_parse_error;
    res.rp_signature_len = item.val.string.len;
    if (res.rp_signature_len > sizeof(res.rp_signature)) {
        charra_log_error("CBOR parser: RP signature exceeds maximum size.");
        goto cbor_parse_error;
    }
    memcpy(res.rp_signature, item.val.string.ptr, res.rp_signature_len);

    /* RP public key */
    if ((cborerr = charra_cbor_get_next(&dc, &item, QCBOR_TYPE_BYTE_STRING)))
        goto cbor_parse_error;
    res.rp_public_key_len = item.val.string.len;
    if (res.rp_public_key_len > sizeof(res.rp_public_key)) {
        charra_log_error("CBOR parser: RP public key exceeds maximum size.");
        goto cbor_parse_error;
    }
    memcpy(res.rp_public_key, item.val.string.ptr, res.rp_public_key_len);

    /* nonce the RP sent to the Attester */
    if ((cborerr = charra_cbor_get_next(&dc, &item, QCBOR_TYPE_BYTE_STRING)))
        goto cbor_parse_error;
    res.attester_nonce_len = item.val.string.len;
    if (res.attester_nonce_len > sizeof(res.attester_nonce)) {
        charra_log_error("CBOR parser: attester nonce exceeds maximum size.");
        goto cbor_parse_error;
    }
    memcpy(res.attester_nonce, item.val.string.ptr, res.attester_nonce_len);

    /* Attester's attestation data */
    if ((cborerr = charra_cbor_get_next(&dc, &item, QCBOR_TYPE_BYTE_STRING)))
        goto cbor_parse_error;
    res.attestation_data_len = item.val.string.len;
    if (res.attestation_data_len > sizeof(res.attestation_data)) {
        charra_log_error("CBOR parser: attestation data exceeds maximum size.");
        goto cbor_parse_error;
    }
    memcpy(res.attestation_data, item.val.string.ptr, res.attestation_data_len);

    /* Attester's signature */
    if ((cborerr = charra_cbor_get_next(&dc, &item, QCBOR_TYPE_BYTE_STRING)))
        goto cbor_parse_error;
    res.tpm2_signature_len = item.val.string.len;
    if (res.tpm2_signature_len > sizeof(res.tpm2_signature)) {
        charra_log_error("CBOR parser: TPM2 signature exceeds maximum size.");
        goto cbor_parse_error;
    }
    memcpy(res.tpm2_signature, item.val.string.ptr, res.tpm2_signature_len);

    /* Attester's public key */
    if ((cborerr = charra_cbor_get_next(&dc, &item, QCBOR_TYPE_BYTE_STRING)))
        goto cbor_parse_error;
    res.tpm2_public_key_len = item.val.string.len;
    if (res.tpm2_public_key_len > sizeof(res.tpm2_public_key)) {
        charra_log_error("CBOR parser: TPM2 public key exceeds maximum size.");
        goto cbor_parse_error;
    }
    memcpy(res.tpm2_public_key, item.val.string.ptr, res.tpm2_public_key_len);

    /* log_r -- borrowed from the caller's buffer, never freed here */
    if ((cborerr = charra_cbor_get_next(&dc, &item, QCBOR_TYPE_BYTE_STRING)))
        goto cbor_parse_error;
    res.log_r_len = item.val.string.len;
    res.log_r = (uint8_t*)item.val.string.ptr;

    /* simulated TEE Attestation Document (see TEE.h) */
    if ((cborerr = charra_cbor_get_next(&dc, &item, QCBOR_TYPE_BYTE_STRING)))
        goto cbor_parse_error;
    if (item.val.string.len != sizeof(res.tee_file_hash)) {
        charra_log_error("CBOR parser: TEE file hash has the wrong size.");
        goto cbor_parse_error;
    }
    memcpy(res.tee_file_hash, item.val.string.ptr, sizeof(res.tee_file_hash));

    if ((cborerr = charra_cbor_get_next(&dc, &item, QCBOR_TYPE_BYTE_STRING)))
        goto cbor_parse_error;
    if (item.val.string.len != sizeof(res.tee_report_data)) {
        charra_log_error("CBOR parser: TEE report data has the wrong size.");
        goto cbor_parse_error;
    }
    memcpy(res.tee_report_data, item.val.string.ptr,
            sizeof(res.tee_report_data));

    if ((cborerr = charra_cbor_get_next(&dc, &item, QCBOR_TYPE_BYTE_STRING)))
        goto cbor_parse_error;
    res.tee_signature_len = item.val.string.len;
    if (res.tee_signature_len > sizeof(res.tee_signature)) {
        charra_log_error("CBOR parser: TEE signature exceeds maximum size.");
        goto cbor_parse_error;
    }
    memcpy(res.tee_signature, item.val.string.ptr, res.tee_signature_len);

    if ((cborerr = charra_cbor_get_next(&dc, &item, QCBOR_TYPE_BYTE_STRING)))
        goto cbor_parse_error;
    res.tee_public_key_len = item.val.string.len;
    if (res.tee_public_key_len > sizeof(res.tee_public_key)) {
        charra_log_error("CBOR parser: TEE public key exceeds maximum size.");
        goto cbor_parse_error;
    }
    memcpy(res.tee_public_key, item.val.string.ptr, res.tee_public_key_len);

    if ((cborerr = QCBORDecode_Finish(&dc))) {
        goto cbor_parse_error;
    }

    *rp_evidence = res;
    return CHARRA_RC_SUCCESS;

cbor_parse_error:
    charra_log_error("CBOR parser: %s", qcbor_err_to_str(cborerr));
    charra_log_info("CBOR parser: skipping parsing.");
    return CHARRA_RC_MARSHALING_ERROR;
}


/* --- RP appraisal (Quote_a + Quote_r + log_r, RP -> Verifier) -----------
 * Follows charra_marshal_attestation_response()'s exact pattern above. */





static CHARRA_RC charra_marshal_attestation_result_internal(
        const msg_attestation_result_dto* attestation_result, UsefulBuf buf_in,
        UsefulBufC* buf_out) {
    charra_log_trace("<ENTER> %s()", __func__);
    assert(attestation_result != NULL);

    QCBOREncodeContext ec = {0};
    QCBOREncode_Init(&ec, buf_in);
    QCBOREncode_OpenArray(&ec);
    QCBOREncode_AddUInt64(&ec, attestation_result->accepted);
    QCBOREncode_AddBytes(&ec,
            (UsefulBufC){.ptr = attestation_result->reason,
                    .len = attestation_result->reason_len});
    QCBOREncode_CloseArray(&ec);

    if (QCBOREncode_Finish(&ec, buf_out) == QCBOR_SUCCESS) {
        return CHARRA_RC_SUCCESS;
    } else {
        return CHARRA_RC_MARSHALING_ERROR;
    }
}

static CHARRA_RC charra_marshal_attestation_result_size(
        const msg_attestation_result_dto* attestation_result,
        size_t* marshaled_data_len) {
    charra_log_trace("<ENTER> %s()", __func__);
    CHARRA_RC charra_r = CHARRA_RC_SUCCESS;
    UsefulBuf buf_in = {.len = SIZE_MAX, .ptr = NULL};
    UsefulBufC buf_out = {0};
    if ((charra_r = charra_marshal_attestation_result_internal(
                 attestation_result, buf_in, &buf_out)) == CHARRA_RC_SUCCESS) {
        *marshaled_data_len = buf_out.len;
    }
    return charra_r;
}

CHARRA_RC charra_marshal_attestation_result(
        const msg_attestation_result_dto* attestation_result,
        uint32_t* marshaled_data_len, uint8_t** marshaled_data) {
    charra_log_trace("<ENTER> %s()", __func__);
    CHARRA_RC charra_r = CHARRA_RC_SUCCESS;
    assert(attestation_result != NULL);

    UsefulBuf buf_in = {.len = 0, .ptr = NULL};
    if ((charra_r = charra_marshal_attestation_result_size(
                 attestation_result, &(buf_in.len))) != CHARRA_RC_SUCCESS) {
        charra_log_error("Could not compute size of marshaled data.");
        return charra_r;
    }
    if ((buf_in.ptr = malloc(buf_in.len)) == NULL) {
        charra_log_error("Allocating %zu bytes of memory failed.", buf_in.len);
        return CHARRA_RC_MARSHALING_ERROR;
    }
    UsefulBufC buf_out = {.len = 0, .ptr = NULL};
    if ((charra_r = charra_marshal_attestation_result_internal(
                 attestation_result, buf_in, &buf_out)) != CHARRA_RC_SUCCESS) {
        charra_log_error("Could not marshal data.");
        free(buf_in.ptr);
        return charra_r;
    }
    *marshaled_data_len = buf_out.len;
    *marshaled_data = (uint8_t*)buf_out.ptr;
    return charra_r;
}

CHARRA_RC charra_unmarshal_attestation_result(
        const uint32_t marshaled_data_len, const uint8_t* marshaled_data,
        msg_attestation_result_dto* attestation_result) {
    msg_attestation_result_dto res = {0};
    QCBORError cborerr = QCBOR_SUCCESS;
    UsefulBufC marshaled_data_buf = {marshaled_data, marshaled_data_len};
    QCBORDecodeContext dc = {0};
    QCBORItem item = {0};

    QCBORDecode_Init(&dc, marshaled_data_buf, QCBOR_DECODE_MODE_NORMAL);

    if ((cborerr = charra_cbor_get_next(&dc, &item, QCBOR_TYPE_ARRAY)))
        goto cbor_parse_error;

    /* parse "accepted" */
    if ((cborerr = charra_cbor_get_next(&dc, &item, QCBOR_TYPE_INT64)))
        goto cbor_parse_error;
    res.accepted = (uint32_t)item.val.uint64;

    /* parse "reason" (bytes) */
    if ((cborerr = charra_cbor_get_next(&dc, &item, QCBOR_TYPE_BYTE_STRING)))
        goto cbor_parse_error;
    res.reason_len = item.val.string.len;
    if (res.reason_len > sizeof(res.reason)) {
        charra_log_error("CBOR parser: reason exceeds maximum allowed size.");
        goto cbor_parse_error;
    }
    memcpy(&(res.reason), item.val.string.ptr, res.reason_len);

    if ((cborerr = QCBORDecode_Finish(&dc))) {
        charra_log_error("CBOR parser: expected end of input, but could not "
                         "find it. Continuing.");
        goto cbor_parse_error;
    }

    *attestation_result = res;
    return CHARRA_RC_SUCCESS;

cbor_parse_error:
    charra_log_error("CBOR parser: %s", qcbor_err_to_str(cborerr));
    charra_log_info("CBOR parser: skipping parsing.");
    return CHARRA_RC_MARSHALING_ERROR;
}


/* --- /get_verifiers request ---------------------------------------------- */

static CHARRA_RC charra_marshal_get_verifiers_request_internal(
        const msg_get_verifiers_request_dto* get_verifiers_request,
        UsefulBuf buf_in, UsefulBufC* buf_out) {
    charra_log_trace("<ENTER> %s()", __func__);

    assert(get_verifiers_request != NULL);
    assert(get_verifiers_request->verifier_ids_len <=
            CHARRA_MAX_REQUESTED_VERIFIERS);

    QCBOREncodeContext ec = {0};
    QCBOREncode_Init(&ec, buf_in);

    /* root array */
    QCBOREncode_OpenArray(&ec);

    /* encode "verifier-ids" */
    QCBOREncode_OpenArray(&ec);
    for (uint32_t i = 0; i < get_verifiers_request->verifier_ids_len; ++i) {
        QCBOREncode_AddInt64(&ec, get_verifiers_request->verifier_ids[i]);
    }
    QCBOREncode_CloseArray(&ec);

    /* close array: root_array_encoder */
    QCBOREncode_CloseArray(&ec);

    if (QCBOREncode_Finish(&ec, buf_out) == QCBOR_SUCCESS) {
        return CHARRA_RC_SUCCESS;
    } else {
        return CHARRA_RC_MARSHALING_ERROR;
    }
}

static CHARRA_RC charra_marshal_get_verifiers_request_size(
        const msg_get_verifiers_request_dto* get_verifiers_request,
        size_t* marshaled_data_len) {
    charra_log_trace("<ENTER> %s()", __func__);

    CHARRA_RC charra_r = CHARRA_RC_SUCCESS;

    UsefulBuf buf_in = {.len = SIZE_MAX, .ptr = NULL};
    UsefulBufC buf_out = {0};

    if ((charra_r = charra_marshal_get_verifiers_request_internal(
                 get_verifiers_request, buf_in, &buf_out)) ==
            CHARRA_RC_SUCCESS) {
        *marshaled_data_len = buf_out.len;
    }

    return charra_r;
}

CHARRA_RC charra_marshal_get_verifiers_request(
        const msg_get_verifiers_request_dto* get_verifiers_request,
        uint32_t* marshaled_data_len, uint8_t** marshaled_data) {
    charra_log_trace("<ENTER> %s()", __func__);

    CHARRA_RC charra_r = CHARRA_RC_SUCCESS;

    assert(get_verifiers_request != NULL);
    if (get_verifiers_request->verifier_ids_len >
            CHARRA_MAX_REQUESTED_VERIFIERS) {
        charra_log_error(
                "verifier_ids_len exceeds CHARRA_MAX_REQUESTED_VERIFIERS.");
        return CHARRA_RC_BAD_ARGUMENT;
    }

    UsefulBuf buf_in = {.len = 0, .ptr = NULL};
    if ((charra_r = charra_marshal_get_verifiers_request_size(
                 get_verifiers_request, &(buf_in.len))) != CHARRA_RC_SUCCESS) {
        charra_log_error("Could not compute size of marshaled data.");
        return charra_r;
    }

    if ((buf_in.ptr = malloc(buf_in.len)) == NULL) {
        charra_log_error("Allocating %zu bytes of memory failed.", buf_in.len);
        return CHARRA_RC_MARSHALING_ERROR;
    }

    UsefulBufC buf_out = {.len = 0, .ptr = NULL};
    if ((charra_r = charra_marshal_get_verifiers_request_internal(
                 get_verifiers_request, buf_in, &buf_out)) !=
            CHARRA_RC_SUCCESS) {
        charra_log_error("Could not marshal data.");
        return charra_r;
    }

    *marshaled_data_len = buf_out.len;
    *marshaled_data = (uint8_t*)buf_out.ptr;

    return charra_r;
}

CHARRA_RC charra_unmarshal_get_verifiers_request(
        const uint32_t marshaled_data_len, const uint8_t* marshaled_data,
        msg_get_verifiers_request_dto* get_verifiers_request) {
    msg_get_verifiers_request_dto res = {0};

    QCBORError cborerr = QCBOR_SUCCESS;
    UsefulBufC marshaled_data_buf = {marshaled_data, marshaled_data_len};
    QCBORDecodeContext dc = {0};
    QCBORItem item = {0};

    QCBORDecode_Init(&dc, marshaled_data_buf, QCBOR_DECODE_MODE_NORMAL);

    if ((cborerr = charra_cbor_get_next(&dc, &item, QCBOR_TYPE_ARRAY)))
        goto cbor_parse_error;

    /* parse array "verifier-ids" */
    if ((cborerr = charra_cbor_get_next(&dc, &item, QCBOR_TYPE_ARRAY)))
        goto cbor_parse_error;
    res.verifier_ids_len = (uint32_t)item.val.uCount;
    /* Bounds-checked against the fixed-size destination array BEFORE the
     * loop below writes anything -- an oversized count here used to be
     * exactly the class of gap that let trust_manager.c's response feed
     * relying_party.c more "records" than it actually sent (see
     * CHARRA_V2_NOTES.md); every field in this file is checked the same
     * way, this one included. */
    if (res.verifier_ids_len > CHARRA_MAX_REQUESTED_VERIFIERS) {
        charra_log_error(
                "CBOR parser: verifier_ids exceeds maximum allowed count.");
        goto cbor_parse_error;
    }
    for (uint32_t i = 0; i < res.verifier_ids_len; ++i) {
        if ((cborerr = charra_cbor_get_next(&dc, &item, QCBOR_TYPE_INT64)))
            goto cbor_parse_error;
        res.verifier_ids[i] = (int32_t)item.val.int64;
    }

    if ((cborerr = QCBORDecode_Finish(&dc))) {
        charra_log_error("CBOR parser: expected end of input, but could not "
                         "find it. Continuing.");
        goto cbor_parse_error;
    }

    *get_verifiers_request = res;

    return CHARRA_RC_SUCCESS;

cbor_parse_error:
    charra_log_error("CBOR parser: %s", qcbor_err_to_str(cborerr));
    charra_log_info("CBOR parser: skipping parsing.");

    return CHARRA_RC_MARSHALING_ERROR;
}

/* --- /get_verifiers response ---------------------------------------------- */

static CHARRA_RC charra_marshal_get_verifiers_response_internal(
        const msg_get_verifiers_response_dto* get_verifiers_response,
        UsefulBuf buf_in, UsefulBufC* buf_out) {
    charra_log_trace("<ENTER> %s()", __func__);

    assert(get_verifiers_response != NULL);
    assert(get_verifiers_response->verifiers_len <=
            CHARRA_MAX_REQUESTED_VERIFIERS);

    QCBOREncodeContext ec = {0};
    QCBOREncode_Init(&ec, buf_in);

    /* root array */
    QCBOREncode_OpenArray(&ec);

    /* encode "verifiers" */
    QCBOREncode_OpenArray(&ec);
    for (uint32_t i = 0; i < get_verifiers_response->verifiers_len; ++i) {
        const msg_verifier_endpoint_dto* v =
                &get_verifiers_response->verifiers[i];

        QCBOREncode_OpenArray(&ec);
        /* ip_address's meaningful length is its NUL-terminated string
         * length, not the full fixed buffer -- same "_len tracks the
         * real content, not the destination's capacity" convention every
         * other string/bytes field in this file uses (e.g. sig_key_id). */
        UsefulBufC ip_address = {.ptr = v->ip_address,
                .len = strnlen(v->ip_address, sizeof(v->ip_address))};
        QCBOREncode_AddBytes(&ec, ip_address);
        QCBOREncode_AddUInt64(&ec, v->port_number);
        QCBOREncode_CloseArray(&ec);
    }
    QCBOREncode_CloseArray(&ec);

    /* close array: root_array_encoder */
    QCBOREncode_CloseArray(&ec);

    if (QCBOREncode_Finish(&ec, buf_out) == QCBOR_SUCCESS) {
        return CHARRA_RC_SUCCESS;
    } else {
        return CHARRA_RC_MARSHALING_ERROR;
    }
}

static CHARRA_RC charra_marshal_get_verifiers_response_size(
        const msg_get_verifiers_response_dto* get_verifiers_response,
        size_t* marshaled_data_len) {
    charra_log_trace("<ENTER> %s()", __func__);

    CHARRA_RC charra_r = CHARRA_RC_SUCCESS;

    UsefulBuf buf_in = {.len = SIZE_MAX, .ptr = NULL};
    UsefulBufC buf_out = {0};

    if ((charra_r = charra_marshal_get_verifiers_response_internal(
                 get_verifiers_response, buf_in, &buf_out)) ==
            CHARRA_RC_SUCCESS) {
        *marshaled_data_len = buf_out.len;
    }

    return charra_r;
}

CHARRA_RC charra_marshal_get_verifiers_response(
        const msg_get_verifiers_response_dto* get_verifiers_response,
        uint32_t* marshaled_data_len, uint8_t** marshaled_data) {
    charra_log_trace("<ENTER> %s()", __func__);

    CHARRA_RC charra_r = CHARRA_RC_SUCCESS;

    assert(get_verifiers_response != NULL);
    if (get_verifiers_response->verifiers_len >
            CHARRA_MAX_REQUESTED_VERIFIERS) {
        charra_log_error(
                "verifiers_len exceeds CHARRA_MAX_REQUESTED_VERIFIERS.");
        return CHARRA_RC_BAD_ARGUMENT;
    }

    UsefulBuf buf_in = {.len = 0, .ptr = NULL};
    if ((charra_r = charra_marshal_get_verifiers_response_size(
                 get_verifiers_response, &(buf_in.len))) !=
            CHARRA_RC_SUCCESS) {
        charra_log_error("Could not compute size of marshaled data.");
        return charra_r;
    }

    if ((buf_in.ptr = malloc(buf_in.len)) == NULL) {
        charra_log_error("Allocating %zu bytes of memory failed.", buf_in.len);
        return CHARRA_RC_MARSHALING_ERROR;
    }

    UsefulBufC buf_out = {.len = 0, .ptr = NULL};
    if ((charra_r = charra_marshal_get_verifiers_response_internal(
                 get_verifiers_response, buf_in, &buf_out)) !=
            CHARRA_RC_SUCCESS) {
        charra_log_error("Could not marshal data.");
        return charra_r;
    }

    *marshaled_data_len = buf_out.len;
    *marshaled_data = (uint8_t*)buf_out.ptr;

    return charra_r;
}

CHARRA_RC charra_unmarshal_get_verifiers_response(
        const uint32_t marshaled_data_len, const uint8_t* marshaled_data,
        msg_get_verifiers_response_dto* get_verifiers_response) {
    msg_get_verifiers_response_dto res = {0};

    QCBORError cborerr = QCBOR_SUCCESS;
    UsefulBufC marshaled_data_buf = {marshaled_data, marshaled_data_len};
    QCBORDecodeContext dc = {0};
    QCBORItem item = {0};

    QCBORDecode_Init(&dc, marshaled_data_buf, QCBOR_DECODE_MODE_NORMAL);

    if ((cborerr = charra_cbor_get_next(&dc, &item, QCBOR_TYPE_ARRAY)))
        goto cbor_parse_error;

    /* parse array "verifiers" */
    if ((cborerr = charra_cbor_get_next(&dc, &item, QCBOR_TYPE_ARRAY)))
        goto cbor_parse_error;
    res.verifiers_len = (uint32_t)item.val.uCount;
    /* Bounds-checked against the fixed-size destination array before the
     * loop writes anything -- this is the exact check the old hand-packed
     * /get_verifiers layout never had on either side (see
     * CHARRA_V2_NOTES.md's response_len bug). A malformed or truncated
     * response is now rejected outright rather than partially parsed. */
    if (res.verifiers_len > CHARRA_MAX_REQUESTED_VERIFIERS) {
        charra_log_error(
                "CBOR parser: verifiers exceeds maximum allowed count.");
        goto cbor_parse_error;
    }

    for (uint32_t i = 0; i < res.verifiers_len; ++i) {
        /* parse array "verifier" */
        if ((cborerr = charra_cbor_get_next(&dc, &item, QCBOR_TYPE_ARRAY)))
            goto cbor_parse_error;

        /* parse "ip-address" (bytes) */
        if ((cborerr = charra_cbor_get_next(
                     &dc, &item, QCBOR_TYPE_BYTE_STRING)))
            goto cbor_parse_error;
        if (item.val.string.len >= sizeof(res.verifiers[i].ip_address)) {
            charra_log_error("CBOR parser: Verifier IP address exceeds "
                             "maximum allowed size.");
            goto cbor_parse_error;
        }
        memcpy(res.verifiers[i].ip_address, item.val.string.ptr,
                item.val.string.len);
        res.verifiers[i].ip_address[item.val.string.len] = '\0';

        /* parse "port-number" */
        if ((cborerr = charra_cbor_get_next(&dc, &item, QCBOR_TYPE_INT64)))
            goto cbor_parse_error;
        res.verifiers[i].port_number = (uint32_t)item.val.uint64;
    }

    if ((cborerr = QCBORDecode_Finish(&dc))) {
        charra_log_error("CBOR parser: expected end of input, but could not "
                         "find it. Continuing.");
        goto cbor_parse_error;
    }

    *get_verifiers_response = res;

    return CHARRA_RC_SUCCESS;

cbor_parse_error:
    charra_log_error("CBOR parser: %s", qcbor_err_to_str(cborerr));
    charra_log_info("CBOR parser: skipping parsing.");

    return CHARRA_RC_MARSHALING_ERROR;
}
