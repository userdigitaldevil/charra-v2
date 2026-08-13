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

    /* parse "key-id" (bytes) */
    if ((cborerr = charra_cbor_get_next(&dc, &item, QCBOR_TYPE_BYTE_STRING)))
        goto cbor_parse_error;
    req.sig_key_id_len = item.val.string.len;
    memcpy(&(req.sig_key_id), item.val.string.ptr, req.sig_key_id_len);

    /* parse "nonce" (bytes) */
    if ((cborerr = charra_cbor_get_next(&dc, &item, QCBOR_TYPE_BYTE_STRING)))
        goto cbor_parse_error;
    req.nonce_len = item.val.string.len;
    memcpy(&(req.nonce), item.val.string.ptr, req.nonce_len);

    /* parse array "pcr-selections" */
    if ((cborerr = charra_cbor_get_next(&dc, &item, QCBOR_TYPE_ARRAY)))
        goto cbor_parse_error;

    /* initialize array and array length */
    req.pcr_selections_len = (uint32_t)item.val.uCount;

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
        uint8_t* event_log_path = (uint8_t*)malloc(req.event_log_path_len);
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

    /* Quote_r */
    QCBOREncode_AddBytes(&ec,
            (UsefulBufC){.ptr = rp_evidence->pcr_r,
                    .len = sizeof(rp_evidence->pcr_r)});
    QCBOREncode_AddBytes(&ec,
            (UsefulBufC){.ptr = rp_evidence->verifier_nonce,
                    .len = rp_evidence->verifier_nonce_len});
    QCBOREncode_AddBytes(&ec,
            (UsefulBufC){.ptr = rp_evidence->rp_signature,
                    .len = rp_evidence->rp_signature_len});

    /* RP public key */
    QCBOREncode_AddBytes(&ec,
            (UsefulBufC){.ptr = rp_evidence->rp_public_key,
                    .len = rp_evidence->rp_public_key_len});

    /* RP's own AK certificate (Step 3a item 1) */
    QCBOREncode_AddBytes(&ec,
            (UsefulBufC){.ptr = rp_evidence->ak_certificate_rp,
                    .len = rp_evidence->ak_certificate_rp_len});

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

    /* Attester's AK certificate, forwarded by RP (Step 3b item 1) */
    QCBOREncode_AddBytes(&ec,
            (UsefulBufC){.ptr = rp_evidence->ak_certificate,
                    .len = rp_evidence->ak_certificate_len});

    /* log_r */
    QCBOREncode_AddBytes(&ec,
            (UsefulBufC){.ptr = rp_evidence->log_r,
                    .len = rp_evidence->log_r_len});

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

    /* PCR_r */
    if ((cborerr = charra_cbor_get_next(&dc, &item, QCBOR_TYPE_BYTE_STRING)))
        goto cbor_parse_error;
    if (item.val.string.len != sizeof(res.pcr_r)) {
        charra_log_error("CBOR parser: PCR_r has the wrong size.");
        goto cbor_parse_error;
    }
    memcpy(res.pcr_r, item.val.string.ptr, sizeof(res.pcr_r));

    /* Verifier's nonce */
    if ((cborerr = charra_cbor_get_next(&dc, &item, QCBOR_TYPE_BYTE_STRING)))
        goto cbor_parse_error;
    res.verifier_nonce_len = item.val.string.len;
    if (res.verifier_nonce_len > sizeof(res.verifier_nonce)) {
        charra_log_error("CBOR parser: verifier nonce exceeds maximum size.");
        goto cbor_parse_error;
    }
    memcpy(res.verifier_nonce, item.val.string.ptr, res.verifier_nonce_len);

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

    /* RP's own AK certificate -- borrowed, same as log_r below */
    if ((cborerr = charra_cbor_get_next(&dc, &item, QCBOR_TYPE_BYTE_STRING)))
        goto cbor_parse_error;
    res.ak_certificate_rp_len = item.val.string.len;
    res.ak_certificate_rp = (uint8_t*)item.val.string.ptr;

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

    /* Attester's AK certificate, forwarded by RP -- borrowed, same as
     * log_r below */
    if ((cborerr = charra_cbor_get_next(&dc, &item, QCBOR_TYPE_BYTE_STRING)))
        goto cbor_parse_error;
    res.ak_certificate_len = item.val.string.len;
    res.ak_certificate = (uint8_t*)item.val.string.ptr;

    /* log_r -- borrowed from the caller's buffer, never freed here */
    if ((cborerr = charra_cbor_get_next(&dc, &item, QCBOR_TYPE_BYTE_STRING)))
        goto cbor_parse_error;
    res.log_r_len = item.val.string.len;
    res.log_r = (uint8_t*)item.val.string.ptr;

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

static CHARRA_RC charra_marshal_rp_appraisal_internal(
        const msg_rp_appraisal_dto* rp_appraisal, UsefulBuf buf_in,
        UsefulBufC* buf_out) {
    charra_log_trace("<ENTER> %s()", __func__);

    assert(rp_appraisal != NULL);
    assert(rp_appraisal->attestation_data != NULL);
    assert(rp_appraisal->tpm2_signature != NULL);
    assert(rp_appraisal->tpm2_public_key != NULL);
    if (rp_appraisal->ak_certificate_len != 0) {
        assert(rp_appraisal->ak_certificate != NULL);
    }
    assert(rp_appraisal->attestation_data_rp != NULL);
    assert(rp_appraisal->tpm2_signature_rp != NULL);
    assert(rp_appraisal->tpm2_public_key_rp != NULL);
    if (rp_appraisal->ak_certificate_rp_len != 0) {
        assert(rp_appraisal->ak_certificate_rp != NULL);
    }
    if (rp_appraisal->event_log_len != 0) {
        assert(rp_appraisal->event_log != NULL);
    }

    QCBOREncodeContext ec = {0};
    QCBOREncode_Init(&ec, buf_in);

    QCBOREncode_OpenArray(&ec);

    UsefulBufC attestation_data = {.ptr = rp_appraisal->attestation_data,
            .len = rp_appraisal->attestation_data_len};
    QCBOREncode_AddBytes(&ec, attestation_data);

    UsefulBufC tpm2_signature = {.ptr = rp_appraisal->tpm2_signature,
            .len = rp_appraisal->tpm2_signature_len};
    QCBOREncode_AddBytes(&ec, tpm2_signature);

    UsefulBufC tpm2_public_key = {.ptr = rp_appraisal->tpm2_public_key,
            .len = rp_appraisal->tpm2_public_key_len};
    QCBOREncode_AddBytes(&ec, tpm2_public_key);

    UsefulBufC ak_certificate = {.ptr = rp_appraisal->ak_certificate,
            .len = rp_appraisal->ak_certificate_len};
    QCBOREncode_AddBytes(&ec, ak_certificate);

    UsefulBufC attestation_data_rp = {.ptr = rp_appraisal->attestation_data_rp,
            .len = rp_appraisal->attestation_data_rp_len};
    QCBOREncode_AddBytes(&ec, attestation_data_rp);

    UsefulBufC tpm2_signature_rp = {.ptr = rp_appraisal->tpm2_signature_rp,
            .len = rp_appraisal->tpm2_signature_rp_len};
    QCBOREncode_AddBytes(&ec, tpm2_signature_rp);

    UsefulBufC tpm2_public_key_rp = {.ptr = rp_appraisal->tpm2_public_key_rp,
            .len = rp_appraisal->tpm2_public_key_rp_len};
    QCBOREncode_AddBytes(&ec, tpm2_public_key_rp);

    UsefulBufC ak_certificate_rp = {.ptr = rp_appraisal->ak_certificate_rp,
            .len = rp_appraisal->ak_certificate_rp_len};
    QCBOREncode_AddBytes(&ec, ak_certificate_rp);

    UsefulBufC event_log = {.ptr = rp_appraisal->event_log,
            .len = rp_appraisal->event_log_len};
    QCBOREncode_AddBytes(&ec, event_log);

    QCBOREncode_CloseArray(&ec);

    if (QCBOREncode_Finish(&ec, buf_out) == QCBOR_SUCCESS) {
        return CHARRA_RC_SUCCESS;
    } else {
        return CHARRA_RC_MARSHALING_ERROR;
    }
}

static CHARRA_RC charra_marshal_rp_appraisal_size(
        const msg_rp_appraisal_dto* rp_appraisal,
        size_t* marshaled_data_len) {
    charra_log_trace("<ENTER> %s()", __func__);

    CHARRA_RC charra_r = CHARRA_RC_SUCCESS;

    UsefulBuf buf_in = {.len = SIZE_MAX, .ptr = NULL};
    UsefulBufC buf_out = {0};

    if ((charra_r = charra_marshal_rp_appraisal_internal(
                 rp_appraisal, buf_in, &buf_out)) == CHARRA_RC_SUCCESS) {
        *marshaled_data_len = buf_out.len;
    }

    return charra_r;
}

CHARRA_RC charra_marshal_rp_appraisal(const msg_rp_appraisal_dto* rp_appraisal,
        uint32_t* marshaled_data_len, uint8_t** marshaled_data) {
    charra_log_trace("<ENTER> %s()", __func__);

    CHARRA_RC charra_r = CHARRA_RC_SUCCESS;

    assert(rp_appraisal != NULL);

    UsefulBuf buf_in = {.len = 0, .ptr = NULL};
    if ((charra_r = charra_marshal_rp_appraisal_size(
                 rp_appraisal, &(buf_in.len))) != CHARRA_RC_SUCCESS) {
        charra_log_error("Could not compute size of marshaled data.");
        return charra_r;
    }

    if ((buf_in.ptr = malloc(buf_in.len)) == NULL) {
        charra_log_error("Allocating %zu bytes of memory failed.", buf_in.len);
        return CHARRA_RC_MARSHALING_ERROR;
    }

    UsefulBufC buf_out = {.len = 0, .ptr = NULL};
    if ((charra_r = charra_marshal_rp_appraisal_internal(
                 rp_appraisal, buf_in, &buf_out)) != CHARRA_RC_SUCCESS) {
        charra_log_error("Could not marshal data.");
        return charra_r;
    }

    *marshaled_data_len = buf_out.len;
    *marshaled_data = (uint8_t*)buf_out.ptr;

    return charra_r;
}

CHARRA_RC charra_unmarshal_rp_appraisal(
        const uint32_t marshaled_data_len, const uint8_t* marshaled_data,
        msg_rp_appraisal_dto* rp_appraisal) {
    msg_rp_appraisal_dto res = {0};
    /* Declared here, initialized to NULL, so every 'goto cbor_parse_error'
     * -- including ones from parses that happen before these -- can safely
     * charra_free_if_not_null() them without reading indeterminate
     * pointers, same convention as event_log below. */
    uint8_t* ak_certificate = NULL;
    uint8_t* ak_certificate_rp = NULL;
    uint8_t* event_log = NULL;

    QCBORError cborerr = QCBOR_SUCCESS;
    UsefulBufC marshaled_data_buf = {marshaled_data, marshaled_data_len};
    QCBORDecodeContext dc = {0};
    QCBORItem item = {0};

    QCBORDecode_Init(&dc, marshaled_data_buf, QCBOR_DECODE_MODE_NORMAL);

    if ((cborerr = charra_cbor_get_next(&dc, &item, QCBOR_TYPE_ARRAY)))
        goto cbor_parse_error;

    /* parse "attestation-data" (Quote_a, bytes) */
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

    /* parse "tpm2-signature" (Quote_a, bytes) */
    if ((cborerr = charra_cbor_get_next(&dc, &item, QCBOR_TYPE_BYTE_STRING)))
        goto cbor_parse_error;
    res.tpm2_signature_len = item.val.string.len;
    if (res.tpm2_signature_len > sizeof(res.tpm2_signature)) {
        charra_log_error(
                "CBOR parser: TPM2 signature exceeds maximum allowed size.");
        goto cbor_parse_error;
    }
    memcpy(&(res.tpm2_signature), item.val.string.ptr, res.tpm2_signature_len);

    /* parse "tpm2-public-key" (Quote_a, bytes) */
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

    /* parse "ak-certificate" (EK_a/AK_a, bytes) -- no fixed upper bound,
     * heap-alloc, same as event-log below */
    if ((cborerr = charra_cbor_get_next(&dc, &item, QCBOR_TYPE_BYTE_STRING)))
        goto cbor_parse_error;
    res.ak_certificate_len = item.val.string.len;
    ak_certificate = (uint8_t*)malloc(res.ak_certificate_len);
    if (ak_certificate == NULL) {
        goto cbor_parse_error;
    }
    res.ak_certificate = ak_certificate;
    memcpy(res.ak_certificate, item.val.string.ptr, res.ak_certificate_len);

    /* parse "attestation-data-rp" (Quote_r, bytes) */
    if ((cborerr = charra_cbor_get_next(&dc, &item, QCBOR_TYPE_BYTE_STRING)))
        goto cbor_parse_error;
    res.attestation_data_rp_len = item.val.string.len;
    if (res.attestation_data_rp_len > sizeof(res.attestation_data_rp)) {
        charra_log_error("CBOR parser: RP attestation data exceeds maximum "
                         "allowed size.");
        goto cbor_parse_error;
    }
    memcpy(&(res.attestation_data_rp), item.val.string.ptr,
            res.attestation_data_rp_len);

    /* parse "tpm2-signature-rp" (Quote_r, bytes) */
    if ((cborerr = charra_cbor_get_next(&dc, &item, QCBOR_TYPE_BYTE_STRING)))
        goto cbor_parse_error;
    res.tpm2_signature_rp_len = item.val.string.len;
    if (res.tpm2_signature_rp_len > sizeof(res.tpm2_signature_rp)) {
        charra_log_error(
                "CBOR parser: RP signature exceeds maximum allowed size.");
        goto cbor_parse_error;
    }
    memcpy(&(res.tpm2_signature_rp), item.val.string.ptr,
            res.tpm2_signature_rp_len);

    /* parse "tpm2-public-key-rp" (Quote_r, bytes) */
    if ((cborerr = charra_cbor_get_next(&dc, &item, QCBOR_TYPE_BYTE_STRING)))
        goto cbor_parse_error;
    res.tpm2_public_key_rp_len = item.val.string.len;
    if (res.tpm2_public_key_rp_len > sizeof(res.tpm2_public_key_rp)) {
        charra_log_error(
                "CBOR parser: RP public key exceeds maximum allowed size.");
        goto cbor_parse_error;
    }
    memcpy(&(res.tpm2_public_key_rp), item.val.string.ptr,
            res.tpm2_public_key_rp_len);

    /* parse "ak-certificate-rp" (EK_r/AK_r, bytes) -- same reasoning as
     * ak-certificate above */
    if ((cborerr = charra_cbor_get_next(&dc, &item, QCBOR_TYPE_BYTE_STRING)))
        goto cbor_parse_error;
    res.ak_certificate_rp_len = item.val.string.len;
    ak_certificate_rp = (uint8_t*)malloc(res.ak_certificate_rp_len);
    if (ak_certificate_rp == NULL) {
        goto cbor_parse_error;
    }
    res.ak_certificate_rp = ak_certificate_rp;
    memcpy(res.ak_certificate_rp, item.val.string.ptr,
            res.ak_certificate_rp_len);

    /* parse "event-log" (log_r, bytes) */
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

    *rp_appraisal = res;

    return CHARRA_RC_SUCCESS;

cbor_parse_error:
    charra_log_error("CBOR parser: %s", qcbor_err_to_str(cborerr));
    charra_log_info("CBOR parser: skipping parsing.");

    charra_free_if_not_null(ak_certificate);
    charra_free_if_not_null(ak_certificate_rp);
    charra_free_if_not_null(event_log);

    return CHARRA_RC_MARSHALING_ERROR;
}

/* --- /certify_ak request ------------------------------------------------ */

static CHARRA_RC charra_marshal_certify_ak_request_internal(
        const msg_certify_ak_request_dto* certify_ak_request, UsefulBuf buf_in,
        UsefulBufC* buf_out) {
    charra_log_trace("<ENTER> %s()", __func__);

    assert(certify_ak_request != NULL);
    if (certify_ak_request->ek_certificate_len != 0) {
        assert(certify_ak_request->ek_certificate != NULL);
    }

    QCBOREncodeContext ec = {0};
    QCBOREncode_Init(&ec, buf_in);

    /* root array */
    QCBOREncode_OpenArray(&ec);

    /* encode "ek-certificate" */
    UsefulBufC ek_certificate = {.ptr = certify_ak_request->ek_certificate,
            .len = certify_ak_request->ek_certificate_len};
    QCBOREncode_AddBytes(&ec, ek_certificate);

    /* encode "ak-public-key" */
    UsefulBufC ak_public_key = {.ptr = certify_ak_request->ak_public_key,
            .len = certify_ak_request->ak_public_key_len};
    QCBOREncode_AddBytes(&ec, ak_public_key);

    /* encode "ak-name" */
    UsefulBufC ak_name = {.ptr = certify_ak_request->ak_name,
            .len = certify_ak_request->ak_name_len};
    QCBOREncode_AddBytes(&ec, ak_name);

    /* close array: root_array_encoder */
    QCBOREncode_CloseArray(&ec);

    if (QCBOREncode_Finish(&ec, buf_out) == QCBOR_SUCCESS) {
        return CHARRA_RC_SUCCESS;
    } else {
        return CHARRA_RC_MARSHALING_ERROR;
    }
}

static CHARRA_RC charra_marshal_certify_ak_request_size(
        const msg_certify_ak_request_dto* certify_ak_request,
        size_t* marshaled_data_len) {
    charra_log_trace("<ENTER> %s()", __func__);

    CHARRA_RC charra_r = CHARRA_RC_SUCCESS;

    UsefulBuf buf_in = {.len = SIZE_MAX, .ptr = NULL};
    UsefulBufC buf_out = {0};

    if ((charra_r = charra_marshal_certify_ak_request_internal(
                 certify_ak_request, buf_in, &buf_out)) == CHARRA_RC_SUCCESS) {
        *marshaled_data_len = buf_out.len;
    }

    return charra_r;
}

CHARRA_RC charra_marshal_certify_ak_request(
        const msg_certify_ak_request_dto* certify_ak_request,
        uint32_t* marshaled_data_len, uint8_t** marshaled_data) {
    charra_log_trace("<ENTER> %s()", __func__);

    CHARRA_RC charra_r = CHARRA_RC_SUCCESS;

    assert(certify_ak_request != NULL);
    if (certify_ak_request->ek_certificate_len != 0) {
        assert(certify_ak_request->ek_certificate != NULL);
    }

    UsefulBuf buf_in = {.len = 0, .ptr = NULL};
    if ((charra_r = charra_marshal_certify_ak_request_size(
                 certify_ak_request, &(buf_in.len))) != CHARRA_RC_SUCCESS) {
        charra_log_error("Could not compute size of marshaled data.");
        return charra_r;
    }

    if ((buf_in.ptr = malloc(buf_in.len)) == NULL) {
        charra_log_error("Allocating %zu bytes of memory failed.", buf_in.len);
        return CHARRA_RC_MARSHALING_ERROR;
    }

    UsefulBufC buf_out = {.len = 0, .ptr = NULL};
    if ((charra_r = charra_marshal_certify_ak_request_internal(
                 certify_ak_request, buf_in, &buf_out)) != CHARRA_RC_SUCCESS) {
        charra_log_error("Could not marshal data.");
        return charra_r;
    }

    *marshaled_data_len = buf_out.len;
    *marshaled_data = (uint8_t*)buf_out.ptr;

    return charra_r;
}

CHARRA_RC charra_unmarshal_certify_ak_request(
        const uint32_t marshaled_data_len, const uint8_t* marshaled_data,
        msg_certify_ak_request_dto* certify_ak_request) {
    msg_certify_ak_request_dto res = {0};
    /* declared/NULLed here so every 'goto cbor_parse_error' can safely
     * charra_free_if_not_null() it, same convention as event_log above */
    uint8_t* ek_certificate = NULL;

    QCBORError cborerr = QCBOR_SUCCESS;
    UsefulBufC marshaled_data_buf = {marshaled_data, marshaled_data_len};
    QCBORDecodeContext dc = {0};
    QCBORItem item = {0};

    QCBORDecode_Init(&dc, marshaled_data_buf, QCBOR_DECODE_MODE_NORMAL);

    if ((cborerr = charra_cbor_get_next(&dc, &item, QCBOR_TYPE_ARRAY)))
        goto cbor_parse_error;

    /* parse "ek-certificate" (bytes) -- no fixed upper bound, heap-alloc */
    if ((cborerr = charra_cbor_get_next(&dc, &item, QCBOR_TYPE_BYTE_STRING)))
        goto cbor_parse_error;
    res.ek_certificate_len = item.val.string.len;
    ek_certificate = (uint8_t*)malloc(res.ek_certificate_len);
    if (ek_certificate == NULL) {
        goto cbor_parse_error;
    }
    res.ek_certificate = ek_certificate;
    memcpy(res.ek_certificate, item.val.string.ptr, res.ek_certificate_len);

    /* parse "ak-public-key" (bytes) */
    if ((cborerr = charra_cbor_get_next(&dc, &item, QCBOR_TYPE_BYTE_STRING)))
        goto cbor_parse_error;
    res.ak_public_key_len = item.val.string.len;
    if (res.ak_public_key_len > sizeof(res.ak_public_key)) {
        charra_log_error(
                "CBOR parser: AK public key exceeds maximum allowed size.");
        goto cbor_parse_error;
    }
    memcpy(&(res.ak_public_key), item.val.string.ptr, res.ak_public_key_len);

    /* parse "ak-name" (bytes) */
    if ((cborerr = charra_cbor_get_next(&dc, &item, QCBOR_TYPE_BYTE_STRING)))
        goto cbor_parse_error;
    res.ak_name_len = item.val.string.len;
    if (res.ak_name_len > sizeof(res.ak_name)) {
        charra_log_error("CBOR parser: AK name exceeds maximum allowed size.");
        goto cbor_parse_error;
    }
    memcpy(&(res.ak_name), item.val.string.ptr, res.ak_name_len);

    if ((cborerr = QCBORDecode_Finish(&dc))) {
        charra_log_error("CBOR parser: expected end of input, but could not "
                         "find it. Continuing.");
        goto cbor_parse_error;
    }

    *certify_ak_request = res;

    return CHARRA_RC_SUCCESS;

cbor_parse_error:
    charra_log_error("CBOR parser: %s", qcbor_err_to_str(cborerr));
    charra_log_info("CBOR parser: skipping parsing.");

    charra_free_if_not_null(ek_certificate);

    return CHARRA_RC_MARSHALING_ERROR;
}

/* --- /certify_ak response ------------------------------------------------ */

static CHARRA_RC charra_marshal_certify_ak_response_internal(
        const msg_certify_ak_response_dto* certify_ak_response,
        UsefulBuf buf_in, UsefulBufC* buf_out) {
    charra_log_trace("<ENTER> %s()", __func__);

    assert(certify_ak_response != NULL);
    if (certify_ak_response->ak_certificate_len != 0) {
        assert(certify_ak_response->ak_certificate != NULL);
    }

    QCBOREncodeContext ec = {0};
    QCBOREncode_Init(&ec, buf_in);

    QCBOREncode_OpenArray(&ec);

    UsefulBufC credential_blob = {.ptr = certify_ak_response->credential_blob,
            .len = certify_ak_response->credential_blob_len};
    QCBOREncode_AddBytes(&ec, credential_blob);

    UsefulBufC wrapped_secret = {.ptr = certify_ak_response->wrapped_secret,
            .len = certify_ak_response->wrapped_secret_len};
    QCBOREncode_AddBytes(&ec, wrapped_secret);

    UsefulBufC aes_gcm_nonce = {.ptr = certify_ak_response->aes_gcm_nonce,
            .len = sizeof(certify_ak_response->aes_gcm_nonce)};
    QCBOREncode_AddBytes(&ec, aes_gcm_nonce);

    UsefulBufC aes_gcm_tag = {.ptr = certify_ak_response->aes_gcm_tag,
            .len = sizeof(certify_ak_response->aes_gcm_tag)};
    QCBOREncode_AddBytes(&ec, aes_gcm_tag);

    UsefulBufC ak_certificate = {.ptr = certify_ak_response->ak_certificate,
            .len = certify_ak_response->ak_certificate_len};
    QCBOREncode_AddBytes(&ec, ak_certificate);

    QCBOREncode_CloseArray(&ec);

    if (QCBOREncode_Finish(&ec, buf_out) == QCBOR_SUCCESS) {
        return CHARRA_RC_SUCCESS;
    } else {
        return CHARRA_RC_MARSHALING_ERROR;
    }
}

static CHARRA_RC charra_marshal_certify_ak_response_size(
        const msg_certify_ak_response_dto* certify_ak_response,
        size_t* marshaled_data_len) {
    charra_log_trace("<ENTER> %s()", __func__);

    CHARRA_RC charra_r = CHARRA_RC_SUCCESS;

    UsefulBuf buf_in = {.len = SIZE_MAX, .ptr = NULL};
    UsefulBufC buf_out = {0};

    if ((charra_r = charra_marshal_certify_ak_response_internal(
                 certify_ak_response, buf_in, &buf_out)) ==
            CHARRA_RC_SUCCESS) {
        *marshaled_data_len = buf_out.len;
    }

    return charra_r;
}

CHARRA_RC charra_marshal_certify_ak_response(
        const msg_certify_ak_response_dto* certify_ak_response,
        uint32_t* marshaled_data_len, uint8_t** marshaled_data) {
    charra_log_trace("<ENTER> %s()", __func__);

    CHARRA_RC charra_r = CHARRA_RC_SUCCESS;

    assert(certify_ak_response != NULL);
    if (certify_ak_response->ak_certificate_len != 0) {
        assert(certify_ak_response->ak_certificate != NULL);
    }

    UsefulBuf buf_in = {.len = 0, .ptr = NULL};
    if ((charra_r = charra_marshal_certify_ak_response_size(
                 certify_ak_response, &(buf_in.len))) != CHARRA_RC_SUCCESS) {
        charra_log_error("Could not compute size of marshaled data.");
        return charra_r;
    }

    if ((buf_in.ptr = malloc(buf_in.len)) == NULL) {
        charra_log_error("Allocating %zu bytes of memory failed.", buf_in.len);
        return CHARRA_RC_MARSHALING_ERROR;
    }

    UsefulBufC buf_out = {.len = 0, .ptr = NULL};
    if ((charra_r = charra_marshal_certify_ak_response_internal(
                 certify_ak_response, buf_in, &buf_out)) !=
            CHARRA_RC_SUCCESS) {
        charra_log_error("Could not marshal data.");
        return charra_r;
    }

    *marshaled_data_len = buf_out.len;
    *marshaled_data = (uint8_t*)buf_out.ptr;

    return charra_r;
}

CHARRA_RC charra_unmarshal_certify_ak_response(
        const uint32_t marshaled_data_len, const uint8_t* marshaled_data,
        msg_certify_ak_response_dto* certify_ak_response) {
    msg_certify_ak_response_dto res = {0};
    uint8_t* ak_certificate = NULL;

    QCBORError cborerr = QCBOR_SUCCESS;
    UsefulBufC marshaled_data_buf = {marshaled_data, marshaled_data_len};
    QCBORDecodeContext dc = {0};
    QCBORItem item = {0};

    QCBORDecode_Init(&dc, marshaled_data_buf, QCBOR_DECODE_MODE_NORMAL);

    if ((cborerr = charra_cbor_get_next(&dc, &item, QCBOR_TYPE_ARRAY)))
        goto cbor_parse_error;

    /* parse "credential-blob" (bytes) */
    if ((cborerr = charra_cbor_get_next(&dc, &item, QCBOR_TYPE_BYTE_STRING)))
        goto cbor_parse_error;
    res.credential_blob_len = item.val.string.len;
    if (res.credential_blob_len > sizeof(res.credential_blob)) {
        charra_log_error(
                "CBOR parser: credential blob exceeds maximum allowed size.");
        goto cbor_parse_error;
    }
    memcpy(&(res.credential_blob), item.val.string.ptr,
            res.credential_blob_len);

    /* parse "wrapped-secret" (bytes) */
    if ((cborerr = charra_cbor_get_next(&dc, &item, QCBOR_TYPE_BYTE_STRING)))
        goto cbor_parse_error;
    res.wrapped_secret_len = item.val.string.len;
    if (res.wrapped_secret_len > sizeof(res.wrapped_secret)) {
        charra_log_error(
                "CBOR parser: wrapped secret exceeds maximum allowed size.");
        goto cbor_parse_error;
    }
    memcpy(&(res.wrapped_secret), item.val.string.ptr, res.wrapped_secret_len);

    /* parse "aes-gcm-nonce" (bytes) -- fixed size, checked exactly */
    if ((cborerr = charra_cbor_get_next(&dc, &item, QCBOR_TYPE_BYTE_STRING)))
        goto cbor_parse_error;
    if (item.val.string.len != sizeof(res.aes_gcm_nonce)) {
        charra_log_error("CBOR parser: AES-GCM nonce has the wrong size.");
        goto cbor_parse_error;
    }
    memcpy(&(res.aes_gcm_nonce), item.val.string.ptr,
            sizeof(res.aes_gcm_nonce));

    /* parse "aes-gcm-tag" (bytes) -- fixed size, checked exactly */
    if ((cborerr = charra_cbor_get_next(&dc, &item, QCBOR_TYPE_BYTE_STRING)))
        goto cbor_parse_error;
    if (item.val.string.len != sizeof(res.aes_gcm_tag)) {
        charra_log_error("CBOR parser: AES-GCM tag has the wrong size.");
        goto cbor_parse_error;
    }
    memcpy(&(res.aes_gcm_tag), item.val.string.ptr, sizeof(res.aes_gcm_tag));

    /* parse "ak-certificate" (bytes) -- no fixed upper bound, heap-alloc */
    if ((cborerr = charra_cbor_get_next(&dc, &item, QCBOR_TYPE_BYTE_STRING)))
        goto cbor_parse_error;
    res.ak_certificate_len = item.val.string.len;
    ak_certificate = (uint8_t*)malloc(res.ak_certificate_len);
    if (ak_certificate == NULL) {
        goto cbor_parse_error;
    }
    res.ak_certificate = ak_certificate;
    memcpy(res.ak_certificate, item.val.string.ptr, res.ak_certificate_len);

    if ((cborerr = QCBORDecode_Finish(&dc))) {
        charra_log_error("CBOR parser: expected end of input, but could not "
                         "find it. Continuing.");
        goto cbor_parse_error;
    }

    *certify_ak_response = res;

    return CHARRA_RC_SUCCESS;

cbor_parse_error:
    charra_log_error("CBOR parser: %s", qcbor_err_to_str(cborerr));
    charra_log_info("CBOR parser: skipping parsing.");

    charra_free_if_not_null(ak_certificate);

    return CHARRA_RC_MARSHALING_ERROR;
}
