/* SPDX-License-Identifier: BSD-3-Clause */
/*****************************************************************************
 * Copyright 2019, Fraunhofer Institute for Secure Information Technology SIT.
 * All rights reserved.
 ****************************************************************************/

/**
 * @file charra_marshaling.h
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

#ifndef MARSHALING_UTIL_H
#define MARSHALING_UTIL_H

#include <qcbor/qcbor.h>
#include <tss2/tss2_esys.h>

#include "../common/charra_error.h"
#include "../core/charra_dto.h"

/**
 * @brief Marshals an attestation request DTO.
 *
 * @param attestation_request[in] The attestation request DTO.
 * @param marshaled_data_len[out] The length of the marshaled data.
 * @param marshaled_data[out] The marshaled data.
 * @return CHARRA_RC_SUCCESS on success.
 * @return CHARRA_RC_ERROR on error.
 */
CHARRA_RC charra_marshal_attestation_request(
        const msg_attestation_request_dto* attestation_request,
        uint32_t* marshaled_data_len, uint8_t** marshaled_data);

/**
 * @brief Unmarshals an attestation request DTO.
 *
 * @param marshaled_data_len[in] The length of the marshaled data.
 * @param marshaled_data[in] The marshaled data.
 * @param attestation_request[out] The attestation request DTO.
 * @return CHARRA_RC_SUCCESS on success.
 * @return CHARRA_RC_ERROR on error.
 */
CHARRA_RC charra_unmarshal_attestation_request(
        const uint32_t marshaled_data_len, const uint8_t* marshaled_data,
        msg_attestation_request_dto* attestation_request);

/**
 * @brief Marshals an attestation response DTO.
 *
 * @param attestation_response[in] The attestation response DTO.
 * @param marshaled_data_len[out] The length of the marshaled data.
 * @param marshaled_data[out] The marshaled data.
 * @return CHARRA_RC_SUCCESS on success.
 * @return CHARRA_RC_ERROR on error.
 */
CHARRA_RC charra_marshal_attestation_response(
        const msg_attestation_response_dto* attestation_response,
        uint32_t* marshaled_data_len, uint8_t** marshaled_data);

/**
 * @brief Unmarshals an attestation response DTO.
 *
 * @param marshaled_data_len[in] The length of the marshaled data.
 * @param marshaled_data[in] The marshaled data.
 * @param attestation_response[out] The attestation response DTO.
 * @return CHARRA_RC_SUCCESS on success.
 * @return CHARRA_RC_ERROR on error.
 */
CHARRA_RC charra_unmarshal_attestation_response(
        const uint32_t marshaled_data_len, const uint8_t* marshaled_data,
        msg_attestation_response_dto* attestation_response);

/**
 * @brief Marshals an RP appraisal DTO (Quote_a + Quote_r + log_r, the
 * RP->Verifier message -- see msg_rp_appraisal_dto in charra_dto.h).
 *
 * Implementation owned by RP-side work; declared here so verifier.c has a
 * stable signature to build and link against independently.
 *
 * @param rp_appraisal[in] The RP appraisal DTO.
 * @param marshaled_data_len[out] The length of the marshaled data.
 * @param marshaled_data[out] The marshaled data.
 * @return CHARRA_RC_SUCCESS on success.
 * @return CHARRA_RC_ERROR on error.
 */
CHARRA_RC charra_marshal_rp_appraisal(
        const msg_rp_appraisal_dto* rp_appraisal,
        uint32_t* marshaled_data_len, uint8_t** marshaled_data);

/**
 * @brief Unmarshals an RP appraisal DTO (Quote_a + Quote_r + log_r, the
 * RP->Verifier message -- see msg_rp_appraisal_dto in charra_dto.h).
 *
 * Expected to apply the same bounds checks charra_unmarshal_attestation_response()
 * does for its three fixed-size fields (attestation_data_len <=
 * sizeof(TPM2B_ATTEST) i.e. attestation_data's array bound, likewise for
 * tpm2_signature/tpm2_public_key) to all SIX fixed-size fields here --
 * including the three new _rp ones, which are exactly as attacker-reachable
 * as the originals were before that bug was fixed.
 *
 * @param marshaled_data_len[in] The length of the marshaled data.
 * @param marshaled_data[in] The marshaled data.
 * @param rp_appraisal[out] The RP appraisal DTO.
 * @return CHARRA_RC_SUCCESS on success.
 * @return CHARRA_RC_BAD_ARGUMENT / CHARRA_RC_MARSHALING_ERROR on bad input.
 */
/**
 * @brief Marshals an RP evidence DTO (the RP->Verifier message carrying
 * Quote_r and the redacted log -- see msg_rp_evidence_dto in charra_dto.h).
 *
 * @param rp_evidence[in] The RP evidence DTO.
 * @param marshaled_data_len[out] The length of the marshaled data.
 * @param marshaled_data[out] The marshaled data; caller must free() it.
 * @return CHARRA_RC_SUCCESS on success, otherwise
 * CHARRA_RC_MARSHALING_ERROR.
 */
CHARRA_RC charra_marshal_rp_evidence(const msg_rp_evidence_dto* rp_evidence,
        uint32_t* marshaled_data_len, uint8_t** marshaled_data);

/**
 * @brief Unmarshals an RP evidence DTO.
 *
 * log_r points into the caller's marshaled_data buffer and must not be
 * freed; it stays valid only as long as that buffer does. Every other field
 * is copied into the DTO.
 *
 * @param marshaled_data_len[in] The length of the marshaled data.
 * @param marshaled_data[in] The marshaled data.
 * @param rp_evidence[out] The RP evidence DTO.
 * @return CHARRA_RC_SUCCESS on success, otherwise
 * CHARRA_RC_MARSHALING_ERROR.
 */
CHARRA_RC charra_unmarshal_rp_evidence(const uint32_t marshaled_data_len,
        const uint8_t* marshaled_data, msg_rp_evidence_dto* rp_evidence);

CHARRA_RC charra_unmarshal_rp_appraisal(
        const uint32_t marshaled_data_len, const uint8_t* marshaled_data,
        msg_rp_appraisal_dto* rp_appraisal);

#endif /* MARSHALING_UTIL_H */
