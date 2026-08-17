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

/**
 * @brief Marshals a /certify_ak request DTO (see msg_certify_ak_request_dto
 * in charra_dto.h).
 */
CHARRA_RC charra_marshal_certify_ak_request(
        const msg_certify_ak_request_dto* certify_ak_request,
        uint32_t* marshaled_data_len, uint8_t** marshaled_data);

/**
 * @brief Unmarshals a /certify_ak request DTO. Bounds-checks
 * ak_public_key_len/ak_name_len against their fixed-size destination
 * arrays, same defense-in-depth style as
 * charra_unmarshal_attestation_response(). ek_certificate has no fixed
 * upper bound (real certificates vary in size), so it is heap-allocated,
 * same as event_log elsewhere in this file.
 */
CHARRA_RC charra_unmarshal_certify_ak_request(
        const uint32_t marshaled_data_len, const uint8_t* marshaled_data,
        msg_certify_ak_request_dto* certify_ak_request);

/**
 * @brief Marshals a /certify_ak response DTO (see
 * msg_certify_ak_response_dto in charra_dto.h).
 */
CHARRA_RC charra_marshal_certify_ak_response(
        const msg_certify_ak_response_dto* certify_ak_response,
        uint32_t* marshaled_data_len, uint8_t** marshaled_data);

/**
 * @brief Unmarshals a /certify_ak response DTO. Bounds-checks
 * credential_blob_len/wrapped_secret_len against their fixed-size
 * destination arrays; aes_gcm_nonce/aes_gcm_tag are fixed-size and
 * length-checked exactly, not just capped. ak_certificate is
 * heap-allocated, same reasoning as ek_certificate above.
 */
CHARRA_RC charra_unmarshal_certify_ak_response(
        const uint32_t marshaled_data_len, const uint8_t* marshaled_data,
        msg_certify_ak_response_dto* certify_ak_response);

/**
 * @brief Marshals a /certify_ak_of_attester response DTO for kind ==
 * ACTIVATE (see msg_activate_credential_response_dto in charra_dto.h).
 */
CHARRA_RC charra_marshal_activate_credential_response(
        const msg_activate_credential_response_dto* activate_response,
        uint32_t* marshaled_data_len, uint8_t** marshaled_data);

/**
 * @brief Unmarshals a /certify_ak_of_attester response DTO for kind ==
 * ACTIVATE. Bounds-checks secret_len against its fixed-size destination.
 */
CHARRA_RC charra_unmarshal_activate_credential_response(
        const uint32_t marshaled_data_len, const uint8_t* marshaled_data,
        msg_activate_credential_response_dto* activate_response);

/**
 * @brief Marshals a /certify_ak_of_attester response DTO for kind == FETCH
 * (see msg_ak_identity_response_dto in charra_dto.h).
 */
CHARRA_RC charra_marshal_ak_identity_response(
        const msg_ak_identity_response_dto* ak_identity_response,
        uint32_t* marshaled_data_len, uint8_t** marshaled_data);

/**
 * @brief Unmarshals a /certify_ak_of_attester response DTO for kind ==
 * FETCH. Bounds-checks ak_public_key_len/ak_name_len against their
 * fixed-size destination arrays, same as charra_unmarshal_certify_ak_
 * request(); ek_certificate has no fixed upper bound, so it is
 * heap-allocated, same as ek_certificate there.
 */
CHARRA_RC charra_unmarshal_ak_identity_response(
        const uint32_t marshaled_data_len, const uint8_t* marshaled_data,
        msg_ak_identity_response_dto* ak_identity_response);

/**
 * @brief Marshals a /certify_ak_of_attester request DTO for kind ==
 * DELIVER_RP or DELIVER_VERIFIER (see
 * msg_certify_ak_of_attester_request_dto in charra_dto.h).
 */
CHARRA_RC charra_marshal_certify_ak_of_attester_request(
        const msg_certify_ak_of_attester_request_dto*
                certify_ak_of_attester_request,
        uint32_t* marshaled_data_len, uint8_t** marshaled_data);

/**
 * @brief Unmarshals a /certify_ak_of_attester request DTO. Bounds-checks
 * credential_blob_len/wrapped_secret_len against their fixed-size
 * destination arrays; aes_gcm_nonce/aes_gcm_tag are fixed-size and
 * length-checked exactly, same as charra_unmarshal_certify_ak_response().
 * ak_certificate is heap-allocated, same reasoning as there.
 */
CHARRA_RC charra_unmarshal_certify_ak_of_attester_request(
        const uint32_t marshaled_data_len, const uint8_t* marshaled_data,
        msg_certify_ak_of_attester_request_dto*
                certify_ak_of_attester_request);

/**
 * @brief Marshals a /qualify response DTO (see msg_qualify_response_dto in
 * charra_dto.h).
 */
CHARRA_RC charra_marshal_qualify_response(
        const msg_qualify_response_dto* qualify_response,
        uint32_t* marshaled_data_len, uint8_t** marshaled_data);

/**
 * @brief Unmarshals a /qualify response DTO. challenge_log has no fixed
 * upper bound (a fabricated log's size is a Verifier policy choice, not a
 * protocol constant), so it is heap-allocated, same as event_log elsewhere
 * in this file.
 */
CHARRA_RC charra_unmarshal_qualify_response(
        const uint32_t marshaled_data_len, const uint8_t* marshaled_data,
        msg_qualify_response_dto* qualify_response);

/**
 * @brief Marshals a /qualify/submit request DTO (see
 * msg_qualify_submit_request_dto in charra_dto.h).
 */
CHARRA_RC charra_marshal_qualify_submit_request(
        const msg_qualify_submit_request_dto* qualify_submit_request,
        uint32_t* marshaled_data_len, uint8_t** marshaled_data);

/**
 * @brief Unmarshals a /qualify/submit request DTO. Bounds-checks
 * rp_signature_len/rp_public_key_len against their fixed-size destination
 * arrays and submitted_pcr_digest for its exact expected size, same
 * defense-in-depth style as charra_unmarshal_rp_evidence(). submitted_
 * redacted_log/ak_certificate_rp have no fixed upper bound, so they are
 * heap-allocated, same as ek_certificate elsewhere in this file.
 */
CHARRA_RC charra_unmarshal_qualify_submit_request(
        const uint32_t marshaled_data_len, const uint8_t* marshaled_data,
        msg_qualify_submit_request_dto* qualify_submit_request);

/**
 * @brief Marshals a /qualify/submit response DTO (verdict + granted
 * expiry) into CBOR. See msg_qualify_submit_response_dto in charra_dto.h.
 */
CHARRA_RC charra_marshal_qualify_submit_response(
        const msg_qualify_submit_response_dto* qualify_submit_response,
        uint32_t* marshaled_data_len, uint8_t** marshaled_data);

/**
 * @brief Unmarshals a /qualify/submit response DTO from CBOR.
 */
CHARRA_RC charra_unmarshal_qualify_submit_response(
        const uint32_t marshaled_data_len, const uint8_t* marshaled_data,
        msg_qualify_submit_response_dto* qualify_submit_response);

/**
 * @brief Marshals a /get_verifiers request DTO (see
 * msg_get_verifiers_request_dto in charra_dto.h) -- replaces the raw,
 * hand-packed `int[]` layout relying_party.c and trust_manager.c used to
 * each independently encode/decode, the one wire format in this codebase
 * that wasn't going through this shared, tested marshal/unmarshal pattern.
 */
CHARRA_RC charra_marshal_get_verifiers_request(
        const msg_get_verifiers_request_dto* get_verifiers_request,
        uint32_t* marshaled_data_len, uint8_t** marshaled_data);

/**
 * @brief Unmarshals a /get_verifiers request DTO. Bounds-checks
 * verifier_ids_len against CHARRA_MAX_REQUESTED_VERIFIERS (the fixed-size
 * destination array) before writing any element, same defense-in-depth
 * style as every other unmarshal function in this file.
 */
CHARRA_RC charra_unmarshal_get_verifiers_request(
        const uint32_t marshaled_data_len, const uint8_t* marshaled_data,
        msg_get_verifiers_request_dto* get_verifiers_request);

/**
 * @brief Marshals a /get_verifiers response DTO (see
 * msg_get_verifiers_response_dto in charra_dto.h).
 */
CHARRA_RC charra_marshal_get_verifiers_response(
        const msg_get_verifiers_response_dto* get_verifiers_response,
        uint32_t* marshaled_data_len, uint8_t** marshaled_data);

/**
 * @brief Unmarshals a /get_verifiers response DTO. Bounds-checks
 * verifiers_len against CHARRA_MAX_REQUESTED_VERIFIERS and each entry's
 * ip_address string length against CHARRA_VERIFIER_IP_MAXLEN - 1 (room
 * for the NUL terminator) before writing anything -- this is exactly the
 * class of check the old hand-packed layout never had, which let a
 * response shorter than expected be silently over-read.
 */
CHARRA_RC charra_unmarshal_get_verifiers_response(
        const uint32_t marshaled_data_len, const uint8_t* marshaled_data,
        msg_get_verifiers_response_dto* get_verifiers_response);

#endif /* MARSHALING_UTIL_H */
