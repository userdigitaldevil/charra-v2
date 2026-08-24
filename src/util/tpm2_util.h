/* SPDX-License-Identifier: BSD-3-Clause */
/*****************************************************************************
 * Copyright 2019, Fraunhofer Institute for Secure Information Technology SIT.
 * All rights reserved.
 ****************************************************************************/

/**
 * @file tpm2_util.h
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

#ifndef TPM2_UTIL_H
#define TPM2_UTIL_H

#include <stdio.h>
#include <tss2/tss2_esys.h>

#include "../common/charra_error.h"

/**
 * @brief Creates the RESTRICTED RSA-2048 signing primary in the owner
 * hierarchy -- the Attester's quoting key.
 *
 * Deterministic: the same hierarchy seed and template reproduce the same
 * key on every call and every process restart, which is what lets
 * keys/trusted_keys.txt vouch for it without any runtime provisioning.
 * Wiping the TPM's NVChip reseeds the hierarchy and therefore changes this
 * key -- regenerate the trust anchor afterwards (keys/gen-trusted-keys.sh).
 *
 * Restricted signing keys are the only ones TPM2_Quote accepts, and are
 * correspondingly forbidden from signing caller-supplied buffers; use
 * tpm2_create_primary_key_rsa2048_unrestricted() for that.
 *
 * @param[in,out] ctx The TSS ESAPI context.
 * @param[out] primary_handle The TSS key handle of the generated primary key.
 * @return TSS2_RC The TSS return code.
 */
TSS2_RC tpm2_create_primary_key_rsa2048(
        ESYS_CONTEXT* ctx, ESYS_TR* primary_handle, TPM2B_PUBLIC** out_public);

/**
 * @brief Creates the UNRESTRICTED RSA-2048 signing primary -- the RP's
 * Quote_r signing key.
 *
 * Same template and the same determinism as the restricted version above,
 * minus TPMA_OBJECT_RESTRICTED. TPM2_Quote accepts either kind, so Quote_r
 * does not need the flag cleared; rp_sign_with_ak() does, because it signs
 * a caller-supplied digest and a restricted key refuses that for want of a
 * TPM-produced validation ticket. The differing template also makes this a
 * different key from the Attester's even on one TPM -- though the two roles
 * now have a TPM each, so their seeds differ anyway.
 *
 * @param[in,out] ctx The TSS ESAPI context.
 * @param[out] primary_handle The TSS key handle of the generated primary key.
 * @return TSS2_RC The TSS return code.
 */
TSS2_RC tpm2_create_primary_key_rsa2048_unrestricted(
        ESYS_CONTEXT* ctx, ESYS_TR* primary_handle, TPM2B_PUBLIC** out_public);

/**
 * @brief Stores a key in the TPM NVRAM under the first available NV index.
 *
 * @param ctx[in,out] The ESAPI context.
 * @param key_handle[in] The TPM key handle.
 * @return TSS2_RC The TSS return code.
 */
TSS2_RC tpm2_store_key_in_nvram(ESYS_CONTEXT* ctx, const ESYS_TR* key_handle);

/**
 * @brief TPM2_PCR_Reset: return a PCR to its power-on all-zero state.
 *
 * Only works on PCRs the platform declares resettable from locality 0 --
 * on the PC Client profile that is 16 and 23. Every other PCR, PCR 10
 * included, refuses with "bad locality", which is the point of a PCR: it
 * may only be extended, never rewound, and nothing short of a real power
 * cycle clears it.
 *
 * That is why the RP replays log_r into PCR 23 rather than PCR 10. It
 * needs a PCR it may legitimately rewind before each replay; the
 * Attester's PCR 10 is exactly the kind it must not be able to.
 */
TSS2_RC tpm2_pcr_reset(ESYS_CONTEXT* ctx, const uint32_t pcr_idx);

/**
 * @brief Extends a TPM 2.0 PCR.
 *
 * @param ctx[in,out] The ESAPI context.
 * @param pcr_idx[in] The PCR index to be extended.
 * @param digests[in] The digests to be extended to the PCR.
 * @return TSS2_RC The TSS return code.
 */
TSS2_RC tpm2_pcr_extend(ESYS_CONTEXT* ctx, const uint32_t pcr_idx,
        const TPML_DIGEST_VALUES* digests);

/**
 * @brief Generates random bytes using the TPM 2.0.
 *
 * @param ctx[in,out] The ESAPI context.
 * @param len[in] Length of the random bytes to be generated.
 * @param random_bytes[out] The generated random bytes.
 * @return TSS2_RC The TSS return code.
 */
TSS2_RC tpm2_get_random(
        ESYS_CONTEXT* ctx, const uint32_t len, TPM2B_DIGEST** random_bytes);

/**
 * @brief Executes a TPM quote operation.
 *
 * @param ctx[in,out] The ESAPI context.
 * @param sign_key_handle[in] The TPM2 handle of the signature key.
 * @param pcr_selection[in] The PCR selection
 * @param qualifying_data[in] The qualifying data, such as a nonce for
 * freshness.
 * @param attest[out] The attestation data structure.
 * @param signature[out] The TPM2 signature over \a attest->attestationData.
 * @return TSS2_RC The TSS return code.
 */
TSS2_RC tpm2_quote(ESYS_CONTEXT* ctx, const ESYS_TR sign_key_handle,
        const TPML_PCR_SELECTION* pcr_selection,
        const TPM2B_DATA* qualifyingData, TPM2B_ATTEST** attest,
        TPMT_SIGNATURE** signature);

#endif /* TPM2_UTIL_H */
