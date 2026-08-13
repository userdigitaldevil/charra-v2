/* SPDX-License-Identifier: BSD-3-Clause */
/*****************************************************************************
 * Copyright 2019, Fraunhofer Institute for Secure Information Technology SIT.
 * All rights reserved.
 ****************************************************************************/

/**
 * @file charra_key_mgr.h
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

#ifndef CHARRA_KEY_MGR_H
#define CHARRA_KEY_MGR_H

#include <inttypes.h>
#include <tss2/tss2_esys.h>
#include <tss2/tss2_tpm2_types.h>

#include "../common/charra_error.h"

CHARRA_RC charra_load_tpm2_key(ESYS_CONTEXT* ctx, const uint32_t key_len,
        const uint8_t* key, ESYS_TR* key_handle, TPM2B_PUBLIC** out_public);

CHARRA_RC charra_load_external_public_key(ESYS_CONTEXT* ctx,
        TPM2B_PUBLIC* external_public_key, ESYS_TR* key_handle);

/**
 * @brief Wrap a secret (TPM2_MakeCredential) so only a TPM holding
 * ek_public_key's private key, with the object named ak_name currently
 * loaded, can recover it. Used by the Verifier's Privacy CA role
 * (/certify_ak) to hand the requester a certificate they can only unwrap
 * by proving, via TPM2_ActivateCredential on their own end, that they
 * genuinely hold both the EK and the named AK.
 *
 * Needs no TPM identity of the Verifier's own: MakeCredential is public-
 * key crypto against the caller-supplied EK, loaded externally the same
 * way charra_load_external_public_key() already loads quote-signing keys.
 *
 * @param[in] esys_ctx an initialized ESAPI context
 * @param[in] ek_public_key the requester's EK public key
 * @param[in] ak_name the requester's AK's TPM2B_NAME, exactly as their own
 * Esys_ReadPublic() reports it -- NOT recomputed here. A name that doesn't
 * match the requester's actually-loaded AK just makes their later
 * ActivateCredential fail; nothing is lost by trusting it unverified here.
 * @param[in] credential the secret to wrap; must fit within the TPM's
 * digest-size cap (commonly 32 bytes for a SHA-256-named object) -- in
 * this project, a fresh symmetric key used to encrypt the actual issued
 * AK certificate, see charra_crypto_sign_ak_certificate().
 * @param[out] credential_blob_out caller must Esys_Free() this.
 * @param[out] wrapped_secret_out caller must Esys_Free() this.
 * @returns CHARRA_RC_SUCCESS, CHARRA_RC_BAD_ARGUMENT on NULL input,
 * CHARRA_RC_TPM if loading the EK or the MakeCredential call itself fails.
 */
CHARRA_RC charra_tpm_make_credential_for_ak(ESYS_CONTEXT* esys_ctx,
        TPM2B_PUBLIC* ek_public_key, const TPM2B_NAME* ak_name,
        const TPM2B_DIGEST* credential,
        TPM2B_ID_OBJECT** credential_blob_out,
        TPM2B_ENCRYPTED_SECRET** wrapped_secret_out);

#endif /* CHARRA_KEY_MGR_H */
