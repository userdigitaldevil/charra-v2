/* SPDX-License-Identifier: BSD-3-Clause */
/*****************************************************************************
 * Copyright 2019, Fraunhofer Institute for Secure Information Technology SIT.
 * All rights reserved.
 ****************************************************************************/

/**
 * @file charra_key_mgr.c
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

#include "charra_key_mgr.h"

#include <inttypes.h>
#include <string.h>
#include <tss2/tss2_esys.h>
#include <tss2/tss2_tpm2_types.h>

#include "../common/charra_error.h"
#include "../common/charra_log.h"
#include "../util/tpm2_util.h"

CHARRA_RC charra_load_tpm2_key(ESYS_CONTEXT* ctx, const uint32_t key_len,
        const uint8_t* key, ESYS_TR* key_handle, TPM2B_PUBLIC** out_public) {
    TSS2_RC r = TSS2_RC_SUCCESS;
    if (memcmp(key, "PK.RSA.default", key_len) == 0) {
        charra_log_info("Loading key \"PK.RSA.default\".");
        r = tpm2_create_primary_key_rsa2048(ctx, key_handle, out_public);
        if (r != TSS2_RC_SUCCESS) {
            charra_log_error("Loading of key \"PK.RSA.default\" failed.");
            return CHARRA_RC_ERROR;
        }
    } else {
        charra_log_error("TPM key not found.");
        return CHARRA_RC_ERROR;
    }

    return CHARRA_RC_SUCCESS;
}

CHARRA_RC charra_load_external_public_key(ESYS_CONTEXT* ctx,
        TPM2B_PUBLIC* external_public_key, ESYS_TR* key_handle) {
    TSS2_RC r = TSS2_RC_SUCCESS;
    if (external_public_key == NULL) {
        charra_log_error("External public key does not exist.");
        return CHARRA_RC_ERROR;
    }

    r = Esys_LoadExternal(ctx, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, NULL,
            external_public_key, TPM2_RH_OWNER, key_handle);
    if (r != TSS2_RC_SUCCESS) {
        charra_log_error("Loading external public key failed.");
        return CHARRA_RC_ERROR;
    }

    return CHARRA_RC_SUCCESS;
}

CHARRA_RC charra_tpm_make_credential_for_ak(ESYS_CONTEXT* esys_ctx,
        TPM2B_PUBLIC* ek_public_key, const TPM2B_NAME* ak_name,
        const TPM2B_DIGEST* credential,
        TPM2B_ID_OBJECT** credential_blob_out,
        TPM2B_ENCRYPTED_SECRET** wrapped_secret_out) {
    if (esys_ctx == NULL || ek_public_key == NULL || ak_name == NULL ||
            credential == NULL || credential_blob_out == NULL ||
            wrapped_secret_out == NULL) {
        return CHARRA_RC_BAD_ARGUMENT;
    }
    *credential_blob_out = NULL;
    *wrapped_secret_out = NULL;

    ESYS_TR ek_handle = ESYS_TR_NONE;
    CHARRA_RC charra_r = charra_load_external_public_key(
            esys_ctx, ek_public_key, &ek_handle);
    if (charra_r != CHARRA_RC_SUCCESS) {
        charra_log_error(
                "charra_tpm_make_credential_for_ak: could not load EK "
                "public key.");
        return charra_r;
    }

    TSS2_RC tss_r =
            Esys_MakeCredential(esys_ctx, ek_handle, ESYS_TR_NONE,
                    ESYS_TR_NONE, ESYS_TR_NONE, credential, ak_name,
                    credential_blob_out, wrapped_secret_out);

    if (Esys_FlushContext(esys_ctx, ek_handle) != TSS2_RC_SUCCESS) {
        /* not fatal to the MakeCredential result itself -- log and
         * continue, matching this file's other flush-failure handling */
        charra_log_error("charra_tpm_make_credential_for_ak: "
                         "Esys_FlushContext (EK handle) failed.");
    }

    if (tss_r != TSS2_RC_SUCCESS) {
        charra_log_error("charra_tpm_make_credential_for_ak: "
                         "Esys_MakeCredential failed: 0x%x",
                tss_r);
        return CHARRA_RC_TPM;
    }

    return CHARRA_RC_SUCCESS;
}
