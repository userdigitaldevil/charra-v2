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
#include "charra_trusted_keys.h"

/**
 * @brief The one signing-key name /attest accepts.
 *
 * A label, not a TPM object: nothing is stored under this name and nothing
 * is looked up. Matching it selects the Attester's restricted primary,
 * which tpm2_create_primary_key_rsa2048() derives from the owner hierarchy
 * on every call.
 *
 * Deliberately the SAME string the trust anchor uses for that identity, so
 * one name covers the whole life of the key: `--role attester` provisions
 * it, `# attester` labels it in keys/trusted_keys.txt, /attest names it on
 * the wire, and charra_trusted_keys_check() reports it back on a match. A
 * separate wire name would be a third vocabulary for one key.
 */
#define CHARRA_AK_A_KEY_ID CHARRA_ROLE_ATTESTER
#define CHARRA_AK_A_KEY_ID_LEN (sizeof(CHARRA_AK_A_KEY_ID) - 1)

/**
 * @brief Resolves a signing-key name to a loaded TPM key handle.
 *
 * Rejects any name that is not exactly CHARRA_AK_A_KEY_ID -- length first,
 * then bytes. The length term is load-bearing: memcmp() over a
 * caller-supplied length is a prefix match, and over zero bytes it returns
 * 0, so an empty name would otherwise be accepted as correct.
 */
CHARRA_RC charra_load_tpm2_key(ESYS_CONTEXT* ctx, const uint32_t key_len,
        const uint8_t* key, ESYS_TR* key_handle, TPM2B_PUBLIC** out_public);

CHARRA_RC charra_load_external_public_key(ESYS_CONTEXT* ctx,
        TPM2B_PUBLIC* external_public_key, ESYS_TR* key_handle);

#endif /* CHARRA_KEY_MGR_H */
