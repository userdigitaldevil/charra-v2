/**
 * @file attester_identity.h
 * @brief The Attester's own EK/AK identity keypair and its persistence.
 */

#ifndef CHARRA_ATTESTER_IDENTITY_H
#define CHARRA_ATTESTER_IDENTITY_H

#include <tss2/tss2_esys.h>
#include <tss2/tss2_tcti.h>
#include <tss2/tss2_tpm2_types.h>

#include "../common/charra_error.h"

/**
 * @brief Ensure the Attester's own EK/AK identity exists on disk, creating
 * it on first call. Idempotent and cheap on every call after the first --
 * this is a single-threaded process, so no mutex is needed the way
 * rp_identity.c's ensure_rp_ak_keypair() requires.
 */
CHARRA_RC ensure_attester_ak_keypair(void);

/**
 * @brief Loads EK+AK on an ALREADY-OPEN ESAPI context, at the Attester's
 * key paths.
 *
 * Exists for coap_attest_handler(), which reuses the connection it already
 * holds rather than opening a second concurrent one the simulator cannot
 * accept.
 */
CHARRA_RC attester_load_ak(ESYS_CONTEXT* esys_ctx, ESYS_TR* ek_handle_out,
        ESYS_TR* ak_handle_out, TPM2B_NAME** ak_name_out,
        TPM2B_PUBLIC* ak_public_out);

/**
 * @brief Open a fresh TPM connection and load the Attester's persisted
 * identity (EK + AK), ready for ActivateCredential or to answer /ak_identity
 * -shaped requests.
 */
CHARRA_RC attester_open_tpm_and_load_ak(ESYS_CONTEXT** esys_ctx_out,
        TSS2_TCTI_CONTEXT** tcti_ctx_out, ESYS_TR* ek_handle_out,
        ESYS_TR* ak_handle_out, TPM2B_NAME** ak_name_out,
        TPM2B_PUBLIC* ak_public_out);

#endif /* CHARRA_ATTESTER_IDENTITY_H */
