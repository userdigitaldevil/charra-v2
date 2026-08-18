/**
 * @file rp_identity.h
 * @brief RP's own TPM-resident EK+AK, and its AK certificate per Verifier.
 *
 * The keypair is created once per process and is Verifier-agnostic; the
 * certificate is per-Verifier, because each Verifier is its own CA and
 * tracks its own issuances. Both are cached on disk, so a restart normally
 * costs no TPM work and no network round trips.
 */

#ifndef CHARRA_RP_IDENTITY_H
#define CHARRA_RP_IDENTITY_H

#include <tss2/tss2_esys.h>

#include "../common/charra_error.h"
#include "../core/charra_dto.h"

/** @brief Create (or reload) RP's EK+AK. Idempotent, once per process. */
CHARRA_RC ensure_rp_ak_keypair(void);

/**
 * @brief Obtain RP's AK certificate from verifiers[verifier_index] via the
 * two-leg /certify_ak handshake, or reload it from cache.
 */
CHARRA_RC ensure_rp_ak_certificate(int verifier_index);

/** @brief Drop the cached certificate for one Verifier (memory and disk) so
 * the next ensure_rp_ak_certificate() genuinely re-provisions. Used after
 * that Verifier rejects the certificate as invalid or expired. */
void invalidate_cached_rp_ak_certificate(int verifier_index);

/** @brief One /certify_ak round trip; req->kind selects CHALLENGE or
 * CONFIRM. Serialised on rp_ak_reprovision_mutex, which guards the shared
 * response globals; the response is snapshotted out before unlocking so
 * ownership of its heap field passes to the caller. */
CHARRA_RC rp_certify_ak_exchange(const char* host, unsigned int port,
        const msg_certify_ak_request_dto* req,
        msg_certify_ak_response_dto* response_out);

/** @brief Open a TPM connection and load RP's persisted AK. Caller must
 * hold rp_tpm_mutex and must close promptly -- see rp_shared.h. */
CHARRA_RC rp_open_tpm_and_load_ak(ESYS_CONTEXT** esys_ctx_out,
        TSS2_TCTI_CONTEXT** tcti_ctx_out, ESYS_TR* ek_handle_out,
        ESYS_TR* ak_handle_out, TPM2B_NAME** ak_name_out);

#endif /* CHARRA_RP_IDENTITY_H */
