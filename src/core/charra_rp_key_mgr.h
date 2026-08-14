/**
 * @file charra_rp_key_mgr.h
 * @brief RP's TPM-resident EK/AK identity: creation, (re)loading across
 * process restarts, the ActivateCredential half of a /certify_ak round
 * trip, and signing with the AK.
 *
 * Design notes (see CHARRA_V2_NOTES.md for the full writeup):
 *
 * - EK: an RSA-2048 primary key in the endorsement hierarchy
 * (ESYS_TR_RH_ENDORSEMENT), empty auth. TPM2_CreatePrimary is
 * deterministic given the same hierarchy seed and template, so the EK
 * never needs to be persisted -- charra_rp_key_mgr_create_ek() reproduces
 * the identical public key on every call/process restart. This mirrors
 * how real EK provisioning works (burned in once, always reproducible),
 * with empty auth in place of the real EK template's adminWithPolicy --
 * a deliberate simplification: it lets Esys_ActivateCredential() below
 * authorize with ESYS_TR_PASSWORD directly instead of a PolicySecret
 * session against the endorsement hierarchy.
 *
 * - AK: an RSA-2048 *unrestricted* RSA-PSS/SHA-256 signing key, created as
 * a child of the EK. Unrestricted, not restricted like the Attester's own
 * quoting key (tpm2_util.c's tpm2_create_primary_key_rsa2048()): Quote_r's
 * signed payload (PCR_r || nonce, see msg_rp_evidence_dto) is caller-
 * supplied data replayed from a software PCR composite, not a TPM-
 * generated attestation structure -- a *restricted* signing key can only
 * sign the latter (TPM2_Quote/TPM2_Certify outputs) without an external
 * validation ticket. Unlike the EK, the AK's private area does need
 * persisting (charra_rp_key_mgr_save_ak()/_load_ak()): TPM2_Create's
 * output is sealed to its specific parent, but since the EK reproduces
 * identically every time, loading the same saved AK under a freshly
 * recreated EK reproduces the same AK handle and TPM2B_NAME.
 */

#ifndef CHARRA_RP_KEY_MGR_H
#define CHARRA_RP_KEY_MGR_H

#include <stdint.h>
#include <tss2/tss2_esys.h>
#include <tss2/tss2_tpm2_types.h>

#include "../common/charra_error.h"

/**
 * @brief Create (or reproduce) RP's TPM-resident EK. Deterministic: safe
 * to call once per process, result is the same public key every time.
 *
 * @param[out] ek_handle_out loaded, ready to use as a parent handle or in
 * charra_rp_key_mgr_activate_credential(). Caller should Esys_FlushContext()
 * it when done, same convention as this codebase's other transient handles.
 * @param[out] ek_public_out Esys_Free()-owned by the caller.
 */
CHARRA_RC charra_rp_key_mgr_create_ek(
        ESYS_CONTEXT* esys_ctx, ESYS_TR* ek_handle_out,
        TPM2B_PUBLIC** ek_public_out);

/**
 * @brief Create a fresh AK as a child of ek_handle. Only needed the first
 * time RP provisions an identity; charra_rp_key_mgr_load_ak() reloads it
 * on every subsequent run.
 *
 * @param[out] ak_handle_out loaded, ready to sign with or present to
 * Esys_ActivateCredential(). Caller should Esys_FlushContext() it when done.
 * @param[out] ak_public_out Esys_Free()-owned by the caller.
 * @param[out] ak_private_out Esys_Free()-owned by the caller; persist this
 * (charra_rp_key_mgr_save_private()) alongside ak_public_out to reload the
 * same AK later.
 * @param[out] ak_name_out Esys_Free()-owned by the caller; this is exactly
 * what a /certify_ak request's ak_name field must carry.
 */
CHARRA_RC charra_rp_key_mgr_create_ak(ESYS_CONTEXT* esys_ctx,
        ESYS_TR ek_handle, ESYS_TR* ak_handle_out, TPM2B_PUBLIC** ak_public_out,
        TPM2B_PRIVATE** ak_private_out, TPM2B_NAME** ak_name_out);

/**
 * @brief Reload a previously-created AK (from its saved public/private
 * blobs) under a freshly recreated EK.
 *
 * @param[out] ak_handle_out loaded, ready to use. Caller should
 * Esys_FlushContext() it when done.
 * @param[out] ak_name_out Esys_Free()-owned by the caller.
 */
CHARRA_RC charra_rp_key_mgr_load_ak(ESYS_CONTEXT* esys_ctx, ESYS_TR ek_handle,
        const TPM2B_PUBLIC* ak_public, const TPM2B_PRIVATE* ak_private,
        ESYS_TR* ak_handle_out, TPM2B_NAME** ak_name_out);

/**
 * @brief The RP-side half of a /certify_ak round trip: recovers the AES
 * key the Verifier wrapped in msg_certify_ak_response_dto, by presenting
 * both the AK (must genuinely be loaded under ek_handle -- this is what
 * makes ActivateCredential meaningful) and the EK to the TPM.
 *
 * @param[out] credential_out Esys_Free()-owned by the caller; its `buffer`
 * (size CHARRA_AES256GCM_KEY_LEN) is the AES key
 * charra_crypto_aes256gcm_decrypt() needs to recover the plaintext AK
 * certificate from msg_certify_ak_response_dto's ak_certificate field.
 */
CHARRA_RC charra_rp_key_mgr_activate_credential(ESYS_CONTEXT* esys_ctx,
        ESYS_TR ak_handle, ESYS_TR ek_handle,
        const TPM2B_ID_OBJECT* credential_blob,
        const TPM2B_ENCRYPTED_SECRET* wrapped_secret,
        TPM2B_DIGEST** credential_out);

/**
 * @brief Sign data with the AK: SHA-256(data), then TPM2_Sign with an
 * RSA-PSS scheme and a null validation ticket (telling the TPM "this
 * digest did not come from the TPM itself", which an *unrestricted*
 * signing key is allowed to sign -- see this header's file-level comment).
 *
 * @param[out] signature_out raw RSA-PSS signature bytes (not a TPMT_SIGNATURE
 * wrapper), buffer of at least CHARRA_RSA_SIGNATURE_LEN bytes -- the same
 * shape charra_crypto_rsa_sign() and charra_crypto_rsa_verify_signature()
 * already use, so the Verifier's existing signature check needs no changes.
 */
CHARRA_RC charra_rp_key_mgr_sign(ESYS_CONTEXT* esys_ctx, ESYS_TR ak_handle,
        const uint8_t* data, size_t data_len, uint8_t* signature_out);

/**
 * @brief DER-encode an AK's public half -- the shape msg_rp_evidence_dto's
 * rp_public_key travels in (see charra_dto.h for why: keeps the wire
 * format's existing DER convention even though the key is now
 * TPM-resident, not a software keypair).
 *
 * @param[out] der_out buffer of at least CHARRA_RSA_PUB_KEY_DER_MAX bytes
 * @param[out] der_len_out bytes written into der_out
 */
CHARRA_RC charra_rp_key_mgr_public_key_to_der(const TPM2B_PUBLIC* ak_public,
        uint8_t* der_out, size_t der_out_size, uint32_t* der_len_out);

/** @brief Persist a TPM2B_PUBLIC to path (raw struct dump). */
CHARRA_RC charra_rp_key_mgr_save_public(
        const char* path, const TPM2B_PUBLIC* pub);
/** @brief Load a TPM2B_PUBLIC previously saved with the function above. */
CHARRA_RC charra_rp_key_mgr_load_public(const char* path, TPM2B_PUBLIC* pub_out);

/** @brief Persist a TPM2B_PRIVATE to path (raw struct dump). */
CHARRA_RC charra_rp_key_mgr_save_private(
        const char* path, const TPM2B_PRIVATE* priv);
/** @brief Load a TPM2B_PRIVATE previously saved with the function above. */
CHARRA_RC charra_rp_key_mgr_load_private(
        const char* path, TPM2B_PRIVATE* priv_out);

#endif /* CHARRA_RP_KEY_MGR_H */
