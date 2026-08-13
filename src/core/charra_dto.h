/* SPDX-License-Identifier: BSD-3-Clause */
/*****************************************************************************
 * Copyright 2019, Fraunhofer Institute for Secure Information Technology SIT.
 * All rights reserved.
 ****************************************************************************/

/**
 * @file charra_dto.h
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

#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <tss2/tss2_tpm2_types.h>

#include "../util/crypto_util.h"

#ifndef CHARRA_DTO_H
#define CHARRA_DTO_H

#define SIG_KEY_ID_MAXLEN 256

/* --- data transfer objects ---------------------------------------------- */

typedef struct {
    uint16_t tcg_hash_alg_id;  // TPM2_ALG_ID
    uint32_t pcrs_len;
    uint8_t pcrs[TPM2_MAX_PCRS];
} pcr_selection_dto;

typedef struct {
    uint64_t clock;
    uint32_t resetCounter;
    uint32_t restartCounter;
    bool safe;
} tpms_clock_info_dto;

typedef struct {
    uint16_t hash;  // TPMI_ALG_HASH (TPM2_ALG_ID)
    uint8_t sizeofSelect;
    uint8_t pcrSelect[TPM2_PCR_SELECT_MAX];
} tpms_pcr_selection_dto;

typedef struct {
    uint32_t count;
    tpms_pcr_selection_dto pcr_selections[TPM2_NUM_PCR_BANKS];
} tpml_pcr_selection_dto;

typedef struct {
    uint16_t size;
    uint8_t buffer[sizeof(TPMU_HA)];
} tpm2b_digest_dto;

typedef struct {
    tpml_pcr_selection_dto pcr_select;  // TPML_PCR_SELECTION
    tpm2b_digest_dto pcr_digest;        // TPM2B_DIGEST
} tpms_quote_info_dto;

typedef struct {
    uint16_t qualified_signer;  // TPM2B_NAME
    tpms_clock_info_dto clock_info;
    uint64_t firmware_version;
    tpms_quote_info_dto quote;
} tpms_attest_dto;

/* --- messages ----------------------------------------------------------- */

typedef struct {
    bool hello;
    size_t sig_key_id_len;
    uint8_t sig_key_id[SIG_KEY_ID_MAXLEN];
    size_t nonce_len;
    uint8_t nonce[sizeof(TPMU_HA)];
    uint32_t pcr_selections_len;
    pcr_selection_dto pcr_selections[TPM2_NUM_PCR_BANKS];
    uint32_t event_log_path_len;
    uint8_t* event_log_path;
} msg_attestation_request_dto;

typedef struct {
    // TODO Use tpms_attest_dto attestation_data;
    uint32_t attestation_data_len;
    uint8_t attestation_data[sizeof(TPM2B_ATTEST)];
    uint32_t tpm2_signature_len;
    uint8_t tpm2_signature[sizeof(TPMT_SIGNATURE)];
    uint32_t tpm2_public_key_len;
    uint8_t tpm2_public_key[sizeof(TPM2B_PUBLIC)];
    uint32_t event_log_len;
    uint8_t* event_log;
} msg_attestation_response_dto;

typedef struct {
    /* Attester's evidence, forwarded by RP */
    uint32_t attestation_data_len;
    uint8_t attestation_data[sizeof(TPM2B_ATTEST)];
    uint32_t tpm2_signature_len;
    uint8_t tpm2_signature[sizeof(TPMT_SIGNATURE)];
    uint32_t tpm2_public_key_len;
    uint8_t tpm2_public_key[sizeof(TPM2B_PUBLIC)];
    /* EK_a/AK_a: the AK certificate (DER) the Attester obtained via its own
     * earlier /certify_ak call, forwarded by RP -- Step 3b item 1's input.
     * No fixed upper bound (real certificates vary in size), heap-allocated
     * on unmarshal, same as event_log below. */
    uint32_t ak_certificate_len;
    uint8_t* ak_certificate;

    /* RP's own quote, proving RP genuinely produced event_log below */
    uint32_t attestation_data_rp_len;
    uint8_t attestation_data_rp[sizeof(TPM2B_ATTEST)];
    uint32_t tpm2_signature_rp_len;
    uint8_t tpm2_signature_rp[sizeof(TPMT_SIGNATURE)];
    uint32_t tpm2_public_key_rp_len;
    uint8_t tpm2_public_key_rp[sizeof(TPM2B_PUBLIC)];
    /* EK_r/AK_r: RP's own AK certificate (DER), obtained via its own
     * earlier /certify_ak call -- Step 3a item 1's input. Same
     * no-fixed-bound reasoning as ak_certificate above. */
    uint32_t ak_certificate_rp_len;
    uint8_t* ak_certificate_rp;

    /* log_r -- RP's redacted log, not Attester's raw one */
    uint32_t event_log_len;
    uint8_t* event_log;
} msg_rp_appraisal_dto;

/**
 * @brief RP -> Verifier message: the redacted log plus everything needed to
 * check who produced it.
 *
 * Quote_r's PCR_r is computed in software by replaying log_r (not a real
 * TPM2_Quote over live PCRs), but rp_signature is now produced by RP's own
 * TPM-resident AK (an unrestricted signing key, since PCR_r||nonce is
 * caller-supplied data a *restricted* signing key could not sign without a
 * validation ticket) rather than a throwaway software keypair -- and
 * ak_certificate_rp is that AK's certificate from RP's own earlier
 * /certify_ak call, letting the Verifier's Step 3a item 1 chain-verify it
 * and confirm rp_public_key is the certified key, not an unrelated one.
 * Quote_r therefore proves "a TPM-certified identity signed this PCR_r for
 * this nonce" -- still not "the TPM itself attests this PCR_r", which
 * would need PCR_r to come from a genuine TPM2_Quote instead of a
 * software replay of log_r. That remaining gap is tracked in
 * CHARRA_V2_NOTES.md.
 *
 * The Attester's raw event log is deliberately absent: log_r replaces it,
 * and forwarding the raw one would defeat the redaction entirely.
 */
typedef struct {
    /* --- Quote_r: the signed (PCR_r, nonce) pair --- */
    /** PCR composite digest over a replay of log_r. */
    uint8_t pcr_r[TPM2_SHA256_DIGEST_SIZE];
    /** Nonce the Verifier issued, proving freshness to the Verifier. */
    uint32_t verifier_nonce_len;
    uint8_t verifier_nonce[sizeof(TPMU_HA)];
    /** RSA-PSS/SHA-256 over (pcr_r || verifier_nonce), produced by RP's
     * TPM-resident AK (see charra_rp_identity.h). */
    uint32_t rp_signature_len;
    uint8_t rp_signature[CHARRA_RSA_SIGNATURE_LEN];

    /* --- the key that signature verifies under --- */
    /** DER encoding of the AK's public half -- same convention
     * charra_crypto_rsa_public_key_to_der() uses, even though the key
     * itself is now TPM-resident rather than a software keypair, so this
     * field's wire shape (and every existing caller of
     * charra_crypto_rsa_verify_signature() against it) is unchanged. */
    uint32_t rp_public_key_len;
    uint8_t rp_public_key[CHARRA_RSA_PUB_KEY_DER_MAX];

    /* EK_r/AK_r: RP's own AK certificate (DER), obtained via its own
     * earlier /certify_ak call -- Step 3a item 1's input. Chained against
     * the Verifier's CA, then rp_public_key above is checked to be the
     * certified key (charra_crypto_verify_cert_public_key_matches_der_key(),
     * since rp_public_key is DER, not a TPM2B_PUBLIC). No fixed upper
     * bound (real certificates vary in size); on unmarshal this points
     * into the caller's marshaled buffer rather than a fresh allocation,
     * same as log_r below -- not freed by the unmarshaler. */
    uint32_t ak_certificate_rp_len;
    uint8_t* ak_certificate_rp;

    /* --- the nonce the RP sent to the Attester --- */
    /** Lets the Verifier see which challenge the Attester's quote answers. */
    uint32_t attester_nonce_len;
    uint8_t attester_nonce[sizeof(TPMU_HA)];

    /* --- Attester's evidence, forwarded verbatim minus the event log --- */
    uint32_t attestation_data_len;
    uint8_t attestation_data[sizeof(TPM2B_ATTEST)];
    uint32_t tpm2_signature_len;
    uint8_t tpm2_signature[sizeof(TPMT_SIGNATURE)];
    uint32_t tpm2_public_key_len;
    uint8_t tpm2_public_key[sizeof(TPM2B_PUBLIC)];

    /* EK_a/AK_a: the Attester's AK certificate (DER), forwarded by RP --
     * Step 3b item 1's input. Present in the wire format for symmetry
     * with ak_certificate_rp above, but will be empty until the Attester
     * itself gains a /certify_ak client -- see CHARRA_V2_NOTES.md. Step 3b
     * item 1 correctly fails closed (empty certificate) until then, rather
     * than being silently skipped. Same borrowed-pointer convention as
     * ak_certificate_rp above. */
    uint32_t ak_certificate_len;
    uint8_t* ak_certificate;

    /* --- log_r itself --- */
    uint32_t log_r_len;
    uint8_t* log_r;
} msg_rp_evidence_dto;

/**
 * /certify_ak request: asks the Verifier, acting as Privacy CA, to certify
 * an AK. Sent by whichever party wants an AK certified (RP for itself, or
 * relayed for the Attester) -- the protocol itself doesn't distinguish
 * who's asking. A separate exchange from msg_rp_appraisal_dto, completed
 * once (or on renewal) before that AK is ever presented in an appraisal --
 * see CHARRA_V2_NOTES.md for why the two can't be merged into one message.
 */
typedef struct {
    /* EK certificate (DER), chains to the manufacturer root */
    uint32_t ek_certificate_len;
    uint8_t* ek_certificate;

    /* the AK's public key, to be certified */
    uint32_t ak_public_key_len;
    uint8_t ak_public_key[sizeof(TPM2B_PUBLIC)];

    /* the AK's TPM2B_NAME, exactly as the requester's own Esys_ReadPublic()
     * reports it -- NOT recomputed by the Verifier, see
     * charra_tpm_make_credential_for_ak()'s docstring for why that's safe */
    uint32_t ak_name_len;
    uint8_t ak_name[sizeof(TPM2B_NAME)];
} msg_certify_ak_request_dto;

/**
 * /certify_ak response: the TPM2_MakeCredential() output, plus the actual
 * signed AK certificate -- too large to fit inside MakeCredential's own
 * small credential field, so it travels alongside, AES-256-GCM-encrypted
 * under that field's contents (a fresh symmetric key, not the certificate
 * itself). Only a TPM that completes ActivateCredential with the matching
 * EK/AK pair ever recovers that key, and so ever recovers the certificate.
 */
typedef struct {
    /* TPM2_MakeCredential() outputs */
    uint32_t credential_blob_len;
    uint8_t credential_blob[sizeof(TPM2B_ID_OBJECT)];
    uint32_t wrapped_secret_len;
    uint8_t wrapped_secret[sizeof(TPM2B_ENCRYPTED_SECRET)];

    /* AES-256-GCM parameters for ak_certificate below; key = the 32-byte
     * credential recovered via ActivateCredential */
    uint8_t aes_gcm_nonce[12];
    uint8_t aes_gcm_tag[16];

    /* the signed AK certificate (DER), AES-256-GCM-encrypted as above */
    uint32_t ak_certificate_len;
    uint8_t* ak_certificate;
} msg_certify_ak_response_dto;

#endif /* CHARRA_DTO_H */
