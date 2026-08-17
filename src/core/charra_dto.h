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
#include "charra_sdk.h"

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
    /* EK_a/AK_a: Attester's AK cert as certified by a Verifier
     * (/certify_ak_of_attester's DELIVER_VERIFIER leg) -- Step 3b item 1's
     * input. No fixed upper bound, borrowed pointer like event_log above. */
    uint32_t ak_certificate_attester_by_verifier_len;
    uint8_t* ak_certificate_attester_by_verifier;
    /* Attester's AK cert as certified by RP's own CA (DELIVER_RP leg) --
     * forwarded alongside, so both independently-issued certs reach the
     * Verifier. */
    uint32_t ak_certificate_attester_by_rp_len;
    uint8_t* ak_certificate_attester_by_rp;
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
     * TPM-resident AK (see charra_rp_key_mgr.h). */
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

    /* EK_a/AK_a: Attester's AK cert as certified by a Verifier -- Step 3b
     * item 1's input, checked by every Verifier. Borrowed pointer, same
     * convention as ak_certificate_rp above. */
    uint32_t ak_certificate_attester_by_verifier_len;
    uint8_t* ak_certificate_attester_by_verifier;

    /* Attester's AK cert as certified by RP's own CA -- forwarded alongside,
     * not independently checked by the Verifier. */
    uint32_t ak_certificate_attester_by_rp_len;
    uint8_t* ak_certificate_attester_by_rp;

    /* --- log_r itself --- */
    uint32_t log_r_len;
    uint8_t* log_r;
} msg_rp_evidence_dto;

/**
 * /certify_ak "kind" values -- the two legs of the credential-activation
 * handshake the Verifier runs before certifying an AK.
 *
 * CHALLENGE: Verifier validates the EK chain and returns a random secret
 * wrapped via TPM2_MakeCredential; nothing is signed or recorded yet.
 * CONFIRM: requester echoes back the secret it recovered via
 * TPM2_ActivateCredential -- only the right TPM can -- and the Verifier
 * then signs, records, and releases the certificate.
 *
 * Two legs because a one-shot response forced the Verifier to sign and
 * revoke the prior certificate before any proof, so anyone holding a copy
 * of an EK certificate (public data) could knock out a working identity.
 */
#define CHARRA_CERTIFY_AK_CHALLENGE 0
#define CHARRA_CERTIFY_AK_CONFIRM 1

/** CHALLENGE secret size -- the largest MakeCredential reliably carries. */
#define CHARRA_CERTIFY_AK_SECRET_LEN 32

/**
 * `subject` values -- whose identity this /certify_ak call is for. Lets the
 * Verifier route the issuance into a separate ledger per identity kind
 * (state/verifier/ak-provisioning/rp/ vs .../attester/), since an RP AK
 * certificate and a relayed Attester AK certificate must never be tracked
 * (or revoked) as if they were the same kind of thing.
 */
#define CHARRA_CERTIFY_AK_SUBJECT_RP 0
#define CHARRA_CERTIFY_AK_SUBJECT_ATTESTER 1

/**
 * /certify_ak request, both legs (discriminated by `kind`): asks the
 * Verifier, acting as Privacy CA, to certify an AK. Sent by whichever party
 * wants one certified (RP for itself, or relayed for the Attester).
 */
typedef struct {
    uint32_t kind; /* one of CHARRA_CERTIFY_AK_* above */

    /* CHALLENGE only: one of CHARRA_CERTIFY_AK_SUBJECT_* above. Bound into
     * the pending challenge, so CONFIRM's ledger routing uses this value
     * regardless of what (if anything) CONFIRM itself sends. */
    uint32_t subject;

    /* EK certificate (DER). CHALLENGE validates it; CONFIRM uses its
     * SHA-256 to look the pending challenge up. */
    uint32_t ek_certificate_len;
    uint8_t* ek_certificate;

    /* CHALLENGE only. Not re-sent on CONFIRM: the Verifier certifies the
     * key it already bound into the challenge, so a leaked secret can't be
     * redirected onto a different key. */
    uint32_t ak_public_key_len;
    uint8_t ak_public_key[sizeof(TPM2B_PUBLIC)];

    /* CHALLENGE only: the AK's TPM2B_NAME as the requester's own
     * Esys_ReadPublic() reports it -- not recomputed by the Verifier, see
     * charra_tpm_make_credential_for_ak(). */
    uint32_t ak_name_len;
    uint8_t ak_name[sizeof(TPM2B_NAME)];

    /* CONFIRM only: the secret recovered via TPM2_ActivateCredential. */
    uint32_t secret_len;
    uint8_t secret[CHARRA_CERTIFY_AK_SECRET_LEN];
} msg_certify_ak_request_dto;

/**
 * /certify_ak response: CHALLENGE populates credential_blob +
 * wrapped_secret, CONFIRM populates ak_certificate.
 *
 * The certificate is sent in the clear -- the same bytes travel
 * unencrypted in every later /appraise anyway. Encrypting it under the
 * MakeCredential secret only ever served as an implicit possession proof,
 * which CONFIRM now makes explicit (and which would be self-defeating here,
 * since CONFIRM puts that secret on the wire).
 */
typedef struct {
    /* TPM2_MakeCredential() outputs (CHALLENGE leg) */
    uint32_t credential_blob_len;
    uint8_t credential_blob[sizeof(TPM2B_ID_OBJECT)];
    uint32_t wrapped_secret_len;
    uint8_t wrapped_secret[sizeof(TPM2B_ENCRYPTED_SECRET)];

    /* the signed AK certificate (DER), plaintext (CONFIRM leg) */
    uint32_t ak_certificate_len;
    uint8_t* ak_certificate;
} msg_certify_ak_response_dto;

/**
 * /certify_ak_of_attester "kind" values -- the Attester's single resource
 * (see CHARRA_V2_NOTES.md) used for all three legs of getting its own AK
 * certified, always initiated by the RP (Attester and every Verifier stay
 * fully passive throughout):
 *
 *   FETCH:            RP asks; Attester responds with its EK certificate +
 *                      AK public key + AK name (msg_ak_identity_response_dto
 *                      below).
 *   DELIVER_RP:        RP relays back a credential-wrapped AK certificate it
 *                      signed itself, with its own CA.
 *   ACTIVATE:          RP relays a Verifier's /certify_ak CHALLENGE; the
 *                      Attester activates it and returns the recovered
 *                      secret, which the RP relays as that Verifier's
 *                      CONFIRM. Only the Attester's TPM could produce it.
 *   DELIVER_VERIFIER:  RP relays back the plaintext AK certificate the
 *                      Verifier released once CONFIRM succeeded.
 *
 * All three non-FETCH legs use msg_certify_ak_of_attester_request_dto
 * below; the Attester ends up holding two independently-issued
 * certificates for the same identity, one from each CA.
 */
#define CHARRA_CERTIFY_AK_OF_ATTESTER_FETCH 0
#define CHARRA_CERTIFY_AK_OF_ATTESTER_DELIVER_RP 1
#define CHARRA_CERTIFY_AK_OF_ATTESTER_DELIVER_VERIFIER 2
#define CHARRA_CERTIFY_AK_OF_ATTESTER_ACTIVATE 3

/**
 * /certify_ak_of_attester response for kind == FETCH: Attester -> RP,
 * everything RP needs to drive both certification tracks on the Attester's
 * behalf. The "AK" here is a dedicated identity keypair the Attester
 * creates the same way ensure_rp_ak_keypair() creates the RP's own
 * (charra_rp_key_mgr_create_ek()/_create_ak(), reused as-is) -- NOT the
 * Attester's existing quoting key that signs Quote_a; the two are
 * deliberately independent identities.
 */
typedef struct {
    /* EK certificate (DER), chains to the manufacturer root -- same
     * convention as msg_certify_ak_request_dto's own ek_certificate. */
    uint32_t ek_certificate_len;
    uint8_t* ek_certificate;

    /* the AK's public key, to be certified by both CAs */
    uint32_t ak_public_key_len;
    uint8_t ak_public_key[sizeof(TPM2B_PUBLIC)];

    /* the AK's TPM2B_NAME, exactly as the Attester's own Esys_ReadPublic()
     * reports it -- same "not recomputed by the CA" convention
     * msg_certify_ak_request_dto's own ak_name already documents. */
    uint32_t ak_name_len;
    uint8_t ak_name[sizeof(TPM2B_NAME)];
} msg_ak_identity_response_dto;

/**
 * /certify_ak_of_attester request for every kind except FETCH: RP ->
 * Attester. Fields populated follow from `kind`:
 *
 *   DELIVER_RP:       credential_blob + wrapped_secret + aes_gcm_* +
 *                      ak_certificate (ciphertext) -- RP is the CA here and
 *                      still uses the one-shot wrapped form, so the
 *                      Attester's unwrap is what proves it holds the EK/AK.
 *   ACTIVATE:         credential_blob + wrapped_secret only.
 *   DELIVER_VERIFIER: ak_certificate only, plaintext -- the preceding
 *                      ACTIVATE already supplied the possession proof.
 */
typedef struct {
    uint32_t kind; /* one of CHARRA_CERTIFY_AK_OF_ATTESTER_* above */

    /* TPM2_MakeCredential() outputs (DELIVER_RP, ACTIVATE) */
    uint32_t credential_blob_len;
    uint8_t credential_blob[sizeof(TPM2B_ID_OBJECT)];
    uint32_t wrapped_secret_len;
    uint8_t wrapped_secret[sizeof(TPM2B_ENCRYPTED_SECRET)];

    /* AES-256-GCM parameters for ak_certificate below (DELIVER_RP only);
     * key = the 32-byte credential recovered via ActivateCredential */
    uint8_t aes_gcm_nonce[12];
    uint8_t aes_gcm_tag[16];

    /* the signed AK certificate (DER) -- AES-256-GCM-encrypted as above for
     * DELIVER_RP, plaintext for DELIVER_VERIFIER */
    uint32_t ak_certificate_len;
    uint8_t* ak_certificate;
} msg_certify_ak_of_attester_request_dto;

/**
 * /certify_ak_of_attester response for kind == ACTIVATE: the secret the
 * Attester recovered via TPM2_ActivateCredential, relayed by the RP as that
 * Verifier's CONFIRM leg.
 */
typedef struct {
    uint32_t secret_len;
    uint8_t secret[CHARRA_CERTIFY_AK_SECRET_LEN];
} msg_activate_credential_response_dto;

/**
 * /qualify response: Verifier -> RP, the raw fabricated log to redact plus
 * the salt to redact it with -- see charra_rp_qualification.h for the full
 * handshake this and msg_qualify_submit_request_dto below implement the
 * wire side of.
 *
 * salt is the one deliberate exception to redaction's usual "salt is never
 * transmitted" rule (see charra_sdk.h): the RP's redaction of this
 * challenge log has to come out byte-identical to the Verifier's own
 * golden-log redaction of it, which is only possible if both sides use the
 * same salt. Safe here specifically because challenge_log is synthetic
 * (fabricated paths, not a real device's) -- never do this for real
 * evidence.
 */
typedef struct {
    uint32_t challenge_log_len;
    uint8_t* challenge_log;
    uint8_t salt[CHARRA_SDK_PATH_SALT_LEN];
} msg_qualify_response_dto;

/**
 * /qualify/submit request: RP -> Verifier, proof that this RP's own
 * redaction pipeline was run against the /qualify challenge.
 *
 * submitted_redacted_log is the RP's own redaction of that challenge log;
 * submitted_pcr_digest is the PCR composite digest a replay of it produces.
 * rp_signature is an RSA-PSS/SHA-256 signature over submitted_pcr_digest,
 * produced by RP's TPM-resident AK (charra_rp_key_mgr_sign()) -- proving
 * *this* already-certified RP produced the submission, not an
 * unauthenticated third party relaying bytes. rp_public_key/
 * ak_certificate_rp are the same DER-encoded key + AK certificate
 * msg_rp_evidence_dto carries, checked the same way (chain to the
 * Verifier's CA, then confirm the certified key matches rp_public_key).
 */
typedef struct {
    uint32_t submitted_redacted_log_len;
    uint8_t* submitted_redacted_log;
    uint8_t submitted_pcr_digest[TPM2_SHA256_DIGEST_SIZE];

    uint32_t rp_signature_len;
    uint8_t rp_signature[CHARRA_RSA_SIGNATURE_LEN];
    uint32_t rp_public_key_len;
    uint8_t rp_public_key[CHARRA_RSA_PUB_KEY_DER_MAX];
    uint32_t ak_certificate_rp_len;
    uint8_t* ak_certificate_rp;
} msg_qualify_submit_request_dto;

/**
 * /get_verifiers request: RP -> Trust Manager, which Verifier IDs (the
 * numbering used as the first column of Trust Manager's own
 * verifiers_config.txt) to resolve to IP:port.
 *
 * A fixed-size field, not heap-allocated, like pcr_selections in
 * msg_attestation_request_dto above -- the RP already knows how many
 * Verifiers it is about to fan out to (its own num_verifiers sweep bound),
 * the same kind of small, caller-controlled count PCR selections are.
 */
#define CHARRA_MAX_REQUESTED_VERIFIERS 32

typedef struct {
    uint32_t verifier_ids_len;
    int32_t verifier_ids[CHARRA_MAX_REQUESTED_VERIFIERS];
} msg_get_verifiers_request_dto;

/** One resolved Verifier's connection info -- ip_address is a
 * NUL-terminated IPv4/hostname string, not raw bytes; MAXLEN includes
 * room for the terminator, matching verifier_info's own ip_address[16]
 * field in both trust_manager.c and relying_party.c. */
#define CHARRA_VERIFIER_IP_MAXLEN 16

typedef struct {
    char ip_address[CHARRA_VERIFIER_IP_MAXLEN];
    uint32_t port_number;
} msg_verifier_endpoint_dto;

/**
 * /get_verifiers response: Trust Manager -> RP, one entry per requested
 * Verifier ID that was actually found in verifiers_config.txt -- may be
 * FEWER than msg_get_verifiers_request_dto.verifier_ids_len if some
 * requested IDs are missing from that file (see trust_manager.c's
 * coap_handler(), "Lookup summary: ... missing"); callers must not assume
 * verifiers_len == the number requested.
 */
typedef struct {
    uint32_t verifiers_len;
    msg_verifier_endpoint_dto verifiers[CHARRA_MAX_REQUESTED_VERIFIERS];
} msg_get_verifiers_response_dto;

#endif /* CHARRA_DTO_H */
