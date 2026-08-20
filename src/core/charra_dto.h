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
    /* No certificate travels here, because there are none. tpm2_public_key
     * above IS the identity claim: both the RP and the Verifier look it up
     * in the trust anchor (see charra_trusted_keys.h). */
} msg_attestation_response_dto;


/**
 * @brief RP -> Verifier message: the redacted log plus everything needed to
 * check who produced it.
 *
 * Quote_r is a genuine TPM2_Quote, taken by the RP's own TPM over the PCR
 * it replayed log_r into (RP_REPLAY_PCR_INDEX, see rp_signing_key.h). The
 * RP does not assemble the signed bytes: the TPM reads the PCR itself and
 * builds rp_attestation_data -- magic, type, extraData = the Verifier's
 * nonce, pcrDigest = the composite over that one PCR -- then signs it.
 * Both the nonce and the PCR digest therefore live INSIDE the signed
 * structure, which is why neither travels as a field of its own.
 *
 * The Verifier's Step 3a checks all three halves: rp_public_key must be in
 * the trust anchor (charra_trusted_keys.h), the signature must verify
 * under it, and -- the part that ties the quote to the log -- replaying
 * log_r must reproduce the pcrDigest inside rp_attestation_data. Without
 * that last check the quote would only prove some PCR held some value.
 *
 * The Attester's raw event log is deliberately absent: log_r replaces it,
 * and forwarding the raw one would defeat the redaction entirely.
 */
typedef struct {
    /* --- Quote_r: the TPM's own signed attestation --- */
    /** TPMS_ATTEST the RP's TPM produced, carrying extraData (the
     * Verifier's nonce) and pcrDigest (the composite over the replay
     * PCR). Same shape and same bound as the Attester's
     * attestation_data below -- both are TPM2_Quote output now. */
    uint32_t rp_attestation_data_len;
    uint8_t rp_attestation_data[sizeof(TPMS_ATTEST)];
    /** RSA-PSS/SHA-256 over rp_attestation_data, produced by RP's TPM
     * signing primary (see
     * tpm2_create_primary_key_rsa2048_unrestricted()). Raw signature
     * bytes, not a marshaled TPMT_SIGNATURE. */
    uint32_t rp_signature_len;
    uint8_t rp_signature[CHARRA_RSA_SIGNATURE_LEN];

    /* --- the key that signature verifies under --- */
    /** The RP's public signing key, in the same TPM2B_PUBLIC shape the
     * Attester's tpm2_public_key travels in below. Both keys come from a
     * TPM and both are checked the same way -- looked up in the trust
     * anchor, see charra_trusted_keys.h -- so there is no reason for them
     * to arrive in different encodings. */
    uint32_t rp_public_key_len;
    uint8_t rp_public_key[sizeof(TPM2B_PUBLIC)];

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

    /* --- log_r itself --- */
    uint32_t log_r_len;
    uint8_t* log_r;
} msg_rp_evidence_dto;

/**
 * RP -> Attester: the verdict of RP's own Step 2a local verification.
 *
 * The spec's Step 2a ends "-> fail: negative proof to Attester", but the
 * Attester is the *server* of /attest -- its evidence is the last message
 * of that exchange, so there is no reply slot left for RP to reject it in.
 * (Steps 3a/3b have no such problem: the Verifier is the server there, so
 * its verdict rides back as the /appraise response.) Hence a separate
 * RP-initiated resource, which also keeps the Attester a pure passive
 * responder with no client logic of its own.
 *
 * Advisory only: nothing downstream depends on the Attester receiving it.
 * It exists so a rejected device can log/alert/re-measure instead of
 * silently continuing to believe its own state is fine.
 */
typedef struct {
    /** 1 = evidence accepted, 0 = rejected. */
    uint32_t accepted;
    /** Human-readable reason, for the Attester's log. May be empty. */
    uint32_t reason_len;
    uint8_t reason[128];
} msg_attestation_result_dto;

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
 * submitted_redacted_log is the RP's own redaction of that challenge log,
 * and comparing it byte-for-byte against the Verifier's own redaction is
 * the entire test. No PCR and no replay are involved: two identical logs
 * replay to the same PCR by construction, so a PCR check would only
 * restate the log check.
 *
 * rp_signature is an RSA-PSS/SHA-256 signature over
 * (submitted_redacted_log || salt), produced by RP's TPM-resident AK. It
 * is not part of the redaction test -- it answers a different question:
 * WHO is submitting. The grant is recorded against a key fingerprint, so
 * an unsigned submission could win a grant in another RP's name. Binding
 * in the salt ties the signature to THIS challenge, so a submission
 * captured from an earlier round cannot be replayed into a later one.
 * rp_public_key is the same TPM2B_PUBLIC msg_rp_evidence_dto carries,
 * and is checked the same way: looked up in the trust anchor (see
 * charra_trusted_keys.h).
 */
typedef struct {
    uint32_t submitted_redacted_log_len;
    uint8_t* submitted_redacted_log;

    uint32_t rp_signature_len;
    uint8_t rp_signature[CHARRA_RSA_SIGNATURE_LEN];
    uint32_t rp_public_key_len;
    uint8_t rp_public_key[sizeof(TPM2B_PUBLIC)];
} msg_qualify_submit_request_dto;

/**
 * /qualify/submit response: the Verifier's verdict, plus the deadline it
 * granted.
 *
 * expires_at is on the wire deliberately. The Verifier that ran the
 * handshake is the sole issuer of the grant -- its
 * --qualification-validity is what stamps the deadline, and that same
 * number goes into the file every Verifier reads. The RP needs it because
 * /appraise reports only pass or fail, never why: without the deadline the
 * RP could not know to re-qualify before the grant lapses, and would
 * simply be voted down until it happened to try again.
 *
 * Carrying it here also avoids the alternative, which is for the RP to
 * assume the window from a compile-time constant matching the Verifier's
 * -- a silent contract between two binaries that breaks the moment either
 * side changes it.
 */
typedef struct {
    /** 1 = qualified, 0 = not qualified. */
    uint32_t qualified;
    /** Absolute epoch seconds the grant is valid until; 0 when not
     * qualified. */
    uint64_t expires_at;
} msg_qualify_submit_response_dto;

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
