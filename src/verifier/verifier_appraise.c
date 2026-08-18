/**
 * @file verifier_appraise.c
 * @brief See verifier_appraise.h.
 */

#include "verifier_appraise.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <tss2/tss2_mu.h>
#include <tss2/tss2_tctildr.h>
#include <tss2/tss2_tpm2_types.h>

#include "../common/charra_log.h"
#include "../common/charra_macro.h"
#include "../core/charra_ak_state.h"
#include "../core/charra_dto.h"
#include "../core/charra_helper.h"
#include "../core/charra_key_mgr.h"
#include "../core/charra_marshaling.h"
#include "../core/charra_qualification_state.h"
#include "../core/charra_rp_qualification.h"
#include "../util/cbor_util.h"
#include "../util/charra_util.h"
#include "../util/coap_util.h"
#include "../util/crypto_util.h"
#include "../util/io_util.h"
#include "../util/tpm2_util.h"
#include "verifier_shared.h"
#include "verifier_util.h"

#define LOG_NAME "verifier"

void coap_appraise_handler(struct coap_resource_t* resource,
                                struct coap_session_t* session,
                                const struct coap_pdu_t* request,
                                const struct coap_string_t* query,
                                struct coap_pdu_t* response) {
    int coap_r = 0;
    TSS2_RC tss_r = 0;

    log_peer_address("/appraise", session);

    ESYS_TR sig_key_handle = ESYS_TR_NONE;
    TPMT_TK_VERIFIED* validation = NULL;
    /* Quote_r has no TPM-side key load/verification ticket of its own --
     * it's a software RSA-PSS signature (mbedtls only), checked in Step 3a
     * item 2 below. */
    /* Declared here (rather than right before first use, further down) and
     * initialized to NULL so that every earlier 'goto cleanup' -- including
     * the fopen() failure right below -- leaves cleanup able to safely check
     * them instead of reading indeterminate values. */
    ESYS_CONTEXT* esys_ctx = NULL;
    TSS2_TCTI_CONTEXT* tcti_ctx = NULL;
    /* Trust anchor for Step 3a/3b item 1 (EK_r/AK_r, EK_a/AK_a) -- both AK
     * certificates are checked against the Verifier's own CA, since the
     * Verifier is the sole issuer via /certify_ak. Declared here for the
     * same reason as esys_ctx/tcti_ctx above. */
    char* verifier_ca_cert_der = NULL;
    size_t verifier_ca_cert_der_len = 0;

    FILE * p_file;
    p_file = fopen("durations_verifier.txt", "w");
    // If p_file is a null pointer, the file opening failed.
    if (p_file == NULL) {
        printf("File does not exist!");
        goto cleanup;
    }

    /* --- receive incoming data --- */

    /* get data */
    size_t data_len = 0;
    const uint8_t* data = NULL;
    size_t data_offset = 0;
    size_t data_total_len = 0;
    if ((coap_r = coap_get_data_large(
                 request, &data_len, &data, &data_offset, &data_total_len)) == 0) {
        charra_log_error("[" LOG_NAME "] Could not get CoAP PDU data.");
        attestation_rc = CHARRA_RC_ERROR;
        goto cleanup;
    } else {
        charra_log_info(
                "[" LOG_NAME "] Received evidence of length %zu.", data_len);
        charra_log_info("[" LOG_NAME "] Received evidence of total length %zu.",
                data_total_len);
    }

    clock_t start_appraise, end_appraise;
    double appraise_duration;
    start_appraise = clock();

    /* unmarshal data */
    clock_t start_unmarshal, end_unmarshal;
    double unmarshal_duration;
    start_unmarshal = clock();
    charra_log_info("[" LOG_NAME "] Parsing received CBOR data.");
    /* Quote_a (Attester's evidence, forwarded) + Quote_r (RP's own,
     * software-PCR-replay-based quote, signed by RP's TPM-resident AK) +
     * log_r (RP's redacted log, not Attester's raw one) -- see
     * msg_rp_evidence_dto in charra_dto.h. */
    msg_rp_evidence_dto res = {0};
    if ((attestation_rc = charra_unmarshal_rp_evidence(
                 data_len, data, &res)) != CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Could not parse CBOR data.");
        goto cleanup;
    }
    end_unmarshal = clock();
    unmarshal_duration = ((double) (end_unmarshal - start_unmarshal)) / CLOCKS_PER_SEC;
    fprintf(p_file, "unmarshal evidence took %f seconds to execute \n", unmarshal_duration);
    charra_log_info(
            "[" LOG_NAME "] Parsed evidence: log_r is %u byte(s).",
            res.log_r_len);
    charra_log_info(
            "[" LOG_NAME "] Timing: unmarshal evidence took %f second(s).",
            unmarshal_duration);

    /* verify data */
    /* Checked against sizeof(TPMS_ATTEST), not sizeof(TPM2B_ATTEST): this
     * data is later memcpy'd into attest.attestationData (see below), which
     * is a BYTE[sizeof(TPMS_ATTEST)] sub-field of TPM2B_ATTEST -- smaller
     * than the whole struct by (at least) the leading UINT16 size field.
     * Checking against the larger struct size let a too-long
     * attestation_data_len pass here and then overflow attestationData. */
    if (res.attestation_data_len > sizeof(TPMS_ATTEST)) {
        charra_log_error(
                "[" LOG_NAME
                "] Length of attestation data exceeds maximum allowed size.");
        attestation_rc = CHARRA_RC_ERROR;
        goto cleanup;
    }
    if (res.tpm2_signature_len > sizeof(TPMT_SIGNATURE)) {
        charra_log_error("[" LOG_NAME
                         "] Length of signature exceeds maximum allowed size.");
        attestation_rc = CHARRA_RC_ERROR;
        goto cleanup;
    }
    /* Quote_r's fields -- re-checked here independently of whatever bounds
     * charra_unmarshal_rp_evidence() itself applies, same defense-in-depth
     * style as the rest of this function. */
    if (res.rp_signature_len != CHARRA_RSA_SIGNATURE_LEN) {
        charra_log_error(
                "[" LOG_NAME "] RP signature is not exactly the expected "
                "RSA-2048 signature size.");
        attestation_rc = CHARRA_RC_ERROR;
        goto cleanup;
    }
    if (res.rp_public_key_len == 0 ||
            res.rp_public_key_len > sizeof(res.rp_public_key)) {
        charra_log_error("[" LOG_NAME "] RP public key has an unusable "
                         "length.");
        attestation_rc = CHARRA_RC_ERROR;
        goto cleanup;
    }

    /* --- verify TPM Quote --- */
    charra_log_info("[" LOG_NAME "] Starting verification.");

    clock_t start_init, end_init;
    double init_duration;
    start_init = clock();
    /* initialize ESAPI */
    if ((tss_r = Tss2_TctiLdr_Initialize(getenv("CHARRA_TCTI"), &tcti_ctx)) !=
            TSS2_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Tss2_TctiLdr_Initialize.");
        attestation_rc = CHARRA_RC_ERROR;
        goto cleanup;
    }
    if ((tss_r = Esys_Initialize(&esys_ctx, tcti_ctx, NULL)) !=
            TSS2_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Esys_Initialize.");
        attestation_rc = CHARRA_RC_ERROR;
        goto cleanup;
    }
    end_init = clock();
    init_duration = ((double) (end_init - start_init)) / CLOCKS_PER_SEC;
    fprintf(p_file, "init took %f seconds to execute \n", init_duration);
    charra_log_info("[" LOG_NAME "] Timing: TPM init took %f second(s).",
            init_duration);

    /* Trust anchor for the EK/AK checks below: both EK_r/AK_r (Step 3a item
     * 1) and EK_a/AK_a (Step 3b item 1) are AK certificates issued by this
     * Verifier's own CA via /certify_ak -- the EK certificate itself was
     * already validated once, during that earlier provisioning call, so
     * only the already-issued AK certificate needs checking here, against
     * the same CA coap_certify_ak_handler() signs with. */
    if ((attestation_rc = charra_io_read_file(verifier_ca_cert_path,
                 &verifier_ca_cert_der, &verifier_ca_cert_der_len)) !=
            CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Could not read Verifier CA "
                         "certificate ('%s').",
                verifier_ca_cert_path);
        goto cleanup;
    }

    /* =====================================================================
     * Step 3a -- New Evidence Verification (Evidence_r = Quote_r, log_r,
     * EK_r/AK_r), per the supervisor's DRA-TLS spec. Checked in full before
     * Step 3b below, matching the spec's own ordering ("If the verification
     * is passed, proceed to Step 3b").
     * ===================================================================== */

    /* Step 3a item 1: validate EK_r/AK_r certificate -- checks that RP's AK
     * certificate (obtained via its own earlier /certify_ak call) chains to
     * the Verifier's own CA, and that its embedded key matches
     * rp_public_key, the key that actually signs Quote_r below -- not some
     * other, unrelated key. Uses charra_crypto_verify_cert_public_key_
     * matches_der_key() rather than charra_crypto_verify_ekak_certificate()
     * (used for Step 3b below): rp_public_key travels as plain DER, not a
     * TPM2B_PUBLIC -- see msg_rp_evidence_dto's docstring in charra_dto.h. */
    uint8_t ak_serial_rp[16] = {0};
    bool attestation_result_ekak_rp = false;
    {
        mbedtls_x509_crt ak_cert_rp_leaf;
        CHARRA_RC chain_rc = charra_crypto_verify_x509_cert_chain(
                res.ak_certificate_rp, res.ak_certificate_rp_len,
                (uint8_t*)verifier_ca_cert_der, verifier_ca_cert_der_len,
                &ak_cert_rp_leaf);
        if (chain_rc == CHARRA_RC_SUCCESS) {
            if (ak_cert_rp_leaf.serial.len == 16) {
                memcpy(ak_serial_rp, ak_cert_rp_leaf.serial.p, 16);
            }
            attestation_result_ekak_rp =
                    charra_crypto_verify_cert_public_key_matches_der_key(
                            &ak_cert_rp_leaf, res.rp_public_key,
                            res.rp_public_key_len) == CHARRA_RC_SUCCESS;
            if (attestation_result_ekak_rp) {
                charra_crypto_log_cert_summary(
                        "RP's AK cert", &ak_cert_rp_leaf);
            }
            mbedtls_x509_crt_free(&ak_cert_rp_leaf);
        }
    }
    uint8_t ek_fingerprint_rp[32] = {0};
    if (attestation_result_ekak_rp) {
        char ak_serial_rp_hex[33] = {0};
        hex_prefix(ak_serial_rp, sizeof(ak_serial_rp), ak_serial_rp_hex,
                sizeof(ak_serial_rp_hex));
        charra_log_info(
                "[" LOG_NAME "]     => RP's AK certificate is valid! "
                "(serial %s...)",
                ak_serial_rp_hex);
        time_t ak_cert_expires_at_rp = 0;
        attestation_result_ekak_rp = charra_ak_state_check_serial_valid(
                rp_ak_state_file_path, ak_serial_rp, ek_fingerprint_rp,
                &ak_cert_expires_at_rp);
        if (attestation_result_ekak_rp) {
            char ek_fingerprint_rp_hex[17] = {0};
            hex_prefix(ek_fingerprint_rp, sizeof(ek_fingerprint_rp),
                    ek_fingerprint_rp_hex, sizeof(ek_fingerprint_rp_hex));
            charra_log_info(
                    "[" LOG_NAME "]     => RP identity %s...: AK certificate "
                    "is currently valid (expires at %ld, in %ld second(s)).",
                    ek_fingerprint_rp_hex, (long)ak_cert_expires_at_rp,
                    (long)(ak_cert_expires_at_rp - time(NULL)));
        }
    } else {
        charra_log_error("[" LOG_NAME "]     => RP's AK certificate did NOT "
                         "verify (chain or key mismatch)!");
    }

    /* Step 3a item 1b: RP qualification -- has THIS specific RP (identified
     * by ek_fingerprint_rp above, the same identity charra_ak_state.h
     * already tracks) passed /qualify + /qualify/submit within the last
     * CHARRA_RP_QUALIFICATION_VALIDITY_SECONDS? Only meaningful once the AK
     * certificate itself checked out -- ek_fingerprint_rp is only valid
     * when attestation_result_ekak_rp is true. Looked up in the
     * qualification ledger (qualification_state_file_path), shared with
     * every sibling Verifier instance -- see that variable's comment. */
    bool attestation_result_qualified = false;
    /* Distinguishes "never qualified" from "qualified once, but that record
     * has since expired" -- both leave attestation_result_qualified false,
     * but the RP's correct next step is the same either way (redo /qualify),
     * and telling it which case this is (see the response message chain
     * below) saves it from having to guess. */
    bool qualification_record_found = false;
    time_t qualification_expires_at = 0;
    if (attestation_result_ekak_rp) {
        charra_qualification_state_record* qual_records = NULL;
        uint32_t qual_count = 0;
        if (charra_qualification_state_load(qualification_state_file_path,
                    &qual_records, &qual_count) == CHARRA_RC_SUCCESS) {
            uint32_t qual_index = 0;
            if (charra_qualification_state_find_by_ek_fingerprint(
                        qual_records, qual_count, ek_fingerprint_rp,
                        &qual_index)) {
                qualification_record_found = true;
                qualification_expires_at = qual_records[qual_index].expires_at;
                attestation_result_qualified =
                        charra_qualification_state_is_valid(
                                &qual_records[qual_index], time(NULL));
            }
            free(qual_records);
        } else {
            charra_log_error(
                    "[" LOG_NAME "] Could not load qualification state.");
        }
        char ek_fingerprint_rp_hex[17] = {0};
        hex_prefix(ek_fingerprint_rp, sizeof(ek_fingerprint_rp),
                ek_fingerprint_rp_hex, sizeof(ek_fingerprint_rp_hex));
        if (attestation_result_qualified) {
            charra_log_info(
                    "[" LOG_NAME "]     => RP %s... is currently qualified "
                    "(expires at %ld, in %ld second(s)).",
                    ek_fingerprint_rp_hex, (long)qualification_expires_at,
                    (long)(qualification_expires_at - time(NULL)));
        } else if (qualification_record_found) {
            charra_log_error(
                    "[" LOG_NAME "]     => RP %s...'s qualification has "
                    "EXPIRED (was valid until %ld)!",
                    ek_fingerprint_rp_hex, (long)qualification_expires_at);
        } else {
            charra_log_error(
                    "[" LOG_NAME "]     => RP %s... is NOT currently "
                    "qualified (no passing /qualify/submit on record for "
                    "this identity)!",
                    ek_fingerprint_rp_hex);
        }
    }

    /* Step 3a item 2: verify Quote_r signature -- RSA-PSS/SHA-256 over
     * (PCR_r || verifier_nonce) under RP's AK public key (rp_public_key,
     * DER-encoded), NOT a TPM quote verification: PCR_r itself is a
     * software replay of log_r, not TPM-generated, so there is no
     * TPMT_SIGNATURE/TPM2B_ATTEST to check here -- see msg_rp_evidence_dto's
     * docstring in charra_dto.h. */
    clock_t start_verifiy_signature, end_verifiy_signature;
    double verify_signature_duration;
    start_verifiy_signature = clock();

    mbedtls_pk_context rp_pub_key_ctx;
    mbedtls_pk_init(&rp_pub_key_ctx);
    bool attestation_result_signature_rp = false;
    if (mbedtls_pk_parse_public_key(&rp_pub_key_ctx, res.rp_public_key,
                res.rp_public_key_len) != 0) {
        charra_log_error(
                "[" LOG_NAME "]     => Could not parse RP's public key!");
    } else if (mbedtls_pk_get_type(&rp_pub_key_ctx) != MBEDTLS_PK_RSA) {
        charra_log_error(
                "[" LOG_NAME "]     => RP's public key is not RSA!");
    } else if (mbedtls_rsa_set_padding(mbedtls_pk_rsa(rp_pub_key_ctx),
                       MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA256) != 0) {
        charra_log_error(
                "[" LOG_NAME "]     => Could not select RSA-PSS padding!");
    } else {
        uint8_t signed_data[sizeof(res.pcr_r) + sizeof(res.verifier_nonce)] =
                {0};
        memcpy(signed_data, res.pcr_r, sizeof(res.pcr_r));
        memcpy(signed_data + sizeof(res.pcr_r), res.verifier_nonce,
                res.verifier_nonce_len);
        attestation_result_signature_rp =
                charra_crypto_rsa_verify_signature(
                        mbedtls_pk_rsa(rp_pub_key_ctx), MBEDTLS_MD_SHA256,
                        signed_data, sizeof(res.pcr_r) + res.verifier_nonce_len,
                        res.rp_signature) == CHARRA_RC_SUCCESS;
    }
    mbedtls_pk_free(&rp_pub_key_ctx);
    if (attestation_result_signature_rp) {
        charra_log_info("[" LOG_NAME "]     => Quote_r signature is valid!");
    } else {
        charra_log_error(
                "[" LOG_NAME "]     => Quote_r signature is NOT valid!");
    }
    end_verifiy_signature = clock();
    verify_signature_duration = ((double) (end_verifiy_signature - start_verifiy_signature)) / CLOCKS_PER_SEC;
    fprintf(p_file, "verify signature took %f seconds to execute \n", verify_signature_duration);
    charra_log_info(
            "[" LOG_NAME "] Timing: verify Quote_r signature took %f "
            "second(s).",
            verify_signature_duration);

    /* log_r content verification (self-consistency, PCR replay, file-hash
     * policy) is NOT done here -- it is the RP App's own Step 2a
     * local-verification gate, run against the log it receives from the
     * Attester, before cleansing. See verify_log_entries_self_consistent(),
     * verify_log_matches_quote_r_pcr() and
     * verify_log_file_hashes_against_policy() in charra_event_log.h. */

    /* Step 3a item 3: check nonce consistency -- Quote_r's verifier_nonce
     * must be exactly the challenge this Verifier itself generated and
     * handed out in coap_nonce_handler() (verifier_challenge_nonce, a
     * genuine Verifier-picked value, not something RP merely echoed back
     * -- see that global's own comment for why the distinction matters). A
     * plain byte-compare proves freshness, same reasoning the old
     * TPM-quote-qualifying-data check used, just without a TPM structure to
     * unwrap. (verifier_challenge_nonce is a single-in-flight global, same
     * known cross-session-fragility class as last_request -- bug #6 in
     * CHARRA_V2_NOTES.md's verifier.c audit, deliberately left as is for
     * now.) */
    clock_t start_verifiy_nonce, end_verifiy_nonce;
    double verify_nonce_duration;
    start_verifiy_nonce = clock();
    bool attestation_result_nonce_rp = false;
    {
        charra_log_info("[" LOG_NAME "] Verifying RP nonce ...");
        attestation_result_nonce_rp =
                res.verifier_nonce_len == verifier_challenge_nonce_len &&
                memcmp(res.verifier_nonce, verifier_challenge_nonce,
                        verifier_challenge_nonce_len) == 0;
        if (attestation_result_nonce_rp == true) {
            charra_log_info("[" LOG_NAME "]     => Nonce in Quote_r is "
                            "valid! (matches the one sent)");
        } else {
            char expected_nonce_hex[17] = {0};
            char received_nonce_hex[17] = {0};
            hex_prefix(verifier_challenge_nonce, verifier_challenge_nonce_len,
                    expected_nonce_hex, sizeof(expected_nonce_hex));
            hex_prefix(res.verifier_nonce, res.verifier_nonce_len,
                    received_nonce_hex, sizeof(received_nonce_hex));
            charra_log_error("[" LOG_NAME
                             "]     => Nonce in Quote_r is NOT valid! (does "
                             "not match the one sent)");
            charra_log_error(
                    "[" LOG_NAME "]     => expected %u byte(s), starting "
                    "%s...; received %u byte(s), starting %s...",
                    verifier_challenge_nonce_len, expected_nonce_hex,
                    res.verifier_nonce_len, received_nonce_hex);
        }
    }
    end_verifiy_nonce = clock();
    verify_nonce_duration = ((double) (end_verifiy_nonce - start_verifiy_nonce)) / CLOCKS_PER_SEC;
    fprintf(p_file, "verify nonce took %f seconds to execute \n", verify_nonce_duration);
    charra_log_info(
            "[" LOG_NAME "] Timing: verify RP nonce took %f second(s).",
            verify_nonce_duration);

    /* Quote_r has no mbedtls-vs-TPM double-check the way Quote_a's TPM
     * quote does (both a TPM-side and an mbedtls-side signature check
     * running and being ANDed together) -- there is no TPM-side quote
     * verification available for a software PCR replay, only the mbedtls
     * RSA-PSS check above. */
    bool attestation_result_signature_rp_mbedtls = attestation_result_signature_rp;

    /* Step 3a gate: "If the verification is passed, proceed to Step 3b.
     * Otherwise, send a negative proof result to the relying party." A
     * failure anywhere in Step 3a skips Step 3b entirely -- Quote_a is not
     * even looked at, matching the spec's early-exit wording exactly
     * (previously all six checks ran unconditionally and were only ANDed
     * together at the end; that no longer matches the spec's text). */
    bool step_3a_passed = attestation_result_ekak_rp &&
                          attestation_result_signature_rp &&
                          attestation_result_signature_rp_mbedtls &&
                          attestation_result_nonce_rp;

    bool attestation_result_ekak = false;
    bool attestation_result_signature = false;
    bool attestation_result_signature_mbedtls = false;
    bool attestation_result_nonce = false;

    if (!step_3a_passed) {
        charra_log_error("[" LOG_NAME "] Step 3a FAILED -- skipping Step 3b "
                         "(Quote_a is not checked; negative result below).");
    } else {
        charra_log_info(
                "[" LOG_NAME "] Step 3a passed, proceeding to Step 3b ...");

        /* =================================================================
         * Step 3b -- Original Evidence Verification (Evidence_a' =
         * Quote_a, EK_a/AK_a; log_a itself is never forwarded to the
         * Verifier).
         * ================================================================= */

        /* Step 3b item 1: validate EK_a/AK_a certificate -- same check as
         * Step 3a item 1 above, against the Attester's AK certificate
         * (obtained via its own earlier /certify_ak call, forwarded here by
         * RP) and the key that actually signed Quote_a. */
        uint8_t ak_serial[16] = {0};
        if (res.ak_certificate_attester_by_verifier_len == 0) {
            charra_log_error(
                    "[" LOG_NAME "]     => Attester's AK certificate is "
                    "EMPTY -- the Attester has not completed "
                    "/certify_ak_of_attester's DELIVER_VERIFIER leg yet.");
            attestation_result_ekak = false;
        } else {
            /* Chain check, then the revocation check below. The ledger
             * lookup used to be skipped here because the Attester was
             * certified by a single relayed Verifier, so every other
             * Verifier's ledger had no record of it and the lookup would
             * fail spuriously. That premise is gone: each Verifier now
             * certifies the Attester under its own CA and records the
             * issuance in its own attester/ ledger, so the Verifier
             * appraising this evidence always has its own record of the
             * serial it is looking at. */
            attestation_result_ekak = charra_crypto_verify_ekak_certificate(
                    res.ak_certificate_attester_by_verifier,
                    res.ak_certificate_attester_by_verifier_len,
                    (uint8_t*)verifier_ca_cert_der, verifier_ca_cert_der_len,
                    (TPM2B_PUBLIC*)res.tpm2_public_key, ak_serial) ==
                    CHARRA_RC_SUCCESS;
            if (attestation_result_ekak) {
                char ak_serial_hex[33] = {0};
                hex_prefix(ak_serial, sizeof(ak_serial), ak_serial_hex,
                        sizeof(ak_serial_hex));
                /* Chain validity alone cannot see a certificate that was
                 * superseded by a later renewal for the same EK -- only the
                 * issuance ledger knows that. Same check Step 3a item 1
                 * already runs for the RP's own certificate. */
                time_t attester_cert_expires_at = 0;
                attestation_result_ekak = charra_ak_state_check_serial_valid(
                        attester_ak_state_file_path, ak_serial, NULL,
                        &attester_cert_expires_at);
                if (attestation_result_ekak) {
                    charra_log_info(
                            "[" LOG_NAME "]     => Attester's AK certificate "
                            "is valid! (serial %s..., expires at %ld, in %ld "
                            "second(s))",
                            ak_serial_hex, (long)attester_cert_expires_at,
                            (long)(attester_cert_expires_at - time(NULL)));
                } else {
                    charra_log_error(
                            "[" LOG_NAME "]     => Attester's AK certificate "
                            "(serial %s...) chains correctly but is REVOKED "
                            "or EXPIRED in this Verifier's issuance ledger!",
                            ak_serial_hex);
                }
            } else {
                charra_log_error(
                        "[" LOG_NAME "]     => Attester's AK certificate "
                        "did NOT verify (chain or key mismatch)!");
            }
        }

        /* Step 3b item 2: verify Quote_a signature */
        TPM2B_PUBLIC* tpm2_public_key = (TPM2B_PUBLIC*)res.tpm2_public_key;
        charra_log_info("[" LOG_NAME "] Loading TPM key.");
        if ((attestation_rc = charra_load_external_public_key(esys_ctx,
                     tpm2_public_key, &sig_key_handle)) != CHARRA_RC_SUCCESS) {
            charra_log_error(
                    "[" LOG_NAME "] Loading external public key failed.");
            goto cleanup;
        } else {
            charra_log_info("[" LOG_NAME "] External public key loaded.");
        }

        charra_log_info("[" LOG_NAME "] Preparing TPM Quote verification.");
        TPM2B_ATTEST attest = {0};
        attest.size = res.attestation_data_len;
        memcpy(attest.attestationData, res.attestation_data,
                res.attestation_data_len);
        TPMT_SIGNATURE signature = {0};
        memcpy(&signature, res.tpm2_signature, res.tpm2_signature_len);

        attestation_result_signature =
                charra_verify_tpm2_quote_signature_with_tpm_logged(esys_ctx,
                        sig_key_handle, &attest, &signature, &validation);
        if (!charra_crypto_verify_quote_signature_mbedtls(tpm2_public_key,
                    res.attestation_data, res.attestation_data_len,
                    &signature, &attestation_result_signature_mbedtls)) {
            goto cleanup;
        }

        /* unmarshal Quote_a's attestation data -- needed for its nonce
         * check right below */
        TPMS_ATTEST attest_struct = {0};
        attestation_rc = charra_unmarshal_tpm2_quote(res.attestation_data_len,
                res.attestation_data, &attest_struct);
        if (attestation_rc != CHARRA_RC_SUCCESS) {
            charra_log_error(
                    "[" LOG_NAME "] Error while unmarshaling TPM2 Quote.");
            goto cleanup;
        }

        /* Step 3b item 3: check nonce consistency */
        charra_log_info("[" LOG_NAME "] Verifying nonce ...");
        attestation_result_nonce = charra_verify_tpm2_quote_qualifying_data(
                last_request.nonce_len, last_request.nonce, &attest_struct);
        if (attestation_result_nonce == true) {
            charra_log_info("[" LOG_NAME "]     => Nonce in TPM Quote is "
                            "valid! (matches the one sent)");
        } else {
            char expected_nonce_hex[17] = {0};
            char received_nonce_hex[17] = {0};
            hex_prefix(last_request.nonce, last_request.nonce_len,
                    expected_nonce_hex, sizeof(expected_nonce_hex));
            hex_prefix(attest_struct.extraData.buffer,
                    attest_struct.extraData.size, received_nonce_hex,
                    sizeof(received_nonce_hex));
            charra_log_error("[" LOG_NAME
                             "]     => Nonce in TPM Quote is NOT valid! (does "
                             "not match the one sent)");
            charra_log_error(
                    "[" LOG_NAME "]     => expected %zu byte(s), starting "
                    "%s...; received %u byte(s), starting %s...",
                    last_request.nonce_len, expected_nonce_hex,
                    attest_struct.extraData.size, received_nonce_hex);
        }
    }

    /* --- output result --- */
    /* Order matches Step 3a then Step 3b, RP's evidence before Attester's.
     * Equivalent to step_3a_passed && (Step 3b's four results), since
     * Step 3b's results default to false whenever it was skipped. */

    bool attestation_result = attestation_result_ekak_rp &&
                              attestation_result_qualified &&
                              attestation_result_signature_rp &&
                              attestation_result_signature_rp_mbedtls &&
                              attestation_result_nonce_rp &&
                              attestation_result_ekak &&
                              attestation_result_signature &&
                              attestation_result_signature_mbedtls &&
                              attestation_result_nonce;


    char ek_fingerprint_rp_hex_result[17] = {0};
    hex_prefix(ek_fingerprint_rp, sizeof(ek_fingerprint_rp),
            ek_fingerprint_rp_hex_result, sizeof(ek_fingerprint_rp_hex_result));

    const char* message;
    coap_pdu_code_t response_code = COAP_RESPONSE_CODE_CONTENT;
    /* print attestation result */
    charra_log_info("[" LOG_NAME "] +----------------------------+");
    charra_log_info("[" LOG_NAME "]   RP identity: %s...",
            attestation_result_ekak_rp ? ek_fingerprint_rp_hex_result
                                       : "(unknown -- AK cert rejected)");
    if (attestation_result) {
        attestation_rc = CHARRA_RC_SUCCESS;
        message = "Attestation successful!\0";
        charra_log_info("[" LOG_NAME "] |   ATTESTATION SUCCESSFUL   |");
    } else if (!attestation_result_ekak_rp) {
        /* Distinct from any other appraisal failure: RP's OWN AK
         * certificate (Step 3a item 1) failed to chain-verify, or chained
         * fine but is expired/revoked (charra_ak_state_check_serial_valid()).
         * Signalled with 4.01 Unauthorized -- the same code /certify_ak
         * itself already uses for a bad EK certificate -- so RP can tell
         * "go redo /certify_ak and retry" apart from "your evidence itself
         * didn't check out," which a blind retry can never fix. */
        attestation_rc = CHARRA_RC_VERIFICATION_FAILED;
        message = "RP AK certificate invalid or expired!\0";
        response_code = COAP_RESPONSE_CODE_UNAUTHORIZED;
        charra_log_info("[" LOG_NAME "] |  RP AK CERTIFICATE REJECTED  |");
    } else if (!attestation_result_qualified) {
        /* Also distinct: the RP's AK certificate itself is fine, but this
         * specific identity hasn't passed /qualify + /qualify/submit
         * against THIS Verifier recently (see charra_qualification_
         * state.h). Deliberately 4.03 Forbidden, not 4.01 -- RP's retry
         * logic treats 4.01 as "go redo /certify_ak", which would be the
         * wrong reaction here; the fix is redoing /qualify, not AK
         * reprovisioning. Same response code either way (both mean "not
         * currently qualified, go fix that"), but the message text tells
         * RP which case it is -- "expired" specifically means it WAS
         * qualified and should just redo /qualify, not that something is
         * fundamentally wrong with its identity. */
        attestation_rc = CHARRA_RC_VERIFICATION_FAILED;
        response_code = COAP_RESPONSE_CODE_FORBIDDEN;
        if (qualification_record_found) {
            message = "RP qualification expired!\0";
            charra_log_info("[" LOG_NAME "] |  RP QUALIFICATION EXPIRED  |");
        } else {
            message = "RP not qualified!\0";
            charra_log_info("[" LOG_NAME "] |     RP NOT QUALIFIED       |");
        }
    } else if (!attestation_result_ekak) {
        /* Third distinct signal, and the Step 3b counterpart of the 4.01
         * above: RP's own identity is fine, but the ATTESTER's AK
         * certificate -- the one this Verifier issued and RP forwards --
         * is empty, unverifiable, expired or revoked. Without its own code
         * this folded into the generic failure below, which RP cannot act
         * on: it would resend the same dead certificate every cycle
         * forever, since nothing would ever invalidate its cache. 4.12
         * Precondition Failed, distinct from 4.01 (redo /certify_ak for
         * RP) and 4.03 (redo /qualify), tells RP to redo
         * /certify_ak_of_attester for THIS Verifier and retry once.
         * Every other Step 3b check still ran and is logged above; only
         * the response code is specialised. */
        attestation_rc = CHARRA_RC_VERIFICATION_FAILED;
        message = "Attester AK certificate invalid or expired!\0";
        response_code = COAP_RESPONSE_CODE_PRECONDITION_FAILED;
        charra_log_info(
                "[" LOG_NAME "] | ATTESTER AK CERT REJECTED  |");
    } else {
        attestation_rc = CHARRA_RC_VERIFICATION_FAILED;
        message = "Attestation failed!    \0";
        charra_log_info("[" LOG_NAME "] |     ATTESTATION FAILED     |");
    }
    charra_log_info("[" LOG_NAME "] +----------------------------+");

    coap_pdu_set_code(response, response_code);
    
    end_appraise = clock();
    appraise_duration = ((double) (end_appraise - start_appraise)) / CLOCKS_PER_SEC;


    fprintf(p_file, "appraising took %f seconds to execute \n", appraise_duration);
    double total_measured = unmarshal_duration + init_duration + verify_nonce_duration + verify_signature_duration;
    fprintf(p_file, "total measured %f  \n", total_measured);
    charra_log_info(
            "[" LOG_NAME "] Timing: total /appraise handling took %f "
            "second(s) (%f second(s) measured across sub-phases).",
            appraise_duration, total_measured);

    if ((coap_r = coap_add_data_large_response(resource, session, request, response,
                query, COAP_MEDIATYPE_TEXT_PLAIN, -1, 0,
                strlen(message), (const uint8_t *)message, NULL, (void *)strlen(message))) == 0) {
        charra_log_error("[" LOG_NAME
                         "] Error invoking coap_add_data_large_response().");
        //goto error;
    }
cleanup:
    /* close duration log file -- every path through this function reaches
     * here exactly once, so this is the only fclose() needed */
    if (p_file != NULL) {
        fclose(p_file);
    }

    /* flush handles */
    if (sig_key_handle != ESYS_TR_NONE) {
        if (Esys_FlushContext(esys_ctx, sig_key_handle) != TSS2_RC_SUCCESS) {
            charra_log_error(
                    "[" LOG_NAME "] TSS cleanup sig_key_handle failed.");
        }
    }
    /* log_r, ak_certificate and ak_certificate_rp are NOT freed here:
     * charra_unmarshal_rp_evidence() points them straight into the CoAP
     * request buffer (the same borrowed-pointer convention msg_rp_evidence_dto
     * uses throughout, see charra_dto.h) rather than heap-allocating a
     * fresh copy -- freeing them here would free memory this handler never
     * owned. (An earlier DTO this handler used, since deleted, did
     * heap-allocate these fields and free them here; that is no longer the
     * wire format in use.) */

    /* free ESAPI objects */
    if (validation != NULL) {
        Esys_Free(validation);
    }

    /* finalize ESAPI & TCTI */
    if (esys_ctx != NULL) {
        Esys_Finalize(&esys_ctx);
    }
    if (tcti_ctx != NULL) {
        Tss2_TctiLdr_Finalize(&tcti_ctx);
    }

    /* free the Verifier CA certificate buffer read for Step 3a/3b item 1 */
    charra_io_free_file_buffer(&verifier_ca_cert_der);
}
