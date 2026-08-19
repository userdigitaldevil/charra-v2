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

/* tss2_tpm2_types only: TPM2B_PUBLIC / TPMT_SIGNATURE are still the wire
 * shapes of Quote_a's fields. No TCTI, no ESAPI -- appraisal opens no TPM. */
#include <tss2/tss2_tpm2_types.h>

#include "../common/charra_log.h"
#include "../core/charra_ak_state.h"
#include "../core/charra_dto.h"
#include "../core/charra_helper.h"
#include "../core/charra_key_mgr.h"
#include "../core/charra_marshaling.h"
#include "../core/charra_qualification_state.h"
#include "../util/charra_util.h"
#include "../util/coap_util.h"
#include "../util/crypto_util.h"
#include "../util/hex_util.h"
#include "../util/io_util.h"
#include "verifier_shared.h"
#include "verifier_util.h"

#define LOG_NAME "verifier"

void coap_appraise_handler(struct coap_resource_t* resource,
                                struct coap_session_t* session,
                                const struct coap_pdu_t* request,
                                const struct coap_string_t* query,
                                struct coap_pdu_t* response) {
    int coap_r = 0;
    CHARRA_RC charra_r = CHARRA_RC_ERROR;
    /* Set by any exit that jumps to cleanup BEFORE a verdict is reached, so
     * those still tell the RP why rather than closing silently -- an
     * unexplained NO is exactly as unhelpful as a wrong one. */
    const char* early_fail_reason = NULL;
    bool verdict_reached = false;

    charra_coap_log_peer_address(LOG_NAME, "/appraise", session);

    /* Trust anchor for Step 3a/3b item 1 (EK_r/AK_r, EK_a/AK_a) -- both AK
     * certificates are checked against the Verifier's own CA, since the
     * Verifier is the sole issuer via /certify_ak. */
    char* verifier_ca_cert_der = NULL;
    size_t verifier_ca_cert_der_len = 0;

    /* Appended, not truncated, and per-port: several Verifiers share one
     * working directory, and each round's timings are wanted, not just the
     * last one's. Matches attester.c's timings_attester.txt. */
    FILE* p_file = fopen(durations_file_path, "a");
    if (p_file == NULL) {
        charra_log_error("[" LOG_NAME "] Could not open the duration log "
                         "file ('%s').",
                durations_file_path);
        early_fail_reason = "Verifier-side error: could not open its duration "
                            "log file";
        goto cleanup;
    }

    /* --- receive incoming data --- */

    /* get data */
    size_t data_len = 0;
    const uint8_t* data = NULL;
    size_t data_total_len = 0;
    if (!charra_coap_get_payload(request, LOG_NAME, "/appraise", &data,
                &data_len, &data_total_len)) {
        early_fail_reason = "malformed request: no CoAP payload";
        goto cleanup;
    }
    charra_log_info("[" LOG_NAME "] Received evidence of length %zu (%zu "
                    "total).",
            data_len, data_total_len);

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
    if ((charra_r = charra_unmarshal_rp_evidence(data_len, data, &res)) !=
            CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Could not parse CBOR data.");
        early_fail_reason = "malformed request: evidence is not valid CBOR";
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
     * data is later memcpy'd into attest.attestationData, a
     * BYTE[sizeof(TPMS_ATTEST)] sub-field of TPM2B_ATTEST -- smaller than
     * the whole struct by its leading UINT16 size field. */
    if (res.attestation_data_len > sizeof(TPMS_ATTEST)) {
        charra_log_error(
                "[" LOG_NAME
                "] Length of attestation data exceeds maximum allowed size.");
        early_fail_reason = "malformed request: Quote_a attestation data "
                            "exceeds the maximum allowed size";
        goto cleanup;
    }
    if (res.tpm2_signature_len > sizeof(TPMT_SIGNATURE)) {
        charra_log_error("[" LOG_NAME
                         "] Length of signature exceeds maximum allowed size.");
        early_fail_reason = "malformed request: Quote_a signature exceeds the "
                            "maximum allowed size";
        goto cleanup;
    }
    /* Quote_r's fields -- re-checked independently of whatever bounds
     * charra_unmarshal_rp_evidence() applies, same defense-in-depth style as
     * the rest of this function. */
    if (res.rp_signature_len != CHARRA_RSA_SIGNATURE_LEN) {
        charra_log_error(
                "[" LOG_NAME "] RP signature is not exactly the expected "
                "RSA-2048 signature size.");
        early_fail_reason =
                "malformed request: RP signature is not the expected RSA-2048 size";
        goto cleanup;
    }
    if (res.rp_public_key_len == 0 ||
            res.rp_public_key_len > sizeof(res.rp_public_key)) {
        charra_log_error("[" LOG_NAME "] RP public key has an unusable "
                         "length.");
        early_fail_reason = "malformed request: RP public key length unusable";
        goto cleanup;
    }

    /* --- verify TPM Quote --- */
    charra_log_info("[" LOG_NAME "] Starting verification.");

    /* No TPM is opened here. Every check in Steps 3a and 3b is public-key
     * math over data the RP sent, so mbedTLS does all of it -- see the
     * Quote_a signature check below. Keeping a TCTI open would have made a
     * Verifier that can answer perfectly well in software vote NO whenever
     * the (single-client) TPM simulator was busy or down. */

    /* Trust anchor for the EK/AK checks below. The EK certificate itself was
     * validated once during /certify_ak, so only the AK certificate that
     * call issued needs checking here, against the same CA it signs with. */
    if ((charra_r = charra_io_read_file(verifier_ca_cert_path,
                 &verifier_ca_cert_der, &verifier_ca_cert_der_len)) !=
            CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Could not read Verifier CA "
                         "certificate ('%s').",
                verifier_ca_cert_path);
        early_fail_reason =
                "Verifier-side error: could not read this Verifier's CA certificate";
        goto cleanup;
    }

    /* =====================================================================
     * Step 3a -- New Evidence Verification (Evidence_r = Quote_r, log_r,
     * EK_r/AK_r), per the supervisor's DRA-TLS spec.
     * ===================================================================== */

    /* Step 3a item 1: validate EK_r/AK_r certificate -- checks that RP's AK
     * certificate (from its own earlier /certify_ak call) chains to the
     * Verifier's CA, and that its embedded key matches rp_public_key, the
     * key that actually signs Quote_r below. Uses charra_crypto_verify_cert_
     * public_key_matches_der_key() rather than the TPM2B_PUBLIC-based
     * charra_crypto_verify_ekak_certificate() used for Step 3b, because
     * rp_public_key travels as plain DER -- see msg_rp_evidence_dto. */
    uint8_t ak_serial_rp[CHARRA_AK_STATE_SERIAL_LEN] = {0};
    bool attestation_result_ekak_rp = false;
    /* Why this check failed, for the consolidated reason list at the
     * verdict. Only read when the check actually failed. */
    const char* ekak_rp_why = "not verified";
    if (res.ak_certificate_rp_len == 0) {
        /* The RP sends its own AK certificate; an empty field means it never
         * obtained one from this Verifier. Still a NO -- unverified is
         * unverified -- but attributed to the RP, so the record shows what
         * was received rather than implying the RP went silent. */
        ekak_rp_why = "MISSING -- the RP sent no certificate for itself";
        charra_log_error("[" LOG_NAME "]     => the RP sent an EMPTY AK "
                         "certificate for itself -- nothing to verify "
                         "(Step 3a item 1). Rejecting.");
    } else {
        mbedtls_x509_crt ak_cert_rp_leaf;
        CHARRA_RC chain_rc = charra_crypto_verify_x509_cert_chain(
                res.ak_certificate_rp, res.ak_certificate_rp_len,
                (uint8_t*)verifier_ca_cert_der, verifier_ca_cert_der_len,
                &ak_cert_rp_leaf);
        if (chain_rc != CHARRA_RC_SUCCESS) {
            ekak_rp_why = "WRONG -- does not chain to this Verifier's CA";
            charra_log_error("[" LOG_NAME "]     => the AK certificate the RP "
                             "sent for itself did NOT chain to this "
                             "Verifier's CA (Step 3a item 1). Rejecting.");
        } else {
            /* A serial of any other width is not one we issued; looking it
             * up zero-padded would query the ledger for a serial nobody
             * holds, reading as "revoked" rather than "malformed". */
            if (ak_cert_rp_leaf.serial.len != sizeof(ak_serial_rp)) {
                ekak_rp_why = "WRONG -- serial number is not the width this "
                              "Verifier issues";
                charra_log_error("[" LOG_NAME "]     => the AK certificate the "
                                 "RP sent for itself chains correctly but its "
                                 "serial is %zu byte(s), not %zu. Rejecting.",
                        ak_cert_rp_leaf.serial.len, sizeof(ak_serial_rp));
            } else {
                memcpy(ak_serial_rp, ak_cert_rp_leaf.serial.p,
                        sizeof(ak_serial_rp));
                attestation_result_ekak_rp =
                        charra_crypto_verify_cert_public_key_matches_der_key(
                                &ak_cert_rp_leaf, res.rp_public_key,
                                res.rp_public_key_len) == CHARRA_RC_SUCCESS;
                if (attestation_result_ekak_rp) {
                    charra_crypto_log_cert_summary(
                            "RP's AK cert", &ak_cert_rp_leaf);
                } else {
                    ekak_rp_why = "MISMATCH -- does not match the key that "
                                  "signed Quote_r";
                    charra_log_error("[" LOG_NAME "]     => the AK certificate "
                                     "the RP sent for itself chains correctly "
                                     "but does NOT match the key that signed "
                                     "Quote_r. Rejecting.");
                }
            }
            mbedtls_x509_crt_free(&ak_cert_rp_leaf);
        }
    }
    uint8_t ek_fingerprint_rp[32] = {0};
    if (attestation_result_ekak_rp) {
        char ak_serial_rp_hex[33] = {0};
        charra_hex_encode_prefix(ak_serial_rp, sizeof(ak_serial_rp), ak_serial_rp_hex,
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
            charra_hex_encode_prefix(ek_fingerprint_rp, sizeof(ek_fingerprint_rp),
                    ek_fingerprint_rp_hex, sizeof(ek_fingerprint_rp_hex));
            charra_log_info(
                    "[" LOG_NAME "]     => RP identity %s...: AK certificate "
                    "is currently valid (expires at %ld, in %ld second(s)).",
                    ek_fingerprint_rp_hex, (long)ak_cert_expires_at_rp,
                    (long)(ak_cert_expires_at_rp - time(NULL)));
        } else {
            ekak_rp_why = "REVOKED or EXPIRED in this Verifier's ledger";
            charra_log_error("[" LOG_NAME "]     => the AK certificate the RP "
                             "sent for itself chains correctly but is REVOKED "
                             "or EXPIRED in this Verifier's issuance ledger!");
        }
    }

    /* Step 3a item 1b: RP qualification -- has THIS specific RP (identified
     * by ek_fingerprint_rp, the same identity charra_ak_state.h tracks)
     * passed /qualify + /qualify/submit recently enough? Looked up in the
     * ledger shared with every sibling Verifier -- see
     * qualification_state_file_path. */
    bool attestation_result_qualified = false;
    /* Distinguishes "never qualified" from "qualified once, since expired".
     * Both are a NO and both need the same remedy, but saying which saves
     * the reader from guessing. */
    bool qualification_record_found = false;
    time_t qualification_expires_at = 0;
    /* Whether we resolved WHICH RP this is, which is all the qualification
     * lookup needs -- a revoked certificate still identifies its owner, so
     * this runs even when Step 3a item 1 failed on validity. Only a
     * certificate we could not tie to any identity blocks it. */
    bool rp_identity_known = false;
    for (size_t i = 0; i < sizeof(ek_fingerprint_rp); ++i) {
        if (ek_fingerprint_rp[i] != 0) {
            rp_identity_known = true;
            break;
        }
    }
    if (rp_identity_known) {
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
        charra_hex_encode_prefix(ek_fingerprint_rp, sizeof(ek_fingerprint_rp),
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
     * (PCR_r || verifier_nonce) under RP's AK public key (DER-encoded), NOT
     * a TPM quote verification: PCR_r is a software replay of log_r, so
     * there is no TPMT_SIGNATURE/TPM2B_ATTEST to check. There is likewise no
     * TPM-side second opinion to AND in, the way Step 3b item 2 has. */
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
     * Attester, before cleansing. See charra_event_log.h. */

    /* Step 3a item 3: check nonce consistency -- Quote_r's verifier_nonce
     * must be exactly the challenge coap_nonce_handler() generated, a
     * Verifier-picked value rather than something RP chose itself. */
    clock_t start_verifiy_nonce, end_verifiy_nonce;
    double verify_nonce_duration;
    start_verifiy_nonce = clock();
    bool attestation_result_nonce_rp = false;
    {
        charra_log_info("[" LOG_NAME "] Verifying RP nonce ...");
        /* The len != 0 term is load-bearing, not defensive: with no
         * challenge outstanding both lengths are 0 and memcmp(_, _, 0)
         * returns 0, so an empty nonce would match. */
        attestation_result_nonce_rp =
                verifier_challenge_nonce_len != 0 &&
                res.verifier_nonce_len == verifier_challenge_nonce_len &&
                memcmp(res.verifier_nonce, verifier_challenge_nonce,
                        verifier_challenge_nonce_len) == 0;
        /* Snapshot for the failure diagnostic below -- the challenge is
         * spent immediately after. */
        uint8_t expected_nonce[TPM2_SHA256_DIGEST_SIZE] = {0};
        uint32_t expected_nonce_len = verifier_challenge_nonce_len;
        memcpy(expected_nonce, verifier_challenge_nonce,
                sizeof(expected_nonce));
        /* Single-use: spend the challenge once it has been checked, pass or
         * fail, so a captured bundle cannot be replayed until the next
         * /nonce rotates it. A retry needs a fresh /nonce. */
        memset(verifier_challenge_nonce, 0, sizeof(verifier_challenge_nonce));
        verifier_challenge_nonce_len = 0;
        if (attestation_result_nonce_rp == true) {
            charra_log_info("[" LOG_NAME "]     => Nonce in Quote_r is "
                            "valid! (matches the one sent)");
        } else {
            char expected_nonce_hex[17] = {0};
            char received_nonce_hex[17] = {0};
            charra_hex_encode_prefix(expected_nonce, expected_nonce_len, expected_nonce_hex,
                    sizeof(expected_nonce_hex));
            charra_hex_encode_prefix(res.verifier_nonce, res.verifier_nonce_len,
                    received_nonce_hex, sizeof(received_nonce_hex));
            charra_log_error("[" LOG_NAME
                             "]     => Nonce in Quote_r is NOT valid! (%s)",
                    expected_nonce_len == 0
                            ? "no challenge outstanding -- /nonce was never "
                              "called, or this one was already spent"
                            : "does not match the one sent");
            charra_log_error(
                    "[" LOG_NAME "]     => expected %u byte(s), starting "
                    "%s...; received %u byte(s), starting %s...",
                    expected_nonce_len, expected_nonce_hex,
                    res.verifier_nonce_len, received_nonce_hex);
        }
    }
    end_verifiy_nonce = clock();
    verify_nonce_duration = ((double) (end_verifiy_nonce - start_verifiy_nonce)) / CLOCKS_PER_SEC;
    fprintf(p_file, "verify nonce took %f seconds to execute \n", verify_nonce_duration);
    charra_log_info(
            "[" LOG_NAME "] Timing: verify RP nonce took %f second(s).",
            verify_nonce_duration);

    bool step_3a_passed = attestation_result_ekak_rp &&
                          attestation_result_qualified &&
                          attestation_result_signature_rp &&
                          attestation_result_nonce_rp;

    bool attestation_result_ekak = false;
    /* Why Step 3b item 1 failed, for the reason list at the verdict. */
    const char* ekak_att_why = "not verified";
    bool attestation_result_signature = false;
    bool attestation_result_nonce = false;

    /* Step 3b runs whatever Step 3a decided. Its three checks read only
     * fields of the received evidence (the Attester's certificate, Quote_a,
     * and the nonce), so nothing here depends on RP's identity having
     * verified -- the spec's "if 3a passes, proceed to 3b" gate was policy,
     * not a data dependency. Running it always means one appraisal reports
     * every problem at once instead of one round trip at a time.
     *
     * The verdict is unchanged and still fail-closed: every result below is
     * ANDed with Step 3a's. Note this does tell a peer that failed Step 3a
     * how the Attester's evidence fared, which the gate previously withheld. */
    {
        if (!step_3a_passed) {
            charra_log_error("[" LOG_NAME "] Step 3a FAILED -- evaluating "
                             "Step 3b anyway, to report every reason.");
        } else {
            charra_log_info(
                    "[" LOG_NAME "] Step 3a passed, proceeding to Step 3b ...");
        }

        /* =================================================================
         * Step 3b -- Original Evidence Verification (Evidence_a' =
         * Quote_a, EK_a/AK_a; log_a itself is never forwarded here).
         * ================================================================= */

        /* Step 3b item 1: validate EK_a/AK_a certificate -- same check as
         * Step 3a item 1, against the Attester's AK certificate (obtained
         * via its own /certify_ak call, forwarded here by RP) and the key
         * that actually signed Quote_a. */
        uint8_t ak_serial[CHARRA_AK_STATE_SERIAL_LEN] = {0};
        if (res.ak_certificate_attester_by_verifier_len == 0) {
            /* Attributed to the sender, not the subject: the RP fills this
             * in from its own per-Verifier cache (see
             * charra_rp_build_evidence_message()), so an empty one usually
             * means /certify_ak_of_attester never completed for this
             * Verifier -- not evidence of anything about the Attester.
             * Still a NO: unverified is unverified. */
            ekak_att_why = "MISSING -- the RP forwarded no certificate";
            charra_log_error(
                    "[" LOG_NAME "]     => the RP forwarded an EMPTY AK "
                    "certificate for the Attester -- nothing to verify. The "
                    "RP relays this certificate (/certify_ak_of_attester); "
                    "an empty one points at the RP, not the Attester.");
        } else {
            /* Chain check, then the ledger check below. The ledger lookup
             * used to be skipped here because the Attester was certified by
             * a single relayed Verifier, so every other Verifier's ledger
             * had no record of it. That premise is gone: each Verifier now
             * certifies the Attester under its own CA and records the
             * issuance, so the appraising Verifier always has its own
             * record of the serial it is looking at. */
            attestation_result_ekak = charra_crypto_verify_ekak_certificate(
                    res.ak_certificate_attester_by_verifier,
                    res.ak_certificate_attester_by_verifier_len,
                    (uint8_t*)verifier_ca_cert_der, verifier_ca_cert_der_len,
                    (TPM2B_PUBLIC*)res.tpm2_public_key, ak_serial) ==
                    CHARRA_RC_SUCCESS;
            if (attestation_result_ekak) {
                char ak_serial_hex[33] = {0};
                charra_hex_encode_prefix(ak_serial, sizeof(ak_serial), ak_serial_hex,
                        sizeof(ak_serial_hex));
                /* Chain validity alone cannot see a certificate superseded
                 * by a later renewal for the same EK -- only the ledger
                 * knows that. Same check Step 3a item 1 runs for the RP. */
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
                    ekak_att_why =
                            "REVOKED or EXPIRED in this Verifier's ledger";
                    charra_log_error(
                            "[" LOG_NAME "]     => the AK certificate the RP "
                            "forwarded for the Attester (serial %s...) chains "
                            "correctly but is REVOKED or EXPIRED in this "
                            "Verifier's issuance ledger!",
                            ak_serial_hex);
                }
            } else {
                /* Same attribution point as the empty case: the RP chose
                 * which certificate to forward, so a chain or key mismatch
                 * can equally mean the RP sent the wrong one (e.g. another
                 * Verifier's) as that the Attester's identity is bad. */
                ekak_att_why = "WRONG -- not issued by this Verifier's CA, "
                               "or does not match the key that signed Quote_a";
                charra_log_error(
                        "[" LOG_NAME "]     => the AK certificate the RP "
                        "forwarded for the Attester did NOT verify (chain or "
                        "key mismatch) -- either it was not issued by this "
                        "Verifier's CA, or it does not match the key that "
                        "signed Quote_a.");
            }
        }

        /* Step 3b item 2: verify Quote_a signature */
        TPM2B_PUBLIC* tpm2_public_key = (TPM2B_PUBLIC*)res.tpm2_public_key;
        TPMT_SIGNATURE signature = {0};
        memcpy(&signature, res.tpm2_signature, res.tpm2_signature_len);

        /* Verifying an RSA-PSS signature needs only the public key, so this
         * runs in software -- the same choice, for the same reason, that
         * charra_rp_appraise_evidence() makes for its own Quote_a check. */
        charra_log_info("[" LOG_NAME "] Verifying Quote_a signature ...");
        if (!charra_crypto_verify_quote_signature_mbedtls(tpm2_public_key,
                    res.attestation_data, res.attestation_data_len,
                    &signature, &attestation_result_signature)) {
            early_fail_reason = "Quote_a signature (Step 3b item 2): could not "
                                "be checked -- the Attester's public key is "
                                "unusable";
            goto cleanup;
        }

        /* unmarshal Quote_a's attestation data -- needed for its nonce
         * check right below */
        TPMS_ATTEST attest_struct = {0};
        if ((charra_r = charra_unmarshal_tpm2_quote(res.attestation_data_len,
                     res.attestation_data, &attest_struct)) !=
                CHARRA_RC_SUCCESS) {
            charra_log_error(
                    "[" LOG_NAME "] Error while unmarshaling TPM2 Quote.");
            early_fail_reason = "malformed request: Quote_a attestation data "
                                "is not a valid TPM2 quote structure";
            goto cleanup;
        }

        /* Step 3b item 3: check nonce consistency. Same single-use
         * treatment, and for the same reason, as Quote_r's nonce above: the
         * len != 0 term is load-bearing because
         * charra_verify_tpm2_quote_qualifying_data() compares two
         * zero-length buffers as equal, so with nothing outstanding a quote
         * carrying empty extraData would pass. */
        charra_log_info("[" LOG_NAME "] Verifying nonce ...");
        attestation_result_nonce =
                last_request.nonce_len != 0 &&
                charra_verify_tpm2_quote_qualifying_data(
                        last_request.nonce_len, last_request.nonce,
                        &attest_struct);
        char expected_nonce_hex[17] = {0};
        charra_hex_encode_prefix(last_request.nonce, last_request.nonce_len,
                expected_nonce_hex, sizeof(expected_nonce_hex));
        size_t expected_attester_nonce_len = last_request.nonce_len;
        /* Spent whichever way it went, so the next round must re-establish
         * it through /nonce. */
        memset(last_request.nonce, 0, sizeof(last_request.nonce));
        last_request.nonce_len = 0;
        if (attestation_result_nonce == true) {
            charra_log_info("[" LOG_NAME "]     => Nonce in TPM Quote is "
                            "valid! (matches the one sent)");
        } else {
            char received_nonce_hex[17] = {0};
            charra_hex_encode_prefix(attest_struct.extraData.buffer,
                    attest_struct.extraData.size, received_nonce_hex,
                    sizeof(received_nonce_hex));
            charra_log_error("[" LOG_NAME
                             "]     => Nonce in TPM Quote is NOT valid! (%s)",
                    expected_attester_nonce_len == 0
                            ? "no nonce outstanding -- /nonce was never "
                              "called, or this one was already spent"
                            : "does not match the one sent");
            charra_log_error(
                    "[" LOG_NAME "]     => expected %zu byte(s), starting "
                    "%s...; received %u byte(s), starting %s...",
                    expected_attester_nonce_len, expected_nonce_hex,
                    attest_struct.extraData.size, received_nonce_hex);
        }
    }

    /* --- output result --- */
    /* Order matches Step 3a then Step 3b, RP's evidence before Attester's. */
    bool attestation_result = step_3a_passed && attestation_result_ekak &&
                              attestation_result_signature &&
                              attestation_result_nonce;

    char ek_fingerprint_rp_hex_result[17] = {0};
    charra_hex_encode_prefix(ek_fingerprint_rp, sizeof(ek_fingerprint_rp),
            ek_fingerprint_rp_hex_result, sizeof(ek_fingerprint_rp_hex_result));

    /* Every reason this vote is a NO, in one place. Logged HERE ONLY -- the
     * RP is told the verdict, not the analysis. It cannot act on most of
     * these (they describe what this Verifier decided about evidence the RP
     * merely relayed), and shipping them would leak appraisal detail to a
     * peer that may itself have just failed Step 3a. */
    if (!attestation_result) {
        charra_log_error("[" LOG_NAME "] Voting NO. Reason(s):");
#define LOG_REASON(...)                                                        \
    do {                                                                       \
        char one[192];                                                         \
        snprintf(one, sizeof(one), __VA_ARGS__);                               \
        charra_log_error("[" LOG_NAME "]   - %s", one);                        \
    } while (0)
        if (!attestation_result_ekak_rp) {
            LOG_REASON("RP AK certificate (Step 3a item 1): %s", ekak_rp_why);
        }
        if (!attestation_result_qualified) {
            /* The lookup is keyed by ek_fingerprint_rp; without an identity
             * it never ran and must not be reported as a real failure. */
            LOG_REASON("RP qualification (Step 3a item 1b): %s",
                    !rp_identity_known
                            ? "NOT EVALUATED -- RP's certificate could not be "
                              "tied to any known identity"
                            : qualification_record_found
                                    ? "EXPIRED -- RP must redo /qualify"
                                    : "MISSING -- RP has never qualified "
                                      "with this Verifier");
        }
        if (!attestation_result_signature_rp) {
            LOG_REASON("Quote_r signature (Step 3a item 2): MISMATCH -- not a "
                       "valid signature by RP's AK over PCR_r");
        }
        if (!attestation_result_nonce_rp) {
            LOG_REASON("RP nonce (Step 3a item 3): WRONG -- Quote_r is not "
                       "bound to the challenge this Verifier issued");
        }
        if (!attestation_result_ekak) {
            LOG_REASON("Attester AK certificate (Step 3b item 1): %s",
                    ekak_att_why);
        }
        if (!attestation_result_signature) {
            LOG_REASON("Quote_a signature (Step 3b item 2): MISMATCH -- not a "
                       "valid signature by the Attester's AK");
        }
        if (!attestation_result_nonce) {
            LOG_REASON("Attester nonce (Step 3b item 3): WRONG -- Quote_a is "
                       "not bound to the expected nonce");
        }
#undef LOG_REASON
    }

    /* One uniform answer: pass or fail. The Verifier's decision is a vote,
     * not a work order -- it does not tell the RP which remedy to attempt,
     * and the RP does not retry on its say-so. Which checks failed, and why,
     * is in this Verifier's own log; the wire carries only the verdict. */
    const char* message;
    charra_log_info("[" LOG_NAME "] +----------------------------+");
    charra_log_info("[" LOG_NAME "]   RP identity: %s...",
            attestation_result_ekak_rp ? ek_fingerprint_rp_hex_result
                                       : "(unknown -- AK cert rejected)");
    if (attestation_result) {
        message = "Attestation successful!";
        charra_log_info("[" LOG_NAME "] |   ATTESTATION SUCCESSFUL   |");
    } else {
        /* Banner names the first failing check, so a log skimmer sees the
         * headline cause; the full list is logged above either way. */
        message = "Attestation failed!    ";
        if (!attestation_result_ekak_rp) {
            charra_log_info("[" LOG_NAME "] | RP AK CERTIFICATE REJECTED |");
        } else if (!attestation_result_qualified) {
            charra_log_info(qualification_record_found
                            ? "[" LOG_NAME "] |  RP QUALIFICATION EXPIRED  |"
                            : "[" LOG_NAME "] |     RP NOT QUALIFIED       |");
        } else if (!attestation_result_ekak) {
            charra_log_info("[" LOG_NAME "] | ATTESTER AK CERT REJECTED  |");
        } else {
            charra_log_info("[" LOG_NAME "] |     ATTESTATION FAILED     |");
        }
    }
    charra_log_info("[" LOG_NAME "] +----------------------------+");

    verdict_reached = true;
    coap_pdu_set_code(response, COAP_RESPONSE_CODE_CONTENT);

    end_appraise = clock();
    appraise_duration = ((double) (end_appraise - start_appraise)) / CLOCKS_PER_SEC;
    fprintf(p_file, "appraising took %f seconds to execute \n", appraise_duration);
    double total_measured = unmarshal_duration + verify_nonce_duration + verify_signature_duration;
    fprintf(p_file, "total measured %f  \n", total_measured);
    charra_log_info(
            "[" LOG_NAME "] Timing: total /appraise handling took %f "
            "second(s) (%f second(s) measured across sub-phases).",
            appraise_duration, total_measured);

    if ((coap_r = coap_add_data_large_response(resource, session, request,
                 response, query, COAP_MEDIATYPE_TEXT_PLAIN, -1, 0,
                 strlen(message), (const uint8_t*)message, NULL, NULL)) == 0) {
        charra_log_error("[" LOG_NAME
                         "] Error invoking coap_add_data_large_response().");
    }

cleanup:
    if (!verdict_reached) {
        const char* why = (early_fail_reason != NULL)
                                  ? early_fail_reason
                                  : "evidence rejected before appraisal could "
                                    "complete";
        /* Logged here only, like the reason list above; the RP gets the same
         * shape of answer as any other NO, not a distinct status it would
         * have to interpret. */
        charra_log_error("[" LOG_NAME "] Voting NO (no appraisal). Reason: %s",
                why);
        static const char failed_msg[] = "Attestation failed!    ";
        coap_pdu_set_code(response, COAP_RESPONSE_CODE_CONTENT);
        coap_add_data_large_response(resource, session, request, response,
                query, COAP_MEDIATYPE_TEXT_PLAIN, -1, 0, strlen(failed_msg),
                (const uint8_t*)failed_msg, NULL, NULL);
    }

    /* every path through this function reaches here exactly once */
    if (p_file != NULL) {
        fclose(p_file);
    }

    /* log_r, ak_certificate_* and rp's own AK cert are NOT freed here:
     * charra_unmarshal_rp_evidence() points them straight into the CoAP
     * request buffer (the borrowed-pointer convention msg_rp_evidence_dto
     * uses throughout, see charra_dto.h) rather than heap-allocating a
     * copy -- freeing them would free memory this handler never owned. */

    charra_io_free_file_buffer(&verifier_ca_cert_der);
}
