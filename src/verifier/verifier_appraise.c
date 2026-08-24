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

#include <tss2/tss2_tpm2_types.h>

#include "../common/charra_log.h"
#include "../core/charra_dto.h"
#include "../core/charra_event_log.h"
#include "../core/charra_helper.h"
#include "../core/charra_marshaling.h"
#include "../core/charra_trusted_keys.h"
#include "../util/charra_util.h"
#include "../util/coap_util.h"
#include "../util/crypto_util.h"
#include "../util/hex_util.h"
#include "../util/io_util.h"
#include "verifier_shared.h"
#include "verifier_util.h"

#define LOG_NAME "verifier"

/** Source files this Verifier expects the RP's appraisal-and-redaction to
 * run -- its own reference measurement, known independently rather than
 * asked of the RP or of any TEE code: exactly as a real relying party holds
 * its own copy of an expected enclave measurement, not one fetched from the
 * device it is checking. Must name the same files RP's rp_evidence.c passes
 * to its TEE (see rp_appraisal_code_files there); keep the two in sync by
 * hand if either ever changes -- there is deliberately no shared symbol
 * between them, since the Verifier does not call into RP's TEE code at
 * all. */
static const char* const expected_appraisal_code_files[] = {
        "src/rp/rp_evidence.c",
        "src/core/charra_sdk.c",
        "src/core/charra_event_log.c",
};

/**
 * @brief Independently hashes expected_appraisal_code_files together, in
 * list order -- the same construction TEE.c's tee_hash_files() uses, but
 * run here, by the Verifier itself against its own copy of the source, and
 * never by calling into RP's TEE code.
 */
static CHARRA_RC verifier_hash_expected_appraisal_code(
        uint8_t hash_out[TPM2_SHA256_DIGEST_SIZE]) {
    uint8_t* combined = NULL;
    size_t combined_len = 0;
    CHARRA_RC result = CHARRA_RC_SUCCESS;

    for (size_t i = 0; i < sizeof(expected_appraisal_code_files) /
                                sizeof(expected_appraisal_code_files[0]);
            i++) {
        char* content = NULL;
        size_t content_len = 0;
        if (charra_io_read_file(expected_appraisal_code_files[i], &content,
                    &content_len) != CHARRA_RC_SUCCESS) {
            charra_log_error(
                    "[" LOG_NAME "] Could not read expected appraisal file "
                    "'%s'.",
                    expected_appraisal_code_files[i]);
            result = CHARRA_RC_ERROR;
            break;
        }

        uint8_t* grown = realloc(combined, combined_len + content_len);
        if (grown == NULL) {
            charra_io_free_file_buffer(&content);
            result = CHARRA_RC_ERROR;
            break;
        }
        combined = grown;
        memcpy(combined + combined_len, content, content_len);
        combined_len += content_len;
        charra_io_free_file_buffer(&content);
    }

    if (result == CHARRA_RC_SUCCESS) {
        result = hash_sha256(combined_len, combined, hash_out);
    }
    free(combined);
    return result;
}

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
     * TPM-produced quote, signed by RP's TPM-resident signing key) +
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
    if (res.rp_attestation_data_len == 0 ||
            res.rp_attestation_data_len > sizeof(res.rp_attestation_data)) {
        charra_log_error("[" LOG_NAME "] Quote_r attestation data has an "
                         "unusable length.");
        early_fail_reason = "malformed request: Quote_r attestation data "
                            "length unusable";
        goto cleanup;
    }
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
    /* TEE Attestation Document's fields (see TEE.h) -- same style as
     * Quote_r's above. */
    if (res.tee_signature_len != CHARRA_RSA_SIGNATURE_LEN) {
        charra_log_error(
                "[" LOG_NAME "] TEE signature is not exactly the expected "
                "RSA-2048 signature size.");
        early_fail_reason = "malformed request: TEE signature is not the "
                            "expected RSA-2048 size";
        goto cleanup;
    }
    if (res.tee_public_key_len == 0 ||
            res.tee_public_key_len > sizeof(res.tee_public_key)) {
        charra_log_error("[" LOG_NAME "] TEE public key has an unusable "
                         "length.");
        early_fail_reason = "malformed request: TEE public key length unusable";
        goto cleanup;
    }

    /* --- verify TPM Quote --- */
    charra_log_info("[" LOG_NAME "] Starting verification.");

    /* No TPM is opened here. Every check in Steps 3a and 3b is public-key
     * math over data the RP sent, so mbedTLS does all of it -- see the
     * Quote_a/Quote_r signature checks below. Keeping a TCTI open would
     * have made a Verifier that can answer perfectly well in software vote
     * NO whenever the (single-client) TPM simulator was busy or down. */

    /* =====================================================================
     * Step 3a -- New Evidence Verification (Evidence_r = Quote_r, log_r,
     * AK_r), per the supervisor's DRA-TLS spec.
     * ===================================================================== */

    /* Step 3a item 1: is AK_r an identity we trust? We look the RP's
     * Quote_r signing key up in the trust anchor (keys/trusted_keys.txt).
     * A key that appears there was vouched for before any of this ran,
     * which is the whole of the identity check -- no certificate, no chain
     * walk, no serial, no issuance ledger, because nothing is issued at
     * runtime. See charra_trusted_keys.h for what that does and does not
     * buy. */
    bool attestation_result_ekak_rp = false;
    /* Why this check failed, for the consolidated reason list at the
     * verdict. Only read when the check actually failed. */
    const char* ekak_rp_why = "not verified";
    char rp_key_name[128] = {0};
    if (res.rp_public_key_len == 0) {
        ekak_rp_why = "MISSING -- the RP sent no public key for itself";
        charra_log_error("[" LOG_NAME "]     => the RP sent an EMPTY public "
                         "key -- nothing to identify it by (Step 3a item 1). "
                         "Rejecting.");
    } else {
        attestation_result_ekak_rp =
                res.rp_public_key_len == sizeof(TPM2B_PUBLIC) &&
                charra_trusted_keys_check(NULL,
                        (const TPM2B_PUBLIC*)res.rp_public_key, rp_key_name,
                        sizeof(rp_key_name)) == CHARRA_RC_SUCCESS;
        if (attestation_result_ekak_rp) {
            charra_log_info("[" LOG_NAME "]     => RP's signing key is "
                            "trusted: '%s'",
                    rp_key_name);
        } else {
            ekak_rp_why = "UNTRUSTED -- not in the trust anchor";
            charra_log_error("[" LOG_NAME "]     => the key that signed "
                             "Quote_r is NOT in the trust anchor "
                             "(Step 3a item 1). Rejecting.");
        }
    }

    /* Step 3a item 2: verify Quote_r's signature -- RSA-PSS/SHA-256 over
     * the TPMS_ATTEST the RP's TPM built, under RP's public key. Same shape
     * as Step 3b item 2 now: both roles send a real TPM2_Quote, so both are
     * checked the same way. */
    clock_t start_verifiy_signature, end_verifiy_signature;
    double verify_signature_duration;
    start_verifiy_signature = clock();

    mbedtls_rsa_context rp_rsa_pub_key = {0};
    bool attestation_result_signature_rp = false;
    if (res.rp_public_key_len != sizeof(TPM2B_PUBLIC)) {
        charra_log_error("[" LOG_NAME "]     => RP's public key is not a "
                         "TPM2B_PUBLIC!");
    } else if (charra_crypto_tpm_pub_key_to_mbedtls_pub_key(
                       (const TPM2B_PUBLIC*)res.rp_public_key,
                       &rp_rsa_pub_key) != CHARRA_RC_SUCCESS) {
        charra_log_error(
                "[" LOG_NAME "]     => Could not convert RP's public key!");
    } else {
        attestation_result_signature_rp =
                charra_crypto_rsa_verify_signature(&rp_rsa_pub_key,
                        MBEDTLS_MD_SHA256, res.rp_attestation_data,
                        res.rp_attestation_data_len,
                        res.rp_signature) == CHARRA_RC_SUCCESS;
        mbedtls_rsa_free(&rp_rsa_pub_key);
    }
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

    /* Unmarshal Quote_r's attestation data -- the nonce and the PCR digest
     * both live inside it, put there by the RP's TPM. */
    TPMS_ATTEST rp_attest = {0};
    bool rp_attest_parsed =
            charra_unmarshal_tpm2_quote(res.rp_attestation_data_len,
                    res.rp_attestation_data, &rp_attest) == CHARRA_RC_SUCCESS;
    if (!rp_attest_parsed) {
        charra_log_error("[" LOG_NAME "]     => Quote_r's attestation data is "
                         "not a valid TPM2 quote structure!");
    }

    /* Step 3a item 3: check nonce consistency -- read from the quote's
     * extraData, not from a field beside it: the TPM put it there, so it is
     * covered by the signature just checked. Quote_r's extraData must be
     * exactly the challenge coap_nonce_handler() generated, a
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
                rp_attest_parsed && verifier_challenge_nonce_len != 0 &&
                charra_verify_tpm2_quote_qualifying_data(
                        (uint16_t)verifier_challenge_nonce_len,
                        verifier_challenge_nonce, &rp_attest);
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
            charra_hex_encode_prefix(rp_attest.extraData.buffer,
                    rp_attest.extraData.size, received_nonce_hex,
                    sizeof(received_nonce_hex));
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
                    rp_attest.extraData.size, received_nonce_hex);
        }
    }
    end_verifiy_nonce = clock();
    verify_nonce_duration = ((double) (end_verifiy_nonce - start_verifiy_nonce)) / CLOCKS_PER_SEC;
    fprintf(p_file, "verify nonce took %f seconds to execute \n", verify_nonce_duration);
    charra_log_info(
            "[" LOG_NAME "] Timing: verify RP nonce took %f second(s).",
            verify_nonce_duration);

    /* Step 3a item 4: does log_r actually produce the PCR digest the quote
     * attests? This is what binds the quote to the log. Without it Quote_r
     * would only prove that SOME PCR held SOME value freshly -- the RP
     * could replay a log of its choosing, quote the result honestly, and
     * send an unrelated log_r alongside it.
     *
     * The RP extended log_r's PCR-10-tagged entries into its own replay
     * PCR, which started at zero; replaying the same entries in software
     * from zero must give the same value. One PCR is selected, so the
     * composite the TPM signed is SHA-256 of just that value. */
    clock_t start_replay = clock();
    bool attestation_result_pcr_rp = false;
    {
        charra_log_info("[" LOG_NAME "] Replaying log_r against Quote_r's PCR "
                        "digest ...");
        uint8_t replayed_pcr[TPM2_SHA256_DIGEST_SIZE] = {0};
        uint8_t expected_digest[TPM2_SHA256_DIGEST_SIZE] = {0};
        if (!rp_attest_parsed) {
            /* already reported above */
        } else if (charra_replay_ima_log(res.log_r, res.log_r_len,
                           CHARRA_IMA_PCR_INDEX, replayed_pcr) !=
                   CHARRA_RC_SUCCESS) {
            charra_log_error("[" LOG_NAME "]     => log_r does not replay -- "
                             "it is malformed.");
        } else if (hash_sha256(sizeof(replayed_pcr), replayed_pcr,
                           expected_digest) != CHARRA_RC_SUCCESS) {
            charra_log_error("[" LOG_NAME "]     => Could not compute the "
                             "expected PCR composite digest.");
        } else {
            const TPM2B_DIGEST* quoted = &rp_attest.attested.quote.pcrDigest;
            attestation_result_pcr_rp =
                    quoted->size == sizeof(expected_digest) &&
                    memcmp(quoted->buffer, expected_digest,
                            sizeof(expected_digest)) == 0;
            if (attestation_result_pcr_rp) {
                charra_log_info("[" LOG_NAME "]     => log_r replays to the "
                                "PCR digest Quote_r attests!");
            } else {
                char want[17] = {0};
                char got[17] = {0};
                charra_hex_encode_prefix(expected_digest,
                        sizeof(expected_digest), want, sizeof(want));
                charra_hex_encode_prefix(quoted->buffer, quoted->size, got,
                        sizeof(got));
                charra_log_error("[" LOG_NAME "]     => log_r does NOT match "
                                 "Quote_r's PCR digest! (expected %s..., "
                                 "quote says %s...)",
                        want, got);
            }
        }
    }
    charra_log_info("[" LOG_NAME "] Timing: replay log_r took %f second(s).",
            ((double)(clock() - start_replay)) / CLOCKS_PER_SEC);

    bool step_3a_passed = attestation_result_ekak_rp &&
                          attestation_result_signature_rp &&
                          attestation_result_nonce_rp &&
                          attestation_result_pcr_rp;

    bool attestation_result_ekak = false;
    /* Why Step 3b item 1 failed, for the reason list at the verdict. */
    const char* ekak_att_why = "not verified";
    bool attestation_result_signature = false;
    bool attestation_result_nonce = false;
    bool attestation_result_tee = false;
    /* Why the TEE Attestation Document check failed, for the reason list at
     * the verdict. */
    const char* tee_why = "not verified";

    /* Step 3b runs whatever Step 3a decided. Its checks read only fields of
     * the received evidence (the Attester's public key, Quote_a, and the
     * nonce), so nothing here depends on RP's identity having verified --
     * the spec's "if 3a passes, proceed to 3b" gate was policy, not a data
     * dependency. Running it always means one appraisal reports every
     * problem at once instead of one round trip at a time.
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
         * Quote_a, AK_a; log_a itself is never forwarded here).
         * ================================================================= */

        /* Step 3b item 1: is AK_a an identity we trust? Same lookup as
         * Step 3a item 1, against the key that actually signed Quote_a
         * (tpm2_public_key, forwarded verbatim by the RP). Nothing is
         * relayed alongside it, because there is nothing to relay: both
         * roles' public keys were written offline into the one trust
         * anchor every Verifier reads. */
        if (res.tpm2_public_key_len == 0) {
            ekak_att_why = "MISSING -- the RP forwarded no Attester key";
            charra_log_error(
                    "[" LOG_NAME "]     => the RP forwarded an EMPTY public "
                    "key for the Attester -- nothing to verify. Rejecting.");
        } else {
            char attester_key_name[128] = {0};
            attestation_result_ekak =
                    charra_trusted_keys_check(NULL,
                            (const TPM2B_PUBLIC*)res.tpm2_public_key,
                            attester_key_name,
                            sizeof(attester_key_name)) == CHARRA_RC_SUCCESS;
            if (attestation_result_ekak) {
                charra_log_info("[" LOG_NAME "]     => Attester's signing key "
                                "is trusted: '%s'",
                        attester_key_name);
            } else {
                ekak_att_why = "UNTRUSTED -- not in the trust anchor";
                charra_log_error("[" LOG_NAME "]     => the key that signed "
                                 "Quote_a is NOT in the trust anchor. "
                                 "Rejecting.");
            }
        }

        /* Step 3b item 2: verify Quote_a signature. Verifying an RSA-PSS
         * signature needs only the public key, so this runs in software --
         * the same choice, for the same reason, that
         * charra_rp_appraise_evidence() makes for its own Quote_a check. */
        TPM2B_PUBLIC* tpm2_public_key = (TPM2B_PUBLIC*)res.tpm2_public_key;
        TPMT_SIGNATURE signature = {0};
        memcpy(&signature, res.tpm2_signature, res.tpm2_signature_len);

        charra_log_info("[" LOG_NAME "] Verifying Quote_a signature ...");
        if (!charra_crypto_verify_quote_signature_mbedtls(tpm2_public_key,
                    res.attestation_data, res.attestation_data_len,
                    &signature, &attestation_result_signature)) {
            early_fail_reason = "Quote_a signature (Step 3b item 2): could not "
                                "be checked -- the Attester's public key is "
                                "unusable";
            goto cleanup;
        }
        charra_log_info("[" LOG_NAME "]     => Quote_a signature is %s!",
                attestation_result_signature ? "valid" : "NOT valid");

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

        /* Step 3a item 5: simulated TEE Attestation Document (see TEE.h).
         *
         * Proves the RP's appraisal-and-redaction actually ran the code
         * this Verifier itself expects, against exactly this evidence: the
         * signed file_hash must match this Verifier's own hash of the
         * appraisal/cleaning source, and the signed report_data must match
         * hash(verifier_nonce || pcrdigest_a || log_r) recomputed here --
         * not a log_r built from a different log_a, forwarded alongside a
         * different Quote_r, or answering a different nonce. Placed here,
         * after Quote_a's own nonce check above, because it needs
         * attest_struct's pcrdigest_a, which that check already
         * unmarshaled. verifier_nonce itself comes from rp_attest.extraData
         * -- the actual nonce value Quote_r's own signature covers, not a
         * separately-carried field (see msg_rp_evidence_dto). */
        charra_log_info(
                "[" LOG_NAME "] Verifying TEE Attestation Document ...");
        mbedtls_pk_context tee_pub_key_ctx;
        mbedtls_pk_init(&tee_pub_key_ctx);
        bool tee_signature_ok = false;
        if (mbedtls_pk_parse_public_key(&tee_pub_key_ctx, res.tee_public_key,
                    res.tee_public_key_len) != 0) {
            tee_why = "MALFORMED -- could not parse the TEE's public key";
            charra_log_error(
                    "[" LOG_NAME "]     => could not parse the TEE's public "
                    "key!");
        } else if (mbedtls_pk_get_type(&tee_pub_key_ctx) != MBEDTLS_PK_RSA) {
            tee_why = "MALFORMED -- the TEE's public key is not RSA";
            charra_log_error(
                    "[" LOG_NAME "]     => the TEE's public key is not "
                    "RSA!");
        } else if (mbedtls_rsa_set_padding(mbedtls_pk_rsa(tee_pub_key_ctx),
                           MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA256) != 0) {
            tee_why =
                    "Verifier-side error: could not select RSA-PSS padding";
            charra_log_error(
                    "[" LOG_NAME "]     => could not select RSA-PSS "
                    "padding!");
        } else {
            uint8_t tee_signed_data[sizeof(res.tee_file_hash) +
                    sizeof(res.tee_report_data)] = {0};
            memcpy(tee_signed_data, res.tee_file_hash,
                    sizeof(res.tee_file_hash));
            memcpy(tee_signed_data + sizeof(res.tee_file_hash),
                    res.tee_report_data, sizeof(res.tee_report_data));
            tee_signature_ok =
                    charra_crypto_rsa_verify_signature(
                            mbedtls_pk_rsa(tee_pub_key_ctx), MBEDTLS_MD_SHA256,
                            tee_signed_data, sizeof(tee_signed_data),
                            res.tee_signature) == CHARRA_RC_SUCCESS;
            if (!tee_signature_ok) {
                tee_why = "MISMATCH -- not a valid signature by the "
                          "claimed TEE key over (file_hash || report_data)";
                charra_log_error("[" LOG_NAME "]     => TEE Attestation "
                                 "Document signature is NOT valid!");
            }
        }
        mbedtls_pk_free(&tee_pub_key_ctx);

        bool tee_file_hash_ok = false;
        if (tee_signature_ok) {
            uint8_t expected_file_hash[TPM2_SHA256_DIGEST_SIZE] = {0};
            tee_file_hash_ok =
                    verifier_hash_expected_appraisal_code(
                            expected_file_hash) == CHARRA_RC_SUCCESS &&
                    memcmp(expected_file_hash, res.tee_file_hash,
                            sizeof(expected_file_hash)) == 0;
            if (!tee_file_hash_ok) {
                tee_why = "WRONG CODE -- the attested file_hash does not "
                          "match this Verifier's own copy of the "
                          "appraisal/cleaning code";
                charra_log_error(
                        "[" LOG_NAME "]     => file_hash does NOT match "
                        "this Verifier's own hash of the appraisal/"
                        "cleaning code!");
            }
        }

        bool tee_report_data_ok = false;
        if (tee_file_hash_ok) {
            size_t expected_input_len = (size_t)rp_attest.extraData.size +
                    attest_struct.attested.quote.pcrDigest.size +
                    res.log_r_len;
            uint8_t* expected_input = malloc(expected_input_len);
            if (expected_input == NULL) {
                tee_why = "Verifier-side error: out of memory recomputing "
                          "REPORT_DATA";
                charra_log_error(
                        "[" LOG_NAME "]     => out of memory recomputing "
                        "REPORT_DATA!");
            } else {
                size_t off = 0;
                memcpy(expected_input + off, rp_attest.extraData.buffer,
                        rp_attest.extraData.size);
                off += rp_attest.extraData.size;
                memcpy(expected_input + off,
                        attest_struct.attested.quote.pcrDigest.buffer,
                        attest_struct.attested.quote.pcrDigest.size);
                off += attest_struct.attested.quote.pcrDigest.size;
                memcpy(expected_input + off, res.log_r, res.log_r_len);

                uint8_t expected_report_data[TPM2_SHA256_DIGEST_SIZE] = {0};
                tee_report_data_ok =
                        hash_sha256(expected_input_len, expected_input,
                                expected_report_data) == CHARRA_RC_SUCCESS &&
                        memcmp(expected_report_data, res.tee_report_data,
                                sizeof(expected_report_data)) == 0;
                free(expected_input);
                if (!tee_report_data_ok) {
                    tee_why = "WRONG BINDING -- the attested report_data "
                              "does not match hash(verifier_nonce || "
                              "pcrdigest_a || log_r) for this evidence";
                    charra_log_error(
                            "[" LOG_NAME "]     => report_data does NOT "
                            "match hash(verifier_nonce || pcrdigest_a || "
                            "log_r)!");
                }
            }
        }

        attestation_result_tee =
                tee_signature_ok && tee_file_hash_ok && tee_report_data_ok;
        if (attestation_result_tee) {
            charra_log_info(
                    "[" LOG_NAME "]     => TEE Attestation Document is "
                    "valid: correct code, correctly bound to this "
                    "evidence!");
        }
    }

    /* --- output result --- */
    /* Order matches Step 3a then Step 3b, RP's evidence before Attester's. */
    bool attestation_result = step_3a_passed && attestation_result_ekak &&
                              attestation_result_signature &&
                              attestation_result_nonce &&
                              attestation_result_tee;

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
            LOG_REASON("RP signing key (Step 3a item 1): %s", ekak_rp_why);
        }
        if (!attestation_result_signature_rp) {
            LOG_REASON("Quote_r signature (Step 3a item 2): MISMATCH -- not "
                       "a valid signature by RP's AK over the attestation");
        }
        if (!attestation_result_nonce_rp) {
            LOG_REASON("RP nonce (Step 3a item 3): WRONG -- Quote_r is not "
                       "bound to the challenge this Verifier issued");
        }
        if (!attestation_result_pcr_rp) {
            LOG_REASON("log_r vs Quote_r (Step 3a item 4): MISMATCH -- the "
                       "log sent does not replay to the PCR the quote "
                       "attests");
        }
        if (!attestation_result_ekak) {
            LOG_REASON("Attester signing key (Step 3b item 1): %s",
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
        if (!attestation_result_tee) {
            LOG_REASON("TEE Attestation Document (Step 3a item 5): %s",
                    tee_why);
        }
#undef LOG_REASON
    }

    /* One uniform answer: pass or fail. The Verifier's decision is a vote,
     * not a work order -- it does not tell the RP which remedy to attempt,
     * and the RP does not retry on its say-so. Which checks failed, and why,
     * is in this Verifier's own log; the wire carries only the verdict. */
    const char* message;
    charra_log_info("[" LOG_NAME "] +----------------------------+");
    charra_log_info("[" LOG_NAME "]   RP identity: %s",
            attestation_result_ekak_rp ? rp_key_name
                                       : "(unknown -- key not trusted)");
    if (attestation_result) {
        message = "Attestation successful!";
        charra_log_info("[" LOG_NAME "] |   ATTESTATION SUCCESSFUL   |");
    } else {
        /* Banner names the first failing check, so a log skimmer sees the
         * headline cause; the full list is logged above either way. */
        message = "Attestation failed!    ";
        if (!attestation_result_ekak_rp) {
            charra_log_info("[" LOG_NAME "] |    RP KEY NOT TRUSTED      |");
        } else if (!attestation_result_ekak) {
            charra_log_info("[" LOG_NAME "] | ATTESTER KEY NOT TRUSTED   |");
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

    /* log_r is NOT freed here: charra_unmarshal_rp_evidence() points it
     * straight into the CoAP request buffer (the borrowed-pointer
     * convention msg_rp_evidence_dto uses, see charra_dto.h) rather than
     * heap-allocating a copy -- freeing it would free memory this handler
     * never owned. */
}
