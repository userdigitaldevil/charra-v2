/**
 * @file rp_evidence.c
 * @brief See rp_evidence.h.
 */

#include "rp_evidence.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <mbedtls/platform_util.h>
#include <mbedtls/rsa.h>

#include "../common/charra_log.h"
#include "../common/charra_macro.h"
#include "../core/charra_event_log.h"
#include "../core/charra_marshaling.h"
#include "../core/charra_sdk.h"
#include "../core/charra_trusted_keys.h"
#include "../core/charra_zk.h"
#include "../core/charra_zk_job.h"
#include "../util/charra_util.h"
#include "../util/crypto_util.h"
#include "../util/io_util.h"
#include "rp_shared.h"
#include "rp_signing_key.h"

#define LOG_NAME "relying party"

bool charra_rp_appraise_evidence(
        const msg_attestation_response_dto* res) {
    charra_log_info("[" LOG_NAME
            "]  +------------ RP Appraisal of the Evidence --------------+");

    bool ekak_ok = false;
    bool signature_ok = false;
    bool nonce_ok = false;
    bool entries_ok = false;
    bool pcr_ok = false;
    bool blacklist_ok = false;

    /* Bounds are re-checked here even though charra_unmarshal_attestation_
     * response() has its own: these three fields are attacker-reachable and
     * are about to be memcpy'd into fixed-size structs. */
    if (res->tpm2_signature_len > sizeof(TPMT_SIGNATURE) ||
            res->tpm2_public_key_len > sizeof(TPM2B_PUBLIC) ||
            res->attestation_data_len > sizeof(TPM2B_ATTEST)) {
        charra_log_error("[" LOG_NAME "] Evidence field exceeds its maximum "
                         "size; refusing to appraise.");
        goto done;
    }

    TPMT_SIGNATURE signature = {0};
    memcpy(&signature, res->tpm2_signature, res->tpm2_signature_len);
    TPM2B_PUBLIC* tpm2_public_key = (TPM2B_PUBLIC*)res->tpm2_public_key;

    /* --- 1. Attester's identity -------------------------------------------
     * DRA-TLS Step 2a item 1. The same check the Verifier runs for Step 3b
     * item 1, and for the same reason: the key that signed this quote has
     * to be one we already trust. "Already trust" means "appears in the
     * trust anchor" -- see charra_trusted_keys.h for what that does and
     * does not establish. */
    charra_log_info("[" LOG_NAME "] Verifying the Attester's signing key ...");
    {
        char name[128] = {0};
        ekak_ok = charra_trusted_keys_check(
                          NULL, tpm2_public_key, name, sizeof(name)) ==
                  CHARRA_RC_SUCCESS;
        if (ekak_ok) {
            charra_log_info("[" LOG_NAME "]     => trusted: '%s'", name);
        } else {
            charra_log_error("[" LOG_NAME "]     => the key that signed this "
                             "quote is NOT in the trust anchor!");
        }
    }

    /* --- 2. quote signature, under the Attester's own public key --------- */
    /* mbedTLS rather than the TPM-backed path verifier.c also has: verifying
     * an RSA-PSS signature needs no TPM, and the software TPM serves one
     * client at a time -- the RP opening its own session while fanning out
     * to N verifiers is how the whole testbed deadlocks. */
    charra_log_info("[" LOG_NAME "] Verifying quote signature ...");
    mbedtls_rsa_context mbedtls_rsa_pub_key = {0};
    if (charra_crypto_tpm_pub_key_to_mbedtls_pub_key(tpm2_public_key,
                &mbedtls_rsa_pub_key) != CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Could not convert the Attester's "
                         "public key.");
    } else {
        signature_ok = (charra_crypto_rsa_verify_signature(
                                &mbedtls_rsa_pub_key, MBEDTLS_MD_SHA256,
                                res->attestation_data,
                                (size_t)res->attestation_data_len,
                                signature.signature.rsapss.sig.buffer) ==
                        CHARRA_RC_SUCCESS);
        mbedtls_rsa_free(&mbedtls_rsa_pub_key);
        charra_log_info("[" LOG_NAME "]     => quote signature is %s",
                signature_ok ? "valid!" : "NOT valid!");
    }

    /* --- unmarshal the quote; every remaining check reads it ------------- */
    TPMS_ATTEST attest_struct = {0};
    if (charra_unmarshal_tpm2_quote(res->attestation_data_len,
                res->attestation_data, &attest_struct) != CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Could not unmarshal the TPM Quote.");
        goto done;
    }

    /* --- 3. nonce: the quote must answer the challenge we just sent ------ */
    charra_log_info("[" LOG_NAME "] Verifying nonce ...");
    nonce_ok = charra_verify_tpm2_quote_qualifying_data(
            (uint16_t)last_request.nonce_len, last_request.nonce,
            &attest_struct);
    charra_log_info("[" LOG_NAME "]     => nonce in the quote %s",
            nonce_ok ? "matches the one sent!"
                     : "does NOT match the one sent!");

    /* --- 4. every entry's template_digest == hash(template_data) -------- */
    charra_log_info("[" LOG_NAME "] Verifying log entry self-consistency ...");
    entries_ok = charra_verify_log_entries_self_consistent(
            res->event_log, res->event_log_len);
    charra_log_info("[" LOG_NAME "]     => log entries are %s",
            entries_ok ? "self-consistent!" : "NOT self-consistent!");

    /* --- 5. replay the log and rebuild the PCR composite digest ---------- */
    charra_log_info("[" LOG_NAME "] Replaying the log into the PCRs ...");
    pcr_ok = charra_verify_log_matches_quote_pcr_digest(res->event_log,
            res->event_log_len, tpm_pcr_selection, tpm_pcr_selection_len,
            &attest_struct);
    charra_log_info("[" LOG_NAME "]     => PCR composite digest %s",
            pcr_ok ? "matches the quote!" : "does NOT match the quote!");

    /* --- 6. no measured file may appear on the blacklist ----------------- */
    charra_log_info("[" LOG_NAME "] Checking file hashes against the "
                    "whitelist/blacklist policy ...");
    blacklist_ok = charra_verify_log_file_hashes_against_policy(
            res->event_log, res->event_log_len, whitelist_hashes_path,
            blacklist_hashes_path);
    charra_log_info("[" LOG_NAME "]     => file hashes are %s",
            blacklist_ok ? "not blacklisted!" : "BLACKLISTED!");

done:;
    const bool appraisal_ok = ekak_ok && signature_ok && nonce_ok &&
                              entries_ok && pcr_ok && blacklist_ok;
    charra_log_info("[" LOG_NAME "] +----------------------------+");
    if (appraisal_ok) {
        charra_log_info("[" LOG_NAME "] |  RP Appraisal Successful   |");
    } else {
        charra_log_error("[" LOG_NAME "] |    RP Appraisal Failed     |");
    }
    charra_log_info("[" LOG_NAME "] +----------------------------+");
    return appraisal_ok;
}

/* The proof over log_r, produced once per cycle alongside it. Held here
 * rather than regenerated per Verifier: every Verifier receives the same
 * log_r and the same Quote_a, so the proof is the same too, and proving is
 * the most expensive step in the cycle by two orders of magnitude. */
static uint8_t* rp_zk_proof = NULL;
static uint32_t rp_zk_proof_len = 0;

CHARRA_RC charra_rp_prepare_evidence(void) {
    charra_rp_release_evidence();

    charra_log_info("[" LOG_NAME
            "]  +------------ RP Privacy Cleaning --------------+");

    /* --- redact: only the path of each entry is replaced --------------- */
    struct timespec redact_start, redact_end;
    clock_gettime(CLOCK_MONOTONIC, &redact_start);
    /* The witness holds the real paths and their salts. It never leaves
     * this function's storage, is never marshaled, and is erased below --
     * it is exactly what redaction exists to withhold. */
    charra_zk_witness witness = {0};
    CHARRA_RC charra_r = charra_sdk_redact_ima_log_with_witness(
            last_response.event_log, last_response.event_log_len, &rp_log_r,
            &rp_log_r_len, &witness);
    clock_gettime(CLOCK_MONOTONIC, &redact_end);
    if (charra_r != CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Redaction of the event log failed.");
        goto erase_witness;  /* it may hold entries redacted before the failure */
    }
    double redact_duration = (redact_end.tv_sec - redact_start.tv_sec) +
                              (redact_end.tv_nsec - redact_start.tv_nsec) / 1e9;
    charra_log_info("[" LOG_NAME "] log_r is %u bytes (raw log was %u), "
                    "redaction took %.3fs.",
            rp_log_r_len, last_response.event_log_len, redact_duration);

    /* A software replay, kept only for the log line below: it predicts the
     * value the TPM is about to arrive at, which is what makes a Verifier's
     * later "does NOT match" report diagnosable. Local, not global -- no
     * other module reads it. */
    uint8_t rp_pcr_r[TPM2_SHA256_DIGEST_SIZE] = {0};
    if (charra_replay_ima_log(rp_log_r, rp_log_r_len, CHARRA_IMA_PCR_INDEX,
                rp_pcr_r) != CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Replay of log_r failed.");
        charra_r = CHARRA_RC_ERROR;
        goto erase_witness;
    }
    charra_print_hex(CHARRA_LOG_INFO, sizeof(rp_pcr_r), rp_pcr_r,
            "                        expected PCR_r: 0x", "\n", false);

    /* Replay log_r into the RP's own TPM, ONCE for the whole cycle. Every
     * Verifier's quote reads this same PCR -- quoting does not consume it
     * -- so repeating the replay per Verifier would multiply the most
     * expensive part of the cycle by the Verifier count for no benefit.
     *
     * The signing key is still derived fresh inside each quote and never
     * held here; only the PCR is prepared ahead. */
    struct timespec replay_start, replay_end;
    clock_gettime(CLOCK_MONOTONIC, &replay_start);
    charra_r = rp_replay_log_into_pcr(rp_log_r, rp_log_r_len);
    clock_gettime(CLOCK_MONOTONIC, &replay_end);
    if (charra_r != CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Could not replay log_r into the "
                         "TPM; no Verifier can be answered this cycle.");
        goto erase_witness;
    }
    charra_log_info("[" LOG_NAME "] TPM replay of log_r took %.3fs.",
            (replay_end.tv_sec - replay_start.tv_sec) +
                    (replay_end.tv_nsec - replay_start.tv_nsec) / 1e9);

    /* --- prove the redaction ------------------------------------------
     * The circuit is checked against pcrdigest_a, so it has to come from
     * the quote the Attester's TPM signed -- the same value the Verifier
     * will independently pull out of that quote. Anything the RP could
     * choose freely here would make the proof vacuous. */
    TPMS_ATTEST attest = {0};
    charra_r = charra_unmarshal_tpm2_quote(last_response.attestation_data_len,
            last_response.attestation_data, &attest);
    if (charra_r != CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Could not read pcrDigest out of "
                         "Quote_a; cannot prove the redaction.");
        goto erase_witness;
    }
    if (attest.attested.quote.pcrDigest.size != sizeof(witness.pcrdigest_a)) {
        charra_log_error("[" LOG_NAME "] Quote_a's pcrDigest is %u bytes, not "
                         "the 32 the circuit expects.",
                attest.attested.quote.pcrDigest.size);
        charra_r = CHARRA_RC_ERROR;
        goto erase_witness;
    }
    memcpy(witness.pcrdigest_a, attest.attested.quote.pcrDigest.buffer,
            sizeof(witness.pcrdigest_a));

    struct timespec prove_start, prove_end;
    clock_gettime(CLOCK_MONOTONIC, &prove_start);
    charra_r = charra_zk_prove(&witness, &rp_zk_proof, &rp_zk_proof_len);
    clock_gettime(CLOCK_MONOTONIC, &prove_end);
    if (charra_r != CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Could not prove the redaction; no "
                         "Verifier can be answered this cycle.");
        goto erase_witness;
    }
    charra_log_info("[" LOG_NAME "] Proof is %u bytes, took %.3fs.",
            rp_zk_proof_len,
            (prove_end.tv_sec - prove_start.tv_sec) +
                    (prove_end.tv_nsec - prove_start.tv_nsec) / 1e9);

erase_witness:
    /* Overwrite rather than merely drop: these are the paths the whole
     * design exists to keep off the wire. */
    mbedtls_platform_zeroize(&witness, sizeof(witness));
    return charra_r;
}

void charra_rp_release_evidence(void) {
    charra_free_if_not_null(rp_log_r);
    rp_log_r = NULL;
    rp_log_r_len = 0;
    charra_free_if_not_null(rp_zk_proof);
    rp_zk_proof = NULL;
    rp_zk_proof_len = 0;
    /* Nothing key-related to release: the signing key is derived and
     * discarded inside each signature, never held here. */
}

/**
 * @brief Frees the heap-allocated fields of an /attest response DTO.
 *
 * charra_unmarshal_attestation_response() malloc()s the event log. Freed
 * explicitly rather than left for process exit, so a run that ever
 * attests more than once in one process -- or is checked under valgrind --
 * does not accumulate or misreport it as still reachable. Nulls as it
 * frees, so it's safe on a zeroed struct and safe to call twice.
 */
void charra_free_attestation_response(
        msg_attestation_response_dto* res) {
    if (res == NULL) {
        return;
    }
    charra_free_if_not_null(res->event_log);
    res->event_log_len = 0;
}

/**
 * @brief Builds Quote_r for one Verifier and marshals the whole RP evidence
 * message for it.
 *
 * Quote_r is taken per Verifier, not once per cycle, because each carries
 * that Verifier's own nonce as qualifyingData -- which is what makes the
 * exchange fresh from that Verifier's point of view. Each therefore costs
 * its own TPM2_Quote against the RP's TPM, against the PCR
 * charra_rp_prepare_evidence() already replayed log_r into.
 */
CHARRA_RC charra_rp_build_evidence_message(int verifier_index,
        uint32_t* marshaled_len, uint8_t** marshaled) {
    msg_rp_evidence_dto ev = {0};

    uint32_t nonce_len = verifier_nonce_lens[verifier_index];
    if (nonce_len == 0) {
        charra_log_error("[" LOG_NAME "] No nonce from this Verifier.");
        return CHARRA_RC_ERROR;
    }

    /* Quote the PCR charra_rp_prepare_evidence() already replayed log_r
     * into, under this Verifier's nonce. The key is derived, used and
     * discarded inside this call -- see rp_signing_key.h. */
    TPM2B_PUBLIC ak_public_key = {0};
    CHARRA_RC charra_r = rp_quote_pcr_with_ak(
            verifier_nonces[verifier_index], nonce_len,
            ev.rp_attestation_data, sizeof(ev.rp_attestation_data),
            &ev.rp_attestation_data_len, ev.rp_signature, &ak_public_key);
    if (charra_r != CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Could not produce Quote_r.");
        return charra_r;
    }
    ev.rp_signature_len = CHARRA_RSA_SIGNATURE_LEN;

    /* Straight from the derivation that produced rp_signature above, so
     * the key and the signature cannot disagree. */
    ev.rp_public_key_len = sizeof(ak_public_key);
    memcpy(ev.rp_public_key, &ak_public_key, sizeof(ak_public_key));

    /* the nonce the RP itself sent to the Attester */
    ev.attester_nonce_len = (uint32_t)last_request.nonce_len;
    memcpy(ev.attester_nonce, last_request.nonce, last_request.nonce_len);

    /* the Attester's evidence, minus its event log */
    ev.attestation_data_len = last_response.attestation_data_len;
    memcpy(ev.attestation_data, last_response.attestation_data,
            last_response.attestation_data_len);
    ev.tpm2_signature_len = last_response.tpm2_signature_len;
    memcpy(ev.tpm2_signature, last_response.tpm2_signature,
            last_response.tpm2_signature_len);
    ev.tpm2_public_key_len = last_response.tpm2_public_key_len;
    memcpy(ev.tpm2_public_key, last_response.tpm2_public_key,
            last_response.tpm2_public_key_len);

    ev.log_r = rp_log_r;
    ev.log_r_len = rp_log_r_len;

    ev.zk_proof = rp_zk_proof;
    ev.zk_proof_len = rp_zk_proof_len;

    return charra_marshal_rp_evidence(&ev, marshaled_len, marshaled);
}
