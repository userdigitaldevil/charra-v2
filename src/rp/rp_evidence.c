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
#include "../core/charra_trusted_keys.h"
#include "../core/charra_event_log.h"
#include "../core/charra_ima_ascii.h"
#include "../core/charra_marshaling.h"
#include "../core/charra_sdk.h"
#include "../core/TEE.h"
#include "../core/charra_zk.h"
#include "../core/charra_zk_job.h"
#include "../util/charra_util.h"
#include "../util/io_util.h"
#include "rp_signing_key.h"
#include "rp_shared.h"

#define LOG_NAME "relying party"

/* Monotonic seconds since an arbitrary epoch. The per-step timings below are
 * all differences of this, which keeps one clock_gettime pair per step from
 * crowding out the logic being measured. */
static double charra_now_s(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

double rp_last_appraise_a_seconds = 0.0;

/** Source files the RP passes to the simulated TEE to measure into the
 * Attestation Document's file_hash: the appraisal gate (this file) plus the
 * redaction and replay logic it gates. The TEE itself has no opinion on this
 * list -- see TEE.h -- so it lives here, as the RP's own declaration of what
 * code it is vouching for. The Verifier holds its own, independent copy of
 * this same list (see verifier_appraise.c) rather than reading it from here
 * or from the TEE; keep the two in sync by hand if this ever changes.
 * Order is part of the measurement. */
static const char* const rp_appraisal_code_files[] = {
        "src/rp/rp_evidence.c",
        "src/core/charra_sdk.c",
        "src/core/charra_event_log.c",
};
#define RP_APPRAISAL_CODE_FILES_COUNT \
    (sizeof(rp_appraisal_code_files) / sizeof(rp_appraisal_code_files[0]))

/** pcrdigest_a: the TPM-signed PCR digest from the Attester's own quote,
 * captured during appraisal (check 5 below) so the exact value that gated
 * appraisal is also the one bound into the TEE's REPORT_DATA in
 * charra_rp_build_evidence_message() -- not a second, independent read that
 * could drift from the one actually checked. Zeroed at the start of every
 * appraisal, so a cycle that never got as far as unmarshaling the quote
 * cannot leave the previous cycle's value behind. */
static uint8_t rp_pcrdigest_a[TPM2_SHA256_DIGEST_SIZE] = {0};
static uint32_t rp_pcrdigest_a_len = 0;

/** The ZK proof over log_r, produced once per cycle alongside it.
 *
 * Held here rather than regenerated per Verifier: every Verifier gets the
 * same log_r and the same Quote_a, so the proof is the same for all of them,
 * and proving costs seconds where everything else in the cycle costs
 * milliseconds. Unlike the TEE document, nothing in it is per-Verifier --
 * the nonce is not bound into the circuit, because Quote_r already binds
 * log_r to the nonce and the proof binds log_r to pcrdigest_a. */
static uint8_t* rp_zk_proof = NULL;
static uint32_t rp_zk_proof_len = 0;

bool charra_rp_appraise_evidence(
        const msg_attestation_response_dto* res) {
    const double appraise_a_start = charra_now_s();
    double step_start = 0.0;
    rp_pcrdigest_a_len = 0;
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

    /* --- 1. Attester's identity ------------------------------------------
     * DRA-TLS Step 2a item 1. The same check the Verifier runs for Step 3b
     * item 1, and for the same reason: the key that signed this quote has
     * to be one we already trust. "Already trust" means "appears in the
     * trust anchor" -- see charra_trusted_keys.h for what that does and
     * does not establish. */
    charra_log_info("[" LOG_NAME "] Verifying the Attester's signing key ...");
    step_start = charra_now_s();
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

    charra_log_info("[" LOG_NAME "] Timing: RP verify AK_a (trust anchor) "
                    "took %f second(s).", charra_now_s() - step_start);

    /* --- 2. quote signature, under the Attester's own public key --------- */
    /* mbedTLS rather than the TPM-backed path verifier.c also has: verifying
     * an RSA-PSS signature needs no TPM, and the software TPM serves one
     * client at a time -- the RP opening its own session while fanning out
     * to N verifiers is how the whole testbed deadlocks. */
    charra_log_info("[" LOG_NAME "] Verifying quote signature ...");
    step_start = charra_now_s();
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

    charra_log_info("[" LOG_NAME "] Timing: RP verify Quote_a signature "
                    "took %f second(s).", charra_now_s() - step_start);

    /* --- unmarshal the quote; every remaining check reads it ------------- */
    step_start = charra_now_s();
    TPMS_ATTEST attest_struct = {0};
    if (charra_unmarshal_tpm2_quote(res->attestation_data_len,
                res->attestation_data, &attest_struct) != CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Could not unmarshal the TPM Quote.");
        goto done;
    }

    charra_log_info("[" LOG_NAME "] Timing: RP unmarshal Quote_a took %f "
                    "second(s).", charra_now_s() - step_start);

    /* pcrdigest_a, captured for the TEE's REPORT_DATA -- see the file-level
     * comment on rp_pcrdigest_a. A failed appraisal aborts the whole cycle
     * before charra_rp_build_evidence_message() ever runs, so by the time
     * anything reads this it is always a value that passed. */
    if (attest_struct.attested.quote.pcrDigest.size <=
            sizeof(rp_pcrdigest_a)) {
        rp_pcrdigest_a_len = attest_struct.attested.quote.pcrDigest.size;
        memcpy(rp_pcrdigest_a, attest_struct.attested.quote.pcrDigest.buffer,
                rp_pcrdigest_a_len);
    } else {
        charra_log_error("[" LOG_NAME "] pcrdigest_a exceeds its expected "
                         "size; it will not be available to the TEE.");
    }

    /* --- 3. nonce: the quote must answer the challenge we just sent ------ */
    charra_log_info("[" LOG_NAME "] Verifying nonce ...");
    step_start = charra_now_s();
    nonce_ok = charra_verify_tpm2_quote_qualifying_data(
            (uint16_t)last_request.nonce_len, last_request.nonce,
            &attest_struct);
    charra_log_info("[" LOG_NAME "]     => nonce in the quote %s",
            nonce_ok ? "matches the one sent!"
                     : "does NOT match the one sent!");

    charra_log_info("[" LOG_NAME "] Timing: RP verify Quote_a nonce took %f "
                    "second(s).", charra_now_s() - step_start);

    /* --- 4. every entry's template_digest == hash(template_data) -------- */
    charra_log_info("[" LOG_NAME "] Verifying log entry self-consistency ...");
    step_start = charra_now_s();
    entries_ok = charra_verify_log_entries_self_consistent(
            res->event_log, res->event_log_len);
    charra_log_info("[" LOG_NAME "]     => log entries are %s",
            entries_ok ? "self-consistent!" : "NOT self-consistent!");

    charra_log_info("[" LOG_NAME "] Timing: RP verify log_a self-consistency "
                    "took %f second(s).", charra_now_s() - step_start);

    /* --- 5. replay the log and rebuild the PCR composite digest ---------- */
    charra_log_info("[" LOG_NAME "] Replaying the log into the PCRs ...");
    step_start = charra_now_s();
    pcr_ok = charra_verify_log_matches_quote_pcr_digest(res->event_log,
            res->event_log_len, tpm_pcr_selection, tpm_pcr_selection_len,
            &attest_struct);
    charra_log_info("[" LOG_NAME "]     => PCR composite digest %s",
            pcr_ok ? "matches the quote!" : "does NOT match the quote!");

    charra_log_info("[" LOG_NAME "] Timing: RP replay log_a + PCR composite "
                    "took %f second(s).", charra_now_s() - step_start);

    /* --- 6. no measured file may appear on the blacklist ----------------- */
    charra_log_info("[" LOG_NAME "] Checking file hashes against the "
                    "whitelist/blacklist policy ...");
    step_start = charra_now_s();
    blacklist_ok = charra_verify_log_file_hashes_against_policy(
            res->event_log, res->event_log_len, whitelist_hashes_path,
            blacklist_hashes_path);
    charra_log_info("[" LOG_NAME "]     => file hashes are %s",
            blacklist_ok ? "not blacklisted!" : "BLACKLISTED!");

    charra_log_info("[" LOG_NAME "] Timing: RP whitelist/blacklist policy "
                    "took %f second(s).", charra_now_s() - step_start);

done:;
    rp_last_appraise_a_seconds = charra_now_s() - appraise_a_start;
    charra_log_info("[" LOG_NAME "] Timing: RP total appraisal of evidence_a "
                    "took %f second(s).", rp_last_appraise_a_seconds);
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

CHARRA_RC charra_rp_prepare_evidence(void) {
    charra_rp_release_evidence();

    charra_log_info("[" LOG_NAME
            "]  +------------ RP Privacy Cleaning --------------+");

    /* --- redact: only the path of each entry is replaced --------------- */
    struct timespec redact_start, redact_end;
    clock_gettime(CLOCK_MONOTONIC, &redact_start);
    /* The witness is only collected in ZK mode, and collecting it is also
     * what selects Poseidon commitments -- see charra_sdk.h. It holds the
     * real paths and their salts, so it is wiped before this function
     * returns on every path out. */
    charra_zk_witness zk_witness = {0};
    const bool want_zk = (rp_trust_mode == CHARRA_TRUST_MODE_ZK);

    CHARRA_RC charra_r;
    if (want_zk) {
        charra_r = charra_sdk_redact_ima_log_with_witness(
                last_response.event_log, last_response.event_log_len,
                CHARRA_SDK_DEFAULT_LABEL, &rp_log_r, &rp_log_r_len,
                &zk_witness);
    } else {
        charra_r = charra_sdk_redact_ima_log(last_response.event_log,
                last_response.event_log_len, NULL, CHARRA_SDK_DEFAULT_LABEL,
                &rp_log_r, &rp_log_r_len);
    }
    clock_gettime(CLOCK_MONOTONIC, &redact_end);
    if (charra_r != CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Redaction of the event log failed.");
        goto wipe_witness;
    }
    double redact_duration = (redact_end.tv_sec - redact_start.tv_sec) +
                              (redact_end.tv_nsec - redact_start.tv_nsec) / 1e9;
    charra_log_info("[" LOG_NAME "] log_r is %u bytes (raw log was %u), "
                    "redaction took %.3fs.",
            rp_log_r_len, last_response.event_log_len, redact_duration);

    /* Write log_r out in the same ASCII form the Attester's own log uses, so
     * what the Verifiers actually receive can be read directly and diffed
     * against ima_test_log_path -- redaction moves the path column and the
     * template_digest covering it, and nothing else. Rewritten every cycle.
     *
     * Never fatal: this is an observation point, not part of the attestation.
     * A bad path or a full disk must not fail a cycle that is otherwise
     * sound, so every failure here is a warning and the cycle continues. */
    if (redacted_log_out_path != NULL && redacted_log_out_path[0] != '\0') {
        char* log_r_text = NULL;
        size_t log_r_text_len = 0;
        if (charra_ima_ascii_emit(rp_log_r, rp_log_r_len, &log_r_text,
                    &log_r_text_len) != CHARRA_RC_SUCCESS) {
            charra_log_warn("[" LOG_NAME "] Could not render log_r as ASCII; "
                            "'%s' not written.",
                    redacted_log_out_path);
        } else {
            FILE* log_r_file = fopen(redacted_log_out_path, "w");
            if (log_r_file == NULL) {
                charra_log_warn("[" LOG_NAME "] Could not open '%s' for "
                                "writing; log_r not saved.",
                        redacted_log_out_path);
            } else {
                if (fwrite(log_r_text, 1, log_r_text_len, log_r_file) !=
                        log_r_text_len) {
                    charra_log_warn("[" LOG_NAME "] Short write to '%s'; the "
                                    "saved log_r is incomplete.",
                            redacted_log_out_path);
                } else {
                    charra_log_info("[" LOG_NAME "] Wrote log_r to '%s' "
                                    "(%zu bytes, ASCII).",
                            redacted_log_out_path, log_r_text_len);
                }
                fclose(log_r_file);
            }
            free(log_r_text);
        }
    }

    /* A software replay, kept only for the log line below: it predicts the
     * value the TPM is about to arrive at, which is what makes a Verifier's
     * later "does NOT match" report diagnosable. Local, not global -- no
     * other module reads it. */
    uint8_t rp_pcr_r[TPM2_SHA256_DIGEST_SIZE] = {0};
    if (charra_replay_ima_log(rp_log_r, rp_log_r_len, CHARRA_IMA_PCR_INDEX,
                rp_pcr_r) != CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Replay of log_r failed.");
        return CHARRA_RC_ERROR;
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
        return charra_r;
    }
    charra_log_info("[" LOG_NAME "] TPM replay of log_r took %.3fs.",
            (replay_end.tv_sec - replay_start.tv_sec) +
                    (replay_end.tv_nsec - replay_start.tv_nsec) / 1e9);

    if (!want_zk) {
        return CHARRA_RC_SUCCESS;
    }

    /* --- prove the redaction, once for the whole cycle ------------------ */
    charra_log_info("[" LOG_NAME
            "]  +------------ RP ZK Redaction Proof --------------+");
    if (rp_pcrdigest_a_len == 0) {
        charra_log_error("[" LOG_NAME "] No pcrdigest_a captured during "
                         "appraisal; the proof would have nothing to bind "
                         "log_r to. Abandoning the cycle.");
        charra_r = CHARRA_RC_ERROR;
        goto wipe_witness;
    }
    memcpy(zk_witness.pcrdigest_a, rp_pcrdigest_a, sizeof(zk_witness.pcrdigest_a));

    charra_log_info("[" LOG_NAME "] Proving %u redacted entries against the "
                    "Attester's signed pcrdigest_a ...",
            zk_witness.num_entries);
    struct timespec prove_start, prove_end;
    clock_gettime(CLOCK_MONOTONIC, &prove_start);
    charra_r = charra_zk_prove(&zk_witness, &rp_zk_proof, &rp_zk_proof_len);
    clock_gettime(CLOCK_MONOTONIC, &prove_end);
    if (charra_r != CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Could not prove the redaction; no "
                         "Verifier can be answered this cycle. Is the prover "
                         "container running? (./docker/build-zk.sh, then "
                         "TRUST_MODE=zk ./scripts/run_daemon.sh starts it)");
        goto wipe_witness;
    }
    charra_log_info("[" LOG_NAME "] Proof is %u bytes, took %.3fs. One proof "
                    "serves every Verifier this cycle.",
            rp_zk_proof_len,
            (prove_end.tv_sec - prove_start.tv_sec) +
                    (prove_end.tv_nsec - prove_start.tv_nsec) / 1e9);

wipe_witness:
    /* Paths and salts: secret, and of no further use once the proof exists.
     * mbedtls_platform_zeroize rather than memset, which a compiler is free
     * to elide on a buffer that is never read again. */
    mbedtls_platform_zeroize(&zk_witness, sizeof(zk_witness));
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
 * charra_unmarshal_attestation_response() malloc()s the event log. Under
 * the original one-shot design nothing had to free it -- the process
 * exited right after -- but in daemon mode every cycle allocates a fresh
 * one, so it must be released or they accumulate for the process's
 * lifetime. Nulls as it frees, so it's safe on a zeroed struct and safe to
 * call twice.
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
 * its own reset/replay/quote against the RP's TPM.
 */
/* AK_r's signature over the TEE's public key. The TEE keypair is generated
 * once per process, so this certification is too -- but N Verifier threads
 * reach it concurrently, hence the guard. Caching it also keeps a TPM round
 * trip off the per-Verifier path: without it every thread would re-derive
 * AK_r to sign a value that never changes. */
static pthread_mutex_t rp_tee_cert_mutex = PTHREAD_MUTEX_INITIALIZER;
static bool rp_tee_cert_ready = false;
static uint8_t rp_tee_public_key[CHARRA_RSA_PUB_KEY_DER_MAX] = {0};
static uint32_t rp_tee_public_key_len = 0;
static uint8_t rp_tee_public_key_sig[CHARRA_RSA_SIGNATURE_LEN] = {0};

/**
 * @brief Export the TEE's public key and certify it with AK_r, once.
 *
 * This is what makes the TEE key believable to a Verifier: on its own it is
 * an unanchored key that arrived beside its own signature. AK_r is in the
 * trust anchor, so signing the key with it extends a chain the Verifier
 * already checks.
 */
static CHARRA_RC rp_ensure_tee_key_certified(void) {
    pthread_mutex_lock(&rp_tee_cert_mutex);
    CHARRA_RC charra_r = CHARRA_RC_SUCCESS;
    if (!rp_tee_cert_ready) {
        charra_r = tee_public_key_der(rp_tee_public_key,
                sizeof(rp_tee_public_key), &rp_tee_public_key_len);
        if (charra_r != CHARRA_RC_SUCCESS) {
            charra_log_error("[" LOG_NAME "] Could not export the TEE's "
                             "public key.");
        } else {
            /* Signed over the DER bytes exactly as they travel, so the
             * Verifier can check the signature against what it received
             * without re-encoding anything. */
            TPM2B_PUBLIC ak_public_key = {0};
            charra_r = rp_sign_with_ak(rp_tee_public_key,
                    rp_tee_public_key_len, rp_tee_public_key_sig,
                    &ak_public_key);
            if (charra_r != CHARRA_RC_SUCCESS) {
                charra_log_error("[" LOG_NAME "] AK_r could not certify the "
                                 "TEE's public key.");
            } else {
                rp_tee_cert_ready = true;
            }
        }
    }
    pthread_mutex_unlock(&rp_tee_cert_mutex);
    return charra_r;
}

/**
 * @brief Fill in ev's TEE fields: measure the appraisal code, bind the
 * document to this Verifier's challenge and this evidence, sign it.
 *
 * REPORT_DATA is hash(verifier_nonce || pcrdigest_a || log_r): this
 * Verifier's own challenge, the exact TPM-signed digest appraisal checked
 * log_a's replay against, and the exact log_r this message carries -- so the
 * document cannot be replayed against a different nonce, a different
 * Attester evidence, or a different redacted log.
 */
static CHARRA_RC rp_attach_tee_attestation(
        msg_rp_evidence_dto* ev, int verifier_index, uint32_t nonce_len) {
    if (rp_pcrdigest_a_len == 0) {
        charra_log_error("[" LOG_NAME "] No pcrdigest_a captured; refusing to "
                         "build a TEE Attestation Document.");
        return CHARRA_RC_ERROR;
    }

    charra_log_info("[" LOG_NAME
            "]  +------------ RP TEE Attestation --------------+");

    size_t report_data_input_len =
            (size_t)nonce_len + rp_pcrdigest_a_len + rp_log_r_len;
    uint8_t* report_data_input = malloc(report_data_input_len);
    if (report_data_input == NULL) {
        charra_log_error("[" LOG_NAME "] Out of memory building TEE "
                         "REPORT_DATA.");
        return CHARRA_RC_ERROR;
    }
    memcpy(report_data_input, verifier_nonces[verifier_index], nonce_len);
    memcpy(report_data_input + nonce_len, rp_pcrdigest_a, rp_pcrdigest_a_len);
    memcpy(report_data_input + nonce_len + rp_pcrdigest_a_len, rp_log_r,
            rp_log_r_len);

    uint8_t report_data[TPM2_SHA256_DIGEST_SIZE] = {0};
    CHARRA_RC charra_r =
            hash_sha256(report_data_input_len, report_data_input, report_data);
    free(report_data_input);
    if (charra_r != CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Could not compute TEE REPORT_DATA.");
        return charra_r;
    }

    tee_attestation_document doc = {0};
    charra_r = tee_attestation(rp_appraisal_code_files,
            RP_APPRAISAL_CODE_FILES_COUNT, report_data, &doc);
    if (charra_r != CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] TEE attestation failed.");
        return charra_r;
    }
    memcpy(ev->tee_file_hash, doc.file_hash, sizeof(ev->tee_file_hash));
    memcpy(ev->tee_report_data, doc.report_data, sizeof(ev->tee_report_data));

    charra_r = tee_sign(&doc, ev->tee_signature);
    if (charra_r != CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Could not sign the TEE Attestation "
                         "Document.");
        return charra_r;
    }
    ev->tee_signature_len = CHARRA_RSA_SIGNATURE_LEN;

    charra_r = rp_ensure_tee_key_certified();
    if (charra_r != CHARRA_RC_SUCCESS) {
        return charra_r;
    }
    memcpy(ev->tee_public_key, rp_tee_public_key, rp_tee_public_key_len);
    ev->tee_public_key_len = rp_tee_public_key_len;
    memcpy(ev->tee_public_key_sig, rp_tee_public_key_sig,
            sizeof(rp_tee_public_key_sig));
    ev->tee_public_key_sig_len = sizeof(rp_tee_public_key_sig);

    charra_print_hex(CHARRA_LOG_DEBUG, sizeof(doc.file_hash), doc.file_hash,
            "[" LOG_NAME "]     file_hash (measures rp_appraisal_code_files): "
            "0x", "\n", false);
    charra_print_hex(CHARRA_LOG_DEBUG, sizeof(report_data), report_data,
            "[" LOG_NAME "]     REPORT_DATA = hash(nonce || pcrdigest_a || "
            "log_r): 0x", "\n", false);
    charra_log_info("[" LOG_NAME "]     => TEE Attestation Document signed, "
                    "and its key certified by AK_r.");
    return CHARRA_RC_SUCCESS;
}

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
    const double quote_r_start = charra_now_s();
    CHARRA_RC charra_r = rp_quote_pcr_with_ak(
            verifier_nonces[verifier_index], nonce_len,
            ev.rp_attestation_data, sizeof(ev.rp_attestation_data),
            &ev.rp_attestation_data_len, ev.rp_signature, &ak_public_key);
    if (charra_r != CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Could not produce Quote_r.");
        return charra_r;
    }
    charra_log_info("[" LOG_NAME "] Timing: RP produce Quote_r (derive key "
                    "+ tpm2_quote) took %f second(s).",
            charra_now_s() - quote_r_start);
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

    /* Always stated, so a Verifier configured for the other mode can say so
     * rather than just voting NO. The TEE fields stay zero in QUALIFY mode. */
    ev.trust_mode = (uint32_t)rp_trust_mode;
    if (rp_trust_mode == CHARRA_TRUST_MODE_TEE) {
        charra_r = rp_attach_tee_attestation(&ev, verifier_index, nonce_len);
        if (charra_r != CHARRA_RC_SUCCESS) {
            return charra_r;
        }
    } else if (rp_trust_mode == CHARRA_TRUST_MODE_ZK) {
        /* The same proof for every Verifier -- see rp_zk_proof. Built once in
         * charra_rp_prepare_evidence(); its absence here means that failed,
         * which already abandoned the cycle. */
        if (rp_zk_proof == NULL || rp_zk_proof_len == 0) {
            charra_log_error("[" LOG_NAME "] No redaction proof for this "
                             "cycle; refusing to send evidence a Verifier "
                             "cannot check.");
            return CHARRA_RC_ERROR;
        }
        ev.zk_proof = rp_zk_proof;
        ev.zk_proof_len = rp_zk_proof_len;
    }

    return charra_marshal_rp_evidence(&ev, marshaled_len, marshaled);
}
