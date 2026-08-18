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

#include <mbedtls/rsa.h>
#include <tss2/tss2_tctildr.h>

#include "../common/charra_log.h"
#include "../common/charra_macro.h"
#include "../core/charra_ak_state.h"
#include "../core/charra_event_log.h"
#include "../core/charra_identity_key_mgr.h"
#include "../core/charra_marshaling.h"
#include "../core/charra_sdk.h"
#include "../util/charra_util.h"
#include "../util/crypto_util.h"
#include "../util/io_util.h"
#include "rp_identity.h"
#include "rp_shared.h"

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

    /* --- 1. Attester's AK certificate, issued by RP's own CA -------------
     * DRA-TLS Step 2a item 1. Same chain+key check the Verifier runs for
     * Step 3a/3b item 1 (charra_crypto_verify_ekak_certificate() is written
     * to be shared by both, see its docstring), but RP additionally checks
     * the serial against its own issuance ledger: unlike the Verifier-issued
     * leg (one shared CA, no cross-Verifier ledger), RP signed this cert
     * itself, so revocation is actually checkable here. */
    charra_log_info(
            "[" LOG_NAME "] Verifying Attester's RP-issued AK certificate ...");
    if (res->ak_certificate_attester_by_rp_len == 0) {
        charra_log_error("[" LOG_NAME "]     => certificate is EMPTY -- "
                         "/certify_ak_of_attester's DELIVER_RP leg has not "
                         "completed yet.");
    } else {
        char* rp_ca_cert_der = NULL;
        size_t rp_ca_cert_der_len = 0;
        if (charra_io_read_file(rp_ca_cert_path, &rp_ca_cert_der,
                    &rp_ca_cert_der_len) != CHARRA_RC_SUCCESS) {
            charra_log_error("[" LOG_NAME "]     => could not read RP CA "
                             "certificate ('%s').",
                    rp_ca_cert_path);
        } else {
            uint8_t ak_serial[16] = {0};
            ekak_ok = charra_crypto_verify_ekak_certificate(
                    res->ak_certificate_attester_by_rp,
                    res->ak_certificate_attester_by_rp_len,
                    (uint8_t*)rp_ca_cert_der, rp_ca_cert_der_len,
                    tpm2_public_key, ak_serial) == CHARRA_RC_SUCCESS;
            charra_io_free_file_buffer(&rp_ca_cert_der);
            if (!ekak_ok) {
                charra_log_error("[" LOG_NAME "]     => certificate did NOT "
                                 "verify (chain or key mismatch)!");
            } else {
                charra_print_hex(CHARRA_LOG_INFO, sizeof(ak_serial),
                        ak_serial,
                        "[" LOG_NAME "]     => chain and key valid! serial 0x",
                        "\n", false);
                ekak_ok = charra_ak_state_check_serial_valid(
                        attester_ak_state_file_path, ak_serial, NULL, NULL);
                charra_log_info(
                        "[" LOG_NAME "]     => serial is %s",
                        ekak_ok ? "currently valid (not revoked/expired)!"
                                : "REVOKED or EXPIRED!");
            }
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

CHARRA_RC charra_rp_prepare_evidence(void) {
    charra_rp_release_evidence();

    charra_log_info("[" LOG_NAME
            "]  +------------ RP Privacy Cleaning --------------+");

    /* --- redact: only the path of each entry is replaced --------------- */
    struct timespec redact_start, redact_end;
    clock_gettime(CLOCK_MONOTONIC, &redact_start);
    CHARRA_RC charra_r = charra_sdk_redact_ima_log(last_response.event_log,
            last_response.event_log_len, NULL, &rp_log_r, &rp_log_r_len);
    clock_gettime(CLOCK_MONOTONIC, &redact_end);
    if (charra_r != CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Redaction of the event log failed.");
        return charra_r;
    }
    double redact_duration = (redact_end.tv_sec - redact_start.tv_sec) +
                              (redact_end.tv_nsec - redact_start.tv_nsec) / 1e9;
    charra_log_info("[" LOG_NAME "] log_r is %u bytes (raw log was %u), "
                    "redaction took %.3fs.",
            rp_log_r_len, last_response.event_log_len, redact_duration);

    /* --- replay log_r into the same PCR selection, then composite ------ */
    charra_pcr_accumulator replayed[TPM2_MAX_PCRS] = {{{0}}};
    charra_r = charra_replay_ima_log_pcrs(rp_log_r, rp_log_r_len,
            tpm_pcr_selection, tpm_pcr_selection_len, replayed);
    if (charra_r != CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Replay of log_r failed.");
        return charra_r;
    }
    uint8_t* pcr_values[TPM2_MAX_PCRS] = {NULL};
    for (uint32_t i = 0; i < tpm_pcr_selection_len; i++) {
        pcr_values[i] = replayed[i].value;
    }
    if (hash_sha256_array(pcr_values, tpm_pcr_selection_len, rp_pcr_r) !=
            CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Could not compute PCR_r.");
        return CHARRA_RC_CRYPTO_ERROR;
    }
    charra_print_hex(CHARRA_LOG_INFO, sizeof(rp_pcr_r), rp_pcr_r,
            "                        PCR_r: 0x", "\n", false);

    /* --- keypair Quote_r is signed under --------------------------------
     * Ensured here, once, before any per-Verifier thread starts -- each
     * thread separately calls ensure_rp_ak_certificate(verifier_index) for
     * its own Verifier's AK *certificate*, but the underlying TPM-resident
     * keypair itself is Verifier-agnostic and only needs creating once;
     * this call is idempotent (cheap) once it has been. */
    CHARRA_RC keypair_rc = ensure_rp_ak_keypair();
    if (keypair_rc != CHARRA_RC_SUCCESS) {
        charra_log_error(
                "[" LOG_NAME "] RP AK keypair not provisioned; evidence not "
                "ready.");
        return keypair_rc;
    }
    charra_log_info(
            "[" LOG_NAME "] RP AK keypair ready (public key %u bytes).",
            rp_public_key_der_len);
    return CHARRA_RC_SUCCESS;
}

void charra_rp_release_evidence(void) {
    charra_free_if_not_null(rp_log_r);
    rp_log_r = NULL;
    rp_log_r_len = 0;
    /* rp_public_key_der/rp_ak_cert_der are provisioned once (per-Verifier
     * for the latter) by ensure_rp_ak_keypair()/ensure_rp_ak_certificate()
     * and live for the whole process, not freed per attestation cycle. */
}

/**
 * @brief Frees the heap-allocated fields of an /attest response DTO.
 *
 * charra_unmarshal_attestation_response() malloc()s three of them
 * (event_log plus both Attester AK certificates, ~6 KB per cycle). Under
 * the original one-shot design nothing had to free them -- the process
 * exited right after -- but in daemon mode every cycle allocates a fresh
 * set, so they must be released or they accumulate for the process's
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
    charra_free_if_not_null(res->ak_certificate_attester_by_verifier);
    res->ak_certificate_attester_by_verifier_len = 0;
    charra_free_if_not_null(res->ak_certificate_attester_by_rp);
    res->ak_certificate_attester_by_rp_len = 0;
}

/**
 * @brief Builds Quote_r for one Verifier and marshals the whole RP evidence
 * message for it.
 *
 * Quote_r's signature covers (PCR_r || that Verifier's nonce), so each
 * Verifier gets a signature bound to the challenge it issued -- which is
 * what makes the exchange fresh from the Verifier's point of view.
 */
CHARRA_RC charra_rp_build_evidence_message(int verifier_index,
        uint32_t* marshaled_len, uint8_t** marshaled) {
    /* Only the signing keypair is mandatory -- without it there is no
     * Quote_r at all, so there is nothing to send. A missing AK
     * *certificate* is not a reason to stay silent: send the evidence with
     * the field empty and let the Verifier apply Step 3a item 1 and record
     * its own decision. Its 4.01 also drives RP's re-provision-and-retry,
     * which returning here would skip. */
    if (!rp_ak_keypair_ready) {
        charra_log_error("[" LOG_NAME "] No AK keypair; cannot sign Quote_r.");
        return CHARRA_RC_ERROR;
    }
    if (!rp_ak_cert_ready[verifier_index]) {
        charra_log_error("[" LOG_NAME "] No AK certificate for Verifier %d -- "
                         "sending evidence without one; that Verifier will "
                         "reject it at Step 3a item 1.",
                verifier_index + 1);
    }

    msg_rp_evidence_dto ev = {0};
    memcpy(ev.pcr_r, rp_pcr_r, sizeof(ev.pcr_r));

    ev.verifier_nonce_len = verifier_nonce_lens[verifier_index];
    if (ev.verifier_nonce_len > sizeof(ev.verifier_nonce)) {
        charra_log_error("[" LOG_NAME "] Verifier nonce too long.");
        return CHARRA_RC_ERROR;
    }
    memcpy(ev.verifier_nonce, verifier_nonces[verifier_index],
            ev.verifier_nonce_len);

    /* sign (PCR_r || nonce) with RP's TPM-resident AK -- opens its own
     * short-lived TPM connection (mutex-serialized against any other RP
     * TPM use, including a concurrent sibling verifier thread's own sign
     * here) rather than reusing a long-lived one; see rp_tpm_mutex's
     * comment for why holding a connection open longer than one operation
     * needs is a real problem, not just tidiness, on this dev TPM
     * simulator. */
    uint8_t signed_data[sizeof(ev.pcr_r) + sizeof(ev.verifier_nonce)] = {0};
    memcpy(signed_data, ev.pcr_r, sizeof(ev.pcr_r));
    memcpy(signed_data + sizeof(ev.pcr_r), ev.verifier_nonce,
            ev.verifier_nonce_len);

    pthread_mutex_lock(&rp_tpm_mutex);
    ESYS_CONTEXT* sign_esys_ctx = NULL;
    TSS2_TCTI_CONTEXT* sign_tcti_ctx = NULL;
    ESYS_TR sign_ek_handle = ESYS_TR_NONE;
    ESYS_TR sign_ak_handle = ESYS_TR_NONE;
    TPM2B_NAME* sign_ak_name = NULL;
    CHARRA_RC charra_r = rp_open_tpm_and_load_ak(&sign_esys_ctx,
            &sign_tcti_ctx, &sign_ek_handle, &sign_ak_handle, &sign_ak_name);
    if (charra_r != CHARRA_RC_SUCCESS) {
        pthread_mutex_unlock(&rp_tpm_mutex);
        charra_log_error(
                "[" LOG_NAME "] Could not open TPM connection to sign "
                "Quote_r.");
        return charra_r;
    }
    Esys_Free(sign_ak_name);

    charra_r = charra_identity_key_mgr_sign(sign_esys_ctx, sign_ak_handle,
            signed_data, sizeof(ev.pcr_r) + ev.verifier_nonce_len,
            ev.rp_signature);

    Esys_FlushContext(sign_esys_ctx, sign_ak_handle);
    Esys_FlushContext(sign_esys_ctx, sign_ek_handle);
    Esys_Finalize(&sign_esys_ctx);
    Tss2_TctiLdr_Finalize(&sign_tcti_ctx);
    pthread_mutex_unlock(&rp_tpm_mutex);

    if (charra_r != CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Could not sign Quote_r.");
        return charra_r;
    }
    ev.rp_signature_len = CHARRA_RSA_SIGNATURE_LEN;

    ev.rp_public_key_len = rp_public_key_der_len;
    memcpy(ev.rp_public_key, rp_public_key_der, rp_public_key_der_len);

    ev.ak_certificate_rp_len = rp_ak_cert_der_len[verifier_index];
    ev.ak_certificate_rp = rp_ak_cert_der[verifier_index];

    /* ak_certificate (Attester's) intentionally left empty -- see
     * msg_rp_evidence_dto's docstring in charra_dto.h: the Attester has no
     * /certify_ak client yet, this is a known, documented gap. */

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

    /* EK_a/AK_a: the Attester's AK certificate issued by THIS Verifier's
     * own CA -- substituted from RP's own per-Verifier cache
     * (attester_ak_cert_by_verifier_der[], populated by ensure_attester_
     * identity_certified_by_verifier()), not whatever last_response itself
     * carries. Only RP knows which certificate belongs to which Verifier
     * now that each Verifier has an independent CA; the certificate's
     * validity depends only on its own CA signature, not on who forwarded
     * the bytes, so this is not a trust shortcut. */
    ev.ak_certificate_attester_by_verifier_len =
            attester_ak_cert_by_verifier_der_len[verifier_index];
    ev.ak_certificate_attester_by_verifier =
            attester_ak_cert_by_verifier_der[verifier_index];

    /* RP-issued cert, forwarded alongside the Verifier-issued one above */
    ev.ak_certificate_attester_by_rp_len =
            last_response.ak_certificate_attester_by_rp_len;
    ev.ak_certificate_attester_by_rp =
            last_response.ak_certificate_attester_by_rp;

    ev.log_r = rp_log_r;
    ev.log_r_len = rp_log_r_len;

    return charra_marshal_rp_evidence(&ev, marshaled_len, marshaled);
}
