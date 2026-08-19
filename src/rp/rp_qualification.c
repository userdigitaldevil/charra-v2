/**
 * @file rp_qualification.c
 * @brief See rp_qualification.h.
 *
 * The two CoAP response handlers live here alongside the handshake that
 * drives them: each is paired with its own module-private globals (a
 * libcoap callback cannot return data), and separating a handler from the
 * globals it writes would break silently rather than fail to link.
 */

#include "rp_qualification.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <tss2/tss2_tctildr.h>

#include "../common/charra_log.h"
#include "../common/charra_macro.h"
#include "../core/charra_dto.h"
#include "../core/charra_event_log.h"
#include "../core/charra_identity_key_mgr.h"
#include "../core/charra_marshaling.h"
#include "../core/charra_rp_qualification.h"
#include "../core/charra_sdk.h"
#include "../util/coap_util.h"
#include "../util/io_util.h"
#include "rp_coap.h"
#include "rp_identity.h"
#include "rp_shared.h"

#define LOG_NAME "relying party"

static coap_response_t coap_qualify_response_handler(
        coap_session_t* session CHARRA_UNUSED,
        const coap_pdu_t* sent CHARRA_UNUSED, const coap_pdu_t* received,
        const coap_mid_t mid CHARRA_UNUSED) {
    processing_qualify_response = true;

    size_t data_len = 0;
    const uint8_t* data = NULL;
    if (!charra_coap_get_payload(
                received, LOG_NAME, "/qualify response", &data, &data_len,
                NULL)) {
        qualify_response_rc = CHARRA_RC_ERROR;
        goto cleanup;
    }

    msg_qualify_response_dto resp = {0};
    if ((qualify_response_rc = charra_unmarshal_qualify_response(
                 data_len, data, &resp)) != CHARRA_RC_SUCCESS) {
        charra_log_error(
                "[" LOG_NAME "] /qualify: Could not parse CBOR response.");
        goto cleanup;
    }

    charra_free_if_not_null(qualify_challenge_log);
    qualify_challenge_log = resp.challenge_log;
    qualify_challenge_log_len = resp.challenge_log_len;
    memcpy(qualify_challenge_salt, resp.salt, sizeof(qualify_challenge_salt));

cleanup:
    processing_qualify_response = false;
    return COAP_RESPONSE_OK;
}

static coap_response_t coap_qualify_submit_response_handler(
        coap_session_t* session CHARRA_UNUSED,
        const coap_pdu_t* sent CHARRA_UNUSED, const coap_pdu_t* received,
        const coap_mid_t mid CHARRA_UNUSED) {
    processing_qualify_submit_response = true;

    /* The Verifier now answers with a CBOR verdict carrying the deadline
     * it granted, so RP no longer has to assume the validity window from
     * a shared compile-time constant -- see msg_qualify_submit_response_
     * dto in charra_dto.h. */
    size_t data_len = 0;
    const uint8_t* data = NULL;
    qualify_submit_qualified = false;
    qualify_submit_expires_at = 0;
    if (charra_coap_get_payload(received, LOG_NAME, "/qualify/submit response",
                &data, &data_len, NULL)) {
        msg_qualify_submit_response_dto resp = {0};
        if (charra_unmarshal_qualify_submit_response(
                    (uint32_t)data_len, data, &resp) == CHARRA_RC_SUCCESS) {
            qualify_submit_qualified =
                    coap_pdu_get_code(received) ==
                            COAP_RESPONSE_CODE_CONTENT &&
                    resp.qualified != 0;
            qualify_submit_expires_at = (time_t)resp.expires_at;
        } else {
            charra_log_error("[" LOG_NAME "] /qualify/submit: could not "
                             "parse the Verifier's response.");
        }
    }

    processing_qualify_submit_response = false;
    return COAP_RESPONSE_OK;
}

/**
 * @brief Read the cached qualification expiry from disk.
 *
 * @returns the cached expires_at, or 0 if the file doesn't exist or is
 * unparseable (treated the same as "no cache" -- not an error, a fresh
 * deployment or a first run simply hasn't qualified yet).
 */
static time_t rp_qualification_cache_load(void) {
    FILE* f = fopen(rp_qualification_cache_path, "r");
    if (f == NULL) {
        return 0;
    }
    long long expires_at = 0;
    int scanned = fscanf(f, "%lld", &expires_at);
    fclose(f);
    if (scanned != 1 || expires_at <= 0) {
        return 0;
    }
    return (time_t)expires_at;
}

/**
 * @brief Persist RP's freshly-earned qualification expiry to disk, so a
 * later process invocation can skip the handshake while it's still valid.
 */
static void rp_qualification_cache_save(time_t expires_at) {
    FILE* f = fopen(rp_qualification_cache_path, "w");
    if (f == NULL) {
        charra_log_error(
                "[" LOG_NAME "] Could not write qualification cache '%s'.",
                rp_qualification_cache_path);
        return;
    }
    fprintf(f, "%lld\n", (long long)expires_at);
    fclose(f);
}

/**
 * @brief Is a grant still valid past renew_deadline, consulting the on-disk
 * cache if the in-memory value says it is not?
 *
 * Re-reads the wall clock on every call rather than trusting a once-computed
 * flag, so a process whose run straddles the expiry moment still notices.
 * Without this whole cache RP re-qualified on every attestation cycle
 * regardless of how much of the previous grant was left.
 */
static bool rp_qualification_still_valid(time_t renew_deadline, time_t now) {
    if (rp_qualified_until <= renew_deadline) {
        rp_qualified_until = rp_qualification_cache_load();
    }
    if (rp_qualified_until <= renew_deadline) {
        return false;
    }
    charra_log_info("[" LOG_NAME "] Cached qualification still valid for %ld "
                    "more second(s), skipping /qualify.",
            (long)(rp_qualified_until - now));
    return true;
}

CHARRA_RC rp_perform_qualification_handshake_once(
        int num_verifiers, time_t refresh_margin_seconds) {
    /* AK certificate readiness is orthogonal to the qualification cache
     * below: /qualify/submit needs an AK cert issued by whichever Verifier
     * we end up qualifying against, so it's provisioned per-candidate
     * inside the loop below, not once up front. */

    /* Cache short-circuit: if we already hold a still-valid qualification
     * -- either from earlier this process, or loaded just now from a
     * previous process run's cache file -- skip the /qualify +
     * /qualify/submit round trip entirely. Re-checked against the wall
     * clock on every call (not just once), so this stays correct even if a
     * single process run happens to straddle the expiry moment. This is
     * what makes CHARRA_RP_QUALIFICATION_VALIDITY_SECONDS actually matter:
     * without it, RP re-qualified unconditionally on every single
     * attestation cycle regardless of how much of a previous grant was
     * left. See CHARRA_V2_NOTES.md. */
    /* Compared against now+margin rather than now: with margin 0 this is
     * exactly "renew only once expired"; with a margin it renews while the
     * grant is still valid, which is what lets daemon mode do the renewal
     * in its idle window instead of inside an attestation. */
    time_t now = time(NULL);
    if (rp_qualification_still_valid(now + refresh_margin_seconds, now)) {
        return CHARRA_RC_SUCCESS;
    }

    CHARRA_RC result = CHARRA_RC_ERROR;

    /* Held across the whole handshake below, not just individual field
     * accesses: every one of qualify_challenge_log/_len/_salt,
     * qualify_response_rc, processing_qualify_response,
     * qualify_submit_qualified, and processing_qualify_submit_response is
     * a single shared global -- see rp_qualification_mutex's own comment
     * for why this still matters even though the handshake itself now
     * runs once per cycle. */
    pthread_mutex_lock(&rp_qualification_mutex);

    /* Re-checked under the lock, which is what actually makes the
     * "first thread re-qualifies, the rest short-circuit" behaviour true.
     * The check above the lock is only a fast path: two threads can both
     * pass it, and without this second look both would run the full
     * handshake, the second one discarding a grant it had just renewed. */
    now = time(NULL);
    if (rp_qualification_still_valid(now + refresh_margin_seconds, now)) {
        pthread_mutex_unlock(&rp_qualification_mutex);
        return CHARRA_RC_SUCCESS;
    }

    /* Try each Verifier in order, stopping at the first one reachable at
     * the network level for /qualify -- a transport failure moves on to
     * the next candidate, but a received verdict (qualified or not) stops
     * the search: the qualification ledger is shared, so the verdict would
     * be the same everywhere. */
    for (int verifier_index = 0; verifier_index < num_verifiers;
            ++verifier_index) {
        CHARRA_RC keypair_and_cert_rc =
                ensure_rp_ak_certificate(verifier_index);
        if (keypair_and_cert_rc != CHARRA_RC_SUCCESS) {
            charra_log_error(
                    "[" LOG_NAME "] Verifier n° %d (port %u): RP AK "
                    "certificate not provisioned, trying next Verifier.",
                    verifier_index + 1, verifiers[verifier_index].port_number);
            continue;
        }

        const verifier_info* verifier = &verifiers[verifier_index];
        uint8_t* redacted_log = NULL;
        uint32_t redacted_log_len = 0;

        charra_log_info(
                "[" LOG_NAME "]  +------------ RP Qualification (Verifier "
                "n° %d, port %u) --------------+",
                verifier_index + 1, verifier->port_number);

        /* --- 1. fetch a fresh challenge --- */
        qualify_response_rc = CHARRA_RC_ERROR;
        result = rp_coap_exchange(&(rp_coap_request){
            .host = verifier->ip_address, .port = verifier->port_number,
            .uri_path = "qualify",
            .body = NULL, .body_len = 0,
            .on_response = coap_qualify_response_handler,
            .response_pending = &processing_qualify_response,
            .timeout_seconds = verifier_response_timeout,
            .dtls_rpk_peer_public_key_path = dtls_rpk_verifier_public_key_path,
        });
        if (result != CHARRA_RC_SUCCESS || qualify_response_rc != CHARRA_RC_SUCCESS) {
            charra_log_error(
                    "[" LOG_NAME "] Verifier n° %d (port %u) unreachable "
                    "for /qualify, trying next Verifier.",
                    verifier_index + 1, verifier->port_number);
            continue;
        }
        charra_log_info("[" LOG_NAME "] Received a %u-byte challenge log.",
                qualify_challenge_log_len);

        /* --- 2. redact it with the exact same pipeline real evidence uses --- */
        result = charra_sdk_redact_ima_log(qualify_challenge_log,
                qualify_challenge_log_len, qualify_challenge_salt,
                &redacted_log, &redacted_log_len);
        if (result != CHARRA_RC_SUCCESS) {
            charra_log_error("[" LOG_NAME "] Could not redact the "
                             "qualification challenge log.");
            goto done;
        }

        /* --- 3. replay the redacted log into its PCR digest --- */
        uint8_t submitted_pcr_digest[TPM2_SHA256_DIGEST_SIZE] = {0};
        result = charra_replay_ima_log(redacted_log, redacted_log_len,
                CHARRA_IMA_PCR_INDEX, submitted_pcr_digest);
        if (result != CHARRA_RC_SUCCESS) {
            charra_log_error("[" LOG_NAME "] Could not replay the redacted "
                             "challenge log.");
            charra_free_if_not_null(redacted_log);
            goto done;
        }

        /* --- 4. sign the PCR digest with RP's TPM-resident AK, same
         * short-lived-connection pattern charra_rp_build_evidence_message()
         * uses for Quote_r --- */
        uint8_t rp_signature[CHARRA_RSA_SIGNATURE_LEN] = {0};
        pthread_mutex_lock(&rp_tpm_mutex);
        ESYS_CONTEXT* sign_esys_ctx = NULL;
        TSS2_TCTI_CONTEXT* sign_tcti_ctx = NULL;
        ESYS_TR sign_ek_handle = ESYS_TR_NONE;
        ESYS_TR sign_ak_handle = ESYS_TR_NONE;
        TPM2B_NAME* sign_ak_name = NULL;
        result = rp_open_tpm_and_load_ak(&sign_esys_ctx, &sign_tcti_ctx,
                &sign_ek_handle, &sign_ak_handle, &sign_ak_name);
        if (result != CHARRA_RC_SUCCESS) {
            pthread_mutex_unlock(&rp_tpm_mutex);
            charra_log_error("[" LOG_NAME "] Could not open TPM connection "
                             "to sign the qualification PCR digest.");
            charra_free_if_not_null(redacted_log);
            goto done;
        }
        Esys_Free(sign_ak_name);

        result = charra_identity_key_mgr_sign(sign_esys_ctx, sign_ak_handle,
                submitted_pcr_digest, sizeof(submitted_pcr_digest),
                rp_signature);

        Esys_FlushContext(sign_esys_ctx, sign_ak_handle);
        Esys_FlushContext(sign_esys_ctx, sign_ek_handle);
        Esys_Finalize(&sign_esys_ctx);
        Tss2_TctiLdr_Finalize(&sign_tcti_ctx);
        pthread_mutex_unlock(&rp_tpm_mutex);

        if (result != CHARRA_RC_SUCCESS) {
            charra_log_error(
                    "[" LOG_NAME "] Could not sign the qualification PCR "
                    "digest.");
            charra_free_if_not_null(redacted_log);
            goto done;
        }

        /* --- 5. submit --- */
        msg_qualify_submit_request_dto submit_req = {
                .submitted_redacted_log_len = redacted_log_len,
                .submitted_redacted_log = redacted_log,
                .rp_signature_len = sizeof(rp_signature),
                .rp_public_key_len = rp_public_key_der_len,
                .ak_certificate_rp_len = rp_ak_cert_der_len[verifier_index],
                .ak_certificate_rp = rp_ak_cert_der[verifier_index],
        };
        memcpy(submit_req.submitted_pcr_digest, submitted_pcr_digest,
                sizeof(submitted_pcr_digest));
        memcpy(submit_req.rp_signature, rp_signature, sizeof(rp_signature));
        memcpy(submit_req.rp_public_key, rp_public_key_der,
                rp_public_key_der_len);

        uint8_t* submit_buf = NULL;
        uint32_t submit_buf_len = 0;
        result = charra_marshal_qualify_submit_request(
                &submit_req, &submit_buf_len, &submit_buf);
        if (result != CHARRA_RC_SUCCESS) {
            charra_log_error(
                    "[" LOG_NAME "] Could not marshal /qualify/submit "
                    "request.");
            charra_free_if_not_null(redacted_log);
            goto done;
        }

        result = rp_coap_exchange(&(rp_coap_request){
            .host = verifier->ip_address, .port = verifier->port_number,
            .uri_path = "qualify_submit",
            .body = submit_buf, .body_len = submit_buf_len,
            .on_response = coap_qualify_submit_response_handler,
            .response_pending = &processing_qualify_submit_response,
            .timeout_seconds = verifier_response_timeout,
            .dtls_rpk_peer_public_key_path = dtls_rpk_verifier_public_key_path,
        });
        charra_free_if_not_null(submit_buf);
        if (result != CHARRA_RC_SUCCESS) {
            charra_log_error(
                    "[" LOG_NAME "] Verifier n° %d (port %u) unreachable "
                    "for /qualify_submit, trying next Verifier.",
                    verifier_index + 1, verifier->port_number);
            charra_free_if_not_null(redacted_log);
            continue;
        }

        if (qualify_submit_qualified) {
            charra_log_info(
                    "[" LOG_NAME "] |  RP QUALIFIED with Verifier n° %d "
                    "(port %u)  |",
                    verifier_index + 1, verifier->port_number);
            /* Exactly what the Verifier said it granted -- no local
             * guess at the window. */
            time_t expires_at = qualify_submit_expires_at;
            rp_qualified_until = expires_at;
            rp_qualification_cache_save(expires_at);
            charra_log_info(
                    "[" LOG_NAME "] Qualification valid until %ld (%ld "
                    "second(s) from now, as granted by this Verifier); "
                    "shared with every other Verifier.",
                    (long)expires_at, (long)(expires_at - time(NULL)));
            /* The margin only helps if it fits inside the window the
             * Verifier actually granted -- which RP only learns here, not
             * at CLI-parse time. */
            if (rp_qualify_renew_margin_s > 0 &&
                    (time_t)rp_qualify_renew_margin_s >= expires_at - time(NULL)) {
                charra_log_warn(
                        "[" LOG_NAME "] --qualify-renew-margin (%us) is not smaller "
                        "than the %lds window this Verifier grants; RP will "
                        "re-qualify on every idle pass.",
                        rp_qualify_renew_margin_s, (long)(expires_at - time(NULL)));
            }
            result = CHARRA_RC_SUCCESS;
        } else {
            charra_log_error(
                    "[" LOG_NAME
                    "] |  RP NOT QUALIFIED with Verifier n° %d (port %u)  |",
                    verifier_index + 1, verifier->port_number);
            result = CHARRA_RC_VERIFICATION_FAILED;
        }
        charra_free_if_not_null(redacted_log);
        goto done;
    }

    charra_log_error("[" LOG_NAME "] Could not qualify: no Verifier was "
                     "reachable for /qualify.");
    result = CHARRA_RC_ERROR;

done:
    charra_free_if_not_null(qualify_challenge_log);
    qualify_challenge_log = NULL;
    qualify_challenge_log_len = 0;
    pthread_mutex_unlock(&rp_qualification_mutex);
    return result;
}
