/**
 * @file verifier_qualify.c
 * @brief See verifier_qualify.h.
 *
 * Both legs live together because the second is meaningless without the
 * first: /qualify stores the expected answer, and /qualify_submit is the
 * only thing that ever reads it.
 */

#include "verifier_qualify.h"

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "../common/charra_log.h"
#include "../common/charra_macro.h"
#include "../core/charra_trusted_keys.h"
#include "../core/charra_dto.h"
#include "../core/charra_marshaling.h"
#include "../core/charra_rp_qualification.h"
#include "../util/charra_util.h"
#include "../util/coap_util.h"
#include "../util/crypto_util.h"
#include "../util/hex_util.h"
#include "../util/io_util.h"
#include "verifier_qualified_rps.h"
#include "verifier_shared.h"
#include "verifier_util.h"

#define LOG_NAME "verifier"

/* How many synthetic log entries /qualify challenges the RP with. */
#define CHARRA_RP_QUALIFICATION_NUM_ENTRIES 5

/* The one outstanding challenge's golden answer. Single slot, matching the
 * one-round-in-flight assumption the rest of this Verifier makes. The
 * verdict itself ("has this RP qualified") is kept separately, in memory --
 * see verifier_qualified_rps.h. */
static rp_qualification_state qualification_state = {0};

void coap_qualify_handler(struct coap_resource_t* resource,
                                struct coap_session_t* session,
                                const struct coap_pdu_t* request,
                                const struct coap_string_t* query,
                                struct coap_pdu_t* response) {
    int coap_r = 0;
    CHARRA_RC charra_r = CHARRA_RC_ERROR;
    coap_pdu_code_t response_code = COAP_RESPONSE_CODE_INTERNAL_ERROR;

    charra_coap_log_peer_address(LOG_NAME, "/qualify", session);

    uint8_t* challenge_log = NULL;
    uint32_t challenge_log_len = 0;
    uint8_t* marshaled_response = NULL;
    uint32_t marshaled_response_len = 0;

    /* A fresh /qualify starts a new round; any submit still in flight for
     * the old one is now moot. */
    charra_rp_qualification_state_free(&qualification_state);

    uint32_t seed = 0;
    if ((charra_r = charra_random_bytes(
                 sizeof(seed), (uint8_t*)&seed)) != CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] /qualify: could not generate a "
                         "random challenge seed.");
        goto cleanup;
    }

    /* Shared with the RP below so its redaction of challenge_log comes out
     * byte-identical to golden_log -- the one deliberate exception to "salt
     * is never transmitted", safe only because this log is synthetic. See
     * charra_sdk.h. */
    uint8_t salt[CHARRA_SDK_PATH_SALT_LEN] = {0};
    if ((charra_r = charra_random_bytes(sizeof(salt), salt)) !=
            CHARRA_RC_SUCCESS) {
        charra_log_error(
                "[" LOG_NAME "] /qualify: could not generate a salt.");
        goto cleanup;
    }

    if ((charra_r = charra_rp_qualification_generate(
                 CHARRA_RP_QUALIFICATION_NUM_ENTRIES, seed, salt,
                 &qualification_state, &challenge_log,
                 &challenge_log_len)) != CHARRA_RC_SUCCESS) {
        charra_log_error(
                "[" LOG_NAME "] /qualify: could not generate challenge.");
        goto cleanup;
    }

    msg_qualify_response_dto resp = {
            .challenge_log_len = challenge_log_len,
            .challenge_log = challenge_log,
    };
    memcpy(resp.salt, salt, sizeof(resp.salt));
    if ((charra_r = charra_marshal_qualify_response(&resp,
                 &marshaled_response_len, &marshaled_response)) !=
            CHARRA_RC_SUCCESS) {
        charra_log_error(
                "[" LOG_NAME "] /qualify: could not marshal response.");
        goto cleanup;
    }

    charra_log_info(
            "[" LOG_NAME "] /qualify: issued a %u-entry challenge (%u "
            "bytes).",
            CHARRA_RP_QUALIFICATION_NUM_ENTRIES, challenge_log_len);
    response_code = COAP_RESPONSE_CODE_CONTENT;

cleanup:
    coap_pdu_set_code(response, response_code);
    if (response_code == COAP_RESPONSE_CODE_CONTENT) {
        if ((coap_r = coap_add_data_large_response(resource, session,
                     request, response, query, COAP_MEDIATYPE_APPLICATION_CBOR,
                     -1, 0, marshaled_response_len, marshaled_response,
                     release_response_data, marshaled_response)) == 0) {
            charra_log_error("[" LOG_NAME "] /qualify: Error invoking "
                             "coap_add_data_large_response().");
            /* libcoap did not accept ownership -- still ours to free */
            free(marshaled_response);
        }
        /* else: ownership transferred to libcoap, freed later */
    } else {
        free(marshaled_response);
    }
    free(challenge_log);
}

/**
 * @brief /qualify/submit: check the RP's redaction against the outstanding
 * challenge, gating whether coap_appraise_handler() will accept real
 * evidence from this RP -- see charra_rp_qualification.h.
 *
 * Two things must hold before charra_rp_qualification_check() is consulted:
 * the submitter's AK certificate must chain to this Verifier's CA (the same
 * check Step 3a item 1 runs), and its signature over submitted_pcr_digest
 * must verify under that certified key. Without both, an unauthenticated
 * party could submit an arbitrary log and digest with no proof it ever ran
 * a real RP's redaction pipeline.
 */
void coap_qualify_submit_handler(struct coap_resource_t* resource,
                                struct coap_session_t* session,
                                const struct coap_pdu_t* request,
                                const struct coap_string_t* query,
                                struct coap_pdu_t* response) {
    int coap_r = 0;
    CHARRA_RC charra_r = CHARRA_RC_ERROR;
    coap_pdu_code_t response_code = COAP_RESPONSE_CODE_INTERNAL_ERROR;
    const char* message = "Qualification check errored!";

    charra_coap_log_peer_address(LOG_NAME, "/qualify/submit", session);

    /* declared/zeroed here so cleanup can always safely free them,
     * regardless of which check below first failed */
    msg_qualify_submit_request_dto req = {0};
    msg_qualify_submit_response_dto submit_response = {0};

    size_t data_len = 0;
    const uint8_t* data = NULL;
    if (!charra_coap_get_payload(
                request, LOG_NAME, "/qualify/submit", &data, &data_len, NULL)) {
        response_code = COAP_RESPONSE_CODE_BAD_REQUEST;
        goto cleanup;
    }

    if ((charra_r = charra_unmarshal_qualify_submit_request(
                 data_len, data, &req)) != CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME
                         "] /qualify/submit: could not parse CBOR request.");
        response_code = COAP_RESPONSE_CODE_BAD_REQUEST;
        goto cleanup;
    }

    /* --- who is this: the submitter's AK must be an identity we trust,
     * the same trust-anchor lookup Step 3a item 1 runs --- */
    uint8_t rp_fingerprint[VERIFIER_RP_FINGERPRINT_LEN] = {0};
    bool submitter_identity_ok = false;
    {
        char name[128] = {0};
        submitter_identity_ok =
                req.rp_public_key_len == sizeof(TPM2B_PUBLIC) &&
                charra_trusted_keys_check(NULL,
                        (const TPM2B_PUBLIC*)req.rp_public_key, name,
                        sizeof(name)) == CHARRA_RC_SUCCESS &&
                verifier_qualified_rps_fingerprint(req.rp_public_key,
                        req.rp_public_key_len, rp_fingerprint) ==
                        CHARRA_RC_SUCCESS;
        if (submitter_identity_ok) {
            charra_log_info("[" LOG_NAME "] /qualify/submit: submitter's "
                            "signing key is trusted: '%s'",
                    name);
        }
    }
    if (!submitter_identity_ok) {
        charra_log_error("[" LOG_NAME "] /qualify/submit: the submitter's "
                         "signing key is NOT in the trust anchor.");
        response_code = COAP_RESPONSE_CODE_UNAUTHORIZED;
        message = "Submitter key is not a trusted identity!";
        goto cleanup;
    }

    /* --- Quote_R signature: proves the certified key above actually signed
     * submitted_pcr_digest, not that some unrelated certificate was merely
     * attached to the request --- */
    bool signature_ok = false;
    {
        mbedtls_rsa_context rp_rsa_pub_key = {0};
        if (charra_crypto_tpm_pub_key_to_mbedtls_pub_key(
                    (const TPM2B_PUBLIC*)req.rp_public_key, &rp_rsa_pub_key) ==
                CHARRA_RC_SUCCESS) {
            signature_ok = charra_crypto_rsa_verify_signature(&rp_rsa_pub_key,
                                   MBEDTLS_MD_SHA256, req.submitted_pcr_digest,
                                   sizeof(req.submitted_pcr_digest),
                                   req.rp_signature) == CHARRA_RC_SUCCESS;
            mbedtls_rsa_free(&rp_rsa_pub_key);
        } else {
            charra_log_error("[" LOG_NAME "] /qualify/submit: could not "
                             "convert submitter's public key.");
        }
    }
    if (!signature_ok) {
        charra_log_error("[" LOG_NAME "] /qualify/submit: signature over "
                         "submitted PCR digest is NOT valid.");
        response_code = COAP_RESPONSE_CODE_UNAUTHORIZED;
        message = "Signature over submitted PCR digest invalid!";
        goto cleanup;
    }

    /* --- the actual comparison: golden answer vs. submission. The shared
     * salt (see coap_qualify_handler()) is what makes a correctly-behaving
     * RP's redaction come out byte-identical, so a pass here is the expected
     * common case, not a known-broken path. --- */
    CHARRA_RC qualification_rc = charra_rp_qualification_check(
            &qualification_state, req.submitted_redacted_log,
            req.submitted_redacted_log_len, req.submitted_pcr_digest,
            time(NULL));
    /* Read the granted deadline BEFORE freeing the state: this Verifier's
     * --qualification-validity is what stamped it, and it is the number
     * every other Verifier will honour. */
    const time_t granted_expires_at = qualification_state.expires_at;
    /* Single-use: consume the challenge whichever way it went, so a captured
     * submission cannot be replayed to win a grant. A retry needs a
     * fresh /qualify. */
    charra_rp_qualification_state_free(&qualification_state);

    char rp_fingerprint_hex[17] = {0};
    charra_hex_encode_prefix(rp_fingerprint, sizeof(rp_fingerprint),
            rp_fingerprint_hex, sizeof(rp_fingerprint_hex));

    if (qualification_rc == CHARRA_RC_SUCCESS) {
        /* Recorded in the file every Verifier reads, keyed by this RP's
         * identity -- this is what lets coap_appraise_handler(), here and
         * in every sibling Verifier, later confirm THIS SPECIFIC RP
         * qualified. The RP runs the handshake once; the rest of us learn
         * about it from here. See verifier_qualified_rps.h.
         *
         * A failed write is logged, not fatal to this response: the RP did
         * genuinely qualify and deserves to be told so. The cost is that
         * it will be asked to qualify again. */
        if (verifier_qualified_rps_add(qualified_rps_file_path,
                    rp_fingerprint, granted_expires_at) != CHARRA_RC_SUCCESS) {
            charra_log_error("[" LOG_NAME "] /qualify/submit: could not "
                             "record the qualification; this RP will have to "
                             "qualify again.");
        }

        charra_log_info("[" LOG_NAME "] /qualify/submit: RP %s... qualified "
                        "until %lld (%lld second(s) from now).",
                rp_fingerprint_hex, (long long)granted_expires_at,
                (long long)(granted_expires_at - time(NULL)));
        response_code = COAP_RESPONSE_CODE_CONTENT;
        message = "Qualification successful!";
        submit_response.qualified = 1;
        /* The RP has no other way to learn the window this Verifier chose,
         * and it needs it to re-qualify BEFORE the grant lapses -- /appraise
         * never says why it voted no. */
        submit_response.expires_at = (uint64_t)granted_expires_at;
    } else {
        charra_log_error(
                "[" LOG_NAME "] /qualify/submit: RP %s...'s submitted "
                "log/PCR did NOT match the golden answer.",
                rp_fingerprint_hex);
        response_code = COAP_RESPONSE_CODE_CONTENT;
        message = "Qualification failed!";
    }
cleanup:
    coap_pdu_set_code(response, response_code);
    /* The human-readable message stays in the log; the wire carries only
     * the structured verdict. */
    charra_log_info("[" LOG_NAME "] /qualify/submit: %s", message);
    {
        uint8_t* submit_resp_buf = NULL;
        uint32_t submit_resp_buf_len = 0;
        if (charra_marshal_qualify_submit_response(&submit_response,
                    &submit_resp_buf_len, &submit_resp_buf) !=
                CHARRA_RC_SUCCESS) {
            charra_log_error("[" LOG_NAME "] /qualify/submit: could not "
                             "marshal response.");
            coap_pdu_set_code(response, COAP_RESPONSE_CODE_INTERNAL_ERROR);
        } else if ((coap_r = coap_add_data_large_response(resource, session,
                            request, response, query,
                            COAP_MEDIATYPE_APPLICATION_CBOR, -1, 0,
                            submit_resp_buf_len, submit_resp_buf,
                            release_response_data, submit_resp_buf)) == 0) {
            charra_log_error("[" LOG_NAME "] /qualify/submit: error "
                             "invoking coap_add_data_large_response().");
            free(submit_resp_buf);
        }
    }
    charra_free_if_not_null(req.submitted_redacted_log);
}
