/**
 * @file verifier_qualify.c
 * @brief See verifier_qualify.h.
 *
 * Both legs live together because the second is meaningless without the
 * first: /qualify stores the expected answer in qualification_state, and
 * /qualify_submit is the only thing that ever reads it.
 */

#include "verifier_qualify.h"

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

/**
 * @brief /qualify: fabricate a fresh RP-qualification challenge and hand
 * back its raw (unredacted) log for the RP to redact and prove against via
 * /qualify/submit -- see charra_rp_qualification.h for the full handshake
 * this is the first half of.
 *
 * Ignores the request body: nothing about *which* challenge to generate is
 * caller-supplied, only Verifier policy (CHARRA_RP_QUALIFICATION_NUM_
 * ENTRIES) and a fresh random seed picked here.
 */
void coap_qualify_handler(struct coap_resource_t* resource,
                                struct coap_session_t* session,
                                const struct coap_pdu_t* request,
                                const struct coap_string_t* query,
                                struct coap_pdu_t* response) {
    int coap_r = 0;
    CHARRA_RC charra_r = CHARRA_RC_ERROR;
    coap_pdu_code_t response_code = COAP_RESPONSE_CODE_INTERNAL_ERROR;

    log_peer_address("/qualify", session);

    uint8_t* challenge_log = NULL;
    uint32_t challenge_log_len = 0;
    uint8_t* marshaled_response = NULL;
    uint32_t marshaled_response_len = 0;

    /* discard the previous round's golden answer -- a fresh /qualify call
     * always starts a new round; any /qualify/submit still in flight for
     * the old one is now moot */
    charra_rp_qualification_state_free(&qualification_state);

    uint32_t seed = 0;
    if ((charra_r = charra_random_bytes(
                 sizeof(seed), (uint8_t*)&seed)) != CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] /qualify: could not generate a "
                         "random challenge seed.");
        goto cleanup;
    }

    /* Shared with the RP in the response below, so its redaction of
     * challenge_log comes out byte-identical to golden_log here -- the one
     * deliberate exception to "salt is never transmitted", safe only
     * because this log is synthetic. See charra_sdk.h. */
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
 * @brief /qualify/submit: check the RP's redaction result against the
 * outstanding /qualify challenge, gating whether coap_appraise_handler()
 * will accept real evidence from this RP -- see charra_rp_qualification.h.
 *
 * Two things must hold before charra_rp_qualification_check() is even
 * consulted: the submitter's AK certificate must chain to this Verifier's
 * CA (the same check Step 3a item 1 in coap_appraise_handler() runs), and
 * its signature over submitted_pcr_digest must verify under that certified
 * key. Without both, an unauthenticated party could submit an arbitrary
 * log and PCR digest with no proof it ever ran a real RP's redaction
 * pipeline.
 */
void coap_qualify_submit_handler(struct coap_resource_t* resource,
                                struct coap_session_t* session,
                                const struct coap_pdu_t* request,
                                const struct coap_string_t* query,
                                struct coap_pdu_t* response) {
    int coap_r = 0;
    CHARRA_RC charra_r = CHARRA_RC_ERROR;
    coap_pdu_code_t response_code = COAP_RESPONSE_CODE_INTERNAL_ERROR;
    const char* message = "Qualification check errored!\0";

    log_peer_address("/qualify/submit", session);

    /* declared/zeroed here so cleanup can always safely free them,
     * regardless of which check below first failed -- same convention
     * coap_certify_ak_handler() above uses */
    msg_qualify_submit_request_dto req = {0};
    char* verifier_ca_cert_der = NULL;
    /* Verdict + the deadline actually granted -- the RP has no other
     * way to learn the window this Verifier chose. */
    msg_qualify_submit_response_dto submit_response = {0};
    size_t verifier_ca_cert_der_len = 0;

    size_t data_len = 0;
    const uint8_t* data = NULL;
    size_t data_offset = 0;
    size_t data_total_len = 0;
    if ((coap_r = coap_get_data_large(request, &data_len, &data, &data_offset,
                 &data_total_len)) == 0) {
        charra_log_error("[" LOG_NAME
                         "] /qualify/submit: Could not get CoAP PDU data.");
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

    /* --- who is this: submitter's AK certificate must chain to our CA,
     * same check Step 3a item 1 in coap_appraise_handler() runs --- */
    if ((charra_r = charra_io_read_file(verifier_ca_cert_path,
                 &verifier_ca_cert_der, &verifier_ca_cert_der_len)) !=
            CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] /qualify/submit: could not read "
                         "Verifier CA certificate ('%s').",
                verifier_ca_cert_path);
        goto cleanup;
    }

    /* ek_fingerprint identifies who this is, for the qualification-ledger
     * write below -- declared here (not inside the block) so it survives
     * past it, populated only when submitter_identity_ok ends up true. */
    uint8_t ek_fingerprint[32] = {0};
    bool submitter_identity_ok = false;
    {
        mbedtls_x509_crt ak_cert_rp_leaf;
        uint8_t ak_serial_rp[16] = {0};
        CHARRA_RC chain_rc = charra_crypto_verify_x509_cert_chain(
                req.ak_certificate_rp, req.ak_certificate_rp_len,
                (uint8_t*)verifier_ca_cert_der, verifier_ca_cert_der_len,
                &ak_cert_rp_leaf);
        if (chain_rc == CHARRA_RC_SUCCESS) {
            if (ak_cert_rp_leaf.serial.len == 16) {
                memcpy(ak_serial_rp, ak_cert_rp_leaf.serial.p, 16);
            }
            submitter_identity_ok =
                    charra_crypto_verify_cert_public_key_matches_der_key(
                            &ak_cert_rp_leaf, req.rp_public_key,
                            req.rp_public_key_len) == CHARRA_RC_SUCCESS &&
                    charra_ak_state_check_serial_valid(rp_ak_state_file_path,
                            ak_serial_rp, ek_fingerprint, NULL);
            if (submitter_identity_ok) {
                charra_crypto_log_cert_summary(
                        "/qualify/submit submitter's AK cert",
                        &ak_cert_rp_leaf);
            }
            mbedtls_x509_crt_free(&ak_cert_rp_leaf);
        }
    }
    if (!submitter_identity_ok) {
        charra_log_error("[" LOG_NAME "] /qualify/submit: submitter's AK "
                         "certificate did NOT verify (chain, key mismatch, "
                         "or expired/revoked).");
        response_code = COAP_RESPONSE_CODE_UNAUTHORIZED;
        message = "Submitter AK certificate invalid or expired!\0";
        goto cleanup;
    }

    /* --- Quote_R signature: proves the certified key above actually
     * signed submitted_pcr_digest, not that some unrelated certificate was
     * merely attached to the request --- */
    bool signature_ok = false;
    {
        mbedtls_pk_context rp_pub_key_ctx;
        mbedtls_pk_init(&rp_pub_key_ctx);
        if (mbedtls_pk_parse_public_key(&rp_pub_key_ctx, req.rp_public_key,
                    req.rp_public_key_len) == 0 &&
                mbedtls_pk_get_type(&rp_pub_key_ctx) == MBEDTLS_PK_RSA &&
                mbedtls_rsa_set_padding(mbedtls_pk_rsa(rp_pub_key_ctx),
                        MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA256) == 0) {
            signature_ok = charra_crypto_rsa_verify_signature(
                                   mbedtls_pk_rsa(rp_pub_key_ctx),
                                   MBEDTLS_MD_SHA256, req.submitted_pcr_digest,
                                   sizeof(req.submitted_pcr_digest),
                                   req.rp_signature) == CHARRA_RC_SUCCESS;
        } else {
            charra_log_error("[" LOG_NAME "] /qualify/submit: could not "
                             "parse submitter's public key.");
        }
        mbedtls_pk_free(&rp_pub_key_ctx);
    }
    if (!signature_ok) {
        charra_log_error("[" LOG_NAME "] /qualify/submit: signature over "
                         "submitted PCR digest is NOT valid.");
        response_code = COAP_RESPONSE_CODE_UNAUTHORIZED;
        message = "Signature over submitted PCR digest invalid!\0";
        goto cleanup;
    }

    /* --- the actual qualification comparison: golden answer vs.
     * submission -- see charra_rp_qualification.h. The salt used to redact
     * challenge_log is shared with the RP (see coap_qualify_handler()'s
     * own comment on qualify_challenge_salt) specifically so a correctly-
     * behaving RP's redaction comes out byte-identical to golden_log here;
     * a passing check on a legitimately-behaving RP is the expected,
     * common case, not a known-broken path. */
    if (charra_rp_qualification_check(&qualification_state,
                req.submitted_redacted_log, req.submitted_redacted_log_len,
                req.submitted_pcr_digest, time(NULL)) == CHARRA_RC_SUCCESS) {
        /* Persist the verdict, keyed by this RP's identity -- this is what
         * lets coap_appraise_handler() later confirm THIS SPECIFIC RP
         * qualified, not just "someone did, recently". Deliberately done
         * only here, once the check has actually passed -- a failed
         * charra_qualification_state_renew() call below still leaves the
         * RP correctly told it qualified (the check itself did pass), it
         * just means the durable record didn't get written; logged, not
         * fatal to this response. */
        charra_qualification_state_record qual_record = {0};
        memcpy(qual_record.ek_fingerprint, ek_fingerprint,
                sizeof(qual_record.ek_fingerprint));
        qual_record.qualified_at = time(NULL);
        qual_record.expires_at = qualification_state.expires_at;
        if (charra_qualification_state_renew(qualification_state_file_path,
                    ek_fingerprint, &qual_record) != CHARRA_RC_SUCCESS) {
            charra_log_error("[" LOG_NAME "] /qualify/submit: could not "
                             "persist qualification state.");
        }

        char ek_fingerprint_hex[17] = {0};
        hex_prefix(ek_fingerprint, sizeof(ek_fingerprint), ek_fingerprint_hex,
                sizeof(ek_fingerprint_hex));
        charra_log_info(
                "[" LOG_NAME "] /qualify/submit: RP %s... qualified (valid "
                "until %ld, %ld second(s) from now).",
                ek_fingerprint_hex, (long)qualification_state.expires_at,
                (long)(qualification_state.expires_at - time(NULL)));
        response_code = COAP_RESPONSE_CODE_CONTENT;
        message = "Qualification successful!\0";
        submit_response.qualified = 1;
        submit_response.expires_at =
                (uint64_t)qualification_state.expires_at;
    } else {
        char ek_fingerprint_hex[17] = {0};
        hex_prefix(ek_fingerprint, sizeof(ek_fingerprint), ek_fingerprint_hex,
                sizeof(ek_fingerprint_hex));
        charra_log_error(
                "[" LOG_NAME "] /qualify/submit: RP %s...'s submitted "
                "log/PCR did NOT match the golden answer.",
                ek_fingerprint_hex);
        response_code = COAP_RESPONSE_CODE_CONTENT;
        message = "Qualification failed!  \0";
    }

cleanup:
    coap_pdu_set_code(response, response_code);
    /* The human-readable message stays in the log; the wire now carries
     * the structured verdict so RP need not assume the window. */
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
    charra_free_if_not_null(req.ak_certificate_rp);
    charra_io_free_file_buffer(&verifier_ca_cert_der);
    return;
}
