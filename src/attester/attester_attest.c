/**
 * @file attester_attest.c
 * @brief See attester_attest.h.
 *
 * /attest: produces Quote_a over the requested PCR selection, together with
 * the IMA log those PCRs were extended from. The signing key itself is
 * never provisioned or certified at runtime -- see charra_trusted_keys.h.
 */


#include "attester_attest.h"
#include "../common/charra_log.h"
#include <tss2/tss2_tctildr.h>

#include "../common/charra_macro.h"
#include "../core/charra_helper.h"
#include "../core/charra_key_mgr.h"
#include "../core/charra_marshaling.h"
#include "../util/charra_util.h"
#include "../util/coap_util.h"
#include "../util/io_util.h"
#include "../util/tpm2_util.h"
#include "attester_shared.h"
#include "attester_ima_log.h"
#include "attester_util.h"

#define LOG_NAME "attester"

/* Counts /attest calls this Attester process has served, purely for the log
 * delimiter below -- one /attest call happens per RP cycle (its evidence is
 * reused across every Verifier that cycle forwards to), so this gives an
 * easy-to-scan boundary in a multi-cycle log, the same way the Verifier's
 * attestation_round_counter does on its side. */
static unsigned int attest_request_counter = 0;

/**
 * @brief Formats a TPML_PCR_SELECTION's selected PCR indices (across all
 * its banks) as a compact "0,1,2,...,10" string, purely for logging what
 * was actually quoted -- easier to eyeball than cross-referencing the RP's
 * own request log for the same information.
 */
static void format_pcr_selection(
        const TPML_PCR_SELECTION* sel, char* out, size_t out_len) {
    size_t pos = 0;
    out[0] = '\0';
    for (UINT32 b = 0; b < sel->count && pos < out_len; ++b) {
        const TPMS_PCR_SELECTION* bank = &sel->pcrSelections[b];
        for (int i = 0; i < bank->sizeofSelect * 8 && pos < out_len; ++i) {
            if (bank->pcrSelect[i / 8] & (1 << (i % 8))) {
                int written = snprintf(out + pos, out_len - pos, "%s%d",
                        (pos == 0) ? "" : ",", i);
                if (written < 0) {
                    break;
                }
                pos += (size_t)written;
            }
        }
    }
}

void coap_attest_handler(struct coap_resource_t* resource,
                                struct coap_session_t* session,
                                const struct coap_pdu_t* request,
                                const struct coap_string_t* query,
                                struct coap_pdu_t* response) {
    CHARRA_RC charra_r = CHARRA_RC_SUCCESS;
    int coap_r = 0;
    TSS2_RC tss_r = 0;
    ESYS_TR sig_key_handle = ESYS_TR_NONE;
    TPM2B_PUBLIC* public_key = NULL;
    /* Declared here (rather than right before first use, further down) and
     * initialized to NULL so that every earlier 'goto error' -- including
     * the "Could not get CoAP PDU data" one right below -- leaves the
     * error: cleanup block able to safely check them instead of reading
     * indeterminate values. Skipping over a declaration with an
     * initializer does not run that initializer; branching on or freeing
     * an indeterminate pointer is undefined behavior. Mirrors verifier.c's
     * coap_appraise_handler(), fixed for the exact same reason in an
     * earlier audit round. */
    ESYS_CONTEXT* esys_ctx = NULL;
    TSS2_TCTI_CONTEXT* tcti_ctx = NULL;
    TPM2B_ATTEST* attest_buf = NULL;
    TPMT_SIGNATURE* signature = NULL;
    /* Here for the same reason: charra_unmarshal_attestation_request()
     * heap-allocates req.event_log_path, which the cleanup below frees, and
     * the 'goto error's above this point would otherwise skip the
     * initializer and leave that pointer indeterminate. */
    msg_attestation_request_dto req = {0};
    /* Set true only right before falling through to the cleanup label on
     * the success path below -- every 'goto error' skips that line, so
     * this distinguishes "evidence actually sent" from any of the many
     * failure exits for the closing status banner. */
    bool request_succeeded = false;

    /* Clear delimiter between benchmark cycles -- one /attest call happens
     * per cycle (see attest_request_counter's own comment), so this marks
     * where one cycle's evidence generation ends and the next begins, the
     * same way verifier.c's and relying_party.c's own delimiters do. */
    attest_request_counter++;
    charra_log_info("[" LOG_NAME
                    "] ============================================================");
    charra_log_info("[" LOG_NAME "] Starting /attest request #%u.",
            attest_request_counter);
    charra_log_info("[" LOG_NAME
                    "] ============================================================");
    charra_coap_log_peer_address(LOG_NAME, "/attest", session);

    /* --- receive incoming data --- */
    charra_log_info(
            "[" LOG_NAME "] Resource '%s': Received message.", "attest");
    coap_show_pdu(LOG_DEBUG, request);

    /* get data */
    size_t data_len = 0;
    const uint8_t* data = NULL;
    size_t data_total_len = 0;
    if (!charra_coap_get_payload(request, LOG_NAME, "/attest", &data, &data_len,
                &data_total_len)) {
        goto error;
    } else if (data_len == data_total_len) {
        /* the common case: no block-wise splitting happened, so the two
         * lengths are identical -- collapsed into one line instead of two
         * redundant ones */
        charra_log_info(
                "[" LOG_NAME "] Received attestation request of %zu byte(s).",
                data_len);
    } else {
        charra_log_info(
                "[" LOG_NAME "] Received attestation request: %zu byte(s) "
                "of %zu byte(s) total (block-wise transfer).",
                data_len, data_total_len);
    }

    /* unmarshal data */
    charra_log_info("[" LOG_NAME "] Parsing received CBOR data.");
    if ((charra_r = charra_unmarshal_attestation_request(
                 data_len, data, &req)) != CHARRA_RC_SUCCESS) {
        charra_log_error(
                "[" LOG_NAME "] Could not parse CBOR data: CHARRA_RC=%d.",
                charra_r);
        goto error;
    }

    /* --- TPM quote --- */

    charra_log_info("[" LOG_NAME "] Preparing TPM quote data.");

    /* nonce */
    if (req.nonce_len > sizeof(TPMU_HA)) {
        charra_log_error("[" LOG_NAME "] Nonce too long.");
        goto error;
    }
    TPM2B_DATA qualifying_data = {.size = 0, .buffer = {0}};
    qualifying_data.size = req.nonce_len;
    memcpy(qualifying_data.buffer, req.nonce, req.nonce_len);

    charra_log_info("[" LOG_NAME "] Received nonce of length %zu:", req.nonce_len);
    charra_print_hex(CHARRA_LOG_INFO, req.nonce_len, req.nonce,
            "                                   0x", "\n", false);

    charra_log_info(
            "[" LOG_NAME "] Signing key ID: '%.*s'.",
            (int)req.sig_key_id_len, req.sig_key_id);

    /* PCR selection */
    TPML_PCR_SELECTION pcr_selection = {0};
    if ((charra_r = charra_pcr_selections_to_tpm_pcr_selections(
                 req.pcr_selections_len, req.pcr_selections, &pcr_selection)) !=
            CHARRA_RC_SUCCESS) {
        charra_log_error(
                "[" LOG_NAME "] PCR selection conversion error: "
                "CHARRA_RC=%d.",
                charra_r);
        goto error;
    }
    {
        char pcr_list[128] = {0};
        format_pcr_selection(&pcr_selection, pcr_list, sizeof(pcr_list));
        charra_log_info(
                "[" LOG_NAME "] Quoting PCR(s): %s.", pcr_list);
    }

    struct timespec start_time, end_time;
    double duration;
    clock_gettime(CLOCK_MONOTONIC, &start_time);

    /* initialize ESAPI */
    const char* charra_tcti = getenv("CHARRA_TCTI");
    charra_log_info("[" LOG_NAME "] CHARRA_TCTI = '%s'.",
            (charra_tcti != NULL) ? charra_tcti : "(null)");
    if ((tss_r = Tss2_TctiLdr_Initialize(charra_tcti, &tcti_ctx)) !=
            TSS2_RC_SUCCESS) {
        charra_log_error(
                "[" LOG_NAME "] Tss2_TctiLdr_Initialize failed: 0x%x.",
                tss_r);
        goto error;
    }
    if ((tss_r = Esys_Initialize(&esys_ctx, tcti_ctx, NULL)) !=
            TSS2_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Esys_Initialize failed: 0x%x.",
                tss_r);
        goto error;
    }

    /* Extend the IMA log into the PCRs, once per process: PCRs 0-15 cannot
     * be reset without a reboot, so replaying the log on every request would
     * keep growing PCR 10 and no single replay of the log could reproduce
     * it. */
    static bool ima_log_extended = false;
    if (!ima_log_extended) {
        const uint8_t* log = NULL;
        uint32_t log_len = 0;
        if (charra_get_ima_log(ima_test_log_path, &log, &log_len) ==
                CHARRA_RC_SUCCESS) {
            if ((charra_r = charra_extend_pcrs_from_binary_log(
                         esys_ctx, log, log_len)) != CHARRA_RC_SUCCESS) {
                charra_log_error(
                        "[" LOG_NAME "] Could not extend PCRs from IMA "
                        "log: CHARRA_RC=%d.",
                        charra_r);
                goto error;
            }
        } else {
            charra_log_warn("[" LOG_NAME "] No IMA log available; leaving PCRs "
                            "unextended.");
        }
        ima_log_extended = true;
    } else {
        charra_log_debug(
                "[" LOG_NAME "] PCRs already extended from IMA log earlier "
                "this process's lifetime -- skipping (would grow PCR 10 "
                "further and break replay if repeated).");
    }

    /* Load the AK: the TPM's deterministic RESTRICTED signing primary,
     * which TPM2_Quote below requires and which
     * tpm2_create_primary_key_rsa2048() reproduces identically on every
     * call. No provisioning, no persisted blob -- this key's public half
     * was written into keys/trusted_keys.txt offline (see
     * charra_trusted_keys.h), and both the RP and the Verifier check the
     * key they see here against that file. */
    struct timespec start_key_load, end_key_load;
    clock_gettime(CLOCK_MONOTONIC, &start_key_load);
    charra_log_info("[" LOG_NAME "] Loading TPM key.");
    charra_r = charra_load_tpm2_key(esys_ctx, req.sig_key_id_len,
            req.sig_key_id, &sig_key_handle, &public_key);
    if (charra_r != CHARRA_RC_SUCCESS) {
        charra_log_error(
                "[" LOG_NAME "] Could not load TPM key: CHARRA_RC=%d.",
                charra_r);
        goto error;
    }
    clock_gettime(CLOCK_MONOTONIC, &end_key_load);
    double key_load_duration =
            (end_key_load.tv_sec - start_key_load.tv_sec) +
            (end_key_load.tv_nsec - start_key_load.tv_nsec) / 1e9;
    charra_log_info(
            "[" LOG_NAME "] Timing: TPM key load took %f second(s).",
            key_load_duration);

    /* do the TPM quote */
    struct timespec start_quote, end_quote;
    clock_gettime(CLOCK_MONOTONIC, &start_quote);
    charra_log_info("[" LOG_NAME "] Do TPM Quote.");
    if ((tss_r = tpm2_quote(esys_ctx, sig_key_handle, &pcr_selection,
                 &qualifying_data, &attest_buf, &signature)) !=
            TSS2_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] TPM2 quote failed: 0x%x.", tss_r);
        goto error;
    } else {
        charra_log_info("[" LOG_NAME "] TPM Quote successful.");
    }
    clock_gettime(CLOCK_MONOTONIC, &end_quote);
    double quote_duration = (end_quote.tv_sec - start_quote.tv_sec) +
                            (end_quote.tv_nsec - start_quote.tv_nsec) / 1e9;
    charra_log_info(
            "[" LOG_NAME "] Timing: TPM Quote itself took %f second(s).",
            quote_duration);

    /* The quote's own PCR composite digest, straight from the TPM's signed
     * TPMS_ATTEST -- logged so a PCR mismatch investigation on the
     * Verifier side (comparing this against its own replayed digest) does
     * not require re-deriving it from raw evidence bytes. Best-effort:
     * this is purely informational, so a failure here does not abort the
     * request. */
    {
        TPMS_ATTEST attest_struct = {0};
        if (charra_unmarshal_tpm2_quote(attest_buf->size,
                    attest_buf->attestationData,
                    &attest_struct) == CHARRA_RC_SUCCESS) {
            charra_print_hex(CHARRA_LOG_INFO,
                    attest_struct.attested.quote.pcrDigest.size,
                    attest_struct.attested.quote.pcrDigest.buffer,
                    "[" LOG_NAME "] Quote's PCR composite digest = 0x", "\n",
                    false);
        }
    }

    clock_gettime(CLOCK_MONOTONIC, &end_time);
    duration = (end_time.tv_sec - start_time.tv_sec) + (end_time.tv_nsec - start_time.tv_nsec) / 1e9;

    /* Open file to append duration */
    FILE *file;
    file = fopen("timings_attester.txt", "a");
    if (file == NULL) {
        perror("fopen");
        exit(EXIT_FAILURE);
    }

    /* Write duration to file */
    fprintf(file, "%f\n", duration);
    charra_log_info(
            "[" LOG_NAME "] Timing: total /attest handling took %f "
            "second(s).",
            duration);
    fclose(file);

    /* --- send response data --- */

    /* Send the IMA event log if requested. These are the same bytes the PCRs
     * were extended from -- charra_get_ima_log() caches them -- so replaying
     * the log the Relying Party receives reproduces PCR 10 exactly. */
    const uint8_t* ima_event_log = NULL;
    uint32_t ima_event_log_len = 0;
    if (req.event_log_path_len != 0) {
        char* path = malloc(sizeof(char) * (req.event_log_path_len + 1));
        if (path == NULL) {
            charra_log_error(
                    "[" LOG_NAME "] Could not allocate memory for event "
                    "log path. Sending empty event log!");
            goto skip_event_log;
        }
        memcpy(path, req.event_log_path, req.event_log_path_len);
        path[req.event_log_path_len] = '\0';
        charra_log_info(
                "[" LOG_NAME "] Reading IMA event log from '%s'%s.", path,
                (strcmp(path, ima_test_log_path) == 0)
                        ? " (same file the PCRs were extended from)"
                        : " (DIFFERENT from the IMA log the PCRs were "
                          "extended from -- log_a may not reproduce PCR "
                          "10)");
        CHARRA_RC rc =
                charra_get_ima_log(path, &ima_event_log, &ima_event_log_len);
        free(path);
        if (rc != CHARRA_RC_SUCCESS) {
            charra_log_error("[" LOG_NAME "] Error while reading IMA event "
                             "log. Sending empty event log!");
            ima_event_log_len = 0;
            ima_event_log = NULL;
        } else {
            charra_log_info("[" LOG_NAME
                            "] IMA event log has a size of %u bytes.",
                    ima_event_log_len);
        }
    }
skip_event_log:

    /* prepare response */
    charra_log_info("[" LOG_NAME "] Preparing response.");

    /* prepare response DTO */
    msg_attestation_response_dto res = {
            .attestation_data_len = attest_buf->size,
            .attestation_data = {0},  // must be memcpy'd, see below
            .tpm2_signature_len = sizeof(*signature),
            .tpm2_signature = {0},  // must be memcpy'd, see below
            .tpm2_public_key_len = sizeof(*public_key),
            .tpm2_public_key = {0},  // must be memcpy'd, see below
            .event_log_len = ima_event_log_len,
            /* borrowed from the cache; not freed here */
            .event_log = (uint8_t*)ima_event_log,
    };
    memcpy(res.attestation_data, attest_buf->attestationData,
            res.attestation_data_len);
    memcpy(res.tpm2_signature, signature, res.tpm2_signature_len);
    memcpy(res.tpm2_public_key, public_key, res.tpm2_public_key_len);

    charra_log_info(
            "[" LOG_NAME "] Response components: attestation_data=%u "
            "byte(s), tpm2_signature=%u byte(s), tpm2_public_key=%u "
            "byte(s), event_log=%u byte(s).",
            res.attestation_data_len, res.tpm2_signature_len,
            res.tpm2_public_key_len, res.event_log_len);

    /* clean up */
    charra_free_and_null(signature);
    charra_free_and_null(attest_buf);
    charra_free_and_null(public_key);

    /* marshal response */
    charra_log_info("[" LOG_NAME "] Marshaling response to CBOR.");
    uint32_t res_buf_len = 0;
    uint8_t* res_buf = NULL;
    if ((charra_r = charra_marshal_attestation_response(
                 &res, &res_buf_len, &res_buf)) != CHARRA_RC_SUCCESS) {
        charra_log_error(
                "[" LOG_NAME "] Error marshaling data: CHARRA_RC=%d.",
                charra_r);
        goto error;
    }
    charra_log_info("[" LOG_NAME "] Size of marshaled response is %d bytes.",
            res_buf_len);

    // TODO(any) In case an error occurred, an error respone should be sent.
    // TODO(any): The verifier should be able to handle this error reponse.

    /* add response data to outgoing PDU and send it */
    charra_log_info(
            "[" LOG_NAME
            "] Adding marshaled data to CoAP response PDU and send it.");
    coap_pdu_set_code(response, COAP_RESPONSE_CODE_CONTENT);
    if ((coap_r = coap_add_data_large_response(resource, session, request, response,
                query, COAP_MEDIATYPE_APPLICATION_CBOR, -1, 0,
                res_buf_len, res_buf, attester_release_data, res_buf)) == 0) {
        charra_log_error("[" LOG_NAME
                         "] Error invoking coap_add_data_large_response().");
        goto error;
    }
    charra_log_info("[" LOG_NAME "] Evidence sent to the relying party.");
    request_succeeded = true;

error:
    charra_log_info("[" LOG_NAME "] +----------------------------+");
    if (request_succeeded) {
        charra_log_info("[" LOG_NAME "] |   EVIDENCE GENERATED OK    |");
    } else {
        charra_log_info("[" LOG_NAME "] |   /attest REQUEST FAILED   |");
    }
    charra_log_info("[" LOG_NAME "] +----------------------------+");

    /* free heap objects */
    charra_free_if_not_null(req.event_log_path);
    charra_free_if_not_null(signature);
    charra_free_if_not_null(attest_buf);
    charra_free_if_not_null(public_key);
    /* ima_event_log is owned by the cache in charra_get_ima_log() and lives
     * for the process lifetime -- freeing it here would dangle the cache and
     * change the log between attestations. */

    /* flush handles */
    if (sig_key_handle != ESYS_TR_NONE) {
        if (Esys_FlushContext(esys_ctx, sig_key_handle) != TSS2_RC_SUCCESS) {
            charra_log_error(
                    "[" LOG_NAME "] TSS cleanup sig_key_handle failed.");
        }
    }

    /* finalize ESAPI */
    if (esys_ctx != NULL) {
        Esys_Finalize(&esys_ctx);
    }
    if (tcti_ctx != NULL) {
        Tss2_TctiLdr_Finalize(&tcti_ctx);
    }
}
