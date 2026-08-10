#include <arpa/inet.h>
#include <coap3/coap.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tinydtls/session.h>
#include <tss2/tss2_mu.h>
#include <tss2/tss2_tctildr.h>
#include <tss2/tss2_tpm2_types.h>

#include "common/charra_log.h"
#include "common/charra_macro.h"
#include "core/charra_dto.h"
#include "core/charra_helper.h"
#include "core/charra_key_mgr.h"
#include "core/charra_marshaling.h"
#include "core/charra_rim_mgr.h"
#include "util/cbor_util.h"
#include "util/charra_util.h"
#include "util/cli_util.h"
#include "util/coap_util.h"
#include "util/io_util.h"
#include "util/tpm2_util.h"
#include "util/crypto_util.h"

#define CHARRA_UNUSED __attribute__((unused))

/* --- config ------------------------------------------------------------- */

/* quit signal */
static bool quit = false;
static CHARRA_RC attestation_rc = CHARRA_RC_ERROR;

/* logging */
#define LOG_NAME "verifier"
static uint8_t tpm_pcr_selection[TPM2_MAX_PCRS] = {0, 1, 2, 3, 4, 5, 6, 7, 10};
static uint32_t tpm_pcr_selection_len = 9;
char* reference_pcr_file_path = "reference-pcrs.txt";
coap_log_t coap_log_level = LOG_INFO;
// #define LOG_LEVEL_CBOR LOG_DEBUG
charra_log_t charra_log_level = CHARRA_LOG_INFO;

/* config */
static const char LISTEN_ADDRESS[] = "0.0.0.0";
static unsigned int port = 31415;  
#define CBOR_ENCODER_BUFFER_LENGTH 20480       // 20 KiB should be sufficient
bool use_ima_event_log = false;
char* ima_event_log_path =
        "/sys/kernel/security/ima/binary_runtime_measurements";

// for DTLS-PSK
bool use_dtls_psk = false;
char* dtls_psk_key = "Charra DTLS Key";
char* dtls_psk_identity = "Charra Verifier";
char* dtls_psk_hint = "Charra Attester";

// for DTLS-RPK
bool use_dtls_rpk = false;
char* dtls_rpk_private_key_path = "keys/verifier.der";
char* dtls_rpk_public_key_path = "keys/verifier.pub.der";
char* dtls_rpk_peer_public_key_path = "keys/relying_party.pub.der";
bool dtls_rpk_verify_peer_public_key = true;

static msg_attestation_request_dto last_request = {0};

/**
 * @brief SIGINT handler: set quit to 1 for graceful termination.
 *
 * @param signum the signal number.
 */
static void handle_sigint(int signum);

static void coap_appraise_handler(struct coap_resource_t* resource,
                                struct coap_session_t* session,
                                const struct coap_pdu_t* request,
                                const struct coap_string_t* query,
                                struct coap_pdu_t* response);
                                
static void coap_nonce_handler(struct coap_resource_t* resource,
                                struct coap_session_t* session,
                                const struct coap_pdu_t* request,
                                const struct coap_string_t* query,
                                struct coap_pdu_t* response);

/* --- main --------------------------------------------------------------- */

int main(int argc, char** argv) {
    int result = EXIT_FAILURE;

    /* handle SIGINT */
    signal(SIGINT, handle_sigint);

    /* check environment variables */
    charra_log_level_from_str(
            (const char*)getenv("LOG_LEVEL_CHARRA"), &charra_log_level);
    charra_coap_log_level_from_str(
            (const char*)getenv("LOG_LEVEL_COAP"), &coap_log_level);

    /* initialize structures to pass to the CLI parser */
    /* clang-format off */
    cli_config cli_config = {
        .caller = VERIFIER,
        .common_config = {
            .charra_log_level = &charra_log_level,
            .coap_log_level = &coap_log_level,
            .port = &port,
            .use_dtls_psk = &use_dtls_psk,
            .dtls_psk_key = &dtls_psk_key,
            .use_dtls_rpk = &use_dtls_rpk,
            .dtls_rpk_private_key_path =
                    &dtls_rpk_private_key_path,
            .dtls_rpk_public_key_path =
                    &dtls_rpk_public_key_path,
            .dtls_rpk_peer_public_key_path =
                    &dtls_rpk_peer_public_key_path,
            .dtls_rpk_verify_peer_public_key =
                    &dtls_rpk_verify_peer_public_key,
        },
        .attester_config = {
            .dtls_psk_hint = &dtls_psk_hint,
        },
        .verifier_config = {
            // .dst_host = dst_host,
            // .timeout = &attestation_response_timeout,
            .reference_pcr_file_path = &reference_pcr_file_path,
            .tpm_pcr_selection = tpm_pcr_selection,
            .tpm_pcr_selection_len = &tpm_pcr_selection_len,
            .use_ima_event_log = &use_ima_event_log,
            .ima_event_log_path = &ima_event_log_path,
            .dtls_psk_identity = &dtls_psk_identity,
        },
    };

    /* clang-format on */
    /* parse CLI arguments */
    if ((result = parse_command_line_arguments(argc, argv, &cli_config)) != 0) {
        // 1 means help message is displayed, -1 means error
        return (result == 1) ? EXIT_SUCCESS : EXIT_FAILURE;
    }

    /* set CHARRA and libcoap log levels */
    charra_log_set_level(charra_log_level);
    coap_set_log_level(coap_log_level);
    charra_log_debug("[" LOG_NAME "] Verifier Configuration:");
    charra_log_debug("[" LOG_NAME "]     Used local port: %d", port);
    charra_log_debug("[" LOG_NAME "]     DTLS-PSK enabled: %s",
            (use_dtls_psk == true) ? "true" : "false");
    if (use_dtls_psk) {
        charra_log_debug(
                "[" LOG_NAME "]         Pre-shared key: '%s'", dtls_psk_key);
        charra_log_debug("[" LOG_NAME "]         Hint: '%s'", dtls_psk_hint);
    }
    charra_log_debug("[" LOG_NAME "]     DTLS-RPK enabled: %s",
            (use_dtls_rpk == true) ? "true" : "false");
    if (use_dtls_rpk) {
        charra_log_debug("[" LOG_NAME "]         Private key path: '%s'",
                dtls_rpk_private_key_path);
        charra_log_debug("[" LOG_NAME "]         Public key path: '%s'",
                dtls_rpk_public_key_path);
        charra_log_debug("[" LOG_NAME "]         Peers' public key path: '%s'",
                dtls_rpk_peer_public_key_path);
    }

    /* set varaibles here such that they are valid in case of an 'goto error' */
    coap_context_t* coap_context = NULL;
    coap_endpoint_t* coap_endpoint = NULL;

    if (use_dtls_psk && use_dtls_rpk) {
        charra_log_error(
                "[" LOG_NAME "] Configuration enables both DTSL with PSK "
                "and DTSL with PKI. Aborting!");
        goto error;
    }

    if (use_dtls_psk || use_dtls_rpk) {
        // print TLS version when in debug mode
        coap_show_tls_version(LOG_DEBUG);
    }

    if ((use_dtls_psk || use_dtls_psk) && !coap_dtls_is_supported()) {
        charra_log_error("[" LOG_NAME "] CoAP does not support DTLS but the "
                         "configuration enables DTLS. Aborting!");
        goto error;
    }

    charra_log_info("[" LOG_NAME "] Initializing CoAP in block-wise mode.");
    if ((coap_context = charra_coap_new_context(true)) == NULL) {
        charra_log_error("[" LOG_NAME "] Cannot create CoAP context.");
        goto error;
    }

    if (use_dtls_psk) {
        charra_log_info(
                "[" LOG_NAME "] Creating CoAP server endpoint using DTLS-PSK.");
        if (!coap_context_set_psk(coap_context, dtls_psk_hint,
                    (uint8_t*)dtls_psk_key, strlen(dtls_psk_key))) {
            charra_log_error("[" LOG_NAME
                             "] Error while configuring CoAP to use DTLS-PSK.");
            goto error;
        }

        if ((coap_endpoint = charra_coap_new_endpoint(coap_context,
                     LISTEN_ADDRESS, port, COAP_PROTO_DTLS)) == NULL) {
            charra_log_error("[" LOG_NAME "] Cannot create CoAP server "
                             "endpoint based on DTLS-PSK.\n");
            goto error;
        }
    } else if (use_dtls_rpk) {
        charra_log_info(
                "[" LOG_NAME "] Creating CoAP server endpoint using DTLS-RPK.");
        coap_dtls_pki_t dtls_pki = {0};

        CHARRA_RC rc = charra_coap_setup_dtls_pki_for_rpk(&dtls_pki,
                dtls_rpk_private_key_path, dtls_rpk_public_key_path,
                dtls_rpk_peer_public_key_path, dtls_rpk_verify_peer_public_key);
        if (rc != CHARRA_RC_SUCCESS) {
            charra_log_error("[" LOG_NAME
                             "] Error while setting up DTLS-RPK structure.");
            goto error;
        }

        if (!coap_context_set_pki(coap_context, &dtls_pki)) {
            charra_log_error("[" LOG_NAME
                             "] Error while configuring CoAP to use DTLS-RPK.");
            goto error;
        }

        if ((coap_endpoint = charra_coap_new_endpoint(coap_context,
                     LISTEN_ADDRESS, port, COAP_PROTO_DTLS)) == NULL) {
            charra_log_error("[" LOG_NAME "] Cannot create CoAP server "
                             "endpoint based on DTLS-RPK.\n");
            goto error;
        }
    } else {
        charra_log_info(
                "[" LOG_NAME "] Creating CoAP server endpoint using UDP.");
        if ((coap_endpoint = charra_coap_new_endpoint(coap_context,
                     LISTEN_ADDRESS, port, COAP_PROTO_UDP)) == NULL) {
            charra_log_error(
                    "[" LOG_NAME
                    "] Cannot create CoAP server endpoint based on UDP.\n");
            goto error;
        }
    }

    /* register CoAP resource and resource handler */
    charra_log_info("[" LOG_NAME "] Registering CoAP resources.");
    charra_coap_add_resource(
            coap_context, COAP_REQUEST_FETCH, "appraise", coap_appraise_handler);
    charra_coap_add_resource(
            coap_context, COAP_REQUEST_FETCH, "nonce", coap_nonce_handler);

    /* enter main loop */
    charra_log_debug("[" LOG_NAME "] Entering main loop.");
    while (!quit) {
        /* process CoAP I/O */
        if (coap_io_process(coap_context, COAP_IO_WAIT) == -1) {
            charra_log_error(
                    "[" LOG_NAME "] Error during CoAP I/O processing.");
            goto error;
        }
    }
    result = EXIT_SUCCESS;
    goto finish;

error:
    result = EXIT_FAILURE;

finish:
    /* free CoAP memory */
    charra_free_and_null_ex(coap_endpoint, coap_free_endpoint);
    charra_free_and_null_ex(coap_context, coap_free_context);
    coap_cleanup();

    return result;
}

/* --- function definitions ----------------------------------------------- */

static void handle_sigint(int signum CHARRA_UNUSED) { quit = true; }

static void coap_appraise_handler(struct coap_resource_t* resource,
                                struct coap_session_t* session,
                                const struct coap_pdu_t* request,
                                const struct coap_string_t* query,
                                struct coap_pdu_t* response) {
    int coap_r = 0;
    TSS2_RC tss_r = 0;

    ESYS_TR sig_key_handle = ESYS_TR_NONE;
    TPMT_TK_VERIFIED* validation = NULL;
    /* Declared here (rather than right before first use, further down) and
     * initialized to NULL so that every earlier 'goto cleanup' -- including
     * the fopen() failure right below -- leaves cleanup able to safely check
     * them instead of reading indeterminate values. */
    ESYS_CONTEXT* esys_ctx = NULL;
    TSS2_TCTI_CONTEXT* tcti_ctx = NULL;

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
    msg_attestation_response_dto res = {0};
    if ((attestation_rc = charra_unmarshal_attestation_response(
                 data_len, data, &res)) != CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Could not parse CBOR data.");
        goto cleanup;
    }
    end_unmarshal = clock();
    unmarshal_duration = ((double) (end_unmarshal - start_unmarshal)) / CLOCKS_PER_SEC;
    fprintf(p_file, "unmarshal evidence took %f seconds to execute \n", unmarshal_duration);

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


    /* load TPM key */
    clock_t start_load, end_load;
    double load_duration;
    start_load = clock();
    TPM2B_PUBLIC* tpm2_public_key = (TPM2B_PUBLIC*)res.tpm2_public_key;
    charra_log_info("[" LOG_NAME "] Loading TPM key.");
    if ((attestation_rc = charra_load_external_public_key(esys_ctx,
                 tpm2_public_key, &sig_key_handle)) != CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Loading external public key failed.");
        goto cleanup;
    } else {
        charra_log_info("[" LOG_NAME "] External public key loaded.");
    }
    end_load = clock();
    load_duration = ((double) (end_load - start_load)) / CLOCKS_PER_SEC;
    fprintf(p_file, "load external public key took %f seconds to execute \n", load_duration);

    /* prepare verification */
    charra_log_info("[" LOG_NAME "] Preparing TPM Quote verification.");
    clock_t start_verifiy_signature, end_verifiy_signature;
    double verify_signature_duration;
    start_verifiy_signature = clock();
    TPM2B_ATTEST attest = {0};
    attest.size = res.attestation_data_len;
    memcpy(attest.attestationData, res.attestation_data,
            res.attestation_data_len);
    TPMT_SIGNATURE signature = {0};
    memcpy(&signature, res.tpm2_signature, res.tpm2_signature_len);

    /* --- verify attestation signature --- */
    bool attestation_result_signature = false;
    {
        charra_log_info(
                "[" LOG_NAME "] Verifying TPM Quote signature with TPM ...");
        /* verify attestation signature with TPM */
        if ((attestation_rc = charra_verify_tpm2_quote_signature_with_tpm(
                     esys_ctx, sig_key_handle, TPM2_ALG_SHA256, &attest,
                     &signature, &validation)) == CHARRA_RC_SUCCESS) {
            charra_log_info(
                    "[" LOG_NAME "]     => TPM Quote signature is valid!");
            attestation_result_signature = true;
        } else {
            charra_log_error(
                    "[" LOG_NAME "]     => TPM Quote signature is NOT valid!");
        }
    }
    end_verifiy_signature = clock();
    verify_signature_duration = ((double) (end_verifiy_signature - start_verifiy_signature)) / CLOCKS_PER_SEC;
    fprintf(p_file, "verify signature took %f seconds to execute \n", verify_signature_duration);
    {
        /* convert TPM public key to mbedTLS public key */
        charra_log_info(
                "[" LOG_NAME
                "] Converting TPM public key to mbedTLS public key ...");
        mbedtls_rsa_context mbedtls_rsa_pub_key = {0};
        if ((attestation_rc = charra_crypto_tpm_pub_key_to_mbedtls_pub_key(
                     tpm2_public_key, &mbedtls_rsa_pub_key)) !=
                CHARRA_RC_SUCCESS) {
            charra_log_error("[" LOG_NAME "] mbedTLS RSA error");
            goto cleanup;
        }

        /* verify attestation signature with mbedTLS */
        charra_log_info("[" LOG_NAME
                        "] Verifying TPM Quote signature with mbedTLS ...");
        if ((attestation_rc = charra_crypto_rsa_verify_signature(
                     &mbedtls_rsa_pub_key, MBEDTLS_MD_SHA256,
                     res.attestation_data, (size_t)res.attestation_data_len,
                     signature.signature.rsapss.sig.buffer)) ==
                CHARRA_RC_SUCCESS) {
            charra_log_info(
                    "[" LOG_NAME "]     => TPM Quote signature is valid!");
        } else {
            charra_log_error(
                    "[" LOG_NAME "]     => TPM Quote signature is NOT valid!");
        }
        mbedtls_rsa_free(&mbedtls_rsa_pub_key);
    }

    /* unmarshal attestation data */
    TPMS_ATTEST attest_struct = {0};
    attestation_rc = charra_unmarshal_tpm2_quote(
            res.attestation_data_len, res.attestation_data, &attest_struct);
    if (attestation_rc != CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Error while unmarshaling TPM2 Quote.");
        goto cleanup;
    }

    /* --- verify nonce --- */
    clock_t start_verifiy_nonce, end_verifiy_nonce;
    double verify_nonce_duration;
    start_verifiy_nonce = clock();
    bool attestation_result_nonce = false;
    {
        charra_log_info("[" LOG_NAME "] Verifying nonce ...");
        // TODO: last_request is initialised but never filled with the actual nonce
        // the relying party needs to send the nonce either inside the appraise request or before separately
        attestation_result_nonce = charra_verify_tpm2_quote_qualifying_data(
                last_request.nonce_len, last_request.nonce, &attest_struct);
        if (attestation_result_nonce == true) {
            charra_log_info("[" LOG_NAME "]     => Nonce in TPM Quote is "
                            "valid! (matches the one sent)");
        } else {
            charra_log_error("[" LOG_NAME
                             "]     => Nonce in TPM Quote is NOT valid! (does "
                             "not match the one sent)");
        }
    }
    end_verifiy_nonce = clock();
    verify_nonce_duration = ((double) (end_verifiy_nonce - start_verifiy_nonce)) / CLOCKS_PER_SEC;
    fprintf(p_file, "verify nonce took %f seconds to execute \n", verify_nonce_duration);

    /* --- verify PCRs --- */
    clock_t start_verifiy_pcr, end_verifiy_pcr;
    double verify_pcr_duration;
    start_verifiy_pcr = clock();
    bool attestation_result_pcrs = false;
    {
        charra_log_info("[" LOG_NAME "] Verifying PCRs ...");

        charra_log_info("[" LOG_NAME
                        "] Actual PCR composite digest from TPM Quote is:");
        charra_print_hex(CHARRA_LOG_INFO,
                attest_struct.attested.quote.pcrDigest.size,
                attest_struct.attested.quote.pcrDigest.buffer,                         
                "                        0x", "\n",
                false);

        CHARRA_RC pcr_check = charra_check_pcr_digest_against_reference(
                reference_pcr_file_path, tpm_pcr_selection,
                tpm_pcr_selection_len, &attest_struct);
        if (pcr_check == CHARRA_RC_SUCCESS) {
            charra_log_info(
                    "[" LOG_NAME "]     => PCR composite digest is valid!");
            attestation_result_pcrs = true;
        } else {
            charra_log_error(
                    "[" LOG_NAME
                    "]     => PCR composite digest is NOT valid! (does "
                    "not match any of the digests from the set of reference "
                    "PCRs)");
        }
    }
    end_verifiy_pcr = clock();
    verify_pcr_duration = ((double) (end_verifiy_pcr - start_verifiy_pcr)) / CLOCKS_PER_SEC;
    fprintf(p_file, "verify pcr took %f seconds to execute \n", verify_pcr_duration);
    /* verify event log */
    // TODO(any): Implement real verification.
    bool attestation_event_log = true;
    if (use_ima_event_log) {
        charra_log_info("[" LOG_NAME "] Verifying event log ...");
        if (res.event_log_len == 0) {
            charra_log_error("[" LOG_NAME "] Received no event log altough IMA "
                             "event log verification is on.");
            attestation_event_log = false;
        } else {
            charra_log_info(
                    "[" LOG_NAME "]     <<< This is to be implemented. >>>");
            charra_log_info("[" LOG_NAME
                            "]     IMA Event Log size is %d bytes.",
                    res.event_log_len);
            charra_log_debug("[" LOG_NAME "]     IMA Event Log:");

            if (res.event_log_len > 20) {
                charra_print_hex(CHARRA_LOG_DEBUG, 10, res.event_log,
                        "                                                  0x",
                        "...", false);
                charra_print_hex(CHARRA_LOG_DEBUG, 10,
                        (res.event_log + res.event_log_len - 10), "", "\n",
                        false);
            } else if ((res.event_log_len > 0)) {
                charra_print_hex(CHARRA_LOG_DEBUG, res.event_log_len,
                        res.event_log,
                        "                                                  0x",
                        "\n", false);
            } else {
                charra_log_debug("[" LOG_NAME "]     <none>");
            }
        }
    }

    /* --- output result --- */

    bool attestation_result = attestation_result_signature &&
                              attestation_result_nonce &&
                              attestation_result_pcrs && attestation_event_log;


    const char* message;
    /* print attestation result */
    charra_log_info("[" LOG_NAME "] +----------------------------+");
    if (attestation_result) {
        attestation_rc = CHARRA_RC_SUCCESS;
        message = "Attestation successful!\0";
        charra_log_info("[" LOG_NAME "] |   ATTESTATION SUCCESSFUL   |");
    } else {
        attestation_rc = CHARRA_RC_VERIFICATION_FAILED;
        message = "Attestation failed!    \0";
        charra_log_info("[" LOG_NAME "] |     ATTESTATION FAILED     |");
    }
    charra_log_info("[" LOG_NAME "] +----------------------------+");

    coap_pdu_set_code(response, COAP_RESPONSE_CODE_CONTENT);
    
    end_appraise = clock();
    appraise_duration = ((double) (end_appraise - start_appraise)) / CLOCKS_PER_SEC;


    fprintf(p_file, "appraising took %f seconds to execute \n", appraise_duration);
    double total_measured = unmarshal_duration + init_duration + load_duration + verify_nonce_duration + verify_signature_duration + verify_pcr_duration;
    fprintf(p_file, "total measured %f  \n", total_measured);
    fclose(p_file);

    if ((coap_r = coap_add_data_large_response(resource, session, request, response,
                query, COAP_MEDIATYPE_TEXT_PLAIN, -1, 0,
                strlen(message), (const uint8_t *)message, NULL, (void *)strlen(message))) == 0) {
        charra_log_error("[" LOG_NAME
                         "] Error invoking coap_add_data_large_response().");
        //goto error;
    }
cleanup:
    /* flush handles */
    if (sig_key_handle != ESYS_TR_NONE) {
        if (Esys_FlushContext(esys_ctx, sig_key_handle) != TSS2_RC_SUCCESS) {
            charra_log_error(
                    "[" LOG_NAME "] TSS cleanup sig_key_handle failed.");
        }
    }

    /* free event log */
    // TODO(any): Provide function charra_free_msg_attestation_response_dto().
    charra_free_if_not_null(res.event_log);

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

}

static void coap_nonce_handler(struct coap_resource_t* resource CHARRA_UNUSED,
                                struct coap_session_t* session CHARRA_UNUSED,
                                const struct coap_pdu_t* request,
                                const struct coap_string_t* query CHARRA_UNUSED,
                                struct coap_pdu_t* response CHARRA_UNUSED) {
    CHARRA_RC charra_r = CHARRA_RC_SUCCESS;
    int coap_r = 0;

    /* --- receive incoming data --- */
    coap_show_pdu(LOG_DEBUG, request);

    /* get data */
    size_t data_len = 0;
    const uint8_t* data = NULL;
    size_t data_offset = 0;
    size_t data_total_len = 0;
    if ((coap_r = coap_get_data_large(
                 request, &data_len, &data, &data_offset, &data_total_len)) == 0) {
        charra_log_error("[" LOG_NAME "] Could not get CoAP PDU data.");
        goto error;
    } else {
        charra_log_info(
                "[" LOG_NAME "] Received nonce of length %zu.", data_len);
        charra_log_info("[" LOG_NAME "] Received nonce of total length %zu.",
                data_total_len);
    }

    /* unmarshal data */
    charra_log_info("[" LOG_NAME "] Parsing received CBOR data.");
    msg_attestation_request_dto req = {0};
    if ((charra_r = charra_unmarshal_attestation_request(
                 data_len, data, &req)) != CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Could not parse CBOR data.");
        goto error;
    }

    /* nonce */
    if (req.nonce_len > sizeof(TPMU_HA)) {
        charra_log_error("[" LOG_NAME "] Nonce too long.");
        goto error;
    }
    TPM2B_DATA qualifying_data = {.size = 0, .buffer = {0}};
    qualifying_data.size = req.nonce_len;
    memcpy(qualifying_data.buffer, req.nonce, req.nonce_len);
    last_request = req;

error:
    return;
}
