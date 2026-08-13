#include <arpa/inet.h>
#include <coap3/coap.h>
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tss2/tss2_tctildr.h>
#include <tss2/tss2_tpm2_types.h>
#include <unistd.h>
#include <pthread.h>
#include <math.h>

#include "common/charra_log.h"
#include "common/charra_macro.h"
#include "core/charra_dto.h"
#include "core/charra_event_log.h"
#include "core/charra_key_mgr.h"
#include "core/charra_marshaling.h"
#include "core/charra_rim_mgr.h"
#include "util/charra_util.h"
#include "util/cli_util.h"
#include "util/coap_util.h"
#include "util/crypto_util.h"
#include "util/io_util.h"
#include "util/tpm2_util.h"

/* measurement config */
#define NUM_RUNS 1

/* logging and coap config */ 
#define CHARRA_UNUSED __attribute__((unused))
#define LOG_NAME "relying party"
// #define LOG_LEVEL_CBOR LOG_DEBUG
#define COAP_IO_PROCESS_TIME_MS 2000  // CoAP IO process time in milliseconds
coap_log_t coap_log_level = LOG_INFO;
charra_log_t charra_log_level = CHARRA_LOG_INFO;
CHARRA_RC charra_r = CHARRA_RC_SUCCESS;
static bool quit = false;

/* trust manager config */ 
char trust_manager_host[16] = "127.0.0.1"; 
unsigned int trust_manager_port = 6000;
uint16_t trust_manager_response_timeout = 30;  
static bool processing_trust_manager_response = false;

/* verifiers config */ 
#define MAX_VERIFIERS 10
int verifier_list[5];
// size_t num_verifiers = sizeof(verifier_list) / sizeof(verifier_list[0]);
bool attestation_results[MAX_VERIFIERS];
typedef struct verifier_info {
    char ip_address[16];
    unsigned int port_number;
} verifier_info;
verifier_info verifiers[MAX_VERIFIERS];
uint16_t verifier_response_timeout = 6000;  // timeout when waiting for verifier's answer (attestation results) in seconds
static bool processing_appraisal_response = false;

/* attester config */ 
#define PERIODIC_ATTESTATION_WAIT_TIME_S 2  // Wait time between attestations in seconds (not implemented)
#define TPM_SIG_KEY_ID_LEN 14
#define TPM_SIG_KEY_ID "PK.RSA.default"
static bool processing_attestation_response = false;
static CHARRA_RC attestation_rc = CHARRA_RC_ERROR;
static const bool USE_TPM_FOR_RANDOM_NONCE_GENERATION = false;
static uint8_t tpm_pcr_selection[TPM2_MAX_PCRS] = {0, 1, 2, 3, 4, 5, 6, 7, 10};
static uint32_t tpm_pcr_selection_len = 9;
uint16_t attester_response_timeout = 6000;  // timeout when waiting for the attester's answer (evidence) in seconds
bool use_ima_event_log = false;
char* ima_event_log_path = "/sys/kernel/security/ima/binary_runtime_measurements";
bool use_ima_test_log = true;
char* ima_test_log_path = "ima_test_logs.txt";  // path to the IMA test log file for testing purposes

/* RP appraisal config */
char* blacklist_hashes_path = "blacklist-hashes.txt";
char attester_host[16] = "127.0.0.1";      // 15 characters for IPv4 plus \0
unsigned int attester_port = 5683;         // default port

/* DTLS-PSK config */ 
bool use_dtls_psk = false;
char* dtls_psk_key = "Charra DTLS Key";
char* dtls_psk_identity = "Charra Relying Party";

/* DTLS-RPK config */ 
bool use_dtls_rpk = false;
char* dtls_rpk_private_key_path = "keys/relying_party.der";
char* dtls_rpk_public_key_path = "keys/relying_party.pub.der";
bool dtls_rpk_verify_peer_public_key = true;
char* dtls_rpk_attester_public_key_path = "keys/attester.pub.der";
char* dtls_rpk_verifier_public_key_path = "keys/verifier.pub.der";

/* --- function forward declarations -------------------------------------- */

/**
 * @brief SIGINT handler: set quit to 1 for graceful termination.
 *
 * @param signum the signal number.
 */
static void handle_sigint(int signum);

static CHARRA_RC create_attestation_request(
        msg_attestation_request_dto* attestation_request);

static coap_response_t coap_attester_handler(
        coap_session_t* session CHARRA_UNUSED,
        const coap_pdu_t* sent CHARRA_UNUSED,
        const coap_pdu_t* received,
        const coap_mid_t mid CHARRA_UNUSED);

static coap_response_t coap_verifier_handler_appraisal(coap_session_t* session CHARRA_UNUSED,
        const coap_pdu_t* sent CHARRA_UNUSED,
        const coap_pdu_t* received,
        const coap_mid_t mid CHARRA_UNUSED);

static coap_response_t coap_trust_manager_handler(coap_session_t* session,
                                        const coap_pdu_t* sent,
                                        const coap_pdu_t* received,
                                        const coap_mid_t mid);

/**
 * @brief Appraise the Attester's evidence locally, before any of it is
 * forwarded to the Verifiers.
 *
 * Runs, in order: the quote signature under the Attester's public key, the
 * nonce the RP itself generated, each log entry's internal consistency, the
 * PCR composite digest rebuilt from a replay of the log, and a file-hash
 * blacklist pass. Every check runs even after one fails, so a single run
 * reports everything that is wrong rather than only the first thing.
 *
 * @return true if every check passed.
 */
static bool charra_rp_appraise_evidence(const msg_attestation_response_dto* res);

CHARRA_RC get_verifiers(int* verifier_list, int num_verifiers);

CHARRA_RC get_evidence();

CHARRA_RC get_attestation_results(int num_verifiers);

void* get_attestation_results_thread();

/* --- static variables --------------------------------------------------- */

static msg_attestation_request_dto last_request = {0};
static msg_attestation_response_dto last_response = {0};

/* --- main --------------------------------------------------------------- */

void calculate_stats(double* durations, int num_runs, double* avg, double* stddev) {
    double sum = 0.0;
    for (int i = 0; i < num_runs; i++) {
        sum += durations[i];
    }
    *avg = sum / num_runs;

    double variance_sum = 0.0;
    for (int i = 0; i < num_runs; i++) {
        variance_sum += (durations[i] - *avg) * (durations[i] - *avg);
    }
    *stddev = sqrt(variance_sum / num_runs);
}

int main(int argc CHARRA_UNUSED, char** argv CHARRA_UNUSED) {
    CHARRA_RC result = EXIT_FAILURE;
    FILE *timing_file = fopen("timings_RP_multi_verifiers.txt", "w");
    if (timing_file == NULL) {
        perror("fopen");
        return EXIT_FAILURE;
    }

    signal(SIGINT, handle_sigint);

    /* apply log level from environment (the other binaries do this in their
     * own main(); without it the log module keeps its zero-initialized
     * default of CHARRA_LOG_TRACE and LOG_LEVEL_CHARRA is ignored) */
    charra_log_level_from_str(
            (const char*)getenv("LOG_LEVEL_CHARRA"), &charra_log_level);
    charra_log_set_level(charra_log_level);

    double verifier_durations[NUM_RUNS];
    double evidence_durations[NUM_RUNS];
    double appraisal_durations[NUM_RUNS];
    double total_attestation_durations[NUM_RUNS];

    for (int num_verifiers = 1; num_verifiers <= 5; num_verifiers++) {
        for (int i = 0; i < num_verifiers; i++) {
            verifier_list[i] = i + 1;
        }

        for (int run = 0; run < NUM_RUNS; run++) {
            struct timespec start_time, end_time;
            double duration;

            /* check environment variables */
            charra_log_info("[" LOG_NAME "] Checking environment variables.");
            // Your environment setup code here

            /* Getting verifiers */
            charra_log_info("[" LOG_NAME "] Getting verifiers.");
            clock_gettime(CLOCK_MONOTONIC, &start_time);
            if ((result = get_verifiers(verifier_list, num_verifiers)) != CHARRA_RC_SUCCESS) {
                charra_log_error("[" LOG_NAME "] Error getting verifiers.");
                goto error;
            }
            clock_gettime(CLOCK_MONOTONIC, &end_time);
            duration = (end_time.tv_sec - start_time.tv_sec) + (end_time.tv_nsec - start_time.tv_nsec) / 1e9;
            verifier_durations[run] = duration;

            /* Getting evidence */
            charra_log_info("[" LOG_NAME "] Getting evidence.");
            clock_gettime(CLOCK_MONOTONIC, &start_time);
            if ((result = get_evidence()) != CHARRA_RC_SUCCESS) {
                charra_log_error("[" LOG_NAME "] Error getting evidence.");
                goto error;
            }
            clock_gettime(CLOCK_MONOTONIC, &end_time);
            duration = (end_time.tv_sec - start_time.tv_sec) + (end_time.tv_nsec - start_time.tv_nsec) / 1e9;
            evidence_durations[run] = duration;

            /* Getting attestation results */
            charra_log_info("[" LOG_NAME "] Getting attestation results.");
            clock_gettime(CLOCK_MONOTONIC, &start_time);
            if ((result = get_attestation_results(num_verifiers)) != CHARRA_RC_SUCCESS) {
                charra_log_error("[" LOG_NAME "] Error getting attestation results.");
                goto error;
            }
            clock_gettime(CLOCK_MONOTONIC, &end_time);
            duration = (end_time.tv_sec - start_time.tv_sec) + (end_time.tv_nsec - start_time.tv_nsec) / 1e9;
            appraisal_durations[run] = duration;

            total_attestation_durations[run] = verifier_durations[run] + evidence_durations[run] + appraisal_durations[run];
            result = CHARRA_RC_SUCCESS;
            continue;

        error:
            result = EXIT_FAILURE;
            break;
        }

        if (result == EXIT_FAILURE) {
            break;
        }

        double avg_verifier_duration, stddev_verifier_duration;
        double avg_evidence_duration, stddev_evidence_duration;
        double avg_appraisal_duration, stddev_appraisal_duration;
        double avg_total_attestation_duration, stddev_total_attestation_duration;

        calculate_stats(verifier_durations, NUM_RUNS, &avg_verifier_duration, &stddev_verifier_duration);
        calculate_stats(evidence_durations, NUM_RUNS, &avg_evidence_duration, &stddev_evidence_duration);
        calculate_stats(appraisal_durations, NUM_RUNS, &avg_appraisal_duration, &stddev_appraisal_duration);
        calculate_stats(total_attestation_durations, NUM_RUNS, &avg_total_attestation_duration, &stddev_total_attestation_duration);

        fprintf(timing_file, "Verifiers: %d\n", num_verifiers);
        fprintf(timing_file, "Average Getting verifiers: %f seconds (stddev: %f)\n", avg_verifier_duration, stddev_verifier_duration);
        fprintf(timing_file, "Average Getting evidence: %f seconds (stddev: %f)\n", avg_evidence_duration, stddev_evidence_duration);
        fprintf(timing_file, "Average Appraising evidence: %f seconds (stddev: %f)\n", avg_appraisal_duration, stddev_appraisal_duration);
        fprintf(timing_file, "Average Total Attestation Duration: %f seconds (stddev: %f)\n", avg_total_attestation_duration, stddev_total_attestation_duration);
    }

    fclose(timing_file);
    return result;
}
/* --- function definitions ----------------------------------------------- */

static void handle_sigint(int signum CHARRA_UNUSED) { quit = true; }

static CHARRA_RC create_attestation_request(msg_attestation_request_dto* attestation_request) {
    CHARRA_RC err = CHARRA_RC_ERROR;
    
    /* generate nonce */
    const uint32_t nonce_len = 20;
    uint8_t nonce[nonce_len];
    if (USE_TPM_FOR_RANDOM_NONCE_GENERATION) {
        if ((err = charra_random_bytes_from_tpm(nonce_len, nonce) !=
                    CHARRA_RC_SUCCESS)) {
            charra_log_error("Could not get random bytes from TPM for nonce.");
            return err;
        }
    } else {
        if ((err = charra_random_bytes(nonce_len, nonce) !=
                    CHARRA_RC_SUCCESS)) {
            charra_log_error("Could not get random bytes for nonce.");
            return err;
        }
    }

    charra_log_info("[" LOG_NAME "] Generated nonce of length %d:", nonce_len);
    charra_print_hex(CHARRA_LOG_INFO, nonce_len, nonce,
            "                                                  0x", "\n",
            false);

    /* build attestation request */
    msg_attestation_request_dto req = {
            .hello = false,
            .sig_key_id_len = TPM_SIG_KEY_ID_LEN,
            .sig_key_id = {0},  // must be memcpy'd, see below
            .nonce_len = nonce_len,
            .nonce = {0},  // must be memcpy'd, see below
            .pcr_selections_len = 1,
            .pcr_selections = {{
                    .tcg_hash_alg_id = TPM2_ALG_SHA256,
                    .pcrs_len = tpm_pcr_selection_len,
                    .pcrs = {0}  // must be memcpy'd, see below
            }},
            .event_log_path_len =
                    (use_ima_event_log || use_ima_test_log) ? ((use_ima_event_log) ? strlen(ima_event_log_path) : strlen(ima_test_log_path)) : 0,
            .event_log_path =
                    (use_ima_event_log || use_ima_test_log) ? ((use_ima_event_log) ? (uint8_t*)ima_event_log_path : (uint8_t*)ima_test_log_path) : NULL,
    };
    memcpy(req.sig_key_id, TPM_SIG_KEY_ID, TPM_SIG_KEY_ID_LEN);
    memcpy(req.nonce, nonce, nonce_len);
    memcpy(req.pcr_selections->pcrs, tpm_pcr_selection, tpm_pcr_selection_len);

    /* set output param(s) */
    *attestation_request = req;

    /* return result */
    return CHARRA_RC_SUCCESS;
}

static coap_response_t coap_attester_handler(
        coap_session_t* session CHARRA_UNUSED,
        const coap_pdu_t* sent CHARRA_UNUSED,
        const coap_pdu_t* received,
        const coap_mid_t mid CHARRA_UNUSED) {
    int coap_r = 0;

    processing_attestation_response = true;

    coap_show_pdu(LOG_DEBUG, received);

    /* --- receive incoming data --- */

    /* get data */
    size_t data_len = 0;
    const uint8_t* data = NULL;
    size_t data_offset = 0;
    size_t data_total_len = 0;
    if ((coap_r = coap_get_data_large(
                 received, &data_len, &data, &data_offset, &data_total_len)) == 0) {
        charra_log_error("[" LOG_NAME "] Could not get CoAP PDU data.");
        attestation_rc = CHARRA_RC_ERROR;
        goto cleanup;
    } else {
        // charra_log_info(
        //         "[" LOG_NAME "] Received data of length %zu.", data_len);
        charra_log_info("[" LOG_NAME "] Received evidence of total length %zu.",
                data_total_len);
    }

    /* unmarshal data */
    // charra_log_info("[" LOG_NAME "] Parsing received CBOR data.\n");
    msg_attestation_response_dto res = {0};
    if ((attestation_rc = charra_unmarshal_attestation_response(
                 data_len, data, &res)) != CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Could not parse CBOR data.");
        goto cleanup;
    }
    /* appraise the evidence locally before forwarding any of it */
    if (!charra_rp_appraise_evidence(&res)) {
        attestation_rc = CHARRA_RC_VERIFICATION_FAILED;
        goto cleanup;
    }

    charra_log_info("[" LOG_NAME "] Forwarding evidence to the verifiers.");
    /* store last response */
    last_response = res;

cleanup:

    processing_attestation_response = false;
    return COAP_RESPONSE_OK;
}

static bool charra_rp_appraise_evidence(
        const msg_attestation_response_dto* res) {
    charra_log_info("[" LOG_NAME
            "]  +------------ RP Appraisal of the Evidence --------------+");

    bool signature_ok = false;
    bool nonce_ok = false;
    bool entries_ok = false;
    bool pcr_ok = false;
    bool blacklist_ok = false;

    /* --- 1. quote signature, under the Attester's own public key --------- */
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

    /* --- 2. nonce: the quote must answer the challenge we just sent ------ */
    charra_log_info("[" LOG_NAME "] Verifying nonce ...");
    nonce_ok = charra_verify_tpm2_quote_qualifying_data(
            (uint16_t)last_request.nonce_len, last_request.nonce,
            &attest_struct);
    charra_log_info("[" LOG_NAME "]     => nonce in the quote %s",
            nonce_ok ? "matches the one sent!"
                     : "does NOT match the one sent!");

    /* --- 3. every entry's template_digest == hash(template_data) -------- */
    charra_log_info("[" LOG_NAME "] Verifying log entry self-consistency ...");
    entries_ok = charra_verify_log_entries_self_consistent(
            res->event_log, res->event_log_len);
    charra_log_info("[" LOG_NAME "]     => log entries are %s",
            entries_ok ? "self-consistent!" : "NOT self-consistent!");

    /* --- 4. replay the log and rebuild the PCR composite digest ---------- */
    charra_log_info("[" LOG_NAME "] Replaying the log into the PCRs ...");
    pcr_ok = charra_verify_log_matches_quote_pcr_digest(res->event_log,
            res->event_log_len, tpm_pcr_selection, tpm_pcr_selection_len,
            &attest_struct);
    charra_log_info("[" LOG_NAME "]     => PCR composite digest %s",
            pcr_ok ? "matches the quote!" : "does NOT match the quote!");

    /* --- 5. no measured file may appear on the blacklist ----------------- */
    charra_log_info("[" LOG_NAME "] Checking file hashes against the "
                    "blacklist ...");
    blacklist_ok = charra_verify_log_file_hashes_not_blacklisted(
            res->event_log, res->event_log_len, blacklist_hashes_path);
    charra_log_info("[" LOG_NAME "]     => file hashes are %s",
            blacklist_ok ? "not blacklisted!" : "BLACKLISTED!");

done:;
    const bool appraisal_ok = signature_ok && nonce_ok && entries_ok &&
                              pcr_ok && blacklist_ok;
    charra_log_info("[" LOG_NAME "] +----------------------------+");
    if (appraisal_ok) {
        charra_log_info("[" LOG_NAME "] |  RP Appraisal Successful   |");
    } else {
        charra_log_error("[" LOG_NAME "] |    RP Appraisal Failed     |");
    }
    charra_log_info("[" LOG_NAME "] +----------------------------+");
    return appraisal_ok;
}

static coap_response_t coap_verifier_handler_appraisal(coap_session_t* session,
        const coap_pdu_t* sent CHARRA_UNUSED,
        const coap_pdu_t* received,
        const coap_mid_t mid CHARRA_UNUSED) {
            
    processing_appraisal_response = true;
    int* current_thread_index = coap_session_get_app_data(session);

    int coap_r = 0;
    size_t data_len = 0;
    const uint8_t* data = NULL;
    size_t data_offset = 0;
    size_t data_total_len = 0;
    if ((coap_r = coap_get_data_large(
                 received, &data_len, &data, &data_offset, &data_total_len)) == 0) {
        charra_log_error("[" LOG_NAME "] Could not get CoAP PDU data.");
        attestation_rc = CHARRA_RC_ERROR;
        goto cleanup;
    }

    const char* successful_message = "Attestation successful!\0";

    if (strcmp((const char*)data, successful_message)) {
        attestation_results[*current_thread_index] = true;
    } else {
        charra_log_info("[" LOG_NAME "] False\n");
        attestation_results[*current_thread_index] = false;
    }

cleanup:
    processing_appraisal_response = false;
    return COAP_RESPONSE_OK;
}

static coap_response_t coap_trust_manager_handler(coap_session_t* session,
                                        const coap_pdu_t* sent CHARRA_UNUSED,
                                        const coap_pdu_t* received,
                                        const coap_mid_t mid CHARRA_UNUSED) {
    
    processing_trust_manager_response = true;
    int coap_r = 0;
    int num_verifiers = *(int *)coap_session_get_app_data(session); 
    /* get data */
    size_t data_len = 0;
    const uint8_t* data = NULL;
    size_t data_offset = 0;
    size_t data_total_len = 0;
    if ((coap_r = coap_get_data_large(
                 received, &data_len, &data, &data_offset, &data_total_len)) == 0) {
        charra_log_error("[" LOG_NAME "] Could not get CoAP PDU data.");
        goto cleanup;
    } else {
        charra_log_info(
                "[" LOG_NAME "] Received data of length %zu.", data_len);
        charra_log_info("[" LOG_NAME "] Received data of total length %zu.",
                data_total_len);
    }

    /* Parse the received data */
    const uint8_t* ptr = data;
    for (int i = 0; i < num_verifiers; i++) {
        strncpy(verifiers[i].ip_address, (const char*)ptr, 15);
        verifiers[i].ip_address[15] = '\0';  // Ensure null-terminated string
        ptr += 16;
        memcpy(&verifiers[i].port_number, ptr, sizeof(unsigned int));
        ptr += sizeof(unsigned int);
    }

    /* Print the received verifier information */
    for (int i = 0; i < num_verifiers; i++) {
            charra_log_info(
            "[" LOG_NAME
            "] Verifier ID %d: IP Address = %s, Port Number = %u", verifier_list[i], verifiers[i].ip_address, verifiers[i].port_number);
    }

cleanup:
    processing_trust_manager_response = false;
    return COAP_RESPONSE_OK;
}

CHARRA_RC get_verifiers(int* verifier_list, int num_verifiers) {

    charra_log_info("[" LOG_NAME "]  +------------ Interaction with the Trust Manager --------------+");

    CHARRA_RC result = EXIT_FAILURE;

    coap_context_t* coap_context = NULL;
    coap_session_t* coap_session = NULL;
    coap_optlist_t* coap_options = NULL;

    charra_log_info("[" LOG_NAME "] Initializing CoAP in block-wise mode.");
    if ((coap_context = charra_coap_new_context(true)) == NULL) {
        charra_log_error("[" LOG_NAME "] Cannot create CoAP context.");
        result = CHARRA_RC_COAP_ERROR;
        goto cleanup;
    }

    charra_log_info(
            "[" LOG_NAME "] Creating CoAP client session using UDP.");
    if ((coap_session = charra_coap_new_client_session(coap_context,
                    trust_manager_host, trust_manager_port, COAP_PROTO_UDP)) == NULL) {
        charra_log_error("[" LOG_NAME
                            "] Cannot create client session based on UDP.");
        result = CHARRA_RC_COAP_ERROR;
        goto cleanup;
    }

    charra_log_info("[" LOG_NAME "] Registering CoAP response handler.");
    coap_register_response_handler(coap_context, coap_trust_manager_handler);
    
    coap_session_set_app_data(coap_session, (void *)&num_verifiers);

    /* create CoAP option for content type */
    uint8_t coap_mediatype_cbor_buf_n[4] = {0};
    unsigned int coap_mediatype_cbor_buf_len_n = 0;
    if ((coap_mediatype_cbor_buf_len_n = coap_encode_var_safe(
                 coap_mediatype_cbor_buf_n, sizeof(coap_mediatype_cbor_buf_n),
                 COAP_MEDIATYPE_APPLICATION_CBOR)) == 0) {
        charra_log_error(
                "[" LOG_NAME "] Cannot create option for CONTENT_TYPE.");
        result = CHARRA_RC_COAP_ERROR;
        goto cleanup;
    }

    charra_log_info("[" LOG_NAME "] Adding CoAP option URI_PATH.");
    if (coap_insert_optlist(
                &coap_options, coap_new_optlist(COAP_OPTION_URI_PATH, 13,
                                       (const uint8_t*)"get_verifiers")) != 1) {
        charra_log_error("[" LOG_NAME "] Cannot add CoAP option URI_PATH.");
        result = CHARRA_RC_COAP_ERROR;
        goto cleanup;
    }

    charra_log_info("[" LOG_NAME "] Adding CoAP option CONTENT_TYPE.");
    if (coap_insert_optlist(&coap_options,
                coap_new_optlist(COAP_OPTION_CONTENT_TYPE,
                                       coap_mediatype_cbor_buf_len_n,
                                       coap_mediatype_cbor_buf_n)) != 1) {
        charra_log_error("[" LOG_NAME "] Cannot add CoAP option CONTENT_TYPE.");
        result = CHARRA_RC_COAP_ERROR;
        goto cleanup;
    }    

    /* new CoAP request PDU */
    coap_pdu_t* pdu = NULL;
    charra_log_info("[" LOG_NAME "] Creating request PDU.");
    if ((pdu = charra_coap_new_request(coap_session, COAP_MESSAGE_TYPE_CON,
                 COAP_REQUEST_FETCH, &coap_options, (const uint8_t *)verifier_list, num_verifiers * sizeof(verifier_list[0]))) ==
            NULL) {
        charra_log_error("[" LOG_NAME "] Cannot create request PDU.");
        result = CHARRA_RC_ERROR;
        goto cleanup;
    }

    /* set timeout length */
    coap_fixed_point_t coap_timeout = {trust_manager_response_timeout, 0};
    coap_session_set_ack_timeout(coap_session, coap_timeout);

    /* send CoAP PDU */
    coap_mid_t mid = COAP_INVALID_MID;
    charra_log_info("[" LOG_NAME "] Sending CoAP message.");
    if ((mid = coap_send_large(coap_session, pdu)) == COAP_INVALID_MID) {
        charra_log_error("[" LOG_NAME "] Cannot send CoAP message.");
        result = CHARRA_RC_COAP_ERROR;
        goto cleanup;
    }

    int coap_io_process_time = -1;
    /* processing and waiting for response */
    charra_log_info("[" LOG_NAME "] Processing and waiting for response ...");
    uint16_t response_wait_time = 0;
    while (!processing_trust_manager_response && coap_io_pending(coap_context)) {
        /* process CoAP I/O */
        if ((coap_io_process_time = coap_io_process(
                     coap_context, COAP_IO_PROCESS_TIME_MS)) == -1) {
            charra_log_error(
                    "[" LOG_NAME "] Error during CoAP I/O processing.");
            result = CHARRA_RC_COAP_ERROR;
            goto cleanup;
        }
        /* This wait time is not 100% accurate, it only includes the elapsed
         * time inside the coap_io_process function. But should be good enough.
         */
        response_wait_time += coap_io_process_time;
        if (response_wait_time >= (trust_manager_response_timeout * 1000)) {
            charra_log_error("[" LOG_NAME
                             "] Timeout after %d ms while waiting for or "
                             "processing attestation response.",
                    response_wait_time);
            result = CHARRA_RC_TIMEOUT;
            goto cleanup;
        }
    }

    result = CHARRA_RC_SUCCESS;

cleanup:
    /* free CoAP memory */
    charra_free_if_not_null_ex(coap_options, coap_delete_optlist);
    charra_free_if_not_null_ex(coap_session, coap_session_release);
    charra_free_if_not_null_ex(coap_context, coap_free_context);

    coap_cleanup();

    return result;

}

CHARRA_RC get_evidence() {

    charra_log_info("[" LOG_NAME "]  +------------ Interaction with the Attester --------------+");

    CHARRA_RC result = EXIT_FAILURE;

    coap_context_t* coap_context = NULL;
    coap_session_t* coap_session = NULL;
    coap_optlist_t* coap_options = NULL;
    uint8_t* req_buf = NULL;  // TODO(any): make dynamic

    if (use_dtls_psk && use_dtls_rpk) {
        charra_log_error(
                "[" LOG_NAME "] Configuration enables both DTSL with PSK "
                "and DTSL with PKI. Aborting!");
        goto cleanup;
    }

    if (use_dtls_psk || use_dtls_rpk) {
        // print TLS version when in debug mode
        coap_show_tls_version(LOG_DEBUG);
    }

    if (use_dtls_psk && !coap_dtls_is_supported()) {
        charra_log_error("[" LOG_NAME "] CoAP does not support DTLS but the "
                         "configuration enables DTLS. Aborting!");
        goto cleanup;
    }

    /* create CoAP context */
    charra_log_info("[" LOG_NAME "] Initializing CoAP in block-wise mode.");
    if ((coap_context = charra_coap_new_context(true)) == NULL) {
        charra_log_error("[" LOG_NAME "] Cannot create CoAP context.");
        result = CHARRA_RC_COAP_ERROR;
        goto cleanup;
    }

    /* register CoAP response handler */
    charra_log_info("[" LOG_NAME "] Registering CoAP response handler.");
    coap_register_response_handler(
            coap_context, coap_attester_handler);

    if (use_dtls_psk) {
        charra_log_info("[" LOG_NAME
                        "] Creating CoAP client session using DTLS with PSK.");
        if ((coap_session = charra_coap_new_client_session_psk(
                     coap_context,
                     attester_host, attester_port, COAP_PROTO_DTLS, dtls_psk_identity,
                     (uint8_t*)dtls_psk_key, strlen(dtls_psk_key))) == NULL) {
            charra_log_error(
                    "[" LOG_NAME
                    "] Cannot create client session based on DTLS-PSK.");
            result = CHARRA_RC_ERROR;
            goto cleanup;
        }
    } else if (use_dtls_rpk) {
        charra_log_info(
                "[" LOG_NAME "] Creating CoAP client session using DTLS-RPK.");
        coap_dtls_pki_t dtls_pki = {0};

        result = charra_coap_setup_dtls_pki_for_rpk(&dtls_pki,
                dtls_rpk_private_key_path, dtls_rpk_public_key_path,
                dtls_rpk_attester_public_key_path, dtls_rpk_verify_peer_public_key);
        if (result != CHARRA_RC_SUCCESS) {
            charra_log_error("[" LOG_NAME
                             "] Error while setting up DTLS-RPK structure.");
            goto cleanup;
        }

        if ((coap_session = charra_coap_new_client_session_pki(
                     coap_context,
                     attester_host, attester_port, COAP_PROTO_DTLS,
                     &dtls_pki)) == NULL) {
            charra_log_error(
                    "[" LOG_NAME
                    "] Cannot create client session based on DTLS-RPK.");
            result = CHARRA_RC_ERROR;
            goto cleanup;
        }
    } else {
        charra_log_info(
                "[" LOG_NAME "] Creating CoAP client session using UDP.");
        if ((coap_session = charra_coap_new_client_session(
                     coap_context,
                     attester_host, attester_port, COAP_PROTO_UDP)) == NULL) {
            charra_log_error("[" LOG_NAME
                             "] Cannot create client session based on UDP.");
            result = CHARRA_RC_COAP_ERROR;
            goto cleanup;
        }
    }

    /* define needed variables */
    msg_attestation_request_dto req = {0};
    uint32_t req_buf_len = 0;
    coap_pdu_t* pdu = NULL;
    coap_mid_t mid = COAP_INVALID_MID;
    int coap_io_process_time = -1;

    /* create CoAP option for content type */
    uint8_t coap_mediatype_cbor_buf[4] = {0};
    unsigned int coap_mediatype_cbor_buf_len = 0;
    if ((coap_mediatype_cbor_buf_len = coap_encode_var_safe(
                 coap_mediatype_cbor_buf, sizeof(coap_mediatype_cbor_buf),
                 COAP_MEDIATYPE_APPLICATION_CBOR)) == 0) {
        charra_log_error(
                "[" LOG_NAME "] Cannot create option for CONTENT_TYPE.");
        result = CHARRA_RC_COAP_ERROR;
        goto cleanup;
    }

    
    /* create attestation request */
    charra_log_info("[" LOG_NAME "] Creating attestation request.");
    if ((result = create_attestation_request(&req)) != CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Cannot create attestation request.");
        goto cleanup;
    } else {
        /* store request data */
        last_request = req;
    }


    /* marshal attestation request */
    charra_log_info(
            "[" LOG_NAME "] Marshaling attestation request data to CBOR.");
    if ((result = charra_marshal_attestation_request(
                 &req, &req_buf_len, &req_buf)) != CHARRA_RC_SUCCESS) {
        charra_log_error(
                "[" LOG_NAME "] Marshaling attestation request data failed.");
        goto cleanup;
    }

    /* CoAP options */
    charra_log_info("[" LOG_NAME "] Adding CoAP option URI_PATH.");
    if (coap_insert_optlist(&coap_options,
                coap_new_optlist(COAP_OPTION_URI_PATH, 6,
                                       (const uint8_t*)"attest")) != 1) {
        charra_log_error("[" LOG_NAME "] Cannot add CoAP option URI_PATH.");
        result = CHARRA_RC_COAP_ERROR;
        goto cleanup;
    }
    charra_log_info("[" LOG_NAME "] Adding CoAP option CONTENT_TYPE.");
    if (coap_insert_optlist(&coap_options,
                coap_new_optlist(COAP_OPTION_CONTENT_TYPE,
                                       coap_mediatype_cbor_buf_len,
                                       coap_mediatype_cbor_buf)) != 1) {
        charra_log_error("[" LOG_NAME "] Cannot add CoAP option CONTENT_TYPE.");
        result = CHARRA_RC_COAP_ERROR;
        goto cleanup;
    }

    /* new CoAP request PDU */
    charra_log_info("[" LOG_NAME "] Creating request PDU.");
    if ((pdu = charra_coap_new_request(coap_session,
                 COAP_MESSAGE_TYPE_CON, COAP_REQUEST_FETCH,
                 &coap_options, req_buf, req_buf_len)) ==
            NULL) {
        charra_log_error("[" LOG_NAME "] Cannot create request PDU.");
        result = CHARRA_RC_ERROR;
        goto cleanup;
    }

    /* set timeout length */
    coap_fixed_point_t coap_timeout = {attester_response_timeout, 0};
    coap_session_set_ack_timeout(coap_session, coap_timeout);

    /* send CoAP PDU */
    charra_log_info("[" LOG_NAME "] Sending attestation request.");
    if ((mid = coap_send_large(coap_session, pdu)) ==
            COAP_INVALID_MID) {
        charra_log_error("[" LOG_NAME "] Cannot send CoAP message.");
        result = CHARRA_RC_COAP_ERROR;
        goto cleanup;
    }

    /* processing and waiting for response */
    charra_log_info("[" LOG_NAME "] Processing and waiting for response ...");
    uint16_t response_wait_time = 0; 
    while (!processing_attestation_response && coap_io_pending(coap_context)) {
        /* process CoAP I/O */
        if ((coap_io_process_time = coap_io_process(
                     coap_context, COAP_IO_PROCESS_TIME_MS)) == -1) {
            charra_log_error(
                    "[" LOG_NAME "] Error during CoAP I/O processing.");
            result = CHARRA_RC_COAP_ERROR;
            goto cleanup;
        }
        /* This wait time is not 100% accurate, it only includes the elapsed
         * time inside the coap_io_process function. But should be good enough.
         */
        response_wait_time += coap_io_process_time;
        if (response_wait_time >= (attester_response_timeout * 1000)) {
            charra_log_error("[" LOG_NAME
                             "] Timeout after %d ms while waiting for or "
                             "processing attestation response.",
                    response_wait_time);
            result = CHARRA_RC_TIMEOUT;
            goto cleanup;
        }
    }

    result = CHARRA_RC_SUCCESS;

cleanup:
    /* free CoAP memory */
    charra_free_if_not_null_ex(coap_options, coap_delete_optlist);
    charra_free_if_not_null_ex(coap_session, coap_session_release);
    charra_free_if_not_null_ex(coap_context, coap_free_context);

    /* free variables */
    charra_free_if_not_null(req_buf);

    coap_cleanup();

    return result;
}

void* get_attestation_results_thread(void *arg) {

    CHARRA_RC result = EXIT_FAILURE;

    int current_thread_index = *(int*)arg;
    verifier_info verifier_info = verifiers[current_thread_index];

     /* set varaibles here such that they are valid in case of an 'goto cleanup'
     */
    coap_context_t* coap_context = NULL;
    coap_session_t* coap_session = NULL;
    coap_optlist_t* coap_options = NULL;

    if (use_dtls_psk && use_dtls_rpk) {
        charra_log_error(
                "[" LOG_NAME "] Configuration enables both DTSL with PSK "
                "and DTSL with PKI. Aborting!");
        goto cleanup;
    }

    if (use_dtls_psk || use_dtls_rpk) {
        // print TLS version when in debug mode
        coap_show_tls_version(LOG_DEBUG);
    }

    if (use_dtls_psk && !coap_dtls_is_supported()) {
        charra_log_error("[" LOG_NAME "] CoAP does not support DTLS but the "
                         "configuration enables DTLS. Aborting!");
        goto cleanup;
    }

    /* create CoAP context */
    if ((coap_context = charra_coap_new_context(true)) == NULL) {
        charra_log_error("[" LOG_NAME "] Cannot create CoAP context.");
        result = CHARRA_RC_COAP_ERROR;
        goto cleanup;
    }

    if (use_dtls_psk) {
        charra_log_info("[" LOG_NAME
                        "] Creating CoAP client session using DTLS with PSK.");
        if ((coap_session = charra_coap_new_client_session_psk(
                     coap_context, verifier_info.ip_address, verifier_info.port_number,
                     COAP_PROTO_DTLS, dtls_psk_identity, (uint8_t*)dtls_psk_key,
                     strlen(dtls_psk_key))) == NULL) {
            charra_log_error(
                    "[" LOG_NAME
                    "] Cannot create client session based on DTLS-PSK.");
            result = CHARRA_RC_ERROR;
            goto cleanup;
        }
    } else if (use_dtls_rpk) {
        charra_log_info(
                "[" LOG_NAME "] Creating CoAP client session using DTLS-RPK.");
        coap_dtls_pki_t dtls_pki = {0};

        result = charra_coap_setup_dtls_pki_for_rpk(&dtls_pki,
                dtls_rpk_private_key_path, dtls_rpk_public_key_path,
                dtls_rpk_verifier_public_key_path, dtls_rpk_verify_peer_public_key);
        if (result != CHARRA_RC_SUCCESS) {
            charra_log_error("[" LOG_NAME
                             "] Error while setting up DTLS-RPK structure.");
            goto cleanup;
        }

        if ((coap_session = charra_coap_new_client_session_pki(
                     coap_context, verifier_info.ip_address, verifier_info.port_number,
                     COAP_PROTO_DTLS, &dtls_pki)) == NULL) {
            charra_log_error(
                    "[" LOG_NAME
                    "] Cannot create client session based on DTLS-RPK.");
            result = CHARRA_RC_ERROR;
            goto cleanup;
        }
    } else {
        if ((coap_session = charra_coap_new_client_session(
                     coap_context, verifier_info.ip_address, verifier_info.port_number,
                     COAP_PROTO_UDP)) == NULL) {
            charra_log_error("[" LOG_NAME
                             "] Cannot create client session based on UDP.");
            result = CHARRA_RC_COAP_ERROR;
            goto cleanup;
        }
    }

    /* --- Interaction with the Verifier (sending the nonce) * ---------------------------------------------------------------*/
    coap_pdu_t* pdu_n = NULL;
    coap_mid_t mid_n = COAP_INVALID_MID;
    int coap_io_process_time_n = -1;
    
    /* create CoAP option for content type */
    uint8_t coap_mediatype_cbor_buf_n[4] = {0};
    unsigned int coap_mediatype_cbor_buf_len_n = 0;
    if ((coap_mediatype_cbor_buf_len_n = coap_encode_var_safe(
                 coap_mediatype_cbor_buf_n, sizeof(coap_mediatype_cbor_buf_n),
                 COAP_MEDIATYPE_APPLICATION_CBOR)) == 0) {
        charra_log_error(
                "[" LOG_NAME "] Cannot create option for CONTENT_TYPE.");
        result = CHARRA_RC_COAP_ERROR;
        goto cleanup;
    }

    /* marshal response */
    uint32_t nonce_buf_len = 0;
    uint8_t* nonce_buf = NULL;
    if ((charra_r = charra_marshal_attestation_request(
                 &last_request, &nonce_buf_len, &nonce_buf)) != CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Error marshaling data.");
        goto error;
    }


    /* CoAP options */
    if (coap_insert_optlist(
                &coap_options, coap_new_optlist(COAP_OPTION_URI_PATH, 5,
                                       (const uint8_t*)"nonce")) != 1) {
        charra_log_error("[" LOG_NAME "] Cannot add CoAP option URI_PATH.");
        result = CHARRA_RC_COAP_ERROR;
        goto cleanup;
    }
    if (coap_insert_optlist(&coap_options,
                coap_new_optlist(COAP_OPTION_CONTENT_TYPE,
                                       coap_mediatype_cbor_buf_len_n,
                                       coap_mediatype_cbor_buf_n)) != 1) {
        charra_log_error("[" LOG_NAME "] Cannot add CoAP option CONTENT_TYPE.");
        result = CHARRA_RC_COAP_ERROR;
        goto cleanup;
    }

    if ((pdu_n = charra_coap_new_request(coap_session, COAP_MESSAGE_TYPE_CON, COAP_REQUEST_FETCH,
                 &coap_options, nonce_buf, nonce_buf_len)) ==
            NULL) {
        charra_log_error("[" LOG_NAME "] Cannot create request PDU.");
        result = CHARRA_RC_ERROR;
        goto cleanup;
    }

    coap_fixed_point_t coap_timeout_n = {verifier_response_timeout, 0};
    coap_session_set_ack_timeout(coap_session, coap_timeout_n);

    if ((mid_n = coap_send_large(coap_session, pdu_n)) == COAP_INVALID_MID) {
        charra_log_error("[" LOG_NAME "] Cannot send CoAP message.");
        result = CHARRA_RC_COAP_ERROR;
        goto cleanup;
    }


    uint16_t response_wait_time_n = 0;  
    while (!processing_appraisal_response && coap_io_pending(coap_context)) {
        /* process CoAP I/O */
        if ((coap_io_process_time_n = coap_io_process(
                     coap_context, COAP_IO_PROCESS_TIME_MS)) == -1) {
            charra_log_error(
                    "[" LOG_NAME "] Error during CoAP I/O processing.");
            result = CHARRA_RC_COAP_ERROR;
            goto cleanup;
        }
        /* This wait time is not 100% accurate, it only includes the elapsed
         * time inside the coap_io_process function. But should be good enough.
         */
        response_wait_time_n += coap_io_process_time_n;
        if (response_wait_time_n >= (verifier_response_timeout * 1000)) {
            charra_log_error("[" LOG_NAME
                             "] Timeout after %d ms while waiting for or "
                             "processing attestation response.",
                    response_wait_time_n);
            result = CHARRA_RC_TIMEOUT;
            goto cleanup;
        }
    }

    /* --- Interaction with the Verifier (forwarding the evidence for appraisal) * ---------------------------------------------------------------*/
    /* set varaibles here such that they are valid in case of an 'goto cleanup'
     */
    coap_context_t* coap_context_verifier_appraisal = NULL;
    coap_session_t* coap_session_verifier_appraisal = NULL;
    coap_optlist_t* coap_options_verifier_appraisal = NULL;

    if (use_dtls_psk && use_dtls_rpk) {
        charra_log_error(
                "[" LOG_NAME "] Configuration enables both DTSL with PSK "
                "and DTSL with PKI. Aborting!");
        goto cleanup;
    }

    if (use_dtls_psk || use_dtls_rpk) {
        // print TLS version when in debug mode
        coap_show_tls_version(LOG_DEBUG);
    }

    if (use_dtls_psk && !coap_dtls_is_supported()) {
        charra_log_error("[" LOG_NAME "] CoAP does not support DTLS but the "
                         "configuration enables DTLS. Aborting!");
        goto cleanup;
    }

    /* create CoAP context */

    //charra_log_info("[" LOG_NAME "] Initializing CoAP in block-wise mode.");
    if ((coap_context_verifier_appraisal = charra_coap_new_context(true)) == NULL) {
        charra_log_error("[" LOG_NAME "] Cannot create CoAP context.");
        result = CHARRA_RC_COAP_ERROR;
        goto cleanup;
    }

    /* register CoAP response handler */
    //charra_log_info("[" LOG_NAME "] Registering CoAP response handler.");
    coap_register_response_handler(
            coap_context_verifier_appraisal, coap_verifier_handler_appraisal);

    if (use_dtls_psk) {
        charra_log_info("[" LOG_NAME
                        "] Creating CoAP client session using DTLS with PSK.");
        if ((coap_session_verifier_appraisal = charra_coap_new_client_session_psk(
                     coap_context_verifier_appraisal, verifier_info.ip_address, verifier_info.port_number,
                     COAP_PROTO_DTLS, dtls_psk_identity, (uint8_t*)dtls_psk_key,
                     strlen(dtls_psk_key))) == NULL) {
            charra_log_error(
                    "[" LOG_NAME
                    "] Cannot create client session based on DTLS-PSK.");
            result = CHARRA_RC_ERROR;
            goto cleanup;
        }
    } else if (use_dtls_rpk) {
        charra_log_info(
                "[" LOG_NAME "] Creating CoAP client session using DTLS-RPK.");
        coap_dtls_pki_t dtls_pki = {0};

        result = charra_coap_setup_dtls_pki_for_rpk(&dtls_pki,
                dtls_rpk_private_key_path, dtls_rpk_public_key_path,
                dtls_rpk_verifier_public_key_path, dtls_rpk_verify_peer_public_key);
        if (result != CHARRA_RC_SUCCESS) {
            charra_log_error("[" LOG_NAME
                             "] Error while setting up DTLS-RPK structure.");
            goto cleanup;
        }

        if ((coap_session_verifier_appraisal = charra_coap_new_client_session_pki(
                     coap_context_verifier_appraisal, verifier_info.ip_address, verifier_info.port_number,
                     COAP_PROTO_DTLS, &dtls_pki)) == NULL) {
            charra_log_error(
                    "[" LOG_NAME
                    "] Cannot create client session based on DTLS-RPK.");
            result = CHARRA_RC_ERROR;
            goto cleanup;
        }
    } else {
        //charra_log_info("[" LOG_NAME "] Creating CoAP client session using UDP.");
        if ((coap_session_verifier_appraisal = charra_coap_new_client_session(
                     coap_context_verifier_appraisal, verifier_info.ip_address, verifier_info.port_number,
                     COAP_PROTO_UDP)) == NULL) {
            charra_log_error("[" LOG_NAME
                             "] Cannot create client session based on UDP.");
            result = CHARRA_RC_COAP_ERROR;
            goto cleanup;
        }
    }

    coap_pdu_t* pdu_v = NULL;
    coap_mid_t mid_v = COAP_INVALID_MID;
    int coap_io_process_time_v = -1;

    msg_attestation_response_dto res = last_response;
    
    /* create CoAP option for content type */
    uint8_t coap_mediatype_cbor_buf_v[4] = {0};
    unsigned int coap_mediatype_cbor_buf_len_v = 0;
    if ((coap_mediatype_cbor_buf_len_v = coap_encode_var_safe(
                 coap_mediatype_cbor_buf_v, sizeof(coap_mediatype_cbor_buf_v),
                 COAP_MEDIATYPE_APPLICATION_CBOR)) == 0) {
        charra_log_error(
                "[" LOG_NAME "] Cannot create option for CONTENT_TYPE.");
        result = CHARRA_RC_COAP_ERROR;
        goto cleanup;
    }

    /* marshal response */
    //charra_log_info("[" LOG_NAME "] Marshaling response to CBOR.");
    uint32_t res_buf_len = 0;
    uint8_t* res_buf = NULL;
    if ((charra_r = charra_marshal_attestation_response(
                 &res, &res_buf_len, &res_buf)) != CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Error marshaling data.");
        goto error;
    }
    //charra_log_info("[" LOG_NAME "] Size of marshaled response is %d bytes.",res_buf_len);

    /* CoAP options */
    //charra_log_info("[" LOG_NAME "] Adding CoAP option URI_PATH.");
    if (coap_insert_optlist(
                &coap_options_verifier_appraisal, coap_new_optlist(COAP_OPTION_URI_PATH, 8,
                                       (const uint8_t*)"appraise")) != 1) {
        charra_log_error("[" LOG_NAME "] Cannot add CoAP option URI_PATH.");
        result = CHARRA_RC_COAP_ERROR;
        goto cleanup;
    }
    //charra_log_info("[" LOG_NAME "] Adding CoAP option CONTENT_TYPE.");
    if (coap_insert_optlist(&coap_options_verifier_appraisal,
                coap_new_optlist(COAP_OPTION_CONTENT_TYPE,
                                       coap_mediatype_cbor_buf_len_v,
                                       coap_mediatype_cbor_buf_v)) != 1) {
        charra_log_error("[" LOG_NAME "] Cannot add CoAP option CONTENT_TYPE.");
        result = CHARRA_RC_COAP_ERROR;
        goto cleanup;
    }

    /* new CoAP request PDU */
    //charra_log_info("[" LOG_NAME "] Creating request PDU.");
    if ((pdu_v = charra_coap_new_request(coap_session_verifier_appraisal, COAP_MESSAGE_TYPE_CON, COAP_REQUEST_FETCH,
                 &coap_options_verifier_appraisal, res_buf, res_buf_len)) ==
            NULL) {
        charra_log_error("[" LOG_NAME "] Cannot create request PDU.");
        result = CHARRA_RC_ERROR;
        goto cleanup;
    }

    /* set timeout length */
    coap_fixed_point_t coap_timeout_v = {verifier_response_timeout, 0};
    coap_session_set_ack_timeout(coap_session_verifier_appraisal, coap_timeout_v);

    coap_session_set_app_data(coap_session_verifier_appraisal, &current_thread_index);
    
    /* send CoAP PDU */
    //charra_log_info("[" LOG_NAME "] Sending CoAP message.");
    if ((mid_v = coap_send_large(coap_session_verifier_appraisal, pdu_v)) == COAP_INVALID_MID) {
        charra_log_error("[" LOG_NAME "] Cannot send CoAP message.");
        result = CHARRA_RC_COAP_ERROR;
        goto cleanup;
    }

    /* processing and waiting for response */
    //charra_log_info("[" LOG_NAME "] Processing and waiting for response ...");
    uint16_t response_wait_time_v = 0;  
    while (!processing_appraisal_response && coap_io_pending(coap_context_verifier_appraisal)) {
        /* process CoAP I/O */
        if ((coap_io_process_time_v = coap_io_process(
                     coap_context_verifier_appraisal, COAP_IO_PROCESS_TIME_MS)) == -1) {
            charra_log_error(
                    "[" LOG_NAME "] Error during CoAP I/O processing.");
            result = CHARRA_RC_COAP_ERROR;
            goto cleanup;
        }
        /* This wait time is not 100% accurate, it only includes the elapsed
         * time inside the coap_io_process function. But should be good enough.
         */
        response_wait_time_v += coap_io_process_time_v;
        if (response_wait_time_v >= (verifier_response_timeout * 1000)) {
            charra_log_error("[" LOG_NAME
                             "] Timeout after %d ms while waiting for or "
                             "processing attestation response.",
                    response_wait_time_v);
            result = CHARRA_RC_TIMEOUT;
            goto cleanup;
        }
    }

    result = attestation_rc;
error:
    result = EXIT_FAILURE;

cleanup:
    /* free CoAP memory */
    charra_free_if_not_null_ex(coap_options, coap_delete_optlist);
    charra_free_if_not_null_ex(coap_session, coap_session_release);
    charra_free_if_not_null_ex(coap_context, coap_free_context);

    charra_free_if_not_null_ex(coap_options_verifier_appraisal, coap_delete_optlist);
    charra_free_if_not_null_ex(coap_session_verifier_appraisal, coap_session_release);
    charra_free_if_not_null_ex(coap_context_verifier_appraisal, coap_free_context);
    /* free variables */
    charra_free_if_not_null(res_buf);

    coap_cleanup();

    return NULL;
}

CHARRA_RC get_attestation_results(int num_verifiers) {
    CHARRA_RC result = EXIT_FAILURE;

    charra_log_info("[" LOG_NAME "]  +------------ Interaction with the Verifiers --------------+");

    pthread_t threads[num_verifiers];
    int indexes[num_verifiers];

    for (int i = 0; i < num_verifiers; ++i) {
        indexes[i] = i;
        if (pthread_create(&threads[i], NULL, get_attestation_results_thread, &indexes[i]) != 0) {
            charra_log_error("[" LOG_NAME"] Error creating thread");
            goto error;
        } else {
            charra_log_info("[" LOG_NAME "] Forwarding evidence to Verifier n° %d ...", i+1);
        }
    }

    for (int i = 0; i < num_verifiers; ++i) {
        pthread_join(threads[i], NULL);
    }

    for (int i = 0; i < num_verifiers; ++i) {
        charra_log_info("[" LOG_NAME "] Verifier %d: %s", i+1, attestation_results[i] ? "Attestation successful!" : "Attestation failed!");
    }    

    int num_true = 0;
    for (int i = 0; i < num_verifiers; ++i) {
        if (attestation_results[i]) {
            num_true++;
        }
    }

    if (2 * num_true > num_verifiers) {
        charra_log_info("[" LOG_NAME "] Attestation successful by majority vote!");
    } else {
        charra_log_info("[" LOG_NAME "] Attestation failed by majority vote!");
    }

    result = CHARRA_RC_SUCCESS;


error:
    return result;

}