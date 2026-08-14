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
#include "core/charra_rp_key_mgr.h"
#include "core/charra_sdk.h"
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
/* Set by coap_verifier_handler_appraisal() when a Verifier's /appraise
 * response is specifically "your AK certificate is invalid or expired"
 * (4.01 Unauthorized), as opposed to any other appraisal failure --
 * distinguishes "go redo /certify_ak and retry" from a plain failed vote. */
bool rp_ak_cert_rejected[MAX_VERIFIERS];
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

/* --- privacy-cleaning state, produced once per attestation -------------- */
/* log_r: the redacted log, and PCR_r: the composite digest over a replay of
 * it. Shared by every verifier thread -- the redaction is randomised, so
 * redacting once per verifier would hand each of them a different log_r for
 * the same attestation. */
static uint8_t* rp_log_r = NULL;
static uint32_t rp_log_r_len = 0;
static uint8_t rp_pcr_r[TPM2_SHA256_DIGEST_SIZE] = {0};
/* Quote_r's signing key is RP's TPM-resident AK (see ensure_rp_ak_certificate()
 * / charra_rp_key_mgr.h) -- provisioned once and reused for the process's
 * lifetime, unlike the throwaway software key this used to be. */
static uint8_t rp_public_key_der[CHARRA_RSA_PUB_KEY_DER_MAX] = {0};
static uint32_t rp_public_key_der_len = 0;

/* --- RP TPM identity / /certify_ak config -------------------------------- */
/* Same synthetic test PKI keys/gen-ak-pki.sh generates. manufacturer_root_key
 * is only ever touched here, once, to mint RP's own EK certificate the first
 * time this binary runs against a fresh TPM -- a real device would never
 * hold this key itself (it's normally burned in by the manufacturer at
 * TPM-manufacture time), but there is no real manufacturer in this
 * synthetic PKI, same simplification /certify_ak's own EK-check already
 * documents. */
static char* manufacturer_root_cert_path = "keys/manufacturer-root.crt";
static char* manufacturer_root_key_path = "keys/manufacturer-root.key";
static const char* rp_ek_cert_not_before_utc = "20240101000000";
static const char* rp_ek_cert_not_after_utc = "20340101000000";
/* Cache files -- created on first successful provisioning, reused (skipping
 * the whole /certify_ak round trip) on every later run. Relative to
 * whatever directory bin/relying_party is started from, same convention
 * verifier.c's ak-provisioning-state.txt uses. */
static char* rp_ek_cert_cache_path = "rp-ek-certificate.der";
static char* rp_ak_public_path = "rp-ak-public.bin";
static char* rp_ak_private_path = "rp-ak-private.bin";
static char* rp_ak_cert_path = "rp-ak-certificate.der";

static bool rp_identity_ready = false;
static uint8_t* rp_ak_cert_der = NULL;
static uint32_t rp_ak_cert_der_len = 0;
static bool processing_certify_ak_response = false;
static CHARRA_RC certify_ak_rc = CHARRA_RC_ERROR;

/* --- RP qualification handshake state (/qualify + /qualify/submit) ------
 * See charra_rp_qualification.h. Verifier-local state, so this handshake
 * has to be repeated against each Verifier the RP submits evidence to, not
 * just verifiers[0] like AK provisioning above. */
static uint8_t* qualify_challenge_log = NULL;
static uint32_t qualify_challenge_log_len = 0;
static CHARRA_RC qualify_response_rc = CHARRA_RC_ERROR;
static bool processing_qualify_response = false;
static bool qualify_submit_qualified = false;
static bool processing_qualify_submit_response = false;
/* Guards every TPM connection RP opens (provisioning and, later, each
 * Quote_r signing operation): the TPM simulator this dev environment uses
 * accepts only one client connection at a time, and every other binary
 * (attester.c, verifier.c) already follows an open-do-one-thing-close
 * pattern per request rather than holding a connection for a whole
 * process's lifetime. A connection RP held open for its entire run once
 * starved the Verifier's own /certify_ak TPM work indefinitely -- observed
 * directly (killing the RP process immediately unblocked the Verifier).
 * This mutex keeps RP's own accesses serialized and, just as importantly,
 * keeps each one short-lived so other processes get a turn. */
static pthread_mutex_t rp_tpm_mutex = PTHREAD_MUTEX_INITIALIZER;
/* Guards re-provisioning RP's AK certificate after a Verifier rejects it as
 * invalid/expired (see rp_ak_cert_rejected above). Several verifier threads
 * can discover this at once; without serializing, each would independently
 * wipe the cached AK and request a fresh /certify_ak, and since renewal
 * always revokes the previous record for the same EK, they would keep
 * invalidating each other's freshly-issued certificate. rp_ak_generation is
 * bumped each time a fresh certificate is actually obtained; a thread only
 * performs the re-provisioning itself if the generation hasn't moved since
 * it observed the rejection -- otherwise another thread already refreshed
 * it and this one just retries with what's now cached. */
static pthread_mutex_t rp_ak_reprovision_mutex = PTHREAD_MUTEX_INITIALIZER;
static uint64_t rp_ak_generation = 0;
/* Nonces received from each Verifier, indexed by verifier slot. */
static uint8_t verifier_nonces[MAX_VERIFIERS][sizeof(TPMU_HA)] = {{0}};
static uint32_t verifier_nonce_lens[MAX_VERIFIERS] = {0};
static bool processing_nonce_response = false;
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

/**
 * @brief Privacy-clean the Attester's evidence: redact the log into log_r,
 * replay log_r into PCR_r, and generate the keypair Quote_r is signed with.
 *
 * Run once per attestation, before any verifier thread starts.
 */
static CHARRA_RC charra_rp_prepare_evidence(void);

/** @brief Frees what charra_rp_prepare_evidence() allocated. */
static void charra_rp_release_evidence(void);

static coap_response_t coap_verifier_handler_nonce(coap_session_t* session,
        const coap_pdu_t* sent CHARRA_UNUSED, const coap_pdu_t* received,
        const coap_mid_t mid CHARRA_UNUSED);

static coap_response_t coap_certify_ak_response_handler(
        coap_session_t* session CHARRA_UNUSED,
        const coap_pdu_t* sent CHARRA_UNUSED, const coap_pdu_t* received,
        const coap_mid_t mid CHARRA_UNUSED);

/**
 * @brief Ensure RP has a TPM-resident AK certified by verifier_host's
 * Verifier, provisioning one via /certify_ak if this is the first run
 * (no cached rp-ak/rp-ek certificate files yet) and reloading the cached
 * identity otherwise. Idempotent -- cheap to call before every attestation
 * cycle.
 *
 * Does NOT leave any TPM connection open afterward (see rp_tpm_mutex's
 * comment) -- populates rp_ak_cert_der/_len (Step 3a item 1's input) and
 * rp_public_key_der/_len (the DER-encoded AK public key
 * charra_rp_build_evidence_message() sends as rp_public_key) on disk/in
 * memory only. Signing later reopens a short-lived connection via
 * rp_open_tpm_and_load_ak().
 */
static CHARRA_RC ensure_rp_ak_certificate(
        const char* verifier_host, unsigned int verifier_port);

/**
 * @brief Discard RP's cached AK (public/private/certificate, both on disk
 * and in memory) so the next ensure_rp_ak_certificate() call is forced to
 * provision a fresh one via /certify_ak, instead of reloading what a
 * Verifier just rejected as invalid or expired. The cached EK certificate
 * is deliberately left alone -- the EK itself is not what expired, and
 * charra_rp_key_mgr_create_ek() would just reproduce the identical key
 * anyway.
 */
static void invalidate_cached_rp_ak_certificate(void);

/** @brief See its own definition's docstring, above ensure_rp_ak_certificate()
 * in the .c file -- forward-declared here so charra_rp_build_evidence_
 * message() (defined earlier in the file) can call it too. */
static CHARRA_RC rp_open_tpm_and_load_ak(ESYS_CONTEXT** esys_ctx_out,
        TSS2_TCTI_CONTEXT** tcti_ctx_out, ESYS_TR* ek_handle_out,
        ESYS_TR* ak_handle_out, TPM2B_NAME** ak_name_out);

static coap_response_t coap_qualify_response_handler(
        coap_session_t* session CHARRA_UNUSED,
        const coap_pdu_t* sent CHARRA_UNUSED, const coap_pdu_t* received,
        const coap_mid_t mid CHARRA_UNUSED);

static coap_response_t coap_qualify_submit_response_handler(
        coap_session_t* session CHARRA_UNUSED,
        const coap_pdu_t* sent CHARRA_UNUSED, const coap_pdu_t* received,
        const coap_mid_t mid CHARRA_UNUSED);

/**
 * @brief Run the RP qualification handshake (charra_rp_qualification.h)
 * against one Verifier: fetch a fresh /qualify challenge, redact it with
 * the same pipeline real evidence uses, sign the resulting PCR digest with
 * RP's TPM-resident AK, and submit it all via /qualify/submit.
 *
 * Verifier-local state (unlike the AK certificate, which is trusted by
 * every Verifier equally, see ensure_rp_ak_certificate()'s docstring) --
 * has to be repeated per Verifier the RP intends to submit evidence to.
 * Requires rp_identity_ready (an RP AK certificate must already exist).
 *
 * @returns CHARRA_RC_SUCCESS only if the Verifier's /qualify/submit
 * response reports the RP as qualified. Any other outcome (transport
 * failure, or a genuine "not qualified" verdict) returns a non-success
 * code -- the caller decides whether that's fatal.
 */
static CHARRA_RC rp_perform_qualification_handshake(
        const verifier_info* verifier);

CHARRA_RC get_verifiers(int* verifier_list, int num_verifiers);

CHARRA_RC get_evidence();

CHARRA_RC get_attestation_results(int num_verifiers);

void* get_attestation_results_thread();

/* --- static variables --------------------------------------------------- */

static msg_attestation_request_dto last_request = {0};
static msg_attestation_response_dto last_response = {0};
static msg_certify_ak_response_dto certify_ak_response = {0};

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

            /* Clear delimiter between sweep iterations -- without this, every
             * run's log lines (1..5 verifiers, NUM_RUNS repeats each) run
             * together with no way to tell where one attestation attempt ends
             * and the next begins. */
            charra_log_info("[" LOG_NAME
                            "] ============================================================");
            charra_log_info("[" LOG_NAME
                            "] Starting new attestation run with %d verifier(s) "
                            "(run %d/%d).",
                    num_verifiers, run + 1, NUM_RUNS);
            charra_log_info("[" LOG_NAME
                            "] ============================================================");

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

            /* Ensure RP has a TPM-certified AK -- provisions one via
             * /certify_ak against verifiers[0] on first run, reuses the
             * cached identity on every later call (idempotent). Every
             * verifier trusts the same CA (see CHARRA_V2_NOTES.md), so any
             * one of them works for provisioning. */
            charra_log_info("[" LOG_NAME "] Ensuring RP AK certificate.");
            if ((result = ensure_rp_ak_certificate(verifiers[0].ip_address,
                         verifiers[0].port_number)) != CHARRA_RC_SUCCESS) {
                charra_log_error(
                        "[" LOG_NAME "] Error provisioning RP AK certificate.");
                goto error;
            }

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

    /* NOT actually forwarding yet -- charra_rp_prepare_evidence() (privacy
     * cleaning: redact the log, build Quote_r) still has to run first, in
     * get_attestation_results() below. The real "Forwarding evidence to the
     * verifiers" log is there, after that redaction succeeds. */
    charra_log_info(
            "[" LOG_NAME "] Evidence appraised locally; privacy-cleaning "
            "before forwarding to the Verifiers.");
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

static CHARRA_RC charra_rp_prepare_evidence(void) {
    charra_rp_release_evidence();

    charra_log_info("[" LOG_NAME
            "]  +------------ RP Privacy Cleaning --------------+");

    /* --- redact: only the path of each entry is replaced --------------- */
    CHARRA_RC charra_r = charra_sdk_redact_ima_log(last_response.event_log,
            last_response.event_log_len, &rp_log_r, &rp_log_r_len);
    if (charra_r != CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Redaction of the event log failed.");
        return charra_r;
    }
    charra_log_info("[" LOG_NAME "] log_r is %u bytes (raw log was %u).",
            rp_log_r_len, last_response.event_log_len);

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
     * Provisioned once by ensure_rp_ak_certificate() (called from main()
     * before the first attestation cycle); rp_public_key_der/_len are
     * already populated by then, nothing left to do here. */
    if (!rp_identity_ready) {
        charra_log_error(
                "[" LOG_NAME "] RP AK not provisioned; evidence not ready.");
        return CHARRA_RC_ERROR;
    }
    charra_log_info(
            "[" LOG_NAME "] RP AK ready (public key %u bytes, certificate "
            "%u bytes).",
            rp_public_key_der_len, rp_ak_cert_der_len);
    return CHARRA_RC_SUCCESS;
}

static void charra_rp_release_evidence(void) {
    charra_free_if_not_null(rp_log_r);
    rp_log_r = NULL;
    rp_log_r_len = 0;
    /* rp_ak_handle/rp_public_key_der/rp_ak_cert_der are provisioned once by
     * ensure_rp_ak_certificate() and live for the whole process, not freed
     * per attestation cycle. */
}

/**
 * @brief Builds Quote_r for one Verifier and marshals the whole RP evidence
 * message for it.
 *
 * Quote_r's signature covers (PCR_r || that Verifier's nonce), so each
 * Verifier gets a signature bound to the challenge it issued -- which is
 * what makes the exchange fresh from the Verifier's point of view.
 */
static CHARRA_RC charra_rp_build_evidence_message(int verifier_index,
        uint32_t* marshaled_len, uint8_t** marshaled) {
    if (!rp_identity_ready) {
        charra_log_error("[" LOG_NAME "] No RP AK; evidence not prepared.");
        return CHARRA_RC_ERROR;
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

    charra_r = charra_rp_key_mgr_sign(sign_esys_ctx, sign_ak_handle,
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

    ev.ak_certificate_rp_len = rp_ak_cert_der_len;
    ev.ak_certificate_rp = rp_ak_cert_der;

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

    ev.log_r = rp_log_r;
    ev.log_r_len = rp_log_r_len;

    return charra_marshal_rp_evidence(&ev, marshaled_len, marshaled);
}

static coap_response_t coap_certify_ak_response_handler(
        coap_session_t* session CHARRA_UNUSED,
        const coap_pdu_t* sent CHARRA_UNUSED, const coap_pdu_t* received,
        const coap_mid_t mid CHARRA_UNUSED) {
    processing_certify_ak_response = true;

    int coap_r = 0;
    size_t data_len = 0;
    const uint8_t* data = NULL;
    size_t data_offset = 0;
    size_t data_total_len = 0;
    if ((coap_r = coap_get_data_large(
                 received, &data_len, &data, &data_offset, &data_total_len)) ==
            0) {
        charra_log_error(
                "[" LOG_NAME "] /certify_ak: Could not get CoAP PDU data.");
        certify_ak_rc = CHARRA_RC_ERROR;
        goto cleanup;
    }

    if ((certify_ak_rc = charra_unmarshal_certify_ak_response(
                 data_len, data, &certify_ak_response)) != CHARRA_RC_SUCCESS) {
        charra_log_error(
                "[" LOG_NAME "] /certify_ak: Could not parse CBOR response.");
        goto cleanup;
    }

cleanup:
    processing_certify_ak_response = false;
    return COAP_RESPONSE_OK;
}

/**
 * @brief Send req_buf (may be NULL/0 for an empty body) as a CoAP FETCH
 * request to ip_address:port/uri_path, registering response_handler, and
 * block until libcoap has nothing left pending for the exchange, an I/O
 * error occurs, or verifier_response_timeout is exceeded.
 *
 * Factors out the create-context/create-session/build-and-send-PDU/wait-
 * for-response/tear-down sequence every one-shot RP-as-client exchange in
 * this file repeats (ensure_rp_ak_certificate()'s /certify_ak call,
 * rp_perform_qualification_handshake()'s /qualify and /qualify/submit).
 * response_handler is expected to record the exchange's actual content-
 * level result (parsed data, or a parse failure) in its own dedicated
 * global, the same way coap_certify_ak_response_handler() does for
 * certify_ak_rc -- this function only reports whether the CoAP transport
 * itself completed, not whether the response's content was valid.
 *
 * @param[in,out] processing_flag caller's own dedicated "response handler
 * is currently running" flag (e.g. &processing_qualify_response), reset to
 * false here before sending -- same flag every response handler in this
 * file already toggles true/false around its own body.
 */
static CHARRA_RC rp_coap_fetch(const char* ip_address, unsigned int port,
        const char* uri_path, const uint8_t* req_buf, uint32_t req_buf_len,
        coap_response_handler_t response_handler, bool* processing_flag) {
    CHARRA_RC result = CHARRA_RC_ERROR;
    coap_context_t* coap_context = NULL;
    coap_session_t* coap_session = NULL;
    coap_optlist_t* coap_options = NULL;

    if ((coap_context = charra_coap_new_context(true)) == NULL) {
        charra_log_error(
                "[" LOG_NAME "] Cannot create CoAP context for /%s.", uri_path);
        return CHARRA_RC_COAP_ERROR;
    }
    coap_register_response_handler(coap_context, response_handler);

    if ((coap_session = charra_coap_new_client_session(
                 coap_context, ip_address, port, COAP_PROTO_UDP)) == NULL) {
        charra_log_error(
                "[" LOG_NAME "] Cannot create /%s client session.", uri_path);
        charra_free_if_not_null_ex(coap_context, coap_free_context);
        return CHARRA_RC_COAP_ERROR;
    }

    uint8_t coap_mediatype_cbor_buf[4] = {0};
    unsigned int coap_mediatype_cbor_buf_len = coap_encode_var_safe(
            coap_mediatype_cbor_buf, sizeof(coap_mediatype_cbor_buf),
            COAP_MEDIATYPE_APPLICATION_CBOR);
    coap_insert_optlist(&coap_options,
            coap_new_optlist(COAP_OPTION_URI_PATH, strlen(uri_path),
                    (const uint8_t*)uri_path));
    coap_insert_optlist(&coap_options,
            coap_new_optlist(COAP_OPTION_CONTENT_TYPE,
                    coap_mediatype_cbor_buf_len, coap_mediatype_cbor_buf));

    coap_pdu_t* pdu = charra_coap_new_request(coap_session,
            COAP_MESSAGE_TYPE_CON, COAP_REQUEST_FETCH, &coap_options, req_buf,
            req_buf_len);
    if (pdu == NULL) {
        charra_log_error(
                "[" LOG_NAME "] Cannot create /%s request PDU.", uri_path);
        charra_free_if_not_null_ex(coap_options, coap_delete_optlist);
        charra_free_if_not_null_ex(coap_session, coap_session_release);
        charra_free_if_not_null_ex(coap_context, coap_free_context);
        return CHARRA_RC_ERROR;
    }

    coap_fixed_point_t coap_timeout = {verifier_response_timeout, 0};
    coap_session_set_ack_timeout(coap_session, coap_timeout);

    if (coap_send_large(coap_session, pdu) == COAP_INVALID_MID) {
        charra_log_error("[" LOG_NAME "] Cannot send /%s request.", uri_path);
        charra_free_if_not_null_ex(coap_options, coap_delete_optlist);
        charra_free_if_not_null_ex(coap_session, coap_session_release);
        charra_free_if_not_null_ex(coap_context, coap_free_context);
        return CHARRA_RC_COAP_ERROR;
    }

    *processing_flag = false;
    uint16_t response_wait_time = 0;
    int coap_io_process_time = -1;
    result = CHARRA_RC_SUCCESS;
    while (!(*processing_flag) && coap_io_pending(coap_context)) {
        if ((coap_io_process_time = coap_io_process(
                     coap_context, COAP_IO_PROCESS_TIME_MS)) == -1) {
            charra_log_error(
                    "[" LOG_NAME "] Error during CoAP I/O processing for /%s.",
                    uri_path);
            result = CHARRA_RC_COAP_ERROR;
            break;
        }
        response_wait_time += coap_io_process_time;
        if (response_wait_time >= (verifier_response_timeout * 1000)) {
            charra_log_error(
                    "[" LOG_NAME "] Timeout waiting for /%s response.",
                    uri_path);
            result = CHARRA_RC_TIMEOUT;
            break;
        }
    }

    charra_free_if_not_null_ex(coap_options, coap_delete_optlist);
    charra_free_if_not_null_ex(coap_session, coap_session_release);
    charra_free_if_not_null_ex(coap_context, coap_free_context);
    return result;
}

static coap_response_t coap_qualify_response_handler(
        coap_session_t* session CHARRA_UNUSED,
        const coap_pdu_t* sent CHARRA_UNUSED, const coap_pdu_t* received,
        const coap_mid_t mid CHARRA_UNUSED) {
    processing_qualify_response = true;

    int coap_r = 0;
    size_t data_len = 0;
    const uint8_t* data = NULL;
    size_t data_offset = 0;
    size_t data_total_len = 0;
    if ((coap_r = coap_get_data_large(
                 received, &data_len, &data, &data_offset, &data_total_len)) ==
            0) {
        charra_log_error(
                "[" LOG_NAME "] /qualify: Could not get CoAP PDU data.");
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

cleanup:
    processing_qualify_response = false;
    return COAP_RESPONSE_OK;
}

static coap_response_t coap_qualify_submit_response_handler(
        coap_session_t* session CHARRA_UNUSED,
        const coap_pdu_t* sent CHARRA_UNUSED, const coap_pdu_t* received,
        const coap_mid_t mid CHARRA_UNUSED) {
    processing_qualify_submit_response = true;

    qualify_submit_qualified =
            coap_pdu_get_code(received) == COAP_RESPONSE_CODE_CONTENT;

    /* body is just a human-readable message (see coap_qualify_submit_
     * handler() in verifier.c) -- logged for visibility, not parsed */
    size_t data_len = 0;
    const uint8_t* data = NULL;
    size_t data_offset = 0;
    size_t data_total_len = 0;
    if (coap_get_data_large(received, &data_len, &data, &data_offset,
                &data_total_len) != 0) {
        charra_log_info("[" LOG_NAME "] /qualify/submit: Verifier says: %.*s",
                (int)data_len, (const char*)data);
    }

    processing_qualify_submit_response = false;
    return COAP_RESPONSE_OK;
}

static CHARRA_RC rp_perform_qualification_handshake(
        const verifier_info* verifier) {
    if (!rp_identity_ready) {
        charra_log_error(
                "[" LOG_NAME "] Cannot run qualification handshake: RP AK "
                "not provisioned yet.");
        return CHARRA_RC_ERROR;
    }

    charra_log_info(
            "[" LOG_NAME "]  +------------ RP Qualification --------------+");

    CHARRA_RC result = CHARRA_RC_ERROR;
    uint8_t* redacted_log = NULL;
    uint32_t redacted_log_len = 0;

    /* --- 1. fetch a fresh challenge --- */
    qualify_response_rc = CHARRA_RC_ERROR;
    result = rp_coap_fetch(verifier->ip_address, verifier->port_number,
            "qualify", NULL, 0, coap_qualify_response_handler,
            &processing_qualify_response);
    if (result != CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] /qualify request failed.");
        return result;
    }
    if (qualify_response_rc != CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] /qualify response invalid.");
        return qualify_response_rc;
    }
    charra_log_info("[" LOG_NAME "] Received a %u-byte challenge log.",
            qualify_challenge_log_len);

    /* --- 2. redact it with the exact same pipeline real evidence uses --- */
    result = charra_sdk_redact_ima_log(qualify_challenge_log,
            qualify_challenge_log_len, &redacted_log, &redacted_log_len);
    if (result != CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Could not redact the qualification "
                         "challenge log.");
        goto done;
    }

    /* --- 3. replay the redacted log into its PCR digest --- */
    uint8_t submitted_pcr_digest[TPM2_SHA256_DIGEST_SIZE] = {0};
    result = charra_replay_ima_log(redacted_log, redacted_log_len,
            CHARRA_IMA_PCR_INDEX, submitted_pcr_digest);
    if (result != CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Could not replay the redacted "
                         "challenge log.");
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
        charra_log_error("[" LOG_NAME "] Could not open TPM connection to "
                         "sign the qualification PCR digest.");
        goto done;
    }
    Esys_Free(sign_ak_name);

    result = charra_rp_key_mgr_sign(sign_esys_ctx, sign_ak_handle,
            submitted_pcr_digest, sizeof(submitted_pcr_digest), rp_signature);

    Esys_FlushContext(sign_esys_ctx, sign_ak_handle);
    Esys_FlushContext(sign_esys_ctx, sign_ek_handle);
    Esys_Finalize(&sign_esys_ctx);
    Tss2_TctiLdr_Finalize(&sign_tcti_ctx);
    pthread_mutex_unlock(&rp_tpm_mutex);

    if (result != CHARRA_RC_SUCCESS) {
        charra_log_error(
                "[" LOG_NAME "] Could not sign the qualification PCR "
                "digest.");
        goto done;
    }

    /* --- 5. submit --- */
    msg_qualify_submit_request_dto submit_req = {
            .submitted_redacted_log_len = redacted_log_len,
            .submitted_redacted_log = redacted_log,
            .rp_signature_len = sizeof(rp_signature),
            .rp_public_key_len = rp_public_key_der_len,
            .ak_certificate_rp_len = rp_ak_cert_der_len,
            .ak_certificate_rp = rp_ak_cert_der,
    };
    memcpy(submit_req.submitted_pcr_digest, submitted_pcr_digest,
            sizeof(submitted_pcr_digest));
    memcpy(submit_req.rp_signature, rp_signature, sizeof(rp_signature));
    memcpy(submit_req.rp_public_key, rp_public_key_der, rp_public_key_der_len);

    uint8_t* submit_buf = NULL;
    uint32_t submit_buf_len = 0;
    result = charra_marshal_qualify_submit_request(
            &submit_req, &submit_buf_len, &submit_buf);
    if (result != CHARRA_RC_SUCCESS) {
        charra_log_error(
                "[" LOG_NAME "] Could not marshal /qualify/submit request.");
        goto done;
    }

    result = rp_coap_fetch(verifier->ip_address, verifier->port_number,
            "qualify_submit", submit_buf, submit_buf_len,
            coap_qualify_submit_response_handler,
            &processing_qualify_submit_response);
    charra_free_if_not_null(submit_buf);
    if (result != CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] /qualify/submit request failed.");
        goto done;
    }

    if (qualify_submit_qualified) {
        charra_log_info("[" LOG_NAME "] |  RP QUALIFIED              |");
        result = CHARRA_RC_SUCCESS;
    } else {
        charra_log_error(
                "[" LOG_NAME "] |  RP NOT QUALIFIED -- expected for now, "
                "see CHARRA_V2_NOTES.md (salted redaction vs. byte-exact "
                "golden-log check)  |");
        result = CHARRA_RC_VERIFICATION_FAILED;
    }

done:
    charra_free_if_not_null(qualify_challenge_log);
    qualify_challenge_log = NULL;
    qualify_challenge_log_len = 0;
    charra_free_if_not_null(redacted_log);
    return result;
}

/**
 * @brief Open a fresh TPM connection, recreate RP's EK (deterministic --
 * see charra_rp_key_mgr_create_ek()), and load the AK from its persisted
 * public/private blobs. Caller must hold rp_tpm_mutex and Esys_Finalize()/
 * Tss2_TctiLdr_Finalize() the returned contexts when done -- this is the
 * short-lived-connection building block every TPM operation past initial
 * AK creation uses (provisioning's ActivateCredential step, and later
 * every Quote_r signing), so no single RP operation holds the TPM
 * simulator's one connection slot for longer than that operation itself
 * needs. See rp_tpm_mutex's own comment for why this matters.
 */
static CHARRA_RC rp_open_tpm_and_load_ak(ESYS_CONTEXT** esys_ctx_out,
        TSS2_TCTI_CONTEXT** tcti_ctx_out, ESYS_TR* ek_handle_out,
        ESYS_TR* ak_handle_out, TPM2B_NAME** ak_name_out) {
    TSS2_RC tss_r = 0;
    if ((tss_r = Tss2_TctiLdr_Initialize(getenv("CHARRA_TCTI"), tcti_ctx_out)) !=
            TSS2_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Tss2_TctiLdr_Initialize.");
        return CHARRA_RC_ERROR;
    }
    if ((tss_r = Esys_Initialize(esys_ctx_out, *tcti_ctx_out, NULL)) !=
            TSS2_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Esys_Initialize.");
        Tss2_TctiLdr_Finalize(tcti_ctx_out);
        return CHARRA_RC_ERROR;
    }

    TPM2B_PUBLIC* ek_public = NULL;
    CHARRA_RC result = charra_rp_key_mgr_create_ek(
            *esys_ctx_out, ek_handle_out, &ek_public);
    Esys_Free(ek_public);
    if (result != CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Could not recreate RP's EK.");
        goto error;
    }

    TPM2B_PUBLIC ak_public = {0};
    TPM2B_PRIVATE ak_private = {0};
    if ((result = charra_rp_key_mgr_load_public(
                 rp_ak_public_path, &ak_public)) != CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Could not load AK public key.");
        goto error;
    }
    if ((result = charra_rp_key_mgr_load_private(
                 rp_ak_private_path, &ak_private)) != CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Could not load AK private area.");
        goto error;
    }
    if ((result = charra_rp_key_mgr_load_ak(*esys_ctx_out, *ek_handle_out,
                 &ak_public, &ak_private, ak_handle_out, ak_name_out)) !=
            CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Could not load RP's AK.");
        goto error;
    }
    return CHARRA_RC_SUCCESS;

error:
    /* Esys_Finalize() only tears down client-side state -- it does NOT
     * send TPM2_FlushContext, so any handle that did get loaded before the
     * failure (e.g. the EK, if only the AK's load failed) would otherwise
     * sit orphaned in the TPM's small transient-object table until the
     * simulator itself is restarted. Flush anything that's actually valid
     * before closing. */
    if (*ek_handle_out != ESYS_TR_NONE) {
        Esys_FlushContext(*esys_ctx_out, *ek_handle_out);
    }
    if (*ak_handle_out != ESYS_TR_NONE) {
        Esys_FlushContext(*esys_ctx_out, *ak_handle_out);
    }
    Esys_Finalize(esys_ctx_out);
    Tss2_TctiLdr_Finalize(tcti_ctx_out);
    return result;
}

static void invalidate_cached_rp_ak_certificate(void) {
    remove(rp_ak_public_path);
    remove(rp_ak_private_path);
    remove(rp_ak_cert_path);
    charra_free_if_not_null(rp_ak_cert_der);
    rp_ak_cert_der = NULL;
    rp_ak_cert_der_len = 0;
    rp_public_key_der_len = 0;
    rp_identity_ready = false;
}

static CHARRA_RC ensure_rp_ak_certificate(
        const char* verifier_host, unsigned int verifier_port) {
    if (rp_identity_ready) {
        return CHARRA_RC_SUCCESS;
    }

    charra_log_info(
            "[" LOG_NAME "]  +------------ RP TPM Identity --------------+");

    CHARRA_RC result = CHARRA_RC_ERROR;
    TPM2B_PUBLIC ak_public = {0};
    uint8_t* ek_cert_der = NULL;
    size_t ek_cert_der_len = 0;
    bool ek_cert_der_from_read_file = false;

    bool cached = charra_io_file_exists(rp_ak_public_path) ==
                    CHARRA_RC_SUCCESS &&
            charra_io_file_exists(rp_ak_private_path) == CHARRA_RC_SUCCESS &&
            charra_io_file_exists(rp_ak_cert_path) == CHARRA_RC_SUCCESS;

    if (cached) {
        /* No TPM needed at all here: the DER export below is pure math over
         * the public key, and the cert is just a file read. The AK itself
         * is only ever loaded into the TPM when actually signing (see
         * rp_open_tpm_and_load_ak(), called from charra_rp_build_evidence_
         * message()). */
        charra_log_info(
                "[" LOG_NAME "] Reloading previously provisioned RP AK.");
        if ((result = charra_rp_key_mgr_load_public(
                     rp_ak_public_path, &ak_public)) != CHARRA_RC_SUCCESS) {
            charra_log_error("[" LOG_NAME "] Could not load cached AK public "
                             "key.");
            goto error;
        }

        char* cert_buf = NULL;
        size_t cert_buf_len = 0;
        if ((result = charra_io_read_file(
                     rp_ak_cert_path, &cert_buf, &cert_buf_len)) !=
                CHARRA_RC_SUCCESS) {
            charra_log_error(
                    "[" LOG_NAME "] Could not read cached AK certificate.");
            goto error;
        }
        rp_ak_cert_der = malloc(cert_buf_len);
        if (rp_ak_cert_der == NULL) {
            charra_io_free_file_buffer(&cert_buf);
            result = CHARRA_RC_ERROR;
            goto error;
        }
        memcpy(rp_ak_cert_der, cert_buf, cert_buf_len);
        rp_ak_cert_der_len = (uint32_t)cert_buf_len;
        charra_io_free_file_buffer(&cert_buf);
    } else {
        charra_log_info(
                "[" LOG_NAME "] No cached RP AK -- provisioning a new one "
                "via /certify_ak.");

        /* --- TPM session #1 (mutex-held): create EK + AK, persist blobs,
         * then CLOSE the connection before the /certify_ak round trip
         * below -- critical, not cosmetic: the Verifier's own /certify_ak
         * handler needs its own TPM connection to complete
         * Esys_MakeCredential, and the dev TPM simulator accepts only one
         * client connection at a time. Holding this connection open across
         * the CoAP wait deadlocks the Verifier's response indefinitely
         * (confirmed directly while developing this: killing an RP stuck
         * here immediately unblocked the Verifier's handler, which had
         * been sitting mid-MakeCredential the whole time). --------------
         */
        pthread_mutex_lock(&rp_tpm_mutex);

        ESYS_CONTEXT* esys_ctx = NULL;
        TSS2_TCTI_CONTEXT* tcti_ctx = NULL;
        ESYS_TR ek_handle = ESYS_TR_NONE;
        ESYS_TR ak_handle = ESYS_TR_NONE;
        TPM2B_NAME* ak_name = NULL;
        TPM2B_PUBLIC* ek_public = NULL;
        TPM2B_PRIVATE ak_private = {0};

        TSS2_RC tss_r = 0;
        if ((tss_r = Tss2_TctiLdr_Initialize(
                     getenv("CHARRA_TCTI"), &tcti_ctx)) != TSS2_RC_SUCCESS) {
            charra_log_error("[" LOG_NAME "] Tss2_TctiLdr_Initialize.");
            pthread_mutex_unlock(&rp_tpm_mutex);
            goto error;
        }
        if ((tss_r = Esys_Initialize(&esys_ctx, tcti_ctx, NULL)) !=
                TSS2_RC_SUCCESS) {
            charra_log_error("[" LOG_NAME "] Esys_Initialize.");
            Tss2_TctiLdr_Finalize(&tcti_ctx);
            pthread_mutex_unlock(&rp_tpm_mutex);
            goto error;
        }

        if ((result = charra_rp_key_mgr_create_ek(
                     esys_ctx, &ek_handle, &ek_public)) != CHARRA_RC_SUCCESS) {
            charra_log_error("[" LOG_NAME "] Could not create RP's EK.");
            Esys_Finalize(&esys_ctx);
            Tss2_TctiLdr_Finalize(&tcti_ctx);
            pthread_mutex_unlock(&rp_tpm_mutex);
            goto error;
        }

        /* --- RP's own EK certificate: cached after the first mint, since
         * charra_rp_key_mgr_create_ek() reproduces the same EK every time
         * anyway --------------------------------------------------------- */
        if (charra_io_file_exists(rp_ek_cert_cache_path) == CHARRA_RC_SUCCESS) {
            char* buf = NULL;
            size_t buf_len = 0;
            if ((result = charra_io_read_file(
                         rp_ek_cert_cache_path, &buf, &buf_len)) !=
                    CHARRA_RC_SUCCESS) {
                charra_log_error(
                        "[" LOG_NAME "] Could not read cached EK certificate.");
                Esys_Free(ek_public);
                Esys_FlushContext(esys_ctx, ek_handle);
                Esys_Finalize(&esys_ctx);
                Tss2_TctiLdr_Finalize(&tcti_ctx);
                pthread_mutex_unlock(&rp_tpm_mutex);
                goto error;
            }
            ek_cert_der = (uint8_t*)buf;
            ek_cert_der_len = buf_len;
            ek_cert_der_from_read_file = true;
        } else {
            char* manufacturer_root_der = NULL;
            size_t manufacturer_root_der_len = 0;
            if ((result = charra_io_read_file(manufacturer_root_cert_path,
                         &manufacturer_root_der,
                         &manufacturer_root_der_len)) != CHARRA_RC_SUCCESS) {
                charra_log_error("[" LOG_NAME "] Could not read manufacturer "
                                 "root certificate ('%s').",
                        manufacturer_root_cert_path);
                Esys_Free(ek_public);
                Esys_FlushContext(esys_ctx, ek_handle);
                Esys_Finalize(&esys_ctx);
                Tss2_TctiLdr_Finalize(&tcti_ctx);
                pthread_mutex_unlock(&rp_tpm_mutex);
                goto error;
            }
            mbedtls_x509_crt manufacturer_root_cert;
            mbedtls_x509_crt_init(&manufacturer_root_cert);
            if (mbedtls_x509_crt_parse(&manufacturer_root_cert,
                        (uint8_t*)manufacturer_root_der,
                        manufacturer_root_der_len) != 0) {
                charra_log_error("[" LOG_NAME "] Could not parse "
                                 "manufacturer root certificate.");
                charra_io_free_file_buffer(&manufacturer_root_der);
                result = CHARRA_RC_CRYPTO_ERROR;
                Esys_Free(ek_public);
                Esys_FlushContext(esys_ctx, ek_handle);
                Esys_Finalize(&esys_ctx);
                Tss2_TctiLdr_Finalize(&tcti_ctx);
                pthread_mutex_unlock(&rp_tpm_mutex);
                goto error;
            }
            char issuer_name[256] = {0};
            if (mbedtls_x509_dn_gets(issuer_name, sizeof(issuer_name),
                        &manufacturer_root_cert.subject) <= 0) {
                charra_log_error("[" LOG_NAME "] Could not read manufacturer "
                                 "root subject name.");
                mbedtls_x509_crt_free(&manufacturer_root_cert);
                charra_io_free_file_buffer(&manufacturer_root_der);
                result = CHARRA_RC_CRYPTO_ERROR;
                Esys_Free(ek_public);
                Esys_FlushContext(esys_ctx, ek_handle);
                Esys_Finalize(&esys_ctx);
                Tss2_TctiLdr_Finalize(&tcti_ctx);
                pthread_mutex_unlock(&rp_tpm_mutex);
                goto error;
            }
            mbedtls_x509_crt_free(&manufacturer_root_cert);
            charra_io_free_file_buffer(&manufacturer_root_der);

            uint8_t ek_serial[16] = {0};
            uint32_t ek_cert_der_len_u32 = 0;
            if ((result = charra_crypto_sign_ak_certificate(ek_public,
                         "CN=CHARRA RP EK (test only)", issuer_name,
                         rp_ek_cert_not_before_utc, rp_ek_cert_not_after_utc,
                         manufacturer_root_key_path, &ek_cert_der,
                         &ek_cert_der_len_u32, ek_serial)) !=
                    CHARRA_RC_SUCCESS) {
                charra_log_error(
                        "[" LOG_NAME "] Could not mint RP's EK certificate.");
                Esys_Free(ek_public);
                Esys_FlushContext(esys_ctx, ek_handle);
                Esys_Finalize(&esys_ctx);
                Tss2_TctiLdr_Finalize(&tcti_ctx);
                pthread_mutex_unlock(&rp_tpm_mutex);
                goto error;
            }
            ek_cert_der_len = ek_cert_der_len_u32;
            if ((result = charra_io_write_file(rp_ek_cert_cache_path,
                         ek_cert_der, ek_cert_der_len)) != CHARRA_RC_SUCCESS) {
                charra_log_error(
                        "[" LOG_NAME "] Could not cache RP's EK certificate.");
                Esys_Free(ek_public);
                Esys_FlushContext(esys_ctx, ek_handle);
                Esys_Finalize(&esys_ctx);
                Tss2_TctiLdr_Finalize(&tcti_ctx);
                pthread_mutex_unlock(&rp_tpm_mutex);
                goto error;
            }
        }
        Esys_Free(ek_public);

        /* --- create the AK, persist its blobs -------------------------- */
        TPM2B_PUBLIC* ak_public_p = NULL;
        TPM2B_PRIVATE* ak_private_p = NULL;
        if ((result = charra_rp_key_mgr_create_ak(esys_ctx, ek_handle,
                     &ak_handle, &ak_public_p, &ak_private_p, &ak_name)) !=
                CHARRA_RC_SUCCESS) {
            charra_log_error("[" LOG_NAME "] Could not create RP's AK.");
            Esys_FlushContext(esys_ctx, ek_handle);
            Esys_Finalize(&esys_ctx);
            Tss2_TctiLdr_Finalize(&tcti_ctx);
            pthread_mutex_unlock(&rp_tpm_mutex);
            goto error;
        }
        ak_public = *ak_public_p;
        ak_private = *ak_private_p;
        Esys_Free(ak_public_p);
        Esys_Free(ak_private_p);

        if ((result = charra_rp_key_mgr_save_public(
                     rp_ak_public_path, &ak_public)) != CHARRA_RC_SUCCESS) {
            charra_log_error("[" LOG_NAME "] Could not persist AK public key.");
            Esys_Free(ak_name);
            Esys_FlushContext(esys_ctx, ak_handle);
            Esys_FlushContext(esys_ctx, ek_handle);
            Esys_Finalize(&esys_ctx);
            Tss2_TctiLdr_Finalize(&tcti_ctx);
            pthread_mutex_unlock(&rp_tpm_mutex);
            goto error;
        }
        if ((result = charra_rp_key_mgr_save_private(
                     rp_ak_private_path, &ak_private)) != CHARRA_RC_SUCCESS) {
            charra_log_error(
                    "[" LOG_NAME "] Could not persist AK private area.");
            Esys_Free(ak_name);
            Esys_FlushContext(esys_ctx, ak_handle);
            Esys_FlushContext(esys_ctx, ek_handle);
            Esys_Finalize(&esys_ctx);
            Tss2_TctiLdr_Finalize(&tcti_ctx);
            pthread_mutex_unlock(&rp_tpm_mutex);
            goto error;
        }

        /* --- /certify_ak request, built now while ak_name is still valid,
         * sent AFTER the TPM connection below is closed -------------- */
        msg_certify_ak_request_dto req = {0};
        req.ek_certificate = ek_cert_der;
        req.ek_certificate_len = (uint32_t)ek_cert_der_len;
        req.ak_public_key_len = sizeof(ak_public);
        memcpy(req.ak_public_key, &ak_public, sizeof(ak_public));
        /* raw struct copy, same convention ak_public_key above and
         * tpm2_public_key elsewhere in this codebase use -- the receiving
         * end casts the bytes straight back to TPM2B_NAME*, so the buffer
         * must hold the full struct layout, not just its logical length */
        req.ak_name_len = sizeof(*ak_name);
        memcpy(req.ak_name, ak_name, sizeof(*ak_name));
        Esys_Free(ak_name);

        /* session #1 done -- release the TPM connection before waiting on
         * the Verifier, which needs its own turn with it. Esys_Finalize()
         * alone does NOT flush these from the TPM's own (small) transient-
         * object table -- it only tears down client-side state -- so both
         * handles must be explicitly flushed first, or they sit orphaned
         * on the TPM until it's restarted. */
        Esys_FlushContext(esys_ctx, ak_handle);
        Esys_FlushContext(esys_ctx, ek_handle);
        Esys_Finalize(&esys_ctx);
        Tss2_TctiLdr_Finalize(&tcti_ctx);
        pthread_mutex_unlock(&rp_tpm_mutex);

        uint8_t* req_buf = NULL;
        uint32_t req_buf_len = 0;
        if ((result = charra_marshal_certify_ak_request(
                     &req, &req_buf_len, &req_buf)) != CHARRA_RC_SUCCESS) {
            charra_log_error(
                    "[" LOG_NAME "] Could not marshal /certify_ak request.");
            goto error;
        }

        coap_context_t* coap_context = NULL;
        coap_session_t* coap_session = NULL;
        coap_optlist_t* coap_options = NULL;
        if ((coap_context = charra_coap_new_context(true)) == NULL) {
            charra_log_error("[" LOG_NAME "] Cannot create CoAP context.");
            charra_free_if_not_null(req_buf);
            result = CHARRA_RC_COAP_ERROR;
            goto error;
        }
        coap_register_response_handler(
                coap_context, coap_certify_ak_response_handler);
        if ((coap_session = charra_coap_new_client_session(coap_context,
                     verifier_host, verifier_port, COAP_PROTO_UDP)) == NULL) {
            charra_log_error(
                    "[" LOG_NAME "] Cannot create /certify_ak client session.");
            charra_free_if_not_null(req_buf);
            charra_free_if_not_null_ex(coap_context, coap_free_context);
            result = CHARRA_RC_COAP_ERROR;
            goto error;
        }

        uint8_t coap_mediatype_cbor_buf[4] = {0};
        unsigned int coap_mediatype_cbor_buf_len = coap_encode_var_safe(
                coap_mediatype_cbor_buf, sizeof(coap_mediatype_cbor_buf),
                COAP_MEDIATYPE_APPLICATION_CBOR);
        coap_insert_optlist(&coap_options,
                coap_new_optlist(COAP_OPTION_URI_PATH, 10,
                        (const uint8_t*)"certify_ak"));
        coap_insert_optlist(&coap_options,
                coap_new_optlist(COAP_OPTION_CONTENT_TYPE,
                        coap_mediatype_cbor_buf_len, coap_mediatype_cbor_buf));

        coap_pdu_t* pdu = charra_coap_new_request(coap_session,
                COAP_MESSAGE_TYPE_CON, COAP_REQUEST_FETCH, &coap_options,
                req_buf, req_buf_len);
        if (pdu == NULL) {
            charra_log_error(
                    "[" LOG_NAME "] Cannot create /certify_ak request PDU.");
            charra_free_if_not_null(req_buf);
            charra_free_if_not_null_ex(coap_options, coap_delete_optlist);
            charra_free_if_not_null_ex(coap_session, coap_session_release);
            charra_free_if_not_null_ex(coap_context, coap_free_context);
            result = CHARRA_RC_ERROR;
            goto error;
        }

        coap_fixed_point_t coap_timeout = {verifier_response_timeout, 0};
        coap_session_set_ack_timeout(coap_session, coap_timeout);

        if (coap_send_large(coap_session, pdu) == COAP_INVALID_MID) {
            charra_log_error(
                    "[" LOG_NAME "] Cannot send /certify_ak request.");
            charra_free_if_not_null(req_buf);
            charra_free_if_not_null_ex(coap_options, coap_delete_optlist);
            charra_free_if_not_null_ex(coap_session, coap_session_release);
            charra_free_if_not_null_ex(coap_context, coap_free_context);
            result = CHARRA_RC_COAP_ERROR;
            goto error;
        }

        uint16_t response_wait_time = 0;
        int coap_io_process_time = -1;
        certify_ak_rc = CHARRA_RC_ERROR;
        while (!processing_certify_ak_response &&
                coap_io_pending(coap_context)) {
            if ((coap_io_process_time = coap_io_process(
                         coap_context, COAP_IO_PROCESS_TIME_MS)) == -1) {
                charra_log_error(
                        "[" LOG_NAME "] Error during CoAP I/O processing.");
                result = CHARRA_RC_COAP_ERROR;
                break;
            }
            response_wait_time += coap_io_process_time;
            if (response_wait_time >= (verifier_response_timeout * 1000)) {
                charra_log_error(
                        "[" LOG_NAME "] Timeout waiting for /certify_ak "
                        "response.");
                result = CHARRA_RC_TIMEOUT;
                break;
            }
        }

        charra_free_if_not_null(req_buf);
        charra_free_if_not_null_ex(coap_options, coap_delete_optlist);
        charra_free_if_not_null_ex(coap_session, coap_session_release);
        charra_free_if_not_null_ex(coap_context, coap_free_context);

        if (certify_ak_rc != CHARRA_RC_SUCCESS) {
            charra_log_error("[" LOG_NAME "] /certify_ak did not complete "
                             "successfully.");
            result = certify_ak_rc;
            goto error;
        }

        /* --- TPM session #2 (mutex-held): recover the AES key via
         * ActivateCredential, then decrypt the AK certificate ----------- */
        pthread_mutex_lock(&rp_tpm_mutex);
        ESYS_TR ek_handle2 = ESYS_TR_NONE;
        ESYS_TR ak_handle2 = ESYS_TR_NONE;
        TPM2B_NAME* ak_name2 = NULL;
        if ((result = rp_open_tpm_and_load_ak(&esys_ctx, &tcti_ctx,
                     &ek_handle2, &ak_handle2, &ak_name2)) !=
                CHARRA_RC_SUCCESS) {
            charra_log_error("[" LOG_NAME "] Could not reopen TPM connection "
                             "for ActivateCredential.");
            pthread_mutex_unlock(&rp_tpm_mutex);
            goto error;
        }
        Esys_Free(ak_name2);

        TPM2B_DIGEST* credential = NULL;
        if ((result = charra_rp_key_mgr_activate_credential(esys_ctx,
                     ak_handle2, ek_handle2,
                     (TPM2B_ID_OBJECT*)certify_ak_response.credential_blob,
                     (TPM2B_ENCRYPTED_SECRET*)
                             certify_ak_response.wrapped_secret,
                     &credential)) != CHARRA_RC_SUCCESS) {
            charra_log_error(
                    "[" LOG_NAME "] ActivateCredential failed -- this AK is "
                    "not genuinely bound to this EK, or the TPM rejected "
                    "the request.");
            Esys_FlushContext(esys_ctx, ak_handle2);
            Esys_FlushContext(esys_ctx, ek_handle2);
            Esys_Finalize(&esys_ctx);
            Tss2_TctiLdr_Finalize(&tcti_ctx);
            pthread_mutex_unlock(&rp_tpm_mutex);
            goto error;
        }
        Esys_FlushContext(esys_ctx, ak_handle2);
        Esys_FlushContext(esys_ctx, ek_handle2);
        Esys_Finalize(&esys_ctx);
        Tss2_TctiLdr_Finalize(&tcti_ctx);
        pthread_mutex_unlock(&rp_tpm_mutex);

        charra_log_info("[" LOG_NAME "] ActivateCredential recovered a "
                        "%u-byte credential; decrypting %u-byte AK "
                        "certificate ciphertext.",
                credential->size, certify_ak_response.ak_certificate_len);
        charra_print_hex(CHARRA_LOG_INFO, credential->size, credential->buffer,
                "[DEBUG] recovered credential = 0x", "\n", false);
        charra_print_hex(CHARRA_LOG_INFO,
                sizeof(certify_ak_response.aes_gcm_nonce),
                certify_ak_response.aes_gcm_nonce, "[DEBUG] received nonce = 0x",
                "\n", false);
        charra_print_hex(CHARRA_LOG_INFO,
                sizeof(certify_ak_response.aes_gcm_tag),
                certify_ak_response.aes_gcm_tag, "[DEBUG] received tag = 0x",
                "\n", false);
        if ((result = charra_crypto_aes256gcm_decrypt(credential->buffer,
                     certify_ak_response.ak_certificate,
                     certify_ak_response.ak_certificate_len,
                     certify_ak_response.aes_gcm_nonce,
                     certify_ak_response.aes_gcm_tag, &rp_ak_cert_der)) !=
                CHARRA_RC_SUCCESS) {
            charra_log_error(
                    "[" LOG_NAME "] Could not decrypt AK certificate "
                    "(charra_r=%d).",
                    result);
            Esys_Free(credential);
            goto error;
        }
        rp_ak_cert_der_len = certify_ak_response.ak_certificate_len;
        Esys_Free(credential);

        if ((result = charra_io_write_file(rp_ak_cert_path, rp_ak_cert_der,
                     rp_ak_cert_der_len)) != CHARRA_RC_SUCCESS) {
            charra_log_error(
                    "[" LOG_NAME "] Could not cache AK certificate.");
            goto error;
        }

        charra_log_info("[" LOG_NAME "] RP AK provisioned and certified "
                        "(%u-byte certificate).",
                rp_ak_cert_der_len);
    }

    if ((result = charra_rp_key_mgr_public_key_to_der(&ak_public,
                 rp_public_key_der, sizeof(rp_public_key_der),
                 &rp_public_key_der_len)) != CHARRA_RC_SUCCESS) {
        charra_log_error(
                "[" LOG_NAME "] Could not DER-encode RP's AK public key.");
        goto error;
    }

    rp_identity_ready = true;
    result = CHARRA_RC_SUCCESS;

error:
    if (ek_cert_der_from_read_file) {
        free(ek_cert_der);
    } else {
        charra_free_if_not_null(ek_cert_der);
    }
    return result;
}

static coap_response_t coap_verifier_handler_nonce(coap_session_t* session,
        const coap_pdu_t* sent CHARRA_UNUSED, const coap_pdu_t* received,
        const coap_mid_t mid CHARRA_UNUSED) {
    int* index = coap_session_get_app_data(session);

    size_t data_len = 0;
    const uint8_t* data = NULL;
    size_t data_offset = 0;
    size_t data_total_len = 0;
    if (coap_get_data_large(received, &data_len, &data, &data_offset,
                &data_total_len) == 0) {
        charra_log_error("[" LOG_NAME "] Verifier returned no nonce.");
        goto cleanup;
    }
    if (index == NULL || data_len == 0 ||
            data_len > sizeof(verifier_nonces[0])) {
        charra_log_error("[" LOG_NAME "] Verifier nonce has an unusable "
                         "length (%zu bytes).",
                data_len);
        goto cleanup;
    }

    memcpy(verifier_nonces[*index], data, data_len);
    verifier_nonce_lens[*index] = (uint32_t)data_len;
    charra_log_info("[" LOG_NAME "] Received nonce of %zu bytes from Verifier "
                    "n\u00b0 %d.",
            data_len, *index + 1);

cleanup:
    processing_nonce_response = false;
    return COAP_RESPONSE_OK;
}

static coap_response_t coap_verifier_handler_appraisal(coap_session_t* session,
        const coap_pdu_t* sent CHARRA_UNUSED,
        const coap_pdu_t* received,
        const coap_mid_t mid CHARRA_UNUSED) {
            
    processing_appraisal_response = true;
    int* current_thread_index = coap_session_get_app_data(session);

    rp_ak_cert_rejected[*current_thread_index] = false;

    if (coap_pdu_get_code(received) == COAP_RESPONSE_CODE_UNAUTHORIZED) {
        /* Verifier rejected our AK certificate specifically (see
         * verifier.c's coap_appraise_handler, Step 3a item 1), not the
         * evidence itself -- signal the caller to re-provision via
         * /certify_ak and retry, rather than just recording a failed
         * vote a blind retry could never fix. */
        charra_log_info("[" LOG_NAME "] Verifier n° %d rejected our AK "
                        "certificate as invalid or expired.",
                *current_thread_index + 1);
        rp_ak_cert_rejected[*current_thread_index] = true;
        attestation_results[*current_thread_index] = false;
        goto cleanup;
    }

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

    /* memcmp against the exact sent length, not strcmp on data: data points
     * into the PDU buffer as received (data_len bytes, per
     * coap_add_data_large_response()'s strlen()-based length on the
     * Verifier's side), with no guaranteed NUL terminator past it. */
    if (data_len == strlen(successful_message) &&
            memcmp(data, successful_message, data_len) == 0) {
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
    /* Declared here, not at first use further down, for the same reason as
     * the three above: several earlier goto cleanup jumps in this function
     * would otherwise skip their initializers, leaving cleanup's unconditional
     * charra_free_if_not_null() calls to free() an indeterminate pointer.
     * coap_context_verifier_appraisal/_session_/_options_ used to be
     * declared only right before the appraisal-request section, well after
     * the "Verifier did not supply a nonce" goto cleanup a few lines below
     * this one -- a verifier that timed out on /nonce meant this function
     * jumped straight to cleanup and called coap_free_context()/
     * coap_session_release()/coap_delete_optlist() on garbage stack
     * pointers, corrupting the heap (observed live as "double free or
     * corruption (out)"). Hoisted here for the same reason as the other
     * five. */
    uint8_t* nonce_req_buf = NULL;
    uint32_t nonce_req_buf_len = 0;
    uint8_t* res_buf = NULL;
    uint32_t res_buf_len = 0;
    coap_context_t* coap_context_verifier_appraisal = NULL;
    coap_session_t* coap_session_verifier_appraisal = NULL;
    coap_optlist_t* coap_options_verifier_appraisal = NULL;

    /* RP qualification handshake (/qualify + /qualify/submit) -- Verifier-
     * local state (see rp_perform_qualification_handshake()'s docstring),
     * so unlike AK provisioning this has to run against every verifier,
     * not just verifiers[0]. Not fatal here if it fails: it always does
     * right now, by design -- see CHARRA_V2_NOTES.md -- and
     * coap_appraise_handler() on the Verifier side is the actual
     * enforcement point; a failed handshake here just means the /appraise
     * call below is expected to come back rejected. */
    if (rp_perform_qualification_handshake(&verifier_info) !=
            CHARRA_RC_SUCCESS) {
        charra_log_error(
                "[" LOG_NAME "] Verifier n° %d: qualification handshake did "
                "not succeed; proceeding to /appraise anyway.",
                current_thread_index + 1);
    }

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

    /* Ask the Verifier for a nonce: send the same attestation request RP
     * already built for the Attester (last_request, stable and read-only by
     * now -- populated once in get_evidence(), which always completes
     * before get_attestation_results() spawns this thread). verifier.c's
     * coap_nonce_handler() unmarshals this exact DTO and echoes req.nonce
     * back as the response body -- an empty request body here made it fail
     * unmarshaling immediately ("Could not get CoAP PDU data"), which is
     * why RP never received a nonce and Quote_r could never be built. */
    if ((result = charra_marshal_attestation_request(
                 &last_request, &nonce_req_buf_len, &nonce_req_buf)) !=
            CHARRA_RC_SUCCESS) {
        charra_log_error(
                "[" LOG_NAME "] Could not marshal /nonce request body.");
        goto cleanup;
    }

    coap_session_set_app_data(coap_session, (void*)&current_thread_index);
    coap_register_response_handler(coap_context, coap_verifier_handler_nonce);
    verifier_nonce_lens[current_thread_index] = 0;
    processing_nonce_response = true;
    charra_log_info("[" LOG_NAME "] Requesting a nonce from Verifier n\u00b0 %d ...",
            current_thread_index + 1);


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
                 &coap_options, nonce_req_buf, nonce_req_buf_len)) ==
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
    while (processing_nonce_response && coap_io_pending(coap_context)) {
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

    if (verifier_nonce_lens[current_thread_index] == 0) {
        charra_log_error("[" LOG_NAME "] Verifier n\u00b0 %d did not supply a "
                         "nonce; cannot build Quote_r.",
                current_thread_index + 1);
        result = CHARRA_RC_ERROR;
        goto cleanup;
    }

    /* --- Interaction with the Verifier (sending Quote_r and log_r) * ---------------------------------------------------------------*/
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

    /* CoAP options -- built once, reused for both the first attempt and any
     * AK-certificate-rejection retry below: charra_coap_new_request() only
     * reads from this list, it does not consume or free it. */
    if (coap_insert_optlist(
                &coap_options_verifier_appraisal, coap_new_optlist(COAP_OPTION_URI_PATH, 8,
                                       (const uint8_t*)"appraise")) != 1) {
        charra_log_error("[" LOG_NAME "] Cannot add CoAP option URI_PATH.");
        result = CHARRA_RC_COAP_ERROR;
        goto cleanup;
    }
    if (coap_insert_optlist(&coap_options_verifier_appraisal,
                coap_new_optlist(COAP_OPTION_CONTENT_TYPE,
                                       coap_mediatype_cbor_buf_len_v,
                                       coap_mediatype_cbor_buf_v)) != 1) {
        charra_log_error("[" LOG_NAME "] Cannot add CoAP option CONTENT_TYPE.");
        result = CHARRA_RC_COAP_ERROR;
        goto cleanup;
    }

    coap_fixed_point_t coap_timeout_v = {verifier_response_timeout, 0};
    coap_session_set_ack_timeout(coap_session_verifier_appraisal, coap_timeout_v);
    coap_session_set_app_data(coap_session_verifier_appraisal, &current_thread_index);

    /* Build and marshal the RP evidence message (Quote_r bound to this
     * Verifier's nonce, the RP public key, log_r, the nonce the RP sent to
     * the Attester, and the Attester's evidence minus its raw event log),
     * send it, and wait for the Verifier's response. Retried once if the
     * Verifier's only complaint was our AK certificate being invalid or
     * expired (see coap_verifier_handler_appraisal and verifier.c's Step 3a
     * item 1): re-provision via /certify_ak and try again with a fresh
     * certificate, rather than just recording a failed vote a blind retry
     * could never fix. Not retried for any other kind of failure. */
    for (int attempt = 0; attempt < 2; ++attempt) {
        charra_free_if_not_null(res_buf);
        res_buf = NULL;
        res_buf_len = 0;

        /* Held across the build so a concurrent re-provision (below, same
         * mutex) can't free/replace rp_ak_cert_der/rp_public_key_der while
         * this call is reading them. evidence_generation records which
         * identity this attempt's evidence was built under. */
        pthread_mutex_lock(&rp_ak_reprovision_mutex);
        uint64_t evidence_generation = rp_ak_generation;
        charra_r = charra_rp_build_evidence_message(
                current_thread_index, &res_buf_len, &res_buf);
        pthread_mutex_unlock(&rp_ak_reprovision_mutex);
        if (charra_r != CHARRA_RC_SUCCESS) {
            charra_log_error(
                    "[" LOG_NAME "] Error building RP evidence message.");
            goto error;
        }
        charra_log_info("[" LOG_NAME "] Sending %u bytes of RP evidence to "
                        "Verifier n\u00b0 %d.",
                res_buf_len, current_thread_index + 1);

        coap_pdu_t* pdu_v = NULL;
        if ((pdu_v = charra_coap_new_request(coap_session_verifier_appraisal, COAP_MESSAGE_TYPE_CON, COAP_REQUEST_FETCH,
                     &coap_options_verifier_appraisal, res_buf, res_buf_len)) ==
                NULL) {
            charra_log_error("[" LOG_NAME "] Cannot create request PDU.");
            result = CHARRA_RC_ERROR;
            goto cleanup;
        }

        if (coap_send_large(coap_session_verifier_appraisal, pdu_v) == COAP_INVALID_MID) {
            charra_log_error("[" LOG_NAME "] Cannot send CoAP message.");
            result = CHARRA_RC_COAP_ERROR;
            goto cleanup;
        }

        /* processing and waiting for response */
        processing_appraisal_response = false;
        uint16_t response_wait_time_v = 0;
        while (!processing_appraisal_response && coap_io_pending(coap_context_verifier_appraisal)) {
            int coap_io_process_time_v = coap_io_process(
                    coap_context_verifier_appraisal, COAP_IO_PROCESS_TIME_MS);
            if (coap_io_process_time_v == -1) {
                charra_log_error(
                        "[" LOG_NAME "] Error during CoAP I/O processing.");
                result = CHARRA_RC_COAP_ERROR;
                goto cleanup;
            }
            /* This wait time is not 100% accurate, it only includes the
             * elapsed time inside the coap_io_process function. But should
             * be good enough. */
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

        if (!rp_ak_cert_rejected[current_thread_index] || attempt == 1) {
            break;
        }

        charra_log_info("[" LOG_NAME "] Re-provisioning RP AK certificate "
                        "after rejection by Verifier n\u00b0 %d ...",
                current_thread_index + 1);
        pthread_mutex_lock(&rp_ak_reprovision_mutex);
        CHARRA_RC reprovision_rc = CHARRA_RC_SUCCESS;
        if (rp_ak_generation == evidence_generation) {
            /* Nobody else has refreshed the identity since this attempt's
             * evidence was built -- this thread does it. */
            invalidate_cached_rp_ak_certificate();
            reprovision_rc = ensure_rp_ak_certificate(
                    verifier_info.ip_address, verifier_info.port_number);
            if (reprovision_rc == CHARRA_RC_SUCCESS) {
                rp_ak_generation++;
            }
        }
        /* else: another thread already refreshed it -- fall through to
         * attempt 1, which will build evidence against the now-current
         * (fresh) rp_ak_cert_der/rp_public_key_der. */
        pthread_mutex_unlock(&rp_ak_reprovision_mutex);

        if (reprovision_rc != CHARRA_RC_SUCCESS) {
            charra_log_error("[" LOG_NAME "] Could not re-provision RP AK "
                             "certificate; giving up on Verifier n\u00b0 %d.",
                    current_thread_index + 1);
            break;
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
    charra_free_if_not_null(nonce_req_buf);

    coap_cleanup();

    return NULL;
}

CHARRA_RC get_attestation_results(int num_verifiers) {
    /* Privacy-clean once, before any verifier thread starts: the redaction
     * is randomised, so doing it per thread would give each Verifier a
     * different log_r for the same attestation. */
    if (charra_rp_prepare_evidence() != CHARRA_RC_SUCCESS) {
        charra_rp_release_evidence();
        return CHARRA_RC_ERROR;
    }

    CHARRA_RC result = EXIT_FAILURE;

    charra_log_info("[" LOG_NAME "] Forwarding (redacted) evidence to the verifiers.");
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
    charra_rp_release_evidence();
    return result;

}