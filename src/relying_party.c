#include <coap3/coap.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <tss2/tss2_tpm2_types.h>
#include <pthread.h>

#include "common/charra_log.h"
#include "common/charra_macro.h"
#include "core/charra_dto.h"
#include "util/coap_util.h"
#include "rp/rp_attestation.h"
#include "rp/rp_config.h"
#include "rp/rp_evidence.h"
#include "rp/rp_shared.h"

int rp_num_verifiers = RP_DEFAULT_NUM_VERIFIERS;

/* logging and coap config */
#define LOG_NAME "relying party"
coap_log_t coap_log_level = LOG_INFO;
charra_log_t charra_log_level = CHARRA_LOG_INFO;

/* trust manager config */
char trust_manager_host[16] = "127.0.0.1"; 
unsigned int trust_manager_port = 6000;
uint16_t trust_manager_response_timeout = 30;  
bool processing_trust_manager_response = false;

/* Sized to MAX_VERIFIERS -- the hard cap --verifiers is validated against
 * -- not to rp_num_verifiers, so a smaller run never risks overflowing this
 * array. Every per-Verifier array below is sized the same way for the same
 * reason. */
int verifier_list[MAX_VERIFIERS];
bool attestation_results[MAX_VERIFIERS];
/* Summary-report only: appraisal round-trip latency. */
long verifier_latency_ms[MAX_VERIFIERS];
verifier_info verifiers[MAX_VERIFIERS];
/* Was 6000 -- 1000x too large: this feeds libcoap's ack_timeout (seconds),
 * so a stray retransmission could take tens of real seconds to resolve. */
uint16_t verifier_response_timeout = RP_DEFAULT_VERIFIER_TIMEOUT_S;
bool processing_appraisal_response[MAX_VERIFIERS] = {false};

/* attester config */
bool processing_attestation_response = false;
CHARRA_RC attestation_rc = CHARRA_RC_ERROR;
const bool USE_TPM_FOR_RANDOM_NONCE_GENERATION = false;
uint8_t tpm_pcr_selection[TPM2_MAX_PCRS] = {0, 1, 2, 3, 4, 5, 6, 7, 10};
uint32_t tpm_pcr_selection_len = 9;
/* Same 1000x-too-large bug as verifier_response_timeout above, fixed the
 * same way; a real get_evidence round trip in this dev environment takes
 * ~0.2s, so 6s is generous, not tight. */
uint16_t attester_response_timeout = RP_DEFAULT_ATTESTER_TIMEOUT_S;
bool use_ima_event_log = false;
char* ima_event_log_path = "/sys/kernel/security/ima/binary_runtime_measurements";
bool use_ima_test_log = true;
char* ima_test_log_path = "ima_test_logs.txt";  // path to the IMA test log file for testing purposes

/* RP appraisal config */
char* whitelist_hashes_path = "whitelist-hashes.txt";
char* blacklist_hashes_path = "blacklist-hashes.txt";

/* --- privacy-cleaning state, produced once per attestation -------------- */
/* The redacted log, shared by every verifier thread: the redaction is
 * randomised, so redacting once per verifier would hand each of them a
 * different log_r for the same attestation. There is no PCR_r global to go
 * with it -- the PCR now lives in the RP's TPM, replayed once per cycle by
 * rp_replay_log_into_pcr(). */
uint8_t* rp_log_r = NULL;
uint32_t rp_log_r_len = 0;
/* Quote_r's signing key is RP's TPM-resident unrestricted signing primary.
 * It has no global here on purpose: it is derived fresh for each signature
 * and discarded, so the public key that goes on the wire always comes from
 * the derivation that produced the signature beside it. See
 * rp_signing_key.h.
 *
 * Verifier-agnostic all the same -- the same key signs Quote_r for every
 * Verifier, because the derivation is deterministic, and every Verifier
 * recognises it from the same trust anchor. */

/* Guards every TPM connection RP opens (each Quote_r signing/replay
 * operation): the TPM simulator this dev environment uses accepts only one
 * client connection at a time, and every other binary (attester.c,
 * verifier.c) already follows an open-do-one-thing-close pattern per
 * request rather than holding a connection for a whole process's lifetime.
 * A connection RP held open for its entire run once starved the Verifier's
 * own TPM work indefinitely -- observed directly (killing the RP process
 * immediately unblocked the Verifier). This mutex keeps RP's own accesses
 * serialized and, just as importantly, keeps each one short-lived so other
 * processes get a turn. */
pthread_mutex_t rp_tpm_mutex = PTHREAD_MUTEX_INITIALIZER;
/* Nonces received from each Verifier, indexed by verifier slot. */
uint8_t verifier_nonces[MAX_VERIFIERS][sizeof(TPMU_HA)] = {{0}};
uint32_t verifier_nonce_lens[MAX_VERIFIERS] = {0};
bool processing_nonce_response[MAX_VERIFIERS] = {false};
char attester_host[16] = "127.0.0.1";      // 15 characters for IPv4 plus \0
unsigned int attester_port = 5683;         // default port

/* No CLI reaches these yet -- relying_party has no --psk/--rpk options, so
 * use_psk/use_rpk stay false and rp_coap.c always opens plain UDP. The
 * plumbing below and in rp_coap.c is complete; only the options are missing. */
charra_dtls_config dtls_config = {
        .psk_key = "Charra DTLS Key",
        .psk_identity = "Charra Relying Party",
        .rpk_private_key_path = "keys/relying_party.der",
        .rpk_public_key_path = "keys/relying_party.pub.der",
        .rpk_verify_peer_public_key = true,
};

/* Per-peer, not per-role: the RP is a client to two different servers, so
 * it names both rather than filling in rpk_peer_public_key_path. */
char* dtls_rpk_attester_public_key_path = "keys/attester.pub.der";
char* dtls_rpk_verifier_public_key_path = "keys/verifier.pub.der";

/* --- in-flight message state -------------------------------------------
 * Declared in rp_shared.h; the pipeline modules in src/rp/ fill these in
 * from their CoAP response handlers, which cannot return data. */

msg_attestation_request_dto last_request = {0};
msg_attestation_response_dto last_response = {0};

/* --- attestation cycle -------------------------------------------------- */

/**
 * @brief One complete attestation cycle: resolve Verifiers, fetch and
 * locally appraise the Attester's evidence, then privacy-clean and submit
 * to every Verifier.
 */
static CHARRA_RC run_one_attestation_cycle(
        int num_verifiers, const char* label) {
    CHARRA_RC result = CHARRA_RC_SUCCESS;
    struct timespec start_time, end_time;
    double duration = 0.0;

    for (int i = 0; i < num_verifiers; i++) {
        verifier_list[i] = i + 1;
    }

    /* Clear delimiter between cycles -- without it every cycle's log lines
     * run together with no way to tell where one attempt ends and the next
     * begins. */
    charra_log_info("[" LOG_NAME
                    "] ============================================================");
    charra_log_info("[" LOG_NAME
                    "] Starting new attestation run with %d verifier(s) (%s).",
            num_verifiers, label);
    charra_log_info("[" LOG_NAME
                    "] ============================================================");

    /* Getting verifiers */
    charra_log_info("[" LOG_NAME "] Getting verifiers.");
    clock_gettime(CLOCK_MONOTONIC, &start_time);
    if ((result = get_verifiers(verifier_list, num_verifiers)) !=
            CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Error getting verifiers.");
        return result;
    }
    clock_gettime(CLOCK_MONOTONIC, &end_time);
    duration = (end_time.tv_sec - start_time.tv_sec) +
               (end_time.tv_nsec - start_time.tv_nsec) / 1e9;
    charra_log_info("[" LOG_NAME "] Phase timing: get_verifiers took %.3fs.",
            duration);

    /* Getting evidence */
    charra_log_info("[" LOG_NAME "] Getting evidence.");
    clock_gettime(CLOCK_MONOTONIC, &start_time);
    if ((result = get_evidence()) != CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Error getting evidence.");
        return result;
    }
    clock_gettime(CLOCK_MONOTONIC, &end_time);
    duration = (end_time.tv_sec - start_time.tv_sec) +
               (end_time.tv_nsec - start_time.tv_nsec) / 1e9;
    charra_log_info("[" LOG_NAME "] Phase timing: get_evidence (Attester "
                    "round trip + local appraisal) took %.3fs.",
            duration);

    /* Getting attestation results */
    charra_log_info("[" LOG_NAME "] Getting attestation results.");
    clock_gettime(CLOCK_MONOTONIC, &start_time);
    if ((result = get_attestation_results(num_verifiers)) !=
            CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Error getting attestation results.");
        return result;
    }
    clock_gettime(CLOCK_MONOTONIC, &end_time);
    duration = (end_time.tv_sec - start_time.tv_sec) +
               (end_time.tv_nsec - start_time.tv_nsec) / 1e9;
    charra_log_info("[" LOG_NAME "] Phase timing: get_attestation_results "
                    "(all Verifiers) took %.3fs.",
            duration);

    return CHARRA_RC_SUCCESS;
}

/* --- main --------------------------------------------------------------- */

int main(int argc, char** argv) {
    /* Environment first, so an explicit --log-level/-v on the command line
     * overrides it rather than the other way round. */
    charra_log_level_from_str(
            (const char*)getenv("LOG_LEVEL_CHARRA"), &charra_log_level);

    int parse_result = parse_rp_command_line(argc, argv);
    if (parse_result != 0) {
        return (parse_result == 1) ? EXIT_SUCCESS : EXIT_FAILURE;
    }
    charra_log_set_level(charra_log_level);

    /* Before any setup output, so the top of a log file always states every
     * value this run will use. */
    rp_log_effective_configuration();

    /* No state/ directory to claim: RP's signing key is derived from the
     * TPM on demand and its public half is already named in the read-only
     * trust anchor. Nothing on disk means nothing for a second RP instance
     * to corrupt. */

    CHARRA_RC result = run_one_attestation_cycle(rp_num_verifiers, "run");

    /* Release this cycle's evidence buffers so a clean shutdown really is
     * clean -- makes "still reachable" bytes at exit meaningful under
     * valgrind rather than noise. */
    charra_free_attestation_response(&last_response);
    charra_rp_release_evidence();
    coap_cleanup();

    return (result == CHARRA_RC_SUCCESS) ? EXIT_SUCCESS : EXIT_FAILURE;
}
