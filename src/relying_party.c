#include <coap3/coap.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <tss2/tss2_tpm2_types.h>
#include <pthread.h>

#include "common/charra_log.h"
#include "common/charra_macro.h"
#include "core/charra_dto.h"
#include "core/charra_sdk.h"
#include "util/coap_util.h"
#include "util/crypto_util.h"
#include "util/io_util.h"
#include "rp/rp_attestation.h"
#include "rp/rp_config.h"
#include "rp/rp_evidence.h"
#include "rp/rp_qualification.h"
#include "rp/rp_shared.h"
#include "rp/rp_stats.h"

bool rp_benchmark_mode = false;
unsigned int rp_attestation_interval_s =
        RP_DEFAULT_ATTESTATION_INTERVAL_S;
int rp_num_verifiers = RP_DEFAULT_NUM_VERIFIERS;
/* Optional daemon stop conditions; 0 = unbounded (run until signalled).
 * Both exit through exactly the same path as a signal, so shutdown stays
 * one code path rather than three. */
unsigned int rp_duration_s = 0;
unsigned long rp_max_cycles = 0;

/* logging and coap config (CHARRA_UNUSED comes from rp_shared.h) */
#define LOG_NAME "relying party"
coap_log_t coap_log_level = LOG_INFO;
charra_log_t charra_log_level = CHARRA_LOG_INFO;
bool quit = false;

/* trust manager config */ 
char trust_manager_host[16] = "127.0.0.1"; 
unsigned int trust_manager_port = 6000;
uint16_t trust_manager_response_timeout = 30;  
bool processing_trust_manager_response = false;

/* Sized to MAX_VERIFIERS, not to the benchmark sweep's smaller
 * RP_MAX_SWEEP_VERIFIERS bound, so raising that bound can't silently
 * overflow this array. Every per-Verifier array below is sized the same
 * way for the same reason. */
int verifier_list[MAX_VERIFIERS];
bool attestation_results[MAX_VERIFIERS];
/* Summary-report only: appraisal round-trip latency. */
long verifier_latency_ms[MAX_VERIFIERS];
verifier_info verifiers[MAX_VERIFIERS];
int verifiers_resolved = 0;
/* Was 6000 -- 1000x too large: this feeds libcoap's ack_timeout (seconds),
 * so a stray retransmission could take tens of real seconds to resolve. */
uint16_t verifier_response_timeout = RP_DEFAULT_VERIFIER_TIMEOUT_S;
bool processing_appraisal_response[MAX_VERIFIERS] = {false};

/* attester config (the wait between attestations is --interval, see
 * rp_attestation_interval_s above) */
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

/* --- RP qualification handshake state (/qualify + /qualify/submit) ------
 * See charra_rp_qualification.h. The RP qualifies with the first reachable
 * Verifier; that Verifier records the grant, and its deadline, in the list
 * every Verifier reads (verifier_qualified_rps.h), so all of them honour
 * it until it lapses. The RP then re-qualifies on the first cycle after
 * that. */
uint8_t* qualify_challenge_log = NULL;
uint32_t qualify_challenge_log_len = 0;
/* Salt to redact qualify_challenge_log with, sent alongside it -- see
 * msg_qualify_response_dto's docstring in charra_dto.h for why sharing a
 * salt is safe here (and only here). */
uint8_t qualify_challenge_salt[CHARRA_SDK_PATH_SALT_LEN] = {0};
CHARRA_RC qualify_response_rc = CHARRA_RC_ERROR;
bool processing_qualify_response = false;
bool qualify_submit_qualified = false;
time_t qualify_submit_expires_at = 0;
bool processing_qualify_submit_response = false;
/* When this RP's grant runs out, straight from the Verifier that issued
 * it. The durable record is the Verifier-side shared list; this is the
 * RP's own copy of the deadline, so it can re-qualify BEFORE being voted
 * down -- /appraise never reports why it failed. */
time_t rp_qualified_until = 0;
/* Guards every TPM connection RP opens (provisioning and, later, each
 * Quote_r signing operation): the TPM simulator this dev environment uses
 * accepts only one client connection at a time, and every other binary
 * (attester.c, verifier.c) already follows an open-do-one-thing-close
 * pattern per request rather than holding a connection for a whole
 * process's lifetime. A connection RP held open for its entire run once
 * starved the Verifier's own TPM work indefinitely -- observed
 * directly (killing the RP process immediately unblocked the Verifier).
 * This mutex keeps RP's own accesses serialized and, just as importantly,
 * keeps each one short-lived so other processes get a turn. */
pthread_mutex_t rp_tpm_mutex = PTHREAD_MUTEX_INITIALIZER;
/* Guards /qualify + /qualify/submit's shared response globals (above).
 * The handshake runs at most once per cycle, but the retry-on-rejection
 * path can still reach it from several threads at once: the first through
 * re-qualifies, the rest see the refreshed deadline and short-circuit. */
pthread_mutex_t rp_qualification_mutex = PTHREAD_MUTEX_INITIALIZER;
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

/** @brief SIGINT/SIGTERM handler: requests graceful termination. */
static void handle_sigint(int signum CHARRA_UNUSED) { quit = true; }

/* --- attestation cycle -------------------------------------------------- */

/** Per-cycle phase timings, filled by run_one_attestation_cycle() for the
 * benchmark sweep. Daemon mode passes NULL -- it logs each phase's duration
 * but has no stats file to accumulate them into. */
typedef struct {
    double verifiers;
    double evidence;
    double appraisal;
} rp_cycle_timing;

/**
 * @brief One complete attestation cycle: resolve Verifiers, fetch and
 * locally appraise the Attester's evidence, then privacy-clean and submit
 * to every Verifier.
 *
 * Shared by both modes so they can never drift apart -- the daemon runs
 * exactly the sequence the benchmark measures. The only expensive one-time
 * work left is deriving RP's own signing key and the qualification
 * handshake, both cached for the process's lifetime, so repeat cycles go
 * straight to /attest -> /nonce -> /appraise.
 */
static CHARRA_RC run_one_attestation_cycle(
        int num_verifiers, const char* label, rp_cycle_timing* timing) {
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
    if (timing != NULL) {
        timing->verifiers = duration;
    }
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
    if (timing != NULL) {
        timing->evidence = duration;
    }
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
    if (timing != NULL) {
        timing->appraisal = duration;
    }
    charra_log_info("[" LOG_NAME "] Phase timing: get_attestation_results "
                    "(all Verifiers) took %.3fs.",
            duration);

    return CHARRA_RC_SUCCESS;
}

/* --- main --------------------------------------------------------------- */

int main(int argc, char** argv) {
    /* Process exit status, not a CHARRA_RC: the two enums overlap only by
     * accident (CHARRA_RC_SUCCESS and EXIT_SUCCESS are both 0) and mixing
     * them made benchmark mode return a CHARRA_RC as its exit code. */
    int result = EXIT_SUCCESS;

    signal(SIGINT, handle_sigint);
    /* Same handler for SIGTERM: `timeout`, `docker stop` and systemd all
     * send SIGTERM, and without this they hard-kill the process past the
     * clean shutdown below. */
    signal(SIGTERM, handle_sigint);

    /* Environment first, so an explicit --log-level/-v on the command line
     * overrides it rather than the other way round. */
    charra_log_level_from_str(
            (const char*)getenv("LOG_LEVEL_CHARRA"), &charra_log_level);

    int parse_result = parse_rp_command_line(argc, argv);
    if (parse_result != 0) {
        return (parse_result == 1) ? EXIT_SUCCESS : EXIT_FAILURE;
    }
    charra_log_set_level(charra_log_level);

    /* Before any setup output, so the top of a log file always states which
     * mode this run is in and every value it will use. */
    rp_log_effective_configuration();

    /* No state/ directory to claim: RP's signing key is derived from the
     * TPM on demand, its public half is already named in the read-only
     * trust anchor, and the qualification deadline the Verifier granted is
     * remembered only in memory. Nothing on disk means nothing for a
     * second RP instance to corrupt. */

    if (rp_benchmark_mode) {
        FILE* timing_file = fopen("timings_RP_multi_verifiers.txt", "w");
        if (timing_file == NULL) {
            perror("fopen");
            return EXIT_FAILURE;
        }

        double verifier_durations[NUM_RUNS];
        double evidence_durations[NUM_RUNS];
        double appraisal_durations[NUM_RUNS];
        double total_attestation_durations[NUM_RUNS];

        for (int num_verifiers = 1; num_verifiers <= RP_MAX_SWEEP_VERIFIERS;
                num_verifiers++) {
            /* One discarded warm-up cycle per step, for a reason specific
             * to this sweep: the very first cycle derives RP's signing key
             * from the TPM and runs the qualification handshake, both
             * INSIDE the window timing->appraisal measures. Without this,
             * a step's sample blends steady-state appraisals with one-off
             * setup, and the step-to-step delta reads as per-verifier
             * scaling when part of it is not.
             *
             * The warm-up is not thrown away -- that setup is the expensive
             * TPM path and worth a number of its own, so it is reported
             * separately below rather than blended into the steady state. */
            rp_cycle_timing onboarding = {0};
            {
                char label[32] = {0};
                snprintf(label, sizeof(label), "warm-up (onboarding)");
                if (run_one_attestation_cycle(num_verifiers, label,
                            &onboarding) != CHARRA_RC_SUCCESS) {
                    result = EXIT_FAILURE;
                    break;
                }
            }

            for (int run = 0; run < NUM_RUNS; run++) {
                char label[32] = {0};
                snprintf(label, sizeof(label), "run %d/%d", run + 1, NUM_RUNS);

                rp_cycle_timing timing = {0};
                if (run_one_attestation_cycle(num_verifiers, label, &timing) !=
                        CHARRA_RC_SUCCESS) {
                    result = EXIT_FAILURE;
                    break;
                }
                verifier_durations[run] = timing.verifiers;
                evidence_durations[run] = timing.evidence;
                appraisal_durations[run] = timing.appraisal;
                total_attestation_durations[run] =
                        timing.verifiers + timing.evidence + timing.appraisal;
            }

            if (result == EXIT_FAILURE) {
                break;
            }

            double avg_verifier_duration, stddev_verifier_duration;
            double avg_evidence_duration, stddev_evidence_duration;
            double avg_appraisal_duration, stddev_appraisal_duration;
            double avg_total_attestation_duration,
                    stddev_total_attestation_duration;

            calculate_stats(verifier_durations, NUM_RUNS,
                    &avg_verifier_duration, &stddev_verifier_duration);
            calculate_stats(evidence_durations, NUM_RUNS,
                    &avg_evidence_duration, &stddev_evidence_duration);
            calculate_stats(appraisal_durations, NUM_RUNS,
                    &avg_appraisal_duration, &stddev_appraisal_duration);
            calculate_stats(total_attestation_durations, NUM_RUNS,
                    &avg_total_attestation_duration,
                    &stddev_total_attestation_duration);

            fprintf(timing_file, "Verifiers: %d\n", num_verifiers);
            /* Steady state below; onboarding first so a reader sees which
             * number is which before the averages. */
            fprintf(timing_file,
                    "Onboarding Getting verifiers: %f seconds\n",
                    onboarding.verifiers);
            fprintf(timing_file, "Onboarding Getting evidence: %f seconds\n",
                    onboarding.evidence);
            fprintf(timing_file,
                    "Onboarding Appraising evidence: %f seconds\n",
                    onboarding.appraisal);
            fprintf(timing_file,
                    "Onboarding Total Attestation Duration: %f seconds\n",
                    onboarding.verifiers + onboarding.evidence +
                            onboarding.appraisal);
            fprintf(timing_file,
                    "Average Getting verifiers: %f seconds (stddev: %f)\n",
                    avg_verifier_duration, stddev_verifier_duration);
            fprintf(timing_file,
                    "Average Getting evidence: %f seconds (stddev: %f)\n",
                    avg_evidence_duration, stddev_evidence_duration);
            fprintf(timing_file,
                    "Average Appraising evidence: %f seconds (stddev: %f)\n",
                    avg_appraisal_duration, stddev_appraisal_duration);
            fprintf(timing_file,
                    "Average Total Attestation Duration: %f seconds (stddev: "
                    "%f)\n",
                    avg_total_attestation_duration,
                    stddev_total_attestation_duration);
        }

        fclose(timing_file);
        coap_cleanup();
        return result;
    }

    /* --- daemon mode (default) ----------------------------------------- */
    charra_log_info("[" LOG_NAME "] Entering attestation loop; Ctrl+C (SIGINT) "
                    "to stop.");

    time_t daemon_deadline =
            (rp_duration_s > 0) ? time(NULL) + (time_t)rp_duration_s : 0;
    const char* stop_reason = "signal";
    unsigned long cycle = 0;
    while (!quit) {
        char label[32] = {0};
        snprintf(label, sizeof(label), "cycle %lu", ++cycle);

        /* A failed cycle is not fatal to the daemon: a Verifier or the
         * Attester being briefly unreachable should cost one cycle, not the
         * whole process. The failure is already logged in detail by
         * whichever phase hit it. */
        if (run_one_attestation_cycle(rp_num_verifiers, label, NULL) !=
                CHARRA_RC_SUCCESS) {
            charra_log_error("[" LOG_NAME "] Attestation cycle %lu failed; "
                             "retrying after the usual interval.",
                    cycle);
        }
        if (quit) {
            break;
        }

        if (rp_max_cycles > 0 && cycle >= rp_max_cycles) {
            stop_reason = "--cycles reached";
            break;
        }

        /* Clamp the nap to whatever is left of --duration, so the deadline
         * is honoured to within a second instead of being overshot by up to
         * a full interval. */
        unsigned int nap = rp_attestation_interval_s;
        if (daemon_deadline > 0) {
            time_t remaining = daemon_deadline - time(NULL);
            if (remaining <= 0) {
                stop_reason = "--duration elapsed";
                break;
            }
            if ((time_t)nap > remaining) {
                nap = (unsigned int)remaining;
            }
        }

        charra_log_info("[" LOG_NAME "] Cycle %lu done; sleeping %us until the "
                        "next attestation.",
                cycle, nap);

        /* Nothing happens during the nap: no I/O, no timers. There is
         * nothing to renew -- both signing keys are derived from their
         * TPMs and vouched for by a file written before any of this ran.
         * The sleep is sliced internally so a stop request is acted on
         * within a second rather than at the end of the nap. */
        rp_interruptible_sleep(nap);

        if (daemon_deadline > 0 && time(NULL) >= daemon_deadline) {
            stop_reason = "--duration elapsed";
            break;
        }
    }

    charra_log_info("[" LOG_NAME "] Shutting down (%s) after %lu cycle(s).",
            quit ? "signal" : stop_reason, cycle);

    /* Release the last cycle's evidence buffers so a clean shutdown really
     * is clean -- makes "still reachable" bytes at exit meaningful under
     * valgrind rather than noise. */
    charra_free_attestation_response(&last_response);
    charra_rp_release_evidence();
    coap_cleanup();
    return EXIT_SUCCESS;
}
