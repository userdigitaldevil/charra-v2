#include <arpa/inet.h>
#include <coap3/coap.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <tss2/tss2_tctildr.h>
#include <tss2/tss2_tpm2_types.h>
#include <unistd.h>
#include <pthread.h>
#include <math.h>

#include "common/charra_log.h"
#include "common/charra_macro.h"
#include "core/charra_ak_state.h"
#include "core/charra_dto.h"
#include "core/charra_event_log.h"
#include "core/charra_key_mgr.h"
#include "core/charra_marshaling.h"
#include "core/charra_rim_mgr.h"
#include "core/charra_identity_key_mgr.h"
#include "core/charra_rp_qualification.h"
#include "core/charra_sdk.h"
#include "util/charra_util.h"
#include "util/cli_util.h"
#include "util/coap_util.h"
#include "util/crypto_util.h"
#include "util/io_util.h"
#include "util/tpm2_util.h"
#include "rp/rp_attestation.h"
#include "rp/rp_attester_identity.h"
#include "rp/rp_coap.h"
#include "rp/rp_identity.h"
#include "rp/rp_config.h"
#include "rp/rp_evidence.h"
#include "rp/rp_qualification.h"
#include "rp/rp_shared.h"
#include "rp/rp_stats.h"

/* measurement config. Every verifier count is measured NUM_RUNS times AFTER
 * a discarded warm-up cycle -- see the sweep in main() for why a single
 * sample per step measured the wrong thing. */
#define NUM_RUNS 5

bool rp_benchmark_mode = false;
unsigned int rp_attestation_interval_s =
        RP_DEFAULT_ATTESTATION_INTERVAL_S;
unsigned int rp_qualify_renew_margin_s = RP_DEFAULT_QUALIFY_RENEW_MARGIN_S;
time_t rp_ak_renew_margin_s = RP_DEFAULT_AK_RENEW_MARGIN_S;
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
/* Summary-report only: was_cached (cert reused vs. freshly /certify_ak'd),
 * appraisal round-trip latency, and rejection reason text. */
bool rp_ak_cert_was_cached[MAX_VERIFIERS];
long verifier_latency_ms[MAX_VERIFIERS];
char rejection_reason[MAX_VERIFIERS][128];
verifier_info verifiers[MAX_VERIFIERS];
/* Was 6000 -- 1000x too large: this feeds libcoap's ack_timeout (seconds),
 * so a stray retransmission could take tens of real seconds to resolve. */
uint16_t verifier_response_timeout = 6;  // timeout when waiting for verifier's answer (attestation results) in seconds
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
uint16_t attester_response_timeout = 6;  // timeout when waiting for the attester's answer (evidence) in seconds
bool use_ima_event_log = false;
char* ima_event_log_path = "/sys/kernel/security/ima/binary_runtime_measurements";
bool use_ima_test_log = true;
char* ima_test_log_path = "ima_test_logs.txt";  // path to the IMA test log file for testing purposes

/* RP appraisal config */
char* whitelist_hashes_path = "whitelist-hashes.txt";
char* blacklist_hashes_path = "blacklist-hashes.txt";

/* --- privacy-cleaning state, produced once per attestation -------------- */
/* log_r: the redacted log, and PCR_r: the composite digest over a replay of
 * it. Shared by every verifier thread -- the redaction is randomised, so
 * redacting once per verifier would hand each of them a different log_r for
 * the same attestation. */
uint8_t* rp_log_r = NULL;
uint32_t rp_log_r_len = 0;
uint8_t rp_pcr_r[TPM2_SHA256_DIGEST_SIZE] = {0};
/* Quote_r's signing key is RP's TPM-resident AK (see ensure_rp_ak_keypair()
 * / charra_identity_key_mgr.h) -- created once and reused for the process's
 * lifetime, unlike the throwaway software key this used to be. Verifier-
 * agnostic: the same keypair signs Quote_r for every Verifier -- only its
 * CERTIFICATE differs per Verifier, see rp_ak_cert_der below. */
uint8_t rp_public_key_der[CHARRA_RSA_PUB_KEY_DER_MAX] = {0};
uint32_t rp_public_key_der_len = 0;

/* --- RP TPM identity / /certify_ak config -------------------------------- */
/* Same synthetic test PKI keys/gen-ak-pki.sh generates. manufacturer_root_key
 * is only ever touched here, once, to mint RP's own EK certificate the first
 * time this binary runs against a fresh TPM -- a real device would never
 * hold this key itself (it's normally burned in by the manufacturer at
 * TPM-manufacture time), but there is no real manufacturer in this
 * synthetic PKI, same simplification /certify_ak's own EK-check already
 * documents. */
char* manufacturer_root_cert_path = "keys/manufacturer-root.crt";
char* manufacturer_root_key_path = "keys/manufacturer-root.key";
const char* rp_ek_cert_not_before_utc = "20240101000000";
const char* rp_ek_cert_not_after_utc = "20340101000000";
/* Cache files -- written on first successful provisioning, reused (skipping
 * the /certify_ak round trip) on every later run. All of RP's runtime state
 * lives under state/relying-party/, mkdir'd by main() and split by purpose
 * the same way verifier.c splits state/verifier/:
 *   identity/            the one TPM-resident EK/AK keypair (Verifier-agnostic)
 *   ak-certificates/     per-Verifier AK certificates for that keypair, named
 *                        rp-ak-certificate-<port>.der by
 *                        ensure_rp_ak_certificate()
 *   qualification-cache/ whether RP is still qualified -- a single file,
 *                        since qualifying is Verifier-agnostic */
char* rp_ek_cert_cache_path =
        "state/relying-party/identity/rp-ek-certificate.der";
char* rp_ak_public_path =
        "state/relying-party/identity/rp-ak-public.bin";
char* rp_ak_private_path =
        "state/relying-party/identity/rp-ak-private.bin";
char* rp_qualification_cache_path =
        "state/relying-party/qualification-cache/rp-qualification-until.txt";

/* True once the TPM-resident EK+AK keypair exists and rp_public_key_der is
 * populated -- set once by ensure_rp_ak_keypair(), never per-Verifier. */
bool rp_ak_keypair_ready = false;
/* Per-Verifier AK certificate state: each Verifier independently issues
 * (and tracks the validity/revocation of) its own certificate for RP's one
 * AK public key -- since Verifiers are independent, RP's AK certification
 * has to be too, not a single certificate obtained from verifiers[0] and
 * assumed good everywhere (see CHARRA_V2_NOTES.md). */
bool rp_ak_cert_ready[MAX_VERIFIERS] = {false};
/* When each cached certificate expires, re-checked every call. */
time_t rp_ak_cert_expires_at[MAX_VERIFIERS] = {0};
uint8_t* rp_ak_cert_der[MAX_VERIFIERS] = {NULL};
uint32_t rp_ak_cert_der_len[MAX_VERIFIERS] = {0};
bool processing_certify_ak_response = false;
CHARRA_RC certify_ak_rc = CHARRA_RC_ERROR;

/* --- Attester identity provisioning (/certify_ak_of_attester) -----------
 * Two kinds of CA certify the Attester's AK identity, neither trusting the
 * other's issuance -- see CHARRA_V2_NOTES.md. RP acts as the sole initiator
 * throughout (Attester and every Verifier stay fully passive):
 *   - RP's own CA: one relationship, one certificate, provisioned once per
 *     process by ensure_attester_identity_provisioned() -- the same
 *     one-time shape as ensure_rp_ak_keypair().
 *   - Each Verifier's own CA: a SEPARATE certificate per Verifier, since
 *     Verifiers hold independent CA keys (see verifier.c's
 *     verifier_ca_key_path). ensure_attester_identity_certified_by_verifier()
 *     runs once per Verifier, from that Verifier's own thread.
 * Both live in rp/rp_attester_identity.c. */
char* rp_ca_cert_path = "keys/rp-ca.crt";
char* rp_ca_key_path = "keys/rp-ca.key";
/* Lifetime of the Attester AK certificate RP issues under its own CA,
 * as a duration from issuance rather than a fixed absolute window (see
 * verifier.c's ak_cert_validity_seconds for why). Settable with
 * --attester-ak-validity. Five minutes by default, same reasoning as the
 * Verifier's --ak-validity.
 * Independent of the Verifier's own --ak-validity: that one covers the
 * certificates the Verifier issues, this one only the Attester
 * certificate RP signs itself. Each certificate carries its own
 * notAfter, so the two never need to agree. */
#define RP_AK_CERT_VALIDITY_SECONDS_DEFAULT (5 * 60)
time_t attester_ak_cert_validity_seconds =
        RP_AK_CERT_VALIDITY_SECONDS_DEFAULT;
char* attester_ak_state_file_path =
        "state/relying-party/ak-provisioning/attester-ak-state.txt";
/* The RP-issued leg's cache. Every Verifier-issued leg is cached too, in
 * the same directory as attester-ak-certificate-verifier-<port>.der (see
 * ensure_attester_identity_certified_by_verifier()) -- certificates are
 * public, so RP holds all of them in the clear. What only the Attester's
 * TPM can decrypt is the credential-activation *secret*, not any of these.
 * This file's presence gates ensure_attester_identity_provisioned() (the
 * FETCH + RP-CA leg only); the Verifier legs gate per-Verifier. */
char* attester_ak_cert_rp_cache_path =
        "state/relying-party/attester-ak-certificates/"
        "attester-ak-certificate-rp.der";
bool attester_identity_provisioned = false;
time_t attester_ak_cert_rp_expires_at = 0;
/* ensure_attester_identity_provisioned() used to run exactly once,
 * before any Verifier thread existed, which is why its FETCH globals
 * need no lock of their own. Expiry-driven renewal means a thread can
 * now reach it mid-cycle, so the work is serialised here. Taken before
 * attester_identity_relay_mutex and released before the relay starts,
 * so the two never nest. */
pthread_mutex_t attester_identity_provision_mutex =
        PTHREAD_MUTEX_INITIALIZER;

msg_ak_identity_response_dto ak_identity_response = {0};
CHARRA_RC ak_identity_rc = CHARRA_RC_ERROR;
bool processing_ak_identity_response = false;

/* The Attester's EK certificate + AK public key + AK name, as FETCHed once
 * by ensure_attester_identity_provisioned() -- doesn't vary per Verifier,
 * so every ensure_attester_identity_certified_by_verifier() call reuses
 * this rather than re-FETCHing. Populated once; ek_certificate is this
 * struct's own heap copy, independent of ak_identity_response above. */
msg_ak_identity_response_dto attester_identity_cached = {0};

/* No payload to parse on the DELIVER_RP/DELIVER_VERIFIER leg -- this
 * handler only needs to know the round trip completed, same "ack-only"
 * shape /qualify/submit's response has. */
bool processing_certify_ak_of_attester_deliver_response = false;

/* ACTIVATE leg: the secret the Attester recovered, relayed onward as that
 * Verifier's CONFIRM. */
msg_activate_credential_response_dto activate_credential_response = {0};
CHARRA_RC activate_credential_rc = CHARRA_RC_ERROR;
bool processing_activate_credential_response = false;

/* Per-Verifier Attester AK certificate -- mirrors rp_ak_cert_der/_len/_ready
 * above, same reason: each Verifier issues, and must be sent back, its OWN
 * certificate. charra_rp_build_evidence_message() substitutes it directly
 * rather than relaying whatever the Attester reports, since only RP knows
 * which certificate belongs to which Verifier. Not a trust shortcut: a
 * certificate's validity rests on its CA signature, not on who carried it. */
bool attester_ak_cert_by_verifier_ready[MAX_VERIFIERS] = {false};
time_t attester_ak_cert_by_verifier_expires_at[MAX_VERIFIERS] = {0};
uint8_t* attester_ak_cert_by_verifier_der[MAX_VERIFIERS] = {NULL};
uint32_t attester_ak_cert_by_verifier_der_len[MAX_VERIFIERS] = {0};
/* Guards the Attester-relay round trips in ensure_attester_identity_
 * certified_by_verifier() (ACTIVATE, DELIVER_VERIFIER) against concurrent
 * Verifier threads: both use the shared response globals above, just as
 * /certify_ak's globals need rp_ak_reprovision_mutex. Held for the whole
 * function body rather than per-exchange, because the Attester is
 * single-threaded and serializes these anyway (see attester.c) -- there is
 * no concurrency to preserve here, only correctness to add. */
pthread_mutex_t attester_identity_relay_mutex =
        PTHREAD_MUTEX_INITIALIZER;

/* --- RP qualification handshake state (/qualify + /qualify/submit) ------
 * See charra_rp_qualification.h. The Verifier-side qualification ledger is
 * shared across all Verifier instances (see qualification_state_file_path
 * in verifier.c), so RP runs this handshake only once per validity window,
 * against whichever Verifier is reachable first -- unlike the per-Verifier
 * AK provisioning above. */
uint8_t* qualify_challenge_log = NULL;
uint32_t qualify_challenge_log_len = 0;
/* Salt to redact qualify_challenge_log with, sent alongside it -- see
 * msg_qualify_response_dto's docstring in charra_dto.h for why sharing a
 * salt is safe here (and only here). */
uint8_t qualify_challenge_salt[CHARRA_SDK_PATH_SALT_LEN] = {0};
CHARRA_RC qualify_response_rc = CHARRA_RC_ERROR;
bool processing_qualify_response = false;
bool qualify_submit_qualified = false;
/* Deadline the Verifier reported granting, straight off the wire --
 * authoritative, unlike the old "assume the same constant" approach. */
time_t qualify_submit_expires_at = 0;
bool processing_qualify_submit_response = false;
/* RP's own client-side qualification cache: "qualified until when",
 * persisted to rp-qualification-until.txt so a fresh RP process doesn't
 * redo /qualify + /qualify/submit if a previous run's qualification is
 * still valid. Single value, not per-Verifier, since qualifying is now a
 * one-time, Verifier-agnostic fact. 0 means "unknown/not currently
 * valid". */
time_t rp_qualified_until = 0;
/* How many verifiers[] entries rp_perform_qualification_handshake_once()
 * may try, set once by get_attestation_results() before spawning threads --
 * threads themselves only know their own index (see get_attestation_
 * results_thread()'s arg), so the retry-on-rejection path reads this
 * instead of a parameter. */
int rp_num_verifiers_this_cycle = 0;
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
pthread_mutex_t rp_tpm_mutex = PTHREAD_MUTEX_INITIALIZER;
/* Guards /certify_ak's shared response globals (certify_ak_response/_rc/
 * processing_, above) against concurrent Verifier threads: each thread
 * certifies RP's AK with its own Verifier, so several can legitimately be
 * mid-/certify_ak at once and would otherwise read each other's response.
 * It no longer guards the thundering herd it was written for -- threads
 * each own their rp_ak_cert_der[i] slot now, so that race is gone. */
pthread_mutex_t rp_ak_reprovision_mutex = PTHREAD_MUTEX_INITIALIZER;
/* Guards /qualify + /qualify/submit's shared response globals (above).
 * The handshake runs at most once per cycle, but the retry-on-rejection
 * path can still reach it from several threads at once: the first through
 * re-qualifies, the rest see the now-valid cache and short-circuit.
 * Separate from rp_ak_reprovision_mutex -- disjoint globals, so AK
 * certification and qualification may proceed concurrently. */
pthread_mutex_t rp_qualification_mutex = PTHREAD_MUTEX_INITIALIZER;
/* Nonces received from each Verifier, indexed by verifier slot. */
uint8_t verifier_nonces[MAX_VERIFIERS][sizeof(TPMU_HA)] = {{0}};
uint32_t verifier_nonce_lens[MAX_VERIFIERS] = {0};
bool processing_nonce_response[MAX_VERIFIERS] = {false};
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

/* --- in-flight message state -------------------------------------------
 * Declared in rp_shared.h; the pipeline modules in src/rp/ fill these in
 * from their CoAP response handlers, which cannot return data. */

msg_attestation_request_dto last_request = {0};
msg_attestation_response_dto last_response = {0};
msg_certify_ak_response_dto certify_ak_response = {0};

/** @brief SIGINT/SIGTERM handler: requests graceful termination. */
static void handle_sigint(int signum CHARRA_UNUSED) { quit = true; }

/**
 * @brief Renew any credential already inside its renewal margin.
 *
 * Every call is a cheap no-op unless something is actually due: each
 * ensure_* checks an in-memory expiry first and returns without I/O.
 */
static void rp_renew_due_credentials(int num_verifiers) {
    if (rp_qualify_renew_margin_s > 0) {
        rp_perform_qualification_handshake_once(
                num_verifiers, (time_t)rp_qualify_renew_margin_s);
    }
    for (int i = 0; i < num_verifiers; ++i) {
        ensure_rp_ak_certificate(i);
        ensure_attester_identity_certified_by_verifier(i);
    }
}

/**
 * @brief When the next credential falls due for renewal, or 0 if none is
 * known yet. Used to size the idle nap so RP wakes exactly when something
 * needs doing instead of at the next loop iteration.
 */
static time_t rp_next_renewal_due(int num_verifiers) {
    time_t earliest = 0;
    if (rp_qualify_renew_margin_s > 0 && rp_qualified_until > 0) {
        earliest = rp_qualified_until - (time_t)rp_qualify_renew_margin_s;
    }
    const time_t m = rp_ak_renew_margin_s;
    for (int i = 0; i < num_verifiers; ++i) {
        const time_t due[] = {rp_ak_cert_expires_at[i] - m,
                attester_ak_cert_by_verifier_expires_at[i] - m};
        const time_t have[] = {
                rp_ak_cert_expires_at[i], attester_ak_cert_by_verifier_expires_at[i]};
        for (size_t k = 0; k < 2; ++k) {
            if (have[k] > 0 && (earliest == 0 || due[k] < earliest)) {
                earliest = due[k];
            }
        }
    }
    if (attester_ak_cert_rp_expires_at > 0) {
        time_t d = attester_ak_cert_rp_expires_at - m;
        if (earliest == 0 || d < earliest) {
            earliest = d;
        }
    }
    return earliest;
}

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
 * @brief One complete attestation cycle: resolve Verifiers, ensure the
 * Attester's identity, fetch and locally appraise its evidence, then
 * privacy-clean and submit to every Verifier.
 *
 * Shared by both modes so they can never drift apart -- the daemon runs
 * exactly the sequence the benchmark measures. Everything expensive inside
 * (RP AK keypair/certificates, Attester identity, qualification) is cached
 * by its own ensure_* or cache check, so repeat cycles skip straight to
 * /attest -> /nonce -> /appraise.
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

    /* Only the RP-CA leg of the Attester's identity is ensured here: it is
     * one relationship, FETCHed and signed once per process, and the call
     * no-ops thereafter. Fail-closed -- this is RP's own gate on the
     * Attester's identity, so a failure aborts the cycle rather than
     * appraising unverified evidence.
     *
     * Everything per-Verifier (RP's own AK certificate, and the Attester's
     * certificate from that Verifier's CA) is ensured inside
     * get_attestation_results_thread() instead, since Verifiers hold
     * independent CA keys -- one certificate from verifiers[0] cannot be
     * assumed good everywhere. */
    if ((result = ensure_attester_identity_provisioned()) !=
            CHARRA_RC_SUCCESS) {
        charra_log_error(
                "[" LOG_NAME "] Could not provision the Attester's identity.");
        return result;
    }

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
    CHARRA_RC result = EXIT_FAILURE;

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

    /* RP's own runtime state (TPM identity, per-Verifier AK certificates,
     * shared qualification cache) lives under state/relying-party/ --
     * mkdir() it once, up front, same reasoning verifier.c's main() already
     * documents: fopen(path, "w") fails outright if a parent directory is
     * missing, and nothing else creates these (gitignored, runtime-only). */
    mkdir("state", 0755);
    mkdir("state/relying-party", 0755);
    mkdir("state/relying-party/identity", 0755);
    mkdir("state/relying-party/ak-certificates", 0755);
    mkdir("state/relying-party/qualification-cache", 0755);
    mkdir("state/relying-party/attester-ak-certificates", 0755);
    mkdir("state/relying-party/ak-provisioning", 0755);

    /* Everything above is shared mutable state keyed by nothing but the path,
     * so exactly one RP may own it at a time. */
    if (charra_io_lock_state_dir("state/relying-party/relying-party.lock",
                "relying_party") != CHARRA_RC_SUCCESS) {
        return EXIT_FAILURE;
    }

    if (rp_benchmark_mode) {
        charra_log_info("[" LOG_NAME "] Effective configuration: mode=benchmark "
                        "verifier_sweep=1..%d runs_per_step=%d "
                        "(plus 1 discarded warm-up cycle per step) "
                        "verifier_response_timeout=%us "
                        "attester_response_timeout=%us blacklist='%s' "
                        "ima_test_log='%s' (use_ima_test_log=%s)",
                RP_MAX_SWEEP_VERIFIERS, NUM_RUNS, verifier_response_timeout,
                attester_response_timeout, blacklist_hashes_path,
                ima_test_log_path, use_ima_test_log ? "true" : "false");

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
            /* One discarded warm-up cycle per step, for a reason specific to
             * this sweep: verifiers 1..k-1 are already certified by the time
             * step k runs, but verifier k has never been seen, so its thread
             * performs a full two-leg /certify_ak (plus the Attester AK relay
             * and the qualification handshake) INSIDE the window
             * timing->appraisal measures. Without this, every step's sample
             * is "k-1 steady-state appraisals + one onboarding", and the
             * step-to-step delta reads as per-verifier scaling when much of
             * it is a one-off cost.
             *
             * The warm-up is not thrown away -- onboarding is the expensive
             * TPM path and worth a number of its own, so it is reported
             * separately below rather than blended into the steady state. */
            rp_cycle_timing onboarding = {0};
            {
                char label[32] = {0};
                snprintf(label, sizeof(label), "warm-up (onboarding)");
                result = run_one_attestation_cycle(
                        num_verifiers, label, &onboarding);
                if (result != CHARRA_RC_SUCCESS) {
                    result = EXIT_FAILURE;
                    break;
                }
            }

            for (int run = 0; run < NUM_RUNS; run++) {
                char label[32] = {0};
                snprintf(label, sizeof(label), "run %d/%d", run + 1, NUM_RUNS);

                rp_cycle_timing timing = {0};
                result = run_one_attestation_cycle(
                        num_verifiers, label, &timing);
                if (result != CHARRA_RC_SUCCESS) {
                    result = EXIT_FAILURE;
                    break;
                }
                verifier_durations[run] = timing.verifiers;
                evidence_durations[run] = timing.evidence;
                appraisal_durations[run] = timing.appraisal;
                total_attestation_durations[run] =
                        timing.verifiers + timing.evidence + timing.appraisal;
                result = CHARRA_RC_SUCCESS;
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
    charra_log_info("[" LOG_NAME "] Effective configuration: mode=daemon "
                    "verifiers=%d interval=%us qualify_renew_margin=%us "
                    "ak_renew_margin=%lds "
                    "verifier_response_timeout=%us "
                    "attester_response_timeout=%us blacklist='%s' "
                    "ima_test_log='%s' (use_ima_test_log=%s)",
            rp_num_verifiers, rp_attestation_interval_s, rp_qualify_renew_margin_s,
            (long)rp_ak_renew_margin_s,
            verifier_response_timeout, attester_response_timeout,
            blacklist_hashes_path, ima_test_log_path,
            use_ima_test_log ? "true" : "false");
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

        /* Idle window. Renewals are driven by their own deadlines here, not
         * by the loop's cadence: RP is doing nothing during this sleep, so
         * anything that falls due mid-nap is renewed the moment it does
         * rather than waiting for the next iteration to look. That is what
         * decouples the renewal margins from --interval. Without it, a
         * margin shorter than the interval lets the loop step straight over
         * the renewal window, and the work lands inside the next attestation
         * instead (get_attestation_results()'s margin-0 path), which is
         * exactly what the margins exist to avoid. */
        time_t idle_until = time(NULL) + nap;
        while (!quit) {
            time_t now = time(NULL);
            if (now >= idle_until) {
                break;
            }
            rp_renew_due_credentials(rp_num_verifiers);
            if (quit) {
                break;
            }

            time_t wake = idle_until;
            time_t due = rp_next_renewal_due(rp_num_verifiers);
            if (due > now && due < wake) {
                wake = due;
            }
            now = time(NULL);
            if (wake > now) {
                rp_interruptible_sleep((unsigned int)(wake - now));
            }
        }

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
