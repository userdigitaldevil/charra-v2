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

/* measurement config */
#define NUM_RUNS 1

bool rp_benchmark_mode = false;
unsigned int rp_attestation_interval_s =
        RP_DEFAULT_ATTESTATION_INTERVAL_S;
unsigned int rp_qualify_margin_s = RP_DEFAULT_QUALIFY_MARGIN_S;
int rp_num_verifiers = RP_DEFAULT_NUM_VERIFIERS;
/* Optional daemon stop conditions; 0 = unbounded (run until signalled).
 * Both exit through exactly the same path as a signal, so shutdown stays
 * one code path rather than three. */
unsigned int rp_duration_s = 0;
unsigned long rp_max_cycles = 0;

/* logging and coap config */ 
#define CHARRA_UNUSED __attribute__((unused))
#define LOG_NAME "relying party"
// #define LOG_LEVEL_CBOR LOG_DEBUG
coap_log_t coap_log_level = LOG_INFO;
charra_log_t charra_log_level = CHARRA_LOG_INFO;
CHARRA_RC charra_r = CHARRA_RC_SUCCESS;
bool quit = false;

/* trust manager config */ 
char trust_manager_host[16] = "127.0.0.1"; 
unsigned int trust_manager_port = 6000;
uint16_t trust_manager_response_timeout = 30;  
bool processing_trust_manager_response = false;

/* Sized to MAX_VERIFIERS, not the sweep's current hardcoded bound of 5
 * (see main()'s "for (int num_verifiers = 1; num_verifiers <= 5; ...)"),
 * so raising that bound later can't silently overflow this array the way
 * a fixed verifier_list[5] would -- every other per-Verifier array in this
 * file (attestation_results, verifiers, etc.) is already sized to
 * MAX_VERIFIERS for the same reason. */
int verifier_list[MAX_VERIFIERS];
bool attestation_results[MAX_VERIFIERS];
/* Set by coap_verifier_handler_appraisal() when a Verifier's /appraise
 * response is specifically "your AK certificate is invalid or expired"
 * (4.01 Unauthorized), as opposed to any other appraisal failure --
 * distinguishes "go redo /certify_ak and retry" from a plain failed vote. */
bool rp_ak_cert_rejected[MAX_VERIFIERS];
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

/* attester config */ 
#define PERIODIC_ATTESTATION_WAIT_TIME_S 2  // Wait time between attestations in seconds (not implemented)
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
/* Cache files -- created on first successful provisioning, reused (skipping
 * the whole /certify_ak round trip) on every later run. All of RP's own
 * runtime state lives under state/relying-party/ -- mkdir'd by main() --
 * split by purpose the same way verifier.c splits its own state under
 * state/verifier/: identity/ holds the one TPM-resident EK/AK keypair
 * (verifier-agnostic), ak-certificates/ holds the per-Verifier AK
 * certificates that keypair has been issued (see rp_ak_cert_der below;
 * ensure_rp_ak_certificate() computes
 * "state/relying-party/ak-certificates/rp-ak-certificate-<port>.der" per
 * call), and qualification-cache/ holds RP's own belief about whether it's
 * still qualified, now a single file since qualifying is Verifier-agnostic
 * (rp_qualification_cache_path above). */
char* rp_ek_cert_cache_path =
        "state/relying-party/identity/rp-ek-certificate.der";
char* rp_ak_public_path =
        "state/relying-party/identity/rp-ak-public.bin";
char* rp_ak_private_path =
        "state/relying-party/identity/rp-ak-private.bin";

/* True once the TPM-resident EK+AK keypair exists and rp_public_key_der is
 * populated -- set once by ensure_rp_ak_keypair(), never per-Verifier. */
bool rp_ak_keypair_ready = false;
/* Per-Verifier AK certificate state: each Verifier independently issues
 * (and tracks the validity/revocation of) its own certificate for RP's one
 * AK public key -- since Verifiers are independent, RP's AK certification
 * has to be too, not a single certificate obtained from verifiers[0] and
 * assumed good everywhere (see CHARRA_V2_NOTES.md). */
bool rp_ak_cert_ready[MAX_VERIFIERS] = {false};
uint8_t* rp_ak_cert_der[MAX_VERIFIERS] = {NULL};
uint32_t rp_ak_cert_der_len[MAX_VERIFIERS] = {0};
bool processing_certify_ak_response = false;
CHARRA_RC certify_ak_rc = CHARRA_RC_ERROR;

/* --- Attester identity provisioning (/certify_ak_of_attester) -----------
 * Two kinds of CA certify the Attester's AK identity, neither trusting the
 * other's issuance -- see CHARRA_V2_NOTES.md. RP acts as the sole initiator
 * throughout (Attester and every Verifier stay fully passive):
 *   - RP's own CA: one relationship, one certificate, provisioned once per
 *     process (ensure_attester_identity_provisioned() below) -- mirrors
 *     ensure_rp_ak_keypair() being a one-time thing.
 *   - Each Verifier's own CA: now symmetric with how RP's own AK is
 *     certified (ensure_rp_ak_certificate()) -- a SEPARATE certificate per
 *     Verifier, since Verifiers now hold independent CA keys (see
 *     verifier.c's verifier_ca_key_path). ensure_attester_identity_
 *     certified_by_verifier() below runs once per Verifier, from that
 *     Verifier's own thread, not once globally. */
char* rp_ca_cert_path = "keys/rp-ca.crt";
char* rp_ca_key_path = "keys/rp-ca.key";
/* Lifetime of the Attester AK certificate RP issues under its own CA,
 * as a duration from issuance rather than a fixed absolute window (see
 * verifier.c's ak_cert_validity_seconds for why). Settable with
 * --attester-ak-validity; default matches the old 2024-2034 window.
 * Independent of the Verifier's own --ak-validity: that one covers the
 * certificates the Verifier issues, this one only the Attester
 * certificate RP signs itself. Each certificate carries its own
 * notAfter, so the two never need to agree. */
#define RP_AK_CERT_VALIDITY_SECONDS_DEFAULT (10L * 365 * 24 * 60 * 60)
time_t attester_ak_cert_validity_seconds =
        RP_AK_CERT_VALIDITY_SECONDS_DEFAULT;
char* attester_ak_state_file_path =
        "state/relying-party/ak-provisioning/attester-ak-state.txt";
/* Cache for the RP-issued leg only -- RP genuinely holds the plaintext for
 * this one (it signed it itself), unlike any Verifier-issued leg, which
 * only the Attester's own TPM ever decrypts. Its presence gates
 * ensure_attester_identity_provisioned() (the FETCH + RP-CA leg only, not
 * any Verifier's leg -- those are gated per-Verifier, below). */
char* attester_ak_cert_rp_cache_path =
        "state/relying-party/attester-ak-certificates/"
        "attester-ak-certificate-rp.der";
bool attester_identity_provisioned = false;

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

/* Per-Verifier Attester AK certificate, mirroring rp_ak_cert_der/_len/
 * _ready above exactly -- same pattern, same reason (each Verifier issues
 * and must be sent back its OWN certificate). Substituted directly into
 * that Verifier's evidence message by charra_rp_build_evidence_message(),
 * instead of whatever (if anything) the Attester itself reports in its own
 * /appraise response: only RP knows which certificate belongs to which
 * Verifier, and the certificate's validity depends only on its own CA
 * signature, not on who carried the bytes -- so this is not a trust
 * shortcut, just cutting out a redundant hop. */
bool attester_ak_cert_by_verifier_ready[MAX_VERIFIERS] = {false};
uint8_t* attester_ak_cert_by_verifier_der[MAX_VERIFIERS] = {NULL};
uint32_t attester_ak_cert_by_verifier_der_len[MAX_VERIFIERS] = {0};
/* Guards the Attester-relay round trips inside ensure_attester_identity_
 * certified_by_verifier() (ACTIVATE, DELIVER_VERIFIER) against concurrent
 * Verifier threads -- both use shared response globals (activate_
 * credential_response/_rc/processing_ above, processing_certify_ak_of_
 * attester_deliver_response) the way /certify_ak's own globals need rp_ak_
 * reprovision_mutex. Held for the whole per-Verifier function body, not
 * just individual exchanges (unlike rp_ak_reprovision_mutex): the Attester
 * itself is single-threaded and serializes these anyway (see attester.c),
 * so there's no concurrency to preserve, only correctness to add. */
pthread_mutex_t attester_identity_relay_mutex =
        PTHREAD_MUTEX_INITIALIZER;

/* --- RP qualification handshake state (/qualify + /qualify/submit) ------
 * See charra_rp_qualification.h. Verifier's qualification ledger is now
 * shared across all Verifier instances (see qualification_state_file_path
 * in verifier.c), so RP only ever runs this handshake once per validity
 * window, against whichever Verifier is reachable first -- not once per
 * Verifier like AK provisioning below. */
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
/* Set by coap_verifier_handler_appraisal() when a Verifier's /appraise
 * response is 4.03 Forbidden specifically because our qualification is
 * missing or expired (as opposed to 4.01 Unauthorized for a bad AK
 * certificate, see rp_ak_cert_rejected) -- signals
 * get_attestation_results_thread()'s retry loop to invalidate the cache
 * above, redo the handshake, and resubmit once. Still per-Verifier: it's
 * whichever Verifier's /appraise response we're reacting to, even though
 * the underlying cache it invalidates is now global. */
bool rp_qualification_rejected[MAX_VERIFIERS];
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
/* Guards the /certify_ak CoAP round trip's shared response globals
 * (certify_ak_response/certify_ak_rc/processing_certify_ak_response,
 * above) against concurrent verifier threads: each thread now
 * independently certifies RP's AK with its OWN Verifier (see
 * rp_ak_cert_der's comment above), so several threads can legitimately be
 * mid-/certify_ak at once -- without this, two concurrent responses would
 * race to write the same three globals and one thread could read the
 * other's response. No longer used for the thundering-herd problem this
 * mutex originally guarded against (multiple threads racing to
 * re-provision one shared identity): that problem doesn't exist anymore
 * either, since each thread only ever touches its own rp_ak_cert_der[i]
 * slot. */
pthread_mutex_t rp_ak_reprovision_mutex = PTHREAD_MUTEX_INITIALIZER;
/* Guards the /qualify + /qualify/submit CoAP round trips' shared response
 * globals (qualify_challenge_log/qualify_challenge_log_len/
 * qualify_challenge_salt/qualify_response_rc/processing_qualify_response/
 * qualify_submit_qualified/processing_qualify_submit_response, below).
 * The handshake itself now runs at most once per attestation cycle (see
 * rp_perform_qualification_handshake_once()), but the retry-on-rejection
 * path can still call it from more than one Verifier thread concurrently
 * -- this mutex serializes those calls onto the shared globals; the first
 * one through re-qualifies, the rest observe the now-valid cache and
 * short-circuit. Separate from rp_ak_reprovision_mutex so AK
 * (re)certification and qualification can still proceed concurrently --
 * they guard disjoint globals. */
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

/* --- function forward declarations -------------------------------------- */

/**
 * @brief SIGINT handler: set quit to 1 for graceful termination.
 *
 * @param signum the signal number.
 */
static void handle_sigint(int signum);

/* --- static variables --------------------------------------------------- */

msg_attestation_request_dto last_request = {0};
msg_attestation_response_dto last_response = {0};
msg_certify_ak_response_dto certify_ak_response = {0};

/* --- main --------------------------------------------------------------- */


/* --- daemon mode -------------------------------------------------------- */

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

    /* RP's AK certificate is no longer provisioned here: each Verifier now
     * independently certifies (and tracks) RP's AK -- see
     * ensure_rp_ak_certificate()'s docstring -- so it's ensured
     * per-Verifier, inside get_attestation_results_thread(), not once here
     * against a single verifiers[0]. */

    /* The Attester's identity is FETCHed and certified by RP's own CA only
     * once per process -- ensure_attester_identity_provisioned() itself
     * no-ops on every call after the first. Hard fail-closed: this is RP's
     * own local gate on the Attester's identity, so any failure here aborts
     * the whole cycle rather than proceeding with unverified evidence. Each
     * Verifier's OWN certificate is ensured per-Verifier instead, inside
     * get_attestation_results_thread(), the same way RP's own AK
     * certificate already is (see the comment above). */
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

/** sleep(), but returns within a second of SIGINT instead of up to a whole
 * interval later -- a daemon that ignores Ctrl+C for a minute is not a
 * daemon anyone wants to run in a terminal. */
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

    if (rp_benchmark_mode) {
        charra_log_info("[" LOG_NAME "] Effective configuration: mode=benchmark "
                        "verifier_sweep=1..%d runs_per_step=%d "
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
                    "verifiers=%d interval=%us qualify_margin=%us "
                    "verifier_response_timeout=%us "
                    "attester_response_timeout=%us blacklist='%s' "
                    "ima_test_log='%s' (use_ima_test_log=%s)",
            rp_num_verifiers, rp_attestation_interval_s, rp_qualify_margin_s,
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

        /* Idle-window qualification renewal: done here, between cycles,
         * precisely so it never lands inside an attestation. With the
         * margin it renews while the current grant is still valid, so the
         * next cycle always finds a live qualification and skips /qualify
         * entirely. Failure is non-fatal -- the next attestation's own
         * margin-0 check will retry it, and abort that cycle if it must. */
        if (rp_qualify_margin_s > 0 &&
                rp_perform_qualification_handshake_once(rp_num_verifiers,
                        (time_t)rp_qualify_margin_s) != CHARRA_RC_SUCCESS) {
            charra_log_error("[" LOG_NAME "] Idle-window qualification renewal "
                             "did not complete; will retry next cycle.");
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
/* --- function definitions ----------------------------------------------- */

static void handle_sigint(int signum CHARRA_UNUSED) { quit = true; }
















/* Single, not per-port, cache file path -- qualification is Verifier-
 * agnostic now (see rp_qualified_until's comment). */
char* rp_qualification_cache_path =
        "state/relying-party/qualification-cache/rp-qualification-until.txt";


















