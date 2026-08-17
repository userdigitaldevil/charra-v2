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
#include "rp/rp_config.h"
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
#define COAP_IO_PROCESS_TIME_MS 2000  // CoAP IO process time in milliseconds
coap_log_t coap_log_level = LOG_INFO;
charra_log_t charra_log_level = CHARRA_LOG_INFO;
CHARRA_RC charra_r = CHARRA_RC_SUCCESS;
bool quit = false;

/* trust manager config */ 
char trust_manager_host[16] = "127.0.0.1"; 
unsigned int trust_manager_port = 6000;
uint16_t trust_manager_response_timeout = 30;  
static bool processing_trust_manager_response = false;

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
static bool rp_ak_cert_was_cached[MAX_VERIFIERS];
static long verifier_latency_ms[MAX_VERIFIERS];
static char rejection_reason[MAX_VERIFIERS][128];
typedef struct verifier_info {
    char ip_address[16];
    unsigned int port_number;
} verifier_info;
verifier_info verifiers[MAX_VERIFIERS];
/* Was 6000 -- 1000x too large: this feeds libcoap's ack_timeout (seconds),
 * so a stray retransmission could take tens of real seconds to resolve. */
uint16_t verifier_response_timeout = 6;  // timeout when waiting for verifier's answer (attestation results) in seconds
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
static uint8_t* rp_log_r = NULL;
static uint32_t rp_log_r_len = 0;
static uint8_t rp_pcr_r[TPM2_SHA256_DIGEST_SIZE] = {0};
/* Quote_r's signing key is RP's TPM-resident AK (see ensure_rp_ak_keypair()
 * / charra_identity_key_mgr.h) -- created once and reused for the process's
 * lifetime, unlike the throwaway software key this used to be. Verifier-
 * agnostic: the same keypair signs Quote_r for every Verifier -- only its
 * CERTIFICATE differs per Verifier, see rp_ak_cert_der below. */
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
static char* rp_ek_cert_cache_path =
        "state/relying-party/identity/rp-ek-certificate.der";
static char* rp_ak_public_path =
        "state/relying-party/identity/rp-ak-public.bin";
static char* rp_ak_private_path =
        "state/relying-party/identity/rp-ak-private.bin";

/* True once the TPM-resident EK+AK keypair exists and rp_public_key_der is
 * populated -- set once by ensure_rp_ak_keypair(), never per-Verifier. */
static bool rp_ak_keypair_ready = false;
/* Per-Verifier AK certificate state: each Verifier independently issues
 * (and tracks the validity/revocation of) its own certificate for RP's one
 * AK public key -- since Verifiers are independent, RP's AK certification
 * has to be too, not a single certificate obtained from verifiers[0] and
 * assumed good everywhere (see CHARRA_V2_NOTES.md). */
static bool rp_ak_cert_ready[MAX_VERIFIERS] = {false};
static uint8_t* rp_ak_cert_der[MAX_VERIFIERS] = {NULL};
static uint32_t rp_ak_cert_der_len[MAX_VERIFIERS] = {0};
static bool processing_certify_ak_response = false;
static CHARRA_RC certify_ak_rc = CHARRA_RC_ERROR;

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
static char* rp_ca_cert_path = "keys/rp-ca.crt";
static char* rp_ca_key_path = "keys/rp-ca.key";
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
static char* attester_ak_state_file_path =
        "state/relying-party/ak-provisioning/attester-ak-state.txt";
/* Cache for the RP-issued leg only -- RP genuinely holds the plaintext for
 * this one (it signed it itself), unlike any Verifier-issued leg, which
 * only the Attester's own TPM ever decrypts. Its presence gates
 * ensure_attester_identity_provisioned() (the FETCH + RP-CA leg only, not
 * any Verifier's leg -- those are gated per-Verifier, below). */
static char* attester_ak_cert_rp_cache_path =
        "state/relying-party/attester-ak-certificates/"
        "attester-ak-certificate-rp.der";
static bool attester_identity_provisioned = false;

static msg_ak_identity_response_dto ak_identity_response = {0};
static CHARRA_RC ak_identity_rc = CHARRA_RC_ERROR;
static bool processing_ak_identity_response = false;

/* The Attester's EK certificate + AK public key + AK name, as FETCHed once
 * by ensure_attester_identity_provisioned() -- doesn't vary per Verifier,
 * so every ensure_attester_identity_certified_by_verifier() call reuses
 * this rather than re-FETCHing. Populated once; ek_certificate is this
 * struct's own heap copy, independent of ak_identity_response above. */
static msg_ak_identity_response_dto attester_identity_cached = {0};

/* No payload to parse on the DELIVER_RP/DELIVER_VERIFIER leg -- this
 * handler only needs to know the round trip completed, same "ack-only"
 * shape /qualify/submit's response has. */
static bool processing_certify_ak_of_attester_deliver_response = false;

/* ACTIVATE leg: the secret the Attester recovered, relayed onward as that
 * Verifier's CONFIRM. */
static msg_activate_credential_response_dto activate_credential_response = {0};
static CHARRA_RC activate_credential_rc = CHARRA_RC_ERROR;
static bool processing_activate_credential_response = false;

/* Per-Verifier Attester AK certificate, mirroring rp_ak_cert_der/_len/
 * _ready above exactly -- same pattern, same reason (each Verifier issues
 * and must be sent back its OWN certificate). Substituted directly into
 * that Verifier's evidence message by charra_rp_build_evidence_message(),
 * instead of whatever (if anything) the Attester itself reports in its own
 * /appraise response: only RP knows which certificate belongs to which
 * Verifier, and the certificate's validity depends only on its own CA
 * signature, not on who carried the bytes -- so this is not a trust
 * shortcut, just cutting out a redundant hop. */
static bool attester_ak_cert_by_verifier_ready[MAX_VERIFIERS] = {false};
static uint8_t* attester_ak_cert_by_verifier_der[MAX_VERIFIERS] = {NULL};
static uint32_t attester_ak_cert_by_verifier_der_len[MAX_VERIFIERS] = {0};
/* Guards the Attester-relay round trips inside ensure_attester_identity_
 * certified_by_verifier() (ACTIVATE, DELIVER_VERIFIER) against concurrent
 * Verifier threads -- both use shared response globals (activate_
 * credential_response/_rc/processing_ above, processing_certify_ak_of_
 * attester_deliver_response) the way /certify_ak's own globals need rp_ak_
 * reprovision_mutex. Held for the whole per-Verifier function body, not
 * just individual exchanges (unlike rp_ak_reprovision_mutex): the Attester
 * itself is single-threaded and serializes these anyway (see attester.c),
 * so there's no concurrency to preserve, only correctness to add. */
static pthread_mutex_t attester_identity_relay_mutex =
        PTHREAD_MUTEX_INITIALIZER;

/* --- RP qualification handshake state (/qualify + /qualify/submit) ------
 * See charra_rp_qualification.h. Verifier's qualification ledger is now
 * shared across all Verifier instances (see qualification_state_file_path
 * in verifier.c), so RP only ever runs this handshake once per validity
 * window, against whichever Verifier is reachable first -- not once per
 * Verifier like AK provisioning below. */
static uint8_t* qualify_challenge_log = NULL;
static uint32_t qualify_challenge_log_len = 0;
/* Salt to redact qualify_challenge_log with, sent alongside it -- see
 * msg_qualify_response_dto's docstring in charra_dto.h for why sharing a
 * salt is safe here (and only here). */
static uint8_t qualify_challenge_salt[CHARRA_SDK_PATH_SALT_LEN] = {0};
static CHARRA_RC qualify_response_rc = CHARRA_RC_ERROR;
static bool processing_qualify_response = false;
static bool qualify_submit_qualified = false;
/* Deadline the Verifier reported granting, straight off the wire --
 * authoritative, unlike the old "assume the same constant" approach. */
static time_t qualify_submit_expires_at = 0;
static bool processing_qualify_submit_response = false;
/* RP's own client-side qualification cache: "qualified until when",
 * persisted to rp-qualification-until.txt so a fresh RP process doesn't
 * redo /qualify + /qualify/submit if a previous run's qualification is
 * still valid. Single value, not per-Verifier, since qualifying is now a
 * one-time, Verifier-agnostic fact. 0 means "unknown/not currently
 * valid". */
static time_t rp_qualified_until = 0;
/* How many verifiers[] entries rp_perform_qualification_handshake_once()
 * may try, set once by get_attestation_results() before spawning threads --
 * threads themselves only know their own index (see get_attestation_
 * results_thread()'s arg), so the retry-on-rejection path reads this
 * instead of a parameter. */
static int rp_num_verifiers_this_cycle = 0;
/* Set by coap_verifier_handler_appraisal() when a Verifier's /appraise
 * response is 4.03 Forbidden specifically because our qualification is
 * missing or expired (as opposed to 4.01 Unauthorized for a bad AK
 * certificate, see rp_ak_cert_rejected) -- signals
 * get_attestation_results_thread()'s retry loop to invalidate the cache
 * above, redo the handshake, and resubmit once. Still per-Verifier: it's
 * whichever Verifier's /appraise response we're reacting to, even though
 * the underlying cache it invalidates is now global. */
static bool rp_qualification_rejected[MAX_VERIFIERS];
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
static pthread_mutex_t rp_ak_reprovision_mutex = PTHREAD_MUTEX_INITIALIZER;
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
static pthread_mutex_t rp_qualification_mutex = PTHREAD_MUTEX_INITIALIZER;
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

/** @brief See its own definition's docstring. Forward-declared because
 * main()'s shutdown path frees the final cycle's evidence. */
static void charra_free_attestation_response(
        msg_attestation_response_dto* res);

static coap_response_t coap_verifier_handler_nonce(coap_session_t* session,
        const coap_pdu_t* sent CHARRA_UNUSED, const coap_pdu_t* received,
        const coap_mid_t mid CHARRA_UNUSED);

static coap_response_t coap_certify_ak_response_handler(
        coap_session_t* session CHARRA_UNUSED,
        const coap_pdu_t* sent CHARRA_UNUSED, const coap_pdu_t* received,
        const coap_mid_t mid CHARRA_UNUSED);

static coap_response_t coap_ak_identity_response_handler(
        coap_session_t* session CHARRA_UNUSED,
        const coap_pdu_t* sent CHARRA_UNUSED, const coap_pdu_t* received,
        const coap_mid_t mid CHARRA_UNUSED);

static coap_response_t coap_certify_ak_of_attester_deliver_response_handler(
        coap_session_t* session CHARRA_UNUSED,
        const coap_pdu_t* sent CHARRA_UNUSED,
        const coap_pdu_t* received CHARRA_UNUSED,
        const coap_mid_t mid CHARRA_UNUSED);

/**
 * @brief Ensure the Attester's identity is FETCHed and certified by RP's
 * own CA -- see CHARRA_V2_NOTES.md, "/certify_ak_of_attester". Runs once
 * per process (like ensure_rp_ak_keypair() above); every call after the
 * first returns immediately. Also populates attester_identity_cached for
 * ensure_attester_identity_certified_by_verifier() below to reuse.
 *
 * This is a hard local gate: if the Attester's EK certificate does not
 * chain to the manufacturer root, this returns an error and the caller is
 * expected to abort the whole attestation cycle rather than proceed with
 * an unverified Attester identity.
 */
static CHARRA_RC ensure_attester_identity_provisioned(void);

/**
 * @brief Ensure the Attester's identity is certified by verifier_index's
 * OWN CA -- symmetric with ensure_rp_ak_certificate(): one independent
 * certificate per Verifier, since each now holds its own CA key. Requires
 * ensure_attester_identity_provisioned() to have already succeeded (calls
 * it defensively if not). Every call after the first, for a given
 * verifier_index, returns immediately (cached in memory and on disk).
 */
static CHARRA_RC ensure_attester_identity_certified_by_verifier(
        int verifier_index);

/**
 * @brief Ensure RP's TPM-resident EK+AK keypair exists (creating it once,
 * the first time this is called across the whole process, if it doesn't),
 * and that rp_public_key_der/_len are populated. Verifier-agnostic --
 * called once, indirectly, by ensure_rp_ak_certificate() below, not once
 * per Verifier.
 */
static CHARRA_RC ensure_rp_ak_keypair(void);

/**
 * @brief Ensure RP's AK is certified by verifiers[verifier_index]
 * specifically, provisioning one via /certify_ak against that Verifier if
 * this is the first call for it (no cached rp-ak-certificate-<port>.der
 * yet) and reloading the cached certificate otherwise. Idempotent -- cheap
 * to call before every attestation cycle. Calls ensure_rp_ak_keypair()
 * first, so the underlying keypair is created at most once even though
 * this itself runs once per Verifier.
 *
 * Does NOT leave any TPM connection open afterward (see rp_tpm_mutex's
 * comment) -- populates rp_ak_cert_der[verifier_index]/_len[verifier_index]
 * (Step 3a item 1's input for that Verifier) on disk/in memory only.
 * Signing later reopens a short-lived connection via
 * rp_open_tpm_and_load_ak().
 */
static CHARRA_RC ensure_rp_ak_certificate(int verifier_index);

/**
 * @brief Discard RP's cached AK certificate for verifiers[verifier_index]
 * (both on disk and in memory) so the next ensure_rp_ak_certificate() call
 * for that Verifier is forced to provision a fresh one via /certify_ak,
 * instead of reloading what that Verifier just rejected as invalid or
 * expired. The TPM-resident keypair itself (rp_ak_public_path/
 * rp_ak_private_path, and every OTHER Verifier's certificate) is
 * deliberately left alone -- the keypair is not what expired, and this
 * Verifier rejecting its certificate says nothing about any other
 * Verifier's opinion of it.
 */
static void invalidate_cached_rp_ak_certificate(int verifier_index);

/**
 * @brief Forget RP's cached qualification: delete its on-disk cache file
 * and reset rp_qualified_until to 0, so the next
 * rp_perform_qualification_handshake_once() call redoes /qualify +
 * /qualify/submit instead of trusting a grant a Verifier just told us
 * (via a 4.03 Forbidden /appraise response) it no longer honors.
 */
static void invalidate_cached_rp_qualification(void);

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
 * once: short-circuits to CHARRA_RC_SUCCESS if rp_qualified_until (or its
 * on-disk cache file) says we're already qualified; otherwise tries
 * verifiers[0..num_verifiers) in order, using the first one reachable at
 * the network level to fetch a /qualify challenge, redact it with the same
 * pipeline real evidence uses, sign the resulting PCR digest with RP's
 * TPM-resident AK, and submit via /qualify/submit. A network-level failure
 * against one Verifier tries the next; a received verdict (qualified or
 * not) stops the loop -- the qualification ledger is shared across all
 * Verifiers now (see qualification_state_file_path in verifier.c), so
 * qualifying with one qualifies with all of them, and a "not qualified"
 * verdict would be identical everywhere.
 *
 * @param[in] num_verifiers how many entries of verifiers[] to try.
 * @param[in] refresh_margin_seconds treat a qualification that expires
 * within this many seconds as already needing renewal. 0 = the literal
 * "only if actually expired" behaviour, which is what the attestation path
 * wants (it must qualify, but has no reason to renew early). Daemon mode
 * passes a non-zero margin from its idle window instead, so a renewal
 * never lands in the middle of an attestation -- see rp_qualify_margin_s.
 * @returns CHARRA_RC_SUCCESS if already cached as qualified, or if some
 * Verifier's /qualify/submit response reports the RP as qualified (and
 * caches that). Any other outcome (every Verifier unreachable, or a
 * genuine "not qualified" verdict) returns a non-success code -- the
 * caller decides whether that's fatal.
 */
static CHARRA_RC rp_perform_qualification_handshake_once(
        int num_verifiers, time_t refresh_margin_seconds);

CHARRA_RC get_verifiers(int* verifier_list, int num_verifiers);

CHARRA_RC get_evidence();

CHARRA_RC get_attestation_results(int num_verifiers);

void* get_attestation_results_thread();

/* --- static variables --------------------------------------------------- */

static msg_attestation_request_dto last_request = {0};
static msg_attestation_response_dto last_response = {0};
static msg_certify_ak_response_dto certify_ak_response = {0};

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

static CHARRA_RC create_attestation_request(msg_attestation_request_dto* attestation_request) {
    CHARRA_RC err = CHARRA_RC_ERROR;
    
    /* generate nonce */
    const uint32_t nonce_len = 20;
    uint8_t nonce[nonce_len];
    if (USE_TPM_FOR_RANDOM_NONCE_GENERATION) {
        if ((err = charra_random_bytes_from_tpm(nonce_len, nonce)) !=
                CHARRA_RC_SUCCESS) {
            charra_log_error("[" LOG_NAME "] Could not get random bytes "
                             "from TPM for nonce: CHARRA_RC=%d.",
                    err);
            return err;
        }
    } else {
        if ((err = charra_random_bytes(nonce_len, nonce)) !=
                CHARRA_RC_SUCCESS) {
            charra_log_error(
                    "[" LOG_NAME "] Could not get random bytes for nonce: "
                    "CHARRA_RC=%d.",
                    err);
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
        /* res is fully unmarshaled by now and owns heap buffers; it never
         * reaches last_response on this path, so free it here. */
        charra_free_attestation_response(&res);
        goto cleanup;
    }

    /* NOT actually forwarding yet -- charra_rp_prepare_evidence() (privacy
     * cleaning: redact the log, build Quote_r) still has to run first, in
     * get_attestation_results() below. The real "Forwarding evidence to the
     * verifiers" log is there, after that redaction succeeds. */
    charra_log_info(
            "[" LOG_NAME "] Evidence appraised locally; privacy-cleaning "
            "before forwarding to the Verifiers.");
    /* Store last response, releasing the previous cycle's buffers first --
     * a plain struct assignment would otherwise orphan them once this
     * handler runs more than once (daemon mode). Safe here: get_evidence()
     * completes fully before get_attestation_results() spawns the Verifier
     * threads that read last_response, so nothing still points into the
     * old buffers by the time this runs again. */
    charra_free_attestation_response(&last_response);
    last_response = res;

cleanup:

    processing_attestation_response = false;
    return COAP_RESPONSE_OK;
}

static bool charra_rp_appraise_evidence(
        const msg_attestation_response_dto* res) {
    charra_log_info("[" LOG_NAME
            "]  +------------ RP Appraisal of the Evidence --------------+");

    bool ekak_ok = false;
    bool signature_ok = false;
    bool nonce_ok = false;
    bool entries_ok = false;
    bool pcr_ok = false;
    bool blacklist_ok = false;

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

    /* --- 1. Attester's AK certificate, issued by RP's own CA -------------
     * DRA-TLS Step 2a item 1. Same chain+key check the Verifier runs for
     * Step 3a/3b item 1 (charra_crypto_verify_ekak_certificate() is written
     * to be shared by both, see its docstring), but RP additionally checks
     * the serial against its own issuance ledger: unlike the Verifier-issued
     * leg (one shared CA, no cross-Verifier ledger), RP signed this cert
     * itself, so revocation is actually checkable here. */
    charra_log_info(
            "[" LOG_NAME "] Verifying Attester's RP-issued AK certificate ...");
    if (res->ak_certificate_attester_by_rp_len == 0) {
        charra_log_error("[" LOG_NAME "]     => certificate is EMPTY -- "
                         "/certify_ak_of_attester's DELIVER_RP leg has not "
                         "completed yet.");
    } else {
        char* rp_ca_cert_der = NULL;
        size_t rp_ca_cert_der_len = 0;
        if (charra_io_read_file(rp_ca_cert_path, &rp_ca_cert_der,
                    &rp_ca_cert_der_len) != CHARRA_RC_SUCCESS) {
            charra_log_error("[" LOG_NAME "]     => could not read RP CA "
                             "certificate ('%s').",
                    rp_ca_cert_path);
        } else {
            uint8_t ak_serial[16] = {0};
            ekak_ok = charra_crypto_verify_ekak_certificate(
                    res->ak_certificate_attester_by_rp,
                    res->ak_certificate_attester_by_rp_len,
                    (uint8_t*)rp_ca_cert_der, rp_ca_cert_der_len,
                    tpm2_public_key, ak_serial) == CHARRA_RC_SUCCESS;
            charra_io_free_file_buffer(&rp_ca_cert_der);
            if (!ekak_ok) {
                charra_log_error("[" LOG_NAME "]     => certificate did NOT "
                                 "verify (chain or key mismatch)!");
            } else {
                charra_print_hex(CHARRA_LOG_INFO, sizeof(ak_serial),
                        ak_serial,
                        "[" LOG_NAME "]     => chain and key valid! serial 0x",
                        "\n", false);
                ekak_ok = charra_ak_state_check_serial_valid(
                        attester_ak_state_file_path, ak_serial, NULL, NULL);
                charra_log_info(
                        "[" LOG_NAME "]     => serial is %s",
                        ekak_ok ? "currently valid (not revoked/expired)!"
                                : "REVOKED or EXPIRED!");
            }
        }
    }

    /* --- 2. quote signature, under the Attester's own public key --------- */
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

    /* --- 3. nonce: the quote must answer the challenge we just sent ------ */
    charra_log_info("[" LOG_NAME "] Verifying nonce ...");
    nonce_ok = charra_verify_tpm2_quote_qualifying_data(
            (uint16_t)last_request.nonce_len, last_request.nonce,
            &attest_struct);
    charra_log_info("[" LOG_NAME "]     => nonce in the quote %s",
            nonce_ok ? "matches the one sent!"
                     : "does NOT match the one sent!");

    /* --- 4. every entry's template_digest == hash(template_data) -------- */
    charra_log_info("[" LOG_NAME "] Verifying log entry self-consistency ...");
    entries_ok = charra_verify_log_entries_self_consistent(
            res->event_log, res->event_log_len);
    charra_log_info("[" LOG_NAME "]     => log entries are %s",
            entries_ok ? "self-consistent!" : "NOT self-consistent!");

    /* --- 5. replay the log and rebuild the PCR composite digest ---------- */
    charra_log_info("[" LOG_NAME "] Replaying the log into the PCRs ...");
    pcr_ok = charra_verify_log_matches_quote_pcr_digest(res->event_log,
            res->event_log_len, tpm_pcr_selection, tpm_pcr_selection_len,
            &attest_struct);
    charra_log_info("[" LOG_NAME "]     => PCR composite digest %s",
            pcr_ok ? "matches the quote!" : "does NOT match the quote!");

    /* --- 6. no measured file may appear on the blacklist ----------------- */
    charra_log_info("[" LOG_NAME "] Checking file hashes against the "
                    "whitelist/blacklist policy ...");
    blacklist_ok = charra_verify_log_file_hashes_against_policy(
            res->event_log, res->event_log_len, whitelist_hashes_path,
            blacklist_hashes_path);
    charra_log_info("[" LOG_NAME "]     => file hashes are %s",
            blacklist_ok ? "not blacklisted!" : "BLACKLISTED!");

done:;
    const bool appraisal_ok = ekak_ok && signature_ok && nonce_ok &&
                              entries_ok && pcr_ok && blacklist_ok;
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
    struct timespec redact_start, redact_end;
    clock_gettime(CLOCK_MONOTONIC, &redact_start);
    CHARRA_RC charra_r = charra_sdk_redact_ima_log(last_response.event_log,
            last_response.event_log_len, NULL, &rp_log_r, &rp_log_r_len);
    clock_gettime(CLOCK_MONOTONIC, &redact_end);
    if (charra_r != CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Redaction of the event log failed.");
        return charra_r;
    }
    double redact_duration = (redact_end.tv_sec - redact_start.tv_sec) +
                              (redact_end.tv_nsec - redact_start.tv_nsec) / 1e9;
    charra_log_info("[" LOG_NAME "] log_r is %u bytes (raw log was %u), "
                    "redaction took %.3fs.",
            rp_log_r_len, last_response.event_log_len, redact_duration);

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
     * Ensured here, once, before any per-Verifier thread starts -- each
     * thread separately calls ensure_rp_ak_certificate(verifier_index) for
     * its own Verifier's AK *certificate*, but the underlying TPM-resident
     * keypair itself is Verifier-agnostic and only needs creating once;
     * this call is idempotent (cheap) once it has been. */
    CHARRA_RC keypair_rc = ensure_rp_ak_keypair();
    if (keypair_rc != CHARRA_RC_SUCCESS) {
        charra_log_error(
                "[" LOG_NAME "] RP AK keypair not provisioned; evidence not "
                "ready.");
        return keypair_rc;
    }
    charra_log_info(
            "[" LOG_NAME "] RP AK keypair ready (public key %u bytes).",
            rp_public_key_der_len);
    return CHARRA_RC_SUCCESS;
}

/**
 * @brief Frees the heap-allocated fields of an /attest response DTO.
 *
 * charra_unmarshal_attestation_response() malloc()s three of them
 * (event_log plus both Attester AK certificates, ~6 KB per cycle). Under
 * the original one-shot design nothing had to free them -- the process
 * exited right after -- but in daemon mode every cycle allocates a fresh
 * set, so they must be released or they accumulate for the process's
 * lifetime. Nulls as it frees, so it's safe on a zeroed struct and safe to
 * call twice.
 */
static void charra_free_attestation_response(
        msg_attestation_response_dto* res) {
    if (res == NULL) {
        return;
    }
    charra_free_if_not_null(res->event_log);
    res->event_log_len = 0;
    charra_free_if_not_null(res->ak_certificate_attester_by_verifier);
    res->ak_certificate_attester_by_verifier_len = 0;
    charra_free_if_not_null(res->ak_certificate_attester_by_rp);
    res->ak_certificate_attester_by_rp_len = 0;
}

static void charra_rp_release_evidence(void) {
    charra_free_if_not_null(rp_log_r);
    rp_log_r = NULL;
    rp_log_r_len = 0;
    /* rp_public_key_der/rp_ak_cert_der are provisioned once (per-Verifier
     * for the latter) by ensure_rp_ak_keypair()/ensure_rp_ak_certificate()
     * and live for the whole process, not freed per attestation cycle. */
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
    if (!rp_ak_cert_ready[verifier_index]) {
        charra_log_error("[" LOG_NAME "] No AK certificate for this "
                         "Verifier; evidence not prepared.");
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

    charra_r = charra_identity_key_mgr_sign(sign_esys_ctx, sign_ak_handle,
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

    ev.ak_certificate_rp_len = rp_ak_cert_der_len[verifier_index];
    ev.ak_certificate_rp = rp_ak_cert_der[verifier_index];

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

    /* EK_a/AK_a: the Attester's AK certificate issued by THIS Verifier's
     * own CA -- substituted from RP's own per-Verifier cache
     * (attester_ak_cert_by_verifier_der[], populated by ensure_attester_
     * identity_certified_by_verifier()), not whatever last_response itself
     * carries. Only RP knows which certificate belongs to which Verifier
     * now that each Verifier has an independent CA; the certificate's
     * validity depends only on its own CA signature, not on who forwarded
     * the bytes, so this is not a trust shortcut. */
    ev.ak_certificate_attester_by_verifier_len =
            attester_ak_cert_by_verifier_der_len[verifier_index];
    ev.ak_certificate_attester_by_verifier =
            attester_ak_cert_by_verifier_der[verifier_index];

    /* RP-issued cert, forwarded alongside the Verifier-issued one above */
    ev.ak_certificate_attester_by_rp_len =
            last_response.ak_certificate_attester_by_rp_len;
    ev.ak_certificate_attester_by_rp =
            last_response.ak_certificate_attester_by_rp;

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

static coap_response_t coap_activate_credential_response_handler(
        coap_session_t* session CHARRA_UNUSED,
        const coap_pdu_t* sent CHARRA_UNUSED, const coap_pdu_t* received,
        const coap_mid_t mid CHARRA_UNUSED) {
    processing_activate_credential_response = true;

    int coap_r = 0;
    size_t data_len = 0;
    const uint8_t* data = NULL;
    size_t data_offset = 0;
    size_t data_total_len = 0;
    if ((coap_r = coap_get_data_large(
                 received, &data_len, &data, &data_offset, &data_total_len)) ==
            0) {
        charra_log_error("[" LOG_NAME
                         "] ACTIVATE: Could not get CoAP PDU data.");
        activate_credential_rc = CHARRA_RC_ERROR;
        goto cleanup;
    }

    if ((activate_credential_rc = charra_unmarshal_activate_credential_response(
                 data_len, data, &activate_credential_response)) !=
            CHARRA_RC_SUCCESS) {
        charra_log_error(
                "[" LOG_NAME "] ACTIVATE: Could not parse CBOR response.");
        goto cleanup;
    }

cleanup:
    processing_activate_credential_response = false;
    return COAP_RESPONSE_OK;
}

static coap_response_t coap_ak_identity_response_handler(
        coap_session_t* session CHARRA_UNUSED,
        const coap_pdu_t* sent CHARRA_UNUSED, const coap_pdu_t* received,
        const coap_mid_t mid CHARRA_UNUSED) {
    processing_ak_identity_response = true;

    int coap_r = 0;
    size_t data_len = 0;
    const uint8_t* data = NULL;
    size_t data_offset = 0;
    size_t data_total_len = 0;
    if ((coap_r = coap_get_data_large(
                 received, &data_len, &data, &data_offset, &data_total_len)) ==
            0) {
        charra_log_error("[" LOG_NAME "] /certify_ak_of_attester (FETCH): "
                         "Could not get CoAP PDU data.");
        ak_identity_rc = CHARRA_RC_ERROR;
        goto cleanup;
    }

    if ((ak_identity_rc = charra_unmarshal_ak_identity_response(
                 data_len, data, &ak_identity_response)) != CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] /certify_ak_of_attester (FETCH): "
                         "Could not parse CBOR response.");
        goto cleanup;
    }

cleanup:
    processing_ak_identity_response = false;
    return COAP_RESPONSE_OK;
}

static coap_response_t coap_certify_ak_of_attester_deliver_response_handler(
        coap_session_t* session CHARRA_UNUSED,
        const coap_pdu_t* sent CHARRA_UNUSED,
        const coap_pdu_t* received CHARRA_UNUSED,
        const coap_mid_t mid CHARRA_UNUSED) {
    /* No payload to parse -- a non-error CoAP response code alone means
     * the Attester unwrapped and persisted the delivered certificate; the
     * caller only waits on rp_coap_fetch()'s own transport-level result. */
    processing_certify_ak_of_attester_deliver_response = true;
    processing_certify_ak_of_attester_deliver_response = false;
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
 * rp_perform_qualification_handshake_once()'s /qualify and /qualify/submit).
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
    /* Real elapsed time (CLOCK_MONOTONIC), not a sum of coap_io_process()'s
     * self-reported per-call durations -- that undercounts time spent
     * scheduled out under concurrent load. Also sidesteps the same
     * counter-overflow class of bug a uint16_t/uint32_t millisecond
     * accumulator would otherwise have for large timeouts (see
     * CHARRA_V2_NOTES.md). */
    struct timespec wait_start, wait_now;
    clock_gettime(CLOCK_MONOTONIC, &wait_start);
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
        clock_gettime(CLOCK_MONOTONIC, &wait_now);
        double elapsed_ms = (wait_now.tv_sec - wait_start.tv_sec) * 1000.0 +
                             (wait_now.tv_nsec - wait_start.tv_nsec) / 1e6;
        if (elapsed_ms >= (verifier_response_timeout * 1000)) {
            charra_log_error(
                    "[" LOG_NAME "] Timeout after %.0f ms waiting for /%s "
                    "response.",
                    elapsed_ms, uri_path);
            result = CHARRA_RC_TIMEOUT;
            break;
        }
    }

    charra_free_if_not_null_ex(coap_options, coap_delete_optlist);
    charra_free_if_not_null_ex(coap_session, coap_session_release);
    charra_free_if_not_null_ex(coap_context, coap_free_context);
    return result;
}

/**
 * @brief One /certify_ak round trip (either leg -- req->kind picks which).
 *
 * Serialized on rp_ak_reprovision_mutex: certify_ak_response and friends
 * are shared globals. The response is snapshotted out before unlocking, so
 * ownership of its heap field moves to the caller and a sibling thread's
 * next call can't overwrite or free memory this one still needs. The mutex
 * is never held across the caller's TPM work, preserving the existing
 * "reprovision mutex, then TPM mutex, never nested" lock discipline.
 */
static CHARRA_RC rp_certify_ak_exchange(const char* host, unsigned int port,
        const msg_certify_ak_request_dto* req,
        msg_certify_ak_response_dto* response_out) {
    uint8_t* req_buf = NULL;
    uint32_t req_buf_len = 0;
    CHARRA_RC result = charra_marshal_certify_ak_request(
            req, &req_buf_len, &req_buf);
    if (result != CHARRA_RC_SUCCESS) {
        charra_log_error(
                "[" LOG_NAME "] Could not marshal /certify_ak request.");
        return result;
    }

    pthread_mutex_lock(&rp_ak_reprovision_mutex);
    certify_ak_rc = CHARRA_RC_ERROR;
    memset(&certify_ak_response, 0, sizeof(certify_ak_response));

    result = rp_coap_fetch(host, port, "certify_ak", req_buf, req_buf_len,
            coap_certify_ak_response_handler, &processing_certify_ak_response);
    free(req_buf);

    if (result == CHARRA_RC_SUCCESS && certify_ak_rc != CHARRA_RC_SUCCESS) {
        result = certify_ak_rc;
    }

    *response_out = certify_ak_response;
    certify_ak_response.ak_certificate = NULL;
    certify_ak_response.ak_certificate_len = 0;
    pthread_mutex_unlock(&rp_ak_reprovision_mutex);

    if (result != CHARRA_RC_SUCCESS) {
        charra_free_if_not_null(response_out->ak_certificate);
        memset(response_out, 0, sizeof(*response_out));
    }
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
    memcpy(qualify_challenge_salt, resp.salt, sizeof(qualify_challenge_salt));

cleanup:
    processing_qualify_response = false;
    return COAP_RESPONSE_OK;
}

static coap_response_t coap_qualify_submit_response_handler(
        coap_session_t* session CHARRA_UNUSED,
        const coap_pdu_t* sent CHARRA_UNUSED, const coap_pdu_t* received,
        const coap_mid_t mid CHARRA_UNUSED) {
    processing_qualify_submit_response = true;

    /* The Verifier now answers with a CBOR verdict carrying the deadline
     * it granted, so RP no longer has to assume the validity window from
     * a shared compile-time constant -- see msg_qualify_submit_response_
     * dto in charra_dto.h. */
    size_t data_len = 0;
    const uint8_t* data = NULL;
    size_t data_offset = 0;
    size_t data_total_len = 0;
    qualify_submit_qualified = false;
    qualify_submit_expires_at = 0;
    if (coap_get_data_large(received, &data_len, &data, &data_offset,
                &data_total_len) != 0) {
        msg_qualify_submit_response_dto resp = {0};
        if (charra_unmarshal_qualify_submit_response(
                    (uint32_t)data_len, data, &resp) == CHARRA_RC_SUCCESS) {
            qualify_submit_qualified =
                    coap_pdu_get_code(received) ==
                            COAP_RESPONSE_CODE_CONTENT &&
                    resp.qualified != 0;
            qualify_submit_expires_at = (time_t)resp.expires_at;
        } else {
            charra_log_error("[" LOG_NAME "] /qualify/submit: could not "
                             "parse the Verifier's response.");
        }
    }

    processing_qualify_submit_response = false;
    return COAP_RESPONSE_OK;
}

/* Single, not per-port, cache file path -- qualification is Verifier-
 * agnostic now (see rp_qualified_until's comment). */
static const char* rp_qualification_cache_path =
        "state/relying-party/qualification-cache/rp-qualification-until.txt";

/**
 * @brief Read the cached qualification expiry from disk.
 *
 * @returns the cached expires_at, or 0 if the file doesn't exist or is
 * unparseable (treated the same as "no cache" -- not an error, a fresh
 * deployment or a first run simply hasn't qualified yet).
 */
static time_t rp_qualification_cache_load(void) {
    FILE* f = fopen(rp_qualification_cache_path, "r");
    if (f == NULL) {
        return 0;
    }
    long long expires_at = 0;
    int scanned = fscanf(f, "%lld", &expires_at);
    fclose(f);
    if (scanned != 1 || expires_at <= 0) {
        return 0;
    }
    return (time_t)expires_at;
}

/**
 * @brief Persist RP's freshly-earned qualification expiry to disk, so a
 * later process invocation can skip the handshake while it's still valid.
 */
static void rp_qualification_cache_save(time_t expires_at) {
    FILE* f = fopen(rp_qualification_cache_path, "w");
    if (f == NULL) {
        charra_log_error(
                "[" LOG_NAME "] Could not write qualification cache '%s'.",
                rp_qualification_cache_path);
        return;
    }
    fprintf(f, "%lld\n", (long long)expires_at);
    fclose(f);
}

static void invalidate_cached_rp_qualification(void) {
    remove(rp_qualification_cache_path);
    rp_qualified_until = 0;
}

static CHARRA_RC rp_perform_qualification_handshake_once(
        int num_verifiers, time_t refresh_margin_seconds) {
    /* AK certificate readiness is orthogonal to the qualification cache
     * below: /qualify/submit needs an AK cert issued by whichever Verifier
     * we end up qualifying against, so it's provisioned per-candidate
     * inside the loop below, not once up front. */

    /* Cache short-circuit: if we already hold a still-valid qualification
     * -- either from earlier this process, or loaded just now from a
     * previous process run's cache file -- skip the /qualify +
     * /qualify/submit round trip entirely. Re-checked against the wall
     * clock on every call (not just once), so this stays correct even if a
     * single process run happens to straddle the expiry moment. This is
     * what makes CHARRA_RP_QUALIFICATION_VALIDITY_SECONDS actually matter:
     * without it, RP re-qualified unconditionally on every single
     * attestation cycle regardless of how much of a previous grant was
     * left. See CHARRA_V2_NOTES.md. */
    time_t now = time(NULL);
    /* Compared against now+margin rather than now: with margin 0 this is
     * exactly "renew only once expired"; with a margin it renews while the
     * grant is still valid, which is what lets daemon mode do the renewal
     * in its idle window instead of inside an attestation. */
    time_t renew_deadline = now + refresh_margin_seconds;
    if (rp_qualified_until <= renew_deadline) {
        rp_qualified_until = rp_qualification_cache_load();
    }
    if (rp_qualified_until > renew_deadline) {
        charra_log_info(
                "[" LOG_NAME "] Cached qualification still valid for %ld "
                "more second(s), skipping /qualify.",
                (long)(rp_qualified_until - now));
        return CHARRA_RC_SUCCESS;
    }

    CHARRA_RC result = CHARRA_RC_ERROR;

    /* Held across the whole handshake below, not just individual field
     * accesses: every one of qualify_challenge_log/_len/_salt,
     * qualify_response_rc, processing_qualify_response,
     * qualify_submit_qualified, and processing_qualify_submit_response is
     * a single shared global -- see rp_qualification_mutex's own comment
     * for why this still matters even though the handshake itself now
     * runs once per cycle. */
    pthread_mutex_lock(&rp_qualification_mutex);

    /* Try each Verifier in order, stopping at the first one reachable at
     * the network level for /qualify -- a transport failure moves on to
     * the next candidate, but a received verdict (qualified or not) stops
     * the search: the qualification ledger is shared, so the verdict would
     * be the same everywhere. */
    for (int verifier_index = 0; verifier_index < num_verifiers;
            ++verifier_index) {
        CHARRA_RC keypair_and_cert_rc =
                ensure_rp_ak_certificate(verifier_index);
        if (keypair_and_cert_rc != CHARRA_RC_SUCCESS) {
            charra_log_error(
                    "[" LOG_NAME "] Verifier n° %d (port %u): RP AK "
                    "certificate not provisioned, trying next Verifier.",
                    verifier_index + 1, verifiers[verifier_index].port_number);
            continue;
        }

        const verifier_info* verifier = &verifiers[verifier_index];
        uint8_t* redacted_log = NULL;
        uint32_t redacted_log_len = 0;

        charra_log_info(
                "[" LOG_NAME "]  +------------ RP Qualification (Verifier "
                "n° %d, port %u) --------------+",
                verifier_index + 1, verifier->port_number);

        /* --- 1. fetch a fresh challenge --- */
        qualify_response_rc = CHARRA_RC_ERROR;
        result = rp_coap_fetch(verifier->ip_address, verifier->port_number,
                "qualify", NULL, 0, coap_qualify_response_handler,
                &processing_qualify_response);
        if (result != CHARRA_RC_SUCCESS || qualify_response_rc != CHARRA_RC_SUCCESS) {
            charra_log_error(
                    "[" LOG_NAME "] Verifier n° %d (port %u) unreachable "
                    "for /qualify, trying next Verifier.",
                    verifier_index + 1, verifier->port_number);
            continue;
        }
        charra_log_info("[" LOG_NAME "] Received a %u-byte challenge log.",
                qualify_challenge_log_len);

        /* --- 2. redact it with the exact same pipeline real evidence uses --- */
        result = charra_sdk_redact_ima_log(qualify_challenge_log,
                qualify_challenge_log_len, qualify_challenge_salt,
                &redacted_log, &redacted_log_len);
        if (result != CHARRA_RC_SUCCESS) {
            charra_log_error("[" LOG_NAME "] Could not redact the "
                             "qualification challenge log.");
            goto done;
        }

        /* --- 3. replay the redacted log into its PCR digest --- */
        uint8_t submitted_pcr_digest[TPM2_SHA256_DIGEST_SIZE] = {0};
        result = charra_replay_ima_log(redacted_log, redacted_log_len,
                CHARRA_IMA_PCR_INDEX, submitted_pcr_digest);
        if (result != CHARRA_RC_SUCCESS) {
            charra_log_error("[" LOG_NAME "] Could not replay the redacted "
                             "challenge log.");
            charra_free_if_not_null(redacted_log);
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
            charra_log_error("[" LOG_NAME "] Could not open TPM connection "
                             "to sign the qualification PCR digest.");
            charra_free_if_not_null(redacted_log);
            goto done;
        }
        Esys_Free(sign_ak_name);

        result = charra_identity_key_mgr_sign(sign_esys_ctx, sign_ak_handle,
                submitted_pcr_digest, sizeof(submitted_pcr_digest),
                rp_signature);

        Esys_FlushContext(sign_esys_ctx, sign_ak_handle);
        Esys_FlushContext(sign_esys_ctx, sign_ek_handle);
        Esys_Finalize(&sign_esys_ctx);
        Tss2_TctiLdr_Finalize(&sign_tcti_ctx);
        pthread_mutex_unlock(&rp_tpm_mutex);

        if (result != CHARRA_RC_SUCCESS) {
            charra_log_error(
                    "[" LOG_NAME "] Could not sign the qualification PCR "
                    "digest.");
            charra_free_if_not_null(redacted_log);
            goto done;
        }

        /* --- 5. submit --- */
        msg_qualify_submit_request_dto submit_req = {
                .submitted_redacted_log_len = redacted_log_len,
                .submitted_redacted_log = redacted_log,
                .rp_signature_len = sizeof(rp_signature),
                .rp_public_key_len = rp_public_key_der_len,
                .ak_certificate_rp_len = rp_ak_cert_der_len[verifier_index],
                .ak_certificate_rp = rp_ak_cert_der[verifier_index],
        };
        memcpy(submit_req.submitted_pcr_digest, submitted_pcr_digest,
                sizeof(submitted_pcr_digest));
        memcpy(submit_req.rp_signature, rp_signature, sizeof(rp_signature));
        memcpy(submit_req.rp_public_key, rp_public_key_der,
                rp_public_key_der_len);

        uint8_t* submit_buf = NULL;
        uint32_t submit_buf_len = 0;
        result = charra_marshal_qualify_submit_request(
                &submit_req, &submit_buf_len, &submit_buf);
        if (result != CHARRA_RC_SUCCESS) {
            charra_log_error(
                    "[" LOG_NAME "] Could not marshal /qualify/submit "
                    "request.");
            charra_free_if_not_null(redacted_log);
            goto done;
        }

        result = rp_coap_fetch(verifier->ip_address, verifier->port_number,
                "qualify_submit", submit_buf, submit_buf_len,
                coap_qualify_submit_response_handler,
                &processing_qualify_submit_response);
        charra_free_if_not_null(submit_buf);
        if (result != CHARRA_RC_SUCCESS) {
            charra_log_error(
                    "[" LOG_NAME "] Verifier n° %d (port %u) unreachable "
                    "for /qualify_submit, trying next Verifier.",
                    verifier_index + 1, verifier->port_number);
            charra_free_if_not_null(redacted_log);
            continue;
        }

        if (qualify_submit_qualified) {
            charra_log_info(
                    "[" LOG_NAME "] |  RP QUALIFIED with Verifier n° %d "
                    "(port %u)  |",
                    verifier_index + 1, verifier->port_number);
            /* Exactly what the Verifier said it granted -- no local
             * guess at the window. */
            time_t expires_at = qualify_submit_expires_at;
            rp_qualified_until = expires_at;
            rp_qualification_cache_save(expires_at);
            charra_log_info(
                    "[" LOG_NAME "] Qualification valid until %ld (%ld "
                    "second(s) from now, as granted by this Verifier); "
                    "shared with every other Verifier.",
                    (long)expires_at, (long)(expires_at - time(NULL)));
            /* The margin only helps if it fits inside the window the
             * Verifier actually granted -- which RP only learns here, not
             * at CLI-parse time. */
            if (rp_qualify_margin_s > 0 &&
                    (time_t)rp_qualify_margin_s >= expires_at - time(NULL)) {
                charra_log_warn(
                        "[" LOG_NAME "] --qualify-margin (%us) is not smaller "
                        "than the %lds window this Verifier grants; RP will "
                        "re-qualify on every idle pass.",
                        rp_qualify_margin_s, (long)(expires_at - time(NULL)));
            }
            result = CHARRA_RC_SUCCESS;
        } else {
            charra_log_error(
                    "[" LOG_NAME
                    "] |  RP NOT QUALIFIED with Verifier n° %d (port %u)  |",
                    verifier_index + 1, verifier->port_number);
            result = CHARRA_RC_VERIFICATION_FAILED;
        }
        charra_free_if_not_null(redacted_log);
        goto done;
    }

    charra_log_error("[" LOG_NAME "] Could not qualify: no Verifier was "
                     "reachable for /qualify.");
    result = CHARRA_RC_ERROR;

done:
    charra_free_if_not_null(qualify_challenge_log);
    qualify_challenge_log = NULL;
    qualify_challenge_log_len = 0;
    pthread_mutex_unlock(&rp_qualification_mutex);
    return result;
}

/**
 * @brief Open a fresh TPM connection, recreate RP's EK (deterministic --
 * see charra_identity_key_mgr_create_ek()), and load the AK from its persisted
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
    CHARRA_RC result = charra_identity_key_mgr_create_ek(
            *esys_ctx_out, ek_handle_out, &ek_public);
    Esys_Free(ek_public);
    if (result != CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Could not recreate RP's EK.");
        goto error;
    }

    TPM2B_PUBLIC ak_public = {0};
    TPM2B_PRIVATE ak_private = {0};
    if ((result = charra_identity_key_mgr_load_public(
                 rp_ak_public_path, &ak_public)) != CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Could not load AK public key.");
        goto error;
    }
    if ((result = charra_identity_key_mgr_load_private(
                 rp_ak_private_path, &ak_private)) != CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Could not load AK private area.");
        goto error;
    }
    if ((result = charra_identity_key_mgr_load_ak(*esys_ctx_out, *ek_handle_out,
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

static void invalidate_cached_rp_ak_certificate(int verifier_index) {
    char cert_path[96] = {0};
    snprintf(cert_path, sizeof(cert_path),
            "state/relying-party/ak-certificates/rp-ak-certificate-%u.der",
            verifiers[verifier_index].port_number);
    remove(cert_path);
    charra_free_if_not_null(rp_ak_cert_der[verifier_index]);
    rp_ak_cert_der[verifier_index] = NULL;
    rp_ak_cert_der_len[verifier_index] = 0;
    rp_ak_cert_ready[verifier_index] = false;
    rp_ak_cert_was_cached[verifier_index] = false;
}

static CHARRA_RC ensure_attester_identity_provisioned(void) {
    if (attester_identity_provisioned) {
        return CHARRA_RC_SUCCESS;
    }
    if (charra_io_file_exists(attester_ak_cert_rp_cache_path) ==
            CHARRA_RC_SUCCESS) {
        charra_log_info("[" LOG_NAME "] Attester identity already "
                        "provisioned (cached); skipping re-certification.");
        attester_identity_provisioned = true;
        return CHARRA_RC_SUCCESS;
    }

    charra_log_info("[" LOG_NAME "]  +------------ Attester Identity "
                    "Provisioning --------------+");

    CHARRA_RC result = CHARRA_RC_ERROR;

    /* --- 1. FETCH: get the Attester's EK cert + AK public key + AK name */
    msg_certify_ak_of_attester_request_dto fetch_req = {0};
    fetch_req.kind = CHARRA_CERTIFY_AK_OF_ATTESTER_FETCH;
    uint8_t* fetch_req_buf = NULL;
    uint32_t fetch_req_buf_len = 0;
    if ((result = charra_marshal_certify_ak_of_attester_request(&fetch_req,
                 &fetch_req_buf_len, &fetch_req_buf)) != CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Could not marshal "
                         "/certify_ak_of_attester FETCH request.");
        return result;
    }

    ak_identity_rc = CHARRA_RC_ERROR;
    result = rp_coap_fetch(attester_host, attester_port,
            "certify_ak_of_attester", fetch_req_buf, fetch_req_buf_len,
            coap_ak_identity_response_handler, &processing_ak_identity_response);
    free(fetch_req_buf);
    if (result != CHARRA_RC_SUCCESS) {
        charra_log_error(
                "[" LOG_NAME "] /certify_ak_of_attester FETCH round trip "
                "failed.");
        return result;
    }
    if (ak_identity_rc != CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] /certify_ak_of_attester FETCH did "
                         "not complete successfully.");
        return ak_identity_rc;
    }

    /* Snapshot + release ownership of the shared global's heap field, same
     * convention certify_ak_response uses (see ensure_rp_ak_certificate()
     * below). Safe without a mutex: this whole function runs once, before
     * any per-Verifier thread starts. */
    msg_ak_identity_response_dto identity = ak_identity_response;
    ak_identity_response.ek_certificate = NULL;
    ak_identity_response.ek_certificate_len = 0;

    charra_log_info(
            "[" LOG_NAME "] Received Attester identity: EK certificate %u "
            "byte(s), AK public key %u byte(s).",
            identity.ek_certificate_len, identity.ak_public_key_len);

    /* --- 2. RP-CA local gate: the Attester's EK must chain to the
     * manufacturer root. Hard fail-closed -- the caller is expected to
     * abort the whole attestation cycle on any error return from here on,
     * per "the RP validates the Attester's EK/AK itself" (CHARRA_V2_NOTES.md). */
    char* manufacturer_root_der = NULL;
    size_t manufacturer_root_der_len = 0;
    if ((result = charra_io_read_file(manufacturer_root_cert_path,
                 &manufacturer_root_der, &manufacturer_root_der_len)) !=
            CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Could not read manufacturer root "
                         "certificate ('%s').",
                manufacturer_root_cert_path);
        charra_free_if_not_null(identity.ek_certificate);
        return result;
    }

    mbedtls_x509_crt attester_ek_leaf_cert;
    if ((result = charra_crypto_verify_x509_cert_chain(identity.ek_certificate,
                 identity.ek_certificate_len, (uint8_t*)manufacturer_root_der,
                 manufacturer_root_der_len, &attester_ek_leaf_cert)) !=
            CHARRA_RC_SUCCESS) {
        charra_log_error(
                "[" LOG_NAME "]     => RP's own EK/AK check of the Attester "
                "FAILED -- Attester's EK certificate does NOT verify "
                "against the manufacturer root. Aborting.");
        charra_io_free_file_buffer(&manufacturer_root_der);
        charra_free_if_not_null(identity.ek_certificate);
        return CHARRA_RC_VERIFICATION_FAILED;
    }
    charra_crypto_log_cert_summary(
            "Attester's EK cert (RP's own check)", &attester_ek_leaf_cert);
    charra_log_info(
            "[" LOG_NAME "]     => RP's own EK/AK check of the Attester "
            "passed!");

    TPM2B_PUBLIC attester_ek_public_key = {0};
    if ((result = charra_crypto_build_ek_tpm2b_public_from_cert(
                 &attester_ek_leaf_cert, &attester_ek_public_key)) !=
            CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Could not reconstruct Attester's "
                         "EK TPM2B_PUBLIC from certificate.");
        mbedtls_x509_crt_free(&attester_ek_leaf_cert);
        charra_io_free_file_buffer(&manufacturer_root_der);
        charra_free_if_not_null(identity.ek_certificate);
        return result;
    }
    mbedtls_x509_crt_free(&attester_ek_leaf_cert);
    charra_io_free_file_buffer(&manufacturer_root_der);

    TPM2B_PUBLIC* attester_ak_public_key =
            (TPM2B_PUBLIC*)identity.ak_public_key;
    TPM2B_NAME* attester_ak_name = (TPM2B_NAME*)identity.ak_name;

    /* --- 3. RP-CA track: sign, wrap, deliver -------------------------- */
    /* Validity runs from now, so a long-running RP always issues a full
     * window rather than an ever-shrinking one. */
    time_t rp_cert_issued_at = time(NULL);
    time_t rp_cert_expires_at =
            rp_cert_issued_at + attester_ak_cert_validity_seconds;
    char attester_ak_cert_not_before_utc[15] = {0};
    char attester_ak_cert_not_after_utc[15] = {0};
    uint8_t rp_ca_serial[16] = {0};
    uint8_t* rp_signed_cert_der = NULL;
    uint32_t rp_signed_cert_der_len = 0;
    {
        mbedtls_x509_crt rp_ca_cert;
        mbedtls_x509_crt_init(&rp_ca_cert);
        char* rp_ca_cert_der_buf = NULL;
        size_t rp_ca_cert_der_buf_len = 0;
        if ((result = charra_io_read_file(rp_ca_cert_path, &rp_ca_cert_der_buf,
                     &rp_ca_cert_der_buf_len)) != CHARRA_RC_SUCCESS) {
            charra_log_error("[" LOG_NAME "] Could not read RP CA "
                             "certificate ('%s').",
                    rp_ca_cert_path);
            charra_free_if_not_null(identity.ek_certificate);
            return result;
        }
        if (mbedtls_x509_crt_parse(&rp_ca_cert, (uint8_t*)rp_ca_cert_der_buf,
                    rp_ca_cert_der_buf_len) != 0) {
            charra_log_error("[" LOG_NAME "] Could not parse RP CA "
                             "certificate.");
            charra_io_free_file_buffer(&rp_ca_cert_der_buf);
            charra_free_if_not_null(identity.ek_certificate);
            return CHARRA_RC_CRYPTO_ERROR;
        }
        char rp_ca_subject_name[256] = {0};
        if (mbedtls_x509_dn_gets(rp_ca_subject_name,
                    sizeof(rp_ca_subject_name), &rp_ca_cert.subject) <= 0) {
            charra_log_error(
                    "[" LOG_NAME "] Could not read RP CA subject name.");
            mbedtls_x509_crt_free(&rp_ca_cert);
            charra_io_free_file_buffer(&rp_ca_cert_der_buf);
            charra_free_if_not_null(identity.ek_certificate);
            return CHARRA_RC_CRYPTO_ERROR;
        }
        mbedtls_x509_crt_free(&rp_ca_cert);
        charra_io_free_file_buffer(&rp_ca_cert_der_buf);

        if (!charra_crypto_format_utc_yyyymmddhhmmss(
                    rp_cert_issued_at, attester_ak_cert_not_before_utc) ||
                !charra_crypto_format_utc_yyyymmddhhmmss(rp_cert_expires_at,
                        attester_ak_cert_not_after_utc)) {
            charra_log_error("[" LOG_NAME "] Could not format Attester AK "
                             "certificate validity window.");
            charra_free_if_not_null(identity.ek_certificate);
            return CHARRA_RC_ERROR;
        }
        if ((result = charra_crypto_sign_ak_certificate(attester_ak_public_key,
                     "CN=CHARRA Attester AK (RP-issued)", rp_ca_subject_name,
                     attester_ak_cert_not_before_utc,
                     attester_ak_cert_not_after_utc, rp_ca_key_path,
                     &rp_signed_cert_der, &rp_signed_cert_der_len,
                     rp_ca_serial)) != CHARRA_RC_SUCCESS) {
            charra_log_error("[" LOG_NAME "] Could not sign Attester's AK "
                             "certificate with RP's own CA.");
            charra_free_if_not_null(identity.ek_certificate);
            return result;
        }
    }
    charra_log_info(
            "[" LOG_NAME "] Attester's AK certificate signed by RP's own CA "
            "(%u byte(s)).",
            rp_signed_cert_der_len);

    uint8_t rp_aes_key[CHARRA_AES256GCM_KEY_LEN] = {0};
    {
        mbedtls_ctr_drbg_context ctr_drbg;
        mbedtls_entropy_context entropy;
        if ((result = charra_crypto_seeded_rng_init(&ctr_drbg, &entropy)) !=
                CHARRA_RC_SUCCESS) {
            charra_log_error("[" LOG_NAME "] Could not seed RNG.");
            charra_free_if_not_null(rp_signed_cert_der);
            charra_free_if_not_null(identity.ek_certificate);
            return result;
        }
        int mbedtls_r = mbedtls_ctr_drbg_random(
                &ctr_drbg, rp_aes_key, sizeof(rp_aes_key));
        charra_crypto_seeded_rng_free(&ctr_drbg, &entropy);
        if (mbedtls_r != 0) {
            charra_log_error(
                    "[" LOG_NAME "] Could not generate AES key.");
            charra_free_if_not_null(rp_signed_cert_der);
            charra_free_if_not_null(identity.ek_certificate);
            return CHARRA_RC_CRYPTO_ERROR;
        }
    }

    uint8_t rp_aes_gcm_nonce[CHARRA_AES256GCM_NONCE_LEN] = {0};
    uint8_t rp_aes_gcm_tag[CHARRA_AES256GCM_TAG_LEN] = {0};
    uint8_t* rp_cert_ciphertext = NULL;
    if ((result = charra_crypto_aes256gcm_encrypt(rp_aes_key, rp_signed_cert_der,
                 rp_signed_cert_der_len, rp_aes_gcm_nonce, rp_aes_gcm_tag,
                 &rp_cert_ciphertext)) != CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Could not encrypt RP-signed AK "
                         "certificate.");
        charra_free_if_not_null(rp_signed_cert_der);
        charra_free_if_not_null(identity.ek_certificate);
        return result;
    }

    pthread_mutex_lock(&rp_tpm_mutex);
    ESYS_CONTEXT* esys_ctx = NULL;
    TSS2_TCTI_CONTEXT* tcti_ctx = NULL;
    TSS2_RC tss_r = 0;
    if ((tss_r = Tss2_TctiLdr_Initialize(getenv("CHARRA_TCTI"), &tcti_ctx)) !=
            TSS2_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Tss2_TctiLdr_Initialize.");
        pthread_mutex_unlock(&rp_tpm_mutex);
        charra_free_if_not_null(rp_cert_ciphertext);
        charra_free_if_not_null(rp_signed_cert_der);
        charra_free_if_not_null(identity.ek_certificate);
        return CHARRA_RC_ERROR;
    }
    if ((tss_r = Esys_Initialize(&esys_ctx, tcti_ctx, NULL)) !=
            TSS2_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Esys_Initialize.");
        Tss2_TctiLdr_Finalize(&tcti_ctx);
        pthread_mutex_unlock(&rp_tpm_mutex);
        charra_free_if_not_null(rp_cert_ciphertext);
        charra_free_if_not_null(rp_signed_cert_der);
        charra_free_if_not_null(identity.ek_certificate);
        return CHARRA_RC_ERROR;
    }

    TPM2B_DIGEST rp_credential = {0};
    rp_credential.size = sizeof(rp_aes_key);
    memcpy(rp_credential.buffer, rp_aes_key, sizeof(rp_aes_key));

    TPM2B_ID_OBJECT* rp_credential_blob = NULL;
    TPM2B_ENCRYPTED_SECRET* rp_wrapped_secret = NULL;
    result = charra_tpm_make_credential_for_ak(esys_ctx, &attester_ek_public_key,
            attester_ak_name, &rp_credential, &rp_credential_blob,
            &rp_wrapped_secret);
    Esys_Finalize(&esys_ctx);
    Tss2_TctiLdr_Finalize(&tcti_ctx);
    pthread_mutex_unlock(&rp_tpm_mutex);
    if (result != CHARRA_RC_SUCCESS) {
        charra_log_error(
                "[" LOG_NAME "] Esys_MakeCredential (RP-CA leg) failed.");
        charra_free_if_not_null(rp_cert_ciphertext);
        charra_free_if_not_null(rp_signed_cert_der);
        charra_free_if_not_null(identity.ek_certificate);
        return result;
    }

    /* --- record issuance in RP's own ledger, independent of any
     * Verifier's ------------------------------------------------------- */
    uint8_t attester_ek_fingerprint[32] = {0};
    if (hash_sha256(identity.ek_certificate_len, identity.ek_certificate,
                attester_ek_fingerprint) == CHARRA_RC_SUCCESS) {
        charra_ak_state_record rp_ak_record = {0};
        memcpy(rp_ak_record.ek_fingerprint, attester_ek_fingerprint,
                sizeof(rp_ak_record.ek_fingerprint));
        rp_ak_record.ak_name_len = identity.ak_name_len;
        memcpy(rp_ak_record.ak_name, identity.ak_name, identity.ak_name_len);
        memcpy(rp_ak_record.serial, rp_ca_serial, sizeof(rp_ak_record.serial));
        rp_ak_record.issued_at = time(NULL);
        /* Exactly the value stamped into the certificate above. */
        rp_ak_record.expires_at = rp_cert_expires_at;
        if (charra_ak_state_renew(attester_ak_state_file_path,
                    attester_ek_fingerprint, &rp_ak_record) !=
                CHARRA_RC_SUCCESS) {
            charra_log_error("[" LOG_NAME "] Could not record RP-issued "
                             "Attester AK certificate in state.");
        }
    }

    /* --- deliver to the Attester via /certify_ak_of_attester DELIVER_RP */
    msg_certify_ak_of_attester_request_dto deliver_rp_req = {0};
    deliver_rp_req.kind = CHARRA_CERTIFY_AK_OF_ATTESTER_DELIVER_RP;
    deliver_rp_req.credential_blob_len = sizeof(*rp_credential_blob);
    memcpy(deliver_rp_req.credential_blob, rp_credential_blob,
            deliver_rp_req.credential_blob_len);
    deliver_rp_req.wrapped_secret_len = sizeof(*rp_wrapped_secret);
    memcpy(deliver_rp_req.wrapped_secret, rp_wrapped_secret,
            deliver_rp_req.wrapped_secret_len);
    memcpy(deliver_rp_req.aes_gcm_nonce, rp_aes_gcm_nonce,
            sizeof(rp_aes_gcm_nonce));
    memcpy(deliver_rp_req.aes_gcm_tag, rp_aes_gcm_tag, sizeof(rp_aes_gcm_tag));
    deliver_rp_req.ak_certificate_len = rp_signed_cert_der_len;
    deliver_rp_req.ak_certificate = rp_cert_ciphertext;

    Esys_Free(rp_credential_blob);
    Esys_Free(rp_wrapped_secret);

    uint8_t* deliver_rp_buf = NULL;
    uint32_t deliver_rp_buf_len = 0;
    result = charra_marshal_certify_ak_of_attester_request(
            &deliver_rp_req, &deliver_rp_buf_len, &deliver_rp_buf);
    charra_free_if_not_null(rp_cert_ciphertext);
    if (result != CHARRA_RC_SUCCESS) {
        charra_log_error(
                "[" LOG_NAME "] Could not marshal DELIVER_RP request.");
        charra_free_if_not_null(identity.ek_certificate);
        charra_free_if_not_null(rp_signed_cert_der);
        return result;
    }

    result = rp_coap_fetch(attester_host, attester_port,
            "certify_ak_of_attester", deliver_rp_buf, deliver_rp_buf_len,
            coap_certify_ak_of_attester_deliver_response_handler,
            &processing_certify_ak_of_attester_deliver_response);
    free(deliver_rp_buf);
    if (result != CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] DELIVER_RP round trip to the "
                         "Attester failed.");
        charra_free_if_not_null(identity.ek_certificate);
        charra_free_if_not_null(rp_signed_cert_der);
        return result;
    }
    charra_log_info("[" LOG_NAME "] RP-CA leg delivered to the Attester.");

    /* Cache now, mirroring ensure_rp_ak_certificate(): only once we
     * genuinely trust the bytes (RP signed them itself, and delivery to
     * the Attester just succeeded). File presence is what gates skipping
     * this whole function on a future call/process restart. */
    if (charra_io_write_file(attester_ak_cert_rp_cache_path, rp_signed_cert_der,
                rp_signed_cert_der_len) != CHARRA_RC_SUCCESS) {
        charra_log_error(
                "[" LOG_NAME "] Could not cache RP-issued Attester AK "
                "certificate.");
    }
    charra_free_if_not_null(rp_signed_cert_der);

    /* Cache the fetched identity itself (not just the RP-signed cert) --
     * ensure_attester_identity_certified_by_verifier() below reuses this
     * for every Verifier rather than re-FETCHing per Verifier. Deep copy:
     * `identity` is a local about to go out of scope. */
    attester_identity_cached = identity;
    attester_identity_cached.ek_certificate = NULL;
    if (identity.ek_certificate_len > 0) {
        attester_identity_cached.ek_certificate =
                malloc(identity.ek_certificate_len);
        if (attester_identity_cached.ek_certificate == NULL) {
            charra_log_error("[" LOG_NAME "] Could not cache Attester "
                             "identity for per-Verifier certification.");
            charra_free_if_not_null(identity.ek_certificate);
            return CHARRA_RC_ERROR;
        }
        memcpy(attester_identity_cached.ek_certificate, identity.ek_certificate,
                identity.ek_certificate_len);
        attester_identity_cached.ek_certificate_len = identity.ek_certificate_len;
    }
    charra_free_if_not_null(identity.ek_certificate);

    charra_log_info(
            "[" LOG_NAME "] Attester identity provisioned (RP's own CA); "
            "ready for per-Verifier certification.");
    attester_identity_provisioned = true;
    return CHARRA_RC_SUCCESS;
}

static CHARRA_RC ensure_attester_identity_certified_by_verifier(
        int verifier_index) {
    if (attester_ak_cert_by_verifier_ready[verifier_index]) {
        return CHARRA_RC_SUCCESS;
    }

    CHARRA_RC result = ensure_attester_identity_provisioned();
    if (result != CHARRA_RC_SUCCESS) {
        return result;
    }

    const char* verifier_host = verifiers[verifier_index].ip_address;
    unsigned int verifier_port = verifiers[verifier_index].port_number;

    char cert_path[112] = {0};
    snprintf(cert_path, sizeof(cert_path),
            "state/relying-party/attester-ak-certificates/"
            "attester-ak-certificate-verifier-%u.der",
            verifier_port);

    if (charra_io_file_exists(cert_path) == CHARRA_RC_SUCCESS) {
        char* cert_buf = NULL;
        size_t cert_buf_len = 0;
        if ((result = charra_io_read_file(cert_path, &cert_buf,
                     &cert_buf_len)) != CHARRA_RC_SUCCESS) {
            charra_log_error("[" LOG_NAME "] Could not read cached "
                             "Attester AK certificate for this Verifier.");
            return result;
        }
        uint8_t* cert_der = malloc(cert_buf_len);
        if (cert_der == NULL) {
            charra_io_free_file_buffer(&cert_buf);
            return CHARRA_RC_ERROR;
        }
        memcpy(cert_der, cert_buf, cert_buf_len);
        charra_io_free_file_buffer(&cert_buf);

        mbedtls_x509_crt cached_cert;
        mbedtls_x509_crt_init(&cached_cert);
        if (mbedtls_x509_crt_parse(&cached_cert, cert_der, cert_buf_len) ==
                0) {
            charra_log_info("[" LOG_NAME "] Reloading previously issued "
                            "Attester AK certificate for Verifier %s:%u "
                            "(cached, expires in %ld day(s)).",
                    verifier_host, verifier_port,
                    charra_crypto_x509_days_until_expiry(&cached_cert));
        } else {
            charra_log_info("[" LOG_NAME "] Reloading previously issued "
                            "Attester AK certificate for Verifier %s:%u "
                            "(cached).",
                    verifier_host, verifier_port);
        }
        mbedtls_x509_crt_free(&cached_cert);

        attester_ak_cert_by_verifier_der[verifier_index] = cert_der;
        attester_ak_cert_by_verifier_der_len[verifier_index] =
                (uint32_t)cert_buf_len;
        attester_ak_cert_by_verifier_ready[verifier_index] = true;
        return CHARRA_RC_SUCCESS;
    }

    charra_log_info("[" LOG_NAME "]  +------------ Attester Identity "
                    "Certification (Verifier %s:%u) --------------+",
            verifier_host, verifier_port);

    pthread_mutex_lock(&attester_identity_relay_mutex);

    msg_certify_ak_request_dto verifier_req = {0};
    verifier_req.kind = CHARRA_CERTIFY_AK_CHALLENGE;
    verifier_req.subject = CHARRA_CERTIFY_AK_SUBJECT_ATTESTER;
    verifier_req.ek_certificate = attester_identity_cached.ek_certificate;
    verifier_req.ek_certificate_len =
            attester_identity_cached.ek_certificate_len;
    verifier_req.ak_public_key_len = attester_identity_cached.ak_public_key_len;
    memcpy(verifier_req.ak_public_key, attester_identity_cached.ak_public_key,
            attester_identity_cached.ak_public_key_len);
    verifier_req.ak_name_len = attester_identity_cached.ak_name_len;
    memcpy(verifier_req.ak_name, attester_identity_cached.ak_name,
            attester_identity_cached.ak_name_len);

    msg_certify_ak_response_dto verifier_challenge = {0};
    result = rp_certify_ak_exchange(
            verifier_host, verifier_port, &verifier_req, &verifier_challenge);
    if (result != CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Relayed /certify_ak CHALLENGE to "
                         "the Verifier failed.");
        pthread_mutex_unlock(&attester_identity_relay_mutex);
        return result;
    }

    /* --- relay the challenge to the Attester: only its TPM can activate
     * it, so the secret it returns is the possession proof the RP itself
     * could not have produced. ----------------------------------------- */
    msg_certify_ak_of_attester_request_dto activate_req = {0};
    activate_req.kind = CHARRA_CERTIFY_AK_OF_ATTESTER_ACTIVATE;
    activate_req.credential_blob_len = verifier_challenge.credential_blob_len;
    memcpy(activate_req.credential_blob, verifier_challenge.credential_blob,
            verifier_challenge.credential_blob_len);
    activate_req.wrapped_secret_len = verifier_challenge.wrapped_secret_len;
    memcpy(activate_req.wrapped_secret, verifier_challenge.wrapped_secret,
            verifier_challenge.wrapped_secret_len);
    charra_free_if_not_null(verifier_challenge.ak_certificate);

    uint8_t* activate_buf = NULL;
    uint32_t activate_buf_len = 0;
    result = charra_marshal_certify_ak_of_attester_request(
            &activate_req, &activate_buf_len, &activate_buf);
    if (result != CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Could not marshal ACTIVATE request.");
        pthread_mutex_unlock(&attester_identity_relay_mutex);
        return result;
    }

    activate_credential_rc = CHARRA_RC_ERROR;
    memset(&activate_credential_response, 0,
            sizeof(activate_credential_response));
    result = rp_coap_fetch(attester_host, attester_port,
            "certify_ak_of_attester", activate_buf, activate_buf_len,
            coap_activate_credential_response_handler,
            &processing_activate_credential_response);
    free(activate_buf);
    if (result == CHARRA_RC_SUCCESS && activate_credential_rc !=
            CHARRA_RC_SUCCESS) {
        result = activate_credential_rc;
    }
    if (result != CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Attester could not activate the "
                         "Verifier's challenge.");
        pthread_mutex_unlock(&attester_identity_relay_mutex);
        return result;
    }
    charra_log_info("[" LOG_NAME "] Attester activated the Verifier's "
                    "challenge (%u-byte secret recovered).",
            activate_credential_response.secret_len);

    /* --- CONFIRM on the Attester's behalf, echoing its secret --- */
    msg_certify_ak_request_dto verifier_confirm = {0};
    verifier_confirm.kind = CHARRA_CERTIFY_AK_CONFIRM;
    verifier_confirm.ek_certificate = attester_identity_cached.ek_certificate;
    verifier_confirm.ek_certificate_len =
            attester_identity_cached.ek_certificate_len;
    verifier_confirm.secret_len = activate_credential_response.secret_len;
    memcpy(verifier_confirm.secret, activate_credential_response.secret,
            activate_credential_response.secret_len);

    msg_certify_ak_response_dto verifier_cert_response = {0};
    result = rp_certify_ak_exchange(verifier_host, verifier_port,
            &verifier_confirm, &verifier_cert_response);
    if (result != CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Relayed /certify_ak CONFIRM to the "
                         "Verifier failed.");
        pthread_mutex_unlock(&attester_identity_relay_mutex);
        return result;
    }
    if (verifier_cert_response.ak_certificate_len == 0) {
        charra_log_error("[" LOG_NAME "] Verifier's CONFIRM returned no "
                         "certificate for the Attester.");
        charra_free_if_not_null(verifier_cert_response.ak_certificate);
        pthread_mutex_unlock(&attester_identity_relay_mutex);
        return CHARRA_RC_ERROR;
    }

    charra_log_info(
            "[" LOG_NAME "] Verifier certified the Attester's AK (relayed).");

    /* --- deliver a copy to the Attester too, for its own records. RP
     * itself is what actually forwards the right certificate to each
     * Verifier during /appraise (charra_rp_build_evidence_message()
     * substitutes attester_ak_cert_by_verifier_der[] directly), so this
     * leg is informational only now, not load-bearing -- non-fatal on
     * failure, and harmless if a later Verifier's copy overwrites it
     * (attester.c caches only the most recent one). --------------------- */
    msg_certify_ak_of_attester_request_dto deliver_verifier_req = {0};
    deliver_verifier_req.kind = CHARRA_CERTIFY_AK_OF_ATTESTER_DELIVER_VERIFIER;
    deliver_verifier_req.ak_certificate_len =
            verifier_cert_response.ak_certificate_len;
    deliver_verifier_req.ak_certificate = verifier_cert_response.ak_certificate;

    uint8_t* deliver_verifier_buf = NULL;
    uint32_t deliver_verifier_buf_len = 0;
    if (charra_marshal_certify_ak_of_attester_request(&deliver_verifier_req,
                &deliver_verifier_buf_len, &deliver_verifier_buf) !=
            CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Could not marshal DELIVER_VERIFIER "
                         "request (non-fatal).");
    } else if (rp_coap_fetch(attester_host, attester_port,
                       "certify_ak_of_attester", deliver_verifier_buf,
                       deliver_verifier_buf_len,
                       coap_certify_ak_of_attester_deliver_response_handler,
                       &processing_certify_ak_of_attester_deliver_response) !=
            CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] DELIVER_VERIFIER round trip to the "
                         "Attester failed (non-fatal -- RP already holds "
                         "the certificate itself).");
    }
    free(deliver_verifier_buf);

    pthread_mutex_unlock(&attester_identity_relay_mutex);

    if ((result = charra_io_write_file(cert_path,
                 verifier_cert_response.ak_certificate,
                 verifier_cert_response.ak_certificate_len)) !=
            CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Could not cache Attester AK "
                         "certificate for this Verifier.");
        charra_free_if_not_null(verifier_cert_response.ak_certificate);
        return result;
    }

    attester_ak_cert_by_verifier_der[verifier_index] =
            verifier_cert_response.ak_certificate;
    attester_ak_cert_by_verifier_der_len[verifier_index] =
            verifier_cert_response.ak_certificate_len;
    attester_ak_cert_by_verifier_ready[verifier_index] = true;

    charra_log_info(
            "[" LOG_NAME "] Attester's AK certified by Verifier %s:%u "
            "(%u-byte certificate).",
            verifier_host, verifier_port,
            verifier_cert_response.ak_certificate_len);

    return CHARRA_RC_SUCCESS;
}

static CHARRA_RC ensure_rp_ak_keypair(void) {
    pthread_mutex_lock(&rp_tpm_mutex);
    if (rp_ak_keypair_ready) {
        pthread_mutex_unlock(&rp_tpm_mutex);
        return CHARRA_RC_SUCCESS;
    }

    charra_log_info(
            "[" LOG_NAME "]  +------------ RP TPM Identity --------------+");

    CHARRA_RC result = CHARRA_RC_ERROR;
    TPM2B_PUBLIC ak_public = {0};

    bool cached = charra_io_file_exists(rp_ak_public_path) ==
                    CHARRA_RC_SUCCESS &&
            charra_io_file_exists(rp_ak_private_path) == CHARRA_RC_SUCCESS;

    if (cached) {
        /* No TPM needed at all here: this is a pure file read. The AK
         * itself is only ever loaded into the TPM when actually signing or
         * certifying (see rp_open_tpm_and_load_ak()). */
        charra_log_info(
                "[" LOG_NAME "] Reloading previously provisioned RP AK "
                "keypair.");
        if ((result = charra_identity_key_mgr_load_public(
                     rp_ak_public_path, &ak_public)) != CHARRA_RC_SUCCESS) {
            charra_log_error("[" LOG_NAME "] Could not load cached AK public "
                             "key.");
            pthread_mutex_unlock(&rp_tpm_mutex);
            return result;
        }
    } else {
        charra_log_info(
                "[" LOG_NAME "] No cached RP AK keypair -- creating one.");

        /* --- TPM session (mutex-held): create EK + AK, persist blobs.
         * Closed before returning -- every other TPM use in this file
         * (signing, certifying) opens its own short-lived connection; see
         * rp_tpm_mutex's own comment for why holding one open longer than
         * one operation needs is a real problem on this dev TPM
         * simulator, not just tidiness. */
        ESYS_CONTEXT* esys_ctx = NULL;
        TSS2_TCTI_CONTEXT* tcti_ctx = NULL;
        ESYS_TR ek_handle = ESYS_TR_NONE;
        ESYS_TR ak_handle = ESYS_TR_NONE;
        TPM2B_NAME* ak_name = NULL;
        TPM2B_PUBLIC* ek_public = NULL;
        TPM2B_PRIVATE ak_private = {0};
        uint8_t* ek_cert_der = NULL;
        size_t ek_cert_der_len = 0;
        bool ek_cert_der_from_read_file = false;

        TSS2_RC tss_r = 0;
        if ((tss_r = Tss2_TctiLdr_Initialize(
                     getenv("CHARRA_TCTI"), &tcti_ctx)) != TSS2_RC_SUCCESS) {
            charra_log_error("[" LOG_NAME "] Tss2_TctiLdr_Initialize.");
            pthread_mutex_unlock(&rp_tpm_mutex);
            return CHARRA_RC_ERROR;
        }
        if ((tss_r = Esys_Initialize(&esys_ctx, tcti_ctx, NULL)) !=
                TSS2_RC_SUCCESS) {
            charra_log_error("[" LOG_NAME "] Esys_Initialize.");
            Tss2_TctiLdr_Finalize(&tcti_ctx);
            pthread_mutex_unlock(&rp_tpm_mutex);
            return CHARRA_RC_ERROR;
        }

        if ((result = charra_identity_key_mgr_create_ek(
                     esys_ctx, &ek_handle, &ek_public)) != CHARRA_RC_SUCCESS) {
            charra_log_error("[" LOG_NAME "] Could not create RP's EK.");
            Esys_Finalize(&esys_ctx);
            Tss2_TctiLdr_Finalize(&tcti_ctx);
            pthread_mutex_unlock(&rp_tpm_mutex);
            return result;
        }

        /* --- RP's own EK certificate: cached after the first mint, since
         * charra_identity_key_mgr_create_ek() reproduces the same EK every time
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
                return result;
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
                return result;
            }
            mbedtls_x509_crt manufacturer_root_cert;
            mbedtls_x509_crt_init(&manufacturer_root_cert);
            if (mbedtls_x509_crt_parse(&manufacturer_root_cert,
                        (uint8_t*)manufacturer_root_der,
                        manufacturer_root_der_len) != 0) {
                charra_log_error("[" LOG_NAME "] Could not parse "
                                 "manufacturer root certificate.");
                charra_io_free_file_buffer(&manufacturer_root_der);
                Esys_Free(ek_public);
                Esys_FlushContext(esys_ctx, ek_handle);
                Esys_Finalize(&esys_ctx);
                Tss2_TctiLdr_Finalize(&tcti_ctx);
                pthread_mutex_unlock(&rp_tpm_mutex);
                return CHARRA_RC_CRYPTO_ERROR;
            }
            char issuer_name[256] = {0};
            if (mbedtls_x509_dn_gets(issuer_name, sizeof(issuer_name),
                        &manufacturer_root_cert.subject) <= 0) {
                charra_log_error("[" LOG_NAME "] Could not read manufacturer "
                                 "root subject name.");
                mbedtls_x509_crt_free(&manufacturer_root_cert);
                charra_io_free_file_buffer(&manufacturer_root_der);
                Esys_Free(ek_public);
                Esys_FlushContext(esys_ctx, ek_handle);
                Esys_Finalize(&esys_ctx);
                Tss2_TctiLdr_Finalize(&tcti_ctx);
                pthread_mutex_unlock(&rp_tpm_mutex);
                return CHARRA_RC_CRYPTO_ERROR;
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
                return result;
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
                charra_free_if_not_null(ek_cert_der);
                return result;
            }
        }
        Esys_Free(ek_public);
        if (ek_cert_der_from_read_file) {
            free(ek_cert_der);
        } else {
            charra_free_if_not_null(ek_cert_der);
        }

        /* --- create the AK, persist its blobs -------------------------- */
        TPM2B_PUBLIC* ak_public_p = NULL;
        TPM2B_PRIVATE* ak_private_p = NULL;
        if ((result = charra_identity_key_mgr_create_ak(esys_ctx, ek_handle,
                     &ak_handle, &ak_public_p, &ak_private_p, &ak_name)) !=
                CHARRA_RC_SUCCESS) {
            charra_log_error("[" LOG_NAME "] Could not create RP's AK.");
            Esys_FlushContext(esys_ctx, ek_handle);
            Esys_Finalize(&esys_ctx);
            Tss2_TctiLdr_Finalize(&tcti_ctx);
            pthread_mutex_unlock(&rp_tpm_mutex);
            return result;
        }
        ak_public = *ak_public_p;
        ak_private = *ak_private_p;
        Esys_Free(ak_public_p);
        Esys_Free(ak_private_p);
        Esys_Free(ak_name);

        if ((result = charra_identity_key_mgr_save_public(
                     rp_ak_public_path, &ak_public)) != CHARRA_RC_SUCCESS) {
            charra_log_error("[" LOG_NAME "] Could not persist AK public key.");
            Esys_FlushContext(esys_ctx, ak_handle);
            Esys_FlushContext(esys_ctx, ek_handle);
            Esys_Finalize(&esys_ctx);
            Tss2_TctiLdr_Finalize(&tcti_ctx);
            pthread_mutex_unlock(&rp_tpm_mutex);
            return result;
        }
        if ((result = charra_identity_key_mgr_save_private(
                     rp_ak_private_path, &ak_private)) != CHARRA_RC_SUCCESS) {
            charra_log_error(
                    "[" LOG_NAME "] Could not persist AK private area.");
            Esys_FlushContext(esys_ctx, ak_handle);
            Esys_FlushContext(esys_ctx, ek_handle);
            Esys_Finalize(&esys_ctx);
            Tss2_TctiLdr_Finalize(&tcti_ctx);
            pthread_mutex_unlock(&rp_tpm_mutex);
            return result;
        }

        Esys_FlushContext(esys_ctx, ak_handle);
        Esys_FlushContext(esys_ctx, ek_handle);
        Esys_Finalize(&esys_ctx);
        Tss2_TctiLdr_Finalize(&tcti_ctx);
    }

    if ((result = charra_identity_key_mgr_public_key_to_der(&ak_public,
                 rp_public_key_der, sizeof(rp_public_key_der),
                 &rp_public_key_der_len)) != CHARRA_RC_SUCCESS) {
        charra_log_error(
                "[" LOG_NAME "] Could not DER-encode RP's AK public key.");
        pthread_mutex_unlock(&rp_tpm_mutex);
        return result;
    }

    rp_ak_keypair_ready = true;
    pthread_mutex_unlock(&rp_tpm_mutex);
    return CHARRA_RC_SUCCESS;
}

static CHARRA_RC ensure_rp_ak_certificate(int verifier_index) {
    if (rp_ak_cert_ready[verifier_index]) {
        /* No work happens on this path, so it's "cached" for the summary. */
        rp_ak_cert_was_cached[verifier_index] = true;
        return CHARRA_RC_SUCCESS;
    }

    CHARRA_RC result = ensure_rp_ak_keypair();
    if (result != CHARRA_RC_SUCCESS) {
        return result;
    }

    const char* verifier_host = verifiers[verifier_index].ip_address;
    unsigned int verifier_port = verifiers[verifier_index].port_number;

    charra_log_info("[" LOG_NAME "]  +------------ RP AK Certificate "
                    "(Verifier %s:%u) --------------+",
            verifier_host, verifier_port);

    char cert_path[96] = {0};
    snprintf(cert_path, sizeof(cert_path),
            "state/relying-party/ak-certificates/rp-ak-certificate-%u.der",
            verifier_port);

    if (charra_io_file_exists(cert_path) == CHARRA_RC_SUCCESS) {
        char* cert_buf = NULL;
        size_t cert_buf_len = 0;
        if ((result = charra_io_read_file(cert_path, &cert_buf,
                     &cert_buf_len)) != CHARRA_RC_SUCCESS) {
            charra_log_error(
                    "[" LOG_NAME "] Could not read cached AK certificate.");
            return result;
        }
        uint8_t* cert_der = malloc(cert_buf_len);
        if (cert_der == NULL) {
            charra_io_free_file_buffer(&cert_buf);
            return CHARRA_RC_ERROR;
        }
        memcpy(cert_der, cert_buf, cert_buf_len);
        charra_io_free_file_buffer(&cert_buf);

        /* Informational only -- the Verifier enforces expiry, not this. */
        mbedtls_x509_crt cached_cert;
        mbedtls_x509_crt_init(&cached_cert);
        if (mbedtls_x509_crt_parse(&cached_cert, cert_der, cert_buf_len) ==
                0) {
            charra_log_info("[" LOG_NAME "] Reloading previously issued AK "
                            "certificate for this Verifier (cached, expires "
                            "in %ld day(s)).",
                    charra_crypto_x509_days_until_expiry(&cached_cert));
        } else {
            charra_log_info("[" LOG_NAME "] Reloading previously issued AK "
                            "certificate for this Verifier (cached).");
        }
        mbedtls_x509_crt_free(&cached_cert);

        rp_ak_cert_der[verifier_index] = cert_der;
        rp_ak_cert_der_len[verifier_index] = (uint32_t)cert_buf_len;
        rp_ak_cert_ready[verifier_index] = true;
        rp_ak_cert_was_cached[verifier_index] = true;
        return CHARRA_RC_SUCCESS;
    }

    charra_log_info("[" LOG_NAME "] No cached AK certificate for this "
                    "Verifier -- provisioning via /certify_ak.");

    char* ek_cert_buf = NULL;
    size_t ek_cert_buf_len = 0;
    if ((result = charra_io_read_file(rp_ek_cert_cache_path, &ek_cert_buf,
                 &ek_cert_buf_len)) != CHARRA_RC_SUCCESS) {
        charra_log_error(
                "[" LOG_NAME "] Could not read RP's EK certificate.");
        return result;
    }

    /* --- TPM session #1 (mutex-held): load the already-persisted AK to
     * get ak_public + ak_name, then CLOSE the connection before the
     * /certify_ak round trip below -- critical, not cosmetic: the
     * Verifier's own /certify_ak handler needs its own TPM connection to
     * complete Esys_MakeCredential, and the dev TPM simulator accepts only
     * one client connection at a time. Holding this connection open across
     * the CoAP wait deadlocks the Verifier's response indefinitely
     * (confirmed directly while developing this: killing an RP stuck here
     * immediately unblocked the Verifier's handler, which had been sitting
     * mid-MakeCredential the whole time). ------------------------------ */
    pthread_mutex_lock(&rp_tpm_mutex);
    ESYS_CONTEXT* esys_ctx = NULL;
    TSS2_TCTI_CONTEXT* tcti_ctx = NULL;
    ESYS_TR ek_handle = ESYS_TR_NONE;
    ESYS_TR ak_handle = ESYS_TR_NONE;
    TPM2B_NAME* ak_name = NULL;
    if ((result = rp_open_tpm_and_load_ak(&esys_ctx, &tcti_ctx, &ek_handle,
                 &ak_handle, &ak_name)) != CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Could not open TPM connection to "
                         "load RP's AK.");
        pthread_mutex_unlock(&rp_tpm_mutex);
        charra_io_free_file_buffer(&ek_cert_buf);
        return result;
    }

    TPM2B_PUBLIC ak_public = {0};
    if ((result = charra_identity_key_mgr_load_public(rp_ak_public_path,
                 &ak_public)) != CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Could not load AK public key for "
                         "/certify_ak request.");
        Esys_Free(ak_name);
        Esys_FlushContext(esys_ctx, ak_handle);
        Esys_FlushContext(esys_ctx, ek_handle);
        Esys_Finalize(&esys_ctx);
        Tss2_TctiLdr_Finalize(&tcti_ctx);
        pthread_mutex_unlock(&rp_tpm_mutex);
        charra_io_free_file_buffer(&ek_cert_buf);
        return result;
    }

    /* --- /certify_ak request, built now while ak_name is still valid,
     * sent AFTER the TPM connection below is closed -------------- */
    /* --- CHALLENGE request, built now while ak_name is still valid, sent
     * AFTER the TPM connection below is closed -------------------------- */
    msg_certify_ak_request_dto req = {0};
    req.kind = CHARRA_CERTIFY_AK_CHALLENGE;
    req.subject = CHARRA_CERTIFY_AK_SUBJECT_RP;
    req.ek_certificate = (uint8_t*)ek_cert_buf;
    req.ek_certificate_len = (uint32_t)ek_cert_buf_len;
    req.ak_public_key_len = sizeof(ak_public);
    memcpy(req.ak_public_key, &ak_public, sizeof(ak_public));
    /* Copy only the meaningful prefix (size field + size bytes) and
     * zero the rest: Esys_TR_GetName() leaves the tail of the
     * TPM2B_NAME allocation uninitialised, and copying the whole
     * struct put those heap bytes straight onto the wire (caught by
     * valgrind via libcoap reading them while building the PDU).
     * The field stays fixed-size, so the wire format is unchanged --
     * the tail is now deterministic zeros instead of stale heap. */
    req.ak_name_len = sizeof(*ak_name);
    memset(req.ak_name, 0, sizeof(req.ak_name));
    memcpy(req.ak_name, ak_name, sizeof(ak_name->size) + ak_name->size);
    Esys_Free(ak_name);

    Esys_FlushContext(esys_ctx, ak_handle);
    Esys_FlushContext(esys_ctx, ek_handle);
    Esys_Finalize(&esys_ctx);
    Tss2_TctiLdr_Finalize(&tcti_ctx);
    pthread_mutex_unlock(&rp_tpm_mutex);

    charra_log_info("[" LOG_NAME "] /certify_ak: requesting a CHALLENGE ...");
    msg_certify_ak_response_dto challenge = {0};
    if ((result = rp_certify_ak_exchange(
                 verifier_host, verifier_port, &req, &challenge)) !=
            CHARRA_RC_SUCCESS) {
        charra_log_error(
                "[" LOG_NAME "] /certify_ak CHALLENGE leg did not complete.");
        charra_io_free_file_buffer(&ek_cert_buf);
        return result;
    }

    /* --- TPM session #2: recover the challenge secret via
     * ActivateCredential. Only this TPM can, which is exactly what the
     * Verifier's CONFIRM leg is about to check. --------------------------- */
    charra_log_info("[" LOG_NAME "] Waiting on TPM mutex for "
                    "ActivateCredential (TPM session #2) ...");
    pthread_mutex_lock(&rp_tpm_mutex);
    ESYS_TR ek_handle2 = ESYS_TR_NONE;
    ESYS_TR ak_handle2 = ESYS_TR_NONE;
    TPM2B_NAME* ak_name2 = NULL;
    struct timespec activate_start, activate_end;
    clock_gettime(CLOCK_MONOTONIC, &activate_start);
    if ((result = rp_open_tpm_and_load_ak(&esys_ctx, &tcti_ctx, &ek_handle2,
                 &ak_handle2, &ak_name2)) != CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Could not reopen TPM connection "
                         "for ActivateCredential.");
        pthread_mutex_unlock(&rp_tpm_mutex);
        charra_free_if_not_null(challenge.ak_certificate);
        charra_io_free_file_buffer(&ek_cert_buf);
        return result;
    }
    Esys_Free(ak_name2);

    TPM2B_DIGEST* credential = NULL;
    if ((result = charra_identity_key_mgr_activate_credential(esys_ctx,
                 ak_handle2, ek_handle2,
                 (TPM2B_ID_OBJECT*)challenge.credential_blob,
                 (TPM2B_ENCRYPTED_SECRET*)challenge.wrapped_secret,
                 &credential)) != CHARRA_RC_SUCCESS) {
        charra_log_error(
                "[" LOG_NAME "] ActivateCredential failed -- this AK is not "
                "genuinely bound to this EK, or the TPM rejected the "
                "request.");
        Esys_FlushContext(esys_ctx, ak_handle2);
        Esys_FlushContext(esys_ctx, ek_handle2);
        Esys_Finalize(&esys_ctx);
        Tss2_TctiLdr_Finalize(&tcti_ctx);
        pthread_mutex_unlock(&rp_tpm_mutex);
        charra_free_if_not_null(challenge.ak_certificate);
        charra_io_free_file_buffer(&ek_cert_buf);
        return result;
    }
    Esys_FlushContext(esys_ctx, ak_handle2);
    Esys_FlushContext(esys_ctx, ek_handle2);
    Esys_Finalize(&esys_ctx);
    Tss2_TctiLdr_Finalize(&tcti_ctx);
    pthread_mutex_unlock(&rp_tpm_mutex);
    clock_gettime(CLOCK_MONOTONIC, &activate_end);
    double activate_duration =
            (activate_end.tv_sec - activate_start.tv_sec) +
            (activate_end.tv_nsec - activate_start.tv_nsec) / 1e9;
    charra_free_if_not_null(challenge.ak_certificate);

    charra_log_info("[" LOG_NAME "] ActivateCredential recovered the %u-byte "
                    "challenge secret in %.3fs.",
            credential->size, activate_duration);

    if (credential->size != CHARRA_CERTIFY_AK_SECRET_LEN) {
        charra_log_error("[" LOG_NAME "] Recovered secret has unexpected "
                         "size %u (expected %d).",
                credential->size, CHARRA_CERTIFY_AK_SECRET_LEN);
        Esys_Free(credential);
        charra_io_free_file_buffer(&ek_cert_buf);
        return CHARRA_RC_VERIFICATION_FAILED;
    }

    /* --- CONFIRM: echo the secret back. Only on a match does the Verifier
     * sign, record, and release the certificate. ------------------------- */
    msg_certify_ak_request_dto confirm_req = {0};
    confirm_req.kind = CHARRA_CERTIFY_AK_CONFIRM;
    confirm_req.ek_certificate = (uint8_t*)ek_cert_buf;
    confirm_req.ek_certificate_len = (uint32_t)ek_cert_buf_len;
    confirm_req.secret_len = credential->size;
    memcpy(confirm_req.secret, credential->buffer, credential->size);
    Esys_Free(credential);

    charra_log_info("[" LOG_NAME "] /certify_ak: echoing the secret back "
                    "(CONFIRM) ...");
    msg_certify_ak_response_dto confirmed = {0};
    result = rp_certify_ak_exchange(
            verifier_host, verifier_port, &confirm_req, &confirmed);
    charra_io_free_file_buffer(&ek_cert_buf);
    if (result != CHARRA_RC_SUCCESS) {
        charra_log_error(
                "[" LOG_NAME "] /certify_ak CONFIRM leg did not complete.");
        return result;
    }
    if (confirmed.ak_certificate_len == 0 ||
            confirmed.ak_certificate == NULL) {
        charra_log_error("[" LOG_NAME "] /certify_ak CONFIRM returned no "
                         "certificate.");
        charra_free_if_not_null(confirmed.ak_certificate);
        return CHARRA_RC_ERROR;
    }

    uint8_t* cert_der = confirmed.ak_certificate;
    uint32_t cert_der_len = confirmed.ak_certificate_len;

    if ((result = charra_io_write_file(cert_path, cert_der, cert_der_len)) !=
            CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Could not cache AK certificate.");
        charra_free_if_not_null(cert_der);
        return result;
    }

    rp_ak_cert_der[verifier_index] = cert_der;
    rp_ak_cert_der_len[verifier_index] = cert_der_len;
    rp_ak_cert_ready[verifier_index] = true;

    mbedtls_x509_crt new_cert;
    mbedtls_x509_crt_init(&new_cert);
    if (mbedtls_x509_crt_parse(&new_cert, cert_der, cert_der_len) == 0) {
        charra_log_info("[" LOG_NAME "] RP AK certified by this Verifier "
                        "(freshly provisioned, %u-byte certificate, expires "
                        "in %ld day(s)).",
                cert_der_len, charra_crypto_x509_days_until_expiry(&new_cert));
    } else {
        charra_log_info("[" LOG_NAME "] RP AK certified by this Verifier "
                        "(freshly provisioned, %u-byte certificate).",
                cert_der_len);
    }
    mbedtls_x509_crt_free(&new_cert);
    return CHARRA_RC_SUCCESS;
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
    rp_qualification_rejected[*current_thread_index] = false;

    if (coap_pdu_get_code(received) == COAP_RESPONSE_CODE_UNAUTHORIZED) {
        /* Verifier rejected our AK certificate specifically (see
         * verifier.c's coap_appraise_handler, Step 3a item 1), not the
         * evidence itself -- signal the caller to re-provision via
         * /certify_ak and retry, rather than just recording a failed
         * vote a blind retry could never fix. */
        charra_log_info("[" LOG_NAME "] Verifier n° %d (port %u) rejected "
                        "our AK certificate as invalid or expired.",
                *current_thread_index + 1,
                verifiers[*current_thread_index].port_number);
        snprintf(rejection_reason[*current_thread_index],
                sizeof(rejection_reason[*current_thread_index]),
                "AK certificate rejected as invalid or expired");
        rp_ak_cert_rejected[*current_thread_index] = true;
        attestation_results[*current_thread_index] = false;
        goto cleanup;
    }

    if (coap_pdu_get_code(received) == COAP_RESPONSE_CODE_FORBIDDEN) {
        /* Verifier rejected our qualification specifically (see verifier.c's
         * coap_appraise_handler, Step 3a item 1b) -- either we never
         * qualified with it, or a grant we thought was still valid (per our
         * own local cache, rp_qualified_until) has expired on its end.
         * Either way, the message text says which; log it, then signal the
         * caller to invalidate the local cache, redo /qualify +
         * /qualify/submit, and retry -- same one-retry pattern as the AK
         * certificate case above. */
        size_t forbidden_data_len = 0;
        const uint8_t* forbidden_data = NULL;
        size_t forbidden_data_offset = 0;
        size_t forbidden_data_total_len = 0;
        if (coap_get_data_large(received, &forbidden_data_len,
                    &forbidden_data, &forbidden_data_offset,
                    &forbidden_data_total_len) != 0) {
            charra_log_info("[" LOG_NAME "] Verifier n° %d (port %u): %.*s",
                    *current_thread_index + 1,
                    verifiers[*current_thread_index].port_number,
                    (int)forbidden_data_len, (const char*)forbidden_data);
            int n = (int)forbidden_data_len <
                                    (int)sizeof(
                                            rejection_reason[0]) - 1
                            ? (int)forbidden_data_len
                            : (int)sizeof(rejection_reason[0]) - 1;
            snprintf(rejection_reason[*current_thread_index],
                    sizeof(rejection_reason[*current_thread_index]), "%.*s",
                    n, (const char*)forbidden_data);
        } else {
            charra_log_info("[" LOG_NAME "] Verifier n° %d (port %u) "
                            "rejected our qualification.",
                    *current_thread_index + 1,
                    verifiers[*current_thread_index].port_number);
            snprintf(rejection_reason[*current_thread_index],
                    sizeof(rejection_reason[*current_thread_index]),
                    "qualification rejected");
        }
        rp_qualification_rejected[*current_thread_index] = true;
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

    /* Unmarshal via the same shared, tested CBOR marshal/unmarshal pattern
     * every other endpoint in this codebase uses (charra_marshaling.c) --
     * replaces the hand-packed raw-byte layout this used to parse
     * manually, with no bounds check tying the response's declared length
     * to how many records it actually contains. That gap is exactly what
     * once let a Trust Manager response shorter (or, via a since-fixed
     * response_len bug on the Trust Manager side, longer) than expected
     * be silently over- or mis-read -- see CHARRA_V2_NOTES.md.
     * charra_unmarshal_get_verifiers_response() rejects a malformed or
     * oversized response outright instead. */
    msg_get_verifiers_response_dto resp = {0};
    CHARRA_RC charra_r = charra_unmarshal_get_verifiers_response(
            (uint32_t)data_total_len, data, &resp);
    if (charra_r != CHARRA_RC_SUCCESS) {
        charra_log_error(
                "[" LOG_NAME "] Could not parse CBOR response: CHARRA_RC=%d.",
                charra_r);
        goto cleanup;
    }

    /* Trust Manager can legitimately return FEWER records than
     * num_verifiers requested, if some of the requested IDs aren't in its
     * verifiers_config.txt (see trust_manager.c's "Lookup summary: ...
     * missing" log) -- copy only as many as actually arrived. num_verifiers
     * itself was already bounds-checked against MAX_VERIFIERS before this
     * request was ever sent (see get_verifiers()), so verifiers[] below
     * can't overflow either way. */
    size_t verifiers_to_copy = resp.verifiers_len;
    if (verifiers_to_copy > (size_t)num_verifiers) {
        charra_log_error(
                "[" LOG_NAME "] Trust Manager returned %u verifier "
                "record(s), more than the %d requested -- ignoring the "
                "extra.",
                resp.verifiers_len, num_verifiers);
        verifiers_to_copy = (size_t)num_verifiers;
    } else if (verifiers_to_copy < (size_t)num_verifiers) {
        charra_log_error(
                "[" LOG_NAME "] Trust Manager returned %u verifier "
                "record(s), expected %d -- some requested Verifier ID(s) "
                "are missing from its configuration.",
                resp.verifiers_len, num_verifiers);
    }

    for (size_t i = 0; i < verifiers_to_copy; i++) {
        snprintf(verifiers[i].ip_address, sizeof(verifiers[i].ip_address),
                "%s", resp.verifiers[i].ip_address);
        verifiers[i].port_number = resp.verifiers[i].port_number;
    }

    /* Print the received verifier information */
    for (size_t i = 0; i < verifiers_to_copy; i++) {
            charra_log_info(
            "[" LOG_NAME
            "] Verifier ID %d: IP Address = %s, Port Number = %u", verifier_list[i], verifiers[i].ip_address, verifiers[i].port_number);
    }

cleanup:
    processing_trust_manager_response = false;
    return COAP_RESPONSE_OK;
}

CHARRA_RC get_verifiers(int* verifier_list, int num_verifiers) {

    if (num_verifiers > MAX_VERIFIERS) {
        charra_log_error(
                "[" LOG_NAME "] Requested %d verifier(s), but this process "
                "only has room for %d (MAX_VERIFIERS) -- refusing to "
                "overflow verifier_list/verifiers/attestation_results.",
                num_verifiers, MAX_VERIFIERS);
        return CHARRA_RC_BAD_ARGUMENT;
    }

    charra_log_info("[" LOG_NAME "]  +------------ Interaction with the Trust Manager --------------+");

    CHARRA_RC result = EXIT_FAILURE;

    coap_context_t* coap_context = NULL;
    coap_session_t* coap_session = NULL;
    coap_optlist_t* coap_options = NULL;
    /* Declared/NULLed here, not at first use further down, so the
     * request-marshaling failure's own 'goto cleanup' (and every other
     * early exit) can safely charra_free_if_not_null() it -- same
     * hoisted-declaration convention this file already uses elsewhere
     * (e.g. get_attestation_results_thread()'s own comment on this exact
     * pattern). */
    uint8_t* req_buf = NULL;

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

    /* Marshal the request via the shared, tested CBOR marshal/unmarshal
     * pattern (charra_marshaling.c), replacing the raw int[] this used to
     * send directly over the wire with no shared format definition tying
     * it to trust_manager.c's own decoder. num_verifiers is already
     * bounds-checked against MAX_VERIFIERS (10) above, well under
     * CHARRA_MAX_REQUESTED_VERIFIERS (32), so the DTO's own fixed array
     * can't overflow here. */
    msg_get_verifiers_request_dto req = {0};
    req.verifier_ids_len = (uint32_t)num_verifiers;
    for (int i = 0; i < num_verifiers; ++i) {
        req.verifier_ids[i] = verifier_list[i];
    }
    uint32_t req_buf_len = 0;
    if ((result = charra_marshal_get_verifiers_request(
                 &req, &req_buf_len, &req_buf)) != CHARRA_RC_SUCCESS) {
        charra_log_error(
                "[" LOG_NAME "] Could not marshal /get_verifiers request.");
        goto cleanup;
    }

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
                 COAP_REQUEST_FETCH, &coap_options, req_buf, req_buf_len)) ==
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
    /* Real wall-clock elapsed time, not a sum of coap_io_process()'s own
     * self-reported per-call durations -- that undercounts real time under
     * concurrent load (see rp_coap_fetch()'s docstring comment for the
     * full explanation; this replaces the previous "not 100% accurate...
     * should be good enough" comment that turned out not to be, once
     * actually exercised under 5-way Verifier contention). */
    struct timespec wait_start, wait_now;
    clock_gettime(CLOCK_MONOTONIC, &wait_start);
    while (!processing_trust_manager_response && coap_io_pending(coap_context)) {
        /* process CoAP I/O */
        if ((coap_io_process_time = coap_io_process(
                     coap_context, COAP_IO_PROCESS_TIME_MS)) == -1) {
            charra_log_error(
                    "[" LOG_NAME "] Error during CoAP I/O processing.");
            result = CHARRA_RC_COAP_ERROR;
            goto cleanup;
        }
        clock_gettime(CLOCK_MONOTONIC, &wait_now);
        double elapsed_ms = (wait_now.tv_sec - wait_start.tv_sec) * 1000.0 +
                             (wait_now.tv_nsec - wait_start.tv_nsec) / 1e6;
        if (elapsed_ms >= (trust_manager_response_timeout * 1000)) {
            charra_log_error("[" LOG_NAME
                             "] Timeout after %.0f ms while waiting for or "
                             "processing attestation response.",
                    elapsed_ms);
            result = CHARRA_RC_TIMEOUT;
            goto cleanup;
        }
    }

    result = CHARRA_RC_SUCCESS;

cleanup:
    charra_free_if_not_null(req_buf);
    /* free CoAP memory */
    charra_free_if_not_null_ex(coap_options, coap_delete_optlist);
    charra_free_if_not_null_ex(coap_session, coap_session_release);
    charra_free_if_not_null_ex(coap_context, coap_free_context);

    /* No coap_cleanup() here: it tears down libcoap's *global* state, so
     * calling it per cycle (and from each Verifier thread) would pull the
     * ground out from under contexts still in use and from the next
     * cycle's. Done exactly once, at process exit in main(). */

    return result;

}

/**
 * @brief Sends RP's Step 2a verdict to the Attester (/attest_result).
 *
 * The spec's Step 2a says "-> fail: negative proof to Attester", but the
 * Attester is the server of /attest -- its evidence is the final message of
 * that exchange, leaving RP no reply slot to reject it in. So the verdict
 * goes as a separate RP-initiated request, which also keeps the Attester a
 * pure passive responder.
 *
 * Deliberately called from get_evidence() *after* its CoAP loop finishes,
 * never from inside coap_attester_handler(): starting a second exchange
 * from within a libcoap response callback re-enters the stack while the
 * first context is still mid-dispatch.
 *
 * Advisory: a failure to deliver is logged and otherwise ignored -- the
 * appraisal verdict itself is already decided.
 */
static void rp_send_attestation_result(bool accepted, const char* reason) {
    msg_attestation_result_dto res = {0};
    res.accepted = accepted ? 1 : 0;
    if (reason != NULL) {
        size_t len = strlen(reason);
        if (len > sizeof(res.reason)) {
            len = sizeof(res.reason);
        }
        res.reason_len = (uint32_t)len;
        memcpy(res.reason, reason, len);
    }

    uint8_t* buf = NULL;
    uint32_t buf_len = 0;
    if (charra_marshal_attestation_result(&res, &buf_len, &buf) !=
            CHARRA_RC_SUCCESS) {
        charra_log_error(
                "[" LOG_NAME "] Could not marshal /attest_result verdict.");
        return;
    }

    if (rp_coap_fetch(attester_host, attester_port, "attest_result", buf,
                buf_len, coap_certify_ak_of_attester_deliver_response_handler,
                &processing_certify_ak_of_attester_deliver_response) !=
            CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Could not deliver /attest_result "
                         "verdict to the Attester (non-fatal).");
    } else {
        charra_log_info("[" LOG_NAME "] Sent Step 2a verdict (%s) to the "
                        "Attester.",
                accepted ? "accepted" : "REJECTED");
    }
    free(buf);
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
    /* Real wall-clock elapsed time -- see rp_coap_fetch()'s docstring
     * comment for why this replaced a self-reported-duration sum. */
    struct timespec wait_start, wait_now;
    clock_gettime(CLOCK_MONOTONIC, &wait_start);
    while (!processing_attestation_response && coap_io_pending(coap_context)) {
        /* process CoAP I/O */
        if ((coap_io_process_time = coap_io_process(
                     coap_context, COAP_IO_PROCESS_TIME_MS)) == -1) {
            charra_log_error(
                    "[" LOG_NAME "] Error during CoAP I/O processing.");
            result = CHARRA_RC_COAP_ERROR;
            goto cleanup;
        }
        clock_gettime(CLOCK_MONOTONIC, &wait_now);
        double elapsed_ms = (wait_now.tv_sec - wait_start.tv_sec) * 1000.0 +
                             (wait_now.tv_nsec - wait_start.tv_nsec) / 1e6;
        if (elapsed_ms >= (attester_response_timeout * 1000)) {
            charra_log_error("[" LOG_NAME
                             "] Timeout after %.0f ms while waiting for or "
                             "processing attestation response.",
                    elapsed_ms);
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

    /* Step 2a's verdict back to the Attester -- only meaningful once we
     * actually appraised something, so not on a transport failure or a
     * timeout, where there was no verdict to report. Sent here rather than
     * from the response handler; see rp_send_attestation_result(). */
    if (attestation_rc == CHARRA_RC_VERIFICATION_FAILED) {
        rp_send_attestation_result(
                false, "Step 2a local verification failed");
    } else if (result == CHARRA_RC_SUCCESS &&
               attestation_rc == CHARRA_RC_SUCCESS) {
        rp_send_attestation_result(true, "Step 2a local verification passed");
    }

    /* No coap_cleanup() here: it tears down libcoap's *global* state, so
     * calling it per cycle (and from each Verifier thread) would pull the
     * ground out from under contexts still in use and from the next
     * cycle's. Done exactly once, at process exit in main(). */

    return result;
}

void* get_attestation_results_thread(void *arg) {

    CHARRA_RC result = EXIT_FAILURE;

    int current_thread_index = *(int*)arg;
    verifier_info verifier_info = verifiers[current_thread_index];

    /* Tags this thread's log lines so 5 concurrent Verifier threads don't
     * interleave into one indistinguishable stream. */
    char log_prefix[32] = {0};
    snprintf(log_prefix, sizeof(log_prefix), "[V%d:%u]",
            current_thread_index + 1, verifier_info.port_number);
    charra_log_set_thread_prefix(log_prefix);

    /* cleanup/error below never sets attestation_results[] explicitly, so
     * without this reset an early failure would silently keep a stale PASS
     * from a previous run and get counted toward the vote. Fail closed. */
    attestation_results[current_thread_index] = false;
    rejection_reason[current_thread_index][0] = '\0';
    verifier_latency_ms[current_thread_index] = -1;

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

    /* RP qualification is now handled once, up front, by
     * get_attestation_results() before any thread starts (see
     * rp_perform_qualification_handshake_once()) -- the shared
     * qualification ledger means one Verifier's answer is every Verifier's
     * answer, so nothing to do here. This thread still needs its OWN
     * Verifier's AK *certificate* though (orthogonal, still per-Verifier --
     * charra_rp_build_evidence_message() below only checks rp_ak_cert_
     * ready[current_thread_index], it doesn't provision it). */
    if (ensure_rp_ak_certificate(current_thread_index) != CHARRA_RC_SUCCESS) {
        charra_log_error(
                "[" LOG_NAME "] Verifier n° %d (port %u): RP AK certificate "
                "not provisioned; proceeding to /appraise anyway.",
                current_thread_index + 1,
                verifiers[current_thread_index].port_number);
    }

    /* Symmetric with the above: the Attester's AK certificate, issued by
     * THIS Verifier's own CA, is also per-Verifier now (see
     * ensure_attester_identity_certified_by_verifier()'s docstring). */
    if (ensure_attester_identity_certified_by_verifier(current_thread_index) !=
            CHARRA_RC_SUCCESS) {
        charra_log_error(
                "[" LOG_NAME "] Verifier n° %d (port %u): Attester AK "
                "certificate not provisioned; proceeding to /appraise "
                "anyway.",
                current_thread_index + 1,
                verifiers[current_thread_index].port_number);
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
     * coap_nonce_handler() unmarshals this exact DTO -- keeping req.nonce
     * for its own separate Quote_a freshness check -- then generates and
     * returns its own fresh challenge as the response body, a genuinely
     * Verifier-picked value rather than an echo of what RP just sent (see
     * verifier_challenge_nonce's comment in verifier.c for why that
     * distinction matters). An empty request body here made unmarshaling
     * fail immediately ("Could not get CoAP PDU data"), which is why RP
     * never received a nonce and Quote_r could never be built, before this
     * was fixed. */
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


    /* Real wall-clock elapsed time -- see rp_coap_fetch()'s docstring
     * comment for why this replaced a self-reported-duration sum. */
    struct timespec wait_start_n, wait_now_n;
    clock_gettime(CLOCK_MONOTONIC, &wait_start_n);
    while (processing_nonce_response && coap_io_pending(coap_context)) {
        /* process CoAP I/O */
        if ((coap_io_process_time_n = coap_io_process(
                     coap_context, COAP_IO_PROCESS_TIME_MS)) == -1) {
            charra_log_error(
                    "[" LOG_NAME "] Error during CoAP I/O processing.");
            result = CHARRA_RC_COAP_ERROR;
            goto cleanup;
        }
        clock_gettime(CLOCK_MONOTONIC, &wait_now_n);
        double elapsed_ms_n =
                (wait_now_n.tv_sec - wait_start_n.tv_sec) * 1000.0 +
                (wait_now_n.tv_nsec - wait_start_n.tv_nsec) / 1e6;
        if (elapsed_ms_n >= (verifier_response_timeout * 1000)) {
            charra_log_error("[" LOG_NAME
                             "] Timeout after %.0f ms while waiting for or "
                             "processing attestation response.",
                    elapsed_ms_n);
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
     * could never fix. Retried the same way if the complaint was instead
     * our qualification being missing or expired (Step 3a item 1b): forget
     * the local cache and redo /qualify + /qualify/submit. The two never
     * overlap in one response (coap_appraise_handler checks the AK
     * certificate first and returns immediately on failure, before ever
     * reaching the qualification check), so at most one of
     * rp_ak_cert_rejected/rp_qualification_rejected is ever true here. Not
     * retried for any other kind of failure. */
    long total_appraisal_wait_ms = 0;
    for (int attempt = 0; attempt < 2; ++attempt) {
        charra_free_if_not_null(res_buf);
        res_buf = NULL;
        res_buf_len = 0;

        /* No cross-thread locking needed here (unlike the /certify_ak CoAP
         * round trip itself, still guarded by rp_ak_reprovision_mutex,
         * see ensure_rp_ak_certificate()): this thread is the only one
         * that ever reads or writes rp_ak_cert_der[current_thread_index],
         * since each Verifier's certificate is now independently owned by
         * its own thread's array slot. */
        charra_r = charra_rp_build_evidence_message(
                current_thread_index, &res_buf_len, &res_buf);
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
        /* Real elapsed time, not a self-reported-duration sum -- see
         * rp_coap_fetch() above. */
        struct timespec wait_start_v, wait_now_v;
        clock_gettime(CLOCK_MONOTONIC, &wait_start_v);
        double elapsed_ms_v = 0;
        while (!processing_appraisal_response && coap_io_pending(coap_context_verifier_appraisal)) {
            int coap_io_process_time_v = coap_io_process(
                    coap_context_verifier_appraisal, COAP_IO_PROCESS_TIME_MS);
            if (coap_io_process_time_v == -1) {
                charra_log_error(
                        "[" LOG_NAME "] Error during CoAP I/O processing.");
                result = CHARRA_RC_COAP_ERROR;
                goto cleanup;
            }
            clock_gettime(CLOCK_MONOTONIC, &wait_now_v);
            elapsed_ms_v = (wait_now_v.tv_sec - wait_start_v.tv_sec) * 1000.0 +
                           (wait_now_v.tv_nsec - wait_start_v.tv_nsec) / 1e6;
            if (elapsed_ms_v >= (verifier_response_timeout * 1000)) {
                charra_log_error("[" LOG_NAME
                                 "] Timeout after %.0f ms while waiting for or "
                                 "processing attestation response.",
                        elapsed_ms_v);
                result = CHARRA_RC_TIMEOUT;
                goto cleanup;
            }
        }

        total_appraisal_wait_ms += (long)elapsed_ms_v;
        verifier_latency_ms[current_thread_index] = total_appraisal_wait_ms;

        bool rejected = rp_ak_cert_rejected[current_thread_index] ||
                        rp_qualification_rejected[current_thread_index];
        if (!rejected || attempt == 1) {
            break;
        }

        if (rp_ak_cert_rejected[current_thread_index]) {
            charra_log_info("[" LOG_NAME "] Re-provisioning RP AK "
                            "certificate after rejection by Verifier n\u00b0 "
                            "%d (reason: %s) ...",
                    current_thread_index + 1,
                    rejection_reason[current_thread_index]);
            invalidate_cached_rp_ak_certificate(current_thread_index);
            CHARRA_RC reprovision_rc =
                    ensure_rp_ak_certificate(current_thread_index);

            if (reprovision_rc != CHARRA_RC_SUCCESS) {
                charra_log_error(
                        "[" LOG_NAME "] Could not re-provision RP AK "
                        "certificate; giving up on Verifier n\u00b0 %d.",
                        current_thread_index + 1);
                break;
            }
        } else {
            charra_log_info("[" LOG_NAME "] Re-qualifying with Verifier "
                            "n\u00b0 %d after rejection (reason: %s) ...",
                    current_thread_index + 1,
                    rejection_reason[current_thread_index]);
            invalidate_cached_rp_qualification();
            /* Margin 0: the cache was just invalidated above, so this must
             * qualify now regardless of any renewal-window policy. */
            CHARRA_RC requalify_rc = rp_perform_qualification_handshake_once(
                    rp_num_verifiers_this_cycle, 0);

            if (requalify_rc != CHARRA_RC_SUCCESS) {
                charra_log_error(
                        "[" LOG_NAME "] Could not re-qualify; giving up on "
                        "Verifier n\u00b0 %d.",
                        current_thread_index + 1);
                break;
            }
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

    /* No coap_cleanup() here: it tears down libcoap's *global* state, so
     * calling it per cycle (and from each Verifier thread) would pull the
     * ground out from under contexts still in use and from the next
     * cycle's. Done exactly once, at process exit in main(). */

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

    /* Qualify once, before any verifier thread starts -- the qualification
     * ledger is shared across all Verifiers (see qualification_state_file_
     * path in verifier.c), so one Verifier's answer is every Verifier's
     * answer. No Verifier will accept /appraise without it, so abort here
     * rather than spawning threads that would all fail identically. */
    rp_num_verifiers_this_cycle = num_verifiers;
    /* Margin 0: this is the attestation path -- it needs a valid
     * qualification, but has no reason to renew one that is still good.
     * Daemon mode does early renewal from its idle window instead. */
    if (rp_perform_qualification_handshake_once(num_verifiers, 0) !=
            CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Could not qualify with any "
                         "reachable Verifier; aborting attestation run.");
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
            charra_log_info("[" LOG_NAME "] Forwarding evidence to Verifier n° %d (port %u) ...", i+1, verifiers[i].port_number);
        }
    }

    for (int i = 0; i < num_verifiers; ++i) {
        pthread_join(threads[i], NULL);
    }

    /* Identity readiness, as of right now -- not "did we redo either this
     * cycle": rp_ak_cert_ready[] is per-Verifier, rp_qualified_until is now
     * a single shared value (qualifying is Verifier-agnostic); both are
     * independently cached on disk and only get touched when their cache
     * was missing or expired, so most cycles this just reports cache state
     * untouched this round. */
    int num_not_ready = 0;
    time_t readiness_now = time(NULL);
    bool qualified = rp_qualified_until > readiness_now;
    for (int i = 0; i < num_verifiers; ++i) {
        bool ak_ready = rp_ak_cert_ready[i];
        if (ak_ready && qualified) {
            charra_log_info(
                    "[" LOG_NAME "] Verifier %d (port %u): ready (AK "
                    "certified, qualified).",
                    i + 1, verifiers[i].port_number);
        } else {
            num_not_ready++;
            charra_log_info(
                    "[" LOG_NAME "] Verifier %d (port %u): NOT fully ready "
                    "(AK certified: %s, qualified: %s).",
                    i + 1, verifiers[i].port_number,
                    ak_ready ? "yes" : "no", qualified ? "yes" : "no");
        }
    }
    if (num_not_ready > 0) {
        charra_log_info("[" LOG_NAME "] %d/%d Verifier(s) not yet fully "
                        "ready (missing AK certificate and/or "
                        "qualification).",
                num_not_ready, num_verifiers);
    }

    for (int i = 0; i < num_verifiers; ++i) {
        charra_log_info("[" LOG_NAME "] Verifier %d (port %u): %s", i+1, verifiers[i].port_number, attestation_results[i] ? "Attestation successful!" : "Attestation failed!");
    }

    int num_true = 0;
    for (int i = 0; i < num_verifiers; ++i) {
        if (attestation_results[i]) {
            num_true++;
        }
    }

    if (2 * num_true > num_verifiers) {
        charra_log_info("[" LOG_NAME "] Attestation successful by majority "
                        "vote! (%d/%d Verifiers passed)",
                num_true, num_verifiers);
    } else {
        charra_log_info("[" LOG_NAME "] Attestation failed by majority "
                        "vote! (%d/%d Verifiers passed)",
                num_true, num_verifiers);
    }

    /* --- one-screen run summary --------------------------------------- */
    charra_log_info("[" LOG_NAME "]  +------------ Run Summary --------------+");
    charra_log_info(
            "[" LOG_NAME "] log_r: %u bytes redacted from a %u-byte raw log.",
            rp_log_r_len, last_response.event_log_len);
    for (int i = 0; i < num_verifiers; ++i) {
        const char* reason;
        if (attestation_results[i]) {
            reason = "OK";
        } else if (rejection_reason[i][0] != '\0') {
            reason = rejection_reason[i];
        } else {
            reason = "appraisal failed (see per-Verifier log above)";
        }
        char latency_str[16];
        if (verifier_latency_ms[i] < 0) {
            snprintf(latency_str, sizeof(latency_str), "  n/a");
        } else {
            snprintf(latency_str, sizeof(latency_str), "%5ld", verifier_latency_ms[i]);
        }
        charra_log_info("[" LOG_NAME
                        "] Verifier %d (%s:%u): %-4s | AK %-6s | %s ms | "
                        "%s",
                i + 1, verifiers[i].ip_address, verifiers[i].port_number,
                attestation_results[i] ? "PASS" : "FAIL",
                rp_ak_cert_was_cached[i] ? "cached" : "fresh",
                latency_str, reason);
    }

    result = CHARRA_RC_SUCCESS;


error:
    charra_rp_release_evidence();
    return result;

}