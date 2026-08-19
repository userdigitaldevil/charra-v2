/**
 * @file rp_shared.h
 * @brief State defined in relying_party.c that src/rp/ modules need.
 *
 * The Relying Party's globals stay *defined* in relying_party.c; this
 * header only declares them so the extracted modules can reach them. That
 * is a deliberate compromise rather than an ideal: 19 libcoap response
 * handlers communicate with their callers exclusively through these
 * globals (a CoAP callback cannot return data), so threading a context
 * struct through them would be a far more invasive change than relocating
 * the functions. Splitting the file is the goal here; decoupling the state
 * is a separate job.
 *
 * Anything listed here has had its `static` removed in relying_party.c.
 * Keep the two in sync -- a mismatch is a link error, not a silent bug.
 */

#ifndef CHARRA_RP_SHARED_H
#define CHARRA_RP_SHARED_H

#include <coap3/coap.h>
#include <stdbool.h>
#include <stdint.h>

#include <pthread.h>
#include <time.h>

#include "../common/charra_log.h"
#include <tss2/tss2_esys.h>

#include "../core/charra_dto.h"
#include "../util/coap_util.h"
#include "../util/crypto_util.h"

/* verifiers config */
#define MAX_VERIFIERS 10

/** Default wait for a Verifier's reply, and for the Attester's. Both feed
 * libcoap's ack_timeout AND a wall-clock ceiling on the wait loop, so a
 * stalled exchange cannot outlive them via CoAP's own retransmissions.
 * Six seconds is generous against measured round trips (~0.4s steady
 * state); the tightest real case is the Attester's one-time AK
 * provisioning, ~3.2s in this dev environment. */
#define RP_DEFAULT_VERIFIER_TIMEOUT_S 6
#define RP_DEFAULT_ATTESTER_TIMEOUT_S 6

/** @brief Does a certificate expiring at expires_at need renewing now?
 * expires_at == 0 means "unknown", which counts as needing renewal. Kept in
 * memory and re-checked on EVERY call, exactly like rp_qualified_until: a
 * boolean "ready" flag consulted once at startup lets a daemon run past its
 * own certificate's expiry without ever noticing. */
static inline bool charra_cert_needs_renewal(time_t expires_at) {
    return expires_at <= time(NULL);
}

/* --- daemon-mode config (see parse_rp_command_line()) -------------------
 * RP's default mode is a long-running loop: attest, sleep, repeat -- until
 * SIGINT. `--benchmark` selects the original bounded 1..5-Verifier timing
 * sweep instead, which is what produces timings_RP_multi_verifiers.txt for
 * plot_multi_verifiers.py.
 *
 * Renewal is not scheduled anywhere: each ensure_* re-checks its own expiry
 * when the cycle reaches it and re-provisions only once the credential has
 * genuinely expired. Nothing at all happens during the sleep between
 * cycles. */
#define RP_DEFAULT_ATTESTATION_INTERVAL_S 15
#define RP_DEFAULT_NUM_VERIFIERS 5
#define RP_MAX_SWEEP_VERIFIERS 5

/* Benchmark mode: how many measured cycles each verifier count contributes,
 * after a discarded warm-up cycle -- see the sweep in relying_party.c's
 * main() for why a single sample per step measured the wrong thing. Lives
 * here rather than in relying_party.c so the startup configuration log can
 * report it. */
#define NUM_RUNS 5

/* --- daemon/benchmark configuration (set by parse_rp_command_line) ------ */
extern bool rp_benchmark_mode;
extern unsigned int rp_attestation_interval_s;
extern int rp_num_verifiers;
extern unsigned int rp_duration_s;
extern unsigned long rp_max_cycles;
extern time_t attester_ak_cert_validity_seconds;

/* Set by the SIGINT/SIGTERM handler; polled by the daemon loop and by
 * rp_interruptible_sleep(). */
extern bool quit;

extern charra_log_t charra_log_level;

/* --- CoAP timing ------------------------------------------------------- */
/* Seconds rp_coap_fetch() waits for a response before giving up. */
extern uint16_t verifier_response_timeout;
#define COAP_IO_PROCESS_TIME_MS 2000

typedef struct verifier_info {
    char ip_address[16];
    unsigned int port_number;
} verifier_info;

/* --- Verifier endpoints, resolved once per cycle by get_verifiers() ----- */
extern verifier_info verifiers[MAX_VERIFIERS];

/* How many entries of verifiers[] the Trust Manager actually filled this
 * cycle. The Trust Manager may legitimately answer with fewer records than
 * were requested (an ID missing from its verifiers_config.txt), and the
 * remaining slots then still hold the previous cycle's endpoints -- or
 * nothing at all on the first cycle. get_verifiers() fails the cycle rather
 * than attesting against them; see its own comment. */
extern int verifiers_resolved;

/* --- RP's own identity, provisioned per Verifier ------------------------ */
extern bool rp_ak_cert_ready[MAX_VERIFIERS];
extern time_t rp_ak_cert_expires_at[MAX_VERIFIERS];
extern uint8_t* rp_ak_cert_der[MAX_VERIFIERS];
extern uint32_t rp_ak_cert_der_len[MAX_VERIFIERS];
extern uint8_t rp_public_key_der[CHARRA_RSA_PUB_KEY_DER_MAX];
extern uint32_t rp_public_key_der_len;

/* --- qualification handshake state ------------------------------------- */
extern uint8_t* qualify_challenge_log;
extern uint32_t qualify_challenge_log_len;
extern uint8_t qualify_challenge_salt[CHARRA_SDK_PATH_SALT_LEN];
extern CHARRA_RC qualify_response_rc;
extern bool processing_qualify_response;
extern bool qualify_submit_qualified;
extern time_t qualify_submit_expires_at;
extern bool processing_qualify_submit_response;
extern time_t rp_qualified_until;
extern char* rp_qualification_cache_path;

/* --- locks -------------------------------------------------------------
 * Ordering matters and is easy to lose sight of once the callers live in
 * different files: take rp_ak_reprovision_mutex (or
 * rp_qualification_mutex) *before* rp_tpm_mutex, and never hold one across
 * the other's critical section. rp_tpm_mutex is additionally kept
 * short-lived on purpose -- the dev TPM simulator serves one client at a
 * time, and an RP that held it across a CoAP wait once starved the
 * Verifier's own TPM work outright. */
extern pthread_mutex_t rp_tpm_mutex;
extern pthread_mutex_t rp_qualification_mutex;


/* --- evidence pipeline state (Steps 2a/2b) ----------------------------- */
/** The request RP sent the Attester this cycle; its nonce is what Quote_a
 * must answer, and what gets forwarded so the Verifier can check it too. */
extern msg_attestation_request_dto last_request;
/** The Attester's most recent /attest response. Owns heap buffers --
 * release with charra_free_attestation_response() before overwriting. */
extern msg_attestation_response_dto last_response;

/** log_r: the redacted log, and the PCR digest replayed from it. */
extern uint8_t* rp_log_r;
extern uint32_t rp_log_r_len;
extern uint8_t rp_pcr_r[TPM2_SHA256_DIGEST_SIZE];

/** Per-Verifier nonces, indexed the same way as verifiers[]. */
extern uint8_t verifier_nonces[MAX_VERIFIERS][sizeof(TPMU_HA)];
extern uint32_t verifier_nonce_lens[MAX_VERIFIERS];

/** The Attester's AK certificate as issued by each Verifier's own CA. */
extern bool attester_ak_cert_by_verifier_ready[MAX_VERIFIERS];
extern time_t attester_ak_cert_by_verifier_expires_at[MAX_VERIFIERS];
extern uint8_t* attester_ak_cert_by_verifier_der[MAX_VERIFIERS];
extern uint32_t attester_ak_cert_by_verifier_der_len[MAX_VERIFIERS];

/* --- policy inputs ------------------------------------------------------ */
extern uint8_t tpm_pcr_selection[TPM2_MAX_PCRS];
extern uint32_t tpm_pcr_selection_len;
extern char* whitelist_hashes_path;
extern char* blacklist_hashes_path;
extern char* attester_ak_state_file_path;
extern char* rp_ca_cert_path;


/* --- Attester endpoint -------------------------------------------------- */
extern char attester_host[16];
extern unsigned int attester_port;

/* --- Attester identity provisioning ------------------------------------ */
/** Guards the Attester-relay round trips against concurrent Verifier
 * threads: ACTIVATE and DELIVER_VERIFIER both use the shared response
 * globals below. Held for a whole per-Verifier leg rather than per
 * exchange -- attester.c is single-threaded, so it serialises these
 * regardless and there is no concurrency to preserve. */
extern pthread_mutex_t attester_identity_relay_mutex;
extern bool attester_identity_provisioned;
extern time_t attester_ak_cert_rp_expires_at;
extern pthread_mutex_t attester_identity_provision_mutex;
/** The Attester's EK cert + AK public key + AK name, FETCHed once and
 * reused for every Verifier rather than re-fetched per Verifier. */
extern msg_ak_identity_response_dto attester_identity_cached;
extern msg_ak_identity_response_dto ak_identity_response;
extern CHARRA_RC ak_identity_rc;
extern bool processing_ak_identity_response;
extern msg_activate_credential_response_dto activate_credential_response;
extern CHARRA_RC activate_credential_rc;
extern bool processing_activate_credential_response;
extern bool processing_certify_ak_of_attester_deliver_response;
extern char* attester_ak_cert_rp_cache_path;
extern char* rp_ca_key_path;
extern char* manufacturer_root_cert_path;


/* --- RP's own identity -------------------------------------------------- */
extern bool rp_ak_keypair_ready;
extern char* rp_ak_public_path;
extern char* rp_ak_private_path;
extern char* rp_ek_cert_cache_path;
extern char* manufacturer_root_key_path;
extern const char* rp_ek_cert_not_before_utc;
extern const char* rp_ek_cert_not_after_utc;
/** Reported in the run summary: whether this cycle reused a cached
 * certificate or had to provision a fresh one. */
extern bool rp_ak_cert_was_cached[MAX_VERIFIERS];
/** Shared /certify_ak response slot, guarded by rp_ak_reprovision_mutex --
 * several Verifier threads can legitimately be mid-handshake at once. */
extern msg_certify_ak_response_dto certify_ak_response;
extern CHARRA_RC certify_ak_rc;
extern bool processing_certify_ak_response;
extern pthread_mutex_t rp_ak_reprovision_mutex;


#define TPM_SIG_KEY_ID_LEN 14
#define TPM_SIG_KEY_ID "PK.RSA.default"

/** Whether nonces come from the TPM's RNG rather than the software one. */
extern const bool USE_TPM_FOR_RANDOM_NONCE_GENERATION;

/* --- attestation pipeline: config, DTLS and per-cycle results ----------
 * All defined in relying_party.c; the pipeline modules read them. */
extern CHARRA_RC attestation_rc;
extern bool attestation_results[MAX_VERIFIERS];
extern uint16_t attester_response_timeout;
extern charra_dtls_config dtls_config;
extern char* dtls_rpk_attester_public_key_path;
extern char* dtls_rpk_verifier_public_key_path;
extern char* ima_event_log_path;
extern char* ima_test_log_path;
/* Per-Verifier, not shared: five threads run these exchanges
 * concurrently, and a single flag let one thread's response end
 * another thread's wait loop -- which surfaced as "Verifier n did
 * not supply a nonce" even though it had. */
extern bool processing_appraisal_response[MAX_VERIFIERS];
extern bool processing_attestation_response;
extern bool processing_nonce_response[MAX_VERIFIERS];
extern bool processing_trust_manager_response;
extern char trust_manager_host[16];
extern unsigned int trust_manager_port;
extern uint16_t trust_manager_response_timeout;
extern bool use_ima_event_log;
extern bool use_ima_test_log;
extern long verifier_latency_ms[MAX_VERIFIERS];
extern int verifier_list[MAX_VERIFIERS];

#endif /* CHARRA_RP_SHARED_H */
