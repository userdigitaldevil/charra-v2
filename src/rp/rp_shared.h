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
#include <signal.h>
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
 * state). */
#define RP_DEFAULT_VERIFIER_TIMEOUT_S 6
#define RP_DEFAULT_ATTESTER_TIMEOUT_S 6

/* --- daemon-mode config (see parse_rp_command_line()) -------------------
 * RP's default mode is a long-running loop: attest, sleep, repeat -- until
 * SIGINT. `--benchmark` selects the original bounded 1..5-Verifier timing
 * sweep instead, which is what produces timings_RP_multi_verifiers.txt for
 * plot_multi_verifiers.py.
 *
 * Nothing is provisioned, renewed or scheduled anywhere: both signing
 * keys were vouched for offline in keys/trusted_keys.txt before any of
 * this ran, and qualification is a single handshake per process. Nothing
 * at all happens during the sleep between cycles. */
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
/** How this RP proves it is running the expected appraisal code, one of
 * three:
 *   QUALIFY -- the /qualify handshake, the default; once per cycle, and only
 *              when the previous grant has lapsed
 *   TEE     -- a simulated TEE Attestation Document, once per Verifier
 *   ZK      -- a zero-knowledge proof over log_r, once per cycle and shared
 *              by every Verifier
 * Every Verifier must be configured the same way; the value travels in
 * msg_rp_evidence_dto so a mismatch is named rather than guessed at. */
extern charra_trust_mode rp_trust_mode;

/* Set by the SIGINT/SIGTERM handler; polled by the daemon loop and by
 * rp_interruptible_sleep(). */
extern volatile sig_atomic_t quit;

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

/* --- qualification handshake state ------------------------------------- */
extern uint8_t* qualify_challenge_log;
extern uint32_t qualify_challenge_log_len;
extern uint8_t qualify_challenge_salt[CHARRA_SDK_PATH_SALT_LEN];
extern CHARRA_RC qualify_response_rc;
extern bool processing_qualify_response;
extern bool qualify_submit_qualified;
/** The deadline the Verifier reported granting, straight off the wire --
 * authoritative, rather than the RP assuming the same window from a
 * compile-time constant. */
extern time_t qualify_submit_expires_at;
extern bool processing_qualify_submit_response;
/** When this RP's qualification runs out, as the Verifier that granted it
 * reported. A single value, not one per Verifier: the granting Verifier
 * records the same deadline in the file every Verifier reads, so one
 * handshake qualifies this RP with all of them, until this instant.
 *
 * 0 means "never qualified". Re-checked against the wall clock at the
 * start of every cycle rather than latched into a boolean, so a daemon
 * whose run outlives a grant actually notices. Not persisted: a restarted
 * RP re-qualifies. */
extern time_t rp_qualified_until;

/* --- locks -------------------------------------------------------------
 * Ordering matters and is easy to lose sight of once the callers live in
 * different files: take rp_qualification_mutex *before* rp_tpm_mutex, and
 * never hold one across the other's critical section. rp_tpm_mutex is
 * additionally kept short-lived on purpose -- the dev TPM simulator serves
 * one client at a time, and an RP that held it across a CoAP wait once
 * starved the Verifier's own TPM work outright. */
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

/** Per-Verifier nonces, indexed the same way as verifiers[]. */
extern uint8_t verifier_nonces[MAX_VERIFIERS][sizeof(TPMU_HA)];
extern uint32_t verifier_nonce_lens[MAX_VERIFIERS];

/** SHA-256 of the evidence sent to each Verifier, kept because the signed
 * verdict coming back names it and the response handler has no other way
 * to reach the buffer, which is freed by then. See charra_verdict.h. */
/* Seconds the RP's own appraisal of evidence_a took in the current cycle.
 * Written by charra_rp_appraise_evidence(), read by the getEvidence phase so
 * it can report the Attester round trip with the local appraisal taken out --
 * the two are interleaved (the appraisal runs inside the /attest response
 * handler), so no timer pair can bracket the round trip alone. */
extern double rp_last_appraise_a_seconds;

extern uint8_t verifier_evidence_digests[MAX_VERIFIERS]
                                        [TPM2_SHA256_DIGEST_SIZE];

/* --- policy inputs ------------------------------------------------------ */
extern uint8_t tpm_pcr_selection[TPM2_MAX_PCRS];
extern uint32_t tpm_pcr_selection_len;
extern char* whitelist_hashes_path;
extern char* blacklist_hashes_path;


/* --- Attester endpoint -------------------------------------------------- */
extern char attester_host[16];
extern unsigned int attester_port;


/** Whether nonces come from the TPM's RNG rather than the software one. */
extern const bool USE_TPM_FOR_RANDOM_NONCE_GENERATION;

/* --- attestation pipeline: config, DTLS and per-cycle results ----------
 * All defined in relying_party.c; the pipeline modules read them. */
extern CHARRA_RC attestation_rc;
extern bool attestation_results[MAX_VERIFIERS];
/** Whether each Verifier's verdict verified -- true even for a signed NO.
 * Separates "voted against us" from "sent something we could not count",
 * which are the same NO but very different faults. */
extern bool verifier_verdict_verified[MAX_VERIFIERS];
extern uint16_t attester_response_timeout;
extern charra_dtls_config dtls_config;
extern char* dtls_rpk_attester_public_key_path;
extern char* dtls_rpk_verifier_public_key_path;
extern char* dtls_rpk_trust_manager_public_key_path;
/** Public half of the key Verifiers sign their verdicts with. */
extern char* verifier_public_key_path;
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
