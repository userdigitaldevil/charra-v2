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
 * state). */
#define RP_DEFAULT_VERIFIER_TIMEOUT_S 6
#define RP_DEFAULT_ATTESTER_TIMEOUT_S 6

#define RP_DEFAULT_NUM_VERIFIERS 1

/* --- config (set by parse_rp_command_line) ------------------------------ */
extern int rp_num_verifiers;

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

/* --- locks -------------------------------------------------------------
 * Kept short-lived on purpose: the dev TPM simulator serves one client at
 * a time, and an RP that held this across a CoAP wait once starved the
 * Verifier's own TPM work outright. */
extern pthread_mutex_t rp_tpm_mutex;


/* --- evidence pipeline state (Steps 2a/2b) ----------------------------- */
/** The request RP sent the Attester this cycle; its nonce is what Quote_a
 * must answer, and what gets forwarded so the Verifier can check it too. */
extern msg_attestation_request_dto last_request;
/** The Attester's most recent /attest response. Owns heap buffers --
 * release with charra_free_attestation_response() before overwriting. */
extern msg_attestation_response_dto last_response;

/** log_r: the redacted log. There is no PCR_r global to go with it -- the
 * PCR now lives in the RP's TPM, replayed once per cycle by
 * rp_replay_log_into_pcr() (see rp_signing_key.h). */
extern uint8_t* rp_log_r;
extern uint32_t rp_log_r_len;

/** Per-Verifier nonces, indexed the same way as verifiers[]. */
extern uint8_t verifier_nonces[MAX_VERIFIERS][sizeof(TPMU_HA)];
extern uint32_t verifier_nonce_lens[MAX_VERIFIERS];

/* --- policy inputs ------------------------------------------------------ */
extern uint8_t tpm_pcr_selection[TPM2_MAX_PCRS];
extern uint32_t tpm_pcr_selection_len;
extern char* whitelist_hashes_path;
extern char* blacklist_hashes_path;


/* --- Attester endpoint -------------------------------------------------- */
extern char attester_host[16];
extern unsigned int attester_port;

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
