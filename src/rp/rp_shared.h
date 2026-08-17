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

#ifndef CHARRA_UNUSED
#define CHARRA_UNUSED __attribute__((unused))
#endif

#include <coap3/coap.h>
#include <stdbool.h>
#include <stdint.h>

#include <pthread.h>
#include <time.h>

#include "../common/charra_log.h"
#include <tss2/tss2_esys.h>

#include "../core/charra_dto.h"
#include "../util/crypto_util.h"

/* verifiers config */
#define MAX_VERIFIERS 10

/* --- daemon-mode config (see parse_rp_command_line()) -------------------
 * RP's default mode is a long-running loop: attest, renew qualification if
 * it is close to expiring, sleep, repeat -- until SIGINT. `--benchmark`
 * selects the original bounded 1..5-Verifier timing sweep instead, which is
 * what produces timings_RP_multi_verifiers.txt for plot_multi_verifiers.py.
 *
 * Three coupled values, and the defaults must satisfy
 *   interval < margin < CHARRA_RP_QUALIFICATION_VALIDITY_SECONDS
 * (currently 60 < 120 < 300):
 *  - margin > interval, because the renewal check runs once per loop
 *    iteration -- with margin <= interval the loop can step straight over
 *    the renewal window and land past expiry, paying for /qualify inside an
 *    attestation anyway, which is exactly what the margin exists to avoid.
 *  - margin < validity, because a margin at or above the whole validity
 *    window is never satisfiable, so RP would renew on every idle pass and
 *    the qualification cache would stop meaning anything.
 * parse_rp_command_line() warns if an override breaks either bound. */
#define RP_DEFAULT_ATTESTATION_INTERVAL_S 60
#define RP_DEFAULT_QUALIFY_MARGIN_S 120
#define RP_DEFAULT_NUM_VERIFIERS 5
#define RP_MAX_SWEEP_VERIFIERS 5

/* --- daemon/benchmark configuration (set by parse_rp_command_line) ------ */
extern bool rp_benchmark_mode;
extern unsigned int rp_attestation_interval_s;
extern unsigned int rp_qualify_margin_s;
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

/* --- RP's own identity, provisioned per Verifier ------------------------ */
extern bool rp_ak_cert_ready[MAX_VERIFIERS];
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

/** Provisions RP's AK certificate with verifiers[verifier_index]. Defined
 * in relying_party.c; declared here because the qualification handshake
 * needs a certificate from whichever Verifier it qualifies against. */
CHARRA_RC ensure_rp_ak_certificate(int verifier_index);

/** Opens a TPM connection and loads RP's persisted AK. Caller must hold
 * rp_tpm_mutex, and must close promptly -- see the lock note above. */
CHARRA_RC rp_open_tpm_and_load_ak(ESYS_CONTEXT** esys_ctx_out,
        TSS2_TCTI_CONTEXT** tcti_ctx_out, ESYS_TR* ek_handle_out,
        ESYS_TR* ak_handle_out, TPM2B_NAME** ak_name_out);

#endif /* CHARRA_RP_SHARED_H */
