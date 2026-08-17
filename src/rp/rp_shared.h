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

#include <stdbool.h>
#include <stdint.h>

#include "../common/charra_log.h"

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

#endif /* CHARRA_RP_SHARED_H */
