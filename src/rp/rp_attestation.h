/**
 * @file rp_attestation.h
 * @brief The three phases of one attestation cycle.
 *
 * Ordering matters and is enforced by the caller
 * (run_one_attestation_cycle in relying_party.c):
 *   get_verifiers()          -- resolve Verifier IDs via the Trust Manager
 *   get_evidence()           -- /attest, then Step 2a locally; a hard gate,
 *                               nothing is forwarded if it fails
 *   get_attestation_results()-- Step 2b once, then one thread per Verifier
 *                               for /nonce and /appraise
 */

#ifndef CHARRA_RP_ATTESTATION_H
#define CHARRA_RP_ATTESTATION_H

#include <stdbool.h>

#include "../common/charra_error.h"

/** @brief Resolve verifier_list[0..num_verifiers) to endpoints in
 * verifiers[], via the Trust Manager. */
CHARRA_RC get_verifiers(int* requested_ids, int num_verifiers);

/** @brief Fetch the Attester's evidence and appraise it locally (Step 2a).
 * Also reports the verdict back to the Attester. */
CHARRA_RC get_evidence(void);

/** @brief Privacy-clean once (Step 2b), then fan out to every Verifier in
 * parallel and tally the majority vote. */
CHARRA_RC get_attestation_results(int num_verifiers);

/** @brief One Verifier's thread body: get a nonce, build this Verifier's
 * evidence (Quote_r + log_r), and /appraise. */
void* get_attestation_results_thread(void* arg);

/**
 * @brief Send RP's Step 2a verdict to the Attester (/attest_result).
 *
 * The spec's Step 2a ends "-> fail: negative proof to Attester", but the
 * Attester is the *server* of /attest, so its evidence is the last message
 * of that exchange and there is no reply slot to reject it in. Hence a
 * separate RP-initiated request, which also keeps the Attester a pure
 * passive responder.
 *
 * Must be called after the caller's CoAP loop finishes, never from inside a
 * response handler -- starting a second exchange from within a libcoap
 * callback re-enters the stack mid-dispatch. Advisory: a delivery failure
 * is logged and otherwise ignored, since the verdict is already decided.
 */
void rp_send_attestation_result(bool accepted, const char* reason);

#endif /* CHARRA_RP_ATTESTATION_H */
