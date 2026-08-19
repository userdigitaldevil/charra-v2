/**
 * @file rp_attestation.h
 * @brief The three phases of one attestation cycle.
 *
 * Ordering matters and is enforced by the caller
 * (run_one_attestation_cycle in relying_party.c):
 *   get_verifiers()          -- resolve Verifier IDs via the Trust Manager
 *   get_evidence()           -- /attest, then Step 2a locally; a hard gate,
 *                               nothing is forwarded if it fails
 *   get_attestation_results()-- Step 2b once, qualify once, then one thread
 *                               per Verifier for /nonce and /appraise
 */

#ifndef CHARRA_RP_ATTESTATION_H
#define CHARRA_RP_ATTESTATION_H

#include "../common/charra_error.h"

/** @brief Resolve verifier_list[0..num_verifiers) to endpoints in
 * verifiers[], via the Trust Manager. */
CHARRA_RC get_verifiers(int* requested_ids, int num_verifiers);

/** @brief Fetch the Attester's evidence and appraise it locally (Step 2a).
 * Also reports the verdict back to the Attester. */
CHARRA_RC get_evidence(void);

/** @brief Privacy-clean once (Step 2b), qualify once, then fan out to every
 * Verifier in parallel and tally the majority vote. */
CHARRA_RC get_attestation_results(int num_verifiers);

/** @brief One Verifier's thread body: ensure both AK certificates, get a
 * nonce, build this Verifier's evidence, /appraise, retry once on an
 * AK-certificate or qualification rejection. */
void* get_attestation_results_thread(void* arg);

#endif /* CHARRA_RP_ATTESTATION_H */
