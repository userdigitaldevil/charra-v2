/**
 * @file rp_stats.h
 * @brief Benchmark timing statistics for the Relying Party.
 *
 * Part of src/rp/ -- Relying-Party-only modules, deliberately kept out of
 * the shared $(OBJECTS) list so the Attester, Verifier and Trust Manager do
 * not link RP-specific code.
 */

#ifndef CHARRA_RP_STATS_H
#define CHARRA_RP_STATS_H

/**
 * @brief Mean and population standard deviation over durations[0..num_runs).
 *
 * Pure: touches no RP state, which is why this was the first thing lifted
 * out of relying_party.c.
 */
void calculate_stats(
        double* durations, int num_runs, double* avg, double* stddev);

/** Provisioning flows timed by rp_stats_record_provisioning(). Each is one
 * complete round of getting a credential issued, measured only when the
 * work actually runs -- a cache hit records nothing, since the interesting
 * quantity is what issuance costs, not what a skipped check costs. */
#define RP_FLOW_ATTESTER_AK_BY_RP "attester_ak_by_rp"
#define RP_FLOW_ATTESTER_AK_BY_VERIFIER "attester_ak_by_verifier"
#define RP_FLOW_RP_AK_BY_VERIFIER "rp_ak_by_verifier"
#define RP_FLOW_QUALIFICATION "qualification"

/**
 * @brief Append one provisioning-flow timing to timings_provisioning.txt.
 *
 * Called from Verifier threads as well as the main one, so it takes its own
 * lock: three of the four flows are per-Verifier and run concurrently.
 * Whitespace-separated, #-commented -- the same convention
 * reference-pcrs.txt and the AK ledger already use, and what
 * plot_provisioning.py reads.
 *
 * @param[in] flow one of the RP_FLOW_* names above
 * @param[in] verifier_port the Verifier this round talked to, or 0 for the
 * RP-CA flow, which involves no Verifier
 * @param[in] seconds wall-clock duration of the round
 */
void rp_stats_record_provisioning(
        const char* flow, unsigned int verifier_port, double seconds);

#endif /* CHARRA_RP_STATS_H */
