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

#endif /* CHARRA_RP_STATS_H */
