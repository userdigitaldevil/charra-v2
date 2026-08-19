/**
 * @file rp_stats.c
 * @brief See rp_stats.h.
 */

#include "rp_stats.h"

#include <math.h>
#include <pthread.h>
#include <stdio.h>
#include <time.h>

#include "../common/charra_log.h"

#define LOG_NAME "relying party"

/** Where rp_stats_record_provisioning() appends. Sibling of
 * timings_RP_multi_verifiers.txt; both are gitignored run artefacts. */
#define RP_PROVISIONING_TIMING_PATH "timings_provisioning.txt"

/* Verifier threads race here -- see the header. */
static pthread_mutex_t rp_provisioning_timing_mutex = PTHREAD_MUTEX_INITIALIZER;

void calculate_stats(
        double* durations, int num_runs, double* avg, double* stddev) {
    double sum = 0.0;
    for (int i = 0; i < num_runs; i++) {
        sum += durations[i];
    }
    *avg = sum / num_runs;

    double variance_sum = 0.0;
    for (int i = 0; i < num_runs; i++) {
        variance_sum += (durations[i] - *avg) * (durations[i] - *avg);
    }
    *stddev = sqrt(variance_sum / num_runs);
}

void rp_stats_record_provisioning(
        const char* flow, unsigned int verifier_port, double seconds) {
    if (flow == NULL) {
        return;
    }

    pthread_mutex_lock(&rp_provisioning_timing_mutex);
    FILE* f = fopen(RP_PROVISIONING_TIMING_PATH, "a");
    if (f == NULL) {
        /* Not worth failing an attestation over: this file is measurement,
         * not protocol. Log once and carry on. */
        charra_log_warn("[" LOG_NAME "] Could not open %s for the %s timing.",
                RP_PROVISIONING_TIMING_PATH, flow);
        pthread_mutex_unlock(&rp_provisioning_timing_mutex);
        return;
    }
    /* Header only on a fresh file, so repeated runs append cleanly. */
    if (ftell(f) == 0) {
        fprintf(f, "# flow verifier_port seconds unix_time\n");
    }
    fprintf(f, "%s %u %.6f %ld\n", flow, verifier_port, seconds,
            (long)time(NULL));
    fclose(f);
    pthread_mutex_unlock(&rp_provisioning_timing_mutex);
}
