/**
 * @file rp_stats.c
 * @brief See rp_stats.h.
 */

#include "rp_stats.h"

#include <math.h>

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
