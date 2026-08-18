/**
 * @file rp_config.c
 * @brief Relying Party command-line parsing and the daemon's sleep helper.
 *        See rp_config.h.
 */

#include "rp_config.h"

#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../common/charra_log.h"
#include "../core/charra_rp_qualification.h"
#include "rp_shared.h"

#define LOG_NAME "relying party"

void rp_interruptible_sleep(unsigned int seconds) {
    for (unsigned int i = 0; i < seconds && !quit; i++) {
        sleep(1);
    }
}

static const struct option rp_long_options[] = {{"help", no_argument, 0, '0'},
        {"verbose", no_argument, 0, 'v'},
        {"log-level", required_argument, 0, 'l'},
        {"benchmark", no_argument, 0, 'B'},
        {"interval", required_argument, 0, 'I'},
        {"qualify-renew-margin", required_argument, 0, 'Q'},
        {"ak-renew-margin", required_argument, 0, 'R'},
        {"verifiers", required_argument, 0, 'n'},
        {"attester-ak-validity", required_argument, 0, 'A'},
        {"duration", required_argument, 0, 'D'},
        {"cycles", required_argument, 0, 'C'}, {0}};

/** Parses a positive integer option argument; returns false (and logs) on
 * anything non-numeric, negative, or out of [min, max]. */
static bool rp_parse_uint_arg(
        const char* arg, const char* name, long min, long max, long* out) {
    char* end = NULL;
    errno = 0;
    long value = strtol(arg, &end, 10);
    if (errno != 0 || end == arg || *end != '\0' || value < min ||
            value > max) {
        charra_log_error("[" LOG_NAME "] Invalid --%s value '%s' (expected an "
                         "integer in [%ld, %ld]).",
                name, arg, min, max);
        return false;
    }
    *out = value;
    return true;
}

/**
 * @brief Parses RP's own command line.
 *
 * Deliberately not routed through util/cli_util.c: that parser is built
 * around a binary verifier-or-attester split (its getopt string and option
 * table are chosen with `caller == VERIFIER ? a : b` ternaries), and RP
 * shares none of its options -- no --port, --pcr-file, --psk or --rpk.
 * Adding a third caller there would mean rewriting every one of those
 * ternaries inside a module the other two binaries depend on, for no
 * benefit to either of them.
 *
 * @returns 0 to continue, 1 if help was printed (exit successfully), -1 on
 * a bad argument.
 */
int parse_rp_command_line(int argc, char** argv) {
    for (;;) {
        int index = -1;
        int identifier =
                getopt_long(argc, argv, "vl:BI:Q:R:n:A:D:C:", rp_long_options, &index);
        if (identifier == -1) {
            break;
        }

        long value = 0;
        switch (identifier) {
        case '0':
            printf("\nUsage: relying_party [OPTIONS]\n");
            printf("     --help:                   Print this help message.\n");
            printf(" -v, --verbose:                Set CHARRA log-level to "
                   "DEBUG.\n");
            printf(" -l, --log-level=LEVEL:        Set CHARRA log-level "
                   "(TRACE, DEBUG, INFO, WARN, ERROR, FATAL). Overrides "
                   "$LOG_LEVEL_CHARRA.\n");
            printf(" -B, --benchmark:              Run the bounded 1..%d-"
                   "Verifier timing sweep and exit, writing "
                   "timings_RP_multi_verifiers.txt, instead of the default "
                   "attestation daemon.\n",
                    RP_MAX_SWEEP_VERIFIERS);
            printf(" -I, --interval=SECONDS:       Daemon mode: seconds "
                   "between attestation cycles. Default %d.\n",
                    RP_DEFAULT_ATTESTATION_INTERVAL_S);
            printf("     --qualify-renew-margin=SECONDS: Daemon mode: renew "
                   "qualification once it expires within SECONDS, from the "
                   "idle window rather than inside an attestation. Should "
                   "exceed --interval. Default %d.\n",
                    RP_DEFAULT_QUALIFY_RENEW_MARGIN_S);
            printf("     --ak-renew-margin=SECONDS: Renew an AK "
               "certificate once it is within this long of "
               "expiring.\n");
        printf("               Applies to RP's own AK certificate "
               "and to both of the Attester's. Default: %ds "
               "\n",
                RP_DEFAULT_AK_RENEW_MARGIN_S);
        printf(" -n, --verifiers=COUNT:        Daemon mode: attest against "
                   "COUNT Verifiers per cycle (1..%d). Default %d.\n",
                    MAX_VERIFIERS, RP_DEFAULT_NUM_VERIFIERS);
            printf(" -A, --attester-ak-validity=SECONDS:\n");
            printf("                               Lifetime of the Attester AK "
                   "certificate RP issues under its own CA, measured from "
                   "issuance. Default %ld.\n",
                    (long)attester_ak_cert_validity_seconds);
            printf(" -D, --duration=SECONDS:       Daemon mode: stop cleanly "
                   "after roughly SECONDS. Default 0 (run until "
                   "SIGINT/SIGTERM).\n");
            printf(" -C, --cycles=COUNT:           Daemon mode: stop cleanly "
                   "after COUNT attestation cycles. Default 0 "
                   "(unbounded).\n");
            return 1;
        case 'v':
            charra_log_level = CHARRA_LOG_DEBUG;
            break;
        case 'l':
            if (charra_log_level_from_str(optarg, &charra_log_level) !=
                    CHARRA_RC_SUCCESS) {
                charra_log_error(
                        "[" LOG_NAME "] Invalid --log-level '%s'.", optarg);
                return -1;
            }
            break;
        case 'B':
            rp_benchmark_mode = true;
            break;
        case 'I':
            if (!rp_parse_uint_arg(optarg, "interval", 1, 86400, &value)) {
                return -1;
            }
            rp_attestation_interval_s = (unsigned int)value;
            break;
        case 'Q':
            if (!rp_parse_uint_arg(optarg, "qualify-renew-margin", 0, 86400,
                        &value)) {
                return -1;
            }
            rp_qualify_renew_margin_s = (unsigned int)value;
            break;
        case 'R':
            /* Upper bound is a year: a margin beyond that exceeds any
             * plausible certificate lifetime, which would mean renewing on
             * every cycle forever. */
            if (!rp_parse_uint_arg(optarg, "ak-renew-margin", 0,
                        365L * 24 * 60 * 60, &value)) {
                return -1;
            }
            rp_ak_renew_margin_s = (time_t)value;
            break;
        case 'n':
            if (!rp_parse_uint_arg(
                        optarg, "verifiers", 1, MAX_VERIFIERS, &value)) {
                return -1;
            }
            rp_num_verifiers = (int)value;
            break;
        case 'D':
            if (!rp_parse_uint_arg(optarg, "duration", 1, LONG_MAX,
                        &value)) {
                return -1;
            }
            rp_duration_s = (unsigned int)value;
            break;
        case 'C':
            if (!rp_parse_uint_arg(optarg, "cycles", 1, LONG_MAX,
                        &value)) {
                return -1;
            }
            rp_max_cycles = (unsigned long)value;
            break;
        case 'A':
            if (!rp_parse_uint_arg(optarg, "attester-ak-validity", 1, LONG_MAX,
                        &value)) {
                return -1;
            }
            attester_ak_cert_validity_seconds = (time_t)value;
            break;
        default:
            charra_log_error(
                    "[" LOG_NAME "] Unrecognized option. Try --help.");
            return -1;
        }
    }

        /* The other bound: a margin covering the whole validity window can
     * never be satisfied, so every idle pass would re-qualify. */
    /* No margin-vs-validity check here: the window is the Verifier's to
     * choose (--qualification-validity there) and arrives on the wire, so
     * it is checked where it is actually learned -- see the warning beside
     * qualify_submit_expires_at. */
    return 0;
}

