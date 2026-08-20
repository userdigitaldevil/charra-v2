/**
 * @file rp_config.c
 * @brief Relying Party command-line parsing and the daemon's sleep helper.
 *        See rp_config.h.
 */

#include "rp_config.h"

#include <errno.h>
#include <getopt.h>

#include "../util/cli_util.h"
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

/* Identifiers for options with no short letter. Outside ASCII so they can
 * never collide with a typeable short flag, but inside cli_util's flag range
 * so "(default)" tagging still works. -t/-T were the obvious short forms and
 * were rejected: two timeouts differing only by letter case is a footgun. */
#define RP_OPT_VERIFIER_TIMEOUT 128
#define RP_OPT_ATTESTER_TIMEOUT 129

static const struct option rp_long_options[] = {{"help", no_argument, 0, '0'},
        {"verbose", no_argument, 0, 'v'},
        {"log-level", required_argument, 0, 'l'},
        {"benchmark", no_argument, 0, 'B'},
        {"interval", required_argument, 0, 'I'},
        {"verifiers", required_argument, 0, 'n'},
        {"duration", required_argument, 0, 'D'},
        {"cycles", required_argument, 0, 'C'},
        {"verifier-timeout", required_argument, 0, RP_OPT_VERIFIER_TIMEOUT},
        {"attester-timeout", required_argument, 0, RP_OPT_ATTESTER_TIMEOUT},
        {0}};

/* Which options actually appeared on the command line, indexed by their
 * getopt identifier. Only used to tell "you chose this" from "this is the
 * built-in default" when logging the configuration -- parsing itself does
 * not consult it. */
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
                getopt_long(argc, argv, "vl:BI:n:D:C:", rp_long_options, &index);
        if (identifier == -1) {
            break;
        }
        /* Recorded before the switch so every option is covered by one line
         * rather than a flag-setting statement in each case. An option that
         * fails validation below aborts the run anyway, so marking it here
         * first is harmless. */
        if (identifier >= 0 && identifier <= UCHAR_MAX) {
            charra_cli_flag_mark_given(identifier);
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
        printf(" -n, --verifiers=COUNT:        Daemon mode: attest against "
                   "COUNT Verifiers per attestation cycle (1..%d). "
                   "Default %d.\n",
                    MAX_VERIFIERS, RP_DEFAULT_NUM_VERIFIERS);
            printf(" -D, --duration=SECONDS:       Daemon mode: stop cleanly "
                   "after roughly SECONDS. Default 0 (run until "
                   "SIGINT/SIGTERM).\n");
            printf(" -C, --cycles=COUNT:           Daemon mode: stop cleanly "
                   "after COUNT attestation cycles. Default 0 "
                   "(unbounded).\n");
            printf("     --verifier-timeout=SECONDS: How long to wait for a "
                   "Verifier's reply before giving up. Also bounds every "
                   "other RP round trip (Trust Manager, /qualify, "
                   "/qualify_submit, /appraise). A Verifier that times out "
                   "counts against the "
                   "majority exactly like a NO vote. Default %d.\n",
                    RP_DEFAULT_VERIFIER_TIMEOUT_S);
            printf("     --attester-timeout=SECONDS: How long to wait for the "
                   "Attester's evidence before giving up, ending the cycle. "
                   "Default %d.\n",
                    RP_DEFAULT_ATTESTER_TIMEOUT_S);
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
            if (!charra_cli_parse_uint_arg(
                        LOG_NAME, "--interval", optarg, 1, 86400, &value)) {
                return -1;
            }
            rp_attestation_interval_s = (unsigned int)value;
            break;
        case 'n':
            if (!charra_cli_parse_uint_arg(LOG_NAME, "--verifiers", optarg, 1,
                        MAX_VERIFIERS, &value)) {
                return -1;
            }
            rp_num_verifiers = (int)value;
            break;
        case RP_OPT_VERIFIER_TIMEOUT:
            if (!charra_cli_parse_uint_arg(LOG_NAME, "--verifier-timeout",
                        optarg, 1, 3600, &value)) {
                return -1;
            }
            verifier_response_timeout = (uint16_t)value;
            break;
        case RP_OPT_ATTESTER_TIMEOUT:
            if (!charra_cli_parse_uint_arg(LOG_NAME, "--attester-timeout",
                        optarg, 1, 3600, &value)) {
                return -1;
            }
            attester_response_timeout = (uint16_t)value;
            break;
        case 'D':
            if (!charra_cli_parse_uint_arg(
                        LOG_NAME, "--duration", optarg, 1, LONG_MAX, &value)) {
                return -1;
            }
            rp_duration_s = (unsigned int)value;
            break;
        case 'C':
            if (!charra_cli_parse_uint_arg(
                        LOG_NAME, "--cycles", optarg, 1, LONG_MAX, &value)) {
                return -1;
            }
            rp_max_cycles = (unsigned long)value;
            break;
        default:
            charra_log_error(
                    "[" LOG_NAME "] Unrecognized option. Try --help.");
            return -1;
        }
    }

    return 0;
}


/** Renders an "unlimited when zero" setting, e.g. --duration/--cycles. */
static const char* rp_limit_str(
        unsigned long value, char* buf, size_t buf_len, const char* unit) {
    if (value == 0) {
        return "unlimited";
    }
    snprintf(buf, buf_len, "%lu%s", value, unit);
    return buf;
}

/** Warns about a flag that was given but does not apply to this mode --
 * silently ignoring it is how a flag comes to look like it works. */
static void rp_warn_if_ignored(int identifier, const char* flag_name) {
    if (charra_cli_flag_was_given(identifier)) {
        charra_log_warn("[" LOG_NAME "]   --%s was given but has NO EFFECT in "
                        "benchmark mode.",
                flag_name);
    }
}

void rp_log_effective_configuration(void) {
    char buf_duration[32] = {0};
    char buf_cycles[32] = {0};

    charra_log_info("[" LOG_NAME
                    "] ============================================================");
    if (rp_benchmark_mode) {
        charra_log_info("[" LOG_NAME "] MODE: BENCHMARK -- fixed 1..%d "
                        "Verifier sweep, then exit (--benchmark).",
                RP_MAX_SWEEP_VERIFIERS);
    } else {
        charra_log_info("[" LOG_NAME "] MODE: DAEMON -- continuous attestation "
                        "until stopped (default; pass --benchmark for the "
                        "timing sweep).");
    }
    charra_log_info("[" LOG_NAME
                    "] ============================================================");
    charra_log_info("[" LOG_NAME "] Settings for this run -- \"(default)\" "
                    "means the flag was not given; pass it to change the "
                    "value.");

    if (rp_benchmark_mode) {
        charra_log_info("[" LOG_NAME "]   %-22s 1..%d  (fixed, not settable)",
                "verifier sweep", RP_MAX_SWEEP_VERIFIERS);
        charra_log_info("[" LOG_NAME "]   %-22s %d  (fixed, not settable; "
                        "plus 1 discarded warm-up)",
                "measured runs/step", NUM_RUNS);
        /* Named individually rather than in a loop: each is a real flag a
         * user could reasonably expect to apply here, and saying so beats
         * ignoring it. */
        rp_warn_if_ignored('n', "verifiers");
        rp_warn_if_ignored('I', "interval");
        rp_warn_if_ignored('D', "duration");
        rp_warn_if_ignored('C', "cycles");
    } else {
        charra_log_info("[" LOG_NAME "]   %-22s %d%s", "--verifiers",
                rp_num_verifiers, charra_cli_default_tag('n'));
        charra_log_info("[" LOG_NAME "]   %-22s %us%s", "--interval",
                rp_attestation_interval_s, charra_cli_default_tag('I'));
        charra_log_info("[" LOG_NAME "]   %-22s %s%s", "--duration",
                rp_limit_str(rp_duration_s, buf_duration, sizeof(buf_duration),
                        "s"),
                charra_cli_default_tag('D'));
        charra_log_info("[" LOG_NAME "]   %-22s %s%s", "--cycles",
                rp_limit_str(rp_max_cycles, buf_cycles, sizeof(buf_cycles), ""),
                charra_cli_default_tag('C'));
    }

    /* Log level applies to both modes. */
    charra_log_info("[" LOG_NAME "]   %-22s %s%s", "--log-level",
            charra_log_level_to_str(charra_log_level),
            (charra_cli_flag_was_given('l') || charra_cli_flag_was_given('v'))
                            ? ""
                            : " (default)");

    charra_log_info("[" LOG_NAME "]   %-22s %us%s", "--verifier-timeout",
            verifier_response_timeout,
            charra_cli_default_tag(RP_OPT_VERIFIER_TIMEOUT));
    charra_log_info("[" LOG_NAME "]   %-22s %us%s", "--attester-timeout",
            attester_response_timeout,
            charra_cli_default_tag(RP_OPT_ATTESTER_TIMEOUT));

    /* Compiled-in, no flag -- listed so the log still explains a policy
     * rejection without the reader having to guess the values. */
    /* Both halves of the Step 2a item 6 policy. Which one is actually in
     * force depends on whether the whitelist has entries -- an empty one
     * falls back to allow-by-default -- so that is reported per check by
     * charra_verify_log_file_hashes_against_policy(), not here. */
    charra_log_info("[" LOG_NAME "]   %-22s '%s'  (no flag)", "whitelist",
            whitelist_hashes_path);
    charra_log_info("[" LOG_NAME "]   %-22s '%s'  (no flag)", "blacklist",
            blacklist_hashes_path);
    charra_log_info("[" LOG_NAME "]   %-22s '%s'  (in use: %s, no flag)",
            "IMA test log", ima_test_log_path,
            use_ima_test_log ? "yes" : "no");
    charra_log_info("[" LOG_NAME "] Run with --help for every flag and its "
                    "accepted range.");
    charra_log_info("[" LOG_NAME
                    "] ============================================================");
}
