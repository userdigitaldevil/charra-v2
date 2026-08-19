/**
 * @file rp_config.h
 * @brief Relying Party command-line parsing.
 *
 * The config values themselves live in relying_party.c and are declared in
 * rp_shared.h; this module only populates them.
 *
 * Deliberately not routed through util/cli_util.c: that parser is built
 * around a binary verifier-or-attester split (its getopt string and option
 * table are chosen with `caller == VERIFIER ? a : b` ternaries), and the RP
 * shares none of its options.
 */

#ifndef CHARRA_RP_CONFIG_H
#define CHARRA_RP_CONFIG_H

/**
 * @brief Parses the RP command line into the globals in rp_shared.h.
 * @returns 0 to continue, 1 if help was printed (exit successfully), -1 on
 * a bad argument.
 */
int parse_rp_command_line(int argc, char** argv);

/**
 * @brief Logs every setting this run will use, marking the ones left at
 * their default.
 *
 * Call once, straight after parsing. A run's behaviour is otherwise only
 * inferable from the command line that started it, which is exactly what a
 * log file does not have -- and the defaults are not visible anywhere at
 * all.
 */
void rp_log_effective_configuration(void);

#endif /* CHARRA_RP_CONFIG_H */
