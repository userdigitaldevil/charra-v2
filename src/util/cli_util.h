/* SPDX-License-Identifier: BSD-3-Clause */
/*****************************************************************************
 * Copyright 2021, Fraunhofer Institute for Secure Information Technology SIT.
 * All rights reserved.
 ****************************************************************************/

/**
 * @file command_line_util.h
 * @author Dominik Lorych (dominik.lorych@sit.fraunhofer.de)
 * @brief Provides command line parsing for verifier & attester.
 * @version 0.1
 * @date 2021-02-18
 *
 * @copyright Copyright 2021, Fraunhofer Institute for Secure Information
 * Technology SIT. All rights reserved.
 *
 * @license BSD 3-Clause "New" or "Revised" License (SPDX-License-Identifier:
 * BSD-3-Clause).
 */

#include "../common/charra_log.h"
#include <coap3/coap.h>
#include <stdbool.h>

typedef enum {
    VERIFIER,
    ATTESTER,
} cli_parser_caller;

/**
 * A structure holding pointers to common variables of attester and verifier
 * which might geht modified by the CLI parser
 */
typedef struct {
    charra_log_t* charra_log_level;
    coap_log_t* coap_log_level;
    unsigned int* port;
    bool* use_dtls_psk;
    char** dtls_psk_key;
    bool* use_dtls_rpk;
    char** dtls_rpk_private_key_path;
    char** dtls_rpk_public_key_path;
    char** dtls_rpk_peer_public_key_path;
    bool* dtls_rpk_verify_peer_public_key;
} cli_config_common;

/**
 * A structure holding pointers to variables of the attester
 * which might geht modified by the CLI parser
 */
typedef struct {
    char** dtls_psk_hint;
} cli_config_attester;

/**
 * A structure holding pointers to variables of the verifier
 * which might geht modified by the CLI parser
 */
typedef struct {
    char* dst_host;
    /* Retained only so verifier_old.c still compiles: the current Verifier
     * dropped the options that fed these (--timeout, --pcr-file,
     * --pcr-selection, --ima, --ip), which it parsed but never acted on.
     * Nothing in cli_util.c reads them any more. */
    uint16_t* timeout;
    char** reference_pcr_file_path;
    uint8_t* tpm_pcr_selection;
    uint32_t* tpm_pcr_selection_len;
    bool* use_ima_event_log;
    char** ima_event_log_path;
    char** dtls_psk_identity;
} cli_config_verifier;

/**
 * A structure holding the pointers to all config parameters which might get
 * modified by the CLI parser
 */
typedef struct {
    cli_parser_caller caller;
    cli_config_common common_config;
    cli_config_attester attester_config;
    cli_config_verifier verifier_config;
} cli_config;

/**
*  @brief parses command line interface arguments
*
* @param argc The number of arguments which were given to the CLI.
* @param argv The arguments which were given to the CLI.
* @param variables A struct holding a caller identifier and pointers to config
                   variables which might get modified depending on the CLI
arguments.
* @return 0 on success, -1 on parse error, 1 when help message was displayed
*/
int parse_command_line_arguments(int argc, char** argv, cli_config* variables);

/**
 * @brief Did this option actually appear on the command line?
 *
 * Only meaningful after parse_command_line_arguments() has run. Lets a
 * caller distinguish a value the user chose from one left at its built-in
 * default when logging its effective configuration.
 *
 * @param identifier the option's getopt identifier, e.g. 'b' for --port.
 */
bool charra_cli_flag_was_given(int identifier);

/**
 * @brief Record that an option appeared on the command line.
 *
 * For parsers outside this module -- rp_config.c has its own getopt loop but
 * reports its effective configuration the same way, so it shares the
 * bookkeeping rather than keeping a second copy of it.
 */
void charra_cli_flag_mark_given(int identifier);

/**
 * @brief " (default)" when the option was not given, "" when it was --
 * intended to be appended directly to a logged value.
 */
const char* charra_cli_default_tag(int identifier);

/**
 * @brief Parses an integer option argument, rejecting anything non-numeric,
 * anything with trailing characters, and anything outside [min, max].
 *
 * Logs the reason itself, naming the option, so callers only branch on the
 * result.
 *
 * @param option_name as the user typed it, including the dashes.
 * @return false if the argument is unusable; *out is untouched then.
 */
bool charra_cli_parse_uint_arg(const char* log_name, const char* option_name,
        const char* arg, long min, long max, long* out);
