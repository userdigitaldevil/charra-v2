/* SPDX-License-Identifier: BSD-3-Clause */
/*****************************************************************************
 * Copyright 2021, Fraunhofer Institute for Secure Information Technology SIT.
 * All rights reserved.
 ****************************************************************************/

/**
 * @file command_line_util.c
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

#include "cli_util.h"

#include "../common/charra_log.h"
#include "coap_util.h"
#include "io_util.h"
#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <stdbool.h>
#include <stdlib.h>

/* command line argument handling */
static const struct option verifier_options[] = {
        {"verbose", no_argument, 0, 'v'},
        {"log-level", required_argument, 0, 'l'},
        {"coap-log-level", required_argument, 0, 'c'},
        {"psk", no_argument, 0, 'p'}, {"key", required_argument, 0, 'k'},
        {"identity", required_argument, 0, 'i'}, {"rpk", no_argument, 0, 'r'},
        {"help", no_argument, 0, '0'},
        {"private-key", required_argument, 0, '1'},
        {"public-key", required_argument, 0, '2'},
        {"peer-public-key", required_argument, 0, '3'},
        {"verify-peer", required_argument, 0, '4'},
        {"port", required_argument, 0, 'b'},
        {"qualification-validity", required_argument, 0, '5'},
        {"ak-validity", required_argument, 0, '6'}, {0}};

static const struct option attester_options[] = {
        {"verbose", no_argument, 0, 'v'},
        {"log-level", required_argument, 0, 'l'},
        {"coap-log-level", required_argument, 0, 'c'},
        {"psk", no_argument, 0, 'p'}, {"key", required_argument, 0, 'k'},
        {"hint", required_argument, 0, 'h'}, {"rpk", no_argument, 0, 'r'},
        {"help", no_argument, 0, '0'},
        {"private-key", required_argument, 0, '1'},
        {"public-key", required_argument, 0, '2'},
        {"peer-public-key", required_argument, 0, '3'},
        {"verify-peer", required_argument, 0, '4'},
        {"port", required_argument, 0, 'b'}, {0}};

/* Which options actually appeared on the command line, indexed by their
 * getopt identifier -- lets a caller tell "you chose this" from "this is the
 * built-in default" when echoing its configuration. Parsing never reads it. */
static bool cli_flag_given[UCHAR_MAX + 1] = {false};

bool charra_cli_flag_was_given(int identifier) {
    return identifier >= 0 && identifier <= UCHAR_MAX &&
           cli_flag_given[(unsigned char)identifier];
}

void charra_cli_flag_mark_given(int identifier) {
    if (identifier >= 0 && identifier <= UCHAR_MAX) {
        cli_flag_given[(unsigned char)identifier] = true;
    }
}

const char* charra_cli_default_tag(int identifier) {
    return charra_cli_flag_was_given(identifier) ? "" : " (default)";
}

bool charra_cli_parse_uint_arg(const char* log_name, const char* option_name,
        const char* arg, long min, long max, long* out) {
    if (arg == NULL) {
        charra_log_error(
                "[%s] Missing value for '%s'.", log_name, option_name);
        return false;
    }
    char* end = NULL;
    errno = 0;
    long value = strtol(arg, &end, 10);
    if (errno != 0 || end == arg || *end != '\0' || value < min ||
            value > max) {
        charra_log_error("[%s] Invalid %s value '%s' (expected an integer in "
                         "[%ld, %ld]).",
                log_name, option_name, arg, min, max);
        return false;
    }
    *out = value;
    return true;
}

/* strdup() plus the allocation check every call site below was missing.
 * The sites this replaces sized their buffer with strlen(), then strcpy()'d
 * strlen() + 1 bytes into it, overrunning it by the terminator. */
static char* charra_cli_dup_arg(
        const char* log_name, const char* option_name, const char* value) {
    if (value == NULL) {
        charra_log_error("[%s] Missing value for '%s'.", log_name, option_name);
        return NULL;
    }
    char* copy = malloc(strlen(value) + 1);
    if (copy == NULL) {
        charra_log_error("[%s] Out of memory while parsing '%s'.", log_name,
                option_name);
        return NULL;
    }
    strcpy(copy, value);
    return copy;
}

int parse_command_line_arguments(int argc, char** argv, cli_config* variables) {
    cli_parser_caller caller = variables->caller;
    char* log_name;
    if (caller == VERIFIER) {
        log_name = "verifier";
    } else {
        log_name = "attester";
    }
    for (;;) {
        int index = -1;
        int identifier = getopt_long(argc, argv,
                ((caller == VERIFIER) ? "vl:c:pk:i:r" : "vl:c:pk:h:r"),
                ((caller == VERIFIER) ? verifier_options : attester_options),
                &index);

        if (identifier == -1) {
            return 0;  // end of command line arguments reached
        }
        /* Recorded before the dispatch below so one line covers every
         * option, rather than a statement in each branch. */
        if (identifier >= 0 && identifier <= UCHAR_MAX) {
            charra_cli_flag_mark_given(identifier);
        }
        if (identifier == '0' || identifier == '?') {
            // print help message
            printf("\nUsage: %s [OPTIONS]\n", log_name);
            printf("     --help:                     Print this help "
                   "message.\n");
            printf(" -v, --verbose:                  Set CHARRA and CoAP "
                   "log-level to DEBUG.\n");
            printf(" -l, --log-level=LEVEL:          Set CHARRA log-level to "
                   "LEVEL. Available are: TRACE, DEBUG, INFO, WARN, ERROR, "
                   "FATAL. Default is INFO.\n");
            printf(" -c, --coap-log-level=LEVEL:     Set CoAP log-level to "
                   "LEVEL. Available are: DEBUG, INFO, NOTICE, WARNING, ERR, "
                   "CRIT, ALERT, EMERG, CIPHERS. Default is INFO.\n");
            if (caller == VERIFIER) {
                printf("     --port=PORT:                Connect to PORT "
                       "instead of default port %u.\n",
                        *(variables->common_config.port));
                printf("     --qualification-validity=SECONDS: How long a\n"
                       "                                 passed RP qualification stays "
                       "valid. Must match the RP's own flag. Default %ld.\n",
                        (long)*(variables->verifier_config
                                        .qualification_validity_seconds));
                printf("     --ak-validity=SECONDS:      Lifetime of AK "
                       "certificates this Verifier issues, measured from "
                       "issuance. Default %ld.\n",
                        (long)*(variables->verifier_config
                                        .ak_cert_validity_seconds));
                printf("DTLS-PSK Options:\n");
                printf(" -p, --psk:                      Enable DTLS protocol "
                       "with PSK. By default the key '%s' and identity '%s' "
                       "are used.\n",
                        *variables->common_config.dtls_psk_key,
                        *variables->verifier_config.dtls_psk_identity);
                printf(" -k, --key=KEY:                  Use KEY as pre-shared "
                       "key for DTLS-PSK. Implicitly enables DTLS-PSK.\n");
                printf(" -i, --identity=IDENTITY:        Use IDENTITY as "
                       "identity for DTLS. Implicitly enables DTLS-PSK.\n");
            } else {
                printf("     --port=PORT:                Open PORT instead of "
                       "port %u.\n",
                        *(variables->common_config.port));
                printf("DTLS-PSK Options:\n");
                printf(" -p, --psk:                      Enable DTLS protocol "
                       "with PSK. By default the key '%s' and hint '%s' are "
                       "used.\n",
                        *variables->common_config.dtls_psk_key,
                        *variables->attester_config.dtls_psk_hint);
                printf(" -k, --key=KEY:                  Use KEY as pre-shared "
                       "key for DTLS. Implicitly enables DTLS-PSK.\n");
                printf(" -h, --hint=HINT:                Use HINT as hint for "
                       "DTLS. Implicitly enables DTLS-PSK.\n");
            }
            printf("DTLS-RPK Options:\n");
            printf("                                 Charra includes default "
                   "'keys' in the keys folder, but these are only intended for "
                   "testing. They MUST be changed in actual production "
                   "environments!\n");
            printf(" -r, --rpk:                      Enable DTLS-RPK (raw "
                   "public keys) protocol . The protocol is intended for "
                   "scenarios in which public keys of either attester or "
                   "verifier or both of them are pre-shared.\n");
            printf("     --private-key=PATH:         Specify the path of the "
                   "private key used for RPK. Currently only supports DER "
                   "(ASN.1) format.\n");
            printf("                                 By default '%s' is used. "
                   "Implicitly enables DTLS-RPK.\n",
                    *variables->common_config.dtls_rpk_private_key_path);
            printf("     --public-key=PATH:          Specify the path of the "
                   "public key used for RPK. Currently only supports DER "
                   "(ASN.1) format.\n");
            printf("                                 By default '%s' is used. "
                   "Implicitly enables DTLS-RPK.\n",
                    *variables->common_config.dtls_rpk_public_key_path);
            printf("     --peer-public-key=PATH:     Specify the path of the "
                   "reference public key of the peer, used for RPK. Currently "
                   "only supports DER (ASN.1) format.\n");
            printf("                                 By default '%s' is used. "
                   "Implicitly enables DTLS-RPK.\n",
                    *variables->common_config.dtls_rpk_peer_public_key_path);
            printf("     --verify-peer=[0,1]:        Specify whether the peers "
                   "public key shall be checked against the reference public "
                   "key. 0 means no check, 1 means check. By default the check "
                   "is performed.\n");
            printf("                                 WARNING: Disabling the "
                   "verification means that connections from any peer will be "
                   "accepted. This is primarily intended for the verifier, "
                   "which may not have\n");
            printf("                                 the public keys of all "
                   "attesters and does an identity check with the attestation "
                   "response. Implicitly enables DTLS-RPK.\n");
            printf("\nTo specify TCTI commands for the TPM, set the "
                   "'CHARRA_TCTI' environment variable accordingly.\n");

            /*
             * return -1 if argument could not be parsed, and 1 if help message
             * was called via argument.
             */
            return (identifier == '?') ? -1 : 1;
        } else if (identifier == 'v') {  // verbose logging
            *(variables->common_config.charra_log_level) = CHARRA_LOG_DEBUG;
            *(variables->common_config.coap_log_level) = LOG_DEBUG;
            continue;
        } else if (identifier == 'l') {  // CHARRA log level
            int result = charra_log_level_from_str(
                    optarg, variables->common_config.charra_log_level);
            if (result != 0) {
                charra_log_error("[%s] Error while parsing '-l/--log-level': "
                                 "Unrecognized argument %s",
                        log_name, optarg);
                return -1;
            }
            continue;
        } else if (identifier == 'c') {  // libcoap log level
            int result = charra_coap_log_level_from_str(
                    optarg, variables->common_config.coap_log_level);
            if (result != 0) {
                charra_log_error(
                        "[%s] Error while parsing '-c/--coap-log-level': "
                        "Unrecognized argument %s",
                        log_name, optarg);
                return -1;
            }
            continue;
        } else if (identifier == 'b') {  // port
            long value = 0;
            if (!charra_cli_parse_uint_arg(
                        log_name, "--port", optarg, 1, 65535, &value)) {
                return -1;
            }
            *(variables->common_config.port) = (unsigned int)value;
            continue;
        } else if (identifier == 'p') {  // use DTLS PSK
            *variables->common_config.use_dtls_psk = true;
            continue;
        } else if (identifier == 'k') {  // DTLS PSK key
            *variables->common_config.use_dtls_psk = true;
            char* key = charra_cli_dup_arg(log_name, "--key", optarg);
            if (key == NULL) {
                return -1;
            }
            *(variables->common_config.dtls_psk_key) = key;
            continue;
        } else if (identifier == 'r') {  // use DTLS RPK
            *variables->common_config.use_dtls_rpk = true;
            continue;
        } else if (identifier == '1') {  // DTLS RPK private key
            *variables->common_config.use_dtls_rpk = true;
            char* path = charra_cli_dup_arg(log_name, "--private-key", optarg);
            if (path == NULL) {
                return -1;
            }
            if (charra_io_file_exists(path) == CHARRA_RC_SUCCESS) {
                *(variables->common_config.dtls_rpk_private_key_path) = path;
                continue;
            } else {
                charra_log_error(
                        "[%s] DTLS-RPK: private key file '%s' does not exist.",
                        log_name, path);
                return -1;
            }
        } else if (identifier == '2') {
            *variables->common_config.use_dtls_rpk = true;
            char* path = charra_cli_dup_arg(log_name, "--public-key", optarg);
            if (path == NULL) {
                return -1;
            }
            if (charra_io_file_exists(path) == CHARRA_RC_SUCCESS) {
                *(variables->common_config.dtls_rpk_public_key_path) = path;
                continue;
            } else {
                charra_log_error(
                        "[%s] DTLS-RPK: public key file '%s' does not exist.",
                        log_name, path);
                return -1;
            }
        } else if (identifier == '3') {
            *variables->common_config.use_dtls_rpk = true;
            char* path = charra_cli_dup_arg(log_name, "--peer-public-key", optarg);
            if (path == NULL) {
                return -1;
            }
            if (charra_io_file_exists(path) == CHARRA_RC_SUCCESS) {
                *(variables->common_config.dtls_rpk_peer_public_key_path) =
                        path;
                continue;
            } else {
                charra_log_error("[%s] DTLS-RPK: peers' public key file '%s' "
                                 "does not exist.",
                        log_name, path);
                return -1;
            }
        } else if (identifier == '4') {
            if (strcmp("0", optarg) == 0) {
                *variables->common_config.dtls_rpk_verify_peer_public_key =
                        false;
            } else if (strcmp("1", optarg) == 0) {
                *variables->common_config.dtls_rpk_verify_peer_public_key =
                        true;
            } else {
                charra_log_error("[%s] Error while parsing '--verify-peer': "
                                 "'%s' could not be parsed as 0 or 1.",
                        log_name, optarg);
                return -1;
            }
            continue;
        }

        if (caller == VERIFIER && identifier == '6') {
            // set AK certificate lifetime
            long value = 0;
            if (!charra_cli_parse_uint_arg(log_name, "--ak-validity", optarg, 1,
                        LONG_MAX, &value)) {
                return -1;
            }
            *(variables->verifier_config.ak_cert_validity_seconds) =
                    (time_t)value;
        } else if (caller == VERIFIER && identifier == '5') {
            // set qualification validity window
            long value = 0;
            if (!charra_cli_parse_uint_arg(log_name,
                        "--qualification-validity", optarg, 1, LONG_MAX,
                        &value)) {
                return -1;
            }
            *(variables->verifier_config.qualification_validity_seconds) =
                    (time_t)value;
        } else if (caller == VERIFIER && identifier == 'i') {
            *variables->common_config.use_dtls_psk = true;
            char* identity =
                    charra_cli_dup_arg(log_name, "--identity", optarg);
            if (identity == NULL) {
                return -1;
            }
            *(variables->verifier_config.dtls_psk_identity) = identity;
            continue;
        } else if (caller == ATTESTER && identifier == 'h') {
            *variables->common_config.use_dtls_psk = true;
            char* hint = charra_cli_dup_arg(log_name, "--hint", optarg);
            if (hint == NULL) {
                return -1;
            }
            *(variables->attester_config.dtls_psk_hint) = hint;
            continue;
        } else {
            // undefined behaviour, probably because getopt_long returned an
            // identifier which is not checked here
            charra_log_error("[%s] Error: Undefined behaviour while parsing "
                             "command line",
                    log_name);
            return -1;
        }
    }
}
