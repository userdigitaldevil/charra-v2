/* SPDX-License-Identifier: BSD-3-Clause */
/*****************************************************************************
 * Copyright 2019, Fraunhofer Institute for Secure Information Technology SIT.
 * All rights reserved.
 ****************************************************************************/

/**
 * @file attester.c
 * @author Michael Eckel (michael.eckel@sit.fraunhofer.de)
 * @brief
 * @version 0.1
 * @date 2019-09-19
 *
 * @copyright Copyright 2019, Fraunhofer Institute for Secure Information
 * Technology SIT. All rights reserved.
 *
 * @license BSD 3-Clause "New" or "Revised" License (SPDX-License-Identifier:
 * BSD-3-Clause).
 */

#include <arpa/inet.h>
#include <coap3/coap.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tinydtls/session.h>
#include <tss2/tss2_mu.h>
#include <tss2/tss2_tctildr.h>
#include <tss2/tss2_tpm2_types.h>

#include "common/charra_log.h"
#include "common/charra_macro.h"
#include "core/charra_dto.h"
#include "core/charra_event_log.h"
#include "core/charra_helper.h"
#include "core/charra_key_mgr.h"
#include "core/charra_marshaling.h"
#include "util/cbor_util.h"
#include "util/charra_util.h"
#include "util/cli_util.h"
#include "util/coap_util.h"
#include "util/crypto_util.h"
#include "util/tpm2_util.h"

#include "attester/attester_attest.h"
#include "attester/attester_ima_log.h"
#include "attester/attester_result.h"
#include "attester/attester_shared.h"

/* --- config ------------------------------------------------------------- */

/* quit signal */
static bool quit = false;

/* logging */
#define LOG_NAME "attester"
coap_log_t coap_log_level = LOG_INFO;
// #define LOG_LEVEL_CBOR LOG_DEBUG
charra_log_t charra_log_level = CHARRA_LOG_INFO;

/* config */
static const char LISTEN_ADDRESS[] = "0.0.0.0";
static unsigned int port = 5683;  // default port 5683
charra_dtls_config dtls_config = {
        .psk_key = "Charra DTLS Key",
        .psk_hint = "Charra Attester",
        .rpk_private_key_path = "keys/attester.der",
        .rpk_public_key_path = "keys/attester.pub.der",
        .rpk_peer_public_key_path = "keys/relying_party.pub.der",
        .rpk_verify_peer_public_key = true,
};
/* ASCII IMA measurement log replayed into the TPM's PCRs before the first
 * TPM Quote, so that PCR 10 reflects a non-trivial measurement history
 * instead of staying all-zero. */
char* ima_test_log_path = "ima_test_logs.txt";
// TODO(any): Allocate memory for CBOR buffer with malloc() as logs can be huge.


/**
 * @brief SIGINT handler: set quit to 1 for graceful termination.
 *
 * @param signum the signal number.
 */
static void handle_sigint(int signum);


int main(int argc, char** argv) {
    int result = EXIT_FAILURE;

    /* handle SIGINT */
    signal(SIGINT, handle_sigint);

    /* check environment variables */
    charra_log_level_from_str(
            (const char*)getenv("LOG_LEVEL_CHARRA"), &charra_log_level);
    charra_coap_log_level_from_str(
            (const char*)getenv("LOG_LEVEL_COAP"), &coap_log_level);

    /* initialize structures to pass to the CLI parser */
    /* clang-format off */
    cli_config cli_args = {
        .caller = ATTESTER,
        .common_config = {
            .charra_log_level = &charra_log_level,
            .coap_log_level = &coap_log_level,
            .port = &port,
            .use_dtls_psk = &dtls_config.use_psk,
            .dtls_psk_key = &dtls_config.psk_key,
            .use_dtls_rpk = &dtls_config.use_rpk,
            .dtls_rpk_private_key_path =
                    &dtls_config.rpk_private_key_path,
            .dtls_rpk_public_key_path =
                    &dtls_config.rpk_public_key_path,
            .dtls_rpk_peer_public_key_path =
                    &dtls_config.rpk_peer_public_key_path,
            .dtls_rpk_verify_peer_public_key =
                    &dtls_config.rpk_verify_peer_public_key,
        },
        .attester_config = {
            .dtls_psk_hint = &dtls_config.psk_hint,
        },
    };
    /* clang-format on */

    /* parse CLI arguments */
    if ((result = parse_command_line_arguments(argc, argv, &cli_args)) != 0) {
        // 1 means help message is displayed, -1 means error
        return (result == 1) ? EXIT_SUCCESS : EXIT_FAILURE;
    }

    /* set CHARRA and libcoap log levels */
    charra_log_set_level(charra_log_level);
    coap_set_log_level(coap_log_level);

    charra_log_info("[" LOG_NAME "] Effective configuration: port=%d "
                    "ima_test_log='%s'",
            port, ima_test_log_path);

    charra_log_debug("[" LOG_NAME "] Attester Configuration:");

    charra_coap_server_config server_config = {
        .log_name = LOG_NAME,
        .listen_address = LISTEN_ADDRESS,
        .port = port,
        .use_dtls_psk = dtls_config.use_psk,
        .dtls_psk_key = dtls_config.psk_key,
        .dtls_psk_hint = dtls_config.psk_hint,
        .use_dtls_rpk = dtls_config.use_rpk,
        .dtls_rpk_private_key_path = dtls_config.rpk_private_key_path,
        .dtls_rpk_public_key_path = dtls_config.rpk_public_key_path,
        .dtls_rpk_peer_public_key_path = dtls_config.rpk_peer_public_key_path,
        .dtls_rpk_verify_peer_public_key = dtls_config.rpk_verify_peer_public_key,
    };
    charra_coap_server_log_config(&server_config);

    coap_context_t* coap_context = NULL;
    coap_endpoint_t* coap_endpoint = NULL;
    if (charra_coap_server_start(&server_config, &coap_context,
                &coap_endpoint) != CHARRA_RC_SUCCESS) {
        goto error;
    }

    /* No runtime state to claim: the Attester's signing key is derived
     * from the TPM on demand and its public half sits in the read-only
     * trust anchor, so there is nothing on disk for a second instance to
     * conflict over. */

    /* register CoAP resource and resource handler */
    charra_log_info("[" LOG_NAME "] Registering CoAP resources.");
    charra_coap_add_resource(
            coap_context, COAP_REQUEST_FETCH, "attest", coap_attest_handler);
    charra_coap_add_resource(coap_context, COAP_REQUEST_FETCH, "attest_result",
            coap_attest_result_handler);
    if (charra_coap_server_run(coap_context, LOG_NAME, &quit) !=
            CHARRA_RC_SUCCESS) {
        goto error;
    }

    result = EXIT_SUCCESS;
    goto finish;

error:
    result = EXIT_FAILURE;

finish:
    charra_coap_server_stop(coap_context, coap_endpoint);

    return result;
}

/* --- function definitions ----------------------------------------------- */

static void handle_sigint(int signum CHARRA_UNUSED) { quit = true; }
