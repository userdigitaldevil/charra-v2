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
#include <sys/stat.h>
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
#include "core/charra_identity_key_mgr.h"
#include "util/cbor_util.h"
#include "util/charra_util.h"
#include "util/cli_util.h"
#include "util/coap_util.h"
#include "util/crypto_util.h"
#include "util/io_util.h"
#include "util/tpm2_util.h"

#include "attester/attester_attest.h"
#include "attester/attester_certify_ak.h"
#include "attester/attester_identity.h"
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
#define CBOR_ENCODER_BUFFER_LENGTH 20480       // 20 KiB should be sufficient
bool use_ima_event_log = false;
char* ima_event_log_path =
        "/sys/kernel/security/ima/binary_runtime_measurements";
bool use_dtls_psk = false;
char* dtls_psk_key = "Charra DTLS Key";
char* dtls_psk_hint = "Charra Attester";
/* ASCII IMA measurement log replayed into the TPM's PCRs before the first
 * TPM Quote, so that PCR 10 reflects a non-trivial measurement history
 * instead of staying all-zero. */
char* ima_test_log_path = "ima_test_logs.txt";
// TODO(any): Allocate memory for CBOR buffer with malloc() as logs can be huge.

// for DTLS-RPK
bool use_dtls_rpk = false;
char* dtls_rpk_private_key_path = "keys/attester.der";
char* dtls_rpk_public_key_path = "keys/attester.pub.der";
char* dtls_rpk_peer_public_key_path = "keys/relying_party.pub.der";
bool dtls_rpk_verify_peer_public_key = true;

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
    cli_config cli_config = {
        .caller = ATTESTER,
        .common_config = {
            .charra_log_level = &charra_log_level,
            .coap_log_level = &coap_log_level,
            .port = &port,
            .use_dtls_psk = &use_dtls_psk,
            .dtls_psk_key = &dtls_psk_key,
            .use_dtls_rpk = &use_dtls_rpk,
            .dtls_rpk_private_key_path =
                    &dtls_rpk_private_key_path,
            .dtls_rpk_public_key_path =
                    &dtls_rpk_public_key_path,
            .dtls_rpk_peer_public_key_path =
                    &dtls_rpk_peer_public_key_path,
            .dtls_rpk_verify_peer_public_key =
                    &dtls_rpk_verify_peer_public_key,
        },
        .attester_config = {
            .dtls_psk_hint = &dtls_psk_hint,
        },
    };
    /* clang-format on */

    /* parse CLI arguments */
    if ((result = parse_command_line_arguments(argc, argv, &cli_config)) != 0) {
        // 1 means help message is displayed, -1 means error
        return (result == 1) ? EXIT_SUCCESS : EXIT_FAILURE;
    }

    /* set CHARRA and libcoap log levels */
    charra_log_set_level(charra_log_level);
    coap_set_log_level(coap_log_level);

    charra_log_info("[" LOG_NAME "] Effective configuration: port=%d "
                    "ima_event_log='%s' ima_test_log='%s'",
            port, ima_event_log_path, ima_test_log_path);

    charra_log_debug("[" LOG_NAME "] Attester Configuration:");

    charra_coap_server_config server_config = {
        .log_name = LOG_NAME,
        .listen_address = LISTEN_ADDRESS,
        .port = port,
        .use_dtls_psk = use_dtls_psk,
        .dtls_psk_key = dtls_psk_key,
        .dtls_psk_hint = dtls_psk_hint,
        .use_dtls_rpk = use_dtls_rpk,
        .dtls_rpk_private_key_path = dtls_rpk_private_key_path,
        .dtls_rpk_public_key_path = dtls_rpk_public_key_path,
        .dtls_rpk_peer_public_key_path = dtls_rpk_peer_public_key_path,
        .dtls_rpk_verify_peer_public_key = dtls_rpk_verify_peer_public_key,
    };
    charra_coap_server_log_config(&server_config);

    coap_context_t* coap_context = NULL;
    coap_endpoint_t* coap_endpoint = NULL;
    if (charra_coap_server_start(&server_config, &coap_context,
                &coap_endpoint) != CHARRA_RC_SUCCESS) {
        goto error;
    }

    /* Attester's own runtime state (TPM identity, delivered AK
     * certificates) -- mirrors how relying_party.c organizes state/
     * relying-party/. Ignore EEXIST -- both are expected to already exist
     * on every run after the first. */
    mkdir("state", 0755);
    mkdir("state/attester", 0755);
    mkdir("state/attester/identity", 0755);
    mkdir("state/attester/ak-certificates", 0755);

    /* register CoAP resource and resource handler */
    charra_log_info("[" LOG_NAME "] Registering CoAP resources.");
    charra_coap_add_resource(
            coap_context, COAP_REQUEST_FETCH, "attest", coap_attest_handler);
    charra_coap_add_resource(coap_context, COAP_REQUEST_FETCH,
            "certify_ak_of_attester", coap_certify_ak_of_attester_handler);
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
