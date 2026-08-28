#include <coap3/coap.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <tss2/tss2_tpm2_types.h>

#include "common/charra_log.h"
#include "common/charra_macro.h"
#include "core/charra_trusted_keys.h"
#include "core/charra_rp_qualification.h"
#include "util/cli_util.h"
#include "util/coap_util.h"
#include "verifier/verifier_appraise.h"
#include "verifier/verifier_nonce.h"
#include "verifier/verifier_qualified_rps.h"
#include "verifier/verifier_qualify.h"
#include "core/charra_zk_job.h"
#include "verifier/verifier_shared.h"

/* --- config ------------------------------------------------------------- */

/* quit signal */
static volatile sig_atomic_t quit = 0;

/* logging */
#define LOG_NAME "verifier"
coap_log_t coap_log_level = LOG_INFO;
// #define LOG_LEVEL_CBOR LOG_DEBUG
charra_log_t charra_log_level = CHARRA_LOG_INFO;

/* config */
static const char LISTEN_ADDRESS[] = "0.0.0.0";
static unsigned int port = 31415;

charra_dtls_config dtls_config = {
        .psk_key = "Charra DTLS Key",
        .psk_identity = "Charra Verifier",
        .psk_hint = "Charra Attester",
        .rpk_private_key_path = "keys/verifier.der",
        .rpk_public_key_path = "keys/verifier.pub.der",
        .rpk_peer_public_key_path = "keys/relying_party.pub.der",
        .rpk_verify_peer_public_key = true,
};

/* The trust anchor both /appraise and /qualify_submit consult lives at
 * charra_trusted_keys.h's default path. It is read-only here and written
 * offline by bin/provision_trusted_keys; the one file this Verifier
 * writes that its siblings also read is the shared qualified-RP list
 * below. */

/* Per-round /appraise timings, appended by coap_appraise_handler(). Per
 * port: sibling Verifiers share one working directory and would otherwise
 * interleave into one file. */
static char durations_file_path_buf[64] = {0};
char* durations_file_path = "durations_verifier.txt";

/* Who has qualified. NOT per port -- one file shared by every Verifier, so
 * the RP's single /qualify handshake is honoured by all of them. */
char* qualified_rps_file_path = VERIFIER_QUALIFIED_RPS_DEFAULT_PATH;

/* Default matches the RP's: the /qualify handshake, so an unflagged
 * run behaves exactly as it always has. */
charra_trust_mode verifier_trust_mode = CHARRA_TRUST_MODE_QUALIFY;

/* Key the ZK redaction proof is checked against; --zk-verification-key. */
char* zk_verification_key_path = CHARRA_ZK_VK_DEFAULT;

/* Key this Verifier signs its /appraise verdicts with (see
 * charra_verdict.h). Distinct from the DTLS RPK paths above even though it
 * is the same file today: DTLS is off, and conflating a transport key with
 * an application signing key is how one gets rotated without the other. */
char* verdict_signing_key_path = "keys/verifier.der";

/* Qualification window this Verifier grants, settable with
 * --qualification-validity. Pushed into charra_rp_qualification.c after
 * CLI parsing, which stamps it into the deadline recorded in
 * qualified_rps.txt and echoed to the RP (see that module's header). */
static time_t qualification_validity_seconds =
        CHARRA_RP_QUALIFICATION_VALIDITY_SECONDS;

/**
 * @brief SIGINT handler: set quit to 1 for graceful termination.
 *
 * @param signum the signal number.
 */
static void handle_sigint(int signum);

/* --- main --------------------------------------------------------------- */

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
        .caller = VERIFIER,
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
        .verifier_config = {
            .dtls_psk_identity = &dtls_config.psk_identity,
            .qualification_validity_seconds =
                    &qualification_validity_seconds,
            .trust_mode = &verifier_trust_mode,
            .zk_verification_key_path = &zk_verification_key_path,
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
    charra_zk_set_verification_key_path(zk_verification_key_path);
    coap_set_log_level(coap_log_level);

    /* The shared module is what stamps the qualification challenge's own
     * deadline, so hand it the effective window now that CLI parsing is
     * done. */
    charra_rp_qualification_set_validity_seconds(
            qualification_validity_seconds);

    /* Nothing to provision at startup: this Verifier issues no
     * credentials and holds no CA key. The only file it writes that
     * siblings also read is the shared qualified-RP list, published by
     * rename() rather than edited in place -- see
     * verifier_qualified_rps.h. */

    snprintf(durations_file_path_buf, sizeof(durations_file_path_buf),
            "durations_verifier-%u.txt", port);
    durations_file_path = durations_file_path_buf;

    /* Self-describing log: none of this appears again once startup is done,
     * so a reader coming to the log file cold has no other way to know what
     * the run was configured with -- and the defaults are not visible
     * anywhere at all. */
    charra_log_info("[" LOG_NAME
                    "] ============================================================");
    charra_log_info("[" LOG_NAME "] Verifier starting -- passive CoAP server "
                    "on %s:%u.",
            LISTEN_ADDRESS, port);
    charra_log_info("[" LOG_NAME
                    "] ============================================================");
    charra_log_info("[" LOG_NAME "] Settings for this run -- \"(default)\" "
                    "means the flag was not given; pass it to change the "
                    "value.");
    /* Stated first and in full, because a trust-mode mismatch is the one
     * misconfiguration this design goes out of its way to report, and
     * diagnosing it means comparing what THIS Verifier requires against what
     * the RP sends. The RP announces its own mode the same way. */
    charra_log_info("[" LOG_NAME "] TRUST MODE: %s -- %s.",
            verifier_trust_mode == CHARRA_TRUST_MODE_ZK      ? "ZK"
                    : verifier_trust_mode == CHARRA_TRUST_MODE_TEE ? "TEE"
                                                                   : "QUALIFY",
            verifier_trust_mode == CHARRA_TRUST_MODE_ZK
                    ? "the RP must send a zero-knowledge proof that log_r's "
                      "cleaned paths commit to paths the Attester measured"
            : verifier_trust_mode == CHARRA_TRUST_MODE_TEE
                    ? "the RP must send a TEE Attestation Document naming the "
                      "appraisal code it ran"
                    : "the RP must hold a /qualify grant");
    charra_log_info("[" LOG_NAME
                    "] ============================================================");
    charra_log_info("[" LOG_NAME "]   %-26s %u%s", "--port", port,
            charra_cli_default_tag('b'));
    charra_log_info("[" LOG_NAME "]   %-26s %s%s", "--trust-mode",
            verifier_trust_mode == CHARRA_TRUST_MODE_ZK      ? "zk"
                    : verifier_trust_mode == CHARRA_TRUST_MODE_TEE ? "tee"
                                                                   : "qualify",
            charra_cli_default_tag('6'));
    charra_log_info("[" LOG_NAME "]   %-26s %s%s", "--log-level",
            charra_log_level_to_str(charra_log_level),
            (charra_cli_flag_was_given('l') || charra_cli_flag_was_given('v'))
                    ? ""
                    : " (default)");
    charra_log_info("[" LOG_NAME "]   %-26s %s%s", "DTLS",
            dtls_config.use_psk ? "PSK" : (dtls_config.use_rpk ? "RPK" : "off (plain UDP)"),
            (dtls_config.use_psk || dtls_config.use_rpk) ? "" : " (default)");

    charra_log_info("[" LOG_NAME "]   %-26s '%s'", "trust anchor",
            CHARRA_TRUSTED_KEYS_DEFAULT_PATH);
    /* Only the settings the mode in force actually consults. Printing the
     * qualification window and grant file under --trust-mode=tee or zk
     * invited the reader to think a grant was in play when none is sought. */
    if (verifier_trust_mode == CHARRA_TRUST_MODE_QUALIFY) {
        charra_log_info("[" LOG_NAME "]   %-26s %lds%s",
                "--qualification-validity",
                (long)qualification_validity_seconds,
                charra_cli_default_tag('5'));
        charra_log_info("[" LOG_NAME "]   %-26s '%s' (shared)", "qualified RPs",
                qualified_rps_file_path);
    } else if (verifier_trust_mode == CHARRA_TRUST_MODE_ZK) {
        charra_log_info("[" LOG_NAME "]   %-26s '%s'%s",
                "--zk-verification-key", zk_verification_key_path,
                charra_cli_default_tag('7'));
    }
    charra_log_info("[" LOG_NAME "]   %-26s '%s'", "timings",
            durations_file_path);
    charra_log_info("[" LOG_NAME "] Run with --help for every flag and its "
                    "accepted range.");
    charra_log_info("[" LOG_NAME
                    "] ============================================================");

    charra_log_debug("[" LOG_NAME "] Verifier Configuration:");

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

    /* register CoAP resource and resource handler */
    charra_log_info("[" LOG_NAME "] Registering CoAP resources.");
    charra_coap_add_resource(
            coap_context, COAP_REQUEST_FETCH, "appraise", coap_appraise_handler);
    charra_coap_add_resource(
            coap_context, COAP_REQUEST_FETCH, "nonce", coap_nonce_handler);
    charra_coap_add_resource(
            coap_context, COAP_REQUEST_FETCH, "qualify", coap_qualify_handler);
    charra_coap_add_resource(coap_context, COAP_REQUEST_FETCH,
            "qualify_submit", coap_qualify_submit_handler);

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

static void handle_sigint(int signum CHARRA_UNUSED) { quit = 1; }
