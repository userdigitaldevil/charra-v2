#include <coap3/coap.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <tss2/tss2_tpm2_types.h>

#include "common/charra_log.h"
#include "common/charra_macro.h"
#include "core/charra_rp_qualification.h"
#include "util/cli_util.h"
#include "util/coap_util.h"
#include "util/io_util.h"
#include "verifier/verifier_appraise.h"
#include "verifier/verifier_certify_ak.h"
#include "verifier/verifier_nonce.h"
#include "verifier/verifier_qualify.h"
#include "verifier/verifier_shared.h"

/* --- config ------------------------------------------------------------- */

/* quit signal */
static bool quit = false;

/* logging */
#define LOG_NAME "verifier"
coap_log_t coap_log_level = LOG_INFO;
// #define LOG_LEVEL_CBOR LOG_DEBUG
charra_log_t charra_log_level = CHARRA_LOG_INFO;

/* config */
static const char LISTEN_ADDRESS[] = "0.0.0.0";
static unsigned int port = 31415;

// for DTLS-PSK
bool use_dtls_psk = false;
char* dtls_psk_key = "Charra DTLS Key";
char* dtls_psk_identity = "Charra Verifier";
char* dtls_psk_hint = "Charra Attester";

// for DTLS-RPK
bool use_dtls_rpk = false;
char* dtls_rpk_private_key_path = "keys/verifier.der";
char* dtls_rpk_public_key_path = "keys/verifier.pub.der";
char* dtls_rpk_peer_public_key_path = "keys/relying_party.pub.der";
bool dtls_rpk_verify_peer_public_key = true;

/* config for /certify_ak (Verifier acting as Privacy CA) -- see
 * keys/gen-ak-pki.sh / keys/README.md for what these test-only files are */
char* manufacturer_root_cert_path = "keys/manufacturer-root.crt";
/* Per-port, NOT one CA shared across every `bin/verifier` instance --
 * genuine key material isolation, not just independent ledgers: a
 * compromised or unavailable Verifier's CA no longer affects any other
 * Verifier's ability to issue or validate certificates. Computed once port
 * is known, same mechanism as the two *_ak_state_file_path_buf below. */
static char verifier_ca_cert_path_buf[64] = {0};
char* verifier_ca_cert_path = "keys/verifier-ca.crt";
static char verifier_ca_key_path_buf[64] = {0};
char* verifier_ca_key_path = "keys/verifier-ca.key";
/* AK certificate lifetime, as a duration from issuance rather than a
 * fixed absolute window: with a fixed not_after every certificate this
 * process ever issues would expire at the same instant, so one issued
 * late would live for less time than one issued early. Settable with
 * --ak-validity. Five minutes by default, matching the qualification
 * window: short-lived credentials keep the renewal path exercised on every
 * run instead of lying dormant behind a multi-year default. Must stay
 * comfortably above RP's --ak-renew-margin, or RP re-provisions on every
 * cycle. */
#define CHARRA_AK_CERT_VALIDITY_SECONDS_DEFAULT (5 * 60)
time_t ak_cert_validity_seconds =
        CHARRA_AK_CERT_VALIDITY_SECONDS_DEFAULT;
/* Persisted record of AK certificates issued via /certify_ak -- see
 * charra_ak_state.h. Deliberately per-Verifier, NOT shared across every
 * `bin/verifier` instance start_verifiers.sh spawns, now doubly so since
 * each also signs with its OWN CA key: each Verifier independently
 * certifies (via its own /certify_ak call, see relying_party.c's ensure_rp_ak_
 * certificate()) and independently tracks RP's AK, since Verifiers are
 * meant to be independent (see CHARRA_V2_NOTES.md). This also isn't
 * optional bookkeeping -- charra_ak_state_renew()'s policy revokes any
 * EXISTING record for the same ek_fingerprint before appending the new
 * one, so if every Verifier's issuance shared one ledger, one Verifier
 * certifying RP would immediately revoke every OTHER Verifier's own,
 * separately-issued certificate for the same RP in that shared file.
 * Keyed by this process's own port, same mechanism (and same comment) as
 * qualification_state_file_path below.
 *
 * Two separate ledgers, one per CHARRA_CERTIFY_AK_SUBJECT_* value -- an RP
 * AK and a relayed Attester AK must never be tracked (or revoked) as if
 * they were the same identity kind, even though both currently arrive
 * through this one /certify_ak resource. Live under
 * state/verifier/ak-provisioning/rp/ and .../attester/ respectively --
 * every piece of THIS process's own runtime state lives under
 * state/verifier/, split by purpose, mirroring how relying_party.c
 * organizes its own runtime state under state/relying-party/. */
static char rp_ak_state_file_path_buf[96] = {0};
char* rp_ak_state_file_path =
        "state/verifier/ak-provisioning/rp/rp-ak-provisioning-state.txt";
static char attester_ak_state_file_path_buf[96] = {0};
char* attester_ak_state_file_path = "state/verifier/ak-provisioning/"
                                           "attester/attester-ak-provisioning-state.txt";

/* Persisted, per-RP-identity record of who has passed /qualify +
 * /qualify/submit -- see charra_qualification_state.h. Unlike
 * rp_ak_state_file_path above, ONE FILE SHARED by every `bin/verifier`
 * instance: qualifying with one Verifier qualifies with all of them.
 * Safe because charra_qualification_state_renew() only appends (never
 * revokes-on-write like charra_ak_state_renew()), and ek_fingerprint is
 * already Verifier-agnostic (one RP EK/AK keypair, reused everywhere). */
char* qualification_state_file_path =
        "state/verifier/qualification/rp-qualification-state.txt";

/* Per-round /appraise timings, appended by coap_appraise_handler(). Per
 * port, same reason as the ledgers above: sibling Verifiers share one
 * working directory and would otherwise interleave into one file. */
static char durations_file_path_buf[64] = {0};
char* durations_file_path = "durations_verifier.txt";

/* Qualification window this Verifier grants, settable with
 * --qualification-validity. Pushed into charra_rp_qualification.c after
 * CLI parsing; must match the RP's own flag (see that module's header). */
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
        .verifier_config = {
            .dtls_psk_identity = &dtls_psk_identity,
            .qualification_validity_seconds =
                    &qualification_validity_seconds,
            .ak_cert_validity_seconds = &ak_cert_validity_seconds,
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

    /* The shared module is what actually stamps expires_at into the
     * ledger, so hand it the effective window now that CLI parsing is
     * done. */
    charra_rp_qualification_set_validity_seconds(
            qualification_validity_seconds);

    /* rp_ak_state_file_path/attester_ak_state_file_path are per-port (see
     * their own comments above) -- port is only final once command-line
     * parsing above has run, so this has to happen here, not at
     * static-initialization time (qualification_state_file_path is shared,
     * not per-port, so it needs no such assignment). */

    /* The lock is per-port, matching the ledgers below: two Verifiers on
     * different ports are meant to share state/verifier/, but two on the
     * SAME port are two owners of one issuance ledger, each revoking the
     * other's records. */
    char state_lock_path[80] = {0};
    snprintf(state_lock_path, sizeof(state_lock_path),
            "state/verifier/verifier-%u.lock", port);
    static const char* const state_dirs[] = {
            "state/verifier/ak-provisioning/rp",
            "state/verifier/ak-provisioning/attester",
            "state/verifier/qualification", NULL};
    if (charra_io_claim_state_dir(state_dirs, state_lock_path, "verifier") !=
            CHARRA_RC_SUCCESS) {
        return EXIT_FAILURE;
    }

    snprintf(rp_ak_state_file_path_buf, sizeof(rp_ak_state_file_path_buf),
            "state/verifier/ak-provisioning/rp/rp-ak-provisioning-state-%u."
            "txt",
            port);
    rp_ak_state_file_path = rp_ak_state_file_path_buf;

    snprintf(attester_ak_state_file_path_buf,
            sizeof(attester_ak_state_file_path_buf),
            "state/verifier/ak-provisioning/attester/"
            "attester-ak-provisioning-state-%u.txt",
            port);
    attester_ak_state_file_path = attester_ak_state_file_path_buf;

    /* qualification_state_file_path stays at its shared, non-per-port
     * default (see its own comment) -- no snprintf() here. */

    snprintf(verifier_ca_cert_path_buf, sizeof(verifier_ca_cert_path_buf),
            "keys/verifier-ca-%u.crt", port);
    verifier_ca_cert_path = verifier_ca_cert_path_buf;

    snprintf(verifier_ca_key_path_buf, sizeof(verifier_ca_key_path_buf),
            "keys/verifier-ca-%u.key", port);
    verifier_ca_key_path = verifier_ca_key_path_buf;

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
    charra_log_info("[" LOG_NAME "]   %-26s %u%s", "--port", port,
            charra_cli_default_tag('b'));
    charra_log_info("[" LOG_NAME "]   %-26s %lds%s",
            "--qualification-validity", (long)qualification_validity_seconds,
            charra_cli_default_tag('5'));
    charra_log_info("[" LOG_NAME "]   %-26s %lds%s", "--ak-validity",
            (long)ak_cert_validity_seconds, charra_cli_default_tag('6'));
    charra_log_info("[" LOG_NAME "]   %-26s %s%s", "--log-level",
            charra_log_level_to_str(charra_log_level),
            (charra_cli_flag_was_given('l') || charra_cli_flag_was_given('v'))
                    ? ""
                    : " (default)");
    charra_log_info("[" LOG_NAME "]   %-26s %s%s", "DTLS",
            use_dtls_psk ? "PSK" : (use_dtls_rpk ? "RPK" : "off (plain UDP)"),
            (use_dtls_psk || use_dtls_rpk) ? "" : " (default)");

    /* Warn rather than ignore: these four are parsed and validated but no
     * code reads them, so passing one and seeing nothing happen is exactly
     * how a flag comes to look like it works. */
    {
        const struct {
            int identifier;
            const char* name;
        } unimplemented[] = {{'a', "ip"}, {'f', "pcr-file"},
                {'s', "pcr-selection"}, {'m', "ima"}};
        for (size_t i = 0; i < sizeof(unimplemented) / sizeof(*unimplemented);
                ++i) {
            if (charra_cli_flag_was_given(unimplemented[i].identifier)) {
                charra_log_warn("[" LOG_NAME "]   --%s was given but is NOT "
                                "IMPLEMENTED -- it is parsed and then "
                                "discarded, and changes nothing.",
                        unimplemented[i].name);
            }
        }
    }

    charra_log_info("[" LOG_NAME "]   %-26s '%s'", "RP AK ledger",
            rp_ak_state_file_path);
    charra_log_info("[" LOG_NAME "]   %-26s '%s'", "Attester AK ledger",
            attester_ak_state_file_path);
    charra_log_info("[" LOG_NAME "]   %-26s '%s' (shared)",
            "qualification ledger", qualification_state_file_path);
    charra_log_info("[" LOG_NAME "]   %-26s '%s'", "manufacturer root",
            manufacturer_root_cert_path);
    charra_log_info("[" LOG_NAME "]   %-26s '%s'", "this Verifier's CA",
            verifier_ca_cert_path);
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

    /* register CoAP resource and resource handler */
    charra_log_info("[" LOG_NAME "] Registering CoAP resources.");
    charra_coap_add_resource(
            coap_context, COAP_REQUEST_FETCH, "appraise", coap_appraise_handler);
    charra_coap_add_resource(
            coap_context, COAP_REQUEST_FETCH, "nonce", coap_nonce_handler);
    charra_coap_add_resource(coap_context, COAP_REQUEST_FETCH, "certify_ak",
            coap_certify_ak_handler);
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

static void handle_sigint(int signum CHARRA_UNUSED) { quit = true; }
