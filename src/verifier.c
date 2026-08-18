#include <coap3/coap.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
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
static uint8_t tpm_pcr_selection[TPM2_MAX_PCRS] = {0, 1, 2, 3, 4, 5, 6, 7, 10};
static uint32_t tpm_pcr_selection_len = 9;
char* reference_pcr_file_path = "reference-pcrs.txt";
coap_log_t coap_log_level = LOG_INFO;
// #define LOG_LEVEL_CBOR LOG_DEBUG
charra_log_t charra_log_level = CHARRA_LOG_INFO;

/* config */
static const char LISTEN_ADDRESS[] = "0.0.0.0";
static unsigned int port = 31415;
bool use_ima_event_log = false;
char* ima_event_log_path =
        "/sys/kernel/security/ima/binary_runtime_measurements";

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
    cli_config cli_config = {
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
            // .dst_host = dst_host,
            // .timeout = &attestation_response_timeout,
            .reference_pcr_file_path = &reference_pcr_file_path,
            .tpm_pcr_selection = tpm_pcr_selection,
            .tpm_pcr_selection_len = &tpm_pcr_selection_len,
            .use_ima_event_log = &use_ima_event_log,
            .ima_event_log_path = &ima_event_log_path,
            .dtls_psk_identity = &dtls_psk_identity,
            .qualification_validity_seconds =
                    &qualification_validity_seconds,
            .ak_cert_validity_seconds = &ak_cert_validity_seconds,
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

    /* The shared module is what actually stamps expires_at into the
     * ledger, so hand it the effective window now that CLI parsing is
     * done. */
    charra_rp_qualification_set_validity_seconds(
            qualification_validity_seconds);

    /* rp_ak_state_file_path/attester_ak_state_file_path are per-port (see
     * their own comments above) -- port is only final once command-line
     * parsing above has run, so this has to happen here, not at
     * static-initialization time (qualification_state_file_path is shared,
     * not per-port, so it needs no such assignment). mkdir() the
     * subfolders first: fopen(path, "w") fails outright if any parent
     * directory is missing, and nothing else in this codebase creates them
     * (they're gitignored, runtime-only state, not checked in). Ignore
     * EEXIST -- all are expected to already exist on every run after the
     * first. */
    mkdir("state", 0755);
    mkdir("state/verifier", 0755);
    mkdir("state/verifier/ak-provisioning", 0755);
    mkdir("state/verifier/ak-provisioning/rp", 0755);
    mkdir("state/verifier/ak-provisioning/attester", 0755);
    mkdir("state/verifier/qualification", 0755);

    /* Per-port, matching the ledgers below: two Verifiers on different ports
     * are meant to share state/verifier/, but two on the SAME port are two
     * owners of one issuance ledger, each revoking the other's records. */
    char state_lock_path[80] = {0};
    snprintf(state_lock_path, sizeof(state_lock_path),
            "state/verifier/verifier-%u.lock", port);
    if (charra_io_lock_state_dir(state_lock_path, "verifier") !=
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

    /* Self-describing log: everything below is derived from CLI flags/
     * defaults that never appear again in the log stream once startup is
     * done, so a reader coming to this log file cold has no other way to
     * know, e.g., which state files or CA this run was actually using. */
    charra_log_info("[" LOG_NAME "] Effective configuration: port=%d "
                    "rp_ak_state_file='%s' attester_ak_state_file='%s' "
                    "qualification_state_file='%s' "
                    "manufacturer_root='%s' verifier_ca_cert='%s' "
                    "durations_file='%s'",
            port, rp_ak_state_file_path, attester_ak_state_file_path,
            qualification_state_file_path,
            manufacturer_root_cert_path, verifier_ca_cert_path,
            durations_file_path);

    charra_log_debug("[" LOG_NAME "] Verifier Configuration:");
    charra_log_debug("[" LOG_NAME "]     Used local port: %d", port);
    charra_log_debug("[" LOG_NAME "]     DTLS-PSK enabled: %s",
            (use_dtls_psk == true) ? "true" : "false");
    if (use_dtls_psk) {
        charra_log_debug(
                "[" LOG_NAME "]         Pre-shared key: '%s'", dtls_psk_key);
        charra_log_debug("[" LOG_NAME "]         Hint: '%s'", dtls_psk_hint);
    }
    charra_log_debug("[" LOG_NAME "]     DTLS-RPK enabled: %s",
            (use_dtls_rpk == true) ? "true" : "false");
    if (use_dtls_rpk) {
        charra_log_debug("[" LOG_NAME "]         Private key path: '%s'",
                dtls_rpk_private_key_path);
        charra_log_debug("[" LOG_NAME "]         Public key path: '%s'",
                dtls_rpk_public_key_path);
        charra_log_debug("[" LOG_NAME "]         Peers' public key path: '%s'",
                dtls_rpk_peer_public_key_path);
    }

    /* set varaibles here such that they are valid in case of an 'goto error' */
    coap_context_t* coap_context = NULL;
    coap_endpoint_t* coap_endpoint = NULL;

    if (use_dtls_psk && use_dtls_rpk) {
        charra_log_error(
                "[" LOG_NAME "] Configuration enables both DTSL with PSK "
                "and DTSL with PKI. Aborting!");
        goto error;
    }

    if (use_dtls_psk || use_dtls_rpk) {
        // print TLS version when in debug mode
        coap_show_tls_version(LOG_DEBUG);
    }

    if ((use_dtls_psk || use_dtls_rpk) && !coap_dtls_is_supported()) {
        charra_log_error("[" LOG_NAME "] CoAP does not support DTLS but the "
                         "configuration enables DTLS. Aborting!");
        goto error;
    }

    charra_log_info("[" LOG_NAME "] Initializing CoAP in block-wise mode.");
    if ((coap_context = charra_coap_new_context(true)) == NULL) {
        charra_log_error("[" LOG_NAME "] Cannot create CoAP context.");
        goto error;
    }

    if (use_dtls_psk) {
        charra_log_info(
                "[" LOG_NAME "] Creating CoAP server endpoint using DTLS-PSK.");
        if (!coap_context_set_psk(coap_context, dtls_psk_hint,
                    (uint8_t*)dtls_psk_key, strlen(dtls_psk_key))) {
            charra_log_error("[" LOG_NAME
                             "] Error while configuring CoAP to use DTLS-PSK.");
            goto error;
        }

        if ((coap_endpoint = charra_coap_new_endpoint(coap_context,
                     LISTEN_ADDRESS, port, COAP_PROTO_DTLS)) == NULL) {
            charra_log_error("[" LOG_NAME "] Cannot create CoAP server "
                             "endpoint based on DTLS-PSK.\n");
            goto error;
        }
    } else if (use_dtls_rpk) {
        charra_log_info(
                "[" LOG_NAME "] Creating CoAP server endpoint using DTLS-RPK.");
        coap_dtls_pki_t dtls_pki = {0};

        CHARRA_RC rc = charra_coap_setup_dtls_pki_for_rpk(&dtls_pki,
                dtls_rpk_private_key_path, dtls_rpk_public_key_path,
                dtls_rpk_peer_public_key_path, dtls_rpk_verify_peer_public_key);
        if (rc != CHARRA_RC_SUCCESS) {
            charra_log_error("[" LOG_NAME
                             "] Error while setting up DTLS-RPK structure.");
            goto error;
        }

        if (!coap_context_set_pki(coap_context, &dtls_pki)) {
            charra_log_error("[" LOG_NAME
                             "] Error while configuring CoAP to use DTLS-RPK.");
            goto error;
        }

        if ((coap_endpoint = charra_coap_new_endpoint(coap_context,
                     LISTEN_ADDRESS, port, COAP_PROTO_DTLS)) == NULL) {
            charra_log_error("[" LOG_NAME "] Cannot create CoAP server "
                             "endpoint based on DTLS-RPK.\n");
            goto error;
        }
    } else {
        charra_log_info(
                "[" LOG_NAME "] Creating CoAP server endpoint using UDP.");
        if ((coap_endpoint = charra_coap_new_endpoint(coap_context,
                     LISTEN_ADDRESS, port, COAP_PROTO_UDP)) == NULL) {
            charra_log_error(
                    "[" LOG_NAME
                    "] Cannot create CoAP server endpoint based on UDP.\n");
            goto error;
        }
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

    /* enter main loop */
    charra_log_debug("[" LOG_NAME "] Entering main loop.");
    while (!quit) {
        /* process CoAP I/O */
        if (coap_io_process(coap_context, COAP_IO_WAIT) == -1) {
            charra_log_error(
                    "[" LOG_NAME "] Error during CoAP I/O processing.");
            goto error;
        }
    }
    result = EXIT_SUCCESS;
    goto finish;

error:
    result = EXIT_FAILURE;

finish:
    /* free CoAP memory */
    charra_free_and_null_ex(coap_endpoint, coap_free_endpoint);
    charra_free_and_null_ex(coap_context, coap_free_context);
    coap_cleanup();

    return result;
}

/* --- function definitions ----------------------------------------------- */

static void handle_sigint(int signum CHARRA_UNUSED) { quit = true; }
