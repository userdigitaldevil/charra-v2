#include <arpa/inet.h>
#include <coap3/coap.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <tinydtls/session.h>
#include <tss2/tss2_mu.h>
#include <tss2/tss2_tctildr.h>
#include <tss2/tss2_tpm2_types.h>

#include "common/charra_log.h"
#include "common/charra_macro.h"
#include "core/charra_ak_state.h"
#include "core/charra_dto.h"
#include "core/charra_helper.h"
#include "core/charra_key_mgr.h"
#include "core/charra_marshaling.h"
#include "core/charra_qualification_state.h"
#include "core/charra_rp_qualification.h"
#include "util/cbor_util.h"
#include "util/charra_util.h"
#include "util/cli_util.h"
#include "util/coap_util.h"
#include "util/io_util.h"
#include "util/tpm2_util.h"
#include "util/crypto_util.h"

#define CHARRA_UNUSED __attribute__((unused))

/* --- config ------------------------------------------------------------- */

/* quit signal */
static bool quit = false;
static CHARRA_RC attestation_rc = CHARRA_RC_ERROR;

/* Counts attestation rounds this Verifier process has seen, purely for the
 * log delimiter coap_nonce_handler() prints -- /nonce is always the first
 * request of a new round (RP requests exactly one fresh nonce per cycle
 * per Verifier, before building and sending evidence), so incrementing it
 * there gives an easy-to-scan boundary in this Verifier's own log, the
 * same way relying_party.c's "Starting new attestation run" delimiter
 * does on the RP side. Not shared with or derived from the RP's own
 * num_verifiers/run numbering -- this Verifier has no visibility into
 * that, it only knows how many rounds *it itself* has been asked to
 * participate in. */
static unsigned int attestation_round_counter = 0;

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
#define CBOR_ENCODER_BUFFER_LENGTH 20480       // 20 KiB should be sufficient
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

static msg_attestation_request_dto last_request = {0};

/* The Verifier's OWN freshness challenge for Quote_r, generated fresh by
 * coap_nonce_handler() on every /nonce call -- deliberately separate from
 * last_request.nonce above (the nonce RP gave the ATTESTER, still needed
 * for Quote_a's own freshness check, Step 3b item 3). Quote_r's freshness
 * has to be checked against a value the VERIFIER picked, not one RP picked
 * itself: an RP echoing back its own nonce proves nothing to the Verifier
 * about freshness, since RP could replay an old signature over an old
 * self-chosen nonce it already knows will "match". Same single-in-flight-
 * global limitation as last_request (bug #6 in CHARRA_V2_NOTES.md's
 * verifier.c audit -- deliberately left as is for now, unchanged by this). */
static uint8_t verifier_challenge_nonce[TPM2_SHA256_DIGEST_SIZE] = {0};
static uint32_t verifier_challenge_nonce_len = 0;

/* config for /qualify + /qualify/submit (RP qualification handshake) --
 * see charra_rp_qualification.h. Holds only the CURRENT outstanding
 * challenge's golden answer -- single global, same one-in-flight-round-at-
 * a-time assumption last_request above already makes. The durable verdict
 * ("is EK X currently qualified, until when") is NOT kept here: see
 * qualification_state_file_path below. */
static rp_qualification_state qualification_state = {0};
#define CHARRA_RP_QUALIFICATION_NUM_ENTRIES 5

/* config for /certify_ak (Verifier acting as Privacy CA) -- see
 * keys/gen-ak-pki.sh / keys/README.md for what these test-only files are */
static char* manufacturer_root_cert_path = "keys/manufacturer-root.crt";
/* Per-port, NOT one CA shared across every `bin/verifier` instance --
 * genuine key material isolation, not just independent ledgers: a
 * compromised or unavailable Verifier's CA no longer affects any other
 * Verifier's ability to issue or validate certificates. Computed once port
 * is known, same mechanism as ak_state_file_path_buf below. */
static char verifier_ca_cert_path_buf[64] = {0};
static char* verifier_ca_cert_path = "keys/verifier-ca.crt";
static char verifier_ca_key_path_buf[64] = {0};
static char* verifier_ca_key_path = "keys/verifier-ca.key";
/* AK certificate lifetime, as a duration from issuance rather than a
 * fixed absolute window: with a fixed not_after every certificate this
 * process ever issues would expire at the same instant, so one issued
 * late would live for less time than one issued early. Settable with
 * --ak-validity; the default is the same ~10 years the old hardcoded
 * 2024-2034 window gave. */
#define CHARRA_AK_CERT_VALIDITY_SECONDS_DEFAULT (10L * 365 * 24 * 60 * 60)
static time_t ak_cert_validity_seconds =
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
static char* rp_ak_state_file_path =
        "state/verifier/ak-provisioning/rp/rp-ak-provisioning-state.txt";
static char attester_ak_state_file_path_buf[96] = {0};
static char* attester_ak_state_file_path = "state/verifier/ak-provisioning/"
                                           "attester/attester-ak-provisioning-state.txt";

/* Persisted, per-RP-identity record of who has passed /qualify +
 * /qualify/submit -- see charra_qualification_state.h. Unlike
 * rp_ak_state_file_path above, ONE FILE SHARED by every `bin/verifier`
 * instance: qualifying with one Verifier qualifies with all of them.
 * Safe because charra_qualification_state_renew() only appends (never
 * revokes-on-write like charra_ak_state_renew()), and ek_fingerprint is
 * already Verifier-agnostic (one RP EK/AK keypair, reused everywhere). */
static char* qualification_state_file_path =
        "state/verifier/qualification/rp-qualification-state.txt";

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

static void coap_appraise_handler(struct coap_resource_t* resource,
                                struct coap_session_t* session,
                                const struct coap_pdu_t* request,
                                const struct coap_string_t* query,
                                struct coap_pdu_t* response);
                                
static void coap_nonce_handler(struct coap_resource_t* resource,
                                struct coap_session_t* session,
                                const struct coap_pdu_t* request,
                                const struct coap_string_t* query,
                                struct coap_pdu_t* response);

static void coap_certify_ak_handler(struct coap_resource_t* resource,
                                struct coap_session_t* session,
                                const struct coap_pdu_t* request,
                                const struct coap_string_t* query,
                                struct coap_pdu_t* response);

static void coap_qualify_handler(struct coap_resource_t* resource,
                                struct coap_session_t* session,
                                const struct coap_pdu_t* request,
                                const struct coap_string_t* query,
                                struct coap_pdu_t* response);

static void coap_qualify_submit_handler(struct coap_resource_t* resource,
                                struct coap_session_t* session,
                                const struct coap_pdu_t* request,
                                const struct coap_string_t* query,
                                struct coap_pdu_t* response);

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

    /* Self-describing log: everything below is derived from CLI flags/
     * defaults that never appear again in the log stream once startup is
     * done, so a reader coming to this log file cold has no other way to
     * know, e.g., which state files or CA this run was actually using. */
    charra_log_info("[" LOG_NAME "] Effective configuration: port=%d "
                    "rp_ak_state_file='%s' attester_ak_state_file='%s' "
                    "qualification_state_file='%s' "
                    "manufacturer_root='%s' verifier_ca_cert='%s'",
            port, rp_ak_state_file_path, attester_ak_state_file_path,
            qualification_state_file_path,
            manufacturer_root_cert_path, verifier_ca_cert_path);

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

/**
 * @brief Formats the leading bytes of a buffer as a lowercase hex string,
 * for compact identity fingerprints/serials/nonces inline in log lines --
 * a full 32-byte EK fingerprint or 16-byte AK serial is unwieldy to print
 * in full every time, but a short prefix is still enough to tell two
 * different identities/values apart at a glance across a busy log.
 *
 * @param out_len buffer size in out; at most (out_len - 1) / 2 bytes of buf
 * are rendered, silently truncating anything beyond that. out_len == 0 is
 * a no-op (not an out-of-bounds write): every current call site passes a
 * non-zero literal buffer size, but out_len - 1 would otherwise underflow
 * (it's size_t) into a huge max_bytes and write far past out.
 */
static void hex_prefix(
        const uint8_t* buf, size_t buf_len, char* out, size_t out_len) {
    if (out_len == 0) {
        return;
    }
    size_t max_bytes = (out_len - 1) / 2;
    size_t n = buf_len < max_bytes ? buf_len : max_bytes;
    for (size_t i = 0; i < n; ++i) {
        snprintf(out + (i * 2), 3, "%02x", buf[i]);
    }
    out[n * 2] = '\0';
}

/**
 * @brief Logs the requesting peer's address:port for a CoAP handler --
 * useful once several RPs (or several redundant requests from the same RP)
 * can hit one Verifier, to tell which physical connection a given round's
 * log lines belong to, beyond just the identity fingerprints logged
 * elsewhere.
 */
static void log_peer_address(
        const char* endpoint_name, struct coap_session_t* session) {
    const coap_address_t* remote = coap_session_get_addr_remote(session);
    if (remote == NULL) {
        return;
    }
    unsigned char addr_buf[64] = {0};
    size_t addr_len = coap_print_addr(remote, addr_buf, sizeof(addr_buf) - 1);
    addr_buf[addr_len] = '\0';
    charra_log_info("[" LOG_NAME "] %s: request from %s.", endpoint_name,
            (const char*)addr_buf);
}
static void coap_appraise_handler(struct coap_resource_t* resource,
                                struct coap_session_t* session,
                                const struct coap_pdu_t* request,
                                const struct coap_string_t* query,
                                struct coap_pdu_t* response) {
    int coap_r = 0;
    TSS2_RC tss_r = 0;

    log_peer_address("/appraise", session);

    ESYS_TR sig_key_handle = ESYS_TR_NONE;
    TPMT_TK_VERIFIED* validation = NULL;
    /* Quote_r has no TPM-side key load/verification ticket of its own --
     * it's a software RSA-PSS signature (mbedtls only), checked in Step 3a
     * item 2 below. */
    /* Declared here (rather than right before first use, further down) and
     * initialized to NULL so that every earlier 'goto cleanup' -- including
     * the fopen() failure right below -- leaves cleanup able to safely check
     * them instead of reading indeterminate values. */
    ESYS_CONTEXT* esys_ctx = NULL;
    TSS2_TCTI_CONTEXT* tcti_ctx = NULL;
    /* Trust anchor for Step 3a/3b item 1 (EK_r/AK_r, EK_a/AK_a) -- both AK
     * certificates are checked against the Verifier's own CA, since the
     * Verifier is the sole issuer via /certify_ak. Declared here for the
     * same reason as esys_ctx/tcti_ctx above. */
    char* verifier_ca_cert_der = NULL;
    size_t verifier_ca_cert_der_len = 0;

    FILE * p_file;
    p_file = fopen("durations_verifier.txt", "w");
    // If p_file is a null pointer, the file opening failed.
    if (p_file == NULL) {
        printf("File does not exist!");
        goto cleanup;
    }

    /* --- receive incoming data --- */

    /* get data */
    size_t data_len = 0;
    const uint8_t* data = NULL;
    size_t data_offset = 0;
    size_t data_total_len = 0;
    if ((coap_r = coap_get_data_large(
                 request, &data_len, &data, &data_offset, &data_total_len)) == 0) {
        charra_log_error("[" LOG_NAME "] Could not get CoAP PDU data.");
        attestation_rc = CHARRA_RC_ERROR;
        goto cleanup;
    } else {
        charra_log_info(
                "[" LOG_NAME "] Received evidence of length %zu.", data_len);
        charra_log_info("[" LOG_NAME "] Received evidence of total length %zu.",
                data_total_len);
    }

    clock_t start_appraise, end_appraise;
    double appraise_duration;
    start_appraise = clock();

    /* unmarshal data */
    clock_t start_unmarshal, end_unmarshal;
    double unmarshal_duration;
    start_unmarshal = clock();
    charra_log_info("[" LOG_NAME "] Parsing received CBOR data.");
    /* Quote_a (Attester's evidence, forwarded) + Quote_r (RP's own,
     * software-PCR-replay-based quote, signed by RP's TPM-resident AK) +
     * log_r (RP's redacted log, not Attester's raw one) -- see
     * msg_rp_evidence_dto in charra_dto.h. */
    msg_rp_evidence_dto res = {0};
    if ((attestation_rc = charra_unmarshal_rp_evidence(
                 data_len, data, &res)) != CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Could not parse CBOR data.");
        goto cleanup;
    }
    end_unmarshal = clock();
    unmarshal_duration = ((double) (end_unmarshal - start_unmarshal)) / CLOCKS_PER_SEC;
    fprintf(p_file, "unmarshal evidence took %f seconds to execute \n", unmarshal_duration);
    charra_log_info(
            "[" LOG_NAME "] Parsed evidence: log_r is %u byte(s).",
            res.log_r_len);
    charra_log_info(
            "[" LOG_NAME "] Timing: unmarshal evidence took %f second(s).",
            unmarshal_duration);

    /* verify data */
    /* Checked against sizeof(TPMS_ATTEST), not sizeof(TPM2B_ATTEST): this
     * data is later memcpy'd into attest.attestationData (see below), which
     * is a BYTE[sizeof(TPMS_ATTEST)] sub-field of TPM2B_ATTEST -- smaller
     * than the whole struct by (at least) the leading UINT16 size field.
     * Checking against the larger struct size let a too-long
     * attestation_data_len pass here and then overflow attestationData. */
    if (res.attestation_data_len > sizeof(TPMS_ATTEST)) {
        charra_log_error(
                "[" LOG_NAME
                "] Length of attestation data exceeds maximum allowed size.");
        attestation_rc = CHARRA_RC_ERROR;
        goto cleanup;
    }
    if (res.tpm2_signature_len > sizeof(TPMT_SIGNATURE)) {
        charra_log_error("[" LOG_NAME
                         "] Length of signature exceeds maximum allowed size.");
        attestation_rc = CHARRA_RC_ERROR;
        goto cleanup;
    }
    /* Quote_r's fields -- re-checked here independently of whatever bounds
     * charra_unmarshal_rp_evidence() itself applies, same defense-in-depth
     * style as the rest of this function. */
    if (res.rp_signature_len != CHARRA_RSA_SIGNATURE_LEN) {
        charra_log_error(
                "[" LOG_NAME "] RP signature is not exactly the expected "
                "RSA-2048 signature size.");
        attestation_rc = CHARRA_RC_ERROR;
        goto cleanup;
    }
    if (res.rp_public_key_len == 0 ||
            res.rp_public_key_len > sizeof(res.rp_public_key)) {
        charra_log_error("[" LOG_NAME "] RP public key has an unusable "
                         "length.");
        attestation_rc = CHARRA_RC_ERROR;
        goto cleanup;
    }

    /* --- verify TPM Quote --- */
    charra_log_info("[" LOG_NAME "] Starting verification.");

    clock_t start_init, end_init;
    double init_duration;
    start_init = clock();
    /* initialize ESAPI */
    if ((tss_r = Tss2_TctiLdr_Initialize(getenv("CHARRA_TCTI"), &tcti_ctx)) !=
            TSS2_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Tss2_TctiLdr_Initialize.");
        attestation_rc = CHARRA_RC_ERROR;
        goto cleanup;
    }
    if ((tss_r = Esys_Initialize(&esys_ctx, tcti_ctx, NULL)) !=
            TSS2_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Esys_Initialize.");
        attestation_rc = CHARRA_RC_ERROR;
        goto cleanup;
    }
    end_init = clock();
    init_duration = ((double) (end_init - start_init)) / CLOCKS_PER_SEC;
    fprintf(p_file, "init took %f seconds to execute \n", init_duration);
    charra_log_info("[" LOG_NAME "] Timing: TPM init took %f second(s).",
            init_duration);

    /* Trust anchor for the EK/AK checks below: both EK_r/AK_r (Step 3a item
     * 1) and EK_a/AK_a (Step 3b item 1) are AK certificates issued by this
     * Verifier's own CA via /certify_ak -- the EK certificate itself was
     * already validated once, during that earlier provisioning call, so
     * only the already-issued AK certificate needs checking here, against
     * the same CA coap_certify_ak_handler() signs with. */
    if ((attestation_rc = charra_io_read_file(verifier_ca_cert_path,
                 &verifier_ca_cert_der, &verifier_ca_cert_der_len)) !=
            CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Could not read Verifier CA "
                         "certificate ('%s').",
                verifier_ca_cert_path);
        goto cleanup;
    }

    /* =====================================================================
     * Step 3a -- New Evidence Verification (Evidence_r = Quote_r, log_r,
     * EK_r/AK_r), per the supervisor's DRA-TLS spec. Checked in full before
     * Step 3b below, matching the spec's own ordering ("If the verification
     * is passed, proceed to Step 3b").
     * ===================================================================== */

    /* Step 3a item 1: validate EK_r/AK_r certificate -- checks that RP's AK
     * certificate (obtained via its own earlier /certify_ak call) chains to
     * the Verifier's own CA, and that its embedded key matches
     * rp_public_key, the key that actually signs Quote_r below -- not some
     * other, unrelated key. Uses charra_crypto_verify_cert_public_key_
     * matches_der_key() rather than charra_crypto_verify_ekak_certificate()
     * (used for Step 3b below): rp_public_key travels as plain DER, not a
     * TPM2B_PUBLIC -- see msg_rp_evidence_dto's docstring in charra_dto.h. */
    uint8_t ak_serial_rp[16] = {0};
    bool attestation_result_ekak_rp = false;
    {
        mbedtls_x509_crt ak_cert_rp_leaf;
        CHARRA_RC chain_rc = charra_crypto_verify_x509_cert_chain(
                res.ak_certificate_rp, res.ak_certificate_rp_len,
                (uint8_t*)verifier_ca_cert_der, verifier_ca_cert_der_len,
                &ak_cert_rp_leaf);
        if (chain_rc == CHARRA_RC_SUCCESS) {
            if (ak_cert_rp_leaf.serial.len == 16) {
                memcpy(ak_serial_rp, ak_cert_rp_leaf.serial.p, 16);
            }
            attestation_result_ekak_rp =
                    charra_crypto_verify_cert_public_key_matches_der_key(
                            &ak_cert_rp_leaf, res.rp_public_key,
                            res.rp_public_key_len) == CHARRA_RC_SUCCESS;
            if (attestation_result_ekak_rp) {
                charra_crypto_log_cert_summary(
                        "RP's AK cert", &ak_cert_rp_leaf);
            }
            mbedtls_x509_crt_free(&ak_cert_rp_leaf);
        }
    }
    uint8_t ek_fingerprint_rp[32] = {0};
    if (attestation_result_ekak_rp) {
        char ak_serial_rp_hex[33] = {0};
        hex_prefix(ak_serial_rp, sizeof(ak_serial_rp), ak_serial_rp_hex,
                sizeof(ak_serial_rp_hex));
        charra_log_info(
                "[" LOG_NAME "]     => RP's AK certificate is valid! "
                "(serial %s...)",
                ak_serial_rp_hex);
        time_t ak_cert_expires_at_rp = 0;
        attestation_result_ekak_rp = charra_ak_state_check_serial_valid(
                rp_ak_state_file_path, ak_serial_rp, ek_fingerprint_rp,
                &ak_cert_expires_at_rp);
        if (attestation_result_ekak_rp) {
            char ek_fingerprint_rp_hex[17] = {0};
            hex_prefix(ek_fingerprint_rp, sizeof(ek_fingerprint_rp),
                    ek_fingerprint_rp_hex, sizeof(ek_fingerprint_rp_hex));
            charra_log_info(
                    "[" LOG_NAME "]     => RP identity %s...: AK certificate "
                    "is currently valid (expires at %ld, in %ld second(s)).",
                    ek_fingerprint_rp_hex, (long)ak_cert_expires_at_rp,
                    (long)(ak_cert_expires_at_rp - time(NULL)));
        }
    } else {
        charra_log_error("[" LOG_NAME "]     => RP's AK certificate did NOT "
                         "verify (chain or key mismatch)!");
    }

    /* Step 3a item 1b: RP qualification -- has THIS specific RP (identified
     * by ek_fingerprint_rp above, the same identity charra_ak_state.h
     * already tracks) passed /qualify + /qualify/submit within the last
     * CHARRA_RP_QUALIFICATION_VALIDITY_SECONDS? Only meaningful once the AK
     * certificate itself checked out -- ek_fingerprint_rp is only valid
     * when attestation_result_ekak_rp is true. Looked up in the
     * qualification ledger (qualification_state_file_path), shared with
     * every sibling Verifier instance -- see that variable's comment. */
    bool attestation_result_qualified = false;
    /* Distinguishes "never qualified" from "qualified once, but that record
     * has since expired" -- both leave attestation_result_qualified false,
     * but the RP's correct next step is the same either way (redo /qualify),
     * and telling it which case this is (see the response message chain
     * below) saves it from having to guess. */
    bool qualification_record_found = false;
    time_t qualification_expires_at = 0;
    if (attestation_result_ekak_rp) {
        charra_qualification_state_record* qual_records = NULL;
        uint32_t qual_count = 0;
        if (charra_qualification_state_load(qualification_state_file_path,
                    &qual_records, &qual_count) == CHARRA_RC_SUCCESS) {
            uint32_t qual_index = 0;
            if (charra_qualification_state_find_by_ek_fingerprint(
                        qual_records, qual_count, ek_fingerprint_rp,
                        &qual_index)) {
                qualification_record_found = true;
                qualification_expires_at = qual_records[qual_index].expires_at;
                attestation_result_qualified =
                        charra_qualification_state_is_valid(
                                &qual_records[qual_index], time(NULL));
            }
            free(qual_records);
        } else {
            charra_log_error(
                    "[" LOG_NAME "] Could not load qualification state.");
        }
        char ek_fingerprint_rp_hex[17] = {0};
        hex_prefix(ek_fingerprint_rp, sizeof(ek_fingerprint_rp),
                ek_fingerprint_rp_hex, sizeof(ek_fingerprint_rp_hex));
        if (attestation_result_qualified) {
            charra_log_info(
                    "[" LOG_NAME "]     => RP %s... is currently qualified "
                    "(expires at %ld, in %ld second(s)).",
                    ek_fingerprint_rp_hex, (long)qualification_expires_at,
                    (long)(qualification_expires_at - time(NULL)));
        } else if (qualification_record_found) {
            charra_log_error(
                    "[" LOG_NAME "]     => RP %s...'s qualification has "
                    "EXPIRED (was valid until %ld)!",
                    ek_fingerprint_rp_hex, (long)qualification_expires_at);
        } else {
            charra_log_error(
                    "[" LOG_NAME "]     => RP %s... is NOT currently "
                    "qualified (no passing /qualify/submit on record for "
                    "this identity)!",
                    ek_fingerprint_rp_hex);
        }
    }

    /* Step 3a item 2: verify Quote_r signature -- RSA-PSS/SHA-256 over
     * (PCR_r || verifier_nonce) under RP's AK public key (rp_public_key,
     * DER-encoded), NOT a TPM quote verification: PCR_r itself is a
     * software replay of log_r, not TPM-generated, so there is no
     * TPMT_SIGNATURE/TPM2B_ATTEST to check here -- see msg_rp_evidence_dto's
     * docstring in charra_dto.h. */
    clock_t start_verifiy_signature, end_verifiy_signature;
    double verify_signature_duration;
    start_verifiy_signature = clock();

    mbedtls_pk_context rp_pub_key_ctx;
    mbedtls_pk_init(&rp_pub_key_ctx);
    bool attestation_result_signature_rp = false;
    if (mbedtls_pk_parse_public_key(&rp_pub_key_ctx, res.rp_public_key,
                res.rp_public_key_len) != 0) {
        charra_log_error(
                "[" LOG_NAME "]     => Could not parse RP's public key!");
    } else if (mbedtls_pk_get_type(&rp_pub_key_ctx) != MBEDTLS_PK_RSA) {
        charra_log_error(
                "[" LOG_NAME "]     => RP's public key is not RSA!");
    } else if (mbedtls_rsa_set_padding(mbedtls_pk_rsa(rp_pub_key_ctx),
                       MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA256) != 0) {
        charra_log_error(
                "[" LOG_NAME "]     => Could not select RSA-PSS padding!");
    } else {
        uint8_t signed_data[sizeof(res.pcr_r) + sizeof(res.verifier_nonce)] =
                {0};
        memcpy(signed_data, res.pcr_r, sizeof(res.pcr_r));
        memcpy(signed_data + sizeof(res.pcr_r), res.verifier_nonce,
                res.verifier_nonce_len);
        attestation_result_signature_rp =
                charra_crypto_rsa_verify_signature(
                        mbedtls_pk_rsa(rp_pub_key_ctx), MBEDTLS_MD_SHA256,
                        signed_data, sizeof(res.pcr_r) + res.verifier_nonce_len,
                        res.rp_signature) == CHARRA_RC_SUCCESS;
    }
    mbedtls_pk_free(&rp_pub_key_ctx);
    if (attestation_result_signature_rp) {
        charra_log_info("[" LOG_NAME "]     => Quote_r signature is valid!");
    } else {
        charra_log_error(
                "[" LOG_NAME "]     => Quote_r signature is NOT valid!");
    }
    end_verifiy_signature = clock();
    verify_signature_duration = ((double) (end_verifiy_signature - start_verifiy_signature)) / CLOCKS_PER_SEC;
    fprintf(p_file, "verify signature took %f seconds to execute \n", verify_signature_duration);
    charra_log_info(
            "[" LOG_NAME "] Timing: verify Quote_r signature took %f "
            "second(s).",
            verify_signature_duration);

    /* log_r content verification (self-consistency, PCR replay, file-hash
     * policy) is NOT done here -- it is the RP App's own Step 2a
     * local-verification gate, run against the log it receives from the
     * Attester, before cleansing. See verify_log_entries_self_consistent(),
     * verify_log_matches_quote_r_pcr() and
     * verify_log_file_hashes_against_policy() in charra_event_log.h. */

    /* Step 3a item 3: check nonce consistency -- Quote_r's verifier_nonce
     * must be exactly the challenge this Verifier itself generated and
     * handed out in coap_nonce_handler() (verifier_challenge_nonce, a
     * genuine Verifier-picked value, not something RP merely echoed back
     * -- see that global's own comment for why the distinction matters). A
     * plain byte-compare proves freshness, same reasoning the old
     * TPM-quote-qualifying-data check used, just without a TPM structure to
     * unwrap. (verifier_challenge_nonce is a single-in-flight global, same
     * known cross-session-fragility class as last_request -- bug #6 in
     * CHARRA_V2_NOTES.md's verifier.c audit, deliberately left as is for
     * now.) */
    clock_t start_verifiy_nonce, end_verifiy_nonce;
    double verify_nonce_duration;
    start_verifiy_nonce = clock();
    bool attestation_result_nonce_rp = false;
    {
        charra_log_info("[" LOG_NAME "] Verifying RP nonce ...");
        attestation_result_nonce_rp =
                res.verifier_nonce_len == verifier_challenge_nonce_len &&
                memcmp(res.verifier_nonce, verifier_challenge_nonce,
                        verifier_challenge_nonce_len) == 0;
        if (attestation_result_nonce_rp == true) {
            charra_log_info("[" LOG_NAME "]     => Nonce in Quote_r is "
                            "valid! (matches the one sent)");
        } else {
            char expected_nonce_hex[17] = {0};
            char received_nonce_hex[17] = {0};
            hex_prefix(verifier_challenge_nonce, verifier_challenge_nonce_len,
                    expected_nonce_hex, sizeof(expected_nonce_hex));
            hex_prefix(res.verifier_nonce, res.verifier_nonce_len,
                    received_nonce_hex, sizeof(received_nonce_hex));
            charra_log_error("[" LOG_NAME
                             "]     => Nonce in Quote_r is NOT valid! (does "
                             "not match the one sent)");
            charra_log_error(
                    "[" LOG_NAME "]     => expected %u byte(s), starting "
                    "%s...; received %u byte(s), starting %s...",
                    verifier_challenge_nonce_len, expected_nonce_hex,
                    res.verifier_nonce_len, received_nonce_hex);
        }
    }
    end_verifiy_nonce = clock();
    verify_nonce_duration = ((double) (end_verifiy_nonce - start_verifiy_nonce)) / CLOCKS_PER_SEC;
    fprintf(p_file, "verify nonce took %f seconds to execute \n", verify_nonce_duration);
    charra_log_info(
            "[" LOG_NAME "] Timing: verify RP nonce took %f second(s).",
            verify_nonce_duration);

    /* Quote_r has no mbedtls-vs-TPM double-check the way Quote_a's TPM
     * quote does (both a TPM-side and an mbedtls-side signature check
     * running and being ANDed together) -- there is no TPM-side quote
     * verification available for a software PCR replay, only the mbedtls
     * RSA-PSS check above. */
    bool attestation_result_signature_rp_mbedtls = attestation_result_signature_rp;

    /* Step 3a gate: "If the verification is passed, proceed to Step 3b.
     * Otherwise, send a negative proof result to the relying party." A
     * failure anywhere in Step 3a skips Step 3b entirely -- Quote_a is not
     * even looked at, matching the spec's early-exit wording exactly
     * (previously all six checks ran unconditionally and were only ANDed
     * together at the end; that no longer matches the spec's text). */
    bool step_3a_passed = attestation_result_ekak_rp &&
                          attestation_result_signature_rp &&
                          attestation_result_signature_rp_mbedtls &&
                          attestation_result_nonce_rp;

    bool attestation_result_ekak = false;
    bool attestation_result_signature = false;
    bool attestation_result_signature_mbedtls = false;
    bool attestation_result_nonce = false;

    if (!step_3a_passed) {
        charra_log_error("[" LOG_NAME "] Step 3a FAILED -- skipping Step 3b "
                         "(Quote_a is not checked; negative result below).");
    } else {
        charra_log_info(
                "[" LOG_NAME "] Step 3a passed, proceeding to Step 3b ...");

        /* =================================================================
         * Step 3b -- Original Evidence Verification (Evidence_a' =
         * Quote_a, EK_a/AK_a; log_a itself is never forwarded to the
         * Verifier).
         * ================================================================= */

        /* Step 3b item 1: validate EK_a/AK_a certificate -- same check as
         * Step 3a item 1 above, against the Attester's AK certificate
         * (obtained via its own earlier /certify_ak call, forwarded here by
         * RP) and the key that actually signed Quote_a. */
        uint8_t ak_serial[16] = {0};
        if (res.ak_certificate_attester_by_verifier_len == 0) {
            charra_log_error(
                    "[" LOG_NAME "]     => Attester's AK certificate is "
                    "EMPTY -- the Attester has not completed "
                    "/certify_ak_of_attester's DELIVER_VERIFIER leg yet.");
            attestation_result_ekak = false;
        } else {
            /* Chain check, then the revocation check below. The ledger
             * lookup used to be skipped here because the Attester was
             * certified by a single relayed Verifier, so every other
             * Verifier's ledger had no record of it and the lookup would
             * fail spuriously. That premise is gone: each Verifier now
             * certifies the Attester under its own CA and records the
             * issuance in its own attester/ ledger, so the Verifier
             * appraising this evidence always has its own record of the
             * serial it is looking at. */
            attestation_result_ekak = charra_crypto_verify_ekak_certificate(
                    res.ak_certificate_attester_by_verifier,
                    res.ak_certificate_attester_by_verifier_len,
                    (uint8_t*)verifier_ca_cert_der, verifier_ca_cert_der_len,
                    (TPM2B_PUBLIC*)res.tpm2_public_key, ak_serial) ==
                    CHARRA_RC_SUCCESS;
            if (attestation_result_ekak) {
                char ak_serial_hex[33] = {0};
                hex_prefix(ak_serial, sizeof(ak_serial), ak_serial_hex,
                        sizeof(ak_serial_hex));
                /* Chain validity alone cannot see a certificate that was
                 * superseded by a later renewal for the same EK -- only the
                 * issuance ledger knows that. Same check Step 3a item 1
                 * already runs for the RP's own certificate. */
                time_t attester_cert_expires_at = 0;
                attestation_result_ekak = charra_ak_state_check_serial_valid(
                        attester_ak_state_file_path, ak_serial, NULL,
                        &attester_cert_expires_at);
                if (attestation_result_ekak) {
                    charra_log_info(
                            "[" LOG_NAME "]     => Attester's AK certificate "
                            "is valid! (serial %s..., expires at %ld, in %ld "
                            "second(s))",
                            ak_serial_hex, (long)attester_cert_expires_at,
                            (long)(attester_cert_expires_at - time(NULL)));
                } else {
                    charra_log_error(
                            "[" LOG_NAME "]     => Attester's AK certificate "
                            "(serial %s...) chains correctly but is REVOKED "
                            "or EXPIRED in this Verifier's issuance ledger!",
                            ak_serial_hex);
                }
            } else {
                charra_log_error(
                        "[" LOG_NAME "]     => Attester's AK certificate "
                        "did NOT verify (chain or key mismatch)!");
            }
        }

        /* Step 3b item 2: verify Quote_a signature */
        TPM2B_PUBLIC* tpm2_public_key = (TPM2B_PUBLIC*)res.tpm2_public_key;
        charra_log_info("[" LOG_NAME "] Loading TPM key.");
        if ((attestation_rc = charra_load_external_public_key(esys_ctx,
                     tpm2_public_key, &sig_key_handle)) != CHARRA_RC_SUCCESS) {
            charra_log_error(
                    "[" LOG_NAME "] Loading external public key failed.");
            goto cleanup;
        } else {
            charra_log_info("[" LOG_NAME "] External public key loaded.");
        }

        charra_log_info("[" LOG_NAME "] Preparing TPM Quote verification.");
        TPM2B_ATTEST attest = {0};
        attest.size = res.attestation_data_len;
        memcpy(attest.attestationData, res.attestation_data,
                res.attestation_data_len);
        TPMT_SIGNATURE signature = {0};
        memcpy(&signature, res.tpm2_signature, res.tpm2_signature_len);

        attestation_result_signature =
                charra_verify_tpm2_quote_signature_with_tpm_logged(esys_ctx,
                        sig_key_handle, &attest, &signature, &validation);
        if (!charra_crypto_verify_quote_signature_mbedtls(tpm2_public_key,
                    res.attestation_data, res.attestation_data_len,
                    &signature, &attestation_result_signature_mbedtls)) {
            goto cleanup;
        }

        /* unmarshal Quote_a's attestation data -- needed for its nonce
         * check right below */
        TPMS_ATTEST attest_struct = {0};
        attestation_rc = charra_unmarshal_tpm2_quote(res.attestation_data_len,
                res.attestation_data, &attest_struct);
        if (attestation_rc != CHARRA_RC_SUCCESS) {
            charra_log_error(
                    "[" LOG_NAME "] Error while unmarshaling TPM2 Quote.");
            goto cleanup;
        }

        /* Step 3b item 3: check nonce consistency */
        charra_log_info("[" LOG_NAME "] Verifying nonce ...");
        attestation_result_nonce = charra_verify_tpm2_quote_qualifying_data(
                last_request.nonce_len, last_request.nonce, &attest_struct);
        if (attestation_result_nonce == true) {
            charra_log_info("[" LOG_NAME "]     => Nonce in TPM Quote is "
                            "valid! (matches the one sent)");
        } else {
            char expected_nonce_hex[17] = {0};
            char received_nonce_hex[17] = {0};
            hex_prefix(last_request.nonce, last_request.nonce_len,
                    expected_nonce_hex, sizeof(expected_nonce_hex));
            hex_prefix(attest_struct.extraData.buffer,
                    attest_struct.extraData.size, received_nonce_hex,
                    sizeof(received_nonce_hex));
            charra_log_error("[" LOG_NAME
                             "]     => Nonce in TPM Quote is NOT valid! (does "
                             "not match the one sent)");
            charra_log_error(
                    "[" LOG_NAME "]     => expected %zu byte(s), starting "
                    "%s...; received %u byte(s), starting %s...",
                    last_request.nonce_len, expected_nonce_hex,
                    attest_struct.extraData.size, received_nonce_hex);
        }
    }

    /* --- output result --- */
    /* Order matches Step 3a then Step 3b, RP's evidence before Attester's.
     * Equivalent to step_3a_passed && (Step 3b's four results), since
     * Step 3b's results default to false whenever it was skipped. */

    bool attestation_result = attestation_result_ekak_rp &&
                              attestation_result_qualified &&
                              attestation_result_signature_rp &&
                              attestation_result_signature_rp_mbedtls &&
                              attestation_result_nonce_rp &&
                              attestation_result_ekak &&
                              attestation_result_signature &&
                              attestation_result_signature_mbedtls &&
                              attestation_result_nonce;


    char ek_fingerprint_rp_hex_result[17] = {0};
    hex_prefix(ek_fingerprint_rp, sizeof(ek_fingerprint_rp),
            ek_fingerprint_rp_hex_result, sizeof(ek_fingerprint_rp_hex_result));

    const char* message;
    coap_pdu_code_t response_code = COAP_RESPONSE_CODE_CONTENT;
    /* print attestation result */
    charra_log_info("[" LOG_NAME "] +----------------------------+");
    charra_log_info("[" LOG_NAME "]   RP identity: %s...",
            attestation_result_ekak_rp ? ek_fingerprint_rp_hex_result
                                       : "(unknown -- AK cert rejected)");
    if (attestation_result) {
        attestation_rc = CHARRA_RC_SUCCESS;
        message = "Attestation successful!\0";
        charra_log_info("[" LOG_NAME "] |   ATTESTATION SUCCESSFUL   |");
    } else if (!attestation_result_ekak_rp) {
        /* Distinct from any other appraisal failure: RP's OWN AK
         * certificate (Step 3a item 1) failed to chain-verify, or chained
         * fine but is expired/revoked (charra_ak_state_check_serial_valid()).
         * Signalled with 4.01 Unauthorized -- the same code /certify_ak
         * itself already uses for a bad EK certificate -- so RP can tell
         * "go redo /certify_ak and retry" apart from "your evidence itself
         * didn't check out," which a blind retry can never fix. */
        attestation_rc = CHARRA_RC_VERIFICATION_FAILED;
        message = "RP AK certificate invalid or expired!\0";
        response_code = COAP_RESPONSE_CODE_UNAUTHORIZED;
        charra_log_info("[" LOG_NAME "] |  RP AK CERTIFICATE REJECTED  |");
    } else if (!attestation_result_qualified) {
        /* Also distinct: the RP's AK certificate itself is fine, but this
         * specific identity hasn't passed /qualify + /qualify/submit
         * against THIS Verifier recently (see charra_qualification_
         * state.h). Deliberately 4.03 Forbidden, not 4.01 -- RP's retry
         * logic treats 4.01 as "go redo /certify_ak", which would be the
         * wrong reaction here; the fix is redoing /qualify, not AK
         * reprovisioning. Same response code either way (both mean "not
         * currently qualified, go fix that"), but the message text tells
         * RP which case it is -- "expired" specifically means it WAS
         * qualified and should just redo /qualify, not that something is
         * fundamentally wrong with its identity. */
        attestation_rc = CHARRA_RC_VERIFICATION_FAILED;
        response_code = COAP_RESPONSE_CODE_FORBIDDEN;
        if (qualification_record_found) {
            message = "RP qualification expired!\0";
            charra_log_info("[" LOG_NAME "] |  RP QUALIFICATION EXPIRED  |");
        } else {
            message = "RP not qualified!\0";
            charra_log_info("[" LOG_NAME "] |     RP NOT QUALIFIED       |");
        }
    } else {
        attestation_rc = CHARRA_RC_VERIFICATION_FAILED;
        message = "Attestation failed!    \0";
        charra_log_info("[" LOG_NAME "] |     ATTESTATION FAILED     |");
    }
    charra_log_info("[" LOG_NAME "] +----------------------------+");

    coap_pdu_set_code(response, response_code);
    
    end_appraise = clock();
    appraise_duration = ((double) (end_appraise - start_appraise)) / CLOCKS_PER_SEC;


    fprintf(p_file, "appraising took %f seconds to execute \n", appraise_duration);
    double total_measured = unmarshal_duration + init_duration + verify_nonce_duration + verify_signature_duration;
    fprintf(p_file, "total measured %f  \n", total_measured);
    charra_log_info(
            "[" LOG_NAME "] Timing: total /appraise handling took %f "
            "second(s) (%f second(s) measured across sub-phases).",
            appraise_duration, total_measured);

    if ((coap_r = coap_add_data_large_response(resource, session, request, response,
                query, COAP_MEDIATYPE_TEXT_PLAIN, -1, 0,
                strlen(message), (const uint8_t *)message, NULL, (void *)strlen(message))) == 0) {
        charra_log_error("[" LOG_NAME
                         "] Error invoking coap_add_data_large_response().");
        //goto error;
    }
cleanup:
    /* close duration log file -- every path through this function reaches
     * here exactly once, so this is the only fclose() needed */
    if (p_file != NULL) {
        fclose(p_file);
    }

    /* flush handles */
    if (sig_key_handle != ESYS_TR_NONE) {
        if (Esys_FlushContext(esys_ctx, sig_key_handle) != TSS2_RC_SUCCESS) {
            charra_log_error(
                    "[" LOG_NAME "] TSS cleanup sig_key_handle failed.");
        }
    }
    /* log_r, ak_certificate and ak_certificate_rp are NOT freed here:
     * charra_unmarshal_rp_evidence() points them straight into the CoAP
     * request buffer (the same borrowed-pointer convention msg_rp_evidence_dto
     * uses throughout, see charra_dto.h) rather than heap-allocating a
     * fresh copy -- freeing them here would free memory this handler never
     * owned. (An earlier DTO this handler used, since deleted, did
     * heap-allocate these fields and free them here; that is no longer the
     * wire format in use.) */

    /* free ESAPI objects */
    if (validation != NULL) {
        Esys_Free(validation);
    }

    /* finalize ESAPI & TCTI */
    if (esys_ctx != NULL) {
        Esys_Finalize(&esys_ctx);
    }
    if (tcti_ctx != NULL) {
        Tss2_TctiLdr_Finalize(&tcti_ctx);
    }

    /* free the Verifier CA certificate buffer read for Step 3a/3b item 1 */
    charra_io_free_file_buffer(&verifier_ca_cert_der);
}

static void coap_nonce_handler(struct coap_resource_t* resource,
                                struct coap_session_t* session,
                                const struct coap_pdu_t* request,
                                const struct coap_string_t* query,
                                struct coap_pdu_t* response) {
    CHARRA_RC charra_r = CHARRA_RC_SUCCESS;
    int coap_r = 0;

    /* Clear delimiter between attestation rounds -- without this, a busy
     * Verifier's log (interleaved /certify_ak, /qualify, /qualify_submit,
     * /appraise handling across many rounds) has no visible boundary
     * between one round's requests and the next. /nonce is the best
     * available anchor for "a new round started": on every round after the
     * first with a given RP identity, it genuinely IS the first request
     * (RP's AK certificate and qualification are both cached by then, so
     * neither /certify_ak nor /qualify/qualify_submit get called at all
     * that round -- see relying_party.c's rp_perform_qualification_
     * handshake()). Only on an RP's very first round with this Verifier
     * does the delimiter print a little late, after /certify_ak and
     * /qualify already ran -- acceptable since that round is already
     * self-evidently distinctive in the log (EK/AK certification and
     * qualification-challenge lines that never repeat afterward). Mirrors
     * relying_party.c's own "Starting new attestation run" delimiter. */
    attestation_round_counter++;
    charra_log_info("[" LOG_NAME
                    "] ============================================================");
    charra_log_info(
            "[" LOG_NAME "] Starting attestation round #%u.",
            attestation_round_counter);
    charra_log_info("[" LOG_NAME
                    "] ============================================================");
    log_peer_address("/nonce", session);

    /* --- receive incoming data --- */
    coap_show_pdu(LOG_DEBUG, request);

    /* get data */
    size_t data_len = 0;
    const uint8_t* data = NULL;
    size_t data_offset = 0;
    size_t data_total_len = 0;
    if ((coap_r = coap_get_data_large(
                 request, &data_len, &data, &data_offset, &data_total_len)) == 0) {
        charra_log_error("[" LOG_NAME "] Could not get CoAP PDU data.");
        goto error;
    } else {
        charra_log_info(
                "[" LOG_NAME "] Received nonce of length %zu.", data_len);
        charra_log_info("[" LOG_NAME "] Received nonce of total length %zu.",
                data_total_len);
    }

    /* unmarshal data */
    charra_log_info("[" LOG_NAME "] Parsing received CBOR data.");
    msg_attestation_request_dto req = {0};
    if ((charra_r = charra_unmarshal_attestation_request(
                 data_len, data, &req)) != CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Could not parse CBOR data.");
        goto error;
    }

    /* nonce RP gave the Attester -- kept in last_request for Quote_a's own
     * freshness check (Step 3b item 3); NOT used for Quote_r's, see
     * verifier_challenge_nonce's own comment above. */
    if (req.nonce_len > sizeof(TPMU_HA)) {
        charra_log_error("[" LOG_NAME "] Nonce too long.");
        goto error;
    }
    last_request = req;

    /* Generate the Verifier's own freshness challenge and send THAT back as
     * this response's body -- not req.nonce. A challenge RP picked itself
     * and merely echoed back would prove nothing about freshness from the
     * Verifier's side (RP could replay an old Quote_r over a nonce it
     * already knows will "match"); the challenger has to pick the value.
     * RP's coap_verifier_handler_nonce() stores whatever comes back here as
     * verifier_nonce and signs it into Quote_r, which Step 3a item 3 below
     * then checks against verifier_challenge_nonce. Without a response
     * body at all, RP's client-side nonce wait loop fails every time
     * ("Verifier returned no nonce") -- this handler previously never sent
     * one, before it was fixed to (at the time) echo req.nonce. */
    if ((charra_r = charra_random_bytes(sizeof(verifier_challenge_nonce),
                 verifier_challenge_nonce)) != CHARRA_RC_SUCCESS) {
        charra_log_error(
                "[" LOG_NAME "] Could not generate a random nonce.");
        goto error;
    }
    verifier_challenge_nonce_len = sizeof(verifier_challenge_nonce);

    if ((coap_r = coap_add_data_large_response(resource, session, request,
                 response, query, COAP_MEDIATYPE_APPLICATION_OCTET_STREAM, -1,
                 0, verifier_challenge_nonce_len, verifier_challenge_nonce,
                 NULL, NULL)) == 0) {
        charra_log_error("[" LOG_NAME "] /nonce: Error invoking "
                         "coap_add_data_large_response().");
        goto error;
    }
    coap_pdu_set_code(response, COAP_RESPONSE_CODE_CONTENT);
    return;

error:
    coap_pdu_set_code(response, COAP_RESPONSE_CODE_BAD_REQUEST);
    return;
}

static void release_response_data(
        struct coap_session_t* session CHARRA_UNUSED, void* app_ptr) {
    charra_free_and_null(app_ptr);
}

/* --- /certify_ak pending challenges -------------------------------------
 *
 * What CHALLENGE handed out and CONFIRM must match. Kept in memory only:
 * a handshake spans seconds, and a Verifier restart mid-flight just makes
 * the requester retry. Small table rather than one slot because the RP's
 * own handshake and one relayed for the Attester can overlap. */
#define CERTIFY_AK_MAX_PENDING 8
#define CERTIFY_AK_PENDING_TTL_SECONDS 60

typedef struct {
    bool in_use;
    uint8_t ek_fingerprint[32];
    uint8_t secret[CHARRA_CERTIFY_AK_SECRET_LEN];
    /* The key/name bound into this challenge. CONFIRM certifies THESE, not
     * anything it re-supplies, so a leaked secret can't be redirected. */
    uint32_t ak_public_key_len;
    uint8_t ak_public_key[sizeof(TPM2B_PUBLIC)];
    uint32_t ak_name_len;
    uint8_t ak_name[sizeof(TPM2B_NAME)];
    /* CHARRA_CERTIFY_AK_SUBJECT_* -- which ledger CONFIRM records the
     * issuance in, bound at CHALLENGE time for the same reason as the key/
     * name above: CONFIRM re-sending a different subject can't redirect a
     * proven RP identity into the Attester's ledger or vice versa. */
    uint32_t subject;
    time_t expires_at;
} certify_ak_pending_challenge;

static certify_ak_pending_challenge
        certify_ak_pending[CERTIFY_AK_MAX_PENDING] = {0};

/** Maps a CHARRA_CERTIFY_AK_SUBJECT_* value to its ledger path. Returns NULL
 * for anything else -- callers must reject the request in that case rather
 * than guess which ledger was meant. */
static const char* certify_ak_state_path_for_subject(uint32_t subject) {
    switch (subject) {
    case CHARRA_CERTIFY_AK_SUBJECT_RP:
        return rp_ak_state_file_path;
    case CHARRA_CERTIFY_AK_SUBJECT_ATTESTER:
        return attester_ak_state_file_path;
    default:
        return NULL;
    }
}

/** Human-readable subject name for log lines -- shares the same switch as
 * certify_ak_state_path_for_subject() above so a new subject can't be added
 * to one without the other being noticed. */
static const char* certify_ak_subject_name(uint32_t subject) {
    switch (subject) {
    case CHARRA_CERTIFY_AK_SUBJECT_RP:
        return "RP";
    case CHARRA_CERTIFY_AK_SUBJECT_ATTESTER:
        return "Attester (relayed)";
    default:
        return "unknown";
    }
}

/** Constant-time equality -- the secret is a shared authenticator, so its
 * comparison must not leak how far it matched. */
static bool constant_time_equal(
        const uint8_t* a, const uint8_t* b, size_t len) {
    uint8_t diff = 0;
    for (size_t i = 0; i < len; i++) {
        diff |= (uint8_t)(a[i] ^ b[i]);
    }
    return diff == 0;
}

/** Stores a challenge, replacing any prior one for the same identity (a
 * fresh CHALLENGE abandons whatever the requester didn't finish). */
static void certify_ak_pending_store(
        const certify_ak_pending_challenge* challenge) {
    time_t now = time(NULL);
    int slot = -1;
    for (int i = 0; i < CERTIFY_AK_MAX_PENDING; i++) {
        if (certify_ak_pending[i].in_use &&
                memcmp(certify_ak_pending[i].ek_fingerprint,
                        challenge->ek_fingerprint, 32) == 0) {
            slot = i;
            break;
        }
    }
    if (slot < 0) { /* else a free or expired slot */
        for (int i = 0; i < CERTIFY_AK_MAX_PENDING; i++) {
            if (!certify_ak_pending[i].in_use ||
                    certify_ak_pending[i].expires_at <= now) {
                slot = i;
                break;
            }
        }
    }
    if (slot < 0) {
        slot = 0; /* table full of live challenges: evict the oldest */
        for (int i = 1; i < CERTIFY_AK_MAX_PENDING; i++) {
            if (certify_ak_pending[i].expires_at <
                    certify_ak_pending[slot].expires_at) {
                slot = i;
            }
        }
    }
    certify_ak_pending[slot] = *challenge;
    certify_ak_pending[slot].in_use = true;
}

/** Single-use lookup: a matching challenge is copied out and cleared, so
 * neither a replay nor a retry after a wrong guess can reuse it. */
static bool certify_ak_pending_take(
        const uint8_t ek_fingerprint[32], certify_ak_pending_challenge* out) {
    time_t now = time(NULL);
    for (int i = 0; i < CERTIFY_AK_MAX_PENDING; i++) {
        if (!certify_ak_pending[i].in_use ||
                memcmp(certify_ak_pending[i].ek_fingerprint, ek_fingerprint,
                        32) != 0) {
            continue;
        }
        bool expired = certify_ak_pending[i].expires_at <= now;
        *out = certify_ak_pending[i];
        memset(&certify_ak_pending[i], 0, sizeof(certify_ak_pending[i]));
        return !expired;
    }
    return false;
}

/**
 * @brief /certify_ak CHALLENGE leg: validate the requester's EK
 * certificate, then hand back a fresh random secret wrapped via
 * Esys_MakeCredential against that EK/AK pair. Deliberately signs nothing
 * and records nothing -- an unanswered challenge leaves no trace.
 */
static CHARRA_RC certify_ak_do_challenge(const msg_certify_ak_request_dto* req,
        uint8_t** marshaled_out, uint32_t* marshaled_len_out,
        coap_pdu_code_t* response_code_out) {
    CHARRA_RC charra_r = CHARRA_RC_ERROR;
    TSS2_RC tss_r = 0;

    char* manufacturer_root_der = NULL;
    size_t manufacturer_root_der_len = 0;
    mbedtls_x509_crt ek_leaf_cert;
    bool ek_leaf_cert_inited = false;

    ESYS_CONTEXT* esys_ctx = NULL;
    TSS2_TCTI_CONTEXT* tcti_ctx = NULL;
    TPM2B_ID_OBJECT* credential_blob = NULL;
    TPM2B_ENCRYPTED_SECRET* wrapped_secret = NULL;

    if (certify_ak_state_path_for_subject(req->subject) == NULL) {
        charra_log_error(
                "[" LOG_NAME "] /certify_ak: unrecognized subject %u.",
                req->subject);
        *response_code_out = COAP_RESPONSE_CODE_BAD_REQUEST;
        return CHARRA_RC_BAD_ARGUMENT;
    }

    if ((charra_r = charra_io_read_file(manufacturer_root_cert_path,
                 &manufacturer_root_der, &manufacturer_root_der_len)) !=
            CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME
                         "] /certify_ak: could not read manufacturer root "
                         "certificate ('%s').",
                manufacturer_root_cert_path);
        goto cleanup;
    }

    if ((charra_r = charra_crypto_verify_x509_cert_chain(req->ek_certificate,
                 req->ek_certificate_len, (uint8_t*)manufacturer_root_der,
                 manufacturer_root_der_len, &ek_leaf_cert)) !=
            CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] /certify_ak: EK certificate did "
                         "NOT verify against the manufacturer root.");
        *response_code_out = COAP_RESPONSE_CODE_UNAUTHORIZED;
        goto cleanup;
    }
    ek_leaf_cert_inited = true;
    charra_log_info("[" LOG_NAME "] /certify_ak: EK certificate verified.");
    charra_crypto_log_cert_summary("requester's EK cert", &ek_leaf_cert);

    /* Esys_MakeCredential needs more than the bare RSA key the cert carries */
    TPM2B_PUBLIC ek_public_key = {0};
    if ((charra_r = charra_crypto_build_ek_tpm2b_public_from_cert(
                 &ek_leaf_cert, &ek_public_key)) != CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] /certify_ak: could not "
                         "reconstruct EK TPM2B_PUBLIC from certificate.");
        *response_code_out = COAP_RESPONSE_CODE_UNAUTHORIZED;
        goto cleanup;
    }

    certify_ak_pending_challenge challenge = {0};
    if ((charra_r = charra_random_bytes(sizeof(challenge.secret),
                 challenge.secret)) != CHARRA_RC_SUCCESS) {
        charra_log_error(
                "[" LOG_NAME "] /certify_ak: could not generate secret.");
        goto cleanup;
    }
    if ((charra_r = hash_sha256(req->ek_certificate_len, req->ek_certificate,
                 challenge.ek_fingerprint)) != CHARRA_RC_SUCCESS) {
        charra_log_error(
                "[" LOG_NAME "] /certify_ak: could not hash EK certificate.");
        goto cleanup;
    }
    challenge.ak_public_key_len = req->ak_public_key_len;
    memcpy(challenge.ak_public_key, req->ak_public_key,
            req->ak_public_key_len);
    challenge.ak_name_len = req->ak_name_len;
    memcpy(challenge.ak_name, req->ak_name, req->ak_name_len);
    challenge.subject = req->subject;
    challenge.expires_at = time(NULL) + CERTIFY_AK_PENDING_TTL_SECONDS;

    if ((tss_r = Tss2_TctiLdr_Initialize(getenv("CHARRA_TCTI"), &tcti_ctx)) !=
            TSS2_RC_SUCCESS) {
        charra_log_error(
                "[" LOG_NAME "] /certify_ak: Tss2_TctiLdr_Initialize.");
        charra_r = CHARRA_RC_ERROR;
        goto cleanup;
    }
    if ((tss_r = Esys_Initialize(&esys_ctx, tcti_ctx, NULL)) !=
            TSS2_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] /certify_ak: Esys_Initialize.");
        charra_r = CHARRA_RC_ERROR;
        goto cleanup;
    }

    TPM2B_DIGEST credential = {0};
    credential.size = sizeof(challenge.secret);
    memcpy(credential.buffer, challenge.secret, sizeof(challenge.secret));

    if ((charra_r = charra_tpm_make_credential_for_ak(esys_ctx, &ek_public_key,
                 (TPM2B_NAME*)req->ak_name, &credential, &credential_blob,
                 &wrapped_secret)) != CHARRA_RC_SUCCESS) {
        charra_log_error(
                "[" LOG_NAME "] /certify_ak: Esys_MakeCredential failed.");
        goto cleanup;
    }

    msg_certify_ak_response_dto resp = {0};
    resp.credential_blob_len = sizeof(*credential_blob);
    memcpy(resp.credential_blob, credential_blob, resp.credential_blob_len);
    resp.wrapped_secret_len = sizeof(*wrapped_secret);
    memcpy(resp.wrapped_secret, wrapped_secret, resp.wrapped_secret_len);

    if ((charra_r = charra_marshal_certify_ak_response(
                 &resp, marshaled_len_out, marshaled_out)) !=
            CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME
                         "] /certify_ak: could not marshal CHALLENGE.");
        goto cleanup;
    }

    certify_ak_pending_store(&challenge);
    {
        char fingerprint_hex[17] = {0};
        hex_prefix(challenge.ek_fingerprint, sizeof(challenge.ek_fingerprint),
                fingerprint_hex, sizeof(fingerprint_hex));
        charra_log_info("[" LOG_NAME "] /certify_ak: CHALLENGE issued to "
                        "identity %s... (subject=%s, valid %ds); awaiting "
                        "CONFIRM.",
                fingerprint_hex, certify_ak_subject_name(req->subject),
                CERTIFY_AK_PENDING_TTL_SECONDS);
    }
    *response_code_out = COAP_RESPONSE_CODE_CONTENT;
    charra_r = CHARRA_RC_SUCCESS;

cleanup:
    if (credential_blob != NULL) {
        Esys_Free(credential_blob);
    }
    if (wrapped_secret != NULL) {
        Esys_Free(wrapped_secret);
    }
    if (esys_ctx != NULL) {
        Esys_Finalize(&esys_ctx);
    }
    if (tcti_ctx != NULL) {
        Tss2_TctiLdr_Finalize(&tcti_ctx);
    }
    if (ek_leaf_cert_inited) {
        mbedtls_x509_crt_free(&ek_leaf_cert);
    }
    charra_io_free_file_buffer(&manufacturer_root_der);
    return charra_r;
}

/**
 * @brief /certify_ak CONFIRM leg: match the echoed secret against the
 * pending challenge and only then sign, record, and release the
 * certificate. Needs no TPM -- the proof was produced by the requester's.
 */
static CHARRA_RC certify_ak_do_confirm(const msg_certify_ak_request_dto* req,
        uint8_t** marshaled_out, uint32_t* marshaled_len_out,
        coap_pdu_code_t* response_code_out) {
    CHARRA_RC charra_r = CHARRA_RC_ERROR;

    char* verifier_ca_cert_der = NULL;
    size_t verifier_ca_cert_der_len = 0;
    mbedtls_x509_crt verifier_ca_cert;
    bool verifier_ca_cert_inited = false;
    uint8_t* ak_cert_der = NULL;
    uint32_t ak_cert_der_len = 0;

    uint8_t ek_fingerprint[32] = {0};
    if ((charra_r = hash_sha256(req->ek_certificate_len, req->ek_certificate,
                 ek_fingerprint)) != CHARRA_RC_SUCCESS) {
        charra_log_error(
                "[" LOG_NAME "] /certify_ak: could not hash EK certificate.");
        goto cleanup;
    }
    char ek_fingerprint_hex[17] = {0};
    hex_prefix(ek_fingerprint, sizeof(ek_fingerprint), ek_fingerprint_hex,
            sizeof(ek_fingerprint_hex));

    certify_ak_pending_challenge challenge = {0};
    if (!certify_ak_pending_take(ek_fingerprint, &challenge)) {
        charra_log_error("[" LOG_NAME "] /certify_ak: CONFIRM from identity "
                         "%s... has no live challenge (never issued, already "
                         "used, or expired).",
                ek_fingerprint_hex);
        *response_code_out = COAP_RESPONSE_CODE_UNAUTHORIZED;
        charra_r = CHARRA_RC_VERIFICATION_FAILED;
        goto cleanup;
    }

    if (req->secret_len != sizeof(challenge.secret) ||
            !constant_time_equal(
                    req->secret, challenge.secret, sizeof(challenge.secret))) {
        charra_log_error("[" LOG_NAME "] /certify_ak: CONFIRM from identity "
                         "%s... did NOT echo the challenge secret -- this "
                         "requester does not hold the EK/AK it claims. "
                         "Nothing signed, nothing revoked.",
                ek_fingerprint_hex);
        *response_code_out = COAP_RESPONSE_CODE_UNAUTHORIZED;
        charra_r = CHARRA_RC_VERIFICATION_FAILED;
        goto cleanup;
    }
    charra_log_info("[" LOG_NAME "] /certify_ak: CONFIRM from identity %s... "
                    "echoed the correct secret (ActivateCredential proves "
                    "TPM possession); issuing certificate (subject=%s).",
            ek_fingerprint_hex, certify_ak_subject_name(challenge.subject));

    /* Ledger this issuance belongs in -- taken from the CHALLENGE-time
     * binding above, not anything req (CONFIRM) itself carries. Already
     * validated at CHALLENGE time, so NULL here would mean state corruption
     * (or a pending-challenge struct that predates this field), not
     * attacker input -- checked anyway, since silently falling back to
     * either ledger would be exactly the kind of cross-identity mixup this
     * whole change exists to prevent. */
    const char* subject_ak_state_file_path =
            certify_ak_state_path_for_subject(challenge.subject);
    if (subject_ak_state_file_path == NULL) {
        charra_log_error("[" LOG_NAME "] /certify_ak: CONFIRM from identity "
                         "%s... has an unrecognized subject %u bound into "
                         "its pending challenge -- refusing to guess which "
                         "ledger to use.",
                ek_fingerprint_hex, challenge.subject);
        charra_r = CHARRA_RC_ERROR;
        goto cleanup;
    }

    /* --- sign, for the key bound into the challenge --- */
    if ((charra_r = charra_io_read_file(verifier_ca_cert_path,
                 &verifier_ca_cert_der, &verifier_ca_cert_der_len)) !=
            CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] /certify_ak: could not read "
                         "Verifier CA certificate ('%s').",
                verifier_ca_cert_path);
        goto cleanup;
    }
    mbedtls_x509_crt_init(&verifier_ca_cert);
    verifier_ca_cert_inited = true;
    if (mbedtls_x509_crt_parse(&verifier_ca_cert,
                (uint8_t*)verifier_ca_cert_der, verifier_ca_cert_der_len) !=
            0) {
        charra_log_error("[" LOG_NAME "] /certify_ak: could not parse "
                         "Verifier CA certificate.");
        charra_r = CHARRA_RC_CRYPTO_ERROR;
        goto cleanup;
    }
    char verifier_ca_subject_name[256] = {0};
    if (mbedtls_x509_dn_gets(verifier_ca_subject_name,
                sizeof(verifier_ca_subject_name),
                &verifier_ca_cert.subject) <= 0) {
        charra_log_error("[" LOG_NAME "] /certify_ak: could not read "
                         "Verifier CA subject name.");
        charra_r = CHARRA_RC_CRYPTO_ERROR;
        goto cleanup;
    }

    /* Validity runs from now, so every issuance gets the full window. */
    time_t ak_cert_issued_at = time(NULL);
    time_t ak_cert_expires_at = ak_cert_issued_at + ak_cert_validity_seconds;
    char ak_cert_not_before_utc[15] = {0};
    char ak_cert_not_after_utc[15] = {0};
    if (!charra_crypto_format_utc_yyyymmddhhmmss(
                ak_cert_issued_at, ak_cert_not_before_utc) ||
            !charra_crypto_format_utc_yyyymmddhhmmss(
                    ak_cert_expires_at, ak_cert_not_after_utc)) {
        charra_log_error("[" LOG_NAME "] /certify_ak: could not format AK "
                         "certificate validity window.");
        charra_r = CHARRA_RC_ERROR;
        goto cleanup;
    }

    uint8_t ak_cert_serial[16] = {0};
    if ((charra_r = charra_crypto_sign_ak_certificate(
                 (TPM2B_PUBLIC*)challenge.ak_public_key, "CN=CHARRA AK",
                 verifier_ca_subject_name, ak_cert_not_before_utc,
                 ak_cert_not_after_utc, verifier_ca_key_path, &ak_cert_der,
                 &ak_cert_der_len, ak_cert_serial)) != CHARRA_RC_SUCCESS) {
        charra_log_error(
                "[" LOG_NAME "] /certify_ak: could not sign AK certificate.");
        goto cleanup;
    }
    charra_log_info(
            "[" LOG_NAME "] /certify_ak: AK certificate signed (%u bytes).",
            ak_cert_der_len);

    msg_certify_ak_response_dto resp = {0};
    resp.ak_certificate_len = ak_cert_der_len;
    resp.ak_certificate = ak_cert_der;
    if ((charra_r = charra_marshal_certify_ak_response(
                 &resp, marshaled_len_out, marshaled_out)) !=
            CHARRA_RC_SUCCESS) {
        charra_log_error(
                "[" LOG_NAME "] /certify_ak: could not marshal CONFIRM.");
        goto cleanup;
    }

    /* --- record the issuance, revoking any prior one for this identity.
     * Only reachable past the proof above, so a request that can't answer
     * the challenge can no longer revoke a working certificate. */
    /* ak_cert_expires_at is already the exact value stamped into the
     * certificate above -- no need to parse the string back out. */
    {
        charra_ak_state_record* existing_records = NULL;
        uint32_t existing_count = 0;
        if (charra_ak_state_load(subject_ak_state_file_path, &existing_records,
                    &existing_count) == CHARRA_RC_SUCCESS) {
            uint32_t existing_index = 0;
            if (charra_ak_state_find_by_ek_fingerprint(existing_records,
                        existing_count, ek_fingerprint, &existing_index)) {
                char prev_serial_hex[33] = {0};
                hex_prefix(existing_records[existing_index].serial,
                        sizeof(existing_records[existing_index].serial),
                        prev_serial_hex, sizeof(prev_serial_hex));
                bool prev_was_valid = charra_ak_state_is_valid(
                        &existing_records[existing_index], time(NULL));
                charra_log_info(
                        "[" LOG_NAME "] /certify_ak: identity %s... has a "
                        "prior AK certificate on record (serial %s..., "
                        "%s) -- it will now be revoked in favor of the "
                        "fresh one.",
                        ek_fingerprint_hex, prev_serial_hex,
                        prev_was_valid ? "currently valid"
                                       : "already revoked/expired");
            } else {
                charra_log_info(
                        "[" LOG_NAME "] /certify_ak: identity %s... has no "
                        "prior AK certificate on record -- provisioning a "
                        "new identity.",
                        ek_fingerprint_hex);
            }
            free(existing_records);
        }
    }

    charra_ak_state_record ak_record = {0};
    memcpy(ak_record.ek_fingerprint, ek_fingerprint,
            sizeof(ak_record.ek_fingerprint));
    ak_record.ak_name_len = challenge.ak_name_len;
    memcpy(ak_record.ak_name, challenge.ak_name, challenge.ak_name_len);
    memcpy(ak_record.serial, ak_cert_serial, sizeof(ak_record.serial));
    ak_record.issued_at = time(NULL);
    ak_record.expires_at = ak_cert_expires_at;
    if ((charra_r = charra_ak_state_renew(subject_ak_state_file_path,
                 ek_fingerprint, &ak_record)) != CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] /certify_ak: could not record "
                         "issuance in AK-provisioning state.");
        goto cleanup;
    }
    {
        char new_serial_hex[33] = {0};
        hex_prefix(ak_cert_serial, sizeof(ak_cert_serial), new_serial_hex,
                sizeof(new_serial_hex));
        charra_log_info(
                "[" LOG_NAME "] /certify_ak: identity %s...: new AK "
                "certificate recorded (serial %s..., expires at %ld).",
                ek_fingerprint_hex, new_serial_hex, (long)ak_cert_expires_at);
    }

    *response_code_out = COAP_RESPONSE_CODE_CONTENT;
    charra_r = CHARRA_RC_SUCCESS;

cleanup:
    if (charra_r != CHARRA_RC_SUCCESS) {
        free(*marshaled_out);
        *marshaled_out = NULL;
        *marshaled_len_out = 0;
    }
    free(ak_cert_der);
    if (verifier_ca_cert_inited) {
        mbedtls_x509_crt_free(&verifier_ca_cert);
    }
    charra_io_free_file_buffer(&verifier_ca_cert_der);
    return charra_r;
}

/**
 * @brief /certify_ak: dispatches the two legs of the credential-activation
 * handshake (see CHARRA_CERTIFY_AK_* in charra_dto.h). Unmarshals, routes
 * on `kind`, and sends whatever response the leg produced.
 */
static void coap_certify_ak_handler(struct coap_resource_t* resource,
                                struct coap_session_t* session,
                                const struct coap_pdu_t* request,
                                const struct coap_string_t* query,
                                struct coap_pdu_t* response) {
    int coap_r = 0;
    CHARRA_RC charra_r = CHARRA_RC_ERROR;
    coap_pdu_code_t response_code = COAP_RESPONSE_CODE_INTERNAL_ERROR;

    log_peer_address("/certify_ak", session);

    msg_certify_ak_request_dto req = {0};
    bool req_unmarshaled = false;
    uint8_t* marshaled_response = NULL;
    uint32_t marshaled_response_len = 0;

    size_t data_len = 0;
    const uint8_t* data = NULL;
    size_t data_offset = 0;
    size_t data_total_len = 0;
    if ((coap_r = coap_get_data_large(request, &data_len, &data, &data_offset,
                 &data_total_len)) == 0) {
        charra_log_error(
                "[" LOG_NAME "] /certify_ak: Could not get CoAP PDU data.");
        response_code = COAP_RESPONSE_CODE_BAD_REQUEST;
        goto cleanup;
    }
    charra_log_info(
            "[" LOG_NAME "] /certify_ak: received request of length %zu.",
            data_len);

    if ((charra_r = charra_unmarshal_certify_ak_request(
                 data_len, data, &req)) != CHARRA_RC_SUCCESS) {
        charra_log_error(
                "[" LOG_NAME "] /certify_ak: could not parse CBOR request.");
        response_code = COAP_RESPONSE_CODE_BAD_REQUEST;
        goto cleanup;
    }
    req_unmarshaled = true;

    switch (req.kind) {
    case CHARRA_CERTIFY_AK_CHALLENGE:
        charra_r = certify_ak_do_challenge(
                &req, &marshaled_response, &marshaled_response_len,
                &response_code);
        break;
    case CHARRA_CERTIFY_AK_CONFIRM:
        charra_r = certify_ak_do_confirm(
                &req, &marshaled_response, &marshaled_response_len,
                &response_code);
        break;
    default:
        charra_log_error("[" LOG_NAME "] /certify_ak: unknown kind %u.",
                req.kind);
        response_code = COAP_RESPONSE_CODE_BAD_REQUEST;
        charra_r = CHARRA_RC_BAD_ARGUMENT;
        break;
    }
    if (charra_r != CHARRA_RC_SUCCESS) {
        goto cleanup;
    }

    coap_pdu_set_code(response, response_code);
    if ((coap_r = coap_add_data_large_response(resource, session, request,
                 response, query, COAP_MEDIATYPE_APPLICATION_CBOR, -1, 0,
                 marshaled_response_len, marshaled_response,
                 release_response_data, marshaled_response)) == 0) {
        charra_log_error("[" LOG_NAME "] /certify_ak: Error invoking "
                         "coap_add_data_large_response().");
        /* libcoap did not accept ownership -- still ours to free */
        free(marshaled_response);
    }
    marshaled_response = NULL;
    goto cleanup_success;

cleanup:
    coap_pdu_set_code(response, response_code);

cleanup_success:
    /* NULL on the success path (ownership transferred above). */
    free(marshaled_response);
    if (req_unmarshaled) {
        charra_free_if_not_null(req.ek_certificate);
    }
}

/**
 * @brief /qualify: fabricate a fresh RP-qualification challenge and hand
 * back its raw (unredacted) log for the RP to redact and prove against via
 * /qualify/submit -- see charra_rp_qualification.h for the full handshake
 * this is the first half of.
 *
 * Ignores the request body: nothing about *which* challenge to generate is
 * caller-supplied, only Verifier policy (CHARRA_RP_QUALIFICATION_NUM_
 * ENTRIES) and a fresh random seed picked here.
 */
static void coap_qualify_handler(struct coap_resource_t* resource,
                                struct coap_session_t* session,
                                const struct coap_pdu_t* request,
                                const struct coap_string_t* query,
                                struct coap_pdu_t* response) {
    int coap_r = 0;
    CHARRA_RC charra_r = CHARRA_RC_ERROR;
    coap_pdu_code_t response_code = COAP_RESPONSE_CODE_INTERNAL_ERROR;

    log_peer_address("/qualify", session);

    uint8_t* challenge_log = NULL;
    uint32_t challenge_log_len = 0;
    uint8_t* marshaled_response = NULL;
    uint32_t marshaled_response_len = 0;

    /* discard the previous round's golden answer -- a fresh /qualify call
     * always starts a new round; any /qualify/submit still in flight for
     * the old one is now moot */
    charra_rp_qualification_state_free(&qualification_state);

    uint32_t seed = 0;
    if ((charra_r = charra_random_bytes(
                 sizeof(seed), (uint8_t*)&seed)) != CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] /qualify: could not generate a "
                         "random challenge seed.");
        goto cleanup;
    }

    /* Shared with the RP in the response below, so its redaction of
     * challenge_log comes out byte-identical to golden_log here -- the one
     * deliberate exception to "salt is never transmitted", safe only
     * because this log is synthetic. See charra_sdk.h. */
    uint8_t salt[CHARRA_SDK_PATH_SALT_LEN] = {0};
    if ((charra_r = charra_random_bytes(sizeof(salt), salt)) !=
            CHARRA_RC_SUCCESS) {
        charra_log_error(
                "[" LOG_NAME "] /qualify: could not generate a salt.");
        goto cleanup;
    }

    if ((charra_r = charra_rp_qualification_generate(
                 CHARRA_RP_QUALIFICATION_NUM_ENTRIES, seed, salt,
                 &qualification_state, &challenge_log,
                 &challenge_log_len)) != CHARRA_RC_SUCCESS) {
        charra_log_error(
                "[" LOG_NAME "] /qualify: could not generate challenge.");
        goto cleanup;
    }

    msg_qualify_response_dto resp = {
            .challenge_log_len = challenge_log_len,
            .challenge_log = challenge_log,
    };
    memcpy(resp.salt, salt, sizeof(resp.salt));
    if ((charra_r = charra_marshal_qualify_response(&resp,
                 &marshaled_response_len, &marshaled_response)) !=
            CHARRA_RC_SUCCESS) {
        charra_log_error(
                "[" LOG_NAME "] /qualify: could not marshal response.");
        goto cleanup;
    }

    charra_log_info(
            "[" LOG_NAME "] /qualify: issued a %u-entry challenge (%u "
            "bytes).",
            CHARRA_RP_QUALIFICATION_NUM_ENTRIES, challenge_log_len);
    response_code = COAP_RESPONSE_CODE_CONTENT;

cleanup:
    coap_pdu_set_code(response, response_code);
    if (response_code == COAP_RESPONSE_CODE_CONTENT) {
        if ((coap_r = coap_add_data_large_response(resource, session,
                     request, response, query, COAP_MEDIATYPE_APPLICATION_CBOR,
                     -1, 0, marshaled_response_len, marshaled_response,
                     release_response_data, marshaled_response)) == 0) {
            charra_log_error("[" LOG_NAME "] /qualify: Error invoking "
                             "coap_add_data_large_response().");
            /* libcoap did not accept ownership -- still ours to free */
            free(marshaled_response);
        }
        /* else: ownership transferred to libcoap, freed later */
    } else {
        free(marshaled_response);
    }
    free(challenge_log);
}

/**
 * @brief /qualify/submit: check the RP's redaction result against the
 * outstanding /qualify challenge, gating whether coap_appraise_handler()
 * will accept real evidence from this RP -- see charra_rp_qualification.h.
 *
 * Two things must hold before charra_rp_qualification_check() is even
 * consulted: the submitter's AK certificate must chain to this Verifier's
 * CA (the same check Step 3a item 1 in coap_appraise_handler() runs), and
 * its signature over submitted_pcr_digest must verify under that certified
 * key. Without both, an unauthenticated party could submit an arbitrary
 * log and PCR digest with no proof it ever ran a real RP's redaction
 * pipeline.
 */
static void coap_qualify_submit_handler(struct coap_resource_t* resource,
                                struct coap_session_t* session,
                                const struct coap_pdu_t* request,
                                const struct coap_string_t* query,
                                struct coap_pdu_t* response) {
    int coap_r = 0;
    CHARRA_RC charra_r = CHARRA_RC_ERROR;
    coap_pdu_code_t response_code = COAP_RESPONSE_CODE_INTERNAL_ERROR;
    const char* message = "Qualification check errored!\0";

    log_peer_address("/qualify/submit", session);

    /* declared/zeroed here so cleanup can always safely free them,
     * regardless of which check below first failed -- same convention
     * coap_certify_ak_handler() above uses */
    msg_qualify_submit_request_dto req = {0};
    char* verifier_ca_cert_der = NULL;
    /* Verdict + the deadline actually granted -- the RP has no other
     * way to learn the window this Verifier chose. */
    msg_qualify_submit_response_dto submit_response = {0};
    size_t verifier_ca_cert_der_len = 0;

    size_t data_len = 0;
    const uint8_t* data = NULL;
    size_t data_offset = 0;
    size_t data_total_len = 0;
    if ((coap_r = coap_get_data_large(request, &data_len, &data, &data_offset,
                 &data_total_len)) == 0) {
        charra_log_error("[" LOG_NAME
                         "] /qualify/submit: Could not get CoAP PDU data.");
        response_code = COAP_RESPONSE_CODE_BAD_REQUEST;
        goto cleanup;
    }

    if ((charra_r = charra_unmarshal_qualify_submit_request(
                 data_len, data, &req)) != CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME
                         "] /qualify/submit: could not parse CBOR request.");
        response_code = COAP_RESPONSE_CODE_BAD_REQUEST;
        goto cleanup;
    }

    /* --- who is this: submitter's AK certificate must chain to our CA,
     * same check Step 3a item 1 in coap_appraise_handler() runs --- */
    if ((charra_r = charra_io_read_file(verifier_ca_cert_path,
                 &verifier_ca_cert_der, &verifier_ca_cert_der_len)) !=
            CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] /qualify/submit: could not read "
                         "Verifier CA certificate ('%s').",
                verifier_ca_cert_path);
        goto cleanup;
    }

    /* ek_fingerprint identifies who this is, for the qualification-ledger
     * write below -- declared here (not inside the block) so it survives
     * past it, populated only when submitter_identity_ok ends up true. */
    uint8_t ek_fingerprint[32] = {0};
    bool submitter_identity_ok = false;
    {
        mbedtls_x509_crt ak_cert_rp_leaf;
        uint8_t ak_serial_rp[16] = {0};
        CHARRA_RC chain_rc = charra_crypto_verify_x509_cert_chain(
                req.ak_certificate_rp, req.ak_certificate_rp_len,
                (uint8_t*)verifier_ca_cert_der, verifier_ca_cert_der_len,
                &ak_cert_rp_leaf);
        if (chain_rc == CHARRA_RC_SUCCESS) {
            if (ak_cert_rp_leaf.serial.len == 16) {
                memcpy(ak_serial_rp, ak_cert_rp_leaf.serial.p, 16);
            }
            submitter_identity_ok =
                    charra_crypto_verify_cert_public_key_matches_der_key(
                            &ak_cert_rp_leaf, req.rp_public_key,
                            req.rp_public_key_len) == CHARRA_RC_SUCCESS &&
                    charra_ak_state_check_serial_valid(rp_ak_state_file_path,
                            ak_serial_rp, ek_fingerprint, NULL);
            if (submitter_identity_ok) {
                charra_crypto_log_cert_summary(
                        "/qualify/submit submitter's AK cert",
                        &ak_cert_rp_leaf);
            }
            mbedtls_x509_crt_free(&ak_cert_rp_leaf);
        }
    }
    if (!submitter_identity_ok) {
        charra_log_error("[" LOG_NAME "] /qualify/submit: submitter's AK "
                         "certificate did NOT verify (chain, key mismatch, "
                         "or expired/revoked).");
        response_code = COAP_RESPONSE_CODE_UNAUTHORIZED;
        message = "Submitter AK certificate invalid or expired!\0";
        goto cleanup;
    }

    /* --- Quote_R signature: proves the certified key above actually
     * signed submitted_pcr_digest, not that some unrelated certificate was
     * merely attached to the request --- */
    bool signature_ok = false;
    {
        mbedtls_pk_context rp_pub_key_ctx;
        mbedtls_pk_init(&rp_pub_key_ctx);
        if (mbedtls_pk_parse_public_key(&rp_pub_key_ctx, req.rp_public_key,
                    req.rp_public_key_len) == 0 &&
                mbedtls_pk_get_type(&rp_pub_key_ctx) == MBEDTLS_PK_RSA &&
                mbedtls_rsa_set_padding(mbedtls_pk_rsa(rp_pub_key_ctx),
                        MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA256) == 0) {
            signature_ok = charra_crypto_rsa_verify_signature(
                                   mbedtls_pk_rsa(rp_pub_key_ctx),
                                   MBEDTLS_MD_SHA256, req.submitted_pcr_digest,
                                   sizeof(req.submitted_pcr_digest),
                                   req.rp_signature) == CHARRA_RC_SUCCESS;
        } else {
            charra_log_error("[" LOG_NAME "] /qualify/submit: could not "
                             "parse submitter's public key.");
        }
        mbedtls_pk_free(&rp_pub_key_ctx);
    }
    if (!signature_ok) {
        charra_log_error("[" LOG_NAME "] /qualify/submit: signature over "
                         "submitted PCR digest is NOT valid.");
        response_code = COAP_RESPONSE_CODE_UNAUTHORIZED;
        message = "Signature over submitted PCR digest invalid!\0";
        goto cleanup;
    }

    /* --- the actual qualification comparison: golden answer vs.
     * submission -- see charra_rp_qualification.h. The salt used to redact
     * challenge_log is shared with the RP (see coap_qualify_handler()'s
     * own comment on qualify_challenge_salt) specifically so a correctly-
     * behaving RP's redaction comes out byte-identical to golden_log here;
     * a passing check on a legitimately-behaving RP is the expected,
     * common case, not a known-broken path. */
    if (charra_rp_qualification_check(&qualification_state,
                req.submitted_redacted_log, req.submitted_redacted_log_len,
                req.submitted_pcr_digest, time(NULL)) == CHARRA_RC_SUCCESS) {
        /* Persist the verdict, keyed by this RP's identity -- this is what
         * lets coap_appraise_handler() later confirm THIS SPECIFIC RP
         * qualified, not just "someone did, recently". Deliberately done
         * only here, once the check has actually passed -- a failed
         * charra_qualification_state_renew() call below still leaves the
         * RP correctly told it qualified (the check itself did pass), it
         * just means the durable record didn't get written; logged, not
         * fatal to this response. */
        charra_qualification_state_record qual_record = {0};
        memcpy(qual_record.ek_fingerprint, ek_fingerprint,
                sizeof(qual_record.ek_fingerprint));
        qual_record.qualified_at = time(NULL);
        qual_record.expires_at = qualification_state.expires_at;
        if (charra_qualification_state_renew(qualification_state_file_path,
                    ek_fingerprint, &qual_record) != CHARRA_RC_SUCCESS) {
            charra_log_error("[" LOG_NAME "] /qualify/submit: could not "
                             "persist qualification state.");
        }

        char ek_fingerprint_hex[17] = {0};
        hex_prefix(ek_fingerprint, sizeof(ek_fingerprint), ek_fingerprint_hex,
                sizeof(ek_fingerprint_hex));
        charra_log_info(
                "[" LOG_NAME "] /qualify/submit: RP %s... qualified (valid "
                "until %ld, %ld second(s) from now).",
                ek_fingerprint_hex, (long)qualification_state.expires_at,
                (long)(qualification_state.expires_at - time(NULL)));
        response_code = COAP_RESPONSE_CODE_CONTENT;
        message = "Qualification successful!\0";
        submit_response.qualified = 1;
        submit_response.expires_at =
                (uint64_t)qualification_state.expires_at;
    } else {
        char ek_fingerprint_hex[17] = {0};
        hex_prefix(ek_fingerprint, sizeof(ek_fingerprint), ek_fingerprint_hex,
                sizeof(ek_fingerprint_hex));
        charra_log_error(
                "[" LOG_NAME "] /qualify/submit: RP %s...'s submitted "
                "log/PCR did NOT match the golden answer.",
                ek_fingerprint_hex);
        response_code = COAP_RESPONSE_CODE_CONTENT;
        message = "Qualification failed!  \0";
    }

cleanup:
    coap_pdu_set_code(response, response_code);
    /* The human-readable message stays in the log; the wire now carries
     * the structured verdict so RP need not assume the window. */
    charra_log_info("[" LOG_NAME "] /qualify/submit: %s", message);
    {
        uint8_t* submit_resp_buf = NULL;
        uint32_t submit_resp_buf_len = 0;
        if (charra_marshal_qualify_submit_response(&submit_response,
                    &submit_resp_buf_len, &submit_resp_buf) !=
                CHARRA_RC_SUCCESS) {
            charra_log_error("[" LOG_NAME "] /qualify/submit: could not "
                             "marshal response.");
            coap_pdu_set_code(response, COAP_RESPONSE_CODE_INTERNAL_ERROR);
        } else if ((coap_r = coap_add_data_large_response(resource, session,
                            request, response, query,
                            COAP_MEDIATYPE_APPLICATION_CBOR, -1, 0,
                            submit_resp_buf_len, submit_resp_buf,
                            release_response_data, submit_resp_buf)) == 0) {
            charra_log_error("[" LOG_NAME "] /qualify/submit: error "
                             "invoking coap_add_data_large_response().");
            free(submit_resp_buf);
        }
    }
    charra_free_if_not_null(req.submitted_redacted_log);
    charra_free_if_not_null(req.ak_certificate_rp);
    charra_io_free_file_buffer(&verifier_ca_cert_der);
    return;
}

