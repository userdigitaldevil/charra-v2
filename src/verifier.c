#include <arpa/inet.h>
#include <coap3/coap.h>
#include <errno.h>
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
#include "core/charra_rim_mgr.h"
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

/* logging */
#define LOG_NAME "verifier"
static uint8_t tpm_pcr_selection[TPM2_MAX_PCRS] = {0, 1, 2, 3, 4, 5, 6, 7, 10};
static uint32_t tpm_pcr_selection_len = 9;
char* reference_pcr_file_path = "reference-pcrs.txt";
/* file-content-hash policy for log_r entries (checklist item 6) -- one
 * "0x<64 hex chars>" SHA-256 hash per line, '#' comments and blank lines
 * skipped, same style as reference-pcrs.txt's "0x..." hex convention */
char* whitelist_hashes_file_path = "whitelist-hashes.txt";
char* blacklist_hashes_file_path = "blacklist-hashes.txt";
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

    if ((use_dtls_psk || use_dtls_psk) && !coap_dtls_is_supported()) {
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
 * @brief Verify a TPM Quote's signature with the TPM itself. Sets the
 * file-scope attestation_rc as a side effect, same as this logic did when
 * it was inlined in coap_appraise_handler().
 */
static bool verify_quote_signature_with_tpm(ESYS_CONTEXT* esys_ctx,
        ESYS_TR sig_key_handle, const TPM2B_ATTEST* attest,
        TPMT_SIGNATURE* signature, TPMT_TK_VERIFIED** validation) {
    charra_log_info(
            "[" LOG_NAME "] Verifying TPM Quote signature with TPM ...");
    if ((attestation_rc = charra_verify_tpm2_quote_signature_with_tpm(
                 esys_ctx, sig_key_handle, TPM2_ALG_SHA256, attest, signature,
                 validation)) == CHARRA_RC_SUCCESS) {
        charra_log_info("[" LOG_NAME "]     => TPM Quote signature is valid!");
        return true;
    }
    charra_log_error("[" LOG_NAME "]     => TPM Quote signature is NOT valid!");
    return false;
}

/**
 * @brief Verify a TPM Quote's signature with mbedTLS (defense in depth,
 * independent of the TPM-based check above).
 *
 * Two different failure modes, matching what this logic did before being
 * pulled out of coap_appraise_handler(): converting the TPM public key to
 * an mbedTLS key is a hard error the caller should abort on (returns
 * false, same as the original inline code's 'goto cleanup'); the signature
 * itself not matching is not fatal to the handler, just recorded via
 * *out_valid so the caller can fold it into the overall attestation result.
 */
static bool verify_quote_signature_mbedtls(TPM2B_PUBLIC* tpm2_public_key,
        const uint8_t* attestation_data, uint32_t attestation_data_len,
        TPMT_SIGNATURE* signature, bool* out_valid) {
    *out_valid = false;

    charra_log_info("[" LOG_NAME
                    "] Converting TPM public key to mbedTLS public key ...");
    mbedtls_rsa_context mbedtls_rsa_pub_key = {0};
    if ((attestation_rc = charra_crypto_tpm_pub_key_to_mbedtls_pub_key(
                 tpm2_public_key, &mbedtls_rsa_pub_key)) != CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] mbedTLS RSA error");
        return false;
    }

    charra_log_info(
            "[" LOG_NAME "] Verifying TPM Quote signature with mbedTLS ...");
    if ((attestation_rc = charra_crypto_rsa_verify_signature(
                 &mbedtls_rsa_pub_key, MBEDTLS_MD_SHA256, attestation_data,
                 (size_t)attestation_data_len,
                 signature->signature.rsapss.sig.buffer)) ==
            CHARRA_RC_SUCCESS) {
        charra_log_info("[" LOG_NAME "]     => TPM Quote signature is valid!");
        *out_valid = true;
    } else {
        charra_log_error(
                "[" LOG_NAME "]     => TPM Quote signature is NOT valid!");
    }
    mbedtls_rsa_free(&mbedtls_rsa_pub_key);
    return true;
}

/**
 * @brief Per-entry self-consistency check on log_r: does every entry's
 * template_digest equal SHA256(template_data), both fields as they
 * currently appear in the redacted log?
 *
 * This is NOT a check that redaction was done faithfully against real
 * Attester evidence -- that question needs the separate qualification
 * handshake (charra_rp_qualification.h), since the Verifier never sees the
 * pre-redaction log to compare against. This only catches a log_r that is
 * internally malformed: corruption in transit, a redaction bug, or a
 * tampered field that no longer matches its neighbor within the same
 * entry.
 */
static bool verify_log_r_entries_self_consistent(
        const uint8_t* log, uint32_t log_len) {
    if (log_len == 0) {
        /* an empty log has no entries to be inconsistent */
        return true;
    }

    uint16_t digest_len = 0;
    if (charra_event_log_ima_detect_digest_len(log, log_len, &digest_len) !=
            CHARRA_RC_SUCCESS) {
        charra_log_error(
                "[" LOG_NAME "] log_r: could not detect digest size.");
        return false;
    }

    uint32_t offset = 0;
    uint32_t entry_num = 0;
    while (offset < log_len) {
        charra_event_log_entry entry = {0};
        if (charra_event_log_parse_entry(
                    log, log_len, &offset, digest_len, &entry) !=
                CHARRA_RC_SUCCESS) {
            charra_log_error(
                    "[" LOG_NAME "] log_r: entry %u failed to parse.",
                    entry_num);
            return false;
        }

        uint8_t computed_digest[TPM2_SHA256_DIGEST_SIZE] = {0};
        if (hash_sha256(entry.template_data_len, entry.template_data,
                    computed_digest) != CHARRA_RC_SUCCESS) {
            charra_log_error(
                    "[" LOG_NAME "] log_r: hashing entry %u failed.",
                    entry_num);
            return false;
        }
        if (entry.template_digest_len != TPM2_SHA256_DIGEST_SIZE ||
                memcmp(computed_digest, entry.template_digest,
                        TPM2_SHA256_DIGEST_SIZE) != 0) {
            charra_log_error(
                    "[" LOG_NAME "] log_r: entry %u's template_digest does "
                    "NOT match SHA256(template_data).",
                    entry_num);
            return false;
        }
        entry_num++;
    }
    return true;
}

/**
 * @brief Replay log_r into a PCR value and check it against Quote_r's own
 * pcrDigest -- proves Quote_r genuinely quotes over this exact log_r,
 * independent of the (still open) question of what freshness/nonce Quote_r
 * should be checked against.
 */
static bool verify_log_r_matches_quote_r_pcr(
        const uint8_t* log, uint32_t log_len, TPMS_ATTEST* attest_struct_rp) {
    uint8_t replayed_pcr[TPM2_SHA256_DIGEST_SIZE] = {0};
    if (charra_replay_ima_log(log, log_len, CHARRA_IMA_PCR_INDEX,
                replayed_pcr) != CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] log_r: replay failed.");
        return false;
    }

    uint8_t* pcr_values[1] = {replayed_pcr};
    if (compute_and_check_PCR_digest(pcr_values, 1, attest_struct_rp) !=
            CHARRA_RC_SUCCESS) {
        charra_log_error(
                "[" LOG_NAME "] log_r: replayed PCR does NOT match Quote_r's "
                "pcrDigest.");
        return false;
    }
    return true;
}

/** qsort()/bsearch() comparator treating each TPM2_SHA256_DIGEST_SIZE-byte
 * chunk as an opaque sort key. */
static int compare_hashes(const void* a, const void* b) {
    return memcmp(a, b, TPM2_SHA256_DIGEST_SIZE);
}

/**
 * @brief Load a file of hex-encoded SHA-256 hashes, one per line, into a
 * freshly malloc'd flat array, sorted for hash_list_contains() to
 * binary-search ('#' comments and blank lines skipped, optional "0x"
 * prefix -- same hex convention reference-pcrs.txt uses).
 *
 * @param[out] hashes_out malloc'd buffer of *count_out *
 * TPM2_SHA256_DIGEST_SIZE bytes, sorted ascending by raw byte value; caller
 * frees. NULL if the file has no valid entries.
 * @returns CHARRA_RC_SUCCESS, CHARRA_RC_ERROR if the file can't be opened
 * or allocation fails. An unparseable line is logged and skipped, not a
 * hard error -- consistent with rejecting individual bad entries rather
 * than the whole policy file.
 */
static CHARRA_RC load_hash_list(
        const char* path, uint8_t** hashes_out, uint32_t* count_out) {
    *hashes_out = NULL;
    *count_out = 0;

    FILE* f = fopen(path, "r");
    if (f == NULL) {
        charra_log_error(
                "[" LOG_NAME "] Could not open hash list file '%s'.", path);
        return CHARRA_RC_ERROR;
    }

    uint8_t* hashes = NULL;
    uint32_t count = 0;
    uint32_t capacity = 0;
    char line[256];
    while (fgets(line, sizeof(line), f) != NULL) {
        char* p = line;
        while (*p == ' ' || *p == '\t') {
            p++;
        }
        if (*p == '#' || *p == '\n' || *p == '\0') {
            continue; /* comment or blank line */
        }
        if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) {
            p += 2;
        }

        uint8_t digest[TPM2_SHA256_DIGEST_SIZE];
        bool ok = true;
        for (uint32_t i = 0; i < TPM2_SHA256_DIGEST_SIZE; i++) {
            if (p[i * 2] == '\0' || p[i * 2 + 1] == '\0') {
                ok = false;
                break;
            }
            char byte_str[3] = {p[i * 2], p[i * 2 + 1], '\0'};
            char* end = NULL;
            errno = 0;
            long val = strtol(byte_str, &end, 16);
            if (end != byte_str + 2 || errno != 0) {
                ok = false;
                break;
            }
            digest[i] = (uint8_t)val;
        }
        if (!ok) {
            charra_log_error("[" LOG_NAME "] Hash list file '%s': "
                             "unparseable line, skipping.",
                    path);
            continue;
        }

        if (count == capacity) {
            capacity += 32;
            uint8_t* grown = realloc(
                    hashes, (size_t)capacity * TPM2_SHA256_DIGEST_SIZE);
            if (grown == NULL) {
                free(hashes);
                fclose(f);
                return CHARRA_RC_ERROR;
            }
            hashes = grown;
        }
        memcpy(hashes + (size_t)count * TPM2_SHA256_DIGEST_SIZE, digest,
                TPM2_SHA256_DIGEST_SIZE);
        count++;
    }
    fclose(f);

    qsort(hashes, count, TPM2_SHA256_DIGEST_SIZE, compare_hashes);

    *hashes_out = hashes;
    *count_out = count;
    return CHARRA_RC_SUCCESS;
}

/**
 * @brief Binary search: is needle present in hashes? hashes must already be
 * sorted ascending by raw byte value -- true of every array load_hash_list()
 * returns, and the only producer of these arrays.
 */
static bool hash_list_contains(
        const uint8_t* hashes, uint32_t count, const uint8_t* needle) {
    return bsearch(needle, hashes, count, TPM2_SHA256_DIGEST_SIZE,
                   compare_hashes) != NULL;
}

/**
 * @brief Check every log_r entry's preserved file-content digest against
 * the whitelist/blacklist policy (checklist item 6, unblocked now that
 * charra_sdk_redact_ima_log() preserves that digest through redaction).
 *
 * Default-deny: a digest matching neither list fails, same as one that
 * explicitly matches the blacklist -- only explicitly-approved file hashes
 * pass. The file digest is read directly out of the redacted
 * template_data's known layout ("sha256:" + 32-byte digest + 32-byte path
 * hash, see charra_sdk.h) rather than via extract_file_digest_and_path(),
 * since that helper is charra_sdk.c-local; log_r's layout is fixed and
 * public by design, so re-deriving the same 7-byte offset here is fine.
 */
static bool verify_log_r_file_hashes_against_policy(
        const uint8_t* log, uint32_t log_len) {
    uint8_t* whitelist = NULL;
    uint32_t whitelist_count = 0;
    if (load_hash_list(whitelist_hashes_file_path, &whitelist,
                &whitelist_count) != CHARRA_RC_SUCCESS) {
        return false;
    }
    uint8_t* blacklist = NULL;
    uint32_t blacklist_count = 0;
    if (load_hash_list(blacklist_hashes_file_path, &blacklist,
                &blacklist_count) != CHARRA_RC_SUCCESS) {
        free(whitelist);
        return false;
    }

    bool all_ok = true;
    if (log_len > 0) {
        uint16_t digest_len = 0;
        if (charra_event_log_ima_detect_digest_len(
                    log, log_len, &digest_len) != CHARRA_RC_SUCCESS) {
            all_ok = false;
        } else {
            static const char prefix[] = "sha256:";
            uint32_t prefix_len = (uint32_t)(sizeof(prefix) - 1);
            uint32_t offset = 0;
            uint32_t entry_num = 0;
            while (offset < log_len) {
                charra_event_log_entry entry = {0};
                if (charra_event_log_parse_entry(log, log_len, &offset,
                            digest_len, &entry) != CHARRA_RC_SUCCESS) {
                    all_ok = false;
                    break;
                }
                if (entry.template_data_len <
                        prefix_len + TPM2_SHA256_DIGEST_SIZE) {
                    charra_log_error(
                            "[" LOG_NAME "] log_r: entry %u too short to "
                            "contain a file-content digest.",
                            entry_num);
                    all_ok = false;
                    entry_num++;
                    continue;
                }
                const uint8_t* file_digest = entry.template_data + prefix_len;

                if (hash_list_contains(
                            blacklist, blacklist_count, file_digest)) {
                    charra_log_error(
                            "[" LOG_NAME "] log_r: entry %u's file-content "
                            "digest matches the BLACKLIST.",
                            entry_num);
                    all_ok = false;
                } else if (!hash_list_contains(whitelist, whitelist_count,
                                   file_digest)) {
                    charra_log_error(
                            "[" LOG_NAME "] log_r: entry %u's file-content "
                            "digest is not on the whitelist.",
                            entry_num);
                    all_ok = false;
                }
                entry_num++;
            }
        }
    }

    free(whitelist);
    free(blacklist);
    return all_ok;
}

static void coap_appraise_handler(struct coap_resource_t* resource,
                                struct coap_session_t* session,
                                const struct coap_pdu_t* request,
                                const struct coap_string_t* query,
                                struct coap_pdu_t* response) {
    int coap_r = 0;
    TSS2_RC tss_r = 0;

    ESYS_TR sig_key_handle = ESYS_TR_NONE;
    TPMT_TK_VERIFIED* validation = NULL;
    /* Same pair, for Quote_r -- a separate TPM key load / verification
     * ticket from Quote_a's, since it's a different key and a different
     * signature. */
    ESYS_TR sig_key_handle_rp = ESYS_TR_NONE;
    TPMT_TK_VERIFIED* validation_rp = NULL;
    /* Declared here (rather than right before first use, further down) and
     * initialized to NULL so that every earlier 'goto cleanup' -- including
     * the fopen() failure right below -- leaves cleanup able to safely check
     * them instead of reading indeterminate values. */
    ESYS_CONTEXT* esys_ctx = NULL;
    TSS2_TCTI_CONTEXT* tcti_ctx = NULL;

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
    /* Quote_a (Attester's evidence, forwarded) + Quote_r (RP's own quote) +
     * log_r (RP's redacted log, not Attester's raw one) -- see
     * msg_rp_appraisal_dto in charra_dto.h. */
    msg_rp_appraisal_dto res = {0};
    if ((attestation_rc = charra_unmarshal_rp_appraisal(
                 data_len, data, &res)) != CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Could not parse CBOR data.");
        goto cleanup;
    }
    end_unmarshal = clock();
    unmarshal_duration = ((double) (end_unmarshal - start_unmarshal)) / CLOCKS_PER_SEC;
    fprintf(p_file, "unmarshal evidence took %f seconds to execute \n", unmarshal_duration);

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
    /* Same checks, same reasoning, for Quote_r -- these three fields are
     * exactly as attacker-reachable as the Quote_a ones above. Re-checked
     * here independently of whatever bounds charra_unmarshal_rp_appraisal()
     * itself applies, same defense-in-depth style as the rest of this
     * function. */
    if (res.attestation_data_rp_len > sizeof(TPMS_ATTEST)) {
        charra_log_error("[" LOG_NAME "] Length of RP attestation data "
                         "exceeds maximum allowed size.");
        attestation_rc = CHARRA_RC_ERROR;
        goto cleanup;
    }
    if (res.tpm2_signature_rp_len > sizeof(TPMT_SIGNATURE)) {
        charra_log_error("[" LOG_NAME "] Length of RP signature exceeds "
                         "maximum allowed size.");
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


    /* load TPM key */
    clock_t start_load, end_load;
    double load_duration;
    start_load = clock();
    TPM2B_PUBLIC* tpm2_public_key = (TPM2B_PUBLIC*)res.tpm2_public_key;
    charra_log_info("[" LOG_NAME "] Loading TPM key.");
    if ((attestation_rc = charra_load_external_public_key(esys_ctx,
                 tpm2_public_key, &sig_key_handle)) != CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Loading external public key failed.");
        goto cleanup;
    } else {
        charra_log_info("[" LOG_NAME "] External public key loaded.");
    }
    end_load = clock();
    load_duration = ((double) (end_load - start_load)) / CLOCKS_PER_SEC;
    fprintf(p_file, "load external public key took %f seconds to execute \n", load_duration);

    /* prepare verification */
    charra_log_info("[" LOG_NAME "] Preparing TPM Quote verification.");
    clock_t start_verifiy_signature, end_verifiy_signature;
    double verify_signature_duration;
    start_verifiy_signature = clock();
    TPM2B_ATTEST attest = {0};
    attest.size = res.attestation_data_len;
    memcpy(attest.attestationData, res.attestation_data,
            res.attestation_data_len);
    TPMT_SIGNATURE signature = {0};
    memcpy(&signature, res.tpm2_signature, res.tpm2_signature_len);

    /* --- verify attestation signature --- */
    bool attestation_result_signature = verify_quote_signature_with_tpm(
            esys_ctx, sig_key_handle, &attest, &signature, &validation);
    end_verifiy_signature = clock();
    verify_signature_duration = ((double) (end_verifiy_signature - start_verifiy_signature)) / CLOCKS_PER_SEC;
    fprintf(p_file, "verify signature took %f seconds to execute \n", verify_signature_duration);
    /* --- verify attestation signature (defense in depth, mbedTLS) --- */
    bool attestation_result_signature_mbedtls = false;
    if (!verify_quote_signature_mbedtls(tpm2_public_key, res.attestation_data,
                res.attestation_data_len, &signature,
                &attestation_result_signature_mbedtls)) {
        goto cleanup;
    }

    /* --- verify Quote_r (RP's own quote) --- */
    /* Same load-key / TPM-verify / mbedTLS-verify sequence as Quote_a above,
     * applied to RP's fields instead -- the verification logic doesn't care
     * whose quote it is. Nonce and PCR checks against Quote_r happen further
     * down, alongside Quote_a's -- see "verify Quote_r's nonce" below. */
    TPM2B_PUBLIC* tpm2_public_key_rp = (TPM2B_PUBLIC*)res.tpm2_public_key_rp;
    charra_log_info("[" LOG_NAME "] Loading RP TPM key.");
    if ((attestation_rc = charra_load_external_public_key(esys_ctx,
                 tpm2_public_key_rp, &sig_key_handle_rp)) != CHARRA_RC_SUCCESS) {
        charra_log_error(
                "[" LOG_NAME "] Loading external RP public key failed.");
        goto cleanup;
    }
    charra_log_info("[" LOG_NAME "] External RP public key loaded.");

    TPM2B_ATTEST attest_rp = {0};
    attest_rp.size = res.attestation_data_rp_len;
    memcpy(attest_rp.attestationData, res.attestation_data_rp,
            res.attestation_data_rp_len);
    TPMT_SIGNATURE signature_rp = {0};
    memcpy(&signature_rp, res.tpm2_signature_rp, res.tpm2_signature_rp_len);

    bool attestation_result_signature_rp = verify_quote_signature_with_tpm(
            esys_ctx, sig_key_handle_rp, &attest_rp, &signature_rp,
            &validation_rp);

    bool attestation_result_signature_rp_mbedtls = false;
    if (!verify_quote_signature_mbedtls(tpm2_public_key_rp,
                res.attestation_data_rp, res.attestation_data_rp_len,
                &signature_rp, &attestation_result_signature_rp_mbedtls)) {
        goto cleanup;
    }

    /* unmarshal Quote_r's attestation data -- needed to get at its
     * pcrDigest for the log_r checks right below */
    TPMS_ATTEST attest_struct_rp = {0};
    attestation_rc = charra_unmarshal_tpm2_quote(res.attestation_data_rp_len,
            res.attestation_data_rp, &attest_struct_rp);
    if (attestation_rc != CHARRA_RC_SUCCESS) {
        charra_log_error(
                "[" LOG_NAME "] Error while unmarshaling RP TPM2 Quote.");
        goto cleanup;
    }

    /* --- verify log_r: per-entry self-consistency + PCR replay --- */
    clock_t start_verify_log_r, end_verify_log_r;
    double verify_log_r_duration;
    start_verify_log_r = clock();
    charra_log_info("[" LOG_NAME "] Verifying log_r ...");
    bool attestation_result_log_r_entries = verify_log_r_entries_self_consistent(
            res.event_log, res.event_log_len);
    if (attestation_result_log_r_entries) {
        charra_log_info(
                "[" LOG_NAME "]     => log_r entries are self-consistent!");
    } else {
        charra_log_error("[" LOG_NAME
                         "]     => log_r entries are NOT self-consistent!");
    }
    bool attestation_result_log_r_pcr = verify_log_r_matches_quote_r_pcr(
            res.event_log, res.event_log_len, &attest_struct_rp);
    if (attestation_result_log_r_pcr) {
        charra_log_info(
                "[" LOG_NAME "]     => log_r matches Quote_r's pcrDigest!");
    } else {
        charra_log_error("[" LOG_NAME "]     => log_r does NOT match "
                         "Quote_r's pcrDigest!");
    }
    bool attestation_result_log_r_policy = verify_log_r_file_hashes_against_policy(
            res.event_log, res.event_log_len);
    if (attestation_result_log_r_policy) {
        charra_log_info("[" LOG_NAME "]     => log_r file-content digests "
                        "pass whitelist/blacklist policy!");
    } else {
        charra_log_error("[" LOG_NAME "]     => log_r file-content digests "
                         "do NOT pass whitelist/blacklist policy!");
    }
    end_verify_log_r = clock();
    verify_log_r_duration = ((double) (end_verify_log_r - start_verify_log_r)) / CLOCKS_PER_SEC;
    fprintf(p_file, "verify log_r took %f seconds to execute \n", verify_log_r_duration);

    /* unmarshal attestation data */
    TPMS_ATTEST attest_struct = {0};
    attestation_rc = charra_unmarshal_tpm2_quote(
            res.attestation_data_len, res.attestation_data, &attest_struct);
    if (attestation_rc != CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Error while unmarshaling TPM2 Quote.");
        goto cleanup;
    }

    /* --- verify nonce --- */
    clock_t start_verifiy_nonce, end_verifiy_nonce;
    double verify_nonce_duration;
    start_verifiy_nonce = clock();
    bool attestation_result_nonce = false;
    {
        charra_log_info("[" LOG_NAME "] Verifying nonce ...");
        // TODO: last_request is initialised but never filled with the actual nonce
        // the relying party needs to send the nonce either inside the appraise request or before separately
        attestation_result_nonce = charra_verify_tpm2_quote_qualifying_data(
                last_request.nonce_len, last_request.nonce, &attest_struct);
        if (attestation_result_nonce == true) {
            charra_log_info("[" LOG_NAME "]     => Nonce in TPM Quote is "
                            "valid! (matches the one sent)");
        } else {
            charra_log_error("[" LOG_NAME
                             "]     => Nonce in TPM Quote is NOT valid! (does "
                             "not match the one sent)");
        }
    }
    /* --- verify Quote_r's nonce --- */
    /* Same nonce as Quote_a's, on purpose: RP forwards both quotes in one
     * message, in one attestation session, so Quote_r including the same
     * session nonce as its own extraData proves "I'm responding within
     * THIS session," not replaying an old Quote_r. Reuses the exact
     * mechanism Quote_a's nonce check already uses -- same
     * charra_verify_tpm2_quote_qualifying_data() call, same
     * last_request.nonce global. (That global is the known cross-session
     * fragility tracked as bug #6 -- now read for two purposes instead of
     * one, unchanged risk, not made worse by this.) */
    bool attestation_result_nonce_rp = false;
    {
        charra_log_info("[" LOG_NAME "] Verifying RP nonce ...");
        attestation_result_nonce_rp = charra_verify_tpm2_quote_qualifying_data(
                last_request.nonce_len, last_request.nonce, &attest_struct_rp);
        if (attestation_result_nonce_rp == true) {
            charra_log_info("[" LOG_NAME "]     => Nonce in RP TPM Quote is "
                            "valid! (matches the one sent)");
        } else {
            charra_log_error("[" LOG_NAME
                             "]     => Nonce in RP TPM Quote is NOT valid! "
                             "(does not match the one sent)");
        }
    }
    end_verifiy_nonce = clock();
    verify_nonce_duration = ((double) (end_verifiy_nonce - start_verifiy_nonce)) / CLOCKS_PER_SEC;
    fprintf(p_file, "verify nonce took %f seconds to execute \n", verify_nonce_duration);

    /* --- verify PCRs --- */
    clock_t start_verifiy_pcr, end_verifiy_pcr;
    double verify_pcr_duration;
    start_verifiy_pcr = clock();
    bool attestation_result_pcrs = false;
    {
        charra_log_info("[" LOG_NAME "] Verifying PCRs ...");

        charra_log_info("[" LOG_NAME
                        "] Actual PCR composite digest from TPM Quote is:");
        charra_print_hex(CHARRA_LOG_INFO,
                attest_struct.attested.quote.pcrDigest.size,
                attest_struct.attested.quote.pcrDigest.buffer,                         
                "                        0x", "\n",
                false);

        CHARRA_RC pcr_check = charra_check_pcr_digest_against_reference(
                reference_pcr_file_path, tpm_pcr_selection,
                tpm_pcr_selection_len, &attest_struct);
        if (pcr_check == CHARRA_RC_SUCCESS) {
            charra_log_info(
                    "[" LOG_NAME "]     => PCR composite digest is valid!");
            attestation_result_pcrs = true;
        } else {
            charra_log_error(
                    "[" LOG_NAME
                    "]     => PCR composite digest is NOT valid! (does "
                    "not match any of the digests from the set of reference "
                    "PCRs)");
        }
    }
    end_verifiy_pcr = clock();
    verify_pcr_duration = ((double) (end_verifiy_pcr - start_verifiy_pcr)) / CLOCKS_PER_SEC;
    fprintf(p_file, "verify pcr took %f seconds to execute \n", verify_pcr_duration);
    /* The old placeholder "verify event log" block that used to sit here --
     * gated on use_ima_event_log, hex-dumped res.event_log, always passed
     * except on a missing log, and was explicitly marked
     * "TODO(any): Implement real verification" -- is gone. It was a stand-in
     * for exactly what verify_log_r_entries_self_consistent() and
     * verify_log_r_matches_quote_r_pcr() now do for real, unconditionally,
     * above. Keeping both would mean a fake check sitting next to the real
     * one. */

    /* --- output result --- */

    bool attestation_result = attestation_result_signature &&
                              attestation_result_signature_mbedtls &&
                              attestation_result_signature_rp &&
                              attestation_result_signature_rp_mbedtls &&
                              attestation_result_log_r_entries &&
                              attestation_result_log_r_pcr &&
                              attestation_result_log_r_policy &&
                              attestation_result_nonce &&
                              attestation_result_nonce_rp &&
                              attestation_result_pcrs;


    const char* message;
    /* print attestation result */
    charra_log_info("[" LOG_NAME "] +----------------------------+");
    if (attestation_result) {
        attestation_rc = CHARRA_RC_SUCCESS;
        message = "Attestation successful!\0";
        charra_log_info("[" LOG_NAME "] |   ATTESTATION SUCCESSFUL   |");
    } else {
        attestation_rc = CHARRA_RC_VERIFICATION_FAILED;
        message = "Attestation failed!    \0";
        charra_log_info("[" LOG_NAME "] |     ATTESTATION FAILED     |");
    }
    charra_log_info("[" LOG_NAME "] +----------------------------+");

    coap_pdu_set_code(response, COAP_RESPONSE_CODE_CONTENT);
    
    end_appraise = clock();
    appraise_duration = ((double) (end_appraise - start_appraise)) / CLOCKS_PER_SEC;


    fprintf(p_file, "appraising took %f seconds to execute \n", appraise_duration);
    double total_measured = unmarshal_duration + init_duration + load_duration + verify_nonce_duration + verify_signature_duration + verify_pcr_duration + verify_log_r_duration;
    fprintf(p_file, "total measured %f  \n", total_measured);

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
    if (sig_key_handle_rp != ESYS_TR_NONE) {
        if (Esys_FlushContext(esys_ctx, sig_key_handle_rp) != TSS2_RC_SUCCESS) {
            charra_log_error(
                    "[" LOG_NAME "] TSS cleanup sig_key_handle_rp failed.");
        }
    }

    /* free event log (log_r) */
    // TODO(any): Provide function charra_free_msg_rp_appraisal_dto().
    charra_free_if_not_null(res.event_log);

    /* free ESAPI objects */
    if (validation != NULL) {
        Esys_Free(validation);
    }
    if (validation_rp != NULL) {
        Esys_Free(validation_rp);
    }

    /* finalize ESAPI & TCTI */
    if (esys_ctx != NULL) {
        Esys_Finalize(&esys_ctx);
    }
    if (tcti_ctx != NULL) {
        Tss2_TctiLdr_Finalize(&tcti_ctx);
    }

}

static void coap_nonce_handler(struct coap_resource_t* resource CHARRA_UNUSED,
                                struct coap_session_t* session CHARRA_UNUSED,
                                const struct coap_pdu_t* request,
                                const struct coap_string_t* query CHARRA_UNUSED,
                                struct coap_pdu_t* response CHARRA_UNUSED) {
    CHARRA_RC charra_r = CHARRA_RC_SUCCESS;
    int coap_r = 0;

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

    /* nonce */
    if (req.nonce_len > sizeof(TPMU_HA)) {
        charra_log_error("[" LOG_NAME "] Nonce too long.");
        goto error;
    }
    TPM2B_DATA qualifying_data = {.size = 0, .buffer = {0}};
    qualifying_data.size = req.nonce_len;
    memcpy(qualifying_data.buffer, req.nonce, req.nonce_len);
    last_request = req;

error:
    return;
}
