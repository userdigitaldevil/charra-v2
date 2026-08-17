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
#include "util/io_util.h"
#include "util/tpm2_util.h"

#define CHARRA_UNUSED __attribute__((unused))

/* --- config ------------------------------------------------------------- */

/* quit signal */
static bool quit = false;

/* Counts /attest calls this Attester process has served, purely for the
 * log delimiter coap_attest_handler() prints -- one /attest call happens
 * per RP benchmark cycle (its evidence is reused across every Verifier
 * that cycle forwards to, see relying_party.c's charra_rp_prepare_
 * evidence()), so this gives an easy-to-scan boundary in a multi-cycle
 * log, the same way verifier.c's attestation_round_counter and
 * relying_party.c's "Starting new attestation run" delimiter do. */
static unsigned int attest_request_counter = 0;

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
/* The binary IMA log, converted once and then reused: the PCRs are extended
 * from these exact bytes, so every response must carry these exact bytes. */
static uint8_t* cached_ima_log = NULL;
static uint32_t cached_ima_log_len = 0;
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

static void release_data(
        struct coap_session_t* session CHARRA_UNUSED, void* app_ptr);

static void coap_attest_handler(struct coap_resource_t* resource,
                                struct coap_session_t* session,
                                const struct coap_pdu_t* request,
                                const struct coap_string_t* query,
                                struct coap_pdu_t* response);

/**
 * @brief Converts an ASCII IMA measurement log ("PCR <idx> <digest> ima-ng
 * <alg>:<hash> <path>" per line) into the binary TLV format the rest of
 * CHARRA parses.
 *
 * template_data is rebuilt in the real ima-ng layout and template_digest is
 * recomputed as SHA256(template_data), so the resulting log satisfies its
 * own self-consistency check by construction.
 *
 * @param[in] path the ASCII log to read
 * @param[out] log_out malloc'd binary log; caller frees
 * @param[out] log_len_out length of log_out
 * @return CHARRA_RC_SUCCESS, CHARRA_RC_MARSHALING_ERROR if the file holds no
 * parseable ASCII entries (i.e. it is not an ASCII log), otherwise an error.
 */
CHARRA_RC charra_ima_log_ascii_to_binary(
        const char* path, uint8_t** log_out, uint32_t* log_len_out);

/**
 * @brief Extends every entry of a binary IMA log into the PCR it names.
 *
 * @param esys_ctx[in,out] The ESAPI context.
 */
static CHARRA_RC charra_extend_pcrs_from_binary_log(
        ESYS_CONTEXT* esys_ctx, const uint8_t* log, uint32_t log_len);

/**
 * @brief Returns the Attester's binary IMA log, loading and caching it on
 * first use.
 */
static CHARRA_RC charra_get_ima_log(
        const char* path, const uint8_t** log_out, uint32_t* log_len_out);

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
            coap_context, COAP_REQUEST_FETCH, "attest", coap_attest_handler);
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
 * @brief Logs the requesting peer's address:port for a CoAP handler --
 * useful once more than one RP can hit one Attester, to tell which
 * physical connection a given cycle's log lines belong to. Same helper
 * verifier.c added for the same reason.
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

/**
 * @brief Formats a TPML_PCR_SELECTION's selected PCR indices (across all
 * its banks) as a compact "0,1,2,...,10" string, purely for logging what
 * was actually quoted -- easier to eyeball than cross-referencing the RP's
 * own request log for the same information.
 */
static void format_pcr_selection(
        const TPML_PCR_SELECTION* sel, char* out, size_t out_len) {
    size_t pos = 0;
    out[0] = '\0';
    for (UINT32 b = 0; b < sel->count && pos < out_len; ++b) {
        const TPMS_PCR_SELECTION* bank = &sel->pcrSelections[b];
        for (int i = 0; i < bank->sizeofSelect * 8 && pos < out_len; ++i) {
            if (bank->pcrSelect[i / 8] & (1 << (i % 8))) {
                int written = snprintf(out + pos, out_len - pos, "%s%d",
                        (pos == 0) ? "" : ",", i);
                if (written < 0) {
                    break;
                }
                pos += (size_t)written;
            }
        }
    }
}

static void release_data(
        struct coap_session_t* session CHARRA_UNUSED, void* app_ptr) {
    charra_free_and_null(app_ptr);
}

/**
 * @brief Converts one ASCII hex character to its value, or -1 if it is not a
 * hex digit.
 */
static int hex_nibble(const char c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

/**
 * @brief Decodes hex_len ASCII hex characters into out_len bytes.
 *
 * @return true on success, false if the lengths disagree or a non-hex
 * character is encountered.
 */
static bool hex_str_to_bytes(const char* hex, const size_t hex_len,
        uint8_t* out, const size_t out_len) {
    if (hex == NULL || out == NULL || hex_len != out_len * 2) {
        return false;
    }
    for (size_t i = 0; i < out_len; ++i) {
        const int hi = hex_nibble(hex[2 * i]);
        const int lo = hex_nibble(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) {
            return false;
        }
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return true;
}

/**
 * @brief Serializes one ima-ng entry's template_data into buf.
 *
 * The ima-ng layout is two length-prefixed fields:
 *
 *     u32 len | "<alg>" '\0' <file-digest>     (the d-ng field)
 *     u32 len | "<path>" '\0'                  (the n-ng field)
 *
 * @return the number of bytes written, or 0 if buf_len is too small.
 */
static uint32_t build_ima_ng_template_data(const char* alg,
        const uint8_t* file_digest, uint32_t file_digest_len, const char* path,
        uint8_t* buf, uint32_t buf_len) {
    const uint32_t alg_len = (uint32_t)strlen(alg) + 1; /* includes NUL */
    const uint32_t d_len = alg_len + file_digest_len;
    const uint32_t n_len = (uint32_t)strlen(path) + 1; /* includes NUL */
    const uint32_t total = sizeof(uint32_t) + d_len + sizeof(uint32_t) + n_len;
    if (total > buf_len) {
        return 0;
    }

    uint32_t offset = 0;
    charra_event_log_append_u32(buf, &offset, d_len);
    charra_event_log_append_bytes(buf, &offset, alg, alg_len);
    charra_event_log_append_bytes(buf, &offset, file_digest, file_digest_len);
    charra_event_log_append_u32(buf, &offset, n_len);
    charra_event_log_append_bytes(buf, &offset, path, n_len);
    return offset;
}

CHARRA_RC charra_ima_log_ascii_to_binary(
        const char* path, uint8_t** log_out, uint32_t* log_len_out) {
    if (path == NULL || log_out == NULL || log_len_out == NULL) {
        return CHARRA_RC_BAD_ARGUMENT;
    }
    *log_out = NULL;
    *log_len_out = 0;

    FILE* file = fopen(path, "r");
    if (file == NULL) {
        return CHARRA_RC_ERROR;
    }

    CHARRA_RC charra_r = CHARRA_RC_SUCCESS;
    uint8_t* log = NULL;
    uint32_t log_len = 0;
    uint32_t capacity = 0;
    uint32_t line_no = 0;
    uint32_t entries = 0;
    /* long enough for the longest path an ima-ng entry can carry */
    char line[4096] = {0};

    while (fgets(line, sizeof(line), file) != NULL) {
        ++line_no;

        /* Entries look like
         *     PCR <index> <template-digest> ima-ng <alg>:<file-hash> <path>
         * Accept the same line without the leading "PCR" token too, since
         * the kernel's own ascii_runtime_measurements omits it. */
        char tag[16] = {0};
        char unused_digest[TPM2_SHA256_DIGEST_SIZE * 2 + 1] = {0};
        char template_name[CHARRA_IMA_TEMPLATE_NAME_MAX] = {0};
        char alg_and_hash[TPM2_SHA256_DIGEST_SIZE * 2 + 32] = {0};
        char file_path[2048] = {0};
        unsigned int pcr_idx = 0;
        int scanned = sscanf(line, "%15s %u %64s %63s %95s %2047s", tag,
                &pcr_idx, unused_digest, template_name, alg_and_hash,
                file_path);
        if (scanned != 6 || strcmp(tag, "PCR") != 0) {
            scanned = sscanf(line, "%u %64s %63s %95s %2047s", &pcr_idx,
                    unused_digest, template_name, alg_and_hash, file_path);
            if (scanned != 5) {
                continue; /* blank line or comment */
            }
        }

        /* split "<alg>:<hex-file-hash>" */
        char* colon = strchr(alg_and_hash, ':');
        if (colon == NULL) {
            charra_log_warn("[" LOG_NAME "] Skipping line %u: no \"<alg>:<hash>\""
                            " field.",
                    line_no);
            continue;
        }
        *colon = '\0';
        const char* alg = alg_and_hash;
        const char* file_hash_hex = colon + 1;
        const size_t file_hash_hex_len = strlen(file_hash_hex);
        uint8_t file_digest[TPM2_SHA256_DIGEST_SIZE] = {0};
        if (file_hash_hex_len != TPM2_SHA256_DIGEST_SIZE * 2 ||
                !hex_str_to_bytes(file_hash_hex, file_hash_hex_len, file_digest,
                        TPM2_SHA256_DIGEST_SIZE)) {
            charra_log_warn("[" LOG_NAME "] Skipping line %u: file hash is not "
                            "a valid 32 byte hex digest.",
                    line_no);
            continue;
        }

        uint8_t template_data[4096] = {0};
        const uint32_t template_data_len = build_ima_ng_template_data(alg,
                file_digest, TPM2_SHA256_DIGEST_SIZE, file_path, template_data,
                sizeof(template_data));
        if (template_data_len == 0) {
            charra_log_warn("[" LOG_NAME "] Skipping line %u: template data "
                            "does not fit.",
                    line_no);
            continue;
        }

        /* The template digest is recomputed here rather than taken from the
         * file. The digests in the ASCII file are not reproducible from the
         * fields it shows -- see EDITS.md -- so keeping them would make the
         * log permanently fail its own self-consistency check. Recomputing
         * makes template_digest == SHA256(template_data) hold by
         * construction, which is exactly the property the Relying Party
         * checks. */
        uint8_t template_digest[TPM2_SHA256_DIGEST_SIZE] = {0};
        if (hash_sha256(template_data_len, template_data, template_digest) !=
                CHARRA_RC_SUCCESS) {
            charra_log_error(
                    "[" LOG_NAME "] Hashing template data of line %u failed.",
                    line_no);
            charra_r = CHARRA_RC_CRYPTO_ERROR;
            goto cleanup;
        }

        const uint32_t name_len = (uint32_t)strlen(template_name);
        const uint32_t entry_len = sizeof(uint32_t) /* pcr_index */
                                   + TPM2_SHA256_DIGEST_SIZE /* digest */
                                   + sizeof(uint32_t) + name_len
                                   + sizeof(uint32_t) + template_data_len;
        if (log_len + entry_len > capacity) {
            capacity = (capacity == 0) ? 8192 : capacity * 2;
            while (log_len + entry_len > capacity) {
                capacity *= 2;
            }
            uint8_t* grown = realloc(log, capacity);
            if (grown == NULL) {
                charra_log_error("[" LOG_NAME "] Out of memory building log.");
                charra_r = CHARRA_RC_ERROR;
                goto cleanup;
            }
            log = grown;
        }

        uint32_t offset = log_len;
        charra_event_log_append_u32(log, &offset, pcr_idx);
        charra_event_log_append_bytes(
                log, &offset, template_digest, TPM2_SHA256_DIGEST_SIZE);
        charra_event_log_append_u32(log, &offset, name_len);
        charra_event_log_append_bytes(log, &offset, template_name, name_len);
        charra_event_log_append_u32(log, &offset, template_data_len);
        charra_event_log_append_bytes(
                log, &offset, template_data, template_data_len);
        log_len = offset;
        ++entries;
    }

    if (entries == 0) {
        /* not an ASCII log we understand; let the caller fall back */
        charra_r = CHARRA_RC_MARSHALING_ERROR;
        goto cleanup;
    }

    charra_log_info("[" LOG_NAME "] Converted %u ASCII IMA entries from \"%s\" "
                    "into %u bytes of binary log.",
            entries, path, log_len);
    *log_out = log;
    *log_len_out = log_len;
    fclose(file);
    return CHARRA_RC_SUCCESS;

cleanup:
    free(log);
    fclose(file);
    return charra_r;
}

static CHARRA_RC charra_extend_pcrs_from_binary_log(
        ESYS_CONTEXT* esys_ctx, const uint8_t* log, uint32_t log_len) {
    if (esys_ctx == NULL) {
        charra_log_error("[" LOG_NAME "] Bad ESAPI context.");
        return CHARRA_RC_ERROR;
    }
    if (log_len == 0) {
        return CHARRA_RC_SUCCESS;
    }

    uint16_t digest_len = 0;
    if (charra_event_log_ima_detect_digest_len(log, log_len, &digest_len) !=
            CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Could not detect log digest size.");
        return CHARRA_RC_ERROR;
    }

    uint32_t offset = 0;
    uint32_t entries = 0;
    while (offset < log_len) {
        charra_event_log_entry entry = {0};
        if (charra_event_log_parse_entry(
                    log, log_len, &offset, digest_len, &entry) !=
                CHARRA_RC_SUCCESS) {
            charra_log_error(
                    "[" LOG_NAME "] Malformed entry %u in log.", entries);
            return CHARRA_RC_MARSHALING_ERROR;
        }

        /* A digest shorter than 32 bytes is zero-padded into the SHA-256
         * bank, exactly as charra_pcr_extend() does when the same log is
         * replayed in software -- the replayed value must equal what the TPM
         * holds or appraisal can never match. */
        /* clang-format off */
        TPML_DIGEST_VALUES digests = {
            .count = 1,
            .digests = {{
                .hashAlg = TPM2_ALG_SHA256,
            }},
        };
        /* clang-format on */
        memcpy(digests.digests[0].digest.sha256, entry.template_digest,
                entry.template_digest_len);

        if (tpm2_pcr_extend(esys_ctx, entry.pcr_index, &digests) !=
                TSS2_RC_SUCCESS) {
            charra_log_error("[" LOG_NAME "] Could not extend PCR %u with "
                             "entry %u.",
                    entry.pcr_index, entries);
            return CHARRA_RC_ERROR;
        }
        ++entries;
    }

    charra_log_info("[" LOG_NAME "] Extended %u IMA log entries into the PCRs.",
            entries);
    return CHARRA_RC_SUCCESS;
}

/**
 * @brief Loads the Attester's IMA log, converting it from ASCII if needed.
 *
 * The result is cached in a file-scope buffer: the PCRs are extended from it
 * once, and every attestation response must then send back exactly those
 * bytes, or a replay of the log could not reproduce PCR 10.
 */
static CHARRA_RC charra_get_ima_log(
        const char* path, const uint8_t** log_out, uint32_t* log_len_out) {
    if (cached_ima_log != NULL) {
        *log_out = cached_ima_log;
        *log_len_out = cached_ima_log_len;
        return CHARRA_RC_SUCCESS;
    }

    /* Try the ASCII form first; a real binary log has no parseable ASCII
     * entries and falls through to being read verbatim. */
    uint8_t* log = NULL;
    uint32_t log_len = 0;
    if (charra_ima_log_ascii_to_binary(path, &log, &log_len) ==
            CHARRA_RC_SUCCESS) {
        cached_ima_log = log;
        cached_ima_log_len = log_len;
        *log_out = cached_ima_log;
        *log_len_out = cached_ima_log_len;
        return CHARRA_RC_SUCCESS;
    }

    uint8_t* raw = NULL;
    size_t raw_len = 0;
    if (charra_io_read_continuous_binary_file(path, &raw, &raw_len) !=
            CHARRA_RC_SUCCESS) {
        charra_log_warn(
                "[" LOG_NAME "] Could not read IMA log \"%s\".", path);
        return CHARRA_RC_ERROR;
    }
    cached_ima_log = raw;
    cached_ima_log_len = (uint32_t)raw_len;
    *log_out = cached_ima_log;
    *log_len_out = cached_ima_log_len;
    return CHARRA_RC_SUCCESS;
}

static void coap_attest_handler(struct coap_resource_t* resource,
                                struct coap_session_t* session,
                                const struct coap_pdu_t* request,
                                const struct coap_string_t* query,
                                struct coap_pdu_t* response) {
    CHARRA_RC charra_r = CHARRA_RC_SUCCESS;
    int coap_r = 0;
    TSS2_RC tss_r = 0;
    ESYS_TR sig_key_handle = ESYS_TR_NONE;
    TPM2B_PUBLIC* public_key = NULL;
    /* Declared here (rather than right before first use, further down) and
     * initialized to NULL so that every earlier 'goto error' -- including
     * the "Could not get CoAP PDU data" one right below -- leaves the
     * error: cleanup block able to safely check them instead of reading
     * indeterminate values. Skipping over a declaration with an
     * initializer does not run that initializer; branching on or freeing
     * an indeterminate pointer is undefined behavior. Mirrors verifier.c's
     * coap_appraise_handler(), fixed for the exact same reason in an
     * earlier audit round. */
    ESYS_CONTEXT* esys_ctx = NULL;
    TSS2_TCTI_CONTEXT* tcti_ctx = NULL;
    TPM2B_ATTEST* attest_buf = NULL;
    TPMT_SIGNATURE* signature = NULL;
    /* Set true only right before falling through to the cleanup label on
     * the success path below -- every 'goto error' skips that line, so
     * this distinguishes "evidence actually sent" from any of the many
     * failure exits for the closing status banner. */
    bool request_succeeded = false;

    /* Clear delimiter between benchmark cycles -- one /attest call happens
     * per cycle (see attest_request_counter's own comment), so this marks
     * where one cycle's evidence generation ends and the next begins, the
     * same way verifier.c's and relying_party.c's own delimiters do. */
    attest_request_counter++;
    charra_log_info("[" LOG_NAME
                    "] ============================================================");
    charra_log_info("[" LOG_NAME "] Starting /attest request #%u.",
            attest_request_counter);
    charra_log_info("[" LOG_NAME
                    "] ============================================================");
    log_peer_address("/attest", session);

    /* --- receive incoming data --- */
    charra_log_info(
            "[" LOG_NAME "] Resource '%s': Received message.", "attest");
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
    } else if (data_len == data_total_len) {
        /* the common case: no block-wise splitting happened, so the two
         * lengths are identical -- collapsed into one line instead of two
         * redundant ones */
        charra_log_info(
                "[" LOG_NAME "] Received attestation request of %zu byte(s).",
                data_len);
    } else {
        charra_log_info(
                "[" LOG_NAME "] Received attestation request: %zu byte(s) "
                "of %zu byte(s) total (block-wise transfer).",
                data_len, data_total_len);
    }

    /* unmarshal data */
    charra_log_info("[" LOG_NAME "] Parsing received CBOR data.");
    msg_attestation_request_dto req = {0};
    if ((charra_r = charra_unmarshal_attestation_request(
                 data_len, data, &req)) != CHARRA_RC_SUCCESS) {
        charra_log_error(
                "[" LOG_NAME "] Could not parse CBOR data: CHARRA_RC=%d.",
                charra_r);
        goto error;
    }

    /* --- TPM quote --- */

    charra_log_info("[" LOG_NAME "] Preparing TPM quote data.");

    /* nonce */
    if (req.nonce_len > sizeof(TPMU_HA)) {
        charra_log_error("[" LOG_NAME "] Nonce too long.");
        goto error;
    }
    TPM2B_DATA qualifying_data = {.size = 0, .buffer = {0}};
    qualifying_data.size = req.nonce_len;
    memcpy(qualifying_data.buffer, req.nonce, req.nonce_len);

    charra_log_info("[" LOG_NAME "] Received nonce of length %zu:", req.nonce_len);
    charra_print_hex(CHARRA_LOG_INFO, req.nonce_len, req.nonce,
            "                                   0x", "\n", false);

    charra_log_info(
            "[" LOG_NAME "] Signing key ID: '%.*s'.",
            (int)req.sig_key_id_len, req.sig_key_id);

    /* PCR selection */
    TPML_PCR_SELECTION pcr_selection = {0};
    if ((charra_r = charra_pcr_selections_to_tpm_pcr_selections(
                 req.pcr_selections_len, req.pcr_selections, &pcr_selection)) !=
            CHARRA_RC_SUCCESS) {
        charra_log_error(
                "[" LOG_NAME "] PCR selection conversion error: "
                "CHARRA_RC=%d.",
                charra_r);
        goto error;
    }
    {
        char pcr_list[128] = {0};
        format_pcr_selection(&pcr_selection, pcr_list, sizeof(pcr_list));
        charra_log_info(
                "[" LOG_NAME "] Quoting PCR(s): %s.", pcr_list);
    }

    struct timespec start_time, end_time;
    double duration;
    clock_gettime(CLOCK_MONOTONIC, &start_time);

    /* initialize ESAPI */
    const char* charra_tcti = getenv("CHARRA_TCTI");
    charra_log_info("[" LOG_NAME "] CHARRA_TCTI = '%s'.",
            (charra_tcti != NULL) ? charra_tcti : "(null)");
    if ((tss_r = Tss2_TctiLdr_Initialize(charra_tcti, &tcti_ctx)) !=
            TSS2_RC_SUCCESS) {
        charra_log_error(
                "[" LOG_NAME "] Tss2_TctiLdr_Initialize failed: 0x%x.",
                tss_r);
        goto error;
    }
    if ((tss_r = Esys_Initialize(&esys_ctx, tcti_ctx, NULL)) !=
            TSS2_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Esys_Initialize failed: 0x%x.",
                tss_r);
        goto error;
    }

    /* Extend the IMA log into the PCRs, once per process: PCRs 0-15 cannot
     * be reset without a reboot, so replaying the log on every request would
     * keep growing PCR 10 and no single replay of the log could reproduce
     * it. */
    static bool ima_log_extended = false;
    if (!ima_log_extended) {
        const uint8_t* log = NULL;
        uint32_t log_len = 0;
        if (charra_get_ima_log(ima_test_log_path, &log, &log_len) ==
                CHARRA_RC_SUCCESS) {
            if ((charra_r = charra_extend_pcrs_from_binary_log(
                         esys_ctx, log, log_len)) != CHARRA_RC_SUCCESS) {
                charra_log_error(
                        "[" LOG_NAME "] Could not extend PCRs from IMA "
                        "log: CHARRA_RC=%d.",
                        charra_r);
                goto error;
            }
        } else {
            charra_log_warn("[" LOG_NAME "] No IMA log available; leaving PCRs "
                            "unextended.");
        }
        ima_log_extended = true;
    } else {
        charra_log_debug(
                "[" LOG_NAME "] PCRs already extended from IMA log earlier "
                "this process's lifetime -- skipping (would grow PCR 10 "
                "further and break replay if repeated).");
    }

    /* load TPM key */
    struct timespec start_key_load, end_key_load;
    clock_gettime(CLOCK_MONOTONIC, &start_key_load);
    charra_log_info("[" LOG_NAME "] Loading TPM key.");
    if ((charra_r = charra_load_tpm2_key(esys_ctx, req.sig_key_id_len,
                 req.sig_key_id, &sig_key_handle, &public_key)) !=
            CHARRA_RC_SUCCESS) {
        charra_log_error(
                "[" LOG_NAME "] Could not load TPM key: CHARRA_RC=%d.",
                charra_r);
        goto error;
    }
    clock_gettime(CLOCK_MONOTONIC, &end_key_load);
    double key_load_duration =
            (end_key_load.tv_sec - start_key_load.tv_sec) +
            (end_key_load.tv_nsec - start_key_load.tv_nsec) / 1e9;
    charra_log_info(
            "[" LOG_NAME "] Timing: TPM key load took %f second(s).",
            key_load_duration);

    /* do the TPM quote */
    struct timespec start_quote, end_quote;
    clock_gettime(CLOCK_MONOTONIC, &start_quote);
    charra_log_info("[" LOG_NAME "] Do TPM Quote.");
    if ((tss_r = tpm2_quote(esys_ctx, sig_key_handle, &pcr_selection,
                 &qualifying_data, &attest_buf, &signature)) !=
            TSS2_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] TPM2 quote failed: 0x%x.", tss_r);
        goto error;
    } else {
        charra_log_info("[" LOG_NAME "] TPM Quote successful.");
    }
    clock_gettime(CLOCK_MONOTONIC, &end_quote);
    double quote_duration = (end_quote.tv_sec - start_quote.tv_sec) +
                            (end_quote.tv_nsec - start_quote.tv_nsec) / 1e9;
    charra_log_info(
            "[" LOG_NAME "] Timing: TPM Quote itself took %f second(s).",
            quote_duration);

    /* The quote's own PCR composite digest, straight from the TPM's signed
     * TPMS_ATTEST -- logged so a PCR mismatch investigation on the
     * Verifier side (comparing this against its own replayed digest) does
     * not require re-deriving it from raw evidence bytes. Best-effort:
     * this is purely informational, so a failure here does not abort the
     * request. */
    {
        TPMS_ATTEST attest_struct = {0};
        if (charra_unmarshal_tpm2_quote(attest_buf->size,
                    attest_buf->attestationData,
                    &attest_struct) == CHARRA_RC_SUCCESS) {
            charra_print_hex(CHARRA_LOG_INFO,
                    attest_struct.attested.quote.pcrDigest.size,
                    attest_struct.attested.quote.pcrDigest.buffer,
                    "[" LOG_NAME "] Quote's PCR composite digest = 0x", "\n",
                    false);
        }
    }

    clock_gettime(CLOCK_MONOTONIC, &end_time);
    duration = (end_time.tv_sec - start_time.tv_sec) + (end_time.tv_nsec - start_time.tv_nsec) / 1e9;

    /* Open file to append duration */
    FILE *file;
    file = fopen("timings_attester.txt", "a");
    if (file == NULL) {
        perror("fopen");
        exit(EXIT_FAILURE);
    }

    /* Write duration to file */
    fprintf(file, "%f\n", duration);
    charra_log_info(
            "[" LOG_NAME "] Timing: total /attest handling took %f "
            "second(s).",
            duration);
    fclose(file);

    /* --- send response data --- */

    /* Send the IMA event log if requested. These are the same bytes the PCRs
     * were extended from -- charra_get_ima_log() caches them -- so replaying
     * the log the Relying Party receives reproduces PCR 10 exactly. */
    const uint8_t* ima_event_log = NULL;
    uint32_t ima_event_log_len = 0;
    if (req.event_log_path_len != 0) {
        char* path = malloc(sizeof(char) * (req.event_log_path_len + 1));
        if (path == NULL) {
            charra_log_error(
                    "[" LOG_NAME "] Could not allocate memory for event "
                    "log path. Sending empty event log!");
            goto skip_event_log;
        }
        memcpy(path, req.event_log_path, req.event_log_path_len);
        path[req.event_log_path_len] = '\0';
        charra_log_info(
                "[" LOG_NAME "] Reading IMA event log from '%s'%s.", path,
                (strcmp(path, ima_test_log_path) == 0)
                        ? " (same file the PCRs were extended from)"
                        : " (DIFFERENT from the IMA log the PCRs were "
                          "extended from -- log_a may not reproduce PCR "
                          "10)");
        CHARRA_RC rc =
                charra_get_ima_log(path, &ima_event_log, &ima_event_log_len);
        free(path);
        if (rc != CHARRA_RC_SUCCESS) {
            charra_log_error("[" LOG_NAME "] Error while reading IMA event "
                             "log. Sending empty event log!");
            ima_event_log_len = 0;
            ima_event_log = NULL;
        } else {
            charra_log_info("[" LOG_NAME
                            "] IMA event log has a size of %u bytes.",
                    ima_event_log_len);
        }
    }
skip_event_log:

    /* prepare response */
    charra_log_info("[" LOG_NAME "] Preparing response.");

    /* prepare response DTO */
    msg_attestation_response_dto res = {
            .attestation_data_len = attest_buf->size,
            .attestation_data = {0},  // must be memcpy'd, see below
            .tpm2_signature_len = sizeof(*signature),
            .tpm2_signature = {0},  // must be memcpy'd, see below
            .tpm2_public_key_len = sizeof(*public_key),
            .tpm2_public_key = {0},  // must be memcpy'd, see below
            .event_log_len = ima_event_log_len,
            /* borrowed from the cache; not freed here */
            .event_log = (uint8_t*)ima_event_log,
    };
    memcpy(res.attestation_data, attest_buf->attestationData,
            res.attestation_data_len);
    memcpy(res.tpm2_signature, signature, res.tpm2_signature_len);
    memcpy(res.tpm2_public_key, public_key, res.tpm2_public_key_len);

    charra_log_info(
            "[" LOG_NAME "] Response components: attestation_data=%u "
            "byte(s), tpm2_signature=%u byte(s), tpm2_public_key=%u "
            "byte(s), event_log=%u byte(s).",
            res.attestation_data_len, res.tpm2_signature_len,
            res.tpm2_public_key_len, res.event_log_len);

    /* clean up */
    charra_free_and_null(signature);
    charra_free_and_null(attest_buf);
    charra_free_and_null(public_key);

    /* marshal response */
    charra_log_info("[" LOG_NAME "] Marshaling response to CBOR.");
    uint32_t res_buf_len = 0;
    uint8_t* res_buf = NULL;
    if ((charra_r = charra_marshal_attestation_response(
                 &res, &res_buf_len, &res_buf)) != CHARRA_RC_SUCCESS) {
        charra_log_error(
                "[" LOG_NAME "] Error marshaling data: CHARRA_RC=%d.",
                charra_r);
        goto error;
    }
    charra_log_info("[" LOG_NAME "] Size of marshaled response is %d bytes.",
            res_buf_len);

    // TODO(any) In case an error occurred, an error respone should be sent.
    // TODO(any): The verifier should be able to handle this error reponse.

    /* add response data to outgoing PDU and send it */
    charra_log_info(
            "[" LOG_NAME
            "] Adding marshaled data to CoAP response PDU and send it.");
    coap_pdu_set_code(response, COAP_RESPONSE_CODE_CONTENT);
    if ((coap_r = coap_add_data_large_response(resource, session, request, response,
                query, COAP_MEDIATYPE_APPLICATION_CBOR, -1, 0,
                res_buf_len, res_buf, release_data, res_buf)) == 0) {
        charra_log_error("[" LOG_NAME
                         "] Error invoking coap_add_data_large_response().");
        goto error;
    }
    charra_log_info("[" LOG_NAME "] Evidence sent to the relying party.");
    request_succeeded = true;

error:
    charra_log_info("[" LOG_NAME "] +----------------------------+");
    if (request_succeeded) {
        charra_log_info("[" LOG_NAME "] |   EVIDENCE GENERATED OK    |");
    } else {
        charra_log_info("[" LOG_NAME "] |   /attest REQUEST FAILED   |");
    }
    charra_log_info("[" LOG_NAME "] +----------------------------+");

    /* free heap objects */
    charra_free_if_not_null(signature);
    charra_free_if_not_null(attest_buf);
    charra_free_if_not_null(public_key);
    /* ima_event_log is owned by the cache in charra_get_ima_log() and lives
     * for the process lifetime -- freeing it here would dangle the cache and
     * change the log between attestations. */

    /* flush handles */
    if (sig_key_handle != ESYS_TR_NONE) {
        if (Esys_FlushContext(esys_ctx, sig_key_handle) != TSS2_RC_SUCCESS) {
            charra_log_error(
                    "[" LOG_NAME "] TSS cleanup sig_key_handle failed.");
        }
    }

    /* finalize ESAPI */
    if (esys_ctx != NULL) {
        Esys_Finalize(&esys_ctx);
    }
    if (tcti_ctx != NULL) {
        Tss2_TctiLdr_Finalize(&tcti_ctx);
    }
}
