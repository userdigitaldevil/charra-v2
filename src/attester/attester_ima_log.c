/**
 * @file attester_ima_log.c
 * @brief See attester_ima_log.h.
 *
 * Reads the Attester's IMA measurement log, converts it from ASCII to the
 * binary TLV form the rest of CHARRA parses, and replays it into the TPM's
 * PCRs. Owns the converted log: the PCRs are extended from exactly these
 * bytes, so every /attest response has to carry exactly these bytes.
 */


#include "attester_ima_log.h"
#include "../common/charra_log.h"
#include <coap3/coap.h>

#include "../core/charra_dto.h"
#include "../core/charra_event_log.h"
#include "../util/hex_util.h"
#include "../util/io_util.h"
#include "../util/tpm2_util.h"

#define LOG_NAME "attester"

/* The binary IMA log, converted once and then reused: the PCRs are extended
 * from these exact bytes, so every response must carry these exact bytes. */
static uint8_t* cached_ima_log = NULL;
static uint32_t cached_ima_log_len = 0;

/**
 * @brief Serializes one ima-ng entry's template_data into buf.
 *
 * The ima-ng layout is two length-prefixed fields:
 *
 *     u32 len | "<alg>:" '\0' <file-digest>    (the d-ng field)
 *     u32 len | "<path>" '\0'                  (the n-ng field)
 *
 * The colon belongs to the stored prefix -- the kernel writes "sha256:" NUL,
 * not "sha256" NUL, which is why a sha256 d-ng field is 44 bytes and not 43.
 * Omitting it parsed fine here but broke every consumer that assumed the
 * kernel's layout: the ZK circuit rejects the entry outright, and the ASCII
 * emitter rendered "sha2569c89..." with no separator.
 *
 * @return the number of bytes written, or 0 if buf_len is too small.
 */
static uint32_t build_ima_ng_template_data(const char* alg,
        const uint8_t* file_digest, uint32_t file_digest_len, const char* path,
        uint8_t* buf, uint32_t buf_len) {
    /* strlen(alg) + ':' + NUL */
    const uint32_t alg_len = (uint32_t)strlen(alg) + 2;
    const uint32_t d_len = alg_len + file_digest_len;
    const uint32_t n_len = (uint32_t)strlen(path) + 1; /* includes NUL */
    const uint32_t total = sizeof(uint32_t) + d_len + sizeof(uint32_t) + n_len;
    if (total > buf_len) {
        return 0;
    }

    uint32_t offset = 0;
    charra_event_log_append_u32(buf, &offset, d_len);
    charra_event_log_append_bytes(buf, &offset, alg, (uint32_t)strlen(alg));
    charra_event_log_append_bytes(buf, &offset, ":", 2); /* ':' and its NUL */
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
                !charra_hex_decode(
                        file_hash_hex, TPM2_SHA256_DIGEST_SIZE, file_digest)) {
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

CHARRA_RC charra_extend_pcrs_from_binary_log(
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
CHARRA_RC charra_get_ima_log(
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
