/**
 * @file charra_sdk.c
 * @brief The Verifier's redaction "SDK". See charra_sdk.h.
 */

#include "charra_sdk.h"

#include <stdlib.h>
#include <string.h>

#include <tss2/tss2_tpm2_types.h>

#include "../util/crypto_util.h"
#include "charra_event_log.h"

/**
 * @brief Skip the "sha256:" / "sha1:" + file-digest + NUL prefix inside
 * template_data, leaving only the path.
 *
 * The prefix length depends on which algorithm produced the file digest --
 * derived from digest_len rather than hardcoded, so this handles either
 * template_data shape produced by charra_synth_generate_ima_log() (always
 * "sha256:") or a genuine SHA-1-shaped ima-ng entry.
 *
 * If template_data is too short to contain the expected prefix (e.g.
 * already empty), the path is treated as empty rather than reading out of
 * bounds -- this can legitimately happen on an already-redacted or
 * synthetic-with-no-data entry.
 */
static void extract_path(const charra_event_log_entry* entry,
        uint16_t digest_len, const uint8_t** path_out,
        uint32_t* path_len_out) {
    const char* prefix =
            (digest_len == TPM2_SHA256_DIGEST_SIZE) ? "sha256:" : "sha1:";
    uint32_t skip = (uint32_t)strlen(prefix) + digest_len + 1 /* NUL */;

    if (entry->template_data_len > skip) {
        *path_out = entry->template_data + skip;
        *path_len_out = entry->template_data_len - skip;
    } else {
        *path_out = NULL;
        *path_len_out = 0;
    }
}

CHARRA_RC charra_sdk_redact_ima_log(const uint8_t* raw_log,
        uint32_t raw_log_len, uint8_t** redacted_log_out,
        uint32_t* redacted_log_len_out) {
    if (redacted_log_out == NULL || redacted_log_len_out == NULL) {
        return CHARRA_RC_BAD_ARGUMENT;
    }
    if (raw_log == NULL && raw_log_len != 0) {
        return CHARRA_RC_BAD_ARGUMENT;
    }

    if (raw_log_len == 0) {
        *redacted_log_out = NULL;
        *redacted_log_len_out = 0;
        return CHARRA_RC_SUCCESS;
    }

    uint16_t digest_len = 0;
    CHARRA_RC rc = charra_event_log_ima_detect_digest_len(
            raw_log, raw_log_len, &digest_len);
    if (rc != CHARRA_RC_SUCCESS) {
        return rc;
    }

    /* First pass: count entries only, to size the output buffer. Redacted
     * template_data is always exactly TPM2_SHA256_DIGEST_SIZE bytes (a hash
     * of the path), independent of how large the ORIGINAL template_data
     * was, so this bound cannot be derived from raw_log_len alone -- an
     * entry with a very short original template_data could still expand
     * after redaction. */
    uint32_t num_entries = 0;
    {
        uint32_t offset = 0;
        while (offset < raw_log_len) {
            charra_event_log_entry entry = {0};
            rc = charra_event_log_parse_entry(
                    raw_log, raw_log_len, &offset, digest_len, &entry);
            if (rc != CHARRA_RC_SUCCESS) {
                return rc;
            }
            num_entries++;
        }
    }

    uint32_t max_entry_len = sizeof(uint32_t)      /* pcr_index */
            + TPM2_SHA256_DIGEST_SIZE               /* template_digest */
            + sizeof(uint32_t) + CHARRA_IMA_TEMPLATE_NAME_MAX /* name */
            + sizeof(uint32_t) + TPM2_SHA256_DIGEST_SIZE;     /* data */

    uint8_t* buf = malloc((size_t)max_entry_len * num_entries);
    if (buf == NULL) {
        return CHARRA_RC_ERROR;
    }

    uint32_t out_offset = 0;
    uint32_t offset = 0;
    while (offset < raw_log_len) {
        charra_event_log_entry entry = {0};
        rc = charra_event_log_parse_entry(
                raw_log, raw_log_len, &offset, digest_len, &entry);
        if (rc != CHARRA_RC_SUCCESS) {
            free(buf);
            return rc;
        }

        const uint8_t* path = NULL;
        uint32_t path_len = 0;
        extract_path(&entry, digest_len, &path, &path_len);

        /* "hash the filepath to cleanse the entry": the redacted
         * template_data is nothing but this hash -- no prefix, no
         * separator, no trace of the original path or its length. */
        static const uint8_t empty_buf[1] = {0};
        uint8_t path_hash[TPM2_SHA256_DIGEST_SIZE] = {0};
        rc = hash_sha256(
                path_len, (path != NULL) ? path : empty_buf, path_hash);
        if (rc != CHARRA_RC_SUCCESS) {
            free(buf);
            return rc;
        }

        /* template_digest = SHA256(new template_data) -- recomputed, per
         * the design's requirement, from the REDACTED content, not copied
         * from the original entry. */
        uint8_t new_digest[TPM2_SHA256_DIGEST_SIZE] = {0};
        rc = hash_sha256(
                sizeof(path_hash), path_hash, new_digest);
        if (rc != CHARRA_RC_SUCCESS) {
            free(buf);
            return rc;
        }

        charra_event_log_append_u32(buf, &out_offset, entry.pcr_index);
        charra_event_log_append_bytes(
                buf, &out_offset, new_digest, sizeof(new_digest));
        charra_event_log_append_u32(
                buf, &out_offset, entry.template_name_len);
        charra_event_log_append_bytes(buf, &out_offset, entry.template_name,
                entry.template_name_len);
        charra_event_log_append_u32(buf, &out_offset, sizeof(path_hash));
        charra_event_log_append_bytes(
                buf, &out_offset, path_hash, sizeof(path_hash));
    }

    uint8_t* trimmed = realloc(buf, out_offset);
    *redacted_log_out = (trimmed != NULL) ? trimmed : buf;
    *redacted_log_len_out = out_offset;

    return CHARRA_RC_SUCCESS;
}
