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

/** Literal prefix the redacted template_data always starts with -- see
 * charra_sdk.h's "known limitation" for why this is hardcoded rather than
 * carrying the original algorithm name through. */
static const char REDACTED_PREFIX[] = "sha256:";
#define REDACTED_PREFIX_LEN (sizeof(REDACTED_PREFIX) - 1 /* no NUL */)
#define REDACTED_TEMPLATE_DATA_LEN                                           \
    (REDACTED_PREFIX_LEN + TPM2_SHA256_DIGEST_SIZE + TPM2_SHA256_DIGEST_SIZE)

/**
 * @brief Locate the file-content digest and the path inside template_data
 * (the "sha256:" / "sha1:" + file digest + NUL + path layout).
 *
 * The prefix length depends on which algorithm produced the file digest --
 * derived from digest_len rather than hardcoded, so this handles either
 * template_data shape produced by charra_synth_generate_ima_log() (always
 * "sha256:") or a genuine SHA-1-shaped ima-ng entry (used only to correctly
 * skip past it; see the caller for what happens with a SHA-1 digest).
 *
 * file_digest_out and path_out are set independently: an entry can be too
 * short to contain a path but still long enough to contain the digest
 * (nothing after it), or too short for either. Both cases return NULL for
 * the piece that isn't there rather than reading out of bounds -- this can
 * legitimately happen on an already-redacted or synthetic-with-no-data
 * entry.
 */
static void extract_file_digest_and_path(const charra_event_log_entry* entry,
        uint16_t digest_len, const uint8_t** file_digest_out,
        const uint8_t** path_out, uint32_t* path_len_out) {
    const char* prefix =
            (digest_len == TPM2_SHA256_DIGEST_SIZE) ? "sha256:" : "sha1:";
    uint32_t prefix_len = (uint32_t)strlen(prefix);

    *file_digest_out = (entry->template_data_len >= prefix_len + digest_len)
            ? entry->template_data + prefix_len
            : NULL;

    uint32_t skip = prefix_len + digest_len + 1 /* NUL */;
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
    /* Known limitation (see charra_sdk.h): the redacted prefix is hardcoded
     * to "sha256:" and the preserved file-content digest is assumed to
     * already be 32 bytes. Reject rather than mishandle a SHA-1 log. */
    if (digest_len != TPM2_SHA256_DIGEST_SIZE) {
        return CHARRA_RC_MARSHALING_ERROR;
    }

    /* First pass: count entries only, to size the output buffer. Redacted
     * template_data is always exactly REDACTED_TEMPLATE_DATA_LEN bytes,
     * independent of how large the ORIGINAL template_data was, so this
     * bound cannot be derived from raw_log_len alone -- an entry with a
     * very short original template_data could still expand after
     * redaction. */
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
            + sizeof(uint32_t) + REDACTED_TEMPLATE_DATA_LEN;  /* data */

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

        const uint8_t* file_digest = NULL;
        const uint8_t* path = NULL;
        uint32_t path_len = 0;
        extract_file_digest_and_path(
                &entry, digest_len, &file_digest, &path, &path_len);

        /* Path is sensitive -- only its hash survives. File-content digest
         * is not -- it's preserved as-is. A missing file_digest (template_data
         * too short to contain it -- an already-redacted or
         * synthetic-with-no-data entry, same tolerance the old code had for
         * a missing path) falls back to an all-zero digest rather than
         * failing the whole log. */
        static const uint8_t empty_buf[1] = {0};
        static const uint8_t zero_digest[TPM2_SHA256_DIGEST_SIZE] = {0};
        uint8_t path_hash[TPM2_SHA256_DIGEST_SIZE] = {0};
        rc = hash_sha256(
                path_len, (path != NULL) ? path : empty_buf, path_hash);
        if (rc != CHARRA_RC_SUCCESS) {
            free(buf);
            return rc;
        }

        uint8_t new_template_data[REDACTED_TEMPLATE_DATA_LEN];
        uint32_t td_offset = 0;
        charra_event_log_append_bytes(new_template_data, &td_offset,
                REDACTED_PREFIX, REDACTED_PREFIX_LEN);
        charra_event_log_append_bytes(new_template_data, &td_offset,
                (file_digest != NULL) ? file_digest : zero_digest,
                TPM2_SHA256_DIGEST_SIZE);
        charra_event_log_append_bytes(
                new_template_data, &td_offset, path_hash, sizeof(path_hash));

        /* template_digest = SHA256(new template_data) -- recomputed, per
         * the design's requirement, from the REDACTED content, not copied
         * from the original entry. */
        uint8_t new_digest[TPM2_SHA256_DIGEST_SIZE] = {0};
        rc = hash_sha256(sizeof(new_template_data), new_template_data,
                new_digest);
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
        charra_event_log_append_u32(
                buf, &out_offset, sizeof(new_template_data));
        charra_event_log_append_bytes(buf, &out_offset, new_template_data,
                sizeof(new_template_data));
    }

    uint8_t* trimmed = realloc(buf, out_offset);
    *redacted_log_out = (trimmed != NULL) ? trimmed : buf;
    *redacted_log_len_out = out_offset;

    return CHARRA_RC_SUCCESS;
}
