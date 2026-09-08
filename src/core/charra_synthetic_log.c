/**
 * @file charra_synthetic_log.c
 * @brief Synthetic IMA event log generation. See charra_synthetic_log.h.
 */

#include "charra_synthetic_log.h"

#include <stdlib.h>
#include <string.h>

#include <tss2/tss2_tpm2_types.h>

#include "../util/crypto_util.h"
#include "charra_event_log.h"

static const char TEMPLATE_NAME[] = "ima-ng";

/* Plausible-looking sensitive paths, cycled through by entry index. Nothing
 * here is real; the point is only that a redaction routine has something
 * worth stripping to verify against. */
static const char* const FAKE_SENSITIVE_PATHS[] = {
        "/home/finance/payroll_2024.csv",
        "/etc/company/api_keys.conf",
        "/var/lib/customer_database/records.db",
        "/home/admin/.ssh/id_rsa",
        "/opt/internal/source/proprietary_algorithm.c",
        "/home/hr/employee_ssn_list.xlsx",
        "/etc/vpn/client_certificates.pem",
        "/var/backups/production_db_dump.sql",
};
#define NUM_FAKE_PATHS \
    (sizeof(FAKE_SENSITIVE_PATHS) / sizeof(FAKE_SENSITIVE_PATHS[0]))

/**
 * @brief A fabricated, deterministic 32-byte "file digest" for one entry.
 *
 * Not a real file hash -- there is no real file. Derived from (seed, index)
 * via SHA256 purely so it looks like plausible digest bytes and is
 * reproducible, not because it needs any cryptographic property.
 */
static CHARRA_RC make_fake_file_digest(
        uint32_t seed, uint32_t index, uint8_t out[TPM2_SHA256_DIGEST_SIZE]) {
    uint8_t material[8];
    material[0] = (uint8_t)(seed & 0xff);
    material[1] = (uint8_t)((seed >> 8) & 0xff);
    material[2] = (uint8_t)((seed >> 16) & 0xff);
    material[3] = (uint8_t)((seed >> 24) & 0xff);
    material[4] = (uint8_t)(index & 0xff);
    material[5] = (uint8_t)((index >> 8) & 0xff);
    material[6] = (uint8_t)((index >> 16) & 0xff);
    material[7] = (uint8_t)((index >> 24) & 0xff);

    return hash_sha256(sizeof(material), material, out);
}

CHARRA_RC charra_synth_generate_ima_log(uint32_t num_entries, uint32_t seed,
        uint8_t** log_out, uint32_t* log_len_out) {
    if (num_entries == 0 || log_out == NULL || log_len_out == NULL) {
        return CHARRA_RC_BAD_ARGUMENT;
    }

    /* "sha256:" AND its NUL -- CHARRA_IMA_ALGO_PREFIX_LEN is 8, not 7. The
     * synthetic log has to match what a real kernel writes byte for byte,
     * or the golden redaction the Verifier computes here would only ever
     * agree with logs this file produced. */
    static const char ALGO_PREFIX[] = CHARRA_IMA_ALGO_PREFIX;
    /* upper bound: use the longest path in the pool for every entry, since
     * actual entries will only ever be shorter */
    uint32_t max_path_len = 0;
    for (size_t i = 0; i < NUM_FAKE_PATHS; ++i) {
        uint32_t len = (uint32_t)strlen(FAKE_SENSITIVE_PATHS[i]);
        if (len > max_path_len) {
            max_path_len = len;
        }
    }
    /* real ima-ng template_data is two length-prefixed fields:
     * d-ng = u32 len + ("sha256:" NUL + digest), n-ng = u32 len + path NUL */
    uint32_t max_d_field_len =
            (uint32_t)CHARRA_IMA_ALGO_PREFIX_LEN + TPM2_SHA256_DIGEST_SIZE;
    uint32_t max_n_field_len = max_path_len + 1 /* NUL */;
    uint32_t max_template_data_len = sizeof(uint32_t) + max_d_field_len +
                                      sizeof(uint32_t) + max_n_field_len;
    uint32_t max_entry_len = sizeof(uint32_t) /* pcr_index */
            + TPM2_SHA256_DIGEST_SIZE                 /* template_digest */
            + sizeof(uint32_t) + (sizeof(TEMPLATE_NAME) - 1) /* name */
            + sizeof(uint32_t) + max_template_data_len;       /* data */

    uint8_t* buf = malloc((size_t)max_entry_len * num_entries);
    if (buf == NULL) {
        return CHARRA_RC_ERROR;
    }

    uint32_t offset = 0;
    for (uint32_t i = 0; i < num_entries; ++i) {
        uint8_t file_digest[TPM2_SHA256_DIGEST_SIZE] = {0};
        CHARRA_RC rc = make_fake_file_digest(seed, i, file_digest);
        if (rc != CHARRA_RC_SUCCESS) {
            free(buf);
            return rc;
        }

        const char* path = FAKE_SENSITIVE_PATHS[i % NUM_FAKE_PATHS];
        uint32_t path_len = (uint32_t)strlen(path);

        /* template_data = u32(d_len) + "sha256:" NUL + file_digest
         *               + u32(n_len) + path + '\0'
         * -- real ima-ng's two length-prefixed field pair, not a flat blob */
        uint32_t d_content_len =
                (uint32_t)CHARRA_IMA_ALGO_PREFIX_LEN + TPM2_SHA256_DIGEST_SIZE;
        uint32_t n_content_len = path_len + 1 /* NUL */;
        uint32_t template_data_len = sizeof(uint32_t) + d_content_len +
                                      sizeof(uint32_t) + n_content_len;
        uint8_t* template_data = malloc(template_data_len);
        if (template_data == NULL) {
            free(buf);
            return CHARRA_RC_ERROR;
        }
        uint32_t td_off = 0;
        charra_event_log_append_u32(template_data, &td_off, d_content_len);
        memcpy(template_data + td_off, ALGO_PREFIX,
                CHARRA_IMA_ALGO_PREFIX_LEN);
        td_off += (uint32_t)CHARRA_IMA_ALGO_PREFIX_LEN;
        memcpy(template_data + td_off, file_digest, TPM2_SHA256_DIGEST_SIZE);
        td_off += TPM2_SHA256_DIGEST_SIZE;
        charra_event_log_append_u32(template_data, &td_off, n_content_len);
        memcpy(template_data + td_off, path, path_len);
        td_off += path_len;
        template_data[td_off++] = '\0';

        /* template_digest = SHA256(template_data), exactly as IMA computes
         * it -- this is what makes the generated log valid replay input */
        uint8_t template_digest[TPM2_SHA256_DIGEST_SIZE] = {0};
        rc = hash_sha256(template_data_len, template_data, template_digest);
        if (rc != CHARRA_RC_SUCCESS) {
            free(template_data);
            free(buf);
            return rc;
        }

        charra_event_log_append_u32(buf, &offset, CHARRA_IMA_PCR_INDEX);
        charra_event_log_append_bytes(
                buf, &offset, template_digest, TPM2_SHA256_DIGEST_SIZE);
        charra_event_log_append_u32(
                buf, &offset, (uint32_t)(sizeof(TEMPLATE_NAME) - 1));
        charra_event_log_append_bytes(
                buf, &offset, TEMPLATE_NAME, sizeof(TEMPLATE_NAME) - 1);
        charra_event_log_append_u32(buf, &offset, template_data_len);
        charra_event_log_append_bytes(
                buf, &offset, template_data, template_data_len);

        free(template_data);
    }

    /* trim the allocation down to the exact amount actually written */
    uint8_t* trimmed = realloc(buf, offset);
    *log_out = (trimmed != NULL) ? trimmed : buf;
    *log_len_out = offset;

    return CHARRA_RC_SUCCESS;
}
