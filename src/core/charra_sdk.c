/**
 * @file charra_sdk.c
 * @brief IMA event log redaction. See charra_sdk.h.
 */

#include "charra_sdk.h"

#include "charra_poseidon.h"
#include "charra_zk.h"

#include <stdlib.h>
#include <string.h>

#include <tss2/tss2_tpm2_types.h>

#include "../common/charra_log.h"
#include "../util/charra_util.h"
#include "../util/crypto_util.h"
#include "charra_event_log.h"

#define LOG_NAME "sdk"

/**
 * @brief Split an ima-ng template_data into its two length-prefixed fields.
 *
 * The d-ng field is returned including its own u32 length prefix, since it
 * is copied through verbatim and re-emitted exactly as it arrived. The n-ng
 * field is returned as its contents only -- the path -- because only the
 * contents are replaced.
 *
 * @returns false if template_data is not a well-formed pair of
 * length-prefixed fields.
 */
static bool split_ima_ng_fields(const charra_event_log_entry* entry,
        const uint8_t** d_field_out, uint32_t* d_field_len_out,
        const uint8_t** path_out, uint32_t* path_len_out) {
    const uint8_t* data = entry->template_data;
    const uint32_t len = entry->template_data_len;

    if (data == NULL || len < sizeof(uint32_t)) {
        return false;
    }
    /* d-ng: u32 length prefix followed by that many bytes */
    uint32_t d_len = (uint32_t)data[0] | ((uint32_t)data[1] << 8) |
                     ((uint32_t)data[2] << 16) | ((uint32_t)data[3] << 24);
    if (d_len > len - sizeof(uint32_t)) {
        return false;
    }
    const uint32_t d_field_len = sizeof(uint32_t) + d_len;

    /* n-ng: u32 length prefix followed by the path */
    if (len - d_field_len < sizeof(uint32_t)) {
        return false;
    }
    const uint8_t* n = data + d_field_len;
    uint32_t n_len = (uint32_t)n[0] | ((uint32_t)n[1] << 8) |
                     ((uint32_t)n[2] << 16) | ((uint32_t)n[3] << 24);
    if (n_len > len - d_field_len - sizeof(uint32_t)) {
        return false;
    }

    *d_field_out = data;
    *d_field_len_out = d_field_len;
    *path_out = n + sizeof(uint32_t);
    *path_len_out = n_len;
    return true;
}

/**
 * @brief redacted_path = SHA256(path || salt). salt is mandatory -- callers
 * decide where it comes from: charra_sdk_redact_ima_log() generates a
 * fresh one right before every call (never reused, never transmitted),
 * charra_sdk_redact_ima_log_with_salt() passes the same caller-given salt
 * to every call. This function itself has no notion of "no salt given".
 */
static CHARRA_RC hash_path_with_salt(const uint8_t* path, uint32_t path_len,
        const uint8_t salt[CHARRA_SDK_PATH_SALT_LEN],
        uint8_t out[CHARRA_SDK_REDACTED_PATH_LEN]) {
    uint8_t* buf = malloc((size_t)path_len + CHARRA_SDK_PATH_SALT_LEN);
    if (buf == NULL) {
        return CHARRA_RC_ERROR;
    }
    if (path_len > 0) {
        memcpy(buf, path, path_len);
    }
    memcpy(buf + path_len, salt, CHARRA_SDK_PATH_SALT_LEN);

    CHARRA_RC charra_r = hash_sha256(
            (size_t)path_len + CHARRA_SDK_PATH_SALT_LEN, buf, out);
    free(buf);
    return (charra_r == CHARRA_RC_SUCCESS) ? CHARRA_RC_SUCCESS
                                           : CHARRA_RC_CRYPTO_ERROR;
}

/**
 * @brief Redact one already-parsed entry using entry_salt and append the
 * result to buf at *out_offset, advancing it. Shared by both public
 * redaction functions below -- they differ only in where entry_salt comes
 * from for each entry (a fresh one every call, or always the same one).
 */
/**
 * @brief Redact one entry, optionally collecting the ZK witness for it.
 *
 * `witness_out` does double duty: non-NULL means "ZK mode", which selects
 * Poseidon over SHA-256 for the commitment as well as capturing the path and
 * salt. The two go together and only together -- the circuit can only check a
 * Poseidon commitment, and nothing but the prover ever wants the witness --
 * so coupling them is what keeps qualify and TEE producing byte-identical
 * output to what they produced before ZK mode existed.
 */
static CHARRA_RC redact_one_entry(const charra_event_log_entry* entry,
        uint32_t entry_num,
        const uint8_t entry_salt[CHARRA_SDK_PATH_SALT_LEN], uint8_t* buf,
        uint32_t* out_offset, charra_zk_entry* witness_out) {
    const uint8_t* d_field = NULL;
    uint32_t d_field_len = 0;
    const uint8_t* path = NULL;
    uint32_t path_len = 0;
    if (!split_ima_ng_fields(
                entry, &d_field, &d_field_len, &path, &path_len)) {
        charra_log_error("[" LOG_NAME "] Entry %u's template_data is not a "
                         "well-formed ima-ng field pair.",
                entry_num);
        return CHARRA_RC_MARSHALING_ERROR;
    }

    uint8_t redacted_path[CHARRA_SDK_REDACTED_PATH_LEN] = {0};
    CHARRA_RC charra_r;
    if (witness_out != NULL) {
        if (path_len > CHARRA_POSEIDON_MAX_PATH) {
            charra_log_error("[" LOG_NAME "] Entry %u's path is %u bytes; the "
                             "ZK circuit accepts at most %u. Raise MAX_PATH "
                             "in the circuit, recompile, and redistribute "
                             "zk/vk.",
                    entry_num, path_len, (unsigned)CHARRA_POSEIDON_MAX_PATH);
            return CHARRA_RC_BAD_ARGUMENT;
        }
        charra_r = charra_poseidon_commit(
                path, path_len, entry_salt, redacted_path);
    } else {
        charra_r = hash_path_with_salt(
                path, path_len, entry_salt, redacted_path);
    }
    if (charra_r != CHARRA_RC_SUCCESS) {
        return charra_r;
    }

    if (witness_out != NULL) {
        /* The proof needs exactly what redaction is about to throw away. All
         * of this is secret except file_hash: it must never be marshaled. */
        memset(witness_out, 0, sizeof(*witness_out));
        memcpy(witness_out->path, path, path_len);
        witness_out->path_len = path_len;
        memcpy(witness_out->salt, entry_salt, CHARRA_SDK_PATH_SALT_LEN);
        memcpy(witness_out->commitment, redacted_path,
                CHARRA_SDK_REDACTED_PATH_LEN);
        /* d_field spans its own u32 length prefix too, so the layout is
         *   0..3  d_len | 4..10 "sha256\0" | 11..42 the digest
         * and the circuit wants those last 32 bytes. Reading from 7 lands in
         * the middle of the algorithm name -- which is exactly what happened
         * the first time, and it surfaces only as "pcrdigest_a mismatch"
         * inside the circuit, so it is worth being explicit here. */
        if (d_field_len == sizeof(uint32_t) + 7 + 32) {
            memcpy(witness_out->file_hash, d_field + sizeof(uint32_t) + 7, 32);
        } else {
            charra_log_error("[" LOG_NAME "] Entry %u's d-ng field is %u bytes, "
                             "not the %zu a sha256 ima-ng entry has. The ZK "
                             "circuit cannot describe it.",
                    entry_num, d_field_len, sizeof(uint32_t) + 7 + 32);
            return CHARRA_RC_MARSHALING_ERROR;
        }
    }

    /* new template_data = d-ng verbatim || u32(32) || redacted path */
    const uint32_t new_td_len =
            d_field_len + sizeof(uint32_t) + CHARRA_SDK_REDACTED_PATH_LEN;
    uint8_t* new_template_data = malloc(new_td_len);
    if (new_template_data == NULL) {
        return CHARRA_RC_ERROR;
    }
    uint32_t td_offset = 0;
    charra_event_log_append_bytes(
            new_template_data, &td_offset, d_field, d_field_len);
    charra_event_log_append_u32(
            new_template_data, &td_offset, CHARRA_SDK_REDACTED_PATH_LEN);
    charra_event_log_append_bytes(new_template_data, &td_offset,
            redacted_path, CHARRA_SDK_REDACTED_PATH_LEN);

    /* template_digest = SHA256(new template_data), recomputed from the
     * REDACTED content -- never copied from the original entry. */
    uint8_t new_digest[TPM2_SHA256_DIGEST_SIZE] = {0};
    charra_r = hash_sha256(new_td_len, new_template_data, new_digest);
    if (charra_r != CHARRA_RC_SUCCESS) {
        free(new_template_data);
        return CHARRA_RC_CRYPTO_ERROR;
    }

    charra_event_log_append_u32(buf, out_offset, entry->pcr_index);
    charra_event_log_append_bytes(
            buf, out_offset, new_digest, sizeof(new_digest));
    charra_event_log_append_u32(buf, out_offset, entry->template_name_len);
    charra_event_log_append_bytes(
            buf, out_offset, entry->template_name, entry->template_name_len);
    charra_event_log_append_u32(buf, out_offset, new_td_len);
    charra_event_log_append_bytes(
            buf, out_offset, new_template_data, new_td_len);
    free(new_template_data);
    return CHARRA_RC_SUCCESS;
}

/**
 * @brief The whole redaction. `witness` non-NULL means ZK mode: Poseidon
 * commitments, and every path and salt collected for the prover.
 */
static CHARRA_RC redact_log(const uint8_t* raw_log, uint32_t raw_log_len,
        const uint8_t salt[CHARRA_SDK_PATH_SALT_LEN],
        uint8_t** redacted_log_out, uint32_t* redacted_log_len_out,
        charra_zk_witness* witness) {
    if (redacted_log_out == NULL || redacted_log_len_out == NULL) {
        return CHARRA_RC_BAD_ARGUMENT;
    }
    if (raw_log == NULL && raw_log_len != 0) {
        return CHARRA_RC_BAD_ARGUMENT;
    }

    *redacted_log_out = NULL;
    *redacted_log_len_out = 0;
    if (raw_log_len == 0) {
        return CHARRA_RC_SUCCESS;
    }

    uint16_t digest_len = 0;
    CHARRA_RC charra_r = charra_event_log_ima_detect_digest_len(
            raw_log, raw_log_len, &digest_len);
    if (charra_r != CHARRA_RC_SUCCESS) {
        return charra_r;
    }

    /* A redacted entry is never larger than its original: the d-ng field is
     * copied verbatim, and the n-ng field shrinks to a fixed 32 bytes unless
     * the original path was shorter than that. Size for the worst case --
     * every path shorter than its hash -- plus the digest possibly growing
     * from SHA-1 to SHA-256. */
    uint32_t num_entries = 0;
    {
        uint32_t offset = 0;
        while (offset < raw_log_len) {
            charra_event_log_entry entry = {0};
            charra_r = charra_event_log_parse_entry(
                    raw_log, raw_log_len, &offset, digest_len, &entry);
            if (charra_r != CHARRA_RC_SUCCESS) {
                return charra_r;
            }
            num_entries++;
        }
    }
    const size_t slack = (size_t)num_entries *
                         (CHARRA_SDK_REDACTED_PATH_LEN + TPM2_SHA256_DIGEST_SIZE);
    uint8_t* buf = malloc((size_t)raw_log_len + slack);
    if (buf == NULL) {
        return CHARRA_RC_ERROR;
    }

    uint32_t out_offset = 0;
    uint32_t offset = 0;
    uint32_t entry_num = 0;
    while (offset < raw_log_len) {
        charra_event_log_entry entry = {0};
        charra_r = charra_event_log_parse_entry(
                raw_log, raw_log_len, &offset, digest_len, &entry);
        if (charra_r != CHARRA_RC_SUCCESS) {
            goto error;
        }

        /* entry_salt is either the one caller-given salt (every entry, so
         * output is reproducible -- the qualification-handshake case) or a
         * fresh one generated right here for just this entry, never reused
         * or transmitted (the real-evidence case) -- see charra_sdk.h. */
        uint8_t entry_salt[CHARRA_SDK_PATH_SALT_LEN] = {0};
        if (salt != NULL) {
            memcpy(entry_salt, salt, CHARRA_SDK_PATH_SALT_LEN);
        } else if (charra_random_bytes(CHARRA_SDK_PATH_SALT_LEN, entry_salt) !=
                CHARRA_RC_SUCCESS) {
            charra_log_error("[" LOG_NAME "] Could not generate a path salt.");
            charra_r = CHARRA_RC_CRYPTO_ERROR;
            goto error;
        }

        charra_zk_entry* slot = NULL;
        if (witness != NULL) {
            if (entry_num >= CHARRA_ZK_MAX_ENTRIES) {
                charra_log_error("[" LOG_NAME "] Log has more than %u entries; "
                                 "the ZK circuit cannot prove it. Raise N in "
                                 "zk/circuit/src/main.nr, recompile, and "
                                 "redistribute zk/vk.",
                        (unsigned)CHARRA_ZK_MAX_ENTRIES);
                charra_r = CHARRA_RC_BAD_ARGUMENT;
                goto error;
            }
            slot = &witness->entries[entry_num];
        }

        charra_r = redact_one_entry(
                &entry, entry_num, entry_salt, buf, &out_offset, slot);
        if (charra_r != CHARRA_RC_SUCCESS) {
            goto error;
        }
        entry_num++;
    }
    if (witness != NULL) {
        witness->num_entries = entry_num;
    }

    *redacted_log_out = buf;
    *redacted_log_len_out = out_offset;
    charra_log_info("[" LOG_NAME "] Redacted %u entries, %s commitments "
                    "(%u bytes in, %u out).",
            entry_num, (witness != NULL) ? "Poseidon" : "SHA-256", raw_log_len,
            out_offset);
    return CHARRA_RC_SUCCESS;

error:
    free(buf);
    if (witness != NULL) {
        /* Never leave half a witness behind: it holds real paths and salts,
         * and a partial one would silently prove the wrong thing. */
        memset(witness, 0, sizeof(*witness));
    }
    return charra_r;
}

CHARRA_RC charra_sdk_redact_ima_log(const uint8_t* raw_log,
        uint32_t raw_log_len, const uint8_t salt[CHARRA_SDK_PATH_SALT_LEN],
        uint8_t** redacted_log_out, uint32_t* redacted_log_len_out) {
    return redact_log(raw_log, raw_log_len, salt, redacted_log_out,
            redacted_log_len_out, NULL);
}

CHARRA_RC charra_sdk_redact_ima_log_with_witness(const uint8_t* raw_log,
        uint32_t raw_log_len, uint8_t** redacted_log_out,
        uint32_t* redacted_log_len_out, charra_zk_witness* witness) {
    if (witness == NULL) {
        return CHARRA_RC_BAD_ARGUMENT;
    }
    memset(witness, 0, sizeof(*witness));
    /* Always a fresh per-entry salt: the shared-salt path exists only for the
     * qualification handshake, which does not run in ZK mode. */
    return redact_log(raw_log, raw_log_len, NULL, redacted_log_out,
            redacted_log_len_out, witness);
}
