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
 * @brief commitment = SHA256(dir || salt). salt is mandatory -- callers
 * decide where it comes from: charra_sdk_redact_ima_log() generates a
 * fresh one right before every call (never reused, never transmitted),
 * or passes the same caller-given salt to every entry for the qualification
 * handshake. This function itself has no notion of "no salt given".
 *
 * dir may legitimately be empty -- "/etc" splits into an empty directory and
 * "etc" -- and an empty input still commits, to SHA256(salt). Special-casing
 * it would make two different paths share a redaction.
 */
static CHARRA_RC hash_dir_with_salt(const uint8_t* dir, uint32_t dir_len,
        const uint8_t salt[CHARRA_SDK_PATH_SALT_LEN],
        uint8_t out[CHARRA_SDK_REDACTED_PATH_LEN]) {
    uint8_t* buf = malloc((size_t)dir_len + CHARRA_SDK_PATH_SALT_LEN);
    if (buf == NULL) {
        return CHARRA_RC_ERROR;
    }
    if (dir_len > 0) {
        memcpy(buf, dir, dir_len);
    }
    memcpy(buf + dir_len, salt, CHARRA_SDK_PATH_SALT_LEN);

    CHARRA_RC charra_r =
            hash_sha256((size_t)dir_len + CHARRA_SDK_PATH_SALT_LEN, buf, out);
    free(buf);
    return (charra_r == CHARRA_RC_SUCCESS) ? CHARRA_RC_SUCCESS
                                           : CHARRA_RC_CRYPTO_ERROR;
}

static void hex_encode_lower(const uint8_t* in, uint32_t in_len, uint8_t* out) {
    static const char D[] = "0123456789abcdef";
    for (uint32_t i = 0; i < in_len; i++) {
        out[2 * i] = (uint8_t)D[in[i] >> 4];
        out[2 * i + 1] = (uint8_t)D[in[i] & 0x0f];
    }
}

/**
 * @brief Copy an entry through unchanged.
 *
 * Used for a path with no '/' in it. See charra_sdk.h: rejoining a directory
 * and a filename that were never separated would introduce a leading '/'
 * the Attester never measured.
 */
static void append_entry_verbatim(const charra_event_log_entry* entry,
        uint8_t* buf, uint32_t* out_offset) {
    charra_event_log_append_u32(buf, out_offset, entry->pcr_index);
    charra_event_log_append_bytes(
            buf, out_offset, entry->template_digest, entry->template_digest_len);
    charra_event_log_append_u32(buf, out_offset, entry->template_name_len);
    charra_event_log_append_bytes(
            buf, out_offset, entry->template_name, entry->template_name_len);
    charra_event_log_append_u32(buf, out_offset, entry->template_data_len);
    charra_event_log_append_bytes(
            buf, out_offset, entry->template_data, entry->template_data_len);
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
        const uint8_t entry_salt[CHARRA_SDK_PATH_SALT_LEN], char label,
        uint8_t* buf, uint32_t* out_offset, charra_zk_entry* witness_out) {
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

    /* The n-ng field carries the path's NUL and counts it. Work on the path
     * itself and put the NUL back on the way out. */
    uint32_t plen = path_len;
    while (plen > 0 && path[plen - 1] == '\0') {
        plen--;
    }

    /* Split at the LAST '/': everything before is the directory, everything
     * after is the filename. Keeping all of the leading portion is what
     * makes the join lossless -- "/a//b" gives dir "/a/" and base "b", which
     * rejoins exactly. */
    int64_t slash = -1;
    for (uint32_t i = 0; i < plen; i++) {
        if (path[i] == '/') {
            slash = (int64_t)i;
        }
    }
    if (slash < 0) {
        charra_log_warn("[" LOG_NAME "] Entry %u's path has no '/'; passing it "
                        "through unredacted rather than inventing one.",
                entry_num);
        append_entry_verbatim(entry, buf, out_offset);
        if (witness_out != NULL) {
            /* A verbatim entry has no commitment for the circuit to check,
             * and quietly proving something else is not an option. */
            charra_log_error("[" LOG_NAME "] Entry %u cannot be redacted, so "
                             "no ZK witness can be built for this log.",
                    entry_num);
            return CHARRA_RC_BAD_ARGUMENT;
        }
        return CHARRA_RC_SUCCESS;
    }

    const uint8_t* dir = path;
    const uint32_t dir_len = (uint32_t)slash;
    const uint8_t* base = path + slash + 1;
    const uint32_t base_len = plen - (uint32_t)slash - 1;

    uint8_t commitment[CHARRA_SDK_REDACTED_PATH_LEN] = {0};
    CHARRA_RC charra_r;
    if (witness_out != NULL) {
        if (dir_len > CHARRA_POSEIDON_MAX_PATH) {
            charra_log_error("[" LOG_NAME "] Entry %u's directory is %u bytes; "
                             "the ZK circuit accepts at most %u. Raise "
                             "MAX_PATH in the circuit, recompile, and "
                             "redistribute zk/vk.",
                    entry_num, dir_len, (unsigned)CHARRA_POSEIDON_MAX_PATH);
            return CHARRA_RC_BAD_ARGUMENT;
        }
        charra_r =
                charra_poseidon_commit(dir, dir_len, entry_salt, commitment);
    } else {
        charra_r = hash_dir_with_salt(dir, dir_len, entry_salt, commitment);
    }
    if (charra_r != CHARRA_RC_SUCCESS) {
        return charra_r;
    }

    if (witness_out != NULL) {
        /* The proof needs exactly what redaction is about to throw away --
         * which is now the directory, not the whole path. The filename
         * travels in log_r in the clear, so the circuit will take it as a
         * public input and rejoin the two with '/' to rebuild the record the
         * Attester actually measured. */
        memset(witness_out, 0, sizeof(*witness_out));
        if (dir_len > 0) {
            memcpy(witness_out->path, dir, dir_len);
        }
        witness_out->path_len = dir_len;
        memcpy(witness_out->salt, entry_salt, CHARRA_SDK_PATH_SALT_LEN);
        memcpy(witness_out->commitment, commitment,
                CHARRA_SDK_REDACTED_PATH_LEN);
        /* d_field spans its own u32 length prefix too, so the layout is
         *   0..3  d_len | 4..11 "sha256:" NUL | 12..43 the digest
         * and the circuit wants those last 32 bytes. The prefix is EIGHT
         * bytes -- name, colon, NUL -- not seven; reading from 7 lands on
         * the NUL and shifts the whole digest, which surfaces only as
         * "pcrdigest_a mismatch" inside the circuit. See
         * CHARRA_IMA_ALGO_PREFIX. */
        const uint32_t expect =
                (uint32_t)sizeof(uint32_t) + CHARRA_IMA_ALGO_PREFIX_LEN + 32;
        if (d_field_len == expect) {
            memcpy(witness_out->file_hash,
                    d_field + sizeof(uint32_t) + CHARRA_IMA_ALGO_PREFIX_LEN,
                    32);
        } else {
            charra_log_error("[" LOG_NAME "] Entry %u's d-ng field is %u bytes, "
                             "not the %u a sha256 ima-ng entry has. The ZK "
                             "circuit cannot describe it.",
                    entry_num, d_field_len, expect);
            return CHARRA_RC_MARSHALING_ERROR;
        }
    }

    /* new n-ng contents = hex(commitment) | label | filename | NUL, so the
     * field stays a well-formed NUL-terminated n-ng field and log_r can be
     * re-emitted as a genuine ASCII IMA log. */
    const uint32_t new_n_len =
            CHARRA_SDK_REDACTED_DIR_HEX_LEN + 1 + base_len + 1;
    const uint32_t new_td_len = d_field_len + (uint32_t)sizeof(uint32_t) +
                                new_n_len;
    uint8_t* new_template_data = malloc(new_td_len);
    if (new_template_data == NULL) {
        return CHARRA_RC_ERROR;
    }
    uint32_t td_offset = 0;
    charra_event_log_append_bytes(
            new_template_data, &td_offset, d_field, d_field_len);
    charra_event_log_append_u32(new_template_data, &td_offset, new_n_len);
    hex_encode_lower(commitment, CHARRA_SDK_REDACTED_PATH_LEN,
            new_template_data + td_offset);
    td_offset += CHARRA_SDK_REDACTED_DIR_HEX_LEN;
    new_template_data[td_offset++] = (uint8_t)label;
    if (base_len > 0) {
        memcpy(new_template_data + td_offset, base, base_len);
        td_offset += base_len;
    }
    new_template_data[td_offset++] = '\0';

    /* template_digest recomputed from the REDACTED content -- never copied
     * from the original entry -- and with the SAME algorithm the input log
     * used, so log_r keeps log_a's shape. */
    uint8_t new_digest[TPM2_SHA256_DIGEST_SIZE] = {0};
    const uint16_t digest_len = entry->template_digest_len;
    if (digest_len == TPM2_SHA1_DIGEST_SIZE) {
        charra_r = hash_sha1(new_td_len, new_template_data, new_digest);
    } else {
        charra_r = hash_sha256(new_td_len, new_template_data, new_digest);
    }
    if (charra_r != CHARRA_RC_SUCCESS) {
        free(new_template_data);
        return CHARRA_RC_CRYPTO_ERROR;
    }

    charra_event_log_append_u32(buf, out_offset, entry->pcr_index);
    charra_event_log_append_bytes(buf, out_offset, new_digest, digest_len);
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
        const uint8_t salt[CHARRA_SDK_PATH_SALT_LEN], char label,
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

    /* A redacted entry CAN be larger than its original now: the filename is
     * kept and a 64-character hex commitment replaces the directory, so an
     * entry grows by (64 - dir_len) bytes -- at most 64, when the directory
     * is empty. The template digest keeps the input's width, so it
     * contributes nothing. Size for that worst case, with a digest's worth
     * of margin on top. */
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
    const size_t slack =
            (size_t)num_entries * (CHARRA_SDK_REDACTED_DIR_HEX_LEN +
                                          TPM2_SHA256_DIGEST_SIZE);
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
                &entry, entry_num, entry_salt, label, buf, &out_offset, slot);
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
        char label, uint8_t** redacted_log_out,
        uint32_t* redacted_log_len_out) {
    return redact_log(raw_log, raw_log_len, salt, label, redacted_log_out,
            redacted_log_len_out, NULL);
}

CHARRA_RC charra_sdk_redact_ima_log_with_witness(const uint8_t* raw_log,
        uint32_t raw_log_len, char label, uint8_t** redacted_log_out,
        uint32_t* redacted_log_len_out, charra_zk_witness* witness) {
    if (witness == NULL) {
        return CHARRA_RC_BAD_ARGUMENT;
    }
    memset(witness, 0, sizeof(*witness));
    /* Always a fresh per-entry salt: the shared-salt path exists only for the
     * qualification handshake, which does not run in ZK mode. */
    return redact_log(raw_log, raw_log_len, NULL, label, redacted_log_out,
            redacted_log_len_out, witness);
}
