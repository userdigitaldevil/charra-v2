
/**
 * @file charra_event_log.c
 * @brief IMA event log replay. See charra_event_log.h.
 */

#include "charra_event_log.h"

#include <stdbool.h>
#include <string.h>

#include "../common/charra_log.h"
#include "../util/crypto_util.h"

#define LOG_NAME "event_log"

/* --- helpers ------------------------------------------------------------ */

/**
 * @brief Read a uint32 in the kernel's native byte order.
 *
 * Read byte-wise rather than casting: the buffer has no alignment guarantee,
 * and an explicit assembly makes the endianness assumption visible instead of
 * silently inheriting the host's.
 */
static uint32_t read_u32(const uint8_t* p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

void charra_event_log_append_u32(
        uint8_t* buf, uint32_t* offset, uint32_t value) {
    buf[*offset + 0] = (uint8_t)(value & 0xff);
    buf[*offset + 1] = (uint8_t)((value >> 8) & 0xff);
    buf[*offset + 2] = (uint8_t)((value >> 16) & 0xff);
    buf[*offset + 3] = (uint8_t)((value >> 24) & 0xff);
    *offset += sizeof(uint32_t);
}

void charra_event_log_append_bytes(
        uint8_t* buf, uint32_t* offset, const void* data, uint32_t len) {
    if (len > 0) {
        memcpy(buf + *offset, data, len);
    }
    *offset += len;
}

/**
 * @brief Parse the entry starting at *offset and advance *offset past it.
 *
 * Bounds checks are written as 'need > log_len - offset'. Since offset is
 * never allowed to exceed log_len, that subtraction cannot underflow, whereas
 * the more natural 'offset + need > log_len' could overflow on a hostile
 * length field and wrongly pass.
 *
 * @returns CHARRA_RC_SUCCESS, or CHARRA_RC_MARSHALING_ERROR if the entry is
 * truncated or structurally implausible.
 */
CHARRA_RC charra_event_log_parse_entry(const uint8_t* log, uint32_t log_len,
        uint32_t* offset, uint16_t digest_len, charra_event_log_entry* out) {
    uint32_t off = *offset;

    /* pcr_index */
    if (sizeof(uint32_t) > log_len - off) {
        return CHARRA_RC_MARSHALING_ERROR;
    }
    out->pcr_index = read_u32(log + off);
    off += sizeof(uint32_t);

    /* template_digest -- fixed size, not length-prefixed */
    if (digest_len > log_len - off) {
        return CHARRA_RC_MARSHALING_ERROR;
    }
    out->template_digest = log + off;
    out->template_digest_len = digest_len;
    off += digest_len;

    /* template_name */
    if (sizeof(uint32_t) > log_len - off) {
        return CHARRA_RC_MARSHALING_ERROR;
    }
    uint32_t name_len = read_u32(log + off);
    off += sizeof(uint32_t);
    if (name_len == 0 || name_len > CHARRA_IMA_TEMPLATE_NAME_MAX) {
        return CHARRA_RC_MARSHALING_ERROR;
    }
    if (name_len > log_len - off) {
        return CHARRA_RC_MARSHALING_ERROR;
    }
    const char* name = (const char*)(log + off);
    /* Template names are short printable ASCII. Checking this is cheap
     * validation on its own, and it is also what makes digest-length
     * detection reliable: a wrong digest length shifts every subsequent
     * field, so the "name" almost always lands on non-printable bytes. */
    for (uint32_t i = 0; i < name_len; ++i) {
        if (name[i] < 0x20 || name[i] > 0x7e) {
            return CHARRA_RC_MARSHALING_ERROR;
        }
    }
    /* The legacy "ima" template omits the data_len field and uses a
     * fixed-size filename slot. Parsing it as if it were length-prefixed
     * would desynchronise every following entry, so reject it outright. */
    if (name_len == 3 && memcmp(name, "ima", 3) == 0) {
        return CHARRA_RC_MARSHALING_ERROR;
    }
    out->template_name = name;
    out->template_name_len = name_len;
    off += name_len;

    /* template_data */
    if (sizeof(uint32_t) > log_len - off) {
        return CHARRA_RC_MARSHALING_ERROR;
    }
    uint32_t data_len = read_u32(log + off);
    off += sizeof(uint32_t);
    if (data_len > log_len - off) {
        return CHARRA_RC_MARSHALING_ERROR;
    }
    out->template_data = (data_len > 0) ? (log + off) : NULL;
    out->template_data_len = data_len;
    off += data_len;

    *offset = off;
    return CHARRA_RC_SUCCESS;
}

/**
 * @brief Check whether the whole log parses cleanly at a given digest length.
 *
 * "Cleanly" means: at least one entry, every entry well-formed, and the last
 * one ending exactly at log_len with no trailing bytes.
 */
static bool log_parses_at(
        const uint8_t* log, uint32_t log_len, uint16_t digest_len) {
    uint32_t offset = 0;
    uint32_t entries = 0;

    while (offset < log_len) {
        charra_event_log_entry entry = {0};
        if (charra_event_log_parse_entry(log, log_len, &offset, digest_len, &entry) !=
                CHARRA_RC_SUCCESS) {
            return false;
        }
        entries++;
    }

    return (entries > 0) && (offset == log_len);
}

/* --- PCR accumulator ---------------------------------------------------- */

void charra_pcr_reset(charra_pcr_accumulator* acc) {
    if (acc == NULL) {
        return;
    }
    memset(acc->value, 0, sizeof(acc->value));
}

CHARRA_RC charra_pcr_extend(charra_pcr_accumulator* acc, const uint8_t* digest,
        uint16_t digest_len) {
    if (acc == NULL || digest == NULL) {
        return CHARRA_RC_BAD_ARGUMENT;
    }
    if (digest_len == 0 || digest_len > TPM2_SHA256_DIGEST_SIZE) {
        return CHARRA_RC_BAD_ARGUMENT;
    }

    /* SHA256(acc || digest). The buffer starts zeroed, so a digest shorter
     * than the bank's digest size is zero-padded on the right, matching what
     * the kernel does when extending a SHA-256 bank with a SHA-1 digest. */
    uint8_t buf[TPM2_SHA256_DIGEST_SIZE * 2] = {0};
    memcpy(buf, acc->value, TPM2_SHA256_DIGEST_SIZE);
    memcpy(buf + TPM2_SHA256_DIGEST_SIZE, digest, digest_len);

    if (hash_sha256(sizeof(buf), buf, acc->value) != CHARRA_RC_SUCCESS) {
        return CHARRA_RC_CRYPTO_ERROR;
    }

    return CHARRA_RC_SUCCESS;
}

/* --- IMA binary log ----------------------------------------------------- */

CHARRA_RC charra_event_log_ima_detect_digest_len(
        const uint8_t* log, uint32_t log_len, uint16_t* digest_len_out) {
    if (log == NULL || log_len == 0 || digest_len_out == NULL) {
        return CHARRA_RC_BAD_ARGUMENT;
    }

    /* SHA-1 first: it is the classic format of binary_runtime_measurements,
     * so on an ambiguous log it is the better guess. */
    static const uint16_t candidates[] = {
            TPM2_SHA1_DIGEST_SIZE, TPM2_SHA256_DIGEST_SIZE};

    uint16_t detected = 0;
    size_t num_matches = 0;
    for (size_t i = 0; i < sizeof(candidates) / sizeof(candidates[0]); ++i) {
        if (log_parses_at(log, log_len, candidates[i])) {
            if (num_matches == 0) {
                detected = candidates[i];
            }
            num_matches++;
        }
    }

    if (num_matches == 0) {
        charra_log_error("[" LOG_NAME
                         "] Event log does not parse at any known template "
                         "digest size (tried %d and %d bytes).",
                TPM2_SHA1_DIGEST_SIZE, TPM2_SHA256_DIGEST_SIZE);
        return CHARRA_RC_MARSHALING_ERROR;
    }
    if (num_matches > 1) {
        charra_log_warn("[" LOG_NAME
                        "] Event log parses at more than one template digest "
                        "size; assuming %d bytes.",
                detected);
    }

    charra_log_debug("[" LOG_NAME "] Detected template digest size: %d bytes.",
            detected);
    *digest_len_out = detected;
    return CHARRA_RC_SUCCESS;
}

/**
 * @brief Parse and replay a whole log at a fixed digest length in one pass.
 *
 * Structurally equivalent to log_parses_at() -- fails whenever that would --
 * but folds matching digests into acc as it goes, so a clean parse does not
 * need to be re-walked afterwards to actually replay it.
 *
 * @returns true iff the entire log parsed cleanly (at least one entry, the
 * last one ending exactly at log_len). acc, *num_entries_out and
 * *num_extended_out are only meaningful when this returns true.
 */
static bool replay_at(const uint8_t* log, uint32_t log_len,
        uint16_t digest_len, uint32_t target_pcr_index,
        charra_pcr_accumulator* acc, uint32_t* num_entries_out,
        uint32_t* num_extended_out) {
    charra_pcr_reset(acc);

    uint32_t offset = 0;
    uint32_t num_entries = 0;
    uint32_t num_extended = 0;
    while (offset < log_len) {
        charra_event_log_entry entry = {0};
        if (charra_event_log_parse_entry(log, log_len, &offset, digest_len, &entry) !=
                CHARRA_RC_SUCCESS) {
            return false;
        }
        num_entries++;

        if (entry.pcr_index != target_pcr_index) {
            continue;
        }

        if (charra_pcr_extend(acc, entry.template_digest,
                    entry.template_digest_len) != CHARRA_RC_SUCCESS) {
            return false;
        }
        num_extended++;
    }

    if (num_entries == 0 || offset != log_len) {
        return false;
    }

    *num_entries_out = num_entries;
    *num_extended_out = num_extended;
    return true;
}

CHARRA_RC charra_replay_ima_log(const uint8_t* log, uint32_t log_len,
        uint32_t target_pcr_index, uint8_t pcr_out[TPM2_SHA256_DIGEST_SIZE]) {
    if (pcr_out == NULL) {
        return CHARRA_RC_BAD_ARGUMENT;
    }
    if (log == NULL && log_len != 0) {
        return CHARRA_RC_BAD_ARGUMENT;
    }

    /* An empty log is well-formed: nothing was measured, so the PCR is
     * still in its power-on state. */
    if (log_len == 0) {
        charra_pcr_accumulator acc = {0};
        charra_pcr_reset(&acc);
        memcpy(pcr_out, acc.value, TPM2_SHA256_DIGEST_SIZE);
        return CHARRA_RC_SUCCESS;
    }

    /* Cheap guess at the digest size from just the first entry, to decide
     * which candidate to try first below. The guess never has to be right:
     * if it is wrong, that candidate's full-log attempt fails cleanly and
     * the other one is tried next. A bad guess costs a second pass, never a
     * false rejection of a genuinely well-formed log. */
    uint16_t candidates[2] = {TPM2_SHA1_DIGEST_SIZE, TPM2_SHA256_DIGEST_SIZE};
    {
        uint32_t peek_offset = 0;
        charra_event_log_entry peek_entry = {0};
        if (charra_event_log_parse_entry(log, log_len, &peek_offset,
                    TPM2_SHA1_DIGEST_SIZE, &peek_entry) != CHARRA_RC_SUCCESS) {
            candidates[0] = TPM2_SHA256_DIGEST_SIZE;
            candidates[1] = TPM2_SHA1_DIGEST_SIZE;
        }
    }

    charra_pcr_accumulator acc = {0};
    for (size_t i = 0; i < sizeof(candidates) / sizeof(candidates[0]); ++i) {
        uint32_t num_entries = 0;
        uint32_t num_extended = 0;
        if (!replay_at(log, log_len, candidates[i], target_pcr_index, &acc,
                    &num_entries, &num_extended)) {
            continue;
        }

        charra_log_debug("[" LOG_NAME
                         "] Detected template digest size: %d bytes.",
                candidates[i]);
        if (num_extended == 0) {
            /* Not an error -- a log may legitimately hold only other PCRs'
             * events -- but if it happens for a non-empty log the target PCR
             * is almost certainly wrong (e.g. a kernel built with a
             * different CONFIG_IMA_MEASURE_PCR_IDX), and the composite
             * digest check will fail with no obvious explanation. Say so
             * here instead. */
            charra_log_warn("[" LOG_NAME
                            "] Event log holds %d entries but none for PCR "
                            "%d; replayed value is the all-zero PCR.",
                    num_entries, target_pcr_index);
        } else {
            charra_log_debug("[" LOG_NAME
                             "] Replayed %d of %d event log entries into PCR "
                             "%d.",
                    num_extended, num_entries, target_pcr_index);
        }

        memcpy(pcr_out, acc.value, TPM2_SHA256_DIGEST_SIZE);
        return CHARRA_RC_SUCCESS;
    }

    charra_log_error("[" LOG_NAME
                     "] Event log does not parse at any known template "
                     "digest size (tried %d and %d bytes).",
            TPM2_SHA1_DIGEST_SIZE, TPM2_SHA256_DIGEST_SIZE);
    return CHARRA_RC_MARSHALING_ERROR;
}
