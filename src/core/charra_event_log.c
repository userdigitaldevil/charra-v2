
/**
 * @file charra_event_log.c
 * @brief IMA event log replay. See charra_event_log.h.
 */

#include "charra_event_log.h"

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../common/charra_log.h"
#include "../util/crypto_util.h"
#include "../util/io_util.h"

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

/* --- log content verification -------------------------------------------- */

bool charra_verify_log_entries_self_consistent(
        const uint8_t* log, uint32_t log_len) {
    if (log_len == 0) {
        /* an empty log has no entries to be inconsistent */
        return true;
    }

    uint16_t digest_len = 0;
    if (charra_event_log_ima_detect_digest_len(log, log_len, &digest_len) !=
            CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Could not detect digest size.");
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
                    "[" LOG_NAME "] Entry %u failed to parse.", entry_num);
            return false;
        }

        /* Which hash produced template_digest is not recorded anywhere; its
         * length is the only signal, and the log is uniform in that. */
        uint8_t computed_digest[TPM2_SHA256_DIGEST_SIZE] = {0};
        CHARRA_RC hash_rc =
                (entry.template_digest_len == TPM2_SHA1_DIGEST_SIZE)
                        ? hash_sha1(entry.template_data_len,
                                  entry.template_data, computed_digest)
                        : hash_sha256(entry.template_data_len,
                                  entry.template_data, computed_digest);
        if (hash_rc != CHARRA_RC_SUCCESS) {
            charra_log_error(
                    "[" LOG_NAME "] Hashing entry %u failed.", entry_num);
            return false;
        }
        if ((entry.template_digest_len != TPM2_SHA1_DIGEST_SIZE &&
                    entry.template_digest_len != TPM2_SHA256_DIGEST_SIZE) ||
                memcmp(computed_digest, entry.template_digest,
                        entry.template_digest_len) != 0) {
            charra_log_error(
                    "[" LOG_NAME "] Entry %u's template_digest does NOT "
                    "match SHA256(template_data).",
                    entry_num);
            return false;
        }
        entry_num++;
    }
    return true;
}

CHARRA_RC charra_replay_ima_log_pcrs(const uint8_t* log, uint32_t log_len,
        const uint8_t* pcr_selection, uint32_t pcr_selection_len,
        charra_pcr_accumulator* pcrs_out) {
    if ((log == NULL && log_len != 0) || pcr_selection == NULL ||
            pcrs_out == NULL || pcr_selection_len == 0) {
        return CHARRA_RC_BAD_ARGUMENT;
    }

    /* Every selected PCR starts at its power-on value. Entries then extend
     * whichever PCR each one names, so a PCR no entry mentions simply stays
     * all-zero -- which is exactly the state the Attester's TPM is in for
     * that PCR, given it too was only ever extended from this log. */
    for (uint32_t i = 0; i < pcr_selection_len; i++) {
        charra_pcr_reset(&pcrs_out[i]);
    }
    if (log_len == 0) {
        return CHARRA_RC_SUCCESS;
    }

    uint16_t digest_len = 0;
    if (charra_event_log_ima_detect_digest_len(log, log_len, &digest_len) !=
            CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Could not detect digest size.");
        return CHARRA_RC_MARSHALING_ERROR;
    }

    uint32_t offset = 0;
    uint32_t entry_num = 0;
    while (offset < log_len) {
        charra_event_log_entry entry = {0};
        if (charra_event_log_parse_entry(
                    log, log_len, &offset, digest_len, &entry) !=
                CHARRA_RC_SUCCESS) {
            charra_log_error(
                    "[" LOG_NAME "] Entry %u failed to parse.", entry_num);
            return CHARRA_RC_MARSHALING_ERROR;
        }

        /* find which slot of the selection this entry's PCR occupies */
        bool selected = false;
        for (uint32_t i = 0; i < pcr_selection_len; i++) {
            if (pcr_selection[i] != entry.pcr_index) {
                continue;
            }
            if (charra_pcr_extend(&pcrs_out[i], entry.template_digest,
                        entry.template_digest_len) != CHARRA_RC_SUCCESS) {
                charra_log_error("[" LOG_NAME "] Extending PCR %u with entry "
                                 "%u failed.",
                        entry.pcr_index, entry_num);
                return CHARRA_RC_CRYPTO_ERROR;
            }
            selected = true;
            break;
        }
        /* An entry for an unselected PCR cannot affect the composite digest,
         * so it is skipped rather than treated as an error. */
        if (!selected) {
            charra_log_debug("[" LOG_NAME "] Entry %u targets unselected PCR "
                             "%u; skipped.",
                    entry_num, entry.pcr_index);
        }
        entry_num++;
    }
    return CHARRA_RC_SUCCESS;
}

bool charra_verify_log_matches_quote_pcr_digest(const uint8_t* log,
        uint32_t log_len, const uint8_t* pcr_selection,
        uint32_t pcr_selection_len, const TPMS_ATTEST* attest_struct) {
    if (pcr_selection_len == 0 || pcr_selection_len > TPM2_MAX_PCRS) {
        charra_log_error("[" LOG_NAME "] Bad PCR selection length %u.",
                pcr_selection_len);
        return false;
    }

    charra_pcr_accumulator replayed[TPM2_MAX_PCRS] = {{{0}}};
    if (charra_replay_ima_log_pcrs(log, log_len, pcr_selection,
                pcr_selection_len, replayed) != CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Replay failed.");
        return false;
    }

    /* compute_and_check_PCR_digest() wants an array of pointers, in the same
     * order as the selection the quote was taken over -- the composite
     * digest is order-sensitive. */
    uint8_t* pcr_values[TPM2_MAX_PCRS] = {NULL};
    for (uint32_t i = 0; i < pcr_selection_len; i++) {
        pcr_values[i] = replayed[i].value;
        charra_log_debug("[" LOG_NAME "] Replayed PCR %u:", pcr_selection[i]);
        charra_print_hex(CHARRA_LOG_DEBUG, TPM2_SHA256_DIGEST_SIZE,
                replayed[i].value, "                        0x", "\n", false);
    }

    if (compute_and_check_PCR_digest(
                pcr_values, pcr_selection_len, attest_struct) !=
            CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] PCR composite digest built from the "
                         "replayed log does NOT match the quote.");
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

bool charra_event_log_entry_file_digest(const charra_event_log_entry* entry,
        const uint8_t** digest_out, uint32_t* digest_len_out) {
    if (entry == NULL || digest_out == NULL || digest_len_out == NULL) {
        return false;
    }
    /* ima-ng template_data is two length-prefixed fields:
     *     u32 d_len | "<alg>" '\0' <file-digest>
     *     u32 n_len | "<path>" '\0'
     * so the file digest is what follows the NUL-terminated algorithm name
     * inside the first field. */
    if (entry->template_data_len < sizeof(uint32_t)) {
        return false;
    }
    uint32_t offset = 0;
    const uint32_t d_len = read_u32(entry->template_data);
    offset += sizeof(uint32_t);
    if (d_len > entry->template_data_len - offset) {
        return false;
    }

    const uint8_t* d_field = entry->template_data + offset;
    uint32_t alg_len = 0;
    while (alg_len < d_len && d_field[alg_len] != '\0') {
        alg_len++;
    }
    if (alg_len == d_len) {
        return false; /* no NUL: not an ima-ng d-ng field */
    }
    alg_len++; /* step past the NUL */

    *digest_out = d_field + alg_len;
    *digest_len_out = d_len - alg_len;
    return *digest_len_out > 0;
}

bool charra_verify_log_file_hashes_against_policy(const uint8_t* log,
        uint32_t log_len, const char* whitelist_path,
        const char* blacklist_path) {
    /* Two lists, and which one is authoritative depends on whether a
     * whitelist actually exists:
     *   - blacklist: an explicit deny, always enforced. A listed digest is
     *     rejected even if the whitelist also names it.
     *   - whitelist: enforced as DEFAULT-DENY, but only when it has at
     *     least one entry. An unpopulated whitelist falls back to
     *     allow-by-default, because the alternative is rejecting every
     *     attestation on a fresh checkout -- which looks like a bug, gets
     *     worked around, and leaves the check permanently disabled.
     * So policy strength scales with how much the operator has configured,
     * and the log says plainly which mode is in force rather than leaving
     * "passed" ambiguous between "checked and fine" and "nothing to check
     * against". */
    uint8_t* whitelist = NULL;
    uint32_t whitelist_count = 0;
    uint8_t* blacklist = NULL;
    uint32_t blacklist_count = 0;

    if (load_hash_list(whitelist_path, &whitelist, &whitelist_count) !=
            CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Could not load whitelist '%s'.",
                whitelist_path);
        return false;
    }
    if (load_hash_list(blacklist_path, &blacklist, &blacklist_count) !=
            CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Could not load blacklist '%s'.",
                blacklist_path);
        free(whitelist);
        return false;
    }

    if (whitelist_count > 0) {
        charra_log_info("[" LOG_NAME "] File-hash policy: DEFAULT-DENY "
                        "(whitelist '%s', %u entries; blacklist '%s', %u).",
                whitelist_path, whitelist_count, blacklist_path,
                blacklist_count);
    } else {
        charra_log_warn("[" LOG_NAME "] File-hash policy: allow-by-default "
                        "-- whitelist '%s' is empty, so only the blacklist "
                        "('%s', %u entries) can reject anything.",
                whitelist_path, blacklist_path, blacklist_count);
    }

    bool all_ok = true;
    const bool anything_to_check = whitelist_count > 0 || blacklist_count > 0;
    if (log_len > 0 && anything_to_check) {
        uint16_t digest_len = 0;
        if (charra_event_log_ima_detect_digest_len(log, log_len,
                    &digest_len) != CHARRA_RC_SUCCESS) {
            all_ok = false;
        } else {
            uint32_t offset = 0;
            uint32_t entry_num = 0;
            while (offset < log_len) {
                charra_event_log_entry entry = {0};
                if (charra_event_log_parse_entry(log, log_len, &offset,
                            digest_len, &entry) != CHARRA_RC_SUCCESS) {
                    all_ok = false;
                    break;
                }

                const uint8_t* file_digest = NULL;
                uint32_t file_digest_len = 0;
                if (!charra_event_log_entry_file_digest(
                            &entry, &file_digest, &file_digest_len)) {
                    /* Under default-deny an unreadable digest cannot be
                     * approved -- "I could not tell" must not mean "fine".
                     * With no whitelist there is nothing to approve it
                     * against either way, so it stays a warning. */
                    if (whitelist_count > 0) {
                        charra_log_error(
                                "[" LOG_NAME "] Entry %u carries no readable "
                                "file digest; cannot be matched against the "
                                "whitelist, rejecting.",
                                entry_num);
                        all_ok = false;
                    } else {
                        charra_log_warn("[" LOG_NAME "] Entry %u carries no "
                                        "readable file digest; not checked.",
                                entry_num);
                    }
                    entry_num++;
                    continue;
                }

                if (file_digest_len != TPM2_SHA256_DIGEST_SIZE) {
                    if (whitelist_count > 0) {
                        charra_log_error(
                                "[" LOG_NAME "] Entry %u's file digest is %u "
                                "bytes, not SHA-256; cannot be matched "
                                "against the whitelist, rejecting.",
                                entry_num, file_digest_len);
                        all_ok = false;
                    }
                    entry_num++;
                    continue;
                }

                /* Blacklist first: an explicit deny outranks approval. */
                if (blacklist_count > 0 &&
                        hash_list_contains(
                                blacklist, blacklist_count, file_digest)) {
                    charra_log_error(
                            "[" LOG_NAME "] Entry %u's file-content digest "
                            "matches the BLACKLIST.",
                            entry_num);
                    all_ok = false;
                } else if (whitelist_count > 0 &&
                           !hash_list_contains(
                                   whitelist, whitelist_count, file_digest)) {
                    charra_log_error(
                            "[" LOG_NAME "] Entry %u's file-content digest is "
                            "NOT on the whitelist (default-deny).",
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
