/* SPDX-License-Identifier: BSD-3-Clause */
/**
 * @file charra_zk.c
 * @brief Witness serialisation for the ZK redaction proof -- see charra_zk.h.
 */

#include "charra_zk.h"

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "../common/charra_log.h"
#include "charra_event_log.h"
#include "charra_zk_job.h"

#define LOG_NAME "zk"

static void print_hex(FILE* f, const uint8_t* b, size_t n) {
    for (size_t i = 0; i < n; i++) {
        fprintf(f, "%02x", b[i]);
    }
}

/**
 * A measured path is an arbitrary byte string, not text: it may hold bytes
 * that are not printable and is not guaranteed to be valid UTF-8. Escaping
 * every non-printable byte as \\u00XX keeps the JSON well-formed and lets the
 * reader recover the exact bytes via latin-1, which zk/gen_prover_toml.py
 * relies on. The path's trailing NUL is part of the field and must survive.
 */
static void print_json_string(FILE* f, const uint8_t* s, size_t n) {
    fputc('"', f);
    for (size_t i = 0; i < n; i++) {
        uint8_t c = s[i];
        if (c == '"' || c == '\\') {
            fprintf(f, "\\%c", c);
        } else if (c >= 0x20 && c < 0x7f) {
            fputc(c, f);
        } else {
            fprintf(f, "\\u%04x", c);
        }
    }
    fputc('"', f);
}

CHARRA_RC charra_zk_write_witness_json(
        const charra_zk_witness* witness, const char* path) {
    if (witness == NULL || path == NULL) {
        return CHARRA_RC_BAD_ARGUMENT;
    }
    /* A shorter log is fine -- the circuit pads to N and n_real marks the
     * padding. A longer one is not provable at all, and saying so here, with
     * both numbers, beats letting bb fail ten seconds later on a witness it
     * cannot fit. */
    if (witness->num_entries == 0) {
        charra_log_error("[" LOG_NAME "] Log has no entries; there is nothing "
                         "to prove.");
        return CHARRA_RC_BAD_ARGUMENT;
    }
    if (witness->num_entries > CHARRA_ZK_MAX_ENTRIES) {
        charra_log_error("[" LOG_NAME "] Log has %u entries but the ZK circuit "
                         "is compiled for at most %u. Raise N in "
                         "zk/circuit/src/main.nr, recompile, and redistribute "
                         "zk/vk -- see ZK_REDACTION.md section 7.",
                witness->num_entries, (unsigned)CHARRA_ZK_MAX_ENTRIES);
        return CHARRA_RC_BAD_ARGUMENT;
    }

    FILE* f = fopen(path, "w");
    if (f == NULL) {
        charra_log_error("[" LOG_NAME "] Could not open %s for writing.", path);
        return CHARRA_RC_ERROR;
    }

    fprintf(f, "{\n  \"num_entries\": %u,\n", witness->num_entries);
    fprintf(f, "  \"pcrdigest_a\": \"");
    print_hex(f, witness->pcrdigest_a, 32);
    fprintf(f, "\",\n  \"entries\": [\n");

    for (uint32_t i = 0; i < witness->num_entries; i++) {
        const charra_zk_entry* e = &witness->entries[i];
        fprintf(f, "    {\n      \"index\": %u,\n", i);
        fprintf(f, "      \"pcr_index\": %u,\n", 10u);
        fprintf(f, "      \"path\": ");
        print_json_string(f, e->path, e->path_len);
        fprintf(f, ",\n      \"path_len\": %u,\n", e->path_len);
        fprintf(f, "      \"file_hash\": \"");
        print_hex(f, e->file_hash, 32);
        fprintf(f, "\",\n      \"salt\": \"");
        print_hex(f, e->salt, 32);
        fprintf(f, "\",\n      \"commitment\": \"");
        print_hex(f, e->commitment, 32);
        /* The circuit derives template_data itself, but the generator
         * cross-checks this length against the layout constant it assumes --
         * a mismatch is far easier to read here than as a digest mismatch.
         *
         * Derived rather than written as a literal: this was 47, one short,
         * from before the algorithm prefix gained its colon, and a stale
         * literal here fails as "HEADER_LEN wrong" in a Python script two
         * containers away. u32 d_len | "sha256:" NUL | digest | u32 n_len. */
        const uint32_t header_len = (uint32_t)(2 * sizeof(uint32_t) +
                                               CHARRA_IMA_ALGO_PREFIX_LEN + 32);
        fprintf(f, "\",\n      \"template_data_len\": %u\n",
                header_len + e->path_len);
        fprintf(f, "    }%s\n", (i + 1 < witness->num_entries) ? "," : "");
    }

    fprintf(f, "  ]\n}\n");

    if (fclose(f) != 0) {
        charra_log_error("[" LOG_NAME "] Could not finish writing %s.", path);
        return CHARRA_RC_ERROR;
    }
    charra_log_info("[" LOG_NAME "] Wrote witness for %u entries to %s.",
            witness->num_entries, path);
    return CHARRA_RC_SUCCESS;
}

/* d_field and n-ng, with their u32 length prefixes -- the same layout
 * split_ima_ng_fields() parses in charra_sdk.c, kept separate here so the
 * Verifier does not depend on the RP's redaction module. */
static bool split_fields(const uint8_t* data, uint32_t len,
        const uint8_t** d_field, uint32_t* d_field_len, const uint8_t** path,
        uint32_t* path_len) {
    if (data == NULL || len < sizeof(uint32_t)) {
        return false;
    }
    uint32_t d_len = (uint32_t)data[0] | ((uint32_t)data[1] << 8) |
                     ((uint32_t)data[2] << 16) | ((uint32_t)data[3] << 24);
    if (d_len > len - sizeof(uint32_t)) {
        return false;
    }
    uint32_t dfl = sizeof(uint32_t) + d_len;
    if (len - dfl < sizeof(uint32_t)) {
        return false;
    }
    const uint8_t* n = data + dfl;
    uint32_t n_len = (uint32_t)n[0] | ((uint32_t)n[1] << 8) |
                     ((uint32_t)n[2] << 16) | ((uint32_t)n[3] << 24);
    if (n_len > len - dfl - sizeof(uint32_t)) {
        return false;
    }
    *d_field = data;
    *d_field_len = dfl;
    *path = n + sizeof(uint32_t);
    *path_len = n_len;
    return true;
}

CHARRA_RC charra_zk_public_inputs_from_log_r(const uint8_t* log_r,
        uint32_t log_r_len, const uint8_t pcrdigest_a[32],
        struct charra_zk_public_inputs* out) {
    if (log_r == NULL || pcrdigest_a == NULL || out == NULL) {
        return CHARRA_RC_BAD_ARGUMENT;
    }
    memset(out, 0, sizeof(*out));
    memcpy(out->pcrdigest_a, pcrdigest_a, 32);

    uint16_t digest_len = 0;
    CHARRA_RC charra_r = charra_event_log_ima_detect_digest_len(
            log_r, log_r_len, &digest_len);
    if (charra_r != CHARRA_RC_SUCCESS) {
        return charra_r;
    }

    uint32_t offset = 0;
    uint32_t n = 0;
    while (offset < log_r_len) {
        charra_event_log_entry entry = {0};
        charra_r = charra_event_log_parse_entry(
                log_r, log_r_len, &offset, digest_len, &entry);
        if (charra_r != CHARRA_RC_SUCCESS) {
            return charra_r;
        }
        if (n >= CHARRA_ZK_MAX_ENTRIES) {
            charra_log_error("[" LOG_NAME "] log_r has more than %u entries; "
                             "the circuit is compiled for exactly that many.",
                    (unsigned)CHARRA_ZK_MAX_ENTRIES);
            return CHARRA_RC_BAD_ARGUMENT;
        }

        const uint8_t *d_field = NULL, *path = NULL;
        uint32_t d_field_len = 0, path_len = 0;
        if (!split_fields(entry.template_data, entry.template_data_len,
                    &d_field, &d_field_len, &path, &path_len)) {
            charra_log_error("[" LOG_NAME "] log_r entry %u is not a "
                             "well-formed ima-ng field pair.",
                    n);
            return CHARRA_RC_MARSHALING_ERROR;
        }
        /* 4 (d_len) + 7 ("sha256\0") + 32; the hash starts at offset 11. */
        if (d_field_len != 43) {
            charra_log_error("[" LOG_NAME "] log_r entry %u's d-ng field is %u "
                             "bytes, not the 43 expected for SHA-256.",
                    n, d_field_len);
            return CHARRA_RC_MARSHALING_ERROR;
        }
        /* The redacted path IS the commitment: 32 raw bytes, big-endian. */
        if (path_len != 32) {
            charra_log_error("[" LOG_NAME "] log_r entry %u's redacted path is "
                             "%u bytes, not the 32 a commitment occupies. "
                             "This log was not redacted by a matching RP.",
                    n, path_len);
            return CHARRA_RC_MARSHALING_ERROR;
        }

        memcpy(out->file_hashes[n], d_field + 11, 32);
        memcpy(out->commitments[n], path, 32);
        n++;
    }

    if (n == 0) {
        charra_log_error("[" LOG_NAME "] log_r has no entries; there is "
                         "nothing for a proof to be about.");
        return CHARRA_RC_BAD_ARGUMENT;
    }
    if (n > CHARRA_ZK_MAX_ENTRIES) {
        charra_log_error("[" LOG_NAME "] log_r has %u entries but the ZK "
                         "circuit is compiled for at most %u -- see "
                         "ZK_REDACTION.md section 7.",
                n, (unsigned)CHARRA_ZK_MAX_ENTRIES);
        return CHARRA_RC_BAD_ARGUMENT;
    }

    /* Counted from the log the Verifier actually received. This is what stops
     * the RP understating it to hide entries from the replay. */
    out->n_real = n;
    return CHARRA_RC_SUCCESS;
}
