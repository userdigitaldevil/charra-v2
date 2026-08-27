/* SPDX-License-Identifier: BSD-3-Clause */
/**
 * @file charra_zk.c
 * @brief Witness serialisation for the ZK redaction proof -- see charra_zk.h.
 */

#include "charra_zk.h"

#include <stdio.h>
#include <string.h>

#include "../common/charra_log.h"

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
    if (witness->num_entries != CHARRA_ZK_NUM_ENTRIES) {
        charra_log_error("[" LOG_NAME "] Log has %u entries but the circuit is "
                         "compiled for exactly %u. See ZK_REDACTION.md "
                         "section 7.",
                witness->num_entries, (unsigned)CHARRA_ZK_NUM_ENTRIES);
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
         * a mismatch is far easier to read here than as a digest mismatch. */
        fprintf(f, "\",\n      \"template_data_len\": %u\n", 47u + e->path_len);
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
