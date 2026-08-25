/**
 * @file dump_witness.c
 * @brief Phase 0 of ZK_REDACTION.md: print, for the Attester's IMA log,
 * every intermediate the ZK circuit will have to reproduce.
 *
 * Offline dev tool, not a protocol role and not part of `make all`. It opens
 * no TPM and talks to nobody -- it just replays the log through the same
 * functions the RP's Step 2a check uses (charra_event_log.c), and prints
 * what falls out at each step.
 *
 * The point is debuggability. A circuit that fails to reproduce
 * `pcrdigest_a` gives one bit of information: "wrong". Diffing the
 * circuit's per-entry intermediates against this dump says *which entry*
 * and *which step* diverged, which is the difference between a ten-minute
 * fix and a day of guessing.
 *
 * Emits JSON so a script can turn it straight into a Noir Prover.toml:
 *
 *     make dump_witness && ./bin/dump_witness > zk/witness.json
 *
 * Fields per entry: the private circuit inputs (path), the public ones
 * (file_hash, path_len), and the golden intermediates the circuit must
 * arrive at on its own (template_data, template_digest, pcr_after).
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <tss2/tss2_tpm2_types.h>

#include "attester/attester_ima_log.h"
#include "common/charra_log.h"
#include "core/charra_event_log.h"
#include "util/crypto_util.h"

#define DEFAULT_LOG_PATH "ima_test_logs.txt"

/* The PCR selection the RP asks the Attester to quote (relying_party.c's
 * tpm_pcr_selection). pcrdigest_a is the composite over these, in this
 * order, so the circuit has to reproduce the same set. */
static const uint8_t QUOTED_PCRS[] = {0, 1, 2, 3, 4, 5, 6, 7, 10};
#define NUM_QUOTED_PCRS (sizeof(QUOTED_PCRS) / sizeof(QUOTED_PCRS[0]))

static void print_hex(const uint8_t* buf, uint32_t len) {
    for (uint32_t i = 0; i < len; i++) {
        printf("%02x", buf[i]);
    }
}

/* Print a byte range as a JSON string, escaping what JSON requires and
 * anything non-printable. Paths are ordinary filenames in practice, but
 * this is attacker-influenced data and must not be able to break the
 * output format. */
static void print_json_string(const uint8_t* buf, uint32_t len) {
    putchar('"');
    for (uint32_t i = 0; i < len; i++) {
        unsigned char c = buf[i];
        if (c == '"' || c == '\\') {
            printf("\\%c", c);
        } else if (c >= 0x20 && c < 0x7f) {
            putchar(c);
        } else {
            printf("\\u%04x", c);
        }
    }
    putchar('"');
}

/**
 * @brief Split ima-ng template_data into its d-ng and n-ng halves.
 *
 * Layout (attester_ima_log.c's build_ima_ng_template_data()):
 *     u32le d_len | "<alg>\0" <file-digest> | u32le n_len | <path> '\0'
 *
 * path_len_out counts the bytes of the n-ng field INCLUDING its trailing
 * NUL, because that is what the field carries and therefore what SHA-256
 * consumes. The circuit must include it too.
 */
static bool split_template_data(const uint8_t* data, uint32_t data_len,
        const uint8_t** file_digest_out, uint32_t* file_digest_len_out,
        const uint8_t** path_out, uint32_t* path_len_out) {
    if (data == NULL || data_len < sizeof(uint32_t)) {
        return false;
    }
    uint32_t off = 0;

    const uint32_t d_len = (uint32_t)data[0] | ((uint32_t)data[1] << 8) |
                           ((uint32_t)data[2] << 16) |
                           ((uint32_t)data[3] << 24);
    off += sizeof(uint32_t);
    if (d_len > data_len - off) {
        return false;
    }
    /* the file digest is whatever follows the NUL-terminated algorithm name */
    const uint8_t* d_field = data + off;
    uint32_t alg_len = 0;
    while (alg_len < d_len && d_field[alg_len] != '\0') {
        alg_len++;
    }
    if (alg_len == d_len) {
        return false;
    }
    alg_len++;
    *file_digest_out = d_field + alg_len;
    *file_digest_len_out = d_len - alg_len;
    off += d_len;

    if (sizeof(uint32_t) > data_len - off) {
        return false;
    }
    const uint32_t n_len = (uint32_t)data[off] | ((uint32_t)data[off + 1] << 8) |
                           ((uint32_t)data[off + 2] << 16) |
                           ((uint32_t)data[off + 3] << 24);
    off += sizeof(uint32_t);
    if (n_len > data_len - off) {
        return false;
    }
    *path_out = data + off;
    *path_len_out = n_len;
    return true;
}

int main(int argc, char** argv) {
    /* Quiet by default: the dump goes to stdout and must stay parseable,
     * so the library's own INFO/DEBUG chatter has to stay out of it. */
    charra_log_set_level(CHARRA_LOG_ERROR);

    const char* log_path = (argc > 1) ? argv[1] : DEFAULT_LOG_PATH;

    uint8_t* log = NULL;
    uint32_t log_len = 0;
    if (charra_ima_log_ascii_to_binary(log_path, &log, &log_len) !=
            CHARRA_RC_SUCCESS) {
        fprintf(stderr, "dump_witness: could not read/convert '%s'\n",
                log_path);
        return EXIT_FAILURE;
    }

    uint16_t digest_len = 0;
    if (charra_event_log_ima_detect_digest_len(log, log_len, &digest_len) !=
            CHARRA_RC_SUCCESS) {
        fprintf(stderr, "dump_witness: could not detect digest length\n");
        free(log);
        return EXIT_FAILURE;
    }

    /* Every PCR the quote selects, all starting at their power-on value.
     * Only PCR 10 is ever extended by an IMA log; the other eight stay
     * zero and are carried into the composite as zeros, which is exactly
     * what the circuit will do with them. */
    charra_pcr_accumulator pcrs[NUM_QUOTED_PCRS];
    for (size_t i = 0; i < NUM_QUOTED_PCRS; i++) {
        charra_pcr_reset(&pcrs[i]);
    }
    charra_pcr_accumulator* ima_pcr = NULL;
    for (size_t i = 0; i < NUM_QUOTED_PCRS; i++) {
        if (QUOTED_PCRS[i] == CHARRA_IMA_PCR_INDEX) {
            ima_pcr = &pcrs[i];
        }
    }
    if (ima_pcr == NULL) {
        fprintf(stderr, "dump_witness: PCR %d is not in the quoted set\n",
                CHARRA_IMA_PCR_INDEX);
        free(log);
        return EXIT_FAILURE;
    }

    printf("{\n");
    printf("  \"source_log\": ");
    print_json_string((const uint8_t*)log_path, (uint32_t)strlen(log_path));
    printf(",\n");
    printf("  \"template_digest_len\": %u,\n", digest_len);
    printf("  \"quoted_pcrs\": [");
    for (size_t i = 0; i < NUM_QUOTED_PCRS; i++) {
        printf("%s%u", (i == 0) ? "" : ", ", QUOTED_PCRS[i]);
    }
    printf("],\n");
    printf("  \"entries\": [\n");

    uint32_t offset = 0;
    uint32_t entry_num = 0;
    uint32_t max_path_len = 0;
    bool ok = true;

    while (offset < log_len) {
        charra_event_log_entry entry = {0};
        if (charra_event_log_parse_entry(
                    log, log_len, &offset, digest_len, &entry) !=
                CHARRA_RC_SUCCESS) {
            fprintf(stderr, "dump_witness: entry %u failed to parse\n",
                    entry_num);
            ok = false;
            break;
        }

        const uint8_t* file_digest = NULL;
        uint32_t file_digest_len = 0;
        const uint8_t* path = NULL;
        uint32_t path_len = 0;
        if (!split_template_data(entry.template_data, entry.template_data_len,
                    &file_digest, &file_digest_len, &path, &path_len)) {
            fprintf(stderr,
                    "dump_witness: entry %u is not ima-ng shaped\n", entry_num);
            ok = false;
            break;
        }
        if (path_len > max_path_len) {
            max_path_len = path_len;
        }

        /* Recompute the digest rather than trusting the one in the log --
         * this is the exact SHA-256 the circuit has to match, and computing
         * it here proves the reconstruction above is faithful. */
        uint8_t computed[TPM2_SHA256_DIGEST_SIZE] = {0};
        if (hash_sha256(entry.template_data_len, entry.template_data,
                    computed) != CHARRA_RC_SUCCESS) {
            fprintf(stderr, "dump_witness: hashing entry %u failed\n",
                    entry_num);
            ok = false;
            break;
        }
        const bool digest_matches =
                entry.template_digest_len == TPM2_SHA256_DIGEST_SIZE &&
                memcmp(computed, entry.template_digest,
                        TPM2_SHA256_DIGEST_SIZE) == 0;

        if (entry.pcr_index == CHARRA_IMA_PCR_INDEX) {
            if (charra_pcr_extend(ima_pcr, entry.template_digest,
                        entry.template_digest_len) != CHARRA_RC_SUCCESS) {
                fprintf(stderr, "dump_witness: extend failed at entry %u\n",
                        entry_num);
                ok = false;
                break;
            }
        }

        printf("    %s{\n", (entry_num == 0) ? "" : ", ");
        printf("      \"index\": %u,\n", entry_num);
        printf("      \"pcr_index\": %u,\n", entry.pcr_index);
        printf("      \"path\": ");
        print_json_string(path, path_len);
        printf(",\n");
        printf("      \"path_len\": %u,\n", path_len);
        printf("      \"file_hash\": \"");
        print_hex(file_digest, file_digest_len);
        printf("\",\n");
        printf("      \"template_data\": \"");
        print_hex(entry.template_data, entry.template_data_len);
        printf("\",\n");
        printf("      \"template_data_len\": %u,\n", entry.template_data_len);
        printf("      \"template_digest\": \"");
        print_hex(computed, TPM2_SHA256_DIGEST_SIZE);
        printf("\",\n");
        printf("      \"template_digest_matches_log\": %s,\n",
                digest_matches ? "true" : "false");
        printf("      \"pcr_after\": \"");
        print_hex(ima_pcr->value, TPM2_SHA256_DIGEST_SIZE);
        printf("\"\n");
        printf("    }\n");

        entry_num++;
    }

    printf("  ],\n");

    /* The composite: SHA-256 over every quoted PCR's value, ascending
     * index -- hash_sha256_array() over the same array the RP builds. This
     * is pcrdigest_a, the circuit's public input and its final assertion. */
    uint8_t* pcr_values[NUM_QUOTED_PCRS];
    for (size_t i = 0; i < NUM_QUOTED_PCRS; i++) {
        pcr_values[i] = pcrs[i].value;
    }
    uint8_t composite[TPM2_SHA256_DIGEST_SIZE] = {0};
    if (hash_sha256_array(pcr_values, NUM_QUOTED_PCRS, composite) !=
            CHARRA_RC_SUCCESS) {
        fprintf(stderr, "dump_witness: composite digest failed\n");
        ok = false;
    }

    printf("  \"num_entries\": %u,\n", entry_num);
    printf("  \"max_path_len\": %u,\n", max_path_len);
    printf("  \"pcr10_final\": \"");
    print_hex(ima_pcr->value, TPM2_SHA256_DIGEST_SIZE);
    printf("\",\n");
    printf("  \"pcrdigest_a\": \"");
    print_hex(composite, TPM2_SHA256_DIGEST_SIZE);
    printf("\"\n");
    printf("}\n");

    free(log);

    if (!ok) {
        return EXIT_FAILURE;
    }

    /* Human-readable summary on stderr, so it shows up when you run this
     * interactively but never contaminates a redirected dump. */
    fprintf(stderr,
            "dump_witness: %u entries, max n-ng field %u bytes "
            "(template_data <= %u, %u SHA-256 blocks)\n",
            entry_num, max_path_len, 48 + max_path_len - 1,
            (48 + max_path_len - 1 + 9 + 63) / 64);
    return EXIT_SUCCESS;
}
