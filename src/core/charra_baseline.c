/**
 * @file charra_baseline.c
 * @brief Vendor-baseline and flat-hash policy lists. See charra_baseline.h.
 */

#include "charra_baseline.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../common/charra_log.h"

#define LOG_NAME "baseline"

/* --- shared helpers ----------------------------------------------------- */

static int hex_nibble(char c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

static bool hex_to_sha256(const char* hex, uint8_t out[TPM2_SHA256_DIGEST_SIZE]) {
    for (uint32_t i = 0; i < TPM2_SHA256_DIGEST_SIZE; i++) {
        const int hi = hex_nibble(hex[2 * i]);
        const int lo = hex_nibble(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) {
            return false;
        }
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return hex[2 * TPM2_SHA256_DIGEST_SIZE] == '\0';
}

static CHARRA_RC push_entry(charra_baseline* b, uint32_t* capacity,
        const char* name, const uint8_t* hash) {
    if (b->count == *capacity) {
        const uint32_t grown_cap = (*capacity == 0) ? 64 : *capacity * 2;
        charra_baseline_entry* grown = realloc(
                b->entries, (size_t)grown_cap * sizeof(charra_baseline_entry));
        if (grown == NULL) {
            return CHARRA_RC_ERROR;
        }
        b->entries = grown;
        *capacity = grown_cap;
    }
    charra_baseline_entry* e = &b->entries[b->count];
    memset(e, 0, sizeof(*e));
    if (name != NULL) {
        strncpy(e->name, name, CHARRA_BASELINE_NAME_MAX - 1);
    }
    memcpy(e->hash, hash, TPM2_SHA256_DIGEST_SIZE);
    b->count++;
    return CHARRA_RC_SUCCESS;
}

/** Order by hash, then name, so equal hashes sit together and a lookup can
 * find the hash first and then walk the run for the name. */
static int compare_entries(const void* a, const void* b) {
    const charra_baseline_entry* x = a;
    const charra_baseline_entry* y = b;
    const int c = memcmp(x->hash, y->hash, TPM2_SHA256_DIGEST_SIZE);
    return (c != 0) ? c : strcmp(x->name, y->name);
}

/* --- JSON --------------------------------------------------------------- */

/**
 * @brief Read a JSON string starting at the opening quote.
 *
 * Handles the escapes a path or filename can plausibly contain. \\u is
 * deliberately NOT decoded: a baseline that needs it is outside what this
 * parser claims to understand, and quietly mangling such a name into a
 * mismatch would be worse than saying so.
 */
static bool read_json_string(
        const char* s, size_t len, size_t* i, char* out, size_t out_cap) {
    if (*i >= len || s[*i] != '"') {
        return false;
    }
    (*i)++;
    size_t w = 0;
    while (*i < len && s[*i] != '"') {
        char c = s[*i];
        if (c == '\\') {
            (*i)++;
            if (*i >= len) {
                return false;
            }
            switch (s[*i]) {
            case 'n': c = '\n'; break;
            case 't': c = '\t'; break;
            case 'r': c = '\r'; break;
            case 'b': c = '\b'; break;
            case 'f': c = '\f'; break;
            case '/': c = '/'; break;
            case '\\': c = '\\'; break;
            case '"': c = '"'; break;
            case 'u':
                charra_log_error("[" LOG_NAME "] \\u escapes are not decoded; "
                                 "this baseline cannot be read safely.");
                return false;
            default: c = s[*i]; break;
            }
        }
        if (w + 1 < out_cap) {
            out[w++] = c;
        }
        (*i)++;
    }
    if (*i >= len) {
        return false;
    }
    (*i)++; /* closing quote */
    out[w] = '\0';
    return true;
}

/**
 * @brief Collect every {fileName, fileType, sha256} object in the document.
 *
 * A depth-tracking scan rather than a schema walk: it finds the objects
 * wherever they sit, so a baseline that grows another wrapper level around
 * products/ccFiles keeps working. Keys are matched inside the object that
 * encloses them, so field order does not matter either.
 */
static CHARRA_RC parse_baseline_json(
        const char* text, size_t len, charra_baseline* out) {
    uint32_t capacity = 0;
    int depth = 0;

    /* Fields of the object currently being read, at each nesting level we
     * care about. Only the innermost object can be a ccFiles entry, so one
     * slot is enough. */
    char cur_name[CHARRA_BASELINE_NAME_MAX] = {0};
    char cur_type[64] = {0};
    char cur_hash_hex[128] = {0};
    int cur_depth = -1;
    uint32_t skipped_type = 0, skipped_bad = 0;

    size_t i = 0;
    while (i < len) {
        const char c = text[i];
        if (c == '{') {
            depth++;
            /* A new innermost object: start collecting for it. */
            cur_depth = depth;
            cur_name[0] = cur_type[0] = cur_hash_hex[0] = '\0';
            i++;
            continue;
        }
        if (c == '}') {
            if (depth == cur_depth) {
                if (cur_name[0] != '\0' && cur_hash_hex[0] != '\0') {
                    /* Only IMA rows may approve an IMA measurement. An
                     * absent fileType is accepted: older baselines omit it
                     * and every row in them is a file measurement. */
                    if (cur_type[0] == '\0' || strcmp(cur_type, "IMA") == 0) {
                        uint8_t hash[TPM2_SHA256_DIGEST_SIZE];
                        if (hex_to_sha256(cur_hash_hex, hash)) {
                            if (push_entry(out, &capacity, cur_name, hash) !=
                                    CHARRA_RC_SUCCESS) {
                                return CHARRA_RC_ERROR;
                            }
                        } else {
                            skipped_bad++;
                        }
                    } else {
                        skipped_type++;
                    }
                }
                cur_name[0] = cur_type[0] = cur_hash_hex[0] = '\0';
            }
            depth--;
            cur_depth = depth;
            i++;
            continue;
        }
        if (c == '"') {
            char key[64];
            const size_t key_start = i;
            if (!read_json_string(text, len, &i, key, sizeof(key))) {
                charra_log_error("[" LOG_NAME "] Malformed JSON string at "
                                 "byte %zu.",
                        key_start);
                return CHARRA_RC_MARSHALING_ERROR;
            }
            /* A key is a string followed by ':'. Anything else was a value
             * we do not need, and skipping it here is what keeps the scan
             * from mistaking a value for the next key. */
            size_t j = i;
            while (j < len && (text[j] == ' ' || text[j] == '\t' ||
                                      text[j] == '\n' || text[j] == '\r')) {
                j++;
            }
            if (j < len && text[j] == ':') {
                j++;
                while (j < len && (text[j] == ' ' || text[j] == '\t' ||
                                          text[j] == '\n' || text[j] == '\r')) {
                    j++;
                }
                char* dest = NULL;
                size_t dest_cap = 0;
                if (strcmp(key, "fileName") == 0) {
                    dest = cur_name;
                    dest_cap = sizeof(cur_name);
                } else if (strcmp(key, "fileType") == 0) {
                    dest = cur_type;
                    dest_cap = sizeof(cur_type);
                } else if (strcmp(key, "sha256") == 0) {
                    dest = cur_hash_hex;
                    dest_cap = sizeof(cur_hash_hex);
                }
                if (dest != NULL && j < len && text[j] == '"') {
                    if (!read_json_string(text, len, &j, dest, dest_cap)) {
                        return CHARRA_RC_MARSHALING_ERROR;
                    }
                }
                i = j;
                continue;
            }
            continue;
        }
        i++;
    }

    if (skipped_type > 0) {
        charra_log_info("[" LOG_NAME "] Skipped %u non-IMA baseline entries.",
                skipped_type);
    }
    if (skipped_bad > 0) {
        charra_log_warn("[" LOG_NAME "] Skipped %u baseline entries whose "
                        "sha256 was not a 64-character hex digest.",
                skipped_bad);
    }
    out->has_names = true;
    return CHARRA_RC_SUCCESS;
}

/* --- flat hash list ----------------------------------------------------- */

static CHARRA_RC parse_flat_hash_list(
        const char* text, size_t len, charra_baseline* out) {
    uint32_t capacity = 0;
    size_t i = 0;
    while (i < len) {
        size_t end = i;
        while (end < len && text[end] != '\n') {
            end++;
        }
        size_t p = i;
        while (p < end && (text[p] == ' ' || text[p] == '\t')) {
            p++;
        }
        if (p < end && text[p] != '#' && text[p] != '\r') {
            if (end - p >= 2 && text[p] == '0' &&
                    (text[p + 1] == 'x' || text[p + 1] == 'X')) {
                p += 2;
            }
            char hex[2 * TPM2_SHA256_DIGEST_SIZE + 1];
            if (end - p >= 2 * TPM2_SHA256_DIGEST_SIZE) {
                memcpy(hex, text + p, 2 * TPM2_SHA256_DIGEST_SIZE);
                hex[2 * TPM2_SHA256_DIGEST_SIZE] = '\0';
                uint8_t hash[TPM2_SHA256_DIGEST_SIZE];
                if (hex_to_sha256(hex, hash)) {
                    if (push_entry(out, &capacity, NULL, hash) !=
                            CHARRA_RC_SUCCESS) {
                        return CHARRA_RC_ERROR;
                    }
                } else {
                    charra_log_error("[" LOG_NAME "] Unparseable hash line, "
                                     "skipping.");
                }
            } else {
                charra_log_error(
                        "[" LOG_NAME "] Short hash line, skipping.");
            }
        }
        i = (end < len) ? end + 1 : len;
    }
    out->has_names = false;
    return CHARRA_RC_SUCCESS;
}

/* --- public ------------------------------------------------------------- */

CHARRA_RC charra_baseline_load(const char* path, charra_baseline* out) {
    if (out == NULL) {
        return CHARRA_RC_BAD_ARGUMENT;
    }
    memset(out, 0, sizeof(*out));
    if (path == NULL) {
        return CHARRA_RC_SUCCESS;
    }

    FILE* f = fopen(path, "rb");
    if (f == NULL) {
        /* Absent is "nothing configured", not a failure -- see the header. */
        charra_log_info("[" LOG_NAME "] Policy file '%s' not present; treating "
                        "it as empty.",
                path);
        return CHARRA_RC_SUCCESS;
    }
    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return CHARRA_RC_ERROR;
    }
    const long size = ftell(f);
    if (size < 0 || fseek(f, 0, SEEK_SET) != 0) {
        fclose(f);
        return CHARRA_RC_ERROR;
    }
    char* text = malloc((size_t)size + 1);
    if (text == NULL) {
        fclose(f);
        return CHARRA_RC_ERROR;
    }
    const size_t read = fread(text, 1, (size_t)size, f);
    fclose(f);
    text[read] = '\0';

    /* Sniff the format from the content, not the extension: a policy file
     * renamed by an operator must not silently change how it is enforced. */
    size_t k = 0;
    while (k < read && (text[k] == ' ' || text[k] == '\t' || text[k] == '\n' ||
                               text[k] == '\r')) {
        k++;
    }
    const bool is_json = (k < read && text[k] == '{');

    CHARRA_RC charra_r = is_json ? parse_baseline_json(text, read, out)
                                 : parse_flat_hash_list(text, read, out);
    free(text);
    if (charra_r != CHARRA_RC_SUCCESS) {
        charra_baseline_free(out);
        return charra_r;
    }

    if (out->count > 0) {
        qsort(out->entries, out->count, sizeof(charra_baseline_entry),
                compare_entries);
    }
    charra_log_info("[" LOG_NAME "] Loaded %u entries from '%s' (%s).",
            out->count, path,
            is_json ? "vendor baseline JSON, name+hash"
                    : "flat hash list, hash only");
    return CHARRA_RC_SUCCESS;
}

void charra_baseline_free(charra_baseline* baseline) {
    if (baseline == NULL) {
        return;
    }
    free(baseline->entries);
    baseline->entries = NULL;
    baseline->count = 0;
}

/** @returns index of the first entry with this hash, or -1. */
static int64_t find_first_with_hash(
        const charra_baseline* b, const uint8_t* hash) {
    int64_t lo = 0;
    int64_t hi = (int64_t)b->count - 1;
    int64_t found = -1;
    while (lo <= hi) {
        const int64_t mid = lo + (hi - lo) / 2;
        const int c =
                memcmp(b->entries[mid].hash, hash, TPM2_SHA256_DIGEST_SIZE);
        if (c == 0) {
            found = mid;
            hi = mid - 1; /* keep going left: names are sorted within a hash */
        } else if (c < 0) {
            lo = mid + 1;
        } else {
            hi = mid - 1;
        }
    }
    return found;
}

bool charra_baseline_contains_hash_only(
        const charra_baseline* baseline, const uint8_t* hash) {
    if (baseline == NULL || baseline->count == 0 || hash == NULL) {
        return false;
    }
    return find_first_with_hash(baseline, hash) >= 0;
}

bool charra_baseline_contains(const charra_baseline* baseline, const char* name,
        const uint8_t* hash) {
    if (baseline == NULL || baseline->count == 0 || hash == NULL) {
        return false;
    }
    const int64_t first = find_first_with_hash(baseline, hash);
    if (first < 0) {
        return false;
    }
    /* A hash-only list has nothing to say about names, and a caller that
     * could not read a name gets the same treatment -- it reports that
     * separately rather than having this quietly decide for it. */
    if (!baseline->has_names || name == NULL) {
        return true;
    }
    for (int64_t i = first; i < (int64_t)baseline->count; i++) {
        if (memcmp(baseline->entries[i].hash, hash, TPM2_SHA256_DIGEST_SIZE) !=
                0) {
            break;
        }
        if (strcmp(baseline->entries[i].name, name) == 0) {
            return true;
        }
    }
    return false;
}
