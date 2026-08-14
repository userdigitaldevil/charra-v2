#include "charra_qualification_state.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>

#include "../common/charra_log.h"

#define LOG_NAME "charra_qualification_state"

/** Writes data_len*2 lowercase hex chars + NUL into out (out must be at
 * least data_len*2 + 1 bytes). */
static void hex_encode(const uint8_t* data, size_t data_len, char* out) {
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < data_len; i++) {
        out[2 * i] = digits[(data[i] >> 4) & 0xf];
        out[2 * i + 1] = digits[data[i] & 0xf];
    }
    out[2 * data_len] = '\0';
}

/** Decodes exactly byte_len*2 hex chars from hex into out. Returns false on
 * any non-hex character or if hex is shorter than byte_len*2 chars. */
static bool hex_decode(const char* hex, size_t byte_len, uint8_t* out) {
    for (size_t i = 0; i < byte_len; i++) {
        unsigned int byte = 0;
        if (sscanf(hex + 2 * i, "%2x", &byte) != 1) {
            return false;
        }
        out[i] = (uint8_t)byte;
    }
    return true;
}

CHARRA_RC charra_qualification_state_load(const char* path,
        charra_qualification_state_record** records_out,
        uint32_t* count_out) {
    if (path == NULL || records_out == NULL || count_out == NULL) {
        return CHARRA_RC_BAD_ARGUMENT;
    }
    *records_out = NULL;
    *count_out = 0;

    FILE* f = fopen(path, "r");
    if (f == NULL) {
        /* no state file yet -- nobody has qualified against this Verifier
         * instance yet */
        charra_log_info(
                "[" LOG_NAME "] No qualification state file at '%s' yet.",
                path);
        return CHARRA_RC_SUCCESS;
    }

    charra_qualification_state_record* records = NULL;
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

        charra_qualification_state_record rec = {0};
        char ek_fingerprint_hex[65] = {0};
        long long qualified_at = 0;
        long long expires_at = 0;

        int matched = sscanf(p, "%64s %lld %lld", ek_fingerprint_hex,
                &qualified_at, &expires_at);
        if (matched != 3 ||
                strlen(ek_fingerprint_hex) != sizeof(rec.ek_fingerprint) * 2) {
            charra_log_error("[" LOG_NAME "] Skipping unparseable "
                             "qualification state line.");
            continue;
        }
        if (!hex_decode(ek_fingerprint_hex, sizeof(rec.ek_fingerprint),
                    rec.ek_fingerprint)) {
            charra_log_error("[" LOG_NAME "] Skipping qualification state "
                             "line with bad hex.");
            continue;
        }
        rec.qualified_at = (time_t)qualified_at;
        rec.expires_at = (time_t)expires_at;

        if (count == capacity) {
            uint32_t new_capacity = (capacity == 0) ? 8 : capacity * 2;
            charra_qualification_state_record* grown = realloc(records,
                    new_capacity * sizeof(charra_qualification_state_record));
            if (grown == NULL) {
                free(records);
                fclose(f);
                return CHARRA_RC_ERROR;
            }
            records = grown;
            capacity = new_capacity;
        }
        records[count++] = rec;
    }
    fclose(f);

    *records_out = records;
    *count_out = count;
    return CHARRA_RC_SUCCESS;
}

CHARRA_RC charra_qualification_state_save(const char* path,
        const charra_qualification_state_record* records, uint32_t count) {
    if (path == NULL || (records == NULL && count != 0)) {
        return CHARRA_RC_BAD_ARGUMENT;
    }

    FILE* f = fopen(path, "w");
    if (f == NULL) {
        charra_log_error(
                "[" LOG_NAME "] Could not open '%s' for writing.", path);
        return CHARRA_RC_ERROR;
    }

    fprintf(f, "# ek_fingerprint qualified_at expires_at\n");
    for (uint32_t i = 0; i < count; i++) {
        const charra_qualification_state_record* rec = &records[i];
        char ek_fingerprint_hex[65] = {0};
        hex_encode(rec->ek_fingerprint, sizeof(rec->ek_fingerprint),
                ek_fingerprint_hex);

        fprintf(f, "%s %lld %lld\n", ek_fingerprint_hex,
                (long long)rec->qualified_at, (long long)rec->expires_at);
    }

    fclose(f);
    return CHARRA_RC_SUCCESS;
}

bool charra_qualification_state_find_by_ek_fingerprint(
        const charra_qualification_state_record* records, uint32_t count,
        const uint8_t fingerprint[32], uint32_t* index_out) {
    if (records == NULL || fingerprint == NULL || index_out == NULL) {
        return false;
    }
    /* Scan backward: after N qualifications for the same EK, up to N-1
     * superseded records for it can exist (oldest first, since charra_
     * qualification_state_renew() always appends). Only the most recent
     * one -- last in the array -- is the one worth checking charra_
     * qualification_state_is_valid() against; a forward scan would keep
     * returning the oldest, likely already-expired one instead. Same
     * reasoning as charra_ak_state_find_by_ek_fingerprint(). */
    for (uint32_t i = count; i > 0; i--) {
        uint32_t idx = i - 1;
        if (memcmp(records[idx].ek_fingerprint, fingerprint, 32) == 0) {
            *index_out = idx;
            return true;
        }
    }
    return false;
}

CHARRA_RC charra_qualification_state_renew(const char* path,
        const uint8_t ek_fingerprint[32],
        const charra_qualification_state_record* new_record) {
    if (path == NULL || ek_fingerprint == NULL || new_record == NULL) {
        return CHARRA_RC_BAD_ARGUMENT;
    }
    if (memcmp(ek_fingerprint, new_record->ek_fingerprint, 32) != 0) {
        return CHARRA_RC_BAD_ARGUMENT;
    }

    char lock_path[512];
    if (snprintf(lock_path, sizeof(lock_path), "%s.lock", path) >=
            (int)sizeof(lock_path)) {
        return CHARRA_RC_ERROR;
    }
    FILE* lock_file = fopen(lock_path, "w");
    if (lock_file == NULL) {
        charra_log_error(
                "[" LOG_NAME "] Could not open lock file '%s'.", lock_path);
        return CHARRA_RC_ERROR;
    }
    if (flock(fileno(lock_file), LOCK_EX) != 0) {
        charra_log_error(
                "[" LOG_NAME "] Could not acquire lock on '%s'.", lock_path);
        fclose(lock_file);
        return CHARRA_RC_ERROR;
    }

    CHARRA_RC charra_r = CHARRA_RC_SUCCESS;
    charra_qualification_state_record* records = NULL;
    uint32_t count = 0;
    if ((charra_r = charra_qualification_state_load(path, &records, &count)) !=
            CHARRA_RC_SUCCESS) {
        goto unlock;
    }

    charra_qualification_state_record* grown = realloc(records,
            (count + 1) * sizeof(charra_qualification_state_record));
    if (grown == NULL) {
        charra_r = CHARRA_RC_ERROR;
        goto cleanup;
    }
    records = grown;
    records[count] = *new_record;
    count++;

    charra_r = charra_qualification_state_save(path, records, count);

cleanup:
    free(records);
unlock:
    flock(fileno(lock_file), LOCK_UN);
    fclose(lock_file);
    return charra_r;
}

bool charra_qualification_state_is_valid(
        const charra_qualification_state_record* record, time_t now) {
    if (record == NULL) {
        return false;
    }
    return record->expires_at > now;
}
