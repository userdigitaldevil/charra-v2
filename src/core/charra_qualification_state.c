#include "charra_qualification_state.h"

#include "../util/hex_util.h"
#include "charra_record_file.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>

#include "../common/charra_log.h"

#define LOG_NAME "charra_qualification_state"

/** Writes data_len*2 lowercase hex chars + NUL into out (out must be at
 * least data_len*2 + 1 bytes). */
/* One line of the qualification ledger; field layout and validation are
 * unchanged from when this loop was open-coded. */
static bool parse_qualification_state_line(const char* line, void* record_out) {
    charra_qualification_state_record* rec = record_out;
    char ek_fingerprint_hex[65] = {0};
    long long qualified_at = 0;
    long long expires_at = 0;

    int matched = sscanf(line, "%64s %lld %lld", ek_fingerprint_hex,
            &qualified_at, &expires_at);
    if (matched != 3 ||
            strlen(ek_fingerprint_hex) != sizeof(rec->ek_fingerprint) * 2) {
        charra_log_error("[" LOG_NAME "] Skipping unparseable "
                         "qualification state line.");
        return false;
    }
    if (!charra_hex_decode(ek_fingerprint_hex, sizeof(rec->ek_fingerprint),
                rec->ek_fingerprint)) {
        charra_log_error("[" LOG_NAME "] Skipping qualification state "
                         "line with bad hex.");
        return false;
    }
    rec->qualified_at = (time_t)qualified_at;
    rec->expires_at = (time_t)expires_at;
    return true;
}

CHARRA_RC charra_qualification_state_load(const char* path,
        charra_qualification_state_record** records_out,
        uint32_t* count_out) {
    return charra_record_file_load(path, "qualification state",
            sizeof(charra_qualification_state_record),
            parse_qualification_state_line, (void**)records_out, count_out);
}

static void format_qualification_state_line(
        const void* record, FILE* out) {
    const charra_qualification_state_record* rec = record;
    char ek_fingerprint_hex[65] = {0};
    charra_hex_encode(
            rec->ek_fingerprint, sizeof(rec->ek_fingerprint), ek_fingerprint_hex);

    fprintf(out, "%s %lld %lld\n", ek_fingerprint_hex,
            (long long)rec->qualified_at, (long long)rec->expires_at);
}

CHARRA_RC charra_qualification_state_save(const char* path,
        const charra_qualification_state_record* records, uint32_t count) {
    return charra_record_file_save(path,
            "ek_fingerprint qualified_at expires_at", records,
            sizeof(charra_qualification_state_record), count,
            format_qualification_state_line);
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

    FILE* lock_file = NULL;
    CHARRA_RC lock_rc = charra_record_file_lock(path, &lock_file);
    if (lock_rc != CHARRA_RC_SUCCESS) {
        return lock_rc;
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
    charra_record_file_unlock(lock_file);
    return charra_r;
}

bool charra_qualification_state_is_valid(
        const charra_qualification_state_record* record, time_t now) {
    if (record == NULL) {
        return false;
    }
    return record->expires_at > now;
}
