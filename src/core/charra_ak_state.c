#include "charra_ak_state.h"

#include "../util/hex_util.h"
#include "charra_record_file.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>

#include "../common/charra_log.h"

#define LOG_NAME "charra_ak_state"

/** Writes data_len*2 lowercase hex chars + NUL into out (out must be at
 * least data_len*2 + 1 bytes). */
/* One line of the AK ledger. Field layout and validation are unchanged
 * from when this loop was open-coded; only the surrounding file handling
 * moved into charra_record_file.c. */
static bool parse_ak_state_line(const char* line, void* record_out) {
    charra_ak_state_record* rec = record_out;
    char ek_fingerprint_hex[65] = {0};
    char serial_hex[33] = {0};
    /* Sized generously (sizeof(TPM2B_NAME) is well under 128 bytes on any
     * real TPM); the "%255s" field width below is what actually bounds the
     * write, independent of this buffer's exact size. */
    char ak_name_hex[256] = {0};
    unsigned int ak_name_len = 0;
    long long issued_at = 0;
    long long expires_at = 0;
    unsigned int revoked = 0;

    int matched = sscanf(line, "%64s %32s %u %255s %lld %lld %u",
            ek_fingerprint_hex, serial_hex, &ak_name_len, ak_name_hex,
            &issued_at, &expires_at, &revoked);
    if (matched != 7 || ak_name_len > sizeof(rec->ak_name) ||
            strlen(ek_fingerprint_hex) != sizeof(rec->ek_fingerprint) * 2 ||
            strlen(serial_hex) != sizeof(rec->serial) * 2 ||
            strlen(ak_name_hex) != ak_name_len * 2) {
        charra_log_error(
                "[" LOG_NAME "] Skipping unparseable AK state line.");
        return false;
    }
    if (!charra_hex_decode(ek_fingerprint_hex, sizeof(rec->ek_fingerprint),
                rec->ek_fingerprint) ||
            !charra_hex_decode(serial_hex, sizeof(rec->serial), rec->serial) ||
            !charra_hex_decode(ak_name_hex, ak_name_len, rec->ak_name)) {
        charra_log_error(
                "[" LOG_NAME "] Skipping AK state line with bad hex.");
        return false;
    }
    rec->ak_name_len = ak_name_len;
    rec->issued_at = (time_t)issued_at;
    rec->expires_at = (time_t)expires_at;
    rec->revoked = (revoked != 0);
    return true;
}

CHARRA_RC charra_ak_state_load(const char* path,
        charra_ak_state_record** records_out, uint32_t* count_out) {
    return charra_record_file_load(path, "AK state",
            sizeof(charra_ak_state_record), parse_ak_state_line,
            (void**)records_out, count_out);
}

static void format_ak_state_line(const void* record, FILE* out) {
    const charra_ak_state_record* rec = record;
    char ek_fingerprint_hex[65] = {0};
    char serial_hex[33] = {0};
    char ak_name_hex[2 * sizeof(rec->ak_name) + 1] = {0};
    charra_hex_encode(
            rec->ek_fingerprint, sizeof(rec->ek_fingerprint), ek_fingerprint_hex);
    charra_hex_encode(rec->serial, sizeof(rec->serial), serial_hex);
    charra_hex_encode(rec->ak_name, rec->ak_name_len, ak_name_hex);

    fprintf(out, "%s %s %u %s %lld %lld %u\n", ek_fingerprint_hex, serial_hex,
            rec->ak_name_len, ak_name_hex, (long long)rec->issued_at,
            (long long)rec->expires_at, rec->revoked ? 1 : 0);
}

CHARRA_RC charra_ak_state_save(const char* path,
        const charra_ak_state_record* records, uint32_t count) {
    return charra_record_file_save(path,
            "ek_fingerprint serial ak_name_len ak_name issued_at expires_at "
            "revoked",
            records, sizeof(charra_ak_state_record), count,
            format_ak_state_line);
}

bool charra_ak_state_find_by_ek_fingerprint(
        const charra_ak_state_record* records, uint32_t count,
        const uint8_t fingerprint[32], uint32_t* index_out) {
    if (records == NULL || fingerprint == NULL || index_out == NULL) {
        return false;
    }
    /* Scan backward: after N renewals, up to N-1 revoked records for the
     * same fingerprint can exist (oldest first, since charra_ak_state_renew
     * always appends). Only the most recent one -- last in the array --
     * is the one a caller (including renew() itself, revoking the record a
     * fresh renewal supersedes) means by "the record for this EK." A
     * forward scan would keep returning the oldest, already-revoked one
     * instead. */
    for (uint32_t i = count; i > 0; i--) {
        uint32_t idx = i - 1;
        if (memcmp(records[idx].ek_fingerprint, fingerprint, 32) == 0) {
            *index_out = idx;
            return true;
        }
    }
    return false;
}

bool charra_ak_state_find_by_serial(const charra_ak_state_record* records,
        uint32_t count, const uint8_t serial[16], uint32_t* index_out) {
    if (records == NULL || serial == NULL || index_out == NULL) {
        return false;
    }
    for (uint32_t i = 0; i < count; i++) {
        if (memcmp(records[i].serial, serial, 16) == 0) {
            *index_out = i;
            return true;
        }
    }
    return false;
}

CHARRA_RC charra_ak_state_renew(const char* path,
        const uint8_t ek_fingerprint[32],
        const charra_ak_state_record* new_record) {
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
    charra_ak_state_record* records = NULL;
    uint32_t count = 0;
    if ((charra_r = charra_ak_state_load(path, &records, &count)) !=
            CHARRA_RC_SUCCESS) {
        goto unlock;
    }

    uint32_t existing_index = 0;
    if (charra_ak_state_find_by_ek_fingerprint(
                records, count, ek_fingerprint, &existing_index)) {
        records[existing_index].revoked = true;
    }

    charra_ak_state_record* grown = realloc(
            records, (count + 1) * sizeof(charra_ak_state_record));
    if (grown == NULL) {
        charra_r = CHARRA_RC_ERROR;
        goto cleanup;
    }
    records = grown;
    records[count] = *new_record;
    records[count].revoked = false;
    count++;

    charra_r = charra_ak_state_save(path, records, count);

cleanup:
    free(records);
unlock:
    charra_record_file_unlock(lock_file);
    return charra_r;
}

bool charra_ak_state_is_valid(
        const charra_ak_state_record* record, time_t now) {
    if (record == NULL) {
        return false;
    }
    return !record->revoked && record->expires_at > now;
}

bool charra_ak_state_check_serial_valid(const char* ak_state_file_path,
        const uint8_t serial[16], uint8_t ek_fingerprint_out[32],
        time_t* expires_at_out) {
    charra_ak_state_record* records = NULL;
    uint32_t count = 0;
    if (charra_ak_state_load(ak_state_file_path, &records, &count) !=
            CHARRA_RC_SUCCESS) {
        charra_log_error(
                "[" LOG_NAME "] Could not load AK-provisioning state.");
        return false;
    }
    charra_log_info("[" LOG_NAME "] Checking AK serial against "
                    "AK-provisioning state '%s' (%u issuance record(s)).",
            ak_state_file_path, count);

    bool valid = false;
    uint32_t index = 0;
    if (charra_ak_state_find_by_serial(records, count, serial, &index)) {
        valid = charra_ak_state_is_valid(&records[index], time(NULL));
        /* Report the identity whenever the serial is ON RECORD, valid or
         * not: a revoked or expired certificate still tells us WHICH RP
         * this is, and callers need that to keep appraising (e.g. to look
         * up its qualification) rather than stopping at the first failure.
         * The return value alone says whether it is currently valid. */
        if (ek_fingerprint_out != NULL) {
            memcpy(ek_fingerprint_out, records[index].ek_fingerprint, 32);
        }
        if (expires_at_out != NULL) {
            *expires_at_out = records[index].expires_at;
        }
        if (!valid) {
            charra_log_error("[" LOG_NAME "]     => AK certificate's serial "
                             "is on record but revoked or expired!");
        }
    } else {
        charra_log_error("[" LOG_NAME "]     => AK certificate's serial has "
                         "no issuance record (never issued by this "
                         "Verifier, or state file lost)!");
    }

    free(records);
    return valid;
}
