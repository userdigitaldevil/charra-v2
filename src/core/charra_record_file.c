/**
 * @file charra_record_file.c
 * @brief See charra_record_file.h.
 */

#include "charra_record_file.h"

#include <stdlib.h>
#include <string.h>
#include <sys/file.h>

#include "../common/charra_log.h"

#define LOG_NAME "charra_record_file"

CHARRA_RC charra_record_file_load(const char* path, const char* description,
        size_t record_size, charra_record_parse_fn parse, void** records_out,
        uint32_t* count_out) {
    if (path == NULL || description == NULL || record_size == 0 ||
            parse == NULL || records_out == NULL || count_out == NULL) {
        return CHARRA_RC_BAD_ARGUMENT;
    }
    *records_out = NULL;
    *count_out = 0;

    FILE* f = fopen(path, "r");
    if (f == NULL) {
        charra_log_info("[" LOG_NAME "] No %s file at '%s' yet.", description,
                path);
        return CHARRA_RC_SUCCESS;
    }

    char* records = NULL;
    uint32_t count = 0;
    uint32_t capacity = 0;
    char line[512];
    while (fgets(line, sizeof(line), f) != NULL) {
        const char* p = line;
        while (*p == ' ' || *p == '\t') {
            p++;
        }
        if (*p == '#' || *p == '\n' || *p == '\0') {
            continue; /* comment or blank line */
        }

        if (count == capacity) {
            uint32_t new_capacity = (capacity == 0) ? 8 : capacity * 2;
            char* grown = realloc(records, new_capacity * record_size);
            if (grown == NULL) {
                free(records);
                fclose(f);
                return CHARRA_RC_ERROR;
            }
            records = grown;
            capacity = new_capacity;
        }

        /* Parsed straight into its final slot, so a rejected line simply
         * leaves the slot to be reused by the next one. */
        void* slot = records + ((size_t)count * record_size);
        memset(slot, 0, record_size);
        if (parse(p, slot)) {
            count++;
        }
    }
    fclose(f);

    *records_out = records;
    *count_out = count;
    return CHARRA_RC_SUCCESS;
}

CHARRA_RC charra_record_file_save(const char* path, const char* header,
        const void* records, size_t record_size, uint32_t count,
        charra_record_format_fn format) {
    if (path == NULL || header == NULL || record_size == 0 ||
            format == NULL || (records == NULL && count != 0)) {
        return CHARRA_RC_BAD_ARGUMENT;
    }

    FILE* f = fopen(path, "w");
    if (f == NULL) {
        charra_log_error(
                "[" LOG_NAME "] Could not open '%s' for writing.", path);
        return CHARRA_RC_ERROR;
    }

    fprintf(f, "# %s\n", header);
    for (uint32_t i = 0; i < count; i++) {
        format((const char*)records + ((size_t)i * record_size), f);
    }

    fclose(f);
    return CHARRA_RC_SUCCESS;
}

CHARRA_RC charra_record_file_lock(const char* path, FILE** lock_file_out) {
    if (path == NULL || lock_file_out == NULL) {
        return CHARRA_RC_BAD_ARGUMENT;
    }
    *lock_file_out = NULL;

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

    *lock_file_out = lock_file;
    return CHARRA_RC_SUCCESS;
}

void charra_record_file_unlock(FILE* lock_file) {
    if (lock_file == NULL) {
        return;
    }
    flock(fileno(lock_file), LOCK_UN);
    fclose(lock_file);
}
