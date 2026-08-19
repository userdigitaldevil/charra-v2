/**
 * @file charra_record_file.h
 * @brief The line-oriented record files the Verifier keeps under state/.
 *
 * Both ledgers -- issued AK certificates and passed RP qualifications --
 * are the same thing on disk: a comment header, then one whitespace-
 * separated record per line, rewritten wholesale under a `<path>.lock`
 * companion lock. Only the fields differ, so only the per-line parse and
 * format belong to each module; everything around them lives here.
 */

#ifndef CHARRA_RECORD_FILE_H
#define CHARRA_RECORD_FILE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "../common/charra_error.h"

/**
 * @brief Parses one already-trimmed, non-comment line into a record.
 * @return false to skip the line; the caller logs nothing, so an
 * implementation that rejects a line should say why itself.
 */
typedef bool (*charra_record_parse_fn)(const char* line, void* record_out);

/** @brief Writes one record as a single line, newline included. */
typedef void (*charra_record_format_fn)(const void* record, FILE* out);

/**
 * @brief Read every record in a file into a malloc'd array.
 *
 * A missing file is SUCCESS with zero records, not an error: a fresh
 * deployment simply has not written one yet.
 *
 * @param[in] description names the file in the "none yet" log line, e.g.
 * "AK state".
 * @param[in] record_size sizeof the caller's record type.
 * @param[out] records_out malloc'd array of count_out records; caller frees.
 * NULL when the count is zero.
 */
CHARRA_RC charra_record_file_load(const char* path, const char* description,
        size_t record_size, charra_record_parse_fn parse, void** records_out,
        uint32_t* count_out);

/**
 * @brief Rewrite a file with exactly these records.
 *
 * @param[in] header the leading comment line, without '#' or newline.
 */
CHARRA_RC charra_record_file_save(const char* path, const char* header,
        const void* records, size_t record_size, uint32_t count,
        charra_record_format_fn format);

/**
 * @brief Take the exclusive lock guarding a read-modify-write of path.
 *
 * The lock is a separate `<path>.lock` file rather than path itself, since
 * saving rewrites path from scratch. Pair every success with
 * charra_record_file_unlock().
 */
CHARRA_RC charra_record_file_lock(const char* path, FILE** lock_file_out);

/** @brief Releases a lock taken by charra_record_file_lock(). */
void charra_record_file_unlock(FILE* lock_file);

#endif /* CHARRA_RECORD_FILE_H */
