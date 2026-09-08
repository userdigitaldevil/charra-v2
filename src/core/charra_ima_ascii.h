/**
 * @file charra_ima_ascii.h
 * @brief The ASCII IMA measurement log -- the format a real kernel exposes
 * at /sys/kernel/security/ima/ascii_runtime_measurements, and the format
 * every log this system reads or writes now travels in.
 *
 * One record per line, five space-separated columns:
 *
 *   10 <template_digest hex> ima-ng sha256:<file digest hex> <path>
 *
 * This is a *serialisation*, not the thing IMA hashes. template_digest is
 * always computed over the canonical binary template_data --
 *
 *   u32(d_len) | "<alg>:" '\0' | file digest | u32(n_len) | path '\0'
 *
 * -- with the u32 lengths little-endian, so a record's digest cannot be
 * checked without rebuilding those bytes. Everything downstream (replay,
 * self-consistency, PCR extend) therefore keeps working on the binary form;
 * this file is only the boundary where logs enter and leave.
 *
 * VERIFIED against 167 real records from a Huawei BTS3900/BTS5900 base
 * station (charra-ressources/professor_evidence/evidence.txt): all 167
 * template digests reproduce exactly under the encoding above. That
 * measurement is what settled two details worth stating, because both had
 * been guessed wrong before:
 *
 *  - the d-ng algorithm prefix is EIGHT bytes, "sha256:" plus a NUL, so a
 *    sha256 d-ng field is 40 bytes and not 39. See CHARRA_IMA_ALGO_PREFIX
 *    in charra_event_log.h.
 *  - the n-ng field carries the path's trailing NUL, and its u32 length
 *    counts it.
 *
 * Line wrapping. The captured log above is space-padded to 80-column lines,
 * so a record spans two to four physical lines. That is an artefact of how
 * it was exported, not of the format -- a live kernel emits one unpadded
 * record per line. The parser accepts both: a physical line begins a new
 * record only if it looks like a record header, and anything else is
 * treated as a continuation. The writer always emits unpadded, one record
 * per line, so a log that round-trips through here comes out canonical.
 */

#ifndef CHARRA_IMA_ASCII_H
#define CHARRA_IMA_ASCII_H

#include <stddef.h>
#include <stdint.h>

#include "../common/charra_error.h"

/**
 * @brief Parse an ASCII IMA log into the binary form the rest of the system
 * uses.
 *
 * Tolerant of the 80-column padding described above, of CRLF, and of a
 * missing final newline. Rejects anything that is not "ima-ng": the legacy
 * "ima" template has a different layout, and guessing at it would silently
 * corrupt every following entry.
 *
 * The digest width is taken from each record and must be uniform across the
 * log -- 20 bytes (SHA-1) or 32 (SHA-256). A real kernel is uniform here,
 * and a log that is not is malformed rather than interesting.
 *
 * @param[in] text ASCII log; may be NULL only if text_len is 0
 * @param[in] text_len length of text; 0 is valid and yields an empty log
 * @param[out] log_out receives a malloc'd binary log; caller frees. NULL if
 * the input held no records.
 * @param[out] log_len_out length of *log_out
 * @returns CHARRA_RC_SUCCESS, CHARRA_RC_BAD_ARGUMENT on bad arguments,
 * CHARRA_RC_MARSHALING_ERROR on a malformed record, CHARRA_RC_ERROR on
 * allocation failure.
 */
CHARRA_RC charra_ima_ascii_parse(const char* text, size_t text_len,
        uint8_t** log_out, uint32_t* log_len_out);

/**
 * @brief Render a binary IMA log back to ASCII, one unpadded record per
 * line, each terminated by '\n'.
 *
 * The inverse of charra_ima_ascii_parse() for any log that came through it,
 * and the reason log_a and log_r can be diffed column for column: redaction
 * changes the path column and the template_digest that covers it, and
 * nothing else moves.
 *
 * @param[out] text_out receives a malloc'd NUL-terminated string; caller
 * frees. The NUL is not counted in *text_len_out.
 */
CHARRA_RC charra_ima_ascii_emit(const uint8_t* log, uint32_t log_len,
        char** text_out, size_t* text_len_out);

/**
 * @brief Read an ASCII IMA log from disk and parse it.
 *
 * Convenience over charra_ima_ascii_parse() for the roles that name a log
 * on the command line.
 */
CHARRA_RC charra_ima_ascii_read_file(
        const char* path, uint8_t** log_out, uint32_t* log_len_out);

#endif /* CHARRA_IMA_ASCII_H */
