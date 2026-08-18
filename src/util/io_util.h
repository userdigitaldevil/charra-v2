/* SPDX-License-Identifier: BSD-3-Clause */
/*****************************************************************************
 * Copyright 2019, Fraunhofer Institute for Secure Information Technology SIT.
 * All rights reserved.
 ****************************************************************************/

/**
 * @file io_util.h
 * @author Michael Eckel (michael.eckel@sit.fraunhofer.de)
 * @brief Provides I/O functions, including print.
 * @version 0.1
 * @date 2019-12-22
 *
 * @copyright Copyright 2019, Fraunhofer Institute for Secure Information
 * Technology SIT. All rights reserved.
 *
 * @license BSD 3-Clause "New" or "Revised" License (SPDX-License-Identifier:
 * BSD-3-Clause).
 */

#ifndef IO_UTIL_H
#define IO_UTIL_H

#include "../common/charra_error.h"
#include "../common/charra_log.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <tss2/tss2_tpm2_types.h>

#define CHARRA_BYTE_TO_BINARY_PATTERN "%c%c%c%c%c%c%c%c"
#define CHARRA_BYTE_TO_BINARY(byte)                                            \
    (byte & 0x80 ? '1' : '0'), (byte & 0x40 ? '1' : '0'),                      \
            (byte & 0x20 ? '1' : '0'), (byte & 0x10 ? '1' : '0'),              \
            (byte & 0x08 ? '1' : '0'), (byte & 0x04 ? '1' : '0'),              \
            (byte & 0x02 ? '1' : '0'), (byte & 0x01 ? '1' : '0')

/**
 * @brief
 *
 * @param level the log level to print at
 * @param buf_len Length of the buffer to be printed.
 * @param buf The buffer to be printed.
 * @param prefix A prefix to the output, e.g. "0x", or leave it empty ("").
 * @param postfix  A postfix to the output, e.g. "\n", or leave it empty ("").
 * @param upper_case true: print in uppercase (e.g. "012..ABCDEF"); false: print
 * in lowercase (e.g. "012..abcdef").
 */
void charra_print_hex(const charra_log_t level, const size_t buf_len,
        const uint8_t* const buf, const char* const prefix,
        const char* const postfix, const bool upper_case);

/**
 * @brief
 *
 * @param level the log level to print at
 * @param buf_len Length of the buffer to be printed.
 * @param buf The buffer to be printed.
 * @param prefix A prefix to the output, e.g. an indentation ("  "), or leave it
 * empty ("").
 * @param postfix  A postfix to the output, e.g. "\n", or leave it empty ("").
 */
void charra_print_str(const charra_log_t level, const size_t buf_len,
        const uint8_t* const buf, const char* const prefix,
        const char* const postfix);

/**
 * @brief Print PCR content of selected PCRs.
 *
 * @param level the log level to print at
 * @param pcr_selection the indexes of selected PCRs
 * @param pcr_selection_len the number of PCRs to print
 * @param pcrs the content of the PCRs
 */
void charra_print_pcr_content(const charra_log_t level,
        const uint8_t* const pcr_selection, const uint32_t pcr_selection_len,
        const uint8_t** const pcrs);

/**
 * @brief Checks if file is existing.
 *
 * @param filename the path of the file
 */
CHARRA_RC charra_io_file_exists(const char* const filename);

/**
 * @brief read file into a buffer. The buffer will be initialized in this
 * function.
 *
 * @param[in] filename the path of the file to read
 * @param[out] file_content A pointer to the buffer, assumed to be uninitialized
 * upon calling.
 * @param[out] file_content_len The actual length of the file (aka the size of
 * file_content).
 * @return CHARRA_RC CHARRA_RC_SUCCESS on success, otherwise CHARRA_RC_ERROR
 */
CHARRA_RC charra_io_read_file(const char* filename, char** const file_content,
        size_t* const file_content_len);

/**
 * @brief Write a buffer to a file, creating it if it does not exist and
 * truncating it if it does (fopen mode "wb").
 *
 * @param[in] filename the path of the file to write
 * @param[in] data the buffer to write
 * @param[in] data_len length of data
 * @return CHARRA_RC_SUCCESS on success, CHARRA_RC_BAD_ARGUMENT on NULL
 * filename/data, CHARRA_RC_ERROR if the file could not be opened or the
 * full buffer could not be written
 */
CHARRA_RC charra_io_write_file(
        const char* filename, const uint8_t* data, size_t data_len);

/**
 * @brief free buffer holding the file content. Alternatively
 * free(*file_content) can be called directly.
 *
 * @param[in] file_content A pointer to the buffer.
 */
void charra_io_free_file_buffer(char** const file_content);

/**
 * @brief read binary file of unknown length into a cvector. Used for IMA event
 * log reading, which is a char device. The cvector will be initialized inside
 * this function.
 *
 * @param[in] filename the path of the file to be read
 * @param[out] file_content A pointer to the cvector, assumed to be
 * uninitialized upon calling.
 * @param[out] file_content_len The actual length of the file (aka the size of
 * file_content).
 * @return CHARRA_RC CHARRA_RC_SUCCESS on success, otherwise CHARRA_RC_ERROR
 */
CHARRA_RC charra_io_read_continuous_binary_file(const char* const filename,
        uint8_t** const file_content, size_t* const file_content_len);

/**
 * @brief free cvector holding the file content.
 *
 * @param[in] file_content A pointer to the cvector.
 */
void charra_io_free_continuous_file_buffer(uint8_t** const file_content);

/**
 * @brief Take an exclusive lock on a runtime state directory so two
 * instances can never share one.
 *
 * Nothing under state/ is keyed by instance: a second process on the same
 * directory silently corrupts the first. Its /certify_ak revokes the running
 * instance's record in the shared issuance ledger, and its cache writes leave
 * the running instance presenting a certificate that no longer matches the
 * key it signs quotes with. The result is a permanent stream of failed
 * attestations whose logs blame revoked certificates and quote-signature
 * mismatches -- never the second process that actually caused them. Failing
 * loudly at startup is the only way that cause is ever visible.
 *
 * Uses an atomic O_EXCL create rather than flock(), which is silently a no-op
 * on some shared filesystems -- including a bind-mounted state directory
 * shared between containers, the very case this guards against. Released on
 * normal exit; a lock left behind by a killed process is reclaimed
 * automatically when it names a PID on this host that no longer exists.
 *
 * @param[in] lock_file_path file to create; its parent directory must exist.
 * @param[in] role name used in the error message, e.g. "relying_party".
 * @return CHARRA_RC_SUCCESS if the lock was taken, CHARRA_RC_ERROR if another
 * instance holds it or the file could not be created.
 */
CHARRA_RC charra_io_lock_state_dir(
        const char* const lock_file_path, const char* const role);

#endif /* IO_UTIL_H */
