/* SPDX-License-Identifier: BSD-3-Clause */
/*****************************************************************************
 * Copyright 2019, Fraunhofer Institute for Secure Information Technology SIT.
 * All rights reserved.
 ****************************************************************************/

/**
 * @file io_util.c
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

#include "io_util.h"
#include "../common/charra_log.h"
#include "../common/charra_macro.h"
#include "../core/charra_cvector.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void charra_print_hex(const charra_log_t level, const size_t buf_len,
        const uint8_t* const buf, const char* const prefix,
        const char* const postfix, const bool upper_case) {
    const char* const hex_case = upper_case ? "%02X" : "%02x";

    charra_log_log_raw(level, "%s", prefix);
    /* print upper case */
    for (size_t i = 0; i < buf_len; ++i) {
        charra_log_log_raw(level, hex_case, buf[i]);
    }
    charra_log_log_raw(level, "%s", postfix);
}

void charra_print_str(const charra_log_t level, const size_t buf_len,
        const uint8_t* const buf, const char* const prefix,
        const char* const postfix) {

    charra_log_log_raw(level, "%s", prefix);
    /* print upper case */
    for (size_t i = 0; i < buf_len; ++i) {
        charra_log_log_raw(level, "%c", buf[i]);
    }
    charra_log_log_raw(level, "%s", postfix);
}

void charra_print_pcr_content(const charra_log_t level,
        const uint8_t* const pcr_selection, const uint32_t pcr_selection_len,
        const uint8_t** const pcrs) {
    for (uint32_t i = 0; i < pcr_selection_len; i++) {
        charra_log_log_raw(level, "%02d: 0x", pcr_selection[i]);
        for (uint32_t j = 0; j < TPM2_SHA256_DIGEST_SIZE; j++) {
            charra_print_hex(level, 1, &pcrs[i][j], "", "", true);
        }
        charra_log_log_raw(level, "\n");
    }
}

CHARRA_RC charra_io_file_exists(const char* const filename) {
    if (access(filename, F_OK) == 0) {
        return CHARRA_RC_SUCCESS;
    } else {
        return CHARRA_RC_ERROR;
    }
}

CHARRA_RC charra_io_read_file(const char* filename, char** const file_content,
        size_t* const file_content_len) {
    CHARRA_RC r = CHARRA_RC_SUCCESS;
    FILE* fp = NULL;

    /* open file */
    if ((fp = fopen(filename, "r")) == NULL) {
        charra_log_error("Cannot open file '%s'.", filename);
        r = CHARRA_RC_ERROR;
        goto error;
    }

    /* get file size */
    ssize_t file_size = -1;
    /* Declared before the first 'goto error' rather than at its first use:
     * jumping over a declaration does not run its initializer, so the
     * cleanup at error: would otherwise test and free an indeterminate
     * pointer. */
    char* file_buffer = NULL;
    {
        /* go to end of file */
        if (fseek(fp, 0L, SEEK_END) != 0) {
            r = CHARRA_RC_ERROR;
            goto error;
        }

        /* get position (i.e., the file size) */
        if ((file_size = ftell(fp)) == -1) {
            r = CHARRA_RC_ERROR;
            goto error;
        }

        /* go back to beginning of file */
        if (fseek(fp, 0L, SEEK_SET) != 0) {
            r = CHARRA_RC_ERROR;
            goto error;
        }
    }

    /* allocate memory */
    if ((file_buffer = malloc(file_size * sizeof(*file_buffer))) == NULL) {
        r = CHARRA_RC_ERROR;
        goto error;
    }

    size_t read_size = fread(file_buffer, sizeof(*file_buffer), file_size, fp);
    if (read_size < (size_t)file_size) {
        charra_log_error("Error while reading file '%s', expected size %zu, "
                         "got size %zu.",
                filename, file_size, read_size);
        charra_free_if_not_null(file_buffer);
        r = CHARRA_RC_ERROR;
        goto error;
    }

    /* set output arguments */
    *file_content = file_buffer;
    *file_content_len = read_size;

error:

    /* close file */
    if (fp != NULL) {
        if (fclose(fp) != 0) {
            charra_log_error("Error closing file '%s'.", filename);
            charra_free_if_not_null(file_buffer);
            return CHARRA_RC_ERROR;
        }
    }

    return r;
}

CHARRA_RC charra_io_write_file(
        const char* filename, const uint8_t* data, size_t data_len) {
    if (filename == NULL || data == NULL) {
        return CHARRA_RC_BAD_ARGUMENT;
    }

    FILE* fp = NULL;
    if ((fp = fopen(filename, "wb")) == NULL) {
        charra_log_error("Cannot open file '%s' for writing.", filename);
        return CHARRA_RC_ERROR;
    }

    CHARRA_RC r = CHARRA_RC_SUCCESS;
    size_t written = fwrite(data, sizeof(*data), data_len, fp);
    if (written < data_len) {
        charra_log_error("Error while writing file '%s', expected size %zu, "
                         "wrote size %zu.",
                filename, data_len, written);
        r = CHARRA_RC_ERROR;
    }

    if (fclose(fp) != 0) {
        charra_log_error("Error closing file '%s'.", filename);
        r = CHARRA_RC_ERROR;
    }

    return r;
}

void charra_io_free_file_buffer(char** const file_content) {
    charra_free_if_not_null(*file_content);
}

CHARRA_RC charra_io_read_continuous_binary_file(const char* const filename,
        uint8_t** const file_content, size_t* const file_content_len) {
    /* the size of the event log chunks which get read at once */
#define IMA_EVENT_LOG_STEP_SIZE 1024
    /*
     * Use logarithmic growth for the cvector. Otherwise it would grow on
     * every call to cvector_push_back().
     */
#define CVECTOR_LOGARITHMIC_GROWTH

    cvector_vector_type(uint8_t) file_content_cvector = NULL;
    FILE* fp = NULL;
    if ((fp = fopen(filename, "rb")) == NULL) {
        charra_log_error("Cannot open file '%s'.", filename);
        return CHARRA_RC_ERROR;
    }
    uint8_t processing_array[IMA_EVENT_LOG_STEP_SIZE] = {0};
    size_t read_size = 0;
    do {
        read_size = fread(processing_array, sizeof(*processing_array),
                IMA_EVENT_LOG_STEP_SIZE, fp);
        for (size_t i = 0; i < read_size; ++i) {
            cvector_push_back(file_content_cvector, processing_array[i]);
        }
    } while (read_size == IMA_EVENT_LOG_STEP_SIZE);

    /* flush and close file */
    if (fflush(fp) != 0) {
        charra_log_error("Error flushing file '%s'.", filename);
        charra_free_if_not_null_ex(file_content_cvector, cvector_free);
        return CHARRA_RC_ERROR;
    }
    if (fclose(fp) != 0) {
        charra_log_error("Error closing file '%s'.", filename);
        charra_free_if_not_null_ex(file_content_cvector, cvector_free);
        return CHARRA_RC_ERROR;
    }
    *file_content_len = cvector_size(file_content_cvector);
    *file_content = file_content_cvector;
    return CHARRA_RC_SUCCESS;
}

void charra_io_free_continuous_file_buffer(uint8_t** const file_content) {
    charra_free_if_not_null_ex(*file_content, cvector_free);
}

/* Path of the lock this process owns, so atexit() can remove it. Static
 * because atexit() handlers take no argument; only ever set once. */
static char state_lock_owned_path[256] = {0};

static void charra_io_release_state_lock(void) {
    if (state_lock_owned_path[0] != '\0') {
        unlink(state_lock_owned_path);
    }
}

/* Whether a PID belongs to a process that is still doing something.
 *
 * kill(pid, 0) alone is not enough: it succeeds on a ZOMBIE, and a container
 * whose PID 1 is not a reaping init (a plain shell or `sleep` is common)
 * accumulates zombies that never go away. A SIGKILLed instance would then hold
 * its state lock forever, since its PID still answers. Measured exactly that
 * way -- three killed Verifiers sat in state Z and kept their locks. */
static bool charra_io_pid_is_live(pid_t pid) {
    char stat_path[64] = {0};
    snprintf(stat_path, sizeof(stat_path), "/proc/%ld/stat", (long)pid);
    FILE* stat_file = fopen(stat_path, "r");
    if (stat_file != NULL) {
        char line[512] = {0};
        char* got = fgets(line, sizeof(line), stat_file);
        fclose(stat_file);
        if (got != NULL) {
            /* "<pid> (<comm>) <state> ..." -- comm is arbitrary and may hold
             * spaces or parentheses, so anchor on the LAST ')' instead of
             * tokenizing from the left. */
            const char* rparen = strrchr(line, ')');
            if (rparen != NULL && rparen[1] == ' ') {
                return rparen[2] != 'Z';
            }
        }
        return true; /* unreadable -- never steal a lock on a guess */
    }
    /* No /proc entry: either the process is gone or this is not Linux, where
     * kill() is the only portable answer available. */
    return !(kill(pid, 0) != 0 && errno == ESRCH);
}

/* Reads "<pid> <hostname>" back out of an existing lock file and decides
 * whether its owner is demonstrably gone. Only answers true for a lock this
 * same host wrote: PIDs are per-namespace, so a PID from another host (or
 * another container) may well be live here by coincidence, and treating that
 * as stale would hand out a lock somebody else still holds. */
static bool charra_io_state_lock_is_stale(
        int fd, char* holder_out, size_t holder_out_len) {
    char contents[288] = {0};
    ssize_t n = pread(fd, contents, sizeof(contents) - 1, 0);
    if (n <= 0) {
        /* Created but never filled in -- a previous owner died between
         * open() and write(). Nobody can be holding it. */
        snprintf(holder_out, holder_out_len, "unknown");
        return true;
    }

    long holder_pid = 0;
    char holder_host[256] = {0};
    if (sscanf(contents, "%ld %255s", &holder_pid, holder_host) != 2) {
        snprintf(holder_out, holder_out_len, "unreadable");
        return false;
    }
    snprintf(holder_out, holder_out_len, "PID %ld on host %s", holder_pid,
            holder_host);

    char this_host[256] = {0};
    if (gethostname(this_host, sizeof(this_host) - 1) != 0 ||
            strcmp(this_host, holder_host) != 0) {
        return false; /* another host/container -- unverifiable, so assume live */
    }
    return !charra_io_pid_is_live((pid_t)holder_pid);
}

CHARRA_RC charra_io_lock_state_dir(
        const char* const lock_file_path, const char* const role) {
    if (lock_file_path == NULL || role == NULL) {
        return CHARRA_RC_BAD_ARGUMENT;
    }

    /* O_EXCL, not flock(): flock() is silently a no-op on some shared
     * filesystems (every caller "acquires" it), and a bind-mounted state
     * directory shared between containers is exactly the case this guard
     * exists to catch. An atomic exclusive create works everywhere. */
    int fd = open(lock_file_path, O_RDWR | O_CREAT | O_EXCL, 0644);
    if (fd < 0 && errno == EEXIST) {
        fd = open(lock_file_path, O_RDWR);
        char holder[320] = {0};
        if (fd < 0) {
            charra_log_error("Cannot open state lock file '%s': %s.",
                    lock_file_path, strerror(errno));
            return CHARRA_RC_ERROR;
        }
        if (!charra_io_state_lock_is_stale(fd, holder, sizeof(holder))) {
            charra_log_error("Another %s already holds the state directory "
                             "that '%s' guards (%s).",
                    role, lock_file_path, holder);
            charra_log_error("Two instances sharing one state directory "
                             "revoke each other's certificates and overwrite "
                             "each other's caches, which surfaces only as "
                             "unexplained attestation failures. Refusing to "
                             "start.");
            charra_log_error("If that instance is genuinely gone, delete "
                             "'%s' and start again.",
                    lock_file_path);
            close(fd);
            return CHARRA_RC_ERROR;
        }


        /* Re-create rather than reuse the descriptor, so the reclaim is as
         * atomic as the original acquisition: if two instances start
         * together after a crash they both see the same stale lock, and
         * only the one whose O_EXCL create wins may have it. */
        close(fd);
        unlink(lock_file_path);
        fd = open(lock_file_path, O_RDWR | O_CREAT | O_EXCL, 0644);
        if (fd < 0) {
            charra_log_error("Another %s reclaimed the state lock '%s' at the "
                             "same moment. Refusing to start.",
                    role, lock_file_path);
            return CHARRA_RC_ERROR;
        }
        charra_log_info("Reclaimed state lock '%s' from a %s that exited "
                        "without releasing it (%s).",
                lock_file_path, role, holder);
    } else if (fd < 0) {
        charra_log_error("Cannot create state lock file '%s': %s.",
                lock_file_path, strerror(errno));
        return CHARRA_RC_ERROR;
    }

    /* Identifies the holder in the message above next time. The file is
     * always freshly created by this point, so there is nothing to truncate. */
    char this_host[256] = {0};
    if (gethostname(this_host, sizeof(this_host) - 1) != 0) {
        snprintf(this_host, sizeof(this_host), "unknown");
    }
    char owner[320] = {0};
    int owner_len = snprintf(
            owner, sizeof(owner), "%ld %s\n", (long)getpid(), this_host);
    if (owner_len > 0) {
        /* snprintf returns what it WOULD have written; clamp before it
         * becomes a length passed to pwrite(). */
        size_t to_write = ((size_t)owner_len < sizeof(owner))
                                  ? (size_t)owner_len
                                  : sizeof(owner) - 1;
        ssize_t written = pwrite(fd, owner, to_write, 0);
        (void)written; /* diagnostic only -- never worth failing startup over */
    }
    close(fd);

    snprintf(state_lock_owned_path, sizeof(state_lock_owned_path), "%s",
            lock_file_path);
    atexit(charra_io_release_state_lock);
    return CHARRA_RC_SUCCESS;
}
