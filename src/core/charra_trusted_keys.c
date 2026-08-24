/**
 * @file charra_trusted_keys.c
 * @brief See charra_trusted_keys.h.
 */

#include "charra_trusted_keys.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <mbedtls/bignum.h>
#include <mbedtls/pk.h>
#include <mbedtls/rsa.h>

#include "../common/charra_log.h"
#include "../util/crypto_util.h"
#include "../util/io_util.h"

#define LOG_NAME "trusted keys"

#define PEM_BEGIN "-----BEGIN PUBLIC KEY-----"
#define PEM_END "-----END PUBLIC KEY-----"

/**
 * @brief Do these two RSA public keys have the same modulus and exponent?
 *
 * Both halves are compared, not just the modulus: a key is (n, e), and
 * treating two keys that share n but differ in e as the same key would be
 * wrong even though this project's template always yields e = 65537.
 */
static bool rsa_keys_equal(
        const mbedtls_rsa_context* a, const mbedtls_rsa_context* b) {
    mbedtls_mpi a_n, a_e, b_n, b_e;
    mbedtls_mpi_init(&a_n);
    mbedtls_mpi_init(&a_e);
    mbedtls_mpi_init(&b_n);
    mbedtls_mpi_init(&b_e);

    bool equal = false;
    if (mbedtls_rsa_export(a, &a_n, NULL, NULL, NULL, &a_e) == 0 &&
            mbedtls_rsa_export(b, &b_n, NULL, NULL, NULL, &b_e) == 0) {
        equal = mbedtls_mpi_cmp_mpi(&a_n, &b_n) == 0 &&
                mbedtls_mpi_cmp_mpi(&a_e, &b_e) == 0;
    }

    mbedtls_mpi_free(&a_n);
    mbedtls_mpi_free(&a_e);
    mbedtls_mpi_free(&b_n);
    mbedtls_mpi_free(&b_e);
    return equal;
}

/**
 * @brief Read the `# name` comment sitting directly above a key, so a
 * match can be reported by the label the file gives it rather than by
 * position. Absent or non-comment line: leaves name_out empty.
 */
static void remember_label(
        const char* begin, const char* file_start, char* out, size_t out_size) {
    if (out == NULL || out_size == 0) {
        return;
    }
    out[0] = '\0';

    /* begin points at the "-----BEGIN" marker. Step back over the newline
     * that ends the line above it, then to that line's first character. */
    const char* p = begin;
    if (p - file_start < 2) {
        return;
    }
    p -= 2;
    while (p > file_start && *(p - 1) != '\n') {
        p--;
    }
    if (*p != '#') {
        return;
    }

    const char* line_end = strchr(p, '\n');
    if (line_end == NULL) {
        line_end = p + strlen(p);
    }
    p++; /* skip the '#' */
    while (p < line_end && *p == ' ') {
        p++;
    }

    size_t len = (size_t)(line_end - p);
    if (len >= out_size) {
        len = out_size - 1;
    }
    memcpy(out, p, len);
    out[len] = '\0';
}

CHARRA_RC charra_trusted_keys_check(const char* path,
        const TPM2B_PUBLIC* public_key, char* name_out, size_t name_out_size) {
    if (public_key == NULL) {
        return CHARRA_RC_BAD_ARGUMENT;
    }
    if (path == NULL) {
        path = CHARRA_TRUSTED_KEYS_DEFAULT_PATH;
    }

    char* buf = NULL;
    size_t buf_len = 0;
    if (charra_io_read_file(path, &buf, &buf_len) != CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Could not read the trust anchor "
                         "('%s'). No key can be trusted without it.",
                path);
        return CHARRA_RC_ERROR;
    }

    /* The candidate, converted once, outside the scan. */
    mbedtls_rsa_context candidate = {0};
    if (charra_crypto_tpm_pub_key_to_mbedtls_pub_key(public_key, &candidate) !=
            CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Could not convert the presented "
                         "public key for comparison.");
        charra_io_free_file_buffer(&buf);
        return CHARRA_RC_ERROR;
    }

    CHARRA_RC result = CHARRA_RC_VERIFICATION_FAILED;
    unsigned int examined = 0;

    const char* cursor = buf;
    for (;;) {
        const char* begin = strstr(cursor, PEM_BEGIN);
        if (begin == NULL) {
            break;
        }
        const char* end = strstr(begin, PEM_END);
        if (end == NULL) {
            charra_log_warn("[" LOG_NAME "] Trust anchor ('%s') has a key "
                            "without its END line; ignoring the remainder.",
                    path);
            break;
        }
        end += strlen(PEM_END);
        cursor = end;
        examined++;

        /* mbedtls insists a PEM buffer's length include the terminating
         * NUL, so this is a NUL-terminated copy of just this one key. */
        size_t entry_len = (size_t)(end - begin);
        char* entry = malloc(entry_len + 2);
        if (entry == NULL) {
            result = CHARRA_RC_ERROR;
            break;
        }
        memcpy(entry, begin, entry_len);
        entry[entry_len] = '\n';
        entry[entry_len + 1] = '\0';

        mbedtls_pk_context pk;
        mbedtls_pk_init(&pk);
        int rc = mbedtls_pk_parse_public_key(
                &pk, (const unsigned char*)entry, entry_len + 2);
        if (rc == 0 && mbedtls_pk_get_type(&pk) == MBEDTLS_PK_RSA &&
                rsa_keys_equal(mbedtls_pk_rsa(pk), &candidate)) {
            remember_label(begin, buf, name_out, name_out_size);
            result = CHARRA_RC_SUCCESS;
        } else if (rc != 0) {
            charra_log_warn("[" LOG_NAME "] Trust anchor ('%s') entry %u did "
                            "not parse as a public key: mbedtls -0x%04x.",
                    path, examined, (unsigned int)-rc);
        }
        mbedtls_pk_free(&pk);
        free(entry);

        if (result == CHARRA_RC_SUCCESS) {
            break;
        }
    }

    mbedtls_rsa_free(&candidate);
    charra_io_free_file_buffer(&buf);

    if (examined == 0) {
        charra_log_error("[" LOG_NAME "] The trust anchor ('%s') holds no "
                         "public key at all.",
                path);
        return CHARRA_RC_ERROR;
    }
    if (result != CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Key is not in the trust anchor "
                         "('%s'); checked %u key(s).",
                path, examined);
    }
    return result;
}
