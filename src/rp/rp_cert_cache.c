/**
 * @file rp_cert_cache.c
 * @brief See rp_cert_cache.h.
 */

#include "rp_cert_cache.h"

#include <stdlib.h>
#include <string.h>

#include <mbedtls/x509_crt.h>

#include "../common/charra_log.h"
#include "../util/crypto_util.h"
#include "../util/io_util.h"
#include "rp_shared.h"

#define LOG_NAME "relying party"

bool rp_cert_cache_load(const char* cert_path, const char* description,
        uint8_t** der_out, uint32_t* der_len_out, time_t* expires_at_out) {
    if (cert_path == NULL || description == NULL) {
        return false;
    }
    if (charra_io_file_exists(cert_path) != CHARRA_RC_SUCCESS) {
        return false; /* nothing cached yet -- normal on a first run */
    }

    char* file_buf = NULL;
    size_t file_len = 0;
    if (charra_io_read_file(cert_path, &file_buf, &file_len) !=
            CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Could not read cached %s -- "
                         "re-provisioning.",
                description);
        return false;
    }

    bool usable = false;
    time_t expires_at = 0;
    mbedtls_x509_crt cached_cert;
    mbedtls_x509_crt_init(&cached_cert);
    if (mbedtls_x509_crt_parse(&cached_cert, (const uint8_t*)file_buf,
                file_len) == 0) {
        long days_left = charra_crypto_x509_days_until_expiry(&cached_cert);
        expires_at = charra_crypto_x509_expiry_time(&cached_cert);
        if (!charra_cert_needs_renewal(expires_at)) {
            usable = true;
            charra_log_info("[" LOG_NAME "] Reloading previously issued %s "
                            "(cached, expires in %ld day(s)).",
                    description, days_left);
        } else {
            charra_log_info("[" LOG_NAME "] Cached %s expires in %ld day(s) "
                            "-- re-provisioning.",
                    description, days_left);
        }
    } else {
        charra_log_error("[" LOG_NAME "] Cached %s does not parse -- "
                         "re-provisioning.",
                description);
    }
    mbedtls_x509_crt_free(&cached_cert);

    if (usable && der_out != NULL) {
        /* Copied out of the io_util buffer so the caller can keep it after
         * this function frees the file buffer below. */
        *der_out = malloc(file_len);
        if (*der_out == NULL) {
            usable = false;
        } else {
            memcpy(*der_out, file_buf, file_len);
            if (der_len_out != NULL) {
                *der_len_out = (uint32_t)file_len;
            }
        }
    }
    charra_io_free_file_buffer(&file_buf);

    if (usable && expires_at_out != NULL) {
        *expires_at_out = expires_at;
    }
    return usable;
}
