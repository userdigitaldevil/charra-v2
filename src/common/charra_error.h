/* SPDX-License-Identifier: BSD-3-Clause */
/*****************************************************************************
 * Copyright 2019, Fraunhofer Institute for Secure Information Technology SIT.
 * All rights reserved.
 ****************************************************************************/

/**
 * @file charra_error.h
 * @author Michael Eckel (michael.eckel@sit.fraunhofer.de)
 * @brief
 * @version 0.1
 * @date 2019-09-19
 *
 * @copyright Copyright 2019, Fraunhofer Institute for Secure Information
 * Technology SIT. All rights reserved.
 *
 * @license BSD 3-Clause "New" or "Revised" License (SPDX-License-Identifier:
 * BSD-3-Clause).
 */

#ifndef CHARRA_ERROR_H
#define CHARRA_ERROR_H

#include <inttypes.h>

typedef uint32_t CHARRA_RC;
#define CHARRA_RC_SUCCESS ((CHARRA_RC)0x00000000)
#define CHARRA_RC_ERROR ((CHARRA_RC)0x00000001)
#define CHARRA_RC_CRYPTO_ERROR ((CHARRA_RC)0x0001ffff)
#define CHARRA_RC_NOT_YET_IMPLEMENTED ((CHARRA_RC)0xeeeeee)
#define CHARRA_RC_BAD_ARGUMENT ((CHARRA_RC)0x0000ffff)
#define CHARRA_RC_MARSHALING_ERROR ((CHARRA_RC)0x0000fffe)
#define CHARRA_RC_TPM ((CHARRA_RC)0x0002ffff)
#define CHARRA_RC_VERIFICATION_FAILED ((CHARRA_RC)0x000000ff)
#define CHARRA_RC_NO_MATCH ((CHARRA_RC)0x01010101)
#define CHARRA_RC_CLI_ERROR ((CHARRA_RC)0x0000aaaa)
#define CHARRA_RC_COAP_ERROR ((CHARRA_RC)0x0000C0AF)
#define CHARRA_RC_TIMEOUT ((CHARRA_RC)0x0000000f)

/**
 * @brief Human-readable name for a CHARRA_RC, for log lines like
 * "charra_r=255 (CHARRA_RC_VERIFICATION_FAILED)" instead of a bare number
 * that means nothing without looking up this header. static inline (header-
 * only, no charra_error.c) since it's a fixed small switch over the macros
 * above -- not worth a whole extra translation unit and Makefile entry.
 */
static inline const char* charra_rc_describe(CHARRA_RC rc) {
    switch (rc) {
    case CHARRA_RC_SUCCESS:
        return "CHARRA_RC_SUCCESS";
    case CHARRA_RC_ERROR:
        return "CHARRA_RC_ERROR";
    case CHARRA_RC_CRYPTO_ERROR:
        return "CHARRA_RC_CRYPTO_ERROR";
    case CHARRA_RC_NOT_YET_IMPLEMENTED:
        return "CHARRA_RC_NOT_YET_IMPLEMENTED";
    case CHARRA_RC_BAD_ARGUMENT:
        return "CHARRA_RC_BAD_ARGUMENT";
    case CHARRA_RC_MARSHALING_ERROR:
        return "CHARRA_RC_MARSHALING_ERROR";
    case CHARRA_RC_TPM:
        return "CHARRA_RC_TPM";
    case CHARRA_RC_VERIFICATION_FAILED:
        return "CHARRA_RC_VERIFICATION_FAILED -- e.g. an AES-GCM "
               "authentication tag mismatch or an X.509 chain that failed "
               "to verify";
    case CHARRA_RC_NO_MATCH:
        return "CHARRA_RC_NO_MATCH";
    case CHARRA_RC_CLI_ERROR:
        return "CHARRA_RC_CLI_ERROR";
    case CHARRA_RC_COAP_ERROR:
        return "CHARRA_RC_COAP_ERROR";
    case CHARRA_RC_TIMEOUT:
        return "CHARRA_RC_TIMEOUT";
    default:
        return "unknown CHARRA_RC";
    }
}

#endif /* CHARRA_ERROR_H */
