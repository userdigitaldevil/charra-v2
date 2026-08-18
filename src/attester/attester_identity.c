/**
 * @file attester_identity.c
 * @brief See attester_identity.h.
 *
 * The Attester's own EK/AK identity: created and persisted on first use,
 * then loaded back on demand. Deliberately separate from the quoting key
 * that signs Quote_a -- see msg_ak_identity_response_dto in charra_dto.h.
 */


#include "attester_identity.h"
#include "../common/charra_log.h"
#include <tss2/tss2_tctildr.h>

#include "../common/charra_macro.h"
#include "../core/charra_dto.h"
#include "../core/charra_identity_key_mgr.h"
#include "../util/io_util.h"

#define LOG_NAME "attester"

/* Test-only synthetic manufacturer CA that signs this Attester's EK
 * certificate -- see keys/gen-ak-pki.sh. */
static char* manufacturer_root_cert_path = "keys/manufacturer-root.crt";
static char* manufacturer_root_key_path = "keys/manufacturer-root.key";
static const char* attester_ek_cert_not_before_utc = "20240101000000";
static const char* attester_ek_cert_not_after_utc = "20340101000000";

char* attester_ek_cert_cache_path =
        "state/attester/identity/attester-ek-certificate.der";
char* attester_ak_public_path =
        "state/attester/identity/attester-ak-public.bin";
/* Only this module ever loads the private area. */
static char* attester_ak_private_path =
        "state/attester/identity/attester-ak-private.bin";

static bool attester_ak_keypair_ready = false;

CHARRA_RC ensure_attester_ak_keypair(void) {
    if (attester_ak_keypair_ready) {
        return CHARRA_RC_SUCCESS;
    }

    charra_log_info(
            "[" LOG_NAME "]  +------------ Attester TPM Identity --------------+");

    CHARRA_RC result = CHARRA_RC_ERROR;

    bool cached = charra_io_file_exists(attester_ak_public_path) ==
                    CHARRA_RC_SUCCESS &&
            charra_io_file_exists(attester_ak_private_path) ==
                    CHARRA_RC_SUCCESS;

    if (cached) {
        charra_log_info("[" LOG_NAME "] Reloading previously provisioned "
                        "Attester AK identity.");
        attester_ak_keypair_ready = true;
        return CHARRA_RC_SUCCESS;
    }

    charra_log_info(
            "[" LOG_NAME "] No cached Attester AK identity -- creating one.");

    ESYS_CONTEXT* esys_ctx = NULL;
    TSS2_TCTI_CONTEXT* tcti_ctx = NULL;
    ESYS_TR ek_handle = ESYS_TR_NONE;
    ESYS_TR ak_handle = ESYS_TR_NONE;
    TPM2B_NAME* ak_name = NULL;
    TPM2B_PUBLIC* ek_public = NULL;
    TPM2B_PUBLIC* ak_public_p = NULL;
    TPM2B_PRIVATE* ak_private_p = NULL;
    uint8_t* ek_cert_der = NULL;
    uint32_t ek_cert_der_len = 0;

    TSS2_RC tss_r = 0;
    if ((tss_r = Tss2_TctiLdr_Initialize(getenv("CHARRA_TCTI"), &tcti_ctx)) !=
            TSS2_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Tss2_TctiLdr_Initialize.");
        return CHARRA_RC_ERROR;
    }
    if ((tss_r = Esys_Initialize(&esys_ctx, tcti_ctx, NULL)) !=
            TSS2_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Esys_Initialize.");
        Tss2_TctiLdr_Finalize(&tcti_ctx);
        return CHARRA_RC_ERROR;
    }

    if ((result = charra_identity_key_mgr_create_ek(esys_ctx, &ek_handle,
                 &ek_public)) != CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Could not create Attester's EK.");
        goto cleanup;
    }

    /* --- self-signed EK certificate, cached after the first mint (EK
     * creation is deterministic, so re-minting would just reproduce the
     * same key under a fresh cert every time) -- same pattern
     * ensure_rp_ak_keypair() uses for the RP's own EK cert. */
    if (charra_io_file_exists(attester_ek_cert_cache_path) ==
            CHARRA_RC_SUCCESS) {
        charra_log_info(
                "[" LOG_NAME "] Reusing previously minted Attester EK "
                "certificate.");
    } else {
        char* manufacturer_root_der = NULL;
        size_t manufacturer_root_der_len = 0;
        if ((result = charra_io_read_file(manufacturer_root_cert_path,
                     &manufacturer_root_der, &manufacturer_root_der_len)) !=
                CHARRA_RC_SUCCESS) {
            charra_log_error("[" LOG_NAME "] Could not read manufacturer "
                             "root certificate ('%s').",
                    manufacturer_root_cert_path);
            goto cleanup;
        }
        mbedtls_x509_crt manufacturer_root_cert;
        mbedtls_x509_crt_init(&manufacturer_root_cert);
        if (mbedtls_x509_crt_parse(&manufacturer_root_cert,
                    (uint8_t*)manufacturer_root_der,
                    manufacturer_root_der_len) != 0) {
            charra_log_error("[" LOG_NAME "] Could not parse manufacturer "
                             "root certificate.");
            charra_io_free_file_buffer(&manufacturer_root_der);
            result = CHARRA_RC_CRYPTO_ERROR;
            goto cleanup;
        }
        char issuer_name[256] = {0};
        if (mbedtls_x509_dn_gets(issuer_name, sizeof(issuer_name),
                    &manufacturer_root_cert.subject) <= 0) {
            charra_log_error("[" LOG_NAME "] Could not read manufacturer "
                             "root subject name.");
            mbedtls_x509_crt_free(&manufacturer_root_cert);
            charra_io_free_file_buffer(&manufacturer_root_der);
            result = CHARRA_RC_CRYPTO_ERROR;
            goto cleanup;
        }
        mbedtls_x509_crt_free(&manufacturer_root_cert);
        charra_io_free_file_buffer(&manufacturer_root_der);

        uint8_t ek_serial[16] = {0};
        if ((result = charra_crypto_sign_ak_certificate(ek_public,
                     "CN=CHARRA Attester EK (test only)", issuer_name,
                     attester_ek_cert_not_before_utc,
                     attester_ek_cert_not_after_utc, manufacturer_root_key_path,
                     &ek_cert_der, &ek_cert_der_len, ek_serial)) !=
                CHARRA_RC_SUCCESS) {
            charra_log_error(
                    "[" LOG_NAME "] Could not mint Attester's EK certificate.");
            goto cleanup;
        }
        if ((result = charra_io_write_file(attester_ek_cert_cache_path,
                     ek_cert_der, ek_cert_der_len)) != CHARRA_RC_SUCCESS) {
            charra_log_error(
                    "[" LOG_NAME "] Could not cache Attester's EK certificate.");
            goto cleanup;
        }
    }

    /* restricted: this AK also signs real Quote_a, see coap_attest_handler() */
    if ((result = charra_identity_key_mgr_create_restricted_ak(esys_ctx,
                 ek_handle, &ak_handle, &ak_public_p, &ak_private_p,
                 &ak_name)) != CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Could not create Attester's AK.");
        goto cleanup;
    }
    if ((result = charra_identity_key_mgr_save_public(
                 attester_ak_public_path, ak_public_p)) != CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Could not persist AK public key.");
        goto cleanup;
    }
    if ((result = charra_identity_key_mgr_save_private(
                 attester_ak_private_path, ak_private_p)) !=
            CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Could not persist AK private area.");
        goto cleanup;
    }

    result = CHARRA_RC_SUCCESS;

cleanup:
    Esys_Free(ek_public);
    Esys_Free(ak_public_p);
    Esys_Free(ak_private_p);
    Esys_Free(ak_name);
    charra_free_if_not_null(ek_cert_der);
    if (ak_handle != ESYS_TR_NONE) {
        Esys_FlushContext(esys_ctx, ak_handle);
    }
    if (ek_handle != ESYS_TR_NONE) {
        Esys_FlushContext(esys_ctx, ek_handle);
    }
    Esys_Finalize(&esys_ctx);
    Tss2_TctiLdr_Finalize(&tcti_ctx);

    if (result == CHARRA_RC_SUCCESS) {
        attester_ak_keypair_ready = true;
    }
    return result;
}

/* Loads EK+AK on an already-open esys_ctx -- shared by
 * attester_open_tpm_and_load_ak() (opens its own connection) and
 * coap_attest_handler() (reuses its own already-open one, to avoid a
 * second TPM connection the simulator can't accept concurrently). */
CHARRA_RC attester_load_ak(ESYS_CONTEXT* esys_ctx,
        ESYS_TR* ek_handle_out, ESYS_TR* ak_handle_out,
        TPM2B_NAME** ak_name_out, TPM2B_PUBLIC* ak_public_out) {
    TPM2B_PUBLIC* ek_public = NULL;
    CHARRA_RC result =
            charra_identity_key_mgr_create_ek(esys_ctx, ek_handle_out, &ek_public);
    Esys_Free(ek_public);
    if (result != CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Could not recreate Attester's EK.");
        return result;
    }

    TPM2B_PUBLIC ak_public = {0};
    TPM2B_PRIVATE ak_private = {0};
    if ((result = charra_identity_key_mgr_load_public(
                 attester_ak_public_path, &ak_public)) != CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Could not load AK public key.");
        return result;
    }
    if ((result = charra_identity_key_mgr_load_private(
                 attester_ak_private_path, &ak_private)) !=
            CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Could not load AK private area.");
        return result;
    }
    if ((result = charra_identity_key_mgr_load_ak(esys_ctx, *ek_handle_out,
                 &ak_public, &ak_private, ak_handle_out, ak_name_out)) !=
            CHARRA_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Could not load Attester's AK.");
        return result;
    }
    if (ak_public_out != NULL) {
        *ak_public_out = ak_public;
    }
    return CHARRA_RC_SUCCESS;
}

CHARRA_RC attester_open_tpm_and_load_ak(ESYS_CONTEXT** esys_ctx_out,
        TSS2_TCTI_CONTEXT** tcti_ctx_out, ESYS_TR* ek_handle_out,
        ESYS_TR* ak_handle_out, TPM2B_NAME** ak_name_out,
        TPM2B_PUBLIC* ak_public_out) {
    TSS2_RC tss_r = 0;
    if ((tss_r = Tss2_TctiLdr_Initialize(
                 getenv("CHARRA_TCTI"), tcti_ctx_out)) != TSS2_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Tss2_TctiLdr_Initialize.");
        return CHARRA_RC_ERROR;
    }
    if ((tss_r = Esys_Initialize(esys_ctx_out, *tcti_ctx_out, NULL)) !=
            TSS2_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Esys_Initialize.");
        Tss2_TctiLdr_Finalize(tcti_ctx_out);
        return CHARRA_RC_ERROR;
    }

    CHARRA_RC result = attester_load_ak(*esys_ctx_out, ek_handle_out,
            ak_handle_out, ak_name_out, ak_public_out);
    if (result != CHARRA_RC_SUCCESS) {
        goto error;
    }
    return CHARRA_RC_SUCCESS;

error:
    if (*ek_handle_out != ESYS_TR_NONE) {
        Esys_FlushContext(*esys_ctx_out, *ek_handle_out);
    }
    if (*ak_handle_out != ESYS_TR_NONE) {
        Esys_FlushContext(*esys_ctx_out, *ak_handle_out);
    }
    Esys_Finalize(esys_ctx_out);
    Tss2_TctiLdr_Finalize(tcti_ctx_out);
    return result;
}
