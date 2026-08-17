#include "charra_identity_key_mgr.h"

#include <string.h>

#include "../common/charra_log.h"
#include "../util/crypto_util.h"
#include "../util/io_util.h"

/* --- EK ------------------------------------------------------------------ */

CHARRA_RC charra_identity_key_mgr_create_ek(
        ESYS_CONTEXT* esys_ctx, ESYS_TR* ek_handle_out,
        TPM2B_PUBLIC** ek_public_out) {
    if (esys_ctx == NULL || ek_handle_out == NULL || ek_public_out == NULL) {
        return CHARRA_RC_BAD_ARGUMENT;
    }

    TPM2B_AUTH auth_endorsement = {.size = 0, .buffer = {0}};
    if (Esys_TR_SetAuth(esys_ctx, ESYS_TR_RH_ENDORSEMENT, &auth_endorsement) !=
            TSS2_RC_SUCCESS) {
        charra_log_error("charra_identity_key_mgr_create_ek: Esys_TR_SetAuth");
        return CHARRA_RC_TPM;
    }

    TPM2B_AUTH auth_ek = {.size = 0, .buffer = {0}};
    TPM2B_SENSITIVE_CREATE in_sensitive = {
            .size = 0, .sensitive = {.userAuth = auth_ek, .data = {0}}};

    /* clang-format off */
    TPM2B_PUBLIC in_public = {
        .size = 0,
        .publicArea = {
            .type = TPM2_ALG_RSA,
            .nameAlg = TPM2_ALG_SHA256,
            /* empty auth (userWithAuth), not the real EK template's
             * adminWithPolicy -- see this module's header comment for why */
            .objectAttributes =
                (TPMA_OBJECT_USERWITHAUTH | TPMA_OBJECT_RESTRICTED |
                    TPMA_OBJECT_DECRYPT | TPMA_OBJECT_FIXEDTPM |
                    TPMA_OBJECT_FIXEDPARENT | TPMA_OBJECT_SENSITIVEDATAORIGIN),
            .authPolicy = {.size = 0},
            .parameters.rsaDetail = {
                .symmetric = {
                    .algorithm = TPM2_ALG_AES,
                    .keyBits.aes = 128,
                    .mode.aes = TPM2_ALG_CFB,
                },
                .scheme = {.scheme = TPM2_ALG_NULL},
                .keyBits = 2048,
                .exponent = 0,
            },
            .unique.rsa = {.size = 0, .buffer = {0}},
        },
    };
    /* clang-format on */

    TPM2B_DATA outside_info = {.size = 0, .buffer = {0}};
    TPML_PCR_SELECTION creation_pcr = {.count = 0};

    TSS2_RC create_primary_rc = 0;
    if ((create_primary_rc = Esys_CreatePrimary(esys_ctx,
                 ESYS_TR_RH_ENDORSEMENT, ESYS_TR_PASSWORD, ESYS_TR_NONE,
                 ESYS_TR_NONE, &in_sensitive, &in_public, &outside_info,
                 &creation_pcr, ek_handle_out, ek_public_out, NULL, NULL,
                 NULL)) != TSS2_RC_SUCCESS) {
        charra_log_error("charra_identity_key_mgr_create_ek: Esys_CreatePrimary: "
                         "0x%x",
                create_primary_rc);
        return CHARRA_RC_TPM;
    }

    return CHARRA_RC_SUCCESS;
}

/* --- AK ------------------------------------------------------------------ */

/** Shared by charra_identity_key_mgr_create_ak() and _load_ak(): the EK's auth
 * (empty) is needed to use it as a parent handle for Create/Load. */
static CHARRA_RC set_ek_auth_for_parent_use(
        ESYS_CONTEXT* esys_ctx, ESYS_TR ek_handle) {
    TPM2B_AUTH auth = {.size = 0, .buffer = {0}};
    if (Esys_TR_SetAuth(esys_ctx, ek_handle, &auth) != TSS2_RC_SUCCESS) {
        charra_log_error("set_ek_auth_for_parent_use: Esys_TR_SetAuth");
        return CHARRA_RC_TPM;
    }
    return CHARRA_RC_SUCCESS;
}

/** Shared by charra_identity_key_mgr_create_ak() (unrestricted) and
 * _create_restricted_ak() (restricted, TPM2_Quote-capable) -- identical
 * except for objectAttributes' TPMA_OBJECT_RESTRICTED bit. */
static CHARRA_RC create_ak_internal(ESYS_CONTEXT* esys_ctx, ESYS_TR ek_handle,
        TPMA_OBJECT object_attributes, ESYS_TR* ak_handle_out,
        TPM2B_PUBLIC** ak_public_out, TPM2B_PRIVATE** ak_private_out,
        TPM2B_NAME** ak_name_out) {
    if (esys_ctx == NULL || ak_handle_out == NULL || ak_public_out == NULL ||
            ak_private_out == NULL || ak_name_out == NULL) {
        return CHARRA_RC_BAD_ARGUMENT;
    }

    CHARRA_RC charra_r = set_ek_auth_for_parent_use(esys_ctx, ek_handle);
    if (charra_r != CHARRA_RC_SUCCESS) {
        return charra_r;
    }

    TPM2B_AUTH auth_ak = {.size = 0, .buffer = {0}};
    TPM2B_SENSITIVE_CREATE in_sensitive = {
            .size = 0, .sensitive = {.userAuth = auth_ak, .data = {0}}};

    /* clang-format off */
    TPM2B_PUBLIC in_public = {
        .size = 0,
        .publicArea = {
            .type = TPM2_ALG_RSA,
            .nameAlg = TPM2_ALG_SHA256,
            .objectAttributes = object_attributes,
            .authPolicy = {.size = 0},
            .parameters.rsaDetail = {
                .symmetric = {.algorithm = TPM2_ALG_NULL},
                .scheme = {
                    .scheme = TPM2_ALG_RSAPSS,
                    .details.rsapss.hashAlg = TPM2_ALG_SHA256,
                },
                .keyBits = 2048,
                .exponent = 0,
            },
            .unique.rsa = {.size = 0, .buffer = {0}},
        },
    };
    /* clang-format on */

    TPM2B_DATA outside_info = {.size = 0, .buffer = {0}};
    TPML_PCR_SELECTION creation_pcr = {.count = 0};

    TSS2_RC create_rc = 0;
    if ((create_rc = Esys_Create(esys_ctx, ek_handle, ESYS_TR_PASSWORD,
                 ESYS_TR_NONE, ESYS_TR_NONE, &in_sensitive, &in_public,
                 &outside_info, &creation_pcr, ak_private_out, ak_public_out,
                 NULL, NULL, NULL)) != TSS2_RC_SUCCESS) {
        charra_log_error(
                "charra_identity_key_mgr_create_ak: Esys_Create: 0x%x", create_rc);
        return CHARRA_RC_TPM;
    }

    if (Esys_Load(esys_ctx, ek_handle, ESYS_TR_PASSWORD, ESYS_TR_NONE,
                ESYS_TR_NONE, *ak_private_out, *ak_public_out,
                ak_handle_out) != TSS2_RC_SUCCESS) {
        charra_log_error("charra_identity_key_mgr_create_ak: Esys_Load");
        Esys_Free(*ak_private_out);
        Esys_Free(*ak_public_out);
        *ak_private_out = NULL;
        *ak_public_out = NULL;
        return CHARRA_RC_TPM;
    }

    TPM2B_AUTH auth_for_use = {.size = 0, .buffer = {0}};
    if (Esys_TR_SetAuth(esys_ctx, *ak_handle_out, &auth_for_use) !=
            TSS2_RC_SUCCESS) {
        charra_log_error("charra_identity_key_mgr_create_ak: Esys_TR_SetAuth (AK)");
        return CHARRA_RC_TPM;
    }

    if (Esys_TR_GetName(esys_ctx, *ak_handle_out, ak_name_out) !=
            TSS2_RC_SUCCESS) {
        charra_log_error("charra_identity_key_mgr_create_ak: Esys_TR_GetName");
        return CHARRA_RC_TPM;
    }

    return CHARRA_RC_SUCCESS;
}

CHARRA_RC charra_identity_key_mgr_create_ak(ESYS_CONTEXT* esys_ctx,
        ESYS_TR ek_handle, ESYS_TR* ak_handle_out, TPM2B_PUBLIC** ak_public_out,
        TPM2B_PRIVATE** ak_private_out, TPM2B_NAME** ak_name_out) {
    /* NOT restricted -- see this module's header comment: Quote_r's signed
     * payload is caller-supplied, not TPM-generated */
    return create_ak_internal(esys_ctx, ek_handle,
            (TPMA_OBJECT_USERWITHAUTH | TPMA_OBJECT_SIGN_ENCRYPT |
                    TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_FIXEDPARENT |
                    TPMA_OBJECT_SENSITIVEDATAORIGIN),
            ak_handle_out, ak_public_out, ak_private_out, ak_name_out);
}

CHARRA_RC charra_identity_key_mgr_create_restricted_ak(ESYS_CONTEXT* esys_ctx,
        ESYS_TR ek_handle, ESYS_TR* ak_handle_out, TPM2B_PUBLIC** ak_public_out,
        TPM2B_PRIVATE** ak_private_out, TPM2B_NAME** ak_name_out) {
    /* Restricted -- required for TPM2_Quote; see this module's header
     * comment. Same scheme/keyBits as the unrestricted variant, only
     * TPMA_OBJECT_RESTRICTED added. */
    return create_ak_internal(esys_ctx, ek_handle,
            (TPMA_OBJECT_USERWITHAUTH | TPMA_OBJECT_SIGN_ENCRYPT |
                    TPMA_OBJECT_RESTRICTED | TPMA_OBJECT_FIXEDTPM |
                    TPMA_OBJECT_FIXEDPARENT | TPMA_OBJECT_SENSITIVEDATAORIGIN),
            ak_handle_out, ak_public_out, ak_private_out, ak_name_out);
}

CHARRA_RC charra_identity_key_mgr_load_ak(ESYS_CONTEXT* esys_ctx, ESYS_TR ek_handle,
        const TPM2B_PUBLIC* ak_public, const TPM2B_PRIVATE* ak_private,
        ESYS_TR* ak_handle_out, TPM2B_NAME** ak_name_out) {
    if (esys_ctx == NULL || ak_public == NULL || ak_private == NULL ||
            ak_handle_out == NULL || ak_name_out == NULL) {
        return CHARRA_RC_BAD_ARGUMENT;
    }

    CHARRA_RC charra_r = set_ek_auth_for_parent_use(esys_ctx, ek_handle);
    if (charra_r != CHARRA_RC_SUCCESS) {
        return charra_r;
    }

    TSS2_RC load_rc = 0;
    if ((load_rc = Esys_Load(esys_ctx, ek_handle, ESYS_TR_PASSWORD,
                 ESYS_TR_NONE, ESYS_TR_NONE, ak_private, ak_public,
                 ak_handle_out)) != TSS2_RC_SUCCESS) {
        charra_log_error(
                "charra_identity_key_mgr_load_ak: Esys_Load: 0x%x", load_rc);
        return CHARRA_RC_TPM;
    }

    TPM2B_AUTH auth_for_use = {.size = 0, .buffer = {0}};
    if (Esys_TR_SetAuth(esys_ctx, *ak_handle_out, &auth_for_use) !=
            TSS2_RC_SUCCESS) {
        charra_log_error("charra_identity_key_mgr_load_ak: Esys_TR_SetAuth (AK)");
        return CHARRA_RC_TPM;
    }

    if (Esys_TR_GetName(esys_ctx, *ak_handle_out, ak_name_out) !=
            TSS2_RC_SUCCESS) {
        charra_log_error("charra_identity_key_mgr_load_ak: Esys_TR_GetName");
        return CHARRA_RC_TPM;
    }

    return CHARRA_RC_SUCCESS;
}

/* --- /certify_ak: ActivateCredential --------------------------------------
 */

CHARRA_RC charra_identity_key_mgr_activate_credential(ESYS_CONTEXT* esys_ctx,
        ESYS_TR ak_handle, ESYS_TR ek_handle,
        const TPM2B_ID_OBJECT* credential_blob,
        const TPM2B_ENCRYPTED_SECRET* wrapped_secret,
        TPM2B_DIGEST** credential_out) {
    if (esys_ctx == NULL || credential_blob == NULL ||
            wrapped_secret == NULL || credential_out == NULL) {
        return CHARRA_RC_BAD_ARGUMENT;
    }

    if (Esys_ActivateCredential(esys_ctx, ak_handle, ek_handle,
                ESYS_TR_PASSWORD, ESYS_TR_PASSWORD, ESYS_TR_NONE,
                credential_blob, wrapped_secret,
                credential_out) != TSS2_RC_SUCCESS) {
        charra_log_error("charra_identity_key_mgr_activate_credential: "
                         "Esys_ActivateCredential");
        return CHARRA_RC_TPM;
    }

    return CHARRA_RC_SUCCESS;
}

/* --- signing --------------------------------------------------------------
 */

CHARRA_RC charra_identity_key_mgr_sign(ESYS_CONTEXT* esys_ctx, ESYS_TR ak_handle,
        const uint8_t* data, size_t data_len, uint8_t* signature_out) {
    if (esys_ctx == NULL || data == NULL || signature_out == NULL) {
        return CHARRA_RC_BAD_ARGUMENT;
    }

    uint8_t digest_bytes[TPM2_SHA256_DIGEST_SIZE] = {0};
    if (hash_sha256(data_len, data, digest_bytes) != CHARRA_RC_SUCCESS) {
        return CHARRA_RC_CRYPTO_ERROR;
    }

    TPM2B_DIGEST digest = {.size = sizeof(digest_bytes)};
    memcpy(digest.buffer, digest_bytes, sizeof(digest_bytes));

    TPMT_SIG_SCHEME scheme = {.scheme = TPM2_ALG_RSAPSS,
            .details.rsapss.hashAlg = TPM2_ALG_SHA256};

    /* null ticket: tells the TPM this digest did NOT come from the TPM
     * itself -- required (and only accepted) because the AK is
     * unrestricted, see this module's header comment */
    TPMT_TK_HASHCHECK null_ticket = {
            .tag = TPM2_ST_HASHCHECK, .hierarchy = TPM2_RH_NULL, .digest = {0}};

    TPMT_SIGNATURE* signature = NULL;
    if (Esys_Sign(esys_ctx, ak_handle, ESYS_TR_PASSWORD, ESYS_TR_NONE,
                ESYS_TR_NONE, &digest, &scheme, &null_ticket, &signature) !=
            TSS2_RC_SUCCESS) {
        charra_log_error("charra_identity_key_mgr_sign: Esys_Sign");
        return CHARRA_RC_TPM;
    }

    memcpy(signature_out, signature->signature.rsapss.sig.buffer,
            signature->signature.rsapss.sig.size);
    Esys_Free(signature);

    return CHARRA_RC_SUCCESS;
}

/* --- DER export ------------------------------------------------------------
 */

CHARRA_RC charra_identity_key_mgr_public_key_to_der(const TPM2B_PUBLIC* ak_public,
        uint8_t* der_out, size_t der_out_size, uint32_t* der_len_out) {
    if (ak_public == NULL || der_out == NULL || der_len_out == NULL) {
        return CHARRA_RC_BAD_ARGUMENT;
    }

    mbedtls_rsa_context rsa_pub_key = {0};
    CHARRA_RC charra_r = charra_crypto_tpm_pub_key_to_mbedtls_pub_key(
            ak_public, &rsa_pub_key);
    if (charra_r != CHARRA_RC_SUCCESS) {
        return charra_r;
    }

    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);
    int mbedtls_r = 0;
    if ((mbedtls_r = mbedtls_pk_setup(
                 &pk, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA))) != 0) {
        charra_log_error(
                "charra_identity_key_mgr_public_key_to_der: mbedtls_pk_setup: %d",
                mbedtls_r);
        mbedtls_rsa_free(&rsa_pub_key);
        return CHARRA_RC_CRYPTO_ERROR;
    }
    if ((mbedtls_r = mbedtls_rsa_copy(mbedtls_pk_rsa(pk), &rsa_pub_key)) !=
            0) {
        charra_log_error(
                "charra_identity_key_mgr_public_key_to_der: mbedtls_rsa_copy: %d",
                mbedtls_r);
        mbedtls_rsa_free(&rsa_pub_key);
        mbedtls_pk_free(&pk);
        return CHARRA_RC_CRYPTO_ERROR;
    }
    mbedtls_rsa_free(&rsa_pub_key);

    charra_r = charra_crypto_rsa_public_key_to_der(
            &pk, der_out, der_out_size, der_len_out);
    mbedtls_pk_free(&pk);
    return charra_r;
}

/* --- persistence ------------------------------------------------------- */

CHARRA_RC charra_identity_key_mgr_save_public(
        const char* path, const TPM2B_PUBLIC* pub) {
    if (path == NULL || pub == NULL) {
        return CHARRA_RC_BAD_ARGUMENT;
    }
    return charra_io_write_file(path, (const uint8_t*)pub, sizeof(*pub));
}

CHARRA_RC charra_identity_key_mgr_load_public(
        const char* path, TPM2B_PUBLIC* pub_out) {
    if (path == NULL || pub_out == NULL) {
        return CHARRA_RC_BAD_ARGUMENT;
    }
    char* buf = NULL;
    size_t buf_len = 0;
    if (charra_io_read_file(path, &buf, &buf_len) != CHARRA_RC_SUCCESS) {
        return CHARRA_RC_ERROR;
    }
    if (buf_len != sizeof(*pub_out)) {
        charra_log_error(
                "charra_identity_key_mgr_load_public: '%s' has the wrong size.",
                path);
        charra_io_free_file_buffer(&buf);
        return CHARRA_RC_ERROR;
    }
    memcpy(pub_out, buf, sizeof(*pub_out));
    charra_io_free_file_buffer(&buf);
    return CHARRA_RC_SUCCESS;
}

CHARRA_RC charra_identity_key_mgr_save_private(
        const char* path, const TPM2B_PRIVATE* priv) {
    if (path == NULL || priv == NULL) {
        return CHARRA_RC_BAD_ARGUMENT;
    }
    return charra_io_write_file(path, (const uint8_t*)priv, sizeof(*priv));
}

CHARRA_RC charra_identity_key_mgr_load_private(
        const char* path, TPM2B_PRIVATE* priv_out) {
    if (path == NULL || priv_out == NULL) {
        return CHARRA_RC_BAD_ARGUMENT;
    }
    char* buf = NULL;
    size_t buf_len = 0;
    if (charra_io_read_file(path, &buf, &buf_len) != CHARRA_RC_SUCCESS) {
        return CHARRA_RC_ERROR;
    }
    if (buf_len != sizeof(*priv_out)) {
        charra_log_error(
                "charra_identity_key_mgr_load_private: '%s' has the wrong size.",
                path);
        charra_io_free_file_buffer(&buf);
        return CHARRA_RC_ERROR;
    }
    memcpy(priv_out, buf, sizeof(*priv_out));
    charra_io_free_file_buffer(&buf);
    return CHARRA_RC_SUCCESS;
}
