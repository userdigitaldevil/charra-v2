/**
 * @file provision_trusted_keys.c
 * @brief Writes the trust anchor (keys/trusted_keys.txt) from the TPM's
 * own signing keys. Offline setup, not part of the protocol.
 *
 * This stands in for whatever, in a real deployment, would have satisfied
 * itself that these keys are genuinely TPM-resident and worth trusting.
 * None of that happens at runtime here -- the roles simply assume it
 * already did (see charra_trusted_keys.h), and this tool is what makes
 * that assumption true before they start.
 *
 * It writes two public keys:
 *   - the Attester's restricted quoting key (TPM2_Quote's signer)
 *   - the RP's unrestricted Quote_r signing key
 * Both are read straight out of the TPM rather than generated here, so the
 * file names the keys the daemons will actually sign with.
 *
 * Because TPM2_CreatePrimary derives both keys from the hierarchy seed,
 * wiping the simulator's NVChip changes them and invalidates this file.
 * Re-run this tool after any TPM reset -- run_daemon.sh already does.
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <mbedtls/pk.h>
#include <mbedtls/rsa.h>
#include <tss2/tss2_esys.h>
#include <tss2/tss2_tctildr.h>

#include "common/charra_log.h"
#include "core/charra_trusted_keys.h"
#include "util/crypto_util.h"
#include "util/tpm2_util.h"

#define LOG_NAME "provision"

typedef struct {
    const char* label; /* the `# name` comment written above the key */
    bool restricted;   /* which of the two primaries this identity uses */
} identity;

static const identity IDENTITIES[] = {
        {"attester", true},
        {"relying-party", false},
};
#define NUM_IDENTITIES (sizeof(IDENTITIES) / sizeof(IDENTITIES[0]))

/** @brief Read one identity's public key out of the TPM. */
static bool read_public_key(
        ESYS_CONTEXT* esys_ctx, bool restricted, TPM2B_PUBLIC* public_out) {
    ESYS_TR handle = ESYS_TR_NONE;
    TPM2B_PUBLIC* public_key = NULL;

    TSS2_RC tss_r =
            restricted
                    ? tpm2_create_primary_key_rsa2048(
                              esys_ctx, &handle, &public_key)
                    : tpm2_create_primary_key_rsa2048_unrestricted(
                              esys_ctx, &handle, &public_key);
    if (tss_r != TSS2_RC_SUCCESS || public_key == NULL) {
        charra_log_error("[" LOG_NAME "] Could not create the %s primary "
                         "key: 0x%x.",
                restricted ? "restricted" : "unrestricted", tss_r);
        return false;
    }

    *public_out = *public_key;
    Esys_Free(public_key);
    /* The handle is transient and the TPM's table is small; leaving it
     * loaded would strand it until the TPM itself restarts. */
    Esys_FlushContext(esys_ctx, handle);
    return true;
}

/** @brief PEM-encode a TPM public key's RSA half. */
static bool public_key_to_pem(
        const TPM2B_PUBLIC* public_key, char* out, size_t out_size) {
    mbedtls_rsa_context rsa = {0};
    if (charra_crypto_tpm_pub_key_to_mbedtls_pub_key(public_key, &rsa) !=
            CHARRA_RC_SUCCESS) {
        return false;
    }

    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);
    bool ok = false;
    if (mbedtls_pk_setup(&pk, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA)) == 0 &&
            mbedtls_rsa_copy(mbedtls_pk_rsa(pk), &rsa) == 0 &&
            mbedtls_pk_write_pubkey_pem(
                    &pk, (unsigned char*)out, out_size) == 0) {
        ok = true;
    }
    mbedtls_pk_free(&pk);
    mbedtls_rsa_free(&rsa);
    return ok;
}

int main(int argc, char** argv) {
    const char* out_path = CHARRA_TRUSTED_KEYS_DEFAULT_PATH;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--out") == 0 && i + 1 < argc) {
            out_path = argv[++i];
        } else {
            fprintf(stderr,
                    "usage: %s [--out <path>]\n"
                    "\n"
                    "Reads the Attester's and the RP's public signing keys "
                    "from the TPM\n"
                    "and writes them to the trust anchor both roles read at "
                    "runtime.\n",
                    argv[0]);
            return EXIT_FAILURE;
        }
    }

    charra_log_set_level(CHARRA_LOG_INFO);

    const char* charra_tcti = getenv("CHARRA_TCTI");
    charra_log_info("[" LOG_NAME "] CHARRA_TCTI = '%s'.",
            (charra_tcti != NULL) ? charra_tcti : "(null)");

    TSS2_TCTI_CONTEXT* tcti_ctx = NULL;
    ESYS_CONTEXT* esys_ctx = NULL;
    int result = EXIT_FAILURE;
    FILE* out = NULL;

    TSS2_RC tss_r = Tss2_TctiLdr_Initialize(charra_tcti, &tcti_ctx);
    if (tss_r != TSS2_RC_SUCCESS) {
        charra_log_error(
                "[" LOG_NAME "] Tss2_TctiLdr_Initialize failed: 0x%x.", tss_r);
        return EXIT_FAILURE;
    }
    if ((tss_r = Esys_Initialize(&esys_ctx, tcti_ctx, NULL)) !=
            TSS2_RC_SUCCESS) {
        charra_log_error("[" LOG_NAME "] Esys_Initialize failed: 0x%x.", tss_r);
        goto finish;
    }

    out = fopen(out_path, "w");
    if (out == NULL) {
        charra_log_error(
                "[" LOG_NAME "] Could not open '%s' for writing.", out_path);
        goto finish;
    }

    fprintf(out,
            "# CHARRA trust anchor -- generated by "
            "keys/gen-trusted-keys.sh, do not edit by hand.\n"
            "#\n"
            "# Every public key below is trusted unconditionally: a signing "
            "key is\n"
            "# accepted if and only if it appears here. There are no "
            "certificates, no CA,\n"
            "# no expiry and no revocation -- see "
            "src/core/charra_trusted_keys.h.\n"
            "#\n"
            "# These keys come from the TPM and change whenever its NVChip is "
            "wiped.\n"
            "# Regenerate this file after any TPM reset.\n");

    for (size_t i = 0; i < NUM_IDENTITIES; i++) {
        const identity* id = &IDENTITIES[i];

        TPM2B_PUBLIC public_key = {0};
        if (!read_public_key(esys_ctx, id->restricted, &public_key)) {
            goto finish;
        }

        /* Comfortably larger than a PEM-armoured RSA-2048 SubjectPublicKeyInfo
         * (~450 bytes); mbedtls fails rather than truncates if it is not. */
        char pem[2048] = {0};
        if (!public_key_to_pem(&public_key, pem, sizeof(pem))) {
            charra_log_error("[" LOG_NAME "] Could not PEM-encode the public "
                             "key for '%s'.",
                    id->label);
            goto finish;
        }

        fprintf(out, "\n# %s\n%s", id->label, pem);
        charra_log_info("[" LOG_NAME "] Wrote the public key for '%s' (%s "
                        "primary key).",
                id->label, id->restricted ? "restricted" : "unrestricted");
    }

    charra_log_info("[" LOG_NAME "] Wrote %zu public key(s) to '%s'.",
            NUM_IDENTITIES, out_path);
    result = EXIT_SUCCESS;

finish:
    if (out != NULL) {
        fclose(out);
    }
    if (esys_ctx != NULL) {
        Esys_Finalize(&esys_ctx);
    }
    if (tcti_ctx != NULL) {
        Tss2_TctiLdr_Finalize(&tcti_ctx);
    }
    return result;
}
