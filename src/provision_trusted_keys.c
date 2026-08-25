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
 * Two identities exist:
 *   - "attester"      -- the restricted quoting key (TPM2_Quote's signer)
 *   - "relying-party" -- the unrestricted Quote_r signing key
 * Both are read straight out of a TPM rather than generated here, so the
 * file names the keys the daemons will actually sign with.
 *
 * Without --role it emits both, which is only correct when ONE TPM backs
 * both roles. With --role it emits exactly one, headerless, so each role
 * can be provisioned against ITS OWN TPM and the fragments concatenated.
 *
 * --role is a security boundary, not a convenience. Emitting both
 * identities from each TPM would put a key the RP's own TPM can derive
 * into the anchor labelled "attester" -- and TPM2_Quote accepts a
 * restricted key, so the RP could then produce a genuine hardware quote
 * that satisfies the Verifier's Step 3b. Nothing would be forged and
 * nothing would look wrong. One TPM, one role, one key.
 *
 * Because TPM2_CreatePrimary derives a key from the hierarchy seed and the
 * template, wiping a simulator's NVChip changes that TPM's keys and
 * invalidates its entries here. Re-run after any TPM reset --
 * run_daemon.sh already does.
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
        {CHARRA_ROLE_ATTESTER, true},
        {CHARRA_ROLE_RELYING_PARTY, false},
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

/** @brief Is this a label from IDENTITIES[]? */
static bool is_known_role(const char* label) {
    for (size_t i = 0; i < NUM_IDENTITIES; i++) {
        if (strcmp(label, IDENTITIES[i].label) == 0) {
            return true;
        }
    }
    return false;
}

static void print_usage(const char* argv0) {
    fprintf(stderr,
            "usage: %s [--out <path>] [--role <name>]\n"
            "\n"
            "Reads public signing keys from the TPM named by $CHARRA_TCTI "
            "and writes\n"
            "them to the trust anchor every role reads at runtime.\n"
            "\n"
            "  --out <path>   where to write (default: %s)\n"
            "  --role <name>  emit ONLY this identity, without the file "
            "header, so that\n"
            "                 each TPM can be provisioned separately and "
            "the fragments\n"
            "                 concatenated. Required for a multi-TPM "
            "deployment.\n"
            "                 One of:\n",
            argv0, CHARRA_TRUSTED_KEYS_DEFAULT_PATH);
    for (size_t i = 0; i < NUM_IDENTITIES; i++) {
        fprintf(stderr, "                   %s\n", IDENTITIES[i].label);
    }
}

int main(int argc, char** argv) {
    const char* out_path = CHARRA_TRUSTED_KEYS_DEFAULT_PATH;
    /* NULL = emit every identity, with the explanatory header. Set by
     * --role to emit exactly one, headerless, for concatenation. */
    const char* only_role = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--out") == 0 && i + 1 < argc) {
            out_path = argv[++i];
        } else if (strcmp(argv[i], "--role") == 0 && i + 1 < argc) {
            only_role = argv[++i];
            if (!is_known_role(only_role)) {
                fprintf(stderr, "unknown --role '%s'\n\n", only_role);
                print_usage(argv[0]);
                return EXIT_FAILURE;
            }
        } else if (strcmp(argv[i], "--help") == 0 ||
                   strcmp(argv[i], "-h") == 0) {
            print_usage(argv[0]);
            return EXIT_SUCCESS;
        } else {
            fprintf(stderr, "unrecognised option '%s'\n\n", argv[i]);
            print_usage(argv[0]);
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

    /* A fragment carries no header: keys/gen-trusted-keys.sh writes one
     * header, once, ahead of the concatenated per-TPM parts. */
    if (only_role == NULL) {
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
    }

    size_t written = 0;
    for (size_t i = 0; i < NUM_IDENTITIES; i++) {
        const identity* id = &IDENTITIES[i];
        if (only_role != NULL && strcmp(only_role, id->label) != 0) {
            continue;
        }

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
        written++;
        charra_log_info("[" LOG_NAME "] Wrote the public key for '%s' (%s "
                        "primary key).",
                id->label, id->restricted ? "restricted" : "unrestricted");
    }

    charra_log_info("[" LOG_NAME "] Wrote %zu public key(s) to '%s'.",
            written, out_path);
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
