/**
 * @file test_trusted_keys.c
 * @brief Standalone tests for the trust anchor lookup.
 *
 * This is the whole of the identity check in this PoC -- there are no
 * certificates, no CA and no revocation, so if charra_trusted_keys_check()
 * says yes to a key that is not in the file, nothing else catches it. The
 * negative cases below matter more than the positive one.
 *
 * No TPM needed: a TPM2B_PUBLIC is just a struct, so the tests synthesise
 * one from a software RSA key and compare against a trust anchor written
 * from that same key.
 *
 * Build and run:  make test_trusted_keys && ./bin/test_trusted_keys
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/pk.h>
#include <mbedtls/rsa.h>

#include "../src/core/charra_trusted_keys.h"

static unsigned int tests_run = 0;
static unsigned int tests_failed = 0;

static void check(const char* name, bool condition) {
    tests_run++;
    if (condition) {
        printf("  PASS  %s\n", name);
    } else {
        tests_failed++;
        printf("  FAIL  %s\n", name);
    }
}

#define TMP_ANCHOR "/tmp/charra_test_trusted_keys.txt"

/**
 * @brief Build a TPM2B_PUBLIC around a caller-supplied RSA modulus, the
 * same shape tpm2_create_primary_key_rsa2048() produces.
 *
 * Only the fields charra_crypto_tpm_pub_key_to_mbedtls_pub_key() reads are
 * filled in -- type, the modulus in unique.rsa, and the exponent. The
 * exponent is left 0, which is how the TPM spells "the default, 65537",
 * exactly as the real primary-key template does.
 */
static void make_tpm_public(
        const uint8_t* modulus, size_t modulus_len, TPM2B_PUBLIC* out) {
    memset(out, 0, sizeof(*out));
    out->publicArea.type = TPM2_ALG_RSA;
    out->publicArea.nameAlg = TPM2_ALG_SHA256;
    out->publicArea.parameters.rsaDetail.keyBits = 2048;
    out->publicArea.parameters.rsaDetail.exponent = 0;
    out->publicArea.unique.rsa.size = (uint16_t)modulus_len;
    memcpy(out->publicArea.unique.rsa.buffer, modulus, modulus_len);
}

/** @brief Write a trust anchor holding one PEM key under one label. */
static bool write_anchor(
        const char* path, const char* label, const char* pem) {
    FILE* f = fopen(path, "w");
    if (f == NULL) {
        return false;
    }
    fprintf(f, "# a comment line the parser must skip\n\n# %s\n%s", label, pem);
    fclose(f);
    return true;
}

int main(void) {
    printf("Running trust anchor tests ...\n");

    /* --- a real RSA key, and the two shapes it has to be seen in --- */
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_ctr_drbg_seed(
            &ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0);

    mbedtls_pk_context key;
    mbedtls_pk_init(&key);
    if (mbedtls_pk_setup(&key, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA)) !=
                    0 ||
            mbedtls_rsa_gen_key(mbedtls_pk_rsa(key), mbedtls_ctr_drbg_random,
                    &ctr_drbg, 2048, 65537) != 0) {
        printf("  FATAL  could not generate a test RSA key\n");
        return EXIT_FAILURE;
    }

    uint8_t modulus[256] = {0};
    if (mbedtls_rsa_export_raw(mbedtls_pk_rsa(key), modulus, sizeof(modulus),
                NULL, 0, NULL, 0, NULL, 0, NULL, 0) != 0) {
        printf("  FATAL  could not export the test key's modulus\n");
        return EXIT_FAILURE;
    }

    char pem[2048] = {0};
    if (mbedtls_pk_write_pubkey_pem(&key, (unsigned char*)pem, sizeof(pem)) !=
            0) {
        printf("  FATAL  could not PEM-encode the test key\n");
        return EXIT_FAILURE;
    }

    TPM2B_PUBLIC trusted = {0};
    make_tpm_public(modulus, sizeof(modulus), &trusted);

    /* --- a key that is NOT the one in the file: same size, one bit off ---
     * The flipped bit is in the HIGH byte, deliberately. Flipping the low
     * byte would make the modulus even, which mbedtls rejects as malformed
     * before any comparison happens -- that is a different rejection path,
     * covered separately below, and it would let this test pass without
     * the comparison ever running. */
    uint8_t other_modulus[256] = {0};
    memcpy(other_modulus, modulus, sizeof(modulus));
    other_modulus[0] ^= 0x01;
    TPM2B_PUBLIC untrusted = {0};
    make_tpm_public(other_modulus, sizeof(other_modulus), &untrusted);

    if (!write_anchor(TMP_ANCHOR, "test-identity", pem)) {
        printf("  FATAL  could not write the test trust anchor\n");
        return EXIT_FAILURE;
    }

    printf("\na key present in the trust anchor is accepted\n");
    {
        char name[128] = {0};
        CHARRA_RC rc = charra_trusted_keys_check(
                TMP_ANCHOR, &trusted, name, sizeof(name));
        check("accepted", rc == CHARRA_RC_SUCCESS);
        check("reports the label from the file",
                strcmp(name, "test-identity") == 0);
    }

    printf("\na key that differs by ONE BIT is rejected\n");
    {
        char name[128] = {0};
        CHARRA_RC rc = charra_trusted_keys_check(
                TMP_ANCHOR, &untrusted, name, sizeof(name));
        check("rejected with CHARRA_RC_VERIFICATION_FAILED",
                rc == CHARRA_RC_VERIFICATION_FAILED);
        check("no label reported", name[0] == '\0');
    }

    /* The other rejection path: a key mbedtls will not even parse must not
     * be waved through. */
    printf("\na malformed key is rejected, not waved through\n");
    {
        uint8_t even_modulus[256] = {0};
        memcpy(even_modulus, modulus, sizeof(modulus));
        even_modulus[sizeof(even_modulus) - 1] &= (uint8_t)0xFE; /* now even */
        TPM2B_PUBLIC malformed = {0};
        make_tpm_public(even_modulus, sizeof(even_modulus), &malformed);
        CHARRA_RC rc =
                charra_trusted_keys_check(TMP_ANCHOR, &malformed, NULL, 0);
        check("not accepted", rc != CHARRA_RC_SUCCESS);
    }

    /* An empty or missing anchor must fail closed. Trusting everything when
     * the file cannot be read would turn a deployment mistake into a silent
     * bypass of the only identity check there is. */
    printf("\na missing trust anchor rejects rather than accepts\n");
    {
        CHARRA_RC rc = charra_trusted_keys_check(
                "/tmp/charra_test_no_such_file.txt", &trusted, NULL, 0);
        check("errors, does not accept", rc != CHARRA_RC_SUCCESS);
    }

    printf("\na trust anchor holding no key at all rejects\n");
    {
        FILE* f = fopen(TMP_ANCHOR, "w");
        fprintf(f, "# nothing but comments in here\n");
        fclose(f);
        CHARRA_RC rc =
                charra_trusted_keys_check(TMP_ANCHOR, &trusted, NULL, 0);
        check("errors, does not accept", rc != CHARRA_RC_SUCCESS);
    }

    /* Several identities per file is the normal case -- the real anchor
     * holds the Attester's key and the RP's -- so a match must be found
     * wherever it sits, not just in the first entry. */
    printf("\na key is found when it is not the first entry\n");
    {
        FILE* f = fopen(TMP_ANCHOR, "w");
        fprintf(f, "# decoy\n");
        /* A syntactically valid but different key first. */
        mbedtls_pk_context decoy;
        mbedtls_pk_init(&decoy);
        mbedtls_pk_setup(&decoy, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));
        mbedtls_rsa_gen_key(mbedtls_pk_rsa(decoy), mbedtls_ctr_drbg_random,
                &ctr_drbg, 2048, 65537);
        char decoy_pem[2048] = {0};
        mbedtls_pk_write_pubkey_pem(
                &decoy, (unsigned char*)decoy_pem, sizeof(decoy_pem));
        fprintf(f, "%s\n# wanted\n%s", decoy_pem, pem);
        fclose(f);
        mbedtls_pk_free(&decoy);

        char name[128] = {0};
        CHARRA_RC rc = charra_trusted_keys_check(
                TMP_ANCHOR, &trusted, name, sizeof(name));
        check("accepted", rc == CHARRA_RC_SUCCESS);
        check("reports the second entry's label",
                strcmp(name, "wanted") == 0);
    }

    remove(TMP_ANCHOR);
    mbedtls_pk_free(&key);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

    printf("\n%u tests, %u failed\n", tests_run, tests_failed);
    return (tests_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
