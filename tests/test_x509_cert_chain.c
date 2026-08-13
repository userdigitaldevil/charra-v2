/**
 * @file test_x509_cert_chain.c
 * @brief Standalone tests for charra_crypto_verify_x509_cert_chain(),
 * charra_crypto_verify_cert_public_key_matches_tpm_public_key(), and
 * charra_crypto_sign_ak_certificate() -- the helpers behind the Verifier's
 * EK/AK certificate check (Step 3a/3b item 1) and its role as Privacy CA
 * issuing AK certificates via /certify_ak.
 *
 * Runs against the test-only PKI in keys/ (see keys/gen-ak-pki.sh and
 * keys/README.md): a synthetic "manufacturer" root signs RP's and the
 * Attester's synthetic EK certificates; the Verifier's own CA (a separate,
 * unrelated root) is used both to exercise the "wrong root" failure case
 * and to sign fresh AK certificates in the round-trip test below.
 *
 * Build and run:  make test_x509_cert_chain && ./bin/test_x509_cert_chain
 * (must be run from the repository root, so the keys directory paths
 * resolve)
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <mbedtls/pk.h>
#include <mbedtls/rsa.h>
#include <mbedtls/x509_crt.h>
#include <tss2/tss2_tpm2_types.h>

#include "../src/util/crypto_util.h"
#include "../src/util/io_util.h"

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

/** Reads a DER file via the project's own file-reading helper. */
static bool read_der_file(
        const char* path, uint8_t** out_bytes, size_t* out_len) {
    char* content = NULL;
    if (charra_io_read_file(path, &content, out_len) != CHARRA_RC_SUCCESS) {
        printf("  (setup) could not read '%s' -- run keys/gen-ak-pki.sh "
               "and run this test from the repository root\n",
                path);
        return false;
    }
    *out_bytes = (uint8_t*)content;
    return true;
}

/**
 * @brief Builds a TPM2B_PUBLIC carrying the same RSA key as the given PEM
 * private-key file, so charra_crypto_verify_cert_public_key_matches_tpm_public_key()
 * can be exercised against a real, matching key pair rather than a fixed
 * fixture that could silently drift from whatever keys/gen-ak-pki.sh
 * happens to produce.
 */
static bool build_tpm2b_public_from_key_file(
        const char* key_path, TPM2B_PUBLIC* out) {
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;
    if (charra_crypto_seeded_rng_init(&ctr_drbg, &entropy) !=
            CHARRA_RC_SUCCESS) {
        printf("  (setup) could not seed RNG\n");
        return false;
    }

    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);
    int parse_rc = mbedtls_pk_parse_keyfile(&pk, key_path, NULL,
            mbedtls_ctr_drbg_random, &ctr_drbg);
    charra_crypto_seeded_rng_free(&ctr_drbg, &entropy);
    if (parse_rc != 0) {
        printf("  (setup) could not parse key '%s'\n", key_path);
        return false;
    }
    if (mbedtls_pk_get_type(&pk) != MBEDTLS_PK_RSA) {
        mbedtls_pk_free(&pk);
        return false;
    }

    mbedtls_rsa_context* rsa = mbedtls_pk_rsa(pk);
    mbedtls_mpi n = {0}, e = {0};
    mbedtls_mpi_init(&n);
    mbedtls_mpi_init(&e);

    bool ok = false;
    if (mbedtls_rsa_export(rsa, &n, NULL, NULL, NULL, &e) == 0) {
        memset(out, 0, sizeof(*out));
        out->publicArea.type = TPM2_ALG_RSA;
        out->publicArea.unique.rsa.size = (uint16_t)mbedtls_mpi_size(&n);
        if (mbedtls_mpi_write_binary(&n, out->publicArea.unique.rsa.buffer,
                    out->publicArea.unique.rsa.size) == 0) {
            /* 0 means "use the TPM-conventional default of 65537", matching
             * charra_crypto_tpm_pub_key_to_mbedtls_pub_key()'s own
             * convention -- every key gen-ak-pki.sh produces uses the
             * standard 65537 exponent anyway. */
            out->publicArea.parameters.rsaDetail.exponent = 0;
            ok = true;
        }
    }

    mbedtls_mpi_free(&n);
    mbedtls_mpi_free(&e);
    mbedtls_pk_free(&pk);
    return ok;
}

static void test_valid_chain_verifies(void) {
    printf("\na synthetic EK cert genuinely signed by the manufacturer root "
           "verifies\n");

    uint8_t *leaf = NULL, *root = NULL;
    size_t leaf_len = 0, root_len = 0;
    if (!read_der_file("keys/rp-ek.crt", &leaf, &leaf_len) ||
            !read_der_file(
                    "keys/manufacturer-root.crt", &root, &root_len)) {
        check("setup: could not read test PKI files", false);
        return;
    }

    mbedtls_x509_crt leaf_cert;
    CHARRA_RC rc = charra_crypto_verify_x509_cert_chain(
            leaf, leaf_len, root, root_len, &leaf_cert);
    check("valid chain verifies", rc == CHARRA_RC_SUCCESS);
    if (rc == CHARRA_RC_SUCCESS) {
        mbedtls_x509_crt_free(&leaf_cert);
    }

    free(leaf);
    free(root);
}

static void test_wrong_root_rejected(void) {
    printf("\nan EK cert checked against an unrelated root is rejected\n");

    uint8_t *leaf = NULL, *wrong_root = NULL;
    size_t leaf_len = 0, wrong_root_len = 0;
    if (!read_der_file("keys/rp-ek.crt", &leaf, &leaf_len) ||
            !read_der_file(
                    "keys/verifier-ca.crt", &wrong_root, &wrong_root_len)) {
        check("setup: could not read test PKI files", false);
        return;
    }

    mbedtls_x509_crt leaf_cert;
    CHARRA_RC rc = charra_crypto_verify_x509_cert_chain(
            leaf, leaf_len, wrong_root, wrong_root_len, &leaf_cert);
    check("wrong root rejected", rc == CHARRA_RC_VERIFICATION_FAILED);

    free(leaf);
    free(wrong_root);
}

static void test_tampered_leaf_rejected(void) {
    printf("\na bit-flipped EK cert is rejected, not silently accepted\n");

    uint8_t *leaf = NULL, *root = NULL;
    size_t leaf_len = 0, root_len = 0;
    if (!read_der_file("keys/rp-ek.crt", &leaf, &leaf_len) ||
            !read_der_file(
                    "keys/manufacturer-root.crt", &root, &root_len)) {
        check("setup: could not read test PKI files", false);
        return;
    }

    /* Flip a byte well into the DER body (past the fixed header) so this
     * reliably corrupts the signature rather than just failing to parse. */
    leaf[leaf_len - 20] ^= 0xFF;

    mbedtls_x509_crt leaf_cert;
    CHARRA_RC rc = charra_crypto_verify_x509_cert_chain(
            leaf, leaf_len, root, root_len, &leaf_cert);
    check("tampered leaf rejected", rc != CHARRA_RC_SUCCESS);

    free(leaf);
    free(root);
}

static void test_bad_arguments_rejected(void) {
    printf("\nbad arguments\n");

    uint8_t dummy[4] = {0};
    mbedtls_x509_crt leaf_cert;

    check("NULL leaf rejected",
            charra_crypto_verify_x509_cert_chain(NULL, sizeof(dummy), dummy,
                    sizeof(dummy), &leaf_cert) == CHARRA_RC_BAD_ARGUMENT);
    check("zero-length root rejected",
            charra_crypto_verify_x509_cert_chain(dummy, sizeof(dummy), dummy,
                    0, &leaf_cert) == CHARRA_RC_BAD_ARGUMENT);
    check("NULL leaf_out rejected",
            charra_crypto_verify_x509_cert_chain(dummy, sizeof(dummy), dummy,
                    sizeof(dummy), NULL) == CHARRA_RC_BAD_ARGUMENT);

    check("key-match: NULL cert rejected",
            charra_crypto_verify_cert_public_key_matches_tpm_public_key(
                    NULL, NULL) == CHARRA_RC_BAD_ARGUMENT);
}

static void test_cert_key_matches_same_partys_tpm_key(void) {
    printf("\na cert's embedded key matches a TPM2B_PUBLIC built from the "
           "same key pair\n");

    uint8_t* leaf = NULL;
    size_t leaf_len = 0;
    if (!read_der_file("keys/rp-ek.crt", &leaf, &leaf_len)) {
        check("setup: could not read rp-ek.crt", false);
        return;
    }

    mbedtls_x509_crt leaf_cert;
    mbedtls_x509_crt_init(&leaf_cert);
    if (mbedtls_x509_crt_parse(&leaf_cert, leaf, leaf_len) != 0) {
        check("setup: could not parse rp-ek.crt", false);
        free(leaf);
        return;
    }

    TPM2B_PUBLIC matching_key = {0};
    bool built = build_tpm2b_public_from_key_file(
            "keys/rp-ek.key", &matching_key);
    check("setup: built TPM2B_PUBLIC from rp-ek.key", built);
    if (built) {
        CHARRA_RC rc =
                charra_crypto_verify_cert_public_key_matches_tpm_public_key(
                        &leaf_cert, &matching_key);
        check("matching key pair recognised as matching",
                rc == CHARRA_RC_SUCCESS);
    }

    TPM2B_PUBLIC mismatched_key = {0};
    built = build_tpm2b_public_from_key_file(
            "keys/attester-ek.key", &mismatched_key);
    check("setup: built TPM2B_PUBLIC from attester-ek.key", built);
    if (built) {
        CHARRA_RC rc =
                charra_crypto_verify_cert_public_key_matches_tpm_public_key(
                        &leaf_cert, &mismatched_key);
        check("unrelated key pair recognised as NOT matching",
                rc == CHARRA_RC_VERIFICATION_FAILED);
    }

    mbedtls_x509_crt_free(&leaf_cert);
    free(leaf);
}

static void test_sign_and_verify_ak_certificate(void) {
    printf("\ncharra_crypto_sign_ak_certificate() round-trips through "
           "charra_crypto_verify_x509_cert_chain()\n");

    /* Read the CA's own Subject Name back out of its certificate via
     * mbedtls_x509_dn_gets(), rather than hardcoding a string that has to
     * match keys/gen-ak-pki.sh's "-subj" argument character-for-character
     * -- chain validation matches child.Issuer against parent.Subject by
     * DN comparison, so any drift there would break the chain, not just
     * look cosmetically different. */
    uint8_t* ca_cert_bytes = NULL;
    size_t ca_cert_len = 0;
    if (!read_der_file(
                "keys/verifier-ca.crt", &ca_cert_bytes, &ca_cert_len)) {
        check("setup: could not read verifier-ca.crt", false);
        return;
    }
    mbedtls_x509_crt ca_cert;
    mbedtls_x509_crt_init(&ca_cert);
    if (mbedtls_x509_crt_parse(&ca_cert, ca_cert_bytes, ca_cert_len) != 0) {
        check("setup: could not parse verifier-ca.crt", false);
        free(ca_cert_bytes);
        return;
    }
    char ca_subject_name[256] = {0};
    int name_len = mbedtls_x509_dn_gets(
            ca_subject_name, sizeof(ca_subject_name), &ca_cert.subject);
    mbedtls_x509_crt_free(&ca_cert);
    free(ca_cert_bytes);
    check("setup: read CA subject name", name_len > 0);
    if (name_len <= 0) {
        return;
    }

    TPM2B_PUBLIC ak_public_key = {0};
    bool built =
            build_tpm2b_public_from_key_file("keys/test-ak.key", &ak_public_key);
    check("setup: built TPM2B_PUBLIC from test-ak.key", built);
    if (!built) {
        return;
    }

    uint8_t* ak_cert_der = NULL;
    uint32_t ak_cert_der_len = 0;
    uint8_t serial[16] = {0};
    CHARRA_RC rc = charra_crypto_sign_ak_certificate(&ak_public_key,
            "CN=CHARRA Test AK", ca_subject_name, "20240101000000",
            "20340101000000", "keys/verifier-ca.key", &ak_cert_der,
            &ak_cert_der_len, serial);
    check("signing succeeds",
            rc == CHARRA_RC_SUCCESS && ak_cert_der != NULL &&
                    ak_cert_der_len > 0);
    if (rc != CHARRA_RC_SUCCESS) {
        return;
    }

    uint8_t* root = NULL;
    size_t root_len = 0;
    if (!read_der_file("keys/verifier-ca.crt", &root, &root_len)) {
        check("setup: could not read verifier-ca.crt", false);
        free(ak_cert_der);
        return;
    }

    mbedtls_x509_crt signed_leaf;
    rc = charra_crypto_verify_x509_cert_chain(
            ak_cert_der, ak_cert_der_len, root, root_len, &signed_leaf);
    check("freshly signed AK cert verifies against the Verifier's own CA",
            rc == CHARRA_RC_SUCCESS);
    if (rc == CHARRA_RC_SUCCESS) {
        check("signed cert's key matches the AK's TPM2B_PUBLIC",
                charra_crypto_verify_cert_public_key_matches_tpm_public_key(
                        &signed_leaf, &ak_public_key) == CHARRA_RC_SUCCESS);
        mbedtls_x509_crt_free(&signed_leaf);
    }
    free(root);

    uint8_t* wrong_root = NULL;
    size_t wrong_root_len = 0;
    if (read_der_file(
                "keys/manufacturer-root.crt", &wrong_root, &wrong_root_len)) {
        mbedtls_x509_crt leaf_against_wrong_root;
        rc = charra_crypto_verify_x509_cert_chain(ak_cert_der,
                ak_cert_der_len, wrong_root, wrong_root_len,
                &leaf_against_wrong_root);
        check("same AK cert rejected against an unrelated root",
                rc == CHARRA_RC_VERIFICATION_FAILED);
        free(wrong_root);
    } else {
        check("setup: could not read manufacturer-root.crt", false);
    }

    free(ak_cert_der);
}

int main(void) {
    printf("EK/AK certificate chain verification tests\n");
    printf("============================================\n");

    test_valid_chain_verifies();
    test_wrong_root_rejected();
    test_tampered_leaf_rejected();
    test_bad_arguments_rejected();
    test_cert_key_matches_same_partys_tpm_key();
    test_sign_and_verify_ak_certificate();

    printf("\n============================================\n");
    printf("%u tests, %u failed\n", tests_run, tests_failed);

    return (tests_failed == 0) ? 0 : 1;
}
