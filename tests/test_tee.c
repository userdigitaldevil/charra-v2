/**
 * @file test_tee.c
 * @brief Tests for TEE.h -- the simulated TEE's measurement and signing.
 *
 * Three things make this worth its own suite:
 *
 *   - tee_hash_files() is a MEASUREMENT. If it is not order-sensitive, or
 *     not deterministic, the Verifier's independent recomputation stops
 *     meaning anything -- it would match a different set of files, or fail
 *     against the right ones.
 *   - the Attestation Document is two digests signed as one blob. If a
 *     mutation anywhere in either digest survives verification, the whole
 *     construction is decorative.
 *   - the keypair is generated lazily and shared by every thread. A second
 *     call producing a DIFFERENT key would break every signature already
 *     sent, silently.
 *
 * Pure software: no TPM, no network. Temporary files are written under
 * /tmp, which is also why nothing here measures the real source tree --
 * these tests must not fail because someone edited rp_evidence.c.
 *
 * Build and run:  make test_tee && ./bin/test_tee
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <mbedtls/pk.h>
#include <mbedtls/rsa.h>

#include "../src/core/TEE.h"
#include "../src/util/crypto_util.h"

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

/* --- fixtures ----------------------------------------------------------- */

#define FIXTURE_A "/tmp/charra_test_tee_a.txt"
#define FIXTURE_B "/tmp/charra_test_tee_b.txt"
#define FIXTURE_EMPTY "/tmp/charra_test_tee_empty.txt"
#define FIXTURE_MISSING "/tmp/charra_test_tee_does_not_exist.txt"

static bool write_fixture(const char* path, const char* content) {
    FILE* f = fopen(path, "wb");
    if (f == NULL) {
        return false;
    }
    size_t len = strlen(content);
    bool ok = (len == 0) || (fwrite(content, 1, len, f) == len);
    fclose(f);
    return ok;
}

static bool make_fixtures(void) {
    return write_fixture(FIXTURE_A, "the quick brown fox\n") &&
           write_fixture(FIXTURE_B, "jumps over the lazy dog\n") &&
           write_fixture(FIXTURE_EMPTY, "");
}

static void remove_fixtures(void) {
    remove(FIXTURE_A);
    remove(FIXTURE_B);
    remove(FIXTURE_EMPTY);
}

/* --- tee_hash_files ----------------------------------------------------- */

static void test_hash_files_deterministic(void) {
    printf("\ntee_hash_files: the same files always hash the same\n");

    const char* files[] = {FIXTURE_A, FIXTURE_B};
    uint8_t first[TPM2_SHA256_DIGEST_SIZE] = {0};
    uint8_t second[TPM2_SHA256_DIGEST_SIZE] = {0};

    check("hashing succeeds",
            tee_hash_files(files, 2, first) == CHARRA_RC_SUCCESS);
    check("and again", tee_hash_files(files, 2, second) == CHARRA_RC_SUCCESS);
    check("both runs agree", memcmp(first, second, sizeof(first)) == 0);

    /* The Verifier recomputes this independently; a digest that is not the
     * hash of the concatenation would still be "deterministic" but would
     * not be reproducible by anyone else. */
    uint8_t manual[TPM2_SHA256_DIGEST_SIZE] = {0};
    const char* combined = "the quick brown fox\njumps over the lazy dog\n";
    check("it is SHA-256 over the files concatenated in order",
            hash_sha256(strlen(combined), (const uint8_t*)combined, manual) ==
                            CHARRA_RC_SUCCESS &&
                    memcmp(manual, first, sizeof(manual)) == 0);
}

static void test_hash_files_order_matters(void) {
    printf("\ntee_hash_files: order is part of the measurement\n");

    const char* forward[] = {FIXTURE_A, FIXTURE_B};
    const char* reverse[] = {FIXTURE_B, FIXTURE_A};
    uint8_t h1[TPM2_SHA256_DIGEST_SIZE] = {0};
    uint8_t h2[TPM2_SHA256_DIGEST_SIZE] = {0};

    tee_hash_files(forward, 2, h1);
    tee_hash_files(reverse, 2, h2);
    /* Both sides keep their own hand-maintained list. If order did not
     * matter, two lists that had silently diverged in order would still
     * agree -- and the measurement would be weaker than it looks. */
    check("the same files in a different order hash differently",
            memcmp(h1, h2, sizeof(h1)) != 0);

    /* A subset must not collide with the full set either. */
    uint8_t only_a[TPM2_SHA256_DIGEST_SIZE] = {0};
    tee_hash_files(forward, 1, only_a);
    check("a shorter list hashes differently",
            memcmp(h1, only_a, sizeof(h1)) != 0);
}

static void test_hash_files_empty_file(void) {
    printf("\ntee_hash_files: an empty file contributes nothing\n");

    const char* with_empty[] = {FIXTURE_A, FIXTURE_EMPTY, FIXTURE_B};
    const char* without[] = {FIXTURE_A, FIXTURE_B};
    uint8_t h1[TPM2_SHA256_DIGEST_SIZE] = {0};
    uint8_t h2[TPM2_SHA256_DIGEST_SIZE] = {0};

    /* Regression: realloc(p, 0) may return NULL, which an allocation-failure
     * check reads as an error. An empty file in the list must not fail the
     * measurement. */
    check("a list containing an empty file still hashes",
            tee_hash_files(with_empty, 3, h1) == CHARRA_RC_SUCCESS);
    tee_hash_files(without, 2, h2);
    check("and gives the same digest as omitting it",
            memcmp(h1, h2, sizeof(h1)) == 0);
}

static void test_hash_files_rejects(void) {
    printf("\ntee_hash_files: refuses what it cannot measure\n");

    uint8_t out[TPM2_SHA256_DIGEST_SIZE] = {0};
    const char* missing[] = {FIXTURE_A, FIXTURE_MISSING};
    const char* good[] = {FIXTURE_A};

    /* Fail-closed: a file it cannot read must be an error, never a digest
     * over whatever it did manage to read. */
    check("an unreadable file is rejected",
            tee_hash_files(missing, 2, out) != CHARRA_RC_SUCCESS);
    check("NULL paths rejected",
            tee_hash_files(NULL, 1, out) == CHARRA_RC_BAD_ARGUMENT);
    check("zero files rejected",
            tee_hash_files(good, 0, out) == CHARRA_RC_BAD_ARGUMENT);
    check("NULL output rejected",
            tee_hash_files(good, 1, NULL) == CHARRA_RC_BAD_ARGUMENT);
}

/* --- tee_attestation ---------------------------------------------------- */

static void test_attestation_document(void) {
    printf("\ntee_attestation: measures the code, copies REPORT_DATA\n");

    const char* files[] = {FIXTURE_A, FIXTURE_B};
    uint8_t report_data[TPM2_SHA256_DIGEST_SIZE];
    memset(report_data, 0x5a, sizeof(report_data));

    tee_attestation_document doc = {0};
    check("attestation succeeds",
            tee_attestation(files, 2, report_data, &doc) == CHARRA_RC_SUCCESS);

    uint8_t expected[TPM2_SHA256_DIGEST_SIZE] = {0};
    tee_hash_files(files, 2, expected);
    check("file_hash is tee_hash_files() of the same list",
            memcmp(doc.file_hash, expected, sizeof(expected)) == 0);
    check("report_data is copied verbatim, not re-hashed",
            memcmp(doc.report_data, report_data, sizeof(report_data)) == 0);

    /* Refusing to attest is the whole point when the code cannot be
     * measured: a document with a zero file_hash would still verify. */
    const char* missing[] = {FIXTURE_MISSING};
    tee_attestation_document bad = {0};
    check("an unmeasurable file means no document at all",
            tee_attestation(missing, 1, report_data, &bad) !=
                    CHARRA_RC_SUCCESS);

    check("NULL report_data rejected",
            tee_attestation(files, 2, NULL, &doc) == CHARRA_RC_BAD_ARGUMENT);
    check("NULL output rejected",
            tee_attestation(files, 2, report_data, NULL) ==
                    CHARRA_RC_BAD_ARGUMENT);
}

/* --- signing and the key ------------------------------------------------ */

/** Verifies a signature over (file_hash || report_data) under the TEE's
 * exported public key -- exactly what verifier_appraise.c does. */
static bool verify_doc(const tee_attestation_document* doc,
        const uint8_t* signature, size_t signature_len) {
    uint8_t der[CHARRA_RSA_PUB_KEY_DER_MAX] = {0};
    uint32_t der_len = 0;
    if (tee_public_key_der(der, sizeof(der), &der_len) != CHARRA_RC_SUCCESS) {
        return false;
    }

    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);
    bool ok = false;
    if (mbedtls_pk_parse_public_key(&pk, der, der_len) == 0 &&
            mbedtls_pk_get_type(&pk) == MBEDTLS_PK_RSA &&
            mbedtls_rsa_set_padding(mbedtls_pk_rsa(pk), MBEDTLS_RSA_PKCS_V21,
                    MBEDTLS_MD_SHA256) == 0) {
        uint8_t signed_data[sizeof(doc->file_hash) + sizeof(doc->report_data)];
        memcpy(signed_data, doc->file_hash, sizeof(doc->file_hash));
        memcpy(signed_data + sizeof(doc->file_hash), doc->report_data,
                sizeof(doc->report_data));
        ok = charra_crypto_rsa_verify_signature(mbedtls_pk_rsa(pk),
                     MBEDTLS_MD_SHA256, signed_data, sizeof(signed_data),
                     signature) == CHARRA_RC_SUCCESS &&
             signature_len == CHARRA_RSA_SIGNATURE_LEN;
    }
    mbedtls_pk_free(&pk);
    return ok;
}

static void test_sign_and_verify(void) {
    printf("\ntee_sign: a document verifies under the exported key\n");

    const char* files[] = {FIXTURE_A, FIXTURE_B};
    uint8_t report_data[TPM2_SHA256_DIGEST_SIZE];
    memset(report_data, 0x11, sizeof(report_data));

    tee_attestation_document doc = {0};
    tee_attestation(files, 2, report_data, &doc);

    uint8_t sig[CHARRA_RSA_SIGNATURE_LEN] = {0};
    check("signing succeeds", tee_sign(&doc, sig) == CHARRA_RC_SUCCESS);
    check("and the signature verifies",
            verify_doc(&doc, sig, sizeof(sig)));

    check("NULL document rejected",
            tee_sign(NULL, sig) == CHARRA_RC_BAD_ARGUMENT);
    check("NULL signature buffer rejected",
            tee_sign(&doc, NULL) == CHARRA_RC_BAD_ARGUMENT);
}

static void test_key_is_stable(void) {
    printf("\nthe keypair is generated once and reused\n");

    uint8_t first[CHARRA_RSA_PUB_KEY_DER_MAX] = {0};
    uint8_t second[CHARRA_RSA_PUB_KEY_DER_MAX] = {0};
    uint32_t first_len = 0, second_len = 0;

    check("exporting the public key succeeds",
            tee_public_key_der(first, sizeof(first), &first_len) ==
                    CHARRA_RC_SUCCESS);
    check("and again",
            tee_public_key_der(second, sizeof(second), &second_len) ==
                    CHARRA_RC_SUCCESS);
    /* A second call generating a NEW key would invalidate every signature
     * already sent, and nothing would report it. */
    check("both calls return the same key",
            first_len == second_len && first_len > 0 &&
                    memcmp(first, second, first_len) == 0);

    /* Too small a buffer must be refused, not truncated: a truncated DER
     * key would fail to parse at the Verifier and read as a bad signature. */
    uint8_t tiny[8] = {0};
    uint32_t tiny_len = 0;
    check("a buffer too small to hold the key is rejected",
            tee_public_key_der(tiny, sizeof(tiny), &tiny_len) ==
                    CHARRA_RC_BAD_ARGUMENT);
    check("NULL output rejected",
            tee_public_key_der(NULL, sizeof(first), &first_len) ==
                    CHARRA_RC_BAD_ARGUMENT);
}

static void test_signature_is_randomised(void) {
    printf("\nRSA-PSS is randomised: signatures are not comparable\n");

    const char* files[] = {FIXTURE_A};
    uint8_t report_data[TPM2_SHA256_DIGEST_SIZE];
    memset(report_data, 0x22, sizeof(report_data));
    tee_attestation_document doc = {0};
    tee_attestation(files, 1, report_data, &doc);

    uint8_t sig1[CHARRA_RSA_SIGNATURE_LEN] = {0};
    uint8_t sig2[CHARRA_RSA_SIGNATURE_LEN] = {0};
    tee_sign(&doc, sig1);
    tee_sign(&doc, sig2);

    /* Pinned because it is a trap: the PSS salt is fresh per signature, so
     * anything that compared two signatures byte-for-byte to decide "same
     * document" would be wrong. Compare the signed VALUES. */
    check("two signings of one document differ",
            memcmp(sig1, sig2, sizeof(sig1)) != 0);
    check("but both verify", verify_doc(&doc, sig1, sizeof(sig1)) &&
                                     verify_doc(&doc, sig2, sizeof(sig2)));
}

static void test_mutation_sweep(void) {
    printf("\nevery byte of the document is covered by the signature\n");

    const char* files[] = {FIXTURE_A, FIXTURE_B};
    uint8_t report_data[TPM2_SHA256_DIGEST_SIZE];
    memset(report_data, 0x33, sizeof(report_data));
    tee_attestation_document doc = {0};
    tee_attestation(files, 2, report_data, &doc);

    uint8_t sig[CHARRA_RSA_SIGNATURE_LEN] = {0};
    tee_sign(&doc, sig);

    /* Flip one bit in each byte of file_hash in turn. A survivor here means
     * the RP could claim the expected code while running something else. */
    bool all_rejected = true;
    for (size_t i = 0; i < sizeof(doc.file_hash); i++) {
        tee_attestation_document tampered = doc;
        tampered.file_hash[i] ^= 0x01;
        if (verify_doc(&tampered, sig, sizeof(sig))) {
            printf("        (file_hash byte %zu survived)\n", i);
            all_rejected = false;
            break;
        }
    }
    check("a mutation anywhere in file_hash is rejected", all_rejected);

    /* Same for report_data: a survivor means a document could be replayed
     * against a different nonce, evidence or log. */
    all_rejected = true;
    for (size_t i = 0; i < sizeof(doc.report_data); i++) {
        tee_attestation_document tampered = doc;
        tampered.report_data[i] ^= 0x01;
        if (verify_doc(&tampered, sig, sizeof(sig))) {
            printf("        (report_data byte %zu survived)\n", i);
            all_rejected = false;
            break;
        }
    }
    check("a mutation anywhere in report_data is rejected", all_rejected);

    /* And a mutated signature, for the same reason in reverse. */
    all_rejected = true;
    for (size_t i = 0; i < sizeof(sig); i += 16) {
        uint8_t tampered_sig[CHARRA_RSA_SIGNATURE_LEN];
        memcpy(tampered_sig, sig, sizeof(sig));
        tampered_sig[i] ^= 0x01;
        if (verify_doc(&doc, tampered_sig, sizeof(tampered_sig))) {
            printf("        (signature byte %zu survived)\n", i);
            all_rejected = false;
            break;
        }
    }
    check("a mutated signature is rejected", all_rejected);
}

int main(void) {
    printf("TEE tests\n");
    printf("=========\n");

    if (!make_fixtures()) {
        printf("  FAIL  could not write test fixtures under /tmp\n");
        return 1;
    }

    test_hash_files_deterministic();
    test_hash_files_order_matters();
    test_hash_files_empty_file();
    test_hash_files_rejects();
    test_attestation_document();
    test_sign_and_verify();
    test_key_is_stable();
    test_signature_is_randomised();
    test_mutation_sweep();

    remove_fixtures();

    printf("\n=========\n");
    printf("%u tests, %u failed\n", tests_run, tests_failed);

    return (tests_failed == 0) ? 0 : 1;
}
