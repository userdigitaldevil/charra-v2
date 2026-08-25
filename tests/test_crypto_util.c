/**
 * @file test_crypto_util.c
 * @brief Tests for the hashing and file-backed signing helpers.
 *
 * The hashes are checked against published FIPS/NIST vectors rather than
 * against another call to the same function, because a self-consistent
 * wrapper around a broken configuration would pass the latter. Everything
 * downstream -- PCR replay, the redaction SDK, evidence digests, the trust
 * anchor -- rests on hash_sha256() being SHA-256 and nothing else.
 *
 * The pk helpers are exercised against the real key files in keys/, the
 * same ones a Verifier signs verdicts with.
 *
 * Build and run:  make test_crypto_util && ./bin/test_crypto_util
 */

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "../src/util/crypto_util.h"
#include "../src/util/hex_util.h"

#define PRIVATE_KEY "keys/verifier.der"
#define PUBLIC_KEY "keys/verifier.pub.der"
#define OTHER_PUBLIC_KEY "keys/attester.pub.der"

/** Roomy enough for ECDSA P-256 (~72 bytes DER) and RSA-2048 (256). */
#define SIG_CAP 256

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

/** @brief Compares a digest against its published hex vector. */
static bool digest_is(
        const uint8_t* digest, size_t digest_len, const char* expected_hex) {
    char got[129] = {0};
    if (digest_len * 2 >= sizeof(got)) {
        return false;
    }
    charra_hex_encode(digest, digest_len, got);
    return strcmp(got, expected_hex) == 0;
}

static void test_sha256_vectors(void) {
    printf("\nhash_sha256 against published vectors\n");

    uint8_t d[TPM2_SHA256_DIGEST_SIZE] = {0};

    check("SHA-256(\"abc\")",
            hash_sha256(3, (const uint8_t*)"abc", d) == CHARRA_RC_SUCCESS &&
                    digest_is(d, sizeof(d),
                            "ba7816bf8f01cfea414140de5dae2223"
                            "b00361a396177a9cb410ff61f20015ad"));

    check("SHA-256(\"\") -- the empty input, which the evidence digest "
          "relies on being well defined",
            hash_sha256(0, (const uint8_t*)"", d) == CHARRA_RC_SUCCESS &&
                    digest_is(d, sizeof(d),
                            "e3b0c44298fc1c149afbf4c8996fb924"
                            "27ae41e4649b934ca495991b7852b855"));

    const char* long_msg =
            "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    check("SHA-256 of a multi-block message",
            hash_sha256(strlen(long_msg), (const uint8_t*)long_msg, d) ==
                            CHARRA_RC_SUCCESS &&
                    digest_is(d, sizeof(d),
                            "248d6a61d20638b8e5c026930c3e6039"
                            "a33ce45964ff2167f6ecedd419db06c1"));

    /* One flipped bit must change the digest completely -- the property
     * every tamper check in this project depends on. */
    uint8_t a[TPM2_SHA256_DIGEST_SIZE] = {0};
    uint8_t b[TPM2_SHA256_DIGEST_SIZE] = {0};
    hash_sha256(3, (const uint8_t*)"abc", a);
    hash_sha256(3, (const uint8_t*)"abd", b);
    check("a one-bit input change changes the digest",
            memcmp(a, b, sizeof(a)) != 0);
}

static void test_other_hashes(void) {
    printf("\nthe other digest sizes\n");

    uint8_t d1[TPM2_SHA1_DIGEST_SIZE] = {0};
    check("SHA-1(\"abc\") -- still reachable, since an IMA log may use "
          "SHA-1 template digests",
            hash_sha1(3, (const uint8_t*)"abc", d1) == CHARRA_RC_SUCCESS &&
                    digest_is(d1, sizeof(d1),
                            "a9993e364706816aba3e25717850c26c9cd0d89d"));

    uint8_t d5[TPM2_SHA512_DIGEST_SIZE] = {0};
    check("SHA-512(\"abc\")",
            hash_sha512(3, (const uint8_t*)"abc", d5) == CHARRA_RC_SUCCESS &&
                    digest_is(d5, sizeof(d5),
                            "ddaf35a193617abacc417349ae204131"
                            "12e6fa4e89a97ea20a9eeee64b55d39a"
                            "2192992a274fc1a836ba3c23a3feebbd"
                            "454d4423643ce80e2a9ac94fa54ca49f"));

    /* The generic entry point must agree with the specific one, or the
     * two paths through the codebase would disagree about the same log. */
    uint8_t generic[MBEDTLS_MD_MAX_SIZE] = {0};
    uint8_t specific[TPM2_SHA256_DIGEST_SIZE] = {0};
    hash_sha256(3, (const uint8_t*)"abc", specific);
    check("charra_crypto_hash(SHA256) agrees with hash_sha256",
            charra_crypto_hash(MBEDTLS_MD_SHA256, (const uint8_t*)"abc", 3,
                    generic) == CHARRA_RC_SUCCESS &&
                    memcmp(generic, specific, sizeof(specific)) == 0);
}

static void test_pk_sign_verify(void) {
    printf("\ncharra_crypto_pk_sign_file / _verify_file\n");

    const uint8_t payload[] = "the bytes a Verifier signs into its verdict";
    const size_t payload_len = sizeof(payload) - 1;

    uint8_t sig[SIG_CAP] = {0};
    size_t sig_len = 0;
    check("signing succeeds",
            charra_crypto_pk_sign_file(PRIVATE_KEY, payload, payload_len, sig,
                    sizeof(sig), &sig_len) == CHARRA_RC_SUCCESS);
    check("a signature was produced", sig_len > 0);

    check("it verifies under the matching public key",
            charra_crypto_pk_verify_file(PUBLIC_KEY, payload, payload_len,
                    sig, sig_len) == CHARRA_RC_SUCCESS);

    /* Three distinguishable failure modes, because the caller may want to
     * treat "no key file" (deployment fault) differently from "bad
     * signature" (attack). */
    check("a different public key gives VERIFICATION_FAILED",
            charra_crypto_pk_verify_file(OTHER_PUBLIC_KEY, payload,
                    payload_len, sig,
                    sig_len) == CHARRA_RC_VERIFICATION_FAILED);
    check("a missing key file gives CRYPTO_ERROR, not a false pass",
            charra_crypto_pk_verify_file("keys/does-not-exist.pub.der",
                    payload, payload_len, sig,
                    sig_len) == CHARRA_RC_CRYPTO_ERROR);
    check("signing with a missing key file fails",
            charra_crypto_pk_sign_file("keys/does-not-exist.der", payload,
                    payload_len, sig, sizeof(sig),
                    &sig_len) != CHARRA_RC_SUCCESS);
}

static void test_pk_rejects_tampering(void) {
    printf("\nany change to the signed bytes invalidates the signature\n");

    const uint8_t payload[] = "abcdefghijklmnopqrstuvwxyz0123456789";
    const size_t payload_len = sizeof(payload) - 1;

    uint8_t sig[SIG_CAP] = {0};
    size_t sig_len = 0;
    charra_crypto_pk_sign_file(
            PRIVATE_KEY, payload, payload_len, sig, sizeof(sig), &sig_len);

    /* Sweep every byte of the message rather than sampling one: this is
     * the guarantee /appraise leans on, so it is worth proving over the
     * whole input. */
    unsigned int accepted = 0;
    for (size_t i = 0; i < payload_len; ++i) {
        uint8_t mutated[sizeof(payload)];
        memcpy(mutated, payload, sizeof(payload));
        mutated[i] ^= 0x01;
        if (charra_crypto_pk_verify_file(PUBLIC_KEY, mutated, payload_len,
                    sig, sig_len) == CHARRA_RC_SUCCESS) {
            accepted++;
        }
    }
    check("no single-byte change to the message verifies", accepted == 0);

    /* And every byte of the signature itself. */
    unsigned int sig_accepted = 0;
    for (size_t i = 0; i < sig_len; ++i) {
        uint8_t mutated[SIG_CAP];
        memcpy(mutated, sig, sig_len);
        mutated[i] ^= 0x01;
        if (charra_crypto_pk_verify_file(PUBLIC_KEY, payload, payload_len,
                    mutated, sig_len) == CHARRA_RC_SUCCESS) {
            sig_accepted++;
        }
    }
    check("no single-byte change to the signature verifies",
            sig_accepted == 0);

    check("a truncated signature is rejected",
            charra_crypto_pk_verify_file(PUBLIC_KEY, payload, payload_len,
                    sig, sig_len - 1) != CHARRA_RC_SUCCESS);
    check("an empty signature is rejected",
            charra_crypto_pk_verify_file(PUBLIC_KEY, payload, payload_len,
                    sig, 0) != CHARRA_RC_SUCCESS);
}

static void test_pk_signature_is_deterministic(void) {
    printf("\nECDSA here is deterministic (RFC 6979), not randomised\n");

    const uint8_t payload[] = "identical input, two signings";
    const size_t payload_len = sizeof(payload) - 1;

    uint8_t a[SIG_CAP] = {0};
    uint8_t b[SIG_CAP] = {0};
    size_t a_len = 0, b_len = 0;
    charra_crypto_pk_sign_file(
            PRIVATE_KEY, payload, payload_len, a, sizeof(a), &a_len);
    charra_crypto_pk_sign_file(
            PRIVATE_KEY, payload, payload_len, b, sizeof(b), &b_len);

    /* This build sets MBEDTLS_ECDSA_DETERMINISTIC, so the per-signature k
     * is derived from (key, message) instead of drawn at random. Worth
     * pinning in a test rather than assuming either way, because the two
     * signature schemes in this system behave OPPOSITELY:
     *
     *   - the Verifier's verdict, ECDSA here: same input, same bytes
     *   - Quote_r and the qualification signature, RSA-PSS in the TPM:
     *     salted, so two honest signings never match bytewise
     *
     * Which is why the qualification handshake compares redacted LOGS and
     * never signature bytes -- a rule that reads as over-caution until you
     * notice it is about the other scheme. */
    check("two signings of the same bytes are identical",
            a_len == b_len && memcmp(a, b, a_len) == 0);
    check("and both verify",
            charra_crypto_pk_verify_file(
                    PUBLIC_KEY, payload, payload_len, a, a_len) ==
                    CHARRA_RC_SUCCESS);

    /* Determinism is per (key, message): a different message must still
     * produce a different signature, or the scheme would be broken. */
    const uint8_t other[] = "a different message entirely";
    uint8_t c[SIG_CAP] = {0};
    size_t c_len = 0;
    charra_crypto_pk_sign_file(
            PRIVATE_KEY, other, sizeof(other) - 1, c, sizeof(c), &c_len);
    check("a different message gives a different signature",
            c_len != a_len || memcmp(a, c, a_len) != 0);

    /* Determinism also removes the classic ECDSA footgun -- a repeated
     * random k across two signatures leaks the private key -- so this is
     * a property to keep, not to work around. */
    check("the deterministic signature still fails on the wrong message",
            charra_crypto_pk_verify_file(PUBLIC_KEY, other,
                    sizeof(other) - 1, a,
                    a_len) == CHARRA_RC_VERIFICATION_FAILED);
}

static void test_signature_buffer_cap(void) {
    printf("\nsigning refuses to overflow the caller's buffer\n");

    const uint8_t payload[] = "x";
    uint8_t tiny[8] = {0};
    size_t len = 0;

    /* Fails rather than truncating: a truncated signature would verify
     * nowhere and the caller would have no idea why. */
    check("a too-small output buffer is an error",
            charra_crypto_pk_sign_file(PRIVATE_KEY, payload, 1, tiny,
                    sizeof(tiny), &len) != CHARRA_RC_SUCCESS);
}

int main(void) {
    printf("crypto_util tests\n");
    printf("=================\n");

    test_sha256_vectors();
    test_other_hashes();
    test_pk_sign_verify();
    test_pk_rejects_tampering();
    test_pk_signature_is_deterministic();
    test_signature_buffer_cap();

    printf("\n=================\n");
    printf("%u tests, %u failed\n", tests_run, tests_failed);

    return (tests_failed == 0) ? 0 : 1;
}
