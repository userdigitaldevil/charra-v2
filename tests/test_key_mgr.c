/**
 * @file test_key_mgr.c
 * @brief Tests for the signing-key name check in charra_key_mgr.h.
 *
 * `/attest` carries a `sig_key_id` naming which signing identity the
 * Attester should quote with. The catalogue has exactly one entry, so the
 * only thing this check can do is REFUSE -- which makes the refusal the
 * whole test surface.
 *
 * It earns a suite because the comparison used to be
 * `memcmp(key, LITERAL, key_len)` with a caller-supplied length: a prefix
 * match, and one that accepted an empty name outright, since memcmp over
 * zero bytes returns 0. Harmless while the catalogue has one entry; key
 * confusion the moment it has two.
 *
 * No TPM needed: a name that does not match returns before the ESAPI
 * context is touched, which is why NULL is safe to pass here.
 *
 * Build and run:  make test_key_mgr && ./bin/test_key_mgr
 */

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "../src/core/charra_key_mgr.h"
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

/** @brief Would this name be refused? Never reaches the TPM when it is. */
static bool refused(const char* name, uint32_t len) {
    ESYS_TR handle = ESYS_TR_NONE;
    TPM2B_PUBLIC* public_key = NULL;
    return charra_load_tpm2_key(NULL, len, (const uint8_t*)name, &handle,
                   &public_key) != CHARRA_RC_SUCCESS;
}

static void test_the_name_is_the_anchor_label(void) {
    printf("\nthe accepted name is the trust anchor's own label\n");

    /* Not merely equal by coincidence: this is what stops the wire from
     * becoming a third vocabulary for one key, alongside `--role attester`
     * and the `# attester` comment in keys/trusted_keys.txt. */
    check("CHARRA_AK_A_KEY_ID is CHARRA_ROLE_ATTESTER",
            strcmp(CHARRA_AK_A_KEY_ID, CHARRA_ROLE_ATTESTER) == 0);
    check("its length constant matches the string",
            CHARRA_AK_A_KEY_ID_LEN == strlen(CHARRA_AK_A_KEY_ID));
    check("and that string is \"attester\"",
            strcmp(CHARRA_AK_A_KEY_ID, "attester") == 0);
}

/* Regression: every one of these was ACCEPTED by the old prefix match. */
static void test_prefixes_rejected(void) {
    printf("\na prefix of the correct name is rejected\n");

    const char* full = CHARRA_AK_A_KEY_ID;
    bool all_refused = true;
    for (uint32_t len = 0; len < CHARRA_AK_A_KEY_ID_LEN; ++len) {
        if (!refused(full, len)) {
            printf("        (accepted a %u-byte prefix)\n", len);
            all_refused = false;
            break;
        }
    }
    check("no proper prefix is accepted", all_refused);

    /* Called out separately because it is the sharpest case: memcmp over
     * zero bytes compares equal, so "no name supplied" used to mean
     * "correct name supplied". Same shape as the len != 0 terms guarding
     * every nonce comparison in the tree. */
    check("an EMPTY name is rejected", refused("", 0));
    check("a NULL-ish one-byte name is rejected", refused("\0", 1));
}

static void test_wrong_names_rejected(void) {
    printf("\nnames that are not the one name are rejected\n");

    check("a different name of the same length is rejected",
            refused("attestor", 8));
    check("a longer name with the right prefix is rejected",
            refused("attester_debug", 14));
    check("the upstream name is no longer accepted",
            refused("PK.RSA.default", 14));
    check("the other role's label is rejected",
            refused(CHARRA_ROLE_RELYING_PARTY,
                    (uint32_t)strlen(CHARRA_ROLE_RELYING_PARTY)));
    check("case matters", refused("ATTESTER", 8));
    check("trailing whitespace matters", refused("attester ", 9));

    /* An over-long length must not be read past the literal it is
     * compared against. Checking the length first is what makes this
     * safe; the assertion is that it is refused, not that it crashes. */
    char padded[256];
    memset(padded, 'z', sizeof(padded));
    memcpy(padded, CHARRA_AK_A_KEY_ID, CHARRA_AK_A_KEY_ID_LEN);
    check("an over-long name is rejected without over-reading",
            refused(padded, (uint32_t)sizeof(padded)));
}

int main(void) {
    printf("Signing-key name tests\n");
    printf("======================\n");

    test_the_name_is_the_anchor_label();
    test_prefixes_rejected();
    test_wrong_names_rejected();

    printf("\n======================\n");
    printf("%u tests, %u failed\n", tests_run, tests_failed);

    return (tests_failed == 0) ? 0 : 1;
}
