/**
 * @file charra_verdict.h
 * @brief The /appraise response: one Verifier's vote, signed.
 *
 * Before this existed the answer was the ASCII string "Attestation
 * successful!" over plain UDP, and the RP counted a vote by comparing it
 * byte for byte. Anything that could reach the RP's socket could vote.
 * Signing raises that bar to "holds keys/verifier.der".
 *
 * A vote is not just its verdict bit -- it is bound to the round and to
 * the evidence it was cast over:
 *
 *   challenge_nonce  the 32 bytes THIS Verifier issued from /nonce this
 *                    round. Stops replay across rounds, and -- because
 *                    every Verifier draws its own -- stops a vote from
 *                    being counted in another Verifier's slot.
 *   evidence_digest  SHA-256 over the marshaled evidence appraised, so a
 *                    YES cast over one submission cannot be pasted onto
 *                    another.
 *   signed_at        wall clock, for the log and a staleness bound. It is
 *                    an ASSERTION, not proof: no role here has a trusted
 *                    clock. Freshness comes from the nonce.
 *
 * All five Verifiers currently share one keypair, so a signature says
 * "some Verifier", not "Verifier 3". The per-slot separation comes from
 * the nonce instead, which is why the nonce check is not optional. Moving
 * to per-Verifier keys later changes only which file is opened.
 *
 * Wire shape, deliberately payload-then-signature:
 *
 *   [ payload: bstr, signature: bstr ]
 *   payload = [ accepted: uint, nonce: bstr, digest: bstr, signed_at: uint ]
 *
 * The signature covers the payload BYTES as received, so verification
 * never re-encodes anything and the two sides cannot disagree about
 * canonical form.
 */

#ifndef CHARRA_VERDICT_H
#define CHARRA_VERDICT_H

#include <stdbool.h>
#include <stdint.h>
#include <time.h>

#include <tss2/tss2_tpm2_types.h>

#include "../common/charra_error.h"

/** How far signed_at may sit from the receiver's clock. Generous because
 * nothing synchronises these processes; they merely happen to share a
 * host. Nothing security-critical rests on it -- see the header note. */
#define CHARRA_VERDICT_SKEW_SECONDS 60

/** Bound on a signature from keys/verifier.der. ECDSA P-256 needs ~72
 * bytes DER; sized for RSA-2048 as well so switching key type is a
 * regenerate, not an edit here. */
#define CHARRA_VERDICT_MAX_SIGNATURE_LEN 256

/** The signed fields. Not a wire struct: charra_verdict_sign() encodes it
 * and charra_verdict_verify() checks it, and neither exposes the CBOR. */
typedef struct {
    bool accepted;
    uint8_t challenge_nonce[TPM2_SHA256_DIGEST_SIZE];
    uint32_t challenge_nonce_len;
    uint8_t evidence_digest[TPM2_SHA256_DIGEST_SIZE];
    uint64_t signed_at;
} charra_verdict;

/**
 * @brief Encode a verdict and sign it with the key at private_key_path.
 *
 * @param[out] marshaled_data heap-allocated, caller frees.
 */
CHARRA_RC charra_verdict_sign(const charra_verdict* verdict,
        const char* private_key_path, uint32_t* marshaled_data_len,
        uint8_t** marshaled_data);

/**
 * @brief Parse a verdict, check its signature, and check it belongs to
 * this round and this evidence.
 *
 * One call rather than a parse plus four caller-side comparisons: every
 * check is mandatory, so leaving any of them to the caller only creates a
 * way to forget one. Which check failed is logged here.
 *
 * @param[out] accepted_out the vote, written ONLY on CHARRA_RC_SUCCESS.
 * Every other outcome means "no usable vote", which the caller counts as
 * a NO -- an unverifiable YES and a genuine NO are the same thing.
 * @returns CHARRA_RC_SUCCESS if the record is well-formed, correctly
 * signed, and matches the expected nonce, digest and time window;
 * CHARRA_RC_VERIFICATION_FAILED if any of that does not hold;
 * CHARRA_RC_MARSHALING_ERROR if it is not a verdict record at all.
 */
CHARRA_RC charra_verdict_verify(uint32_t marshaled_data_len,
        const uint8_t* marshaled_data, const char* public_key_path,
        const uint8_t* expected_nonce, uint32_t expected_nonce_len,
        const uint8_t expected_evidence_digest[TPM2_SHA256_DIGEST_SIZE],
        time_t now, bool* accepted_out);

#endif /* CHARRA_VERDICT_H */
