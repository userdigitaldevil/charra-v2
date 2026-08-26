/**
 * @file rp_signing_key.h
 * @brief AK_r -- the RP's attestation key: its TPM's unrestricted signing
 * primary, and the thing that signs Quote_r.
 *
 * An AK by assertion, not by certification. This PoC has no EK and no CA,
 * so nothing proves the key into that role at runtime; what makes it AK_r
 * is that keys/trusted_keys.txt names it (see charra_trusted_keys.h).
 *
 * Nothing is provisioned, stored, or held between uses. The key is
 * re-derived from the TPM's owner-hierarchy seed on every call, which
 * reproduces it identically, so the identity story is "derive, use, send
 * the public half, let the Verifier decide" -- every time, from scratch.
 *
 * UNRESTRICTED, and that is a trade. TPM2_Quote accepts either kind, so
 * quoting does not need it; rp_sign_with_ak() does, because a restricted
 * key refuses a caller-supplied digest for want of a validation ticket.
 * The cost: an unrestricted key can also sign a hand-built TPMS_ATTEST via
 * TPM2_Sign, so "signed by AK_r" alone does not prove a TPM built the
 * structure. What closes that gap is the Verifier replaying log_r and
 * checking it against the quote's pcrDigest.
 *
 * Every entry point opens its own short-lived TPM connection and closes it
 * before returning. Not tidiness: the simulator serves one client at a
 * time, and an RP holding a connection across a CoAP wait once starved
 * every other role.
 */

#ifndef CHARRA_RP_SIGNING_KEY_H
#define CHARRA_RP_SIGNING_KEY_H

#include <stddef.h>
#include <stdint.h>

#include <tss2/tss2_tpm2_types.h>

#include "../common/charra_error.h"

/**
 * @brief Sign data with AK_r, returning the public half of the very key
 * that signed it.
 *
 * SHA-256(data), then TPM2_Sign with a null validation ticket -- "this
 * digest did not come from me", which only an unrestricted key may sign.
 *
 * Both outputs come from one derivation on purpose, so the published key
 * cannot disagree with the signature. Caching the public half while
 * re-deriving the private one would let them drift apart silently, and
 * only under a TPM reset.
 *
 * Takes rp_tpm_mutex; the caller must NOT already hold it.
 *
 * @param[out] signature_out >= CHARRA_RSA_SIGNATURE_LEN bytes; raw RSA-PSS
 * bytes, not a TPMT_SIGNATURE wrapper.
 * @param[out] ak_public_key_out AK_r's public half, wire-shaped. May be
 * NULL.
 */
CHARRA_RC rp_sign_with_ak(const uint8_t* data, size_t data_len,
        uint8_t* signature_out, TPM2B_PUBLIC* ak_public_key_out);

/** PCR the RP replays log_r into. Not PCR 10, for one reason that always
 * applies and one that applies only in a fallback configuration.
 *
 * Always: this PCR must be rewound before each replay (see tpm2_pcr_reset()
 * below), and PCR 10 -- correctly -- refuses, being in the 0-15 range. Only
 * 16 and 23 are resettable from locality 0 on this simulator.
 *
 * Only when the TPMs are shared: 23 is outside the Attester's quoted
 * selection ({0..7, 10}), so RP activity here cannot perturb Quote_a. Under
 * the normal two-TPM setup that is moot -- the roles hold separate devices,
 * so the RP cannot reach the Attester's PCRs whatever index it uses. It
 * matters under TWO_TPMS=0 (run_daemon.sh), which points the RP at the
 * Attester's own TCTI; there, replaying into PCR 10 would corrupt the PCR
 * Quote_a attests to. */
#define RP_REPLAY_PCR_INDEX 23

/**
 * @brief Replay log_r into RP_REPLAY_PCR_INDEX: reset, then one extend per
 * entry.
 *
 * A PCR is a hash chain, so there is no batch form: N entries cost N round
 * trips, and this dominates the cost of Quote_r.
 *
 * Called ONCE PER CYCLE, not per Verifier. The replay is identical for
 * every Verifier -- only the nonce differs, and that enters at quote time.
 * TPM2_Quote reads a PCR without consuming it, so one replay backs every
 * quote in the cycle; doing it per Verifier multiplied the cost by the
 * Verifier count for nothing.
 *
 * Entries are selected by CHARRA_IMA_PCR_INDEX (where the Attester
 * measured them) and extended into RP_REPLAY_PCR_INDEX. Both start at zero
 * and apply the same digests in the same order, so the result matches
 * charra_replay_ima_log(log, len, CHARRA_IMA_PCR_INDEX, ...) exactly --
 * which is how the Verifier checks it.
 *
 * Derives no key: PCR_Reset and PCR_Extend authorise against the PCR.
 */
CHARRA_RC rp_replay_log_into_pcr(const uint8_t* log, uint32_t log_len);

/**
 * @brief TPM2_Quote RP_REPLAY_PCR_INDEX under one Verifier's nonce.
 *
 * Called per Verifier, against whatever rp_replay_log_into_pcr() left in
 * the PCR. The RP does not assemble the signed bytes: it supplies a nonce
 * and a one-PCR selection, and the TPM reads the PCR, builds the
 * TPMS_ATTEST (extraData = the nonce, pcrDigest = the composite) and signs
 * it. That is the difference between asserting a PCR value and attesting
 * one.
 *
 * Quoting does not disturb the PCR, so these may run in any order. What
 * must not happen is a NEW cycle's replay landing mid-cycle; the daemon is
 * sequential (prepare_evidence, then the Verifier loop), so it does not.
 *
 * @param[out] attest_out the TPM2B_ATTEST body, without its size field;
 * needs room for attest_cap bytes.
 * @param[out] signature_out >= CHARRA_RSA_SIGNATURE_LEN raw RSA-PSS bytes.
 * @param[out] ak_public_key_out public half of the signing key. May be
 * NULL.
 */
CHARRA_RC rp_quote_pcr_with_ak(const uint8_t* nonce, uint32_t nonce_len,
        uint8_t* attest_out, uint32_t attest_cap, uint32_t* attest_len_out,
        uint8_t* signature_out, TPM2B_PUBLIC* ak_public_key_out);

#endif /* CHARRA_RP_SIGNING_KEY_H */
