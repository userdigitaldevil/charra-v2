/**
 * @file attester_shared.h
 * @brief State that genuinely crosses module boundaries inside src/attester/.
 *
 * Deliberately short. Anything a single module owns end to end is `static`
 * in that module and absent from here; each item below is declared by the
 * module that PRODUCES it, and appears here only because a second module
 * reads it. Same convention as rp_shared.h and verifier_shared.h.
 */

#ifndef CHARRA_ATTESTER_SHARED_H
#define CHARRA_ATTESTER_SHARED_H

/* --- produced by attester_identity.c ------------------------------------ */

/** This Attester's EK certificate, signed by the synthetic manufacturer CA.
 * Read back by /certify_ak_of_attester, which forwards it to the RP. */
extern char* attester_ek_cert_cache_path;

/** Public half of the Attester's identity AK. Read by
 * /certify_ak_of_attester to answer a FETCH. */
extern char* attester_ak_public_path;

/* --- produced by attester_certify_ak.c ---------------------------------- */

/** AK certificate issued under the RP's own CA, written by DELIVER_RP. */
extern char* attester_ak_cert_rp_path;

/** AK certificate issued under a Verifier's CA, written by
 * DELIVER_VERIFIER. Both are read fresh from disk by /attest on every call
 * rather than cached, since DELIVER_VERIFIER can rewrite this one at any
 * time between /attest calls. */
extern char* attester_ak_cert_verifier_path;

/* --- produced by attester.c (configuration) ----------------------------- */

/** ASCII IMA measurement log replayed into the TPM's PCRs before the first
 * TPM Quote, so PCR 10 reflects a non-trivial measurement history instead
 * of staying all-zero. */
extern char* ima_test_log_path;

#endif /* CHARRA_ATTESTER_SHARED_H */
