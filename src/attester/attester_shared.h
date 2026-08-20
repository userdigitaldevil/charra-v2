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

/* --- produced by attester.c (configuration) ----------------------------- */

/** ASCII IMA measurement log replayed into the TPM's PCRs before the first
 * TPM Quote, so PCR 10 reflects a non-trivial measurement history instead
 * of staying all-zero. */
extern char* ima_test_log_path;

#endif /* CHARRA_ATTESTER_SHARED_H */
