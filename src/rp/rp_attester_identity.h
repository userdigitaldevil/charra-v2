/**
 * @file rp_attester_identity.h
 * @brief Provisioning the Attester's AK identity, RP-mediated.
 *
 * Two independent CAs certify the same Attester AK, neither trusting the
 * other's issuance:
 *  - RP's own CA: one relationship, provisioned once per process.
 *  - Each Verifier's CA: a separate certificate per Verifier, since every
 *    Verifier now holds its own CA key.
 *
 * RP initiates every leg; the Attester and the Verifiers stay purely
 * passive throughout.
 */

#ifndef CHARRA_RP_ATTESTER_IDENTITY_H
#define CHARRA_RP_ATTESTER_IDENTITY_H

#include <stdbool.h>

#include "../common/charra_error.h"

/**
 * @brief FETCH the Attester's identity and certify it under RP's own CA.
 *
 * Runs once per process. A hard local gate: if the Attester's EK
 * certificate does not chain to the manufacturer root this fails, and the
 * caller is expected to abort the cycle rather than proceed with an
 * unverified Attester.
 */
CHARRA_RC ensure_attester_identity_provisioned(void);

/**
 * @brief Certify the Attester's AK under verifiers[verifier_index]'s own
 * CA, via the CHALLENGE -> ACTIVATE -> CONFIRM -> DELIVER relay. Cached in
 * memory and on disk, so this is a no-op after the first success.
 */
CHARRA_RC ensure_attester_identity_certified_by_verifier(int verifier_index);


/**
 * @brief Send RP's Step 2a verdict to the Attester (/attest_result).
 *
 * The spec's Step 2a ends "-> fail: negative proof to Attester", but the
 * Attester is the *server* of /attest, so its evidence is the last message
 * of that exchange and there is no reply slot to reject it in. Hence a
 * separate RP-initiated request.
 *
 * Must be called after the caller's CoAP loop finishes, never from inside a
 * response handler -- starting a second exchange from within a libcoap
 * callback re-enters the stack mid-dispatch. Advisory: delivery failure is
 * logged and ignored.
 */
void rp_send_attestation_result(bool accepted, const char* reason);

#endif /* CHARRA_RP_ATTESTER_IDENTITY_H */
