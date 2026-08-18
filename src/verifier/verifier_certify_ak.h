/**
 * @file verifier_certify_ak.h
 * @brief /certify_ak -- the Verifier acting as Privacy CA.
 */

#ifndef CHARRA_VERIFIER_CERTIFY_AK_H
#define CHARRA_VERIFIER_CERTIFY_AK_H

#include <coap3/coap.h>

/**
 * @brief Two-leg TPM2 credential-activation handshake.
 *
 * CHALLENGE validates the requester's EK certificate and returns a secret
 * wrapped to that EK/AK pair, signing and recording nothing. CONFIRM
 * issues the AK certificate only if the secret comes back intact, proving
 * the AK really lives in the TPM the EK certificate describes.
 *
 * Serves both the RP's own AK and an Attester AK relayed by the RP; the
 * subject is bound at CHALLENGE time, so CONFIRM cannot redirect a proven
 * identity into the other one's ledger.
 */
void coap_certify_ak_handler(struct coap_resource_t* resource,
        struct coap_session_t* session, const struct coap_pdu_t* request,
        const struct coap_string_t* query, struct coap_pdu_t* response);

#endif /* CHARRA_VERIFIER_CERTIFY_AK_H */
